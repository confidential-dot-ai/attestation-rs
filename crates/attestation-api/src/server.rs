use axum::body::Body;
use axum::extract::DefaultBodyLimit;
use axum::http::Request;
use axum::http::StatusCode;
use axum::routing::{get, post};
use axum::{middleware, Router};
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;
use tokio::net::TcpListener;
use tower_http::request_id::{
    MakeRequestId, PropagateRequestIdLayer, RequestId, SetRequestIdLayer,
};
use tower_http::timeout::{RequestBodyTimeoutLayer, TimeoutLayer};
use tower_http::trace::TraceLayer;
use uuid::Uuid;

use crate::api;
use crate::config::ServerConfig;
use crate::middleware as mw;
use crate::AppState;

/// Maximum request body size (1 MiB).
const MAX_BODY_SIZE: usize = 1024 * 1024;
/// A connection must send a request's headers within this long.
const HEADER_TIMEOUT: Duration = Duration::from_secs(10);
/// A request must send its body within this long.
const BODY_TIMEOUT: Duration = Duration::from_secs(10);
/// A connection open this long is closed once its request in progress is
/// answered.
const CONNECTION_TIMEOUT: Duration = Duration::from_secs(60);
/// Added to a `/verify` request's own deadlines (queue and vendors) for the
/// time it may take in all: verifying, and reading and writing.
const REQUEST_SLACK: Duration = Duration::from_secs(30);

/// Generates UUID v4 request IDs for requests that don't already have one.
#[derive(Clone)]
struct UuidRequestId;

impl MakeRequestId for UuidRequestId {
    fn make_request_id<B>(&mut self, _request: &Request<B>) -> Option<RequestId> {
        let id = Uuid::new_v4().to_string();
        id.parse().ok().map(RequestId::new)
    }
}

/// Observability layers shared by all routes (request ID + tracing), and
/// the time limits of a request.
fn observability_layers(router: Router, server: &ServerConfig) -> Router {
    let request_timeout =
        Duration::from_millis(server.queue_deadline_ms + server.fetch_deadline_ms) + REQUEST_SLACK;
    router
        .layer(RequestBodyTimeoutLayer::new(BODY_TIMEOUT))
        .layer(TimeoutLayer::with_status_code(
            StatusCode::SERVICE_UNAVAILABLE,
            request_timeout,
        ))
        .layer(PropagateRequestIdLayer::x_request_id())
        .layer(
            TraceLayer::new_for_http().make_span_with(|request: &Request<Body>| {
                let request_id = request
                    .headers()
                    .get("x-request-id")
                    .and_then(|v| v.to_str().ok())
                    .unwrap_or("-");
                tracing::info_span!(
                    "http_request",
                    method = %request.method(),
                    uri = %request.uri(),
                    request_id = %request_id,
                )
            }),
        )
        .layer(SetRequestIdLayer::x_request_id(UuidRequestId))
}

/// Public routes that do not require authentication.
fn public_routes() -> Router<AppState> {
    Router::new().route("/health", get(api::health::handler))
}

/// Protected routes that require authentication in hosted mode.
fn protected_routes() -> Router<AppState> {
    Router::new()
        .route("/platform", get(api::platform::handler))
        .route("/attest", post(api::attest::handler))
        .route("/verify", post(api::verify::handler))
        .route("/token/jwks", get(api::token::jwks))
        .layer(DefaultBodyLimit::max(MAX_BODY_SIZE))
}

/// Build the core API router without mode-specific middleware.
/// Useful for testing.
pub fn build_api_router(state: AppState) -> Router {
    let server = state.config.server.clone();
    let router = public_routes().merge(protected_routes()).with_state(state);

    observability_layers(router, &server)
}

/// Build the full router with optional API key auth.
///
/// When API keys are configured, `/health` is exempt from auth so that
/// Kubernetes liveness/readiness probes can reach it without credentials.
pub fn build_router(state: AppState) -> Router {
    if state.config.auth.api_keys.is_empty() {
        build_api_router(state)
    } else {
        let server = state.config.server.clone();
        let public = public_routes().with_state(state.clone());

        let protected = protected_routes()
            .layer(middleware::from_fn_with_state(
                state.clone(),
                mw::auth::api_key_auth,
            ))
            .with_state(state);

        observability_layers(public.merge(protected), &server)
    }
}

pub async fn run(state: AppState) -> anyhow::Result<()> {
    let addr: SocketAddr = state.config.server.bind.parse()?;
    let max_connections = state.config.server.max_connections;
    let app = build_router(state);

    tracing::info!(%addr, "starting attestation service");

    let listener = TcpListener::bind(addr).await?;
    serve(listener, app, max_connections, shutdown_signal()).await;

    Ok(())
}

/// Serve `app` on `listener`, at most `max_connections` connections at once
/// (more wait in the listen backlog). A connection slow to send its headers
/// is dropped, and one open [`CONNECTION_TIMEOUT`] is closed once its
/// request in progress is answered. When `shutdown` completes, stop
/// accepting and let open connections finish their requests.
pub async fn serve(
    listener: TcpListener,
    app: Router,
    max_connections: usize,
    shutdown: impl std::future::Future<Output = ()>,
) {
    use hyper_util::rt::{TokioIo, TokioTimer};
    let permits = Arc::new(tokio::sync::Semaphore::new(max_connections));
    let (stop, stopping) = tokio::sync::watch::channel(());
    tokio::pin!(shutdown);
    loop {
        let accepted = tokio::select! {
            () = &mut shutdown => break,
            accepted = async {
                let permit = permits.clone().acquire_owned().await;
                (permit, listener.accept().await)
            } => accepted,
        };
        let (permit, io) = match accepted {
            (Ok(permit), Ok((io, _))) => (permit, io),
            (_, Err(e)) => {
                tracing::warn!(%e, "accept failed");
                tokio::time::sleep(Duration::from_millis(100)).await;
                continue;
            }
            (Err(_), _) => unreachable!("the semaphore is never closed"),
        };
        let service = hyper_util::service::TowerToHyperService::new(app.clone());
        let mut stopping = stopping.clone();
        tokio::spawn(async move {
            let connection = hyper::server::conn::http1::Builder::new()
                .timer(TokioTimer::new())
                .header_read_timeout(HEADER_TIMEOUT)
                .serve_connection(TokioIo::new(io), service);
            tokio::pin!(connection);
            let closed = tokio::select! {
                _ = connection.as_mut() => true,
                () = tokio::time::sleep(CONNECTION_TIMEOUT) => false,
                _ = stopping.changed() => false,
            };
            if !closed {
                connection.as_mut().graceful_shutdown();
                let _ = tokio::time::timeout(CONNECTION_TIMEOUT, connection).await;
            }
            drop(permit);
        });
    }
    drop(stop);
    // Every permit back: every connection has closed.
    let all = u32::try_from(max_connections).unwrap_or(u32::MAX);
    let _ = permits.acquire_many(all).await;
}

async fn shutdown_signal() {
    let ctrl_c = async {
        tokio::signal::ctrl_c()
            .await
            .expect("failed to install Ctrl+C handler");
    };

    #[cfg(unix)]
    let terminate = async {
        tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
            .expect("failed to install SIGTERM handler")
            .recv()
            .await;
    };

    #[cfg(not(unix))]
    let terminate = std::future::pending::<()>();

    tokio::select! {
        _ = ctrl_c => tracing::info!("received Ctrl+C, shutting down"),
        _ = terminate => tracing::info!("received SIGTERM, shutting down"),
    }
}
