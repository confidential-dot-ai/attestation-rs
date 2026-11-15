use axum::body::Body;
use axum::extract::DefaultBodyLimit;
use axum::http::{Request, StatusCode};
use axum::routing::{get, post};
use axum::{middleware, Router};
use std::net::SocketAddr;
use std::time::Duration;
use tokio::net::TcpListener;
use tower_http::classify::{ServerErrorsAsFailures, SharedClassifier};
use tower_http::request_id::{
    MakeRequestId, PropagateRequestIdLayer, RequestId, SetRequestIdLayer,
};
use tower_http::timeout::{RequestBodyTimeoutLayer, TimeoutLayer};
use tower_http::trace::{DefaultOnFailure, TraceLayer};
use tracing::Level;
use uuid::Uuid;

use crate::api;
use crate::middleware as mw;
use crate::AppState;

/// Maximum request body size (1 MiB).
const MAX_BODY_SIZE: usize = 1024 * 1024;
/// How long a client may take to send the request headers, and the body.
const HEADER_TIMEOUT: Duration = Duration::from_secs(10);
const BODY_TIMEOUT: Duration = Duration::from_secs(10);

/// Generates UUID v4 request IDs for requests that don't already have one.
#[derive(Clone)]
struct UuidRequestId;

impl MakeRequestId for UuidRequestId {
    fn make_request_id<B>(&mut self, _request: &Request<B>) -> Option<RequestId> {
        let id = Uuid::new_v4().to_string();
        id.parse().ok().map(RequestId::new)
    }
}

/// Tracing whose 5xx refusals (overloaded, collateral unavailable) are warnings.
fn trace_with_warned_refusals() -> TraceLayer<SharedClassifier<ServerErrorsAsFailures>> {
    TraceLayer::new_for_http().on_failure(DefaultOnFailure::new().level(Level::WARN))
}

/// Observability layers shared by all routes (request ID + tracing).
fn observability_layers(router: Router) -> Router {
    router
        .layer(PropagateRequestIdLayer::x_request_id())
        .layer(
            trace_with_warned_refusals().make_span_with(|request: &Request<Body>| {
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
    let router = public_routes().merge(protected_routes()).with_state(state);

    observability_layers(router)
}

/// Build the full router with optional API key auth.
///
/// When API keys are configured, `/health` is exempt from auth so that
/// Kubernetes liveness/readiness probes can reach it without credentials.
pub fn build_router(state: AppState) -> Router {
    if state.config.auth.api_keys.is_empty() {
        build_api_router(state)
    } else {
        let public = public_routes().with_state(state.clone());

        let protected = protected_routes()
            .layer(middleware::from_fn_with_state(
                state.clone(),
                mw::auth::api_key_auth,
            ))
            .with_state(state);

        observability_layers(public.merge(protected))
    }
}

pub async fn run(state: AppState) -> anyhow::Result<()> {
    let addr: SocketAddr = state.config.server.bind.parse()?;
    // 503 once the body, queue and fetch time and 10 s of verification are spent.
    let (verify, unavailable) = (&state.config.verify, StatusCode::SERVICE_UNAVAILABLE);
    let deadline = Duration::from_millis(verify.queue_deadline_ms + verify.fetch_deadline_ms);
    let app = build_router(state.clone())
        .layer(TimeoutLayer::with_status_code(
            unavailable,
            deadline + 2 * BODY_TIMEOUT,
        ))
        .layer(RequestBodyTimeoutLayer::new(BODY_TIMEOUT));

    tracing::info!(%addr, "starting attestation service");

    let listener = TcpListener::bind(addr).await?;
    let connections = state.config.server.max_connections;
    serve(listener, app, connections, shutdown_signal()).await;
    Ok(())
}

/// Serve `router` with at most `max_connections` open (the rest wait in the
/// backlog) and a header timeout; after `shutdown`, finish within 5 s.
pub async fn serve(
    listener: TcpListener,
    router: Router,
    max_connections: usize,
    shutdown: impl std::future::Future<Output = ()>,
) {
    use hyper_util::rt::{TokioIo, TokioTimer};
    let open = std::sync::Arc::new(tokio::sync::Semaphore::new(max_connections));
    let graceful = hyper_util::server::graceful::GracefulShutdown::new();
    tokio::pin!(shutdown);
    loop {
        let next = async { (open.clone().acquire_owned().await, listener.accept().await) };
        let next = tokio::select! {
            next = next => next,
            _ = &mut shutdown => break,
        };
        let (permit, Ok((io, _))) = next else {
            tokio::time::sleep(Duration::from_millis(100)).await;
            continue;
        };
        let service = hyper_util::service::TowerToHyperService::new(router.clone());
        let connection = hyper::server::conn::http1::Builder::new()
            .timer(TokioTimer::new())
            .header_read_timeout(HEADER_TIMEOUT)
            .serve_connection(TokioIo::new(io), service);
        let connection = graceful.watch(connection);
        tokio::spawn(async move {
            let _permit = permit;
            let _ = connection.await;
        });
    }
    let _ = tokio::time::timeout(Duration::from_secs(5), graceful.shutdown()).await;
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
