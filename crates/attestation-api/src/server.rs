use axum::body::Body;
use axum::extract::DefaultBodyLimit;
use axum::http::Request;
use axum::routing::{get, post};
use axum::{middleware, Router};
use std::net::SocketAddr;
use tokio::net::TcpListener;
use tower_http::request_id::{
    MakeRequestId, PropagateRequestIdLayer, RequestId, SetRequestIdLayer,
};
use tower_http::trace::TraceLayer;
use uuid::Uuid;

use crate::api;
use crate::middleware as mw;
use crate::AppState;

/// Maximum request body size (1 MiB).
const MAX_BODY_SIZE: usize = 1024 * 1024;

/// Generates UUID v4 request IDs for requests that don't already have one.
#[derive(Clone)]
struct UuidRequestId;

impl MakeRequestId for UuidRequestId {
    fn make_request_id<B>(&mut self, _request: &Request<B>) -> Option<RequestId> {
        let id = Uuid::new_v4().to_string();
        id.parse().ok().map(RequestId::new)
    }
}

/// Observability layers shared by all routes (request ID + tracing).
fn observability_layers(router: Router) -> Router {
    router
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
        .route("/certs/status", get(api::certs::status_handler))
        .route("/certs/refresh", post(api::certs::refresh))
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
    let app = build_router(state);

    tracing::info!(%addr, "starting attestation service");

    let listener = TcpListener::bind(addr).await?;
    axum::serve(
        listener,
        app.into_make_service_with_connect_info::<SocketAddr>(),
    )
    .with_graceful_shutdown(shutdown_signal())
    .await?;

    Ok(())
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
