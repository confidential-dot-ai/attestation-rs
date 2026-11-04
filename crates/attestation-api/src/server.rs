use axum::body::Body;
use axum::extract::DefaultBodyLimit;
use axum::http::Request;
use axum::routing::{get, post};
use axum::{middleware, Router};
use std::future::Future;
use std::net::SocketAddr;
use tokio::net::TcpListener;
use tower_http::request_id::{
    MakeRequestId, PropagateRequestIdLayer, RequestId, SetRequestIdLayer,
};
use tower_http::trace::TraceLayer;
use uuid::Uuid;

use crate::api;
use crate::config::Bind;
use crate::middleware as mw;
use crate::AppState;

#[cfg(unix)]
mod unix;

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

/// A bound listener, ready for [`serve`].
pub enum Listener {
    Tcp(TcpListener),
    /// Removes its socket file when dropped.
    #[cfg(unix)]
    Unix(tokio::net::UnixListener, unix::SocketFile),
}

/// Bind the listener for `target`. Unix sockets carry their final mode and
/// group before they become reachable at their path.
pub async fn bind(target: &Bind) -> anyhow::Result<Listener> {
    match target {
        Bind::Tcp(addr) => Ok(Listener::Tcp(TcpListener::bind(addr).await?)),
        #[cfg(unix)]
        Bind::Unix { path, mode, group } => {
            let (listener, file) = unix::bind(path, *mode, *group).await?;
            Ok(Listener::Unix(listener, file))
        }
        #[cfg(not(unix))]
        Bind::Unix { .. } => anyhow::bail!("unix: binds need a Unix platform"),
    }
}

/// Serve `app` on `listener` until `shutdown` completes and in-flight
/// requests finish. A Unix socket file is removed on return.
pub async fn serve(
    listener: Listener,
    app: Router,
    shutdown: impl Future<Output = ()> + Send + 'static,
) -> anyhow::Result<()> {
    match listener {
        Listener::Tcp(listener) => {
            axum::serve(
                listener,
                app.into_make_service_with_connect_info::<SocketAddr>(),
            )
            .with_graceful_shutdown(shutdown)
            .await?
        }
        #[cfg(unix)]
        Listener::Unix(listener, _file) => {
            axum::serve(listener, app.into_make_service())
                .with_graceful_shutdown(shutdown)
                .await?
        }
    }
    Ok(())
}

/// Serve `state` on `target`, which the caller resolved from the config,
/// until SIGINT or SIGTERM.
pub async fn run(state: AppState, target: Bind) -> anyhow::Result<()> {
    let app = build_router(state);
    let listener = bind(&target).await?;
    tracing::info!(bind = %target, "listening");
    serve(listener, app, shutdown_signal()).await
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
