use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use clap::Parser;
use tracing_subscriber::EnvFilter;

use attestation_api::config::{resolve_nras_gpu_url, resolve_nras_switch_url, Config};
use attestation_api::token::{issuer::TokenIssuer, keys};
use attestation_api::AppState;

#[derive(Parser)]
#[command(name = "attestation-api", about = "TEE Attestation REST API")]
struct Cli {
    /// Path to config file (TOML)
    #[arg(short, long, default_value = "config.toml")]
    config: PathBuf,
}

fn main() -> anyhow::Result<()> {
    // Initialize tracing
    tracing_subscriber::fmt()
        .with_env_filter(
            EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info")),
        )
        .init();

    let cli = Cli::parse();
    #[cfg(unix)]
    raise_open_files_limit();

    // Load config (use defaults if file not found)
    let config = if cli.config.exists() {
        tracing::info!(path = %cli.config.display(), "loading config");
        Config::load(&cli.config)?
    } else {
        tracing::info!("no config file found, using defaults");
        Config::default()
    };

    config.validate().map_err(|e| {
        tracing::error!(%e, "invalid configuration");
        anyhow::anyhow!(e)
    })?;

    // Verifications run on their own threads; these only serve connections.
    tokio::runtime::Builder::new_multi_thread()
        .worker_threads(config.server.io_threads())
        .enable_all()
        .build()?
        .block_on(serve(Arc::new(config)))
}

async fn serve(config: Arc<Config>) -> anyhow::Result<()> {
    if config.auth.api_keys.is_empty() {
        tracing::warn!(
            "no API keys configured in [auth].api_keys — all endpoints are unauthenticated"
        );
    }
    if !config
        .server
        .bind
        .parse::<SocketAddr>()
        .is_ok_and(|a| a.ip().is_loopback())
    {
        tracing::warn!(
            bind = %config.server.bind,
            "listener is plain HTTP on a non-loopback address; keep it behind a TLS terminator on a private network"
        );
    }

    // Build token issuer (if enabled)
    let token_issuer = if config.token.enabled {
        let signing_key = keys::load_or_generate(&config.token.key_path)?;
        let issuer = TokenIssuer::new(
            signing_key,
            config.token.issuer.clone(),
            Duration::from_secs(config.token.duration_minutes * 60),
        )?;
        Some(Arc::new(issuer))
    } else {
        None
    };

    // One collateral store for the process: every piece is fetched once,
    // checked, and kept until a newer one replaces it.
    let gpu_url = resolve_nras_gpu_url(&config.nras);
    let switch_url = resolve_nras_switch_url(&config.nras);
    tracing::info!(gpu = %gpu_url, switch = %switch_url, "configured NRAS endpoints");
    let verifier = Arc::new(attestation::Verifier::new(
        attestation::Context::new().with_nras_urls(gpu_url, switch_url)?,
    ));

    // Warm attestation::detect()'s process-lifetime cache before serving, so the
    // first /health/attest/platform request hits the memoized value instead of
    // racing to open the vTPM context.
    #[cfg(target_os = "linux")]
    let _ = attestation::detect();

    let state = AppState::new(config, token_issuer, verifier);
    tracing::info!(
        verify_threads = state.verify_pool.threads(),
        io_threads = state.config.server.io_threads(),
        "verification pool"
    );
    tokio::spawn(state.verify_pool.clone().report(Duration::from_secs(10)));

    attestation_api::server::run(state).await
}

/// Raise the soft limit on open files to the hard limit, so that a
/// launcher's low default (Docker's 1024) does not cap connections.
#[cfg(unix)]
fn raise_open_files_limit() {
    use rustix::process::{getrlimit, setrlimit, Resource, Rlimit};
    let limit = getrlimit(Resource::Nofile);
    let raised = Rlimit {
        current: limit.maximum,
        ..limit
    };
    match setrlimit(Resource::Nofile, raised) {
        Ok(()) => tracing::info!(limit = ?limit.maximum, "open files limit"),
        Err(e) => tracing::warn!(%e, current = ?limit.current, "cannot raise the open files limit"),
    }
}
