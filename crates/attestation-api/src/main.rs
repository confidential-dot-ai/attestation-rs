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

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    // Initialize tracing
    tracing_subscriber::fmt()
        .with_env_filter(
            EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info")),
        )
        .init();

    let cli = Cli::parse();

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

    let config = Arc::new(config);

    if config.auth.api_keys.is_empty() {
        tracing::warn!(
            "no API keys configured in [auth].api_keys — all endpoints are unauthenticated"
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
        attestation::Context::new().with_nras_urls(gpu_url, switch_url),
    ));

    // Warm attestation::detect()'s process-lifetime cache before serving, so the
    // first /health/attest/platform request hits the memoized value instead of
    // racing to open the vTPM context.
    #[cfg(target_os = "linux")]
    let _ = attestation::detect();

    let state = AppState {
        config,
        token_issuer,
        verifier,
    };

    attestation_api::server::run(state).await
}
