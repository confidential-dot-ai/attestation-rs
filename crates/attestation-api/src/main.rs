use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use clap::Parser;
use tracing_subscriber::EnvFilter;

use attestation::collateral::NrasJwks;
use attestation_api::config::{resolve_nras_gpu_url, resolve_nras_switch_url, Bind, Config};
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

    let bind = config.validate().map_err(|e| {
        tracing::error!(%e, "invalid configuration");
        anyhow::anyhow!(e)
    })?;

    let config = Arc::new(config);

    if config.auth.api_keys.is_empty() {
        tracing::warn!(
            "no API keys configured in [auth].api_keys — all endpoints are unauthenticated"
        );
    }
    if matches!(bind, Bind::Tcp(addr) if !addr.ip().is_loopback()) {
        tracing::warn!(
            %bind,
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
    let jwks = attestation::platforms::nvidia_gpu::jwks_url_for_endpoint(&gpu_url)?;
    let verifier = Arc::new(attestation::Verifier::new(
        attestation::Context::new().with_nras_urls(gpu_url, switch_url)?,
    ));

    // Warm attestation::detect()'s process-lifetime cache before serving, so the
    // first /health/attest/platform request hits the memoized value instead of
    // racing to open the vTPM context.
    // A container has no configfs mount of its own, and the kernel hands out
    // reports there when the runtime passed no device node.
    #[cfg(target_os = "linux")]
    match attestation::platforms::tsm::mount_configfs() {
        Ok(true) => tracing::info!("mounted configfs for TSM reports"),
        Ok(false) => {}
        Err(e) => tracing::debug!(error = %e, "configfs not mounted; device nodes only"),
    }
    #[cfg(target_os = "linux")]
    let _ = attestation::detect();

    // Connections, plus vendor sockets, files and stdio, fit the open-files limit.
    let files = rlimit::increase_nofile_limit(65_536)?;
    anyhow::ensure!(
        config.server.max_connections as u64 + 256 <= files,
        "server.max_connections must be at least 256 below the open-files limit ({files}): \
         lower it, or raise the hard limit (LimitNOFILE= or ulimit -Hn)"
    );
    // Fetch the collateral every request needs, and the configured NRAS's key
    // set, before serving, for at most 10 s.
    let (mut warming, now) = (tokio::task::JoinSet::new(), verifier.context().now());
    for url in config.verify.warm.clone() {
        let verifier = verifier.clone();
        warming.spawn(async move { drop(verifier.context().store().serve(&url, now).await) });
    }
    let nras = verifier.clone();
    warming.spawn(async move { drop(nras.context().store().get::<NrasJwks>(&jwks, now).await) });
    let _ = tokio::time::timeout(Duration::from_secs(10), warming.join_all()).await;
    let admission = Arc::new(attestation_api::admission::Admission::new(&config.verify));
    let state = AppState {
        config,
        token_issuer,
        verifier,
        admission,
    };

    attestation_api::server::run(state, bind).await
}
