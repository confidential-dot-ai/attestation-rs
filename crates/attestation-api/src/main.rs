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
    #[arg(short, long)]
    config: Option<PathBuf>,
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
    let default_config = PathBuf::from("config.toml");
    let config_path = cli
        .config
        .or_else(|| default_config.exists().then_some(default_config));
    let config = if let Some(path) = config_path {
        tracing::info!(path = %path.display(), "loading config");
        Config::load(&path)?
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

    #[cfg(unix)]
    let refresh = config
        .verify
        .selected_tdx
        .clone()
        .map(|source| {
            let signal = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::hangup())?;
            Ok::<_, std::io::Error>((
                source,
                signal,
                Duration::from_millis(config.verify.fetch_deadline_ms),
            ))
        })
        .transpose()?;
    let verifier = if config.verify.selected_tdx.is_some() {
        attestation_api::selected_tdx::check_startup(&config.verify).await?;
        Arc::new(attestation::Verifier::new(attestation::Context::held([])))
    } else {
        let gpu_url = resolve_nras_gpu_url(&config.nras);
        let switch_url = resolve_nras_switch_url(&config.nras);
        tracing::info!(gpu = %gpu_url, switch = %switch_url, "configured NRAS endpoints");
        let jwks = attestation::platforms::nvidia_gpu::jwks_url_for_endpoint(&gpu_url)?;
        let verifier = Arc::new(attestation::Verifier::new(
            attestation::Context::new().with_nras_urls(gpu_url, switch_url)?,
        ));

        // Fetch the collateral every request needs, and the configured NRAS's key
        // set, before serving, for at most 10 s.
        let (mut warming, now) = (tokio::task::JoinSet::new(), verifier.context().now());
        for url in config.verify.warm.clone() {
            let verifier = verifier.clone();
            warming.spawn(async move { drop(verifier.context().store().serve(&url, now).await) });
        }
        let nras = verifier.clone();
        warming
            .spawn(async move { drop(nras.context().store().get::<NrasJwks>(&jwks, now).await) });
        let _ = tokio::time::timeout(Duration::from_secs(10), warming.join_all()).await;
        verifier
    };

    // Warm attestation::detect()'s process-lifetime cache before serving, so the
    // first /health/attest/platform request hits the memoized value instead of
    // racing to open the vTPM context.
    #[cfg(target_os = "linux")]
    if config.verify.selected_tdx.is_none() {
        let _ = attestation::detect();
    }

    // Connections, plus vendor sockets, files and stdio, fit the open-files limit.
    let files = rlimit::increase_nofile_limit(65_536)?;
    anyhow::ensure!(
        config.server.max_connections as u64 + 256 <= files,
        "server.max_connections must be at least 256 below the open-files limit ({files}): \
         lower it, or raise the hard limit (LimitNOFILE= or ulimit -Hn)"
    );
    let admission = Arc::new(attestation_api::admission::Admission::new(&config.verify));
    let state = AppState {
        config,
        token_issuer,
        verifier,
        admission,
    };

    let server = attestation_api::server::run(state, bind);
    #[cfg(unix)]
    if let Some((source, signal, deadline)) = refresh {
        return tokio::select! {
            result = server => result,
            result = source.on_hangup(signal, deadline) => result,
        };
    }
    server.await
}
