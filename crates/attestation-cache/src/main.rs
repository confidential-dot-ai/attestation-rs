use std::path::PathBuf;

use attestation_cache::{Cache, Config};
use clap::Parser;
use tracing_subscriber::EnvFilter;

#[derive(Parser)]
#[command(
    name = "attestation-cache",
    about = "Serve verified TEE attestation collateral"
)]
struct Cli {
    /// Configuration file (TOML).
    #[arg(short, long, default_value = "/etc/attestation-cache/config.toml")]
    config: PathBuf,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info")),
        )
        .init();
    let cli = Cli::parse();
    let config: Config = if cli.config.exists() {
        let text = std::fs::read_to_string(&cli.config)?;
        toml::from_str(&text).map_err(|e| anyhow::anyhow!("{}: {e}", cli.config.display()))?
    } else {
        tracing::info!(path = %cli.config.display(), "no config file, using defaults");
        Config::default()
    };
    let cache = Cache::new(config.context()?, &config.warm);
    let router = cache.router();
    tokio::spawn(cache.keep_fresh());

    #[cfg(target_os = "linux")]
    if let Some(port) = config.vsock_port {
        let router = router.clone();
        tracing::info!(port, "listening on vsock");
        tokio::spawn(async move {
            if let Err(e) = attestation_cache::serve_vsock(router, port).await {
                tracing::error!(%e, "vsock listener stopped");
                std::process::exit(1);
            }
        });
    }
    #[cfg(not(target_os = "linux"))]
    if config.vsock_port.is_some() {
        anyhow::bail!("vsock_port: vsock is Linux only");
    }

    let listener = tokio::net::TcpListener::bind(&config.listen).await?;
    tracing::info!(listen = %config.listen, upstream = ?config.upstream, dir = %config.dir.display(), "serving collateral");
    axum::serve(listener, router).await?;
    Ok(())
}
