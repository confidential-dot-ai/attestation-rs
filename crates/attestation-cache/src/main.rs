use std::path::{Path, PathBuf};

use anyhow::Context;

use attestation_cache::{Cache, Config};
use clap::Parser;
use tracing_subscriber::EnvFilter;

#[derive(Parser)]
#[command(
    name = "attestation-cache",
    about = "Serve verified TEE attestation collateral"
)]
struct Cli {
    /// Configuration file (TOML); defaults to /etc/attestation-cache/config.toml.
    #[arg(short, long)]
    config: Option<PathBuf>,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info")),
        )
        .init();
    let cli = Cli::parse();
    let path = cli
        .config
        .as_deref()
        .unwrap_or_else(|| Path::new("/etc/attestation-cache/config.toml"));
    let config = load_config(path, cli.config.is_some())?;
    let cache = Cache::new(config.context()?, &config.warm).with_keys(config.keys.clone());
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
    attestation_cache::serve(listener, router).await;
    Ok(())
}

fn load_config(path: &Path, required: bool) -> anyhow::Result<Config> {
    match std::fs::read_to_string(path) {
        Ok(text) => toml::from_str(&text).with_context(|| path.display().to_string()),
        Err(e) if !required && e.kind() == std::io::ErrorKind::NotFound => {
            tracing::info!(path = %path.display(), "no config file, using defaults");
            Ok(Config::default())
        }
        Err(e) => Err(e).with_context(|| path.display().to_string()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn only_an_implicit_missing_config_uses_defaults() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("config.toml");
        let implicit = Cli::try_parse_from(["attestation-cache"]).unwrap();
        let explicit = Cli::try_parse_from([
            "attestation-cache",
            "--config",
            "/etc/attestation-cache/config.toml",
        ])
        .unwrap();
        let defaults = load_config(&path, implicit.config.is_some()).unwrap();
        assert_eq!(defaults.listen, Config::default().listen);
        assert!(defaults.keys.is_empty());
        let error = load_config(&path, explicit.config.is_some()).err().unwrap();
        assert_eq!(
            error.downcast_ref::<std::io::Error>().unwrap().kind(),
            std::io::ErrorKind::NotFound
        );

        std::fs::write(&path, "listen = '127.0.0.1:9999'\nkeys = ['secret']").unwrap();
        for required in [false, true] {
            let config = load_config(&path, required).unwrap();
            assert_eq!(config.listen, "127.0.0.1:9999");
            assert_eq!(config.keys, ["secret"]);
        }
    }

    #[test]
    fn unreadable_and_invalid_configs_never_use_defaults() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("config.toml");
        for required in [false, true] {
            // A directory cannot be read as TOML, even when running as root.
            let error = load_config(dir.path(), required).err().unwrap();
            assert!(error.downcast_ref::<std::io::Error>().is_some());
            std::fs::write(&path, [0xff]).unwrap();
            let error = load_config(&path, required).err().unwrap();
            assert_eq!(
                error.downcast_ref::<std::io::Error>().unwrap().kind(),
                std::io::ErrorKind::InvalidData
            );
            std::fs::write(&path, "keys = [").unwrap();
            let error = load_config(&path, required).err().unwrap();
            assert!(error.downcast_ref::<toml::de::Error>().is_some());
        }
    }
}
