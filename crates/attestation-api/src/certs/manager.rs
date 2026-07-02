use std::sync::Arc;
use std::time::Duration;

use tokio::task::JoinHandle;
use tokio::time::sleep;

use crate::certs::cache::CertCache;
use crate::certs::hours_to_duration;
use crate::certs::nras_provider::JwksRefreshHandle;
use crate::certs::revocation;
use crate::config::{normalize_generation, CertsConfig};

/// Start background cert management tasks.
/// Returns handles that can be used to abort on shutdown.
pub fn spawn_background_tasks(
    cache: Arc<CertCache>,
    config: &CertsConfig,
    jwks_handle: Option<JwksRefreshHandle>,
) -> Vec<JoinHandle<()>> {
    let mut handles = Vec::new();

    // Resolve configured generations for the refresh loop
    let generations: Vec<String> = config
        .prefetch_chains
        .iter()
        .filter_map(|g| normalize_generation(g).map(String::from))
        .collect();

    // Cert chain refresh loop — refresh at half the TTL
    let chain_interval = chain_refresh_interval(config.chain_ttl_hours);
    let cache_clone = cache.clone();
    let gens_clone = generations.clone();
    handles.push(tokio::spawn(async move {
        cert_refresh_loop(cache_clone, chain_interval, gens_clone).await;
    }));

    // CRL refresh loop
    let crl_interval = hours_to_duration(config.crl_refresh_hours);
    let cache_clone = cache.clone();
    handles.push(tokio::spawn(async move {
        crl_refresh_loop(cache_clone, crl_interval).await;
    }));

    // JWKS refresh loop (NRAS) — refresh at half the TTL, only when configured.
    if let Some(handle) = jwks_handle {
        let jwks_interval = jwks_refresh_interval(config.jwks_ttl_hours);
        handles.push(tokio::spawn(async move {
            jwks_refresh_loop(handle, jwks_interval).await;
        }));
    }

    handles
}

/// Pre-warm the cache on startup with configured cert chains.
pub async fn prefetch(cache: &Arc<CertCache>, chains: &[String]) {
    for gen in chains {
        let gen_name = match normalize_generation(gen) {
            Some(name) => name,
            None => {
                tracing::warn!(
                    gen = gen.as_str(),
                    "unknown processor generation, skipping prefetch"
                );
                continue;
            }
        };

        match cache.get_cert_chain(gen_name).await {
            Ok(_) => tracing::info!(gen = gen_name, "pre-warmed cert chain"),
            Err(e) => tracing::warn!(gen = gen_name, error = %e, "failed to pre-warm cert chain"),
        }
    }

    // Also prefetch CRLs
    revocation::refresh_crls(cache).await;
}

/// Pre-warm the JWKS cache for the NRAS endpoints.
pub async fn prefetch_jwks(handle: &JwksRefreshHandle) {
    for (url, result) in handle.prefetch().await {
        match result {
            Ok(()) => tracing::info!(%url, "pre-warmed NRAS JWKS"),
            Err(e) => tracing::warn!(%url, error = %e, "failed to pre-warm NRAS JWKS"),
        }
    }
}

/// Compute the cert chain refresh interval: half the TTL, with a 60-second floor.
pub(crate) fn chain_refresh_interval(chain_ttl_hours: u64) -> Duration {
    Duration::from_secs((chain_ttl_hours.saturating_mul(3600) / 2).max(60))
}

/// Compute the JWKS refresh interval: half the TTL, with a 60-second floor.
pub(crate) fn jwks_refresh_interval(jwks_ttl_hours: u64) -> Duration {
    Duration::from_secs((jwks_ttl_hours.saturating_mul(3600) / 2).max(60))
}

async fn cert_refresh_loop(cache: Arc<CertCache>, interval: Duration, generations: Vec<String>) {
    loop {
        sleep(interval).await;
        tracing::debug!("running periodic cert chain refresh");
        for gen in &generations {
            if let Err(e) = cache.get_cert_chain(gen).await {
                tracing::warn!(gen = gen.as_str(), error = %e, "periodic cert refresh failed");
            }
        }
    }
}

async fn crl_refresh_loop(cache: Arc<CertCache>, interval: Duration) {
    loop {
        sleep(interval).await;
        tracing::debug!("running periodic CRL refresh");
        revocation::refresh_crls(&cache).await;
    }
}

async fn jwks_refresh_loop(handle: JwksRefreshHandle, interval: Duration) {
    loop {
        sleep(interval).await;
        tracing::debug!("running periodic NRAS JWKS refresh");
        handle.refresh().await;
    }
}
