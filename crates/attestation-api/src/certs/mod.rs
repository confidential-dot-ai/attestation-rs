//! The service's collateral: one library cache built from `[certs]`, pinned
//! and refreshed. The library owns fetching, caching, validity and backoff;
//! this module only maps configuration and renders status.

use std::sync::Arc;
use std::time::Duration;

use attestation::collateral::{
    CachePolicy, CacheStatus, CollateralCache, CollateralKey, CollateralKind, DiskStore, Endpoints,
};
use attestation::{HttpTimeouts, ProcessorGeneration};
use serde::Serialize;

use crate::config::{
    normalize_generation, resolve_nras_gpu_url, resolve_nras_switch_url, CertsConfig,
};

/// Convert hours to a `Duration` with overflow protection and a 60-second floor.
pub(crate) fn hours_to_duration(hours: u64) -> Duration {
    Duration::from_secs(hours.saturating_mul(3600).max(60))
}

/// The generations named in `prefetch_chains`, as the library types them.
pub fn configured_generations(config: &CertsConfig) -> Vec<ProcessorGeneration> {
    config
        .prefetch_chains
        .iter()
        .filter_map(|g| match normalize_generation(g) {
            Some("Milan") => Some(ProcessorGeneration::Milan),
            Some("Genoa") => Some(ProcessorGeneration::Genoa),
            Some("Turin") => Some(ProcessorGeneration::Turin),
            _ => {
                tracing::warn!(gen = g.as_str(), "unknown processor generation, skipping");
                None
            }
        })
        .collect()
}

/// The cache policy `[certs]` describes. TTLs become max ages (refresh
/// triggers); serving is bounded by each artifact's own validity window.
pub fn policy(config: &CertsConfig) -> CachePolicy {
    CachePolicy {
        max_entries: usize::try_from(config.cache_max_entries)
            .unwrap_or(usize::MAX)
            .max(64),
        max_age_vcek: hours_to_duration(config.vcek_ttl_hours),
        max_age_chain: hours_to_duration(config.chain_ttl_hours),
        max_age_crl: hours_to_duration(config.crl_refresh_hours),
        max_age_tdx: hours_to_duration(config.tdx_collateral_ttl_hours),
        max_age_jwks: hours_to_duration(config.jwks_ttl_hours),
        // Under require_crl a suppressed retry refuses verification, so
        // fail-closed deployments always dial.
        backoff_base: Duration::from_secs(if config.require_crl {
            0
        } else {
            config.crl_backoff_base_secs
        }),
        backoff_max: Duration::from_secs(config.crl_backoff_max_secs),
        snp_crl_required: config.require_crl,
    }
}

/// Build the cache, pin the configured chains, CRLs and NRAS key sets.
pub fn build(config: &CertsConfig) -> anyhow::Result<Arc<CollateralCache>> {
    let store = config
        .local_collateral_dir
        .as_ref()
        .filter(|d| !d.is_empty())
        .map(DiskStore::new);
    let gpu_url = resolve_nras_gpu_url(config);
    let switch_url = resolve_nras_switch_url(config);
    let cache = CollateralCache::new(
        policy(config),
        &HttpTimeouts::default(),
        Endpoints::default(),
        store,
    )
    .with_nras_urls(gpu_url.clone(), switch_url.clone());
    for generation in configured_generations(config) {
        cache.pin(CollateralKey::SnpCertChain { generation });
        cache.pin(CollateralKey::SnpCrl { generation });
    }
    cache.pin(CollateralKey::TdxRootCrl);
    if config.prefetch_nras_jwks {
        for url in [&gpu_url, &switch_url] {
            let jwks = attestation::platforms::nvidia_gpu::jwks_url_for_endpoint(url)?;
            cache.pin(CollateralKey::NrasJwks { url: jwks });
        }
    }
    tracing::info!(gpu = %gpu_url, switch = %switch_url, "configured NRAS endpoints");
    Ok(Arc::new(cache))
}

/// Fetch every pinned artifact before serving; failures are logged, the
/// request path fetches on demand.
pub async fn prefetch(cache: &Arc<CollateralCache>) {
    let report = cache.refresh_due().await;
    for (key, e) in &report.failed {
        tracing::warn!(%key, error = %e, "failed to pre-warm collateral");
    }
    tracing::info!(
        attempted = report.attempted,
        failed = report.failed.len(),
        "collateral pre-warmed"
    );
}

/// Refresh interval: half the shortest max age, floored at one minute.
pub fn refresh_interval(config: &CertsConfig) -> Duration {
    let shortest = [
        config.vcek_ttl_hours,
        config.chain_ttl_hours,
        config.crl_refresh_hours,
        config.tdx_collateral_ttl_hours,
        config.jwks_ttl_hours,
    ]
    .into_iter()
    .min()
    .unwrap_or(1);
    Duration::from_secs((shortest.saturating_mul(3600) / 2).max(60))
}

/// What `/certs/status` returns. The first four fields are the previous
/// response shape; `cache` is the full picture.
#[derive(Serialize)]
pub struct CertStatusResponse {
    pub snp_chains_cached: Vec<String>,
    pub vcek_count: usize,
    pub tdx_collateral_count: usize,
    pub crl_status: serde_json::Value,
    pub cache: CacheStatus,
}

pub fn status(cache: &CollateralCache) -> CertStatusResponse {
    let status = cache.status();
    let snp_chains_cached = status
        .entries
        .iter()
        .filter(|e| e.kind == CollateralKind::SnpCertChain)
        .filter_map(|e| e.key.rsplit('/').next().map(str::to_string))
        .collect();
    let crl_status = status
        .entries
        .iter()
        .filter(|e| {
            matches!(
                e.kind,
                CollateralKind::SnpCrl | CollateralKind::TdxPckCrl | CollateralKind::TdxRootCrl
            )
        })
        .map(|e| {
            (
                e.key.clone(),
                serde_json::json!({
                    "last_fetched": e.fetched_at.to_rfc3339(),
                    "valid_until": e.valid_until.map(|t| t.to_rfc3339()),
                    "expires_at": e.expires_at.to_rfc3339(),
                    "stale": e.stale,
                }),
            )
        })
        .collect::<serde_json::Map<_, _>>();
    CertStatusResponse {
        snp_chains_cached,
        vcek_count: cache.count(CollateralKind::SnpVcek),
        tdx_collateral_count: cache.count(CollateralKind::TdxTcbInfo)
            + cache.count(CollateralKind::TdxQeIdentity)
            + cache.count(CollateralKind::TdxPckCrl)
            + cache.count(CollateralKind::TdxRootCrl),
        crl_status: serde_json::Value::Object(crl_status),
        cache: status,
    }
}
