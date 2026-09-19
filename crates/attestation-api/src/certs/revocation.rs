use std::sync::Arc;

use attestation::ProcessorGeneration;

use crate::certs::cache::CertCache;

/// CRL endpoints for AMD (using library URL constants via snp_crl_url).
fn amd_crl_urls() -> Vec<(&'static str, String)> {
    vec![
        (
            "snp_milan",
            attestation::snp_crl_url(ProcessorGeneration::Milan),
        ),
        (
            "snp_genoa",
            attestation::snp_crl_url(ProcessorGeneration::Genoa),
        ),
        (
            "snp_turin",
            attestation::snp_crl_url(ProcessorGeneration::Turin),
        ),
    ]
}

const INTEL_CRL_URLS: &[(&str, &str)] = &[("tdx_root_ca", attestation::INTEL_ROOT_CA_CRL_URL)];

/// Refetch every known CRL, replacing each cached copy on success and
/// keeping it on failure.
pub async fn refresh_crls(cache: &Arc<CertCache>) {
    let amd_urls = amd_crl_urls();
    for (issuer, url) in &amd_urls {
        match cache.refresh_crl(issuer, url).await {
            Ok(entry) => {
                tracing::info!(
                    issuer,
                    fetched = %entry.last_fetched,
                    "CRL refreshed"
                );
            }
            Err(e) => {
                tracing::warn!(issuer, %url, error = %e, "failed to fetch CRL");
            }
        }
    }
    for (issuer, url) in INTEL_CRL_URLS {
        match cache.refresh_crl(issuer, url).await {
            Ok(entry) => {
                tracing::info!(
                    issuer,
                    fetched = %entry.last_fetched,
                    "CRL refreshed"
                );
            }
            Err(e) => {
                tracing::warn!(issuer, %url, error = %e, "failed to fetch CRL");
            }
        }
    }
}
