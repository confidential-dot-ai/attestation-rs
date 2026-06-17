use axum::extract::State;
use axum::Json;
use serde::Serialize;

use crate::AppState;

#[derive(Serialize)]
pub struct HealthResponse {
    pub status: &'static str,
    pub platform: Option<String>,
    pub cache: CacheStats,
    pub token_issuer: bool,
}

#[derive(Serialize)]
pub struct CacheStats {
    pub vcek_entries: u64,
    pub chain_entries: u64,
    pub last_crl_refresh: Option<String>,
}

pub async fn handler(State(state): State<AppState>) -> Json<HealthResponse> {
    // attestation::detect() memoizes the hardware probe, so calling it per
    // request here does not re-open the vTPM context.
    let platform = {
        #[cfg(target_os = "linux")]
        {
            attestation::detect().ok().map(|p| format!("{p}"))
        }
        #[cfg(not(target_os = "linux"))]
        {
            None
        }
    };

    let cache = &state.cert_cache;
    let cache_stats = CacheStats {
        vcek_entries: cache.vcek_entry_count(),
        chain_entries: cache.chain_entry_count(),
        last_crl_refresh: cache.last_crl_refresh().await.map(|t| t.to_rfc3339()),
    };

    Json(HealthResponse {
        status: "ok",
        platform,
        cache: cache_stats,
        token_issuer: state.token_issuer.is_some(),
    })
}
