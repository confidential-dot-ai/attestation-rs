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
    /// Collateral documents held.
    pub documents: u64,
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

    let cache_stats = CacheStats {
        documents: state.verifier.context().store().count(),
    };

    Json(HealthResponse {
        status: "ok",
        platform,
        cache: cache_stats,
        token_issuer: state.token_issuer.is_some(),
    })
}
