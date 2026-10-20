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
    /// Pieces of collateral held.
    pub collateral: u64,
}

pub async fn handler(State(state): State<AppState>) -> Json<HealthResponse> {
    // Service discovery is memoized, so health checks do not re-open devices.
    let platform = {
        #[cfg(target_os = "linux")]
        {
            super::detect_platform().ok().map(|p| format!("{p}"))
        }
        #[cfg(not(target_os = "linux"))]
        {
            None
        }
    };

    let cache_stats = CacheStats {
        collateral: state.verifier.context().store().count(),
    };

    Json(HealthResponse {
        status: "ok",
        platform,
        cache: cache_stats,
        token_issuer: state.token_issuer.is_some(),
    })
}
