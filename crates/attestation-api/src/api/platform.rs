use axum::Json;
use serde::Serialize;

use crate::error::ApiError;

#[derive(Serialize)]
pub struct PlatformResponse {
    pub platform: String,
}

pub async fn handler(
    axum::extract::State(_state): axum::extract::State<crate::AppState>,
) -> Result<Json<PlatformResponse>, ApiError> {
    #[cfg(target_os = "linux")]
    {
        let platform = super::detect_platform(_state.config.verify.selected_tdx.is_some())?;
        Ok(Json(PlatformResponse {
            platform: format!("{platform}"),
        }))
    }
    #[cfg(not(target_os = "linux"))]
    {
        Err(ApiError::NoPlatform)
    }
}
