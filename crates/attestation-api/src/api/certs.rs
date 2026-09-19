use axum::extract::State;
use axum::Json;

use crate::certs::{status, CertStatusResponse};
use crate::error::ApiError;
use crate::AppState;

pub async fn status_handler(State(state): State<AppState>) -> Json<CertStatusResponse> {
    Json(status(&state.cert_cache))
}

/// Refetch every held and pinned artifact. A failure keeps the previous copy;
/// the response reports every failure so an operator sees what is stale.
pub async fn refresh(State(state): State<AppState>) -> Result<Json<CertStatusResponse>, ApiError> {
    let report = state.cert_cache.refresh_all().await;
    if !report.failed.is_empty() {
        let mut lines: Vec<String> = report
            .failed
            .iter()
            .map(|(k, e)| format!("{k}: {e}"))
            .collect();
        lines.sort();
        return Err(ApiError::CertFetch(format!(
            "{} of {} collateral refresh(es) failed; the previous copies are still served: {}",
            report.failed.len(),
            report.attempted,
            lines.join("; ")
        )));
    }
    Ok(Json(status(&state.cert_cache)))
}
