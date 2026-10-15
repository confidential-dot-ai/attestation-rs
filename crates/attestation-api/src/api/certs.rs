use axum::extract::State;
use axum::Json;
use serde::Serialize;

use attestation::collateral::Store;
use attestation::CollateralUsed;

use crate::error::ApiError;
use crate::AppState;

#[derive(Serialize)]
pub struct CertStatusResponse {
    /// The shared collateral held (CRLs, TCB Info, QE Identity, NRAS keys),
    /// each with its source, version and nextUpdate.
    pub collateral: Vec<CollateralUsed>,
    /// How many per-machine pieces are held; not which machines.
    pub amd_vceks: usize,
    pub gce_endorsements: usize,
}

impl CertStatusResponse {
    fn of(store: &Store, now: i64) -> Self {
        let mut held = store.collateral(now);
        let count = |held: &[CollateralUsed], kind: &str| {
            held.iter().filter(|c| c.name.starts_with(kind)).count()
        };
        let (amd_vceks, gce_endorsements) =
            (count(&held, "vcek "), count(&held, "gce-endorsement "));
        held.retain(|c| !c.name.starts_with("vcek ") && !c.name.starts_with("gce-endorsement "));
        held.sort_by(|a, b| a.name.cmp(&b.name));
        Self {
            collateral: held,
            amd_vceks,
            gce_endorsements,
        }
    }
}

pub async fn status(State(state): State<AppState>) -> Json<CertStatusResponse> {
    let ctx = state.verifier.context();
    Json(CertStatusResponse::of(ctx.store(), ctx.now()))
}

/// Refetch the shared collateral held, each piece at most once every few
/// minutes. A piece is replaced only by a valid copy that is not older; one
/// whose refetch fails keeps its current copy.
pub async fn refresh(State(state): State<AppState>) -> Result<Json<CertStatusResponse>, ApiError> {
    let ctx = state.verifier.context();
    let failures = ctx.store().refresh_all(ctx.now()).await;
    if !failures.is_empty() {
        let failures: Vec<String> = failures.iter().map(ToString::to_string).collect();
        return Err(ApiError::RefreshFailed(failures.join("; ")));
    }
    Ok(Json(CertStatusResponse::of(ctx.store(), ctx.now())))
}
