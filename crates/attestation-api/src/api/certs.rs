use axum::extract::State;
use axum::Json;
use serde::Serialize;

use attestation::collateral::{DocKey, Provenance, Store};

use crate::error::ApiError;
use crate::AppState;

#[derive(Serialize)]
pub struct CertStatusResponse {
    /// The shared documents held (CRLs, TCB Info, QE Identity, NRAS keys),
    /// each with its source, window and version.
    pub documents: Vec<Provenance>,
    /// How many per-machine documents are held; not which machines.
    pub amd_vceks: usize,
    pub gce_endorsements: usize,
}

impl CertStatusResponse {
    fn of(store: &Store) -> Self {
        let (per_machine, documents): (Vec<_>, Vec<_>) = store
            .documents()
            .into_iter()
            .partition(|p| p.document.per_machine());
        let amd_vceks = per_machine
            .iter()
            .filter(|p| matches!(p.document, DocKey::AmdVcek(_)))
            .count();
        Self {
            documents,
            amd_vceks,
            gce_endorsements: per_machine.len() - amd_vceks,
        }
    }
}

pub async fn status(State(state): State<AppState>) -> Json<CertStatusResponse> {
    Json(CertStatusResponse::of(state.verifier.context().store()))
}

/// Refetch the shared documents held, each at most once every few minutes.
/// A document is replaced only by a valid copy that is not older; one whose
/// refetch fails keeps its current copy.
pub async fn refresh(State(state): State<AppState>) -> Result<Json<CertStatusResponse>, ApiError> {
    let ctx = state.verifier.context();
    let failures = ctx.store().refresh_all(ctx.now()).await;
    if !failures.is_empty() {
        let failures: Vec<String> = failures.iter().map(ToString::to_string).collect();
        return Err(ApiError::RefreshFailed(failures.join("; ")));
    }
    Ok(Json(CertStatusResponse::of(ctx.store())))
}
