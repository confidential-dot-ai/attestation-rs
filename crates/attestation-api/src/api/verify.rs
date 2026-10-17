use axum::extract::rejection::JsonRejection;
use axum::extract::State;
use axum::Json;
use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::config::{normalize_platform, AttestationConfig};
use crate::error::ApiError;
use crate::token::issuer::PassedVerification;
use crate::AppState;

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct VerifyRequest {
    /// Platform for the platform-specific evidence returned by /attest.
    pub platform: Option<String>,
    pub evidence: Value,
    /// NVIDIA GPU evidence bundle, as returned by /attest with `nvidia_gpu: true`.
    /// When present, `policies.nvidia_gpu` must be set.
    #[serde(default)]
    pub nvidia_gpu: Option<Value>,
    /// The collateral /attest attached, `[{url, body, issuer_chain}]`.
    #[serde(default)]
    pub collateral: Option<Value>,
    /// Accepted platforms and their params. Evidence for a platform without an
    /// entry is refused. Issued tokens carry it as their `policy` claim.
    #[serde(default)]
    pub policies: attestation::Policies,
    #[serde(default)]
    pub issue_token: bool,
}

#[derive(Serialize)]
pub struct VerifyResponse {
    pub result: attestation::Verified,
    /// True when the evidence satisfied every rule in the policies.
    pub passed: bool,
    /// Issued only when requested and `passed` is true.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub token: Option<String>,
}

pub async fn handler(
    State(state): State<AppState>,
    payload: Result<Json<VerifyRequest>, JsonRejection>,
) -> Result<Json<VerifyResponse>, ApiError> {
    let Json(req) = payload?;
    let platform = canonical_platform(req.platform.as_deref())?;
    check_server_floors(&req.policies, &state.config.attestation)?;
    if req.issue_token
        && req
            .policies
            .report_data(platform)
            .is_none_or(<[u8]>::is_empty)
    {
        return Err(ApiError::BadRequest(format!(
            "issue_token requires a non-empty policies.{platform}.report_data"
        )));
    }
    let evidence_json = build_evidence_envelope(
        &platform.to_string(),
        req.evidence,
        req.nvidia_gpu,
        req.collateral,
    )?;

    let result = state.verifier.verify(&evidence_json, &req.policies).await?;
    let passed = PassedVerification::new(&result);

    let token = match &passed {
        Some(passed) if req.issue_token => {
            let issuer = state
                .token_issuer
                .as_ref()
                .ok_or(ApiError::TokenNotConfigured)?;
            Some(issuer.issue(passed, &req.policies)?)
        }
        _ => None,
    };
    let passed = passed.is_some();

    Ok(Json(VerifyResponse {
        result,
        passed,
        token,
    }))
}

/// Params below the server's floors are refused unless its config allows
/// them: `allow_debug`, a TCB status outside the default set, and `max_vmpl`
/// above 0. Collateral floors below the shipped ones and a GPU device policy
/// weaker than the default are always refused.
fn check_server_floors(
    policies: &attestation::Policies,
    config: &AttestationConfig,
) -> Result<(), ApiError> {
    let refuse = |what: &str| {
        Err(ApiError::BadRequest(format!(
            "{what} is disabled by server configuration"
        )))
    };
    let gpu = policies.gpu.as_ref().map(|p| &p.device_policy);
    let debug = policies.tdx_params().any(|p| p.allow_debug)
        || policies.snp_params().any(|p| p.allow_debug)
        || gpu.is_some_and(|p| p.allow_debug);
    if debug && !config.allow_debug {
        return refuse("allow_debug");
    }
    if !config.allow_revoked_or_unlisted_tcb {
        let valid = attestation::TdxParams::default().accepted_tcb_statuses;
        let mut statuses = policies.tdx_params().flat_map(|p| &p.accepted_tcb_statuses);
        if let Some(status) = statuses.find(|s| !valid.contains(s)) {
            return refuse(&format!("accepting TCB status {status}"));
        }
    }
    if !config.allow_nonzero_vmpl && policies.snp_params().any(|p| p.max_vmpl > 0) {
        return refuse("max_vmpl above 0");
    }
    if policies
        .floors
        .lowers(&attestation::collateral::VersionFloors::default())
    {
        return Err(ApiError::BadRequest(
            "floors may raise, not lower, the collateral versions accepted".to_string(),
        ));
    }
    if gpu.is_some_and(|p| !p.require_secboot || !p.require_measres_success) {
        return Err(ApiError::BadRequest(
            "nvidia_gpu.device_policy must require secboot and measres success".to_string(),
        ));
    }
    Ok(())
}

fn canonical_platform(platform: Option<&str>) -> Result<attestation::PlatformType, ApiError> {
    let platform = platform.ok_or_else(|| {
        ApiError::BadRequest("platform is required for evidence verification".to_string())
    })?;
    normalize_platform(platform)
        .and_then(|p| serde_json::from_value(p.into()).ok())
        .ok_or_else(|| ApiError::BadRequest(format!("unknown platform: {platform}")))
}

fn build_evidence_envelope(
    platform: &str,
    evidence: Value,
    nvidia_gpu: Option<Value>,
    collateral: Option<Value>,
) -> Result<Vec<u8>, ApiError> {
    if is_attestation_envelope(&evidence) {
        return Err(ApiError::BadRequest(
            "evidence must be platform-specific evidence; put platform at the top level"
                .to_string(),
        ));
    }

    let mut envelope = serde_json::json!({
        "platform": platform,
        "evidence": evidence,
    });
    if let Some(gpu) = nvidia_gpu {
        envelope["nvidia_gpu"] = gpu;
    }
    if let Some(collateral) = collateral {
        envelope["collateral"] = collateral;
    }

    serde_json::to_vec(&envelope)
        .map_err(|e| ApiError::BadRequest(format!("invalid evidence JSON: {e}")))
}

fn is_attestation_envelope(evidence: &Value) -> bool {
    evidence.get("platform").is_some() && evidence.get("evidence").is_some()
}

#[cfg(test)]
mod tests {
    use serde_json::{json, Value};

    use super::{build_evidence_envelope, canonical_platform};
    use crate::error::ApiError;

    #[test]
    fn build_evidence_envelope_wraps_split_form_with_canonical_platform() {
        let normalized: Value = serde_json::from_slice(
            &build_evidence_envelope(
                &canonical_platform(Some("SNP")).unwrap().to_string(),
                json!({ "report": "abc" }),
                None,
                None,
            )
            .unwrap(),
        )
        .expect("normalized evidence should be JSON");

        assert_eq!(normalized["platform"], "snp");
        assert_eq!(normalized["evidence"]["report"], "abc");
        assert!(normalized.get("nvidia_gpu").is_none());
    }

    #[test]
    fn build_evidence_envelope_includes_gpu_bundle_when_present() {
        let gpu = json!({ "devices": [], "binding": { "kind": "concat" } });
        let normalized: Value = serde_json::from_slice(
            &build_evidence_envelope("tdx", json!({ "quote": "abc" }), Some(gpu.clone()), None)
                .unwrap(),
        )
        .expect("normalized evidence should be JSON");

        assert_eq!(normalized["platform"], "tdx");
        assert_eq!(normalized["nvidia_gpu"], gpu);
    }

    #[test]
    fn build_evidence_envelope_rejects_full_envelope_evidence() {
        let err = build_evidence_envelope(
            "snp",
            json!({
                "platform": "snp",
                "evidence": { "report": "abc" }
            }),
            None,
            None,
        )
        .unwrap_err();

        assert!(matches!(err, ApiError::BadRequest(_)));
    }

    #[test]
    fn platform_is_required_and_must_be_known() {
        assert!(matches!(
            canonical_platform(None),
            Err(ApiError::BadRequest(_))
        ));
        assert!(matches!(
            canonical_platform(Some("not-a-platform")),
            Err(ApiError::BadRequest(_))
        ));
    }

    #[test]
    fn is_attestation_envelope_detects_nested_envelope_shape() {
        assert!(super::is_attestation_envelope(&json!({
            "platform": "snp",
            "evidence": { "report": "abc" }
        })));
    }
}
