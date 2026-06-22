use axum::extract::State;
use axum::Json;
use base64::engine::general_purpose::STANDARD as BASE64;
use base64::Engine;
use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::config::normalize_platform;
use crate::error::ApiError;
use crate::AppState;

#[derive(Deserialize)]
pub struct VerifyRequest {
    /// Platform for the platform-specific evidence returned by /attest.
    pub platform: Option<String>,
    pub evidence: Value,
    #[serde(default)]
    pub params: VerifyParamsInput,
    #[serde(default)]
    pub issue_token: bool,
}

#[derive(Deserialize, Default)]
pub struct VerifyParamsInput {
    /// Expected nonce (base64). Compared against the freshness anchor for
    /// the vendor (report_data for bare-metal, TPM extraData for Azure
    /// overlays).
    pub nonce: Option<String>,
    /// Expected report_data (base64). Compared against the inner TEE
    /// quote's report_data field.
    pub report_data: Option<String>,
    /// Expected canonical launch measurement (base64, 48 bytes).
    pub launch_measurement: Option<String>,
    #[serde(default)]
    pub allow_debug: bool,
}

#[derive(Serialize)]
pub struct VerifyResponse {
    pub result: attestation::VerifyResult,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub token: Option<String>,
}

pub async fn handler(
    State(state): State<AppState>,
    Json(req): Json<VerifyRequest>,
) -> Result<Json<VerifyResponse>, ApiError> {
    let evidence_json = build_evidence_envelope(req.platform, req.evidence)?;

    let nonce = req
        .params
        .nonce
        .map(|s| BASE64.decode(&s))
        .transpose()
        .map_err(|e| ApiError::BadRequest(format!("invalid base64 nonce: {e}")))?;

    let report_data = req
        .params
        .report_data
        .map(|s| BASE64.decode(&s))
        .transpose()
        .map_err(|e| ApiError::BadRequest(format!("invalid base64 report_data: {e}")))?;

    let launch_measurement = req
        .params
        .launch_measurement
        .map(|s| BASE64.decode(&s))
        .transpose()
        .map_err(|e| ApiError::BadRequest(format!("invalid base64 launch_measurement: {e}")))?;

    let allow_debug = req.params.allow_debug;
    if allow_debug && !state.config.attestation.allow_debug {
        return Err(ApiError::BadRequest(
            "allow_debug is disabled by server configuration".to_string(),
        ));
    }

    // DEVIATION: The HTTP API exposes only the canonical anchors. Vendor-precise
    // pinning (MRTD, individual RTMRs, mr_config_id, min_tcb, AK thumbprint, ...)
    // is library-only. Surfacing those needs a per-endpoint policy story about
    // whether the server owns the reference values (e.g. fetched from a manifest
    // registry) or the client supplies them; until that design is settled the
    // safe default is "no comparison" — `vendor` defaults to `Auto` and the
    // response's vendor_policy_failed will be `false`.
    let params = attestation::VerifyParams {
        nonce,
        report_data,
        launch_measurement,
        allow_debug,
        ..Default::default()
    };

    let result = state.verifier.verify(&evidence_json, &params).await?;

    let token = if req.issue_token {
        let issuer = state
            .token_issuer
            .as_ref()
            .ok_or(ApiError::TokenNotConfigured)?;
        Some(issuer.issue(&result)?)
    } else {
        None
    };

    Ok(Json(VerifyResponse { result, token }))
}

fn build_evidence_envelope(platform: Option<String>, evidence: Value) -> Result<Vec<u8>, ApiError> {
    let Some(platform) = platform else {
        return Err(ApiError::BadRequest(
            "platform is required for evidence verification".to_string(),
        ));
    };

    if is_attestation_envelope(&evidence) {
        return Err(ApiError::BadRequest(
            "evidence must be platform-specific evidence; put platform at the top level"
                .to_string(),
        ));
    }

    let platform = normalize_platform(&platform)
        .ok_or_else(|| ApiError::BadRequest(format!("unknown platform: {platform}")))?;

    let envelope = serde_json::json!({
        "platform": platform,
        "evidence": evidence,
    });

    serde_json::to_vec(&envelope)
        .map_err(|e| ApiError::BadRequest(format!("invalid evidence JSON: {e}")))
}

fn is_attestation_envelope(evidence: &Value) -> bool {
    evidence.get("platform").is_some() && evidence.get("evidence").is_some()
}

#[cfg(test)]
mod tests {
    use serde_json::{json, Value};

    use super::build_evidence_envelope;

    #[test]
    fn build_evidence_envelope_wraps_split_form_with_canonical_platform() {
        let normalized: Value = serde_json::from_slice(
            &build_evidence_envelope(Some("SNP".to_string()), json!({ "report": "abc" })).unwrap(),
        )
        .expect("normalized evidence should be JSON");

        assert_eq!(normalized["platform"], "snp");
        assert_eq!(normalized["evidence"]["report"], "abc");
    }

    #[test]
    fn build_evidence_envelope_rejects_full_envelope_evidence() {
        let err = build_evidence_envelope(
            Some("snp".to_string()),
            json!({
                "platform": "snp",
                "evidence": { "report": "abc" }
            }),
        )
        .unwrap_err();

        assert!(err.to_string().contains("platform-specific evidence"));
    }

    #[test]
    fn build_evidence_envelope_requires_platform() {
        let err = build_evidence_envelope(None, json!({ "report": "abc" })).unwrap_err();

        assert!(err.to_string().contains("platform is required"));
    }

    #[test]
    fn build_evidence_envelope_rejects_unknown_platform() {
        let err = build_evidence_envelope(
            Some("not-a-platform".to_string()),
            json!({ "report": "abc" }),
        )
        .unwrap_err();

        assert!(err.to_string().contains("unknown platform"));
    }

    #[test]
    fn is_attestation_envelope_detects_nested_envelope_shape() {
        assert!(super::is_attestation_envelope(&json!({
            "platform": "snp",
            "evidence": { "report": "abc" }
        })));
    }
}
