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
#[serde(deny_unknown_fields)]
pub struct VerifyRequest {
    /// Platform for the platform-specific evidence returned by /attest.
    pub platform: Option<String>,
    pub evidence: Value,
    #[serde(default)]
    pub params: VerifyParamsInput,
    #[serde(default)]
    pub issue_token: bool,
}

/// `deny_unknown_fields`: a typo in any `expected_*` field name would
/// otherwise be silently dropped, leaving the matching `*_match` result as
/// `None` while `signature_valid` stays `true`. Callers reading just the
/// signature flag would treat that as a successful pin when no comparison
/// actually ran — a silent policy bypass. Reject the request instead.
#[derive(Deserialize, Default)]
#[serde(deny_unknown_fields)]
pub struct VerifyParamsInput {
    pub expected_report_data: Option<String>,
    pub expected_init_data_hash: Option<String>,
    #[serde(default)]
    pub allow_debug: bool,
    pub min_tcb: Option<MinTcbInput>,
    /// Expected MRTD (base64-encoded, 48 bytes). TDX-only.
    pub expected_mrtd: Option<String>,
    /// Expected RTMR[0] (base64-encoded, 48 bytes). TDX-only.
    pub expected_rtmr0: Option<String>,
    /// Expected RTMR[1] (base64-encoded, 48 bytes). TDX-only.
    pub expected_rtmr1: Option<String>,
    /// Expected RTMR[2] (base64-encoded, 48 bytes). TDX-only.
    pub expected_rtmr2: Option<String>,
    /// Expected RTMR[3] (base64-encoded, 48 bytes). TDX-only.
    pub expected_rtmr3: Option<String>,
    /// Expected SNP launch digest (base64-encoded, 48 bytes). SNP-only.
    pub expected_launch_digest: Option<String>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MinTcbInput {
    pub bootloader: u8,
    pub tee: u8,
    pub snp: u8,
    pub microcode: u8,
}

#[derive(Serialize)]
pub struct VerifyResponse {
    pub result: attestation::VerificationResult,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub token: Option<String>,
}

pub async fn handler(
    State(state): State<AppState>,
    Json(req): Json<VerifyRequest>,
) -> Result<Json<VerifyResponse>, ApiError> {
    let evidence_json = build_evidence_envelope(req.platform, req.evidence)?;

    let expected_report_data = req
        .params
        .expected_report_data
        .map(|s| BASE64.decode(&s))
        .transpose()
        .map_err(|e| ApiError::BadRequest(format!("invalid base64 report_data: {e}")))?;

    let expected_init_data_hash = req
        .params
        .expected_init_data_hash
        .map(|s| BASE64.decode(&s))
        .transpose()
        .map_err(|e| ApiError::BadRequest(format!("invalid base64 init_data_hash: {e}")))?;

    let min_tcb = req.params.min_tcb.map(|t| attestation::SnpTcb {
        bootloader: t.bootloader,
        tee: t.tee,
        snp: t.snp,
        microcode: t.microcode,
        fmc: None,
    });

    let allow_debug = req.params.allow_debug;
    if allow_debug && !state.config.attestation.allow_debug {
        return Err(ApiError::BadRequest(
            "allow_debug is disabled by server configuration".to_string(),
        ));
    }

    let expected_mrtd = decode_digest_48("expected_mrtd", req.params.expected_mrtd)?;
    let expected_rtmr0 = decode_digest_48("expected_rtmr0", req.params.expected_rtmr0)?;
    let expected_rtmr1 = decode_digest_48("expected_rtmr1", req.params.expected_rtmr1)?;
    let expected_rtmr2 = decode_digest_48("expected_rtmr2", req.params.expected_rtmr2)?;
    let expected_rtmr3 = decode_digest_48("expected_rtmr3", req.params.expected_rtmr3)?;
    let expected_launch_digest =
        decode_digest_48("expected_launch_digest", req.params.expected_launch_digest)?;

    let params = attestation::VerifyParams {
        expected_report_data,
        expected_init_data_hash,
        allow_debug,
        min_tcb,
        expected_mrtd,
        expected_rtmr0,
        expected_rtmr1,
        expected_rtmr2,
        expected_rtmr3,
        expected_launch_digest,
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

/// Decode a base64 string into a 48-byte digest. Returns 400 on bad base64
/// or wrong length so the caller can't silently pin against a truncated
/// reference.
fn decode_digest_48(field: &str, value: Option<String>) -> Result<Option<[u8; 48]>, ApiError> {
    let Some(value) = value else {
        return Ok(None);
    };
    let bytes = BASE64
        .decode(&value)
        .map_err(|e| ApiError::BadRequest(format!("invalid base64 {field}: {e}")))?;
    let arr: [u8; 48] = bytes.as_slice().try_into().map_err(|_| {
        ApiError::BadRequest(format!(
            "{field} must decode to exactly 48 bytes, got {}",
            bytes.len()
        ))
    })?;
    Ok(Some(arr))
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
