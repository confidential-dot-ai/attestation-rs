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
    /// NVIDIA GPU evidence bundle, as returned by /attest with `nvidia_gpu: true`.
    /// When present, the verifier will check it against NRAS — `params.nvidia_gpu_user_nonce`
    /// must also be set.
    #[serde(default)]
    pub nvidia_gpu: Option<Value>,
    #[serde(default)]
    pub params: VerifyParamsInput,
    #[serde(default)]
    pub issue_token: bool,
}

#[derive(Deserialize, Default)]
pub struct VerifyParamsInput {
    pub expected_report_data: Option<String>,
    pub expected_init_data_hash: Option<String>,
    #[serde(default)]
    pub allow_debug: bool,
    pub min_tcb: Option<MinTcbInput>,

    /// Base64-encoded user nonce that seeded the GPU SPDM nonce derivation.
    /// Required when verifying an envelope that carries a `nvidia_gpu`
    /// bundle; ignored otherwise.
    pub nvidia_gpu_user_nonce: Option<String>,
    /// If true, fail verification when the envelope has no GPU bundle.
    #[serde(default)]
    pub nvidia_gpu_required: bool,
    /// Optional whitelist of acceptable GPU/switch architectures
    /// (`"HOPPER"`, `"BLACKWELL"`, `"LS10"`). If absent, all known archs
    /// are accepted.
    pub nvidia_gpu_expected_archs: Option<Vec<attestation::NvidiaGpuArch>>,
}

#[derive(Deserialize)]
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
    let evidence_json = build_evidence_envelope(req.platform, req.evidence, req.nvidia_gpu)?;

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

    let nvidia_gpu_user_nonce = req
        .params
        .nvidia_gpu_user_nonce
        .map(|s| BASE64.decode(&s))
        .transpose()
        .map_err(|e| ApiError::BadRequest(format!("invalid base64 nvidia_gpu_user_nonce: {e}")))?;

    let params = attestation::VerifyParams {
        expected_report_data,
        expected_init_data_hash,
        allow_debug,
        min_tcb,
        // Map the HTTP GPU params into the grouped NvidiaGpuParams struct (the
        // library moved these out of flat VerifyParams). `..Default::default()`
        // fills the remaining GPU fields (allowed_bindings, device_policy) with
        // their secure defaults and main's expected_mrtd/rtmr/launch fields.
        nvidia_gpu: attestation::NvidiaGpuParams {
            user_nonce: nvidia_gpu_user_nonce,
            required: req.params.nvidia_gpu_required,
            expected_archs: req.params.nvidia_gpu_expected_archs,
            ..Default::default()
        },
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

fn build_evidence_envelope(
    platform: Option<String>,
    evidence: Value,
    nvidia_gpu: Option<Value>,
) -> Result<Vec<u8>, ApiError> {
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

    let mut envelope = serde_json::json!({
        "platform": platform,
        "evidence": evidence,
    });
    if let Some(gpu) = nvidia_gpu {
        envelope["nvidia_gpu"] = gpu;
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

    use super::build_evidence_envelope;

    #[test]
    fn build_evidence_envelope_wraps_split_form_with_canonical_platform() {
        let normalized: Value = serde_json::from_slice(
            &build_evidence_envelope(Some("SNP".to_string()), json!({ "report": "abc" }), None)
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
            &build_evidence_envelope(
                Some("tdx".to_string()),
                json!({ "quote": "abc" }),
                Some(gpu.clone()),
            )
            .unwrap(),
        )
        .expect("normalized evidence should be JSON");

        assert_eq!(normalized["platform"], "tdx");
        assert_eq!(normalized["nvidia_gpu"], gpu);
    }

    #[test]
    fn build_evidence_envelope_rejects_full_envelope_evidence() {
        let err = build_evidence_envelope(
            Some("snp".to_string()),
            json!({
                "platform": "snp",
                "evidence": { "report": "abc" }
            }),
            None,
        )
        .unwrap_err();

        assert!(err.to_string().contains("platform-specific evidence"));
    }

    #[test]
    fn build_evidence_envelope_requires_platform() {
        let err = build_evidence_envelope(None, json!({ "report": "abc" }), None).unwrap_err();

        assert!(err.to_string().contains("platform is required"));
    }

    #[test]
    fn build_evidence_envelope_rejects_unknown_platform() {
        let err = build_evidence_envelope(
            Some("not-a-platform".to_string()),
            json!({ "report": "abc" }),
            None,
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
