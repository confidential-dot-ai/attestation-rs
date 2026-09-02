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

    /// Base64 48-byte SEV-SNP launch measurement (`report.measurement`) the
    /// evidence must carry. SNP evidence only.
    pub expected_launch_digest: Option<String>,
    /// Base64 48-byte TDX MRTD the evidence must carry. TDX evidence only.
    pub expected_mrtd: Option<String>,
    /// Base64 48-byte TDX RTMR[0..3] values the evidence must carry. TDX
    /// evidence only.
    pub expected_rtmr0: Option<String>,
    pub expected_rtmr1: Option<String>,
    pub expected_rtmr2: Option<String>,
    pub expected_rtmr3: Option<String>,
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
        expected_launch_digest: decode_digest(
            req.params.expected_launch_digest,
            "expected_launch_digest",
        )?,
        expected_mrtd: decode_digest(req.params.expected_mrtd, "expected_mrtd")?,
        expected_rtmr0: decode_digest(req.params.expected_rtmr0, "expected_rtmr0")?,
        expected_rtmr1: decode_digest(req.params.expected_rtmr1, "expected_rtmr1")?,
        expected_rtmr2: decode_digest(req.params.expected_rtmr2, "expected_rtmr2")?,
        expected_rtmr3: decode_digest(req.params.expected_rtmr3, "expected_rtmr3")?,
        // Map the HTTP GPU params into the grouped NvidiaGpuParams struct (the
        // library moved these out of flat VerifyParams). `..Default::default()`
        // fills the remaining GPU fields (allowed_bindings, device_policy) with
        // their secure defaults.
        nvidia_gpu: attestation::NvidiaGpuParams {
            user_nonce: nvidia_gpu_user_nonce,
            required: req.params.nvidia_gpu_required,
            expected_archs: req.params.nvidia_gpu_expected_archs,
            ..Default::default()
        },
    };

    let result = state.verifier.verify(&evidence_json, &params).await?;
    enforce_expected_measurements(&params, &result)?;

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

/// Decodes a base64 measurement parameter, which must be exactly 48 bytes.
fn decode_digest(value: Option<String>, name: &str) -> Result<Option<[u8; 48]>, ApiError> {
    let Some(value) = value else {
        return Ok(None);
    };
    let bytes = BASE64
        .decode(&value)
        .map_err(|e| ApiError::BadRequest(format!("invalid base64 {name}: {e}")))?;
    let digest: [u8; 48] = bytes.try_into().map_err(|b: Vec<u8>| {
        ApiError::BadRequest(format!("{name} must be 48 bytes, got {}", b.len()))
    })?;
    Ok(Some(digest))
}

/// Refuses a result that does not affirmatively satisfy every expected
/// measurement the caller supplied. The library records a mismatch as
/// `Some(false)` and an expectation the platform cannot answer (an RTMR pin
/// against SEV-SNP evidence, which has no RTMRs) as `None`; both are refusals
/// here, so a pin never reads as a pass on evidence that could not be checked
/// against it. Callers that supply no expectation are unaffected.
fn enforce_expected_measurements(
    params: &attestation::VerifyParams,
    result: &attestation::VerificationResult,
) -> Result<(), ApiError> {
    check_expected(
        "expected_launch_digest",
        params.expected_launch_digest.is_some(),
        result.launch_digest_match,
    )?;
    check_expected(
        "expected_mrtd",
        params.expected_mrtd.is_some(),
        result.mrtd_match,
    )?;
    check_expected(
        "expected_rtmr0",
        params.expected_rtmr0.is_some(),
        result.rtmr0_match,
    )?;
    check_expected(
        "expected_rtmr1",
        params.expected_rtmr1.is_some(),
        result.rtmr1_match,
    )?;
    check_expected(
        "expected_rtmr2",
        params.expected_rtmr2.is_some(),
        result.rtmr2_match,
    )?;
    check_expected(
        "expected_rtmr3",
        params.expected_rtmr3.is_some(),
        result.rtmr3_match,
    )
}

fn check_expected(name: &str, supplied: bool, matched: Option<bool>) -> Result<(), ApiError> {
    match (supplied, matched) {
        (false, _) | (true, Some(true)) => Ok(()),
        (true, Some(false)) => Err(ApiError::MeasurementMismatch(format!(
            "{name} does not match the verified evidence"
        ))),
        (true, None) => Err(ApiError::MeasurementMismatch(format!(
            "{name} cannot be checked: the verified evidence carries no such measurement"
        ))),
    }
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

    use super::{build_evidence_envelope, check_expected, decode_digest};
    use crate::error::ApiError;
    use base64::engine::general_purpose::STANDARD as BASE64;
    use base64::Engine;

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
    fn decode_digest_accepts_48_bytes_and_absent() {
        assert_eq!(decode_digest(None, "expected_mrtd").unwrap(), None);
        let digest = [0xabu8; 48];
        let got = decode_digest(Some(BASE64.encode(digest)), "expected_mrtd").unwrap();
        assert_eq!(got, Some(digest));
    }

    #[test]
    fn decode_digest_rejects_wrong_length_and_bad_base64() {
        let short = decode_digest(Some(BASE64.encode([0u8; 47])), "expected_rtmr1").unwrap_err();
        assert!(
            matches!(short, ApiError::BadRequest(m) if m.contains("expected_rtmr1 must be 48 bytes"))
        );
        let junk = decode_digest(Some("!!not-base64".to_string()), "expected_rtmr1").unwrap_err();
        assert!(
            matches!(junk, ApiError::BadRequest(m) if m.contains("invalid base64 expected_rtmr1"))
        );
    }

    #[test]
    fn check_expected_passes_only_an_affirmative_match() {
        assert!(check_expected("expected_rtmr0", false, None).is_ok());
        assert!(check_expected("expected_rtmr0", false, Some(false)).is_ok());
        assert!(check_expected("expected_rtmr0", true, Some(true)).is_ok());
        let mismatch = check_expected("expected_rtmr0", true, Some(false)).unwrap_err();
        assert!(
            matches!(mismatch, ApiError::MeasurementMismatch(m) if m.contains("does not match"))
        );
        // An RTMR pin against SEV-SNP evidence: the verifier reports no
        // verdict, and that must refuse rather than pass.
        let inapplicable = check_expected("expected_rtmr0", true, None).unwrap_err();
        assert!(
            matches!(inapplicable, ApiError::MeasurementMismatch(m) if m.contains("carries no such measurement"))
        );
    }

    #[test]
    fn is_attestation_envelope_detects_nested_envelope_shape() {
        assert!(super::is_attestation_envelope(&json!({
            "platform": "snp",
            "evidence": { "report": "abc" }
        })));
    }
}
