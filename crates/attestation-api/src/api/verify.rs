use axum::extract::rejection::JsonRejection;
use axum::extract::State;
use axum::Json;
use base64::engine::general_purpose::STANDARD as BASE64;
use base64::Engine;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::BTreeMap;

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
    /// Accepted platforms and their params. Evidence for a platform without an
    /// entry is refused.
    #[serde(default)]
    pub policies: PoliciesInput,
    #[serde(default)]
    pub issue_token: bool,
}

/// Accepted platforms, keyed by platform name, each with its params. Byte
/// values are base64. A field that does not exist for a platform is refused.
/// Issued tokens carry it as their `policy` claim.
#[derive(Deserialize, Serialize, Default)]
#[serde(deny_unknown_fields)]
pub struct PoliciesInput {
    pub tdx: Option<TdxParamsInput>,
    pub snp: Option<SnpParamsInput>,
    #[serde(rename = "az-tdx")]
    pub az_tdx: Option<TdxParamsInput>,
    #[serde(rename = "az-snp")]
    pub az_snp: Option<SnpParamsInput>,
    #[serde(rename = "gcp-tdx")]
    pub gcp_tdx: Option<TdxParamsInput>,
    #[serde(rename = "gcp-snp")]
    pub gcp_snp: Option<SnpParamsInput>,
    pub nvidia_gpu: Option<GpuParamsInput>,
}

/// TDX params (also az-tdx, gcp-tdx). See `attestation::TdxParams`.
#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct TdxParamsInput {
    pub report_data: Option<String>,
    pub init_data: Option<String>,
    /// 48 bytes.
    pub mrtd: Option<String>,
    /// 48 bytes each.
    pub rtmr0: Option<String>,
    pub rtmr1: Option<String>,
    pub rtmr2: Option<String>,
    pub rtmr3: Option<String>,
    #[serde(default)]
    pub allow_debug: bool,
    /// A status outside the default (`Revoked`, `NoMatchingLevel`) is refused
    /// unless `attestation.allow_revoked_or_unlisted_tcb` is set.
    #[serde(default = "default_tcb_statuses")]
    pub accepted_tcb_statuses: Vec<attestation::TdxTcbStatus>,
    /// az-tdx only: expected vTPM PCRs by index, 32 bytes each.
    #[serde(default, deserialize_with = "unique_pcrs")]
    pub pcrs: Option<BTreeMap<u8, String>>,
}

fn default_tcb_statuses() -> Vec<attestation::TdxTcbStatus> {
    attestation::TdxParams::default().accepted_tcb_statuses
}

/// SEV-SNP params (also az-snp, gcp-snp). See `attestation::SnpParams`.
#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct SnpParamsInput {
    pub report_data: Option<String>,
    pub host_data: Option<String>,
    /// 48 bytes.
    pub launch_digest: Option<String>,
    #[serde(default)]
    pub allow_debug: bool,
    pub min_tcb: Option<attestation::SnpTcb>,
    /// Above 0 is refused unless `attestation.allow_nonzero_vmpl` is set.
    #[serde(default)]
    pub max_vmpl: u32,
    /// az-snp only: expected vTPM PCRs by index, 32 bytes each.
    #[serde(default, deserialize_with = "unique_pcrs")]
    pub pcrs: Option<BTreeMap<u8, String>>,
}

/// NVIDIA GPU params. See `attestation::NvidiaGpuParams`.
#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct GpuParamsInput {
    /// The user nonce that seeded the GPU SPDM nonce; must equal the platform
    /// `report_data`.
    pub user_nonce: Option<String>,
    /// Refuse evidence without a GPU bundle.
    #[serde(default)]
    pub required: bool,
    /// Acceptable GPU/switch architectures (`"HOPPER"`, `"BLACKWELL"`,
    /// `"LS10"`). If absent, all known archs are accepted.
    pub expected_archs: Option<Vec<attestation::NvidiaGpuArch>>,
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
    let policies = build_policies(&req.policies, &state.config.attestation)?;
    if req.issue_token && !req.policies.pins_report_data(platform) {
        return Err(ApiError::BadRequest(format!(
            "issue_token requires policies.{platform}.report_data"
        )));
    }
    let evidence_json = build_evidence_envelope(platform, req.evidence, req.nvidia_gpu)?;

    let result = state.verifier.verify(&evidence_json, &policies).await?;
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

impl PoliciesInput {
    fn pins_report_data(&self, platform: &str) -> bool {
        let tdx = |p: &Option<TdxParamsInput>| p.as_ref().is_some_and(|p| p.report_data.is_some());
        let snp = |p: &Option<SnpParamsInput>| p.as_ref().is_some_and(|p| p.report_data.is_some());
        match platform {
            "tdx" => tdx(&self.tdx),
            "az-tdx" => tdx(&self.az_tdx),
            "gcp-tdx" => tdx(&self.gcp_tdx),
            "snp" => snp(&self.snp),
            "az-snp" => snp(&self.az_snp),
            "gcp-snp" => snp(&self.gcp_snp),
            _ => false,
        }
    }
}

fn build_policies(
    input: &PoliciesInput,
    config: &AttestationConfig,
) -> Result<attestation::Policies, ApiError> {
    let tdx = |p: &Option<TdxParamsInput>| p.as_ref().map(|p| p.to_params(config)).transpose();
    let snp = |p: &Option<SnpParamsInput>| p.as_ref().map(|p| p.to_params(config)).transpose();
    // Which `Policies` fields exist depends on attestation's features.
    #[allow(clippy::needless_update)]
    let policies = attestation::Policies {
        tdx: without_pcrs(tdx(&input.tdx)?, "tdx")?,
        snp: without_pcrs(snp(&input.snp)?, "snp")?,
        az_tdx: tdx(&input.az_tdx)?.map(|(tdx, pcrs)| attestation::AzTdxParams { tdx, pcrs }),
        az_snp: snp(&input.az_snp)?.map(|(snp, pcrs)| attestation::AzSnpParams { snp, pcrs }),
        gcp_tdx: without_pcrs(tdx(&input.gcp_tdx)?, "gcp-tdx")?
            .map(|tdx| attestation::GcpTdxParams { tdx }),
        gcp_snp: without_pcrs(snp(&input.gcp_snp)?, "gcp-snp")?
            .map(|snp| attestation::GcpSnpParams { snp }),
        gpu: input
            .nvidia_gpu
            .as_ref()
            .map(GpuParamsInput::to_params)
            .transpose()?,
        ..Default::default()
    };
    Ok(policies)
}

type Pcrs = BTreeMap<u8, [u8; 32]>;

/// PCR pins exist only on the Azure vTPM platforms.
fn without_pcrs<T>(params: Option<(T, Pcrs)>, platform: &str) -> Result<Option<T>, ApiError> {
    match params {
        Some((_, pcrs)) if !pcrs.is_empty() => Err(ApiError::BadRequest(format!(
            "pcrs does not apply to {platform}"
        ))),
        other => Ok(other.map(|(params, _)| params)),
    }
}

fn decode_pcrs(pcrs: &Option<BTreeMap<u8, String>>) -> Result<Pcrs, ApiError> {
    pcrs.iter()
        .flatten()
        .map(|(&index, value)| {
            let name = format!("pcrs.{index}");
            let bytes = decode(&Some(value.clone()), &name)?.unwrap_or_default();
            let value: [u8; 32] = bytes.try_into().map_err(|b: Vec<u8>| {
                ApiError::BadRequest(format!("{name} must be 32 bytes, got {}", b.len()))
            })?;
            Ok((index, value))
        })
        .collect()
}

/// A JSON object of PCR pins. A repeated index is refused rather than
/// silently keeping the last value.
fn unique_pcrs<'de, D>(deserializer: D) -> Result<Option<BTreeMap<u8, String>>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    struct Pins;
    impl<'de> serde::de::Visitor<'de> for Pins {
        type Value = BTreeMap<u8, String>;
        fn expecting(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
            f.write_str("an object of PCR index to base64 value")
        }
        fn visit_map<A: serde::de::MapAccess<'de>>(
            self,
            mut map: A,
        ) -> Result<Self::Value, A::Error> {
            let mut pins = BTreeMap::new();
            while let Some((index, value)) = map.next_entry::<u8, String>()? {
                if pins.insert(index, value).is_some() {
                    return Err(serde::de::Error::custom(format!(
                        "PCR {index} is pinned more than once"
                    )));
                }
            }
            Ok(pins)
        }
    }
    deserializer.deserialize_map(Pins).map(Some)
}

fn check_allow_debug(requested: bool, config: &AttestationConfig) -> Result<(), ApiError> {
    if requested && !config.allow_debug {
        return Err(ApiError::BadRequest(
            "allow_debug is disabled by server configuration".to_string(),
        ));
    }
    Ok(())
}

impl TdxParamsInput {
    fn to_params(
        &self,
        config: &AttestationConfig,
    ) -> Result<(attestation::TdxParams, Pcrs), ApiError> {
        check_allow_debug(self.allow_debug, config)?;
        if !config.allow_revoked_or_unlisted_tcb {
            let valid = default_tcb_statuses();
            if let Some(status) = self
                .accepted_tcb_statuses
                .iter()
                .find(|s| !valid.contains(s))
            {
                return Err(ApiError::BadRequest(format!(
                    "accepting TCB status {status} is disabled by server configuration"
                )));
            }
        }
        let params = attestation::TdxParams {
            report_data: decode(&self.report_data, "report_data")?,
            init_data: decode(&self.init_data, "init_data")?,
            mrtd: decode_digest(&self.mrtd, "mrtd")?,
            rtmr: [
                decode_digest(&self.rtmr0, "rtmr0")?,
                decode_digest(&self.rtmr1, "rtmr1")?,
                decode_digest(&self.rtmr2, "rtmr2")?,
                decode_digest(&self.rtmr3, "rtmr3")?,
            ],
            allow_debug: self.allow_debug,
            accepted_tcb_statuses: self.accepted_tcb_statuses.clone(),
        };
        Ok((params, decode_pcrs(&self.pcrs)?))
    }
}

impl SnpParamsInput {
    fn to_params(
        &self,
        config: &AttestationConfig,
    ) -> Result<(attestation::SnpParams, Pcrs), ApiError> {
        check_allow_debug(self.allow_debug, config)?;
        if self.max_vmpl > 0 && !config.allow_nonzero_vmpl {
            return Err(ApiError::BadRequest(
                "max_vmpl above 0 is disabled by server configuration".to_string(),
            ));
        }
        let params = attestation::SnpParams {
            report_data: decode(&self.report_data, "report_data")?,
            host_data: decode(&self.host_data, "host_data")?,
            launch_digest: decode_digest(&self.launch_digest, "launch_digest")?,
            allow_debug: self.allow_debug,
            min_tcb: self.min_tcb,
            max_vmpl: self.max_vmpl,
        };
        Ok((params, decode_pcrs(&self.pcrs)?))
    }
}

impl GpuParamsInput {
    fn to_params(&self) -> Result<attestation::NvidiaGpuParams, ApiError> {
        Ok(attestation::NvidiaGpuParams {
            user_nonce: decode(&self.user_nonce, "nvidia_gpu.user_nonce")?,
            required: self.required,
            expected_archs: self.expected_archs.clone(),
            ..Default::default()
        })
    }
}

fn decode(value: &Option<String>, name: &str) -> Result<Option<Vec<u8>>, ApiError> {
    value
        .as_ref()
        .map(|v| BASE64.decode(v))
        .transpose()
        .map_err(|e| ApiError::BadRequest(format!("invalid base64 {name}: {e}")))
}

/// Decodes a base64 measurement parameter, which must be exactly 48 bytes.
fn decode_digest(value: &Option<String>, name: &str) -> Result<Option<[u8; 48]>, ApiError> {
    let Some(bytes) = decode(value, name)? else {
        return Ok(None);
    };
    let digest: [u8; 48] = bytes.try_into().map_err(|b: Vec<u8>| {
        ApiError::BadRequest(format!("{name} must be 48 bytes, got {}", b.len()))
    })?;
    Ok(Some(digest))
}

fn canonical_platform(platform: Option<&str>) -> Result<&'static str, ApiError> {
    let platform = platform.ok_or_else(|| {
        ApiError::BadRequest("platform is required for evidence verification".to_string())
    })?;
    normalize_platform(platform)
        .ok_or_else(|| ApiError::BadRequest(format!("unknown platform: {platform}")))
}

fn build_evidence_envelope(
    platform: &str,
    evidence: Value,
    nvidia_gpu: Option<Value>,
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

    serde_json::to_vec(&envelope)
        .map_err(|e| ApiError::BadRequest(format!("invalid evidence JSON: {e}")))
}

fn is_attestation_envelope(evidence: &Value) -> bool {
    evidence.get("platform").is_some() && evidence.get("evidence").is_some()
}

#[cfg(test)]
mod tests {
    use serde_json::{json, Value};

    use super::{
        build_evidence_envelope, build_policies, canonical_platform, decode_digest, PoliciesInput,
    };
    use crate::config::AttestationConfig;
    use crate::error::ApiError;
    use base64::engine::general_purpose::STANDARD as BASE64;
    use base64::Engine;

    #[test]
    fn build_evidence_envelope_wraps_split_form_with_canonical_platform() {
        let normalized: Value = serde_json::from_slice(
            &build_evidence_envelope(
                canonical_platform(Some("SNP")).unwrap(),
                json!({ "report": "abc" }),
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
            &build_evidence_envelope("tdx", json!({ "quote": "abc" }), Some(gpu.clone())).unwrap(),
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
    fn decode_digest_accepts_48_bytes_and_absent() {
        assert_eq!(decode_digest(&None, "mrtd").unwrap(), None);
        let digest = [0xabu8; 48];
        let got = decode_digest(&Some(BASE64.encode(digest)), "mrtd").unwrap();
        assert_eq!(got, Some(digest));
    }

    #[test]
    fn decode_digest_rejects_wrong_length_and_bad_base64() {
        let short = decode_digest(&Some(BASE64.encode([0u8; 47])), "rtmr1").unwrap_err();
        assert!(matches!(short, ApiError::BadRequest(_)));
        let junk = decode_digest(&Some("!!not-base64".to_string()), "rtmr1").unwrap_err();
        assert!(matches!(junk, ApiError::BadRequest(_)));
    }

    #[test]
    fn a_pcr_pinned_twice_is_refused() {
        let pin = BASE64.encode([0u8; 32]);
        let body = format!(r#"{{"az-snp":{{"pcrs":{{"4":"{pin}","4":"{pin}"}}}}}}"#);
        assert!(serde_json::from_str::<PoliciesInput>(&body).is_err());
    }

    #[test]
    fn a_pin_the_platform_does_not_have_is_refused() {
        let mrtd = BASE64.encode([0u8; 48]);
        assert!(
            serde_json::from_value::<PoliciesInput>(json!({ "tdx": { "mrtd": mrtd } })).is_ok()
        );
        assert!(
            serde_json::from_value::<PoliciesInput>(json!({ "snp": { "mrtd": mrtd } })).is_err()
        );

        let policies = |v: Value| serde_json::from_value::<PoliciesInput>(v).unwrap();
        let config = AttestationConfig::default();
        let pcrs = json!({ "4": BASE64.encode([0u8; 32]) });
        assert!(build_policies(&policies(json!({ "az-tdx": { "pcrs": pcrs } })), &config).is_ok());
        let err =
            build_policies(&policies(json!({ "tdx": { "pcrs": pcrs } })), &config).unwrap_err();
        assert!(matches!(err, ApiError::BadRequest(_)));
    }

    #[test]
    fn is_attestation_envelope_detects_nested_envelope_shape() {
        assert!(super::is_attestation_envelope(&json!({
            "platform": "snp",
            "evidence": { "report": "abc" }
        })));
    }
}
