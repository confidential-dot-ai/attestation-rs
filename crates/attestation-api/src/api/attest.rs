use axum::extract::State;
use axum::Json;
#[cfg(target_os = "linux")]
use base64::engine::general_purpose::STANDARD as BASE64;
#[cfg(target_os = "linux")]
use base64::Engine;
use serde::{Deserialize, Serialize};
use serde_json::Value;

#[cfg(target_os = "linux")]
use crate::config::normalize_platform;
use crate::error::ApiError;
use crate::AppState;

#[derive(Deserialize)]
pub struct AttestRequest {
    pub report_data: Option<String>,
    #[serde(default = "default_platform")]
    pub platform: String,
    /// If true, also collect NVIDIA GPU evidence. Requires the service to
    /// be built with the `nvidia-gpu-attest` cargo feature.
    #[serde(default)]
    pub nvidia_gpu: bool,
    /// `"cvm-v1"` (the profile envelope) or `"legacy"`. Absent: the profile
    /// when `nonce` is given, otherwise the legacy envelope, so a client that
    /// predates the profile keeps its response shape for one release.
    #[serde(default)]
    pub format: Option<String>,
    /// The relying party's nonce, base64url without padding, 16 to 64 bytes
    /// (profile only).
    #[serde(default)]
    pub nonce: Option<String>,
    /// Optional key binding (profile section 5.5).
    #[serde(default)]
    pub key: Option<attestation::profile::KeyBinding>,
}

#[derive(Debug, PartialEq, Eq)]
enum AttestMode {
    Profile,
    Legacy,
}

fn attest_mode(format: Option<&str>, has_nonce: bool) -> Result<AttestMode, ApiError> {
    match format {
        Some("cvm-v1") => Ok(AttestMode::Profile),
        Some("legacy") => Ok(AttestMode::Legacy),
        Some(other) => Err(ApiError::BadRequest(format!(
            "unknown format {other:?}; want cvm-v1 or legacy"
        ))),
        None if has_nonce => Ok(AttestMode::Profile),
        None => Ok(AttestMode::Legacy),
    }
}

fn default_platform() -> String {
    "auto".to_string()
}

#[derive(Serialize)]
pub struct AttestResponse {
    pub platform: String,
    pub evidence: Value,
    /// Present when the request set `nvidia_gpu: true` and GPU evidence
    /// collection succeeded. Round-trips through `/verify` unchanged.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub nvidia_gpu: Option<Value>,
}

/// The profile envelope (section 4.1) as the body, or the legacy split form
/// `{platform, evidence, nvidia_gpu?}`.
pub async fn handler(
    State(state): State<AppState>,
    Json(req): Json<AttestRequest>,
) -> Result<Json<Value>, ApiError> {
    if !state.config.attestation.enabled {
        return Err(ApiError::AttestNotAvailable);
    }
    let mode = attest_mode(req.format.as_deref(), req.nonce.is_some())?;

    #[cfg(target_os = "linux")]
    {
        let platform = resolve_platform(&req.platform)?;
        ensure_platform_allowed(&state.config.attestation.platforms, platform)?;
        let options = state.config.attestation.attest_options();

        if mode == AttestMode::Profile {
            let nonce = req.nonce.as_deref().ok_or_else(|| {
                ApiError::BadRequest(
                    "the profile needs a nonce: 16 to 64 bytes, base64url".to_string(),
                )
            })?;
            if req.report_data.is_some() {
                return Err(ApiError::BadRequest(
                    "report_data does not apply to the profile; the nonce is the binding input"
                        .to_string(),
                ));
            }
            let nonce = base64::engine::general_purpose::URL_SAFE_NO_PAD
                .decode(nonce)
                .map_err(|e| ApiError::BadRequest(format!("invalid base64url nonce: {e}")))?;
            if req.nvidia_gpu && !cfg!(feature = "nvidia-gpu-attest") {
                return Err(ApiError::BadRequest(
                    "nvidia_gpu=true requires this service to be built with the \
                     `nvidia-gpu-attest` cargo feature"
                        .to_string(),
                ));
            }
            let bytes =
                attestation::attest_profile(platform, &nonce, req.key, req.nvidia_gpu, &options)
                    .await?;
            let envelope: Value = serde_json::from_slice(&bytes)
                .map_err(|e| ApiError::Internal(format!("failed to parse evidence: {e}")))?;
            return Ok(Json(envelope));
        }

        let report_data = match req.report_data {
            Some(b64) => BASE64
                .decode(&b64)
                .map_err(|e| ApiError::BadRequest(format!("invalid base64 report_data: {e}")))?,
            None => Vec::new(),
        };

        let evidence_bytes = if req.nvidia_gpu {
            #[cfg(feature = "nvidia-gpu-attest")]
            {
                attestation::attest_with_nvidia_gpu(platform, &report_data, &options).await?
            }
            #[cfg(not(feature = "nvidia-gpu-attest"))]
            {
                return Err(ApiError::BadRequest(
                    "nvidia_gpu=true requires this service to be built with the \
                     `nvidia-gpu-attest` cargo feature"
                        .to_string(),
                ));
            }
        } else {
            attestation::attest(platform, &report_data, &options).await?
        };

        let mut envelope: Value = serde_json::from_slice(&evidence_bytes)
            .map_err(|e| ApiError::Internal(format!("failed to parse evidence: {e}")))?;

        let gpu_field = envelope
            .as_object_mut()
            .and_then(|obj| obj.remove("nvidia_gpu"));

        // Keep the service response shape stable: top-level `platform` plus
        // platform-specific `evidence` (+ optional `nvidia_gpu`). /verify
        // accepts this split form when clients send the same fields.
        let response = AttestResponse {
            platform: format!("{platform}"),
            evidence: envelope.get("evidence").cloned().unwrap_or(envelope),
            nvidia_gpu: gpu_field,
        };
        Ok(Json(serde_json::to_value(response).map_err(|e| {
            ApiError::Internal(format!("failed to encode evidence: {e}"))
        })?))
    }

    #[cfg(not(target_os = "linux"))]
    {
        let _ = (req, mode);
        Err(ApiError::NoPlatform)
    }
}

#[cfg(target_os = "linux")]
fn resolve_platform(name: &str) -> Result<attestation::PlatformType, ApiError> {
    match name {
        "auto" => attestation::detect().map_err(|_| ApiError::NoPlatform),
        "snp" => Ok(attestation::PlatformType::Snp),
        "tdx" => Ok(attestation::PlatformType::Tdx),
        "az-snp" => Ok(attestation::PlatformType::AzSnp),
        "az-tdx" => Ok(attestation::PlatformType::AzTdx),
        "gcp-snp" => Ok(attestation::PlatformType::GcpSnp),
        "gcp-tdx" => Ok(attestation::PlatformType::GcpTdx),
        other => Err(ApiError::BadRequest(format!("unknown platform: {other}"))),
    }
}

#[cfg(target_os = "linux")]
fn ensure_platform_allowed(
    allowed: &[String],
    platform: attestation::PlatformType,
) -> Result<(), ApiError> {
    let platform_name = platform.to_string();
    let allowed = allowed
        .iter()
        .filter_map(|name| normalize_platform(name))
        .any(|name| name == platform_name);

    if allowed {
        Ok(())
    } else {
        Err(ApiError::BadRequest(format!(
            "platform '{platform_name}' is not allowed by attestation.platforms"
        )))
    }
}

#[cfg(test)]
mod tests {
    use super::{attest_mode, AttestMode};

    #[test]
    fn a_nonce_selects_the_profile_and_old_requests_keep_the_old_envelope() {
        assert_eq!(attest_mode(None, true).unwrap(), AttestMode::Profile);
        assert_eq!(attest_mode(None, false).unwrap(), AttestMode::Legacy);
        assert_eq!(
            attest_mode(Some("cvm-v1"), false).unwrap(),
            AttestMode::Profile
        );
        assert_eq!(
            attest_mode(Some("legacy"), true).unwrap(),
            AttestMode::Legacy
        );
        assert!(attest_mode(Some("v2"), true).is_err());
    }
}
