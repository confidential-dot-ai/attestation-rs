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

pub async fn handler(
    State(state): State<AppState>,
    Json(req): Json<AttestRequest>,
) -> Result<Json<AttestResponse>, ApiError> {
    if !state.config.attestation.enabled {
        return Err(ApiError::AttestNotAvailable);
    }

    #[cfg(target_os = "linux")]
    {
        let report_data = match req.report_data {
            Some(b64) => BASE64
                .decode(&b64)
                .map_err(|e| ApiError::BadRequest(format!("invalid base64 report_data: {e}")))?,
            None => Vec::new(),
        };

        let platform = resolve_platform(&req.platform)?;
        ensure_platform_allowed(&state.config.attestation.platforms, platform)?;
        let options = state.config.attestation.attest_options();

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
        Ok(Json(AttestResponse {
            platform: format!("{platform}"),
            evidence: envelope.get("evidence").cloned().unwrap_or(envelope),
            nvidia_gpu: gpu_field,
        }))
    }

    #[cfg(not(target_os = "linux"))]
    {
        let _ = req;
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
