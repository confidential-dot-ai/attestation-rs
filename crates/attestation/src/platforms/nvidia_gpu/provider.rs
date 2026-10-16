//! NRAS endpoints and wire types.

use serde::{Deserialize, Serialize};

use crate::error::{AttestationError, Result};
use crate::types::NvidiaGpuArch;

/// Default NRAS GPU endpoint. Override via `NV_NRAS_GPU_URL`.
pub const NRAS_GPU_URL: &str = "https://nras.attestation.nvidia.com/v3/attest/gpu";

/// Default NRAS NVSwitch endpoint. Override via `NV_NRAS_SWITCH_URL`.
pub const NRAS_SWITCH_URL: &str = "https://nras.attestation.nvidia.com/v3/attest/switch";

/// Header name nvtrust uses to opt in to "certificate hold" OCSP statuses.
pub const HEADER_OCSP_ALLOW_CERT_HOLD: &str = "X-NVIDIA-OCSP-ALLOW-CERT-HOLD";

/// NRAS POST body. Matches the schema implemented by nvtrust's
/// `attest_gpu_remote.build_payload`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NrasRequest {
    /// Hex-encoded SPDM nonce. All entries in `evidence_list` were collected
    /// with this nonce.
    pub nonce: String,
    pub evidence_list: Vec<NrasEvidenceEntry>,
    pub arch: NvidiaGpuArch,
    /// Claims schema version (`"2.0"` or `"3.0"`).
    pub claims_version: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NrasEvidenceEntry {
    /// Base64 SPDM blob.
    pub evidence: String,
    /// Base64-encoded PEM cert chain.
    pub certificate: String,
}

/// JWKS (JSON Web Key Set) returned by `/.well-known/jwks.json`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Jwks {
    pub keys: Vec<JwksKey>,
}

/// One key entry inside a JWKS. NRAS serves ES384 keys with `x5c` cert
/// chains; the verifier consumes the public point from the leaf certificate.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JwksKey {
    pub kid: String,
    pub kty: String,
    #[serde(default)]
    pub alg: Option<String>,
    #[serde(default)]
    pub crv: Option<String>,
    #[serde(default)]
    pub x: Option<String>,
    #[serde(default)]
    pub y: Option<String>,
    /// Base64 (standard) DER-encoded X.509 certs. Leaf first.
    #[serde(default)]
    pub x5c: Option<Vec<String>>,
}

/// Derive the JWKS URL for a given NRAS endpoint by replacing the path with
/// `/.well-known/jwks.json` and dropping any query/fragment.
///
/// Hand-rolled to avoid pulling in the `url` crate (keeps the WASM bundle
/// small); the input space is the tightly controlled NRAS endpoint URLs.
pub fn jwks_url_for_endpoint(endpoint: &str) -> Result<String> {
    let (scheme, rest) = endpoint
        .split_once("://")
        .ok_or_else(|| AttestationError::JwksFetch(format!("invalid NRAS URL: {endpoint}")))?;
    let host = rest
        .split('/')
        .next()
        .ok_or_else(|| AttestationError::JwksFetch(format!("invalid NRAS URL: {endpoint}")))?;
    Ok(format!("{scheme}://{host}/.well-known/jwks.json"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn jwks_url_replaces_path_with_well_known() {
        assert_eq!(
            jwks_url_for_endpoint("https://nras.attestation.nvidia.com/v3/attest/gpu").unwrap(),
            "https://nras.attestation.nvidia.com/.well-known/jwks.json"
        );
        assert_eq!(
            jwks_url_for_endpoint("https://nras.attestation.nvidia.com/v3/attest/switch").unwrap(),
            "https://nras.attestation.nvidia.com/.well-known/jwks.json"
        );
    }

    #[test]
    fn jwks_url_rejects_missing_scheme() {
        assert!(jwks_url_for_endpoint("nras.attestation.nvidia.com/x").is_err());
    }
}
