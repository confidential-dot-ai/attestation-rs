use p256::ecdsa::SigningKey;
use p256::elliptic_curve::Generate;
use p256::pkcs8::DecodePrivateKey;
use std::path::Path;

use crate::error::ApiError;

/// Load an EC P-256 signing key from a PEM file, or generate an ephemeral one.
pub fn load_or_generate(key_path: &str) -> Result<SigningKey, ApiError> {
    if key_path.is_empty() {
        tracing::warn!("no token signing key configured — generating ephemeral EC P-256 key");
        tracing::warn!("tokens signed with ephemeral keys cannot be verified after restart");
        let key = SigningKey::generate();
        return Ok(key);
    }

    let path = Path::new(key_path);
    if !path.exists() {
        return Err(ApiError::Internal(format!(
            "token key file not found: {key_path}"
        )));
    }

    let pem = std::fs::read_to_string(path)
        .map_err(|e| ApiError::Internal(format!("failed to read key file: {e}")))?;

    let key = SigningKey::from_pkcs8_pem(&pem)
        .map_err(|e| ApiError::Internal(format!("failed to parse EC P-256 key: {e}")))?;

    tracing::info!("loaded token signing key from configured path");
    Ok(key)
}
