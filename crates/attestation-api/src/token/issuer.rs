use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use p256::ecdsa::{signature::Signer, Signature, SigningKey};
use p256::elliptic_curve::sec1::ToEncodedPoint;
use p256::PublicKey;
use serde::Serialize;
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::fmt;
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use uuid::Uuid;

use crate::error::ApiError;

/// JWT token issuer using ES256 (ECDSA P-256 + SHA-256).
///
/// Signs directly with `p256::ecdsa::SigningKey` which implements `Zeroize` on drop,
/// ensuring key material is scrubbed from memory when the issuer is dropped.
pub struct TokenIssuer {
    signing_key: SigningKey,
    kid: String,
    issuer: String,
    duration: Duration,
    jwks: Value,
}

#[derive(Debug, Serialize)]
struct JwtHeader {
    alg: &'static str,
    typ: &'static str,
    kid: String,
}

#[derive(Serialize)]
struct JwtClaims {
    iss: String,
    jti: String,
    iat: u64,
    nbf: u64,
    exp: u64,
    /// Vendor platform tag (e.g. "tdx", "az-snp").
    platform: String,
    signature_valid: bool,
    collateral_verified: bool,
    /// Hex-encoded canonical launch measurement.
    launch_measurement: String,
    /// Hex-encoded observed report_data.
    report_data: String,
    /// Hex-encoded observed nonce.
    nonce: String,
    nonce_match: Option<bool>,
    report_data_match: Option<bool>,
    launch_measurement_match: Option<bool>,
    vendor_policy_failed: bool,
    /// Vendor-specific verification artifacts (parsed quote/report, etc.).
    vendor: Value,
}

impl fmt::Debug for JwtClaims {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("JwtClaims")
            .field("iss", &self.iss)
            .field("jti", &self.jti)
            .field("platform", &self.platform)
            .field("vendor", &"[redacted]")
            .finish()
    }
}

impl TokenIssuer {
    pub fn new(
        signing_key: SigningKey,
        issuer: String,
        duration: Duration,
    ) -> Result<Self, ApiError> {
        let jwks = build_jwks(&signing_key)?;
        let kid = extract_kid(&jwks)?;

        Ok(Self {
            signing_key,
            kid,
            issuer,
            duration,
            jwks,
        })
    }

    pub fn issue(&self, result: &attestation::VerifyResult) -> Result<String, ApiError> {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|e| ApiError::Internal(format!("system time error: {e}")))?;

        let vendor_json = serde_json::to_value(&result.vendor)
            .map_err(|e| ApiError::Internal(format!("failed to serialize vendor: {e}")))?;

        let jwt_claims = JwtClaims {
            iss: self.issuer.clone(),
            jti: Uuid::new_v4().to_string(),
            iat: now.as_secs(),
            nbf: now.as_secs(),
            exp: now.as_secs() + self.duration.as_secs(),
            platform: format!("{}", result.vendor.platform()),
            signature_valid: result.signature_valid,
            collateral_verified: result.collateral_verified,
            launch_measurement: hex::encode(&result.launch_measurement),
            report_data: hex::encode(&result.report_data),
            nonce: hex::encode(&result.nonce),
            nonce_match: result.nonce_match,
            report_data_match: result.report_data_match,
            launch_measurement_match: result.launch_measurement_match,
            vendor_policy_failed: result.vendor_policy_failed,
            vendor: vendor_json,
        };

        let header = JwtHeader {
            alg: "ES256",
            typ: "JWT",
            kid: self.kid.clone(),
        };
        let header_b64 = b64_encode_json(&header)?;
        let claims_b64 = b64_encode_json(&jwt_claims)?;
        let message = format!("{header_b64}.{claims_b64}");

        // ES256 per RFC 7518 s3.4: fixed-size 64-byte (r || s) signature encoding
        let sig: Signature = self.signing_key.sign(message.as_bytes());
        let sig_b64 = URL_SAFE_NO_PAD.encode(sig.to_bytes());

        Ok(format!("{message}.{sig_b64}"))
    }

    /// Returns the pre-computed JWKS (JSON Web Key Set) for token verification.
    pub fn jwks(&self) -> Value {
        self.jwks.clone()
    }
}

fn extract_kid(jwks: &Value) -> Result<String, ApiError> {
    jwks["keys"][0]["kid"]
        .as_str()
        .map(String::from)
        .ok_or_else(|| ApiError::Internal("JWKS missing kid".to_string()))
}

fn b64_encode_json<T: Serialize>(value: &T) -> Result<String, ApiError> {
    let json = serde_json::to_vec(value)
        .map_err(|e| ApiError::Internal(format!("JSON serialization failed: {e}")))?;
    Ok(URL_SAFE_NO_PAD.encode(json))
}

/// Build a JWKS response from an EC P-256 signing key.
fn build_jwks(signing_key: &SigningKey) -> Result<Value, ApiError> {
    let public_key = PublicKey::from(signing_key.verifying_key());
    let point = public_key.to_encoded_point(false);

    let x = URL_SAFE_NO_PAD.encode(
        point
            .x()
            .ok_or_else(|| ApiError::Internal("missing x coordinate".to_string()))?,
    );
    let y = URL_SAFE_NO_PAD.encode(
        point
            .y()
            .ok_or_else(|| ApiError::Internal("missing y coordinate".to_string()))?,
    );

    // Compute JWK Thumbprint per RFC 7638 for the kid
    let thumbprint_input = format!(r#"{{"crv":"P-256","kty":"EC","x":"{x}","y":"{y}"}}"#);
    let hash = Sha256::digest(thumbprint_input.as_bytes());
    let kid = URL_SAFE_NO_PAD.encode(hash);

    let jwk = json!({
        "kty": "EC",
        "crv": "P-256",
        "x": x,
        "y": y,
        "use": "sig",
        "alg": "ES256",
        "kid": kid,
    });

    Ok(json!({ "keys": [jwk] }))
}
