//! NVIDIA's NRAS signing keys.

use super::{refused, Collateral, Dates};
use crate::error::Result;
use crate::platforms::nvidia_gpu::provider::Jwks;
use crate::platforms::nvidia_gpu::verify::es384_verifying_key_from_jwks_entry;

/// The keys NVIDIA's NRAS signs its attestation tokens with.
#[derive(Debug, Clone)]
pub struct NrasJwks {
    pub jwks: Jwks,
}

impl Collateral for NrasJwks {
    /// Where NRAS publishes its key set
    /// ([`jwks_url_for_endpoint`](crate::platforms::nvidia_gpu::jwks_url_for_endpoint)
    /// of the configured NRAS URL).
    type Id = String;

    fn name(_: &String) -> String {
        "nras-jwks".into()
    }

    fn url(jwks_url: &String) -> String {
        jwks_url.clone()
    }

    /// At least one key's `x5c` chain must lead to the pinned NVIDIA anchor.
    /// The set itself is not signed. Every key is checked again, with its
    /// validity, when a token names it, so a token from a key outside the
    /// anchor is refused rather than looked up again.
    fn verify(json: &[u8], _: Option<&str>, _: &String) -> Result<Self> {
        let jwks: Jwks = serde_json::from_slice(json).map_err(|e| refused(format!("JWKS: {e}")))?;
        if !jwks
            .keys
            .iter()
            .any(|key| es384_verifying_key_from_jwks_entry(key, None).is_ok())
        {
            return Err(refused("JWKS has no key under the NVIDIA anchor"));
        }
        Ok(Self { jwks })
    }

    fn dates(&self) -> Dates {
        Dates::default()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_nras_key_set_parses_and_garbage_is_refused() {
        let body = include_bytes!("../../test_data/collateral/2026-10-14/nras_jwks.json");
        let url = String::new();
        assert!(!NrasJwks::verify(body, None, &url)
            .unwrap()
            .jwks
            .keys
            .is_empty());
        for bad in [&b""[..], b"{\"keys\":[]}", b"<html>"] {
            assert!(NrasJwks::verify(bad, None, &url).is_err());
        }
    }

    #[test]
    fn a_token_from_a_published_key_outside_the_anchor_is_refused() {
        use crate::error::AttestationError;
        use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
        let body = include_bytes!("../../test_data/collateral/2026-10-14/nras_jwks.json");
        let mut set: serde_json::Value = serde_json::from_slice(body).unwrap();
        let keys = set["keys"].as_array_mut().unwrap();
        let mut foreign = keys[0].clone();
        foreign["kid"] = "foreign".into();
        foreign.as_object_mut().unwrap().remove("x5c");
        keys.push(foreign.clone());
        let url = String::new();
        let mixed = serde_json::to_vec(&set).unwrap();
        let jwks = NrasJwks::verify(&mixed, None, &url).unwrap().jwks;
        let header = URL_SAFE_NO_PAD.encode(r#"{"alg":"ES384","kid":"foreign"}"#);
        let token = format!("{header}.e30.{}", URL_SAFE_NO_PAD.encode([0u8; 96]));
        let err =
            crate::platforms::nvidia_gpu::verify::verify_jws_es384(&token, &jwks, 1_792_022_400)
                .unwrap_err();
        assert!(matches!(err, AttestationError::JwsVerification(_)), "{err}");
        assert!(!err.is_retryable());
        let only_foreign = serde_json::to_vec(&serde_json::json!({ "keys": [foreign] })).unwrap();
        assert!(NrasJwks::verify(&only_foreign, None, &url).is_err());
    }
}
