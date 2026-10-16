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
    /// Where NRAS publishes its key set: derived from the configured NRAS
    /// attestation URL ([`jwks_url_for_endpoint`](crate::platforms::nvidia_gpu::jwks_url_for_endpoint)).
    type Id = String;

    fn name(_: &String) -> String {
        "nras-jwks".into()
    }

    fn url(jwks_url: &String) -> String {
        jwks_url.clone()
    }

    /// The keys whose `x5c` chain leads to the pinned NVIDIA anchor; at least
    /// one must. The set itself is not signed. The certificates' validity is
    /// checked when a token is verified with a key.
    fn verify(json: &[u8], _: Option<&str>, _: &String) -> Result<Self> {
        let mut jwks: Jwks =
            serde_json::from_slice(json).map_err(|e| refused(format!("JWKS: {e}")))?;
        jwks.keys
            .retain(|key| es384_verifying_key_from_jwks_entry(key, None).is_ok());
        if jwks.keys.is_empty() {
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
    fn only_keys_under_the_nvidia_anchor_are_kept() {
        let body = include_bytes!("../../test_data/collateral/2026-10-14/nras_jwks.json");
        let mut set: serde_json::Value = serde_json::from_slice(body).unwrap();
        let keys = set["keys"].as_array_mut().unwrap();
        let mut foreign = keys[0].clone();
        foreign["kid"] = "foreign".into();
        foreign.as_object_mut().unwrap().remove("x5c");
        keys.push(foreign.clone());
        let url = String::new();
        let genuine = NrasJwks::verify(body, None, &url).unwrap().jwks.keys.len();
        let mixed = serde_json::to_vec(&set).unwrap();
        let kept = NrasJwks::verify(&mixed, None, &url).unwrap().jwks.keys;
        assert_eq!(kept.len(), genuine);
        assert!(kept.iter().all(|k| k.kid != "foreign"));
        let only_foreign = serde_json::to_vec(&serde_json::json!({ "keys": [foreign] })).unwrap();
        assert!(NrasJwks::verify(&only_foreign, None, &url).is_err());
    }
}
