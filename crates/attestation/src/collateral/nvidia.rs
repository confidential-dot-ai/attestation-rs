//! NVIDIA's NRAS signing keys.

use super::Refused;
use crate::platforms::nvidia_gpu::provider::{jwks_url_for_endpoint, Jwks};

/// The keys NVIDIA's NRAS signs its attestation tokens with.
#[derive(Debug, Clone)]
pub struct NrasJwks {
    pub jwks: Jwks,
}

impl NrasJwks {
    /// The key set of the NRAS at `nras_url`.
    pub fn url(nras_url: &str) -> String {
        jwks_url_for_endpoint(nras_url).unwrap_or_else(|_| nras_url.to_string())
    }

    /// A key set with at least one key. The set is not signed itself: each
    /// key is trusted only through its `x5c` chain to the pinned NVIDIA
    /// anchor, which is checked when a token is verified with it.
    pub fn verify(json: &[u8]) -> Result<Self, Refused> {
        let jwks: Jwks = serde_json::from_slice(json).map_err(|e| format!("JWKS: {e}"))?;
        if jwks.keys.is_empty() {
            return Err("JWKS has no keys".into());
        }
        Ok(Self { jwks })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_nras_key_set_parses_and_garbage_is_refused() {
        let body = include_bytes!("../../test_data/collateral/2026-10-14/nras_jwks.json");
        assert!(!NrasJwks::verify(body).unwrap().jwks.keys.is_empty());
        for bad in [&b""[..], b"{\"keys\":[]}", b"<html>"] {
            assert!(NrasJwks::verify(bad).is_err());
        }
    }
}
