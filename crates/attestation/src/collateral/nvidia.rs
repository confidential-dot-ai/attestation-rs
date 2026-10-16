//! NVIDIA's NRAS signing keys.

use super::{refused, Collateral, Dates};
use crate::error::Result;
use crate::platforms::nvidia_gpu::provider::{jwks_url_for_endpoint, Jwks};

/// The keys NVIDIA's NRAS signs its attestation tokens with.
#[derive(Debug, Clone)]
pub struct NrasJwks {
    pub jwks: Jwks,
}

impl Collateral for NrasJwks {
    /// The NRAS attestation URL the caller configured; its key set is
    /// published next to it.
    type Id = String;

    fn name(_: &String) -> String {
        "nras-jwks".into()
    }

    fn url(nras_url: &String) -> String {
        jwks_url_for_endpoint(nras_url).unwrap_or_else(|_| nras_url.clone())
    }

    /// A key set with at least one key. The set is not signed itself: each
    /// key is trusted only through its `x5c` chain to the pinned NVIDIA
    /// anchor, which is checked when a token is verified with it.
    fn verify(json: &[u8], _: Option<&str>, _: &String) -> Result<Self> {
        let jwks: Jwks = serde_json::from_slice(json).map_err(|e| refused(format!("JWKS: {e}")))?;
        if jwks.keys.is_empty() {
            return Err(refused("JWKS has no keys"));
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
}
