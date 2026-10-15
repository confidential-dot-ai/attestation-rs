//! NVIDIA's NRAS signing keys.

use super::document::{Document, Info, NrasJwks, Raw};
use crate::platforms::nvidia_gpu::provider::Jwks;

impl Document for NrasJwks {
    type Value = Jwks;

    /// A key set with at least one key. The set is not signed itself: each
    /// key is trusted only through its `x5c` chain to the pinned NVIDIA
    /// anchor, which is checked when a token is verified with it.
    fn check(&self, raw: &Raw) -> Result<(Jwks, Info), String> {
        let jwks: Jwks = serde_json::from_slice(&raw.body).map_err(|e| format!("JWKS: {e}"))?;
        if jwks.keys.is_empty() {
            return Err("JWKS has no keys".into());
        }
        Ok((jwks, Info::default()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_nras_key_set_parses_and_garbage_is_refused() {
        let body = include_bytes!("../../test_data/collateral/2026-10-14/nras_jwks.json");
        let raw = |body: &[u8]| Raw {
            body: body.to_vec(),
            issuer_chain: None,
        };
        let (jwks, _) = NrasJwks {}.check(&raw(body)).unwrap();
        assert!(!jwks.keys.is_empty());
        for bad in [&b""[..], b"{\"keys\":[]}", b"<html>"] {
            assert!(NrasJwks {}.check(&raw(bad)).is_err());
        }
    }
}
