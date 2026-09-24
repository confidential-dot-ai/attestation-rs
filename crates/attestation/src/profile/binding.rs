//! Section 5: freshness anchors and the NVIDIA nonce derivation.
//!
//! `||` is byte concatenation with no separators; quoted strings are ASCII
//! bytes with no terminator. Vectors: Appendix B, `tests/profile_vectors.rs`.

use super::{NONCE_MAX, NONCE_MIN};
use sha2::{Digest, Sha256, Sha384};

/// Domain tag of the keyed anchor.
pub const ANCHOR_TAG: &[u8] = b"ats-anchor-v1";
/// SPDM nonce tags for NVIDIA devices.
pub const NRAS_GPU_TAG: &[u8] = b"NVIDIA-GPU-EAT-v1";
pub const NRAS_SWITCH_TAG: &[u8] = b"NVIDIA-SWITCH-EAT-v1";

/// `kind` strings of `cvm_binding.key` as they appear on the wire.
pub const KEY_KIND_SPKI_SHA256: &str = "spki-sha256";
pub const KEY_KIND_X509_TBS_SHA256: &str = "x509-tbs-sha256";
pub const KEY_KIND_RAW: &str = "raw";

/// `pad64(x)`: `x` followed by zero bytes to 64. `x` must be at most 64 bytes.
pub fn pad64(x: &[u8]) -> Option<[u8; 64]> {
    if x.len() > 64 {
        return None;
    }
    let mut out = [0u8; 64];
    out[..x.len()].copy_from_slice(x);
    Some(out)
}

/// The relying party's binding input.
///
/// ```text
/// no key:   anchor = nonce
/// with key: anchor = SHA-384("ats-anchor-v1" || u8(len(nonce)) || nonce
///                            || u8(len(kind)) || kind || u16be(len(value)) || value)
/// ```
/// Returns `None` when a length is outside what the encoding can carry:
/// nonce 16 to 64 bytes, kind 1 to 255 bytes, value at most 65535 bytes.
pub fn anchor(nonce: &[u8], key: Option<(&str, &[u8])>) -> Option<Vec<u8>> {
    if nonce.len() < NONCE_MIN || nonce.len() > NONCE_MAX {
        return None;
    }
    let Some((kind, value)) = key else {
        return Some(nonce.to_vec());
    };
    let kind = kind.as_bytes();
    if kind.is_empty() || kind.len() > 255 || value.len() > 65535 {
        return None;
    }
    let mut h = Sha384::new();
    h.update(ANCHOR_TAG);
    h.update([nonce.len() as u8]);
    h.update(nonce);
    h.update([kind.len() as u8]);
    h.update(kind);
    h.update((value.len() as u16).to_be_bytes());
    h.update(value);
    Some(h.finalize().to_vec())
}

/// `SHA-256(nonce || "NVIDIA-GPU-EAT-v1")`, the SPDM nonce a GPU is challenged with.
pub fn nras_gpu_nonce(nonce: &[u8]) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(nonce);
    h.update(NRAS_GPU_TAG);
    h.finalize().into()
}

/// `SHA-256(nonce || "NVIDIA-SWITCH-EAT-v1")` for NVSwitch.
pub fn nras_switch_nonce(nonce: &[u8]) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(nonce);
    h.update(NRAS_SWITCH_TAG);
    h.finalize().into()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn anchor_bounds() {
        let nonce = [7u8; 16];
        assert_eq!(anchor(&nonce, None).unwrap(), nonce);
        assert!(anchor(&[7u8; 15], None).is_none());
        assert!(anchor(&[7u8; 65], None).is_none());
        assert!(anchor(&nonce, Some(("", &[1u8; 32]))).is_none());
        assert!(anchor(&nonce, Some(("raw", &vec![0u8; 65536]))).is_none());
        assert!(anchor(&nonce, Some(("raw", &vec![0u8; 65535]))).is_some());
        assert!(pad64(&[0u8; 65]).is_none());
        assert_eq!(pad64(&[1, 2]).unwrap()[..3], [1, 2, 0]);
    }
}
