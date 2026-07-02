//! NVIDIA GPU confidential-compute attestation.
//!
//! This module verifies CC-mode NVIDIA GPU evidence (Hopper, Blackwell) and
//! NVSwitch evidence (LS10) by delegating signature/measurement checks to
//! NVIDIA's Remote Attestation Service (NRAS). NRAS returns a signed EAT
//! (Entity Attestation Token, RFC 9711) which is verified locally against
//! NRAS's JWKS.
//!
//! Verification is pure JSON + JWS (ES384) + base64 + SHA-256, so it works on
//! every target the rest of this library supports — including `wasm32` — with
//! no FFI to NVIDIA's Python/C++ SDKs.
//!
//! ## Trust model
//!
//! The GPU evidence is **transitively** bound to the CPU TEE evidence: the
//! caller supplies a `user_nonce`; the attester derives the GPU SPDM nonce
//! `gpu_nonce = SHA256(user_nonce || domain_tag)`; the verifier rederives the
//! same value and checks NRAS attested to it via `eat_nonce`. Because the
//! same `user_nonce` is the basis of the CPU TEE `report_data`, a verifier
//! that accepts both quotes proves that **both** the CPU and the GPU
//! committed to the caller's nonce in the same attestation session.
//!
//! Relying on NRAS shifts trust to NVIDIA's signing key. A future
//! `gpu-local` feature will perform the same checks locally without NRAS.
//!
//! ## Submodule binding (RFC 9711 `submods`)
//!
//! The overall token's `submods` claim carries a detached digest per device of
//! the form `["DIGEST", ["SHA-256", "<hex>"]]`. In principle the digest binds
//! each submodule JWT to the overall token. In practice NVIDIA computes that
//! digest over an *intermediate* serialization of the claims that excludes the
//! `exp`/`nbf`/`iat`/`jti` fields later added to the issued JWT (confirmed
//! against nvtrust's `create_detached_eat_claims`), and the algorithm label
//! differs between code paths (`"SHA256"` vs `"SHA-256"`). The digest therefore
//! cannot be re-derived byte-for-byte from the compact JWS NRAS returns, so we
//! do **not** attempt detached-digest verification.
//!
//! Instead the verifier binds every submodule by its own `eat_nonce`, which
//! NRAS sets to the same SPDM nonce on each submodule and which *is* covered by
//! the submodule's signature. This rejects a submodule spliced from another
//! session — the threat the digest would otherwise guard against — without
//! depending on the unstable digest encoding. Per-device security state
//! (`dbgstat`, `secboot`, `measres`, report-nonce match) is additionally gated
//! by [`crate::types::NvidiaGpuDevicePolicy`] rather than trusting NRAS's single
//! opaque `x-nvidia-overall-att-result` boolean.
//!
//! ## Endpoints
//!
//! Defaults match NVIDIA's production deployment and can be overridden via
//! [`DefaultNrasProvider::with_urls`] or environment variables
//! `NV_NRAS_GPU_URL` / `NV_NRAS_SWITCH_URL`. The relying-party usage of NRAS
//! is governed by NVIDIA's attestation T&C; see README.

use sha2::{Digest, Sha256};

pub mod provider;
pub mod verify;

#[cfg(all(feature = "nvidia-gpu-attest", target_os = "linux"))]
pub mod attest;

pub use provider::{
    jwks_url_for_endpoint, DefaultNrasProvider, Jwks, JwksKey, NrasProvider, NrasRequest,
};
pub use verify::verify_bundle;

use crate::error::{AttestationError, Result};
use crate::types::{NvidiaGpuBinding, NvidiaGpuHashAlgo};

/// Minimum acceptable length for the GPU user nonce.
///
/// Enforced symmetrically on both the attest and verify paths so a caller
/// can't produce evidence that their own verifier will reject.
pub(crate) const MIN_GPU_USER_NONCE_LEN: usize = 16;

/// Reject GPU user nonces shorter than [`MIN_GPU_USER_NONCE_LEN`].
///
/// Integration-tested via `verify_bundle` in `verify::tests`; the attest
/// path call site is verified by code review (FFI-gated, not exercised by CI).
pub(crate) fn check_user_nonce_len(user_nonce: &[u8]) -> Result<()> {
    if user_nonce.len() < MIN_GPU_USER_NONCE_LEN {
        Err(AttestationError::NvidiaGpuNonceTooShort(user_nonce.len()))
    } else {
        Ok(())
    }
}

const GPU_DOMAIN_TAG: &[u8] = b"NVIDIA-GPU-EAT-v1";
const SWITCH_DOMAIN_TAG: &[u8] = b"NVIDIA-SWITCH-EAT-v1";

/// Derive the SPDM nonce used to challenge GPUs in a batch.
///
/// `binding` selects the algorithm; v1 only supports `Concat { Sha256 }`.
/// NRAS accepts one nonce per request shared across every device in the
/// batch, so the v1 binding does not enumerate per-device UUIDs.
pub fn gpu_nonce(user_nonce: &[u8], binding: &NvidiaGpuBinding) -> [u8; 32] {
    derive_nonce(user_nonce, GPU_DOMAIN_TAG, binding)
}

/// Derive the SPDM nonce used to challenge NVSwitches in a batch.
pub fn switch_nonce(user_nonce: &[u8], binding: &NvidiaGpuBinding) -> [u8; 32] {
    derive_nonce(user_nonce, SWITCH_DOMAIN_TAG, binding)
}

fn derive_nonce(user_nonce: &[u8], domain_tag: &[u8], binding: &NvidiaGpuBinding) -> [u8; 32] {
    match binding {
        NvidiaGpuBinding::Concat { algo } => match algo {
            NvidiaGpuHashAlgo::Sha256 => {
                let mut h = Sha256::new();
                h.update(user_nonce);
                h.update(domain_tag);
                h.finalize().into()
            }
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn gpu_nonce_is_deterministic() {
        let user = b"test-nonce";
        let b = NvidiaGpuBinding::default();
        assert_eq!(gpu_nonce(user, &b), gpu_nonce(user, &b));
    }

    #[test]
    fn gpu_and_switch_nonces_are_domain_separated() {
        let user = b"x";
        let b = NvidiaGpuBinding::default();
        assert_ne!(gpu_nonce(user, &b), switch_nonce(user, &b));
    }

    #[test]
    fn distinct_user_nonces_yield_distinct_gpu_nonces() {
        let b = NvidiaGpuBinding::default();
        assert_ne!(gpu_nonce(b"a", &b), gpu_nonce(b"b", &b));
    }
}
