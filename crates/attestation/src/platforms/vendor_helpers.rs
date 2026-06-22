//! Helpers shared by per-vendor verifiers for building
//! [`crate::types::VerifyResult`].
//!
//! Every digest comparison routes through [`crate::utils::constant_time_eq`].
//! No `==` on digest bytes — see the crate's threat model on timing leaks.

use crate::utils::{constant_time_eq, sha384};

/// Canonical TDX launch_measurement = SHA-384(mrtd ‖ rtmr1 ‖ rtmr2 ‖ rtmr3).
///
/// Why this formula:
/// - **mrtd** locks the TD's initial measured state (firmware, kernel, initrd).
/// - **rtmr1/rtmr2** capture early-boot OS measurements (UEFI handoff, kernel).
/// - **rtmr3** is runtime-extendable by the guest (TDG.MR.RTMR.EXTEND), letting
///   workloads bind application-specific data (model hashes, config digests)
///   into the canonical identity.
///
/// This formula is LOCKED — changing it would silently change the
/// `launch_measurement` for every existing deployment, invalidating any
/// pinned references.
pub(crate) fn tdx_launch_measurement(
    mr_td: &[u8; 48],
    rtmr1: &[u8; 48],
    rtmr2: &[u8; 48],
    rtmr3: &[u8; 48],
) -> Vec<u8> {
    let mut buf = Vec::with_capacity(48 * 4);
    buf.extend_from_slice(mr_td);
    buf.extend_from_slice(rtmr1);
    buf.extend_from_slice(rtmr2);
    buf.extend_from_slice(rtmr3);
    sha384(&buf)
}

/// Compare an observed 48-byte digest against an optional expected digest.
/// Returns `(matched, mismatched)`:
/// - `matched`: `Some(true)` if expected was supplied and matched, else `None`/`Some(false)`.
/// - `mismatched`: `true` iff expected was supplied AND did not match.
///
/// Used to accumulate `vendor_policy_failed` without short-circuiting — each
/// pin check still runs and the boolean is OR'd in at the end.
pub(crate) fn check_digest_48(
    observed: &[u8; 48],
    expected: Option<&[u8; 48]>,
) -> (Option<bool>, bool) {
    match expected {
        Some(exp) => {
            let ok = constant_time_eq(observed, exp);
            (Some(ok), !ok)
        }
        None => (None, false),
    }
}

/// Same as `check_digest_48` but expected is a `Vec<u8>`-typed bag of bytes.
pub(crate) fn check_digest_vec(observed: &[u8], expected: Option<&[u8]>) -> (Option<bool>, bool) {
    match expected {
        Some(exp) => {
            let ok = constant_time_eq(observed, exp);
            (Some(ok), !ok)
        }
        None => (None, false),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tdx_launch_measurement_is_stable() {
        let mr_td = [0xAA; 48];
        let rtmr1 = [0xBB; 48];
        let rtmr2 = [0xCC; 48];
        let rtmr3 = [0xDD; 48];
        let lm = tdx_launch_measurement(&mr_td, &rtmr1, &rtmr2, &rtmr3);
        assert_eq!(lm.len(), 48, "SHA-384 output is 48 bytes");

        // Stability: the formula is locked. If this assertion fails, the
        // canonical launch_measurement has changed and every pinned
        // reference value in the wild needs to be recomputed.
        let expected_hex = "7c8e0ac46f3ae672b6f44e34dc5944b748c9b66281b20ae01f481575c357e958e052e657fa29874b6d927c67d9efb530";
        assert_eq!(hex::encode(&lm), expected_hex);
    }

    #[test]
    fn tdx_launch_measurement_diff_inputs_diff_outputs() {
        let mr_td_a = [0u8; 48];
        let mr_td_b = [1u8; 48];
        let rtmrs = [0u8; 48];
        let a = tdx_launch_measurement(&mr_td_a, &rtmrs, &rtmrs, &rtmrs);
        let b = tdx_launch_measurement(&mr_td_b, &rtmrs, &rtmrs, &rtmrs);
        assert_ne!(a, b);
    }

    #[test]
    fn check_digest_48_no_expected() {
        let obs = [0x11; 48];
        let (m, mismatch) = check_digest_48(&obs, None);
        assert_eq!(m, None);
        assert!(!mismatch);
    }

    #[test]
    fn check_digest_48_match() {
        let obs = [0x11; 48];
        let exp = [0x11; 48];
        let (m, mismatch) = check_digest_48(&obs, Some(&exp));
        assert_eq!(m, Some(true));
        assert!(!mismatch);
    }

    #[test]
    fn check_digest_48_mismatch() {
        let obs = [0x11; 48];
        let exp = [0x22; 48];
        let (m, mismatch) = check_digest_48(&obs, Some(&exp));
        assert_eq!(m, Some(false));
        assert!(mismatch);
    }
}
