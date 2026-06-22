//! Helpers shared by per-vendor verifiers for building the new
//! [`crate::types::VerifyResult`] shape.
//!
//! These helpers cover the steady-state work every vendor needs:
//! - computing the canonical synthetic launch_measurement
//! - projecting raw parsed structs into the serializable
//!   `ParsedTdxQuote` / `ParsedSnpReport` / `ParsedTpmQuote` / `ParsedHclReport`
//! - constant-time comparison of canonical anchors
//!
//! Every digest comparison routes through [`crate::utils::constant_time_eq`].
//! No `==` on digest bytes — see the crate's threat model on timing leaks.

use crate::types::{
    ParsedHclReport, ParsedSnpReport, ParsedTdxQuote, ParsedTpmQuote, SnpTcb,
};
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

/// Convert the internal [`crate::platforms::tdx::verify::TdxQuote`] into the
/// serializable projection used by [`crate::types::VendorResult`].
pub(crate) fn project_tdx_quote(
    quote: &crate::platforms::tdx::verify::TdxQuote,
) -> ParsedTdxQuote {
    ParsedTdxQuote {
        quote_version: quote.header.version,
        tee_tcb_svn: quote.body.tee_tcb_svn.to_vec(),
        mr_seam: quote.body.mr_seam.to_vec(),
        mrsigner_seam: quote.body.mrsigner_seam.to_vec(),
        seam_attributes: quote.body.seam_attributes.to_vec(),
        td_attributes: quote.body.td_attributes.to_vec(),
        xfam: quote.body.xfam.to_vec(),
        mr_td: quote.body.mr_td.to_vec(),
        mr_config_id: quote.body.mr_config_id.to_vec(),
        mr_owner: quote.body.mr_owner.to_vec(),
        mr_owner_config: quote.body.mr_owner_config.to_vec(),
        rtmr0: quote.body.rtmr_0.to_vec(),
        rtmr1: quote.body.rtmr_1.to_vec(),
        rtmr2: quote.body.rtmr_2.to_vec(),
        rtmr3: quote.body.rtmr_3.to_vec(),
        report_data: quote.body.report_data.to_vec(),
    }
}

/// Convert a parsed `sev` SNP attestation report into the serializable projection.
#[cfg(feature = "snp")]
pub(crate) fn project_snp_report(report: &sev::firmware::guest::AttestationReport) -> ParsedSnpReport {
    ParsedSnpReport {
        version: report.version,
        vmpl: report.vmpl,
        measurement: report.measurement[..].to_vec(),
        report_data: report.report_data[..].to_vec(),
        host_data: report.host_data[..].to_vec(),
        chip_id: report.chip_id[..].to_vec(),
        policy_debug_allowed: report.policy.debug_allowed(),
        reported_tcb: SnpTcb {
            bootloader: report.reported_tcb.bootloader,
            tee: report.reported_tcb.tee,
            snp: report.reported_tcb.snp,
            microcode: report.reported_tcb.microcode,
            fmc: report.reported_tcb.fmc,
        },
    }
}

/// Project a TPM quote into the serializable shape.
#[cfg(any(feature = "az-snp", feature = "az-tdx"))]
pub(crate) fn project_tpm_quote(
    signature: &[u8],
    message: &[u8],
    pcrs: &[Vec<u8>],
) -> ParsedTpmQuote {
    ParsedTpmQuote {
        signature: signature.to_vec(),
        message: message.to_vec(),
        pcrs: pcrs.iter().map(hex::encode).collect(),
    }
}

/// Project the HCL report metadata.
#[cfg(any(feature = "az-snp", feature = "az-tdx"))]
pub(crate) fn project_hcl_report(
    hcl: &crate::platforms::tpm_common::HclReportData,
) -> ParsedHclReport {
    ParsedHclReport {
        report_type: hcl.report_type,
        var_data: hcl.var_data.clone(),
    }
}

/// Compare an observed 48-byte digest against an optional expected digest.
/// Returns `(matched, mismatched)`:
/// - `matched`: `Some(true)` if expected was supplied and matched, else `None`/`Some(false)`.
/// - `mismatched`: `true` iff expected was supplied AND did not match.
///
/// Used to accumulate `vendor_policy_failed` without short-circuiting — each
/// pin check still runs and the boolean is OR'd in at the end.
pub(crate) fn check_digest_48(observed: &[u8; 48], expected: Option<&[u8; 48]>) -> (Option<bool>, bool) {
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
