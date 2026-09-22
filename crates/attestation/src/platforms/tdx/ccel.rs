//! CCEL (CC Event Log) parsing and RTMR replay verification.
//!
//! The CCEL is a TCG2-format event log stored in the ACPI CCEL table
//! at `/sys/firmware/acpi/tables/data/CCEL`. Each event targets an MR index
//! (1-4 mapping to RTMR[0-3]) and carries a SHA-384 digest. Replaying the
//! events from a zero-initialized state must reproduce the RTMR values in
//! the TDX quote, proving event log integrity.
//!
//! Only RTMR[0-2] (boot-time registers) are subject to this check. RTMR[3]
//! is the runtime-extendable register: the guest kernel's tdx_guest sysfs
//! extend interface appends no CCEL entry (the log area is firmware-owned),
//! so a runtime extend that no log records (the confidential-os operator-key
//! binding, or a per-workload measurer) makes RTMR[3] unreplayable.
//! Relying parties verify `quote.rtmr_3` directly against their own expected
//! value (`expected_rtmr3` / claims).

use crate::error::{AttestationError, Result};

/// Replay a CCEL into RTMR 0 to 3, each from zero in the SHA-384 bank, after
/// mapping MrIndex 1 to 4 onto them. Records the Confidential Containers
/// attestation agent appends (MrIndex 4 by default) replay into RTMR 3.
pub fn replay_rtmrs(ccel: &[u8]) -> Result<[[u8; 48]; 4]> {
    let integrity = crate::profile::cel::cel_err;
    let records =
        tcg_cel::tcg2::to_cel(ccel, tcg_cel::tcg2::IndexMap::CcMrToRtmr).map_err(integrity)?;
    let out = tcg_cel::replay(
        &records,
        tcg_cel::HashAlg::SHA384,
        |i| matches!(i, tcg_cel::Index::Pcr(0..=3)).then(|| vec![0; 48]),
        tcg_cel::ReplayOptions::default(),
    )
    .map_err(integrity)?;
    let mut rtmrs = [[0u8; 48]; 4];
    for (index, reg) in out.registers {
        if let tcg_cel::Index::Pcr(i @ 0..=3) = index {
            rtmrs[i as usize].copy_from_slice(&reg.value);
        }
    }
    Ok(rtmrs)
}

/// Verify that a CCEL replays to the RTMRs of a TDX quote.
///
/// Enforces RTMR[0-2] only. RTMR[3] takes runtime extends the firmware log
/// does not carry (see module docs), so a mismatch there only logs a warning
/// and relying parties verify `quote.rtmr_3` directly. Returns whether RTMR[3]
/// reproduced too, as it does when every runtime extend was logged.
pub fn verify_ccel_against_rtmrs(
    ccel_data: &[u8],
    rtmr_0: &[u8; 48],
    rtmr_1: &[u8; 48],
    rtmr_2: &[u8; 48],
    rtmr_3: &[u8; 48],
) -> Result<bool> {
    let replayed = replay_rtmrs(ccel_data)?;

    let expected = [rtmr_0, rtmr_1, rtmr_2];
    for (i, (got, want)) in replayed.iter().zip(expected.iter()).enumerate() {
        if !crate::utils::constant_time_eq(got, *want) {
            return Err(AttestationError::EventlogIntegrityFailed(format!(
                "RTMR[{i}] mismatch: replayed={}, expected={}",
                hex::encode(got),
                hex::encode(want)
            )));
        }
    }

    let rtmr3 = crate::utils::constant_time_eq(&replayed[3], rtmr_3);
    if !rtmr3 {
        log::warn!(
            "RTMR[3] replay mismatch (runtime extends are not logged to the CCEL; verify quote.rtmr_3 directly): replayed={}, quote={}",
            hex::encode(replayed[3]),
            hex::encode(rtmr_3)
        );
    }
    Ok(rtmr3)
}

#[cfg(test)]
mod tests {
    use super::*;

    const LIVE_CCEL: &[u8] = include_bytes!("../../../test_data/tdx_ccel_live.bin");
    const LIVE_TDREPORT: &[u8] = include_bytes!("../../../test_data/tdx_tdreport_live.bin");

    #[test]
    fn test_parse_ccel_live() {
        let log = tcg_cel::tcg2::parse(LIVE_CCEL).expect("failed to parse CCEL");
        assert!(!log.events.is_empty(), "CCEL should contain events");
        assert_eq!(log.spec_id.algorithms, [(tcg_cel::HashAlg::SHA384, 48)]);
        for (i, event) in log.events.iter().enumerate() {
            assert!(
                (1..=4).contains(&event.index),
                "event {i} MR index {} out of range",
                event.index
            );
        }
        // The older CCEL recording puts its header at MrIndex 0.
        let older = include_bytes!("../../../test_data/CCEL_data");
        assert_eq!(tcg_cel::tcg2::parse(older).unwrap().header.index, 0);
        assert!(replay_rtmrs(older).is_ok());
    }

    #[test]
    fn test_replay_rtmrs_match_tdreport() {
        let replayed = replay_rtmrs(LIVE_CCEL).expect("replay CCEL");

        // Extract RTMRs from TDREPORT
        // TDINFO at offset 512: td_attributes[8], xfam[8], mrtd[48], mrconfigid[48],
        // mrowner[48], mrownerconfig[48], rtmr0[48], rtmr1[48], rtmr2[48], rtmr3[48]
        const TDINFO: usize = 512;
        let hw_rtmr0: [u8; 48] = LIVE_TDREPORT[TDINFO + 208..TDINFO + 256]
            .try_into()
            .unwrap();
        let hw_rtmr1: [u8; 48] = LIVE_TDREPORT[TDINFO + 256..TDINFO + 304]
            .try_into()
            .unwrap();
        let hw_rtmr2: [u8; 48] = LIVE_TDREPORT[TDINFO + 304..TDINFO + 352]
            .try_into()
            .unwrap();
        let hw_rtmr3: [u8; 48] = LIVE_TDREPORT[TDINFO + 352..TDINFO + 400]
            .try_into()
            .unwrap();

        assert_eq!(
            hex::encode(replayed[0]),
            hex::encode(hw_rtmr0),
            "RTMR[0] mismatch"
        );
        assert_eq!(
            hex::encode(replayed[1]),
            hex::encode(hw_rtmr1),
            "RTMR[1] mismatch"
        );
        assert_eq!(
            hex::encode(replayed[2]),
            hex::encode(hw_rtmr2),
            "RTMR[2] mismatch"
        );
        assert_eq!(
            hex::encode(replayed[3]),
            hex::encode(hw_rtmr3),
            "RTMR[3] mismatch"
        );
    }

    #[test]
    fn test_verify_ccel_against_rtmrs() {
        const TDINFO: usize = 512;
        let rtmr0: [u8; 48] = LIVE_TDREPORT[TDINFO + 208..TDINFO + 256]
            .try_into()
            .unwrap();
        let rtmr1: [u8; 48] = LIVE_TDREPORT[TDINFO + 256..TDINFO + 304]
            .try_into()
            .unwrap();
        let rtmr2: [u8; 48] = LIVE_TDREPORT[TDINFO + 304..TDINFO + 352]
            .try_into()
            .unwrap();
        let rtmr3: [u8; 48] = LIVE_TDREPORT[TDINFO + 352..TDINFO + 400]
            .try_into()
            .unwrap();

        let result = verify_ccel_against_rtmrs(LIVE_CCEL, &rtmr0, &rtmr1, &rtmr2, &rtmr3);
        assert!(
            matches!(result, Ok(true)),
            "CCEL replay should match all four RTMRs: {result:?}"
        );
    }

    #[test]
    fn test_verify_ccel_tampered_boot_rtmr_fails() {
        const TDINFO: usize = 512;
        let rtmr0: [u8; 48] = LIVE_TDREPORT[TDINFO + 208..TDINFO + 256]
            .try_into()
            .unwrap();
        let rtmr1: [u8; 48] = LIVE_TDREPORT[TDINFO + 256..TDINFO + 304]
            .try_into()
            .unwrap();
        let rtmr3: [u8; 48] = LIVE_TDREPORT[TDINFO + 352..TDINFO + 400]
            .try_into()
            .unwrap();
        // Wrong boot-time register (RTMR[2]) must hard-fail.
        let mut rtmr2 = [0u8; 48];
        rtmr2[0] = 0xFF;

        let result = verify_ccel_against_rtmrs(LIVE_CCEL, &rtmr0, &rtmr1, &rtmr2, &rtmr3);
        assert!(result.is_err(), "tampered RTMR[2] should fail verification");
    }

    #[test]
    fn test_verify_ccel_runtime_extended_rtmr3_passes() {
        const TDINFO: usize = 512;
        let rtmr0: [u8; 48] = LIVE_TDREPORT[TDINFO + 208..TDINFO + 256]
            .try_into()
            .unwrap();
        let rtmr1: [u8; 48] = LIVE_TDREPORT[TDINFO + 256..TDINFO + 304]
            .try_into()
            .unwrap();
        let rtmr2: [u8; 48] = LIVE_TDREPORT[TDINFO + 304..TDINFO + 352]
            .try_into()
            .unwrap();
        // A guest-side runtime extend (e.g. operator-key binding) changes
        // RTMR[3] without a CCEL entry; replay diverges but verification
        // must still pass (warn-only).
        let rtmr3_base: [u8; 48] = LIVE_TDREPORT[TDINFO + 352..TDINFO + 400]
            .try_into()
            .unwrap();
        use sha2::{Digest, Sha384};
        let mut hasher = Sha384::new();
        hasher.update(rtmr3_base);
        hasher.update([0xAB; 48]);
        let mut rtmr3 = [0u8; 48];
        rtmr3.copy_from_slice(&hasher.finalize());

        let result = verify_ccel_against_rtmrs(LIVE_CCEL, &rtmr0, &rtmr1, &rtmr2, &rtmr3);
        assert!(
            matches!(result, Ok(false)),
            "runtime-extended RTMR[3] must not fail eventlog verification: {result:?}"
        );
    }
}
