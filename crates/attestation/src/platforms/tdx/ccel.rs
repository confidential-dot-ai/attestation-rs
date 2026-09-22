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
//! so any legitimate runtime extend — e.g. the confidential-os operator-key
//! binding, or a per-workload measurer — makes RTMR[3] unreplayable by
//! construction. Relying parties verify `quote.rtmr_3` directly against
//! their own expected value (`expected_rtmr3` / claims).

use sha2::{Digest, Sha384};

use crate::error::{AttestationError, Result};

/// Maximum digest algorithms per event (TCG spec allows ~3; cap at 16 for safety).
/// A parsed CCEL event.
#[derive(Debug, Clone)]
// Parsed for callers of parse_ccel; replay reads only the index and digest.
#[cfg_attr(not(feature = "unstable-internals"), allow(dead_code))]
pub struct CcelEvent {
    /// MR index: 1=RTMR[0], 2=RTMR[1], 3=RTMR[2], 4=RTMR[3].
    pub mr_index: u32,
    /// TCG2 event type (e.g. 0x80000001 = EV_EFI_VARIABLE_DRIVER_CONFIG).
    pub event_type: u32,
    /// SHA-384 digest for this event.
    pub sha384_digest: Vec<u8>,
    /// Raw event data (variable structure, interpretation depends on event_type).
    pub event_data: Vec<u8>,
}

/// Parse a CCEL binary blob into a list of events.
///
/// The first event is a TCG Spec ID Event header (EV_NO_ACTION at PCR 0)
/// which is skipped. Subsequent events are TCG_PCR_EVENT2 structures.
pub fn parse_ccel(data: &[u8]) -> Result<Vec<CcelEvent>> {
    let events = crate::profile::tcg2::parse(data, crate::profile::tcg2::TPM_ALG_SHA384)?;
    Ok(events
        .into_iter()
        .map(|e| CcelEvent {
            mr_index: e.index,
            event_type: e.event_type,
            sha384_digest: e.digest,
            event_data: e.event_data,
        })
        .collect())
}

/// Replay CCEL events to compute RTMR values.
///
/// Each RTMR starts as 48 zero bytes. For each event:
///   `RTMR_new = SHA384(RTMR_old || event_digest)`
///
/// Returns `[RTMR[0], RTMR[1], RTMR[2], RTMR[3]]`.
pub fn replay_rtmrs(events: &[CcelEvent]) -> [[u8; 48]; 4] {
    let mut rtmrs = [[0u8; 48]; 4];

    for event in events {
        let idx = match event.mr_index {
            1 => 0,
            2 => 1,
            3 => 2,
            4 => 3,
            _ => continue,
        };

        let mut hasher = Sha384::new();
        hasher.update(rtmrs[idx]);
        hasher.update(&event.sha384_digest);
        let result = hasher.finalize();
        rtmrs[idx].copy_from_slice(&result);
    }

    rtmrs
}

/// Verify that replayed RTMR values from a CCEL match those in a TDX quote body.
///
/// Enforces RTMR[0-2] only. RTMR[3] is runtime-extendable and such extends
/// never appear in the CCEL (see module docs), so a mismatch there is
/// expected on any guest that runtime-extends and only logs a warning;
/// relying parties verify `quote.rtmr_3` directly.
///
/// Returns `Ok(())` if RTMR[0-2] match, or an error describing the first mismatch.
pub fn verify_ccel_against_rtmrs(
    ccel_data: &[u8],
    rtmr_0: &[u8; 48],
    rtmr_1: &[u8; 48],
    rtmr_2: &[u8; 48],
    rtmr_3: &[u8; 48],
) -> Result<()> {
    let events = parse_ccel(ccel_data)?;
    let replayed = replay_rtmrs(&events);

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

    if !crate::utils::constant_time_eq(&replayed[3], rtmr_3) {
        log::warn!(
            "RTMR[3] replay mismatch (runtime extends are not logged to the CCEL; verify quote.rtmr_3 directly): replayed={}, quote={}",
            hex::encode(replayed[3]),
            hex::encode(rtmr_3)
        );
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    const LIVE_CCEL: &[u8] = include_bytes!("../../../test_data/tdx_ccel_live.bin");
    const LIVE_TDREPORT: &[u8] = include_bytes!("../../../test_data/tdx_tdreport_live.bin");

    #[test]
    fn test_parse_ccel_live() {
        let events = parse_ccel(LIVE_CCEL).expect("failed to parse CCEL");
        assert!(!events.is_empty(), "CCEL should contain events");

        // All events should have 48-byte SHA-384 digests
        for (i, event) in events.iter().enumerate() {
            assert_eq!(
                event.sha384_digest.len(),
                48,
                "event {i} should have 48-byte SHA-384 digest"
            );
            assert!(
                (1..=4).contains(&event.mr_index),
                "event {i} MR index {} out of range",
                event.mr_index
            );
        }
    }

    #[test]
    fn test_replay_rtmrs_match_tdreport() {
        let events = parse_ccel(LIVE_CCEL).expect("parse CCEL");
        let replayed = replay_rtmrs(&events);

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
            result.is_ok(),
            "CCEL replay should match: {:?}",
            result.err()
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
        let mut hasher = Sha384::new();
        hasher.update(rtmr3_base);
        hasher.update([0xAB; 48]);
        let mut rtmr3 = [0u8; 48];
        rtmr3.copy_from_slice(&hasher.finalize());

        let result = verify_ccel_against_rtmrs(LIVE_CCEL, &rtmr0, &rtmr1, &rtmr2, &rtmr3);
        assert!(
            result.is_ok(),
            "runtime-extended RTMR[3] must not fail eventlog verification: {:?}",
            result.err()
        );
    }
}
