//! Kernel runtime measurement registers for bare-metal SEV-SNP guests.
//!
//! The guest kernel holds 16 SHA-384 registers and a log of every extend, and
//! writes `H || C` into the `REPORT_DATA` of every report it requests:
//!
//! - `H` = `event_count` (u32 LE) || 12 zero bytes;
//! - `C` = SHA-384(`"snp-kmr-v1"` || `H` || `R[0]` || … || `R[15]` || caller_data),
//!   where caller_data is the 64 bytes the requester asked for.
//!
//! Registers start at zero; an extend with digest `d` is
//! `R[i] = SHA-384(R[i] || d)`; each log entry is `i` (u8) || `d` (48 bytes).

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha384};

use crate::error::{AttestationError, Result};
use crate::utils::b64;

pub const REGISTER_COUNT: usize = 16;
pub const ENTRY_LEN: usize = 49;
const TAG: &[u8] = b"snp-kmr-v1";

pub type Register = [u8; 48];

/// The registers a report commits to: the replay of the first
/// `event_count` log entries.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RuntimeRegisters {
    pub event_count: u32,
    #[serde(with = "b64::digest_list")]
    pub registers: Vec<Register>,
}

pub fn extend(register: &mut Register, digest: &[u8]) {
    *register = Sha384::new()
        .chain_update(*register)
        .chain_update(digest)
        .finalize()
        .into();
}

pub fn header(event_count: u32) -> [u8; 16] {
    let mut h = [0u8; 16];
    h[..4].copy_from_slice(&event_count.to_le_bytes());
    h
}

pub fn report_data(
    event_count: u32,
    registers: &[Register; REGISTER_COUNT],
    caller_data: &[u8; 64],
) -> [u8; 64] {
    let h = header(event_count);
    let mut c = Sha384::new().chain_update(TAG).chain_update(h);
    for r in registers {
        c.update(r);
    }
    c.update(caller_data);
    let mut out = [0u8; 64];
    out[..16].copy_from_slice(&h);
    out[16..].copy_from_slice(&c.finalize());
    out
}

/// Replay the first `event_count` entries of `log` from zero registers.
pub fn replay(log: &[u8], event_count: u32) -> Result<[Register; REGISTER_COUNT]> {
    if log.len() / ENTRY_LEN < event_count as usize {
        return Err(bad_log(format!(
            "{event_count} events committed, log is shorter"
        )));
    }
    let mut registers = [[0u8; 48]; REGISTER_COUNT];
    for entry in log.chunks_exact(ENTRY_LEN).take(event_count as usize) {
        let register = registers
            .get_mut(entry[0] as usize)
            .ok_or_else(|| bad_log(format!("register index {} above 15", entry[0])))?;
        extend(register, &entry[1..]);
    }
    Ok(registers)
}

/// The registers that `reported` (a report's `REPORT_DATA`) commits to with
/// `caller_data`, replayed from `log`; `None` when `reported` is not that
/// commitment.
pub fn verify(
    reported: &[u8; 64],
    log: &[u8],
    caller_data: &[u8; 64],
) -> Result<Option<RuntimeRegisters>> {
    let event_count = u32::from_le_bytes(reported[..4].try_into().unwrap());
    let registers = replay(log, event_count)?;
    let expected = report_data(event_count, &registers, caller_data);
    Ok(
        crate::utils::constant_time_eq(reported, &expected).then(|| RuntimeRegisters {
            event_count,
            registers: registers.to_vec(),
        }),
    )
}

fn bad_log(msg: String) -> AttestationError {
    AttestationError::EvidenceDeserialize(format!("SNP event log: {msg}"))
}

#[cfg(test)]
mod tests {
    use super::*;

    const VECTORS: &str = include_str!("../../../test_data/snp/kmr-vectors.json");

    struct Vector {
        caller_data: [u8; 64],
        log: Vec<u8>,
        event_count: u32,
        registers: Vec<Register>,
        report_data: [u8; 64],
    }

    fn vectors() -> Vec<Vector> {
        let json: serde_json::Value = serde_json::from_str(VECTORS).unwrap();
        let hex = |v: &serde_json::Value| hex::decode(v.as_str().unwrap()).unwrap();
        json["vectors"]
            .as_array()
            .unwrap()
            .iter()
            .map(|v| Vector {
                caller_data: hex(&v["caller_data"]).try_into().unwrap(),
                log: hex(&v["event_log"]),
                event_count: v["event_count"].as_u64().unwrap() as u32,
                registers: v["registers"]
                    .as_array()
                    .unwrap()
                    .iter()
                    .map(|r| hex(r).try_into().unwrap())
                    .collect(),
                report_data: hex(&v["report_data"]).try_into().unwrap(),
            })
            .collect()
    }

    /// A vector with events in several registers and a longer log than it commits to.
    fn prefix_vector() -> Vector {
        let v = vectors().swap_remove(3);
        assert!(v.event_count == 4 && v.log.len() == 5 * ENTRY_LEN);
        v
    }

    fn verify_vector(v: &Vector) -> Result<Option<RuntimeRegisters>> {
        verify(&v.report_data, &v.log, &v.caller_data)
    }

    #[test]
    fn golden_vectors() {
        for v in vectors() {
            let registers = replay(&v.log, v.event_count).unwrap();
            assert_eq!(registers.to_vec(), v.registers);
            assert_eq!(
                report_data(v.event_count, &registers, &v.caller_data),
                v.report_data
            );
            let verified = verify_vector(&v).unwrap().expect("commitment matches");
            assert_eq!(verified.event_count, v.event_count);
            assert_eq!(verified.registers, v.registers);
        }
    }

    #[test]
    fn a_changed_log_entry_is_rejected() {
        let mut v = prefix_vector();
        assert!(verify_vector(&v).unwrap().is_some());
        v.log[ENTRY_LEN + 10] ^= 1;
        assert!(verify_vector(&v).unwrap().is_none());
    }

    #[test]
    fn a_moved_log_entry_is_rejected() {
        let mut v = prefix_vector();
        assert!(verify_vector(&v).unwrap().is_some());
        v.log[0] = 2;
        assert!(verify_vector(&v).unwrap().is_none());
        v.log[0] = 16;
        assert!(verify_vector(&v).is_err());
    }

    #[test]
    fn entries_past_the_committed_count_are_not_attested() {
        let mut v = prefix_vector();
        v.log[4 * ENTRY_LEN + 10] ^= 1;
        assert!(verify_vector(&v).unwrap().is_some());
    }

    #[test]
    fn a_commitment_over_other_registers_is_rejected() {
        let v = prefix_vector();
        let mut registers: [Register; REGISTER_COUNT] = v.registers.clone().try_into().unwrap();
        assert!(verify(
            &report_data(4, &registers, &v.caller_data),
            &v.log,
            &v.caller_data
        )
        .unwrap()
        .is_some());
        registers[1][0] ^= 1;
        let forged = report_data(4, &registers, &v.caller_data);
        assert!(verify(&forged, &v.log, &v.caller_data).unwrap().is_none());
    }

    #[test]
    fn a_changed_event_count_is_rejected() {
        let mut v = prefix_vector();
        assert!(verify_vector(&v).unwrap().is_some());
        v.report_data[0] = 3;
        assert!(verify_vector(&v).unwrap().is_none());
        v.report_data[0] = 6;
        assert!(verify_vector(&v).is_err(), "log shorter than the count");
    }

    #[test]
    fn other_caller_data_is_rejected() {
        let mut v = prefix_vector();
        assert!(verify_vector(&v).unwrap().is_some());
        v.caller_data[63] ^= 1;
        assert!(verify_vector(&v).unwrap().is_none());
    }

    #[test]
    fn nonzero_header_padding_is_rejected() {
        let mut v = prefix_vector();
        assert!(verify_vector(&v).unwrap().is_some());
        v.report_data[15] = 1;
        assert!(verify_vector(&v).unwrap().is_none());
    }
}
