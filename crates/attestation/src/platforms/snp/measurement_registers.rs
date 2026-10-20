//! Kernel measurement registers for bare-metal SEV-SNP guests.
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
pub struct MeasurementRegisters {
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

/// Replay the first `event_count` entries of `log` from zero registers;
/// `None` when the log has fewer entries. A log that is not whole entries
/// naming registers 0 to 15 is malformed, whatever the count.
pub fn replay(log: &[u8], event_count: u32) -> Result<Option<[Register; REGISTER_COUNT]>> {
    if !log.len().is_multiple_of(ENTRY_LEN) {
        return Err(bad_log(format!(
            "length {} is not whole entries",
            log.len()
        )));
    }
    if let Some(entry) = log
        .as_chunks::<ENTRY_LEN>()
        .0
        .iter()
        .find(|e| e[0] as usize >= REGISTER_COUNT)
    {
        return Err(bad_log(format!("register index {} above 15", entry[0])));
    }
    if log.len() / ENTRY_LEN < event_count as usize {
        return Ok(None);
    }
    let mut registers = [[0u8; 48]; REGISTER_COUNT];
    for entry in log
        .as_chunks::<ENTRY_LEN>()
        .0
        .iter()
        .take(event_count as usize)
    {
        extend(&mut registers[entry[0] as usize], &entry[1..]);
    }
    Ok(Some(registers))
}

/// The registers that `reported` (a report's `REPORT_DATA`) commits to with
/// `caller_data`, replayed from `log`; `None` when `reported` is not that
/// commitment. Err only for a malformed log.
pub fn verify(
    reported: &[u8; 64],
    log: &[u8],
    caller_data: &[u8; 64],
) -> Result<Option<MeasurementRegisters>> {
    let event_count = u32::from_le_bytes(reported[..4].try_into().unwrap());
    let Some(registers) = replay(log, event_count)? else {
        return Ok(None);
    };
    let expected = report_data(event_count, &registers, caller_data);
    Ok(
        crate::utils::constant_time_eq(reported, &expected).then(|| MeasurementRegisters {
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

    fn verify_vector(v: &Vector) -> Result<Option<MeasurementRegisters>> {
        verify(&v.report_data, &v.log, &v.caller_data)
    }

    #[test]
    fn golden_vectors() {
        for v in vectors() {
            let registers = replay(&v.log, v.event_count).unwrap().unwrap();
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
    fn a_malformed_log_is_an_error_whatever_the_count() {
        let v = prefix_vector();
        assert!(verify_vector(&v).unwrap().is_some());
        let mut past_the_count = v.log.clone();
        past_the_count[4 * ENTRY_LEN] = 16;
        let mut trailing = v.log.clone();
        trailing.push(0);
        for log in [past_the_count, trailing] {
            assert!(verify(&v.report_data, &log, &v.caller_data).is_err());
        }
    }

    #[test]
    fn rejected_golden_vectors() {
        let json: serde_json::Value = serde_json::from_str(VECTORS).unwrap();
        let hex = |v: &serde_json::Value| hex::decode(v.as_str().unwrap()).unwrap();
        let rejected = json["rejected"].as_array().unwrap();
        assert!(!rejected.is_empty());
        for v in rejected {
            let result = verify(
                &hex(&v["report_data"]).try_into().unwrap(),
                &hex(&v["event_log"]),
                &hex(&v["caller_data"]).try_into().unwrap(),
            );
            match v["expect"].as_str().unwrap() {
                "malformed" => assert!(result.is_err(), "{}", v["name"]),
                "mismatch" => assert!(result.unwrap().is_none(), "{}", v["name"]),
                other => panic!("unknown expectation {other}"),
            }
        }
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
        assert!(
            verify_vector(&v).unwrap().is_none(),
            "log shorter than the count"
        );
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

    /// A seeded xorshift64* generator, so property cases are reproducible.
    struct Rng(u64);

    impl Rng {
        fn next(&mut self) -> u64 {
            self.0 ^= self.0 >> 12;
            self.0 ^= self.0 << 25;
            self.0 ^= self.0 >> 27;
            self.0.wrapping_mul(0x2545_F491_4F6C_DD1D)
        }
        fn below(&mut self, n: usize) -> usize {
            (self.next() % n as u64) as usize
        }
        fn bytes<const N: usize>(&mut self) -> [u8; N] {
            std::array::from_fn(|_| self.next() as u8)
        }
        fn log(&mut self, entries: usize) -> Vec<u8> {
            (0..entries)
                .flat_map(|_| {
                    let mut entry = vec![self.below(REGISTER_COUNT) as u8];
                    entry.extend(self.bytes::<48>());
                    entry
                })
                .collect()
        }
    }

    fn flip_bit(bytes: &mut [u8], rng: &mut Rng) {
        let bit = rng.below(bytes.len() * 8);
        bytes[bit / 8] ^= 1 << (bit % 8);
    }

    const CASES: usize = 10_000;

    #[test]
    fn any_commitment_round_trips_and_any_flip_in_it_is_rejected() {
        let mut rng = Rng(0x5eed_6b6d_7231);
        for case in 0..CASES {
            let entries = rng.below(41);
            let log = rng.log(entries);
            let event_count = rng.below(entries + 1) as u32;
            let caller_data = rng.bytes::<64>();
            let registers = replay(&log, event_count).unwrap().unwrap();
            for (i, register) in registers.iter().enumerate() {
                let named = log
                    .as_chunks::<ENTRY_LEN>()
                    .0
                    .iter()
                    .take(event_count as usize)
                    .any(|e| e[0] as usize == i);
                assert_eq!(*register != [0; 48], named, "case {case}");
            }
            let reported = report_data(event_count, &registers, &caller_data);
            let verified = verify(&reported, &log, &caller_data).unwrap().unwrap();
            assert_eq!(verified.event_count, event_count, "case {case}");
            assert_eq!(verified.registers, registers.to_vec(), "case {case}");

            let committed = event_count as usize * ENTRY_LEN;
            let (mut log2, mut caller2, mut reported2) = (log.clone(), caller_data, reported);
            let target = match rng.below(4) {
                0 if committed > 0 => {
                    flip_bit(&mut log2[..committed], &mut rng);
                    "committed log"
                }
                1 => {
                    flip_bit(&mut caller2, &mut rng);
                    "caller data"
                }
                2 if committed < log.len() => {
                    flip_bit(&mut log2[committed..], &mut rng);
                    "log past the count"
                }
                _ => {
                    flip_bit(&mut reported2, &mut rng);
                    "report data"
                }
            };
            let result = verify(&reported2, &log2, &caller2);
            if target == "log past the count" {
                match result {
                    Ok(Some(r)) => assert_eq!(r, verified, "case {case}"),
                    Ok(None) => panic!("case {case}: a flip past the count changed the answer"),
                    Err(_) => assert!(log2.as_chunks::<ENTRY_LEN>().0.iter().any(|e| e[0] > 15)),
                }
            } else {
                assert!(
                    !matches!(result, Ok(Some(_))),
                    "case {case}: a flip in the {target} still verified"
                );
            }
        }
    }

    #[test]
    fn arbitrary_bytes_give_an_answer_by_the_error_contract() {
        let mut rng = Rng(0x0dd_b17e5);
        for case in 0..CASES {
            let mut reported = rng.bytes::<64>();
            if rng.below(2) == 0 {
                reported[..4].copy_from_slice(&(rng.below(8) as u32).to_le_bytes());
            }
            let entries = rng.below(8);
            let mut log = rng.log(entries);
            match rng.below(3) {
                0 => {
                    let junk = rng.below(ENTRY_LEN);
                    log.extend((0..junk).map(|_| rng.next() as u8));
                }
                1 if !log.is_empty() => {
                    let i = rng.below(log.len() / ENTRY_LEN) * ENTRY_LEN;
                    log[i] = rng.next() as u8;
                }
                _ => {}
            }
            let malformed = !log.len().is_multiple_of(ENTRY_LEN)
                || log.as_chunks::<ENTRY_LEN>().0.iter().any(|e| e[0] > 15);
            match verify(&reported, &log, &rng.bytes::<64>()) {
                Err(_) => assert!(malformed, "case {case}"),
                Ok(answer) => assert!(!malformed && answer.is_none(), "case {case}"),
            }
        }
    }
}
