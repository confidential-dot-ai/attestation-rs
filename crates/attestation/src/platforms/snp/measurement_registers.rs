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

    fn entry(index: u8, byte: u8) -> Vec<u8> {
        let mut entry = vec![index];
        entry.extend([byte; 48]);
        entry
    }

    fn hex<const N: usize>(s: &str) -> [u8; N] {
        hex::decode(s).unwrap().try_into().unwrap()
    }

    struct Vector {
        caller_data: [u8; 64],
        log: Vec<u8>,
        report_data: [u8; 64],
    }

    /// Four events in registers 0, 1, 0 and 15, and a fifth entry past the
    /// count. The expected values are from Python hashlib.
    fn prefix_vector() -> Vector {
        let mut log = [entry(0, 1), entry(1, 2), entry(0, 3), entry(15, 4)].concat();
        log.extend(entry(4, 5));
        Vector {
            caller_data: [7; 64],
            log,
            report_data: hex("0400000000000000000000000000000099bc02ea57ae232704f512bcc942c10c023dd6bc7efedde64bb6fc4f0b8ed443b6e6183e3db85da964f4768e0129b6f1"),
        }
    }

    fn verify_vector(v: &Vector) -> Result<Option<MeasurementRegisters>> {
        verify(&v.report_data, &v.log, &v.caller_data)
    }

    #[test]
    fn known_answers() {
        let caller_data: [u8; 64] = std::array::from_fn(|i| i as u8);
        let genesis = hex("00000000000000000000000000000000d48e8448c5430f57994fb15caa1855aa3fa0f03b6e4c91511aa3f83b363ad4474bb701d740aac53b0cfabba7c2ffa6a7");
        let verified = verify(&genesis, &[], &caller_data).unwrap().unwrap();
        assert_eq!(verified.event_count, 0);
        assert_eq!(verified.registers, vec![[0; 48]; REGISTER_COUNT]);

        let v = prefix_vector();
        let mut expected = vec![[0; 48]; REGISTER_COUNT];
        expected[0] = hex("6198ab2caaa45d0bcc5d1f27e7c4a763f5518d272c0d74c2166aec2c5d280418d9d341caf10434d4f87a4921778d2d6a");
        expected[1] = hex("66f60db53f35b91eb7f71aad347e076712169849778651cebd1b6f3c3b5eb756820617468d20330a8ea9913f60c1cc55");
        expected[15] = hex("273130d1fd0a53dad497ed8fc5c79d3c9f3c16963ff6cfac62b5890eeea1fc9bef91b9fefb568e5cdf375bcdbdcc817b");
        let verified = verify_vector(&v).unwrap().unwrap();
        assert_eq!(verified.event_count, 4);
        assert_eq!(verified.registers, expected);
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
    fn rejected_cases() {
        let v = prefix_vector();
        assert!(verify_vector(&v).unwrap().is_some());
        let four = &v.log[..4 * ENTRY_LEN];
        let with = |log: &[u8], at: usize, value: u8| {
            let mut log = log.to_vec();
            log[at] = value;
            log
        };
        let mut padding = v.report_data;
        padding[15] = 1;
        let mut other_caller = v.caller_data;
        other_caller[63] ^= 1;
        let reordered = [
            &four[2 * ENTRY_LEN..3 * ENTRY_LEN],
            &four[ENTRY_LEN..2 * ENTRY_LEN],
            &four[..ENTRY_LEN],
            &four[3 * ENTRY_LEN..],
        ]
        .concat();
        let malformed = [
            ("index above 15", with(four, 3 * ENTRY_LEN, 16)),
            (
                "index above 15 past the count",
                with(&v.log, 4 * ENTRY_LEN, 16),
            ),
            ("trailing partial entry", [four, &[0]].concat()),
        ];
        for (name, log) in malformed {
            assert!(
                verify(&v.report_data, &log, &v.caller_data).is_err(),
                "{name}"
            );
        }
        let mismatch = [
            (
                "log shorter than the count",
                &four[..3 * ENTRY_LEN],
                v.report_data,
                v.caller_data,
            ),
            ("nonzero header padding", four, padding, v.caller_data),
            (
                "reordered within a register",
                &reordered,
                v.report_data,
                v.caller_data,
            ),
            ("other caller data", four, v.report_data, other_caller),
        ];
        for (name, log, reported, caller_data) in mismatch {
            assert!(
                verify(&reported, log, &caller_data).unwrap().is_none(),
                "{name}"
            );
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
        let mut registers = replay(&v.log, 4).unwrap().unwrap();
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
