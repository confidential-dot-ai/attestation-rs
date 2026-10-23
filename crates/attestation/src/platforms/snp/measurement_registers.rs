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

use base64::{engine::general_purpose::STANDARD as BASE64, Engine};

use super::verify::SnpResult;
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

/// Replay the event log prefix that `report_data` names and replace
/// `report_data_match` with whether `report_data` commits to it and
/// `caller_data`. Registers are compared with `expected` only when the
/// launch digest pin also held (without the provider the commitment means
/// nothing), and exposed only when the whole result passed.
pub(super) fn check_measurement_registers(
    result: &mut SnpResult,
    report_data: &[u8; 64],
    event_log: Option<&str>,
    caller_data: &[u8; 64],
    expected: &[[u8; 48]],
) -> Result<()> {
    let event_log = event_log.unwrap_or_default();
    crate::utils::check_field_size("event_log", event_log.len())?;
    let log = BASE64
        .decode(event_log)
        .map_err(|e| AttestationError::EvidenceDeserialize(format!("event_log base64: {e}")))?;
    let registers = verify(report_data, &log, caller_data)?
        .filter(|_| result.launch_digest_match == Some(true));
    result.report_data_match = Some(registers.is_some());
    result.measurement_registers_match = Some(registers.as_ref().is_some_and(|r| {
        r.registers
            .iter()
            .enumerate()
            .all(|(i, value)| *value == expected.get(i).copied().unwrap_or([0; 48]))
    }));
    result.measurement_registers = registers.filter(|_| result.passed());
    Ok(())
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
        let mut lower_count = v.report_data;
        lower_count[0] = 3;
        let mut other_registers = replay(&v.log, 4).unwrap().unwrap();
        other_registers[1][0] ^= 1;
        let over_other_registers = report_data(4, &other_registers, &v.caller_data);
        let moved = with(four, 0, 2);
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
            (
                "an entry moved to another register",
                &moved,
                v.report_data,
                v.caller_data,
            ),
            ("a lower event count", four, lower_count, v.caller_data),
            (
                "a commitment over other registers",
                four,
                over_other_registers,
                v.caller_data,
            ),
        ];
        for (name, log, reported, caller_data) in mismatch {
            assert!(
                verify(&reported, log, &caller_data).unwrap().is_none(),
                "{name}"
            );
        }
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

    // ---------------------------------------------------------------
    // Measurement-register mode through `Snp::verify`
    // ---------------------------------------------------------------

    use super::super::evidence::{SnpCertChain, SnpEvidence};
    use super::super::verify::{parse_report, Snp, SnpParams, SnpResult};
    use crate::platform::Platform;
    use crate::testing;
    use crate::types::ProcessorGeneration;
    use sev::firmware::guest::AttestationReport;

    const LIVE_REPORT_V5: &[u8] = include_bytes!("../../../test_data/snp/live-report-v5-genoa.bin");
    const LIVE_VCEK_GENOA: &[u8] = include_bytes!("../../../test_data/snp/live-vcek-genoa.der");

    fn evidence(report: &[u8], vcek_der: &[u8]) -> SnpEvidence {
        SnpEvidence {
            attestation_report: BASE64.encode(report),
            cert_chain: Some(SnpCertChain {
                vcek: BASE64.encode(vcek_der),
                ask: None,
                ark: None,
            }),
            event_log: None,
        }
    }

    /// Verify the live Genoa report (no measurement-register kernel).
    async fn verify_live(params: &SnpParams) -> Result<SnpResult> {
        testing::verify::<Snp>(
            &evidence(LIVE_REPORT_V5, LIVE_VCEK_GENOA),
            params,
            vec![testing::amd_crl(ProcessorGeneration::Genoa)],
        )
        .await
    }

    fn measurement_params(report: &AttestationReport) -> SnpParams {
        SnpParams {
            report_data: Some(vec![7; 64]),
            launch_digest: Some(vec![report.measurement]),
            measurement_registers: Some(vec![]),
            ..Default::default()
        }
    }

    #[test]
    fn measurement_register_params_need_the_strict_mode() {
        let report = parse_report(LIVE_REPORT_V5).unwrap();
        let ok = measurement_params(&report);
        ok.validate().unwrap();
        // Debug is the caller's choice, as for any SNP report.
        SnpParams {
            allow_debug: true,
            ..ok.clone()
        }
        .validate()
        .unwrap();
        SnpParams {
            measurement_registers: Some(vec![[1; 48]; 16]),
            ..ok.clone()
        }
        .validate()
        .unwrap();
        let bad = [
            SnpParams {
                report_data: Some(vec![7; 63]),
                ..ok.clone()
            },
            SnpParams {
                report_data: None,
                ..ok.clone()
            },
            SnpParams {
                launch_digest: None,
                ..ok.clone()
            },
            SnpParams {
                max_vmpl: 1,
                ..ok.clone()
            },
            SnpParams {
                measurement_registers: Some(vec![[1; 48]; 17]),
                ..ok.clone()
            },
        ];
        for params in bad {
            assert!(params.validate().is_err(), "{params:?}");
        }
    }

    #[test]
    fn measurement_registers_are_an_ordered_list_in_json() {
        let parse = |registers: &str| {
            serde_json::from_str::<SnpParams>(&format!(
                r#"{{"measurement_registers":{registers}}}"#
            ))
            .map(|p| p.measurement_registers)
        };
        let r0 = BASE64.encode([1; 48]);
        assert_eq!(parse("null").unwrap(), None);
        assert_eq!(parse("[]").unwrap(), Some(vec![]));
        assert_eq!(
            parse(&format!(r#"["{r0}","{}"]"#, BASE64.encode([0; 48]))).unwrap(),
            Some(vec![[1; 48], [0; 48]])
        );
        assert!(
            parse(&format!(r#""{r0}""#)).is_err(),
            "one value is not a list"
        );
        let params = SnpParams {
            measurement_registers: Some(vec![]),
            ..Default::default()
        };
        let json = serde_json::to_value(&params).unwrap();
        assert_eq!(json["measurement_registers"], serde_json::json!([]));
        // Unset, the field is left out, so parsers that predate it accept the JSON.
        let json = serde_json::to_value(SnpParams::default()).unwrap();
        assert!(json.get("measurement_registers").is_none());
    }

    #[test]
    fn evidence_without_an_event_log_leaves_the_field_out() {
        // Verifiers that predate `event_log` refuse unknown fields, so evidence
        // from a kernel without the provider must not name it.
        let plain = evidence(LIVE_REPORT_V5, LIVE_VCEK_GENOA);
        let with_log = SnpEvidence {
            event_log: Some(BASE64.encode(entry(0, 1))),
            ..plain.clone()
        };
        assert!(serde_json::to_value(with_log)
            .unwrap()
            .get("event_log")
            .is_some());
        assert!(serde_json::to_value(plain)
            .unwrap()
            .get("event_log")
            .is_none());
    }

    #[tokio::test]
    async fn measurement_register_mode_without_an_event_log_fails_even_on_the_callers_bytes() {
        // An image without the provider passes the caller's bytes through as
        // REPORT_DATA; the evidence carries no event log.
        let report = parse_report(LIVE_REPORT_V5).unwrap();
        let plain = SnpParams {
            report_data: Some(report.report_data.to_vec()),
            launch_digest: Some(vec![report.measurement]),
            ..Default::default()
        };
        assert!(verify_live(&plain).await.unwrap().passed());
        let r = verify_live(&SnpParams {
            measurement_registers: Some(vec![]),
            ..plain
        })
        .await
        .unwrap();
        assert_eq!(r.report_data_match, Some(false));
        assert!(r.measurement_registers.is_none() && !r.passed());
    }

    // ---------------------------------------------------------------
    // Hardware fixtures: Genoa guest kernels with measurement registers
    // ---------------------------------------------------------------

    /// The VCEK of the Genoa chip all the kernel fixtures ran on (issued 2026-10-19).
    const KMR_VCEK: &[u8] = include_bytes!("../../../test_data/snp/kmr-vcek.der");
    // The measurement-register kernel guest (launch digest 5d931eed…) after a
    // full log: 4096 events, then extend fails with ENOSPC; 2026-10-20.
    const KMR_REPORT: &[u8] = include_bytes!("../../../test_data/snp/kmr-full-report.bin");
    const KMR_EVENT_LOG: &[u8] = include_bytes!("../../../test_data/snp/kmr-full-event-log.bin");
    const KMR_CALLER_DATA: &[u8] =
        include_bytes!("../../../test_data/snp/kmr-full-caller-data.bin");

    /// The registers after the whole log, replayed with sha2 directly rather
    /// than with `measurement_registers`.
    fn kmr_expected() -> Vec<[u8; 48]> {
        use sha2::{Digest, Sha384};
        let mut registers = vec![[0u8; 48]; 16];
        for entry in KMR_EVENT_LOG.chunks(49) {
            let r = &mut registers[entry[0] as usize];
            *r = Sha384::new()
                .chain_update(*r)
                .chain_update(&entry[1..])
                .finalize()
                .into();
        }
        registers
    }

    fn kmr_params() -> SnpParams {
        SnpParams {
            report_data: Some(KMR_CALLER_DATA.to_vec()),
            launch_digest: Some(vec![parse_report(KMR_REPORT).unwrap().measurement]),
            measurement_registers: Some(kmr_expected()),
            ..Default::default()
        }
    }

    async fn verify_kmr_with(report: &[u8], event_log: &[u8], params: &SnpParams) -> SnpResult {
        try_verify_kmr(report, event_log, params).await.unwrap()
    }

    /// Verify a kernel fixture at 2026-10-20, inside its VCEK's window.
    async fn try_verify_kmr(
        report: &[u8],
        event_log: &[u8],
        params: &SnpParams,
    ) -> Result<SnpResult> {
        const AT: i64 = 1_792_454_400;
        let mut evidence = evidence(report, KMR_VCEK);
        evidence.event_log = Some(BASE64.encode(event_log));
        let ctx = crate::context::Context::held(vec![testing::amd_crl(ProcessorGeneration::Genoa)])
            .at(AT)
            .unwrap();
        let (collateral, _) = Snp::gather(&evidence, ctx.store(), AT).await.unwrap();
        Snp::verify(&evidence, params, &collateral, AT)
    }

    #[tokio::test]
    async fn a_kernel_report_verifies_with_its_registers() {
        assert_eq!(KMR_EVENT_LOG.len(), 4096 * ENTRY_LEN);
        let r = verify_kmr_with(KMR_REPORT, KMR_EVENT_LOG, &kmr_params()).await;
        assert_eq!(r.report_data_match, Some(true));
        let registers = r.measurement_registers.as_ref().unwrap();
        assert_eq!(registers.event_count, 4096);
        assert_eq!(registers.registers, kmr_expected());
        assert!(registers.registers.iter().all(|r| *r != [0; 48]));
        assert_eq!(r.measurement_registers_match, Some(true));
        assert!(r.passed());

        let mut other_caller = kmr_params();
        other_caller.report_data.as_mut().unwrap()[0] ^= 1;
        let r = verify_kmr_with(KMR_REPORT, KMR_EVENT_LOG, &other_caller).await;
        assert_eq!(r.report_data_match, Some(false));
        assert!(r.measurement_registers.is_none() && !r.passed());

        let mut other_log = KMR_EVENT_LOG.to_vec();
        other_log[60] ^= 1;
        let r = verify_kmr_with(KMR_REPORT, &other_log, &kmr_params()).await;
        assert_eq!(r.report_data_match, Some(false));
        assert!(r.measurement_registers.is_none() && !r.passed());

        let mut other_value = kmr_params();
        other_value.measurement_registers.as_mut().unwrap()[15][47] ^= 1;
        let mut shorter_list = kmr_params();
        shorter_list
            .measurement_registers
            .as_mut()
            .unwrap()
            .truncate(15);
        for params in [other_value, shorter_list] {
            let r = verify_kmr_with(KMR_REPORT, KMR_EVENT_LOG, &params).await;
            assert_eq!(r.measurement_registers_match, Some(false));
            assert!(!r.passed());
        }
    }

    #[tokio::test]
    async fn a_kernel_log_follows_the_error_contract() {
        let params = kmr_params();
        let log = |change: &dyn Fn(&mut Vec<u8>)| {
            let mut log = KMR_EVENT_LOG.to_vec();
            change(&mut log);
            log
        };
        // Bytes that are not whole entries are malformed, whatever the count.
        for junk in [1, 48] {
            let bad = log(&|l| l.extend(vec![0; junk]));
            let err = try_verify_kmr(KMR_REPORT, &bad, &params).await;
            assert!(
                matches!(err, Err(AttestationError::EvidenceDeserialize(_))),
                "{junk} trailing bytes"
            );
        }
        // A whole entry past the count is not attested and changes nothing.
        let longer = log(&|l| {
            l.push(3);
            l.extend([9; 48]);
        });
        let r = verify_kmr_with(KMR_REPORT, &longer, &params).await;
        assert_eq!(r.measurement_registers.as_ref().unwrap().event_count, 4096);
        assert!(r.passed());
        // A log shorter than the count is a mismatch, not an error.
        for shorter in [log(&|l| l.truncate(4095 * ENTRY_LEN)), Vec::new()] {
            let r = verify_kmr_with(KMR_REPORT, &shorter, &params).await;
            assert_eq!(r.report_data_match, Some(false));
            assert!(r.measurement_registers.is_none() && !r.passed());
        }
    }

    #[tokio::test]
    async fn snp_verify_refuses_params_validate_refuses() {
        let ok = kmr_params();
        assert!(verify_kmr_with(KMR_REPORT, KMR_EVENT_LOG, &ok)
            .await
            .passed());
        let bad = SnpParams { max_vmpl: 1, ..ok };
        let r = try_verify_kmr(KMR_REPORT, KMR_EVENT_LOG, &bad).await;
        assert!(matches!(r, Err(AttestationError::InvalidParams(_))));
    }

    #[tokio::test]
    async fn an_event_log_above_the_field_limit_is_refused() {
        // Whole zero entries, just over the 1 MiB base64 limit: without the
        // limit this decodes to a well-formed log that is only a mismatch.
        let log = vec![0; 147 * 5350];
        assert!(BASE64.encode(&log).len() > crate::utils::MAX_EVIDENCE_FIELD_SIZE);
        let r = try_verify_kmr(KMR_REPORT, &log, &kmr_params()).await;
        assert!(matches!(r, Err(AttestationError::EvidenceDeserialize(_))));
    }

    #[tokio::test]
    async fn a_kernel_report_above_vmpl_0_fails() {
        // SNP_GET_REPORT with req.vmpl = 1 from the measurement-register kernel
        // guest (launch digest d6c2c431…), committing to the first 6 entries
        // of its log and its caller data; 2026-10-20.
        let report = include_bytes!("../../../test_data/snp/kmr-vmpl/vmpl1.report.bin");
        let log = include_bytes!("../../../test_data/snp/kmr-vmpl/event-log.bin");
        let caller = include_bytes!("../../../test_data/snp/kmr-vmpl/caller-data.bin");
        // The expectation is the log's own replay, so only the VMPL can fail.
        let params = SnpParams {
            report_data: Some(caller.to_vec()),
            launch_digest: Some(vec![parse_report(report).unwrap().measurement]),
            measurement_registers: Some(replay(log, 6).unwrap().unwrap().to_vec()),
            ..Default::default()
        };
        let r = verify_kmr_with(report, log, &params).await;
        assert_eq!(r.vmpl, 1);
        assert_eq!(r.report_data_match, Some(true));
        assert_eq!(r.measurement_registers_match, Some(true));
        assert!(!r.passed() && r.measurement_registers.is_none());
        let accepting_vmpl1 = SnpResult { max_vmpl: 1, ..r };
        assert!(accepting_vmpl1.passed(), "only the VMPL fails");
    }

    /// Guest root on an image without the provider passes a forged `H || C`
    /// as its report data. Only the launch digest pin tells it apart.
    #[tokio::test]
    async fn a_forged_commitment_passes_only_where_its_image_is_pinned() {
        // A guest image built without the provider (launch digest d294414b…),
        // same chip and TCB, 2026-10-20. Guest root asked for a report with
        // user_data = H || C computed off-guest over event-log.bin (mr1, mr4
        // extended with "forged: …" digests) and caller-data.bin.
        let report = include_bytes!("../../../test_data/snp/kmr-forge/report.bin");
        let log = include_bytes!("../../../test_data/snp/kmr-forge/event-log.bin");
        let caller = include_bytes!("../../../test_data/snp/kmr-forge/caller-data.bin");
        let hex48 = |s: &str| -> [u8; 48] { hex::decode(s).unwrap().try_into().unwrap() };
        let forged = vec![
            [0; 48],
            hex48("faef475db093da0bf48d02e58db273cf2efd9cc33fea6f75c86b094c9f2352b73c7021e4629e7f784f97893febebfc0d"),
            [0; 48],
            [0; 48],
            hex48("9447d432169ab5914449fe9c0cc297b1ed8fca7b9a934151a81d174ab72df392fdd6e0305ff7c1587254f511381d9efa"),
        ];
        let image = parse_report(report).unwrap().measurement;
        let provider = parse_report(KMR_REPORT).unwrap().measurement;
        let params = |launch_digest: Vec<[u8; 48]>| SnpParams {
            report_data: Some(caller.to_vec()),
            launch_digest: Some(launch_digest),
            measurement_registers: Some(forged.clone()),
            ..Default::default()
        };

        let r = verify_kmr_with(report, log, &params(vec![provider])).await;
        assert_eq!(r.launch_digest_match, Some(false));
        assert_eq!(r.report_data_match, Some(false));
        assert_eq!(r.measurement_registers_match, Some(false));
        assert!(r.measurement_registers.is_none() && !r.passed());

        // Pinning the image without the provider, even next to a provider
        // image, accepts the forged registers.
        let r = verify_kmr_with(report, log, &params(vec![provider, image])).await;
        assert_eq!(
            r.measurement_registers.as_ref().unwrap().registers[..5],
            forged[..]
        );
        assert!(r.passed());
    }
}
