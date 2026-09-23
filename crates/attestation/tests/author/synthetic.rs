//! Synthetic cases: the recordings of the authored cases, changed in one
//! place each, so every normative statement a recording can show has a case.
//! A case changes one thing; where an input breaks several rules, the
//! verification order of section 11 decides, and the statement says so.

use super::*;
use attestation::profile::{FixedBytes, TdxFloor};

const TEST_VCEK: &[u8] = include_bytes!("../../test_data/snp/test-vcek.der");
const VLEK_REPORT: &[u8] = include_bytes!("../../test_data/snp/test-vlek-report.bin");
const VLEK: &[u8] = include_bytes!("../../test_data/snp/test-vlek.der");
const DSTACK: &str = include_str!("../../../tcg-cel/tests/data/dstack_tdx_getquote.json");

/// A value with `f` applied.
fn tweak(mut v: Value, f: impl FnOnce(&mut Value)) -> Value {
    f(&mut v);
    v
}

/// `v` written compact with `key: dup` appended to the object at `path`,
/// which already holds `key`: the only way to author a duplicate member.
fn with_duplicate(v: &Value, path: &[&str], key: &str, dup: &Value) -> Input {
    fn emit(v: &Value, path: Option<&[&str]>, key: &str, dup: &Value, out: &mut String) {
        let Value::Object(m) = v else {
            out.push_str(&serde_json::to_string(v).unwrap());
            return;
        };
        out.push('{');
        for (i, (k, x)) in m.iter().enumerate() {
            if i > 0 {
                out.push(',');
            }
            out.push_str(&serde_json::to_string(k).unwrap());
            out.push(':');
            let sub = match path {
                Some([head, rest @ ..]) if *head == k.as_str() => Some(rest),
                _ => None,
            };
            emit(x, sub, key, dup, out);
        }
        if path == Some(&[][..]) {
            assert!(m.contains_key(key), "{key} is not already a member");
            out.push(',');
            out.push_str(&serde_json::to_string(key).unwrap());
            out.push(':');
            out.push_str(&serde_json::to_string(dup).unwrap());
        }
        out.push('}');
    }
    let mut out = String::new();
    emit(v, Some(path), key, dup, &mut out);
    Input::Raw(out.into_bytes())
}

/// `v` written compact and padded with an unknown top-level claim to exactly
/// `size` bytes.
fn padded_to(v: &Value, size: usize) -> Input {
    let base = serde_json::to_string(v).unwrap();
    let head = &base[..base.len() - 1];
    let frame = head.len() + r#","x_padding":""}"#.len();
    assert!(size > frame, "the envelope is already {} bytes", base.len());
    let mut out = String::with_capacity(size);
    out.push_str(head);
    out.push_str(r#","x_padding":""#);
    out.push_str(&"A".repeat(size - frame));
    out.push_str(r#""}"#);
    assert_eq!(out.len(), size);
    Input::Raw(out.into_bytes())
}

fn gpu_device(ueid: &str, arch: &str) -> Value {
    json!({
        "arch": arch,
        "uuid": ueid,
        "evidence_b64": "AA==",
        "cert_chain_b64": "AA==",
        "cvm_binding": {"pattern": "challenge", "mode": "nras-nonce"}
    })
}

/// The Genoa envelope with `n` GPU submodules beside its cpu.
fn with_gpus(nonce: &[u8], n: usize) -> Value {
    tweak(snp_envelope(nonce), |v| {
        for i in 0..n {
            let ueid = format!("GPU-{i:04}");
            v["submods"][format!("gpu/{ueid}")] = gpu_device(&ueid, "HOPPER");
        }
    })
}

/// The CCEL of the live quote as a CEL log in the encoding asked for.
fn cel_log(ccel: &[u8], json: bool) -> Vec<u8> {
    let records =
        attestation::tcg_cel::tcg2::to_cel(ccel, attestation::tcg_cel::tcg2::IndexMap::CcMrToRtmr)
            .unwrap();
    if json {
        attestation::tcg_cel::encode_json(&records)
            .unwrap()
            .into_bytes()
    } else {
        attestation::tcg_cel::encode_cbor(&records).unwrap()
    }
}

fn tdx_with_log(format: &str, data: &[u8]) -> Value {
    tweak(tdx_envelope_with_ccel(LIVE_QUOTE, LIVE_CCEL2), |v| {
        v["submods"]["cpu"]["cvm_log"] = json!({"format": format, "data": b64url(data)});
    })
}

/// dstack's recorded GetQuote response as the profile envelope: the quote,
/// its RTMRs as registers and the event log, bound to its report data.
fn dstack_envelope(event_log: &str) -> Value {
    let d: Value = serde_json::from_str(DSTACK).unwrap();
    let quote = hex::decode(d["quote"].as_str().unwrap()).unwrap();
    let q = attestation::platforms::tdx::verify::parse_tdx_quote(&quote).unwrap();
    let data = q.body.report_data;
    let used = data.len() - data.iter().rev().take_while(|b| **b == 0).count();
    let nonce = &data[..used.max(16)];
    let rtmrs = [q.body.rtmr_0, q.body.rtmr_1, q.body.rtmr_2, q.body.rtmr_3];
    json!({
        "eat_profile": PROFILE_URI,
        "eat_nonce": b64url(nonce),
        "cvm_version": 1,
        "submods": {
            "cpu": {
                "cvm_platform": {"vendor": "intel", "tee": "tdx", "hosting": "dstack"},
                "cvm_report": ["application/vnd.confidential-ai.tdx-quote", b64url(&quote), 4],
                "cvm_binding": {"pattern": "challenge", "mode": "report-data"},
                "cvm_registers": rtmrs.iter().enumerate().map(|(i, r)| json!({
                    "index": i, "alg": "sha384", "value": b64url(r),
                    "source": "tdx-rtmr", "backing": "hardware"
                })).collect::<Vec<_>>(),
                "cvm_log": {"format": "dstack-json", "data": b64url(event_log.as_bytes())}
            }
        }
    })
}

/// dstack's event log with the first runtime event that has a payload changed.
fn dstack_log_with_altered_runtime_event() -> String {
    let d: Value = serde_json::from_str(DSTACK).unwrap();
    let mut log: Value = serde_json::from_str(d["event_log"].as_str().unwrap()).unwrap();
    let event = log
        .as_array_mut()
        .unwrap()
        .iter_mut()
        .find(|e| {
            e["event_type"] == json!(attestation::tcg_cel::dstack::RUNTIME_EVENT_TYPE)
                && e["event_payload"].as_str().is_some_and(|p| !p.is_empty())
        })
        .expect("the recording carries a runtime event with a payload");
    let payload = event["event_payload"].as_str().unwrap().to_string();
    let last = payload.chars().last().unwrap();
    let swapped = if last == '0' { '1' } else { '0' };
    event["event_payload"] = json!(format!("{}{swapped}", &payload[..payload.len() - 1]));
    serde_json::to_string(&log).unwrap()
}

fn snp_floor(bootloader: u8, fmc: Option<u8>) -> TcbFloor {
    TcbFloor {
        snp: Some(SnpFloor {
            min: SnpTcb {
                bootloader,
                tee: 0,
                snp: 0,
                microcode: 0,
                fmc,
            },
            values: SnpTcbValue::all(),
        }),
        tdx: None,
    }
}

fn tdx_floor(svn: Option<[u8; 16]>, evaluation: Option<u32>) -> TcbFloor {
    TcbFloor {
        snp: None,
        tdx: Some(TdxFloor {
            min_tee_tcb_svn: svn.map(FixedBytes),
            min_tcb_evaluation_data_number: evaluation,
        }),
    }
}

/// An Azure envelope whose HCL report (the vtpm's `cvm_tpm_ak.data`) has `f` applied.
fn with_hcl(v: &Value, f: impl FnOnce(&mut Vec<u8>)) -> Value {
    tweak(v.clone(), |v| {
        let ak = &mut v["submods"]["vtpm"]["cvm_tpm_ak"]["data"];
        let mut hcl = Bytes::decode(ak.as_str().unwrap()).unwrap().0;
        f(&mut hcl);
        *ak = json!(b64url(&hcl));
    })
}

/// The Genoa envelope carrying `report` in place of the recorded one.
fn snp_with_report(nonce: &[u8], report: &[u8]) -> Value {
    tweak(snp_envelope(nonce), |v| {
        v["submods"]["cpu"]["cvm_report"][1] = json!(b64url(report));
    })
}

/// The recorded Genoa report with one byte changed after signing.
fn snp_report_with(offset: usize, value: u8) -> Vec<u8> {
    let mut r = SNP_REPORT.to_vec();
    assert_ne!(r[offset], value);
    r[offset] = value;
    r
}

/// A Milan report signed by a VLEK, whose CHIP_ID is all zero, with the VLEK inline.
fn vlek_envelope() -> Value {
    let report = attestation::platforms::snp::verify::parse_report(VLEK_REPORT).unwrap();
    assert!(report.chip_id.iter().all(|b| *b == 0));
    let nonce = attestation::utils::strip_trailing_nulls(&report.report_data).to_vec();
    tweak(snp_envelope(&nonce), |v| {
        let cpu = &mut v["submods"]["cpu"];
        cpu["cvm_report"][1] = json!(b64url(VLEK_REPORT));
        cpu["cvm_endorsements"]["snp.vek"][1] = json!(b64url(VLEK));
    })
}

fn with_policy(base: VerifyPolicy, f: impl FnOnce(&mut VerifyPolicy)) -> VerifyPolicy {
    let mut p = base;
    f(&mut p);
    p
}

pub(super) fn cases() -> Vec<Authored> {
    let nonce = snp_nonce();
    let report = attestation::platforms::snp::verify::parse_report(SNP_REPORT).unwrap();
    let snp = snp_envelope(&nonce);
    let (az_snp, az_nonce) = azure_envelope(AZ_SNP, "az-snp");
    let az_report = {
        let b64 = az_snp["submods"]["cpu"]["cvm_report"][1].as_str().unwrap();
        attestation::platforms::snp::verify::parse_report(&Bytes::decode(b64).unwrap().0).unwrap()
    };
    let az_pcr = |i: usize| -> Vec<u8> {
        let regs = az_snp["submods"]["vtpm"]["cvm_registers"]
            .as_array()
            .unwrap();
        let reg = regs.iter().find(|r| r["index"] == json!(i)).unwrap();
        Bytes::decode(reg["value"].as_str().unwrap()).unwrap().0
    };
    let mut az_snp_policy = lenient();
    az_snp_policy.min_backing = Backing::PrivilegedService;
    let live = attestation::platforms::tdx::verify::parse_tdx_quote(LIVE_QUOTE).unwrap();
    let mut live_policy = v4_policy();
    live_policy.tcb.require_revocation = false;
    live_policy.tcb.require_signed_collateral = false;
    let tdx_live = tdx_envelope_with_ccel(LIVE_QUOTE, LIVE_CCEL2);
    // The live quote with its RTMRs as registers and no log, for the rules
    // that never read one.
    let tdx_regs = tweak(tdx_live.clone(), |v| {
        v["submods"]["cpu"]
            .as_object_mut()
            .unwrap()
            .remove("cvm_log");
    });
    let sha384 = |b: &[u8]| Digest {
        alg: HashAlg::Sha384,
        value: Bytes(b.to_vec()),
    };
    // vtpm-extradata needs the paravisor pinned (section 9.4).
    az_snp_policy.reference.launch_measurement = vec![sha384(&az_report.measurement)];
    let key32 = |b: u8| json!({"kind": "spki-sha256", "value": b64url(&[b; 32])});
    let keyed = |p: &mut VerifyPolicy| {
        p.freshness.key = Some(serde_json::from_value(key32(0x11)).unwrap());
    };
    let floors = |p: &mut VerifyPolicy| {
        p.tcb.floors.insert("low".into(), snp_floor(0, None));
        p.tcb.floors.insert("high".into(), snp_floor(255, None));
    };
    let this_chip = |floor: Option<&str>| IdentityPolicy {
        machines: vec![MachineEntry {
            id: Bytes(report.chip_id.to_vec()),
            tcb_floor: floor.map(String::from),
        }],
    };
    let tdx = tdx_fixture_collateral();
    let genoa_crl = snp_crl_collateral(false);
    let cpu = |f: fn(&mut Value)| tweak(snp.clone(), f);

    let case = |id,
                section,
                statement,
                now,
                evidence: Input,
                policy: Option<Input>,
                collateral,
                expect| Authored {
        id,
        section,
        statement,
        now,
        evidence,
        policy,
        collateral,
        expect,
    };
    let none = BTreeMap::new;
    use RefusalCode as R;
    let snp_case = |id, section, statement, evidence: Value, expect| {
        case(
            id,
            section,
            statement,
            SNP_NOW,
            evidence.into(),
            Some(lenient().into()),
            none(),
            expect,
        )
    };

    let mut out = vec![
        // Section 4.3 and step 1: the envelope's own claims.
        snp_case("envelope-nonce-too-short", "4.1", "eat_nonce is 16 to 64 bytes: 15 is refused",
            snp_envelope(&[7u8; 15]), Some(R::EnvelopeInvalid)),
        snp_case("envelope-nonce-too-long", "4.1", "eat_nonce is 16 to 64 bytes: 65 is refused",
            snp_envelope(&[7u8; 65]), Some(R::EnvelopeInvalid)),
        snp_case("envelope-profile-unknown", "11", "step 1: an unknown profile version is refused",
            tweak(snp.clone(), |v| v["eat_profile"] = json!("tag:confidential.ai,2026:cvm#2")),
            Some(R::EnvelopeInvalid)),
        snp_case("envelope-version-unknown", "11", "step 1: cvm_version other than 1 is refused",
            tweak(snp.clone(), |v| v["cvm_version"] = json!(2)), Some(R::EnvelopeInvalid)),
        snp_case("envelope-submodule-name-unknown", "4.2", "a submodule name outside the reserved forms is rejected",
            tweak(snp.clone(), |v| v["submods"]["tpm"] = v["submods"]["cpu"].clone()),
            Some(R::EnvelopeInvalid)),
        snp_case("envelope-no-cpu-submodule", "4.2", "the cpu submodule is required",
            tweak(snp.clone(), |v| v["submods"] = json!({})), Some(R::EnvelopeInvalid)),
        // Section 4.10: encoding.
        case("envelope-duplicate-member", "4.7", "an object with a duplicate member name is rejected: the envelope",
            SNP_NOW, with_duplicate(&snp, &[], "eat_nonce", &json!(b64url(&[7u8; 16]))),
            Some(lenient().into()), none(), Some(R::EnvelopeInvalid)),
        case("envelope-duplicate-member-in-cvm-object", "4.7", "an object with a duplicate member name is rejected: a cvm_* object",
            SNP_NOW, with_duplicate(&snp, &["submods", "cpu", "cvm_platform"], "tee", &json!("sev-snp")),
            Some(lenient().into()), none(), Some(R::EnvelopeInvalid)),
        case("envelope-duplicate-label-in-cmw-collection", "4.7", "an object with a duplicate member name is rejected: a CMW collection",
            SNP_NOW, with_duplicate(&snp, &["submods", "cpu", "cvm_endorsements"], "snp.vek",
                &json!(["application/pkix-cert", b64url(SNP_VCEK), 2])),
            Some(lenient().into()), none(), Some(R::EnvelopeInvalid)),
        snp_case("envelope-null-member", "4.7", "null is not a value: an optional member is absent or holds its type",
            tweak(snp.clone(), |v| v["submods"]["cpu"]["dbgstat"] = Value::Null), Some(R::EnvelopeInvalid)),
        snp_case("envelope-floating-point", "4.7", "integers are JSON numbers and no profile claim holds floating point",
            tweak(snp.clone(), |v| v["cvm_version"] = json!(1.0)), Some(R::EnvelopeInvalid)),
        snp_case("envelope-object-as-array", "4.7",
            "one encoding per value: a cvm_* object written as the array of its members is refused",
            tweak(snp.clone(), |v| v["submods"]["cpu"]["cvm_binding"] = json!(["challenge", "report-data"])),
            Some(R::EnvelopeInvalid)),
        snp_case("envelope-enumerated-value-as-object", "4.7",
            "one encoding per value: an enumerated value is its text, never an object naming it",
            tweak(snp.clone(), |v| v["submods"]["cpu"]["cvm_binding"]["pattern"] = json!({"challenge": null})),
            Some(R::EnvelopeInvalid)),
        snp_case("envelope-unknown-claim-ignored", "4.7", "an unknown top-level claim is ignored whatever it holds",
            tweak(snp.clone(), |v| v["x_vendor"] = json!({"note": "ignored", "weight": 1.5, "empty": null})),
            None),
        snp_case("envelope-byte-string-padded", "4.7", "byte strings are base64url without padding",
            tweak(snp.clone(), |v| v["eat_nonce"] = json!(format!("{}=", b64url(&nonce)))),
            Some(R::EnvelopeInvalid)),
        snp_case("envelope-byte-string-standard-alphabet", "4.7", "byte strings are base64url: the standard alphabet is refused",
            tweak(snp.clone(), |v| {
                let text = b64url(SNP_REPORT);
                assert!(text.contains('-') || text.contains('_'));
                v["submods"]["cpu"]["cvm_report"][1] = json!(text.replace('-', "+").replace('_', "/"));
            }),
            Some(R::EnvelopeInvalid)),
        snp_case("envelope-byte-string-noncanonical", "4.7", "byte strings are base64url with zero trailing bits (RFC 4648 section 3.5)",
            tweak(snp.clone(), |v| {
                // The last character of a partial group carries zero bits
                // below the data; setting the lowest one keeps the length.
                const ALPHABET: &[u8] =
                    b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
                let text = b64url(&nonce);
                assert_ne!(text.len() % 4, 0, "the nonce ends in a partial group");
                let last = *text.as_bytes().last().unwrap();
                let index = ALPHABET.iter().position(|&c| c == last).unwrap();
                let bumped = ALPHABET[index | 1] as char;
                v["eat_nonce"] = json!(format!("{}{bumped}", &text[..text.len() - 1]));
            }),
            Some(R::EnvelopeInvalid)),
        // Section 4.10: bounds.
        snp_case("envelope-submodules-at-bound", "4.7",
            "an envelope carries at most 66 submodules: 66 parse, and the appraisal refuses more devices than it accepts (device-not-allowed)",
            with_gpus(&nonce, 65), Some(R::DeviceNotAllowed)),
        snp_case("envelope-submodules-over-bound", "4.7", "an envelope carries at most 66 submodules: 67 are refused",
            with_gpus(&nonce, 66), Some(R::EnvelopeInvalid)),
        case("envelope-field-at-bound", "4.7",
            "every byte string field is at most 1 MiB: a 1 MiB log parses, and a log that is not CEL is refused (log-invalid)",
            SNP_NOW, tdx_with_log("tcg-cel-cbor", &vec![0u8; 1 << 20]).into(), Some(live_policy.clone().into()), none(),
            Some(R::LogInvalid)),
        case("envelope-field-over-bound", "4.7", "every byte string field is at most 1 MiB: one byte more is refused",
            SNP_NOW, tdx_with_log("tcg-cel-cbor", &vec![0u8; (1 << 20) + 1]).into(), Some(live_policy.clone().into()), none(),
            Some(R::EnvelopeInvalid)),
        case("envelope-at-size-bound", "4.7", "the whole envelope is at most 10 MiB: exactly 10 MiB appraises",
            SNP_NOW, padded_to(&snp, 10 << 20), Some(lenient().into()), none(), None),
        case("envelope-over-size-bound", "4.7", "the whole envelope is at most 10 MiB: one byte more is refused",
            SNP_NOW, padded_to(&snp, (10 << 20) + 1), Some(lenient().into()), none(), Some(R::EnvelopeInvalid)),
        snp_case("envelope-cmw-collection-over-bound", "4.7", "a CMW collection carries at most 32 entries",
            tweak(snp.clone(), |v| {
                for i in 0..32 {
                    v["submods"]["cpu"]["cvm_endorsements"][format!("x{i}")] =
                        json!(["application/pkix-cert", b64url(SNP_VCEK), 2]);
                }
            }),
            Some(R::EnvelopeInvalid)),
        snp_case("envelope-cmw-collection-nested", "10.1", "cvm_endorsements accepts no nested collection",
            tweak(snp.clone(), |v| {
                v["submods"]["cpu"]["cvm_endorsements"]["snp.vek"] =
                    json!({"snp.vek": ["application/pkix-cert", b64url(SNP_VCEK), 2]});
            }),
            Some(R::EnvelopeInvalid)),
        // Section 4.4 and 4.2: the cpu claims set.
        snp_case("snp-platform-vendor-disagrees-with-tee", "4.3", "cvm_platform: the vendor is the TEE's vendor",
            cpu(|v| v["submods"]["cpu"]["cvm_platform"]["vendor"] = json!("intel")), Some(R::EnvelopeInvalid)),
        snp_case("snp-generation-hint-contradicts-report", "3.4",
            "a hint that contradicts the signed data is an error: generation Milan on a Genoa report",
            cpu(|v| v["submods"]["cpu"]["cvm_platform"]["generation"] = json!("Milan")), Some(R::EnvelopeInvalid)),
        snp_case("snp-generation-hint-agrees", "4.3", "cvm_platform.generation names the generation the report carries",
            cpu(|v| v["submods"]["cpu"]["cvm_platform"]["generation"] = json!("Genoa")), None),
        snp_case("snp-generation-hint-unknown", "4.3", "cvm_platform.generation is Milan, Genoa or Turin on SEV-SNP",
            cpu(|v| v["submods"]["cpu"]["cvm_platform"]["generation"] = json!("genoa")), Some(R::EnvelopeInvalid)),
        snp_case("snp-report-indicator-not-evidence", "4.3", "cvm_report: the indicator is required and exactly 4",
            cpu(|v| v["submods"]["cpu"]["cvm_report"][2] = json!(2)), Some(R::EnvelopeInvalid)),
        snp_case("snp-report-type-unknown", "4.3", "cvm_report: a media type outside the profile's is refused",
            cpu(|v| v["submods"]["cpu"]["cvm_report"][0] = json!("application/octet-stream")), Some(R::EnvelopeInvalid)),
        snp_case("snp-report-type-for-other-tee", "4.3", "cvm_report: a TD quote under an SEV-SNP platform is refused",
            cpu(|v| v["submods"]["cpu"]["cvm_report"][0] = json!("application/vnd.confidential-ai.tdx-quote")),
            Some(R::EnvelopeInvalid)),
        snp_case("snp-provenance-ignored", "4.3", "cvm_provenance is reserved and a v1 verifier ignores it",
            cpu(|v| v["submods"]["cpu"]["cvm_provenance"] = json!({"ppid": "AAEC", "registry": "https://example.com"})),
            None),
        snp_case("snp-dbgstat-hint-agrees", "4.3",
            "dbgstat is compared on whether debug is enabled; the disabled qualifier is the attester's",
            cpu(|v| v["submods"]["cpu"]["dbgstat"] = json!("disabled-permanently")), None),
        snp_case("snp-registers-without-commitment", "6.5", "snp-vmr registers appear only with the commitment binding",
            cpu(|v| v["submods"]["cpu"]["cvm_registers"] = json!([{"index": 4, "alg": "sha384",
                "value": b64url(&[0u8; 48]), "source": "snp-vmr", "backing": "virtualized"}])),
            Some(R::EnvelopeInvalid)),
        snp_case("snp-chain-claims-without-commitment", "4.3", "cvm_chain and bootseed belong to the commitment binding",
            cpu(|v| {
                v["submods"]["cpu"]["cvm_chain"] = json!({"chain_len": 1});
                v["submods"]["cpu"]["bootseed"] = json!(b64url(&[0u8; 32]));
            }),
            Some(R::EnvelopeInvalid)),
        snp_case("snp-commitment-without-chain", "8.1", "commitment requires cvm_chain, bootseed and all 16 registers",
            cpu(|v| v["submods"]["cpu"]["cvm_binding"]["mode"] = json!("commitment")), Some(R::EnvelopeInvalid)),
        snp_case("snp-binding-mode-for-other-platform", "5.4", "vtpm-extradata binds Azure evidence; a bare SEV-SNP report binds its report data",
            cpu(|v| v["submods"]["cpu"]["cvm_binding"]["mode"] = json!("vtpm-extradata")), Some(R::EnvelopeInvalid)),
        case("tdx-binding-commitment", "5.4", "the commitment binding is SEV-SNP's; a TD quote binds its report data",
            SNP_NOW, tweak(tdx_regs.clone(), |v| v["submods"]["cpu"]["cvm_binding"]["mode"] = json!("commitment")).into(),
            Some(live_policy.clone().into()), none(), Some(R::EnvelopeInvalid)),
        // Section 4.5: keys and the anchor.
        snp_case("snp-key-kind-reserved", "5.3", "tls-exporter is reserved for v2; a v1 verifier rejects it as an unknown kind",
            tweak(snp.clone(), |v| v["submods"]["cpu"]["cvm_binding"]["key"] =
                json!({"kind": "tls-exporter", "value": b64url(&[0x11; 32])})),
            Some(R::EnvelopeInvalid)),
        snp_case("snp-key-value-wrong-size", "5.3", "spki-sha256 is 32 bytes",
            tweak(snp.clone(), |v| v["submods"]["cpu"]["cvm_binding"]["key"] =
                json!({"kind": "spki-sha256", "value": b64url(&[0x11; 31])})),
            Some(R::EnvelopeInvalid)),
        snp_case("snp-raw-key-too-long", "5.3", "a raw key value is at most 65535 bytes",
            tweak(snp.clone(), |v| v["submods"]["cpu"]["cvm_binding"]["key"] =
                json!({"kind": "raw", "value": b64url(&vec![0x11; 65536])})),
            Some(R::EnvelopeInvalid)),
        snp_case("snp-certificate-pattern-needs-tbs-key", "5.3", "the certificate pattern binds an x509-tbs-sha256 key",
            tweak(snp.clone(), |v| {
                v["submods"]["cpu"]["cvm_binding"]["pattern"] = json!("certificate");
                v["submods"]["cpu"]["cvm_binding"]["key"] = key32(0x11);
            }),
            Some(R::EnvelopeInvalid)),
        snp_case("snp-tbs-key-needs-certificate-pattern", "5.3", "an x509-tbs-sha256 key belongs to the certificate pattern",
            tweak(snp.clone(), |v| v["submods"]["cpu"]["cvm_binding"]["key"] =
                json!({"kind": "x509-tbs-sha256", "value": b64url(&[0x22; 32])})),
            Some(R::EnvelopeInvalid)),
        case("snp-keyed-anchor-not-bound", "5.2",
            "with a key the anchor is SHA-384(\"ats-anchor-v1\" || ...); a report bound to the bare nonce is refused",
            SNP_NOW, tweak(snp.clone(), |v| v["submods"]["cpu"]["cvm_binding"]["key"] = key32(0x11)).into(),
            Some(with_policy(lenient(), keyed).into()), none(), Some(R::BindingMismatch)),
        case("snp-policy-key-not-bound", "5.2", "a key the policy requires and the envelope does not bind is refused",
            SNP_NOW, snp.clone().into(), Some(with_policy(lenient(), keyed).into()), none(), Some(R::BindingMismatch)),
        snp_case("snp-certificate-pattern-without-presented-certificate", "5.5",
            "the verifier compares the certificate it was presented with; without it the certificate pattern is refused",
            tweak(snp.clone(), |v| {
                v["submods"]["cpu"]["cvm_binding"]["pattern"] = json!("certificate");
                v["submods"]["cpu"]["cvm_binding"]["key"] =
                    json!({"kind": "x509-tbs-sha256", "value": b64url(&[0x22; 32])});
            }),
            Some(R::BindingMismatch)),
        // Section 4.7: registers.
        case("tdx-log-without-registers", "6.1", "cvm_registers is required whenever cvm_log is present",
            SNP_NOW, tweak(tdx_live.clone(), |v| {
                v["submods"]["cpu"].as_object_mut().unwrap().remove("cvm_registers");
            }).into(),
            Some(live_policy.clone().into()), none(), Some(R::EnvelopeInvalid)),
        case("tdx-register-index-out-of-range", "6.2", "for tdx-rtmr the index is the RTMR ordinal 0 to 3",
            SNP_NOW, tweak(tdx_regs.clone(), |v| v["submods"]["cpu"]["cvm_registers"][3]["index"] = json!(4)).into(),
            Some(live_policy.clone().into()), none(), Some(R::EnvelopeInvalid)),
        case("tdx-register-alg-not-sha384", "6.1", "alg is pinned per source: sha384 for tdx-rtmr",
            SNP_NOW, tweak(tdx_regs.clone(), |v| {
                v["submods"]["cpu"]["cvm_registers"][0]["alg"] = json!("sha256");
                v["submods"]["cpu"]["cvm_registers"][0]["value"] = json!(b64url(&[0u8; 32]));
            }).into(),
            Some(live_policy.clone().into()), none(), Some(R::EnvelopeInvalid)),
        case("tdx-register-backing-not-hardware", "6.4", "backing is constrained by source: hardware for tdx-rtmr",
            SNP_NOW, tweak(tdx_regs.clone(), |v| v["submods"]["cpu"]["cvm_registers"][0]["backing"] = json!("virtualized")).into(),
            Some(live_policy.clone().into()), none(), Some(R::EnvelopeInvalid)),
        case("tdx-register-value-wrong-length", "6.1", "value is exactly the digest length of alg",
            SNP_NOW, tweak(tdx_regs.clone(), |v| v["submods"]["cpu"]["cvm_registers"][0]["value"] = json!(b64url(&[0u8; 47]))).into(),
            Some(live_policy.clone().into()), none(), Some(R::EnvelopeInvalid)),
        case("tdx-register-repeated", "6.1", "each register index appears once",
            SNP_NOW, tweak(tdx_regs.clone(), |v| {
                let first = v["submods"]["cpu"]["cvm_registers"][0].clone();
                v["submods"]["cpu"]["cvm_registers"].as_array_mut().unwrap().push(first);
            }).into(),
            Some(live_policy.clone().into()), none(), Some(R::EnvelopeInvalid)),
        case("azure-snp-register-backing-hardware", "6.4", "backing is constrained by source: privileged-service for vtpm-pcr",
            SNP_NOW, tweak(az_snp.clone(), |v| v["submods"]["vtpm"]["cvm_registers"][0]["backing"] = json!("hardware")).into(),
            Some(az_snp_policy.clone().into()), none(), Some(R::EnvelopeInvalid)),
        case("azure-snp-register-differs-from-quoted-pcr", "4.4", "a vtpm register equals the quoted PCR of its index",
            SNP_NOW, tweak(az_snp.clone(), |v| v["submods"]["vtpm"]["cvm_registers"][0]["value"] = json!(b64url(&[9u8; 32]))).into(),
            Some(az_snp_policy.clone().into()), none(), Some(R::EnvelopeInvalid)),
        case("azure-snp-quoted-pcrs-altered", "6.5",
            "for vtpm-pcr the quoted PCR digest must reproduce from the registers: a PCR changed with its register is refused",
            SNP_NOW, tweak(az_snp.clone(), |v| {
                let index = v["submods"]["vtpm"]["cvm_registers"][0]["index"].as_u64().unwrap() as usize;
                v["submods"]["vtpm"]["cvm_tpm_quote"]["pcrs"][index] = json!(b64url(&[9u8; 32]));
                v["submods"]["vtpm"]["cvm_registers"][0]["value"] = json!(b64url(&[9u8; 32]));
            }).into(),
            Some(az_snp_policy.clone().into()), none(), Some(R::RegisterMismatch)),
        case("azure-snp-quote-with-23-pcrs", "4.4", "cvm_tpm_quote carries the 24 PCR values of the quoted bank",
            SNP_NOW, tweak(az_snp.clone(), |v| {
                v["submods"]["vtpm"]["cvm_tpm_quote"]["pcrs"].as_array_mut().unwrap().pop();
            }).into(),
            Some(az_snp_policy.clone().into()), none(), Some(R::EnvelopeInvalid)),
        case("azure-snp-register-outside-bank", "6.1", "a vtpm register's alg is the quoted bank",
            SNP_NOW, tweak(az_snp.clone(), |v| {
                v["submods"]["vtpm"]["cvm_registers"][0]["alg"] = json!("sha384");
                v["submods"]["vtpm"]["cvm_registers"][0]["value"] = json!(b64url(&[0u8; 48]));
            }).into(),
            Some(az_snp_policy.clone().into()), none(), Some(R::EnvelopeInvalid)),
        // Sections 4.4 and 4.5: the vTPM binding.
        case("azure-snp-nonce-not-bound", "5.4", "vtpm-extradata: extraData == anchor; another nonce of the same length is refused",
            SNP_NOW, tweak(az_snp.clone(), |v| {
                let mut other = az_nonce.clone();
                other[0] ^= 1;
                v["eat_nonce"] = json!(b64url(&other));
            }).into(),
            Some(az_snp_policy.clone().into()), none(), Some(R::BindingMismatch)),
        case("azure-snp-nonce-length-differs", "5.4", "vtpm-extradata: extraData == anchor; a nonce of another length is refused",
            SNP_NOW, tweak(az_snp.clone(), |v| {
                let len = if az_nonce.len() == 16 { 20 } else { 16 };
                v["eat_nonce"] = json!(b64url(&vec![0x42; len]));
            }).into(),
            Some(az_snp_policy.clone().into()), none(), Some(R::BindingMismatch)),
        case("azure-snp-hcl-hash-type-not-sha256", "9.4.1",
            "the HCL report's report data hash type (offset 0x4CC) is 1, SHA-256; another value is refused",
            SNP_NOW, with_hcl(&az_snp, |h| {
                assert_eq!(h[0x4CC], 1);
                h[0x4CC] = 2;
            }).into(),
            Some(az_snp_policy.clone().into()), none(), Some(R::EnvelopeInvalid)),
        case("azure-snp-hcl-report-type-for-tdx", "9.4.1",
            "the HCL report's type names the TEE of the cpu submodule; an SEV-SNP cpu with report type 4 (TDX) is refused",
            SNP_NOW, with_hcl(&az_snp, |h| {
                assert_eq!(h[0x4C8], 2);
                h[0x4C8] = 4;
            }).into(),
            Some(az_snp_policy.clone().into()), none(), Some(R::EnvelopeInvalid)),
        case("azure-snp-hcl-variable-data-size-includes-padding", "9.4.1",
            "the variable data is exactly its declared size; a size that takes in the zero padding after the JSON object is refused",
            SNP_NOW, with_hcl(&az_snp, |h| {
                let size = u32::from_le_bytes(h[0x4D0..0x4D4].try_into().unwrap());
                assert_eq!(h[0x4D4 + size as usize], 0);
                h[0x4D0..0x4D4].copy_from_slice(&(size + 1).to_le_bytes());
            }).into(),
            Some(az_snp_policy.clone().into()), none(), Some(R::EnvelopeInvalid)),
        case("azure-snp-cpu-report-not-the-hcl-area", "9.4.2",
            "the cpu submodule's SNP report is the HCL report's hardware area byte for byte; a genuine report of another machine with its own VCEK is refused",
            SNP_NOW, tweak(az_snp.clone(), |v| {
                let cpu = &mut v["submods"]["cpu"];
                cpu["cvm_report"][1] = json!(b64url(SNP_REPORT));
                cpu["cvm_endorsements"]["snp.vek"][1] = json!(b64url(SNP_VCEK));
            }).into(),
            Some(az_snp_policy.clone().into()), none(), Some(R::EnvelopeInvalid)),
        case("azure-cpu-without-vtpm", "4.2", "a cpu bound through vtpm-extradata needs its vtpm submodule",
            SNP_NOW, tweak(az_snp.clone(), |v| {
                v["submods"].as_object_mut().unwrap().remove("vtpm");
            }).into(),
            Some(az_snp_policy.clone().into()), none(), Some(R::EnvelopeInvalid)),
        snp_case("snp-vtpm-without-vtpm-binding", "4.2", "a vtpm submodule belongs to a cpu bound through vtpm-extradata",
            tweak(snp.clone(), |v| v["submods"]["vtpm"] = az_snp["submods"]["vtpm"].clone()),
            Some(R::EnvelopeInvalid)),
        case("azure-snp-vtpm-log-not-tpm2", "9.4", "the vtpm submodule's log is a TPM2 event log in this release",
            SNP_NOW, tweak(az_snp.clone(), |v| v["submods"]["vtpm"]["cvm_log"] =
                json!({"format": "tcg-cel-json", "data": b64url(b"[]")})).into(),
            Some(az_snp_policy.clone().into()), none(), Some(R::Unsupported)),
        case("azure-snp-backing-below-minimum", "13.1", "min_backing: a privileged-service register under the default hardware floor is refused",
            SNP_NOW, az_snp.clone().into(),
            Some(with_policy(az_snp_policy.clone(), |p| p.min_backing = Backing::Hardware).into()),
            none(), Some(R::BackingBelowMinimum)),
        case("azure-snp-pcr8-pinned", "12.4", "vtpm: executables is 2 when the launch measurement is pinned and every pinned PCR matches",
            SNP_NOW, az_snp.clone().into(),
            Some(with_policy(az_snp_policy.clone(), |p| {
                p.reference.pcrs.insert(8, vec![Digest { alg: HashAlg::Sha256, value: Bytes(az_pcr(8)) }]);
            }).into()),
            none(), None),
        case("azure-snp-pcr8-pinned-without-launch-measurement", "9.4",
            "vtpm-extradata: without a pinned launch measurement nothing establishes the paravisor that binds the nonce, so the evidence is refused",
            SNP_NOW, az_snp.clone().into(),
            Some(with_policy(az_snp_policy.clone(), |p| {
                p.reference.launch_measurement.clear();
                p.reference.pcrs.insert(8, vec![Digest { alg: HashAlg::Sha256, value: Bytes(az_pcr(8)) }]);
            }).into()),
            none(), Some(R::BindingMismatch)),
        case("azure-snp-owner-key-accepted", "13.4", "owner.id_key_digests: a report whose ID key is listed appraises",
            SNP_NOW, az_snp.clone().into(),
            Some(with_policy(az_snp_policy.clone(), |p| {
                p.owner = Some(OwnerPolicy { id_key_digests: vec![FixedBytes(az_report.id_key_digest)] });
            }).into()),
            none(), None),
        // Section 4.6: endorsements.
        snp_case("snp-endorsement-label-unknown", "10.1", "cvm_endorsements labels are exactly the ones section 10.1 lists",
            cpu(|v| v["submods"]["cpu"]["cvm_endorsements"]["snp.ask"] = json!(["application/pkix-cert", b64url(SNP_VCEK), 2])),
            Some(R::EnvelopeInvalid)),
        snp_case("snp-endorsement-for-other-tee", "10.1", "an endorsement for another TEE is refused",
            cpu(|v| v["submods"]["cpu"]["cvm_endorsements"]["tdx.root_crl"] = json!(["application/pkix-crl", b64url(ROOT_CRL), 2])),
            Some(R::EnvelopeInvalid)),
        snp_case("snp-endorsement-type-wrong", "10.1", "snp.vek is application/pkix-cert",
            cpu(|v| v["submods"]["cpu"]["cvm_endorsements"]["snp.vek"][0] = json!("application/pkix-crl")),
            Some(R::EnvelopeInvalid)),
        snp_case("snp-endorsement-indicator-evidence", "10.1", "an endorsement's indicator is exactly 2, or 1 for reference values",
            cpu(|v| v["submods"]["cpu"]["cvm_endorsements"]["snp.vek"][2] = json!(4)),
            Some(R::EnvelopeInvalid)),
        snp_case("snp-endorsements-type-tag-wrong", "10.1", "cvm_endorsements' __cmwc_t is tag:confidential.ai,2026:cvm-endorsements#1",
            cpu(|v| v["submods"]["cpu"]["cvm_endorsements"]["__cmwc_t"] = json!("tag:example.com,2026:endorsements")),
            Some(R::EnvelopeInvalid)),
        snp_case("snp-endorsements-without-type-tag", "10.1", "cvm_endorsements carries its __cmwc_t",
            cpu(|v| { v["submods"]["cpu"]["cvm_endorsements"].as_object_mut().unwrap().remove("__cmwc_t"); }),
            Some(R::EnvelopeInvalid)),
        snp_case("snp-inline-vek-of-another-chip", "10.2",
            "inline endorsements are inputs: a VEK that is not the report's is not used, and with no other source the VEK is unavailable",
            tweak(snp.clone(), |v| v["submods"]["cpu"]["cvm_endorsements"]["snp.vek"][1] = json!(b64url(TEST_VCEK))),
            Some(R::CollateralUnavailable)),
        case("snp-vek-from-the-provider", "10.2", "a VEK the verifier's provider holds serves an envelope that carries none",
            SNP_NOW, tweak(snp.clone(), |v| {
                v["submods"]["cpu"].as_object_mut().unwrap().remove("cvm_endorsements");
            }).into(),
            Some(lenient().into()),
            BTreeMap::from([(
                attestation::collateral::CollateralKey::SnpVcek {
                    generation: attestation::ProcessorGeneration::Genoa,
                    chip_id: report.chip_id,
                    tcb: SnpTcb {
                        bootloader: report.reported_tcb.bootloader,
                        tee: report.reported_tcb.tee,
                        snp: report.reported_tcb.snp,
                        microcode: report.reported_tcb.microcode,
                        fmc: report.reported_tcb.fmc,
                    },
                }.id(),
                {
                    write("collateral/genoa_vcek.der", SNP_VCEK);
                    CollateralRef::File("collateral/genoa_vcek.der".into())
                },
            )]),
            None),
        // Section 4.8: logs.
        case("tdx-cel-cbor-replays", "7.4",
            "tcg-cel-cbor: the log replays from zero into the RTMRs it extends, each reproducing the signed value",
            SNP_NOW, tdx_with_log("tcg-cel-cbor", &cel_log(LIVE_CCEL2, false)).into(), Some(live_policy.clone().into()), none(), None),
        case("tdx-cel-json-replays", "7.4", "tcg-cel-json: the same records in CEL-JSON replay the same way",
            SNP_NOW, tdx_with_log("tcg-cel-json", &cel_log(LIVE_CCEL2, true)).into(), Some(live_policy.clone().into()), none(), None),
        case("tdx-cel-log-from-another-boot", "7.4", "a CEL log that does not reproduce the signed RTMRs is refused",
            SNP_NOW, tdx_with_log("tcg-cel-cbor", &cel_log(LIVE_CCEL, false)).into(), Some(live_policy.clone().into()), none(),
            Some(R::ReplayMismatch)),
        case("tdx-cel-log-unparseable", "7.1", "a log that cannot be parsed whole under its format is refused",
            SNP_NOW, tdx_with_log("tcg-cel-cbor", b"not a CEL log").into(), Some(live_policy.clone().into()), none(),
            Some(R::LogInvalid)),
        case("tdx-aael-log-unsupported", "7.1", "the standalone attestation-agent log is parsed but this release's appraisal refuses it",
            SNP_NOW, tdx_with_log("aael", b"AAEL").into(), Some(live_policy.clone().into()), none(), Some(R::Unsupported)),
        case("dstack-json-replays", "9.3",
            "dstack-json: boot events keep their TCG digests, runtime events recompute, and the log reproduces the signed RTMRs",
            SNP_NOW, dstack_envelope(serde_json::from_str::<Value>(DSTACK).unwrap()["event_log"].as_str().unwrap()).into(),
            Some(live_policy.clone().into()), none(), None),
        case("dstack-json-runtime-event-altered", "9.3", "dstack-json: a runtime event whose digest does not recompute is refused",
            SNP_NOW, dstack_envelope(&dstack_log_with_altered_runtime_event()).into(),
            Some(live_policy.clone().into()), none(), Some(R::ReplayMismatch)),
        // Sections 5.2 and 7: reference values.
        snp_case("snp-launch-measurement-pinned", "12.4",
            "executables is 3 when only the launch measurement matched", snp.clone(), None),
        snp_case("snp-host-data-pinned", "13.4", "reference.host_data: the value cvm_host_data must carry appraises", snp.clone(), None),
        snp_case("snp-host-data-zero-padded", "13.4", "reference.host_data is zero-padded to the platform's length", snp.clone(), None),
        snp_case("snp-host-data-differs", "13.4", "reference.host_data: another value is refused", snp.clone(), Some(R::ReferenceMismatch)),
        snp_case("snp-host-data-longer-than-the-field", "13.4",
            "reference.host_data longer than the platform's field is a pin no report meets",
            snp.clone(), Some(R::ReferenceMismatch)),
        snp_case("snp-owner-key-not-accepted", "13.4", "owner.id_key_digests: an ID key outside the list is refused",
            snp.clone(), Some(R::ReferenceMismatch)),
        // Section 9.1.4: what the report signature covers.
        snp_case("snp-tcb-reserved-byte-altered", "9.1.4",
            "step 3: the signature covers bytes 0x000 to 0x29F as received, so a reserved byte of REPORTED_TCB changed after signing is refused",
            snp_with_report(&nonce, &snp_report_with(0x182, 1)), Some(R::SignatureInvalid)),
        snp_case("snp-signature-upper-bytes-nonzero", "9.1.4",
            "step 3: the upper 24 bytes of R and S are zero; a report whose R carries a non-zero byte there is refused",
            snp_with_report(&nonce, &snp_report_with(0x2A0 + 48, 1)), Some(R::SignatureInvalid)),
        case("snp-vlek-chain-appraises", "9.1.4",
            "step 2: SIGNING_KEY 1 names a VLEK, which the ASVK signs; the chain, the signature and the TCB cross-check hold with no chip identifier (the recording was taken at VMPL 1, which the vector reports as configuration 96)",
            "2025-06-01T00:00:00Z", vlek_envelope().into(),
            Some(with_policy(lenient(), |p| p.policy_bits.require_vmpl0 = false).into()),
            none(), None),
        case("snp-vlek-masked-chip-identifies-no-machine", "13.3",
            "a VLEK-endorsed report whose CHIP_ID is all zero identifies no machine, so an allowlist entry of 64 zero bytes does not match it",
            "2025-06-01T00:00:00Z", vlek_envelope().into(),
            Some(with_policy(lenient(), |p| {
                p.policy_bits.require_vmpl0 = false;
                p.identity = Some(IdentityPolicy {
                    machines: vec![MachineEntry { id: Bytes(vec![0u8; 64]), tcb_floor: None }],
                });
            }).into()),
            none(), Some(R::MachineNotAllowed)),
        case("tdx-registers-pinned", "12.4", "executables is 2 when the launch measurement and every pinned register match",
            SNP_NOW, tdx_live.clone().into(),
            Some(with_policy(live_policy.clone(), |p| {
                p.reference.launch_measurement = vec![sha384(&live.body.mr_td)];
                for (i, r) in [live.body.rtmr_0, live.body.rtmr_1, live.body.rtmr_2].iter().enumerate() {
                    p.reference.registers.insert(i as u16, vec![sha384(r)]);
                }
            }).into()),
            none(), None),
        case("tdx-registers-pinned-without-launch-measurement", "12.4",
            "with the launch measurement unpinned nothing vouches for the firmware, so executables makes no claim",
            SNP_NOW, tdx_regs.clone().into(),
            Some(with_policy(live_policy.clone(), |p| {
                p.reference.registers.insert(0, vec![sha384(&live.body.rtmr_0)]);
            }).into()),
            none(), None),
        case("tdx-register-not-in-reference", "13.4", "reference.registers: a register outside its reference values is refused",
            SNP_NOW, tdx_regs.clone().into(),
            Some(with_policy(live_policy.clone(), |p| {
                p.reference.registers.insert(1, vec![sha384(&[0u8; 48])]);
            }).into()),
            none(), Some(R::ReferenceMismatch)),
        case("tdx-owner-pin-unsatisfiable", "13.1",
            "a pin nothing in the evidence can satisfy is refused: owner.id_key_digests on a TD quote",
            SNP_NOW, tdx_regs.clone().into(),
            Some(with_policy(live_policy.clone(), |p| {
                p.owner = Some(OwnerPolicy { id_key_digests: vec![FixedBytes([0x11; 48])] });
            }).into()),
            none(), Some(R::ReferenceMismatch)),
        // Section 7: floors.
        snp_case("snp-machine-floor-overrides-default", "13.3", "a machine that names a tcb_floor is held to it, not to default_floor",
            snp.clone(), None),
        snp_case("snp-machine-floor-applies", "13.3", "a machine's own tcb_floor applies", snp.clone(), Some(R::TcbNotAllowed)),
        snp_case("snp-default-floor-for-machine-without-floor", "13.3", "every other machine is held to default_floor",
            snp.clone(), Some(R::TcbNotAllowed)),
        snp_case("snp-floor-names-fmc-before-turin", "13.2", "a floor that names the FMC SPL fails a report without one",
            snp.clone(), Some(R::TcbNotAllowed)),
        case("tdx-floor-tee-tcb-svn", "13.2", "a TDX floor adds tee_tcb_svn componentwise", TDX_FIXTURE_NOW,
            tdx_envelope(V4_QUOTE).into(),
            Some(with_policy(v4_policy(), |p| {
                p.tcb.floors.insert("f".into(), tdx_floor(Some([0xff; 16]), None));
                p.tcb.default_floor = Some("f".into());
            }).into()),
            tdx.clone(), Some(R::TcbNotAllowed)),
        case("tdx-floor-evaluation-data-number", "13.2", "a TDX floor adds tcbEvaluationDataNumber", TDX_FIXTURE_NOW,
            tdx_envelope(V4_QUOTE).into(),
            Some(with_policy(v4_policy(), |p| {
                p.tcb.floors.insert("f".into(), tdx_floor(None, Some(u32::MAX)));
                p.tcb.default_floor = Some("f".into());
            }).into()),
            tdx.clone(), Some(R::TcbNotAllowed)),
        case("tdx-floor-met", "13.2", "a TDX floor the quote and its TCB Info meet appraises", TDX_FIXTURE_NOW,
            tdx_envelope(V4_QUOTE).into(),
            Some(with_policy(v4_policy(), |p| {
                p.tcb.floors.insert("f".into(), tdx_floor(Some([0; 16]), Some(1)));
                p.tcb.default_floor = Some("f".into());
            }).into()),
            tdx.clone(), None),
        // Section 7: devices.
        snp_case("snp-gpu-required-without-device", "13.5", "gpu.required with no device submodule is refused",
            snp.clone(), Some(R::DeviceRequired)),
        snp_case("snp-gpu-arch-not-allowed", "13.5", "gpu.expected_archs: a device of another architecture is refused",
            tweak(snp.clone(), |v| v["submods"]["gpu/GPU-0000"] = gpu_device("GPU-0000", "BLACKWELL")),
            Some(R::DeviceNotAllowed)),
        snp_case("gpu-device-uuid-differs-from-name", "4.5", "a device's uuid is the <ueid> of its submodule name",
            tweak(snp.clone(), |v| v["submods"]["gpu/GPU-0000"] = gpu_device("GPU-0001", "HOPPER")),
            Some(R::EnvelopeInvalid)),
        snp_case("gpu-device-arch-under-gpu-name", "4.5", "an NVSwitch (LS10) is named nvswitch/<ueid>",
            tweak(snp.clone(), |v| v["submods"]["gpu/GPU-0000"] = gpu_device("GPU-0000", "LS10")),
            Some(R::EnvelopeInvalid)),
        snp_case("gpu-device-binding-not-nras-nonce", "4.5", "a device submodule binds in nras-nonce mode",
            tweak(snp.clone(), |v| {
                v["submods"]["gpu/GPU-0000"] = gpu_device("GPU-0000", "HOPPER");
                v["submods"]["gpu/GPU-0000"]["cvm_binding"]["mode"] = json!("report-data");
            }),
            Some(R::EnvelopeInvalid)),
        snp_case("gpu-device-unknown-claim-ignored", "4.7",
            "an unknown claim in a device submodule is ignored; the appraisal goes on to NRAS, which this case records no exchange for",
            tweak(snp.clone(), |v| {
                v["submods"]["gpu/GPU-0000"] = gpu_device("GPU-0000", "HOPPER");
                v["submods"]["gpu/GPU-0000"]["x_sdk_version"] = json!("1.2.3");
            }),
            Some(R::CollateralUnavailable)),
        snp_case("cca-nested-token-not-implemented", "9", "Arm CCA is a platform this release does not appraise",
            tweak(snp.clone(), |v| v["submods"]["cpu"] = json!(["CBOR", b64url(b"\xd9\x03\x8b\xa0")])),
            Some(R::PlatformUnsupported)),
        // Section 7: the policy's own validation.
        snp_case("policy-unknown-member", "13.1", "a policy with an unknown member fails its validation", snp.clone(),
            Some(R::PolicyInvalid)),
        snp_case("policy-null-member", "13.1", "null is not a value in a policy either", snp.clone(), Some(R::PolicyInvalid)),
        snp_case("policy-member-not-an-object", "13.1", "a policy member that is an object is written as one; an array is refused",
            snp.clone(), Some(R::PolicyInvalid)),
        snp_case("policy-default-floor-not-defined", "13.2", "default_floor names one of tcb.floors", snp.clone(),
            Some(R::PolicyInvalid)),
        snp_case("policy-machine-floor-not-defined", "13.3", "a machine's tcb_floor names one of tcb.floors", snp.clone(),
            Some(R::PolicyInvalid)),
        snp_case("policy-revoked-status-allowed", "13.2", "Revoked can never be an allowed TDX status", snp.clone(),
            Some(R::PolicyInvalid)),
        snp_case("policy-empty-machine-allowlist", "13.3", "an empty allowlist admits nothing and is refused", snp.clone(),
            Some(R::PolicyInvalid)),
        snp_case("policy-floor-constrains-nothing", "13.2", "a named floor constrains something", snp.clone(),
            Some(R::PolicyInvalid)),
        snp_case("policy-commitment-header-not-pinned", "13.1", "commitment.header16 is the value section 8.1 pins", snp.clone(),
            Some(R::PolicyInvalid)),
        // Section 5.1: the policy's identifier names the effective policy.
        case("snp-crl-checked-under-the-default-policy", "13.1", "a case without a policy runs under the section 13.1 defaults",
            SNP_NOW, snp.clone().into(), None, genoa_crl.clone(), None),
        case("snp-crl-checked-with-defaults-spelled-out", "12.5",
            "the policy id is the SHA-384 of the effective policy: the defaults written out name the same policy as no policy",
            SNP_NOW, snp.clone().into(), Some(VerifyPolicy::default().into()), genoa_crl.clone(), None),
    ];

    // The policies of the cases above that need their own.
    let policies: Vec<(&str, Input)> = vec![
        (
            "snp-launch-measurement-pinned",
            with_policy(lenient(), |p| {
                p.reference.launch_measurement = vec![sha384(&report.measurement)];
            })
            .into(),
        ),
        (
            "snp-host-data-pinned",
            with_policy(lenient(), |p| {
                p.reference.host_data = Some(Bytes(vec![0; 32]))
            })
            .into(),
        ),
        (
            "snp-host-data-zero-padded",
            with_policy(lenient(), |p| {
                p.reference.host_data = Some(Bytes(vec![0; 1]))
            })
            .into(),
        ),
        (
            "snp-host-data-differs",
            with_policy(lenient(), |p| {
                p.reference.host_data = Some(Bytes(vec![1; 32]))
            })
            .into(),
        ),
        (
            "snp-host-data-longer-than-the-field",
            with_policy(lenient(), |p| {
                p.reference.host_data = Some(Bytes(vec![0; 48]))
            })
            .into(),
        ),
        (
            "snp-owner-key-not-accepted",
            with_policy(lenient(), |p| {
                p.owner = Some(OwnerPolicy {
                    id_key_digests: vec![FixedBytes([0x11; 48])],
                });
            })
            .into(),
        ),
        (
            "snp-machine-floor-overrides-default",
            with_policy(lenient(), |p| {
                floors(p);
                p.tcb.default_floor = Some("high".into());
                p.identity = Some(this_chip(Some("low")));
            })
            .into(),
        ),
        (
            "snp-machine-floor-applies",
            with_policy(lenient(), |p| {
                floors(p);
                p.tcb.default_floor = Some("low".into());
                p.identity = Some(this_chip(Some("high")));
            })
            .into(),
        ),
        (
            "snp-default-floor-for-machine-without-floor",
            with_policy(lenient(), |p| {
                floors(p);
                p.tcb.default_floor = Some("high".into());
                p.identity = Some(this_chip(None));
            })
            .into(),
        ),
        (
            "snp-floor-names-fmc-before-turin",
            with_policy(lenient(), |p| {
                p.tcb.floors.insert("turin".into(), snp_floor(0, Some(0)));
                p.tcb.default_floor = Some("turin".into());
            })
            .into(),
        ),
        (
            "snp-gpu-required-without-device",
            with_policy(lenient(), |p| p.gpu.required = true).into(),
        ),
        (
            "snp-gpu-arch-not-allowed",
            with_policy(lenient(), |p| {
                p.gpu.expected_archs = Some(vec![attestation::profile::GpuArch::Hopper]);
            })
            .into(),
        ),
        (
            "policy-unknown-member",
            tweak(serde_json::to_value(lenient()).unwrap(), |v| {
                v["surprise"] = json!(true)
            })
            .into(),
        ),
        (
            "policy-null-member",
            tweak(serde_json::to_value(lenient()).unwrap(), |v| {
                v["identity"] = Value::Null
            })
            .into(),
        ),
        (
            "policy-member-not-an-object",
            tweak(serde_json::to_value(lenient()).unwrap(), |v| {
                v["tcb"] = json!([])
            })
            .into(),
        ),
        (
            "policy-default-floor-not-defined",
            tweak(serde_json::to_value(lenient()).unwrap(), |v| {
                v["tcb"]["default_floor"] = json!("genoa-2026-09")
            })
            .into(),
        ),
        (
            "policy-machine-floor-not-defined",
            tweak(serde_json::to_value(lenient()).unwrap(), |v| {
                v["identity"] =
                    json!({"machines": [{"id": b64url(&[1; 64]), "tcb_floor": "missing"}]})
            })
            .into(),
        ),
        (
            "policy-revoked-status-allowed",
            tweak(serde_json::to_value(lenient()).unwrap(), |v| {
                v["tcb"]["tdx_allowed_status"] = json!(["UpToDate", "Revoked"])
            })
            .into(),
        ),
        (
            "policy-empty-machine-allowlist",
            tweak(serde_json::to_value(lenient()).unwrap(), |v| {
                v["identity"] = json!({"machines": []})
            })
            .into(),
        ),
        (
            "policy-floor-constrains-nothing",
            tweak(serde_json::to_value(lenient()).unwrap(), |v| {
                v["tcb"]["floors"] = json!({"f": {}})
            })
            .into(),
        ),
        (
            "policy-commitment-header-not-pinned",
            tweak(serde_json::to_value(lenient()).unwrap(), |v| {
                v["commitment"]["header16"] = json!(b64url(&[0; 16]))
            })
            .into(),
        ),
    ];
    for (id, policy) in policies {
        let c = out
            .iter_mut()
            .find(|c| c.id == id)
            .unwrap_or_else(|| panic!("{id}"));
        c.policy = Some(policy);
    }
    out
}
