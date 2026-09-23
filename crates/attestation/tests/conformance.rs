#![cfg(all(feature = "snp", feature = "tdx", feature = "nvidia-gpu"))]
//! The conformance corpus (design doc section 14), run against this
//! implementation: every case under `conformance/cases` must reproduce its
//! decision. With `UPDATE_CONFORMANCE=1` the authored cases and their expected
//! appraisals are rewritten from this implementation, which is the reference.

use attestation::collateral::{HeldCollateral, HeldNras};
use attestation::profile::{
    Backing, Bytes, Digest, HashAlg, IdentityPolicy, MachineEntry, OwnerPolicy, SnpFloor,
    SnpTcbValue, TcbFloor, VerifyPolicy, PROFILE_URI,
};
use attestation::{AttestationError, RefusalCode, SnpTcb, TdxTcbStatus, Verifier};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};

fn root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../../conformance")
}

/// One case, in the section 14.2 format.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Case {
    id: String,
    rule: Rule,
    now: String,
    evidence: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    policy: Option<String>,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    collateral: BTreeMap<String, CollateralRef>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    nras: Vec<NrasExchange>,
    expect: Expect,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Rule {
    section: String,
    statement: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(untagged, deny_unknown_fields)]
enum CollateralRef {
    File(String),
    Signed { body: String, signing_chain: String },
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct NrasExchange {
    arch: String,
    nonce: String,
    response: String,
    jwks: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "lowercase", deny_unknown_fields)]
enum Expect {
    Appraisal(String),
    Refusal(RefusalCode),
}

/// Section 14.2: an input whose path ends in `.gz` is stored gzip-compressed
/// and is its decompressed content.
fn read(path: &str) -> Vec<u8> {
    let p = root().join("inputs").join(path);
    let bytes = std::fs::read(&p).unwrap_or_else(|e| panic!("{}: {e}", p.display()));
    if !path.ends_with(".gz") {
        return bytes;
    }
    use std::io::Read;
    let mut out = Vec::new();
    flate2::read::GzDecoder::new(bytes.as_slice())
        .take(MAX_INPUT as u64 + 1)
        .read_to_end(&mut out)
        .unwrap_or_else(|e| panic!("{}: {e}", p.display()));
    assert!(
        out.len() <= MAX_INPUT,
        "{}: decompresses past {MAX_INPUT} bytes",
        p.display()
    );
    out
}

/// No input is larger than an envelope past its bound needs to be.
const MAX_INPUT: usize = 16 << 20;

fn write(path: &str, bytes: &[u8]) {
    let p = root().join("inputs").join(path);
    std::fs::create_dir_all(p.parent().unwrap()).unwrap();
    std::fs::write(&p, bytes).unwrap_or_else(|e| panic!("{}: {e}", p.display()));
}

/// The case's collateral, held by key; nothing else exists.
fn held_for(case: &Case, now: DateTime<Utc>) -> HeldCollateral {
    let mut held = HeldCollateral::new().at(now);
    for (key, r) in &case.collateral {
        held = match r {
            CollateralRef::File(p) => held.with_bytes(key, read(p)),
            CollateralRef::Signed {
                body,
                signing_chain,
            } => held.with_signed(key, read(body), read(signing_chain)),
        };
    }
    held
}

/// The case's recorded NRAS exchanges, held; nothing reaches a network.
fn nras_for(case: &Case) -> HeldNras {
    HeldNras::new(
        case.nras
            .iter()
            .map(|e| attestation::collateral::NrasExchange {
                arch: serde_json::from_value(json!(e.arch))
                    .unwrap_or_else(|err| panic!("{}: {err}", case.id)),
                nonce: e.nonce.clone(),
                response: serde_json::from_slice(&read(&e.response)).unwrap(),
                jwks: serde_json::from_slice(&read(&e.jwks)).unwrap(),
            })
            .collect(),
    )
}

fn verifier_for(case: &Case) -> Verifier {
    let now: DateTime<Utc> = case
        .now
        .parse::<DateTime<chrono::FixedOffset>>()
        .unwrap_or_else(|e| panic!("{}: now: {e}", case.id))
        .with_timezone(&Utc);
    let held = held_for(case, now);
    let mut v = Verifier::offline()
        .with_cert_provider(held.clone())
        .with_nras_provider(nras_for(case))
        .with_clock(std::sync::Arc::new(move || now));
    if held.holds_tdx() {
        v = v.with_tdx_provider(held);
    }
    v
}

/// The case's policy through the library's own parser: one that fails its
/// validation is a `policy-invalid` refusal (section 14.4).
fn policy_for(case: &Case) -> Result<VerifyPolicy, AttestationError> {
    match &case.policy {
        Some(p) => VerifyPolicy::from_json(&read(p)),
        None => Ok(VerifyPolicy::default()),
    }
}

/// Section 14.3: the members that are the implementation's own.
fn strip(appraisal: &mut Value) {
    if let Some(o) = appraisal.as_object_mut() {
        o.remove("iat");
        o.remove("ear_verifier_id");
        o.remove("ear_raw_evidence");
        if let Some(submods) = o.get_mut("submods").and_then(Value::as_object_mut) {
            for sub in submods.values_mut() {
                if let Some(checks) = sub
                    .pointer_mut("/ear_verifier_claims/cvm_collateral")
                    .and_then(Value::as_object_mut)
                {
                    for check in checks.values_mut() {
                        if let Some(c) = check.as_object_mut() {
                            c.remove("reason");
                        }
                    }
                }
            }
        }
    }
}

/// The appraisal this implementation produces for a case, as emitted.
async fn appraise_case(case: &Case) -> Result<Value, AttestationError> {
    let verifier = verifier_for(case);
    let policy = policy_for(case)?;
    let appraisal = verifier
        .appraise_json(&read(&case.evidence), &policy)
        .await?;
    Ok(serde_json::to_value(&appraisal).unwrap())
}

/// What this implementation decides for a case: the stripped appraisal, or
/// the refusal (its code is the decision; its message helps authors).
async fn decide(case: &Case) -> Result<Value, AttestationError> {
    let mut v = appraise_case(case).await?;
    strip(&mut v);
    Ok(v)
}

/// The section numbers the design doc has headings for.
fn doc_sections() -> Vec<String> {
    let doc = std::fs::read_to_string(root().join("../docs/design/cvm-attestation-profile-v1.md"))
        .unwrap();
    doc.lines()
        .filter_map(|l| l.strip_prefix("#"))
        .map(|l| l.trim_start_matches('#').trim())
        .filter_map(|l| l.split_whitespace().next())
        .map(|n| n.trim_end_matches('.').to_string())
        .filter(|n| n.chars().next().is_some_and(|c| c.is_ascii_digit()))
        .collect()
}

fn load_cases() -> Vec<Case> {
    let dir = root().join("cases");
    let mut paths: Vec<PathBuf> = std::fs::read_dir(&dir)
        .unwrap_or_else(|e| panic!("{}: {e}", dir.display()))
        .map(|e| e.unwrap().path())
        .filter(|p| p.extension().is_some_and(|x| x == "json"))
        .collect();
    paths.sort();
    paths
        .iter()
        .map(|p| {
            let case: Case = serde_json::from_slice(&std::fs::read(p).unwrap())
                .unwrap_or_else(|e| panic!("{}: {e}", p.display()));
            assert_eq!(
                Some(case.id.as_str()),
                p.file_stem().and_then(|s| s.to_str()),
                "a case file is named by its id"
            );
            case
        })
        .collect()
}

#[tokio::test]
async fn the_corpus_holds_against_this_implementation() {
    if std::env::var_os("UPDATE_CONFORMANCE").is_some() {
        author::write_all().await;
    }
    let sections = doc_sections();
    let cases = load_cases();
    assert!(!cases.is_empty(), "no cases under conformance/cases");
    let mut failures = Vec::new();
    for case in &cases {
        let section = case.rule.section.split_whitespace().next().unwrap_or("");
        if !sections.iter().any(|s| s == section) {
            failures.push(format!(
                "{}: cites section {:?}, which the design doc does not have",
                case.id, case.rule.section
            ));
            continue;
        }
        let decided = decide(case).await;
        // CONFORMANCE_EXPLAIN=1 prints each decision with the implementation's
        // reason, so a reviewer can see a refusal came from the rule its case names.
        if std::env::var_os("CONFORMANCE_EXPLAIN").is_some() {
            match &decided {
                Ok(_) => eprintln!("{:<60} appraised", case.id),
                Err(e) => eprintln!("{:<60} {:<22} {e}", case.id, e.refusal_code().to_string()),
            }
        }
        let got = decided.map_err(|e| e.refusal_code());
        let verdict = match (&case.expect, &got) {
            (Expect::Refusal(want), Err(code)) if want == code => Ok(()),
            (Expect::Refusal(want), Err(code)) => {
                Err(format!("refused with {code}, expected {want}"))
            }
            (Expect::Refusal(want), Ok(_)) => Err(format!("appraised, expected refusal {want}")),
            (Expect::Appraisal(_), Err(code)) => {
                Err(format!("refused with {code}, expected an appraisal"))
            }
            (Expect::Appraisal(path), Ok(v)) => {
                let want: Value = serde_json::from_slice(&read(path)).unwrap();
                if *v == want {
                    Ok(())
                } else {
                    Err(format!(
                        "appraisal differs from {path}:\n{}",
                        diff(&want, v)
                    ))
                }
            }
        };
        if let Err(why) = verdict {
            failures.push(format!("{}: {why}", case.id));
        }
    }
    assert!(
        failures.is_empty(),
        "{} of {} cases failed:\n{}",
        failures.len(),
        cases.len(),
        failures.join("\n")
    );
}

/// The JSON pointers at which two values differ.
fn diff(want: &Value, got: &Value) -> String {
    fn walk(path: &str, a: &Value, b: &Value, out: &mut Vec<String>) {
        match (a, b) {
            (Value::Object(x), Value::Object(y)) => {
                for k in x.keys().chain(y.keys().filter(|k| !x.contains_key(*k))) {
                    match (x.get(k), y.get(k)) {
                        (Some(va), Some(vb)) => walk(&format!("{path}/{k}"), va, vb, out),
                        (Some(_), None) => out.push(format!("{path}/{k}: missing")),
                        (None, Some(_)) => out.push(format!("{path}/{k}: unexpected")),
                        (None, None) => {}
                    }
                }
            }
            _ if a != b => out.push(format!("{path}: expected {a}, got {b}")),
            _ => {}
        }
    }
    let mut out = Vec::new();
    walk("", want, got, &mut out);
    out.join("\n")
}

/// The authored cases: the recordings this repository holds, each as the
/// profile envelope, and the rules they can show. Run with
/// `UPDATE_CONFORMANCE=1`; the expected appraisals come from this
/// implementation and the expected refusals are checked against it, so an
/// authored expectation this implementation does not meet fails here.
mod author {
    use super::*;
    use attestation::profile::Evidence;

    mod synthetic;

    const SNP_REPORT: &[u8] = include_bytes!("../test_data/snp/live-report-v5-genoa.bin");
    const SNP_VCEK: &[u8] = include_bytes!("../test_data/snp/live-vcek-genoa.der");
    const V4_QUOTE: &[u8] = include_bytes!("../test_data/tdx_quote_4.dat");
    const LIVE_QUOTE: &[u8] = include_bytes!("../test_data/tdx_quote_live.dat");
    const LIVE_CCEL: &[u8] = include_bytes!("../test_data/tdx_ccel_live.bin");
    const LIVE_CCEL2: &[u8] = include_bytes!("../test_data/tdx_ccel_live2.dat");
    const TCB_INFO: &[u8] = include_bytes!("../test_data/collateral/tcb_info_50806f000000.json");
    const TD_QE_IDENTITY: &[u8] = include_bytes!("../test_data/collateral/td_qe_identity.json");
    const TCB_SIGNING_CHAIN: &[u8] =
        include_bytes!("../test_data/collateral/tcb_signing_chain.pem");
    const QE_SIGNING_CHAIN: &[u8] =
        include_bytes!("../test_data/collateral/qe_identity_signing_chain.pem");
    const PCK_CRL: &[u8] = include_bytes!("../test_data/collateral/pck_crl_platform.der");
    const ROOT_CRL: &[u8] = include_bytes!("../test_data/collateral/root_ca_crl.der");
    const AZ_TDX: &[u8] = include_bytes!("../test_data/az_tdx/live-evidence.json");
    const AZ_SNP: &[u8] = include_bytes!("../test_data/az_snp/live-evidence.json");
    /// AMD KDS, fetched 2026-09-22: thisUpdate 2026-08-19, nextUpdate 2026-10-04.
    const GENOA_CRL: &[u8] = include_bytes!("../test_data/snp/genoa-crl-2026-08-19.der");

    const SNP_NOW: &str = "2026-09-22T00:00:00Z";
    /// The Intel fixtures were captured 2026-03-16 and expire 2026-04-15.
    const TDX_FIXTURE_NOW: &str = "2026-03-17T00:00:00Z";

    fn b64url(b: &[u8]) -> String {
        Bytes(b.to_vec()).encode()
    }

    fn snp_nonce() -> Vec<u8> {
        let report = attestation::platforms::snp::verify::parse_report(SNP_REPORT).unwrap();
        attestation::utils::strip_trailing_nulls(&report.report_data).to_vec()
    }

    fn snp_envelope(nonce: &[u8]) -> Value {
        json!({
            "eat_profile": PROFILE_URI,
            "eat_nonce": b64url(nonce),
            "cvm_version": 1,
            "submods": {
                "cpu": {
                    "cvm_platform": {"vendor": "amd", "tee": "sev-snp", "hosting": "bare"},
                    "cvm_report": ["application/vnd.confidential-ai.sev-snp-report", b64url(SNP_REPORT), 4],
                    "cvm_binding": {"pattern": "challenge", "mode": "report-data"},
                    "cvm_endorsements": {
                        "__cmwc_t": "tag:confidential.ai,2026:cvm-endorsements#1",
                        "snp.vek": ["application/pkix-cert", b64url(SNP_VCEK), 2]
                    }
                }
            }
        })
    }

    /// The nonce a quote bound: its report data without padding, or 32 zero
    /// bytes for a quote taken with zero report data, whose pad64 form it is.
    fn tdx_nonce(quote: &[u8]) -> Vec<u8> {
        let q = attestation::platforms::tdx::verify::parse_tdx_quote(quote).unwrap();
        let stripped = attestation::utils::strip_trailing_nulls(&q.body.report_data);
        if stripped.is_empty() {
            vec![0u8; 32]
        } else {
            stripped.to_vec()
        }
    }

    fn tdx_envelope(quote: &[u8]) -> Value {
        json!({
            "eat_profile": PROFILE_URI,
            "eat_nonce": b64url(&tdx_nonce(quote)),
            "cvm_version": 1,
            "submods": {
                "cpu": {
                    "cvm_platform": {"vendor": "intel", "tee": "tdx", "hosting": "bare"},
                    "cvm_report": ["application/vnd.confidential-ai.tdx-quote", b64url(quote), 4],
                    "cvm_binding": {"pattern": "challenge", "mode": "report-data"}
                }
            }
        })
    }

    /// The TDX envelope with its RTMRs as registers and a CCEL.
    fn tdx_envelope_with_ccel(quote: &[u8], ccel: &[u8]) -> Value {
        let q = attestation::platforms::tdx::verify::parse_tdx_quote(quote).unwrap();
        let rtmrs = [q.body.rtmr_0, q.body.rtmr_1, q.body.rtmr_2, q.body.rtmr_3];
        let mut env = tdx_envelope(quote);
        env["submods"]["cpu"]["cvm_registers"] = rtmrs
            .iter()
            .enumerate()
            .map(|(i, r)| {
                json!({"index": i, "alg": "sha384", "value": b64url(r), "source": "tdx-rtmr", "backing": "hardware"})
            })
            .collect();
        env["submods"]["cpu"]["cvm_log"] = json!({"format": "tdx-ccel", "data": b64url(ccel)});
        env
    }

    fn lenient() -> VerifyPolicy {
        let mut p = VerifyPolicy::default();
        p.tcb.require_revocation = false;
        p.tcb.require_signed_collateral = false;
        p
    }

    /// The v4 TDX fixture was minted with the TD debug attribute set and
    /// predates SEPT_VE_DISABLE enforcement.
    fn v4_policy() -> VerifyPolicy {
        let mut p = VerifyPolicy::default();
        p.policy_bits.allow_debug = true;
        p.policy_bits.require_sept_ve_disable = false;
        p.tcb.tdx_allowed_status = vec![
            TdxTcbStatus::UpToDate,
            TdxTcbStatus::SWHardeningNeeded,
            TdxTcbStatus::OutOfDate,
            TdxTcbStatus::ConfigurationNeeded,
            TdxTcbStatus::ConfigurationAndSWHardeningNeeded,
            TdxTcbStatus::OutOfDateConfigurationNeeded,
        ];
        p
    }

    fn tdx_fixture_collateral() -> BTreeMap<String, CollateralRef> {
        write("collateral/tcb_info_50806f000000.json", TCB_INFO);
        write("collateral/tcb_signing_chain.pem", TCB_SIGNING_CHAIN);
        write("collateral/td_qe_identity.json", TD_QE_IDENTITY);
        write("collateral/qe_identity_signing_chain.pem", QE_SIGNING_CHAIN);
        write("collateral/pck_crl_platform.der", PCK_CRL);
        write("collateral/root_ca_crl.der", ROOT_CRL);
        let signed = |body: &str, chain: &str| CollateralRef::Signed {
            body: body.into(),
            signing_chain: chain.into(),
        };
        BTreeMap::from([
            (
                "tdx_tcb_info/50806f000000".to_string(),
                signed(
                    "collateral/tcb_info_50806f000000.json",
                    "collateral/tcb_signing_chain.pem",
                ),
            ),
            (
                "tdx_qe_identity/td".to_string(),
                signed(
                    "collateral/td_qe_identity.json",
                    "collateral/qe_identity_signing_chain.pem",
                ),
            ),
            (
                "tdx_pck_crl/platform".to_string(),
                CollateralRef::File("collateral/pck_crl_platform.der".into()),
            ),
            (
                "tdx_root_crl".to_string(),
                CollateralRef::File("collateral/root_ca_crl.der".into()),
            ),
        ])
    }

    /// An Azure recording as the profile envelope, through the legacy mapping.
    fn azure_envelope(legacy: &[u8], hosting: &str) -> (Value, Vec<u8>) {
        let raw: Value = serde_json::from_slice(legacy).unwrap();
        let evidence = if raw.get("evidence").is_some() {
            raw.clone()
        } else {
            json!({"platform": hosting, "evidence": raw})
        };
        let tpm_message = hex::decode(
            evidence["evidence"]["tpm_quote"]["message"]
                .as_str()
                .unwrap(),
        )
        .unwrap();
        let nonce = attestation::platforms::tpm_common::extract_tpm_nonce(&tpm_message).unwrap();
        let mapped =
            Evidence::from_legacy(&serde_json::to_vec(&evidence).unwrap(), &nonce, None).unwrap();
        (
            serde_json::from_slice(&mapped.to_json().unwrap()).unwrap(),
            nonce,
        )
    }

    /// An inline PCS artifact: `{body, issuer_chain}` as the profile carries it.
    fn pcs(body: &[u8], chain: &[u8]) -> String {
        b64url(
            serde_json::to_vec(&json!({"body": b64url(body), "issuer_chain": b64url(chain)}))
                .unwrap()
                .as_slice(),
        )
    }

    /// The v4 TDX envelope carrying the March fixtures inline, with the root
    /// CRL's signature corrupted.
    fn tdx_envelope_with_forged_inline_root_crl() -> Value {
        let mut forged = ROOT_CRL.to_vec();
        let n = forged.len();
        forged[n - 1] ^= 0xff;
        forged[n - 2] ^= 0xff;
        let mut env = tdx_envelope(V4_QUOTE);
        env["submods"]["cpu"]["cvm_endorsements"] = json!({
            "__cmwc_t": "tag:confidential.ai,2026:cvm-endorsements#1",
            "tdx.root_crl": ["application/pkix-crl", b64url(&forged), 2],
            "tdx.pck_crl": ["application/pkix-crl", b64url(PCK_CRL), 2],
            "tdx.tcb_info": ["application/vnd.confidential-ai.pcs-signed+json", pcs(TCB_INFO, TCB_SIGNING_CHAIN), 2],
            "tdx.qe_identity": ["application/vnd.confidential-ai.pcs-signed+json", pcs(TD_QE_IDENTITY, QE_SIGNING_CHAIN), 2]
        });
        env
    }

    /// The fixture collateral with the TCB Info body altered under its
    /// signature (the issue date's year).
    fn tdx_fixture_collateral_with_forged_tcb_info() -> BTreeMap<String, CollateralRef> {
        let text = std::str::from_utf8(TCB_INFO).unwrap();
        let forged = text.replacen("2026-03-16T", "2025-03-16T", 1);
        assert_ne!(forged, text, "the TCB Info fixture carries its issue date");
        write(
            "collateral/tcb_info_50806f000000.forged.json",
            forged.as_bytes(),
        );
        let mut map = tdx_fixture_collateral();
        map.insert(
            "tdx_tcb_info/50806f000000".to_string(),
            CollateralRef::Signed {
                body: "collateral/tcb_info_50806f000000.forged.json".into(),
                signing_chain: "collateral/tcb_signing_chain.pem".into(),
            },
        );
        map
    }

    fn snp_crl_collateral(forged: bool) -> BTreeMap<String, CollateralRef> {
        let path = if forged {
            let mut bytes = GENOA_CRL.to_vec();
            let n = bytes.len();
            bytes[n - 1] ^= 0xff;
            bytes[n - 2] ^= 0xff;
            write("collateral/amd_genoa_crl_2026-08-19.forged.der", &bytes);
            "collateral/amd_genoa_crl_2026-08-19.forged.der"
        } else {
            write("collateral/amd_genoa_crl_2026-08-19.der", GENOA_CRL);
            "collateral/amd_genoa_crl_2026-08-19.der"
        };
        BTreeMap::from([(
            "snp_crl/Genoa".to_string(),
            CollateralRef::File(path.into()),
        )])
    }

    /// An authored input: a JSON value, written pretty, or exact bytes (a
    /// duplicate member, a size bound).
    pub(super) enum Input {
        Json(Value),
        Raw(Vec<u8>),
    }

    impl From<Value> for Input {
        fn from(v: Value) -> Self {
            Input::Json(v)
        }
    }

    impl From<VerifyPolicy> for Input {
        /// Written from the struct, so members keep the declaration order.
        fn from(p: VerifyPolicy) -> Self {
            Input::Raw(serde_json::to_vec_pretty(&p).unwrap())
        }
    }

    impl Input {
        fn bytes(&self) -> Vec<u8> {
            match self {
                Input::Json(v) => serde_json::to_vec_pretty(v).unwrap(),
                Input::Raw(b) => b.clone(),
            }
        }
    }

    /// Inputs over 1 MiB are stored gzip-compressed (section 14.2), with a
    /// fixed header so the file is the same on every run.
    const GZIP_OVER: usize = 1 << 20;

    fn store(dir: &str, id: &str, input: &Input) -> String {
        let bytes = input.bytes();
        let plain = format!("{dir}/{id}.json");
        let gz = format!("{plain}.gz");
        for stale in [&plain, &gz] {
            let _ = std::fs::remove_file(root().join("inputs").join(stale));
        }
        if bytes.len() <= GZIP_OVER {
            write(&plain, &bytes);
            return plain;
        }
        use std::io::Write;
        let mut enc = flate2::GzBuilder::new()
            .mtime(0)
            .write(Vec::new(), flate2::Compression::best());
        enc.write_all(&bytes).unwrap();
        write(&gz, &enc.finish().unwrap());
        gz
    }

    struct Authored {
        id: &'static str,
        section: &'static str,
        statement: &'static str,
        now: &'static str,
        evidence: Input,
        policy: Option<Input>,
        collateral: BTreeMap<String, CollateralRef>,
        expect: Option<RefusalCode>,
    }

    fn cases() -> Vec<Authored> {
        let nonce = snp_nonce();
        let mut wrong_nonce = nonce.clone();
        wrong_nonce[0] ^= 1;
        let tdx = tdx_fixture_collateral();
        let (az_tdx, _) = azure_envelope(AZ_TDX, "az-tdx");
        let (az_snp, _) = azure_envelope(AZ_SNP, "az-snp");
        let snp_report = attestation::platforms::snp::verify::parse_report(SNP_REPORT).unwrap();
        let mut azure_policy = v4_policy();
        azure_policy.tcb.require_revocation = false;
        azure_policy.tcb.require_signed_collateral = false;
        azure_policy.min_backing = Backing::PrivilegedService;
        let mut az_snp_policy = lenient();
        az_snp_policy.min_backing = Backing::PrivilegedService;
        let mut az_snp_pcr8 = az_snp_policy.clone();
        az_snp_pcr8.reference.pcrs.insert(
            8,
            vec![Digest {
                alg: HashAlg::Sha256,
                value: Bytes(vec![7u8; 32]),
            }],
        );
        let mut floor_above = lenient();
        floor_above.tcb.floors.insert(
            "f".into(),
            TcbFloor {
                snp: Some(SnpFloor {
                    min: SnpTcb {
                        bootloader: 255,
                        tee: 0,
                        snp: 0,
                        microcode: 0,
                        fmc: None,
                    },
                    values: vec![SnpTcbValue::Reported],
                }),
                tdx: None,
            },
        );
        floor_above.tcb.default_floor = Some("f".into());
        let mut launch_pinned = lenient();
        launch_pinned.reference.launch_measurement = vec![Digest {
            alg: HashAlg::Sha384,
            value: Bytes(vec![0u8; 48]),
        }];
        let mut other_machine = lenient();
        other_machine.identity = Some(IdentityPolicy {
            machines: vec![MachineEntry {
                id: Bytes(vec![9u8; 64]),
                tcb_floor: None,
            }],
        });
        let mut this_machine = lenient();
        this_machine.identity = Some(IdentityPolicy {
            machines: vec![MachineEntry {
                id: Bytes(snp_report.chip_id.to_vec()),
                tcb_floor: None,
            }],
        });
        let mut pcr_pinned = lenient();
        pcr_pinned.reference.pcrs.insert(
            8,
            vec![Digest {
                alg: HashAlg::Sha256,
                value: Bytes(vec![0u8; 32]),
            }],
        );
        let mut revocation_required = lenient();
        revocation_required.tcb.require_revocation = true;
        let mut up_to_date_only = v4_policy();
        up_to_date_only.tcb.tdx_allowed_status = vec![TdxTcbStatus::UpToDate];
        let mut hinted = snp_envelope(&nonce);
        hinted["submods"]["cpu"]["dbgstat"] = json!("enabled");
        let mut stray_claim = snp_envelope(&nonce);
        stray_claim["submods"]["cpu"]["cvm_extra"] = json!(1);
        let mut stray_field = snp_envelope(&nonce);
        stray_field["submods"]["cpu"]["cvm_binding"]["extra"] = json!(1);
        let mut altered_rtmr = tdx_envelope_with_ccel(LIVE_QUOTE, LIVE_CCEL2);
        altered_rtmr["submods"]["cpu"]["cvm_registers"][0]["value"] = json!(b64url(&[1u8; 48]));
        let mut live_lenient = v4_policy();
        live_lenient.tcb.require_revocation = false;
        live_lenient.tcb.require_signed_collateral = false;
        let mut revocation_checked = lenient();
        revocation_checked.tcb.require_revocation = true;

        vec![
            Authored {
                id: "snp-genoa-report-data",
                section: "4.5",
                statement: "report-data: report_data == pad64(anchor); a Genoa report with its VEK inline appraises",
                now: SNP_NOW,
                evidence: snp_envelope(&nonce).into(),
                policy: Some(lenient().into()),
                collateral: BTreeMap::new(),
                expect: None,
            },
            Authored {
                id: "snp-nonce-not-bound",
                section: "4.5",
                statement: "report-data: report_data == pad64(anchor); another nonce is refused",
                now: SNP_NOW,
                evidence: snp_envelope(&wrong_nonce).into(),
                policy: Some(lenient().into()),
                collateral: BTreeMap::new(),
                expect: Some(RefusalCode::BindingMismatch),
            },
            Authored {
                id: "snp-dbgstat-hint-contradicts-report",
                section: "5.1",
                statement: "an attester dbgstat hint that contradicts the signed report is refused",
                now: SNP_NOW,
                evidence: hinted.into(),
                policy: Some(lenient().into()),
                collateral: BTreeMap::new(),
                expect: Some(RefusalCode::EnvelopeInvalid),
            },
            Authored {
                id: "snp-unknown-submodule-claim-ignored",
                section: "4.10",
                statement: "unknown claims at the top level or in a submodule claims set are ignored, as EAT extensibility requires",
                now: SNP_NOW,
                evidence: stray_claim.into(),
                policy: Some(lenient().into()),
                collateral: BTreeMap::new(),
                expect: None,
            },
            Authored {
                id: "snp-unknown-cvm-field-refused",
                section: "4.10",
                statement: "an unknown field inside any cvm_* object is rejected",
                now: SNP_NOW,
                evidence: stray_field.into(),
                policy: Some(lenient().into()),
                collateral: BTreeMap::new(),
                expect: Some(RefusalCode::EnvelopeInvalid),
            },
            Authored {
                id: "snp-tcb-below-floor",
                section: "7",
                statement: "a TCB floor bounds each value it names; reported below the floor is refused",
                now: SNP_NOW,
                evidence: snp_envelope(&nonce).into(),
                policy: Some(floor_above.into()),
                collateral: BTreeMap::new(),
                expect: Some(RefusalCode::TcbNotAllowed),
            },
            Authored {
                id: "snp-launch-measurement-not-in-reference",
                section: "7",
                statement: "a pinned launch measurement the report does not match is refused",
                now: SNP_NOW,
                evidence: snp_envelope(&nonce).into(),
                policy: Some(launch_pinned.into()),
                collateral: BTreeMap::new(),
                expect: Some(RefusalCode::ReferenceMismatch),
            },
            Authored {
                id: "snp-machine-not-on-allowlist",
                section: "6",
                statement: "step 3: when policy carries a machine allowlist, the authenticated identity must be on it",
                now: SNP_NOW,
                evidence: snp_envelope(&nonce).into(),
                policy: Some(other_machine.into()),
                collateral: BTreeMap::new(),
                expect: Some(RefusalCode::MachineNotAllowed),
            },
            Authored {
                id: "snp-machine-on-allowlist",
                section: "6",
                statement: "step 3: the authenticated identity on the allowlist appraises",
                now: SNP_NOW,
                evidence: snp_envelope(&nonce).into(),
                policy: Some(this_machine.into()),
                collateral: BTreeMap::new(),
                expect: None,
            },
            Authored {
                id: "snp-pcr-pin-without-vtpm",
                section: "7",
                statement: "a vTPM PCR pin cannot be honored by evidence without a vtpm submodule",
                now: SNP_NOW,
                evidence: snp_envelope(&nonce).into(),
                policy: Some(pcr_pinned.into()),
                collateral: BTreeMap::new(),
                expect: Some(RefusalCode::ReferenceMismatch),
            },
            Authored {
                id: "snp-revocation-required-without-crl",
                section: "6",
                statement: "step 6: policy requires revocation and no CRL can be obtained",
                now: SNP_NOW,
                evidence: snp_envelope(&nonce).into(),
                policy: Some(revocation_required.into()),
                collateral: BTreeMap::new(),
                expect: Some(RefusalCode::CollateralUnavailable),
            },
            Authored {
                id: "tdx-v4-quote-with-fixture-collateral",
                section: "6",
                statement: "step 6: revocation, TCB status and QE identity from signed collateral; the debug attribute is reported in the vector",
                now: TDX_FIXTURE_NOW,
                evidence: tdx_envelope(V4_QUOTE).into(),
                policy: Some(v4_policy().into()),
                collateral: tdx.clone(),
                expect: None,
            },
            Authored {
                id: "tdx-debug-attribute-refused",
                section: "6",
                statement: "step 4: TD debug bit clear unless policy allows",
                now: TDX_FIXTURE_NOW,
                evidence: tdx_envelope(V4_QUOTE).into(),
                policy: None,
                collateral: tdx.clone(),
                expect: Some(RefusalCode::GuestPolicy),
            },
            Authored {
                id: "tdx-tcb-status-not-allowed",
                section: "7",
                statement: "tcb.tdx_allowed_status: a status outside the set is refused",
                now: TDX_FIXTURE_NOW,
                evidence: tdx_envelope(V4_QUOTE).into(),
                policy: Some(up_to_date_only.into()),
                collateral: tdx.clone(),
                expect: Some(RefusalCode::TcbNotAllowed),
            },
            Authored {
                id: "tdx-collateral-required-but-unavailable",
                section: "6",
                statement: "step 6: policy requires signed collateral and none can be obtained",
                now: TDX_FIXTURE_NOW,
                evidence: tdx_envelope(V4_QUOTE).into(),
                policy: Some(v4_policy().into()),
                collateral: BTreeMap::new(),
                expect: Some(RefusalCode::CollateralUnavailable),
            },
            Authored {
                id: "tdx-inline-root-crl-forged",
                section: "4.6",
                statement: "inline endorsements are inputs, never authority: a root CRL whose signature does not verify is refused",
                now: TDX_FIXTURE_NOW,
                evidence: tdx_envelope_with_forged_inline_root_crl().into(),
                policy: Some(v4_policy().into()),
                collateral: BTreeMap::new(),
                expect: Some(RefusalCode::CollateralInvalid),
            },
            Authored {
                id: "tdx-collateral-past-its-window",
                section: "4.6",
                statement: "every validity window and nextUpdate is checked before use: the March fixtures evaluated in May are refused",
                now: "2026-05-01T00:00:00Z",
                evidence: tdx_envelope(V4_QUOTE).into(),
                policy: Some(v4_policy().into()),
                collateral: tdx.clone(),
                expect: Some(RefusalCode::CollateralInvalid),
            },
            Authored {
                id: "tdx-tcb-info-signature-forged",
                section: "6",
                statement: "step 6: TCB status comes from TCB Info with its signing chain anchored; a body altered under the signature is refused",
                now: TDX_FIXTURE_NOW,
                evidence: tdx_envelope(V4_QUOTE).into(),
                policy: Some(v4_policy().into()),
                collateral: tdx_fixture_collateral_with_forged_tcb_info(),
                expect: Some(RefusalCode::CollateralInvalid),
            },
            Authored {
                id: "snp-crl-checked",
                section: "6",
                statement: "step 6: revocation checked against AMD's CRL for the generation, signed by the ARK and inside its window",
                now: SNP_NOW,
                evidence: snp_envelope(&nonce).into(),
                policy: Some(revocation_checked.clone().into()),
                collateral: snp_crl_collateral(false),
                expect: None,
            },
            Authored {
                id: "snp-crl-past-its-window",
                section: "4.6",
                statement: "every validity window and nextUpdate is checked before use: AMD's CRL after its nextUpdate is refused",
                now: "2026-12-01T00:00:00Z",
                evidence: snp_envelope(&nonce).into(),
                policy: Some(revocation_checked.clone().into()),
                collateral: snp_crl_collateral(false),
                expect: Some(RefusalCode::CollateralInvalid),
            },
            Authored {
                id: "snp-crl-forged",
                section: "6",
                statement: "step 6: a CRL whose signature does not verify against the ARK is refused",
                now: SNP_NOW,
                evidence: snp_envelope(&nonce).into(),
                policy: Some(revocation_checked.into()),
                collateral: snp_crl_collateral(true),
                expect: Some(RefusalCode::CollateralInvalid),
            },
            Authored {
                id: "tdx-ccel-replays-every-rtmr",
                section: "4.8",
                statement: "tdx-ccel: the log replays into RTMR 0 to 3, each reproducing the signed value",
                now: SNP_NOW,
                evidence: tdx_envelope_with_ccel(LIVE_QUOTE, LIVE_CCEL2).into(),
                policy: Some(live_lenient.clone().into()),
                collateral: BTreeMap::new(),
                expect: None,
            },
            Authored {
                id: "tdx-ccel-from-another-boot",
                section: "4.8",
                statement: "tdx-ccel: a log that does not replay to the signed RTMR 0 to 2 is refused",
                now: SNP_NOW,
                evidence: tdx_envelope_with_ccel(LIVE_QUOTE, LIVE_CCEL).into(),
                policy: Some(live_lenient.clone().into()),
                collateral: BTreeMap::new(),
                expect: Some(RefusalCode::ReplayMismatch),
            },
            Authored {
                id: "tdx-register-differs-from-quote",
                section: "4.7",
                statement: "for tdx-rtmr the envelope values must equal the signed report",
                now: SNP_NOW,
                evidence: altered_rtmr.into(),
                policy: Some(live_lenient.into()),
                collateral: BTreeMap::new(),
                expect: Some(RefusalCode::RegisterMismatch),
            },
            Authored {
                id: "azure-tdx-through-vtpm",
                section: "4.4",
                statement: "vtpm: the TD quote binds through vtpm-extradata and the quoted PCRs become privileged-service registers",
                now: SNP_NOW,
                evidence: az_tdx.into(),
                policy: Some(azure_policy.into()),
                collateral: BTreeMap::new(),
                expect: None,
            },
            Authored {
                id: "azure-snp-through-vtpm",
                section: "4.4",
                statement: "vtpm: the SNP report binds through vtpm-extradata and the quoted PCRs become privileged-service registers",
                now: SNP_NOW,
                evidence: az_snp.clone().into(),
                policy: Some(az_snp_policy.into()),
                collateral: BTreeMap::new(),
                expect: None,
            },
            Authored {
                id: "azure-snp-pcr8-not-in-reference",
                section: "7",
                statement: "reference.pcrs: a quoted PCR outside its reference values is refused",
                now: SNP_NOW,
                evidence: az_snp.into(),
                policy: Some(az_snp_pcr8.into()),
                collateral: BTreeMap::new(),
                expect: Some(RefusalCode::ReferenceMismatch),
            },
        ]
    }

    pub async fn write_all() {
        let dir = root().join("cases");
        std::fs::create_dir_all(&dir).unwrap();
        let mut ids = std::collections::BTreeSet::new();
        for a in cases().into_iter().chain(synthetic::cases()) {
            assert!(ids.insert(a.id), "{}: authored twice", a.id);
            let evidence_path = store("evidence", a.id, &a.evidence);
            let policy_path = a.policy.as_ref().map(|p| store("policy", a.id, p));
            let mut case = Case {
                id: a.id.to_string(),
                rule: Rule {
                    section: a.section.to_string(),
                    statement: a.statement.to_string(),
                },
                now: a.now.to_string(),
                evidence: evidence_path,
                policy: policy_path,
                collateral: a.collateral,
                nras: Vec::new(),
                expect: Expect::Refusal(RefusalCode::EnvelopeInvalid),
            };
            let got = decide(&case).await;
            case.expect = match (a.expect, got) {
                (None, Ok(v)) => {
                    let path = format!("expected/{}.json", a.id);
                    write(&path, &serde_json::to_vec_pretty(&v).unwrap());
                    Expect::Appraisal(path)
                }
                (Some(want), Err(e)) if want == e.refusal_code() => Expect::Refusal(want),
                (Some(want), Err(e)) => panic!(
                    "{}: authored to refuse with {want}, this implementation refuses with {}: {e}",
                    a.id,
                    e.refusal_code()
                ),
                (Some(want), Ok(_)) => panic!(
                    "{}: authored to refuse with {want}, this implementation appraises",
                    a.id
                ),
                (None, Err(e)) => panic!(
                    "{}: authored to appraise, this implementation refuses with {}: {e}",
                    a.id,
                    e.refusal_code()
                ),
            };
            let mut text = serde_json::to_string_pretty(&case).unwrap();
            text.push('\n');
            std::fs::write(dir.join(format!("{}.json", a.id)), text).unwrap();
        }
        // Section 5.1: the policy id names the effective policy, so the
        // defaults written out and no policy at all are one appraisal.
        let same = |a: &str, b: &str| {
            let read_expected = |id: &str| read(&format!("expected/{id}.json"));
            assert_eq!(read_expected(a), read_expected(b), "{a} and {b} differ");
        };
        same(
            "snp-crl-checked-under-the-default-policy",
            "snp-crl-checked-with-defaults-spelled-out",
        );
        same("envelope-at-size-bound", "snp-genoa-report-data");
    }
}

/// Section 8: the CDDL module (`schemas/cvm-profile-v1.cddl`) agrees with the
/// committed JSON Schemas and with this implementation's parsers, on every
/// input of the corpus and on single-point changes of the inputs that cover
/// every member path. For each instance:
///
/// - what the CDDL accepts, the JSON Schema accepts (the schema may be looser);
/// - what the parser accepts, the CDDL accepts;
/// - what the CDDL accepts, the parser accepts, unless the parser's refusal is
///   one of the rules CDDL cannot state (`PROSE`).
///
/// The CDDL verdicts come from `cddl-check`, the JSON Schema ones from the
/// `jsonschema` crate.
#[tokio::test]
async fn the_cddl_module_agrees_with_the_schemas_and_the_parsers() {
    use check::{mutants, paths, shrink, Checker, Root};
    let checker = Checker::load();

    // Every input of the corpus, and every appraisal as this implementation
    // emits it.
    let mut bases: Vec<(Root, Value)> = Vec::new();
    for case in load_cases() {
        if let Ok(v) = serde_json::from_slice::<Value>(&read(&case.evidence)) {
            bases.push((Root::Evidence, v));
        }
        if let Some(p) = &case.policy {
            bases.push((Root::Policy, serde_json::from_slice(&read(p)).unwrap()));
        }
        if matches!(case.expect, Expect::Appraisal(_)) {
            bases.push((Root::Appraisal, appraise_case(&case).await.unwrap()));
        }
    }
    bases.push((Root::Policy, json!({})));
    bases.sort_by_cached_key(|(r, v)| (*r as u8, v.to_string()));
    bases.dedup();

    // Mutate the fewest bases that cover every member path of their root.
    let mut instances: Vec<(Root, Value, String)> = bases
        .iter()
        .map(|(r, v)| (*r, v.clone(), "as in the corpus".to_string()))
        .collect();
    for root in [Root::Evidence, Root::Policy, Root::Appraisal] {
        let mut uncovered: BTreeSet<String> = bases
            .iter()
            .filter(|(r, _)| *r == root)
            .flat_map(|(_, v)| paths(v))
            .collect();
        let mut pool: Vec<Value> = bases
            .iter()
            .filter(|(r, _)| *r == root)
            .map(|(_, v)| shrink(v))
            .collect();
        while !uncovered.is_empty() {
            let (i, gain) = pool
                .iter()
                .enumerate()
                .map(|(i, v)| (i, paths(v).intersection(&uncovered).count()))
                .max_by_key(|(_, g)| *g)
                .unwrap();
            assert!(gain > 0);
            let base = pool.swap_remove(i);
            for p in paths(&base) {
                uncovered.remove(&p);
            }
            for (what, m) in mutants(&base) {
                instances.push((root, m, what));
            }
        }
    }
    instances.sort_by_cached_key(|(r, v, _)| (*r as u8, v.to_string()));
    instances.dedup_by(|a, b| a.0 == b.0 && a.1 == b.1);

    let verdicts = checker.run(&instances);
    let mut failures = Vec::new();
    let mut prose_seen = BTreeSet::new();
    for ((root, value, what), (cddl, schema)) in instances.iter().zip(&verdicts) {
        let parsed = match root {
            Root::Evidence => Some(
                attestation::profile::Evidence::from_json(value.to_string().as_bytes())
                    .map(|_| ())
                    .map_err(|e| e.to_string()),
            ),
            Root::Policy => Some(
                VerifyPolicy::from_json(value.to_string().as_bytes())
                    .map(|_| ())
                    .map_err(|e| e.to_string()),
            ),
            Root::Appraisal => None,
        };
        let text = || {
            let t = value.to_string();
            if t.len() > 400 {
                format!("{}...", &t[..400])
            } else {
                t
            }
        };
        if *cddl && !*schema {
            failures.push(format!(
                "{root:?} {what}: the CDDL accepts what the JSON Schema refuses: {}",
                text()
            ));
        }
        match parsed {
            Some(Ok(())) if !*cddl => failures.push(format!(
                "{root:?} {what}: the parser accepts what the CDDL refuses: {}",
                text()
            )),
            Some(Err(e)) if *cddl => match PROSE.iter().find(|(needle, _)| e.contains(needle)) {
                Some((_, rule)) => {
                    prose_seen.insert(*rule);
                }
                None => failures.push(format!(
                    "{root:?} {what}: the CDDL accepts what the parser refuses ({e}): {}",
                    text()
                )),
            },
            None if what == "as in the corpus" && !(*cddl && *schema) => failures.push(format!(
                "{root:?}: an emitted appraisal fails the {}: {}",
                if *cddl { "JSON Schema" } else { "CDDL" },
                text()
            )),
            _ => {}
        }
    }
    eprintln!(
        "CDDL check: {} instances, prose rules exercised: {:?}",
        instances.len(),
        prose_seen
    );
    assert!(
        failures.is_empty(),
        "{} disagreements:\n{}",
        failures.len(),
        failures.join("\n")
    );
}

/// The rules of sections 4 and 7 that CDDL cannot state, by the parser's
/// refusal: uniqueness, equality between two members, and names that must
/// resolve inside the same document.
const PROSE: &[(&str, &str)] = &[
    (
        "duplicate register",
        "4.7: each register index appears once",
    ),
    (
        "differs from the quoted PCR",
        "4.7: a vtpm register equals the quoted PCR of its index",
    ),
    (
        "carries all 16 snp-vmr registers",
        "4.9: the commitment carries each of the 16 slots once",
    ),
    (
        "differs from the submodule name",
        "4.4: a device's uuid is the <ueid> of its name",
    ),
    (
        "is not in tcb.floors",
        "7: a floor name names one of tcb.floors",
    ),
    (
        "empty or repeated",
        "7: an SNP floor names each TCB value at most once",
    ),
    (
        "evidence too large",
        "4.10: the whole envelope is at most 10 MiB",
    ),
];

mod check {
    use super::*;

    #[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
    pub enum Root {
        Evidence,
        Policy,
        Appraisal,
    }

    impl Root {
        fn cddl(self) -> &'static str {
            match self {
                Root::Evidence => "cvm-evidence",
                Root::Policy => "cvm-policy",
                Root::Appraisal => "cvm-appraisal",
            }
        }
        fn schema(self) -> &'static str {
            match self {
                Root::Evidence => "cvm-evidence-v1.json",
                Root::Policy => "cvm-policy-v1.json",
                Root::Appraisal => "cvm-claims-v1.json",
            }
        }
    }

    pub struct Checker {
        module: cddl_check::Module,
        schemas: Vec<(Root, jsonschema::Validator)>,
    }

    impl Checker {
        pub fn load() -> Self {
            let dir = root().join("../schemas");
            let text = std::fs::read_to_string(dir.join("cvm-profile-v1.cddl")).unwrap();
            let module = cddl_check::Module::parse(&text).unwrap_or_else(|e| panic!("{e}"));
            let schemas = [Root::Evidence, Root::Policy, Root::Appraisal]
                .into_iter()
                .map(|r| {
                    let schema: Value =
                        serde_json::from_slice(&std::fs::read(dir.join(r.schema())).unwrap())
                            .unwrap();
                    let v = jsonschema::validator_for(&schema)
                        .unwrap_or_else(|e| panic!("{}: {e}", r.schema()));
                    (r, v)
                })
                .collect();
            Checker { module, schemas }
        }

        /// (the CDDL accepts, the JSON Schema accepts) for each instance.
        pub fn run(&self, instances: &[(Root, Value, String)]) -> Vec<(bool, bool)> {
            instances
                .iter()
                .map(|(r, v, _)| {
                    let cddl = self.module.validate(r.cddl(), v, &["json"]).unwrap();
                    let schema = self
                        .schemas
                        .iter()
                        .find(|(s, _)| s == r)
                        .map(|(_, s)| s.is_valid(v))
                        .unwrap();
                    (cddl, schema)
                })
                .collect()
        }
    }

    /// The member paths of a value: array positions and device names folded.
    pub fn paths(v: &Value) -> BTreeSet<String> {
        fn walk(v: &Value, at: String, out: &mut BTreeSet<String>) {
            out.insert(at.clone());
            match v {
                Value::Object(m) => {
                    for (k, x) in m {
                        let k = if k.starts_with("gpu/") || k.starts_with("nvswitch/") {
                            k.split('/').next().unwrap().to_string() + "/*"
                        } else {
                            k.clone()
                        };
                        walk(x, format!("{at}/{k}"), out);
                    }
                }
                Value::Array(a) => {
                    for x in a {
                        walk(x, format!("{at}/#"), out);
                    }
                }
                _ => {}
            }
        }
        let mut out = BTreeSet::new();
        walk(v, String::new(), &mut out);
        out
    }

    fn is_b64url(s: &str) -> bool {
        !s.is_empty()
            && s.bytes()
                .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
    }

    /// A base for mutation: long byte strings and the nonce made small, so
    /// every change is checked quickly. The parsers bound these fields only
    /// by being non-empty and at most 1 MiB, so no verdict moves.
    pub fn shrink(v: &Value) -> Value {
        fn walk(v: &mut Value) {
            match v {
                Value::String(s) if s.len() > 128 && is_b64url(s) => *s = "AAAA".into(),
                Value::Object(m) => m.values_mut().for_each(walk),
                Value::Array(a) => a.iter_mut().for_each(walk),
                _ => {}
            }
        }
        let mut v = v.clone();
        walk(&mut v);
        v
    }

    fn pointer(path: &[String]) -> String {
        path.iter()
            .map(|s| format!("/{}", s.replace('~', "~0").replace('/', "~1")))
            .collect()
    }

    /// Every single-point change of `root`: each value replaced by values of
    /// other types, removed, doubled or emptied, strings made non-canonical,
    /// integers moved past their bounds, an unknown member added.
    pub fn mutants(root: &Value) -> Vec<(String, Value)> {
        let mut out = Vec::new();
        let mut stack = vec![(Vec::<String>::new(), root.clone())];
        while let Some((path, node)) = stack.pop() {
            let at = pointer(&path);
            fn change(
                out: &mut Vec<(String, Value)>,
                root: &Value,
                at: &str,
                what: String,
                f: &dyn Fn(&mut Value),
            ) {
                let mut m = root.clone();
                if let Some(slot) = m.pointer_mut(at) {
                    f(slot);
                    if m != *root {
                        out.push((format!("{what} at {at}"), m));
                    }
                }
            }
            if !path.is_empty() {
                for replacement in [
                    Value::Null,
                    json!(true),
                    json!(0),
                    json!(-1),
                    json!(1.5),
                    json!(""),
                    json!("zz"),
                    json!([]),
                    json!({}),
                ] {
                    let r = replacement.clone();
                    change(
                        &mut out,
                        root,
                        &at,
                        format!("replaced by {replacement}"),
                        &move |s| *s = r.clone(),
                    );
                }
                let (parent, last) = path.split_at(path.len() - 1);
                let parent_at = pointer(parent);
                let mut m = root.clone();
                match m.pointer_mut(&parent_at) {
                    Some(Value::Object(o)) => {
                        o.remove(&last[0]);
                        out.push((format!("removed at {at}"), m));
                    }
                    Some(Value::Array(a)) => {
                        a.remove(last[0].parse::<usize>().unwrap());
                        out.push((format!("removed at {at}"), m));
                    }
                    _ => {}
                }
            }
            match &node {
                Value::Object(o) => {
                    change(&mut out, root, &at, "unknown member added".into(), &|s| {
                        s.as_object_mut()
                            .unwrap()
                            .insert("zz_unknown".into(), json!(1));
                    });
                    for (k, x) in o {
                        let mut p = path.clone();
                        p.push(k.clone());
                        stack.push((p, x.clone()));
                    }
                }
                Value::Array(a) => {
                    if let Some(first) = a.first().cloned() {
                        change(
                            &mut out,
                            root,
                            &at,
                            "first element doubled".into(),
                            &move |s| {
                                s.as_array_mut().unwrap().push(first.clone());
                            },
                        );
                    }
                    for (i, x) in a.iter().enumerate() {
                        let mut p = path.clone();
                        p.push(i.to_string());
                        stack.push((p, x.clone()));
                    }
                }
                Value::String(s) if is_b64url(s) => {
                    let t = s.clone();
                    change(&mut out, root, &at, "padded".into(), &move |x| {
                        *x = json!(format!("{t}="))
                    });
                    let t = s.clone();
                    change(&mut out, root, &at, "standard alphabet".into(), &move |x| {
                        *x = json!(format!("+{t}"))
                    });
                    let t = s.clone();
                    change(
                        &mut out,
                        root,
                        &at,
                        "last character dropped".into(),
                        &move |x| *x = json!(t[..t.len() - 1].to_string()),
                    );
                }
                Value::Number(n) => {
                    if let Some(i) = n.as_i64() {
                        change(&mut out, root, &at, "plus one".into(), &move |x| {
                            *x = json!(i + 1)
                        });
                        change(&mut out, root, &at, "minus one".into(), &move |x| {
                            *x = json!(i - 1)
                        });
                    }
                    change(&mut out, root, &at, "u64::MAX".into(), &|x| {
                        *x = json!(u64::MAX)
                    });
                }
                _ => {}
            }
        }
        out
    }
}
