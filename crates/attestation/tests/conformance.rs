#![cfg(all(feature = "snp", feature = "tdx", feature = "nvidia-gpu"))]
//! The conformance corpus (design doc section 14), run against this
//! implementation: every case under `conformance/cases` must reproduce its
//! decision. With `UPDATE_CONFORMANCE=1` the authored cases and their expected
//! appraisals are rewritten from this implementation, which is the reference.

use attestation::collateral::{
    CertProvider, CollateralKey, Jwks, NrasProvider, NrasRequest, SignedCollateral,
    TdxCollateralProvider, NRAS_GPU_URL, NRAS_SWITCH_URL,
};
use attestation::profile::{
    Backing, Bytes, Digest, HashAlg, IdentityPolicy, MachineEntry, SnpFloor, SnpTcbValue, TcbFloor,
    VerifyPolicy, PROFILE_URI,
};
use attestation::{
    AttestationError, NvidiaGpuArch, ProcessorGeneration, RefusalCode, SnpTcb, TdxTcbStatus,
    Verifier,
};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::collections::BTreeMap;
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

fn read(path: &str) -> Vec<u8> {
    let p = root().join("inputs").join(path);
    std::fs::read(&p).unwrap_or_else(|e| panic!("{}: {e}", p.display()))
}

fn write(path: &str, bytes: &[u8]) {
    let p = root().join("inputs").join(path);
    std::fs::create_dir_all(p.parent().unwrap()).unwrap();
    std::fs::write(&p, bytes).unwrap_or_else(|e| panic!("{}: {e}", p.display()));
}

/// The case's collateral, served by key; nothing else exists.
#[derive(Clone)]
struct CaseCollateral {
    files: BTreeMap<String, CollateralRef>,
    now: DateTime<Utc>,
}

impl CaseCollateral {
    fn bytes(&self, key: &str) -> attestation::Result<Vec<u8>> {
        match self.files.get(key) {
            Some(CollateralRef::File(p)) => Ok(read(p)),
            Some(CollateralRef::Signed { .. }) => Err(AttestationError::CertFetchError(format!(
                "{key}: the case carries a signed artifact where bytes were expected"
            ))),
            None => Err(AttestationError::CertFetchError(format!(
                "{key}: the case carries no such collateral"
            ))),
        }
    }

    fn signed(&self, key: &str) -> attestation::Result<SignedCollateral> {
        match self.files.get(key) {
            Some(CollateralRef::Signed {
                body,
                signing_chain,
            }) => Ok(SignedCollateral {
                body: read(body),
                signing_chain: read(signing_chain),
            }),
            Some(CollateralRef::File(_)) => Err(AttestationError::CertFetchError(format!(
                "{key}: the case carries bytes where a signed artifact was expected"
            ))),
            None => Err(AttestationError::CertFetchError(format!(
                "{key}: the case carries no such collateral"
            ))),
        }
    }

    fn has_tdx(&self) -> bool {
        self.files.keys().any(|k| k.starts_with("tdx_"))
    }
}

#[async_trait::async_trait]
impl CertProvider for CaseCollateral {
    async fn get_snp_vcek(
        &self,
        generation: ProcessorGeneration,
        chip_id: &[u8; 64],
        tcb: &SnpTcb,
    ) -> attestation::Result<Vec<u8>> {
        let key = CollateralKey::SnpVcek {
            generation,
            chip_id: *chip_id,
            tcb: *tcb,
        };
        self.bytes(&key.id())
    }
    async fn get_snp_cert_chain(
        &self,
        generation: ProcessorGeneration,
    ) -> attestation::Result<(Vec<u8>, Vec<u8>)> {
        Err(AttestationError::CertFetchError(format!(
            "snp_cert_chain/{}: the corpus carries no vendor chains; the roots are embedded",
            generation.product_name()
        )))
    }
    async fn get_snp_crl(
        &self,
        generation: ProcessorGeneration,
    ) -> attestation::Result<Option<Vec<u8>>> {
        let key = CollateralKey::SnpCrl { generation }.id();
        match self.files.get(&key) {
            Some(_) => self.bytes(&key).map(Some),
            None => Ok(None),
        }
    }
}

#[async_trait::async_trait]
impl TdxCollateralProvider for CaseCollateral {
    async fn get_tcb_info(&self, fmspc: &str) -> attestation::Result<SignedCollateral> {
        self.signed(&format!("tdx_tcb_info/{}", fmspc.to_ascii_lowercase()))
    }
    async fn get_qe_identity(&self) -> attestation::Result<SignedCollateral> {
        self.signed("tdx_qe_identity/sgx")
    }
    async fn get_td_qe_identity(&self) -> attestation::Result<SignedCollateral> {
        self.signed("tdx_qe_identity/td")
    }
    async fn get_root_ca_crl(&self) -> attestation::Result<Vec<u8>> {
        self.bytes("tdx_root_crl")
    }
    async fn get_pck_crl(&self, ca: &str) -> attestation::Result<Vec<u8>> {
        self.bytes(&format!("tdx_pck_crl/{ca}"))
    }
    fn now(&self) -> DateTime<Utc> {
        self.now
    }
}

/// The case's recorded NRAS exchanges; a request the case did not record is
/// unavailable collateral.
struct CaseNras {
    exchanges: Vec<NrasExchange>,
}

#[async_trait::async_trait]
impl NrasProvider for CaseNras {
    fn url_for(&self, arch: NvidiaGpuArch) -> &str {
        match arch {
            NvidiaGpuArch::Ls10 => NRAS_SWITCH_URL,
            _ => NRAS_GPU_URL,
        }
    }
    async fn attest(&self, request: &NrasRequest) -> attestation::Result<Value> {
        let arch = request.arch.to_string();
        let hit = self
            .exchanges
            .iter()
            .find(|e| e.arch.eq_ignore_ascii_case(&arch) && e.nonce == request.nonce)
            .ok_or_else(|| {
                AttestationError::NrasRequestFailed(format!(
                    "the case records no NRAS exchange for {arch} with nonce {}",
                    request.nonce
                ))
            })?;
        serde_json::from_slice(&read(&hit.response))
            .map_err(|e| AttestationError::NrasResponseParse(e.to_string()))
    }
    async fn jwks(&self, arch: NvidiaGpuArch) -> attestation::Result<Jwks> {
        let arch = arch.to_string();
        let hit = self
            .exchanges
            .iter()
            .find(|e| e.arch.eq_ignore_ascii_case(&arch))
            .ok_or_else(|| {
                AttestationError::JwksFetch(format!("the case records no JWKS for {arch}"))
            })?;
        serde_json::from_slice(&read(&hit.jwks))
            .map_err(|e| AttestationError::JwksFetch(e.to_string()))
    }
}

fn verifier_for(case: &Case) -> Verifier {
    let now: DateTime<Utc> = case
        .now
        .parse::<DateTime<chrono::FixedOffset>>()
        .unwrap_or_else(|e| panic!("{}: now: {e}", case.id))
        .with_timezone(&Utc);
    let collateral = CaseCollateral {
        files: case.collateral.clone(),
        now,
    };
    let mut v = Verifier::offline()
        .with_cert_provider(collateral.clone())
        .with_nras_provider(CaseNras {
            exchanges: case.nras.clone(),
        })
        .with_clock(std::sync::Arc::new(move || now));
    if collateral.has_tdx() {
        v = v.with_tdx_provider(collateral);
    }
    v
}

fn policy_for(case: &Case) -> VerifyPolicy {
    match &case.policy {
        Some(p) => serde_json::from_slice(&read(p)).unwrap_or_else(|e| panic!("{}: {e}", case.id)),
        None => VerifyPolicy::default(),
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

/// What this implementation decides for a case: the stripped appraisal, or
/// the refusal (its code is the decision; its message helps authors).
async fn decide(case: &Case) -> Result<Value, AttestationError> {
    let verifier = verifier_for(case);
    let policy = policy_for(case);
    match verifier.appraise_json(&read(&case.evidence), &policy).await {
        Ok(a) => {
            let mut v = serde_json::to_value(&a).unwrap();
            strip(&mut v);
            Ok(v)
        }
        Err(e) => Err(e),
    }
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
        let got = decide(case).await.map_err(|e| e.refusal_code());
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

    struct Authored {
        id: &'static str,
        section: &'static str,
        statement: &'static str,
        now: &'static str,
        evidence: Value,
        policy: Option<VerifyPolicy>,
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

        vec![
            Authored {
                id: "snp-genoa-report-data",
                section: "4.5",
                statement: "report-data: report_data == pad64(anchor); a Genoa report with its VEK inline appraises",
                now: SNP_NOW,
                evidence: snp_envelope(&nonce),
                policy: Some(lenient()),
                collateral: BTreeMap::new(),
                expect: None,
            },
            Authored {
                id: "snp-nonce-not-bound",
                section: "4.5",
                statement: "report-data: report_data == pad64(anchor); another nonce is refused",
                now: SNP_NOW,
                evidence: snp_envelope(&wrong_nonce),
                policy: Some(lenient()),
                collateral: BTreeMap::new(),
                expect: Some(RefusalCode::BindingMismatch),
            },
            Authored {
                id: "snp-dbgstat-hint-contradicts-report",
                section: "5.1",
                statement: "an attester dbgstat hint that contradicts the signed report is refused",
                now: SNP_NOW,
                evidence: hinted,
                policy: Some(lenient()),
                collateral: BTreeMap::new(),
                expect: Some(RefusalCode::EnvelopeInvalid),
            },
            Authored {
                id: "snp-unknown-submodule-claim-ignored",
                section: "4.10",
                statement: "unknown claims at the top level or in a submodule claims set are ignored, as EAT extensibility requires",
                now: SNP_NOW,
                evidence: stray_claim,
                policy: Some(lenient()),
                collateral: BTreeMap::new(),
                expect: None,
            },
            Authored {
                id: "snp-unknown-cvm-field-refused",
                section: "4.10",
                statement: "an unknown field inside any cvm_* object is rejected",
                now: SNP_NOW,
                evidence: stray_field,
                policy: Some(lenient()),
                collateral: BTreeMap::new(),
                expect: Some(RefusalCode::EnvelopeInvalid),
            },
            Authored {
                id: "snp-tcb-below-floor",
                section: "7",
                statement: "a TCB floor bounds each value it names; reported below the floor is refused",
                now: SNP_NOW,
                evidence: snp_envelope(&nonce),
                policy: Some(floor_above),
                collateral: BTreeMap::new(),
                expect: Some(RefusalCode::TcbNotAllowed),
            },
            Authored {
                id: "snp-launch-measurement-not-in-reference",
                section: "7",
                statement: "a pinned launch measurement the report does not match is refused",
                now: SNP_NOW,
                evidence: snp_envelope(&nonce),
                policy: Some(launch_pinned),
                collateral: BTreeMap::new(),
                expect: Some(RefusalCode::ReferenceMismatch),
            },
            Authored {
                id: "snp-machine-not-on-allowlist",
                section: "6",
                statement: "step 3: when policy carries a machine allowlist, the authenticated identity must be on it",
                now: SNP_NOW,
                evidence: snp_envelope(&nonce),
                policy: Some(other_machine),
                collateral: BTreeMap::new(),
                expect: Some(RefusalCode::MachineNotAllowed),
            },
            Authored {
                id: "snp-machine-on-allowlist",
                section: "6",
                statement: "step 3: the authenticated identity on the allowlist appraises",
                now: SNP_NOW,
                evidence: snp_envelope(&nonce),
                policy: Some(this_machine),
                collateral: BTreeMap::new(),
                expect: None,
            },
            Authored {
                id: "snp-pcr-pin-without-vtpm",
                section: "7",
                statement: "a vTPM PCR pin cannot be honored by evidence without a vtpm submodule",
                now: SNP_NOW,
                evidence: snp_envelope(&nonce),
                policy: Some(pcr_pinned),
                collateral: BTreeMap::new(),
                expect: Some(RefusalCode::ReferenceMismatch),
            },
            Authored {
                id: "snp-revocation-required-without-crl",
                section: "6",
                statement: "step 6: policy requires revocation and no CRL can be obtained",
                now: SNP_NOW,
                evidence: snp_envelope(&nonce),
                policy: Some(revocation_required),
                collateral: BTreeMap::new(),
                expect: Some(RefusalCode::CollateralUnavailable),
            },
            Authored {
                id: "tdx-v4-quote-with-fixture-collateral",
                section: "6",
                statement: "step 6: revocation, TCB status and QE identity from signed collateral; the debug attribute is reported in the vector",
                now: TDX_FIXTURE_NOW,
                evidence: tdx_envelope(V4_QUOTE),
                policy: Some(v4_policy()),
                collateral: tdx.clone(),
                expect: None,
            },
            Authored {
                id: "tdx-debug-attribute-refused",
                section: "6",
                statement: "step 4: TD debug bit clear unless policy allows",
                now: TDX_FIXTURE_NOW,
                evidence: tdx_envelope(V4_QUOTE),
                policy: None,
                collateral: tdx.clone(),
                expect: Some(RefusalCode::GuestPolicy),
            },
            Authored {
                id: "tdx-tcb-status-not-allowed",
                section: "7",
                statement: "tcb.tdx_allowed_status: a status outside the set is refused",
                now: TDX_FIXTURE_NOW,
                evidence: tdx_envelope(V4_QUOTE),
                policy: Some(up_to_date_only),
                collateral: tdx.clone(),
                expect: Some(RefusalCode::TcbNotAllowed),
            },
            Authored {
                id: "tdx-collateral-required-but-unavailable",
                section: "6",
                statement: "step 6: policy requires signed collateral and none can be obtained",
                now: TDX_FIXTURE_NOW,
                evidence: tdx_envelope(V4_QUOTE),
                policy: Some(v4_policy()),
                collateral: BTreeMap::new(),
                expect: Some(RefusalCode::CollateralUnavailable),
            },
            Authored {
                id: "tdx-ccel-replays-every-rtmr",
                section: "4.8",
                statement: "tdx-ccel: the log replays into RTMR 0 to 3, each reproducing the signed value",
                now: SNP_NOW,
                evidence: tdx_envelope_with_ccel(LIVE_QUOTE, LIVE_CCEL2),
                policy: Some(live_lenient.clone()),
                collateral: BTreeMap::new(),
                expect: None,
            },
            Authored {
                id: "tdx-ccel-from-another-boot",
                section: "4.8",
                statement: "tdx-ccel: a log that does not replay to the signed RTMR 0 to 2 is refused",
                now: SNP_NOW,
                evidence: tdx_envelope_with_ccel(LIVE_QUOTE, LIVE_CCEL),
                policy: Some(live_lenient.clone()),
                collateral: BTreeMap::new(),
                expect: Some(RefusalCode::ReplayMismatch),
            },
            Authored {
                id: "tdx-register-differs-from-quote",
                section: "4.7",
                statement: "for tdx-rtmr the envelope values must equal the signed report",
                now: SNP_NOW,
                evidence: altered_rtmr,
                policy: Some(live_lenient),
                collateral: BTreeMap::new(),
                expect: Some(RefusalCode::RegisterMismatch),
            },
            Authored {
                id: "azure-tdx-through-vtpm",
                section: "4.4",
                statement: "vtpm: the TD quote binds through vtpm-extradata and the quoted PCRs become privileged-service registers",
                now: SNP_NOW,
                evidence: az_tdx,
                policy: Some(azure_policy),
                collateral: BTreeMap::new(),
                expect: None,
            },
            Authored {
                id: "azure-snp-through-vtpm",
                section: "4.4",
                statement: "vtpm: the SNP report binds through vtpm-extradata and the quoted PCRs become privileged-service registers",
                now: SNP_NOW,
                evidence: az_snp.clone(),
                policy: Some(az_snp_policy),
                collateral: BTreeMap::new(),
                expect: None,
            },
            Authored {
                id: "azure-snp-pcr8-not-in-reference",
                section: "7",
                statement: "reference.pcrs: a quoted PCR outside its reference values is refused",
                now: SNP_NOW,
                evidence: az_snp,
                policy: Some(az_snp_pcr8),
                collateral: BTreeMap::new(),
                expect: Some(RefusalCode::ReferenceMismatch),
            },
        ]
    }

    pub async fn write_all() {
        let dir = root().join("cases");
        std::fs::create_dir_all(&dir).unwrap();
        for a in cases() {
            let evidence_path = format!("evidence/{}.json", a.id);
            write(
                &evidence_path,
                &serde_json::to_vec_pretty(&a.evidence).unwrap(),
            );
            let policy_path = a.policy.as_ref().map(|p| {
                let path = format!("policy/{}.json", a.id);
                write(&path, &serde_json::to_vec_pretty(p).unwrap());
                path
            });
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
    }
}
