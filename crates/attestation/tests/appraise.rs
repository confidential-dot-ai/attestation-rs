#![cfg(all(feature = "snp", feature = "tdx"))]
//! `appraise` end to end on the SNP and TDX fixtures, with inline
//! endorsements and fixture collateral, no network.

use attestation::collateral::{CertProvider, SignedCollateral, TdxCollateralProvider};
use attestation::profile::{
    AttesterClaims, Backing, Bytes, DebugStatus, Digest, HashAlg, Identity, KeyBinding, KeyKind,
    SnpFloor, SnpTcbValue, Tcb, TcbFloor, Tier, VerifyPolicy, PROFILE_URI,
};
use attestation::{ProcessorGeneration, SnpTcb, TdxTcbStatus, Verifier};
use base64::engine::general_purpose::STANDARD as BASE64;
use base64::Engine;
use serde_json::json;

const SNP_REPORT: &[u8] = include_bytes!("../test_data/snp/live-report-v5-genoa.bin");
const SNP_VCEK: &[u8] = include_bytes!("../test_data/snp/live-vcek-genoa.der");
const V4_QUOTE: &[u8] = include_bytes!("../test_data/tdx_quote_4.dat");
const TCB_INFO: &[u8] = include_bytes!("../test_data/collateral/tcb_info_50806f000000.json");
const TD_QE_IDENTITY: &[u8] = include_bytes!("../test_data/collateral/td_qe_identity.json");
const TCB_SIGNING_CHAIN: &[u8] = include_bytes!("../test_data/collateral/tcb_signing_chain.pem");
const QE_SIGNING_CHAIN: &[u8] =
    include_bytes!("../test_data/collateral/qe_identity_signing_chain.pem");
const PCK_CRL: &[u8] = include_bytes!("../test_data/collateral/pck_crl_platform.der");
const ROOT_CRL: &[u8] = include_bytes!("../test_data/collateral/root_ca_crl.der");

/// No network: no CRL, no chain.
struct NoCollateral;

#[async_trait::async_trait]
impl CertProvider for NoCollateral {
    async fn get_snp_vcek(
        &self,
        _: ProcessorGeneration,
        _: &[u8; 64],
        _: &SnpTcb,
    ) -> attestation::Result<Vec<u8>> {
        Err(attestation::AttestationError::CertFetchError(
            "offline".into(),
        ))
    }
    async fn get_snp_cert_chain(
        &self,
        _: ProcessorGeneration,
    ) -> attestation::Result<(Vec<u8>, Vec<u8>)> {
        Err(attestation::AttestationError::CertFetchError(
            "offline".into(),
        ))
    }
}

const TCB_INFO_LIVE: &[u8] = include_bytes!("../test_data/collateral/tcb_info_90c06f000000.json");
const LIVE_QUOTE: &[u8] = include_bytes!("../test_data/tdx_quote_live.dat");
const LIVE_CCEL: &[u8] = include_bytes!("../test_data/tdx_ccel_live.bin");
const LIVE_CCEL2: &[u8] = include_bytes!("../test_data/tdx_ccel_live2.dat");

/// Fixture collateral, captured 2026-03-16 and expiring 2026-04-15, so a
/// verifier using it runs at the day after capture.
struct Fixtures;

fn fixture_clock() -> attestation::Clock {
    std::sync::Arc::new(|| {
        chrono::TimeZone::with_ymd_and_hms(&chrono::Utc, 2026, 3, 17, 0, 0, 0).unwrap()
    })
}

#[async_trait::async_trait]
impl TdxCollateralProvider for Fixtures {
    async fn get_tcb_info(&self, fmspc: &str) -> attestation::Result<SignedCollateral> {
        let body = match fmspc {
            "50806f000000" => TCB_INFO.to_vec(),
            "90c06f000000" => TCB_INFO_LIVE.to_vec(),
            other => panic!("no fixture for FMSPC {other}"),
        };
        Ok(SignedCollateral {
            body,
            signing_chain: TCB_SIGNING_CHAIN.to_vec(),
        })
    }
    fn now(&self) -> chrono::DateTime<chrono::Utc> {
        chrono::TimeZone::with_ymd_and_hms(&chrono::Utc, 2026, 3, 17, 0, 0, 0).unwrap()
    }
    async fn get_qe_identity(&self) -> attestation::Result<SignedCollateral> {
        Err(attestation::AttestationError::CertFetchError(
            "no SGX QE fixture".into(),
        ))
    }
    async fn get_td_qe_identity(&self) -> attestation::Result<SignedCollateral> {
        Ok(SignedCollateral {
            body: TD_QE_IDENTITY.to_vec(),
            signing_chain: QE_SIGNING_CHAIN.to_vec(),
        })
    }
    async fn get_root_ca_crl(&self) -> attestation::Result<Vec<u8>> {
        Ok(ROOT_CRL.to_vec())
    }
    async fn get_pck_crl(&self, _ca: &str) -> attestation::Result<Vec<u8>> {
        Ok(PCK_CRL.to_vec())
    }
}

fn b64url(b: &[u8]) -> String {
    Bytes(b.to_vec()).encode()
}

/// The live Genoa report's report_data is what its attester bound; the
/// profile's anchor with no key is the nonce itself, so a nonce equal to the
/// unpadded report_data reproduces it.
fn snp_nonce() -> Vec<u8> {
    let report = attestation::platforms::snp::verify::parse_report(SNP_REPORT).unwrap();
    attestation::utils::strip_trailing_nulls(&report.report_data).to_vec()
}

fn snp_envelope(nonce: &[u8]) -> Vec<u8> {
    serde_json::to_vec(&json!({
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
    }))
    .unwrap()
}

fn lenient_policy() -> VerifyPolicy {
    let mut p = VerifyPolicy::default();
    p.tcb.require_revocation = false;
    p.tcb.require_signed_collateral = false;
    p
}

#[tokio::test]
async fn snp_report_with_inline_vek_appraises() {
    let nonce = snp_nonce();
    assert!(
        nonce.len() >= 16,
        "fixture report_data must serve as a nonce"
    );
    let verifier = Verifier::offline().with_cert_provider(NoCollateral);
    let appraisal = verifier
        .appraise_json(&snp_envelope(&nonce), &lenient_policy())
        .await
        .unwrap();
    let cpu = &appraisal.submods["cpu"];
    assert_eq!(cpu.ear_status, Tier::Affirming);
    // No TCB floor and no CRL: nothing assessed the TCB, so no hardware claim.
    assert_eq!(cpu.ear_trustworthiness_vector.hardware, None);
    assert_eq!(cpu.ear_trustworthiness_vector.runtime_opaque, Some(2));
    assert!(appraisal.ear_all_submods_bound.is_true());
    let AttesterClaims::Cpu(claims) = &cpu.ear_attester_claims else {
        panic!("cpu claims")
    };
    assert_eq!(claims.cvm_platform.generation.as_deref(), Some("Genoa"));
    assert!(matches!(claims.cvm_identity, Identity::Snp { .. }));
    assert_eq!(claims.dbgstat, DebugStatus::DisabledSinceBoot);
    assert_eq!(
        cpu.ear_appraisal_policy_ids,
        [PROFILE_URI.to_string(), lenient_policy().id()]
    );
    assert_eq!(
        claims.compat["snp"]["measurement"],
        hex::encode(&claims.cvm_launch_measurement.value.0)
    );
    let j = serde_json::to_value(&appraisal).unwrap();
    assert_eq!(j["submods"]["cpu"]["ear_status"], "affirming");
    assert_eq!(
        j["submods"]["cpu"]["ear_attester_claims"]["dbgstat"],
        "disabled-since-boot"
    );
    assert_eq!(j["eat_profile"], "tag:ietf.org,2026:rats/ear#04");
    assert!(
        j["submods"]["cpu"]["ear_verifier_claims"]["cvm_collateral"]["snp_crl"]["status"]
            == "skipped"
    );
}

/// A floor bounds each TCB value it names, and the error names the value.
#[tokio::test]
async fn snp_floors_hold_every_named_tcb_value() {
    let nonce = snp_nonce();
    let envelope = snp_envelope(&nonce);
    let verifier = Verifier::offline().with_cert_provider(NoCollateral);
    let a = verifier
        .appraise_json(&envelope, &lenient_policy())
        .await
        .unwrap();
    let AttesterClaims::Cpu(c) = &a.submods["cpu"].ear_attester_claims else {
        panic!("cpu claims")
    };
    let Tcb::Snp(set) = &c.cvm_tcb else {
        panic!("snp tcb")
    };
    let floor_at = |min: SnpTcb, values: Vec<SnpTcbValue>| {
        let mut p = lenient_policy();
        p.tcb.floors.insert(
            "f".to_string(),
            TcbFloor {
                snp: Some(SnpFloor { min, values }),
                tdx: None,
            },
        );
        p.tcb.default_floor = Some("f".to_string());
        p
    };
    let all = [set.reported, set.current, set.committed, set.launch];
    let lowest = SnpTcb {
        bootloader: all.iter().map(|t| t.bootloader).min().unwrap(),
        tee: all.iter().map(|t| t.tee).min().unwrap(),
        snp: all.iter().map(|t| t.snp).min().unwrap(),
        microcode: all.iter().map(|t| t.microcode).min().unwrap(),
        fmc: None,
    };
    verifier
        .appraise_json(&envelope, &floor_at(lowest, SnpTcbValue::all()))
        .await
        .expect("a floor at the lowest value holds on all four");
    for (value, have) in [
        (SnpTcbValue::Reported, set.reported),
        (SnpTcbValue::Current, set.current),
        (SnpTcbValue::Committed, set.committed),
        (SnpTcbValue::Launch, set.launch),
    ] {
        let mut min = have;
        min.microcode = have.microcode.checked_add(1).unwrap();
        let err = verifier
            .appraise_json(&envelope, &floor_at(min, vec![value]))
            .await
            .unwrap_err();
        assert!(
            err.to_string().contains(&format!("{} TCB", value.as_str())),
            "{err}"
        );
    }
    // A floor that names the FMC SPL fails a Genoa report, which has none.
    let with_fmc = SnpTcb {
        fmc: Some(0),
        ..lowest
    };
    assert!(verifier
        .appraise_json(&envelope, &floor_at(with_fmc, vec![SnpTcbValue::Reported]))
        .await
        .is_err());
}

#[tokio::test]
async fn a_dbgstat_hint_that_contradicts_the_report_is_refused() {
    let nonce = snp_nonce();
    let verifier = Verifier::offline().with_cert_provider(NoCollateral);
    let mut v: serde_json::Value = serde_json::from_slice(&snp_envelope(&nonce)).unwrap();
    v["submods"]["cpu"]["dbgstat"] = json!("disabled");
    verifier
        .appraise_json(&serde_json::to_vec(&v).unwrap(), &lenient_policy())
        .await
        .expect("a hint that agrees is accepted");
    v["submods"]["cpu"]["dbgstat"] = json!("enabled");
    let err = verifier
        .appraise_json(&serde_json::to_vec(&v).unwrap(), &lenient_policy())
        .await
        .unwrap_err();
    assert!(err.to_string().contains("dbgstat"), "{err}");
    // RFC 9711 JSON carries the text value; the CBOR integer is not JSON.
    v["submods"]["cpu"]["dbgstat"] = json!(2);
    assert!(attestation::profile::Evidence::from_json(&serde_json::to_vec(&v).unwrap()).is_err());
}

#[tokio::test]
async fn snp_policy_failures_are_errors() {
    let nonce = snp_nonce();
    let verifier = Verifier::offline().with_cert_provider(NoCollateral);
    // A PCR pin cannot be honored by evidence without a vtpm submodule.
    let mut pinned = lenient_policy();
    pinned.reference.pcrs.insert(
        8,
        vec![Digest {
            alg: HashAlg::Sha256,
            value: Bytes(vec![0u8; 32]),
        }],
    );
    let err = verifier
        .appraise_json(&snp_envelope(&nonce), &pinned)
        .await
        .unwrap_err();
    assert!(err.to_string().contains("no vtpm submodule"), "{err}");
    // Wrong nonce: the binding fails.
    let mut wrong = nonce.clone();
    wrong[0] ^= 1;
    let err = verifier
        .appraise_json(&snp_envelope(&wrong), &lenient_policy())
        .await
        .unwrap_err();
    assert!(
        matches!(err, attestation::AttestationError::ReportDataMismatch),
        "{err}"
    );
    // Revocation required, no CRL: refused.
    let mut strict = lenient_policy();
    strict.tcb.require_revocation = true;
    let err = verifier
        .appraise_json(&snp_envelope(&nonce), &strict)
        .await
        .unwrap_err();
    assert!(err.to_string().contains("revocation"), "{err}");
    // A launch measurement pin that does not match: refused.
    let mut pinned = lenient_policy();
    pinned.reference.launch_measurement = vec![Digest {
        alg: HashAlg::Sha384,
        value: Bytes(vec![0u8; 48]),
    }];
    let err = verifier
        .appraise_json(&snp_envelope(&nonce), &pinned)
        .await
        .unwrap_err();
    assert!(err.to_string().contains("reference"), "{err}");
    // A machine allowlist without this chip: refused; with it: instance identity affirming.
    let report = attestation::platforms::snp::verify::parse_report(SNP_REPORT).unwrap();
    let mut listed = lenient_policy();
    listed.identity = Some(attestation::profile::IdentityPolicy {
        machines: vec![attestation::profile::MachineEntry {
            id: Bytes(vec![9u8; 64]),
            tcb_floor: None,
        }],
    });
    let err = verifier
        .appraise_json(&snp_envelope(&nonce), &listed)
        .await
        .unwrap_err();
    assert!(err.to_string().contains("allowlist"), "{err}");
    listed.identity = Some(attestation::profile::IdentityPolicy {
        machines: vec![attestation::profile::MachineEntry {
            id: Bytes(report.chip_id.to_vec()),
            tcb_floor: None,
        }],
    });
    let ok = verifier
        .appraise_json(&snp_envelope(&nonce), &listed)
        .await
        .unwrap();
    assert_eq!(
        ok.submods["cpu"]
            .ear_trustworthiness_vector
            .instance_identity,
        Some(2)
    );
    // A pinned launch measurement that matches: executables 3 (launch only).
    let mut pinned_ok = lenient_policy();
    pinned_ok.reference.launch_measurement = vec![Digest {
        alg: HashAlg::Sha384,
        value: Bytes(report.measurement.to_vec()),
    }];
    let ok = verifier
        .appraise_json(&snp_envelope(&nonce), &pinned_ok)
        .await
        .unwrap();
    assert_eq!(
        ok.submods["cpu"].ear_trustworthiness_vector.executables,
        Some(3)
    );
    assert_eq!(
        ok.submods["cpu"].ear_trustworthiness_vector.configuration,
        Some(2)
    );
    // Nothing pinned: no executables claim at all.
    let none = verifier
        .appraise_json(&snp_envelope(&nonce), &lenient_policy())
        .await
        .unwrap();
    assert_eq!(
        none.submods["cpu"].ear_trustworthiness_vector.executables,
        None
    );
    // The host_data gate (Kata initdata): wrong value refused, right value passes.
    let mut host = lenient_policy();
    host.reference.host_data = Some(Bytes(vec![0xEE; 32]));
    let err = verifier
        .appraise_json(&snp_envelope(&nonce), &host)
        .await
        .unwrap_err();
    assert!(
        matches!(err, attestation::AttestationError::InitDataMismatch),
        "{err}"
    );
    host.reference.host_data = Some(Bytes(report.host_data.to_vec()));
    verifier
        .appraise_json(&snp_envelope(&nonce), &host)
        .await
        .unwrap();
    // The certificate pattern needs the relying party's key in policy.
    let mut cert_env: serde_json::Value = serde_json::from_slice(&snp_envelope(&nonce)).unwrap();
    cert_env["submods"]["cpu"]["cvm_binding"] = json!({
        "pattern": "certificate", "mode": "report-data",
        "key": {"kind": "x509-tbs-sha256", "value": b64url(&[0x22; 32])}
    });
    let err = verifier
        .appraise_json(&serde_json::to_vec(&cert_env).unwrap(), &lenient_policy())
        .await
        .unwrap_err();
    assert!(err.to_string().contains("certificate pattern"), "{err}");
    // A key the policy requires that the evidence did not bind: refused.
    let mut keyed = lenient_policy();
    keyed.freshness.key = Some(KeyBinding {
        kind: KeyKind::SpkiSha256,
        value: Bytes(vec![1u8; 32]),
    });
    let err = verifier
        .appraise_json(&snp_envelope(&nonce), &keyed)
        .await
        .unwrap_err();
    assert!(err.to_string().contains("key"), "{err}");
}

fn tdx_nonce() -> Vec<u8> {
    let quote = attestation::platforms::tdx::verify::parse_tdx_quote(V4_QUOTE).unwrap();
    attestation::utils::strip_trailing_nulls(&quote.body.report_data).to_vec()
}

fn tdx_envelope(nonce: &[u8]) -> Vec<u8> {
    serde_json::to_vec(&json!({
        "eat_profile": PROFILE_URI,
        "eat_nonce": b64url(nonce),
        "cvm_version": 1,
        "submods": {
            "cpu": {
                "cvm_platform": {"vendor": "intel", "tee": "tdx", "hosting": "bare"},
                "cvm_report": ["application/vnd.confidential-ai.tdx-quote", b64url(V4_QUOTE), 4],
                "cvm_binding": {"pattern": "challenge", "mode": "report-data"}
            }
        }
    }))
    .unwrap()
}

/// The v4 fixture was minted with the TD debug attribute set and predates
/// SEPT_VE_DISABLE enforcement.
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

#[tokio::test]
async fn tdx_quote_with_fixture_collateral_appraises() {
    let nonce = tdx_nonce();
    let verifier = Verifier::offline()
        .with_cert_provider(NoCollateral)
        .with_tdx_provider(Fixtures)
        .with_clock(fixture_clock());
    let appraisal = verifier
        .appraise_json(&tdx_envelope(&nonce), &v4_policy())
        .await
        .unwrap();
    let cpu = &appraisal.submods["cpu"];
    // Policy allowed debug; the vector still says so (section 5.2).
    assert_eq!(cpu.ear_trustworthiness_vector.configuration, Some(96));
    assert_eq!(cpu.ear_status, Tier::Contraindicated);
    let AttesterClaims::Cpu(claims) = &cpu.ear_attester_claims else {
        panic!("cpu claims")
    };
    assert_eq!(
        claims.cvm_platform.generation.as_deref(),
        Some("50806f000000")
    );
    assert!(matches!(claims.cvm_identity, Identity::Tdx { .. }));
    let regs = claims.cvm_registers.as_ref().unwrap();
    assert_eq!(regs.len(), 4);
    assert!(regs
        .iter()
        .all(|r| r.backing == Backing::Hardware && !r.replayed));
    assert_eq!(claims.dbgstat, DebugStatus::Enabled);
    assert_eq!(claims.compat["tdx_rtmr0"], hex::encode(&regs[0].value.0));
    let j = serde_json::to_value(&appraisal).unwrap();
    assert_eq!(
        j["submods"]["cpu"]["ear_verifier_claims"]["cvm_collateral"]["tdx_tcb_info"]["status"],
        "checked"
    );
    assert!(j["submods"]["cpu"]["ear_attester_claims"]["cvm_tcb"]["status"].is_string());
}

#[tokio::test]
async fn tdx_policy_bits_and_collateral_requirements() {
    let nonce = tdx_nonce();
    let verifier = Verifier::offline()
        .with_cert_provider(NoCollateral)
        .with_tdx_provider(Fixtures)
        .with_clock(fixture_clock());
    let strict = VerifyPolicy::default();
    let err = verifier
        .appraise_json(&tdx_envelope(&nonce), &strict)
        .await
        .unwrap_err();
    assert!(
        matches!(err, attestation::AttestationError::DebugPolicyViolation),
        "{err}"
    );
    // No provider and policy requires collateral: refused before anything is trusted.
    let offline = Verifier::offline().with_cert_provider(NoCollateral);
    let err = offline
        .appraise_json(&tdx_envelope(&nonce), &v4_policy())
        .await
        .unwrap_err();
    assert!(err.to_string().contains("collateral"), "{err}");
    // Without the requirement the checks are reported as skipped and no hardware claim is made.
    let mut lenient = v4_policy();
    lenient.tcb.require_revocation = false;
    lenient.tcb.require_signed_collateral = false;
    let a = offline
        .appraise_json(&tdx_envelope(&nonce), &lenient)
        .await
        .unwrap();
    assert_eq!(a.submods["cpu"].ear_trustworthiness_vector.hardware, None);
    let j = serde_json::to_value(&a).unwrap();
    assert_eq!(
        j["submods"]["cpu"]["ear_verifier_claims"]["cvm_collateral"]["tdx_tcb_info"]["status"],
        "skipped"
    );
}

#[tokio::test]
async fn a_forged_inline_crl_is_rejected_and_the_provider_wins() {
    let nonce = tdx_nonce();
    // No provider: the inline root CRL is the only source, and a corrupted
    // signature must be refused.
    let mut forged = ROOT_CRL.to_vec();
    let n = forged.len();
    forged[n - 1] ^= 0xff;
    forged[n - 2] ^= 0xff;
    let pcs = |body: &[u8], chain: &[u8]| {
        b64url(
            serde_json::to_vec(&json!({"body": b64url(body), "issuer_chain": b64url(chain)}))
                .unwrap()
                .as_slice(),
        )
    };
    let mut env: serde_json::Value = serde_json::from_slice(&tdx_envelope(&nonce)).unwrap();
    env["submods"]["cpu"]["cvm_endorsements"] = json!({
        "__cmwc_t": "tag:confidential.ai,2026:cvm-endorsements#1",
        "tdx.root_crl": ["application/pkix-crl", b64url(&forged), 2],
        "tdx.pck_crl": ["application/pkix-crl", b64url(PCK_CRL), 2],
        "tdx.tcb_info": ["application/vnd.confidential-ai.pcs-signed+json", pcs(TCB_INFO, TCB_SIGNING_CHAIN), 2],
        "tdx.qe_identity": ["application/vnd.confidential-ai.pcs-signed+json", pcs(TD_QE_IDENTITY, QE_SIGNING_CHAIN), 2]
    });
    let offline = Verifier::offline().with_cert_provider(NoCollateral);
    let err = offline
        .appraise_json(&serde_json::to_vec(&env).unwrap(), &v4_policy())
        .await
        .unwrap_err();
    assert!(err.to_string().contains("CRL"), "{err}");

    // With a provider configured, its collateral is used and the forged
    // inline copy never matters.
    let with_provider = Verifier::offline()
        .with_cert_provider(NoCollateral)
        .with_tdx_provider(Fixtures)
        .with_clock(fixture_clock());
    with_provider
        .appraise_json(&serde_json::to_vec(&env).unwrap(), &v4_policy())
        .await
        .unwrap();
}

#[tokio::test]
async fn a_legacy_tdx_log_must_replay_to_the_signed_rtmrs() {
    let quote = attestation::platforms::tdx::verify::parse_tdx_quote(LIVE_QUOTE).unwrap();
    // The live attester bound nothing: report_data is all zero, which a
    // 64-byte zero nonce reproduces exactly.
    let rd = &quote.body.report_data;
    let nonce = if rd.iter().all(|b| *b == 0) {
        vec![0u8; 64]
    } else {
        attestation::utils::strip_trailing_nulls(rd).to_vec()
    };
    // The live platform has no TCB Info fixture (the live PCS tests cover
    // it), so this runs without collateral under a policy that allows that;
    // the DCAP chain still anchors at the pinned Intel root.
    let verifier = Verifier::offline().with_cert_provider(NoCollateral);
    let mut policy = v4_policy();
    policy.tcb.require_revocation = false;
    policy.tcb.require_signed_collateral = false;
    let legacy = |log: &[u8]| {
        serde_json::to_vec(&json!({
            "platform": "tdx",
            "evidence": {"quote": BASE64.encode(LIVE_QUOTE), "cc_eventlog": BASE64.encode(log)}
        }))
        .unwrap()
    };
    // A log from another boot does not replay to the quote's RTMRs: refused.
    let err = verifier
        .appraise_legacy_json(&legacy(LIVE_CCEL), &nonce, None, &policy)
        .await
        .unwrap_err();
    assert!(
        matches!(
            err,
            attestation::AttestationError::EventlogIntegrityFailed(_)
        ),
        "{err}"
    );
    // The log captured with this quote replays, and the registers say so.
    let a = verifier
        .appraise_legacy_json(&legacy(LIVE_CCEL2), &nonce, None, &policy)
        .await
        .unwrap();
    let AttesterClaims::Cpu(claims) = &a.submods["cpu"].ear_attester_claims else {
        panic!()
    };
    let regs = claims.cvm_registers.as_ref().unwrap();
    // This guest made no runtime extend, so the log reproduces RTMR 3 as well.
    assert_eq!(
        regs.iter().map(|r| r.replayed).collect::<Vec<_>>(),
        vec![true, true, true, true]
    );
}

/// The nonce a recorded Azure attestation bound (its TPM quote's extraData),
/// and the same nonce with its last byte changed.
fn recorded_nonce(evidence: &serde_json::Value) -> (Vec<u8>, Vec<u8>) {
    let message = hex::decode(evidence["tpm_quote"]["message"].as_str().unwrap()).unwrap();
    let nonce = attestation::platforms::tpm_common::extract_tpm_nonce(&message).unwrap();
    let mut wrong = nonce.clone();
    *wrong.last_mut().unwrap() ^= 1;
    (nonce, wrong)
}

/// The launch measurement of a recorded Azure attestation, as the pin that
/// `vtpm-extradata` requires (section 9.4.4).
fn launch_pin(legacy: &[u8], nonce: &[u8]) -> Digest {
    let evidence = attestation::profile::Evidence::from_legacy(legacy, nonce, None).unwrap();
    let Some(attestation::profile::Submod::Cpu(cpu)) = evidence.submods.get("cpu") else {
        panic!("cpu submodule")
    };
    let raw = cpu.cvm_report.value.as_slice();
    let value = if cpu.cvm_platform.tee == attestation::profile::Tee::Tdx {
        attestation::platforms::tdx::verify::parse_tdx_quote(raw)
            .unwrap()
            .body
            .mr_td
            .to_vec()
    } else {
        attestation::platforms::snp::verify::parse_report(raw)
            .unwrap()
            .measurement
            .to_vec()
    };
    Digest {
        alg: HashAlg::Sha384,
        value: Bytes(value),
    }
}

#[tokio::test]
async fn azure_tdx_evidence_appraises_through_the_vtpm() {
    // Recorded on an Azure TDX VM; the nonce is the one the recording bound.
    let raw: serde_json::Value =
        serde_json::from_slice(include_bytes!("../test_data/az_tdx/live-evidence.json")).unwrap();
    let (nonce, wrong) = recorded_nonce(&raw);
    let nonce = nonce.as_slice();
    let legacy = serde_json::to_vec(&json!({"platform": "az-tdx", "evidence": raw})).unwrap();
    let legacy = legacy.as_slice();
    // The recorded platform has no TCB Info fixture, so collateral is
    // skipped under a policy that allows it; the DCAP chain still anchors at
    // the pinned Intel root, and a vTPM register is privileged-service.
    let mut policy = v4_policy();
    policy.tcb.require_revocation = false;
    policy.tcb.require_signed_collateral = false;
    policy.min_backing = Backing::PrivilegedService;
    let mut unpinned = policy.clone();
    policy.reference.launch_measurement = vec![launch_pin(legacy, nonce)];
    let verifier = Verifier::offline().with_cert_provider(NoCollateral);
    // Without the paravisor pinned, vtpm-extradata establishes no freshness.
    unpinned.reference.launch_measurement.clear();
    let err = verifier
        .appraise_legacy_json(legacy, nonce, None, &unpinned)
        .await
        .unwrap_err();
    assert_eq!(
        err.refusal_code(),
        attestation::RefusalCode::BindingMismatch,
        "{err}"
    );
    let a = verifier
        .appraise_legacy_json(legacy, nonce, None, &policy)
        .await
        .unwrap();
    assert!(a.ear_all_submods_bound.is_true());
    let AttesterClaims::Vtpm(vtpm) = &a.submods["vtpm"].ear_attester_claims else {
        panic!("vtpm claims")
    };
    assert!(!vtpm.cvm_registers.is_empty());
    assert!(vtpm
        .cvm_registers
        .iter()
        .all(|r| r.backing == Backing::PrivilegedService));
    let AttesterClaims::Cpu(cpu) = &a.submods["cpu"].ear_attester_claims else {
        panic!("cpu claims")
    };
    assert_eq!(
        cpu.cvm_freshness.mode,
        attestation::profile::BindingMode::VtpmExtradata
    );
    assert_eq!(
        cpu.cvm_platform.hosting,
        attestation::profile::Hosting::Azure
    );

    // A wrong nonce fails in the vTPM quote, before any CPU work.
    let err = verifier
        .appraise_legacy_json(legacy, &wrong, None, &policy)
        .await
        .unwrap_err();
    assert!(
        matches!(err, attestation::AttestationError::ReportDataMismatch),
        "{err}"
    );

    // The default backing floor (hardware) refuses a vTPM register.
    let mut strict = policy.clone();
    strict.min_backing = Backing::Hardware;
    let err = verifier
        .appraise_legacy_json(legacy, nonce, None, &strict)
        .await
        .unwrap_err();
    assert!(err.to_string().contains("backed by"), "{err}");

    // A PCR pin that matches passes and is reported; a wrong one fails.
    let pcr0 = vtpm
        .cvm_registers
        .iter()
        .find(|r| r.index == 0)
        .unwrap()
        .value
        .clone();
    let mut pinned = policy.clone();
    pinned.reference.pcrs.insert(
        0,
        vec![Digest {
            alg: HashAlg::Sha256,
            value: pcr0,
        }],
    );
    // PCR pins earn executables only beside the launch measurement pin that
    // vouches for the paravisor which measured them.
    pinned.reference.launch_measurement = vec![Digest {
        alg: HashAlg::Sha384,
        value: cpu.cvm_launch_measurement.value.clone(),
    }];
    let a = verifier
        .appraise_legacy_json(legacy, nonce, None, &pinned)
        .await
        .unwrap();
    assert_eq!(
        a.submods["vtpm"].ear_trustworthiness_vector.executables,
        Some(2)
    );
    assert_eq!(a.submods["vtpm"].ear_status, Tier::Affirming);
    let reference = a.submods["vtpm"]
        .ear_verifier_claims
        .cvm_reference
        .as_ref()
        .unwrap();
    assert_eq!(reference.launch_measurement, None);
    assert_eq!(reference.registers.get(&0), Some(&true));
    pinned.reference.pcrs.insert(
        0,
        vec![Digest {
            alg: HashAlg::Sha256,
            value: Bytes(vec![7u8; 32]),
        }],
    );
    assert!(verifier
        .appraise_legacy_json(legacy, nonce, None, &pinned)
        .await
        .is_err());
}

#[tokio::test]
async fn azure_snp_evidence_appraises_through_the_vtpm() {
    // Recorded on an Azure SEV-SNP (Milan) VM; the nonce is the one it bound.
    let legacy = include_bytes!("../test_data/az_snp/live-evidence.json");
    let envelope: serde_json::Value = serde_json::from_slice(legacy).unwrap();
    let (nonce, wrong) = recorded_nonce(&envelope["evidence"]);
    let nonce = nonce.as_slice();
    let mut policy = lenient_policy();
    policy.min_backing = Backing::PrivilegedService;
    policy.reference.launch_measurement = vec![launch_pin(legacy, nonce)];
    let verifier = Verifier::offline().with_cert_provider(NoCollateral);
    let a = verifier
        .appraise_legacy_json(legacy, nonce, None, &policy)
        .await
        .unwrap();
    assert!(a.ear_all_submods_bound.is_true());
    assert_eq!(a.submods.len(), 2);
    let AttesterClaims::Cpu(cpu) = &a.submods["cpu"].ear_attester_claims else {
        panic!("cpu claims")
    };
    assert_eq!(cpu.cvm_platform.generation.as_deref(), Some("Milan"));
    assert_eq!(
        cpu.cvm_platform.hosting,
        attestation::profile::Hosting::Azure
    );
    assert_eq!(
        cpu.cvm_freshness.mode,
        attestation::profile::BindingMode::VtpmExtradata
    );
    assert_eq!(a.submods["cpu"].ear_status, Tier::Affirming);
    let AttesterClaims::Vtpm(vtpm) = &a.submods["vtpm"].ear_attester_claims else {
        panic!("vtpm claims")
    };
    assert_eq!(vtpm.cvm_registers.len(), 24);
    assert_eq!(
        vtpm.cvm_freshness.mode,
        attestation::profile::BindingMode::VtpmExtradata
    );
    // Nothing pinned: the vtpm makes no trustworthiness claim of its own.
    assert_eq!(a.submods["vtpm"].ear_status, Tier::None);
    assert!(a.submods["vtpm"]
        .ear_verifier_claims
        .cvm_reference
        .is_none());
    let j = serde_json::to_value(&a).unwrap();
    assert_eq!(
        j["submods"]["vtpm"]["ear_attester_claims"]["cvm_tpm_ak"]["method"],
        "hcl-report"
    );

    // The vTPM quote is only as good as its nonce.
    let err = verifier
        .appraise_legacy_json(legacy, &wrong, None, &policy)
        .await
        .unwrap_err();
    assert!(
        matches!(err, attestation::AttestationError::ReportDataMismatch),
        "{err}"
    );
}

#[tokio::test]
async fn legacy_envelopes_map_to_the_profile() {
    let verifier = Verifier::offline()
        .with_cert_provider(NoCollateral)
        .with_tdx_provider(Fixtures)
        .with_clock(fixture_clock());
    let legacy_tdx = serde_json::to_vec(&json!({
        "platform": "tdx",
        "evidence": {"quote": BASE64.encode(V4_QUOTE)}
    }))
    .unwrap();
    let a = verifier
        .appraise_legacy_json(&legacy_tdx, &tdx_nonce(), None, &v4_policy())
        .await
        .unwrap();
    assert!(a.submods.contains_key("cpu"));
    let legacy_snp = serde_json::to_vec(&json!({
        "platform": "gcp-snp",
        "evidence": {"attestation_report": BASE64.encode(SNP_REPORT), "cert_chain": {"vcek": BASE64.encode(SNP_VCEK)}}
    }))
    .unwrap();
    let a = verifier
        .appraise_legacy_json(&legacy_snp, &snp_nonce(), None, &lenient_policy())
        .await
        .unwrap();
    let AttesterClaims::Cpu(claims) = &a.submods["cpu"].ear_attester_claims else {
        panic!()
    };
    assert_eq!(
        claims.cvm_platform.hosting,
        attestation::profile::Hosting::Gcp
    );
}

/// Device submodules go to NRAS, whose tokens chain to a pinned NVIDIA key,
/// so these tests stop at the provider: they check what the verifier sends
/// and what it refuses before sending.
#[cfg(feature = "nvidia-gpu")]
mod devices {
    use super::*;
    use attestation::collateral::{Jwks, NrasProvider, NrasRequest};
    use attestation::profile::binding::nras_gpu_nonce;
    use attestation::profile::GpuArch;
    use attestation::{AttestationError, NvidiaGpuArch};
    use std::sync::Mutex;

    #[derive(Default)]
    struct Recording {
        requests: Mutex<Vec<NrasRequest>>,
    }

    #[async_trait::async_trait]
    impl NrasProvider for Recording {
        fn url_for(&self, _arch: NvidiaGpuArch) -> &str {
            "https://nras.invalid/v4/attest/gpu"
        }
        async fn attest(&self, request: &NrasRequest) -> attestation::Result<serde_json::Value> {
            self.requests.lock().unwrap().push(request.clone());
            Err(AttestationError::NrasRequestFailed("recorded".to_string()))
        }
        async fn jwks(&self, _arch: NvidiaGpuArch) -> attestation::Result<Jwks> {
            Err(AttestationError::JwksFetch("recorded".to_string()))
        }
    }

    fn gpu_submod(uuid: &str, arch: &str) -> serde_json::Value {
        json!({
            "arch": arch,
            "uuid": uuid,
            "evidence_b64": "AAAA",
            "cert_chain_b64": "AAAA",
            "cvm_binding": {"pattern": "challenge", "mode": "nras-nonce"}
        })
    }

    fn envelope_with_devices(nonce: &[u8]) -> Vec<u8> {
        let mut v: serde_json::Value = serde_json::from_slice(&snp_envelope(nonce)).unwrap();
        v["submods"]["gpu/GPU-b"] = gpu_submod("GPU-b", "HOPPER");
        v["submods"]["gpu/GPU-a"] = gpu_submod("GPU-a", "HOPPER");
        v["submods"]["nvswitch/SW-1"] = gpu_submod("SW-1", "LS10");
        serde_json::to_vec(&v).unwrap()
    }

    #[tokio::test]
    async fn devices_are_batched_per_architecture_with_the_derived_nonce() {
        let nonce = snp_nonce();
        let recording = std::sync::Arc::new(Recording::default());
        let verifier = Verifier::offline()
            .with_cert_provider(NoCollateral)
            .with_nras_provider(recording.clone());
        let err = verifier
            .appraise_json(&envelope_with_devices(&nonce), &lenient_policy())
            .await
            .unwrap_err();
        assert!(
            matches!(err, AttestationError::NrasRequestFailed(_)),
            "{err}"
        );
        let requests = recording.requests.lock().unwrap();
        // The Hopper batch went first (the cpu appraised fine before it) and
        // carries both GPUs in envelope order; the switch batch never went
        // because the first failure is final.
        assert_eq!(requests.len(), 1);
        assert_eq!(requests[0].arch, NvidiaGpuArch::Hopper);
        assert_eq!(requests[0].nonce, hex::encode(nras_gpu_nonce(&nonce)));
        assert_eq!(requests[0].evidence_list.len(), 2);
        assert_eq!(requests[0].claims_version, "3.0");
    }

    #[tokio::test]
    async fn device_gates_apply_before_nras_is_asked() {
        let nonce = snp_nonce();
        let recording = std::sync::Arc::new(Recording::default());
        let verifier = Verifier::offline()
            .with_cert_provider(NoCollateral)
            .with_nras_provider(recording.clone());
        let mut policy = lenient_policy();
        policy.gpu.expected_archs = Some(vec![GpuArch::Blackwell]);
        let err = verifier
            .appraise_json(&envelope_with_devices(&nonce), &policy)
            .await
            .unwrap_err();
        assert!(
            matches!(err, AttestationError::NvidiaGpuArchNotAllowed(_)),
            "{err}"
        );
        assert!(recording.requests.lock().unwrap().is_empty());

        // A policy that requires a device refuses an envelope without one.
        let mut policy = lenient_policy();
        policy.gpu.required = true;
        let err = verifier
            .appraise_json(&snp_envelope(&nonce), &policy)
            .await
            .unwrap_err();
        assert!(matches!(err, AttestationError::NvidiaGpuRequired), "{err}");
        // Without the requirement the cpu alone appraises.
        assert!(verifier
            .appraise_json(&snp_envelope(&nonce), &lenient_policy())
            .await
            .is_ok());
    }

    #[test]
    fn a_legacy_gpu_bundle_becomes_device_submodules() {
        let nonce = snp_nonce();
        let legacy = serde_json::to_vec(&json!({
            "platform": "snp",
            "evidence": {"attestation_report": BASE64.encode(SNP_REPORT), "cert_chain": {"vcek": BASE64.encode(SNP_VCEK)}},
            "nvidia_gpu": {
                "devices": [
                    {"arch": "HOPPER", "uuid": "GPU-1", "evidence_b64": "AAAA", "cert_chain_b64": "AAAA"},
                    {"arch": "LS10", "uuid": "SW-1", "evidence_b64": "AAAA", "cert_chain_b64": "AAAA"}
                ],
                "binding": {"kind": "concat", "algo": "sha256"}
            }
        }))
        .unwrap();
        let e = attestation::profile::Evidence::from_legacy(&legacy, &nonce, None).unwrap();
        assert_eq!(e.submods.len(), 3);
        let attestation::profile::Submod::Device(d) = &e.submods["gpu/GPU-1"] else {
            panic!("device")
        };
        assert_eq!(d.arch, GpuArch::Hopper);
        assert_eq!(
            d.cvm_binding.mode,
            attestation::profile::BindingMode::NrasNonce
        );
        assert!(matches!(
            &e.submods["nvswitch/SW-1"],
            attestation::profile::Submod::Device(d) if d.arch == GpuArch::Ls10
        ));
    }
}
