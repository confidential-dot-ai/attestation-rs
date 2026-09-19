#![cfg(all(feature = "snp", feature = "tdx"))]
//! `appraise` end to end on the SNP and TDX fixtures, with inline
//! endorsements and fixture collateral, no network.

use attestation::collateral::{CertProvider, SignedCollateral, TdxCollateralProvider};
use attestation::profile::{
    AttesterClaims, Backing, Bytes, Digest, HashAlg, Identity, KeyBinding, KeyKind, Tier,
    VerifyPolicy, PROFILE_URI,
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

struct Fixtures;

#[async_trait::async_trait]
impl TdxCollateralProvider for Fixtures {
    async fn get_tcb_info(&self, fmspc: &str) -> attestation::Result<SignedCollateral> {
        assert_eq!(fmspc, "50806f000000");
        Ok(SignedCollateral {
            body: TCB_INFO.to_vec(),
            signing_chain: TCB_SIGNING_CHAIN.to_vec(),
        })
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
    assert_eq!(cpu.ear_trustworthiness_vector.hardware, Some(2));
    assert_eq!(cpu.ear_trustworthiness_vector.runtime_opaque, Some(2));
    assert!(appraisal.ear_all_submods_bound);
    let AttesterClaims::Cpu(claims) = &cpu.ear_attester_claims else {
        panic!("cpu claims")
    };
    assert_eq!(claims.cvm_platform.generation.as_deref(), Some("Genoa"));
    assert!(matches!(claims.cvm_identity, Identity::Snp { .. }));
    assert_eq!(claims.dbgstat, 2);
    assert_eq!(
        claims.compat["snp"]["measurement"],
        hex::encode(&claims.cvm_launch_measurement.value.0)
    );
    let j = serde_json::to_value(&appraisal).unwrap();
    assert_eq!(j["submods"]["cpu"]["ear_status"], "affirming");
    assert_eq!(j["eat_profile"], "tag:ietf.org,2026:rats/ear#04");
    assert!(
        j["submods"]["cpu"]["ear_verifier_claims"]["cvm_collateral"]["snp_crl"]["status"]
            == "skipped"
    );
}

#[tokio::test]
async fn snp_policy_failures_are_errors() {
    let nonce = snp_nonce();
    let verifier = Verifier::offline().with_cert_provider(NoCollateral);
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
        .with_tdx_provider(Fixtures);
    let appraisal = verifier
        .appraise_json(&tdx_envelope(&nonce), &v4_policy())
        .await
        .unwrap();
    let cpu = &appraisal.submods["cpu"];
    assert!(matches!(cpu.ear_status, Tier::Affirming | Tier::Warning));
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
    assert_eq!(claims.dbgstat, 0);
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
        .with_tdx_provider(Fixtures);
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
async fn legacy_envelopes_map_to_the_profile() {
    let verifier = Verifier::offline()
        .with_cert_provider(NoCollateral)
        .with_tdx_provider(Fixtures);
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
