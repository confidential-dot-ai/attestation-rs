use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

use crate::collateral::{AmdCrl, AmdKey, CollateralUsed, Store};
use crate::error::{AttestationError, Result};
use crate::platform::Platform;
use crate::platforms::snp::{SnpParams, SnpResult};
use crate::platforms::tpm_common;
use crate::types::{PlatformType, ProcessorGeneration};
use crate::utils::decode_base64url;

use super::evidence::AzSnpEvidence;

/// What a caller can ask of Azure SEV-SNP (vTPM) evidence. `snp.report_data`
/// is checked against the vTPM quote nonce and `snp.host_data` (a 32-byte
/// init-data hash) against `PCR[8]`.
/// In JSON, the `snp` params and `pcrs` (`{ "<index>": "<base64>" }`)
/// are one object.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AzSnpParams {
    #[serde(flatten)]
    pub snp: SnpParams,
    /// Expected vTPM PCR values (SHA-256 bank) by index. Empty means no check.
    #[serde(default, with = "crate::utils::b64::pcrs")]
    pub pcrs: BTreeMap<u8, [u8; 32]>,
}

impl AzSnpParams {
    /// Reject params that cannot be applied, before any I/O.
    pub fn validate(&self) -> Result<()> {
        self.snp.validate()?;
        if self.snp.caller_data.is_some() {
            return Err(AttestationError::InvalidParams(
                "runtime registers are bare-metal SNP only".into(),
            ));
        }
        tpm_common::check_init_data_len(self.snp.host_data.as_deref())?;
        tpm_common::check_pcr_pin_indexes(&self.pcrs)
    }
}

/// The answer for genuine Azure SEV-SNP evidence. The vTPM PCRs and nonce are
/// in `snp.claims.platform_data.tpm`.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[must_use]
pub struct AzSnpResult {
    #[serde(flatten)]
    pub snp: SnpResult,
    /// Every pinned PCR matched (`None` if no PCR was pinned). A PCR outside
    /// the quote's signed PCR selection does not match.
    pub pcrs_match: Option<bool>,
}

impl AzSnpResult {
    /// True when the evidence satisfied every rule in the params.
    pub fn passed(&self) -> bool {
        self.snp.passed() && self.pcrs_match != Some(false)
    }
}

/// A verified az-snp attestation and what locates its revocation collateral.
pub struct VerifiedReport {
    /// Verification result; revocation is not checked yet.
    pub result: AzSnpResult,
    /// AMD processor generation the VCEK chain validated against.
    pub matched_gen: ProcessorGeneration,
    /// VCEK certificate (DER), from the HCL report.
    pub vcek_der: Vec<u8>,
    /// SNP attestation report version parsed from the HCL TEE report.
    pub report_version: u32,
}

/// The az-snp collateral set: the AMD CRL (the VCEK comes in the
/// evidence).
pub struct AzSnpCollateralSet {
    pub crl: AmdCrl,
}

/// Azure SEV-SNP: an SNP report wrapped in an HCL report, bound to a vTPM quote.
pub struct AzSnp;

impl Platform for AzSnp {
    const KIND: PlatformType = PlatformType::AzSnp;
    type Evidence = AzSnpEvidence;
    type Params = AzSnpParams;
    type Result = AzSnpResult;
    type CollateralSet = AzSnpCollateralSet;

    fn validate(params: &AzSnpParams) -> Result<()> {
        params.validate()
    }

    /// The whole evidence verifies first; its VCEK names the CRL.
    async fn gather(
        evidence: &AzSnpEvidence,
        store: &Store,
        now: i64,
    ) -> Result<(AzSnpCollateralSet, Vec<CollateralUsed>)> {
        let verified = verify_report(evidence, &AzSnpParams::default(), now)?;
        let key = AmdKey::of_vek(&verified.vcek_der)?;
        let (crl, used) = store
            .get::<AmdCrl>(&(verified.matched_gen, key), now)
            .await?;
        Ok((AzSnpCollateralSet { crl }, vec![used]))
    }

    fn verify(
        evidence: &AzSnpEvidence,
        params: &AzSnpParams,
        collateral: &AzSnpCollateralSet,
        now: i64,
    ) -> Result<AzSnpResult> {
        let verified = verify_report(evidence, params, now)?;
        let revoked = crate::platforms::snp::verify::vek_revoked(
            &verified.vcek_der,
            &collateral.crl,
            verified.matched_gen,
        )?;
        let mut result = verified.result;
        result.snp.crl_ok = Some(!revoked);
        Ok(result)
    }
}

/// The cryptographic core of az-snp verification.
///
/// Performs the TPM quote signature check, AK-to-TEE binding, VCEK certificate
/// chain validation and SNP report signature, then evaluates the params
/// (nonce, init data, launch digest, VMPL, debug, TCB). Revocation needs the
/// AMD CRL, so it is left to [`AzSnp::verify`]; the matched generation and
/// VCEK returned here name that CRL. `now` is the evaluation time in Unix
/// seconds.
pub fn verify_report(
    evidence: &AzSnpEvidence,
    params: &AzSnpParams,
    now: i64,
) -> Result<VerifiedReport> {
    params.validate()?;
    let pcrs = &params.pcrs;
    let params = &params.snp;
    if evidence.version != 1 {
        return Err(AttestationError::EvidenceDeserialize(format!(
            "unsupported az_snp evidence version: {}",
            evidence.version
        )));
    }

    // Input size validation
    crate::utils::check_field_size("hcl_report", evidence.hcl_report.len())?;
    crate::utils::check_field_size("vcek", evidence.vcek.len())?;
    crate::utils::check_field_size("tpm_quote.signature", evidence.tpm_quote.signature.len())?;
    crate::utils::check_field_size("tpm_quote.message", evidence.tpm_quote.message.len())?;

    // Decode
    let hcl_report_bytes = decode_base64url(&evidence.hcl_report)
        .map_err(|e| AttestationError::EvidenceDeserialize(format!("HCL report base64: {e}")))?;
    let hcl = tpm_common::parse_hcl_report(&hcl_report_bytes)?;
    if hcl.report_type != tpm_common::HCL_REPORT_TYPE_SNP {
        return Err(AttestationError::QuoteParseFailed(format!(
            "HCL report_type is {} (expected {} for SNP)",
            hcl.report_type,
            tpm_common::HCL_REPORT_TYPE_SNP
        )));
    }
    let vcek_der = decode_base64url(&evidence.vcek)
        .map_err(|e| AttestationError::EvidenceDeserialize(format!("VCEK base64: {e}")))?;
    let (tpm_sig, tpm_msg, tpm_pcrs) = tpm_common::decode_tpm_quote(&evidence.tpm_quote)?;
    let snp_report = crate::platforms::snp::verify::parse_report(&hcl.tee_report)?;

    // Version range check: Azure HCL may use v2 (no CPUID), up to MAX_REPORT_VERSION
    const AZ_MIN_REPORT_VERSION: u32 = 2;
    if snp_report.version < AZ_MIN_REPORT_VERSION
        || snp_report.version > crate::platforms::snp::verify::MAX_REPORT_VERSION
    {
        return Err(AttestationError::UnsupportedReportVersion {
            version: snp_report.version,
            min: AZ_MIN_REPORT_VERSION,
            max: crate::platforms::snp::verify::MAX_REPORT_VERSION,
        });
    }

    // TPM layer
    //
    // Verification order safety:
    // 1. TPM sig uses the AK (attestation key) extracted from var_data in the HCL
    //    report — an attacker cannot substitute a different AK without forging the
    //    TPM signature (RSA-2048 with the TPM's internal signing key).
    // 2. HCL binding then confirms var_data is bound to the TEE report via
    //    report_data[..32] == SHA-256(var_data).
    // 3. The TEE report itself is signed by the platform (VCEK/VLEK for SNP).
    // Trust chain: TEE report → var_data → AK → TPM quote → nonce
    tpm_common::verify_tpm_signature(&tpm_sig, &tpm_msg, &hcl.var_data)?;
    if params.report_data.is_none() {
        log::warn!("az-snp: no report_data provided; TPM nonce binding will not be verified");
    }
    let report_data_match = tpm_common::check_report_data(&tpm_msg, params.report_data.as_deref())?;
    tpm_common::verify_tpm_pcrs(&tpm_msg, &tpm_pcrs)?;
    let pcrs_match = tpm_common::check_pcrs(&tpm_msg, &tpm_pcrs, pcrs)?;

    // HCL binding
    tpm_common::verify_hcl_var_data_binding(snp_report.report_data.as_ref(), &hcl.var_data)?;

    // VEK endorsement (chain to the bundled AMD roots, validity, chip-id/TCB
    // OIDs), as on bare-metal SNP. Azure v2 reports carry no CPUID, so the
    // generation is found by trying each known root.
    let cpuid_fam_id = snp_report.cpuid_fam_id.unwrap_or(0);
    let cpuid_mod_id = snp_report.cpuid_mod_id.unwrap_or(0);
    let gens = match ProcessorGeneration::from_cpuid(cpuid_fam_id, cpuid_mod_id) {
        Some(g) => vec![g],
        None => {
            log::warn!(
                "could not determine processor generation from CPUID \
                 (family=0x{cpuid_fam_id:02X}, model=0x{cpuid_mod_id:02X}); trying all known generations"
            );
            vec![
                ProcessorGeneration::Milan,
                ProcessorGeneration::Genoa,
                ProcessorGeneration::Turin,
            ]
        }
    };
    let mut last_err = None;
    let mut matched_gen = None;
    for gen in &gens {
        match crate::platforms::snp::verify::verify_vek_endorsement(
            &snp_report,
            &vcek_der,
            *gen,
            now,
        ) {
            Ok(()) => {
                if gens.len() > 1 {
                    log::warn!("az-snp: processor generation fallback matched {gen:?}");
                }
                matched_gen = Some(*gen);
                break;
            }
            Err(e) => {
                log::debug!("VEK endorsement check failed for {gen:?}: {e}");
                last_err = Some(e);
            }
        }
    }
    let matched_gen = matched_gen.ok_or_else(|| {
        last_err.unwrap_or_else(|| {
            AttestationError::CertChainError("no matching AMD root cert found".to_string())
        })
    })?;

    // SNP report signature against VCEK
    crate::platforms::snp::verify::verify_report_signature(&hcl.tee_report, &vcek_der)?;

    // The params' rules. The CRL result is set by VerifiedReport::check_crl;
    // this synchronous core has not checked revocation.
    let mut snp = crate::platforms::snp::verify::evaluate_report(&snp_report, params, None);
    snp.report_data_match = report_data_match;
    snp.host_data_match =
        tpm_common::check_init_data(&tpm_msg, &tpm_pcrs, params.host_data.as_deref())?;
    snp.claims = tpm_common::tpm_claims(snp.claims, &tpm_pcrs, &tpm_msg);

    Ok(VerifiedReport {
        result: AzSnpResult { snp, pcrs_match },
        matched_gen,
        vcek_der,
        report_version: snp_report.version,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::platforms::tpm_common::TpmQuote;
    use base64::{engine::general_purpose::URL_SAFE_NO_PAD as BASE64URL, Engine};

    fn build_dummy_tpm_quote() -> TpmQuote {
        TpmQuote {
            signature: "00".repeat(256),
            message: "ff544347".to_string() + &"00".repeat(100),
            pcrs: (0..24).map(|_| "00".repeat(32)).collect(),
        }
    }

    #[test]
    fn runtime_registers_are_bare_metal_only() {
        let snp = SnpParams {
            launch_digest: Some(vec![[1; 48]]),
            caller_data: Some(vec![7; 64]),
            ..Default::default()
        };
        snp.validate().unwrap();
        let params = AzSnpParams {
            snp,
            ..Default::default()
        };
        assert!(params.validate().is_err());
    }

    #[test]
    fn test_hcl_report_too_short() {
        let short_hcl = vec![0u8; 100]; // Way too short
        let evidence = AzSnpEvidence {
            version: 1,
            tpm_quote: build_dummy_tpm_quote(),
            hcl_report: BASE64URL.encode(&short_hcl),
            vcek: BASE64URL.encode([0u8; 100]),
        };

        let result = verify_report(&evidence, &AzSnpParams::default(), 0);
        assert!(
            matches!(result, Err(AttestationError::QuoteParseFailed(_))),
            "{:?}",
            result.as_ref().err()
        );
        assert!(tpm_common::parse_hcl_report(&short_hcl).is_err());
        assert!(tpm_common::parse_hcl_report(COCO_HCL_REPORT).is_ok());
    }

    #[test]
    fn test_invalid_base64_hcl_report() {
        let evidence = AzSnpEvidence {
            version: 1,
            tpm_quote: build_dummy_tpm_quote(),
            hcl_report: "!!!invalid_base64!!!".to_string(),
            vcek: BASE64URL.encode([0u8; 100]),
        };

        let result = verify_report(&evidence, &AzSnpParams::default(), 0);
        assert!(
            matches!(result, Err(AttestationError::EvidenceDeserialize(_))),
            "{:?}",
            result.as_ref().err()
        );
    }

    // --- Tests using real CoCo HCL report fixture ---

    const COCO_HCL_REPORT: &[u8] = include_bytes!("../../../test_data/az_snp/hcl-report.bin");

    #[test]
    fn test_coco_hcl_report_parses() {
        let parsed = tpm_common::parse_hcl_report(COCO_HCL_REPORT);
        assert!(
            parsed.is_ok(),
            "CoCo HCL report should parse: {:?}",
            parsed.err()
        );

        let parsed = parsed.unwrap();
        assert_eq!(parsed.tee_report.len(), 1184);
        assert_eq!(parsed.report_type, tpm_common::HCL_REPORT_TYPE_SNP);
        assert!(!parsed.var_data.is_empty(), "var_data should not be empty");
    }

    #[test]
    fn test_coco_hcl_snp_report_parses() {
        let parsed = tpm_common::parse_hcl_report(COCO_HCL_REPORT).unwrap();
        let report = crate::platforms::snp::verify::parse_report(&parsed.tee_report);
        assert!(
            report.is_ok(),
            "SNP report from CoCo HCL should parse: {:?}",
            report.err()
        );
        assert_eq!(
            report.unwrap().version,
            2,
            "CoCo fixture uses SNP report v2"
        );
    }

    #[test]
    fn test_coco_hcl_var_data_binding() {
        let parsed = tpm_common::parse_hcl_report(COCO_HCL_REPORT).unwrap();
        let snp_report = crate::platforms::snp::verify::parse_report(&parsed.tee_report).unwrap();

        let var_data_hash = crate::utils::sha256(&parsed.var_data);

        assert!(
            crate::utils::constant_time_eq(
                snp_report
                    .report_data
                    .get(..32)
                    .expect("report_data >= 32 bytes"),
                &var_data_hash
            ),
            "HCL var_data binding: report_data[..32] == SHA-256(null-trimmed var_data)"
        );
    }

    #[test]
    fn test_coco_hcl_var_data_contains_ak_pub() {
        let parsed = tpm_common::parse_hcl_report(COCO_HCL_REPORT).unwrap();

        let result = tpm_common::extract_ak_pub_from_jwk_json(&parsed.var_data);
        assert!(
            result.is_ok(),
            "should extract AK pub from JWK JSON: {:?}",
            result.err()
        );

        let (modulus, exponent) = result.unwrap();
        assert_eq!(modulus.len(), 256, "RSA 2048 modulus should be 256 bytes");
        assert_eq!(exponent, vec![0x01, 0x00, 0x01], "exponent should be 65537");
    }

    #[test]
    fn test_coco_tpm_signature_verification() {
        // Use evidence-v1.json which has matching TPM quote + HCL report
        let json = include_str!("../../../test_data/az_snp/evidence-v1.json");
        let envelope: crate::types::AttestationEvidence = serde_json::from_str(json).unwrap();
        let evidence: AzSnpEvidence = serde_json::from_value(envelope.evidence).unwrap();

        let hcl_bytes = decode_base64url(&evidence.hcl_report).unwrap();
        let parsed = tpm_common::parse_hcl_report(&hcl_bytes).unwrap();

        let sig = hex::decode(&evidence.tpm_quote.signature).unwrap();
        let msg = hex::decode(&evidence.tpm_quote.message).unwrap();

        let result = tpm_common::verify_tpm_signature(&sig, &msg, &parsed.var_data);
        assert!(
            result.is_ok(),
            "CoCo TPM signature should verify: {:?}",
            result.err()
        );
    }

    #[test]
    fn test_coco_evidence_v1_deserializes() {
        let json = include_str!("../../../test_data/az_snp/evidence-v1.json");
        let envelope: crate::types::AttestationEvidence = serde_json::from_str(json).unwrap();
        assert_eq!(envelope.platform, crate::types::PlatformType::AzSnp);
        let evidence: std::result::Result<AzSnpEvidence, _> =
            serde_json::from_value(envelope.evidence);
        assert!(
            evidence.is_ok(),
            "CoCo evidence-v1.json should deserialize: {:?}",
            evidence.err()
        );

        let evidence = evidence.unwrap();
        assert_eq!(evidence.version, 1);
        assert_eq!(evidence.tpm_quote.pcrs.len(), 24);
        assert!(!evidence.hcl_report.is_empty());
        assert!(!evidence.vcek.is_empty());
    }

    // --- Full cryptographic verification core (verify_report) ---

    fn load_az_snp_evidence(json: &str) -> AzSnpEvidence {
        let envelope: crate::types::AttestationEvidence = serde_json::from_str(json).unwrap();
        assert_eq!(envelope.platform, crate::types::PlatformType::AzSnp);
        serde_json::from_value(envelope.evidence).unwrap()
    }

    // A real recorded Azure Milan az-snp attestation (HCL report + vTPM quote +
    // VCEK), chaining to the bundled AMD Milan roots. It exercises the entire
    // verification core: TPM signature against the AK, AK->TEE binding, PCR
    // digest, VCEK chain, SNP report signature, and policy.
    const MILAN_V3_FIXTURE: &str =
        include_str!("../../../test_data/az_snp/milan-v3-attestation.json");

    #[test]
    fn test_verify_report_milan_fixture() {
        let evidence = load_az_snp_evidence(MILAN_V3_FIXTURE);

        let verified = verify_report(&evidence, &AzSnpParams::default(), now())
            .expect("Milan az-snp fixture should verify end to end");

        assert!(verified.result.passed());
        assert_eq!(
            verified.report_version, 3,
            "this fixture uses SNP report v3"
        );
        assert!(
            !verified.vcek_der.is_empty(),
            "VCEK is returned for the CRL check"
        );
        // No report_data supplied → freshness binding is not checked.
        assert_eq!(verified.result.snp.report_data_match, None);
        // The verification core does not run the (async) CRL revocation check.
    }

    fn params_with_nonce(nonce: &[u8]) -> AzSnpParams {
        AzSnpParams {
            snp: SnpParams {
                report_data: Some(nonce.to_vec()),
                ..Default::default()
            },
            ..Default::default()
        }
    }

    fn now() -> i64 {
        chrono::Utc::now().timestamp()
    }

    #[test]
    fn test_verify_report_reports_wrong_nonce() {
        // This fixture's quote carries an empty extraData, so any non-empty
        // expected report_data is a mismatch.
        let evidence = load_az_snp_evidence(MILAN_V3_FIXTURE);

        let verified = verify_report(&evidence, &params_with_nonce(b"unexpected-nonce"), now())
            .expect("a nonce mismatch is a value, not an error");
        assert_eq!(verified.result.snp.report_data_match, Some(false));
        assert!(!verified.result.passed());
    }

    #[test]
    fn test_verify_report_binds_report_data() {
        // evidence-v1.json's vTPM quote binds the ASCII nonce "challenge"; the
        // core must confirm the freshness binding when that nonce is expected.
        let evidence =
            load_az_snp_evidence(include_str!("../../../test_data/az_snp/evidence-v1.json"));

        let verified = verify_report(&evidence, &params_with_nonce(b"challenge"), now())
            .expect("evidence-v1 should verify with its bound nonce");
        assert_eq!(verified.result.snp.report_data_match, Some(true));

        // A different nonce is reported as a mismatch.
        let wrong =
            verify_report(&evidence, &params_with_nonce(b"not-the-challenge"), now()).unwrap();
        assert_eq!(wrong.result.snp.report_data_match, Some(false));
    }

    // --- Revocation (AMD CRL) on real Azure Genoa evidence ---

    // An image on Azure Standard_DC2as_v5, 2026-10-11: AMD EPYC 9V74 (Genoa),
    // SNP report v5, VCEK from the Azure IMDS cache, vTPM quote over a 48-byte
    // nonce.
    const GENOA_V5_FIXTURE: &str =
        include_str!("../../../test_data/az_snp/genoa-v5-attestation.json");
    const GENOA_V5_NONCE: &str = "4b44a067436275615ed70852f6dc34c1d465c02e113c583fddfbfed20e9c114c323026b0c3ddc9759ba7149d7f595cf7";

    fn verify_genoa(params: &AzSnpParams) -> VerifiedReport {
        verify_report(
            &load_az_snp_evidence(GENOA_V5_FIXTURE),
            params,
            crate::testing::NOW,
        )
        .expect("Genoa az-snp fixture should verify")
    }

    #[tokio::test]
    async fn test_genoa_fixture_with_current_crl() {
        let params = params_with_nonce(&hex::decode(GENOA_V5_NONCE).unwrap());
        assert_eq!(
            verify_genoa(&params).matched_gen,
            ProcessorGeneration::Genoa
        );
        let result = crate::testing::verify::<AzSnp>(
            &load_az_snp_evidence(GENOA_V5_FIXTURE),
            &params,
            vec![crate::testing::amd_crl(ProcessorGeneration::Genoa)],
        )
        .await
        .unwrap();
        assert_eq!(result.snp.crl_ok, Some(true));
        assert!(result.passed());
    }

    #[tokio::test]
    async fn test_genoa_fixture_needs_the_genoa_crl() {
        for held in [
            vec![],
            vec![crate::testing::amd_crl(ProcessorGeneration::Milan)],
        ] {
            let err = crate::testing::verify::<AzSnp>(
                &load_az_snp_evidence(GENOA_V5_FIXTURE),
                &AzSnpParams::default(),
                held,
            )
            .await
            .expect_err("the Genoa CRL is held nowhere");
            assert!(err.is_retryable(), "{err}");
        }
    }
}
