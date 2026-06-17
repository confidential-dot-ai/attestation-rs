use crate::collateral::CertProvider;
use crate::error::{AttestationError, Result};
use crate::platforms::tpm_common;
use crate::types::{PlatformType, ProcessorGeneration, VerificationResult, VerifyParams};
use crate::utils::decode_base64url;

use super::evidence::AzSnpEvidence;

/// A verified az-snp attestation together with the locator for its revocation
/// collateral.
///
/// [`verify_report`] performs the full cryptographic verification (TPM quote, AK
/// binding, VCEK chain, SNP report signature, policy) but deliberately does not
/// fetch or check revocation collateral — that is a separate concern. It returns
/// this struct so a caller that *does* care about revocation (notably
/// [`verify_evidence`]) has the pieces it needs to locate and run the CRL check:
/// the matched generation pins the AMD root, and the VCEK is what the CRL is
/// checked against.
pub struct VerifiedReport {
    /// Verification result with `collateral_verified = false` (no CRL checked yet).
    pub result: VerificationResult,
    /// AMD processor generation the VCEK chain validated against.
    pub matched_gen: ProcessorGeneration,
    /// VCEK certificate (DER) — needed for the CRL revocation check.
    pub vcek_der: Vec<u8>,
    /// SNP attestation report version parsed from the HCL TEE report.
    pub report_version: u32,
}

/// Verify Azure SNP vTPM attestation evidence — the full flow.
///
/// Assembles the two halves of az-snp verification: the cryptographic core in
/// [`verify_report`], then the revocation check. This keeps the same signature
/// as every other platform's `verify_evidence` so call sites are uniform.
pub async fn verify_evidence(
    evidence: &AzSnpEvidence,
    params: &VerifyParams,
    cert_provider: &dyn CertProvider,
) -> Result<VerificationResult> {
    let VerifiedReport {
        mut result,
        matched_gen,
        vcek_der,
        ..
    } = verify_report(evidence, params)?;

    // CRL revocation check (if provider supplies CRL data)
    // AMD CRLs are signed by the ARK (root), not the ASK/ASVK intermediate.
    let ark_der = crate::platforms::snp::certs::get_ark(matched_gen);
    if let Some(crl_der) = cert_provider.get_snp_crl(matched_gen).await? {
        crate::platforms::snp::verify::check_vcek_not_revoked(&vcek_der, &crl_der, ark_der)?;
        result.collateral_verified = true;
    } else {
        log::warn!(
            "az-snp: SNP CRL data not available from cert provider; skipping revocation check"
        );
    }

    Ok(result)
}

/// The cryptographic core of az-snp verification.
///
/// Performs the TPM quote signature check, AK-to-TEE binding, VCEK certificate
/// chain validation, SNP report signature, and all policy enforcement (VMPL,
/// debug, TCB). Revocation is intentionally out of scope: it is a separate fetch
/// (the CRL) and check that needs a [`CertProvider`], so this returns the
/// still-`collateral_verified = false` result together with the matched
/// generation and VCEK that locate the collateral. Callers wanting the full flow
/// use [`verify_evidence`]; callers without an async cert provider — notably
/// WASM — call this directly and handle revocation separately, if at all.
pub fn verify_report(evidence: &AzSnpEvidence, params: &VerifyParams) -> Result<VerifiedReport> {
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
    if params.expected_report_data.is_none() {
        log::warn!(
            "az-snp: no expected_report_data provided; TPM nonce binding will not be verified"
        );
    }
    let report_data_match =
        tpm_common::check_report_data(&tpm_msg, params.expected_report_data.as_deref())?;
    tpm_common::verify_tpm_pcrs(&tpm_msg, &tpm_pcrs)?;

    // HCL binding
    tpm_common::verify_hcl_var_data_binding(snp_report.report_data.as_ref(), &hcl.var_data)?;

    // VCEK/VLEK validation against bundled AMD CA chain
    let is_vlek = crate::platforms::snp::verify::is_vlek_cert(&vcek_der)?;
    let cpuid_fam_id = snp_report.cpuid_fam_id.unwrap_or(0);
    let cpuid_mod_id = snp_report.cpuid_mod_id.unwrap_or(0);
    let processor_gen = ProcessorGeneration::from_cpuid(cpuid_fam_id, cpuid_mod_id);
    let gens = match processor_gen {
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
        let ark_der = crate::platforms::snp::certs::get_ark(*gen);
        // VLEK chain: ARK → ASVK → VLEK; VCEK chain: ARK → ASK → VCEK
        let intermediate_der = if is_vlek {
            crate::platforms::snp::certs::get_asvk(*gen)
        } else {
            crate::platforms::snp::certs::get_ask(*gen)
        };
        match crate::platforms::snp::verify::verify_cert_chain(ark_der, intermediate_der, &vcek_der)
        {
            Ok(()) => {
                if gens.len() > 1 {
                    log::warn!("az-snp: processor generation fallback matched {gen:?}");
                }
                matched_gen = Some(*gen);
                break;
            }
            Err(e) => {
                log::debug!("VEK chain check failed for {gen:?}: {e}");
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

    // VMPL check
    if snp_report.vmpl != 0 {
        return Err(AttestationError::VmplCheckFailed(snp_report.vmpl));
    }

    // Debug policy enforcement
    if snp_report.policy.debug_allowed() && !params.allow_debug {
        return Err(AttestationError::DebugPolicyViolation);
    }

    // VCEK OID cross-validation
    crate::platforms::snp::verify::verify_vcek_tcb(&snp_report, &vcek_der)?;

    // Minimum TCB enforcement (including FMC for Turin)
    if let Some(ref min_tcb) = params.min_tcb {
        crate::platforms::snp::verify::enforce_min_tcb(&snp_report.reported_tcb, min_tcb)?;
    }

    // Init data and result
    let init_data_match =
        tpm_common::check_init_data(&tpm_pcrs, params.expected_init_data_hash.as_deref())?;

    // Optional launch-measurement comparison against a pre-computed reference.
    // Mismatch does NOT fail verification — surfaced via the result field for
    // the caller's policy layer.
    let launch_digest_match = params.expected_launch_digest.as_ref().map(|expected| {
        crate::utils::constant_time_eq(&snp_report.measurement[..], expected)
    });

    let snp_claims = crate::platforms::snp::claims::extract_claims(&snp_report);
    let mut result = tpm_common::build_tpm_verification_result(
        snp_claims,
        &tpm_pcrs,
        &tpm_msg,
        PlatformType::AzSnp,
        report_data_match,
        init_data_match,
        // collateral_verified is set by the async wrapper after the CRL check;
        // the synchronous core has not checked revocation.
        false,
    );
    result.launch_digest_match = launch_digest_match;
    Ok(VerifiedReport {
        result,
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
    fn test_hcl_report_too_short() {
        let short_hcl = vec![0u8; 100]; // Way too short
        let evidence = AzSnpEvidence {
            version: 1,
            tpm_quote: build_dummy_tpm_quote(),
            hcl_report: BASE64URL.encode(&short_hcl),
            vcek: BASE64URL.encode([0u8; 100]),
        };

        let rt = tokio::runtime::Runtime::new().unwrap();
        let provider = crate::collateral::DefaultCertProvider::new();
        let params = VerifyParams::default();

        let result = rt.block_on(verify_evidence(&evidence, &params, &provider));
        assert!(result.is_err(), "short HCL report should fail");
        let err = format!("{:?}", result.err().unwrap());
        assert!(
            err.contains("too short"),
            "error should mention too short: {err}"
        );
    }

    #[test]
    fn test_invalid_base64_hcl_report() {
        let evidence = AzSnpEvidence {
            version: 1,
            tpm_quote: build_dummy_tpm_quote(),
            hcl_report: "!!!invalid_base64!!!".to_string(),
            vcek: BASE64URL.encode([0u8; 100]),
        };

        let rt = tokio::runtime::Runtime::new().unwrap();
        let provider = crate::collateral::DefaultCertProvider::new();
        let params = VerifyParams::default();

        let result = rt.block_on(verify_evidence(&evidence, &params, &provider));
        assert!(result.is_err());
        let err = format!("{:?}", result.err().unwrap());
        assert!(
            err.contains("base64") || err.contains("Base64"),
            "error: {err}"
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

        let verified = verify_report(&evidence, &VerifyParams::default())
            .expect("Milan az-snp fixture should verify end to end");

        assert!(verified.result.signature_valid);
        assert_eq!(verified.result.platform, crate::types::PlatformType::AzSnp);
        assert_eq!(
            verified.report_version, 3,
            "this fixture uses SNP report v3"
        );
        assert!(
            !verified.vcek_der.is_empty(),
            "VCEK is returned for the CRL check"
        );
        // No expected_report_data supplied → freshness binding is not enforced.
        assert_eq!(verified.result.report_data_match, None);
        // The verification core does not run the (async) CRL revocation check.
        assert!(!verified.result.collateral_verified);
    }

    #[test]
    fn test_verify_report_rejects_wrong_nonce() {
        // This fixture's quote carries an empty extraData, so any non-empty
        // expected report_data must fail closed (TPM nonce length mismatch).
        let evidence = load_az_snp_evidence(MILAN_V3_FIXTURE);

        let params = VerifyParams {
            expected_report_data: Some(b"unexpected-nonce".to_vec()),
            ..Default::default()
        };
        assert!(
            verify_report(&evidence, &params).is_err(),
            "non-empty expected report_data must not match an empty quote nonce"
        );
    }

    #[test]
    fn test_verify_report_binds_report_data() {
        // evidence-v1.json's vTPM quote binds the ASCII nonce "challenge"; the
        // core must confirm the freshness binding when that nonce is expected.
        let evidence =
            load_az_snp_evidence(include_str!("../../../test_data/az_snp/evidence-v1.json"));

        let params = VerifyParams {
            expected_report_data: Some(b"challenge".to_vec()),
            ..Default::default()
        };
        let verified = verify_report(&evidence, &params)
            .expect("evidence-v1 should verify with its bound nonce");
        assert_eq!(verified.result.report_data_match, Some(true));

        // A different nonce must fail closed.
        let wrong = VerifyParams {
            expected_report_data: Some(b"not-the-challenge".to_vec()),
            ..Default::default()
        };
        assert!(verify_report(&evidence, &wrong).is_err());
    }
}
