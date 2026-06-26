use crate::collateral::TdxCollateralProvider;
use crate::error::{AttestationError, Result};
use crate::platforms::tdx::{claims::extract_claims, dcap, verify as tdx_verify};
use crate::platforms::tpm_common;
use crate::types::{PlatformType, VerificationResult, VerifyParams};
use crate::utils::decode_base64url;

use super::evidence::AzTdxEvidence;

/// Verify Azure TDX vTPM attestation evidence.
///
/// When `collateral_provider` is `Some`, performs full DCAP collateral verification.
/// When `None`, CRL/TCB/QE Identity checks are skipped.
pub async fn verify_evidence(
    evidence: &AzTdxEvidence,
    params: &VerifyParams,
    collateral_provider: Option<&dyn TdxCollateralProvider>,
) -> Result<VerificationResult> {
    if evidence.version != 1 {
        return Err(AttestationError::EvidenceDeserialize(format!(
            "unsupported az_tdx evidence version: {}",
            evidence.version
        )));
    }

    // Input size validation
    crate::utils::check_field_size("hcl_report", evidence.hcl_report.len())?;
    crate::utils::check_field_size("td_quote", evidence.td_quote.len())?;
    crate::utils::check_field_size("tpm_quote.signature", evidence.tpm_quote.signature.len())?;
    crate::utils::check_field_size("tpm_quote.message", evidence.tpm_quote.message.len())?;

    // Decode
    let hcl_report_bytes = decode_base64url(&evidence.hcl_report)
        .map_err(|e| AttestationError::EvidenceDeserialize(format!("HCL report base64: {e}")))?;
    let hcl = tpm_common::parse_hcl_report(&hcl_report_bytes)?;
    if hcl.report_type != tpm_common::HCL_REPORT_TYPE_TDX {
        return Err(AttestationError::QuoteParseFailed(format!(
            "HCL report_type is {} (expected {} for TDX)",
            hcl.report_type,
            tpm_common::HCL_REPORT_TYPE_TDX
        )));
    }
    let td_quote_bytes = decode_base64url(&evidence.td_quote)
        .map_err(|e| AttestationError::EvidenceDeserialize(format!("TD quote base64: {e}")))?;
    let (tpm_sig, tpm_msg, tpm_pcrs) = tpm_common::decode_tpm_quote(&evidence.tpm_quote)?;

    // TPM layer
    //
    // Verification order safety:
    // 1. TPM sig uses the AK (attestation key) extracted from var_data in the HCL
    //    report — an attacker cannot substitute a different AK without forging the
    //    TPM signature (RSA-2048 with the TPM's internal signing key).
    // 2. HCL binding then confirms var_data is bound to the TEE report via
    //    report_data[..32] == SHA-256(var_data).
    // 3. The TEE report itself is signed by Intel's QE (DCAP chain for TDX).
    // Trust chain: TEE report → var_data → AK → TPM quote → nonce
    tpm_common::verify_tpm_signature(&tpm_sig, &tpm_msg, &hcl.var_data)?;
    if params.expected_report_data.is_none() {
        log::warn!(
            "az-tdx: no expected_report_data provided; TPM nonce binding will not be verified"
        );
    }
    let report_data_match =
        tpm_common::check_report_data(&tpm_msg, params.expected_report_data.as_deref())?;
    tpm_common::verify_tpm_pcrs(&tpm_msg, &tpm_pcrs)?;

    // TDX DCAP layer
    let tdx_quote = tdx_verify::parse_tdx_quote(&td_quote_bytes)?;
    tdx_verify::verify_quote_signature(&td_quote_bytes, &tdx_quote)?;
    dcap::verify_dcap_chain(&td_quote_bytes, tdx_quote.quote_version, None)?;

    // TDX debug policy enforcement (bit 0 of td_attributes)
    if tdx_quote.body.td_attributes[0] & 0x01 != 0 && !params.allow_debug {
        return Err(AttestationError::DebugPolicyViolation);
    }

    // DCAP collateral checks (CRL, TCB, QE Identity) when provider is available
    let tcb_status = if let Some(provider) = collateral_provider {
        let body_end = dcap::compute_body_end(&td_quote_bytes, tdx_quote.quote_version)?;
        let auth = dcap::parse_auth_data(&td_quote_bytes, body_end)?;

        // Preparse PCK cert chain PEM once for reuse across checks
        let pck_der_certs = dcap::parse_pem_to_der(auth.pck_cert_chain_pem)?;

        // PCK CRL revocation check (leaf + intermediate CA)
        provider
            .check_pck_revocation(auth.pck_cert_chain_pem)
            .await?;

        // TCB status evaluation
        let fmspc = dcap::extract_fmspc_from_pck_der(&pck_der_certs)?;
        let tcb_info_json = provider.get_tcb_info(&fmspc).await?;
        let tcb_signing_chain = provider.get_tcb_signing_chain().await?;
        let status = dcap::evaluate_tcb_status(
            &tcb_info_json,
            &tdx_quote.body.tee_tcb_svn,
            auth.pck_cert_chain_pem,
            tcb_signing_chain.as_deref(),
        )?;

        // Reject Revoked TCB status
        if status.tcb_status == crate::types::TdxTcbStatus::Revoked {
            return Err(AttestationError::TcbMismatch(
                "TDX TCB status is Revoked".into(),
            ));
        }

        // QE Identity verification (TDX uses TD_QE, not SGX QE)
        let qe_identity_json = provider.get_td_qe_identity().await?;
        let qe_signing_chain = provider.get_td_qe_identity_signing_chain().await?;
        dcap::verify_qe_identity(
            auth.qe_report_body,
            &qe_identity_json,
            qe_signing_chain.as_deref(),
        )?;

        Some(status)
    } else {
        log::warn!("TDX collateral provider not available; skipping CRL, TCB status, and QE Identity checks");
        None
    };

    // Bindings
    tpm_common::verify_hcl_var_data_binding(&tdx_quote.body.report_data, &hcl.var_data)?;
    let init_data_match =
        tpm_common::check_init_data(&tpm_pcrs, params.expected_init_data_hash.as_deref())?;

    // Optional MRTD / RTMR compares. Mismatches surface in the result and
    // do not fail verification.
    let mrtd_match = params
        .expected_mrtd
        .as_ref()
        .map(|expected| crate::utils::constant_time_eq(&tdx_quote.body.mr_td, expected));
    let rtmr0_match = params
        .expected_rtmr0
        .as_ref()
        .map(|expected| crate::utils::constant_time_eq(&tdx_quote.body.rtmr_0, expected));
    let rtmr1_match = params
        .expected_rtmr1
        .as_ref()
        .map(|expected| crate::utils::constant_time_eq(&tdx_quote.body.rtmr_1, expected));
    let rtmr2_match = params
        .expected_rtmr2
        .as_ref()
        .map(|expected| crate::utils::constant_time_eq(&tdx_quote.body.rtmr_2, expected));
    let rtmr3_match = params
        .expected_rtmr3
        .as_ref()
        .map(|expected| crate::utils::constant_time_eq(&tdx_quote.body.rtmr_3, expected));

    // Result
    let tdx_claims = extract_claims(&tdx_quote);
    let collateral_verified = tcb_status.is_some();
    let mut result = tpm_common::build_tpm_verification_result(
        tdx_claims,
        &tpm_pcrs,
        &tpm_msg,
        PlatformType::AzTdx,
        report_data_match,
        init_data_match,
        collateral_verified,
    );
    result.tcb_status = tcb_status;
    result.mrtd_match = mrtd_match;
    result.rtmr0_match = rtmr0_match;
    result.rtmr1_match = rtmr1_match;
    result.rtmr2_match = rtmr2_match;
    result.rtmr3_match = rtmr3_match;
    Ok(result)
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

    fn build_hcl_report(report_type: u32, content: &[u8]) -> Vec<u8> {
        let tee_end = 0x20 + 1184;
        let content_start = tee_end + 20;
        let mut hcl = vec![0u8; content_start + content.len()];
        hcl[0..4].copy_from_slice(b"HCLA");
        let total = (20 + content.len()) as u32;
        hcl[tee_end..tee_end + 4].copy_from_slice(&total.to_le_bytes());
        hcl[tee_end + 4..tee_end + 8].copy_from_slice(&1u32.to_le_bytes());
        hcl[tee_end + 8..tee_end + 12].copy_from_slice(&report_type.to_le_bytes());
        hcl[tee_end + 12..tee_end + 16].copy_from_slice(&1u32.to_le_bytes());
        hcl[tee_end + 16..tee_end + 20].copy_from_slice(&(content.len() as u32).to_le_bytes());
        hcl[content_start..].copy_from_slice(content);
        hcl
    }

    #[test]
    fn test_invalid_base64_hcl_report() {
        let evidence = AzTdxEvidence {
            version: 1,
            tpm_quote: build_dummy_tpm_quote(),
            hcl_report: "!!!invalid!!!".to_string(),
            td_quote: BASE64URL.encode([0u8; 100]),
        };

        let rt = tokio::runtime::Runtime::new().unwrap();
        let params = VerifyParams::default();

        let result = rt.block_on(verify_evidence(&evidence, &params, None));
        assert!(result.is_err());
        let err = format!("{:?}", result.err().unwrap());
        assert!(
            err.contains("base64") || err.contains("Base64"),
            "error: {err}"
        );
    }

    #[test]
    fn test_evidence_version_rejected() {
        let evidence = AzTdxEvidence {
            version: 99,
            tpm_quote: build_dummy_tpm_quote(),
            hcl_report: "dGVzdA".to_string(),
            td_quote: "AAAA".to_string(),
        };

        let rt = tokio::runtime::Runtime::new().unwrap();
        let params = VerifyParams::default();

        let result = rt.block_on(verify_evidence(&evidence, &params, None));
        assert!(result.is_err());
        let err = format!("{:?}", result.err().unwrap());
        assert!(
            err.contains("version"),
            "error should mention version: {err}"
        );
    }

    #[test]
    fn test_hcl_report_type_must_be_tdx() {
        let hcl = build_hcl_report(tpm_common::HCL_REPORT_TYPE_SNP, b"{}");

        let evidence = AzTdxEvidence {
            version: 1,
            tpm_quote: build_dummy_tpm_quote(),
            hcl_report: BASE64URL.encode(&hcl),
            td_quote: BASE64URL.encode([0u8; 100]),
        };

        let rt = tokio::runtime::Runtime::new().unwrap();
        let params = VerifyParams::default();

        let result = rt.block_on(verify_evidence(&evidence, &params, None));
        assert!(result.is_err());
        let err = format!("{:?}", result.err().unwrap());
        assert!(
            err.contains("report_type") || err.contains("expected"),
            "error: {err}"
        );
    }

    #[test]
    fn test_hcl_report_too_short() {
        let short_hcl = vec![0u8; 100];

        let evidence = AzTdxEvidence {
            version: 1,
            tpm_quote: build_dummy_tpm_quote(),
            hcl_report: BASE64URL.encode(&short_hcl),
            td_quote: BASE64URL.encode([0u8; 100]),
        };

        let rt = tokio::runtime::Runtime::new().unwrap();
        let params = VerifyParams::default();

        let result = rt.block_on(verify_evidence(&evidence, &params, None));
        assert!(result.is_err());
        let err = format!("{:?}", result.err().unwrap());
        assert!(
            err.contains("too short"),
            "error should mention too short: {err}"
        );
    }

    // --- Tests using real CoCo TDX HCL report fixture ---

    const COCO_TDX_HCL_REPORT: &[u8] = include_bytes!("../../../test_data/az_tdx/hcl-report.bin");

    #[test]
    fn test_coco_tdx_hcl_report_parses() {
        let parsed = tpm_common::parse_hcl_report(COCO_TDX_HCL_REPORT);
        assert!(
            parsed.is_ok(),
            "TDX HCL report should parse: {:?}",
            parsed.err()
        );

        let parsed = parsed.unwrap();
        assert_eq!(parsed.tee_report.len(), 1184);
        assert_eq!(parsed.report_type, tpm_common::HCL_REPORT_TYPE_TDX);
        assert!(!parsed.var_data.is_empty());
    }

    #[test]
    fn test_coco_tdx_hcl_var_data_is_jwk_json() {
        let parsed = tpm_common::parse_hcl_report(COCO_TDX_HCL_REPORT).unwrap();

        let json: serde_json::Value =
            serde_json::from_slice(&parsed.var_data).expect("TDX var_data should be valid JSON");
        assert!(json["keys"].is_array(), "JSON should contain 'keys' array");

        let keys = json["keys"].as_array().unwrap();
        let ak_key = keys.iter().find(|k| k["kid"] == "HCLAkPub");
        assert!(ak_key.is_some(), "should contain HCLAkPub key");
        assert_eq!(ak_key.unwrap()["kty"], "RSA");
    }

    #[test]
    fn test_coco_tdx_hcl_var_data_contains_ak_pub() {
        let parsed = tpm_common::parse_hcl_report(COCO_TDX_HCL_REPORT).unwrap();

        let result = tpm_common::extract_ak_pub_from_jwk_json(&parsed.var_data);
        assert!(
            result.is_ok(),
            "should extract AK pub from TDX JWK JSON: {:?}",
            result.err()
        );

        let (modulus, exponent) = result.unwrap();
        assert_eq!(modulus.len(), 256, "RSA 2048 modulus should be 256 bytes");
        assert_eq!(exponent, vec![0x01, 0x00, 0x01], "exponent should be 65537");
    }

    #[test]
    fn test_coco_tdx_tpm_quote_v1_deserializes() {
        let json = include_str!("../../../test_data/az_tdx/tpm-quote-v1.json");
        let quote: std::result::Result<tpm_common::TpmQuote, _> = serde_json::from_str(json);
        assert!(
            quote.is_ok(),
            "tpm-quote-v1.json should deserialize: {:?}",
            quote.err()
        );

        let quote = quote.unwrap();
        assert_eq!(quote.pcrs.len(), 24);
        assert!(!quote.signature.is_empty());
        assert!(!quote.message.is_empty());
    }

    #[test]
    fn test_coco_tdx_evidence_v1_deserializes() {
        let json = include_str!("../../../test_data/az_tdx/evidence-v1.json");
        let envelope: crate::types::AttestationEvidence = serde_json::from_str(json).unwrap();
        assert_eq!(envelope.platform, crate::types::PlatformType::AzTdx);
        let evidence: std::result::Result<AzTdxEvidence, _> =
            serde_json::from_value(envelope.evidence);
        assert!(
            evidence.is_ok(),
            "TDX evidence-v1.json should deserialize: {:?}",
            evidence.err()
        );

        let evidence = evidence.unwrap();
        assert_eq!(evidence.version, 1);
        assert!(!evidence.hcl_report.is_empty());
        assert!(!evidence.td_quote.is_empty());
    }

    #[test]
    fn test_coco_tdx_tpm_signature_verification() {
        let parsed = tpm_common::parse_hcl_report(COCO_TDX_HCL_REPORT).unwrap();

        let json = include_str!("../../../test_data/az_tdx/tpm-quote-v1.json");
        let quote: tpm_common::TpmQuote = serde_json::from_str(json).unwrap();

        let sig = hex::decode(&quote.signature).unwrap();
        let msg = hex::decode(&quote.message).unwrap();

        let result = tpm_common::verify_tpm_signature(&sig, &msg, &parsed.var_data);
        assert!(
            result.is_ok(),
            "TDX TPM signature should verify: {:?}",
            result.err()
        );
    }
}
