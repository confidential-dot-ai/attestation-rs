//! Integration tests for Azure TDX CVM attestation.
//!
//! These tests require:
//! - Running on an Azure TDX Confidential VM
//! - tpm2-tools installed (tpm2_nvread, tpm2_quote, tpm2_pcrread)
//! - Access to Azure IMDS
//! - Sufficient permissions for TPM access (root or tss group)
//!
//! Run with: cargo test --test az_tdx_live --features "az-tdx,attest" -- --ignored
//!
//! Tests are #[ignore] by default — run with --ignored to execute on real hardware.

#![cfg(all(feature = "attest", feature = "az-tdx", target_os = "linux"))]

use std::path::Path;

use base64::Engine;

use attestation::types::VerifyParams;

/// Helper: check if we're running on an Azure TDX CVM with the required tools.
fn is_az_tdx_cvm() -> bool {
    // Check for TPM device
    let has_tpm = Path::new("/dev/tpmrm0").exists() || Path::new("/dev/tpm0").exists();

    // Check for Azure environment via IMDS (more reliable than file checks)
    let is_azure = std::process::Command::new("curl")
        .args([
            "-s",
            "-o",
            "/dev/null",
            "-w",
            "%{http_code}",
            "--max-time",
            "2",
            "-H",
            "Metadata:true",
            "http://169.254.169.254/metadata/instance?api-version=2021-02-01",
        ])
        .output()
        .map(|o| String::from_utf8_lossy(&o.stdout).trim() == "200")
        .unwrap_or(false);

    // Check for tpm2-tools
    let has_tools = std::process::Command::new("which")
        .arg("tpm2_nvread")
        .output()
        .map(|o| o.status.success())
        .unwrap_or(false);

    has_tpm && is_azure && has_tools
}

#[tokio::test]
#[ignore]
async fn test_az_tdx_detect_platform() {
    if !is_az_tdx_cvm() {
        eprintln!("SKIP: not running on an Azure TDX CVM");
        return;
    }

    let platform = attestation::detect();
    assert!(
        platform.is_ok(),
        "detect() should succeed on Azure TDX CVM: {:?}",
        platform.err()
    );
    assert_eq!(
        platform.unwrap(),
        attestation::PlatformType::AzTdx,
        "should detect AzTdx platform"
    );
}

#[tokio::test]
#[ignore]
async fn test_az_tdx_attest_generates_valid_evidence() {
    if !is_az_tdx_cvm() {
        eprintln!("SKIP: not running on an Azure TDX CVM");
        return;
    }

    // Generate evidence with a test nonce
    let nonce = b"integration-test-nonce-12345678";
    let evidence = attestation::platforms::az_tdx::attest::generate_evidence(nonce).await;
    assert!(
        evidence.is_ok(),
        "generate_evidence() should succeed: {:?}",
        evidence.err()
    );

    let evidence = evidence.unwrap();

    // Basic structural checks
    assert_eq!(evidence.version, 1);
    assert!(
        !evidence.hcl_report.is_empty(),
        "HCL report should not be empty"
    );
    assert!(
        !evidence.td_quote.is_empty(),
        "TD quote should not be empty"
    );
    assert!(
        !evidence.tpm_quote.signature.is_empty(),
        "TPM signature should not be empty"
    );
    assert!(
        !evidence.tpm_quote.message.is_empty(),
        "TPM message should not be empty"
    );
    assert_eq!(
        evidence.tpm_quote.pcrs.len(),
        24,
        "should have 24 PCR values"
    );

    // HCL report should decode and have HCLA magic
    let hcl_bytes = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(evidence.hcl_report.trim_end_matches('='))
        .expect("HCL report should be valid base64url");
    assert_eq!(
        &hcl_bytes[..4],
        b"HCLA",
        "HCL report should have HCLA magic"
    );
    assert_eq!(hcl_bytes.len(), 2600, "HCL report should be 2600 bytes");

    // TD quote should decode to valid bytes with TDX TEE type
    let td_quote_bytes = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(evidence.td_quote.trim_end_matches('='))
        .expect("TD quote should be valid base64url");
    assert!(
        td_quote_bytes.len() > 48,
        "TD quote should be larger than header (48 bytes), got {}",
        td_quote_bytes.len()
    );
    // TDX TEE type at offset 4 should be 0x00000081
    let tee_type = u32::from_le_bytes(td_quote_bytes[4..8].try_into().unwrap());
    assert_eq!(tee_type, 0x81, "TEE type should be 0x81 (TDX)");

    // Evidence should round-trip through JSON
    let json = serde_json::to_string(&evidence).unwrap();
    let deserialized: attestation::platforms::az_tdx::evidence::AzTdxEvidence =
        serde_json::from_str(&json).unwrap();
    assert_eq!(deserialized.version, evidence.version);
    assert_eq!(deserialized.tpm_quote.pcrs.len(), 24);
}

#[tokio::test]
#[ignore]
async fn test_az_tdx_attest_then_verify_roundtrip() {
    if !is_az_tdx_cvm() {
        eprintln!("SKIP: not running on an Azure TDX CVM");
        return;
    }

    // Generate evidence
    let nonce = b"roundtrip-test-nonce-abcdef1234";
    let evidence = attestation::platforms::az_tdx::attest::generate_evidence(nonce)
        .await
        .expect("generate_evidence() should succeed");

    // Verify without expected values (just check structure)
    let params = VerifyParams::default();
    let result =
        attestation::platforms::az_tdx::verify::verify_evidence(&evidence, &params, None).await;

    assert!(
        result.is_ok(),
        "verify() should succeed on freshly-attested evidence: {:?}",
        result.err()
    );

    let result = result.unwrap();

    // TPM signature should be valid
    assert!(
        result.signature_valid,
        "TPM signature should be valid on fresh evidence"
    );

    // Platform should be AzTdx
    assert_eq!(result.platform, attestation::PlatformType::AzTdx);

    // Claims should be populated
    assert!(
        !result.claims.launch_digest.is_empty(),
        "launch_digest should not be empty"
    );
    assert_eq!(
        result.claims.report_data.len(),
        64,
        "report_data should be 64 bytes"
    );

    // No expected values were provided, so these should be None
    assert!(result.report_data_match.is_none());
    assert!(result.init_data_match.is_none());
}

#[tokio::test]
#[ignore]
async fn test_az_tdx_verify_with_expected_nonce() {
    if !is_az_tdx_cvm() {
        eprintln!("SKIP: not running on an Azure TDX CVM");
        return;
    }

    let nonce = b"nonce-verification-test";
    let evidence = attestation::platforms::az_tdx::attest::generate_evidence(nonce)
        .await
        .expect("generate_evidence() should succeed");

    // Verify with correct nonce (unpadded — TPM stores the raw qualifying data)
    let params = VerifyParams {
        expected_report_data: Some(nonce.to_vec()),
        ..Default::default()
    };

    let result =
        attestation::platforms::az_tdx::verify::verify_evidence(&evidence, &params, None).await;

    assert!(
        result.is_ok(),
        "verify with correct nonce should succeed: {:?}",
        result.err()
    );
    let result = result.unwrap();
    assert!(result.signature_valid);
}

#[tokio::test]
#[ignore]
async fn test_az_tdx_hcl_report_contains_tdx_report() {
    if !is_az_tdx_cvm() {
        eprintln!("SKIP: not running on an Azure TDX CVM");
        return;
    }

    let evidence = attestation::platforms::az_tdx::attest::generate_evidence(b"hcl-test")
        .await
        .expect("generate_evidence() should succeed");

    // Parse HCL report
    let hcl_bytes = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(evidence.hcl_report.trim_end_matches('='))
        .unwrap();

    let hcl = attestation::platforms::tpm_common::parse_hcl_report(&hcl_bytes)
        .expect("HCL report should parse");

    // Should be TDX type
    assert_eq!(
        hcl.report_type,
        attestation::platforms::tpm_common::HCL_REPORT_TYPE_TDX,
        "report type should be TDX (4)"
    );

    // TEE report should be 1184 bytes (TDX report)
    assert_eq!(hcl.tee_report.len(), 1184);

    // var_data should be valid JWK JSON
    let json: serde_json::Value =
        serde_json::from_slice(&hcl.var_data).expect("var_data should be valid JSON");
    assert!(json["keys"].is_array(), "should have keys array");
}

#[tokio::test]
#[ignore]
async fn test_az_tdx_cross_process_serialization() {
    if !is_az_tdx_cvm() {
        eprintln!("SKIP: not running on an Azure TDX CVM");
        return;
    }

    let evidence = attestation::platforms::az_tdx::attest::generate_evidence(b"cross-process")
        .await
        .expect("generate_evidence() should succeed");

    // Serialize to JSON file
    let tmp = tempfile::NamedTempFile::new().unwrap();
    let json = serde_json::to_string_pretty(&evidence).unwrap();
    std::fs::write(tmp.path(), &json).unwrap();

    // Read back and deserialize
    let json_back = std::fs::read_to_string(tmp.path()).unwrap();
    let evidence_back: attestation::platforms::az_tdx::evidence::AzTdxEvidence =
        serde_json::from_str(&json_back).unwrap();

    // Verify the deserialized evidence
    let params = VerifyParams::default();
    let result =
        attestation::platforms::az_tdx::verify::verify_evidence(&evidence_back, &params, None)
            .await;

    assert!(
        result.is_ok(),
        "should verify evidence deserialized from file: {:?}",
        result.err()
    );
    assert!(result.unwrap().signature_valid);
}

#[tokio::test]
#[ignore]
async fn test_az_tdx_dcap_chain_validation() {
    if !is_az_tdx_cvm() {
        eprintln!("SKIP: not running on an Azure TDX CVM");
        return;
    }

    // Generate fresh evidence
    let evidence = attestation::platforms::az_tdx::attest::generate_evidence(b"dcap-test")
        .await
        .expect("generate_evidence() should succeed");

    // Decode TD quote
    let td_quote_bytes = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(evidence.td_quote.trim_end_matches('='))
        .expect("TD quote should be valid base64url");

    let tdx_quote = attestation::platforms::tdx::verify::parse_tdx_quote(&td_quote_bytes)
        .expect("TD quote should parse");

    // Full DCAP chain verification
    let body_end = attestation::platforms::tdx::dcap::compute_body_end(
        &td_quote_bytes,
        tdx_quote.quote_version,
    )
    .expect("compute_body_end should succeed");

    let auth = attestation::platforms::tdx::dcap::parse_auth_data(&td_quote_bytes, body_end)
        .expect("parse_auth_data should succeed");

    let pck_key = attestation::platforms::tdx::dcap::verify_pck_cert_chain(auth.pck_cert_chain_pem)
        .expect("PCK cert chain should validate to Intel Root CA");

    attestation::platforms::tdx::dcap::verify_qe_report_signature(&auth, &pck_key)
        .expect("QE report signature should verify with PCK key");

    attestation::platforms::tdx::dcap::verify_qe_report_binding(&auth)
        .expect("QE report binding should pass");
}

// ---------------------------------------------------------------
// Report data (nonce) tests
// ---------------------------------------------------------------

#[tokio::test]
#[ignore]
async fn test_az_tdx_wrong_nonce_fails_verification() {
    if !is_az_tdx_cvm() {
        eprintln!("SKIP: not running on an Azure TDX CVM");
        return;
    }

    let nonce = b"correct-nonce-value";
    let evidence = attestation::platforms::az_tdx::attest::generate_evidence(nonce)
        .await
        .expect("generate_evidence() should succeed");

    // Verify with WRONG nonce — should fail
    let params = VerifyParams {
        expected_report_data: Some(b"wrong-nonce-value!!".to_vec()),
        ..Default::default()
    };

    let result =
        attestation::platforms::az_tdx::verify::verify_evidence(&evidence, &params, None).await;

    assert!(
        result.is_err(),
        "verification with wrong nonce should fail, but got: {:?}",
        result.unwrap()
    );

    // Should be a ReportDataMismatch error
    let err = format!("{:?}", result.err().unwrap());
    assert!(
        err.contains("ReportDataMismatch"),
        "error should be ReportDataMismatch, got: {}",
        err
    );
}

#[tokio::test]
#[ignore]
async fn test_az_tdx_top_level_api_roundtrip_with_nonce() {
    if !is_az_tdx_cvm() {
        eprintln!("SKIP: not running on an Azure TDX CVM");
        return;
    }

    // Use the top-level attest() API
    let nonce = b"top-level-api-nonce-test";
    let evidence_json = attestation::attest(
        attestation::PlatformType::AzTdx,
        nonce,
        &attestation::AttestOptions::default(),
    )
    .await
    .expect("attest() should succeed");

    // Verify through top-level verify() API with matching nonce
    let params = VerifyParams {
        expected_report_data: Some(nonce.to_vec()),
        ..Default::default()
    };
    let result = attestation::verify(&evidence_json, &params)
        .await
        .expect("verify() with correct nonce should succeed");

    assert!(result.signature_valid, "signature should be valid");
    assert_eq!(result.platform, attestation::PlatformType::AzTdx);
    assert_eq!(
        result.report_data_match,
        Some(true),
        "report_data_match should be Some(true)"
    );

    // Print the result for visibility
    eprintln!("=== Top-level API roundtrip with nonce ===");
    eprintln!("  Platform: {}", result.platform);
    eprintln!("  Signature valid: {}", result.signature_valid);
    eprintln!("  Report data match: {:?}", result.report_data_match);
    eprintln!("  Launch digest: {}", result.claims.launch_digest);
    eprintln!(
        "  Report data (hex): {}",
        hex::encode(&result.claims.report_data)
    );
}

#[tokio::test]
#[ignore]
async fn test_az_tdx_top_level_api_wrong_nonce_fails() {
    if !is_az_tdx_cvm() {
        eprintln!("SKIP: not running on an Azure TDX CVM");
        return;
    }

    let nonce = b"attest-nonce-abc";
    let evidence_json = attestation::attest(
        attestation::PlatformType::AzTdx,
        nonce,
        &attestation::AttestOptions::default(),
    )
    .await
    .expect("attest() should succeed");

    // Verify through top-level verify() API with WRONG nonce
    let params = VerifyParams {
        expected_report_data: Some(b"completely-different".to_vec()),
        ..Default::default()
    };
    let result = attestation::verify(&evidence_json, &params).await;

    assert!(result.is_err(), "verify() with wrong nonce should fail");
}

#[tokio::test]
#[ignore]
async fn test_az_tdx_empty_nonce_roundtrip() {
    if !is_az_tdx_cvm() {
        eprintln!("SKIP: not running on an Azure TDX CVM");
        return;
    }

    // Attest with empty report_data
    let evidence = attestation::platforms::az_tdx::attest::generate_evidence(b"")
        .await
        .expect("generate_evidence() with empty nonce should succeed");

    // Verify without expected_report_data (don't check nonce)
    let params = VerifyParams::default();
    let result = attestation::platforms::az_tdx::verify::verify_evidence(&evidence, &params, None)
        .await
        .expect("verify() with empty nonce evidence should succeed");

    assert!(result.signature_valid);
    assert!(result.report_data_match.is_none());

    eprintln!("=== Empty nonce roundtrip ===");
    eprintln!("  Signature valid: {}", result.signature_valid);
}

#[tokio::test]
#[ignore]
async fn test_az_tdx_32_byte_nonce() {
    if !is_az_tdx_cvm() {
        eprintln!("SKIP: not running on an Azure TDX CVM");
        return;
    }

    // 32-byte nonce (SHA-256 hash size, common use case)
    let nonce = [0xAB_u8; 32];
    let evidence = attestation::platforms::az_tdx::attest::generate_evidence(&nonce)
        .await
        .expect("generate_evidence() with 32-byte nonce should succeed");

    // Verify with matching nonce
    let params = VerifyParams {
        expected_report_data: Some(nonce.to_vec()),
        ..Default::default()
    };
    let result = attestation::platforms::az_tdx::verify::verify_evidence(&evidence, &params, None)
        .await
        .expect("verify() with 32-byte nonce should succeed");

    assert!(result.signature_valid);

    eprintln!("=== 32-byte nonce roundtrip ===");
    eprintln!("  Signature valid: {}", result.signature_valid);
    eprintln!("  Report data match: {:?}", result.report_data_match);
}

#[tokio::test]
#[ignore]
async fn test_az_tdx_64_byte_nonce_rejected_by_tpm() {
    if !is_az_tdx_cvm() {
        eprintln!("SKIP: not running on an Azure TDX CVM");
        return;
    }

    // 64-byte nonce: Azure vTPM's TPM2_Quote rejects this size for qualifyingData
    // despite pad_report_data() allowing up to 64 bytes. The TPM2B_DATA buffer
    // has a max of sizeof(TPMU_HA) = 64, but the Azure vTPM enforces a stricter
    // limit. This is a known limitation of Azure TDX vs bare TDX.
    let nonce = [0xAB_u8; 64];
    let result = attestation::platforms::az_tdx::attest::generate_evidence(&nonce).await;

    assert!(
        result.is_err(),
        "64-byte nonce should be rejected by Azure vTPM"
    );

    eprintln!("=== 64-byte nonce (expected failure) ===");
    eprintln!("  Error: {:?}", result.err().unwrap());
    eprintln!("  Note: Azure vTPM rejects 64-byte qualifyingData in TPM2_Quote");
}

#[tokio::test]
#[ignore]
async fn test_az_tdx_nonce_not_in_quote_report_data() {
    if !is_az_tdx_cvm() {
        eprintln!("SKIP: not running on an Azure TDX CVM");
        return;
    }

    // For Azure TDX, the user's nonce goes into the TPM message (extraData),
    // NOT into the TDX quote's report_data field. The quote's report_data
    // contains SHA-256(HCL var_data) instead.
    let nonce = b"nonce-location-test";
    let evidence = attestation::platforms::az_tdx::attest::generate_evidence(nonce)
        .await
        .expect("generate_evidence() should succeed");

    // Decode TD quote and check report_data
    let td_quote_bytes = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(evidence.td_quote.trim_end_matches('='))
        .expect("TD quote should be valid base64url");

    let tdx_quote = attestation::platforms::tdx::verify::parse_tdx_quote(&td_quote_bytes)
        .expect("TD quote should parse");

    // The quote's report_data should NOT contain the raw nonce.
    // It should contain SHA-256(HCL var_data) in the first 32 bytes.
    let mut nonce_padded = [0u8; 64];
    nonce_padded[..nonce.len()].copy_from_slice(nonce);
    assert_ne!(
        tdx_quote.body.report_data, nonce_padded,
        "Azure TDX quote report_data should NOT contain the raw user nonce"
    );

    // Instead, decode HCL var_data and verify binding
    let hcl_bytes = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(evidence.hcl_report.trim_end_matches('='))
        .unwrap();
    let hcl = attestation::platforms::tpm_common::parse_hcl_report(&hcl_bytes).unwrap();
    let var_data_hash = attestation::utils::sha256(&hcl.var_data);

    assert_eq!(
        &tdx_quote.body.report_data[..32],
        &var_data_hash[..],
        "Azure TDX quote report_data[0:32] should be SHA-256(var_data)"
    );

    eprintln!("=== Nonce location verification ===");
    eprintln!("  User nonce: {:?}", String::from_utf8_lossy(nonce));
    eprintln!(
        "  Quote report_data[0:32]: {}",
        hex::encode(&tdx_quote.body.report_data[..32])
    );
    eprintln!("  SHA-256(var_data): {}", hex::encode(&var_data_hash));
    eprintln!("  Match: true (nonce is in TPM extraData, not in quote report_data)");
}
