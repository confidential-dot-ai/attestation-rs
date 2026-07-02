//! Integration tests for Azure SNP CVM attestation.
//!
//! These tests require:
//! - Running on an Azure SEV-SNP Confidential VM
//! - tpm2-tools installed (tpm2_nvread, tpm2_quote, tpm2_pcrread)
//! - Access to Azure IMDS
//! - Sufficient permissions for TPM access (root or tss group)
//!
//! Run with: cargo test --test az_snp_live --features "az-snp,attest" -- --ignored
//!
//! Tests are #[ignore] by default — run with --ignored to execute on real hardware.

#![cfg(all(feature = "attest", feature = "az-snp", target_os = "linux"))]

use std::path::Path;

use base64::Engine;

use attestation::types::VerifyParams;

/// Helper: check if we're running on an Azure SNP CVM with the required tools.
fn is_az_snp_cvm() -> bool {
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
async fn test_az_snp_detect_platform() {
    if !is_az_snp_cvm() {
        eprintln!("SKIP: not running on an Azure SNP CVM");
        return;
    }

    let platform = attestation::detect();
    assert!(
        platform.is_ok(),
        "detect() should succeed on Azure SNP CVM: {:?}",
        platform.err()
    );
    assert_eq!(
        platform.unwrap(),
        attestation::PlatformType::AzSnp,
        "should detect AzSnp platform"
    );
}

#[tokio::test]
#[ignore]
async fn test_az_snp_attest_generates_valid_evidence() {
    if !is_az_snp_cvm() {
        eprintln!("SKIP: not running on an Azure SNP CVM");
        return;
    }

    // Generate evidence with a test nonce
    let nonce = b"integration-test-nonce-12345678";
    let evidence = attestation::platforms::az_snp::attest::generate_evidence(nonce).await;
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
    assert!(!evidence.vcek.is_empty(), "VCEK should not be empty");
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

    // VCEK should be valid DER
    let vcek_der = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(evidence.vcek.trim_end_matches('='))
        .expect("VCEK should be valid base64url");
    assert!(vcek_der.len() > 100, "VCEK DER should be reasonably sized");

    // Evidence should round-trip through JSON
    let json = serde_json::to_string(&evidence).unwrap();
    let deserialized: attestation::platforms::az_snp::evidence::AzSnpEvidence =
        serde_json::from_str(&json).unwrap();
    assert_eq!(deserialized.version, evidence.version);
    assert_eq!(deserialized.tpm_quote.pcrs.len(), 24);
}

#[tokio::test]
#[ignore]
async fn test_az_snp_attest_then_verify_roundtrip() {
    if !is_az_snp_cvm() {
        eprintln!("SKIP: not running on an Azure SNP CVM");
        return;
    }

    // Generate evidence
    let nonce = b"roundtrip-test-nonce-abcdef1234";
    let evidence = attestation::platforms::az_snp::attest::generate_evidence(nonce)
        .await
        .expect("generate_evidence() should succeed");

    // Verify without expected values (just check structure)
    let params = VerifyParams::default();
    let provider = attestation::collateral::DefaultCertProvider::new();
    let result =
        attestation::platforms::az_snp::verify::verify_evidence(&evidence, &params, &provider)
            .await;

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

    // Platform should be AzSnp
    assert_eq!(result.platform, attestation::PlatformType::AzSnp);

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
async fn test_az_snp_verify_with_expected_nonce() {
    if !is_az_snp_cvm() {
        eprintln!("SKIP: not running on an Azure SNP CVM");
        return;
    }

    let nonce = b"nonce-verification-test";
    let evidence = attestation::platforms::az_snp::attest::generate_evidence(nonce)
        .await
        .expect("generate_evidence() should succeed");

    // Verify with correct nonce
    let mut padded_nonce = vec![0u8; 64];
    padded_nonce[..nonce.len()].copy_from_slice(nonce);

    let params = VerifyParams {
        expected_report_data: Some(padded_nonce),
        expected_init_data_hash: None,
        ..Default::default()
    };

    let provider = attestation::collateral::DefaultCertProvider::new();
    let result =
        attestation::platforms::az_snp::verify::verify_evidence(&evidence, &params, &provider)
            .await
            .expect("verify should succeed");

    assert!(result.signature_valid);
}

#[tokio::test]
#[ignore]
async fn test_az_snp_hcl_report_contains_snp_report() {
    if !is_az_snp_cvm() {
        eprintln!("SKIP: not running on an Azure SNP CVM");
        return;
    }

    let evidence = attestation::platforms::az_snp::attest::generate_evidence(b"hcl-test")
        .await
        .expect("generate_evidence() should succeed");

    // Parse HCL report
    let hcl_bytes = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(evidence.hcl_report.trim_end_matches('='))
        .unwrap();

    let hcl = attestation::platforms::tpm_common::parse_hcl_report(&hcl_bytes)
        .expect("HCL report should parse");

    // Should be SNP type
    assert_eq!(
        hcl.report_type,
        attestation::platforms::tpm_common::HCL_REPORT_TYPE_SNP,
        "report type should be SNP (2)"
    );

    // TEE report should be 1184 bytes (SNP report)
    assert_eq!(hcl.tee_report.len(), 1184);

    // Should parse as a valid SNP report
    let snp_report = attestation::platforms::snp::verify::parse_report(&hcl.tee_report)
        .expect("should parse as SNP report");

    // Version should be >= 3
    assert!(
        snp_report.version >= 3,
        "SNP report version should be >= 3, got {}",
        snp_report.version
    );

    // VMPL should be 0 on Azure CVMs
    assert_eq!(snp_report.vmpl, 0, "VMPL should be 0");

    // var_data should be valid JWK JSON
    let json: serde_json::Value =
        serde_json::from_slice(&hcl.var_data).expect("var_data should be valid JSON");
    assert!(json["keys"].is_array(), "should have keys array");
}

#[tokio::test]
#[ignore]
async fn test_az_snp_cross_process_serialization() {
    if !is_az_snp_cvm() {
        eprintln!("SKIP: not running on an Azure SNP CVM");
        return;
    }

    let evidence = attestation::platforms::az_snp::attest::generate_evidence(b"cross-process")
        .await
        .expect("generate_evidence() should succeed");

    // Serialize to JSON file
    let tmp = tempfile::NamedTempFile::new().unwrap();
    let json = serde_json::to_string_pretty(&evidence).unwrap();
    std::fs::write(tmp.path(), &json).unwrap();

    // Read back and deserialize
    let json_back = std::fs::read_to_string(tmp.path()).unwrap();
    let evidence_back: attestation::platforms::az_snp::evidence::AzSnpEvidence =
        serde_json::from_str(&json_back).unwrap();

    // Verify the deserialized evidence
    let params = VerifyParams::default();
    let provider = attestation::collateral::DefaultCertProvider::new();
    let result =
        attestation::platforms::az_snp::verify::verify_evidence(&evidence_back, &params, &provider)
            .await;

    assert!(
        result.is_ok(),
        "should verify evidence deserialized from file: {:?}",
        result.err()
    );
    assert!(result.unwrap().signature_valid);
}
