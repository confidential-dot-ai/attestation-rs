//! Utility to capture live attestation evidence and save as test fixture.
//! Run with: cargo test --test capture_fixture --features "attest" -- --ignored --nocapture

#![cfg(all(feature = "attest", target_os = "linux"))]

#[cfg(feature = "tdx")]
#[tokio::test]
#[ignore]
async fn capture_tdx_evidence_fixture() {
    let nonce = b"attestation-test-fixture";
    let evidence = attestation::platforms::tdx::attest::generate_evidence(nonce)
        .await
        .expect("attest failed");

    let json = serde_json::to_string_pretty(&evidence).unwrap();
    let path = "test_data/tdx_live_evidence.json";
    std::fs::write(path, &json).unwrap();
    eprintln!("Wrote {} ({} bytes)", path, json.len());

    // Verify it — first without collateral, then with
    let params = attestation::types::VerifyParams::default();

    let result = attestation::platforms::tdx::verify::verify_evidence(&evidence, &params, None)
        .await
        .expect("verify without collateral failed");
    eprintln!(
        "Verified (no collateral): signature_valid={}, platform={}",
        result.signature_valid, result.platform
    );
    eprintln!("Launch digest (MRTD): {}", result.claims.launch_digest);
    assert!(result.signature_valid);

    // With collateral
    let provider = attestation::collateral::DefaultTdxCollateralProvider::new();
    match attestation::platforms::tdx::verify::verify_evidence(&evidence, &params, Some(&provider))
        .await
    {
        Ok(r) => {
            eprintln!(
                "Verified (with collateral): collateral_verified={}",
                r.collateral_verified
            );
            if let Some(ref tcb) = r.tcb_status {
                eprintln!("  TCB status: {}", tcb.tcb_status);
                eprintln!("  FMSPC: {}", tcb.fmspc);
            }
        }
        Err(e) => {
            eprintln!("Collateral verification failed (may be expected): {e}");
        }
    }
}

#[cfg(all(feature = "attest", feature = "az-snp"))]
#[tokio::test]
#[ignore]
async fn capture_az_snp_evidence_fixture() {
    let nonce = b"attestation-test-fixture";
    let evidence = attestation::platforms::az_snp::attest::generate_evidence(nonce)
        .await
        .expect("attest failed");

    let json = serde_json::to_string_pretty(&evidence).unwrap();
    let path = "test_data/az_snp/live-evidence.json";
    std::fs::write(path, &json).unwrap();
    eprintln!("Wrote {} ({} bytes)", path, json.len());

    // Also verify it
    let params = attestation::types::VerifyParams::default();
    let provider = attestation::collateral::DefaultCertProvider::new();
    let result =
        attestation::platforms::az_snp::verify::verify_evidence(&evidence, &params, &provider)
            .await
            .expect("verify failed");
    eprintln!(
        "Verified: signature_valid={}, platform={}",
        result.signature_valid, result.platform
    );
    eprintln!("Launch digest: {}", result.claims.launch_digest);
    assert!(result.signature_valid);
}

#[cfg(all(feature = "attest", feature = "az-tdx"))]
#[tokio::test]
#[ignore]
async fn capture_az_tdx_evidence_fixture() {
    let nonce = b"attestation-test-fixture";
    let evidence = attestation::platforms::az_tdx::attest::generate_evidence(nonce)
        .await
        .expect("attest failed");

    let json = serde_json::to_string_pretty(&evidence).unwrap();
    let path = "test_data/az_tdx/live-evidence.json";
    std::fs::write(path, &json).unwrap();
    eprintln!("Wrote {} ({} bytes)", path, json.len());

    // Also verify it
    let params = attestation::types::VerifyParams::default();
    let result = attestation::platforms::az_tdx::verify::verify_evidence(&evidence, &params, None)
        .await
        .expect("verify failed");
    eprintln!(
        "Verified: signature_valid={}, platform={}",
        result.signature_valid, result.platform
    );
    eprintln!("Launch digest: {}", result.claims.launch_digest);
    assert!(result.signature_valid);
}
