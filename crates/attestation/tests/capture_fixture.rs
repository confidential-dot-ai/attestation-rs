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
    use attestation::{Context, Platform, Tdx, TdxParams};
    let params = TdxParams::default();

    let result = Tdx::verify(&evidence, &params, &Context::offline())
        .await
        .expect("verify without collateral failed");
    eprintln!("Verified (no collateral): passed={}", result.passed());
    eprintln!("Launch digest (MRTD): {}", result.claims.launch_digest);

    // With collateral
    match Tdx::verify(&evidence, &params, &Context::new()).await {
        Ok(r) => {
            eprintln!("Verified (with collateral): crl_ok={:?}", r.crl_ok);
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
    use attestation::{AzSnp, AzSnpParams, Context, Platform};
    let result = AzSnp::verify(&evidence, &AzSnpParams::default(), &Context::new())
        .await
        .expect("verify failed");
    eprintln!("Verified: passed={}", result.passed());
    eprintln!("Launch digest: {}", result.snp.claims.launch_digest);
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
    use attestation::{AzTdx, AzTdxParams, Context, Platform};
    let result = AzTdx::verify(&evidence, &AzTdxParams::default(), &Context::offline())
        .await
        .expect("verify failed");
    eprintln!("Verified: passed={}", result.passed());
    eprintln!("Launch digest: {}", result.tdx.claims.launch_digest);
}
