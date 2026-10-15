//! Utility to capture live attestation evidence and save as test fixture.
//! Run with: cargo test --test capture_fixture --features "attest" -- --ignored --nocapture

#![cfg(all(feature = "attest", target_os = "linux"))]

/// Verify the captured evidence as `platform` and print the verdict.
async fn verify(platform: &str, evidence: &impl serde::Serialize) {
    let envelope = serde_json::json!({ "platform": platform, "evidence": evidence });
    let verified = attestation::verify(
        envelope.to_string().as_bytes(),
        &attestation::Policies::all(),
    )
    .await
    .expect("verify failed");
    eprintln!("Verified: passed={}", verified.passed());
    eprintln!(
        "Launch digest: {}",
        verified.platform.claims().launch_digest
    );
    for c in &verified.collateral {
        eprintln!("  {} current={}", c.name, c.current);
    }
}

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

    verify("tdx", &evidence).await;
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

    verify("az-snp", &evidence).await;
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

    verify("az-tdx", &evidence).await;
}
