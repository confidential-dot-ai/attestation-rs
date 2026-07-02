//! GCP bare-metal AMD SEV-SNP attestation example.
//!
//! Run on a GCP Confidential VM with SEV-SNP:
//!   cargo run --example gcp_snp --features "gcp-snp,attest"
//!
//! # Production usage note
//!
//! The nonce MUST be a fresh, cryptographically random challenge supplied by
//! the *verifier* side, not a static string. AMD SNP reports have no expiry —
//! a replayed report with a known static nonce passes all verification steps.
//! Always set `VerifyParams::expected_report_data` to the nonce you sent, or
//! the freshness guarantee is meaningless.

#[cfg(not(target_os = "linux"))]
fn main() {
    eprintln!("This example requires Linux.");
}

#[cfg(target_os = "linux")]
#[tokio::main]
async fn main() {
    use attestation::{PlatformType, VerifyParams};

    // PRODUCTION: replace with a fresh random challenge from the verifier.
    let nonce = b"example-gcp-snp-nonce-replace-me";

    eprintln!("Generating GCP SNP attestation evidence...");
    let evidence_json = attestation::attest(
        PlatformType::GcpSnp,
        nonce,
        &attestation::AttestOptions::default(),
    )
    .await
    .expect("attestation failed");

    eprintln!("Evidence: {} bytes", evidence_json.len());

    eprintln!("Verifying...");
    let params = VerifyParams {
        expected_report_data: Some(nonce.to_vec()),
        ..Default::default()
    };
    let result = attestation::verify(&evidence_json, &params)
        .await
        .expect("verification failed");

    assert_eq!(
        result.report_data_match,
        Some(true),
        "nonce binding failed — evidence does not match the challenge"
    );

    eprintln!("Signature valid: {}", result.signature_valid);
    eprintln!("Platform: {}", result.platform);
    eprintln!("Launch digest: {}", result.claims.launch_digest);
    println!("{}", String::from_utf8_lossy(&evidence_json));
}
