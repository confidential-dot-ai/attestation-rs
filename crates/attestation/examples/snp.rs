//! Bare-metal AMD SEV-SNP attestation example.
//!
//! Run on an SNP-enabled machine:
//!   cargo run --example snp --features "snp,attest"

#[cfg(not(target_os = "linux"))]
fn main() {
    eprintln!("This example requires Linux.");
}

#[cfg(target_os = "linux")]
#[tokio::main]
async fn main() {
    use attestation::{PlatformType, Policies, SnpParams};

    let nonce = b"example-snp-nonce";

    eprintln!("Generating SNP attestation evidence...");
    let evidence_json = attestation::attest(
        PlatformType::Snp,
        nonce,
        &attestation::AttestOptions::default(),
    )
    .await
    .expect("attestation failed");

    eprintln!("Evidence: {} bytes", evidence_json.len());

    eprintln!("Verifying...");
    let policies = Policies {
        snp: Some(SnpParams {
            report_data: Some(nonce.to_vec()),
            ..Default::default()
        }),
        ..Default::default()
    };
    let verified = attestation::verify(&evidence_json, &policies)
        .await
        .expect("verification failed");

    eprintln!("Passed: {}", verified.passed());
    eprintln!(
        "Launch digest: {}",
        verified.platform.claims().launch_digest
    );
    println!("{}", String::from_utf8_lossy(&evidence_json));
}
