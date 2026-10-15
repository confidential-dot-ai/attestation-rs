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
//! Always set `report_data` in the params to the nonce you sent, or
//! the freshness guarantee is meaningless.

#[cfg(not(target_os = "linux"))]
fn main() {
    eprintln!("This example requires Linux.");
}

#[cfg(target_os = "linux")]
#[tokio::main]
async fn main() {
    use attestation::{GcpSnpParams, PlatformType, Policies, SnpParams};

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
    let policies = Policies {
        gcp_snp: Some(GcpSnpParams {
            snp: SnpParams {
                report_data: Some(nonce.to_vec()),
                ..Default::default()
            },
        }),
        ..Default::default()
    };
    let verified = attestation::verify(&evidence_json, &policies)
        .await
        .expect("verification failed");

    assert!(
        verified.passed(),
        "nonce binding failed — evidence does not match the challenge"
    );

    eprintln!(
        "Launch digest: {}",
        verified.platform.claims().launch_digest
    );
    println!("{}", String::from_utf8_lossy(&evidence_json));
}
