//! GCP bare-metal Intel TDX attestation example.
//!
//! Run on a GCP Confidential VM with TDX:
//!   cargo run --example gcp_tdx --features "gcp-tdx,attest"
//!
//! # Production usage note
//!
//! The nonce MUST be a fresh, cryptographically random challenge supplied by
//! the *verifier* side, not a static string. TDX quotes have no expiry —
//! a replayed quote with a known static nonce passes all verification steps.
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
    let nonce = b"example-gcp-tdx-nonce-replace-me";

    eprintln!("Generating GCP TDX attestation evidence...");
    let evidence_json = attestation::attest(
        PlatformType::GcpTdx,
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

    if let Some(tcb_status) = &result.tcb_status {
        eprintln!("TCB status: {:?}", tcb_status.tcb_status);
        eprintln!("FMSPC: {}", tcb_status.fmspc);
    }

    println!("{}", String::from_utf8_lossy(&evidence_json));
}
