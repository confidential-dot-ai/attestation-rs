//! Bare-metal Intel TDX attestation example.
//!
//! Run on a TDX-enabled machine:
//!   cargo run --example tdx --features "tdx,attest"

use attestation::{PlatformType, VendorResult, VerifyParams};

#[tokio::main]
async fn main() {
    let nonce = b"example-tdx-nonce";

    eprintln!("Generating TDX attestation evidence...");
    let evidence_json = attestation::attest(
        PlatformType::Tdx,
        nonce,
        &attestation::AttestOptions::default(),
    )
    .await
    .expect("attestation failed");

    eprintln!("Evidence: {} bytes", evidence_json.len());

    eprintln!("Verifying...");
    let params = VerifyParams::default();
    let result = attestation::verify(&evidence_json, &params)
        .await
        .expect("verification failed");

    eprintln!("Signature valid: {}", result.signature_valid);
    eprintln!("Platform: {}", result.vendor.platform());
    eprintln!(
        "Launch measurement: {}",
        hex::encode(&result.launch_measurement)
    );

    if let VendorResult::Tdx(ref t) = result.vendor {
        if let Some(tcb_status) = &t.tcb_status {
            eprintln!("TCB status: {:?}", tcb_status.tcb_status);
            eprintln!("FMSPC: {}", tcb_status.fmspc);
        }
    }

    println!("{}", String::from_utf8_lossy(&evidence_json));
}
