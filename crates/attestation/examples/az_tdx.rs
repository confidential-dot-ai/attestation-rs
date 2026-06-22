//! Azure TDX (vTPM) attestation example.
//!
//! Run on an Azure TDX Confidential VM:
//!   cargo run --example az_tdx --features "az-tdx,attest"

use std::env;
use std::time::Instant;

use attestation::{PlatformType, VendorResult, VerifyParams};

#[tokio::main]
async fn main() {
    let nonce: Vec<u8> = env::args()
        .nth(1)
        .map(|s| s.into_bytes())
        .unwrap_or_else(|| b"example-az-tdx-nonce".to_vec());

    eprintln!("Nonce: {:?}", String::from_utf8_lossy(&nonce));

    let t0 = Instant::now();

    eprintln!("Generating Azure TDX attestation evidence...");
    let evidence_json = attestation::attest(
        PlatformType::AzTdx,
        &nonce,
        &attestation::AttestOptions::default(),
    )
    .await
    .expect("attestation failed");
    eprintln!(
        "[attest]  {:?} ({} bytes)",
        t0.elapsed(),
        evidence_json.len()
    );

    eprintln!("Verifying...");
    let t1 = Instant::now();
    let params = VerifyParams::default();
    let result = attestation::verify(&evidence_json, &params)
        .await
        .expect("verification failed");
    eprintln!("[verify]  {:?}", t1.elapsed());

    eprintln!("[total]   {:?}", t0.elapsed());
    eprintln!("Signature valid: {}", result.signature_valid);
    eprintln!("Platform: {}", result.vendor.platform());
    eprintln!(
        "Launch measurement: {}",
        hex::encode(&result.launch_measurement)
    );

    if let VendorResult::AzTdx(ref t) = result.vendor {
        if let Some(tcb_status) = &t.tcb_status {
            eprintln!("TCB status: {:?}", tcb_status.tcb_status);
            eprintln!("FMSPC: {}", tcb_status.fmspc);
        }
    }

    println!("{}", String::from_utf8_lossy(&evidence_json));
}
