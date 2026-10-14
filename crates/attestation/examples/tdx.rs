//! Bare-metal Intel TDX attestation example.
//!
//! Run on a TDX-enabled machine:
//!   cargo run --example tdx --features "tdx,attest"

#[cfg(not(target_os = "linux"))]
fn main() {
    eprintln!("This example requires Linux.");
}

#[cfg(target_os = "linux")]
#[tokio::main]
async fn main() {
    use attestation::{Context, Platform, PlatformType, Tdx, TdxParams};

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
    let envelope: attestation::AttestationEvidence =
        serde_json::from_slice(&evidence_json).expect("envelope");
    let evidence = serde_json::from_value(envelope.evidence).expect("TDX evidence");
    let params = TdxParams {
        report_data: Some(nonce.to_vec()),
        ..Default::default()
    };
    let result = Tdx::verify(&evidence, &params, &Context::new())
        .await
        .expect("verification failed");

    eprintln!("Passed: {}", result.passed());
    eprintln!("Launch digest: {}", result.claims.launch_digest);

    if let Some(tcb_status) = &result.tcb_status {
        eprintln!("TCB status: {:?}", tcb_status.tcb_status);
        eprintln!("FMSPC: {}", tcb_status.fmspc);
    }

    println!("{}", String::from_utf8_lossy(&evidence_json));
}
