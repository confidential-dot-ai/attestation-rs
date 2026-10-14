//! End-to-end CPU TEE + NVIDIA GPU attestation against NRAS.
//!
//! Run on a CC-mode host (SNP or TDX) with at least one CC-mode NVIDIA GPU:
//!
//!   # TDX host:
//!   cargo run --example gpu_nras --features "attest tdx nvidia-gpu-attest"
//!
//!   # SNP host:
//!   cargo run --example gpu_nras --features "attest snp nvidia-gpu-attest"

#[cfg(not(target_os = "linux"))]
fn main() {
    eprintln!("This example requires Linux.");
}

#[cfg(target_os = "linux")]
#[tokio::main]
async fn main() {
    use attestation::{AttestOptions, NvidiaGpuParams, Policies, SnpParams, TdxParams};

    let user_nonce: Vec<u8> = (0..32).map(|i| i as u8).collect();

    let platform = attestation::detect().expect("no TEE platform detected");
    eprintln!("Detected platform: {platform}");

    eprintln!("Generating {platform} quote + NVIDIA GPU bundle…");
    let envelope =
        attestation::attest_with_nvidia_gpu(platform, &user_nonce, &AttestOptions::default())
            .await
            .expect("attest_with_nvidia_gpu failed");

    eprintln!("Envelope: {} bytes", envelope.len());

    eprintln!("Verifying via NRAS…");
    let policies = Policies {
        tdx: Some(TdxParams {
            report_data: Some(user_nonce.clone()),
            ..Default::default()
        }),
        snp: Some(SnpParams {
            report_data: Some(user_nonce.clone()),
            ..Default::default()
        }),
        gpu: Some(NvidiaGpuParams {
            user_nonce: Some(user_nonce.clone()),
            required: true,
            ..Default::default()
        }),
        ..Default::default()
    };
    let verified = attestation::verify(&envelope, &policies)
        .await
        .expect("verify failed");

    eprintln!("Passed: {}", verified.passed());
    let gpu = verified.gpu.as_ref().expect("GPU result missing");
    eprintln!("GPU overall_ok: {}", gpu.claims.overall_ok);
    for (i, dev) in gpu.claims.devices.iter().enumerate() {
        eprintln!(
            "  device[{i}] arch={:?} measres={:?} driver={:?} vbios={:?}",
            dev.arch, dev.measres, dev.driver_version, dev.vbios_version
        );
    }
    println!("{}", String::from_utf8_lossy(&envelope));
}
