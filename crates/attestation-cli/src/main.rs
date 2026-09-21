#[cfg(all(feature = "attest", target_os = "linux"))]
use std::io::Write;
use std::io::{self, Read};
use std::path::PathBuf;
use std::process;
use std::time::Instant;

#[cfg(all(feature = "attest", target_os = "linux"))]
use clap::ValueEnum;
use clap::{Parser, Subcommand};

use attestation::types::VerifyParams;

#[derive(Parser)]
#[command(
    name = "attestation-cli",
    about = "TEE attestation evidence generation and verification",
    version
)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Generate attestation evidence from TEE hardware (Linux only).
    #[cfg(all(feature = "attest", target_os = "linux"))]
    Attest(AttestArgs),
    /// Verify attestation evidence.
    Verify(VerifyArgs),
    /// Detect the current TEE platform (Linux only).
    #[cfg(all(feature = "attest", target_os = "linux"))]
    Detect,
}

#[cfg(all(feature = "attest", target_os = "linux"))]
#[derive(clap::Args)]
#[group(multiple = false)]
struct ReportDataGroup {
    /// Custom report data as a UTF-8 string.
    #[arg(long)]
    report_data: Option<String>,

    /// Custom report data as hex-encoded bytes.
    #[arg(long)]
    report_data_hex: Option<String>,

    /// Read custom report data from a file.
    #[arg(long)]
    report_data_file: Option<PathBuf>,
}

#[cfg(all(feature = "attest", target_os = "linux"))]
#[derive(clap::Args)]
struct AttestArgs {
    /// Platform to attest with. Auto-detects if not specified.
    #[arg(short, long)]
    platform: Option<PlatformArg>,

    #[command(flatten)]
    data: ReportDataGroup,

    /// Also collect NVIDIA GPU attestation evidence (CC-mode Hopper/Blackwell).
    /// The report data is used as the GPU user nonce, so it must be non-empty.
    #[cfg(feature = "nvidia-gpu-attest")]
    #[arg(long)]
    nvidia_gpu: bool,

    /// Write evidence JSON to a file instead of stdout.
    #[arg(short, long)]
    output: Option<PathBuf>,
}

#[derive(clap::Args)]
struct VerifyArgs {
    /// Path to evidence JSON file. Reads from stdin if not specified.
    #[arg(short, long)]
    evidence: Option<PathBuf>,

    /// Expected report data (hex-encoded) for nonce binding verification.
    #[arg(long)]
    expected_report_data: Option<String>,

    /// Expected init data hash (hex-encoded) for init data binding verification.
    #[arg(long)]
    expected_init_data: Option<String>,

    /// Expected MRTD (hex-encoded, 48 bytes). TDX-only.
    #[arg(long)]
    expected_mrtd: Option<String>,

    /// Expected RTMR[0] (hex-encoded, 48 bytes). TDX-only.
    #[arg(long)]
    expected_rtmr0: Option<String>,

    /// Expected RTMR[1] (hex-encoded, 48 bytes). TDX-only.
    #[arg(long)]
    expected_rtmr1: Option<String>,

    /// Expected RTMR[2] (hex-encoded, 48 bytes). TDX-only.
    #[arg(long)]
    expected_rtmr2: Option<String>,

    /// Expected RTMR[3] (hex-encoded, 48 bytes). TDX-only.
    #[arg(long)]
    expected_rtmr3: Option<String>,

    /// Expected SNP launch digest (hex-encoded, 48 bytes). SNP-only.
    #[arg(long)]
    expected_launch_digest: Option<String>,

    /// NVIDIA GPU user nonce (hex) that seeded the GPU SPDM nonce. Enables GPU
    /// bundle verification via NRAS. If --expected-report-data is not given, it
    /// is set to this value (the GPU binding requires them to be equal).
    #[cfg(feature = "nvidia-gpu")]
    #[arg(long)]
    nvidia_gpu_user_nonce: Option<String>,

    /// Fail verification if the evidence carries no NVIDIA GPU bundle.
    #[cfg(feature = "nvidia-gpu")]
    #[arg(long)]
    nvidia_gpu_required: bool,

    /// Comma-separated whitelist of acceptable GPU/switch archs
    /// (HOPPER,BLACKWELL,LS10). If omitted, all known archs are accepted.
    #[cfg(feature = "nvidia-gpu")]
    #[arg(long, value_delimiter = ',')]
    nvidia_gpu_expected_archs: Option<Vec<String>>,
}

#[cfg(all(feature = "attest", target_os = "linux"))]
#[derive(Clone, ValueEnum)]
enum PlatformArg {
    Snp,
    Tdx,
    AzSnp,
    AzTdx,
    GcpSnp,
    GcpTdx,
}

#[cfg(all(feature = "attest", target_os = "linux"))]
impl PlatformArg {
    fn to_platform_type(&self) -> attestation::PlatformType {
        match self {
            PlatformArg::Snp => attestation::PlatformType::Snp,
            PlatformArg::Tdx => attestation::PlatformType::Tdx,
            PlatformArg::AzSnp => attestation::PlatformType::AzSnp,
            PlatformArg::AzTdx => attestation::PlatformType::AzTdx,
            PlatformArg::GcpSnp => attestation::PlatformType::GcpSnp,
            PlatformArg::GcpTdx => attestation::PlatformType::GcpTdx,
        }
    }
}

#[cfg(all(feature = "attest", target_os = "linux"))]
fn resolve_report_data(group: &ReportDataGroup) -> Result<Vec<u8>, String> {
    if let Some(s) = &group.report_data {
        Ok(s.as_bytes().to_vec())
    } else if let Some(h) = &group.report_data_hex {
        hex::decode(h).map_err(|e| format!("invalid hex for --report-data-hex: {e}"))
    } else if let Some(path) = &group.report_data_file {
        std::fs::read(path).map_err(|e| format!("failed to read {}: {e}", path.display()))
    } else {
        Ok(Vec::new())
    }
}

fn read_evidence(args: &VerifyArgs) -> Result<Vec<u8>, String> {
    let max_size = attestation::MAX_EVIDENCE_SIZE;

    if let Some(path) = &args.evidence {
        let meta = std::fs::metadata(path)
            .map_err(|e| format!("failed to stat {}: {e}", path.display()))?;
        if meta.len() > max_size as u64 {
            return Err(format!(
                "evidence file too large: {} bytes (max {} bytes)",
                meta.len(),
                max_size
            ));
        }
        std::fs::read(path).map_err(|e| format!("failed to read {}: {e}", path.display()))
    } else {
        let mut buf = Vec::new();
        io::stdin()
            .take(max_size as u64 + 1)
            .read_to_end(&mut buf)
            .map_err(|e| format!("failed to read stdin: {e}"))?;
        if buf.len() > max_size {
            return Err(format!(
                "evidence from stdin too large: {} bytes (max {} bytes)",
                buf.len(),
                max_size
            ));
        }
        Ok(buf)
    }
}

#[tokio::main(flavor = "current_thread")]
async fn main() {
    let cli = Cli::parse();

    match cli.command {
        #[cfg(all(feature = "attest", target_os = "linux"))]
        Commands::Detect => cmd_detect(),
        #[cfg(all(feature = "attest", target_os = "linux"))]
        Commands::Attest(args) => cmd_attest(args).await,
        Commands::Verify(args) => cmd_verify(args).await,
    }
}

#[cfg(all(feature = "attest", target_os = "linux"))]
fn cmd_detect() {
    match attestation::detect() {
        Ok(platform) => {
            println!("{}", platform);
        }
        Err(_) => {
            eprintln!("No TEE platform detected.");
            process::exit(1);
        }
    }
}

#[cfg(all(feature = "attest", target_os = "linux"))]
async fn cmd_attest(args: AttestArgs) {
    let report_data = match resolve_report_data(&args.data) {
        Ok(d) => d,
        Err(e) => {
            eprintln!("Error: {e}");
            process::exit(1);
        }
    };

    let platform = if let Some(p) = &args.platform {
        p.to_platform_type()
    } else {
        match attestation::detect() {
            Ok(p) => p,
            Err(e) => {
                eprintln!("Error: {e}");
                process::exit(1);
            }
        }
    };

    eprintln!("Platform: {}", platform);
    if report_data.is_empty() {
        eprintln!("Report data: (empty)");
    } else {
        eprintln!("Report data: {} bytes", report_data.len());
    }

    let t0 = Instant::now();
    let opts = attestation::AttestOptions::default();

    #[cfg(feature = "nvidia-gpu-attest")]
    let evidence_result = if args.nvidia_gpu {
        eprintln!("Collecting NVIDIA GPU evidence...");
        attestation::attest_with_nvidia_gpu(platform, &report_data, &opts).await
    } else {
        attestation::attest(platform, &report_data, &opts).await
    };
    #[cfg(not(feature = "nvidia-gpu-attest"))]
    let evidence_result = attestation::attest(platform, &report_data, &opts).await;

    let evidence_json = match evidence_result {
        Ok(json) => json,
        Err(e) => {
            eprintln!("Attestation failed: {e}");
            process::exit(1);
        }
    };
    let elapsed = t0.elapsed();

    eprintln!(
        "Evidence generated in {:?} ({} bytes)",
        elapsed,
        evidence_json.len()
    );

    if let Some(path) = &args.output {
        if let Err(e) = std::fs::write(path, &evidence_json) {
            eprintln!("Failed to write {}: {e}", path.display());
            process::exit(1);
        }
        eprintln!("Written to {}", path.display());
    } else {
        if let Err(e) = io::stdout().write_all(&evidence_json) {
            eprintln!("Failed to write to stdout: {e}");
            process::exit(1);
        }
        // Ensure trailing newline for terminal readability
        if !evidence_json.ends_with(b"\n") {
            if let Err(e) = writeln!(io::stdout()) {
                eprintln!("Failed to write to stdout: {e}");
                process::exit(1);
            }
        }
    }
}

async fn cmd_verify(args: VerifyArgs) {
    let evidence_json = match read_evidence(&args) {
        Ok(e) => e,
        Err(e) => {
            eprintln!("Error: {e}");
            process::exit(1);
        }
    };

    let mut params = VerifyParams::default();

    if let Some(hex_str) = &args.expected_report_data {
        match hex::decode(hex_str) {
            Ok(data) => params.expected_report_data = Some(data),
            Err(e) => {
                eprintln!("Error: invalid hex for --expected-report-data: {e}");
                process::exit(1);
            }
        }
    }

    if let Some(hex_str) = &args.expected_init_data {
        match hex::decode(hex_str) {
            Ok(data) => params.expected_init_data_hash = Some(data),
            Err(e) => {
                eprintln!("Error: invalid hex for --expected-init-data: {e}");
                process::exit(1);
            }
        }
    }

    let parse_digest = |hex_str: &str, name: &str| -> [u8; 48] {
        let bytes = match hex::decode(hex_str) {
            Ok(b) => b,
            Err(e) => {
                eprintln!("Error: invalid hex for --{name}: {e}");
                process::exit(1);
            }
        };
        match <[u8; 48]>::try_from(bytes.as_slice()) {
            Ok(d) => d,
            Err(_) => {
                eprintln!(
                    "Error: --{name} must be 48 bytes (96 hex chars), got {} bytes",
                    bytes.len()
                );
                process::exit(1);
            }
        }
    };

    if let Some(hex_str) = &args.expected_mrtd {
        params.expected_mrtd = Some(parse_digest(hex_str, "expected-mrtd"));
    }
    if let Some(hex_str) = &args.expected_launch_digest {
        params.expected_launch_digest = Some(parse_digest(hex_str, "expected-launch-digest"));
    }
    if let Some(h) = &args.expected_rtmr0 {
        params.expected_rtmr0 = Some(parse_digest(h, "expected-rtmr0"));
    }
    if let Some(h) = &args.expected_rtmr1 {
        params.expected_rtmr1 = Some(parse_digest(h, "expected-rtmr1"));
    }
    if let Some(h) = &args.expected_rtmr2 {
        params.expected_rtmr2 = Some(parse_digest(h, "expected-rtmr2"));
    }
    if let Some(h) = &args.expected_rtmr3 {
        params.expected_rtmr3 = Some(parse_digest(h, "expected-rtmr3"));
    }

    #[cfg(feature = "nvidia-gpu")]
    {
        if let Some(hex_str) = &args.nvidia_gpu_user_nonce {
            let nonce = match hex::decode(hex_str) {
                Ok(n) => n,
                Err(e) => {
                    eprintln!("Error: invalid hex for --nvidia-gpu-user-nonce: {e}");
                    process::exit(1);
                }
            };
            // The GPU nonce binding requires expected_report_data == user_nonce;
            // default the former to the nonce when the caller did not pin it.
            if params.expected_report_data.is_none() {
                params.expected_report_data = Some(nonce.clone());
            }
            params.nvidia_gpu.user_nonce = Some(nonce);
        }
        params.nvidia_gpu.required = args.nvidia_gpu_required;
        if let Some(archs) = &args.nvidia_gpu_expected_archs {
            let mut parsed = Vec::with_capacity(archs.len());
            for a in archs {
                let arch = match a.to_ascii_uppercase().as_str() {
                    "HOPPER" => attestation::NvidiaGpuArch::Hopper,
                    "BLACKWELL" => attestation::NvidiaGpuArch::Blackwell,
                    "LS10" => attestation::NvidiaGpuArch::Ls10,
                    other => {
                        eprintln!(
                            "Error: unknown arch for --nvidia-gpu-expected-archs: {other} \
                             (want HOPPER, BLACKWELL, or LS10)"
                        );
                        process::exit(1);
                    }
                };
                parsed.push(arch);
            }
            params.nvidia_gpu.expected_archs = Some(parsed);
        }
    }

    eprintln!("Verifying evidence...");

    let t0 = Instant::now();
    let result = match attestation::verify(&evidence_json, &params).await {
        Ok(r) => r,
        Err(e) => {
            eprintln!("Verification failed: {e}");
            process::exit(1);
        }
    };
    let elapsed = t0.elapsed();

    // Human-readable summary to stderr
    eprintln!("Verified in {elapsed:?}");
    eprintln!("  Signature valid: {}", result.signature_valid);
    eprintln!("  Platform: {}", result.platform);
    eprintln!("  Launch digest: {}", result.claims.launch_digest);
    if let Some(m) = result.report_data_match {
        eprintln!("  Report data match: {m}");
    }
    if let Some(m) = result.init_data_match {
        eprintln!("  Init data match: {m}");
    }
    if let Some(m) = result.mrtd_match {
        eprintln!("  MRTD match: {m}");
    }
    if let Some(m) = result.launch_digest_match {
        eprintln!("  Launch digest match: {m}");
    }
    for (i, m) in [
        result.rtmr0_match,
        result.rtmr1_match,
        result.rtmr2_match,
        result.rtmr3_match,
    ]
    .iter()
    .enumerate()
    {
        if let Some(b) = m {
            eprintln!("  RTMR[{i}] match: {b}");
        }
    }
    #[cfg(feature = "nvidia-gpu")]
    if let Some(gpu) = &result.claims.nvidia_gpu {
        eprintln!(
            "  NVIDIA GPU: overall_ok={} nonce_binding_ok={} devices={}",
            gpu.overall_ok,
            gpu.nonce_binding_ok,
            gpu.devices.len()
        );
    }

    // Structured JSON to stdout
    let json = serde_json::to_string_pretty(&result).expect("failed to serialize result");
    println!("{json}");

    // A supplied expected_* reference that mismatches fails verify() itself,
    // so reaching this point means every pinned reference matched.
    if !result.signature_valid {
        process::exit(1);
    }
}
