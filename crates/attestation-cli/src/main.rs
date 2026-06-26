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
    if let Some(ref s) = group.report_data {
        Ok(s.as_bytes().to_vec())
    } else if let Some(ref h) = group.report_data_hex {
        hex::decode(h).map_err(|e| format!("invalid hex for --report-data-hex: {e}"))
    } else if let Some(ref path) = group.report_data_file {
        std::fs::read(path).map_err(|e| format!("failed to read {}: {e}", path.display()))
    } else {
        Ok(Vec::new())
    }
}

fn read_evidence(args: &VerifyArgs) -> Result<Vec<u8>, String> {
    let max_size = attestation::MAX_EVIDENCE_SIZE;

    if let Some(ref path) = args.evidence {
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

    let platform = if let Some(ref p) = args.platform {
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
    let evidence_json = match attestation::attest(
        platform,
        &report_data,
        &attestation::AttestOptions::default(),
    )
    .await
    {
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

    if let Some(ref path) = args.output {
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

    if let Some(ref hex_str) = args.expected_report_data {
        match hex::decode(hex_str) {
            Ok(data) => params.expected_report_data = Some(data),
            Err(e) => {
                eprintln!("Error: invalid hex for --expected-report-data: {e}");
                process::exit(1);
            }
        }
    }

    if let Some(ref hex_str) = args.expected_init_data {
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

    if let Some(ref hex_str) = args.expected_mrtd {
        params.expected_mrtd = Some(parse_digest(hex_str, "expected-mrtd"));
    }
    if let Some(ref hex_str) = args.expected_launch_digest {
        params.expected_launch_digest = Some(parse_digest(hex_str, "expected-launch-digest"));
    }
    let any_rtmr = args.expected_rtmr0.is_some()
        || args.expected_rtmr1.is_some()
        || args.expected_rtmr2.is_some()
        || args.expected_rtmr3.is_some();
    if any_rtmr {
        let mut rtmrs: [Option<[u8; 48]>; 4] = [None, None, None, None];
        if let Some(ref h) = args.expected_rtmr0 {
            rtmrs[0] = Some(parse_digest(h, "expected-rtmr0"));
        }
        if let Some(ref h) = args.expected_rtmr1 {
            rtmrs[1] = Some(parse_digest(h, "expected-rtmr1"));
        }
        if let Some(ref h) = args.expected_rtmr2 {
            rtmrs[2] = Some(parse_digest(h, "expected-rtmr2"));
        }
        if let Some(ref h) = args.expected_rtmr3 {
            rtmrs[3] = Some(parse_digest(h, "expected-rtmr3"));
        }
        params.expected_rtmrs = Some(rtmrs);
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
    if let Some(matches) = result.rtmr_matches {
        for (i, m) in matches.iter().enumerate() {
            if let Some(b) = m {
                eprintln!("  RTMR[{i}] match: {b}");
            }
        }
    }

    // Structured JSON to stdout
    let json = serde_json::to_string_pretty(&result).expect("failed to serialize result");
    println!("{json}");

    // Exit non-zero on signature failure or any explicit policy mismatch
    // so CI/deploy gates fail closed when a pinned reference drifts.
    let policy_failed = matches!(result.report_data_match, Some(false))
        || matches!(result.init_data_match, Some(false))
        || matches!(result.mrtd_match, Some(false))
        || matches!(result.launch_digest_match, Some(false))
        || result
            .rtmr_matches
            .as_ref()
            .is_some_and(|m| m.iter().any(|x| matches!(x, Some(false))));
    if !result.signature_valid || policy_failed {
        process::exit(1);
    }
}
