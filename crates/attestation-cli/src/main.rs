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
use serde::Serialize;

/// Flat CLI output shape. The library's `VerifyResult` is intentionally not
/// `Serialize`; the CLI projects the canonical anchors here for stdout.
#[derive(Serialize)]
struct CliVerifyOutput<'a> {
    signature_valid: bool,
    collateral_verified: bool,
    vendor: &'a str,
    /// Hex-encoded canonical launch measurement.
    launch_measurement: String,
    /// Hex-encoded observed nonce (vendor-specific source).
    nonce: Option<String>,
    /// Hex-encoded observed report_data.
    report_data: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    nonce_match: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    report_data_match: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    launch_measurement_match: Option<bool>,
    vendor_policy_failed: bool,
    policy_failed: bool,
}

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

/// `attestation-cli verify` exposes only the canonical anchors. Vendor-specific
/// pin policy (MRTD, individual RTMRs, min_tcb, etc.) is library-only — callers
/// who need that finer control write Rust. The CLI is intentionally narrow so
/// CI gates can express "this evidence matches what I deployed" without
/// branching on which TEE produced it.
#[derive(clap::Args)]
struct VerifyArgs {
    /// Path to evidence JSON file. Reads from stdin if not specified.
    #[arg(short, long)]
    evidence: Option<PathBuf>,

    /// Expected nonce (hex-encoded). Compared against the appropriate
    /// freshness anchor for the vendor (report_data for bare-metal, TPM
    /// extraData for Azure overlays).
    #[arg(long)]
    nonce: Option<String>,

    /// Expected report_data (hex-encoded). Compared against the inner TEE
    /// quote's report_data field.
    #[arg(long)]
    report_data: Option<String>,

    /// Expected canonical launch measurement (hex-encoded, 48 bytes).
    ///
    /// For TDX-family vendors this is SHA-384(mrtd || rtmr1 || rtmr2 || rtmr3);
    /// for SNP-family vendors this is the SNP report's measurement field.
    #[arg(long)]
    launch_measurement: Option<String>,

    /// Allow guests launched with debug policy enabled. Default: false.
    #[arg(long, default_value_t = false)]
    allow_debug: bool,
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

    let mut params = VerifyParams {
        allow_debug: args.allow_debug,
        ..Default::default()
    };

    let decode_hex = |hex_str: &str, name: &str| -> Vec<u8> {
        match hex::decode(hex_str) {
            Ok(data) => data,
            Err(e) => {
                eprintln!("Error: invalid hex for --{name}: {e}");
                process::exit(1);
            }
        }
    };

    if let Some(ref hex_str) = args.nonce {
        params.nonce = Some(decode_hex(hex_str, "nonce"));
    }
    if let Some(ref hex_str) = args.report_data {
        params.report_data = Some(decode_hex(hex_str, "report-data"));
    }
    if let Some(ref hex_str) = args.launch_measurement {
        let bytes = decode_hex(hex_str, "launch-measurement");
        if bytes.len() != 48 {
            eprintln!(
                "Error: --launch-measurement must be 48 bytes (96 hex chars), got {} bytes",
                bytes.len()
            );
            process::exit(1);
        }
        params.launch_measurement = Some(bytes);
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
    eprintln!("  Vendor: {}", result.vendor.platform());
    eprintln!(
        "  Launch measurement: {}",
        hex::encode(&result.launch_measurement)
    );
    if let Some(m) = result.nonce_match {
        eprintln!("  Nonce match: {m}");
    }
    if let Some(m) = result.report_data_match {
        eprintln!("  Report data match: {m}");
    }
    if let Some(m) = result.launch_measurement_match {
        eprintln!("  Launch measurement match: {m}");
    }
    if result.vendor_policy_failed {
        eprintln!("  Vendor policy: FAILED");
    }

    // Structured JSON to stdout. Build a flat DTO from the (non-Serialize)
    // VerifyResult — vendor-specific parsed bodies are intentionally not
    // surfaced here; CI gates pin canonical anchors and read the booleans.
    let vendor_tag = format!("{}", result.vendor.platform());
    let nonce_hex = (!result.nonce.is_empty()).then(|| hex::encode(&result.nonce));
    let report_data_hex =
        (!result.report_data.is_empty()).then(|| hex::encode(&result.report_data));
    let cli_output = CliVerifyOutput {
        signature_valid: result.signature_valid,
        collateral_verified: result.collateral_verified,
        vendor: &vendor_tag,
        launch_measurement: hex::encode(&result.launch_measurement),
        nonce: nonce_hex,
        report_data: report_data_hex,
        nonce_match: result.nonce_match,
        report_data_match: result.report_data_match,
        launch_measurement_match: result.launch_measurement_match,
        vendor_policy_failed: result.vendor_policy_failed,
        policy_failed: result.policy_failed(),
    };
    let json = serde_json::to_string_pretty(&cli_output).expect("failed to serialize result");
    println!("{json}");

    // Exit code: non-zero on signature failure OR any policy mismatch (canonical
    // or vendor). This is the entire point of the canonical anchors — CI gates
    // can pin a launch_measurement and have the CLI exit non-zero if the
    // measurement drifts.
    if !result.signature_valid || result.policy_failed() {
        process::exit(1);
    }
}
