#[cfg(all(feature = "attest", target_os = "linux"))]
use std::io::Write;
use std::io::{self, Read};
use std::path::PathBuf;
use std::process;
use std::time::Instant;

use clap::{Parser, Subcommand, ValueEnum};

use attestation::{PlatformType, Policies, SnpParams, TdxParams};

#[cfg(all(feature = "test-vendor", not(debug_assertions)))]
compile_error!("the test-vendor feature is for debug builds only");

const EXIT_CODES: &str = "\
Exit codes:
  0  passed: genuine, and every rule in the flags held
  1  did not pass, or the evidence is not genuine
  2  usage error or invalid params
  3  collateral unavailable (AMD KDS, Intel PCS, NRAS); retrying may help";

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

// Parsed once at startup; boxing the larger variant would buy nothing.
#[allow(clippy::large_enum_variant)]
#[derive(Subcommand)]
enum Commands {
    /// Generate attestation evidence from TEE hardware (Linux only).
    #[cfg(all(feature = "attest", target_os = "linux"))]
    Attest(AttestArgs),
    /// Verify attestation evidence.
    #[command(after_help = EXIT_CODES)]
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

    /// Platform to accept; repeat to accept several. Without it, the
    /// platform-specific flags decide (--expected-mrtd/--expected-rtmrN: the
    /// TDX platforms, --expected-launch-digest: the SNP platforms). Evidence
    /// for any other platform is refused.
    #[arg(short, long)]
    platform: Vec<PlatformArg>,

    /// Verify without network access, with the collateral saved by earlier
    /// runs. Collateral not saved yet exits 3.
    #[arg(long)]
    offline: bool,

    /// Evaluate at this time (Unix seconds) instead of now. For tests; not
    /// in release builds.
    #[cfg(debug_assertions)]
    #[arg(long, hide = true)]
    at: Option<i64>,

    /// Expected report data (hex-encoded) for nonce binding verification.
    #[arg(long)]
    expected_report_data: Option<String>,

    /// Expected init data hash (hex-encoded): TDX MRCONFIGID, SNP HOST_DATA,
    /// or the vTPM PCR[8] init-data hash on Azure.
    #[arg(long)]
    expected_init_data: Option<String>,

    /// Allowed MRTD (hex-encoded, 48 bytes). TDX-only. Repeatable: the MRTD
    /// must equal one of the given values.
    #[arg(long)]
    expected_mrtd: Vec<String>,

    /// Allowed RTMR[0] (hex-encoded, 48 bytes). TDX-only. Repeatable, as for
    /// --expected-mrtd.
    #[arg(long)]
    expected_rtmr0: Vec<String>,

    /// Allowed RTMR[1], as for --expected-rtmr0.
    #[arg(long)]
    expected_rtmr1: Vec<String>,

    /// Allowed RTMR[2], as for --expected-rtmr0.
    #[arg(long)]
    expected_rtmr2: Vec<String>,

    /// Allowed RTMR[3], as for --expected-rtmr0.
    #[arg(long)]
    expected_rtmr3: Vec<String>,

    /// Allowed SNP launch digest (hex-encoded, 48 bytes). SNP-only.
    /// Repeatable, as for --expected-mrtd.
    #[arg(long)]
    expected_launch_digest: Vec<String>,

    /// Expected vTPM PCR as INDEX=HEX (SHA-256 bank, 32 bytes). Repeatable.
    /// Azure vTPM only (az-snp, az-tdx).
    #[arg(long, value_name = "INDEX=HEX")]
    expected_pcr: Vec<String>,

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

#[derive(Clone, Copy, ValueEnum)]
enum PlatformArg {
    Snp,
    Tdx,
    AzSnp,
    AzTdx,
    GcpSnp,
    GcpTdx,
}

impl PlatformArg {
    fn to_platform_type(self) -> attestation::PlatformType {
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
    // The verifier then needs nothing but its roots. Without collateral the
    // evidence still verifies where the verifier may fetch.
    let verifier = attestation::Verifier::new(context(attestation::Context::new()));
    let evidence_json = match verifier
        .attach_collateral(&evidence_json, &report_data)
        .await
    {
        Ok(json) => json,
        Err(e) => {
            eprintln!("Collateral not attached: {e}");
            evidence_json
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

/// Print `msg` and exit 2, the exit code clap uses for usage errors.
fn usage_error(msg: &str) -> ! {
    eprintln!("Error: {msg}");
    process::exit(2);
}

fn parse_hex(hex_str: &str, flag: &str) -> Vec<u8> {
    hex::decode(hex_str).unwrap_or_else(|e| usage_error(&format!("invalid hex for --{flag}: {e}")))
}

fn parse_digest(hex_str: &str, flag: &str) -> [u8; 48] {
    let bytes = parse_hex(hex_str, flag);
    <[u8; 48]>::try_from(bytes.as_slice()).unwrap_or_else(|_| {
        usage_error(&format!(
            "--{flag} must be 48 bytes (96 hex chars), got {} bytes",
            bytes.len()
        ))
    })
}

const ALL_PLATFORMS: [PlatformType; 6] = [
    PlatformType::Tdx,
    PlatformType::AzTdx,
    PlatformType::GcpTdx,
    PlatformType::Snp,
    PlatformType::AzSnp,
    PlatformType::GcpSnp,
];
const TDX_PLATFORMS: [PlatformType; 3] =
    [PlatformType::Tdx, PlatformType::AzTdx, PlatformType::GcpTdx];
const SNP_PLATFORMS: [PlatformType; 3] =
    [PlatformType::Snp, PlatformType::AzSnp, PlatformType::GcpSnp];
const AZURE_PLATFORMS: [PlatformType; 2] = [PlatformType::AzTdx, PlatformType::AzSnp];

/// The platforms to accept: `--platform`, or else the platforms every
/// platform-specific pin applies to. Never the evidence's own tag, which is
/// an attester claim. A pin that does not apply to an accepted platform is a
/// usage error.
fn accepted_platforms(args: &VerifyArgs) -> Vec<PlatformType> {
    let mut pins: Vec<(&str, &[PlatformType])> = Vec::new();
    let rtmr_pinned = [
        &args.expected_rtmr0,
        &args.expected_rtmr1,
        &args.expected_rtmr2,
        &args.expected_rtmr3,
    ]
    .iter()
    .any(|r| !r.is_empty());
    if !args.expected_mrtd.is_empty() || rtmr_pinned {
        pins.push(("--expected-mrtd/--expected-rtmrN", &TDX_PLATFORMS));
    }
    if !args.expected_launch_digest.is_empty() {
        pins.push(("--expected-launch-digest", &SNP_PLATFORMS));
    }
    if !args.expected_pcr.is_empty() {
        pins.push(("--expected-pcr", &AZURE_PLATFORMS));
    }

    let platforms: Vec<PlatformType> = if args.platform.is_empty() {
        if pins.is_empty() {
            usage_error(
                "say which platform the evidence must come from with --platform \
                 (or pin a platform-specific value such as --expected-mrtd)",
            );
        }
        ALL_PLATFORMS
            .into_iter()
            .filter(|p| pins.iter().all(|(_, applies)| applies.contains(p)))
            .collect()
    } else {
        args.platform.iter().map(|p| p.to_platform_type()).collect()
    };
    if platforms.is_empty() {
        usage_error("the pins given do not all apply to any one platform");
    }
    for platform in &platforms {
        for (flag, applies) in &pins {
            if !applies.contains(platform) {
                usage_error(&format!("{flag} does not apply to {platform} evidence"));
            }
        }
    }
    platforms
}

/// Build one policy per accepted platform from the flags. A pin an accepted
/// platform cannot answer (`--expected-mrtd` with `--platform snp`) is a usage
/// error.
fn build_policies(args: &VerifyArgs) -> Policies {
    let platforms = accepted_platforms(args);
    let report_data = args
        .expected_report_data
        .as_deref()
        .map(|h| parse_hex(h, "expected-report-data"));
    let init_data = args
        .expected_init_data
        .as_deref()
        .map(|h| parse_hex(h, "expected-init-data"));
    let digests = |values: &[String], flag: &str| -> Option<Vec<[u8; 48]>> {
        (!values.is_empty()).then(|| values.iter().map(|h| parse_digest(h, flag)).collect())
    };
    let mrtd = digests(&args.expected_mrtd, "expected-mrtd");
    let rtmr = [
        digests(&args.expected_rtmr0, "expected-rtmr0"),
        digests(&args.expected_rtmr1, "expected-rtmr1"),
        digests(&args.expected_rtmr2, "expected-rtmr2"),
        digests(&args.expected_rtmr3, "expected-rtmr3"),
    ];
    let launch_digest = digests(&args.expected_launch_digest, "expected-launch-digest");
    let mut pcrs = std::collections::BTreeMap::<u8, [u8; 32]>::new();
    for pin in &args.expected_pcr {
        let (index, value) = parse_pcr_pin(pin)
            .unwrap_or_else(|e| usage_error(&format!("invalid --expected-pcr {pin:?}: {e}")));
        if pcrs.insert(index, value).is_some() {
            usage_error(&format!("--expected-pcr pins PCR[{index}] more than once"));
        }
    }

    #[allow(unused_mut)]
    let mut policies = Policies::default();

    #[cfg(feature = "nvidia-gpu")]
    let report_data = {
        let mut report_data = report_data;
        let gpu_flags_given = args.nvidia_gpu_user_nonce.is_some()
            || args.nvidia_gpu_required
            || args.nvidia_gpu_expected_archs.is_some();
        if gpu_flags_given {
            let user_nonce = args
                .nvidia_gpu_user_nonce
                .as_deref()
                .map(|h| parse_hex(h, "nvidia-gpu-user-nonce"));
            // The GPU nonce binding requires report_data == user_nonce;
            // default the former to the nonce when the caller did not pin it.
            if report_data.is_none() {
                report_data.clone_from(&user_nonce);
            }
            let expected_archs = args.nvidia_gpu_expected_archs.as_ref().map(|archs| {
                archs
                    .iter()
                    .map(|a| match a.to_ascii_uppercase().as_str() {
                        "HOPPER" => attestation::NvidiaGpuArch::Hopper,
                        "BLACKWELL" => attestation::NvidiaGpuArch::Blackwell,
                        "LS10" => attestation::NvidiaGpuArch::Ls10,
                        other => usage_error(&format!(
                            "unknown arch for --nvidia-gpu-expected-archs: {other} \
                             (want HOPPER, BLACKWELL, or LS10)"
                        )),
                    })
                    .collect()
            });
            policies.gpu = Some(attestation::NvidiaGpuParams {
                user_nonce,
                required: args.nvidia_gpu_required,
                expected_archs,
                ..Default::default()
            });
        }
        report_data
    };

    let tdx = || TdxParams {
        report_data: report_data.clone(),
        init_data: init_data.clone(),
        mrtd: mrtd.clone(),
        rtmr: rtmr.clone(),
        ..Default::default()
    };
    let snp = || SnpParams {
        report_data: report_data.clone(),
        host_data: init_data.clone(),
        launch_digest: launch_digest.clone(),
        ..Default::default()
    };
    for platform in platforms {
        match platform {
            PlatformType::Tdx => policies.tdx = Some(tdx()),
            PlatformType::AzTdx => {
                policies.az_tdx = Some(attestation::AzTdxParams {
                    tdx: tdx(),
                    pcrs: pcrs.clone(),
                })
            }
            PlatformType::GcpTdx => {
                policies.gcp_tdx = Some(attestation::GcpTdxParams { tdx: tdx() })
            }
            PlatformType::Snp => policies.snp = Some(snp()),
            PlatformType::AzSnp => {
                policies.az_snp = Some(attestation::AzSnpParams {
                    snp: snp(),
                    pcrs: pcrs.clone(),
                })
            }
            PlatformType::GcpSnp => {
                policies.gcp_snp = Some(attestation::GcpSnpParams { snp: snp() })
            }
            // Not a --platform value.
            PlatformType::Dstack => {}
        }
    }
    policies
}

/// Exit for a verification error: 2 for invalid params, 3 when retrying may
/// help, 1 otherwise.
fn exit_for_error(e: &attestation::AttestationError) -> ! {
    if e.is_invalid_params() {
        usage_error(&e.to_string());
    }
    if e.is_retryable() {
        eprintln!("Verification could not complete: {e}");
        process::exit(3);
    }
    eprintln!("Verification failed: {e}");
    process::exit(1);
}

async fn cmd_verify(args: VerifyArgs) {
    let evidence_json = read_evidence(&args).unwrap_or_else(|e| usage_error(&e));
    let policies = build_policies(&args);
    let ctx = if args.offline {
        attestation::Context::offline()
    } else {
        attestation::Context::new()
    };
    #[cfg(debug_assertions)]
    let ctx = match args.at {
        Some(t) => ctx.at(t).unwrap_or_else(|e| usage_error(&e.to_string())),
        None => ctx,
    };
    #[cfg(feature = "test-vendor")]
    let ctx = match std::env::var("ATTESTATION_TEST_VENDOR") {
        // A cache over vsock, or a fake vendor on loopback.
        Ok(base) if base.starts_with("vsock://") => {
            ctx.with_upstream(&base).expect("a vsock address")
        }
        Ok(base) => ctx.with_test_vendor(&base),
        Err(_) => ctx,
    };
    let verifier = attestation::Verifier::new(context(ctx));

    eprintln!("Verifying evidence...");

    let t0 = Instant::now();
    let verified = verifier
        .verify(&evidence_json, &policies)
        .await
        .unwrap_or_else(|e| exit_for_error(&e));
    let elapsed = t0.elapsed();
    let passed = verified.passed();

    let mut json = serde_json::to_value(&verified).expect("failed to serialize result");
    json["passed"] = passed.into();

    // Human-readable summary to stderr
    eprintln!("Verified in {elapsed:?}");
    eprintln!("  Platform: {}", verified.platform.platform());
    eprintln!(
        "  Launch digest: {}",
        verified.platform.claims().launch_digest
    );
    if let Some(fields) = json.as_object() {
        for (name, value) in fields {
            let is_rule =
                name.ends_with("_match") || name.ends_with("_met") || name.ends_with("_accepted");
            if is_rule && !value.is_null() {
                eprintln!("  {name}: {value}");
            }
        }
    }
    #[cfg(feature = "nvidia-gpu")]
    if let Some(gpu) = &verified.gpu {
        eprintln!(
            "  NVIDIA GPU: overall_ok={} passed={} devices={}",
            gpu.claims.overall_ok,
            gpu.passed(),
            gpu.claims.devices.len()
        );
    }
    for c in &verified.collateral {
        let version = c.version.map(|v| format!(" v{v}")).unwrap_or_default();
        let current = if c.current { "current" } else { "not current" };
        eprintln!("  Collateral: {}{version}, {current} ({})", c.name, c.from);
    }
    eprintln!("  Passed: {passed}");

    // Structured JSON to stdout
    println!(
        "{}",
        serde_json::to_string_pretty(&json).expect("failed to serialize result")
    );

    // Exit non-zero when any rule failed, so CI/deploy gates fail closed when
    // a pinned reference drifts.
    if !passed {
        process::exit(1);
    }
}

/// `ctx` keeping collateral between runs in the user's cache directory.
fn context(ctx: attestation::Context) -> attestation::Context {
    match cache_dir() {
        Some(dir) => ctx.with_cache_dir(dir),
        None => ctx,
    }
}

/// Where verified collateral is kept between runs: the user's cache
/// directory.
fn cache_dir() -> Option<PathBuf> {
    use etcetera::BaseStrategy;
    let dir = etcetera::choose_base_strategy().ok()?.cache_dir();
    Some(dir.join("attestation"))
}

/// Parse an `--expected-pcr` value of the form `INDEX=HEX`.
fn parse_pcr_pin(pin: &str) -> Result<(u8, [u8; 32]), String> {
    let (index, value) = pin.split_once('=').ok_or("expected INDEX=HEX")?;
    let index: u8 = index
        .parse()
        .ok()
        .filter(|i| *i <= 23)
        .ok_or_else(|| format!("PCR index {index:?} is not 0-23"))?;
    let bytes = hex::decode(value).map_err(|e| format!("bad hex: {e}"))?;
    let value = <[u8; 32]>::try_from(bytes.as_slice())
        .map_err(|_| format!("PCR value must be 32 bytes, got {}", bytes.len()))?;
    Ok((index, value))
}
