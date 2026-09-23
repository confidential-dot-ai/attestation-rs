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
    Verify(Box<VerifyArgs>),
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

    /// Evidence format: the profile envelope (cvm-v1, the report data is the
    /// relying party's nonce of 16 to 64 bytes) or the legacy envelope.
    #[arg(long, value_enum, default_value_t = FormatArg::CvmV1)]
    format: FormatArg,

    /// Write evidence JSON to a file instead of stdout.
    #[arg(short, long)]
    output: Option<PathBuf>,
}

#[cfg(all(feature = "attest", target_os = "linux"))]
#[derive(Clone, Copy, PartialEq, Eq, ValueEnum)]
enum FormatArg {
    CvmV1,
    Legacy,
}

#[derive(clap::Args)]
struct VerifyArgs {
    /// Path to evidence JSON file. Reads from stdin if not specified.
    #[arg(short, long)]
    evidence: Option<PathBuf>,

    /// Appraise under the profile: a VerifyPolicy JSON file
    /// (schemas/cvm-policy-v1.json). A profile envelope is appraised with
    /// strict defaults when this is omitted.
    #[arg(long)]
    policy: Option<PathBuf>,

    /// The nonce the relying party issued (hex). Checked against eat_nonce
    /// of a profile envelope; required to appraise a legacy envelope.
    #[arg(long)]
    nonce_hex: Option<String>,

    /// Keep fetched collateral (VCEKs, AMD chains and CRLs, Intel TCB Info,
    /// QE identity and CRLs) in this directory and serve it from there while
    /// each artifact is inside its own validity window, so repeated runs on
    /// one machine do not refetch from AMD KDS, which rate-limits.
    #[arg(long)]
    collateral_dir: Option<PathBuf>,

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
        Commands::Verify(args) => cmd_verify(*args).await,
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
    let (min, max) = (
        attestation::profile::NONCE_MIN,
        attestation::profile::NONCE_MAX,
    );
    if args.format == FormatArg::CvmV1 && !(min..=max).contains(&report_data.len()) {
        eprintln!(
            "Error: the cvm-v1 format binds a nonce of {min} to {max} bytes and got {}; \
             pass it with --report-data-hex, or use --format legacy",
            report_data.len()
        );
        process::exit(1);
    }

    let t0 = Instant::now();
    let opts = attestation::AttestOptions::default();

    #[cfg(feature = "nvidia-gpu-attest")]
    let with_devices = args.nvidia_gpu;
    #[cfg(not(feature = "nvidia-gpu-attest"))]
    let with_devices = false;
    if with_devices {
        eprintln!("Collecting NVIDIA GPU evidence...");
    }
    let evidence_result = match args.format {
        FormatArg::CvmV1 => {
            attestation::attest_profile(platform, &report_data, None, with_devices, &opts).await
        }
        #[cfg(feature = "nvidia-gpu-attest")]
        FormatArg::Legacy if with_devices => {
            attestation::attest_with_nvidia_gpu(platform, &report_data, &opts).await
        }
        FormatArg::Legacy => attestation::attest(platform, &report_data, &opts).await,
    };

    let evidence_json = match evidence_result {
        Ok(json) => json,
        Err(e) => {
            eprintln!("Attestation failed: {e}");
            process::exit(1);
        }
    };
    let elapsed = t0.elapsed();

    eprintln!("Evidence generated in {elapsed:?}");

    if let Some(path) = &args.output {
        if let Err(e) = std::fs::write(path, &evidence_json) {
            eprintln!("Failed to write {}: {e}", path.display());
            process::exit(1);
        }
        eprintln!("Written to {}", path.display());
    } else {
        if io::stdout().write_all(&evidence_json).is_err() {
            eprintln!("Failed to write the evidence to stdout");
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

/// The profile path (section 6): the envelope, or a legacy envelope mapped
/// through section 9 with the relying party's nonce, appraised under a policy.
/// The legacy expectation flags keep their meaning on the profile path: each
/// becomes the corresponding policy pin, so a caller that migrates the
/// evidence format loses no check.
fn apply_expectation_flags(
    mut policy: attestation::profile::VerifyPolicy,
    args: &VerifyArgs,
    evidence: &attestation::profile::Evidence,
) -> Result<attestation::profile::VerifyPolicy, String> {
    use attestation::profile::{Bytes, Digest, HashAlg, Hosting, Submod};
    let digest48 = |hex_str: &str, name: &str| -> Result<Digest, String> {
        let bytes = hex::decode(hex_str).map_err(|e| format!("invalid hex for --{name}: {e}"))?;
        if bytes.len() != 48 {
            return Err(format!(
                "--{name} must be 48 bytes (96 hex chars), got {}",
                bytes.len()
            ));
        }
        Ok(Digest {
            alg: HashAlg::Sha384,
            value: Bytes(bytes),
        })
    };
    for (flag, name) in [
        (&args.expected_launch_digest, "expected-launch-digest"),
        (&args.expected_mrtd, "expected-mrtd"),
    ] {
        if let Some(h) = flag {
            pin_digest(
                &mut policy.reference.launch_measurement,
                digest48(h, name)?,
                name,
            )?;
        }
    }
    for (i, flag) in [
        &args.expected_rtmr0,
        &args.expected_rtmr1,
        &args.expected_rtmr2,
        &args.expected_rtmr3,
    ]
    .into_iter()
    .enumerate()
    {
        if let Some(h) = flag {
            let name = format!("expected-rtmr{i}");
            pin_digest(
                policy.reference.registers.entry(i as u16).or_default(),
                digest48(h, &name)?,
                &name,
            )?;
        }
    }
    if let Some(h) = &args.expected_init_data {
        let bytes =
            hex::decode(h).map_err(|e| format!("invalid hex for --expected-init-data: {e}"))?;
        let azure = matches!(evidence.cpu(), Some(Submod::Cpu(cpu))
            if cpu.cvm_platform.hosting == Hosting::Azure);
        if azure {
            if bytes.len() != 32 {
                return Err("--expected-init-data must be 32 bytes for Azure".to_string());
            }
            pin_digest(
                policy.reference.pcrs.entry(8).or_default(),
                Digest {
                    alg: HashAlg::Sha256,
                    value: Bytes(attestation::utils::sha256_two(&[0; 32], &bytes)),
                },
                "expected-init-data",
            )?;
        } else {
            policy.reference.host_data = Some(Bytes(bytes));
        }
    }
    #[cfg(feature = "nvidia-gpu")]
    {
        policy.gpu.required |= args.nvidia_gpu_required;
        if let Some(archs) = &args.nvidia_gpu_expected_archs {
            let mut parsed = Vec::with_capacity(archs.len());
            for a in archs {
                parsed.push(match a.to_ascii_uppercase().as_str() {
                    "HOPPER" => attestation::profile::GpuArch::Hopper,
                    "BLACKWELL" => attestation::profile::GpuArch::Blackwell,
                    "LS10" => attestation::profile::GpuArch::Ls10,
                    other => {
                        return Err(format!(
                            "unknown arch for --nvidia-gpu-expected-archs: {other} (want HOPPER, BLACKWELL, or LS10)"
                        ))
                    }
                });
            }
            policy.gpu.expected_archs = Some(parsed);
        }
    }
    Ok(policy)
}

/// CLI expectations are additional constraints: retain only the expected value
/// when the policy already permits it, and refuse a conflicting policy.
fn pin_digest(
    accepted: &mut Vec<attestation::profile::Digest>,
    expected: attestation::profile::Digest,
    flag: &str,
) -> Result<(), String> {
    if !accepted.is_empty() && !accepted.contains(&expected) {
        return Err(format!(
            "--{flag} conflicts with the policy reference values"
        ));
    }
    *accepted = vec![expected];
    Ok(())
}

/// The default verifier, or one whose collateral cache is backed by
/// `--collateral-dir`.
fn verifier(args: &VerifyArgs) -> attestation::Verifier {
    match &args.collateral_dir {
        None => attestation::Verifier::new(),
        Some(dir) => attestation::Verifier::offline().with_collateral(std::sync::Arc::new(
            attestation::CollateralCache::new(
                attestation::CachePolicy::default(),
                &attestation::HttpTimeouts::default(),
                attestation::Endpoints::default(),
                Some(attestation::DiskStore::new(dir)),
            ),
        )),
    }
}

async fn cmd_appraise(args: &VerifyArgs, evidence_json: &[u8], is_profile: bool) {
    let policy: attestation::profile::VerifyPolicy = match &args.policy {
        Some(path) => match std::fs::read(path)
            .map_err(|e| e.to_string())
            .and_then(|b| serde_json::from_slice(&b).map_err(|e| e.to_string()))
        {
            Ok(p) => p,
            Err(e) => {
                eprintln!("Error: cannot read --policy {}: {e}", path.display());
                process::exit(1);
            }
        },
        None => attestation::profile::VerifyPolicy::default(),
    };
    // The relying party's nonce: --nonce-hex, or the legacy --expected-report-data,
    // which is the same value (the anchor with no key).
    let nonce = match args
        .nonce_hex
        .as_deref()
        .or(args.expected_report_data.as_deref())
    {
        Some(h) => match hex::decode(h) {
            Ok(n) => Some(n),
            Err(e) => {
                eprintln!("Error: invalid hex for the nonce: {e}");
                process::exit(1);
            }
        },
        None => None,
    };
    #[cfg(feature = "nvidia-gpu")]
    if let (Some(gpu), Some(n)) = (&args.nvidia_gpu_user_nonce, &nonce) {
        if hex::decode(gpu).ok().as_deref() != Some(n.as_slice()) {
            eprintln!("Error: --nvidia-gpu-user-nonce must equal the nonce; the profile derives the device nonce from eat_nonce");
            process::exit(1);
        }
    }
    let Some(nonce) = &nonce else {
        eprintln!("Error: appraisal needs the nonce this relying party issued: --nonce-hex or --expected-report-data");
        process::exit(1);
    };
    let evidence = if is_profile {
        attestation::profile::Evidence::from_json(evidence_json)
    } else {
        attestation::profile::Evidence::from_legacy(evidence_json, nonce, None)
    };
    let evidence = match evidence {
        Ok(e) => e,
        Err(e) => {
            eprintln!("Appraisal failed: {e}");
            process::exit(1);
        }
    };
    if !attestation::utils::constant_time_eq(nonce, evidence.eat_nonce.as_slice()) {
        eprintln!("Appraisal failed: eat_nonce differs from the nonce this relying party issued");
        process::exit(1);
    }
    let policy = match apply_expectation_flags(policy, args, &evidence) {
        Ok(p) => p,
        Err(e) => {
            eprintln!("Error: {e}");
            process::exit(1);
        }
    };
    let verifier = verifier(args);
    eprintln!("Appraising evidence...");
    let t0 = Instant::now();
    let appraisal = verifier.appraise(&evidence, &policy).await;
    let appraisal = match appraisal {
        Ok(a) => a,
        Err(e) => {
            eprintln!("Appraisal failed: {e}");
            process::exit(1);
        }
    };
    eprintln!("Appraised in {:?}", t0.elapsed());
    eprintln!(
        "  All submodules bound: {}",
        appraisal.ear_all_submods_bound
    );
    for (name, sub) in &appraisal.submods {
        eprintln!("  {name}: {:?}", sub.ear_status);
    }
    let json = serde_json::to_string_pretty(&appraisal).expect("failed to serialize appraisal");
    println!("{json}");
}

async fn cmd_verify(args: VerifyArgs) {
    let evidence_json = match read_evidence(&args) {
        Ok(e) => e,
        Err(e) => {
            eprintln!("Error: {e}");
            process::exit(1);
        }
    };

    let is_profile = serde_json::from_slice::<serde_json::Value>(&evidence_json)
        .map(|v| v.get("eat_profile").is_some())
        .unwrap_or(false);
    if is_profile || args.policy.is_some() || args.nonce_hex.is_some() {
        cmd_appraise(&args, &evidence_json, is_profile).await;
        return;
    }

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
    let result = match verifier(&args).verify(&evidence_json, &params).await {
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

    // Exit non-zero on signature failure or any explicit policy mismatch
    // so CI/deploy gates fail closed when a pinned reference drifts.
    let policy_failed = matches!(result.report_data_match, Some(false))
        || matches!(result.init_data_match, Some(false))
        || matches!(result.mrtd_match, Some(false))
        || matches!(result.launch_digest_match, Some(false))
        || matches!(result.rtmr0_match, Some(false))
        || matches!(result.rtmr1_match, Some(false))
        || matches!(result.rtmr2_match, Some(false))
        || matches!(result.rtmr3_match, Some(false));
    if !result.signature_valid || policy_failed {
        process::exit(1);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use attestation::profile::{Bytes, Digest, Evidence, HashAlg, VerifyPolicy, PROFILE_URI};
    use serde_json::json;

    fn args(flags: &[&str]) -> VerifyArgs {
        let cli = Cli::try_parse_from(
            ["attestation-cli", "verify"]
                .into_iter()
                .chain(flags.iter().copied()),
        )
        .unwrap();
        match cli.command {
            Commands::Verify(args) => *args,
            #[cfg(all(feature = "attest", target_os = "linux"))]
            _ => panic!("expected verify"),
        }
    }

    fn cpu_evidence(vendor: &str, tee: &str, hosting: &str) -> Evidence {
        Evidence::from_json(
            &serde_json::to_vec(&json!({
                "eat_profile": PROFILE_URI,
                "eat_nonce": Bytes(vec![1; 32]).encode(),
                "cvm_version": 1,
                "submods": {"cpu": {
                    "cvm_platform": {"vendor": vendor, "tee": tee, "hosting": hosting},
                    "cvm_report": [if tee == "tdx" { "application/vnd.confidential-ai.tdx-quote" }
                        else { "application/vnd.confidential-ai.sev-snp-report" }, "AQ", 4],
                    "cvm_binding": {"pattern": "challenge", "mode": "report-data"}
                }}
            }))
            .unwrap(),
        )
        .unwrap()
    }

    fn digest(b: u8) -> Digest {
        Digest {
            alg: HashAlg::Sha384,
            value: Bytes(vec![b; 48]),
        }
    }

    #[test]
    fn cli_measurements_narrow_policy_allowlists_and_reject_conflicts() {
        let evidence = cpu_evidence("intel", "tdx", "bare");
        let expected = "22".repeat(48);
        for (flag, slot) in [
            ("--expected-mrtd", None),
            ("--expected-launch-digest", None),
            ("--expected-rtmr0", Some(0)),
            ("--expected-rtmr1", Some(1)),
            ("--expected-rtmr2", Some(2)),
            ("--expected-rtmr3", Some(3)),
        ] {
            let args = args(&[flag, &expected]);
            for accepted in [vec![], vec![digest(0x22)], vec![digest(0x11), digest(0x22)]] {
                let mut policy = VerifyPolicy::default();
                match slot {
                    Some(slot) => {
                        policy.reference.registers.insert(slot, accepted);
                    }
                    None => policy.reference.launch_measurement = accepted,
                }
                let result = apply_expectation_flags(policy, &args, &evidence).unwrap();
                let actual = match slot {
                    Some(slot) => &result.reference.registers[&slot],
                    None => &result.reference.launch_measurement,
                };
                assert_eq!(actual, &[digest(0x22)], "{flag}");
            }
            let mut policy = VerifyPolicy::default();
            match slot {
                Some(slot) => {
                    policy.reference.registers.insert(slot, vec![digest(0x11)]);
                }
                None => policy.reference.launch_measurement = vec![digest(0x11)],
            }
            assert!(
                apply_expectation_flags(policy, &args, &evidence)
                    .unwrap_err()
                    .contains("conflicts"),
                "{flag}"
            );
        }
        let conflicting = args(&[
            "--expected-mrtd",
            &expected,
            "--expected-launch-digest",
            &"11".repeat(48),
        ]);
        assert!(apply_expectation_flags(VerifyPolicy::default(), &conflicting, &evidence).is_err());
    }

    /// The nonce a recorded Azure attestation bound: its TPM quote's
    /// extraData, after TPMS_ATTEST's magic, type and qualifiedSigner.
    fn recorded_nonce(evidence: &serde_json::Value) -> Vec<u8> {
        let m = hex::decode(evidence["tpm_quote"]["message"].as_str().unwrap()).unwrap();
        let at = 8 + usize::from(u16::from_be_bytes([m[6], m[7]]));
        let len = usize::from(u16::from_be_bytes([m[at], m[at + 1]]));
        m[at + 2..at + 2 + len].to_vec()
    }

    fn azure_evidence(tee: &str) -> Evidence {
        let envelope: serde_json::Value = if tee == "snp" {
            serde_json::from_slice(include_bytes!(
                "../../attestation/test_data/az_snp/live-evidence.json"
            ))
            .unwrap()
        } else {
            let raw: serde_json::Value = serde_json::from_slice(include_bytes!(
                "../../attestation/test_data/az_tdx/live-evidence.json"
            ))
            .unwrap();
            json!({"platform": "az-tdx", "evidence": raw})
        };
        let nonce = recorded_nonce(&envelope["evidence"]);
        Evidence::from_legacy(&serde_json::to_vec(&envelope).unwrap(), &nonce, None).unwrap()
    }

    #[test]
    fn azure_init_data_pins_pcr8_in_legacy_and_profile_evidence() {
        let expected = Digest {
            alg: HashAlg::Sha256,
            value: Bytes(
                hex::decode("8878b15a7d6a3a4f464e8f9f42591dbc0cf4bedea0ec309003d2b2ee53655ef8")
                    .unwrap(),
            ),
        };
        let args = args(&["--expected-init-data", &"11".repeat(32)]);
        for tee in ["snp", "tdx"] {
            let legacy = azure_evidence(tee);
            let profile = Evidence::from_json(&legacy.to_json().unwrap()).unwrap();
            for evidence in [legacy, profile] {
                let mut policy = VerifyPolicy::default();
                let host_data = Some(Bytes(vec![7; 32]));
                policy.reference.host_data = host_data.clone();
                policy.reference.pcrs.insert(
                    8,
                    vec![
                        expected.clone(),
                        Digest {
                            alg: HashAlg::Sha256,
                            value: Bytes(vec![0; 32]),
                        },
                    ],
                );
                let result = apply_expectation_flags(policy, &args, &evidence).unwrap();
                assert_eq!(result.reference.pcrs[&8], vec![expected.clone()]);
                assert_eq!(result.reference.host_data, host_data);
                let mut conflicting = VerifyPolicy::default();
                conflicting.reference.pcrs.insert(
                    8,
                    vec![Digest {
                        alg: HashAlg::Sha256,
                        value: Bytes(vec![0; 32]),
                    }],
                );
                assert!(apply_expectation_flags(conflicting, &args, &evidence).is_err());
            }
        }
    }

    #[test]
    fn azure_init_data_requires_a_sha256_hash() {
        let evidence = azure_evidence("snp");
        for size in [0, 31, 33] {
            let args = args(&["--expected-init-data", &"11".repeat(size)]);
            assert!(
                apply_expectation_flags(VerifyPolicy::default(), &args, &evidence)
                    .unwrap_err()
                    .contains("32 bytes")
            );
        }
    }

    #[test]
    fn other_platforms_keep_the_host_data_expectation() {
        let args = args(&["--expected-init-data", &"11".repeat(32)]);
        for (vendor, tee, hosting) in [
            ("amd", "sev-snp", "bare"),
            ("amd", "sev-snp", "gcp"),
            ("intel", "tdx", "bare"),
            ("intel", "tdx", "gcp"),
            ("intel", "tdx", "dstack"),
        ] {
            let evidence = cpu_evidence(vendor, tee, hosting);
            let result =
                apply_expectation_flags(VerifyPolicy::default(), &args, &evidence).unwrap();
            assert_eq!(result.reference.host_data, Some(Bytes(vec![0x11; 32])));
            assert!(result.reference.pcrs.is_empty());
        }
    }
}
