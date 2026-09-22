//! The CLI on real hardware: `attest` emits the profile by default and `verify`
//! appraises it, on every runner the confidential-e2e workflow reaches. Tests
//! are `#[ignore]`d and named `live_<runner>_*`; the workflow selects them per
//! runner, and a test on the wrong machine fails instead of skipping.

#![cfg(all(feature = "attest", target_os = "linux"))]

use std::io::Read;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};

use attestation::profile::{Backing, VerifyPolicy, PROFILE_URI};
use attestation::TdxTcbStatus;
use base64::Engine;

const CLI: &str = env!("CARGO_BIN_EXE_attestation-cli");

fn random_hex(n: usize) -> String {
    let mut buf = vec![0u8; n];
    std::fs::File::open("/dev/urandom")
        .and_then(|mut f| f.read_exact(&mut buf))
        .expect("read /dev/urandom");
    hex::encode(buf)
}

fn cli(args: &[&str]) -> Output {
    let out = Command::new(CLI)
        .args(args)
        .output()
        .expect("run attestation-cli");
    eprintln!(
        "$ attestation-cli {} -> {}\n{}",
        args.join(" "),
        out.status,
        String::from_utf8_lossy(&out.stderr)
    );
    out
}

fn require(device: &str) {
    assert!(
        Path::new(device).exists(),
        "{device} is absent: this test runs on a specific runner"
    );
}

struct Run {
    dir: tempfile::TempDir,
}

impl Run {
    fn new() -> Self {
        Run {
            dir: tempfile::tempdir().expect("tempdir"),
        }
    }

    fn path(&self, name: &str) -> PathBuf {
        self.dir.path().join(name)
    }

    fn policy(&self, policy: &VerifyPolicy) -> String {
        let path = self.path("policy.json");
        std::fs::write(&path, serde_json::to_vec(policy).unwrap()).unwrap();
        path.to_str().unwrap().to_string()
    }

    /// `attest --platform P --report-data-hex N`, the default format.
    fn attest(&self, platform: &str, nonce: &str, name: &str, extra: &[&str]) -> String {
        let out = self.path(name);
        let out = out.to_str().unwrap().to_string();
        let mut args = vec![
            "attest",
            "--platform",
            platform,
            "--report-data-hex",
            nonce,
            "--output",
            &out,
        ];
        args.extend_from_slice(extra);
        let result = cli(&args);
        assert!(result.status.success(), "attest failed");
        out
    }
}

fn policy_for(platform: &str) -> VerifyPolicy {
    let mut p = VerifyPolicy::default();
    if platform.starts_with("az-") {
        p.min_backing = Backing::PrivilegedService;
    }
    if platform.ends_with("tdx") {
        p.tcb.tdx_allowed_status = vec![
            TdxTcbStatus::UpToDate,
            TdxTcbStatus::SWHardeningNeeded,
            TdxTcbStatus::ConfigurationNeeded,
            TdxTcbStatus::ConfigurationAndSWHardeningNeeded,
            TdxTcbStatus::OutOfDate,
            TdxTcbStatus::OutOfDateConfigurationNeeded,
        ];
    }
    p
}

fn launch_measurement_hex(appraisal: &serde_json::Value) -> String {
    let b64 = appraisal["submods"]["cpu"]["ear_attester_claims"]["cvm_launch_measurement"]["value"]
        .as_str()
        .expect("cvm_launch_measurement");
    hex::encode(
        base64::engine::general_purpose::URL_SAFE_NO_PAD
            .decode(b64)
            .expect("base64url"),
    )
}

/// attest then verify with the flags the runner gate uses, under a policy
/// that accepts the runner; then the negative cases and the old envelope.
fn round_trip(platform: &str, device: &str, nonce_len: usize) {
    require(device);
    let run = Run::new();
    let policy = run.policy(&policy_for(platform));
    let nonce = random_hex(nonce_len);

    let envelope = run.attest(platform, &nonce, "evidence.json", &[]);
    let body: serde_json::Value =
        serde_json::from_slice(&std::fs::read(&envelope).unwrap()).unwrap();
    assert_eq!(body["eat_profile"], PROFILE_URI, "attest emits the profile");

    let out = cli(&[
        "verify",
        "--evidence",
        &envelope,
        "--expected-report-data",
        &nonce,
        "--policy",
        &policy,
    ]);
    assert!(out.status.success(), "verify under the runner policy");
    let appraisal: serde_json::Value =
        serde_json::from_slice(&out.stdout).expect("verify prints the appraisal");
    eprintln!("{}", serde_json::to_string_pretty(&appraisal).unwrap());
    assert_eq!(appraisal["ear_all_submods_bound"], true);

    // A measurement pin narrows the policy: the true value passes, another fails.
    let pin = if platform.ends_with("tdx") {
        "--expected-mrtd"
    } else {
        "--expected-launch-digest"
    };
    let measurement = launch_measurement_hex(&appraisal);
    let verify_pinned = |value: &str| {
        cli(&[
            "verify",
            "--evidence",
            &envelope,
            "--expected-report-data",
            &nonce,
            "--policy",
            &policy,
            pin,
            value,
        ])
    };
    assert!(verify_pinned(&measurement).status.success());
    assert!(!verify_pinned(&"00".repeat(48)).status.success());

    // Another nonce is refused before any appraisal.
    let other = cli(&[
        "verify",
        "--evidence",
        &envelope,
        "--expected-report-data",
        &random_hex(nonce_len),
        "--policy",
        &policy,
    ]);
    assert!(!other.status.success());
    assert!(String::from_utf8_lossy(&other.stderr).contains("eat_nonce differs"));

    // The old envelope and the old verify path still work.
    let legacy = run.attest(platform, &nonce, "legacy.json", &["--format", "legacy"]);
    let body: serde_json::Value = serde_json::from_slice(&std::fs::read(&legacy).unwrap()).unwrap();
    assert!(body.get("eat_profile").is_none());
    assert!(cli(&[
        "verify",
        "--evidence",
        &legacy,
        "--expected-report-data",
        &nonce
    ])
    .status
    .success());

    // The profile binds a nonce; attesting without one says how to proceed.
    let bare = cli(&["attest", "--platform", platform]);
    assert!(!bare.status.success());
    assert!(String::from_utf8_lossy(&bare.stderr).contains("--format legacy"));
}

/// The exact commands `attest-runner.yml` runs, with this commit's CLI on both
/// sides and no policy file: what the runner gate does once this lands.
fn gate_command(platform: &str, device: &str) {
    require(device);
    let run = Run::new();
    let nonce = random_hex(64);
    let envelope = run.attest(platform, &nonce, "evidence.json", &[]);

    // The gate pins the image; learn this runner's value under a lenient policy.
    let policy = run.policy(&policy_for(platform));
    let out = cli(&[
        "verify",
        "--evidence",
        &envelope,
        "--expected-report-data",
        &nonce,
        "--policy",
        &policy,
    ]);
    assert!(out.status.success(), "verify under the runner policy");
    let appraisal: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap();
    let measurement = launch_measurement_hex(&appraisal);
    eprintln!("launch measurement {measurement}");

    let pin = if platform == "tdx" {
        "--expected-mrtd"
    } else {
        "--expected-launch-digest"
    };
    let gate = cli(&[
        "verify",
        "--evidence",
        &envelope,
        "--expected-report-data",
        &nonce,
        pin,
        &measurement,
    ]);
    assert!(
        gate.status.success(),
        "the runner gate's verify command refuses this runner under the strict default policy"
    );
}

#[test]
#[ignore = "needs the SEV-SNP metal runner"]
fn live_snp_metal_cli_round_trip() {
    round_trip("snp", "/dev/sev-guest", 64);
}

#[test]
#[ignore = "needs the SEV-SNP metal runner"]
fn live_snp_metal_cli_gate_command() {
    gate_command("snp", "/dev/sev-guest");
}

#[test]
#[ignore = "needs the TDX metal runner"]
fn live_tdx_metal_cli_round_trip() {
    round_trip("tdx", "/dev/tdx_guest", 64);
}

#[test]
#[ignore = "needs the TDX metal runner"]
fn live_tdx_metal_cli_gate_command() {
    gate_command("tdx", "/dev/tdx_guest");
}

#[test]
#[ignore = "needs the Azure SEV-SNP runner"]
fn live_azure_snp_cli_round_trip() {
    round_trip("az-snp", "/dev/tpmrm0", 32);
}

#[test]
#[ignore = "needs the Azure TDX runner"]
fn live_azure_tdx_cli_round_trip() {
    round_trip("az-tdx", "/dev/tpmrm0", 32);
}
