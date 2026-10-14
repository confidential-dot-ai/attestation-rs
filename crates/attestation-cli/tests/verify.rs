//! `attestation-cli verify` on real SEV-SNP evidence (a Genoa report), run
//! offline so the tests never touch the network.

use base64::{engine::general_purpose::STANDARD as BASE64, Engine};
use std::process::{Command, Output};
use std::sync::atomic::{AtomicUsize, Ordering};

const REPORT: &[u8] = include_bytes!("../../attestation/test_data/snp/live-report-v5-genoa.bin");
const VCEK: &[u8] = include_bytes!("../../attestation/test_data/snp/live-vcek-genoa.der");

fn run(evidence: serde_json::Value, args: &[&str]) -> Output {
    static N: AtomicUsize = AtomicUsize::new(0);
    let n = N.fetch_add(1, Ordering::Relaxed);
    let path = std::env::temp_dir().join(format!("cli-verify-{}-{n}.json", std::process::id()));
    std::fs::write(&path, evidence.to_string()).unwrap();
    let out = Command::new(env!("CARGO_BIN_EXE_attestation-cli"))
        .args(["verify", "--offline", "--evidence", path.to_str().unwrap()])
        .args(args)
        .output()
        .unwrap();
    std::fs::remove_file(&path).ok();
    out
}

/// The Genoa evidence with its VCEK inline.
fn verify(args: &[&str]) -> Output {
    run(
        serde_json::json!({
            "platform": "snp",
            "evidence": {
                "attestation_report": BASE64.encode(REPORT),
                "cert_chain": { "vcek": BASE64.encode(VCEK) },
            },
        }),
        args,
    )
}

fn stdout_json(out: &Output) -> serde_json::Value {
    serde_json::from_slice(&out.stdout).expect("result JSON on stdout")
}

#[test]
fn matching_launch_digest_exits_zero() {
    let digest = stdout_json(&verify(&["--platform", "snp"]))["claims"]["launch_digest"]
        .as_str()
        .unwrap()
        .to_string();
    let out = verify(&["--expected-launch-digest", &digest]);
    assert_eq!(out.status.code(), Some(0));
    let json = stdout_json(&out);
    assert_eq!(json["launch_digest_match"], true);
    assert_eq!(json["passed"], true);
}

#[test]
fn launch_digest_in_allowed_set_exits_zero() {
    let digest = stdout_json(&verify(&["--platform", "snp"]))["claims"]["launch_digest"]
        .as_str()
        .unwrap()
        .to_string();
    let other = "aa".repeat(48);
    let out = verify(&[
        "--expected-launch-digest",
        &other,
        "--expected-launch-digest",
        &digest,
    ]);
    assert_eq!(out.status.code(), Some(0));
    assert_eq!(stdout_json(&out)["launch_digest_match"], true);
}

#[test]
fn launch_digest_mismatch_prints_result_and_exits_one() {
    let out = verify(&["--expected-launch-digest", &"aa".repeat(48)]);
    assert_eq!(out.status.code(), Some(1));
    let json = stdout_json(&out);
    assert_eq!(json["launch_digest_match"], false);
    assert_eq!(json["passed"], false);
}

#[test]
fn evidence_for_a_platform_not_accepted_exits_one() {
    let out = verify(&["--platform", "tdx"]);
    assert_eq!(out.status.code(), Some(1));
    assert!(out.stdout.is_empty(), "nothing was verified");
}

#[test]
fn usage_errors_exit_two() {
    for args in [
        &["--platform", "snp", "--expected-mrtd", &"aa".repeat(48)][..],
        &[
            "--platform",
            "snp",
            "--expected-pcr",
            &format!("4={}", "aa".repeat(32)),
        ],
        &["--platform", "snp", "--fetch-gcp-endorsement"],
        &[
            "--platform",
            "snp",
            "--gcp-endorsement",
            concat!(
                env!("CARGO_MANIFEST_DIR"),
                "/../attestation/test_data/gcp_snp/endorsement-0e017d2f.binarypb"
            ),
        ],
        &["--expected-pcr", &format!("24={}", "aa".repeat(32))],
        &[
            "--expected-pcr",
            &format!("4={}", "aa".repeat(32)),
            "--expected-pcr",
            &format!("4={}", "bb".repeat(32)),
        ],
        &["--platform", "snp", "--expected-report-data", "zz"],
        &[
            "--platform",
            "snp",
            "--expected-report-data",
            &"aa".repeat(65),
        ],
        &[],
    ] {
        let out = verify(args);
        assert_eq!(out.status.code(), Some(2), "{args:?}");
        assert!(out.stdout.is_empty(), "nothing was verified: {args:?}");
    }
}

#[test]
fn collateral_unavailable_exits_three() {
    let out = run(
        serde_json::json!({
            "platform": "snp",
            "evidence": { "attestation_report": BASE64.encode(REPORT) },
        }),
        &["--platform", "snp"],
    );
    assert_eq!(out.status.code(), Some(3));
    assert!(out.stdout.is_empty(), "nothing was verified");
}
