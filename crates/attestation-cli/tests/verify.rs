//! `attestation-cli verify` on real SEV-SNP evidence (Genoa report with its
//! VCEK inline, so verification needs no network).

use base64::{engine::general_purpose::STANDARD as BASE64, Engine};
use std::process::{Command, Output};
use std::sync::atomic::{AtomicUsize, Ordering};

const REPORT: &[u8] = include_bytes!("../../attestation/test_data/snp/live-report-v5-genoa.bin");
const VCEK: &[u8] = include_bytes!("../../attestation/test_data/snp/live-vcek-genoa.der");

fn verify(extra: &[&str]) -> Output {
    let evidence = serde_json::json!({
        "platform": "snp",
        "evidence": {
            "attestation_report": BASE64.encode(REPORT),
            "cert_chain": { "vcek": BASE64.encode(VCEK) },
        },
    });
    static N: AtomicUsize = AtomicUsize::new(0);
    let n = N.fetch_add(1, Ordering::Relaxed);
    let path = std::env::temp_dir().join(format!("cli-verify-{}-{n}.json", std::process::id()));
    std::fs::write(&path, evidence.to_string()).unwrap();
    let out = Command::new(env!("CARGO_BIN_EXE_attestation-cli"))
        .args(["verify", "--evidence", path.to_str().unwrap()])
        .args(extra)
        .output()
        .unwrap();
    std::fs::remove_file(&path).ok();
    out
}

fn stdout_json(out: &Output) -> serde_json::Value {
    serde_json::from_slice(&out.stdout).expect("result JSON on stdout")
}

#[test]
fn matching_launch_digest_exits_zero() {
    let digest = stdout_json(&verify(&[]))["claims"]["launch_digest"]
        .as_str()
        .unwrap()
        .to_string();
    let out = verify(&["--expected-launch-digest", &digest]);
    assert!(out.status.success());
    assert_eq!(stdout_json(&out)["launch_digest_match"], true);
}

#[test]
fn launch_digest_mismatch_prints_result_and_exits_one() {
    let out = verify(&["--expected-launch-digest", &"aa".repeat(48)]);
    assert_eq!(out.status.code(), Some(1));
    let json = stdout_json(&out);
    assert_eq!(json["launch_digest_match"], false);
    assert_eq!(json["signature_valid"], true);
    assert_eq!(json["issues"][0]["check"], "launch_digest");
    assert_eq!(json["issues"][0]["problem"], "mismatch");
}

#[test]
fn unanswerable_pin_prints_result_and_exits_one() {
    let out = verify(&["--expected-mrtd", &"aa".repeat(48)]);
    assert_eq!(out.status.code(), Some(1));
    let json = stdout_json(&out);
    assert!(json.get("mrtd_match").is_none());
    assert_eq!(
        json["issues"],
        serde_json::json!([{ "check": "mrtd", "problem": "unanswerable" }])
    );
}
