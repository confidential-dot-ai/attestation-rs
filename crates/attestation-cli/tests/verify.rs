//! `attestation-cli verify` on real SEV-SNP evidence (a Genoa report), run
//! offline with AMD's Genoa CRL in the cache, so the tests never touch the
//! network.

use base64::{engine::general_purpose::STANDARD as BASE64, Engine};
use std::process::{Command, Output};
use std::sync::atomic::{AtomicUsize, Ordering};

const REPORT: &[u8] = include_bytes!("../../attestation/test_data/snp/live-report-v5-genoa.bin");
const VCEK: &[u8] = include_bytes!("../../attestation/test_data/snp/live-vcek-genoa.der");

const GENOA_CRL: &[u8] =
    include_bytes!("../../attestation/test_data/collateral/2026-10-14/amd_crl_genoa.der");
/// 2026-10-16T00:00:00Z, inside the CRL's window.
const AT: &str = "1792108800";

/// AMD's Genoa CRL, as the vendor response for its URL.
fn genoa_crl() -> attestation::HeldResponse {
    use attestation::collateral::{AmdCrl, AmdKey, Collateral};
    let url = AmdCrl::url(&(attestation::ProcessorGeneration::Genoa, AmdKey::Vcek));
    (url, GENOA_CRL.to_vec(), None)
}

fn run(evidence: serde_json::Value, args: &[&str]) -> Output {
    run_at(evidence, AT, args)
}

fn run_at(evidence: serde_json::Value, at: &str, args: &[&str]) -> Output {
    static N: AtomicUsize = AtomicUsize::new(0);
    let n = N.fetch_add(1, Ordering::Relaxed);
    let dir = std::env::temp_dir().join(format!("cli-verify-{}-{n}", std::process::id()));
    let (url, body, _) = genoa_crl();
    attestation::collateral::save_to_cache_dir(&dir.join("attestation"), &url, &body, None);
    let path = dir.join("evidence.json");
    std::fs::write(&path, evidence.to_string()).unwrap();
    let out = Command::new(env!("CARGO_BIN_EXE_attestation-cli"))
        .env("XDG_CACHE_HOME", &dir)
        .args(["verify", "--offline", "--at", at, "--evidence"])
        .arg(&path)
        .args(args)
        .output()
        .unwrap();
    std::fs::remove_dir_all(&dir).ok();
    out
}

/// The Genoa evidence with its VCEK inline.
fn evidence() -> serde_json::Value {
    serde_json::json!({
        "platform": "snp",
        "evidence": {
            "attestation_report": BASE64.encode(REPORT),
            "cert_chain": { "vcek": BASE64.encode(VCEK) },
        },
    })
}

fn verify(args: &[&str]) -> Output {
    run(evidence(), args)
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

/// The CLI has no measurement-register mode. On evidence from a kernel with the
/// provider, `REPORT_DATA` is the kernel's commitment, so pinning the
/// requester's bytes fails.
#[test]
fn a_measurement_register_report_fails_the_requesters_report_data() {
    const DIR: &str = "../attestation/test_data/snp";
    let read = |file: &str| std::fs::read(format!("{DIR}/{file}")).unwrap();
    let report = read("kmr-full-report.bin");
    let evidence = serde_json::json!({
        "platform": "snp",
        "evidence": {
            "attestation_report": BASE64.encode(&report),
            "cert_chain": { "vcek": BASE64.encode(read("kmr-vcek.der")) },
            "event_log": BASE64.encode(read("kmr-full-event-log.bin")),
        },
    });
    // 2026-10-20, inside the kernel guest VCEK's window.
    let verify = |report_data: &[u8]| {
        run_at(
            evidence.clone(),
            "1792454400",
            &[
                "--platform",
                "snp",
                "--expected-report-data",
                &hex::encode(report_data),
            ],
        )
    };
    let out = verify(&report[0x50..0x90]);
    assert_eq!(out.status.code(), Some(0), "the raw REPORT_DATA matches");

    let out = verify(&read("kmr-full-caller-data.bin"));
    assert_eq!(out.status.code(), Some(1));
    let json = stdout_json(&out);
    assert_eq!(json["report_data_match"], false);
    assert!(json["measurement_registers"].is_null());
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

/// The verdict without where each piece came from, after checking that every
/// piece came from `from`.
fn sourced_from(mut json: serde_json::Value, from: &str) -> serde_json::Value {
    for piece in json["collateral"].as_array_mut().unwrap() {
        assert_eq!(piece.as_object_mut().unwrap().remove("from").unwrap(), from);
    }
    json
}

#[tokio::test]
async fn the_answer_is_the_librarys() {
    let out = verify(&["--platform", "snp"]);
    assert_eq!(out.status.code(), Some(0));

    let ctx = attestation::Context::offline()
        .with_held([genoa_crl()])
        .at(AT.parse().unwrap())
        .unwrap();
    let policies = attestation::Policies {
        snp: Some(Default::default()),
        ..Default::default()
    };
    let lib = attestation::Verifier::new(ctx)
        .verify(evidence().to_string().as_bytes(), &policies)
        .await
        .unwrap();
    let mut lib_json = serde_json::to_value(&lib).unwrap();
    lib_json["passed"] = lib.passed().into();
    assert_eq!(
        sourced_from(stdout_json(&out), "disk"),
        sourced_from(lib_json, "held")
    );
}

/// A vendor on localhost that serves `crl` for CRL URLs and 404 for
/// everything else.
#[cfg(feature = "test-vendor")]
fn vendor(crl: Vec<u8>) -> String {
    use std::io::{Read, Write};
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let base = format!("http://{}", listener.local_addr().unwrap());
    std::thread::spawn(move || {
        for mut sock in listener.incoming().flatten() {
            let mut req = [0; 8192];
            let n = sock.read(&mut req).unwrap_or(0);
            let line = String::from_utf8_lossy(&req[..n]);
            let is_crl = line.lines().next().is_some_and(|l| l.contains("/crl "));
            let (status, body) = if is_crl {
                (200, &crl[..])
            } else {
                (404, &[][..])
            };
            let head = format!(
                "HTTP/1.1 {status} X\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                body.len()
            );
            let _ = sock.write_all(head.as_bytes());
            let _ = sock.write_all(body);
        }
    });
    base
}

/// `verify` against the vendor at `base`, with an empty cache.
#[cfg(feature = "test-vendor")]
fn run_online(evidence: serde_json::Value, base: &str) -> Output {
    static N: AtomicUsize = AtomicUsize::new(0);
    let n = N.fetch_add(1, Ordering::Relaxed);
    let dir = std::env::temp_dir().join(format!("cli-online-{}-{n}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let path = dir.join("evidence.json");
    std::fs::write(&path, evidence.to_string()).unwrap();
    let out = Command::new(env!("CARGO_BIN_EXE_attestation-cli"))
        .env("XDG_CACHE_HOME", &dir)
        .env("ATTESTATION_TEST_VENDOR", base)
        .args(["verify", "--platform", "snp", "--at", AT, "--evidence"])
        .arg(&path)
        .output()
        .unwrap();
    std::fs::remove_dir_all(&dir).ok();
    out
}

#[cfg(feature = "test-vendor")]
#[test]
fn collateral_that_is_not_the_vendors_exits_one() {
    let mut crl = GENOA_CRL.to_vec();
    *crl.last_mut().unwrap() ^= 1;
    let out = run_online(evidence(), &vendor(crl));
    assert_eq!(out.status.code(), Some(1));
    assert!(out.stdout.is_empty(), "nothing was verified");
}

#[cfg(feature = "test-vendor")]
#[test]
fn a_vcek_the_vendor_does_not_publish_exits_one() {
    let without_vcek = serde_json::json!({
        "platform": "snp",
        "evidence": { "attestation_report": BASE64.encode(REPORT) },
    });
    let out = run_online(without_vcek, &vendor(GENOA_CRL.to_vec()));
    assert_eq!(out.status.code(), Some(1));
    assert!(out.stdout.is_empty(), "nothing was verified");
}
