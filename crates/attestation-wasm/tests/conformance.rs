//! The conformance corpus (profile section 14) through this build's
//! `appraise_with`: the wasm entry decides every case as the reference
//! runner does. It runs natively; the entry's decision logic is plain Rust,
//! and the wasm32 build of the same code is compiled in CI.

use attestation_wasm::{appraise_with_inputs, Failure};
use base64::engine::general_purpose::STANDARD;
use base64::Engine;
use serde::Deserialize;
use serde_json::{json, Value};
use std::collections::BTreeMap;
use std::io::Read;
use std::path::{Path, PathBuf};

fn corpus() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../../conformance")
}

/// Section 14.2: a `.gz` input is its decompressed content.
fn read(path: &str) -> Vec<u8> {
    let p = corpus().join("inputs").join(path);
    let bytes = std::fs::read(&p).unwrap_or_else(|e| panic!("{}: {e}", p.display()));
    if !path.ends_with(".gz") {
        return bytes;
    }
    let mut out = Vec::new();
    flate2::read::GzDecoder::new(bytes.as_slice())
        .take(16 << 20)
        .read_to_end(&mut out)
        .unwrap();
    out
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Case {
    id: String,
    #[allow(dead_code)]
    rule: Value,
    now: String,
    evidence: String,
    #[serde(default)]
    policy: Option<String>,
    #[serde(default)]
    collateral: BTreeMap<String, Collateral>,
    #[serde(default)]
    nras: Vec<Nras>,
    expect: Expect,
}

#[derive(Deserialize)]
#[serde(untagged)]
enum Collateral {
    File(String),
    Signed { body: String, signing_chain: String },
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Nras {
    arch: String,
    nonce: String,
    response: String,
    jwks: String,
}

#[derive(Deserialize)]
#[serde(rename_all = "lowercase", deny_unknown_fields)]
enum Expect {
    Appraisal(String),
    Refusal(String),
}

/// Section 14.3: the members that are the implementation's own.
fn strip(v: &mut Value) {
    let Some(o) = v.as_object_mut() else { return };
    for member in ["iat", "ear_verifier_id", "ear_raw_evidence"] {
        o.remove(member);
    }
    for sub in o
        .get_mut("submods")
        .and_then(Value::as_object_mut)
        .into_iter()
        .flat_map(|s| s.values_mut())
    {
        let checks = sub
            .pointer_mut("/ear_verifier_claims/cvm_collateral")
            .and_then(Value::as_object_mut);
        for check in checks.into_iter().flat_map(|c| c.values_mut()) {
            if let Some(c) = check.as_object_mut() {
                c.remove("reason");
            }
        }
    }
}

/// The case's inputs in the form `appraise_with` takes.
fn inputs(case: &Case) -> String {
    let collateral: BTreeMap<&String, Value> = case
        .collateral
        .iter()
        .map(|(k, c)| {
            let v = match c {
                Collateral::File(p) => json!({"body": STANDARD.encode(read(p))}),
                Collateral::Signed {
                    body,
                    signing_chain,
                } => json!({
                    "body": STANDARD.encode(read(body)),
                    "signing_chain": STANDARD.encode(read(signing_chain)),
                }),
            };
            (k, v)
        })
        .collect();
    let nras: Vec<Value> = case
        .nras
        .iter()
        .map(|x| {
            let response: Value = serde_json::from_slice(&read(&x.response)).unwrap();
            let jwks: Value = serde_json::from_slice(&read(&x.jwks)).unwrap();
            json!({"arch": x.arch, "nonce": x.nonce, "response": response, "jwks": jwks})
        })
        .collect();
    json!({"now": case.now, "collateral": collateral, "nras": nras}).to_string()
}

#[tokio::test]
async fn the_corpus_holds_through_appraise_with() {
    let mut paths: Vec<PathBuf> = std::fs::read_dir(corpus().join("cases"))
        .unwrap()
        .map(|e| e.unwrap().path())
        .filter(|p| p.extension().is_some_and(|x| x == "json"))
        .collect();
    paths.sort();
    assert!(!paths.is_empty());
    let mut failures = Vec::new();
    for p in &paths {
        let case: Case = serde_json::from_slice(&std::fs::read(p).unwrap())
            .unwrap_or_else(|e| panic!("{}: {e}", p.display()));
        let evidence = String::from_utf8(read(&case.evidence)).unwrap();
        let policy = case
            .policy
            .as_ref()
            .map(|p| String::from_utf8(read(p)).unwrap());
        let got = appraise_with_inputs(&evidence, policy.as_deref(), &inputs(&case)).await;
        let verdict = match (&case.expect, got) {
            (Expect::Refusal(want), Err(Failure::Refused { code, .. }))
                if code.as_str() == want =>
            {
                Ok(())
            }
            (Expect::Refusal(want), Err(Failure::Refused { code, message })) => {
                Err(format!("refused with {code}, expected {want}: {message}"))
            }
            (_, Err(Failure::Usage(m))) => Err(format!("did not decide: {m}")),
            (_, Err(Failure::Internal(m))) => Err(format!("did not decide: {m}")),
            (Expect::Refusal(want), Ok(_)) => Err(format!("appraised, expected refusal {want}")),
            (Expect::Appraisal(_), Err(Failure::Refused { code, message })) => Err(format!(
                "refused with {code}, expected an appraisal: {message}"
            )),
            (Expect::Appraisal(path), Ok(json)) => {
                let mut got: Value = serde_json::from_str(&json).unwrap();
                let mut want: Value = serde_json::from_slice(&read(path)).unwrap();
                strip(&mut got);
                strip(&mut want);
                if got == want {
                    Ok(())
                } else {
                    Err(format!("appraisal differs from {path}"))
                }
            }
        };
        if let Err(why) = verdict {
            failures.push(format!("{}: {why}", case.id));
        }
    }
    assert!(
        failures.is_empty(),
        "{} of {} cases failed:\n{}",
        failures.len(),
        paths.len(),
        failures.join("\n")
    );
}
