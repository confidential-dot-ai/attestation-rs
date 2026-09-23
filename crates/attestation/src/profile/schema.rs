//! JSON Schemas generated from the profile types. The committed copies under
//! `schemas/` are what attestation-go and c8s-verify-js pin; `schema_drift`
//! fails when they no longer match, and `UPDATE_SCHEMAS=1 cargo test` rewrites them.

use super::appraisal::Appraisal;
use super::evidence::Evidence;
use super::policy::VerifyPolicy;
use serde_json::Value;

pub const EVIDENCE_SCHEMA_FILE: &str = "cvm-evidence-v1.json";
pub const CLAIMS_SCHEMA_FILE: &str = "cvm-claims-v1.json";
pub const POLICY_SCHEMA_FILE: &str = "cvm-policy-v1.json";

/// Section 4.10: null is not a value, so no schema admits it where the
/// profile types have an optional member (schemars writes `Option<T>` as
/// `T` or null).
fn drop_null(schema: &mut schemars::Schema) {
    if let Some(obj) = schema.as_object_mut() {
        if let Some(Value::Array(types)) = obj.get_mut("type") {
            types.retain(|t| t != "null");
            if types.len() == 1 {
                let only = types.remove(0);
                obj.insert("type".into(), only);
            }
        }
        if let Some(Value::Array(any)) = obj.get_mut("anyOf") {
            any.retain(|s| s != &serde_json::json!({"type": "null"}));
            if any.len() == 1 {
                let only = any.remove(0);
                obj.remove("anyOf");
                if let Value::Object(members) = only {
                    for (k, v) in members {
                        obj.entry(k).or_insert(v);
                    }
                }
            }
        }
    }
    schemars::transform::transform_subschemas(&mut drop_null, schema);
}

fn generate<T: schemars::JsonSchema>(id: &str, title: &str) -> Value {
    let generator = schemars::generate::SchemaSettings::draft2020_12()
        .with_transform(drop_null)
        .into_generator();
    let mut v =
        serde_json::to_value(generator.into_root_schema_for::<T>()).expect("schema serializes");
    if let Value::Object(m) = &mut v {
        m.insert(
            "$id".into(),
            Value::String(format!("https://confidential.ai/schemas/{id}")),
        );
        m.insert("title".into(), Value::String(title.into()));
    }
    v
}

pub fn evidence_schema() -> Value {
    generate::<Evidence>(
        EVIDENCE_SCHEMA_FILE,
        "CVM attestation profile v1: evidence envelope",
    )
}

pub fn claims_schema() -> Value {
    generate::<Appraisal>(CLAIMS_SCHEMA_FILE, "CVM attestation profile v1: EAR claims")
}

pub fn policy_schema() -> Value {
    generate::<VerifyPolicy>(
        POLICY_SCHEMA_FILE,
        "CVM attestation profile v1: verifier policy",
    )
}

/// Pretty JSON with every object's keys sorted, so the output is identical
/// whichever `serde_json` map implementation feature unification picked.
pub fn canonical_json(v: &Value) -> String {
    fn sort(v: &Value) -> Value {
        match v {
            Value::Object(m) => {
                let mut entries: Vec<(&String, &Value)> = m.iter().collect();
                entries.sort_by(|a, b| a.0.cmp(b.0));
                let mut out = serde_json::Map::new();
                for (k, v) in entries {
                    out.insert(k.clone(), sort(v));
                }
                Value::Object(out)
            }
            Value::Array(a) => Value::Array(a.iter().map(sort).collect()),
            other => other.clone(),
        }
    }
    let mut s = serde_json::to_string_pretty(&sort(v)).expect("value serializes");
    s.push('\n');
    s
}

/// Every schema the crate publishes, by file name.
pub fn all() -> Vec<(&'static str, Value)> {
    vec![
        (EVIDENCE_SCHEMA_FILE, evidence_schema()),
        (CLAIMS_SCHEMA_FILE, claims_schema()),
        (POLICY_SCHEMA_FILE, policy_schema()),
    ]
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    fn schemas_dir() -> PathBuf {
        PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../schemas")
    }

    #[test]
    fn schema_drift() {
        let update = std::env::var_os("UPDATE_SCHEMAS").is_some();
        let mut drifted = Vec::new();
        for (name, schema) in all() {
            let path = schemas_dir().join(name);
            let rendered = canonical_json(&schema);
            if update {
                std::fs::write(&path, &rendered).unwrap();
                continue;
            }
            match std::fs::read_to_string(&path) {
                Ok(on_disk) if on_disk == rendered => {}
                _ => drifted.push(name),
            }
        }
        assert!(
            drifted.is_empty(),
            "schemas drifted from the types: {drifted:?}; run UPDATE_SCHEMAS=1 cargo test -p attestation schema_drift and commit"
        );
    }

    #[test]
    fn canonical_json_sorts_keys() {
        let v: Value = serde_json::from_str(r#"{"b":[{"z":1,"a":2}],"a":1}"#).unwrap();
        assert_eq!(
            canonical_json(&v),
            "{\n  \"a\": 1,\n  \"b\": [\n    {\n      \"a\": 2,\n      \"z\": 1\n    }\n  ]\n}\n"
        );
    }

    #[test]
    fn evidence_schema_pins_the_profile() {
        let s = evidence_schema();
        assert_eq!(
            s["$id"],
            "https://confidential.ai/schemas/cvm-evidence-v1.json"
        );
        let req = s["required"].as_array().unwrap();
        for f in ["eat_profile", "eat_nonce", "cvm_version", "submods"] {
            assert!(req.iter().any(|r| r == f), "{f} required");
        }
    }
}
