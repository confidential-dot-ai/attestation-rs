//! Appendix A: CBOR claim keys (CWT private use, RFC 8392 section 9.1) and
//! the EAR labels of draft-ietf-rats-ear-04. The JSON encoding uses names;
//! the CBOR encoding uses these keys.

/// Profile claims and their CBOR keys. Reserved entries carry no v1 semantics.
pub const CBOR_KEYS: &[(&str, i64)] = &[
    ("cvm_version", -70000),
    ("cvm_platform", -70001),
    ("cvm_report", -70002),
    ("cvm_binding", -70003),
    ("cvm_endorsements", -70004),
    ("cvm_registers", -70005),
    ("cvm_log", -70006),
    ("cvm_chain", -70007),
    ("cvm_provenance", -70008),
    ("cvm_tpm_quote", -70010),
    ("cvm_tpm_ak", -70011),
    ("cvm_launch_measurement", -70020),
    ("cvm_freshness", -70021),
    ("cvm_host_data", -70022),
    ("cvm_owner", -70023),
    ("cvm_policy", -70024),
    ("cvm_tcb", -70025),
    ("cvm_identity", -70026),
    ("cvm_workload_id", -70027),
    ("cvm_collateral", -70030),
    ("cvm_reference", -70031),
    ("cvm_backing_min", -70032),
];

/// Standard EAT claim keys the profile uses (RFC 9711).
pub const EAT_KEY_NONCE: i64 = 10;
pub const EAT_KEY_UEID: i64 = 256;
pub const EAT_KEY_DBGSTAT: i64 = 263;
pub const EAT_KEY_PROFILE: i64 = 265;
pub const EAT_KEY_SUBMODS: i64 = 266;
pub const EAT_KEY_BOOTSEED: i64 = 268;
pub const EAT_KEY_INTUSE: i64 = 275;

/// EAR labels (draft-ietf-rats-ear-04 section 9).
pub const EAR_KEY_STATUS: i64 = 1000;
pub const EAR_KEY_TRUSTWORTHINESS_VECTOR: i64 = 1001;
pub const EAR_KEY_RAW_EVIDENCE: i64 = 1002;
pub const EAR_KEY_APPRAISAL_POLICY_IDS: i64 = 1003;
pub const EAR_KEY_VERIFIER_ID: i64 = 1004;
pub const EAR_KEY_ATTESTER_CLAIMS: i64 = 1005;
pub const EAR_KEY_VERIFIER_CLAIMS: i64 = 1006;
pub const EAR_KEY_DEVICE_TOPOLOGY: i64 = 1007;

/// The CBOR key of a profile claim, by its JSON name.
pub fn cbor_key(name: &str) -> Option<i64> {
    CBOR_KEYS.iter().find(|(n, _)| *n == name).map(|(_, k)| *k)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeSet;

    #[test]
    fn keys_are_unique_private_use_and_named_once() {
        let names: BTreeSet<_> = CBOR_KEYS.iter().map(|(n, _)| *n).collect();
        let keys: BTreeSet<_> = CBOR_KEYS.iter().map(|(_, k)| *k).collect();
        assert_eq!(names.len(), CBOR_KEYS.len());
        assert_eq!(keys.len(), CBOR_KEYS.len());
        assert!(
            keys.iter().all(|k| *k < -65536),
            "CWT private use is below -65536"
        );
        assert!(names.iter().all(|n| n.starts_with("cvm_")));
        assert_eq!(cbor_key("cvm_registers"), Some(-70005));
        assert_eq!(cbor_key("cvm_provenance"), Some(-70008));
        assert_eq!(cbor_key("cvm_workload_id"), Some(-70027));
        assert_eq!(
            cbor_key("tdx_mrtd"),
            None,
            "compatibility claims keep text keys"
        );
    }
}
