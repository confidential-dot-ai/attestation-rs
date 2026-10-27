//! Shared fixtures for the attestation-api integration tests.

/// A `Verified` that passed, as `/verify` returns it.
pub fn passed_snp_json() -> serde_json::Value {
    serde_json::json!({
        "platform": "snp",
        "claims": {
            "launch_digest": "",
            "report_data": "",
            "signed_data": "",
            "init_data": "",
            "tcb": { "type": "Snp", "bootloader": 0, "tee": 0, "snp": 0, "microcode": 0 },
            "platform_data": {},
        },
        "report_data_match": true,
        "host_data_match": null,
        "launch_digest_match": null,
        "debug": false,
        "allow_debug": false,
        "vmpl": 0,
        "max_vmpl": 0,
        "reported_tcb": { "bootloader": 0, "tee": 0, "snp": 0, "microcode": 0 },
        "min_tcb_met": null,
    })
}
