use serde::{Deserialize, Serialize};

/// Raw SNP attestation evidence.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SnpEvidence {
    /// The raw attestation report bytes (1184 bytes), base64 encoded.
    pub attestation_report: String,
    /// Optional certificate chain from the hypervisor (VCEK/VLEK + ASK + ARK),
    /// each cert as base64-encoded DER.
    #[serde(default)]
    pub cert_chain: Option<SnpCertChain>,
    /// The guest kernel's runtime-register event log (raw 49-byte entries),
    /// base64 encoded. Read after the report, so it extends the log prefix
    /// the report commits to.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub event_log: Option<String>,
}

/// Certificate chain provided by the hypervisor in the extended report.
///
/// Only the VCEK/VLEK is used from the hypervisor-provided chain.
/// The ASK and ARK are accepted for serialization compatibility but are
/// **intentionally ignored** during verification — the library always resolves
/// these from bundled trust anchors to prevent an attacker from substituting
/// a rogue intermediate or root certificate.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SnpCertChain {
    /// VCEK or VLEK certificate (DER, base64 encoded).
    pub vcek: String,
    /// ASK certificate (DER, base64 encoded). Ignored during verification —
    /// bundled ASK is always used as the trust anchor.
    #[serde(default)]
    pub ask: Option<String>,
    /// ARK certificate (DER, base64 encoded). Ignored during verification —
    /// bundled ARK is always used as the trust anchor.
    #[serde(default)]
    pub ark: Option<String>,
}
