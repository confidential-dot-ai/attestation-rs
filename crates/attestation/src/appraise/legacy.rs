//! Section 9: the pre-profile envelope `{platform, evidence}` mapped to the
//! profile so existing callers keep working while they migrate.

use super::invalid;
use crate::error::{AttestationError, Result};
use crate::profile::{
    Binding, BindingMode, Bytes, CmwCollection, CmwEntry, CmwRecord, CpuEvidence, EventLog,
    Evidence, FreshnessPattern, Hosting, KeyBinding, LogFormat, PlatformHint, Submod, Tee, Vendor,
    CMW_IND_ENDORSEMENTS, CMW_IND_EVIDENCE, CVM_VERSION, ENDORSEMENTS_COLLECTION_TAG,
    MEDIA_TYPE_PKIX_CERT, MEDIA_TYPE_SNP_REPORT, MEDIA_TYPE_TDX_QUOTE, PROFILE_URI,
};
use crate::types::PlatformType;
use base64::engine::general_purpose::STANDARD as BASE64;
use base64::Engine;
use std::collections::BTreeMap;

#[derive(serde::Deserialize)]
struct LegacyEnvelope {
    platform: PlatformType,
    evidence: serde_json::Value,
    #[serde(default)]
    nvidia_gpu: Option<serde_json::Value>,
}

#[derive(serde::Deserialize)]
struct LegacySnp {
    attestation_report: String,
    #[serde(default)]
    cert_chain: Option<LegacyChain>,
}

#[derive(serde::Deserialize)]
struct LegacyChain {
    vcek: String,
}

#[derive(serde::Deserialize)]
struct LegacyTdx {
    quote: String,
    #[serde(default)]
    cc_eventlog: Option<String>,
}

fn b64(field: &str, s: &str) -> Result<Vec<u8>> {
    BASE64
        .decode(s)
        .map_err(|e| invalid(format!("legacy {field}: base64: {e}")))
}

/// A dstack quote is hex or base64; the profile carries raw bytes.
fn quote_bytes(s: &str) -> Result<Vec<u8>> {
    if s.len() >= 1264 && s.bytes().all(|b| b.is_ascii_hexdigit()) {
        return hex::decode(s).map_err(|e| invalid(format!("legacy quote: hex: {e}")));
    }
    b64("quote", s)
}

impl Evidence {
    /// Map a `{platform, evidence}` envelope to the profile. `nonce` is what
    /// the relying party expected as `report_data` (the profile's anchor with
    /// no key), or the nonce behind `key` when a key was bound.
    pub fn from_legacy(json: &[u8], nonce: &[u8], key: Option<KeyBinding>) -> Result<Evidence> {
        if json.len() > crate::MAX_EVIDENCE_SIZE {
            return Err(AttestationError::EvidenceTooLarge {
                size: json.len(),
                max: crate::MAX_EVIDENCE_SIZE,
            });
        }
        let env: LegacyEnvelope = serde_json::from_slice(json)
            .map_err(|e| AttestationError::EvidenceDeserialize(e.to_string()))?;
        if env.nvidia_gpu.is_some() {
            return Err(AttestationError::PlatformNotEnabled(
                "legacy nvidia_gpu bundle mapping".to_string(),
            ));
        }
        let (vendor, tee, hosting) = match env.platform {
            PlatformType::Snp => (Vendor::Amd, Tee::SevSnp, Hosting::Bare),
            PlatformType::GcpSnp => (Vendor::Amd, Tee::SevSnp, Hosting::Gcp),
            PlatformType::Tdx => (Vendor::Intel, Tee::Tdx, Hosting::Bare),
            PlatformType::GcpTdx => (Vendor::Intel, Tee::Tdx, Hosting::Gcp),
            PlatformType::Dstack => (Vendor::Intel, Tee::Tdx, Hosting::Dstack),
            PlatformType::AzSnp | PlatformType::AzTdx => {
                return Err(AttestationError::PlatformNotEnabled(
                    "legacy Azure evidence mapping".to_string(),
                ))
            }
        };
        let (report, endorsements, log) = match tee {
            Tee::SevSnp => {
                let ev: LegacySnp = serde_json::from_value(env.evidence)
                    .map_err(|e| AttestationError::EvidenceDeserialize(e.to_string()))?;
                let report = b64("attestation_report", &ev.attestation_report)?;
                let endorsements = match ev.cert_chain {
                    Some(chain) => {
                        let vek = b64("cert_chain.vcek", &chain.vcek)?;
                        let mut entries = BTreeMap::new();
                        entries.insert(
                            "snp.vek".to_string(),
                            CmwEntry::Record(CmwRecord::new(
                                MEDIA_TYPE_PKIX_CERT,
                                vek,
                                Some(CMW_IND_ENDORSEMENTS),
                            )),
                        );
                        Some(CmwCollection {
                            collection_type: Some(ENDORSEMENTS_COLLECTION_TAG.to_string()),
                            entries,
                        })
                    }
                    None => None,
                };
                (
                    CmwRecord::new(MEDIA_TYPE_SNP_REPORT, report, Some(CMW_IND_EVIDENCE)),
                    endorsements,
                    None,
                )
            }
            Tee::Tdx => {
                let ev: LegacyTdx = serde_json::from_value(env.evidence)
                    .map_err(|e| AttestationError::EvidenceDeserialize(e.to_string()))?;
                let quote = quote_bytes(&ev.quote)?;
                let log = match ev.cc_eventlog {
                    Some(l) => Some(EventLog {
                        format: LogFormat::TdxCcel,
                        data: Bytes(b64("cc_eventlog", &l)?),
                    }),
                    None => None,
                };
                (
                    CmwRecord::new(MEDIA_TYPE_TDX_QUOTE, quote, Some(CMW_IND_EVIDENCE)),
                    None,
                    log,
                )
            }
            Tee::Cca => unreachable!("no legacy CCA platform"),
        };
        let cpu = CpuEvidence {
            cvm_platform: PlatformHint {
                vendor,
                tee,
                generation: None,
                hosting,
            },
            cvm_report: report,
            cvm_binding: Binding {
                pattern: FreshnessPattern::Challenge,
                mode: BindingMode::ReportData,
                key,
            },
            cvm_endorsements: endorsements,
            // A legacy log rides along; registers are required beside a log,
            // and the TDX ones come from the signed quote, so they are filled
            // by the appraiser from the report, never from the caller.
            cvm_registers: None,
            cvm_log: log,
            cvm_chain: None,
            bootseed: None,
            dbgstat: None,
            cvm_provenance: None,
        };
        let mut submods = BTreeMap::new();
        submods.insert("cpu".to_string(), Submod::Cpu(cpu));
        let evidence = Evidence {
            eat_profile: PROFILE_URI.to_string(),
            eat_nonce: Bytes(nonce.to_vec()),
            cvm_version: CVM_VERSION,
            submods,
        };
        evidence.validate_legacy()?;
        Ok(evidence)
    }
}
