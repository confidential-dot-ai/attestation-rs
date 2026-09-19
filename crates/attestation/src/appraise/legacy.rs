//! Section 9: the pre-profile envelope `{platform, evidence}` mapped to the
//! profile so existing callers keep working while they migrate.

use super::invalid;
use crate::error::{AttestationError, Result};
use crate::profile::{
    Binding, BindingMode, Bytes, CmwCollection, CmwEntry, CmwRecord, CpuEvidence, EventLog,
    Evidence, FreshnessPattern, Hosting, KeyBinding, LogFormat, PlatformHint, Register, Submod,
    Tee, Vendor, CMW_IND_ENDORSEMENTS, CMW_IND_EVIDENCE, CVM_VERSION, ENDORSEMENTS_COLLECTION_TAG,
    MEDIA_TYPE_PKIX_CERT, MEDIA_TYPE_SNP_REPORT, MEDIA_TYPE_TDX_QUOTE, PROFILE_URI,
};
use crate::types::PlatformType;
use base64::engine::general_purpose::STANDARD as BASE64;
use base64::Engine;
use std::collections::BTreeMap;

#[derive(serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct LegacyEnvelope {
    platform: PlatformType,
    evidence: serde_json::Value,
    #[serde(default)]
    nvidia_gpu: Option<serde_json::Value>,
}

#[derive(serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct LegacySnp {
    attestation_report: String,
    #[serde(default)]
    cert_chain: Option<LegacyChain>,
}

/// The ASK and ARK are accepted for compatibility and ignored: the bundled
/// AMD roots are the trust anchors.
#[derive(serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct LegacyChain {
    vcek: String,
    #[serde(default)]
    #[allow(dead_code)]
    ask: Option<String>,
    #[serde(default)]
    #[allow(dead_code)]
    ark: Option<String>,
}

#[derive(serde::Deserialize)]
#[serde(deny_unknown_fields)]
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
            #[cfg(any(feature = "az-snp", feature = "az-tdx"))]
            PlatformType::AzSnp => return azure(env.evidence, Tee::SevSnp, nonce, key),
            #[cfg(any(feature = "az-snp", feature = "az-tdx"))]
            PlatformType::AzTdx => return azure(env.evidence, Tee::Tdx, nonce, key),
            #[cfg(not(any(feature = "az-snp", feature = "az-tdx")))]
            PlatformType::AzSnp | PlatformType::AzTdx => {
                return Err(AttestationError::PlatformNotEnabled(
                    "legacy Azure evidence mapping".to_string(),
                ))
            }
        };
        let (report, endorsements, log, registers) = match tee {
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
                // The registers the profile requires beside a log come from
                // the signed quote; the appraiser re-derives them from the
                // report and rejects any difference.
                let registers = tdx_registers(&quote)?;
                (
                    CmwRecord::new(MEDIA_TYPE_TDX_QUOTE, quote, Some(CMW_IND_EVIDENCE)),
                    None,
                    log,
                    Some(registers),
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
            cvm_registers: registers,
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
        evidence.validate()?;
        Ok(evidence)
    }
}

/// The four RTMRs of a quote as profile registers (section 4.7).
#[cfg(feature = "tdx")]
fn tdx_registers(quote: &[u8]) -> Result<Vec<Register>> {
    let parsed = crate::platforms::tdx::verify::parse_tdx_quote(quote)?;
    let body = &parsed.body;
    Ok([body.rtmr_0, body.rtmr_1, body.rtmr_2, body.rtmr_3]
        .iter()
        .enumerate()
        .map(|(i, v)| Register {
            index: i as u16,
            alg: crate::profile::HashAlg::Sha384,
            value: Bytes(v.to_vec()),
            source: crate::profile::RegisterSource::TdxRtmr,
            backing: crate::profile::Backing::Hardware,
        })
        .collect())
}

#[cfg(not(feature = "tdx"))]
fn tdx_registers(_quote: &[u8]) -> Result<Vec<Register>> {
    Err(AttestationError::PlatformNotEnabled("tdx".to_string()))
}

#[cfg(any(feature = "az-snp", feature = "az-tdx"))]
/// Legacy Azure evidence: `hcl_report` and (TDX) `td_quote` base64url, the
/// VCEK base64url (SNP), and a hex TPM quote.
#[derive(serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct LegacyAzure {
    version: u32,
    hcl_report: String,
    #[serde(default)]
    vcek: Option<String>,
    #[serde(default)]
    td_quote: Option<String>,
    tpm_quote: LegacyTpmQuote,
}

#[cfg(any(feature = "az-snp", feature = "az-tdx"))]
#[derive(serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct LegacyTpmQuote {
    signature: String,
    message: String,
    pcrs: Vec<String>,
}

#[cfg(any(feature = "az-snp", feature = "az-tdx"))]
fn b64url(field: &str, s: &str) -> Result<Vec<u8>> {
    crate::utils::decode_base64url(s)
        .map_err(|e| invalid(format!("legacy {field}: base64url: {e}")))
}

#[cfg(any(feature = "az-snp", feature = "az-tdx"))]
fn hexf(field: &str, s: &str) -> Result<Vec<u8>> {
    hex::decode(s).map_err(|e| invalid(format!("legacy {field}: hex: {e}")))
}

#[cfg(any(feature = "az-snp", feature = "az-tdx"))]
fn azure(
    evidence: serde_json::Value,
    tee: Tee,
    nonce: &[u8],
    key: Option<KeyBinding>,
) -> Result<Evidence> {
    use crate::platforms::tpm_common::{parse_hcl_report, parse_quote_info};
    use crate::profile::{Register, TpmAkBinding, TpmAkMethod, TpmQuote, VtpmEvidence};

    let ev: LegacyAzure = serde_json::from_value(evidence)
        .map_err(|e| AttestationError::EvidenceDeserialize(e.to_string()))?;
    if ev.version != 1 {
        return Err(AttestationError::EvidenceDeserialize(format!(
            "unsupported Azure evidence version {}",
            ev.version
        )));
    }
    let hcl_bytes = b64url("hcl_report", &ev.hcl_report)?;
    let hcl = parse_hcl_report(&hcl_bytes)?;
    let message = hexf("tpm_quote.message", &ev.tpm_quote.message)?;
    let signature = hexf("tpm_quote.signature", &ev.tpm_quote.signature)?;
    let pcrs = ev
        .tpm_quote
        .pcrs
        .iter()
        .map(|p| hexf("tpm_quote.pcrs", p).map(Bytes))
        .collect::<Result<Vec<_>>>()?;
    // Only PCRs inside the quote's signed selection are authenticated, so
    // only those are projected as registers.
    let (selected, _) = parse_quote_info(&message)?;
    let registers = selected
        .iter()
        .filter_map(|&i| {
            pcrs.get(i).map(|v| Register {
                index: i as u16,
                alg: crate::profile::HashAlg::Sha256,
                value: v.clone(),
                source: crate::profile::RegisterSource::VtpmPcr,
                backing: crate::profile::Backing::PrivilegedService,
            })
        })
        .collect();
    let vtpm = VtpmEvidence {
        cvm_tpm_quote: TpmQuote {
            message: Bytes(message),
            signature: Bytes(signature),
            pcrs,
            bank: crate::profile::HashAlg::Sha256,
        },
        cvm_tpm_ak: TpmAkBinding {
            method: TpmAkMethod::HclReport,
            data: Bytes(hcl_bytes),
        },
        cvm_registers: registers,
        cvm_log: None,
    };

    let (vendor, report, endorsements, cpu_registers) = match tee {
        Tee::SevSnp => {
            let vek = ev
                .vcek
                .as_deref()
                .ok_or_else(|| invalid("legacy az-snp evidence carries no vcek"))?;
            let vek = b64url("vcek", vek)?;
            let mut entries = BTreeMap::new();
            entries.insert(
                "snp.vek".to_string(),
                CmwEntry::Record(CmwRecord::new(
                    MEDIA_TYPE_PKIX_CERT,
                    vek,
                    Some(CMW_IND_ENDORSEMENTS),
                )),
            );
            (
                Vendor::Amd,
                CmwRecord::new(
                    MEDIA_TYPE_SNP_REPORT,
                    hcl.tee_report.clone(),
                    Some(CMW_IND_EVIDENCE),
                ),
                Some(CmwCollection {
                    collection_type: Some(ENDORSEMENTS_COLLECTION_TAG.to_string()),
                    entries,
                }),
                None,
            )
        }
        Tee::Tdx => {
            let quote = ev
                .td_quote
                .as_deref()
                .ok_or_else(|| invalid("legacy az-tdx evidence carries no td_quote"))?;
            let quote = b64url("td_quote", quote)?;
            let registers = tdx_registers(&quote)?;
            (
                Vendor::Intel,
                CmwRecord::new(MEDIA_TYPE_TDX_QUOTE, quote, Some(CMW_IND_EVIDENCE)),
                None,
                Some(registers),
            )
        }
        Tee::Cca => unreachable!("no legacy CCA platform"),
    };
    let cpu = CpuEvidence {
        cvm_platform: PlatformHint {
            vendor,
            tee,
            generation: None,
            hosting: Hosting::Azure,
        },
        cvm_report: report,
        cvm_binding: Binding {
            pattern: FreshnessPattern::Challenge,
            mode: BindingMode::VtpmExtradata,
            key,
        },
        cvm_endorsements: endorsements,
        cvm_registers: cpu_registers,
        cvm_log: None,
        cvm_chain: None,
        bootseed: None,
        dbgstat: None,
        cvm_provenance: None,
    };
    let mut submods = BTreeMap::new();
    submods.insert("cpu".to_string(), Submod::Cpu(cpu));
    submods.insert("vtpm".to_string(), Submod::Vtpm(vtpm));
    let evidence = Evidence {
        eat_profile: PROFILE_URI.to_string(),
        eat_nonce: Bytes(nonce.to_vec()),
        cvm_version: CVM_VERSION,
        submods,
    };
    evidence.validate()?;
    Ok(evidence)
}
