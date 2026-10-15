//! What every collateral document has in common: an identity, the bytes a
//! vendor served, a validity window and a version.

use std::fmt;

use base64::{engine::general_purpose::STANDARD as BASE64, Engine};
use serde::{Deserialize, Serialize};

use crate::types::{ProcessorGeneration, SnpTcb};

/// Bytes exactly as a vendor served them, plus the issuer chain Intel PCS
/// sends in a response header (URL-decoded PEM).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Raw {
    #[serde(with = "b64")]
    pub body: Vec<u8>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub issuer_chain: Option<String>,
}

mod b64 {
    use super::*;

    pub fn serialize<S: serde::Serializer>(bytes: &[u8], s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(&BASE64.encode(bytes))
    }

    pub fn deserialize<'de, D: serde::Deserializer<'de>>(d: D) -> Result<Vec<u8>, D::Error> {
        let s = String::deserialize(d)?;
        BASE64.decode(s).map_err(serde::de::Error::custom)
    }
}

/// The validity window and version a document states about itself, in Unix
/// seconds.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Info {
    /// thisUpdate, issueDate, or notBefore.
    pub this_update: Option<i64>,
    /// nextUpdate, or notAfter. `None` when the document does not expire.
    pub next_update: Option<i64>,
    /// CRL Number or tcbEvaluationDataNumber.
    pub version: Option<u64>,
}

/// Whether a document was current at the evaluation time.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Freshness {
    Current,
    /// Past its nextUpdate (or notAfter).
    Expired,
    /// Issued after the evaluation time.
    NotYetValid,
}

impl Info {
    pub fn freshness(&self, now: i64) -> Freshness {
        if self.this_update.is_some_and(|t| now < t) {
            Freshness::NotYetValid
        } else if self.next_update.is_some_and(|t| now > t) {
            Freshness::Expired
        } else {
            Freshness::Current
        }
    }

    /// True unless `self` is an older issue than `other`: a lower version,
    /// or the same version issued earlier.
    pub fn not_older_than(&self, other: &Info) -> bool {
        (self.version, self.this_update) >= (other.version, other.this_update)
    }
}

/// A vendor document a verifier can ask for. The value of the type is the
/// document's identity (its key).
pub trait Document: sealed::Sealed + Clone + Into<DocKey> + Send + Sync + 'static {
    /// What a checked document gives the verifier.
    type Value: Send + Sync + 'static;

    /// Parse `raw`, check its signature against the vendor roots compiled
    /// into this crate, and check that it is the document `self` names. `Err`
    /// carries the reason it is refused.
    fn check(&self, raw: &Raw) -> Result<(Self::Value, Info), String>;
}

/// AMD signs one CRL per generation for the certificates its ARK issues, at
/// two paths: for VCEKs (ASK) and for VLEKs (ASVK).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum AmdSigner {
    Ask,
    Asvk,
}

/// The Intel CA that issued a PCK certificate.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum PckCa {
    Platform,
    Processor,
}

/// The TEE a GCE launch endorsement is for.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum GceTee {
    Tdx,
    SevSnp,
}

/// An AMD VCEK: the per-chip key a SEV-SNP report is signed with, for one
/// TCB.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct AmdVcek {
    pub generation: ProcessorGeneration,
    /// The report's CHIP_ID, hex.
    pub chip_id: String,
    pub tcb: SnpTcb,
}

/// The AMD CRL for one generation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct AmdCrl {
    pub generation: ProcessorGeneration,
    pub signer: AmdSigner,
}

/// Intel's TDX TCB Info for one platform (FMSPC).
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct IntelTcbInfo {
    /// Lowercase hex.
    pub fmspc: String,
}

/// Intel's TD Quoting Enclave identity.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct IntelQeIdentity {}

/// The CRL of an Intel PCK CA.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct IntelPckCrl {
    pub ca: PckCa,
}

/// The CRL of the Intel SGX Root CA.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct IntelRootCrl {}

/// Google's signed launch endorsement for a GCE firmware build, named by the
/// launch measurement (MRTD or SEV-SNP measurement).
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct GceEndorsement {
    pub tee: GceTee,
    /// Hex.
    pub measurement: String,
}

/// The keys NVIDIA's NRAS signs its attestation tokens with.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct NrasJwks {}

/// Any document, by identity.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(tag = "document", rename_all = "kebab-case")]
pub enum DocKey {
    AmdVcek(AmdVcek),
    AmdCrl(AmdCrl),
    IntelTcbInfo(IntelTcbInfo),
    IntelQeIdentity(IntelQeIdentity),
    IntelPckCrl(IntelPckCrl),
    IntelRootCrl(IntelRootCrl),
    GceEndorsement(GceEndorsement),
    NrasJwks(NrasJwks),
}

mod sealed {
    pub trait Sealed {}
}

macro_rules! into_key {
    ($($t:ident),*) => {$(
        impl sealed::Sealed for $t {}

        impl From<$t> for DocKey {
            fn from(d: $t) -> Self {
                DocKey::$t(d)
            }
        }
    )*};
}
into_key!(
    AmdVcek,
    AmdCrl,
    IntelTcbInfo,
    IntelQeIdentity,
    IntelPckCrl,
    IntelRootCrl,
    GceEndorsement,
    NrasJwks
);

pub(crate) const AMD_KDS: &str = "https://kdsintf.amd.com";
pub(crate) const INTEL_PCS: &str = "https://api.trustedservices.intel.com";
pub(crate) const INTEL_CERTS: &str = "https://certificates.trustedservices.intel.com";
pub(crate) const GCE_TCB_INTEGRITY: &str =
    "https://storage.googleapis.com/gce_tcb_integrity/ovmf_x64_csm";
pub(crate) const NRAS: &str = "https://nras.attestation.nvidia.com";

impl DocKey {
    /// Where the vendor publishes the document.
    pub fn url(&self) -> String {
        match self {
            DocKey::AmdVcek(k) => {
                // Turin keys the lookup on the first 8 bytes of CHIP_ID.
                let chip_id = match k.generation {
                    ProcessorGeneration::Turin => k.chip_id.get(..16).unwrap_or(&k.chip_id),
                    _ => &k.chip_id,
                };
                let t = &k.tcb;
                let mut url = format!(
                    "{AMD_KDS}/vcek/v1/{}/{chip_id}?blSPL={:02}&teeSPL={:02}&snpSPL={:02}&ucodeSPL={:02}",
                    k.generation.product_name(),
                    t.bootloader,
                    t.tee,
                    t.snp,
                    t.microcode
                );
                if let Some(fmc) = t.fmc {
                    url.push_str(&format!("&fmcSPL={fmc:02}"));
                }
                url
            }
            DocKey::AmdCrl(k) => {
                let path = match k.signer {
                    AmdSigner::Ask => "vcek",
                    AmdSigner::Asvk => "vlek",
                };
                format!("{AMD_KDS}/{path}/v1/{}/crl", k.generation.product_name())
            }
            DocKey::IntelTcbInfo(k) => {
                format!("{INTEL_PCS}/tdx/certification/v4/tcb?fmspc={}", k.fmspc)
            }
            DocKey::IntelQeIdentity(_) => format!("{INTEL_PCS}/tdx/certification/v4/qe/identity"),
            DocKey::IntelPckCrl(k) => {
                let ca = match k.ca {
                    PckCa::Platform => "platform",
                    PckCa::Processor => "processor",
                };
                format!("{INTEL_PCS}/sgx/certification/v4/pckcrl?ca={ca}")
            }
            DocKey::IntelRootCrl(_) => format!("{INTEL_CERTS}/IntelSGXRootCA.der"),
            DocKey::GceEndorsement(k) => {
                let dir = match k.tee {
                    GceTee::Tdx => "tdx",
                    GceTee::SevSnp => "sevsnp",
                };
                format!("{GCE_TCB_INTEGRITY}/{dir}/{}.binarypb", k.measurement)
            }
            DocKey::NrasJwks(_) => format!("{NRAS}/.well-known/jwks.json"),
        }
    }

    /// The response header Intel PCS sends the document's issuer chain in.
    pub fn issuer_chain_header(&self) -> Option<&'static str> {
        match self {
            DocKey::IntelTcbInfo(_) => Some("TCB-Info-Issuer-Chain"),
            DocKey::IntelQeIdentity(_) => Some("SGX-Enclave-Identity-Issuer-Chain"),
            DocKey::IntelPckCrl(_) => Some("SGX-PCK-CRL-Issuer-Chain"),
            _ => None,
        }
    }
}

impl fmt::Display for DocKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            DocKey::AmdVcek(k) => write!(f, "AMD VCEK {:?} {}", k.generation, k.chip_id),
            DocKey::AmdCrl(k) => write!(f, "AMD CRL {:?} {:?}", k.generation, k.signer),
            DocKey::IntelTcbInfo(k) => write!(f, "Intel TCB Info {}", k.fmspc),
            DocKey::IntelQeIdentity(_) => f.write_str("Intel TD QE Identity"),
            DocKey::IntelPckCrl(k) => write!(f, "Intel PCK CRL {:?}", k.ca),
            DocKey::IntelRootCrl(_) => f.write_str("Intel Root CA CRL"),
            DocKey::GceEndorsement(k) => {
                write!(f, "GCE launch endorsement {:?} {}", k.tee, k.measurement)
            }
            DocKey::NrasJwks(_) => f.write_str("NRAS JWKS"),
        }
    }
}

/// The CRL Number extension, when it fits a u64.
#[cfg(any(feature = "snp", feature = "tdx"))]
pub(crate) fn crl_number(
    crl: &x509_parser::revocation_list::CertificateRevocationList,
) -> Option<u64> {
    let bytes = crl.crl_number()?.to_bytes_be();
    (bytes.len() <= 8).then(|| bytes.iter().fold(0u64, |n, b| n << 8 | u64::from(*b)))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn info(this: i64, next: i64, version: u64) -> Info {
        Info {
            this_update: Some(this),
            next_update: Some(next),
            version: Some(version),
        }
    }

    #[test]
    fn freshness_follows_the_window() {
        let i = info(100, 200, 1);
        assert_eq!(i.freshness(99), Freshness::NotYetValid);
        assert_eq!(i.freshness(100), Freshness::Current);
        assert_eq!(i.freshness(200), Freshness::Current);
        assert_eq!(i.freshness(201), Freshness::Expired);
        assert_eq!(Info::default().freshness(0), Freshness::Current);
    }

    #[test]
    fn a_higher_version_or_a_later_issue_is_newer() {
        assert!(info(100, 200, 2).not_older_than(&info(150, 250, 1)));
        assert!(!info(150, 250, 1).not_older_than(&info(100, 200, 2)));
        assert!(info(150, 250, 1).not_older_than(&info(100, 200, 1)));
        assert!(!info(100, 200, 1).not_older_than(&info(150, 250, 1)));
        assert!(info(100, 200, 1).not_older_than(&info(100, 200, 1)));
    }

    #[test]
    fn keys_name_vendor_urls() {
        let tcb = SnpTcb {
            bootloader: 10,
            tee: 0,
            snp: 27,
            microcode: 28,
            fmc: None,
        };
        let vcek = DocKey::from(AmdVcek {
            generation: ProcessorGeneration::Genoa,
            chip_id: "ab".repeat(64),
            tcb,
        });
        assert_eq!(
            vcek.url(),
            format!(
                "https://kdsintf.amd.com/vcek/v1/Genoa/{}?blSPL=10&teeSPL=00&snpSPL=27&ucodeSPL=28",
                "ab".repeat(64)
            )
        );
        let turin = DocKey::from(AmdVcek {
            generation: ProcessorGeneration::Turin,
            chip_id: "cd".repeat(64),
            tcb: SnpTcb {
                fmc: Some(3),
                ..tcb
            },
        });
        assert_eq!(
            turin.url(),
            format!(
                "https://kdsintf.amd.com/vcek/v1/Turin/{}?blSPL=10&teeSPL=00&snpSPL=27&ucodeSPL=28&fmcSPL=03",
                "cd".repeat(8)
            )
        );
        assert_eq!(
            DocKey::from(AmdCrl {
                generation: ProcessorGeneration::Milan,
                signer: AmdSigner::Asvk
            })
            .url(),
            "https://kdsintf.amd.com/vlek/v1/Milan/crl"
        );
        assert_eq!(
            DocKey::from(IntelPckCrl {
                ca: PckCa::Processor
            })
            .url(),
            "https://api.trustedservices.intel.com/sgx/certification/v4/pckcrl?ca=processor"
        );
    }

    #[test]
    fn keys_round_trip_through_json() {
        for key in [
            DocKey::from(IntelQeIdentity {}),
            DocKey::from(IntelTcbInfo {
                fmspc: "70a06d070000".into(),
            }),
            DocKey::from(AmdCrl {
                generation: ProcessorGeneration::Genoa,
                signer: AmdSigner::Ask,
            }),
        ] {
            let json = serde_json::to_string(&key).unwrap();
            assert_eq!(serde_json::from_str::<DocKey>(&json).unwrap(), key);
        }
    }
}
