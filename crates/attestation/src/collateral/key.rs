//! One key type for every piece of vendor collateral the verifier consumes.

use crate::types::{ProcessorGeneration, SnpTcb};
use serde::{Deserialize, Serialize};
use std::fmt;

/// Which Intel PCK CA issued a certificate, and therefore which PCK CRL applies.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum PckCa {
    Platform,
    Processor,
}

impl PckCa {
    pub fn as_str(self) -> &'static str {
        match self {
            PckCa::Platform => "platform",
            PckCa::Processor => "processor",
        }
    }
    pub fn parse(s: &str) -> Option<Self> {
        match s {
            "platform" => Some(PckCa::Platform),
            "processor" => Some(PckCa::Processor),
            _ => None,
        }
    }
}

/// An Intel FMSPC: twelve lowercase hex characters, validated on every
/// construction path (constructor, `Deserialize`, `TryFrom`), so no key can
/// carry a string that is not one.
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(try_from = "String", into = "String")]
pub struct Fmspc(String);

impl Fmspc {
    pub fn new(s: &str) -> Option<Self> {
        let lower = s.to_ascii_lowercase();
        (lower.len() == 12 && lower.bytes().all(|b| b.is_ascii_hexdigit())).then_some(Fmspc(lower))
    }
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl TryFrom<String> for Fmspc {
    type Error = String;
    fn try_from(s: String) -> Result<Self, String> {
        Fmspc::new(&s).ok_or_else(|| format!("{s:?} is not an FMSPC (twelve hex characters)"))
    }
}

impl From<Fmspc> for String {
    fn from(f: Fmspc) -> String {
        f.0
    }
}

impl fmt::Display for Fmspc {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

/// The artifact family, for policy (max age) and reporting.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CollateralKind {
    SnpVcek,
    SnpCertChain,
    SnpCrl,
    TdxTcbInfo,
    TdxQeIdentity,
    TdxPckCrl,
    TdxRootCrl,
    NrasJwks,
}

impl CollateralKind {
    pub const ALL: [CollateralKind; 8] = [
        CollateralKind::SnpVcek,
        CollateralKind::SnpCertChain,
        CollateralKind::SnpCrl,
        CollateralKind::TdxTcbInfo,
        CollateralKind::TdxQeIdentity,
        CollateralKind::TdxPckCrl,
        CollateralKind::TdxRootCrl,
        CollateralKind::NrasJwks,
    ];

    pub fn as_str(self) -> &'static str {
        match self {
            CollateralKind::SnpVcek => "snp_vcek",
            CollateralKind::SnpCertChain => "snp_cert_chain",
            CollateralKind::SnpCrl => "snp_crl",
            CollateralKind::TdxTcbInfo => "tdx_tcb_info",
            CollateralKind::TdxQeIdentity => "tdx_qe_identity",
            CollateralKind::TdxPckCrl => "tdx_pck_crl",
            CollateralKind::TdxRootCrl => "tdx_root_crl",
            CollateralKind::NrasJwks => "nras_jwks",
        }
    }

    /// Media type of the canonical bytes (section 10.1 of the profile).
    pub fn media_type(self) -> &'static str {
        match self {
            CollateralKind::SnpVcek => "application/pkix-cert",
            CollateralKind::SnpCertChain => "application/pem-certificate-chain",
            CollateralKind::SnpCrl | CollateralKind::TdxPckCrl | CollateralKind::TdxRootCrl => {
                "application/pkix-crl"
            }
            CollateralKind::TdxTcbInfo | CollateralKind::TdxQeIdentity => {
                "application/vnd.confidential-ai.pcs-signed+json"
            }
            CollateralKind::NrasJwks => "application/jwk-set+json",
        }
    }

    /// Whether the artifact carries its own validity window. A JWKS does not,
    /// so only the configured max age bounds it.
    pub fn has_validity(self) -> bool {
        !matches!(self, CollateralKind::NrasJwks)
    }

    /// Whether a copy may be kept on disk across restarts. Everything with a
    /// validity window qualifies: a stored copy is served only inside it.
    pub fn durable(self) -> bool {
        self.has_validity()
    }
}

/// Identity of one collateral artifact. Every field is typed, so a key can
/// name a URL, a disk path and a log line without string parsing anywhere.
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum CollateralKey {
    SnpVcek {
        generation: ProcessorGeneration,
        #[serde(with = "serde_hex_64")]
        chip_id: [u8; 64],
        tcb: SnpTcb,
    },
    SnpCertChain {
        generation: ProcessorGeneration,
    },
    SnpCrl {
        generation: ProcessorGeneration,
    },
    TdxTcbInfo {
        fmspc: Fmspc,
    },
    TdxQeIdentity {
        /// The TD QE (TDX endpoint) or the SGX QE.
        td: bool,
    },
    TdxPckCrl {
        ca: PckCa,
    },
    TdxRootCrl,
    NrasJwks {
        url: String,
    },
}

mod serde_hex_64 {
    use serde::{Deserialize, Deserializer, Serializer};
    pub fn serialize<S: Serializer>(v: &[u8; 64], s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(&hex::encode(v))
    }
    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<[u8; 64], D::Error> {
        let s = String::deserialize(d)?;
        let v = hex::decode(s).map_err(serde::de::Error::custom)?;
        <[u8; 64]>::try_from(v.as_slice())
            .map_err(|_| serde::de::Error::custom("chip_id is 64 bytes"))
    }
}

impl CollateralKey {
    pub fn kind(&self) -> CollateralKind {
        match self {
            CollateralKey::SnpVcek { .. } => CollateralKind::SnpVcek,
            CollateralKey::SnpCertChain { .. } => CollateralKind::SnpCertChain,
            CollateralKey::SnpCrl { .. } => CollateralKind::SnpCrl,
            CollateralKey::TdxTcbInfo { .. } => CollateralKind::TdxTcbInfo,
            CollateralKey::TdxQeIdentity { .. } => CollateralKind::TdxQeIdentity,
            CollateralKey::TdxPckCrl { .. } => CollateralKind::TdxPckCrl,
            CollateralKey::TdxRootCrl => CollateralKind::TdxRootCrl,
            CollateralKey::NrasJwks { .. } => CollateralKind::NrasJwks,
        }
    }

    /// A TCB Info key, refusing anything that is not an FMSPC.
    pub fn tdx_tcb_info(fmspc: &str) -> Option<Self> {
        Fmspc::new(fmspc).map(|fmspc| CollateralKey::TdxTcbInfo { fmspc })
    }

    /// The hex TCB string a VCEK is filed under: the four SPLs, plus the FMC
    /// SPL on Turin, since it is part of the KDS lookup.
    pub fn vcek_tcb_id(tcb: &SnpTcb) -> String {
        let mut key = format!(
            "{:02X}{:02X}{:02X}{:02X}",
            tcb.bootloader, tcb.tee, tcb.snp, tcb.microcode
        );
        if let Some(fmc) = tcb.fmc {
            key.push_str(&format!("{fmc:02X}"));
        }
        key
    }

    /// Stable, path-safe identifier: one segment per typed field.
    pub fn id(&self) -> String {
        match self {
            CollateralKey::SnpVcek {
                generation,
                chip_id,
                tcb,
            } => format!(
                "snp_vcek/{}/{}-{}",
                generation.product_name(),
                hex::encode(chip_id),
                Self::vcek_tcb_id(tcb)
            ),
            CollateralKey::SnpCertChain { generation } => {
                format!("snp_cert_chain/{}", generation.product_name())
            }
            CollateralKey::SnpCrl { generation } => {
                format!("snp_crl/{}", generation.product_name())
            }
            CollateralKey::TdxTcbInfo { fmspc } => format!("tdx_tcb_info/{fmspc}"),
            CollateralKey::TdxQeIdentity { td: true } => "tdx_qe_identity/td".to_string(),
            CollateralKey::TdxQeIdentity { td: false } => "tdx_qe_identity/sgx".to_string(),
            CollateralKey::TdxPckCrl { ca } => format!("tdx_pck_crl/{}", ca.as_str()),
            CollateralKey::TdxRootCrl => "tdx_root_crl".to_string(),
            CollateralKey::NrasJwks { url } => format!("nras_jwks/{}", hex::encode(url.as_bytes())),
        }
    }
}

impl fmt::Display for CollateralKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            CollateralKey::NrasJwks { url } => write!(f, "nras_jwks/{url}"),
            other => f.write_str(&other.id()),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ids_are_distinct_and_path_safe() {
        let tcb = SnpTcb {
            bootloader: 3,
            tee: 0,
            snp: 10,
            microcode: 27,
            fmc: None,
        };
        let a = CollateralKey::SnpVcek {
            generation: ProcessorGeneration::Genoa,
            chip_id: [0xab; 64],
            tcb,
        };
        let b = CollateralKey::SnpVcek {
            generation: ProcessorGeneration::Turin,
            chip_id: [0xab; 64],
            tcb: SnpTcb {
                fmc: Some(0x10),
                ..tcb
            },
        };
        assert_ne!(a.id(), b.id());
        assert!(a.id().ends_with("-03000A1B"));
        assert!(b.id().ends_with("-03000A1B10"));
        for k in [
            a,
            b,
            CollateralKey::SnpCertChain {
                generation: ProcessorGeneration::Milan,
            },
            CollateralKey::tdx_tcb_info("50806f000000").unwrap(),
            CollateralKey::TdxQeIdentity { td: true },
            CollateralKey::TdxPckCrl {
                ca: PckCa::Platform,
            },
            CollateralKey::TdxRootCrl,
            CollateralKey::NrasJwks {
                url: "https://nras.attestation.nvidia.com/.well-known/jwks.json".into(),
            },
        ] {
            let id = k.id();
            assert!(!id.contains(".."), "{id}");
            assert!(
                id.bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b"/-_.".contains(&b)),
                "{id}"
            );
            let json = serde_json::to_string(&k).unwrap();
            assert_eq!(serde_json::from_str::<CollateralKey>(&json).unwrap(), k);
        }
        assert!(CollateralKey::tdx_tcb_info("50806F000000").is_some());
        assert!(CollateralKey::tdx_tcb_info("../x").is_none());
        assert!(CollateralKey::tdx_tcb_info("50806f0000").is_none());
        let traversal = r#"{"kind":"tdx_tcb_info","fmspc":"../../../../tmp/x"}"#;
        assert!(
            serde_json::from_str::<CollateralKey>(traversal).is_err(),
            "deserialization validates too"
        );
        let upper = r#"{"kind":"tdx_tcb_info","fmspc":"50806F000000"}"#;
        assert_eq!(
            serde_json::from_str::<CollateralKey>(upper).unwrap().id(),
            "tdx_tcb_info/50806f000000"
        );
    }
}
