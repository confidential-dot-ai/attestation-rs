//! Intel PCS documents for TDX: TCB Info, the TD QE Identity, and the CRLs
//! of the PCK CAs and the SGX Root CA.

use serde::Deserialize;

use super::document::{
    Document, Info, IntelPckCrl, IntelQeIdentity, IntelRootCrl, IntelTcbInfo, Raw,
};
use crate::platforms::tdx::dcap::{self, Signer};

/// The fields of a signed TCB Info or QE Identity body that say what it is
/// and when it is valid.
#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct SignedBody {
    id: String,
    issue_date: String,
    next_update: String,
    tcb_evaluation_data_number: u64,
    #[serde(default)]
    fmspc: Option<String>,
}

fn signed_body(json: &[u8], field: &str) -> Result<(SignedBody, Info), String> {
    let mut envelope: serde_json::Map<String, serde_json::Value> =
        serde_json::from_slice(json).map_err(|e| format!("{field}: {e}"))?;
    let body = envelope
        .remove(field)
        .ok_or_else(|| format!("no {field:?} object"))?;
    let body: SignedBody = serde_json::from_value(body).map_err(|e| format!("{field}: {e}"))?;
    let time = |name: &str, value: &str| {
        chrono::DateTime::parse_from_rfc3339(value)
            .map(|t| t.timestamp())
            .map_err(|e| format!("{field} {name} {value:?}: {e}"))
    };
    let info = Info {
        this_update: Some(time("issueDate", &body.issue_date)?),
        next_update: Some(time("nextUpdate", &body.next_update)?),
        version: Some(body.tcb_evaluation_data_number),
    };
    Ok((body, info))
}

fn issuer_chain(raw: &Raw) -> Result<&[u8], String> {
    raw.issuer_chain
        .as_deref()
        .map(str::as_bytes)
        .ok_or_else(|| "no issuer chain".to_string())
}

impl Document for IntelTcbInfo {
    /// The JSON as Intel served it (its signature covers the raw bytes).
    type Value = Vec<u8>;

    /// Signed by Intel's TCB Signing key (issuer chain to the pinned SGX Root
    /// CA), for TDX and this FMSPC.
    fn check(&self, raw: &Raw) -> Result<(Vec<u8>, Info), String> {
        let (body, info) = signed_body(&raw.body, "tcbInfo")?;
        let issued = info.this_update.unwrap_or_default();
        dcap::verify_tcb_info_signature(&raw.body, issuer_chain(raw)?, issued)
            .map_err(|e| e.to_string())?;
        if body.id != "TDX" {
            return Err(format!("TCB Info is for {:?}, not TDX", body.id));
        }
        match body.fmspc {
            Some(f) if f.eq_ignore_ascii_case(&self.fmspc) => Ok((raw.body.clone(), info)),
            other => Err(format!(
                "TCB Info is for FMSPC {other:?}, not {}",
                self.fmspc
            )),
        }
    }
}

impl Document for IntelQeIdentity {
    type Value = dcap::QeIdentity;

    /// Signed by Intel's TCB Signing key, for the TD QE.
    fn check(&self, raw: &Raw) -> Result<(dcap::QeIdentity, Info), String> {
        let (body, info) = signed_body(&raw.body, "enclaveIdentity")?;
        let issued = info.this_update.unwrap_or_default();
        dcap::verify_qe_identity_signature(&raw.body, issuer_chain(raw)?, issued)
            .map_err(|e| e.to_string())?;
        if body.id != "TD_QE" {
            return Err(format!("QE Identity is for {:?}, not TD_QE", body.id));
        }
        let identity = dcap::parse_qe_identity(&raw.body).map_err(|e| e.to_string())?;
        Ok((identity, info))
    }
}

impl Document for IntelPckCrl {
    /// The CRL, DER.
    type Value = Vec<u8>;

    /// Signed by the PCK CA of this key, which chains to the pinned SGX Root
    /// CA.
    fn check(&self, raw: &Raw) -> Result<(Vec<u8>, Info), String> {
        let chain = dcap::parse_pem_to_der(issuer_chain(raw)?).map_err(|e| e.to_string())?;
        let issuer = chain.first().ok_or("empty issuer chain")?;
        let (der, info) =
            dcap::check_crl(&raw.body, issuer, "PCK CRL").map_err(|e| e.to_string())?;
        let issued = info.this_update.unwrap_or_default();
        dcap::verify_signing_cert_chain(issuer_chain(raw)?, issued, Signer::PckCa(self.ca))
            .map_err(|e| e.to_string())?;
        Ok((der, info))
    }
}

impl Document for IntelRootCrl {
    /// The CRL, DER.
    type Value = Vec<u8>;

    /// Signed by the bundled SGX Root CA.
    fn check(&self, raw: &Raw) -> Result<(Vec<u8>, Info), String> {
        dcap::check_crl(&raw.body, dcap::INTEL_SGX_ROOT_CA, "Root CA CRL")
            .map_err(|e| e.to_string())
    }
}

impl IntelPckCrl {
    /// The CRL of the CA that issued the PCK leaf in `pck_chain_der`.
    pub fn for_pck_chain(pck_chain_der: &[Vec<u8>]) -> crate::error::Result<Self> {
        Ok(Self {
            ca: dcap::determine_ca_type_from_der(pck_chain_der)?,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::collateral::document::{Freshness, PckCa};

    const DIR: &str = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/test_data/collateral/2026-10-14/"
    );

    fn file(name: &str) -> Vec<u8> {
        std::fs::read(format!("{DIR}{name}")).unwrap()
    }

    fn raw(body: &str, chain: Option<&str>) -> Raw {
        Raw {
            body: file(body),
            issuer_chain: chain.map(|c| String::from_utf8(file(c)).unwrap()),
        }
    }

    fn tcb_info() -> IntelTcbInfo {
        IntelTcbInfo {
            fmspc: "70a06d070000".into(),
        }
    }

    /// 2026-10-15T00:00:00Z.
    const NOW: i64 = 1_792_022_400;
    const CHAIN: Option<&str> = Some("tcb_signing_chain.pem");

    fn tamper(mut r: Raw, from: &str, to: &str) -> Raw {
        let s = String::from_utf8(r.body).unwrap();
        assert!(s.contains(from), "fixture lacks {from:?}");
        r.body = s.replacen(from, to, 1).into_bytes();
        r
    }

    fn flip_last(mut r: Raw) -> Raw {
        let last = r.body.len() - 1;
        r.body[last] ^= 1;
        r
    }

    #[test]
    fn tcb_info_checks_for_its_fmspc_with_its_evaluation_number() {
        let (_, info) = tcb_info()
            .check(&raw("tcb_info_70a06d070000.json", CHAIN))
            .unwrap();
        assert_eq!(info.version, Some(20));
        assert_eq!(info.freshness(NOW), Freshness::Current);
        let (_, early) = tcb_info()
            .check(&raw("tcb_info_70a06d070000_early.json", CHAIN))
            .unwrap();
        assert_eq!(early.version, Some(22));
        let (_, older) = tcb_info()
            .check(&raw("tcb_info_70a06d070000_eval21.json", CHAIN))
            .unwrap();
        assert!(early.not_older_than(&older) && !older.not_older_than(&early));
    }

    #[test]
    fn tcb_info_past_next_update_is_expired() {
        let (_, info) = tcb_info()
            .check(&raw("tcb_info_70a06d070000.json", CHAIN))
            .unwrap();
        assert_eq!(
            info.freshness(info.next_update.unwrap() + 1),
            Freshness::Expired
        );
    }

    #[test]
    fn tampered_tcb_info_is_refused() {
        let good = || raw("tcb_info_70a06d070000.json", CHAIN);
        for bad in [
            tamper(good(), "\"OutOfDate\"", "\"UpToDate\""),
            tamper(good(), "\"signature\":\"", "\"signature\":\"00"),
        ] {
            assert!(tcb_info().check(&bad).is_err());
        }
    }

    #[test]
    fn tcb_info_for_another_fmspc_or_without_its_chain_is_refused() {
        let other = IntelTcbInfo {
            fmspc: "00a06d080000".into(),
        };
        assert!(other
            .check(&raw("tcb_info_70a06d070000.json", CHAIN))
            .is_err());
        assert!(tcb_info()
            .check(&raw("tcb_info_70a06d070000.json", None))
            .is_err());
        assert!(tcb_info()
            .check(&raw(
                "tcb_info_70a06d070000.json",
                Some("pck_crl_platform_chain.pem")
            ))
            .is_err());
    }

    #[test]
    fn qe_identity_in_place_of_tcb_info_is_refused_and_vice_versa() {
        assert!(tcb_info()
            .check(&raw("td_qe_identity.json", CHAIN))
            .is_err());
        assert!(IntelQeIdentity {}
            .check(&raw("tcb_info_70a06d070000.json", CHAIN))
            .is_err());
    }

    #[test]
    fn qe_identity_checks_and_an_expired_one_is_expired() {
        let (_, info) = IntelQeIdentity {}
            .check(&raw("td_qe_identity.json", CHAIN))
            .unwrap();
        assert_eq!(info.freshness(NOW), Freshness::Current);
        let (_, old) = IntelQeIdentity {}
            .check(&raw("td_qe_identity_2026-03-16_eval18_expired.json", CHAIN))
            .unwrap();
        assert_eq!(old.version, Some(18));
        assert_eq!(old.freshness(NOW), Freshness::Expired);
        assert!(info.not_older_than(&old) && !old.not_older_than(&info));
    }

    #[test]
    fn tampered_qe_identity_is_refused() {
        let bad = tamper(raw("td_qe_identity.json", CHAIN), "\"TD_QE\"", "\"QE\"");
        assert!(IntelQeIdentity {}.check(&bad).is_err());
    }

    #[test]
    fn pck_crls_check_against_their_ca_in_pem_and_der() {
        let platform = IntelPckCrl {
            ca: PckCa::Platform,
        };
        let processor = IntelPckCrl {
            ca: PckCa::Processor,
        };
        let chain = Some("pck_crl_platform_chain.pem");
        let (pem_der, info) = platform.check(&raw("pck_crl_platform.pem", chain)).unwrap();
        assert_eq!(info.freshness(NOW), Freshness::Current);
        assert!(platform.check(&raw("pck_crl_platform.der", chain)).is_ok());
        assert!(pem_der.starts_with(&[0x30]));
        assert!(processor
            .check(&raw(
                "pck_crl_processor.pem",
                Some("pck_crl_processor_chain.pem")
            ))
            .is_ok());
        assert!(processor
            .check(&raw("pck_crl_platform.pem", chain))
            .is_err());
        assert!(platform
            .check(&raw(
                "pck_crl_platform.pem",
                Some("pck_crl_processor_chain.pem")
            ))
            .is_err());
        assert!(platform.check(&raw("pck_crl_platform.pem", None)).is_err());
    }

    #[test]
    fn an_old_pck_crl_checks_but_is_expired_and_older() {
        let platform = IntelPckCrl {
            ca: PckCa::Platform,
        };
        let chain = Some("pck_crl_platform_chain.pem");
        let (_, old) = platform
            .check(&raw("pck_crl_platform_2026-03-16_expired.der", chain))
            .unwrap();
        let (_, current) = platform.check(&raw("pck_crl_platform.der", chain)).unwrap();
        assert_eq!(old.freshness(NOW), Freshness::Expired);
        assert!(current.not_older_than(&old) && !old.not_older_than(&current));
    }

    #[test]
    fn a_crl_with_a_bad_signature_is_refused() {
        let platform = IntelPckCrl {
            ca: PckCa::Platform,
        };
        assert!(platform
            .check(&flip_last(raw(
                "pck_crl_platform.der",
                Some("pck_crl_platform_chain.pem")
            )))
            .is_err());
        assert!(IntelRootCrl {}
            .check(&flip_last(raw("root_ca_crl.der", None)))
            .is_err());
    }

    #[test]
    fn the_root_crl_checks_against_the_bundled_root_and_nothing_else() {
        let (_, info) = IntelRootCrl {}
            .check(&raw("root_ca_crl.der", None))
            .unwrap();
        assert_eq!(info.freshness(NOW), Freshness::Current);
        assert!(IntelRootCrl {}
            .check(&raw("pck_crl_platform.der", None))
            .is_err());
    }

    #[test]
    fn malformed_bytes_are_refused() {
        for body in [Vec::new(), b"<html>503</html>".to_vec(), b"{}".to_vec()] {
            let r = Raw {
                body,
                issuer_chain: CHAIN.map(|c| String::from_utf8(file(c)).unwrap()),
            };
            assert!(tcb_info().check(&r).is_err());
            assert!(IntelQeIdentity {}.check(&r).is_err());
            assert!(IntelPckCrl {
                ca: PckCa::Platform
            }
            .check(&r)
            .is_err());
            assert!(IntelRootCrl {}.check(&r).is_err());
        }
    }

    #[test]
    fn the_bundled_root_is_the_pinned_root() {
        // verify_signing_cert_chain pins the root key; the bundled root is
        // the certificate that chain ends in.
        assert!(dcap::verify_signing_cert_chain(
            &file("tcb_signing_chain.pem"),
            NOW,
            Signer::TcbSigning
        )
        .is_ok());
        let chain = dcap::parse_pem_to_der(&file("tcb_signing_chain.pem")).unwrap();
        assert_eq!(chain[1], dcap::INTEL_SGX_ROOT_CA);
    }

    #[test]
    fn only_the_right_intel_certificate_may_sign() {
        let tcb = file("tcb_signing_chain.pem");
        let platform = file("pck_crl_platform_chain.pem");
        let check = |pem: &[u8], signer| dcap::verify_signing_cert_chain(pem, NOW, signer).is_ok();
        assert!(check(&tcb, Signer::TcbSigning));
        assert!(!check(&tcb, Signer::PckCa(PckCa::Platform)));
        assert!(check(&platform, Signer::PckCa(PckCa::Platform)));
        assert!(!check(&platform, Signer::PckCa(PckCa::Processor)));
        assert!(!check(&platform, Signer::TcbSigning));
    }
}
