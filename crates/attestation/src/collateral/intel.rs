//! Intel PCS collateral for TDX: TCB Info, the TD QE Identity, and the CRLs
//! of the PCK CAs and the SGX Root CA.

use serde::Deserialize;

use super::{refused, Collateral, Dates, Fmspc, PckCa};
use crate::error::Result;
use crate::platforms::tdx::dcap;

const INTEL_PCS: &str = "https://api.trustedservices.intel.com";
const INTEL_CERTS: &str = "https://certificates.trustedservices.intel.com";

/// Intel's TDX TCB Info for one platform (FMSPC).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TcbInfo {
    /// The JSON as Intel served it (its signature covers the raw bytes).
    pub json: Vec<u8>,
    pub fmspc: Fmspc,
    pub issue_date: i64,
    pub next_update: i64,
    pub evaluation_number: u64,
    /// The TCB Signing certificate, DER.
    pub signer: Vec<u8>,
}

/// Intel's TD Quoting Enclave identity.
#[derive(Debug)]
pub struct QeIdentity {
    pub identity: dcap::QeIdentity,
    pub issue_date: i64,
    pub next_update: i64,
    pub evaluation_number: u64,
    /// The TCB Signing certificate, DER.
    pub signer: Vec<u8>,
}

/// The CRL of an Intel PCK CA.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PckCrl {
    /// The CRL, DER.
    pub der: Vec<u8>,
    pub ca: PckCa,
    pub this_update: i64,
    pub next_update: i64,
    pub number: Option<u64>,
}

/// The CRL of the Intel SGX Root CA.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RootCrl {
    /// The CRL, DER.
    pub der: Vec<u8>,
    pub this_update: i64,
    pub next_update: i64,
    pub number: Option<u64>,
}

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

/// The body, its issueDate and its nextUpdate.
fn signed_body(json: &[u8], field: &str) -> Result<(SignedBody, i64, i64)> {
    let mut envelope: serde_json::Map<String, serde_json::Value> =
        serde_json::from_slice(json).map_err(|e| refused(format!("{field}: {e}")))?;
    let body = envelope
        .remove(field)
        .ok_or_else(|| refused(format!("no {field:?} object")))?;
    let body: SignedBody =
        serde_json::from_value(body).map_err(|e| refused(format!("{field}: {e}")))?;
    let time = |name: &str, value: &str| {
        chrono::DateTime::parse_from_rfc3339(value)
            .map(|t| t.timestamp())
            .map_err(|e| refused(format!("{field} {name} {value:?}: {e}")))
    };
    let issued = time("issueDate", &body.issue_date)?;
    let next = time("nextUpdate", &body.next_update)?;
    Ok((body, issued, next))
}

fn chain(issuer_chain: Option<&str>) -> Result<&[u8]> {
    issuer_chain
        .map(str::as_bytes)
        .ok_or_else(|| refused("no issuer chain"))
}

/// The first certificate of a verified issuer chain.
fn signer(chain: &[u8]) -> Result<Vec<u8>> {
    dcap::parse_pem_to_der(chain)?
        .into_iter()
        .next()
        .ok_or_else(|| refused("empty issuer chain"))
}

impl Collateral for TcbInfo {
    type Id = Fmspc;
    const NAMED_BY_EVIDENCE: bool = true;

    fn name(fmspc: &Fmspc) -> String {
        format!("tcb-info {}", hex::encode(fmspc))
    }

    fn url(fmspc: &Fmspc) -> String {
        format!(
            "{INTEL_PCS}/tdx/certification/v4/tcb?fmspc={}",
            hex::encode(fmspc)
        )
    }

    /// Signed by Intel's TCB Signing key (issuer chain to the pinned SGX Root
    /// CA), for TDX and this FMSPC.
    fn verify(json: &[u8], issuer_chain: Option<&str>, fmspc: &Fmspc) -> Result<Self> {
        let (body, issue_date, next_update) = signed_body(json, "tcbInfo")?;
        let chain = chain(issuer_chain)?;
        dcap::verify_tcb_info_signature(json, chain, issue_date)?;
        if body.id != "TDX" {
            return Err(refused(format!("TCB Info is for {:?}, not TDX", body.id)));
        }
        if body.fmspc.and_then(|f| hex::decode(f).ok()).as_deref() != Some(fmspc) {
            return Err(refused(format!(
                "TCB Info is not for FMSPC {}",
                hex::encode(fmspc)
            )));
        }
        Ok(Self {
            json: json.to_vec(),
            fmspc: *fmspc,
            issue_date,
            next_update,
            evaluation_number: body.tcb_evaluation_data_number,
            signer: signer(chain)?,
        })
    }

    fn dates(&self) -> Dates {
        Dates::window(
            self.issue_date,
            self.next_update,
            Some(self.evaluation_number),
        )
    }
}

impl Collateral for QeIdentity {
    type Id = ();

    fn name(_: &()) -> String {
        "qe-identity".into()
    }

    fn url(_: &()) -> String {
        format!("{INTEL_PCS}/tdx/certification/v4/qe/identity")
    }

    /// Signed by Intel's TCB Signing key, for the TD QE.
    fn verify(json: &[u8], issuer_chain: Option<&str>, _: &()) -> Result<Self> {
        let (body, issue_date, next_update) = signed_body(json, "enclaveIdentity")?;
        let chain = chain(issuer_chain)?;
        dcap::verify_qe_identity_signature(json, chain, issue_date)?;
        if body.id != "TD_QE" {
            return Err(refused(format!(
                "QE Identity is for {:?}, not TD_QE",
                body.id
            )));
        }
        Ok(Self {
            identity: dcap::parse_qe_identity(json)?,
            issue_date,
            next_update,
            evaluation_number: body.tcb_evaluation_data_number,
            signer: signer(chain)?,
        })
    }

    fn dates(&self) -> Dates {
        Dates::window(
            self.issue_date,
            self.next_update,
            Some(self.evaluation_number),
        )
    }
}

impl Collateral for PckCrl {
    type Id = PckCa;

    fn name(ca: &PckCa) -> String {
        format!("pck-crl {}", ca.name())
    }

    fn url(ca: &PckCa) -> String {
        format!("{INTEL_PCS}/sgx/certification/v4/pckcrl?ca={}", ca.name())
    }

    /// Signed by the PCK CA `ca`, which chains to the pinned SGX Root CA.
    /// DER or PEM.
    fn verify(crl: &[u8], issuer_chain: Option<&str>, &ca: &PckCa) -> Result<Self> {
        let pem = chain(issuer_chain)?;
        let issuers = dcap::parse_pem_to_der(pem)?;
        let issuer = issuers
            .first()
            .ok_or_else(|| refused("empty issuer chain"))?;
        let (der, this_update, next_update, number) = dcap::check_crl(crl, issuer, "PCK CRL")?;
        dcap::verify_signing_cert_chain(pem, this_update, ca.signer())?;
        Ok(Self {
            der,
            ca,
            this_update,
            next_update,
            number,
        })
    }

    fn dates(&self) -> Dates {
        Dates::window(self.this_update, self.next_update, self.number)
    }
}

impl Collateral for RootCrl {
    type Id = ();

    fn name(_: &()) -> String {
        "root-crl".into()
    }

    fn url(_: &()) -> String {
        format!("{INTEL_CERTS}/IntelSGXRootCA.der")
    }

    /// Signed by the bundled SGX Root CA.
    fn verify(crl: &[u8], _: Option<&str>, _: &()) -> Result<Self> {
        let (der, this_update, next_update, number) =
            dcap::check_crl(crl, dcap::INTEL_SGX_ROOT_CA, "Root CA CRL")?;
        Ok(Self {
            der,
            this_update,
            next_update,
            number,
        })
    }

    fn dates(&self) -> Dates {
        Dates::window(self.this_update, self.next_update, self.number)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const DIR: &str = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/test_data/collateral/2026-10-14/"
    );

    fn file(name: &str) -> Vec<u8> {
        std::fs::read(format!("{DIR}{name}")).unwrap()
    }

    fn text(name: &str) -> String {
        String::from_utf8(file(name)).unwrap()
    }

    const FMSPC: Fmspc = [0x70, 0xa0, 0x6d, 0x07, 0x00, 0x00];

    /// 2026-10-15T00:00:00Z.
    const NOW: i64 = 1_792_022_400;
    const CHAIN: &str = "tcb_signing_chain.pem";
    const PLATFORM_CHAIN: &str = "pck_crl_platform_chain.pem";

    fn tcb_info(name: &str, chain: Option<&str>) -> Result<TcbInfo> {
        TcbInfo::verify(&file(name), chain.map(text).as_deref(), &FMSPC)
    }

    fn qe(name: &str) -> Result<QeIdentity> {
        QeIdentity::verify(&file(name), Some(&text(CHAIN)), &())
    }

    fn pck(name: &str, chain: Option<&str>, ca: PckCa) -> Result<PckCrl> {
        PckCrl::verify(&file(name), chain.map(text).as_deref(), &ca)
    }

    fn tamper(name: &str, from: &str, to: &str) -> Vec<u8> {
        let s = text(name);
        assert!(s.contains(from), "fixture lacks {from:?}");
        s.replacen(from, to, 1).into_bytes()
    }

    fn flip_last(mut b: Vec<u8>) -> Vec<u8> {
        *b.last_mut().unwrap() ^= 1;
        b
    }

    #[test]
    fn tcb_info_verifies_for_its_fmspc_with_its_evaluation_number() {
        let info = tcb_info("tcb_info_70a06d070000.json", Some(CHAIN)).unwrap();
        assert_eq!(info.evaluation_number, 20);
        assert!(info.issue_date <= NOW && NOW <= info.next_update);
        let early = tcb_info("tcb_info_70a06d070000_early.json", Some(CHAIN)).unwrap();
        assert_eq!(early.evaluation_number, 22);
        let older = tcb_info("tcb_info_70a06d070000_eval21.json", Some(CHAIN)).unwrap();
        assert_eq!(older.evaluation_number, 21);
    }

    #[test]
    fn tampered_tcb_info_is_refused() {
        let chain = text(CHAIN);
        for bad in [
            tamper(
                "tcb_info_70a06d070000.json",
                "\"OutOfDate\"",
                "\"UpToDate\"",
            ),
            tamper(
                "tcb_info_70a06d070000.json",
                "\"signature\":\"",
                "\"signature\":\"00",
            ),
        ] {
            assert!(TcbInfo::verify(&bad, Some(&chain), &FMSPC).is_err());
        }
    }

    #[test]
    fn tcb_info_for_another_fmspc_or_without_its_chain_is_refused() {
        let json = file("tcb_info_70a06d070000.json");
        let other = [0x00, 0xa0, 0x6d, 0x08, 0x00, 0x00];
        assert!(TcbInfo::verify(&json, Some(&text(CHAIN)), &other).is_err());
        assert!(tcb_info("tcb_info_70a06d070000.json", None).is_err());
        assert!(tcb_info("tcb_info_70a06d070000.json", Some(PLATFORM_CHAIN)).is_err());
    }

    #[test]
    fn qe_identity_in_place_of_tcb_info_is_refused_and_vice_versa() {
        assert!(tcb_info("td_qe_identity.json", Some(CHAIN)).is_err());
        assert!(qe("tcb_info_70a06d070000.json").is_err());
    }

    #[test]
    fn qe_identity_verifies_and_an_expired_one_is_expired() {
        let current = qe("td_qe_identity.json").unwrap();
        assert!(current.issue_date <= NOW && NOW <= current.next_update);
        let old = qe("td_qe_identity_2026-03-16_eval18_expired.json").unwrap();
        assert_eq!(old.evaluation_number, 18);
        assert!(old.next_update < NOW);
    }

    #[test]
    fn tampered_qe_identity_is_refused() {
        let bad = tamper("td_qe_identity.json", "\"TD_QE\"", "\"QE\"");
        assert!(QeIdentity::verify(&bad, Some(&text(CHAIN)), &()).is_err());
    }

    #[test]
    fn pck_crls_verify_against_their_ca_in_pem_and_der() {
        use PckCa::{Platform, Processor};
        let from_pem = pck("pck_crl_platform.pem", Some(PLATFORM_CHAIN), Platform).unwrap();
        assert!(from_pem.this_update <= NOW && NOW <= from_pem.next_update);
        assert!(from_pem.der.starts_with(&[0x30]));
        assert!(pck("pck_crl_platform.der", Some(PLATFORM_CHAIN), Platform).is_ok());
        let processor_chain = Some("pck_crl_processor_chain.pem");
        assert!(pck("pck_crl_processor.pem", processor_chain, Processor).is_ok());
        assert!(pck("pck_crl_platform.pem", Some(PLATFORM_CHAIN), Processor).is_err());
        assert!(pck("pck_crl_platform.pem", processor_chain, Platform).is_err());
        assert!(pck("pck_crl_platform.pem", None, Platform).is_err());
    }

    #[test]
    fn an_old_pck_crl_verifies_but_is_expired() {
        let old = pck(
            "pck_crl_platform_2026-03-16_expired.der",
            Some(PLATFORM_CHAIN),
            PckCa::Platform,
        )
        .unwrap();
        let current = pck(
            "pck_crl_platform.der",
            Some(PLATFORM_CHAIN),
            PckCa::Platform,
        )
        .unwrap();
        assert!(old.next_update < NOW);
        assert!(old.this_update < current.this_update);
    }

    #[test]
    fn a_crl_with_a_bad_signature_is_refused() {
        let bad = flip_last(file("pck_crl_platform.der"));
        assert!(PckCrl::verify(&bad, Some(&text(PLATFORM_CHAIN)), &PckCa::Platform).is_err());
        assert!(RootCrl::verify(&flip_last(file("root_ca_crl.der")), None, &()).is_err());
    }

    #[test]
    fn the_root_crl_verifies_against_the_bundled_root_and_nothing_else() {
        let root = RootCrl::verify(&file("root_ca_crl.der"), None, &()).unwrap();
        assert!(root.this_update <= NOW && NOW <= root.next_update);
        assert!(RootCrl::verify(&file("pck_crl_platform.der"), None, &()).is_err());
    }

    #[test]
    fn malformed_bytes_are_refused() {
        let chain = text(CHAIN);
        for body in [Vec::new(), b"<html>503</html>".to_vec(), b"{}".to_vec()] {
            assert!(TcbInfo::verify(&body, Some(&chain), &FMSPC).is_err());
            assert!(QeIdentity::verify(&body, Some(&chain), &()).is_err());
            assert!(PckCrl::verify(&body, Some(&chain), &PckCa::Platform).is_err());
            assert!(RootCrl::verify(&body, None, &()).is_err());
        }
    }

    #[test]
    fn the_bundled_root_is_the_pinned_root() {
        // verify_signing_cert_chain pins the root key; the bundled root is
        // the certificate that chain ends in.
        assert!(dcap::verify_signing_cert_chain(&file(CHAIN), NOW, dcap::TCB_SIGNING).is_ok());
        let chain = dcap::parse_pem_to_der(&file(CHAIN)).unwrap();
        assert_eq!(chain[1], dcap::INTEL_SGX_ROOT_CA);
    }

    #[test]
    fn only_the_right_intel_certificate_may_sign() {
        let tcb = file(CHAIN);
        let platform = file(PLATFORM_CHAIN);
        let check = |pem: &[u8], signer| dcap::verify_signing_cert_chain(pem, NOW, signer).is_ok();
        assert!(check(&tcb, dcap::TCB_SIGNING));
        assert!(!check(&tcb, PckCa::Platform.signer()));
        assert!(check(&platform, PckCa::Platform.signer()));
        assert!(!check(&platform, PckCa::Processor.signer()));
        assert!(!check(&platform, dcap::TCB_SIGNING));
    }

    #[test]
    fn urls_name_the_pcs_paths() {
        assert_eq!(
            PckCrl::url(&PckCa::Processor),
            "https://api.trustedservices.intel.com/sgx/certification/v4/pckcrl?ca=processor"
        );
        assert_eq!(
            TcbInfo::url(&FMSPC),
            "https://api.trustedservices.intel.com/tdx/certification/v4/tcb?fmspc=70a06d070000"
        );
    }
}
