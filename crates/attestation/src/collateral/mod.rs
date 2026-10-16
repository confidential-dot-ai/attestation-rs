//! Collateral: the vendor-signed pieces a verifier uses besides the
//! evidence. Each piece implements [`Collateral`]: `url`, where the vendor
//! publishes it, and `verify`: parse, check the signature against the vendor
//! roots compiled into this crate, and check that it is the piece the
//! evidence names. The [`Store`] gets pieces from held copies, memory, disk
//! and the vendors, and verifies each on the way in.

// Without a platform there is no piece to store.
#![cfg_attr(
    not(any(
        feature = "snp",
        feature = "tdx",
        feature = "gcp-tdx",
        feature = "gcp-snp",
        feature = "nvidia-gpu"
    )),
    allow(dead_code)
)]

#[cfg(feature = "snp")]
mod amd;
#[cfg(not(target_arch = "wasm32"))]
pub(crate) mod disk;
#[cfg(any(feature = "gcp-tdx", feature = "gcp-snp"))]
mod gce;
#[cfg(feature = "tdx")]
mod intel;
#[cfg(feature = "nvidia-gpu")]
mod nvidia;
mod store;
#[cfg(not(target_arch = "wasm32"))]
pub(crate) mod vendor;

#[cfg(feature = "snp")]
pub use amd::{AmdCrl, Vcek};
#[cfg(any(feature = "gcp-tdx", feature = "gcp-snp"))]
pub use gce::GceEndorsement;
#[cfg(feature = "tdx")]
pub use intel::{PckCrl, QeIdentity, RootCrl, TcbInfo};
#[cfg(feature = "nvidia-gpu")]
pub use nvidia::NrasJwks;
pub use store::{CollateralUsed, Source, Store};

use crate::error::Result;

/// One piece of vendor-signed collateral: something we download, check
/// against the vendor's compiled-in roots, and that carries its own validity
/// dates.
pub trait Collateral: Sized {
    /// What picks the right piece: the FMSPC for TCB Info, the PCK CA for a
    /// PCK CRL, chip and TCB for a VCEK, `()` when there is only one.
    type Id;
    /// A vendor 404 for this piece means the evidence names something the
    /// vendor never issued, so the evidence is refused rather than retried.
    const NAMED_BY_EVIDENCE: bool = false;
    /// How a verdict names the piece, for example `tcb-info 70a06d070000`.
    fn name(id: &Self::Id) -> String;
    /// Where the vendor publishes it.
    fn url(id: &Self::Id) -> String;
    /// Parse `bytes`, check the signature against the compiled-in roots (via
    /// `issuer_chain` where the vendor sends one), and check that it is the
    /// piece `id` names.
    fn verify(bytes: &[u8], issuer_chain: Option<&str>, id: &Self::Id) -> Result<Self>;
    fn dates(&self) -> Dates;
}

/// A piece's own validity window and version, in Unix seconds.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct Dates {
    /// thisUpdate, issueDate, or notBefore.
    pub this_update: Option<i64>,
    /// nextUpdate, or notAfter. `None` when the piece does not expire.
    pub next_update: Option<i64>,
    /// CRL Number or tcbEvaluationDataNumber.
    pub version: Option<u64>,
}

impl Dates {
    pub fn window(this_update: i64, next_update: i64, version: Option<u64>) -> Self {
        Self {
            this_update: Some(this_update),
            next_update: Some(next_update),
            version,
        }
    }

    /// True when `now` is inside the window.
    pub fn current(&self, now: i64) -> bool {
        !self.this_update.is_some_and(|t| now < t) && !self.next_update.is_some_and(|t| now > t)
    }
}

/// A piece that does not verify: the evidence is not genuine.
#[cfg(any(
    feature = "snp",
    feature = "tdx",
    feature = "gcp-tdx",
    feature = "gcp-snp",
    feature = "nvidia-gpu"
))]
pub(crate) fn refused(why: impl std::fmt::Display) -> crate::error::AttestationError {
    crate::error::AttestationError::CertChainError(why.to_string())
}

/// AMD signs one CRL per generation for the certificates its ARK issues, at
/// two paths: the CRL for VCEKs and the CRL for VLEKs.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum AmdKey {
    Vcek,
    Vlek,
}

/// The Intel CA that issued a PCK certificate.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum PckCa {
    Platform,
    Processor,
}

impl PckCa {
    pub fn name(self) -> &'static str {
        match self {
            PckCa::Platform => "platform",
            PckCa::Processor => "processor",
        }
    }

    /// The Intel CA certificate that signs this CA's CRL.
    pub fn signer(self) -> &'static str {
        match self {
            PckCa::Platform => "Intel SGX PCK Platform CA",
            PckCa::Processor => "Intel SGX PCK Processor CA",
        }
    }
}

/// An Intel platform's FMSPC (Family-Model-Stepping-Platform-CustomSKU).
pub type Fmspc = [u8; 6];

/// The CRL Number extension, when it fits a u64.
#[cfg(any(feature = "snp", feature = "tdx"))]
pub(crate) fn crl_number(
    crl: &x509_parser::revocation_list::CertificateRevocationList,
) -> Option<u64> {
    let bytes = crl.crl_number()?.to_bytes_be();
    (bytes.len() <= 8).then(|| bytes.iter().fold(0u64, |n, b| n << 8 | u64::from(*b)))
}

impl Dates {
    /// True unless `self` is an older issue than `other`: a lower version,
    /// or the same version issued earlier.
    #[cfg_attr(target_arch = "wasm32", allow(dead_code))]
    pub(crate) fn not_older_than(&self, other: &Dates) -> bool {
        (self.version, self.this_update) >= (other.version, other.this_update)
    }
}

/// Save a vendor response for `url` in a cache directory, as the store does
/// after a fetch. For tests of programs that read the cache.
#[cfg(not(target_arch = "wasm32"))]
#[doc(hidden)]
pub fn save_to_cache_dir(
    dir: &std::path::Path,
    url: &str,
    body: &[u8],
    issuer_chain: Option<&str>,
) {
    disk::Disk::new(dir).write(url, body, issuer_chain);
}

#[cfg(test)]
mod tests {
    use super::Dates;

    fn dates(this: i64, next: i64, version: u64) -> Dates {
        Dates {
            this_update: Some(this),
            next_update: Some(next),
            version: Some(version),
        }
    }

    #[test]
    fn current_follows_the_window() {
        let d = dates(100, 200, 1);
        assert!(!d.current(99));
        assert!(d.current(100));
        assert!(d.current(200));
        assert!(!d.current(201));
        assert!(Dates::default().current(0));
    }

    #[test]
    fn a_higher_version_or_a_later_issue_is_newer() {
        assert!(dates(100, 200, 2).not_older_than(&dates(150, 250, 1)));
        assert!(!dates(150, 250, 1).not_older_than(&dates(100, 200, 2)));
        assert!(dates(150, 250, 1).not_older_than(&dates(100, 200, 1)));
        assert!(!dates(100, 200, 1).not_older_than(&dates(150, 250, 1)));
        assert!(dates(100, 200, 1).not_older_than(&dates(100, 200, 1)));
    }
}
