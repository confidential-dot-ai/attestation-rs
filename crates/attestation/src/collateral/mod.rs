//! Collateral: the vendor-signed pieces a verifier needs besides the
//! evidence. Each piece is a plain type with `url(..)`, where the vendor
//! publishes it, and `verify(..)`: parse, check the signature against the
//! vendor roots compiled into this crate, and check that it is the piece the
//! evidence names. The [`Store`] gets pieces from held copies, memory, disk
//! and the vendors, and verifies each on the way in.

#[cfg(feature = "snp")]
mod amd;
// Without a platform there is no piece to store.
#[cfg_attr(
    not(any(
        feature = "snp",
        feature = "tdx",
        feature = "gcp-tdx",
        feature = "gcp-snp",
        feature = "nvidia-gpu"
    )),
    allow(dead_code)
)]
#[cfg(not(target_arch = "wasm32"))]
pub(crate) mod disk;
#[cfg(any(feature = "gcp-tdx", feature = "gcp-snp"))]
mod gce;
#[cfg(feature = "tdx")]
mod intel;
#[cfg(feature = "nvidia-gpu")]
mod nvidia;
#[cfg_attr(
    not(any(
        feature = "snp",
        feature = "tdx",
        feature = "gcp-tdx",
        feature = "gcp-snp",
        feature = "nvidia-gpu"
    )),
    allow(dead_code)
)]
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

/// Why a piece of collateral was refused: it does not parse, its signature
/// does not verify, or it is not the piece the evidence names.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Refused(pub String);

impl std::fmt::Display for Refused {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

impl std::error::Error for Refused {}

impl From<crate::error::AttestationError> for Refused {
    fn from(e: crate::error::AttestationError) -> Self {
        Self(e.to_string())
    }
}

impl From<String> for Refused {
    fn from(why: String) -> Self {
        Self(why)
    }
}

impl From<&str> for Refused {
    fn from(why: &str) -> Self {
        Self(why.into())
    }
}

/// AMD signs one CRL per generation for the certificates its ARK issues, at
/// two paths: for VCEKs (ASK) and for VLEKs (ASVK).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum AmdSigner {
    Ask,
    Asvk,
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
}

/// The TEE a GCE launch endorsement is for.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum GceTee {
    Tdx,
    SevSnp,
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

/// A piece's own validity window and version, in Unix seconds.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub(crate) struct Dates {
    /// thisUpdate, issueDate, or notBefore.
    pub this_update: Option<i64>,
    /// nextUpdate, or notAfter. `None` when the piece does not expire.
    pub next_update: Option<i64>,
    /// CRL Number or tcbEvaluationDataNumber.
    pub version: Option<u64>,
}

impl Dates {
    pub fn current(&self, now: i64) -> bool {
        !self.this_update.is_some_and(|t| now < t) && !self.next_update.is_some_and(|t| now > t)
    }

    /// True unless `self` is an older issue than `other`: a lower version,
    /// or the same version issued earlier.
    pub fn not_older_than(&self, other: &Dates) -> bool {
        (self.version, self.this_update) >= (other.version, other.this_update)
    }
}

/// What the store needs to know about every piece.
#[cfg_attr(
    not(any(
        feature = "snp",
        feature = "tdx",
        feature = "gcp-tdx",
        feature = "gcp-snp",
        feature = "nvidia-gpu"
    )),
    allow(dead_code)
)]
pub(crate) trait Dated {
    fn dates(&self) -> Dates;
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
