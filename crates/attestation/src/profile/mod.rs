//! The CVM attestation profile v1: `docs/standard/cvm-attestation-v1.md`.
//!
//! Types here are the profile one to one. Evidence and policy parse fail-closed:
//! every structural rule in sections 4 and 13 is enforced by `validate` before a
//! verifier sees the value, and an unknown field inside any `cvm_*` object is an
//! error. The JSON Schemas under `schemas/` are generated from these types and
//! checked for drift in CI.

pub mod appraisal;
pub mod binding;
pub mod bytes;
pub mod cel;
pub mod cmw;
pub mod evidence;
pub mod keys;
pub mod policy;
pub mod registers;
pub mod schema;
pub mod strict;

pub use appraisal::*;
pub use bytes::{Bytes, FixedBytes};
pub use cmw::{CmwCollection, CmwEntry, CmwRecord};
pub use evidence::*;
pub use policy::*;

/// `eat_profile` of every evidence envelope (section 4.1).
pub const PROFILE_URI: &str = "tag:confidential.ai,2026:cvm#1";
/// `cvm_version` of this profile.
pub const CVM_VERSION: u32 = 1;
/// `eat_profile` of every result (section 12.1).
pub const EAR_PROFILE_URI: &str = "tag:ietf.org,2026:rats/ear#04";
/// Media type of the evidence envelope on the wire (RFC 9782).
pub const ENVELOPE_MEDIA_TYPE: &str =
    "application/eat-ucs+json; eat_profile=\"tag:confidential.ai,2026:cvm#1\"";
/// `__cmwc_t` of `cvm_endorsements` (section 10.1).
pub const ENDORSEMENTS_COLLECTION_TAG: &str = "tag:confidential.ai,2026:cvm-endorsements#1";

/// Media types of `cvm_report` (section 4.3).
pub const MEDIA_TYPE_SNP_REPORT: &str = "application/vnd.confidential-ai.sev-snp-report";
pub const MEDIA_TYPE_TDX_QUOTE: &str = "application/vnd.confidential-ai.tdx-quote";
/// Accepted on ingest only, never emitted.
pub const MEDIA_TYPE_TSM_REPORT: &str = "application/vnd.veraison.tsm-report+json";

/// Media types of endorsement entries (section 10.1).
pub const MEDIA_TYPE_PKIX_CERT: &str = "application/pkix-cert";
pub const MEDIA_TYPE_PKIX_CRL: &str = "application/pkix-crl";
pub const MEDIA_TYPE_PCS_SIGNED: &str = "application/vnd.confidential-ai.pcs-signed+json";
pub const MEDIA_TYPE_JWK_SET: &str = "application/jwk-set+json";

/// RFC 9999 indicator bits.
pub const CMW_IND_REFERENCE_VALUES: u32 = 1 << 0;
pub const CMW_IND_ENDORSEMENTS: u32 = 1 << 1;
pub const CMW_IND_EVIDENCE: u32 = 1 << 2;
pub const CMW_IND_ATTESTATION_RESULTS: u32 = 1 << 3;

/// `eat_nonce` bounds (section 4.1).
pub const NONCE_MIN: usize = 16;
pub const NONCE_MAX: usize = 64;

/// Section 6.1: a submodule's register array must not exceed this. Sixteen SNP
/// slots plus twenty-four vTPM PCRs plus four RTMRs is the largest sensible set.
pub const MAX_REGISTERS: usize = 64;

pub(crate) fn invalid(msg: impl Into<String>) -> crate::error::AttestationError {
    crate::error::AttestationError::ProfileEvidenceInvalid(msg.into())
}
