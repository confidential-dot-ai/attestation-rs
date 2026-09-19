//! Sections 4.8 and 4.9: runtime event records and the `ats-mr-v1` commitment.
//!
//! Everything here is a pure function over bytes so the attester, the verifier
//! and the vector script agree byte for byte. Vectors: Appendix B.

use sha2::{Digest, Sha384};

/// Registers in an `ats-mr-v1` bank.
pub const REG_COUNT: usize = 16;
/// Slots 0 to 3 keep the TDX RTMR semantics; 4 to 15 are workload slots.
pub const FIRST_WORKLOAD_SLOT: u8 = 4;
/// Slot the boot record is extended into.
pub const BOOT_SLOT: u8 = 3;
/// The genesis seed, `SHA-384("ats-mr-v1/seed")`.
pub const SEED: [u8; 48] = [
    0x60, 0xcd, 0xca, 0xea, 0xc3, 0xf1, 0x5a, 0x96, 0xcb, 0x2a, 0x1b, 0x85, 0xd4, 0x2c, 0x5a, 0x4d,
    0x12, 0x9f, 0xce, 0xd6, 0x54, 0x35, 0x04, 0x4c, 0x92, 0x50, 0xfd, 0xff, 0xef, 0x98, 0x98, 0x4c,
    0xc3, 0xbd, 0x42, 0x09, 0x72, 0xc3, 0xaf, 0x58, 0x29, 0x5e, 0x0f, 0x61, 0xba, 0x21, 0xe4, 0xa7,
];
/// The pinned commitment header: `ATS-MR-1`, version 1, alg 1 (SHA-384),
/// reg_count 16, flags 0, four reserved zero bytes.
pub const HEADER16: [u8; 16] = *b"ATS-MR-1\x01\x01\x10\x00\x00\x00\x00\x00";
/// CEL content type of a c8s runtime event (section 4.8): value 200, name `cvm`.
pub const CEL_CONTENT_TYPE_CVM: u64 = 200;
pub const CEL_CONTENT_NAME_CVM: &str = "cvm";
/// TPM_ALG_SHA384, the `hashAlg` of every c8s record digest.
pub const TPM_ALG_SHA384: u64 = 0x000C;
/// Domain and operations of the records the profile itself defines.
pub const DOMAIN_ATS: &str = "ats";
pub const OP_BOOT: &str = "boot";
pub const OP_CLAIM: &str = "claim";
/// `owner` and `purpose` of a claim record are at most this many bytes of UTF-8.
pub const CLAIM_STRING_MAX: usize = 255;

fn sha384(parts: &[&[u8]]) -> [u8; 48] {
    let mut h = Sha384::new();
    for p in parts {
        h.update(p);
    }
    h.finalize().into()
}

/// `R[i] = SHA-384(zeros48 || "ats-mr-v1/genesis" || seed || u8(i))`.
pub fn genesis(i: u8, seed: &[u8; 48]) -> [u8; 48] {
    sha384(&[&[0u8; 48], b"ats-mr-v1/genesis", seed, &[i]])
}

/// `R[i] = SHA-384(R[i] || d)`.
pub fn extend(r: &[u8; 48], d: &[u8; 48]) -> [u8; 48] {
    sha384(&[r, d])
}

/// `C = SHA-384("ats-mr-v1/commit" || R[0] || ... || R[15] || u64le(chain_len) || caller_data)`.
pub fn commit(regs: &[[u8; 48]; REG_COUNT], chain_len: u64, caller_data: &[u8; 64]) -> [u8; 48] {
    let mut h = Sha384::new();
    h.update(b"ats-mr-v1/commit");
    for r in regs {
        h.update(r);
    }
    h.update(chain_len.to_le_bytes());
    h.update(caller_data);
    h.finalize().into()
}

/// `report_data = header16 || C`, 64 bytes exactly.
pub fn report_data(header16: &[u8; 16], c: &[u8; 48]) -> [u8; 64] {
    let mut out = [0u8; 64];
    out[..16].copy_from_slice(header16);
    out[16..].copy_from_slice(c);
    out
}

/// Bare-bones deterministic CBOR (RFC 8949 section 4.2.1) for the record shapes
/// the profile defines. Lengths above 65535 never occur in those shapes.
pub mod cbor {
    fn head(major: u8, n: u64, out: &mut Vec<u8>) {
        match n {
            0..=23 => out.push(major << 5 | n as u8),
            24..=0xff => {
                out.push(major << 5 | 24);
                out.push(n as u8);
            }
            0x100..=0xffff => {
                out.push(major << 5 | 25);
                out.extend_from_slice(&(n as u16).to_be_bytes());
            }
            0x1_0000..=0xffff_ffff => {
                out.push(major << 5 | 26);
                out.extend_from_slice(&(n as u32).to_be_bytes());
            }
            _ => {
                out.push(major << 5 | 27);
                out.extend_from_slice(&n.to_be_bytes());
            }
        }
    }
    pub fn uint(n: u64, out: &mut Vec<u8>) {
        head(0, n, out);
    }
    pub fn bstr(b: &[u8], out: &mut Vec<u8>) {
        head(2, b.len() as u64, out);
        out.extend_from_slice(b);
    }
    pub fn tstr(s: &str, out: &mut Vec<u8>) {
        head(3, s.len() as u64, out);
        out.extend_from_slice(s.as_bytes());
    }
    pub fn array_head(n: usize, out: &mut Vec<u8>) {
        head(4, n as u64, out);
    }
    /// Map head; callers write keys in ascending numeric order, which for
    /// unsigned integer keys is the deterministic order (shorter encoding first,
    /// then bytewise).
    pub fn map_head(n: usize, out: &mut Vec<u8>) {
        head(5, n as u64, out);
    }
}

/// Content bytes of one c8s event: the deterministic CBOR map
/// `{0: domain, 1: operation, 2: content_digest, 3: content?}` (section 4.8).
pub fn event_content(
    domain: &str,
    operation: &str,
    content_digest: &[u8; 48],
    content: Option<&[u8]>,
) -> Vec<u8> {
    let mut out = Vec::with_capacity(
        64 + domain.len() + operation.len() + content.map_or(0, |c| c.len() + 3),
    );
    cbor::map_head(3 + usize::from(content.is_some()), &mut out);
    cbor::uint(0, &mut out);
    cbor::tstr(domain, &mut out);
    cbor::uint(1, &mut out);
    cbor::tstr(operation, &mut out);
    cbor::uint(2, &mut out);
    cbor::bstr(content_digest, &mut out);
    if let Some(c) = content {
        cbor::uint(3, &mut out);
        cbor::bstr(c, &mut out);
    }
    out
}

/// The record digest `d = SHA-384(content_bytes)`, the value that is extended.
pub fn record_digest(content_bytes: &[u8]) -> [u8; 48] {
    sha384(&[content_bytes])
}

/// The boot record: domain `ats`, operation `boot`, `content_digest = SHA-384(bootseed)`,
/// no content (section 4.9).
pub fn boot_record(bootseed: &[u8; 32]) -> Vec<u8> {
    event_content(DOMAIN_ATS, OP_BOOT, &sha384(&[bootseed]), None)
}

/// Body of a claim record: the deterministic CBOR map `{0: owner, 1: purpose}`.
/// `None` when either string exceeds [`CLAIM_STRING_MAX`] bytes.
pub fn claim_body(owner: &str, purpose: &str) -> Option<Vec<u8>> {
    if owner.len() > CLAIM_STRING_MAX || purpose.len() > CLAIM_STRING_MAX {
        return None;
    }
    let mut out = Vec::with_capacity(8 + owner.len() + purpose.len());
    cbor::map_head(2, &mut out);
    cbor::uint(0, &mut out);
    cbor::tstr(owner, &mut out);
    cbor::uint(1, &mut out);
    cbor::tstr(purpose, &mut out);
    Some(out)
}

/// The claim record that opens a workload slot: domain `ats`, operation `claim`,
/// content the claim body and its digest (section 4.9).
pub fn claim_record(owner: &str, purpose: &str) -> Option<Vec<u8>> {
    let body = claim_body(owner, purpose)?;
    Some(event_content(
        DOMAIN_ATS,
        OP_CLAIM,
        &sha384(&[&body]),
        Some(&body),
    ))
}

/// One CEL-CBOR record of content type `cvm`:
/// `{0: recnum, 1: slot, 3: [{0: 12, 1: d}], 200: content}` with `content` a byte string.
pub fn cel_record(recnum: u64, slot: u8, d: &[u8; 48], content: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(content.len() + 70);
    cbor::map_head(4, &mut out);
    cbor::uint(0, &mut out);
    cbor::uint(recnum, &mut out);
    cbor::uint(1, &mut out);
    cbor::uint(u64::from(slot), &mut out);
    cbor::uint(3, &mut out);
    cbor::array_head(1, &mut out);
    cbor::map_head(2, &mut out);
    cbor::uint(0, &mut out);
    cbor::uint(TPM_ALG_SHA384, &mut out);
    cbor::uint(1, &mut out);
    cbor::bstr(d, &mut out);
    cbor::uint(CEL_CONTENT_TYPE_CVM, &mut out);
    cbor::bstr(content, &mut out);
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn seed_and_header_are_the_published_constants() {
        assert_eq!(SEED, sha384(&[b"ats-mr-v1/seed"]));
        assert_eq!(&HEADER16[..8], b"ATS-MR-1");
        assert_eq!(HEADER16[8..], [1, 1, 16, 0, 0, 0, 0, 0]);
    }

    #[test]
    fn cbor_heads() {
        let mut v = Vec::new();
        cbor::uint(23, &mut v);
        cbor::uint(24, &mut v);
        cbor::uint(200, &mut v);
        cbor::uint(256, &mut v);
        cbor::uint(65536, &mut v);
        assert_eq!(
            v,
            [0x17, 0x18, 0x18, 0x18, 0xc8, 0x19, 0x01, 0x00, 0x1a, 0, 1, 0, 0]
        );
        let mut b = Vec::new();
        cbor::bstr(&[0u8; 82], &mut b);
        assert_eq!(&b[..2], &[0x58, 0x52]);
    }

    #[test]
    fn claim_strings_bounded() {
        assert!(claim_body(&"a".repeat(256), "x").is_none());
        assert!(claim_body("x", &"a".repeat(255)).is_some());
    }
}
