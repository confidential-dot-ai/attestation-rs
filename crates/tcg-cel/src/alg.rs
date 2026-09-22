use sha2::Digest as _;

/// A `TPM_ALG_ID` from the TCG Algorithm Registry: the `hashAlg` of a CEL digest.
///
/// The CEL CDDL names eight hash algorithms. Others are carried by value, with
/// the digest length the log declares, and cannot be replayed.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct HashAlg(pub u16);

impl HashAlg {
    pub const SHA1: Self = Self(0x0004);
    pub const SHA256: Self = Self(0x000B);
    pub const SHA384: Self = Self(0x000C);
    pub const SHA512: Self = Self(0x000D);
    pub const SM3_256: Self = Self(0x0012);
    pub const SHA3_256: Self = Self(0x0027);
    pub const SHA3_384: Self = Self(0x0028);
    pub const SHA3_512: Self = Self(0x0029);

    const KNOWN: [(Self, &'static str, usize); 8] = [
        (Self::SHA1, "sha1", 20),
        (Self::SHA256, "sha256", 32),
        (Self::SHA384, "sha384", 48),
        (Self::SHA512, "sha512", 64),
        (Self::SM3_256, "sm3_256", 32),
        (Self::SHA3_256, "sha3_256", 32),
        (Self::SHA3_384, "sha3_384", 48),
        (Self::SHA3_512, "sha3_512", 64),
    ];

    /// The digest length, for the algorithms the CEL CDDL names.
    pub fn digest_size(self) -> Option<usize> {
        Self::KNOWN
            .iter()
            .find(|(a, _, _)| *a == self)
            .map(|&(_, _, n)| n)
    }

    /// The CEL-JSON name (`sha256`), for the algorithms the CEL CDDL names.
    pub fn json_name(self) -> Option<&'static str> {
        Self::KNOWN
            .iter()
            .find(|(a, _, _)| *a == self)
            .map(|&(_, n, _)| n)
    }

    /// A CEL-JSON `hashAlg`: a CDDL name (`sha` is SHA-1), or the `0x000B` form.
    pub(crate) fn from_json(s: &str) -> Option<Self> {
        if s == "sha" {
            return Some(Self::SHA1);
        }
        if let Some(&(a, _, _)) = Self::KNOWN.iter().find(|(_, n, _)| *n == s) {
            return Some(a);
        }
        let hex4 = s.strip_prefix("0x").filter(|h| h.len() == 4)?;
        u16::from_str_radix(hex4, 16).ok().map(Self)
    }

    /// The CEL-JSON form this crate writes: the CDDL name, else `0x` and four hex digits.
    pub(crate) fn to_json(self) -> String {
        self.json_name()
            .map(str::to_string)
            .unwrap_or_else(|| format!("0x{:04X}", self.0))
    }

    /// `H(a || b)` in this bank, for the algorithms this crate can replay.
    pub(crate) fn extend(self, a: &[u8], b: &[u8]) -> Option<Vec<u8>> {
        fn h<D: sha2::Digest>(a: &[u8], b: &[u8]) -> Vec<u8> {
            let mut d = D::new();
            d.update(a);
            d.update(b);
            d.finalize().to_vec()
        }
        match self {
            Self::SHA256 => Some(h::<sha2::Sha256>(a, b)),
            Self::SHA384 => Some(h::<sha2::Sha384>(a, b)),
            Self::SHA512 => Some(h::<sha2::Sha512>(a, b)),
            _ => None,
        }
    }

    /// `H(data)` in this bank, for the algorithms this crate can replay.
    pub fn hash(self, data: &[u8]) -> Option<Vec<u8>> {
        match self {
            Self::SHA256 => Some(sha2::Sha256::digest(data).to_vec()),
            Self::SHA384 => Some(sha2::Sha384::digest(data).to_vec()),
            Self::SHA512 => Some(sha2::Sha512::digest(data).to_vec()),
            _ => None,
        }
    }
}

impl std::fmt::Display for HashAlg {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.to_json())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn json_names_follow_the_cddl() {
        assert_eq!(HashAlg::from_json("sha"), Some(HashAlg::SHA1));
        assert_eq!(HashAlg::from_json("sha384"), Some(HashAlg::SHA384));
        assert_eq!(HashAlg::from_json("0x000B"), Some(HashAlg::SHA256));
        assert_eq!(HashAlg::from_json("0x000b"), Some(HashAlg::SHA256));
        assert_eq!(HashAlg::from_json("0x00B"), None);
        assert_eq!(HashAlg::from_json("SHA256"), None);
        assert_eq!(HashAlg(0x0099).to_json(), "0x0099");
        assert_eq!(HashAlg::SM3_256.to_json(), "sm3_256");
        assert_eq!(HashAlg(0x0099).digest_size(), None);
    }
}
