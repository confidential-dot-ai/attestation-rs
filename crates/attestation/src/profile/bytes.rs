//! Byte strings on the wire: base64url without padding (section 4.10).

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use schemars::{json_schema, JsonSchema, Schema, SchemaGenerator};
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use std::borrow::Cow;
use std::fmt;

/// Variable-length bytes. `URL_SAFE_NO_PAD` rejects padding and the standard
/// alphabet on decode, so the encoding rule is enforced at parse time.
#[derive(Clone, PartialEq, Eq, Hash, Default)]
pub struct Bytes(pub Vec<u8>);

impl Bytes {
    pub fn len(&self) -> usize {
        self.0.len()
    }
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }
    pub fn as_slice(&self) -> &[u8] {
        &self.0
    }
    pub fn encode(&self) -> String {
        URL_SAFE_NO_PAD.encode(&self.0)
    }
    pub fn decode(s: &str) -> Result<Self, base64::DecodeError> {
        URL_SAFE_NO_PAD.decode(s).map(Bytes)
    }
}

impl fmt::Debug for Bytes {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Bytes({} bytes, {})", self.0.len(), hex::encode(&self.0))
    }
}

impl From<Vec<u8>> for Bytes {
    fn from(v: Vec<u8>) -> Self {
        Bytes(v)
    }
}

impl From<&[u8]> for Bytes {
    fn from(v: &[u8]) -> Self {
        Bytes(v.to_vec())
    }
}

impl AsRef<[u8]> for Bytes {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

impl Serialize for Bytes {
    fn serialize<S: Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(&self.encode())
    }
}

impl<'de> Deserialize<'de> for Bytes {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        let s = <Cow<'de, str>>::deserialize(d)?;
        Bytes::decode(&s).map_err(|e| serde::de::Error::custom(format!("base64url: {e}")))
    }
}

impl JsonSchema for Bytes {
    fn schema_name() -> Cow<'static, str> {
        "Base64Url".into()
    }
    fn json_schema(_: &mut SchemaGenerator) -> Schema {
        json_schema!({
            "type": "string",
            "description": "bytes, base64url without padding (RFC 4648 section 5), canonical trailing bits",
            // A tail of 2 bytes is 3 characters, the last with 2 zero bits;
            // a tail of 1 byte is 2 characters, the last with 4 zero bits.
            "pattern": "^(?:[A-Za-z0-9_-]{4})*(?:[A-Za-z0-9_-]{2}[AEIMQUYcgkosw048]|[A-Za-z0-9_-][AQgw])?$",
            "contentEncoding": "base64url"
        })
    }
}

/// Exactly `N` bytes; the length is part of the type, so a 31-byte
/// `bootseed` never reaches the verifier.
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct FixedBytes<const N: usize>(pub [u8; N]);

impl<const N: usize> FixedBytes<N> {
    pub const LEN: usize = N;
    pub fn as_slice(&self) -> &[u8] {
        &self.0
    }
    pub fn encode(&self) -> String {
        URL_SAFE_NO_PAD.encode(self.0)
    }
    /// Length of the base64url text for `N` bytes, without padding.
    pub const fn encoded_len() -> usize {
        N.div_ceil(3) * 4 - [0usize, 2, 1][N % 3]
    }
}

impl<const N: usize> Default for FixedBytes<N> {
    fn default() -> Self {
        FixedBytes([0u8; N])
    }
}

impl<const N: usize> fmt::Debug for FixedBytes<N> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "FixedBytes<{N}>({})", hex::encode(self.0))
    }
}

impl<const N: usize> From<[u8; N]> for FixedBytes<N> {
    fn from(v: [u8; N]) -> Self {
        FixedBytes(v)
    }
}

impl<const N: usize> AsRef<[u8]> for FixedBytes<N> {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

impl<const N: usize> TryFrom<&[u8]> for FixedBytes<N> {
    type Error = usize;
    fn try_from(v: &[u8]) -> Result<Self, usize> {
        <[u8; N]>::try_from(v).map(FixedBytes).map_err(|_| v.len())
    }
}

impl<const N: usize> Serialize for FixedBytes<N> {
    fn serialize<S: Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(&self.encode())
    }
}

impl<'de, const N: usize> Deserialize<'de> for FixedBytes<N> {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        let s = <Cow<'de, str>>::deserialize(d)?;
        let v = URL_SAFE_NO_PAD
            .decode(&*s)
            .map_err(|e| serde::de::Error::custom(format!("base64url: {e}")))?;
        FixedBytes::try_from(v.as_slice())
            .map_err(|got| serde::de::Error::custom(format!("expected {N} bytes, got {got}")))
    }
}

impl<const N: usize> JsonSchema for FixedBytes<N> {
    fn schema_name() -> Cow<'static, str> {
        format!("Base64UrlBytes{N}").into()
    }
    fn json_schema(_: &mut SchemaGenerator) -> Schema {
        // The final character carries the padding bits, which must be zero.
        let full = N / 3 * 4;
        let pattern = match N % 3 {
            0 => format!("^[A-Za-z0-9_-]{{{full}}}$"),
            1 => format!("^[A-Za-z0-9_-]{{{}}}[AQgw]$", full + 1),
            _ => format!("^[A-Za-z0-9_-]{{{}}}[AEIMQUYcgkosw048]$", full + 2),
        };
        json_schema!({
            "type": "string",
            "description": format!("exactly {N} bytes, base64url without padding"),
            "pattern": pattern,
            "contentEncoding": "base64url"
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn base64url_pattern_admits_exactly_the_canonical_encodings() {
        let schema = serde_json::to_value(schemars::schema_for!(Bytes)).unwrap();
        let re = regex::Regex::new(schema["pattern"].as_str().unwrap()).unwrap();
        for len in 0..=12usize {
            let bytes: Vec<u8> = (0..len as u8).map(|b| b.wrapping_mul(37) ^ 0xa5).collect();
            let text = Bytes(bytes).encode();
            assert!(re.is_match(&text), "{len} bytes: {text}");
            if let Some(last) = text.chars().last().filter(|_| len % 3 != 0) {
                // The same text with a non-zero bit below the data.
                let alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
                let i = alphabet.find(last).unwrap();
                let bumped = alphabet.chars().nth(i | 1).unwrap();
                let bad = format!("{}{bumped}", &text[..text.len() - 1]);
                assert!(!re.is_match(&bad), "{len} bytes: {bad}");
                assert!(Bytes::decode(&bad).is_err(), "the decoder agrees: {bad}");
            }
            assert!(!re.is_match(&format!("{text}=")), "no padding");
        }
        assert!(!re.is_match("A"), "a single character encodes no byte");
    }

    #[test]
    fn strict_base64url() {
        assert_eq!(Bytes::decode("AQID").unwrap().0, vec![1, 2, 3]);
        assert!(Bytes::decode("AQI=").is_err(), "padding is rejected");
        assert!(
            Bytes::decode("+/8").is_err(),
            "standard alphabet is rejected"
        );
        let b: Bytes = serde_json::from_str("\"AQID\"").unwrap();
        assert_eq!(serde_json::to_string(&b).unwrap(), "\"AQID\"");
    }

    #[test]
    fn fixed_length_enforced() {
        let ok: Result<FixedBytes<3>, _> = serde_json::from_str("\"AQID\"");
        assert!(ok.is_ok());
        let short: Result<FixedBytes<4>, _> = serde_json::from_str("\"AQID\"");
        assert!(short.is_err());
        assert_eq!(FixedBytes::<32>::encoded_len(), 43);
        assert_eq!(FixedBytes::<48>::encoded_len(), 64);
        assert_eq!(FixedBytes::<16>::encoded_len(), 22);
        assert_eq!(FixedBytes::<3>::encoded_len(), 4);
        assert_eq!(FixedBytes::<32>::default().encode().len(), 43);
        assert_eq!(FixedBytes::<48>::default().encode().len(), 64);
        assert!(Bytes::decode("AQ").is_ok());
        assert!(
            Bytes::decode("AR").is_err(),
            "non-zero trailing bits are rejected"
        );
        assert!(Bytes::decode("A").is_err(), "length 1 mod 4 is rejected");
    }
}
