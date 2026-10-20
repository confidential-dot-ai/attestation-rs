use base64::engine::general_purpose::URL_SAFE_NO_PAD as BASE64URL;
use base64::Engine;
use sha2::{Digest, Sha256, Sha384};
use subtle::ConstantTimeEq;

/// Pad report_data to exactly `target_len` bytes.
/// Errors if input exceeds `target_len`.
pub fn pad_report_data(data: &[u8], target_len: usize) -> crate::error::Result<Vec<u8>> {
    if data.len() > target_len {
        return Err(crate::error::AttestationError::ReportDataTooLarge { max: target_len });
    }
    let mut padded = vec![0u8; target_len];
    padded[..data.len()].copy_from_slice(data);
    Ok(padded)
}

/// SHA-256 hash.
pub fn sha256(data: &[u8]) -> Vec<u8> {
    let mut hasher = Sha256::new();
    hasher.update(data);
    hasher.finalize().to_vec()
}

/// SHA-256 hash of two concatenated byte slices.
pub fn sha256_two(a: &[u8], b: &[u8]) -> Vec<u8> {
    let mut hasher = Sha256::new();
    hasher.update(a);
    hasher.update(b);
    hasher.finalize().to_vec()
}

/// SHA-384 hash.
pub fn sha384(data: &[u8]) -> Vec<u8> {
    let mut hasher = Sha384::new();
    hasher.update(data);
    hasher.finalize().to_vec()
}

/// Decode URL-safe base64, tolerating optional padding.
pub fn decode_base64url(input: &str) -> std::result::Result<Vec<u8>, base64::DecodeError> {
    BASE64URL.decode(input.trim_end_matches('='))
}

/// Strip trailing null bytes from a byte slice.
/// Returns a subslice without any trailing 0x00 bytes.
pub fn strip_trailing_nulls(data: &[u8]) -> &[u8] {
    let end = data.iter().rposition(|&b| b != 0).map_or(0, |i| i + 1);
    &data[..end]
}

/// Maximum allowed size for a single evidence field (1 MiB).
pub const MAX_EVIDENCE_FIELD_SIZE: usize = 1_048_576;

/// Validate that an evidence field does not exceed the size limit.
pub fn check_field_size(name: &str, len: usize) -> crate::error::Result<()> {
    if len > MAX_EVIDENCE_FIELD_SIZE {
        return Err(crate::error::AttestationError::EvidenceDeserialize(
            format!("field '{name}' too large: {len} bytes (max {MAX_EVIDENCE_FIELD_SIZE})"),
        ));
    }
    Ok(())
}

/// Check whether `data` looks like a PEM-encoded block.
///
/// Returns `true` if the (whitespace-trimmed) data starts with `-----BEGIN`.
pub fn is_pem(data: &[u8]) -> bool {
    let s = match std::str::from_utf8(data) {
        Ok(s) => s,
        Err(_) => return false,
    };
    s.trim_start().starts_with("-----BEGIN")
}

/// Decode a single PEM block into DER bytes, accepting any label.
///
/// Returns the DER payload of the first PEM block found. Returns an error if
/// the data is not valid PEM — callers should use [`is_pem`] first if they
/// need to distinguish PEM from raw DER.
pub fn decode_pem_to_der(data: &[u8]) -> crate::error::Result<Vec<u8>> {
    let parsed = pem::parse(data)
        .map_err(|e| crate::error::AttestationError::CertChainError(format!("PEM decode: {e}")))?;
    Ok(parsed.contents().to_vec())
}

/// Convert a Unix timestamp to the `x509_parser` time type used for
/// certificate and CRL validity checks.
#[cfg(any(feature = "snp", feature = "tdx"))]
pub fn asn1_time(unix_seconds: i64) -> crate::error::Result<x509_parser::time::ASN1Time> {
    x509_parser::time::ASN1Time::from_timestamp(unix_seconds).map_err(|e| {
        crate::error::AttestationError::InvalidParams(format!(
            "evaluation time {unix_seconds} out of range: {e}"
        ))
    })
}

/// Compare `actual` with a set of allowed values: `None` when no set was
/// given, otherwise whether `actual` equals one of them. Every value is
/// compared in constant time. An empty set never matches; params validation
/// refuses it ([`check_allowed_set`]).
pub fn match_any(actual: &[u8], allowed: Option<&[[u8; 48]]>) -> Option<bool> {
    allowed.map(|allowed| {
        allowed.iter().fold(false, |found, value| {
            found | constant_time_eq(actual, value)
        })
    })
}

/// An allowed set, when given, must not be empty: it could never match.
pub fn check_allowed_set(name: &str, allowed: Option<&[[u8; 48]]>) -> crate::error::Result<()> {
    if allowed.is_some_and(<[_]>::is_empty) {
        return Err(crate::error::AttestationError::InvalidParams(format!(
            "{name}: the allowed set is empty"
        )));
    }
    Ok(())
}

/// Compare two byte slices in constant time.
///
/// **Timing note:** The length check early-return leaks whether the lengths
/// differ, but this is necessary because `ct_eq` panics on mismatched lengths.
/// In all call sites the expected length is either fixed or publicly known
/// (e.g. 32-byte hashes, 64-byte report_data), so the length is not secret.
pub fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    a.ct_eq(b).into()
}

/// The JSON encodings of params values (`#[serde(with = ...)]`): bytes are
/// standard base64.
pub(crate) mod b64 {
    use base64::engine::general_purpose::STANDARD;
    use base64::Engine;
    use serde::de::Error;
    #[cfg(any(feature = "tdx", feature = "snp", feature = "nvidia-gpu"))]
    use serde::Serialize;
    use serde::{Deserialize, Deserializer, Serializer};

    fn decode<E: Error>(value: &str) -> Result<Vec<u8>, E> {
        STANDARD
            .decode(value)
            .map_err(|e| E::custom(format!("invalid base64: {e}")))
    }

    #[cfg(any(feature = "tdx", feature = "snp"))]
    fn decode_fixed<const N: usize, E: Error>(value: &str) -> Result<[u8; N], E> {
        decode(value)?
            .try_into()
            .map_err(|b: Vec<u8>| E::custom(format!("must be {N} bytes, got {}", b.len())))
    }

    /// Required bytes, including attached collateral bodies.
    pub mod vec {
        use super::*;
        pub fn serialize<S: Serializer>(value: &[u8], s: S) -> Result<S::Ok, S::Error> {
            s.serialize_str(&STANDARD.encode(value))
        }
        pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<Vec<u8>, D::Error> {
            decode(&String::deserialize(d)?)
        }
    }

    /// Optional bytes.
    #[cfg(any(feature = "tdx", feature = "snp", feature = "nvidia-gpu"))]
    pub mod bytes {
        use super::*;

        pub fn serialize<S: Serializer>(value: &Option<Vec<u8>>, s: S) -> Result<S::Ok, S::Error> {
            value.as_ref().map(|b| STANDARD.encode(b)).serialize(s)
        }

        pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<Option<Vec<u8>>, D::Error> {
            Option::<String>::deserialize(d)?
                .map(|v| decode(&v))
                .transpose()
        }
    }

    /// Optional allowed 48-byte values: one value or a non-empty array.
    #[cfg(any(feature = "tdx", feature = "snp"))]
    pub mod digests {
        use super::*;

        #[derive(Deserialize)]
        #[serde(untagged)]
        enum OneOrMany {
            One(String),
            Many(Vec<String>),
        }

        pub fn serialize<S: Serializer>(
            value: &Option<Vec<[u8; 48]>>,
            s: S,
        ) -> Result<S::Ok, S::Error> {
            value
                .as_ref()
                .map(|v| v.iter().map(|d| STANDARD.encode(d)).collect::<Vec<_>>())
                .serialize(s)
        }

        pub fn deserialize<'de, D: Deserializer<'de>>(
            d: D,
        ) -> Result<Option<Vec<[u8; 48]>>, D::Error> {
            let values = match Option::<OneOrMany>::deserialize(d)? {
                None => return Ok(None),
                Some(OneOrMany::One(v)) => vec![v],
                Some(OneOrMany::Many(vs)) => vs,
            };
            if values.is_empty() {
                return Err(D::Error::custom("the allowed set is empty"));
            }
            values
                .iter()
                .map(|v| decode_fixed(v))
                .collect::<Result<_, _>>()
                .map(Some)
        }
    }

    /// Required 48-byte values.
    #[cfg(feature = "snp")]
    pub mod digest_list {
        use super::*;

        pub fn serialize<S: Serializer>(value: &[[u8; 48]], s: S) -> Result<S::Ok, S::Error> {
            s.collect_seq(value.iter().map(|d| STANDARD.encode(d)))
        }

        pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<Vec<[u8; 48]>, D::Error> {
            Vec::<String>::deserialize(d)?
                .iter()
                .map(|v| decode_fixed(v))
                .collect()
        }
    }

    /// vTPM PCR pins: an object of index to 32 bytes. An index given twice
    /// is refused rather than keeping the last value; `null` is no pins.
    #[cfg(any(feature = "az-tdx", feature = "az-snp"))]
    pub mod pcrs {
        use std::collections::BTreeMap;

        use serde::de::{MapAccess, Visitor};

        use super::*;

        type Pins = BTreeMap<u8, [u8; 32]>;

        pub fn serialize<S: Serializer>(pins: &Pins, s: S) -> Result<S::Ok, S::Error> {
            s.collect_map(pins.iter().map(|(i, v)| (i, STANDARD.encode(v))))
        }

        pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<Pins, D::Error> {
            struct PinsVisitor;
            impl<'de> Visitor<'de> for PinsVisitor {
                type Value = Pins;
                fn expecting(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
                    f.write_str("an object of PCR index to base64 value")
                }
                fn visit_none<E: Error>(self) -> Result<Pins, E> {
                    Ok(Pins::new())
                }
                fn visit_some<D: Deserializer<'de>>(self, d: D) -> Result<Pins, D::Error> {
                    d.deserialize_map(self)
                }
                fn visit_map<A: MapAccess<'de>>(self, mut map: A) -> Result<Pins, A::Error> {
                    let mut pins = Pins::new();
                    while let Some((index, value)) = map.next_entry::<u8, String>()? {
                        let value = decode_fixed(&value)
                            .map_err(|e: A::Error| A::Error::custom(format!("PCR {index}: {e}")))?;
                        if pins.insert(index, value).is_some() {
                            return Err(A::Error::custom(format!(
                                "PCR {index} is pinned more than once"
                            )));
                        }
                    }
                    Ok(pins)
                }
            }
            d.deserialize_option(PinsVisitor)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_pad_report_data_exact() {
        let data = vec![0xAA; 64];
        let padded = pad_report_data(&data, 64).unwrap();
        assert_eq!(padded, data);
    }

    #[test]
    fn test_pad_report_data_short() {
        let data = vec![0xBB; 32];
        let padded = pad_report_data(&data, 64).unwrap();
        assert_eq!(&padded[..32], &data);
        assert_eq!(&padded[32..], &[0u8; 32]);
    }

    #[test]
    fn test_pad_report_data_too_large() {
        let data = vec![0xCC; 65];
        let result = pad_report_data(&data, 64);
        assert!(result.is_err());
    }

    #[test]
    fn test_strip_trailing_nulls() {
        assert_eq!(strip_trailing_nulls(b"hello\0\0\0"), b"hello");
        assert_eq!(strip_trailing_nulls(b"hello"), b"hello");
        assert_eq!(strip_trailing_nulls(b"\0\0\0"), b"" as &[u8]);
        assert_eq!(strip_trailing_nulls(b""), b"" as &[u8]);
        assert_eq!(strip_trailing_nulls(b"a\0b\0\0"), b"a\0b");
    }
}
