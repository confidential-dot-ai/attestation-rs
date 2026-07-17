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
        .map_err(|e| crate::error::AttestationError::CertFetchError(format!("PEM decode: {e}")))?;
    Ok(parsed.contents().to_vec())
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

/// Check a measurement register against an optional caller-supplied
/// reference value. Not supplied → `Ok(None)`; supplied and equal →
/// `Ok(Some(true))`; supplied and different → `MeasurementMismatch`,
/// failing verification. `Some(false)` is never produced.
pub(crate) fn check_expected(
    name: &'static str,
    actual: &[u8],
    expected: Option<&[u8]>,
) -> crate::error::Result<Option<bool>> {
    match expected {
        None => Ok(None),
        Some(expected) if constant_time_eq(actual, expected) => Ok(Some(true)),
        Some(_) => Err(crate::error::AttestationError::MeasurementMismatch(name)),
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
