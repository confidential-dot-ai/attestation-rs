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

/// Compares a measured value against the caller's expected value (constant
/// time). A mismatch adds an [`Issue`](crate::types::Issue) to `issues`.
/// Returns `None` when no value was supplied.
#[cfg(any(feature = "snp", feature = "tdx"))]
pub(crate) fn compare(
    issues: &mut Vec<crate::types::Issue>,
    check: crate::types::Check,
    actual: &[u8],
    expected: Option<&[u8]>,
) -> Option<bool> {
    let expected = expected?;
    let matched = constant_time_eq(actual, expected);
    if !matched {
        issues.push(crate::types::Issue::mismatch(check, [expected], actual));
    }
    Some(matched)
}

/// Adds an `Unanswerable` issue for every value in `params` the platform
/// could not compare (its `*_match` is `None`), e.g. an RTMR pin on SEV-SNP
/// evidence. Each platform verifier calls this last.
#[cfg(any(feature = "snp", feature = "tdx"))]
pub(crate) fn add_unanswered_issues(
    params: &crate::types::VerifyParams,
    result: &mut crate::types::VerificationResult,
) {
    use crate::types::{Check, Issue, Problem};
    let checks = [
        (
            Check::LaunchDigest,
            params.expected_launch_digest.is_some(),
            result.launch_digest_match,
        ),
        (
            Check::Mrtd,
            params.expected_mrtd.is_some(),
            result.mrtd_match,
        ),
        (
            Check::Rtmr(0),
            params.expected_rtmr0.is_some(),
            result.rtmr0_match,
        ),
        (
            Check::Rtmr(1),
            params.expected_rtmr1.is_some(),
            result.rtmr1_match,
        ),
        (
            Check::Rtmr(2),
            params.expected_rtmr2.is_some(),
            result.rtmr2_match,
        ),
        (
            Check::Rtmr(3),
            params.expected_rtmr3.is_some(),
            result.rtmr3_match,
        ),
        (
            Check::ReportData,
            params.expected_report_data.is_some(),
            result.report_data_match,
        ),
        (
            Check::InitData,
            params.expected_init_data_hash.is_some(),
            result.init_data_match,
        ),
    ];
    for (check, supplied, matched) in checks {
        if supplied && matched.is_none() {
            result.issues.push(Issue {
                check,
                problem: Problem::Unanswerable,
            });
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
