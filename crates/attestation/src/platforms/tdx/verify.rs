use base64::{engine::general_purpose::STANDARD as BASE64, Engine};
use p256::ecdsa::signature::hazmat::PrehashVerifier;
use p256::ecdsa::{Signature, VerifyingKey};
use scroll::Pread;

use crate::collateral::TdxCollateralProvider;
use crate::error::{AttestationError, Result};
use crate::platforms::vendor_helpers;
use crate::types::{
    DcapVerificationStatus, TdxResult, VendorParams, VendorResult, VerifyParams, VerifyResult,
    VerifyTdx,
};

use super::evidence::TdxEvidence;

/// TDX Quote header (48 bytes).
#[derive(Debug, Clone)]
pub struct QuoteHeader {
    pub version: u16,
    pub att_key_type: u16,
    pub tee_type: u32,
    pub reserved: [u8; 2],
    pub vendor_id: [u8; 16],
    pub user_data: [u8; 20],
}

/// TDX Quote Report Body (v4/v5 compatible).
#[derive(Debug, Clone)]
pub struct TdxReportBody {
    pub tee_tcb_svn: [u8; 16],
    pub mr_seam: [u8; 48],
    pub mrsigner_seam: [u8; 48],
    pub seam_attributes: [u8; 8],
    pub td_attributes: [u8; 8],
    pub xfam: [u8; 8],
    pub mr_td: [u8; 48],
    pub mr_config_id: [u8; 48],
    pub mr_owner: [u8; 48],
    pub mr_owner_config: [u8; 48],
    pub rtmr_0: [u8; 48],
    pub rtmr_1: [u8; 48],
    pub rtmr_2: [u8; 48],
    pub rtmr_3: [u8; 48],
    pub report_data: [u8; 64],
    /// Additional TCB SVN for TDX 1.5 (present only in V5 body_type=3).
    pub tee_tcb_svn2: Option<[u8; 16]>,
    /// Service TD measurement for TDX 1.5 TD Partitioning (present only in V5 body_type=3).
    pub mr_servicetd: Option<[u8; 48]>,
}

/// Parsed TDX quote (supports v4 and v5 formats).
#[derive(Debug, Clone)]
pub struct TdxQuote {
    pub header: QuoteHeader,
    pub body: TdxReportBody,
    pub quote_version: QuoteVersion,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum QuoteVersion {
    V4,
    V5Tdx10,
    V5Tdx15,
}

pub(crate) const QUOTE_HEADER_SIZE: usize = 48;
pub(crate) const REPORT_BODY_SIZE: usize = 584;

impl QuoteHeader {
    pub fn from_bytes(data: &[u8]) -> Result<Self> {
        if data.len() < QUOTE_HEADER_SIZE {
            return Err(AttestationError::QuoteParseFailed(format!(
                "quote header too short: {} bytes",
                data.len()
            )));
        }

        let version = data
            .pread_with::<u16>(0, scroll::LE)
            .map_err(|e| AttestationError::QuoteParseFailed(format!("version: {e}")))?;
        let att_key_type = data
            .pread_with::<u16>(2, scroll::LE)
            .map_err(|e| AttestationError::QuoteParseFailed(format!("att_key_type: {e}")))?;
        let tee_type = data
            .pread_with::<u32>(4, scroll::LE)
            .map_err(|e| AttestationError::QuoteParseFailed(format!("tee_type: {e}")))?;

        let mut reserved = [0u8; 2];
        reserved.copy_from_slice(&data[8..10]);

        let mut vendor_id = [0u8; 16];
        vendor_id.copy_from_slice(&data[12..28]);

        let mut user_data = [0u8; 20];
        user_data.copy_from_slice(&data[28..48]);

        Ok(Self {
            version,
            att_key_type,
            tee_type,
            reserved,
            vendor_id,
            user_data,
        })
    }
}

impl TdxReportBody {
    pub fn from_bytes(data: &[u8]) -> Result<Self> {
        if data.len() < REPORT_BODY_SIZE {
            return Err(AttestationError::QuoteParseFailed(format!(
                "report body too short: {} bytes, expected {}",
                data.len(),
                REPORT_BODY_SIZE
            )));
        }

        let mut offset = 0;

        macro_rules! read_bytes {
            ($size:expr) => {{
                let mut buf = [0u8; $size];
                buf.copy_from_slice(&data[offset..offset + $size]);
                offset += $size;
                buf
            }};
        }

        let tee_tcb_svn = read_bytes!(16);
        let mr_seam = read_bytes!(48);
        let mrsigner_seam = read_bytes!(48);
        let seam_attributes = read_bytes!(8);
        let td_attributes = read_bytes!(8);
        let xfam = read_bytes!(8);
        let mr_td = read_bytes!(48);
        let mr_config_id = read_bytes!(48);
        let mr_owner = read_bytes!(48);
        let mr_owner_config = read_bytes!(48);
        let rtmr_0 = read_bytes!(48);
        let rtmr_1 = read_bytes!(48);
        let rtmr_2 = read_bytes!(48);
        let rtmr_3 = read_bytes!(48);
        let report_data = read_bytes!(64);

        // TDX 1.5 extra fields (64 bytes: tee_tcb_svn2[16] + mr_servicetd[48])
        let (tee_tcb_svn2, mr_servicetd) = if data.len() >= offset + 64 {
            let svn2 = read_bytes!(16);
            let svc = read_bytes!(48);
            (Some(svn2), Some(svc))
        } else {
            (None, None)
        };
        let _ = offset; // suppress unused assignment warning from macro

        Ok(Self {
            tee_tcb_svn,
            mr_seam,
            mrsigner_seam,
            seam_attributes,
            td_attributes,
            xfam,
            mr_td,
            mr_config_id,
            mr_owner,
            mr_owner_config,
            rtmr_0,
            rtmr_1,
            rtmr_2,
            rtmr_3,
            report_data,
            tee_tcb_svn2,
            mr_servicetd,
        })
    }
}

/// Parse a TDX quote from raw bytes. Supports v4 and v5 formats.
/// Expected TDX TEE type value in the quote header.
const TDX_TEE_TYPE: u32 = 0x81;

pub fn parse_tdx_quote(data: &[u8]) -> Result<TdxQuote> {
    let header = QuoteHeader::from_bytes(data)?;

    // Validate TEE type is TDX (0x81)
    if header.tee_type != TDX_TEE_TYPE {
        return Err(AttestationError::QuoteParseFailed(format!(
            "invalid TEE type: expected 0x{:02X} (TDX), got 0x{:02X}",
            TDX_TEE_TYPE, header.tee_type
        )));
    }

    match header.version {
        4 => {
            // v4: header (48) + body (584) + auth data
            if data.len() < QUOTE_HEADER_SIZE + REPORT_BODY_SIZE {
                return Err(AttestationError::QuoteParseFailed(format!(
                    "v4 quote too short: need {} bytes, have {}",
                    QUOTE_HEADER_SIZE + REPORT_BODY_SIZE,
                    data.len()
                )));
            }
            let body = TdxReportBody::from_bytes(
                &data[QUOTE_HEADER_SIZE..QUOTE_HEADER_SIZE + REPORT_BODY_SIZE],
            )?;
            Ok(TdxQuote {
                header,
                body,
                quote_version: QuoteVersion::V4,
            })
        }
        5 => {
            // v5: header (48) + type (2) + size (4) + body
            if data.len() < QUOTE_HEADER_SIZE + 6 {
                return Err(AttestationError::QuoteParseFailed(
                    "v5 quote too short for type/size fields".to_string(),
                ));
            }

            let body_type = data
                .pread_with::<u16>(QUOTE_HEADER_SIZE, scroll::LE)
                .map_err(|e| AttestationError::QuoteParseFailed(format!("v5 type: {e}")))?;
            let body_size = data
                .pread_with::<u32>(QUOTE_HEADER_SIZE + 2, scroll::LE)
                .map_err(|e| AttestationError::QuoteParseFailed(format!("v5 size: {e}")))?
                as usize;

            // Validate body_size matches expected size for the body type
            let expected_body_size = match body_type {
                2 => REPORT_BODY_SIZE,      // TDX 1.0: 584 bytes
                3 => REPORT_BODY_SIZE + 64, // TDX 1.5: 648 bytes (584 + 64 for TEE_TCB_SVN2)
                _ => 0,                     // will be caught below
            };
            if expected_body_size > 0 && body_size != expected_body_size {
                return Err(AttestationError::QuoteParseFailed(format!(
                    "v5 body_size {body_size} does not match expected {expected_body_size} for type {body_type}"
                )));
            }

            let body_offset = QUOTE_HEADER_SIZE + 6;
            if data.len() < body_offset + body_size {
                return Err(AttestationError::QuoteParseFailed(format!(
                    "v5 quote too short: need {} bytes, have {}",
                    body_offset + body_size,
                    data.len()
                )));
            }

            let body = TdxReportBody::from_bytes(&data[body_offset..body_offset + body_size])?;

            let quote_version = match body_type {
                2 => QuoteVersion::V5Tdx10, // TDX 1.0
                3 => QuoteVersion::V5Tdx15, // TDX 1.5
                _ => {
                    return Err(AttestationError::QuoteParseFailed(format!(
                        "unknown v5 body type: {body_type}"
                    )));
                }
            };

            Ok(TdxQuote {
                header,
                body,
                quote_version,
            })
        }
        v => Err(AttestationError::QuoteParseFailed(format!(
            "unsupported quote version: {v}"
        ))),
    }
}

/// Extract and verify the ECDSA P-256 quote signature.
///
/// The TDX quote auth data follows the report body and contains:
/// - sig_data_len (4 bytes LE)
/// - ECDSA P-256 signature (64 bytes: R[32] || S[32])
/// - ECDSA attestation public key (64 bytes: X[32] || Y[32])
/// - QE certification data (variable)
///
/// The signature covers SHA-256(header + body).
pub fn verify_quote_signature(quote_bytes: &[u8], quote: &TdxQuote) -> Result<bool> {
    // Determine where the body ends (and auth data begins)
    let body_end = super::dcap::compute_body_end(quote_bytes, quote.quote_version)?;

    // Need at least sig_data_len(4) + signature(64) + attest_key(64) = 132 bytes of auth data
    if quote_bytes.len() < body_end + 132 {
        return Err(AttestationError::QuoteParseFailed(
            "quote too short for auth data (signature + attestation key)".to_string(),
        ));
    }

    let sig_data_len = quote_bytes
        .pread_with::<u32>(body_end, scroll::LE)
        .map_err(|e| AttestationError::QuoteParseFailed(format!("sig_data_len: {e}")))?
        as usize;

    if sig_data_len < 128 {
        return Err(AttestationError::QuoteParseFailed(format!(
            "sig_data_len too small: {sig_data_len} (need at least 128 for sig + key)"
        )));
    }

    // Extract ECDSA P-256 signature (64 bytes: R || S)
    let sig_offset = body_end + 4;
    let sig_r = &quote_bytes[sig_offset..sig_offset + 32];
    let sig_s = &quote_bytes[sig_offset + 32..sig_offset + 64];

    // Extract attestation public key (64 bytes: X || Y)
    let key_offset = sig_offset + 64;
    let key_x = &quote_bytes[key_offset..key_offset + 32];
    let key_y = &quote_bytes[key_offset + 32..key_offset + 64];

    // The signed data is the quote header + body
    let signed_data = &quote_bytes[..body_end];

    // Compute SHA-256 hash of the signed data
    let hash = crate::utils::sha256(signed_data);

    // Construct the ECDSA P-256 signature
    let mut r_arr = [0u8; 32];
    let mut s_arr = [0u8; 32];
    r_arr.copy_from_slice(sig_r);
    s_arr.copy_from_slice(sig_s);
    let signature =
        Signature::from_scalars(p256::FieldBytes::from(r_arr), p256::FieldBytes::from(s_arr))
            .map_err(|e| {
                AttestationError::SignatureVerificationFailed(format!("construct P-256 sig: {e}"))
            })?;

    // Construct the verifying key from the uncompressed public key point
    // SEC1 uncompressed point format: 0x04 || X || Y
    let mut uncompressed = vec![0x04u8];
    uncompressed.extend_from_slice(key_x);
    uncompressed.extend_from_slice(key_y);

    let verifying_key = VerifyingKey::from_sec1_bytes(&uncompressed).map_err(|e| {
        AttestationError::SignatureVerificationFailed(format!("parse attestation key: {e}"))
    })?;

    // Verify: the signature is over the raw SHA-256 hash (pre-hashed)
    // DCAP signs SHA-256(header+body), so we need to use verify_prehash
    match verifying_key.verify_prehash(&hash, &signature) {
        Ok(()) => Ok(true),
        Err(e) => Err(AttestationError::SignatureVerificationFailed(format!(
            "ECDSA P-256 DCAP: {e}"
        ))),
    }
}

/// Internal: run the full TDX verification pipeline and return the parsed
/// quote together with the canonical-but-not-yet-vendor-pinned result.
///
/// This is the shared core used by bare-metal TDX, GCP TDX, and Dstack: each
/// of those is the same TDX DCAP pipeline; the only differences are the
/// vendor-specific pin checks (passed in via `vendor`) and the wrapper that
/// re-tags the platform. The function:
///
/// - Parses + signature-verifies the quote
/// - Walks the DCAP chain
/// - Enforces debug policy
/// - Runs optional collateral checks (CRL, TCB, QE Identity)
/// - Verifies CC eventlog integrity when present
/// - Computes the canonical [`crate::types::VerifyResult`] (canonical anchors,
///   synthetic launch_measurement, vendor-result populated with the parsed
///   quote and TCB status)
///
/// Returns `(quote, result)` so wrappers (GCP, Dstack) can re-tag the vendor
/// result if they need a different platform identity.
pub(crate) async fn verify_evidence_inner(
    evidence: &TdxEvidence,
    params: &VerifyParams,
    collateral_provider: Option<&dyn TdxCollateralProvider>,
) -> Result<(TdxQuote, VerifyResult)> {
    // 0. Input size validation
    crate::utils::check_field_size("quote", evidence.quote.len())?;

    // 1. Decode the quote
    let quote_bytes = BASE64
        .decode(&evidence.quote)
        .map_err(|e| AttestationError::EvidenceDeserialize(format!("quote base64: {e}")))?;

    // 2. Parse the quote
    let quote = parse_tdx_quote(&quote_bytes)?;

    // 3. DCAP ECDSA P-256 signature verification
    let sig_valid = verify_quote_signature(&quote_bytes, &quote)?;

    // 3b. Full DCAP chain verification: PCK cert chain → QE report sig → QE binding
    super::dcap::verify_dcap_chain(&quote_bytes, quote.quote_version, None)?;

    // 3c. TDX debug policy enforcement (bit 0 of td_attributes)
    if quote.body.td_attributes[0] & 0x01 != 0 && !params.allow_debug {
        return Err(AttestationError::DebugPolicyViolation);
    }

    // 3d. DCAP collateral checks (CRL, TCB, QE Identity) when provider is available
    let tcb_status: Option<DcapVerificationStatus> = if let Some(provider) = collateral_provider {
        let body_end = super::dcap::compute_body_end(&quote_bytes, quote.quote_version)?;
        let auth = super::dcap::parse_auth_data(&quote_bytes, body_end)?;

        // PCK CRL revocation check (leaf + intermediate CA)
        provider
            .check_pck_revocation(auth.pck_cert_chain_pem)
            .await?;

        // TCB status evaluation
        let fmspc = super::dcap::extract_fmspc_from_pck(auth.pck_cert_chain_pem)?;
        let tcb_info_json = provider.get_tcb_info(&fmspc).await?;
        let tcb_signing_chain = provider.get_tcb_signing_chain().await?;
        let status = super::dcap::evaluate_tcb_status(
            &tcb_info_json,
            &quote.body.tee_tcb_svn,
            auth.pck_cert_chain_pem,
            tcb_signing_chain.as_deref(),
        )?;

        // Reject Revoked TCB status
        if status.tcb_status == crate::types::TdxTcbStatus::Revoked {
            return Err(AttestationError::TcbMismatch(
                "TDX TCB status is Revoked".into(),
            ));
        }

        // QE Identity verification (TDX uses TD_QE, not SGX QE)
        let qe_identity_json = provider.get_td_qe_identity().await?;
        let qe_signing_chain = provider.get_td_qe_identity_signing_chain().await?;
        super::dcap::verify_qe_identity(
            auth.qe_report_body,
            &qe_identity_json,
            qe_signing_chain.as_deref(),
        )?;

        Some(status)
    } else {
        log::warn!("TDX collateral provider not available; skipping CRL, TCB status, and QE Identity checks");
        None
    };

    // 4. Eventlog integrity check (if present)
    if let Some(ref eventlog_b64) = evidence.cc_eventlog {
        crate::utils::check_field_size("cc_eventlog", eventlog_b64.len())?;
        let ccel_data = BASE64
            .decode(eventlog_b64)
            .map_err(|e| AttestationError::EventlogIntegrityFailed(format!("CCEL base64: {e}")))?;
        super::ccel::verify_ccel_against_rtmrs(
            &ccel_data,
            &quote.body.rtmr_0,
            &quote.body.rtmr_1,
            &quote.body.rtmr_2,
            &quote.body.rtmr_3,
        )?;
    }

    // 5. Canonical anchors. For bare-metal TDX the caller's nonce IS the
    // report_data — there is no separate vTPM layer to put it on. We expose
    // both `nonce` and `report_data` so the result shape is uniform across
    // bare-metal and overlay platforms.
    let report_data = quote.body.report_data.to_vec();
    let launch_measurement = vendor_helpers::tdx_launch_measurement(
        &quote.body.mr_td,
        &quote.body.rtmr_1,
        &quote.body.rtmr_2,
        &quote.body.rtmr_3,
    );

    // 5a. Canonical anchor comparisons (constant-time, no early return).
    let (nonce_match, _) = check_padded_report_data(&quote.body.report_data, params.nonce.as_deref())?;
    let (report_data_match, _) =
        check_padded_report_data(&quote.body.report_data, params.report_data.as_deref())?;
    let launch_measurement_match = params
        .launch_measurement
        .as_deref()
        .map(|exp| crate::utils::constant_time_eq(&launch_measurement, exp));

    // 6. Vendor-specific pin checks. Accumulate into `vendor_policy_failed`;
    // do NOT short-circuit — each pin runs even if an earlier one mismatched,
    // so the caller gets a complete picture.
    let (vendor_policy_failed, expected_mr_config_id_match) = match &params.vendor {
        VendorParams::Auto => (false, None),
        VendorParams::Tdx(v) => apply_tdx_pins(&quote, v),
        // Wrappers (GCP TDX, Dstack) re-validate their own VendorParams in
        // their respective verify_evidence — the inner core just enforces
        // the Auto/Tdx-only contract. Other vendor variants are unreachable
        // here because the top-level dispatcher rejected a mismatched tag.
        other => return Err(AttestationError::PlatformMismatch {
            expected: "tdx".to_string(),
            actual: format!("{other:?}"),
        }),
    };

    let _ = expected_mr_config_id_match; // already folded into vendor_policy_failed

    let parsed_quote = vendor_helpers::project_tdx_quote(&quote);
    let collateral_verified = tcb_status.is_some();
    let vendor = VendorResult::Tdx(TdxResult {
        quote: parsed_quote,
        tcb_status,
    });

    let result = VerifyResult {
        signature_valid: sig_valid,
        collateral_verified,
        nonce: quote.body.report_data.to_vec(), // bare-metal: nonce == report_data
        report_data,
        launch_measurement,
        nonce_match,
        report_data_match,
        launch_measurement_match,
        vendor,
        vendor_policy_failed,
    };

    Ok((quote, result))
}

/// Constant-time-equal report_data with a zero-padded expected value. Returns
/// `(match, mismatched)` for accumulation. The expected value is padded to 64
/// bytes (the report_data field size) — callers pass the raw nonce / hash.
pub(crate) fn check_padded_report_data(
    observed: &[u8; 64],
    expected: Option<&[u8]>,
) -> Result<(Option<bool>, bool)> {
    let Some(expected) = expected else {
        return Ok((None, false));
    };
    let padded = crate::utils::pad_report_data(expected, 64)?;
    let ok = crate::utils::constant_time_eq(observed, &padded);
    Ok((Some(ok), !ok))
}

/// Apply TDX vendor pin checks. Returns `(vendor_policy_failed, mr_config_id_match)`.
fn apply_tdx_pins(quote: &TdxQuote, v: &VerifyTdx) -> (bool, Option<bool>) {
    let mut failed = false;

    // MRTD pin
    let (_, m) = vendor_helpers::check_digest_48(&quote.body.mr_td, v.mrtd.as_ref());
    failed |= m;

    // RTMR pins
    let rtmrs = [
        &quote.body.rtmr_0,
        &quote.body.rtmr_1,
        &quote.body.rtmr_2,
        &quote.body.rtmr_3,
    ];
    for (i, slot) in v.rtmrs.iter().enumerate() {
        let (_, m) = vendor_helpers::check_digest_48(rtmrs[i], slot.as_ref());
        failed |= m;
    }

    // MRCONFIGID pin
    let (mr_match, m) =
        vendor_helpers::check_digest_48(&quote.body.mr_config_id, v.mr_config_id.as_ref());
    failed |= m;

    (failed, mr_match)
}

/// Verify TDX attestation evidence.
///
/// When `collateral_provider` is `Some`, performs full DCAP collateral verification:
/// PCK CRL revocation check, TCB status evaluation, and QE Identity verification.
/// When `None`, these checks are skipped (suitable for offline/testing scenarios).
pub async fn verify_evidence(
    evidence: &TdxEvidence,
    params: &VerifyParams,
    collateral_provider: Option<&dyn TdxCollateralProvider>,
) -> Result<VerifyResult> {
    let (_quote, result) = verify_evidence_inner(evidence, params, collateral_provider).await?;
    Ok(result)
}

#[cfg(test)]
mod tests {
    use super::*;

    // Load real test fixtures at compile time
    const V4_QUOTE: &[u8] = include_bytes!("../../../test_data/tdx_quote_4.dat");
    const V5_QUOTE: &[u8] = include_bytes!("../../../test_data/tdx_quote_5.dat");

    #[test]
    fn test_parse_v4_quote() {
        let quote = parse_tdx_quote(V4_QUOTE).unwrap();
        assert_eq!(quote.header.version, 4);
        assert_eq!(quote.quote_version, QuoteVersion::V4);
        // TDX TEE type is 0x81
        assert_eq!(quote.header.tee_type, 0x81);
    }

    #[test]
    fn test_parse_v5_quote() {
        let quote = parse_tdx_quote(V5_QUOTE).unwrap();
        assert_eq!(quote.header.version, 5);
        assert!(matches!(
            quote.quote_version,
            QuoteVersion::V5Tdx10 | QuoteVersion::V5Tdx15
        ));
    }

    #[test]
    fn test_parse_invalid_version() {
        let mut data = vec![0u8; 700];
        // Set version to 99
        data[0] = 99;
        assert!(parse_tdx_quote(&data).is_err());
    }

    // ---------------------------------------------------------------
    // Tests using real TDX quote fixtures
    // ---------------------------------------------------------------

    #[test]
    fn test_v4_quote_header_fields() {
        let quote = parse_tdx_quote(V4_QUOTE).expect("failed to parse v4 quote");

        assert_eq!(quote.header.version, 4);
        assert_eq!(quote.header.att_key_type, 2); // ECDSA-256-with-P-256 curve
        assert_eq!(quote.header.tee_type, 0x81); // TDX TEE type
        assert_eq!(quote.quote_version, QuoteVersion::V4);

        // Vendor ID should be populated (Intel QE vendor ID)
        assert!(
            quote.header.vendor_id.iter().any(|&b| b != 0),
            "vendor_id should not be all zeroes"
        );
        assert_eq!(quote.header.vendor_id[0], 0x93);
    }

    #[test]
    fn test_v5_quote_header_fields() {
        let quote = parse_tdx_quote(V5_QUOTE).expect("failed to parse v5 quote");

        assert_eq!(quote.header.version, 5);
        assert_eq!(quote.header.att_key_type, 2);
        assert_eq!(quote.header.tee_type, 0x81);

        // V5 with body type 3 => TDX 1.5
        assert_eq!(quote.quote_version, QuoteVersion::V5Tdx15);

        // V5 TDX 1.5 should have extra fields
        if quote.quote_version == QuoteVersion::V5Tdx15 {
            if let Some(ref svn2) = quote.body.tee_tcb_svn2 {
                assert_eq!(svn2.len(), 16);
            }
            if let Some(ref svc) = quote.body.mr_servicetd {
                assert_eq!(svc.len(), 48);
            }
        }
    }

    #[test]
    fn test_v4_has_no_tdx15_fields() {
        let quote = parse_tdx_quote(V4_QUOTE).expect("failed to parse v4 quote");
        assert!(
            quote.body.tee_tcb_svn2.is_none(),
            "V4 quote should not have tee_tcb_svn2"
        );
        assert!(
            quote.body.mr_servicetd.is_none(),
            "V4 quote should not have mr_servicetd"
        );
    }

    #[test]
    fn test_quote_truncation_header_only() {
        // A quote with only the header (48 bytes) but no body should fail
        let truncated = &V4_QUOTE[..QUOTE_HEADER_SIZE];
        let result = parse_tdx_quote(truncated);
        assert!(
            result.is_err(),
            "truncated quote with header only should fail"
        );
    }

    #[test]
    fn test_quote_truncation_one_byte_short() {
        // V4: header (48) + body (584) = 632 minimum
        // One byte short of a complete body
        let min_size = QUOTE_HEADER_SIZE + REPORT_BODY_SIZE;
        let truncated = &V4_QUOTE[..min_size - 1];
        let result = parse_tdx_quote(truncated);
        assert!(
            result.is_err(),
            "quote one byte short of minimum should fail"
        );
    }

    #[test]
    fn test_quote_truncation_exact_minimum_v4() {
        // V4: exactly header + body should parse OK
        let min_size = QUOTE_HEADER_SIZE + REPORT_BODY_SIZE;
        let truncated = &V4_QUOTE[..min_size];
        let result = parse_tdx_quote(truncated);
        assert!(
            result.is_ok(),
            "exact minimum v4 quote should parse: {:?}",
            result.err()
        );
    }

    #[test]
    fn test_quote_truncation_v5_no_type_size() {
        // V5 needs header + type(2) + size(4) = 54 bytes minimum before body
        // Truncate to just the header
        let truncated = &V5_QUOTE[..QUOTE_HEADER_SIZE + 2]; // Has type but no size
        let result = parse_tdx_quote(truncated);
        assert!(result.is_err(), "v5 quote without size field should fail");
    }

    #[test]
    fn test_quote_truncation_v5_no_body() {
        // V5 header + type + size but no body
        let truncated = &V5_QUOTE[..QUOTE_HEADER_SIZE + 6];
        let result = parse_tdx_quote(truncated);
        assert!(result.is_err(), "v5 quote without body should fail");
    }

    #[test]
    fn test_quote_truncation_empty() {
        let result = parse_tdx_quote(&[]);
        assert!(result.is_err(), "empty quote should fail");
    }

    #[test]
    fn test_v5_invalid_body_type() {
        // Create a v5 quote with an invalid body type
        let mut data = V5_QUOTE.to_vec();
        // body_type is at offset 48 (after header), set to invalid value 99
        data[48] = 99;
        data[49] = 0;
        let result = parse_tdx_quote(&data);
        assert!(
            result.is_err(),
            "v5 quote with invalid body type should fail"
        );
    }

    #[test]
    fn test_debug_policy_enforcement() {
        // v4 fixture has debug bit set, v5 does not
        let v4 = parse_tdx_quote(V4_QUOTE).unwrap();
        assert_eq!(
            v4.body.td_attributes[0] & 0x01,
            1,
            "v4 fixture has debug bit set"
        );
        let v5 = parse_tdx_quote(V5_QUOTE).unwrap();
        assert_eq!(
            v5.body.td_attributes[0] & 0x01,
            0,
            "v5 fixture should not have debug bit set"
        );
    }

    #[tokio::test]
    async fn test_verify_evidence_debug_td_rejected() {
        // v4 fixture has debug bit set — should be rejected with allow_debug=false
        let evidence = make_tdx_evidence(V4_QUOTE);
        let params = VerifyParams::default(); // allow_debug = false

        let result = verify_evidence(&evidence, &params, None).await;
        assert!(result.is_err(), "debug TD should not pass verification");
        let err = format!("{:?}", result.err().unwrap());
        assert!(
            err.contains("DebugPolicyViolation"),
            "should be DebugPolicyViolation, got: {err}"
        );
    }

    #[tokio::test]
    async fn test_verify_evidence_debug_td_allowed() {
        // v4 fixture has debug bit set — should pass with allow_debug=true
        let quote = parse_tdx_quote(V4_QUOTE).unwrap();
        let evidence = make_tdx_evidence(V4_QUOTE);
        let params = VerifyParams {
            nonce: Some(quote.body.report_data.to_vec()),
            allow_debug: true,
            ..Default::default()
        };
        let result = verify_evidence(&evidence, &params, None).await;
        assert!(
            result.is_ok(),
            "debug TD with allow_debug should pass: {:?}",
            result.err()
        );
    }

    #[test]
    fn test_quote_header_from_bytes_too_short() {
        let data = vec![0u8; 20]; // Less than 48 bytes
        let result = QuoteHeader::from_bytes(&data);
        assert!(result.is_err());
    }

    #[test]
    fn test_report_body_from_bytes_too_short() {
        let data = vec![0u8; 100]; // Less than 584 bytes
        let result = TdxReportBody::from_bytes(&data);
        assert!(result.is_err());
    }

    #[test]
    fn test_dcap_signature_verification_v4() {
        // Verify the real ECDSA P-256 signature on the v4 quote
        let quote = parse_tdx_quote(V4_QUOTE).expect("failed to parse v4 quote");
        let result = verify_quote_signature(V4_QUOTE, &quote);
        assert!(
            result.is_ok(),
            "v4 DCAP sig verification should succeed: {:?}",
            result.err()
        );
        assert!(result.unwrap(), "v4 DCAP signature should be valid");
    }

    #[test]
    fn test_dcap_signature_verification_v5() {
        // Verify the real ECDSA P-256 signature on the v5 quote
        let quote = parse_tdx_quote(V5_QUOTE).expect("failed to parse v5 quote");
        let result = verify_quote_signature(V5_QUOTE, &quote);
        assert!(
            result.is_ok(),
            "v5 DCAP sig verification should succeed: {:?}",
            result.err()
        );
        assert!(result.unwrap(), "v5 DCAP signature should be valid");
    }

    #[test]
    fn test_dcap_signature_tamper_detection() {
        // Flip a byte in the quote body and verify the sig fails
        let mut tampered = V4_QUOTE.to_vec();
        tampered[100] ^= 0xFF; // Flip a byte in the report body
        let quote = parse_tdx_quote(&tampered).expect("parse should still work");
        let result = verify_quote_signature(&tampered, &quote);
        assert!(
            result.is_err(),
            "tampered quote should fail DCAP sig verification"
        );
    }

    #[test]
    fn test_dcap_signature_truncated_auth_data() {
        // Quote with just header + body but no auth data
        let body_end = QUOTE_HEADER_SIZE + REPORT_BODY_SIZE;
        let truncated = &V4_QUOTE[..body_end + 10]; // Some bytes but not enough
        let quote = parse_tdx_quote(truncated).expect("parse should work");
        let result = verify_quote_signature(truncated, &quote);
        assert!(
            result.is_err(),
            "truncated auth data should fail verification"
        );
    }

    // ---------------------------------------------------------------
    // verify_evidence report_data tests (bare TDX path)
    // ---------------------------------------------------------------

    fn make_tdx_evidence(quote_bytes: &[u8]) -> TdxEvidence {
        TdxEvidence {
            quote: BASE64.encode(quote_bytes),
            cc_eventlog: None,
        }
    }

    // ---------------------------------------------------------------
    // Fixture-backed collateral provider for testing the full DCAP
    // collateral path (TCB info, QE identity, CRL checks).
    //
    // Collateral files were captured from Intel PCS v4 and stored in
    // test_data/collateral/. The signing chains and CRLs have long
    // validity, but TCB Info `nextUpdate` will eventually expire.
    // `evaluate_tcb_status` surfaces that as `collateral_expired: true`
    // rather than a hard failure, so the tests remain valid.
    // ---------------------------------------------------------------

    const TCB_INFO_V4: &[u8] =
        include_bytes!("../../../test_data/collateral/tcb_info_50806f000000.json");
    const TCB_INFO_V5: &[u8] =
        include_bytes!("../../../test_data/collateral/tcb_info_90c06f000000.json");
    const TCB_SIGNING_CHAIN: &[u8] =
        include_bytes!("../../../test_data/collateral/tcb_signing_chain.pem");
    const TD_QE_IDENTITY: &[u8] =
        include_bytes!("../../../test_data/collateral/td_qe_identity.json");
    const QE_IDENTITY_SIGNING_CHAIN: &[u8] =
        include_bytes!("../../../test_data/collateral/qe_identity_signing_chain.pem");
    const PCK_CRL_DER: &[u8] = include_bytes!("../../../test_data/collateral/pck_crl_platform.der");
    const ROOT_CA_CRL_DER: &[u8] = include_bytes!("../../../test_data/collateral/root_ca_crl.der");

    struct FixtureCollateralProvider {
        fmspc_tcb_info: std::collections::HashMap<String, Vec<u8>>,
    }

    impl FixtureCollateralProvider {
        fn new() -> Self {
            let mut map = std::collections::HashMap::new();
            map.insert("50806f000000".to_string(), TCB_INFO_V4.to_vec());
            map.insert("90c06f000000".to_string(), TCB_INFO_V5.to_vec());
            Self {
                fmspc_tcb_info: map,
            }
        }
    }

    #[async_trait::async_trait]
    impl TdxCollateralProvider for FixtureCollateralProvider {
        async fn get_tcb_info(&self, fmspc: &str) -> crate::error::Result<Vec<u8>> {
            self.fmspc_tcb_info.get(fmspc).cloned().ok_or_else(|| {
                AttestationError::CertFetchError(format!("no fixture TCB info for FMSPC {fmspc}"))
            })
        }

        async fn get_qe_identity(&self) -> crate::error::Result<Vec<u8>> {
            Err(AttestationError::CertFetchError(
                "fixture provider only has TD QE identity, not SGX QE identity".into(),
            ))
        }

        async fn get_td_qe_identity(&self) -> crate::error::Result<Vec<u8>> {
            Ok(TD_QE_IDENTITY.to_vec())
        }

        async fn get_root_ca_crl(&self) -> crate::error::Result<Vec<u8>> {
            Ok(ROOT_CA_CRL_DER.to_vec())
        }

        async fn get_pck_crl(&self, _ca: &str) -> crate::error::Result<Vec<u8>> {
            Ok(PCK_CRL_DER.to_vec())
        }

        async fn get_tcb_signing_chain(&self) -> crate::error::Result<Option<Vec<u8>>> {
            Ok(Some(TCB_SIGNING_CHAIN.to_vec()))
        }

        async fn get_qe_identity_signing_chain(&self) -> crate::error::Result<Option<Vec<u8>>> {
            Ok(Some(QE_IDENTITY_SIGNING_CHAIN.to_vec()))
        }

        async fn get_td_qe_identity_signing_chain(&self) -> crate::error::Result<Option<Vec<u8>>> {
            Ok(Some(QE_IDENTITY_SIGNING_CHAIN.to_vec()))
        }
    }

    // ---------------------------------------------------------------
    // verify_evidence tests — each test runs both without collateral
    // (None) and with the fixture provider to cover both paths.
    // ---------------------------------------------------------------

    #[tokio::test]
    async fn test_verify_evidence_v4_no_expected_report_data() {
        let evidence = make_tdx_evidence(V4_QUOTE);
        // v4 fixture has debug bit set, so allow_debug must be true
        let params = VerifyParams {
            allow_debug: true,
            ..Default::default()
        };

        // Without collateral
        let result = verify_evidence(&evidence, &params, None).await;
        assert!(result.is_ok(), "verify should succeed: {:?}", result.err());
        let r = result.unwrap();
        assert!(r.signature_valid);
        assert!(
            r.report_data_match.is_none(),
            "should be None when no expected value"
        );
        assert!(!r.collateral_verified, "no provider means no collateral");

        // With collateral
        let provider = FixtureCollateralProvider::new();
        let result = verify_evidence(&evidence, &params, Some(&provider)).await;
        assert!(
            result.is_ok(),
            "verify with collateral should succeed: {:?}",
            result.err()
        );
        let r = result.unwrap();
        assert!(r.signature_valid);
        assert!(r.collateral_verified, "collateral should be verified");
        assert!(
            matches!(&r.vendor, VendorResult::Tdx(t) if t.tcb_status.is_some()),
            "TDX vendor result should carry tcb_status"
        );
    }

    fn vendor_quote(r: &VerifyResult) -> &crate::types::ParsedTdxQuote {
        match &r.vendor {
            VendorResult::Tdx(t) => &t.quote,
            other => panic!("expected VendorResult::Tdx, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn test_verify_evidence_v4_matching_nonce() {
        let quote = parse_tdx_quote(V4_QUOTE).unwrap();
        let evidence = make_tdx_evidence(V4_QUOTE);

        let params = VerifyParams {
            nonce: Some(quote.body.report_data.to_vec()),
            allow_debug: true,
            ..Default::default()
        };

        let r = verify_evidence(&evidence, &params, None).await.unwrap();
        assert_eq!(r.nonce_match, Some(true));
        assert!(!r.policy_failed());

        let provider = FixtureCollateralProvider::new();
        let r = verify_evidence(&evidence, &params, Some(&provider))
            .await
            .unwrap();
        assert_eq!(r.nonce_match, Some(true));
        assert!(r.collateral_verified);
        assert!(matches!(&r.vendor, VendorResult::Tdx(t) if t.tcb_status.is_some()));
    }

    #[tokio::test]
    async fn test_verify_evidence_v4_wrong_nonce_records_some_false() {
        let evidence = make_tdx_evidence(V4_QUOTE);
        let params = VerifyParams {
            nonce: Some(vec![0xFF; 64]),
            allow_debug: true,
            ..Default::default()
        };
        let r = verify_evidence(&evidence, &params, None).await.unwrap();
        assert_eq!(r.nonce_match, Some(false));
        assert!(r.policy_failed());
        assert!(r.signature_valid, "wrong nonce must not fail signature");
    }

    #[tokio::test]
    async fn test_verify_evidence_v5_matching_nonce() {
        let quote = parse_tdx_quote(V5_QUOTE).unwrap();
        let evidence = make_tdx_evidence(V5_QUOTE);
        let params = VerifyParams {
            nonce: Some(quote.body.report_data.to_vec()),
            ..Default::default()
        };
        let r = verify_evidence(&evidence, &params, None).await.unwrap();
        assert_eq!(r.nonce_match, Some(true));
    }

    #[tokio::test]
    async fn test_verify_evidence_v5_wrong_nonce_is_some_false() {
        let evidence = make_tdx_evidence(V5_QUOTE);
        let params = VerifyParams {
            nonce: Some(vec![0x00; 64]),
            ..Default::default()
        };
        let r = verify_evidence(&evidence, &params, None).await.unwrap();
        assert_eq!(r.nonce_match, Some(false));
    }

    #[tokio::test]
    async fn test_verify_evidence_nonce_too_large() {
        let evidence = make_tdx_evidence(V4_QUOTE);
        let params = VerifyParams {
            nonce: Some(vec![0xAA; 65]),
            allow_debug: true,
            ..Default::default()
        };
        let result = verify_evidence(&evidence, &params, None).await;
        assert!(result.is_err(), "65-byte nonce should be rejected");
    }

    // ---------------------------------------------------------------
    // Vendor-specific pin checks via VendorParams::Tdx
    // ---------------------------------------------------------------

    #[tokio::test]
    async fn test_verify_evidence_no_pins_yields_none() {
        let evidence = make_tdx_evidence(V4_QUOTE);
        let params = VerifyParams {
            allow_debug: true,
            ..Default::default()
        };
        let r = verify_evidence(&evidence, &params, None).await.unwrap();
        assert!(r.nonce_match.is_none());
        assert!(r.report_data_match.is_none());
        assert!(r.launch_measurement_match.is_none());
        assert!(!r.vendor_policy_failed);
        assert!(!r.policy_failed());
    }

    #[tokio::test]
    async fn test_verify_evidence_matching_mrtd_pin() {
        let quote = parse_tdx_quote(V4_QUOTE).unwrap();
        let evidence = make_tdx_evidence(V4_QUOTE);
        let params = VerifyParams {
            allow_debug: true,
            vendor: VendorParams::Tdx(VerifyTdx {
                mrtd: Some(quote.body.mr_td),
                ..Default::default()
            }),
            ..Default::default()
        };
        let r = verify_evidence(&evidence, &params, None).await.unwrap();
        assert!(!r.vendor_policy_failed);
        let parsed = vendor_quote(&r);
        assert_eq!(parsed.mr_td, quote.body.mr_td.to_vec());
    }

    #[tokio::test]
    async fn test_verify_evidence_wrong_mrtd_pin_records_failure() {
        let evidence = make_tdx_evidence(V4_QUOTE);
        let params = VerifyParams {
            allow_debug: true,
            vendor: VendorParams::Tdx(VerifyTdx {
                mrtd: Some([0xAA; 48]),
                ..Default::default()
            }),
            ..Default::default()
        };
        let r = verify_evidence(&evidence, &params, None).await.unwrap();
        assert!(r.vendor_policy_failed);
        assert!(r.policy_failed());
        assert!(r.signature_valid, "wrong pin must not fail signature");
    }

    #[tokio::test]
    async fn test_verify_evidence_mixed_rtmr_pins() {
        let quote = parse_tdx_quote(V4_QUOTE).unwrap();
        let evidence = make_tdx_evidence(V4_QUOTE);
        let params = VerifyParams {
            allow_debug: true,
            vendor: VendorParams::Tdx(VerifyTdx {
                rtmrs: [
                    Some(quote.body.rtmr_0), // match
                    Some([0xFF; 48]),        // mismatch
                    None,                    // skip
                    Some(quote.body.rtmr_3), // match
                ],
                ..Default::default()
            }),
            ..Default::default()
        };
        let r = verify_evidence(&evidence, &params, None).await.unwrap();
        // At least one pin failed → vendor_policy_failed is true.
        assert!(r.vendor_policy_failed);
        assert!(r.policy_failed());
    }

    #[tokio::test]
    async fn test_verify_evidence_canonical_launch_measurement_matches() {
        let quote = parse_tdx_quote(V4_QUOTE).unwrap();
        let evidence = make_tdx_evidence(V4_QUOTE);
        let expected_lm = crate::platforms::vendor_helpers::tdx_launch_measurement(
            &quote.body.mr_td,
            &quote.body.rtmr_1,
            &quote.body.rtmr_2,
            &quote.body.rtmr_3,
        );
        let params = VerifyParams {
            allow_debug: true,
            launch_measurement: Some(expected_lm.clone()),
            ..Default::default()
        };
        let r = verify_evidence(&evidence, &params, None).await.unwrap();
        assert_eq!(r.launch_measurement, expected_lm);
        assert_eq!(r.launch_measurement_match, Some(true));
        assert!(!r.policy_failed());
    }
}
