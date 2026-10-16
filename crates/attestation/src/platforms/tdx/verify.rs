use base64::{engine::general_purpose::STANDARD as BASE64, Engine};
use p256::ecdsa::signature::hazmat::PrehashVerifier;
use p256::ecdsa::{Signature, VerifyingKey};
use scroll::Pread;

use serde::{Deserialize, Serialize};

use crate::collateral::TdxCollateralProvider;
use crate::context::Context;
use crate::error::{AttestationError, Result};
use crate::platform::Platform;
use crate::types::{Claims, DcapVerificationStatus, PlatformType, TdxTcbStatus};

use super::claims::extract_claims;
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

/// What a caller can ask of TDX evidence.
#[derive(Debug, Clone)]
pub struct TdxParams {
    /// Expected `report_data` (at most 64 bytes, zero-padded). Result in
    /// [`TdxResult::report_data_match`]. On Azure (vTPM) this is checked
    /// against the vTPM quote nonce instead.
    pub report_data: Option<Vec<u8>>,
    /// Expected init data: MRCONFIGID (at most 48 bytes, zero-padded). On
    /// Azure (vTPM) a 32-byte hash checked against PCR[8].
    pub init_data: Option<Vec<u8>>,
    /// Allowed MRTD values: the MRTD must equal one of them. Cloud firmware
    /// varies by host build, memory size and machine type. Must not be empty.
    pub mrtd: Option<Vec<[u8; 48]>>,
    /// Allowed RTMR[0..4] values, as for `mrtd`.
    pub rtmr: [Option<Vec<[u8; 48]>>; 4],
    /// Accept a TD with the debug attribute set. Default: false.
    pub allow_debug: bool,
    /// TCB statuses the caller accepts when DCAP collateral is evaluated.
    /// Default: every status except `Revoked` and `NoMatchingLevel`. Must
    /// not be empty.
    pub accepted_tcb_statuses: Vec<TdxTcbStatus>,
}

impl Default for TdxParams {
    fn default() -> Self {
        Self {
            report_data: None,
            init_data: None,
            mrtd: None,
            rtmr: [None, None, None, None],
            allow_debug: false,
            accepted_tcb_statuses: vec![
                TdxTcbStatus::UpToDate,
                TdxTcbStatus::SWHardeningNeeded,
                TdxTcbStatus::ConfigurationNeeded,
                TdxTcbStatus::ConfigurationAndSWHardeningNeeded,
                TdxTcbStatus::OutOfDate,
                TdxTcbStatus::OutOfDateConfigurationNeeded,
            ],
        }
    }
}

impl TdxParams {
    /// Reject params that cannot be applied. Runs before any collateral is
    /// fetched, so caller misuse is never reported as a retryable error.
    pub fn validate(&self) -> Result<()> {
        if self.report_data.as_ref().is_some_and(|d| d.len() > 64) {
            return Err(AttestationError::ReportDataTooLarge { max: 64 });
        }
        if self.init_data.as_ref().is_some_and(|d| d.len() > 48) {
            return Err(AttestationError::InvalidParams(
                "init_data exceeds 48 bytes".into(),
            ));
        }
        if self.accepted_tcb_statuses.is_empty() {
            return Err(AttestationError::InvalidParams(
                "accepted_tcb_statuses is empty".into(),
            ));
        }
        crate::utils::check_allowed_set("mrtd", self.mrtd.as_deref())?;
        for (i, rtmr) in self.rtmr.iter().enumerate() {
            crate::utils::check_allowed_set(&format!("rtmr{i}"), rtmr.as_deref())?;
        }
        Ok(())
    }
}

/// The answer for genuine TDX evidence. Every `*_match` is `None` when the
/// params did not ask, `Some(false)` on a mismatch.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[must_use]
pub struct TdxResult {
    pub claims: Claims,
    pub report_data_match: Option<bool>,
    pub init_data_match: Option<bool>,
    pub mrtd_match: Option<bool>,
    pub rtmr_match: [Option<bool>; 4],
    /// The TD's debug attribute is set.
    pub debug: bool,
    /// The params allowed a debug TD.
    pub allow_debug: bool,
    /// Neither the PCK certificate nor its issuing CA is listed in Intel's
    /// CRLs (`None` when collateral was not evaluated).
    pub crl_ok: Option<bool>,
    /// TCB status from Intel collateral (`None` when not evaluated).
    pub tcb_status: Option<DcapVerificationStatus>,
    /// The TCB status is in `accepted_tcb_statuses` (`None` when not evaluated).
    pub tcb_status_accepted: Option<bool>,
}

impl TdxResult {
    /// True when the evidence satisfied every rule in the params.
    pub fn passed(&self) -> bool {
        let [r0, r1, r2, r3] = self.rtmr_match;
        crate::platform::all_held(&[
            self.report_data_match,
            self.init_data_match,
            self.mrtd_match,
            r0,
            r1,
            r2,
            r3,
            self.crl_ok,
            self.tcb_status_accepted,
        ]) && (!self.debug || self.allow_debug)
    }

    /// Record evaluated DCAP collateral and whether the params accept its
    /// TCB status.
    pub fn set_collateral(&mut self, collateral: TdxCollateral, params: &TdxParams) {
        let status = collateral.tcb;
        self.tcb_status_accepted = Some(params.accepted_tcb_statuses.contains(&status.tcb_status));
        self.tcb_status = Some(status);
        self.crl_ok = Some(!collateral.pck_revoked);
    }
}

/// What Intel's DCAP collateral says about a genuine quote.
#[derive(Debug, Clone)]
pub struct TdxCollateral {
    pub tcb: DcapVerificationStatus,
    /// The PCK certificate or its issuing CA is listed in Intel's CRLs.
    pub pck_revoked: bool,
}

/// Bare-metal Intel TDX (DCAP quote, optional CC event log).
pub struct Tdx;

impl Platform for Tdx {
    const KIND: PlatformType = PlatformType::Tdx;
    type Evidence = TdxEvidence;
    type Params = TdxParams;
    type Result = TdxResult;

    /// When the context has a TDX collateral provider, performs full DCAP
    /// collateral verification: PCK CRL revocation check, TCB status
    /// evaluation, and QE Identity verification. Offline, these are skipped.
    async fn verify(
        evidence: &TdxEvidence,
        params: &TdxParams,
        ctx: &Context,
    ) -> Result<TdxResult> {
        params.validate()?;
        crate::utils::check_field_size("quote", evidence.quote.len())?;
        let quote_bytes = BASE64
            .decode(&evidence.quote)
            .map_err(|e| AttestationError::EvidenceDeserialize(format!("quote base64: {e}")))?;

        let (quote, mut result) = verify_quote(&quote_bytes, params, ctx)?;

        result.report_data_match = params
            .report_data
            .as_deref()
            .map(|expected| {
                let padded = crate::utils::pad_report_data(expected, 64)?;
                Ok::<_, AttestationError>(crate::utils::constant_time_eq(
                    &quote.body.report_data,
                    &padded,
                ))
            })
            .transpose()?;
        result.init_data_match = params
            .init_data
            .as_deref()
            .map(|expected| {
                let padded = crate::utils::pad_report_data(expected, 48)?;
                Ok::<_, AttestationError>(crate::utils::constant_time_eq(
                    &quote.body.mr_config_id,
                    &padded,
                ))
            })
            .transpose()?;

        if let Some(ref eventlog_b64) = evidence.cc_eventlog {
            crate::utils::check_field_size("cc_eventlog", eventlog_b64.len())?;
            let ccel_data = BASE64.decode(eventlog_b64).map_err(|e| {
                AttestationError::EventlogIntegrityFailed(format!("CCEL base64: {e}"))
            })?;
            super::ccel::verify_ccel_against_rtmrs(
                &ccel_data,
                &quote.body.rtmr_0,
                &quote.body.rtmr_1,
                &quote.body.rtmr_2,
                &quote.body.rtmr_3,
            )?;
        }

        check_collateral(&mut result, &quote_bytes, &quote, params, ctx).await?;
        Ok(result)
    }
}

/// Verify a TD quote (signature, DCAP chain) and evaluate the params' quote
/// rules: MRTD, RTMRs, debug. `report_data_match` and `init_data_match` are
/// left `None`: where those values live depends on the platform (quote body
/// or vTPM). Collateral is [`check_collateral`], once every genuineness check
/// of the platform has passed.
pub(crate) fn verify_quote(
    quote_bytes: &[u8],
    params: &TdxParams,
    ctx: &Context,
) -> Result<(TdxQuote, TdxResult)> {
    let quote = parse_tdx_quote(quote_bytes)?;
    verify_quote_signature(quote_bytes, &quote)?;
    super::dcap::verify_dcap_chain(quote_bytes, quote.quote_version, ctx.now())?;

    let body = &quote.body;
    let compare = |allowed: &Option<Vec<[u8; 48]>>, actual: &[u8; 48]| {
        crate::utils::match_any(actual, allowed.as_deref())
    };
    let result = TdxResult {
        claims: extract_claims(&quote),
        report_data_match: None,
        init_data_match: None,
        mrtd_match: compare(&params.mrtd, &body.mr_td),
        rtmr_match: [
            compare(&params.rtmr[0], &body.rtmr_0),
            compare(&params.rtmr[1], &body.rtmr_1),
            compare(&params.rtmr[2], &body.rtmr_2),
            compare(&params.rtmr[3], &body.rtmr_3),
        ],
        debug: body.td_attributes[0] & 0x01 != 0,
        allow_debug: params.allow_debug,
        crl_ok: None,
        tcb_status: None,
        tcb_status_accepted: None,
    };

    Ok((quote, result))
}

/// Evaluate DCAP collateral into `result` when the context has a provider.
/// Call it last, after the evidence is known to be genuine, so forged
/// evidence is never reported as retryable.
pub(crate) async fn check_collateral(
    result: &mut TdxResult,
    quote_bytes: &[u8],
    quote: &TdxQuote,
    params: &TdxParams,
    ctx: &Context,
) -> Result<()> {
    if let Some(provider) = ctx.tdx_collateral() {
        let collateral = verify_collateral(quote_bytes, quote, provider, ctx.now()).await?;
        result.set_collateral(collateral, params);
    } else {
        log::warn!("TDX collateral provider not available; skipping CRL, TCB status, and QE Identity checks");
    }
    Ok(())
}

/// Run the DCAP collateral checks (PCK CRL revocation, TCB status, TD-QE
/// identity) on an already parsed quote and return what they found. Whether
/// that is acceptable is the caller's policy ([`TdxResult::set_collateral`]).
/// The TCB status combines the platform's and the QE's.
///
/// Collateral that cannot be fetched, parsed or verified is
/// [`AttestationError::CollateralUnavailable`]. A QE that is not Intel's
/// (MRSIGNER, ISVPRODID, MISCSELECT, ATTRIBUTES) is an error about the quote.
///
/// The PCK chain and QE report are taken from the quote as authentic: call
/// this only after the quote itself has verified. It exists so a caller can
/// attribute failures to the collateral without verifying the evidence twice.
pub async fn verify_collateral(
    quote_bytes: &[u8],
    quote: &TdxQuote,
    provider: &dyn TdxCollateralProvider,
    now: i64,
) -> Result<TdxCollateral> {
    let body_end = super::dcap::compute_body_end(quote_bytes, quote.quote_version)?;
    let auth = super::dcap::parse_auth_data(quote_bytes, body_end)?;

    let pck_revoked = provider
        .pck_revoked(auth.pck_cert_chain_pem)
        .await
        .map_err(unusable)?;

    // TCB status evaluation
    let fmspc = super::dcap::extract_fmspc_from_pck(auth.pck_cert_chain_pem)?;
    let tcb_info_json = provider.get_tcb_info(&fmspc).await?;
    let tcb_signing_chain = provider
        .get_tcb_signing_chain()
        .await?
        .ok_or_else(unsigned)?;
    let mut status = super::dcap::evaluate_tcb_status(
        &tcb_info_json,
        &quote.body.tee_tcb_svn,
        auth.pck_cert_chain_pem,
        Some(&tcb_signing_chain),
        now,
    )
    .map_err(unusable)?;

    // QE Identity verification (TDX uses TD_QE, not SGX QE)
    let qe_identity_json = provider.get_td_qe_identity().await?;
    let qe_signing_chain = provider
        .get_td_qe_identity_signing_chain()
        .await?
        .ok_or_else(unsigned)?;
    super::dcap::verify_qe_identity_signature(&qe_identity_json, &qe_signing_chain, now)
        .map_err(unusable)?;
    let qe_identity = super::dcap::parse_qe_identity(&qe_identity_json).map_err(unusable)?;
    let qe_status = super::dcap::check_qe_report(auth.qe_report_body, &qe_identity)?;
    status.tcb_status = super::dcap::combine_tcb_status(status.tcb_status, qe_status);
    status.qe_tcb_status = Some(qe_status);

    Ok(TdxCollateral {
        tcb: status,
        pck_revoked,
    })
}

/// Intel signs its TCB Info and QE Identity; without the issuer chain the
/// signature cannot be checked, so the collateral is refused.
fn unsigned() -> AttestationError {
    AttestationError::CertChainError("Intel collateral came without its issuer chain".into())
}

/// Fetched collateral that does not parse or verify was not usefully
/// obtained.
fn unusable(e: AttestationError) -> AttestationError {
    match e {
        AttestationError::CollateralUnavailable(_) => e,
        other => AttestationError::CollateralUnavailable(format!("Intel collateral: {other}")),
    }
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
    async fn test_verify_evidence_debug_td_is_a_value() {
        // v4 fixture has debug bit set: genuine evidence, so Ok, but it fails
        // the default policy (allow_debug = false).
        let evidence = make_tdx_evidence(V4_QUOTE);
        let r = verify(&evidence, &TdxParams::default(), false)
            .await
            .expect("a debug TD is still genuine evidence");
        assert!(r.debug);
        assert!(!r.passed(), "debug TD must not pass without allow_debug");
    }

    #[tokio::test]
    async fn test_verify_evidence_debug_td_allowed() {
        // v4 fixture has debug bit set — passes with allow_debug=true
        let quote = parse_tdx_quote(V4_QUOTE).unwrap();
        let evidence = make_tdx_evidence(V4_QUOTE);
        let params = TdxParams {
            report_data: Some(quote.body.report_data.to_vec()),
            allow_debug: true,
            ..Default::default()
        };
        let r = verify(&evidence, &params, false).await.unwrap();
        assert!(r.debug);
        assert!(r.passed(), "debug TD with allow_debug should pass");
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
    // Tdx::verify report_data tests (bare TDX path)
    // ---------------------------------------------------------------

    fn make_tdx_evidence(quote_bytes: &[u8]) -> TdxEvidence {
        TdxEvidence {
            quote: BASE64.encode(quote_bytes),
            cc_eventlog: None,
        }
    }

    /// Verify through the platform contract, offline or with the fixture
    /// collateral provider.
    async fn verify(
        evidence: &TdxEvidence,
        params: &TdxParams,
        with_collateral: bool,
    ) -> Result<TdxResult> {
        let ctx = if with_collateral {
            Context::offline().with_tdx_provider(FixtureCollateralProvider::new())
        } else {
            Context::offline()
        };
        Tdx::verify(evidence, params, &ctx).await
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
                AttestationError::CollateralUnavailable(format!(
                    "no fixture TCB info for FMSPC {fmspc}"
                ))
            })
        }

        async fn get_qe_identity(&self) -> crate::error::Result<Vec<u8>> {
            Err(AttestationError::CollateralUnavailable(
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
    // Tdx::verify tests — each test runs both without collateral
    // (None) and with the fixture provider to cover both paths.
    // ---------------------------------------------------------------

    #[tokio::test]
    async fn test_verify_evidence_v4_no_expected_report_data() {
        let evidence = make_tdx_evidence(V4_QUOTE);
        // v4 fixture has debug bit set, so allow_debug must be true
        let params = TdxParams {
            allow_debug: true,
            ..Default::default()
        };

        // Without collateral
        let result = verify(&evidence, &params, false).await;
        assert!(result.is_ok(), "verify should succeed: {:?}", result.err());
        let r = result.unwrap();
        assert!(
            r.report_data_match.is_none(),
            "should be None when no expected value"
        );
        assert_eq!(r.crl_ok, None, "no provider means no collateral");

        // With collateral
        let result = verify(&evidence, &params, true).await;
        assert!(
            result.is_ok(),
            "verify with collateral should succeed: {:?}",
            result.err()
        );
        let r = result.unwrap();
        assert_eq!(r.crl_ok, Some(true), "collateral should be evaluated");
        assert!(r.tcb_status.is_some(), "tcb_status should be populated");
    }

    #[tokio::test]
    async fn test_verify_evidence_v4_matching_report_data() {
        let quote = parse_tdx_quote(V4_QUOTE).unwrap();
        let evidence = make_tdx_evidence(V4_QUOTE);

        let params = TdxParams {
            report_data: Some(quote.body.report_data.to_vec()),
            allow_debug: true,
            ..Default::default()
        };

        let result = verify(&evidence, &params, false).await;
        assert!(
            result.is_ok(),
            "verify with matching report_data should succeed: {:?}",
            result.err()
        );
        assert_eq!(result.unwrap().report_data_match, Some(true));

        let result = verify(&evidence, &params, true).await;
        assert!(
            result.is_ok(),
            "verify with collateral + matching report_data should succeed: {:?}",
            result.err()
        );
        let r = result.unwrap();
        assert_eq!(r.report_data_match, Some(true));
        assert_eq!(r.crl_ok, Some(true));
    }

    #[tokio::test]
    async fn test_verify_evidence_v4_wrong_report_data_is_some_false() {
        let evidence = make_tdx_evidence(V4_QUOTE);

        let params = TdxParams {
            report_data: Some(vec![0xFF; 64]),
            allow_debug: true,
            ..Default::default()
        };
        let r = verify(&evidence, &params, false)
            .await
            .expect("a report_data mismatch is a value, not an error");
        assert_eq!(r.report_data_match, Some(false));
        assert!(!r.passed());
    }

    #[tokio::test]
    async fn test_verify_evidence_v5_matching_report_data() {
        let quote = parse_tdx_quote(V5_QUOTE).unwrap();
        let evidence = make_tdx_evidence(V5_QUOTE);

        let params = TdxParams {
            report_data: Some(quote.body.report_data.to_vec()),
            ..Default::default()
        };

        let result = verify(&evidence, &params, false).await;
        assert!(
            result.is_ok(),
            "v5 verify with matching report_data should succeed: {:?}",
            result.err()
        );
        assert_eq!(result.unwrap().report_data_match, Some(true));

        // NOTE: v5 fixture's PCK TCB values predate the current Intel TCB
        // Info levels (CompSVN [1,1,...] < required [3,3,...]), so collateral
        // verification cannot find a matching SGX TCB level. Collateral
        // testing for the v5 code path is covered by the v4 tests above,
        // which share the same `evaluate_tcb_status` / `verify_qe_identity`
        // implementation.
    }

    #[tokio::test]
    async fn test_verify_evidence_v5_wrong_report_data_is_some_false() {
        let evidence = make_tdx_evidence(V5_QUOTE);

        let params = TdxParams {
            report_data: Some(vec![0x00; 64]),
            ..Default::default()
        };
        let r = verify(&evidence, &params, false).await.unwrap();
        assert_eq!(r.report_data_match, Some(false));
        assert!(!r.passed());
    }

    #[tokio::test]
    async fn test_verify_evidence_report_data_too_large() {
        let evidence = make_tdx_evidence(V4_QUOTE);

        let params = TdxParams {
            report_data: Some(vec![0xAA; 65]),
            allow_debug: true,
            ..Default::default()
        };
        let result = verify(&evidence, &params, false).await;
        assert!(result.is_err(), "65-byte report_data should be rejected");
    }

    // expected_mrtd / expected_rtmrs tests

    #[tokio::test]
    async fn test_verify_evidence_no_expected_measurements_yields_none() {
        // Sanity: when the caller supplies no expected_* values, the result
        // fields are None — distinguishing "skipped" from "failed".
        let evidence = make_tdx_evidence(V4_QUOTE);
        let params = TdxParams {
            allow_debug: true,
            ..Default::default()
        };
        let r = verify(&evidence, &params, false).await.unwrap();
        assert!(r.mrtd_match.is_none(), "no mrtd pin → None");
        assert_eq!(r.rtmr_match, [None; 4], "no rtmr pins → None");
        assert!(r.passed());
    }

    #[tokio::test]
    async fn test_verify_evidence_matching_mrtd() {
        let quote = parse_tdx_quote(V4_QUOTE).unwrap();
        let evidence = make_tdx_evidence(V4_QUOTE);
        let params = TdxParams {
            allow_debug: true,
            mrtd: Some(vec![quote.body.mr_td]),
            ..Default::default()
        };
        let r = verify(&evidence, &params, false).await.unwrap();
        assert_eq!(r.mrtd_match, Some(true));
    }

    #[tokio::test]
    async fn test_verify_evidence_wrong_mrtd_is_some_false() {
        // Wrong MRTD must record Some(false) without failing verification.
        let evidence = make_tdx_evidence(V4_QUOTE);
        let params = TdxParams {
            allow_debug: true,
            mrtd: Some(vec![[0xAA; 48]]),
            ..Default::default()
        };
        let r = verify(&evidence, &params, false).await.unwrap();
        assert_eq!(r.mrtd_match, Some(false));
        assert!(!r.passed());
    }

    #[tokio::test]
    async fn test_verify_evidence_partial_rtmr_check() {
        // Caller pins only rtmr0; the other rtmrN_match fields stay None.
        let quote = parse_tdx_quote(V4_QUOTE).unwrap();
        let evidence = make_tdx_evidence(V4_QUOTE);
        let params = TdxParams {
            allow_debug: true,
            rtmr: [Some(vec![quote.body.rtmr_0]), None, None, None],
            ..Default::default()
        };
        let r = verify(&evidence, &params, false).await.unwrap();
        assert_eq!(r.rtmr_match, [Some(true), None, None, None]);
    }

    #[tokio::test]
    async fn test_verify_evidence_mixed_rtmr_match_and_mismatch() {
        let quote = parse_tdx_quote(V4_QUOTE).unwrap();
        let evidence = make_tdx_evidence(V4_QUOTE);
        let params = TdxParams {
            allow_debug: true,
            // rtmr0 matches, rtmr1 does not, rtmr2 is not asked, rtmr3 matches
            rtmr: [
                Some(vec![quote.body.rtmr_0]),
                Some(vec![[0xFF; 48]]),
                None,
                Some(vec![quote.body.rtmr_3]),
            ],
            ..Default::default()
        };
        let r = verify(&evidence, &params, false).await.unwrap();
        assert_eq!(r.rtmr_match, [Some(true), Some(false), None, Some(true)]);
        assert!(!r.passed());
    }

    #[tokio::test]
    async fn test_tcb_status_outside_accepted_set_is_a_value() {
        let evidence = make_tdx_evidence(V4_QUOTE);
        let accepted = TdxParams {
            allow_debug: true,
            ..Default::default()
        };
        let r = verify(&evidence, &accepted, true).await.unwrap();
        let status = r
            .tcb_status
            .as_ref()
            .expect("collateral evaluated")
            .tcb_status;
        assert_eq!(r.tcb_status_accepted, Some(true));
        assert!(r.passed());

        let refused = TdxParams {
            accepted_tcb_statuses: TdxParams::default()
                .accepted_tcb_statuses
                .into_iter()
                .filter(|s| *s != status)
                .collect(),
            ..accepted
        };
        let r = verify(&evidence, &refused, true).await.unwrap();
        assert_eq!(r.tcb_status_accepted, Some(false));
        assert!(!r.passed());
    }

    #[tokio::test]
    async fn test_empty_accepted_tcb_statuses_is_invalid_params() {
        let params = TdxParams {
            accepted_tcb_statuses: vec![],
            allow_debug: true,
            ..Default::default()
        };
        let err = verify(&make_tdx_evidence(V4_QUOTE), &params, false)
            .await
            .expect_err("an empty accepted set cannot be satisfied");
        assert!(matches!(err, AttestationError::InvalidParams(_)));
    }

    #[tokio::test]
    async fn test_mrtd_allowlist() {
        let mrtd = parse_tdx_quote(V4_QUOTE).unwrap().body.mr_td;
        let evidence = make_tdx_evidence(V4_QUOTE);
        let verify_with = |allowed: Vec<[u8; 48]>| {
            let params = TdxParams {
                allow_debug: true,
                mrtd: Some(allowed),
                ..Default::default()
            };
            let evidence = evidence.clone();
            async move { verify(&evidence, &params, false).await }
        };

        let r = verify_with(vec![[0xAA; 48], mrtd]).await.unwrap();
        assert_eq!(r.mrtd_match, Some(true));
        let r = verify_with(vec![[0xAA; 48], [0xBB; 48]]).await.unwrap();
        assert_eq!(r.mrtd_match, Some(false));
        let err = verify_with(vec![]).await.unwrap_err();
        assert!(matches!(err, AttestationError::InvalidParams(_)));
    }
}
