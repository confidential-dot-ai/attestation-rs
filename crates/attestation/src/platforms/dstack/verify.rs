//! dstack TDX attestation verification.
//!
//! # What this module verifies
//!
//! Delegates to the TDX DCAP verification pipeline, which checks:
//! - TDX quote ECDSA P-256 signature (hardware-rooted)
//! - PCK certificate chain up to Intel SGX Root CA
//! - QE report signature and binding
//! - QE Identity against Intel PCS (when collateral provider is available)
//! - TCB status evaluation and CRL revocation checks
//! - `nonce` / `report_data` binding (when `VerifyParams::nonce` or
//!   `VerifyParams::report_data` is set)
//! - `mr_config_id` binding via [`VerifyDstack::mr_config_id`]
//!
//! # What the caller must verify
//!
//! The following checks are **not** performed by this module and are the
//! caller's responsibility (RTMR values are available in `DstackResult::quote`):
//!
//! - **RTMR3 event log replay**: dstack records compose-hash, instance-id, and
//!   key-provider events in RTMR3 via SHA-384 hash chaining. The event log is
//!   available in `DstackEvidence::event_log` but is not replayed or verified
//!   here. dstack uses a different event log format than the ACPI CCEL CC
//!   eventlog used by bare-metal TDX.
//! - **RTMR0-2 OS measurements**: platform/OS identity (firmware, kernel,
//!   initrd) is in RTMR0-2 but not compared against expected values unless
//!   pinned via [`VerifyDstack::rtmrs`].
//! - **Docker image digest pinning**: the compose-hash in RTMR3 covers the
//!   docker-compose configuration; verifying that images use `@sha256:` digests
//!   rather than mutable tags is the caller's responsibility.

use base64::{engine::general_purpose::STANDARD as BASE64, Engine};

use crate::collateral::TdxCollateralProvider;
use crate::error::Result;
use crate::types::{
    DstackResult, VendorParams, VendorResult, VerifyDstack, VerifyParams, VerifyResult, VerifyTdx,
};

use super::evidence::DstackEvidence;

/// Normalize a quote string to base64.
///
/// dstack historically returns hex-encoded quotes; the attestation pipeline
/// stores base64. This function accepts either encoding so that evidence
/// produced by both old (hex) and new (base64) versions can be verified.
///
/// Detection heuristic: hex-encoded TDX quotes are pure `[0-9a-fA-F]` strings
/// with even length. A TDX v4 quote is at least 632 bytes, so its hex encoding
/// is at least 1264 characters. Valid base64 strings almost always contain `+`,
/// `/`, or `=`, which cause `hex::decode` to fail, preventing false positives.
/// The minimum-length check further guards against short hex-safe strings.
fn normalize_quote_to_base64(quote: &str) -> String {
    // Minimum TDX quote size: header(48) + report_body(584) = 632 bytes → 1264 hex chars
    const MIN_TDX_QUOTE_HEX_LEN: usize = 1264;

    if quote.len() >= MIN_TDX_QUOTE_HEX_LEN {
        if let Ok(raw) = hex::decode(quote) {
            return BASE64.encode(&raw);
        }
    }
    quote.to_string()
}

/// Verify dstack TDX attestation evidence.
///
/// Since dstack produces standard Intel TDX v4/v5 quotes, verification
/// is delegated to the existing TDX DCAP verification pipeline. The only
/// difference is that the vendor result is tagged as Dstack.
pub async fn verify_evidence(
    evidence: &DstackEvidence,
    params: &VerifyParams,
    collateral_provider: Option<&dyn TdxCollateralProvider>,
) -> Result<VerifyResult> {
    // Validate field sizes
    crate::utils::check_field_size("quote", evidence.quote.len())?;

    let quote_b64 = normalize_quote_to_base64(&evidence.quote);

    // Convert DstackEvidence to TdxEvidence for reuse of TDX verification
    let tdx_evidence = crate::platforms::tdx::evidence::TdxEvidence {
        quote: quote_b64,
        // dstack's event_log is in a different format than the CC eventlog
        // from ACPI CCEL, so we don't pass it through to TDX verification
        cc_eventlog: None,
    };

    let inner_params = translate_params(params)?;
    let (quote, mut result) = crate::platforms::tdx::verify::verify_evidence_inner(
        &tdx_evidence,
        &inner_params,
        collateral_provider,
    )
    .await?;

    let tcb_status = match result.vendor {
        VendorResult::Tdx(t) => t.tcb_status,
        _ => None,
    };
    result.vendor = VendorResult::Dstack(DstackResult { quote, tcb_status });
    Ok(result)
}

fn translate_params(params: &VerifyParams) -> Result<VerifyParams> {
    let inner_vendor = match &params.vendor {
        VendorParams::Auto => VendorParams::Auto,
        VendorParams::Dstack(VerifyDstack {
            mrtd,
            rtmrs,
            mr_config_id,
        }) => VendorParams::Tdx(VerifyTdx {
            mrtd: *mrtd,
            rtmrs: *rtmrs,
            mr_config_id: *mr_config_id,
        }),
        other => {
            return Err(crate::error::AttestationError::PlatformMismatch {
                expected: "dstack".to_string(),
                actual: format!("{other:?}"),
            });
        }
    };
    Ok(VerifyParams {
        nonce: params.nonce.clone(),
        report_data: params.report_data.clone(),
        launch_measurement: params.launch_measurement.clone(),
        allow_debug: params.allow_debug,
        vendor: inner_vendor,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hex_input_above_min_size_is_converted_to_base64() {
        // 632 zero bytes → 1264 hex chars (minimum TDX quote size)
        let hex_input = "00".repeat(632);
        let result = normalize_quote_to_base64(&hex_input);
        // Should be base64-encoded, not the original hex
        assert_ne!(result, hex_input);
        let decoded = BASE64.decode(&result).expect("should be valid base64");
        assert_eq!(decoded.len(), 632);
        assert!(decoded.iter().all(|&b| b == 0));
    }

    #[test]
    fn base64_input_is_returned_unchanged() {
        // Real base64 contains characters like +, /, = that fail hex::decode
        let b64_input = BASE64.encode(vec![0xFFu8; 700]);
        let result = normalize_quote_to_base64(&b64_input);
        assert_eq!(result, b64_input);
    }

    #[test]
    fn short_hex_string_is_not_converted() {
        // Below MIN_TDX_QUOTE_HEX_LEN — should be treated as base64
        let short_hex = "deadbeef";
        let result = normalize_quote_to_base64(short_hex);
        assert_eq!(result, short_hex);
    }

    #[test]
    fn short_hex_at_boundary_is_not_converted() {
        // 631 bytes = 1262 hex chars (just under the 1264 threshold)
        let hex_input = "ab".repeat(631);
        let result = normalize_quote_to_base64(&hex_input);
        assert_eq!(
            result, hex_input,
            "should not convert hex below minimum TDX quote size"
        );
    }
}
