//! dstack TDX attestation verification.
//!
//! # What this module verifies
//!
//! Delegates to the TDX DCAP verification pipeline, which checks:
//! - TDX quote ECDSA P-256 signature (hardware-rooted)
//! - PCK certificate chain up to Intel SGX Root CA
//! - QE report signature and binding
//! - QE Identity against Intel's collateral
//! - TCB status evaluation and CRL revocation checks
//! - `report_data` binding (when `TdxParams::report_data` is set)
//! - `mr_config_id` binding (when `TdxParams::init_data` is set)
//!
//! # What the caller must verify
//!
//! The following checks are **not** performed by this module and are the
//! caller's responsibility (RTMR values are available in
//! `TdxResult::claims::platform_data`):
//!
//! - **RTMR3 event log replay**: dstack records compose-hash, instance-id, and
//!   key-provider events in RTMR3 via SHA-384 hash chaining. The event log is
//!   available in `DstackEvidence::event_log` but is not replayed or verified
//!   here. dstack uses a different event log format than the ACPI CCEL CC
//!   eventlog used by bare-metal TDX.
//! - **RTMR0-2 OS measurements**: platform/OS identity (firmware, kernel,
//!   initrd) is in RTMR0-2 but not compared against expected values.
//! - **Docker image digest pinning**: the compose-hash in RTMR3 covers the
//!   docker-compose configuration; verifying that images use `@sha256:` digests
//!   rather than mutable tags is the caller's responsibility.

use base64::{engine::general_purpose::STANDARD as BASE64, Engine};

use serde::{Deserialize, Serialize};

use crate::collateral::{Provenance, Store};
use crate::error::Result;
use crate::platform::Platform;
use crate::platforms::tdx::verify::TdxCollateral;
use crate::platforms::tdx::{Tdx, TdxParams, TdxResult};
use crate::types::PlatformType;

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

/// What a caller can ask of dstack evidence.
#[derive(Debug, Clone, Default)]
pub struct DstackParams {
    pub tdx: TdxParams,
}

/// The answer for genuine dstack evidence.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[must_use]
pub struct DstackResult {
    #[serde(flatten)]
    pub tdx: TdxResult,
}

impl DstackResult {
    /// True when the evidence satisfied every rule in the params.
    pub fn passed(&self) -> bool {
        self.tdx.passed()
    }
}

/// dstack (Phala) TDX. dstack produces standard Intel TDX v4/v5 quotes, so
/// verification is delegated to the TDX verifier.
pub struct Dstack;

impl Platform for Dstack {
    const KIND: PlatformType = PlatformType::Dstack;
    type Evidence = DstackEvidence;
    type Params = DstackParams;
    type Result = DstackResult;
    type Collateral = TdxCollateral;

    fn validate(params: &DstackParams) -> Result<()> {
        params.tdx.validate()
    }

    async fn gather(evidence: &DstackEvidence, store: &Store, now: i64) -> Result<TdxCollateral> {
        Tdx::gather(&tdx_evidence(evidence)?, store, now).await
    }

    fn verify(
        evidence: &DstackEvidence,
        params: &DstackParams,
        collateral: &TdxCollateral,
        now: i64,
    ) -> Result<DstackResult> {
        let tdx = Tdx::verify(&tdx_evidence(evidence)?, &params.tdx, collateral, now)?;
        Ok(DstackResult { tdx })
    }

    fn provenance(collateral: &TdxCollateral) -> Vec<Provenance> {
        collateral.provenance()
    }
}

/// dstack's event_log is in a different format than the CC eventlog from
/// ACPI CCEL, so it is not passed through to TDX verification.
fn tdx_evidence(evidence: &DstackEvidence) -> Result<crate::platforms::tdx::evidence::TdxEvidence> {
    crate::utils::check_field_size("quote", evidence.quote.len())?;
    Ok(crate::platforms::tdx::evidence::TdxEvidence {
        quote: normalize_quote_to_base64(&evidence.quote),
        cc_eventlog: None,
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
