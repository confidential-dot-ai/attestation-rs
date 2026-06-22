// INVARIANT CLASS: Correctness
// GCP TDX verification delegates entirely to the bare-metal TDX verifier.
// The only differences are:
//   1. The vendor result is re-tagged as GcpTdx (carries an optional JWT slot
//      for forward compatibility; today's envelope has no JWT so the slot is
//      None and jwt_signature_valid is false).
//   2. The dispatcher accepts VendorParams::GcpTdx in addition to Auto.
//
// THREAT MODEL:
//   Attacker controls: the hypervisor, guest OS environment, DMI/SMBIOS tables,
//   and the `platform` field in the attestation evidence envelope.
//   Attacker goal: obtain a VerifyResult with vendor=GcpTdx and
//   signature_valid=true from hardware they control (not GCP).
//   Protection: The Intel DCAP root-of-trust (Intel Root CA → PCK cert chain
//   → QE report → quote signature) is the only cryptographic trust anchor.
//   A valid result proves the hardware contains a genuine Intel TDX processor
//   with an unrevoked PCK certificate. It does NOT prove the hardware is
//   inside GCP's infrastructure.
//   Non-goal: This verifier cannot distinguish GCP hardware from any other
//   valid Intel TDX machine. The GcpTdx tag is an attester-reported claim.
//
// SECURITY NOTE: The GcpTdx tag in the VendorResult reflects what the
// *attester* claimed, not a cryptographic proof of GCP origin. The Intel
// TDX DCAP quote does not contain cloud-provider identity. Policy engines
// should NOT grant elevated trust based solely on the GcpTdx tag — use
// report fields (mr_td, rtmr_*, tee_tcb_svn) instead.

use crate::collateral::TdxCollateralProvider;
use crate::error::Result;
use crate::platforms::tdx::evidence::TdxEvidence;
use crate::platforms::vendor_helpers;
use crate::types::{
    GcpTdxResult, VendorParams, VendorResult, VerifyGcpTdx, VerifyParams, VerifyResult, VerifyTdx,
};

/// Verify GCP TDX attestation evidence.
///
/// Delegates to the bare-metal TDX verification pipeline. The quote format,
/// DCAP certificate chain, and all cryptographic verification are identical
/// to bare-metal TDX.
///
/// **Note:** The `GcpTdx` vendor result reflects the attester's claim, not a
/// cryptographic proof of GCP origin. Policy decisions should use report
/// fields (mr_td, rtmr_*, tee_tcb_svn) rather than the platform tag alone.
pub async fn verify_evidence(
    evidence: &TdxEvidence,
    params: &VerifyParams,
    collateral_provider: Option<&dyn TdxCollateralProvider>,
) -> Result<VerifyResult> {
    // Translate VendorParams::GcpTdx into VendorParams::Tdx for the bare-metal
    // inner pipeline (subset of fields). Auto stays Auto. Anything else is a
    // platform mismatch (the dispatcher already rejects those, this is
    // defense-in-depth).
    let inner_params = translate_params(params)?;

    let (quote, mut result) =
        crate::platforms::tdx::verify::verify_evidence_inner(evidence, &inner_params, collateral_provider)
            .await?;

    // Re-tag the vendor result as GcpTdx.
    let tcb_status = match result.vendor {
        VendorResult::Tdx(t) => t.tcb_status,
        // Unreachable: the inner only produces VendorResult::Tdx.
        _ => None,
    };
    let inner_tdx_quote = vendor_helpers::project_tdx_quote(&quote);
    let jwt_signature_valid = false; // No JWT in today's GCP envelope.
    result.vendor = VendorResult::GcpTdx(GcpTdxResult {
        jwt: None,
        inner_tdx_quote,
        tcb_status,
        jwt_signature_valid,
    });
    Ok(result)
}

/// Translate caller-supplied VendorParams for the GCP TDX dispatcher into
/// the bare-metal TDX VendorParams the inner pipeline understands.
fn translate_params(params: &VerifyParams) -> Result<VerifyParams> {
    let inner_vendor = match &params.vendor {
        VendorParams::Auto => VendorParams::Auto,
        VendorParams::GcpTdx(VerifyGcpTdx {
            mrtd,
            rtmrs,
            mr_config_id,
            gcp_jwt_audience: _, // No JWT today; pin ignored.
        }) => VendorParams::Tdx(VerifyTdx {
            mrtd: *mrtd,
            rtmrs: *rtmrs,
            mr_config_id: *mr_config_id,
        }),
        other => {
            return Err(crate::error::AttestationError::PlatformMismatch {
                expected: "gcp-tdx".to_string(),
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
    use crate::platforms::tdx::verify::parse_tdx_quote;
    use base64::{engine::general_purpose::STANDARD as BASE64, Engine};

    // Same v4 fixture the bare-metal TDX tests use.
    const V4_QUOTE: &[u8] = include_bytes!("../../../test_data/tdx_quote_4.dat");

    fn make_tdx_evidence(quote_bytes: &[u8]) -> TdxEvidence {
        TdxEvidence {
            quote: BASE64.encode(quote_bytes),
            cc_eventlog: None,
        }
    }

    #[tokio::test]
    async fn test_gcp_tdx_propagates_mrtd_pin_match() {
        let quote = parse_tdx_quote(V4_QUOTE).unwrap();
        let evidence = make_tdx_evidence(V4_QUOTE);
        let params = VerifyParams {
            allow_debug: true,
            vendor: VendorParams::GcpTdx(VerifyGcpTdx {
                mrtd: Some(quote.body.mr_td),
                ..Default::default()
            }),
            ..Default::default()
        };
        let r = verify_evidence(&evidence, &params, None).await.unwrap();
        assert!(matches!(r.vendor, VendorResult::GcpTdx(_)));
        assert!(!r.vendor_policy_failed);
    }

    #[tokio::test]
    async fn test_gcp_tdx_propagates_mrtd_pin_mismatch() {
        let evidence = make_tdx_evidence(V4_QUOTE);
        let params = VerifyParams {
            allow_debug: true,
            vendor: VendorParams::GcpTdx(VerifyGcpTdx {
                mrtd: Some([0x55; 48]),
                ..Default::default()
            }),
            ..Default::default()
        };
        let r = verify_evidence(&evidence, &params, None).await.unwrap();
        assert!(matches!(r.vendor, VendorResult::GcpTdx(_)));
        assert!(r.vendor_policy_failed);
        assert!(r.policy_failed());
    }
}
