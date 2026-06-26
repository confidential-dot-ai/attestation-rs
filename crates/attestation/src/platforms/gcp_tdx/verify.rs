// INVARIANT CLASS: Correctness
// GCP TDX verification delegates entirely to the bare-metal TDX verifier.
// The only difference is the platform tag in the result, which allows
// callers to distinguish GCP-originated evidence for policy decisions.
//
// THREAT MODEL:
//   Attacker controls: the hypervisor, guest OS environment, DMI/SMBIOS tables,
//   and the `platform` field in the attestation evidence envelope.
//   Attacker goal: obtain a VerificationResult with platform=GcpTdx and
//   signature_valid=true from hardware they control (not GCP).
//   Protection: The Intel DCAP root-of-trust (Intel Root CA → PCK cert chain
//   → QE report → quote signature) is the only cryptographic trust anchor.
//   A valid result proves the hardware contains a genuine Intel TDX processor
//   with an unrevoked PCK certificate. It does NOT prove the hardware is
//   inside GCP's infrastructure.
//   Non-goal: This verifier cannot distinguish GCP hardware from any other
//   valid Intel TDX machine. The `GcpTdx` tag is an attester-reported claim.
//
// SECURITY NOTE: The `GcpTdx` platform tag in VerificationResult reflects
// what the *attester* claimed, not a cryptographic proof of GCP origin.
// The Intel TDX DCAP quote does not contain cloud-provider identity.
// Policy engines should NOT grant elevated trust based solely on the
// `GcpTdx` tag — use report fields (mr_td, rtmr_*, tee_tcb_svn) instead.

use crate::collateral::TdxCollateralProvider;
use crate::error::Result;
use crate::platforms::tdx::evidence::TdxEvidence;
use crate::types::{PlatformType, VerificationResult, VerifyParams};

/// Verify GCP TDX attestation evidence.
///
/// Delegates to the bare-metal TDX verification pipeline and overrides the
/// platform tag to `GcpTdx`. The quote format, DCAP certificate chain, and
/// all cryptographic verification are identical to bare-metal TDX.
///
/// **Note:** The `GcpTdx` platform tag reflects the attester's claim, not a
/// cryptographic proof of GCP origin. Policy decisions should use report
/// fields (mr_td, rtmr_*, tee_tcb_svn) rather than the platform tag alone.
pub async fn verify_evidence(
    evidence: &TdxEvidence,
    params: &VerifyParams,
    collateral_provider: Option<&dyn TdxCollateralProvider>,
) -> Result<VerificationResult> {
    let mut result =
        crate::platforms::tdx::verify::verify_evidence(evidence, params, collateral_provider)
            .await?;
    result.platform = PlatformType::GcpTdx;
    Ok(result)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::platforms::tdx::verify::parse_tdx_quote;
    use base64::{engine::general_purpose::STANDARD as BASE64, Engine};

    const V4_QUOTE: &[u8] = include_bytes!("../../../test_data/tdx_quote_4.dat");

    fn make_tdx_evidence(quote_bytes: &[u8]) -> TdxEvidence {
        TdxEvidence {
            quote: BASE64.encode(quote_bytes),
            cc_eventlog: None,
        }
    }

    #[tokio::test]
    async fn test_gcp_tdx_propagates_expected_mrtd_match() {
        let quote = parse_tdx_quote(V4_QUOTE).unwrap();
        let evidence = make_tdx_evidence(V4_QUOTE);
        let params = VerifyParams {
            allow_debug: true, // v4 fixture has the debug bit set
            expected_mrtd: Some(quote.body.mr_td),
            ..Default::default()
        };
        let r = verify_evidence(&evidence, &params, None).await.unwrap();
        assert_eq!(r.platform, PlatformType::GcpTdx);
        assert_eq!(r.mrtd_match, Some(true));
    }

    #[tokio::test]
    async fn test_gcp_tdx_propagates_wrong_mrtd_match() {
        let evidence = make_tdx_evidence(V4_QUOTE);
        let params = VerifyParams {
            allow_debug: true,
            expected_mrtd: Some([0x55; 48]),
            ..Default::default()
        };
        let r = verify_evidence(&evidence, &params, None).await.unwrap();
        assert_eq!(r.platform, PlatformType::GcpTdx);
        assert_eq!(r.mrtd_match, Some(false));
    }
}
