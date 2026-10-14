// INVARIANT CLASS: Correctness
// GCP TDX verification delegates entirely to the bare-metal TDX verifier.
// The only difference is the platform tag in the result, which allows
// callers to distinguish GCP-originated evidence for policy decisions.
//
// THREAT MODEL:
//   Attacker controls: the hypervisor, guest OS environment, DMI/SMBIOS tables,
//   and the `platform` field in the attestation evidence envelope.
//   Attacker goal: obtain a result tagged GcpTdx and
//   an Ok result from hardware they control (not GCP).
//   Protection: The Intel DCAP root-of-trust (Intel Root CA → PCK cert chain
//   → QE report → quote signature) is the only cryptographic trust anchor.
//   A valid result proves the hardware contains a genuine Intel TDX processor
//   with an unrevoked PCK certificate. It does NOT prove the hardware is
//   inside GCP's infrastructure.
//   Non-goal: This verifier cannot distinguish GCP hardware from any other
//   valid Intel TDX machine. The `GcpTdx` tag is an attester-reported claim.
//
// SECURITY NOTE: The `GcpTdx` platform tag in the result reflects
// what the *attester* claimed, not a cryptographic proof of GCP origin.
// The Intel TDX DCAP quote does not contain cloud-provider identity.
// Policy engines should NOT grant elevated trust based solely on the
// `GcpTdx` tag — use report fields (mr_td, rtmr_*, tee_tcb_svn) instead.

use serde::{Deserialize, Serialize};

use crate::context::Context;
use crate::error::Result;
use crate::platform::Platform;
use crate::platforms::tdx::evidence::TdxEvidence;
use crate::platforms::tdx::{Tdx, TdxParams, TdxResult};
use crate::types::PlatformType;

/// What a caller can ask of GCP TDX evidence.
#[derive(Debug, Clone, Default)]
pub struct GcpTdxParams {
    pub tdx: TdxParams,
}

/// The answer for genuine GCP TDX evidence.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[must_use]
pub struct GcpTdxResult {
    #[serde(flatten)]
    pub tdx: TdxResult,
}

impl GcpTdxResult {
    /// True when the evidence satisfied every rule in the params.
    pub fn passed(&self) -> bool {
        self.tdx.passed()
    }
}

/// GCP Confidential VM running Intel TDX.
///
/// Delegates to the bare-metal TDX verifier. The quote format, DCAP
/// certificate chain, and all cryptographic verification are identical to
/// bare-metal TDX.
///
/// **Note:** The `GcpTdx` platform tag reflects the attester's claim, not a
/// cryptographic proof of GCP origin. Policy decisions should use report
/// fields (mr_td, rtmr_*, tee_tcb_svn) rather than the platform tag alone.
pub struct GcpTdx;

impl Platform for GcpTdx {
    const KIND: PlatformType = PlatformType::GcpTdx;
    type Evidence = TdxEvidence;
    type Params = GcpTdxParams;
    type Result = GcpTdxResult;

    async fn verify(
        evidence: &TdxEvidence,
        params: &GcpTdxParams,
        ctx: &Context,
    ) -> Result<GcpTdxResult> {
        let tdx = Tdx::verify(evidence, &params.tdx, ctx).await?;
        Ok(GcpTdxResult { tdx })
    }
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
        let params = GcpTdxParams {
            tdx: TdxParams {
                allow_debug: true, // v4 fixture has the debug bit set
                mrtd: Some(vec![quote.body.mr_td]),
                ..Default::default()
            },
        };
        let r = GcpTdx::verify(&evidence, &params, &Context::offline())
            .await
            .unwrap();
        assert_eq!(r.tdx.mrtd_match, Some(true));
    }

    #[tokio::test]
    async fn test_gcp_tdx_propagates_wrong_mrtd_match() {
        let evidence = make_tdx_evidence(V4_QUOTE);
        let params = GcpTdxParams {
            tdx: TdxParams {
                allow_debug: true,
                mrtd: Some(vec![[0x55; 48]]),
                ..Default::default()
            },
        };
        let r = GcpTdx::verify(&evidence, &params, &Context::offline())
            .await
            .unwrap();
        assert_eq!(r.tdx.mrtd_match, Some(false));
        assert!(!r.passed());
    }
}
