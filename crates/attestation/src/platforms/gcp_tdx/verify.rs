// INVARIANT CLASS: Correctness
// GCP TDX verification is bare-metal TDX verification plus, when the caller
// supplies one, Google's launch endorsement for the firmware.
//
// THREAT MODEL:
//   Attacker controls: the hypervisor, guest OS environment, DMI/SMBIOS tables,
//   and the `platform` field in the attestation evidence envelope.
//   Attacker goal: obtain a result tagged GcpTdx and
//   an Ok result from hardware they control (not GCP).
//   Protection: The Intel DCAP root-of-trust (Intel Root CA → PCK cert chain
//   → QE report → quote signature) is the trust anchor for the evidence.
//   A valid result proves the hardware contains a genuine Intel TDX processor
//   with an unrevoked PCK certificate. The endorsement (signed under the
//   pinned GCE-cc-tcb-root) proves only that the MRTD is a Google OVMF build.
//   Non-goal: This verifier cannot distinguish GCP hardware from any other
//   valid Intel TDX machine: any TDX host can boot Google's published OVMF,
//   so `endorsement_match` is firmware provenance, not host provenance. The
//   `GcpTdx` tag is an attester-reported claim.
//
// SECURITY NOTE: Policy engines should NOT grant elevated trust based on the
// `GcpTdx` tag or `endorsement_match` as proof of GCP origin. Use report
// fields (mr_td, rtmr_*, tee_tcb_svn) instead.

use serde::{Deserialize, Serialize};

use crate::context::Context;
use crate::error::Result;
use crate::platform::Platform;
use crate::platforms::gcp_endorsement;
use crate::platforms::tdx::evidence::TdxEvidence;
use crate::platforms::tdx::{Tdx, TdxParams, TdxResult};
use crate::types::PlatformType;

/// What a caller can ask of GCP TDX evidence.
#[derive(Debug, Clone, Default)]
pub struct GcpTdxParams {
    pub tdx: TdxParams,
    /// Google's launch endorsement for the firmware (a serialized
    /// `VMLaunchEndorsement`, see
    /// [`endorsement_url`](crate::platforms::gcp_endorsement::endorsement_url)).
    /// An endorsement that does not verify is
    /// [`InvalidParams`](crate::AttestationError::InvalidParams).
    pub endorsement: Option<Vec<u8>>,
}

/// The answer for genuine GCP TDX evidence. `endorsement_match` proves
/// firmware provenance (a Google OVMF build), not that the host is GCP.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[must_use]
pub struct GcpTdxResult {
    #[serde(flatten)]
    pub tdx: TdxResult,
    /// The endorsement lists the quote's MRTD (`None` if no endorsement was
    /// given): the firmware is a Google OVMF build. Any TDX host can boot it,
    /// so this does not mean the host is GCP.
    pub endorsement_match: Option<bool>,
}

impl GcpTdxResult {
    /// True when the evidence satisfied every rule in the params.
    pub fn passed(&self) -> bool {
        self.tdx.passed() && self.endorsement_match != Some(false)
    }
}

/// GCP Confidential VM running Intel TDX.
///
/// Delegates to the bare-metal TDX verifier. The quote format, DCAP
/// certificate chain, and all cryptographic verification are identical to
/// bare-metal TDX. A supplied launch endorsement is verified first (it is a
/// param) and matched against the quote's MRTD.
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
        let golden = params
            .endorsement
            .as_deref()
            .map(|endorsement| gcp_endorsement::verify_endorsement(endorsement, ctx.now()))
            .transpose()?;
        let tdx = Tdx::verify(evidence, &params.tdx, ctx).await?;
        let endorsement_match = match &golden {
            Some(golden) => Some(gcp_endorsement::endorses_tdx(
                golden,
                &gcp_endorsement::tdx_mrtd(evidence)?,
            )),
            None => None,
        };
        Ok(GcpTdxResult {
            tdx,
            endorsement_match,
        })
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
            ..Default::default()
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
            ..Default::default()
        };
        let r = GcpTdx::verify(&evidence, &params, &Context::offline())
            .await
            .unwrap();
        assert_eq!(r.tdx.mrtd_match, Some(false));
        assert!(!r.passed());
    }

    // A real GCP TDX quote and the endorsements of two OVMF builds: the one it
    // booted (lists its MRTD) and another (does not).
    const GCP_BOOT_QUOTE: &[u8] = include_bytes!("../../../test_data/gcp_tdx/boot-quote.dat");
    const ENDORSEMENT: &[u8] =
        include_bytes!("../../../test_data/gcp_tdx/endorsement-c1ee9c16.binarypb");
    const OTHER_BUILD_ENDORSEMENT: &[u8] =
        include_bytes!("../../../test_data/gcp_snp/endorsement-0e017d2f.binarypb");

    async fn verify_endorsed(endorsement: Option<&[u8]>) -> Result<GcpTdxResult> {
        let params = GcpTdxParams {
            endorsement: endorsement.map(<[u8]>::to_vec),
            ..Default::default()
        };
        GcpTdx::verify(
            &make_tdx_evidence(GCP_BOOT_QUOTE),
            &params,
            &Context::offline(),
        )
        .await
    }

    #[tokio::test]
    async fn test_gcp_tdx_launch_endorsement() {
        let r = verify_endorsed(Some(ENDORSEMENT)).await.unwrap();
        assert_eq!(r.endorsement_match, Some(true));
        assert!(r.passed());

        assert_eq!(verify_endorsed(None).await.unwrap().endorsement_match, None);

        let r = verify_endorsed(Some(OTHER_BUILD_ENDORSEMENT))
            .await
            .unwrap();
        assert_eq!(r.endorsement_match, Some(false));
        assert!(!r.passed());
    }

    #[tokio::test]
    async fn test_gcp_tdx_tampered_endorsement_is_invalid_params() {
        let mut endorsement = ENDORSEMENT.to_vec();
        *endorsement.last_mut().unwrap() ^= 1;
        let err = verify_endorsed(Some(&endorsement)).await.unwrap_err();
        assert!(
            matches!(err, crate::AttestationError::InvalidParams(_)),
            "{err}"
        );
    }
}
