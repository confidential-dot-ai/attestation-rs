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

use crate::collateral::{CollateralUsed, GceEndorsement, Store};
use crate::error::Result;
use crate::platform::Platform;
use crate::platforms::gcp_endorsement;
use crate::platforms::tdx::evidence::TdxEvidence;
use crate::platforms::tdx::verify::{genuine_quote, TdxCollateralSet};
use crate::platforms::tdx::{Tdx, TdxParams, TdxResult};
use crate::types::PlatformType;

/// What a caller can ask of GCP TDX evidence.
#[derive(Debug, Clone, Default)]
pub struct GcpTdxParams {
    pub tdx: TdxParams,
}

/// The answer for genuine GCP TDX evidence. `endorsement_match` proves
/// firmware provenance (a Google OVMF build), not that the host is GCP.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[must_use]
pub struct GcpTdxResult {
    #[serde(flatten)]
    pub tdx: TdxResult,
    /// Google's endorsement for the quote's MRTD exists and lists it: the
    /// firmware is a Google OVMF build. Any TDX host can boot it,
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
/// bare-metal TDX. Google's launch endorsement for the firmware is collateral,
/// matched against the quote's MRTD.
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
    type CollateralSet = GcpTdxCollateralSet;

    fn validate(params: &GcpTdxParams) -> Result<()> {
        Tdx::validate(&params.tdx)
    }

    /// The Tdx collateral and Google's endorsement for the MRTD, if Google
    /// publishes one, fetched once the quote has verified (as for Tdx).
    async fn gather(
        evidence: &TdxEvidence,
        store: &Store,
        now: i64,
    ) -> Result<(GcpTdxCollateralSet, Vec<CollateralUsed>)> {
        let (quote_bytes, quote) = genuine_quote(evidence, now)?;
        let mrtd = (Self::KIND, quote.body.mr_td.to_vec());
        let (tdx, endorsement) = futures_util::join!(
            TdxCollateralSet::gather(&quote_bytes, &quote, store, now),
            store.get_if_published::<GceEndorsement>(&mrtd, now)
        );
        let (tdx, mut used) = tdx?;
        let endorsement = endorsement?.map(|(endorsement, u)| {
            used.push(u);
            endorsement
        });
        Ok((GcpTdxCollateralSet { tdx, endorsement }, used))
    }

    fn verify(
        evidence: &TdxEvidence,
        params: &GcpTdxParams,
        collateral: &GcpTdxCollateralSet,
        now: i64,
    ) -> Result<GcpTdxResult> {
        let tdx = Tdx::verify(evidence, &params.tdx, &collateral.tdx, now)?;

        let measurement = gcp_endorsement::tdx_mrtd(evidence)?.to_vec();
        let endorsement_match = collateral
            .endorsement
            .as_ref()
            .is_some_and(|e| gcp_endorsement::endorses_tdx(&e.golden, &measurement));
        Ok(GcpTdxResult {
            tdx,
            endorsement_match: Some(endorsement_match),
        })
    }
}

/// The GcpTdx collateral set: the Tdx collateral set and Google's launch
/// endorsement for the firmware (`None` when Google publishes none for the
/// measurement).
pub struct GcpTdxCollateralSet {
    pub tdx: TdxCollateralSet,
    pub endorsement: Option<GceEndorsement>,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::platforms::tdx::verify::parse_tdx_quote;
    use crate::testing;
    use crate::AttestationError;
    use base64::{engine::general_purpose::STANDARD as BASE64, Engine};

    // A real GCP TDX quote and the endorsements of two OVMF builds: the one it
    // booted (lists its MRTD) and another (does not).
    const GCP_BOOT_QUOTE: &[u8] = include_bytes!("../../../test_data/gcp_tdx/boot-quote.dat");
    const ENDORSEMENT: &[u8] =
        include_bytes!("../../../test_data/gcp_tdx/endorsement-c1ee9c16.binarypb");
    const OTHER_BUILD_ENDORSEMENT: &[u8] =
        include_bytes!("../../../test_data/gcp_snp/endorsement-0e017d2f.binarypb");

    fn evidence() -> TdxEvidence {
        TdxEvidence {
            quote: BASE64.encode(GCP_BOOT_QUOTE),
            cc_eventlog: None,
        }
    }

    async fn verify(endorsement: &[u8], params: &GcpTdxParams) -> Result<GcpTdxResult> {
        let mrtd = parse_tdx_quote(GCP_BOOT_QUOTE).unwrap().body.mr_td;
        let url = <GceEndorsement as crate::collateral::Collateral>::url(&(
            PlatformType::GcpTdx,
            mrtd.to_vec(),
        ));
        let mut held = testing::intel();
        held.push((url, endorsement.to_vec(), None));
        testing::verify::<GcpTdx>(&evidence(), params, held).await
    }

    #[tokio::test]
    async fn test_gcp_tdx_launch_endorsement_and_mrtd() {
        let mrtd = parse_tdx_quote(GCP_BOOT_QUOTE).unwrap().body.mr_td;
        let params = |mrtd| GcpTdxParams {
            tdx: TdxParams {
                mrtd: Some(vec![mrtd]),
                ..Default::default()
            },
        };
        let r = verify(ENDORSEMENT, &params(mrtd)).await.unwrap();
        assert_eq!(r.endorsement_match, Some(true));
        assert_eq!(r.tdx.mrtd_match, Some(true));
        let r = verify(ENDORSEMENT, &params([0x55; 48])).await.unwrap();
        assert_eq!(r.tdx.mrtd_match, Some(false));
        assert!(!r.passed());
    }

    #[tokio::test]
    async fn an_endorsement_for_another_build_or_tampered_is_refused() {
        let mut tampered = ENDORSEMENT.to_vec();
        *tampered.last_mut().unwrap() ^= 1;
        for endorsement in [OTHER_BUILD_ENDORSEMENT.to_vec(), tampered] {
            let err = verify(&endorsement, &GcpTdxParams::default())
                .await
                .unwrap_err();
            assert!(matches!(err, AttestationError::CertChainError(_)), "{err}");
        }
    }

    #[tokio::test]
    async fn without_an_endorsement_the_firmware_is_not_endorsed() {
        let ctx = testing::context(testing::intel());
        let collateral = GcpTdxCollateralSet {
            tdx: Tdx::gather(&evidence(), ctx.store(), testing::NOW)
                .await
                .unwrap()
                .0,
            endorsement: None,
        };
        let r = GcpTdx::verify(
            &evidence(),
            &GcpTdxParams::default(),
            &collateral,
            testing::NOW,
        )
        .unwrap();
        assert_eq!(r.endorsement_match, Some(false));
        assert!(!r.passed());
    }

    #[tokio::test]
    async fn a_forged_quote_is_not_genuine_and_names_no_collateral() {
        let mut quote = GCP_BOOT_QUOTE.to_vec();
        // A byte of REPORTDATA: the quote no longer matches its signature.
        quote[crate::platforms::tdx::verify::QUOTE_HEADER_SIZE + 520] ^= 1;
        let forged = TdxEvidence {
            quote: BASE64.encode(quote),
            cc_eventlog: None,
        };
        let ctx = crate::context::Context::held([]);
        let err = GcpTdx::gather(&forged, ctx.store(), testing::NOW)
            .await
            .err()
            .unwrap();
        assert!(!err.is_retryable(), "{err}");
        assert!(ctx.store().missing().is_empty());
    }
}
