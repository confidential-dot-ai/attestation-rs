// INVARIANT CLASS: Correctness
// GCP SNP verification is bare-metal SNP verification plus, when the caller
// supplies one, Google's launch endorsement for the firmware.
//
// THREAT MODEL:
//   Attacker controls: the hypervisor, guest OS environment, DMI/SMBIOS tables,
//   and the `platform` field in the attestation evidence envelope.
//   Attacker goal: obtain a result tagged GcpSnp and
//   an Ok result from hardware they control (not GCP).
//   Protection: The AMD hardware root-of-trust (ARK/ASK/VCEK chain) is the
//   trust anchor for the evidence. A valid result proves the hardware is a
//   genuine AMD SEV-SNP processor with an unrevoked VCEK. The endorsement
//   (signed under the pinned GCE-cc-tcb-root) proves only that the launch
//   measurement is a Google OVMF build.
//   Non-goal: This verifier cannot distinguish GCP hardware from any other
//   valid AMD SEV-SNP machine: any SNP host can boot Google's published OVMF,
//   so `endorsement_match` is firmware provenance, not host provenance. The
//   `GcpSnp` tag is an attester-reported claim.
//
// SECURITY NOTE: Policy engines should NOT grant elevated trust based on the
// `GcpSnp` tag or `endorsement_match` as proof of GCP origin. Use report
// fields (measurement, chip_id, TCB) instead.

use serde::{Deserialize, Serialize};

use crate::context::Context;
use crate::error::Result;
use crate::platform::Platform;
use crate::platforms::gcp_endorsement;
use crate::platforms::snp::evidence::SnpEvidence;
use crate::platforms::snp::{Snp, SnpParams, SnpResult};
use crate::types::PlatformType;

/// What a caller can ask of GCP SEV-SNP evidence.
#[derive(Debug, Clone, Default)]
pub struct GcpSnpParams {
    pub snp: SnpParams,
    /// Google's launch endorsement for the firmware (a serialized
    /// `VMLaunchEndorsement`, see
    /// [`endorsement_url`](crate::platforms::gcp_endorsement::endorsement_url)).
    /// An endorsement that does not verify is
    /// [`InvalidParams`](crate::AttestationError::InvalidParams).
    pub endorsement: Option<Vec<u8>>,
}

/// The answer for genuine GCP SEV-SNP evidence. `endorsement_match` proves
/// firmware provenance (a Google OVMF build), not that the host is GCP.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[must_use]
pub struct GcpSnpResult {
    #[serde(flatten)]
    pub snp: SnpResult,
    /// The endorsement lists the report's launch measurement and the guest
    /// policy is no wider than the endorsed one (`None` if no endorsement was
    /// given): the firmware is a Google OVMF build. Any SNP host can boot it,
    /// so this does not mean the host is GCP.
    pub endorsement_match: Option<bool>,
}

impl GcpSnpResult {
    /// True when the evidence satisfied every rule in the params.
    pub fn passed(&self) -> bool {
        self.snp.passed() && self.endorsement_match != Some(false)
    }
}

/// GCP Confidential VM running AMD SEV-SNP.
///
/// Delegates to the bare-metal SNP verifier. The attestation report format,
/// certificate chain, and all cryptographic verification are identical to
/// bare-metal SNP. A supplied launch endorsement is verified first (it is a
/// param) and matched against the report's launch measurement and guest
/// policy.
///
/// **Note:** The `GcpSnp` platform tag reflects the attester's claim, not a
/// cryptographic proof of GCP origin. Policy decisions should use report
/// fields (measurement, chip_id, TCB) rather than the platform tag alone.
pub struct GcpSnp;

impl Platform for GcpSnp {
    const KIND: PlatformType = PlatformType::GcpSnp;
    type Evidence = SnpEvidence;
    type Params = GcpSnpParams;
    type Result = GcpSnpResult;

    async fn verify(
        evidence: &SnpEvidence,
        params: &GcpSnpParams,
        ctx: &Context,
    ) -> Result<GcpSnpResult> {
        let golden = params
            .endorsement
            .as_deref()
            .map(|endorsement| gcp_endorsement::verify_endorsement(endorsement, ctx.now()))
            .transpose()?;
        let snp = Snp::verify(evidence, &params.snp, ctx).await?;
        let endorsement_match = match &golden {
            Some(golden) => {
                let report = gcp_endorsement::snp_report(evidence)?;
                Some(gcp_endorsement::endorses_snp(
                    golden,
                    &report.measurement[..],
                    report.policy.into(),
                ))
            }
            None => None,
        };
        Ok(GcpSnpResult {
            snp,
            endorsement_match,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::error::AttestationError;
    use crate::platforms::snp::evidence::SnpCertChain;
    use crate::platforms::snp::verify::parse_report;
    use crate::types::{ProcessorGeneration, SnpTcb};
    use base64::{engine::general_purpose::STANDARD as BASE64, Engine};

    const LIVE_REPORT_V5: &[u8] = include_bytes!("../../../test_data/snp/live-report-v5-genoa.bin");
    const LIVE_VCEK_GENOA: &[u8] = include_bytes!("../../../test_data/snp/live-vcek-genoa.der");

    /// Cert provider that returns the bundled live Genoa VCEK. No network,
    /// no CRL.
    struct StubCertProvider;

    #[async_trait::async_trait]
    impl crate::collateral::CertProvider for StubCertProvider {
        async fn get_snp_vcek(
            &self,
            _processor_gen: ProcessorGeneration,
            _chip_id: &[u8; 64],
            _reported_tcb: &SnpTcb,
        ) -> crate::error::Result<Vec<u8>> {
            Ok(LIVE_VCEK_GENOA.to_vec())
        }

        async fn get_snp_cert_chain(
            &self,
            _processor_gen: ProcessorGeneration,
        ) -> crate::error::Result<(Vec<u8>, Vec<u8>)> {
            Err(AttestationError::CollateralUnavailable(
                "stub provider does not serve full chain".to_string(),
            ))
        }
    }

    fn make_snp_evidence(report: &[u8], vcek_der: &[u8]) -> SnpEvidence {
        SnpEvidence {
            attestation_report: BASE64.encode(report),
            cert_chain: Some(SnpCertChain {
                vcek: BASE64.encode(vcek_der),
                ask: None,
                ark: None,
            }),
        }
    }

    #[tokio::test]
    async fn test_gcp_snp_propagates_matching_launch_digest() {
        let report = parse_report(LIVE_REPORT_V5).unwrap();
        let mut expected = [0u8; 48];
        expected.copy_from_slice(&report.measurement[..]);

        let evidence = make_snp_evidence(LIVE_REPORT_V5, LIVE_VCEK_GENOA);
        let params = GcpSnpParams {
            snp: SnpParams {
                launch_digest: Some(vec![expected]),
                ..Default::default()
            },
            ..Default::default()
        };
        let ctx = Context::offline().with_cert_provider(StubCertProvider);
        let r = GcpSnp::verify(&evidence, &params, &ctx).await.unwrap();
        assert_eq!(r.snp.launch_digest_match, Some(true));
    }

    #[tokio::test]
    async fn test_gcp_snp_propagates_wrong_launch_digest() {
        let evidence = make_snp_evidence(LIVE_REPORT_V5, LIVE_VCEK_GENOA);
        let params = GcpSnpParams {
            snp: SnpParams {
                launch_digest: Some(vec![[0x77; 48]]),
                ..Default::default()
            },
            ..Default::default()
        };
        let ctx = Context::offline().with_cert_provider(StubCertProvider);
        let r = GcpSnp::verify(&evidence, &params, &ctx).await.unwrap();
        assert_eq!(r.snp.launch_digest_match, Some(false));
        assert!(!r.passed());
    }

    // Real GCP SEV-SNP evidence (n2d, Milan, 2 vCPUs, host-supplied cert chain;
    // see test_data/gcp_snp/README.md) and the endorsements of two OVMF builds:
    // the one it booted and another.
    const GCP_EVIDENCE: &str = include_str!("../../../test_data/gcp_snp/evidence-boot1.json");
    const ENDORSEMENT: &[u8] =
        include_bytes!("../../../test_data/gcp_snp/endorsement-0e017d2f.binarypb");
    const OTHER_BUILD_ENDORSEMENT: &[u8] =
        include_bytes!("../../../test_data/gcp_tdx/endorsement-c1ee9c16.binarypb");

    async fn verify_endorsed(endorsement: &[u8]) -> Result<GcpSnpResult> {
        let envelope: serde_json::Value = serde_json::from_str(GCP_EVIDENCE).unwrap();
        let evidence: SnpEvidence = serde_json::from_value(envelope["evidence"].clone()).unwrap();
        let params = GcpSnpParams {
            endorsement: Some(endorsement.to_vec()),
            ..Default::default()
        };
        GcpSnp::verify(&evidence, &params, &Context::offline()).await
    }

    #[tokio::test]
    async fn test_gcp_snp_launch_endorsement() {
        let r = verify_endorsed(ENDORSEMENT).await.unwrap();
        assert_eq!(r.endorsement_match, Some(true));
        assert!(r.passed());

        let r = verify_endorsed(OTHER_BUILD_ENDORSEMENT).await.unwrap();
        assert_eq!(r.endorsement_match, Some(false));
        assert!(!r.passed());
    }

    #[tokio::test]
    async fn test_gcp_snp_tampered_endorsement_is_invalid_params() {
        let mut endorsement = ENDORSEMENT.to_vec();
        *endorsement.last_mut().unwrap() ^= 1;
        let err = verify_endorsed(&endorsement).await.unwrap_err();
        assert!(matches!(err, AttestationError::InvalidParams(_)), "{err}");
    }
}
