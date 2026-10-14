// INVARIANT CLASS: Correctness
// GCP SNP verification delegates entirely to the bare-metal SNP verifier.
// The only difference is the platform tag in the result, which allows
// callers to distinguish GCP-originated evidence for policy decisions.
//
// THREAT MODEL:
//   Attacker controls: the hypervisor, guest OS environment, DMI/SMBIOS tables,
//   and the `platform` field in the attestation evidence envelope.
//   Attacker goal: obtain a result tagged GcpSnp and
//   an Ok result from hardware they control (not GCP).
//   Protection: The AMD hardware root-of-trust (ARK/ASK/VCEK chain) is the
//   only cryptographic trust anchor. A valid result proves the hardware is a
//   genuine AMD SEV-SNP processor with an unrevoked VCEK. It does NOT prove
//   the hardware is inside GCP's infrastructure.
//   Non-goal: This verifier cannot distinguish GCP hardware from any other
//   valid AMD SEV-SNP machine. The `GcpSnp` tag is an attester-reported claim.
//
// SECURITY NOTE: The `GcpSnp` platform tag in the result reflects
// what the *attester* claimed, not a cryptographic proof of GCP origin.
// The AMD SNP attestation report does not contain cloud-provider identity.
// Policy engines should NOT grant elevated trust based solely on the
// `GcpSnp` tag — use report fields (measurement, chip_id, TCB) instead.

use serde::{Deserialize, Serialize};

use crate::context::Context;
use crate::error::Result;
use crate::platform::Platform;
use crate::platforms::snp::evidence::SnpEvidence;
use crate::platforms::snp::{Snp, SnpParams, SnpResult};
use crate::types::PlatformType;

/// What a caller can ask of GCP SEV-SNP evidence.
#[derive(Debug, Clone, Default)]
pub struct GcpSnpParams {
    pub snp: SnpParams,
}

/// The answer for genuine GCP SEV-SNP evidence.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[must_use]
pub struct GcpSnpResult {
    #[serde(flatten)]
    pub snp: SnpResult,
}

impl GcpSnpResult {
    /// True when the evidence satisfied every rule in the params.
    pub fn passed(&self) -> bool {
        self.snp.passed()
    }
}

/// GCP Confidential VM running AMD SEV-SNP.
///
/// Delegates to the bare-metal SNP verifier. The attestation report format,
/// certificate chain, and all cryptographic verification are identical to
/// bare-metal SNP.
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
        let snp = Snp::verify(evidence, &params.snp, ctx).await?;
        Ok(GcpSnpResult { snp })
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
        };
        let ctx = Context::offline().with_cert_provider(StubCertProvider);
        let r = GcpSnp::verify(&evidence, &params, &ctx).await.unwrap();
        assert_eq!(r.snp.launch_digest_match, Some(false));
        assert!(!r.passed());
    }
}
