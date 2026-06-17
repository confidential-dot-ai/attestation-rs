// INVARIANT CLASS: Correctness
// GCP SNP verification delegates entirely to the bare-metal SNP verifier.
// The only difference is the platform tag in the result, which allows
// callers to distinguish GCP-originated evidence for policy decisions.
//
// THREAT MODEL:
//   Attacker controls: the hypervisor, guest OS environment, DMI/SMBIOS tables,
//   and the `platform` field in the attestation evidence envelope.
//   Attacker goal: obtain a VerificationResult with platform=GcpSnp and
//   signature_valid=true from hardware they control (not GCP).
//   Protection: The AMD hardware root-of-trust (ARK/ASK/VCEK chain) is the
//   only cryptographic trust anchor. A valid result proves the hardware is a
//   genuine AMD SEV-SNP processor with an unrevoked VCEK. It does NOT prove
//   the hardware is inside GCP's infrastructure.
//   Non-goal: This verifier cannot distinguish GCP hardware from any other
//   valid AMD SEV-SNP machine. The `GcpSnp` tag is an attester-reported claim.
//
// SECURITY NOTE: The `GcpSnp` platform tag in VerificationResult reflects
// what the *attester* claimed, not a cryptographic proof of GCP origin.
// The AMD SNP attestation report does not contain cloud-provider identity.
// Policy engines should NOT grant elevated trust based solely on the
// `GcpSnp` tag — use report fields (measurement, chip_id, TCB) instead.

use crate::collateral::CertProvider;
use crate::error::Result;
use crate::platforms::snp::evidence::SnpEvidence;
use crate::types::{PlatformType, VerificationResult, VerifyParams};

/// Verify GCP SNP attestation evidence.
///
/// Delegates to the bare-metal SNP verification pipeline and overrides the
/// platform tag to `GcpSnp`. The attestation report format, certificate chain,
/// and all cryptographic verification are identical to bare-metal SNP.
///
/// **Note:** The `GcpSnp` platform tag reflects the attester's claim, not a
/// cryptographic proof of GCP origin. Policy decisions should use report
/// fields (measurement, chip_id, TCB) rather than the platform tag alone.
pub async fn verify_evidence(
    evidence: &SnpEvidence,
    params: &VerifyParams,
    cert_provider: &dyn CertProvider,
) -> Result<VerificationResult> {
    let mut result =
        crate::platforms::snp::verify::verify_evidence(evidence, params, cert_provider).await?;
    result.platform = PlatformType::GcpSnp;
    Ok(result)
}

#[cfg(test)]
mod tests {
    use super::*;
    use base64::{engine::general_purpose::STANDARD as BASE64, Engine};
    use crate::error::AttestationError;
    use crate::platforms::snp::evidence::SnpCertChain;
    use crate::platforms::snp::verify::parse_report;
    use crate::types::{ProcessorGeneration, SnpTcb};

    // Same live Genoa v5 fixture used by the bare-metal SNP tests.
    const LIVE_REPORT_V5: &[u8] =
        include_bytes!("../../../test_data/snp/live-report-v5-genoa.bin");
    const LIVE_VCEK_GENOA: &[u8] = include_bytes!("../../../test_data/snp/live-vcek-genoa.der");

    /// Cert provider that returns the bundled live Genoa VCEK. No network,
    /// no CRL (so collateral_verified=false).
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
            Err(AttestationError::CertFetchError(
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
        let params = VerifyParams {
            expected_launch_digest: Some(expected),
            ..Default::default()
        };
        let r = verify_evidence(&evidence, &params, &StubCertProvider).await.unwrap();
        assert_eq!(r.platform, PlatformType::GcpSnp);
        assert_eq!(r.launch_digest_match, Some(true));
    }

    #[tokio::test]
    async fn test_gcp_snp_propagates_wrong_launch_digest() {
        let evidence = make_snp_evidence(LIVE_REPORT_V5, LIVE_VCEK_GENOA);
        let params = VerifyParams {
            expected_launch_digest: Some([0x77; 48]),
            ..Default::default()
        };
        let r = verify_evidence(&evidence, &params, &StubCertProvider).await.unwrap();
        assert_eq!(r.platform, PlatformType::GcpSnp);
        assert_eq!(r.launch_digest_match, Some(false));
        // Even with wrong digest, signature still valid — policy decision in caller
        assert!(r.signature_valid);
    }
}
