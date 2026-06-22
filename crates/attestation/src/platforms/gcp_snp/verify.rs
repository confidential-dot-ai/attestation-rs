// INVARIANT CLASS: Correctness
// GCP SNP verification delegates entirely to the bare-metal SNP verifier.
// The only differences are:
//   1. The vendor result is re-tagged as GcpSnp.
//   2. The dispatcher accepts VendorParams::GcpSnp in addition to Auto.
//
// THREAT MODEL:
//   Attacker controls: the hypervisor, guest OS environment, DMI/SMBIOS tables,
//   and the `platform` field in the attestation evidence envelope.
//   Attacker goal: obtain a VerifyResult with vendor=GcpSnp and
//   signature_valid=true from hardware they control (not GCP).
//   Protection: The AMD hardware root-of-trust (ARK/ASK/VCEK chain) is the
//   only cryptographic trust anchor. A valid result proves the hardware is a
//   genuine AMD SEV-SNP processor with an unrevoked VCEK. It does NOT prove
//   the hardware is inside GCP's infrastructure.
//   Non-goal: This verifier cannot distinguish GCP hardware from any other
//   valid AMD SEV-SNP machine. The GcpSnp tag is an attester-reported claim.
//
// SECURITY NOTE: The GcpSnp vendor tag reflects what the *attester* claimed,
// not a cryptographic proof of GCP origin. The AMD SNP attestation report
// does not contain cloud-provider identity. Policy engines should NOT grant
// elevated trust based solely on the GcpSnp tag — use report fields
// (measurement, chip_id, TCB) instead.

use crate::collateral::CertProvider;
use crate::error::Result;
use crate::platforms::snp::evidence::SnpEvidence;
use crate::types::{
    GcpSnpResult, VendorParams, VendorResult, VerifyGcpSnp, VerifyParams, VerifyResult, VerifySnp,
};

/// Verify GCP SNP attestation evidence.
///
/// Delegates to the bare-metal SNP verification pipeline. The attestation
/// report format, certificate chain, and all cryptographic verification are
/// identical to bare-metal SNP.
///
/// **Note:** The `GcpSnp` vendor result reflects the attester's claim, not a
/// cryptographic proof of GCP origin. Policy decisions should use report
/// fields (measurement, chip_id, TCB) rather than the platform tag alone.
pub async fn verify_evidence(
    evidence: &SnpEvidence,
    params: &VerifyParams,
    cert_provider: &dyn CertProvider,
) -> Result<VerifyResult> {
    let inner_params = translate_params(params)?;
    let (report, mut result) = crate::platforms::snp::verify::verify_evidence_inner(
        evidence,
        &inner_params,
        cert_provider,
    )
    .await?;
    result.vendor = VendorResult::GcpSnp(GcpSnpResult {
        inner_snp_report: report,
        jwt_signature_valid: false,
    });
    Ok(result)
}

fn translate_params(params: &VerifyParams) -> Result<VerifyParams> {
    let inner_vendor = match &params.vendor {
        VendorParams::Auto => VendorParams::Auto,
        VendorParams::GcpSnp(VerifyGcpSnp {
            min_tcb,
            gcp_jwt_audience: _,
        }) => VendorParams::Snp(VerifySnp { min_tcb: *min_tcb }),
        other => {
            return Err(crate::error::AttestationError::PlatformMismatch {
                expected: "gcp-snp".to_string(),
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
    use crate::error::AttestationError;
    use crate::platforms::snp::evidence::SnpCertChain;
    use crate::platforms::snp::verify::parse_report;
    use crate::types::{ProcessorGeneration, SnpTcb};
    use base64::{engine::general_purpose::STANDARD as BASE64, Engine};

    // Same live Genoa v5 fixture used by the bare-metal SNP tests.
    const LIVE_REPORT_V5: &[u8] = include_bytes!("../../../test_data/snp/live-report-v5-genoa.bin");
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
    async fn test_gcp_snp_matching_launch_measurement() {
        let report = parse_report(LIVE_REPORT_V5).unwrap();
        let expected = report.measurement[..].to_vec();

        let evidence = make_snp_evidence(LIVE_REPORT_V5, LIVE_VCEK_GENOA);
        let params = VerifyParams {
            launch_measurement: Some(expected),
            ..Default::default()
        };
        let r = verify_evidence(&evidence, &params, &StubCertProvider)
            .await
            .unwrap();
        assert!(matches!(r.vendor, VendorResult::GcpSnp(_)));
        assert_eq!(r.launch_measurement_match, Some(true));
    }

    #[tokio::test]
    async fn test_gcp_snp_wrong_launch_measurement() {
        let evidence = make_snp_evidence(LIVE_REPORT_V5, LIVE_VCEK_GENOA);
        let params = VerifyParams {
            launch_measurement: Some(vec![0x77; 48]),
            ..Default::default()
        };
        let r = verify_evidence(&evidence, &params, &StubCertProvider)
            .await
            .unwrap();
        assert!(matches!(r.vendor, VendorResult::GcpSnp(_)));
        assert_eq!(r.launch_measurement_match, Some(false));
        assert!(r.signature_valid);
        assert!(r.policy_failed());
    }
}
