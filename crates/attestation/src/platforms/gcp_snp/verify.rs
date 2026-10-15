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

use crate::collateral::{Doc, GceEndorsement, GceTee, Provenance, Store};
use crate::error::{AttestationError, Result, Unavailable};
use crate::platform::Platform;
use crate::platforms::gcp_endorsement;
use crate::platforms::snp::evidence::SnpEvidence;
use crate::platforms::snp::verify::{genuine_report, SnpCollateral};
use crate::platforms::snp::{Snp, SnpParams, SnpResult};
use crate::types::PlatformType;

/// What a caller can ask of GCP SEV-SNP evidence.
#[derive(Debug, Clone, Default)]
pub struct GcpSnpParams {
    pub snp: SnpParams,
}

/// The answer for genuine GCP SEV-SNP evidence. `endorsement_match` proves
/// firmware provenance (a Google OVMF build), not that the host is GCP.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[must_use]
pub struct GcpSnpResult {
    #[serde(flatten)]
    pub snp: SnpResult,
    /// Google's endorsement for the report's launch measurement exists, lists
    /// it, and the guest policy is no wider than the endorsed one: the
    /// firmware is a Google OVMF build. Any SNP host can boot it,
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
/// bare-metal SNP. Google's launch endorsement for the firmware is collateral,
/// matched against the report's launch measurement and guest
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
    type Collateral = GcpSnpCollateral;

    fn validate(params: &GcpSnpParams) -> Result<()> {
        Snp::validate(&params.snp)
    }

    /// The Snp collateral and Google's endorsement for the measurement, if
    /// Google publishes one. A report that carries its VEK is checked first
    /// (as for Snp); one whose VCEK must be fetched is checked against it
    /// before the endorsement is looked at.
    async fn gather(evidence: &SnpEvidence, store: &Store, now: i64) -> Result<GcpSnpCollateral> {
        let (report, gen, inline) = genuine_report(evidence, now)?;
        let key = GceEndorsement {
            tee: GceTee::SevSnp,
            measurement: hex::encode(report.measurement),
        };
        let (snp, endorsement) = futures_util::join!(
            SnpCollateral::gather(&report, gen, inline, store, now),
            store.get(key, now)
        );
        let snp = snp?;
        let endorsement = match endorsement {
            Ok(doc) => Some(doc),
            Err(AttestationError::CollateralUnavailable {
                reason: Unavailable::NotFound { .. },
                ..
            }) => None,
            Err(e) => return Err(e),
        };
        Ok(GcpSnpCollateral { snp, endorsement })
    }

    fn verify(
        evidence: &SnpEvidence,
        params: &GcpSnpParams,
        collateral: &GcpSnpCollateral,
        now: i64,
    ) -> Result<GcpSnpResult> {
        let snp = Snp::verify(evidence, &params.snp, &collateral.snp, now)?;
        let report = gcp_endorsement::snp_report(evidence)?;
        let measurement = report.measurement.to_vec();
        let endorsement_match = collateral.endorsement.as_ref().is_some_and(|e| {
            e.key.measurement == hex::encode(&measurement)
                && gcp_endorsement::endorses_snp(&e.value, &measurement, report.policy.into())
        });
        Ok(GcpSnpResult {
            snp,
            endorsement_match: Some(endorsement_match),
        })
    }

    fn provenance(collateral: &GcpSnpCollateral) -> Vec<Provenance> {
        let mut docs = collateral.snp.provenance();
        docs.extend(collateral.endorsement.as_ref().map(|e| e.provenance()));
        docs
    }
}

/// What GcpSnp verification needs: the Snp collateral and Google's launch
/// endorsement for the firmware (`None` when Google publishes none for the
/// measurement).
pub struct GcpSnpCollateral {
    pub snp: SnpCollateral,
    pub endorsement: Option<Doc<GceEndorsement>>,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::collateral::{DocKey, Raw};
    use crate::platforms::snp::evidence::SnpCertChain;
    use crate::platforms::snp::verify::parse_report;
    use crate::testing;
    use crate::types::ProcessorGeneration;
    use base64::{engine::general_purpose::STANDARD as BASE64, Engine};

    const LIVE_REPORT_V5: &[u8] = include_bytes!("../../../test_data/snp/live-report-v5-genoa.bin");
    const LIVE_VCEK_GENOA: &[u8] = include_bytes!("../../../test_data/snp/live-vcek-genoa.der");

    /// Verify with the SNP collateral held and no endorsement.
    async fn verify_unendorsed(evidence: &SnpEvidence, params: &GcpSnpParams) -> GcpSnpResult {
        let ctx = testing::context(vec![testing::amd_crl(ProcessorGeneration::Genoa)]);
        let collateral = GcpSnpCollateral {
            snp: Snp::gather(evidence, ctx.store(), testing::NOW)
                .await
                .unwrap(),
            endorsement: None,
        };
        GcpSnp::verify(evidence, params, &collateral, testing::NOW).unwrap()
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
    async fn test_gcp_snp_propagates_launch_digest_and_needs_an_endorsement() {
        let report = parse_report(LIVE_REPORT_V5).unwrap();
        let mut expected = [0u8; 48];
        expected.copy_from_slice(&report.measurement[..]);
        let evidence = make_snp_evidence(LIVE_REPORT_V5, LIVE_VCEK_GENOA);
        let params = |digest| GcpSnpParams {
            snp: SnpParams {
                launch_digest: Some(vec![digest]),
                ..Default::default()
            },
        };
        let r = verify_unendorsed(&evidence, &params(expected)).await;
        assert_eq!(r.snp.launch_digest_match, Some(true));
        assert_eq!(r.endorsement_match, Some(false));
        assert!(!r.passed());
        let r = verify_unendorsed(&evidence, &params([0x77; 48])).await;
        assert_eq!(r.snp.launch_digest_match, Some(false));
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
        let report = gcp_endorsement::snp_report(&evidence).unwrap();
        let key = GceEndorsement {
            tee: GceTee::SevSnp,
            measurement: hex::encode(report.measurement),
        };
        let held: (DocKey, Raw) = (
            key.into(),
            Raw {
                body: endorsement.to_vec(),
                issuer_chain: None,
            },
        );
        testing::verify::<GcpSnp>(
            &evidence,
            &GcpSnpParams::default(),
            vec![testing::amd_crl(ProcessorGeneration::Milan), held],
        )
        .await
    }

    #[tokio::test]
    async fn test_gcp_snp_launch_endorsement() {
        let r = verify_endorsed(ENDORSEMENT).await.unwrap();
        assert_eq!(r.endorsement_match, Some(true));
        assert!(r.passed());
    }

    #[tokio::test]
    async fn an_endorsement_for_another_build_or_tampered_is_refused() {
        let mut tampered = ENDORSEMENT.to_vec();
        *tampered.last_mut().unwrap() ^= 1;
        for endorsement in [OTHER_BUILD_ENDORSEMENT.to_vec(), tampered] {
            let err = verify_endorsed(&endorsement).await.unwrap_err();
            assert!(matches!(err, AttestationError::CertChainError(_)), "{err}");
        }
    }

    #[tokio::test]
    async fn a_forged_report_is_not_genuine_and_names_no_collateral() {
        let envelope: serde_json::Value = serde_json::from_str(GCP_EVIDENCE).unwrap();
        let mut evidence: SnpEvidence =
            serde_json::from_value(envelope["evidence"].clone()).unwrap();
        let mut report = BASE64.decode(&evidence.attestation_report).unwrap();
        // A byte of REPORT_DATA: the report no longer matches its signature.
        report[0x50] ^= 1;
        evidence.attestation_report = BASE64.encode(report);
        let ctx = crate::context::Context::held([]);
        let err = GcpSnp::gather(&evidence, ctx.store(), testing::NOW)
            .await
            .err()
            .unwrap();
        assert!(!err.is_retryable(), "{err}");
        assert!(ctx.store().missing().is_empty());
    }
}
