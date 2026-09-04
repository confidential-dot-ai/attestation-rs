use std::sync::Arc;
use std::time::Duration;

use base64::engine::general_purpose::STANDARD as BASE64;
use base64::Engine;
use serde::Deserialize;
use serde_json::Value;
use tokio::time::timeout;

use attestation::platforms::snp::certs::get_bundled_certs;
use attestation::platforms::snp::evidence::{SnpCertChain, SnpEvidence};
use attestation::platforms::snp::verify::{parse_report, verify_cert_chain};
use attestation::{CertProvider, ProcessorGeneration, SnpTcb};

/// Bound on the VCEK lookup as seen by the request; a timed-out fetch keeps
/// running detached so it can still warm the cache for the next request.
const VCEK_LOOKUP_TIMEOUT: Duration = Duration::from_secs(5);

/// Embed `cert_chain.vcek` into chainless bare-SNP evidence via the given
/// cert provider, so offline verifiers get the chain without their own KDS
/// fetch. Returns the evidence unchanged when a chain is already present or
/// the VCEK cannot be resolved within [`VCEK_LOOKUP_TIMEOUT`] — enrichment
/// never fails the request.
pub async fn enrich_snp_evidence(provider: Arc<dyn CertProvider>, evidence: Value) -> Value {
    let snp = match SnpEvidence::deserialize(&evidence) {
        Ok(snp) => snp,
        Err(e) => {
            // /attest produced this evidence in-process, so a shape mismatch
            // is a bug in this binary, not an input condition.
            tracing::error!(error = %e, "SNP evidence does not round-trip; skipping VCEK enrichment");
            return evidence;
        }
    };
    if snp.cert_chain.is_some() {
        return evidence;
    }

    let (gen, chip_id, tcb) = match vcek_identity(&snp.attestation_report) {
        Ok(identity) => identity,
        Err(reason) => {
            tracing::warn!(
                reason,
                "cannot derive VCEK identity from SNP report; serving chainless evidence"
            );
            return evidence;
        }
    };

    let lookup = tokio::spawn(async move { provider.get_snp_vcek(gen, &chip_id, &tcb).await });
    let vcek_der = match timeout(VCEK_LOOKUP_TIMEOUT, lookup).await {
        Ok(Ok(Ok(vcek_der))) => vcek_der,
        Ok(Ok(Err(e))) => {
            tracing::warn!(error = %e, "VCEK unavailable; serving chainless evidence");
            return evidence;
        }
        Ok(Err(e)) => {
            tracing::error!(error = %e, "VCEK lookup task failed; serving chainless evidence");
            return evidence;
        }
        Err(_) => {
            tracing::warn!(
                timeout_secs = VCEK_LOOKUP_TIMEOUT.as_secs(),
                "VCEK lookup timed out; serving chainless evidence"
            );
            return evidence;
        }
    };

    // Embedded certs bypass the verifier's own KDS fallback, so never embed
    // bytes that don't chain to the bundled AMD anchors.
    let (ark, ask) = get_bundled_certs(gen);
    if let Err(e) = verify_cert_chain(ark, ask, &vcek_der) {
        tracing::warn!(error = %e, "resolved VCEK fails AMD chain validation; serving chainless evidence");
        return evidence;
    }

    let enriched = SnpEvidence {
        attestation_report: snp.attestation_report,
        cert_chain: Some(SnpCertChain {
            vcek: BASE64.encode(vcek_der),
            ask: None,
            ark: None,
        }),
    };
    serde_json::to_value(&enriched).unwrap_or(evidence)
}

/// Derive the KDS lookup identity (generation, chip_id, reported TCB) from a
/// base64-encoded SNP report. Mirrors attestation-rs snp::verify::resolve_vcek.
fn vcek_identity(report_b64: &str) -> Result<(ProcessorGeneration, [u8; 64], SnpTcb), String> {
    let report_bytes = BASE64
        .decode(report_b64)
        .map_err(|e| format!("attestation_report base64: {e}"))?;
    let report = parse_report(&report_bytes).map_err(|e| format!("report parse: {e}"))?;

    if report.chip_id.iter().all(|&b| b == 0) {
        return Err(
            "chip_id is all zeros (MASK_CHIP_ID set); VCEK cannot be looked up".to_string(),
        );
    }

    let (Some(fam), Some(model)) = (report.cpuid_fam_id, report.cpuid_mod_id) else {
        return Err(format!(
            "report v{} lacks CPUID family/model fields",
            report.version
        ));
    };
    let gen = ProcessorGeneration::from_cpuid(fam, model)
        .ok_or_else(|| format!("unknown processor: family=0x{fam:02X}, model=0x{model:02X}"))?;

    let tcb = SnpTcb {
        bootloader: report.reported_tcb.bootloader,
        tee: report.reported_tcb.tee,
        snp: report.reported_tcb.snp,
        microcode: report.reported_tcb.microcode,
        fmc: if gen == ProcessorGeneration::Turin {
            report.reported_tcb.fmc
        } else {
            None
        },
    };
    let mut chip_id = [0u8; 64];
    chip_id.copy_from_slice(&report.chip_id[..]);
    Ok((gen, chip_id, tcb))
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;
    use std::sync::Mutex;

    // Real report/VCEK pair from lunal-dev/attestation-rs test_data (Apache-2.0).
    const REPORT_V5_GENOA: &[u8] =
        include_bytes!("../../../attestation/test_data/snp/live-report-v5-genoa.bin");
    const VCEK_GENOA: &[u8] =
        include_bytes!("../../../attestation/test_data/snp/live-vcek-genoa.der");
    const REPORT_V2_MILAN: &[u8] =
        include_bytes!("../../../attestation/test_data/snp/test-report.bin");

    // Identity of REPORT_V5_GENOA, spelled literally so derivation drift fails loudly.
    const V5_CHIP_ID_HEX: &str = "b5f9a4c8280e63c97d288db6648577dc2b848884aa682d7a227ba40e50deb2b0\
d112b599d87aaccda78d06f4254b1e81c4d953ef3c699db39d4e06013e9fa4ce";
    const V5_TCB: SnpTcb = SnpTcb {
        bootloader: 0x0A,
        tee: 0x00,
        snp: 0x1B,
        microcode: 0x1B,
        fmc: None,
    };

    /// Stub provider: records the lookup arguments and serves a fixed response.
    struct StubProvider {
        response: Result<Vec<u8>, String>,
        calls: Mutex<Vec<(ProcessorGeneration, [u8; 64], SnpTcb)>>,
    }

    impl StubProvider {
        fn ok(vcek_der: &[u8]) -> Arc<Self> {
            Arc::new(Self {
                response: Ok(vcek_der.to_vec()),
                calls: Mutex::new(Vec::new()),
            })
        }

        fn err(message: &str) -> Arc<Self> {
            Arc::new(Self {
                response: Err(message.to_string()),
                calls: Mutex::new(Vec::new()),
            })
        }
    }

    #[async_trait::async_trait]
    impl CertProvider for StubProvider {
        async fn get_snp_vcek(
            &self,
            gen: ProcessorGeneration,
            chip_id: &[u8; 64],
            tcb: &SnpTcb,
        ) -> attestation::Result<Vec<u8>> {
            self.calls.lock().unwrap().push((gen, *chip_id, *tcb));
            self.response
                .clone()
                .map_err(attestation::AttestationError::CertFetchError)
        }

        async fn get_snp_cert_chain(
            &self,
            _gen: ProcessorGeneration,
        ) -> attestation::Result<(Vec<u8>, Vec<u8>)> {
            unreachable!("enrichment never fetches the ARK/ASK chain")
        }
    }

    /// Provider with no network: every fetch errors (for the verifier round-trip).
    struct OfflineProvider;

    #[async_trait::async_trait]
    impl CertProvider for OfflineProvider {
        async fn get_snp_vcek(
            &self,
            _gen: ProcessorGeneration,
            _chip_id: &[u8; 64],
            _tcb: &SnpTcb,
        ) -> attestation::Result<Vec<u8>> {
            Err(attestation::AttestationError::CertFetchError(
                "offline".to_string(),
            ))
        }

        async fn get_snp_cert_chain(
            &self,
            _gen: ProcessorGeneration,
        ) -> attestation::Result<(Vec<u8>, Vec<u8>)> {
            Err(attestation::AttestationError::CertFetchError(
                "offline".to_string(),
            ))
        }
    }

    /// Provider whose lookup never resolves (for the timeout arm).
    struct HangingProvider;

    #[async_trait::async_trait]
    impl CertProvider for HangingProvider {
        async fn get_snp_vcek(
            &self,
            _gen: ProcessorGeneration,
            _chip_id: &[u8; 64],
            _tcb: &SnpTcb,
        ) -> attestation::Result<Vec<u8>> {
            std::future::pending().await
        }

        async fn get_snp_cert_chain(
            &self,
            _gen: ProcessorGeneration,
        ) -> attestation::Result<(Vec<u8>, Vec<u8>)> {
            unreachable!("enrichment never fetches the ARK/ASK chain")
        }
    }

    fn chainless_evidence(report: &[u8]) -> Value {
        json!({
            "attestation_report": BASE64.encode(report),
            "cert_chain": null,
        })
    }

    #[test]
    fn vcek_identity_extracts_report_fields() {
        let (gen, chip_id, tcb) = vcek_identity(&BASE64.encode(REPORT_V5_GENOA)).unwrap();
        assert_eq!(gen, ProcessorGeneration::Genoa);
        assert_eq!(hex::encode(chip_id), V5_CHIP_ID_HEX);
        assert_eq!(tcb, V5_TCB);
    }

    #[tokio::test]
    async fn enriches_chainless_evidence_and_result_verifies() {
        let provider = StubProvider::ok(VCEK_GENOA);
        let enriched =
            enrich_snp_evidence(provider.clone(), chainless_evidence(REPORT_V5_GENOA)).await;

        // The lookup used the report's own identity.
        {
            let calls = provider.calls.lock().unwrap();
            assert_eq!(calls.len(), 1);
            let (gen, chip_id, tcb) = &calls[0];
            assert_eq!(*gen, ProcessorGeneration::Genoa);
            assert_eq!(hex::encode(chip_id), V5_CHIP_ID_HEX);
            assert_eq!(*tcb, V5_TCB);
        }

        assert_eq!(
            enriched["cert_chain"]["vcek"],
            json!(BASE64.encode(VCEK_GENOA))
        );
        assert_eq!(
            enriched["attestation_report"],
            json!(BASE64.encode(REPORT_V5_GENOA))
        );

        // End to end: the enriched evidence verifies offline — the verifier's
        // provider errors, so the chain can only come from the evidence.
        let envelope = json!({ "platform": "snp", "evidence": enriched });
        let verifier = attestation::Verifier::new().with_cert_provider(OfflineProvider);
        let result = verifier
            .verify(
                &serde_json::to_vec(&envelope).unwrap(),
                &attestation::VerifyParams::default(),
            )
            .await
            .expect("enriched evidence must verify offline");
        assert!(result.signature_valid);
    }

    #[tokio::test]
    async fn keeps_existing_cert_chain() {
        let provider = StubProvider::ok(VCEK_GENOA);
        let evidence = json!({
            "attestation_report": BASE64.encode(REPORT_V5_GENOA),
            "cert_chain": { "vcek": "aHlwZXJ2aXNvcg==" },
        });
        let result = enrich_snp_evidence(provider.clone(), evidence.clone()).await;
        assert_eq!(result, evidence);
        assert!(provider.calls.lock().unwrap().is_empty());
    }

    #[tokio::test]
    async fn serves_chainless_when_chip_id_masked() {
        // chip_id lives at 0x1A0..0x1E0 in the SNP report.
        let mut masked = REPORT_V5_GENOA.to_vec();
        masked[0x1A0..0x1E0].fill(0);
        let err = vcek_identity(&BASE64.encode(&masked)).unwrap_err();
        assert!(err.contains("chip_id"), "unexpected error: {err}");

        let provider = StubProvider::ok(VCEK_GENOA);
        let evidence = chainless_evidence(&masked);
        let result = enrich_snp_evidence(provider.clone(), evidence.clone()).await;
        assert_eq!(result, evidence);
        assert!(provider.calls.lock().unwrap().is_empty());
    }

    #[tokio::test]
    async fn serves_chainless_for_v2_report_without_cpuid() {
        let err = vcek_identity(&BASE64.encode(REPORT_V2_MILAN)).unwrap_err();
        assert!(
            err.contains("CPUID") || err.contains("unknown processor"),
            "unexpected error: {err}"
        );

        let provider = StubProvider::ok(VCEK_GENOA);
        let evidence = chainless_evidence(REPORT_V2_MILAN);
        let result = enrich_snp_evidence(provider.clone(), evidence.clone()).await;
        assert_eq!(result, evidence);
        assert!(provider.calls.lock().unwrap().is_empty());
    }

    #[tokio::test]
    async fn serves_unrecognized_evidence_unchanged() {
        let mut with_extra_field = chainless_evidence(REPORT_V5_GENOA);
        with_extra_field["unexpected"] = json!(true);
        for evidence in [
            json!({ "attestation_report": "!!not-base64" }),
            json!("not an object"),
            with_extra_field,
        ] {
            let provider = StubProvider::ok(VCEK_GENOA);
            let result = enrich_snp_evidence(provider.clone(), evidence.clone()).await;
            assert_eq!(result, evidence);
            assert!(provider.calls.lock().unwrap().is_empty());
        }
    }

    #[tokio::test]
    async fn serves_chainless_when_lookup_fails() {
        let provider = StubProvider::err("KDS unreachable");
        let evidence = chainless_evidence(REPORT_V5_GENOA);
        let result = enrich_snp_evidence(provider, evidence.clone()).await;
        assert_eq!(result, evidence);
    }

    #[tokio::test]
    async fn rejects_vcek_that_fails_chain_validation() {
        let provider = StubProvider::ok(b"not a certificate");
        let evidence = chainless_evidence(REPORT_V5_GENOA);
        let result = enrich_snp_evidence(provider, evidence.clone()).await;
        assert_eq!(result, evidence);
    }

    #[tokio::test(start_paused = true)]
    async fn serves_chainless_on_lookup_timeout() {
        let evidence = chainless_evidence(REPORT_V5_GENOA);
        let result = enrich_snp_evidence(Arc::new(HangingProvider), evidence.clone()).await;
        assert_eq!(result, evidence);
    }
}
