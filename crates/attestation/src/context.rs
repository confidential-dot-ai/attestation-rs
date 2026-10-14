//! Everything a platform verifier gets from outside: collateral providers and
//! the evaluation time.

use async_trait::async_trait;

use crate::collateral::{
    CertProvider, DefaultCertProvider, DefaultTdxCollateralProvider, TdxCollateralProvider,
};
use crate::error::{AttestationError, Result};
use crate::types::{ProcessorGeneration, SnpTcb};

/// Providers and evaluation time shared by every platform verifier.
///
/// Platforms do not build HTTP clients or read the clock themselves; they ask
/// the context. Construct once and reuse.
pub struct Context {
    cert_provider: Box<dyn CertProvider>,
    /// `None` = offline: TDX collateral checks (PCK CRL, TCB status, QE
    /// identity) are skipped and their result fields stay `None`.
    tdx_collateral: Option<Box<dyn TdxCollateralProvider>>,
    #[cfg(feature = "nvidia-gpu")]
    nras: Box<dyn crate::platforms::nvidia_gpu::NrasProvider>,
    /// Fixed evaluation time in Unix seconds; `None` = the current time.
    time: Option<i64>,
}

impl Context {
    /// Default network-backed providers, evaluated at the current time.
    #[must_use]
    pub fn new() -> Self {
        Self {
            cert_provider: Box::new(DefaultCertProvider::new()),
            tdx_collateral: Some(Box::new(DefaultTdxCollateralProvider::new())),
            #[cfg(feature = "nvidia-gpu")]
            nras: Box::new(crate::platforms::nvidia_gpu::DefaultNrasProvider::new()),
            time: None,
        }
    }

    /// No network: quote signatures and cert chains verify against the
    /// bundled AMD/Intel roots, and checks that need fetched collateral are
    /// skipped (their result fields stay `None`). Evidence that cannot be
    /// verified without a fetch (SNP without an inline VEK, an NVIDIA GPU
    /// bundle, which needs NRAS) fails with
    /// [`AttestationError::CollateralUnavailable`]. This is the mode the WASM
    /// verifier runs in.
    #[must_use]
    pub fn offline() -> Self {
        Self {
            cert_provider: Box::new(Offline),
            tdx_collateral: None,
            #[cfg(feature = "nvidia-gpu")]
            nras: Box::new(Offline),
            time: None,
        }
    }

    #[must_use]
    pub fn with_cert_provider(mut self, provider: impl CertProvider + 'static) -> Self {
        self.cert_provider = Box::new(provider);
        self
    }

    #[must_use]
    pub fn with_tdx_provider(mut self, provider: impl TdxCollateralProvider + 'static) -> Self {
        self.tdx_collateral = Some(Box::new(provider));
        self
    }

    #[cfg(feature = "nvidia-gpu")]
    #[must_use]
    pub fn with_nras_provider(
        mut self,
        provider: impl crate::platforms::nvidia_gpu::NrasProvider + 'static,
    ) -> Self {
        self.nras = Box::new(provider);
        self
    }

    /// Evaluate certificate, CRL and token validity at a fixed time (Unix
    /// seconds) instead of the current time. A time outside years 1-9999 is
    /// [`AttestationError::InvalidParams`].
    pub fn at(mut self, unix_seconds: i64) -> Result<Self> {
        // 0001-01-01T00:00:00Z ..= 9999-12-31T23:59:59Z, the X.509 time range.
        if !(-62_135_596_800..=253_402_300_799).contains(&unix_seconds) {
            return Err(AttestationError::InvalidParams(format!(
                "evaluation time {unix_seconds} is out of range"
            )));
        }
        self.time = Some(unix_seconds);
        Ok(self)
    }

    /// The evaluation time in Unix seconds.
    pub fn now(&self) -> i64 {
        self.time.unwrap_or_else(|| chrono::Utc::now().timestamp())
    }

    pub fn cert_provider(&self) -> &dyn CertProvider {
        self.cert_provider.as_ref()
    }

    /// The TDX collateral provider (`None` in offline mode).
    pub fn tdx_collateral(&self) -> Option<&dyn TdxCollateralProvider> {
        self.tdx_collateral.as_deref()
    }

    #[cfg(feature = "nvidia-gpu")]
    pub fn nras(&self) -> &dyn crate::platforms::nvidia_gpu::NrasProvider {
        self.nras.as_ref()
    }
}

impl Default for Context {
    fn default() -> Self {
        Self::new()
    }
}

/// The providers behind [`Context::offline`]: every fetch fails without
/// touching the network.
struct Offline;

fn offline(what: &str) -> AttestationError {
    AttestationError::CollateralUnavailable(format!("offline mode does not fetch {what}"))
}

#[async_trait]
impl CertProvider for Offline {
    async fn get_snp_vcek(
        &self,
        _processor_gen: ProcessorGeneration,
        _chip_id: &[u8; 64],
        _reported_tcb: &SnpTcb,
    ) -> Result<Vec<u8>> {
        Err(offline("the VEK (the evidence carries none)"))
    }

    async fn get_snp_cert_chain(
        &self,
        _processor_gen: ProcessorGeneration,
    ) -> Result<(Vec<u8>, Vec<u8>)> {
        Err(offline("the AMD cert chain"))
    }
}

#[cfg(feature = "nvidia-gpu")]
#[cfg_attr(not(target_arch = "wasm32"), async_trait)]
#[cfg_attr(target_arch = "wasm32", async_trait(?Send))]
impl crate::platforms::nvidia_gpu::NrasProvider for Offline {
    fn url_for(&self, _arch: crate::types::NvidiaGpuArch) -> &str {
        ""
    }

    async fn attest(
        &self,
        _request: &crate::platforms::nvidia_gpu::NrasRequest,
    ) -> Result<serde_json::Value> {
        Err(offline("an NRAS attestation"))
    }

    async fn jwks(
        &self,
        _arch: crate::types::NvidiaGpuArch,
    ) -> Result<crate::platforms::nvidia_gpu::Jwks> {
        Err(offline("the NRAS signing keys"))
    }
}

#[cfg(all(test, any(feature = "snp", feature = "tdx")))]
mod tests {
    use super::*;

    // Each test runs a fixture whose verification needs a fetch under
    // `Context::new()`. Offline, the fetch is never attempted: the evidence
    // either verifies with the collateral checks left `None`, or fails with
    // `CollateralUnavailable` from the offline provider.

    #[test]
    fn an_evaluation_time_out_of_range_is_invalid_params() {
        assert!(Context::offline().at(1_791_244_800).is_ok());
        for t in [i64::MIN, i64::MAX, 253_402_300_800] {
            assert!(matches!(
                Context::offline().at(t),
                Err(AttestationError::InvalidParams(_))
            ));
        }
    }

    #[cfg(feature = "snp")]
    #[tokio::test]
    async fn offline_snp_without_inline_vek_does_not_fetch_it() {
        use crate::platform::Platform;
        use crate::platforms::snp::{Snp, SnpParams};

        let envelope: serde_json::Value =
            serde_json::from_str(include_str!("../test_data/snp/live-evidence-genoa.json"))
                .unwrap();
        let mut evidence: crate::platforms::snp::evidence::SnpEvidence =
            serde_json::from_value(envelope["evidence"].clone()).unwrap();
        let ctx = Context::offline();

        let r = Snp::verify(&evidence, &SnpParams::default(), &ctx)
            .await
            .expect("inline VEK verifies offline");
        assert!(r.crl_ok.is_none(), "the AMD CRL is not fetched");

        evidence.cert_chain = None;
        let err = Snp::verify(&evidence, &SnpParams::default(), &ctx)
            .await
            .expect_err("no VEK and no fetch");
        assert!(matches!(err, AttestationError::CollateralUnavailable(_)));

        // Invalid params are refused before the VEK would be fetched.
        let oversize = SnpParams {
            report_data: Some(vec![0; 65]),
            ..Default::default()
        };
        let err = Snp::verify(&evidence, &oversize, &ctx)
            .await
            .expect_err("invalid params");
        assert!(matches!(err, AttestationError::ReportDataTooLarge { .. }));
    }

    #[cfg(feature = "tdx")]
    #[tokio::test]
    async fn offline_tdx_skips_pcs_collateral() {
        use crate::platform::Platform;
        use crate::platforms::tdx::{evidence::TdxEvidence, Tdx, TdxParams};
        use base64::Engine;

        let evidence = TdxEvidence {
            quote: base64::engine::general_purpose::STANDARD
                .encode(include_bytes!("../test_data/tdx_quote_5.dat")),
            cc_eventlog: None,
        };
        let r = Tdx::verify(&evidence, &TdxParams::default(), &Context::offline())
            .await
            .expect("verifies offline");
        assert!(r.tcb_status.is_none());
        assert!(r.crl_ok.is_none());
    }

    #[cfg(all(feature = "nvidia-gpu", feature = "tdx"))]
    #[tokio::test]
    async fn offline_gpu_bundle_does_not_call_nras() {
        use crate::platform::Policies;
        use crate::platforms::tdx::TdxParams;
        use crate::types::{
            AttestationEvidence, NvidiaGpuArch, NvidiaGpuDeviceEvidence, NvidiaGpuEvidenceBundle,
            NvidiaGpuParams, PlatformType,
        };
        use base64::Engine;

        let nonce = vec![7u8; 32];
        let envelope = AttestationEvidence {
            platform: PlatformType::Tdx,
            evidence: serde_json::json!({
                "quote": base64::engine::general_purpose::STANDARD
                    .encode(include_bytes!("../test_data/tdx_quote_5.dat")),
            }),
            nvidia_gpu: Some(NvidiaGpuEvidenceBundle {
                devices: vec![NvidiaGpuDeviceEvidence {
                    arch: NvidiaGpuArch::Hopper,
                    uuid: "GPU-0".into(),
                    evidence_b64: String::new(),
                    cert_chain_b64: String::new(),
                }],
                binding: Default::default(),
            }),
        };
        #[allow(clippy::needless_update)]
        let policies = Policies {
            tdx: Some(TdxParams {
                report_data: Some(nonce.clone()),
                ..Default::default()
            }),
            gpu: Some(NvidiaGpuParams {
                user_nonce: Some(nonce),
                ..Default::default()
            }),
            ..Default::default()
        };
        let err = crate::Verifier::new(Context::offline())
            .verify(&serde_json::to_vec(&envelope).unwrap(), &policies)
            .await
            .expect_err("NRAS is not reachable offline");
        assert!(matches!(err, AttestationError::CollateralUnavailable(_)));
    }

    #[cfg(all(feature = "nvidia-gpu", feature = "snp"))]
    #[tokio::test]
    async fn gpu_misuse_is_refused_before_the_cpu_fetch() {
        use crate::platform::Policies;
        use crate::platforms::snp::SnpParams;
        use crate::types::{NvidiaGpuArch, NvidiaGpuDeviceEvidence, NvidiaGpuEvidenceBundle};

        // SNP evidence without its VEK: verifying the CPU side offline would
        // fail with CollateralUnavailable, so any other error came first.
        let mut envelope: serde_json::Value =
            serde_json::from_str(include_str!("../test_data/snp/live-evidence-genoa.json"))
                .unwrap();
        envelope["evidence"]
            .as_object_mut()
            .unwrap()
            .remove("cert_chain");
        envelope["nvidia_gpu"] = serde_json::to_value(NvidiaGpuEvidenceBundle {
            devices: vec![NvidiaGpuDeviceEvidence {
                arch: NvidiaGpuArch::Hopper,
                uuid: "GPU-0".into(),
                evidence_b64: String::new(),
                cert_chain_b64: String::new(),
            }],
            binding: Default::default(),
        })
        .unwrap();
        let envelope = serde_json::to_vec(&envelope).unwrap();
        let verify = |policies: Policies| {
            let envelope = envelope.clone();
            async move {
                crate::Verifier::new(Context::offline())
                    .verify(&envelope, &policies)
                    .await
                    .expect_err("refused")
            }
        };
        let gpu = |user_nonce: Option<Vec<u8>>| {
            Some(crate::types::NvidiaGpuParams {
                user_nonce,
                ..Default::default()
            })
        };
        let snp = |report_data: Vec<u8>| SnpParams {
            report_data: Some(report_data),
            ..Default::default()
        };

        #[allow(clippy::needless_update)]
        let err = verify(Policies {
            snp: Some(snp(vec![7; 32])),
            gpu: gpu(None),
            ..Default::default()
        })
        .await;
        assert!(err.is_invalid_params(), "{err}");

        #[allow(clippy::needless_update)]
        let err = verify(Policies {
            snp: Some(snp(vec![7; 8])),
            gpu: gpu(Some(vec![7; 8])),
            ..Default::default()
        })
        .await;
        assert!(err.is_invalid_params(), "{err}");

        #[allow(clippy::needless_update)]
        let err = verify(Policies {
            gpu: gpu(Some(vec![7; 32])),
            ..Default::default()
        })
        .await;
        assert!(
            matches!(err, AttestationError::PlatformNotAllowed(_)),
            "{err}"
        );
    }
}
