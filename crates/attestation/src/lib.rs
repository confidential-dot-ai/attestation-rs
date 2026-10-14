//! Unified TEE attestation evidence generation and verification.
//!
//! This library provides a single interface for generating and verifying
//! attestation evidence across multiple Trusted Execution Environment (TEE)
//! platforms: AMD SEV-SNP, Intel TDX, Azure SEV-SNP (vTPM), Azure TDX (vTPM),
//! GCP SEV-SNP (bare-metal), and GCP TDX (bare-metal).
//!
//! # Platform Support
//!
//! Each platform can be individually enabled via cargo features:
//! `snp`, `tdx`, `az-snp`, `az-tdx`, `gcp-snp`, `gcp-tdx` (all on by default).
//! Evidence generation requires the `attest` feature and Linux with TEE hardware.
//!
//! # Quick Start
//!
//! **Verifier** (any machine, including WASM): say which platforms you accept
//! and what each must satisfy.
//! ```rust,ignore
//! use attestation::{Policies, TdxParams};
//!
//! let policies = Policies {
//!     tdx: Some(TdxParams { report_data: Some(nonce.to_vec()), ..Default::default() }),
//!     ..Default::default()
//! };
//! let verified = attestation::verify(&evidence_json, &policies).await?;
//! assert!(verified.passed());
//! ```
//!
//! An `Err` means the evidence could not be verified (malformed, not
//! genuine, platform not allowed, invalid params) or collateral could not be
//! fetched ([`AttestationError::CollateralUnavailable`], retryable). A genuine
//! answer the caller may not like — a mismatch, debug, a low TCB — is a value
//! in the result; `passed()` is true only when every rule held.
//!
//! **Attester** (inside TEE, with `attest` feature):
//! ```rust,ignore
//! let platform = attestation::detect()?;
//! let evidence_json = attestation::attest(platform, b"nonce", &attestation::AttestOptions::default()).await?;
//! ```

#[cfg(all(feature = "attest", target_os = "linux"))]
use std::sync::OnceLock;

pub mod collateral;
pub mod context;
pub mod error;
pub mod platform;
pub mod platforms;
pub mod types;
pub mod utils;

pub use collateral::{
    snp_cert_chain_url, snp_crl_url, snp_vcek_url, CertProvider, DefaultCertProvider,
    DefaultTdxCollateralProvider, HttpTimeouts, TdxCollateralProvider, AMD_KDS_VCEK_BASE,
    AMD_KDS_VLEK_BASE, INTEL_CERTS_BASE, INTEL_PCS_V4_BASE, INTEL_QE_IDENTITY_URL,
    INTEL_ROOT_CA_CRL_URL, INTEL_TDX_PCS_V4_BASE, INTEL_TD_QE_IDENTITY_URL,
};
pub use context::Context;
pub use error::{AttestationError, Result};
pub use platform::{Platform, PlatformResult, Policies, Verified};
#[cfg(feature = "az-snp")]
pub use platforms::az_snp::{AzSnp, AzSnpParams, AzSnpResult};
#[cfg(feature = "az-tdx")]
pub use platforms::az_tdx::{AzTdx, AzTdxParams, AzTdxResult};
#[cfg(feature = "dstack")]
pub use platforms::dstack::{Dstack, DstackParams, DstackResult};
#[cfg(feature = "gcp-snp")]
pub use platforms::gcp_snp::{GcpSnp, GcpSnpParams, GcpSnpResult};
#[cfg(feature = "gcp-tdx")]
pub use platforms::gcp_tdx::{GcpTdx, GcpTdxParams, GcpTdxResult};
#[cfg(feature = "snp")]
pub use platforms::snp::{Snp, SnpParams, SnpResult};
#[cfg(all(feature = "attest", feature = "tdx", target_os = "linux"))]
pub use platforms::tdx::attest::TdxQuoteMethod;
#[cfg(feature = "tdx")]
pub use platforms::tdx::dcap::{cert_revoked, determine_ca_type, intermediate_ca_revoked};
#[cfg(feature = "tdx")]
pub use platforms::tdx::{Tdx, TdxParams, TdxResult};
pub use types::*;

/// Detect the current TEE platform.
/// Checks Azure variants first (they also have bare-metal device paths),
/// then bare-metal variants.
///
/// # Detection ordering invariant
///
/// Cloud-overlay platforms (Azure, GCP) are checked before their bare-metal
/// counterparts because they share the same underlying hardware device paths.
/// On a GCP Confidential VM, both `gcp-snp` and `snp` detection would succeed;
/// `gcp-snp` must win to produce the correct envelope tag.
///
/// Order: `az-tdx` → `az-snp` → `gcp-tdx` → `gcp-snp` → `tdx` → `snp`
///
/// The result is memoized: the underlying hardware probes (which open a vTPM
/// context on vTPM-backed platforms) run once for the process, so callers on
/// hot paths — `/health` probes, `/attest`, `/platform` — do not re-probe the
/// device on every request.
#[cfg(all(feature = "attest", target_os = "linux"))]
pub fn detect() -> Result<PlatformType> {
    // OnceLock holds Option: Some(platform) on detection, None when no platform
    // is present. Both outcomes are static for the process — hardware does not
    // appear or vanish at runtime — so caching either is sound. (Result is not
    // cached directly because AttestationError is not Clone.)
    static DETECTED: OnceLock<Option<PlatformType>> = OnceLock::new();
    match DETECTED.get_or_init(|| detect_uncached().ok()) {
        Some(platform) => Ok(*platform),
        None => Err(AttestationError::NoPlatformDetected),
    }
}

/// Probe the hardware for the current TEE platform. Uncached; [`detect`] wraps
/// this with process-lifetime memoization.
#[cfg(all(feature = "attest", target_os = "linux"))]
fn detect_uncached() -> Result<PlatformType> {
    #[cfg(feature = "az-tdx")]
    if platforms::az_tdx::attest::is_available() {
        return Ok(PlatformType::AzTdx);
    }

    #[cfg(feature = "az-snp")]
    if platforms::az_snp::attest::is_available() {
        return Ok(PlatformType::AzSnp);
    }

    #[cfg(feature = "gcp-tdx")]
    if platforms::gcp_tdx::attest::is_available() {
        return Ok(PlatformType::GcpTdx);
    }

    #[cfg(feature = "gcp-snp")]
    if platforms::gcp_snp::attest::is_available() {
        return Ok(PlatformType::GcpSnp);
    }

    // Check dstack before bare-metal TDX — on Phala CVM both may exist
    // but dstack is the correct interface for quote generation.
    #[cfg(feature = "dstack")]
    if platforms::dstack::attest::is_available() {
        return Ok(PlatformType::Dstack);
    }

    #[cfg(feature = "tdx")]
    if platforms::tdx::attest::is_available() {
        return Ok(PlatformType::Tdx);
    }

    #[cfg(feature = "snp")]
    if platforms::snp::attest::is_available() {
        return Ok(PlatformType::Snp);
    }

    Err(AttestationError::NoPlatformDetected)
}

/// Platform-specific attestation options.
///
/// Pass to [`attest_with_options`] to control quote generation behavior.
/// Non-TDX platforms ignore TDX-specific fields.
#[cfg(all(feature = "attest", target_os = "linux"))]
#[derive(Debug, Clone, Default)]
pub struct AttestOptions {
    /// TDX quote generation method. Only used for TDX-based platforms
    /// (Tdx, AzTdx, GcpTdx). Ignored for SNP platforms.
    #[cfg(feature = "tdx")]
    pub tdx_quote_method: platforms::tdx::attest::TdxQuoteMethod,
}

/// Generate attestation evidence and wrap it in a self-describing envelope.
///
/// Returns JSON bytes containing an [`AttestationEvidence`] envelope with
/// the platform tag and platform-specific evidence payload.
///
/// Pass `AttestOptions::default()` for standard behavior (auto-detects the
/// fastest available quote method for TDX platforms).
#[cfg(all(feature = "attest", target_os = "linux"))]
pub async fn attest(
    platform: PlatformType,
    report_data: &[u8],
    options: &AttestOptions,
) -> Result<Vec<u8>> {
    let evidence_value = match platform {
        #[cfg(feature = "snp")]
        PlatformType::Snp => {
            let evidence = platforms::snp::attest::generate_evidence(report_data).await?;
            serde_json::to_value(&evidence)
                .map_err(|e| AttestationError::EvidenceDeserialize(e.to_string()))?
        }
        #[cfg(feature = "tdx")]
        PlatformType::Tdx => {
            let evidence = platforms::tdx::attest::generate_evidence_with(
                report_data,
                options.tdx_quote_method,
            )
            .await?;
            serde_json::to_value(&evidence)
                .map_err(|e| AttestationError::EvidenceDeserialize(e.to_string()))?
        }
        #[cfg(feature = "az-snp")]
        PlatformType::AzSnp => {
            let evidence = platforms::az_snp::attest::generate_evidence(report_data).await?;
            serde_json::to_value(&evidence)
                .map_err(|e| AttestationError::EvidenceDeserialize(e.to_string()))?
        }
        #[cfg(feature = "az-tdx")]
        PlatformType::AzTdx => {
            let evidence = platforms::az_tdx::attest::generate_evidence_with(
                report_data,
                options.tdx_quote_method,
            )
            .await?;
            serde_json::to_value(&evidence)
                .map_err(|e| AttestationError::EvidenceDeserialize(e.to_string()))?
        }
        #[cfg(feature = "gcp-snp")]
        PlatformType::GcpSnp => {
            let evidence = platforms::gcp_snp::attest::generate_evidence(report_data).await?;
            serde_json::to_value(&evidence)
                .map_err(|e| AttestationError::EvidenceDeserialize(e.to_string()))?
        }
        #[cfg(feature = "gcp-tdx")]
        PlatformType::GcpTdx => {
            let evidence = platforms::gcp_tdx::attest::generate_evidence_with(
                report_data,
                options.tdx_quote_method,
            )
            .await?;
            serde_json::to_value(&evidence)
                .map_err(|e| AttestationError::EvidenceDeserialize(e.to_string()))?
        }
        #[cfg(feature = "dstack")]
        PlatformType::Dstack => {
            let evidence = platforms::dstack::attest::generate_evidence(report_data).await?;
            serde_json::to_value(&evidence)
                .map_err(|e| AttestationError::EvidenceDeserialize(e.to_string()))?
        }
        #[cfg(not(all(
            feature = "snp",
            feature = "tdx",
            feature = "az-snp",
            feature = "az-tdx",
            feature = "gcp-snp",
            feature = "gcp-tdx",
            feature = "dstack"
        )))]
        other => return Err(AttestationError::PlatformNotEnabled(other.to_string())),
    };

    let envelope = AttestationEvidence {
        platform,
        evidence: evidence_value,
        nvidia_gpu: None,
    };

    serde_json::to_vec(&envelope).map_err(|e| AttestationError::EvidenceDeserialize(e.to_string()))
}

/// Attest a CPU TEE quote and an attached NVIDIA GPU bundle in one shot.
///
/// Returns a self-describing envelope where the CPU TEE `report_data` carries
/// `user_nonce` directly and the `nvidia_gpu` field carries SPDM evidence for
/// every CC GPU on the host.
#[cfg(all(feature = "nvidia-gpu-attest", feature = "attest", target_os = "linux"))]
pub async fn attest_with_nvidia_gpu(
    platform: PlatformType,
    user_nonce: &[u8],
    options: &AttestOptions,
) -> Result<Vec<u8>> {
    // Enforce the same minimum nonce length the verifier requires so callers
    // can't produce evidence their own verifier will reject.
    platforms::nvidia_gpu::check_user_nonce_len(user_nonce)?;
    let cpu_envelope_bytes = attest(platform, user_nonce, options).await?;
    let mut envelope: AttestationEvidence = serde_json::from_slice(&cpu_envelope_bytes)
        .map_err(|e| AttestationError::EvidenceDeserialize(e.to_string()))?;
    let bundle = platforms::nvidia_gpu::attest::collect_bundle(
        user_nonce,
        types::NvidiaGpuBinding::default(),
    )
    .await?;
    envelope.nvidia_gpu = Some(bundle);
    serde_json::to_vec(&envelope).map_err(|e| AttestationError::EvidenceDeserialize(e.to_string()))
}

/// Maximum accepted evidence size (10 MiB).
pub const MAX_EVIDENCE_SIZE: usize = 10 * 1024 * 1024;

/// Reusable verifier: reads the envelope's platform, takes that platform's
/// params from [`Policies`], and runs its [`Platform::verify`].
///
/// Construct once (e.g. at service startup), store, and call `.verify()`
/// for each request.
///
/// ```rust,ignore
/// let verifier = Verifier::new(Context::new().with_cert_provider(my_cached_provider));
/// let verified = verifier.verify(&evidence_json, &policies).await?;
/// ```
pub struct Verifier {
    ctx: Context,
}

impl Verifier {
    #[must_use]
    pub fn new(ctx: Context) -> Self {
        Self { ctx }
    }

    /// The context passed to every platform verifier. Use it to call a
    /// platform directly when the caller knows the platform, e.g.
    /// `Tdx::verify(&evidence, &params, verifier.context())`.
    pub fn context(&self) -> &Context {
        &self.ctx
    }

    /// Verify attestation evidence from a self-describing JSON envelope.
    ///
    /// The evidence JSON must be an [`AttestationEvidence`] envelope. Its
    /// `platform` picks the verifier, and only platforms with params in
    /// `policies` are accepted.
    ///
    /// # Errors
    ///
    /// Evidence too large or malformed, a platform not compiled in or not in
    /// `policies`, invalid params, evidence that is not genuine, or
    /// collateral that could not be fetched.
    pub async fn verify(&self, evidence_json: &[u8], policies: &Policies) -> Result<Verified> {
        if evidence_json.len() > MAX_EVIDENCE_SIZE {
            return Err(AttestationError::EvidenceTooLarge {
                size: evidence_json.len(),
                max: MAX_EVIDENCE_SIZE,
            });
        }

        let envelope: AttestationEvidence = serde_json::from_slice(evidence_json)
            .map_err(|e| AttestationError::EvidenceDeserialize(e.to_string()))?;

        // Rules that need no verification run first, so caller misuse is never
        // reported after (or as) a collateral fetch.
        policies.check_allowed(envelope.platform)?;

        #[cfg(not(feature = "nvidia-gpu"))]
        if envelope.nvidia_gpu.is_some() {
            return Err(AttestationError::PlatformNotEnabled("nvidia-gpu".into()));
        }
        #[cfg(feature = "nvidia-gpu")]
        match (&envelope.nvidia_gpu, &policies.gpu) {
            (Some(_), None) => {
                return Err(AttestationError::PlatformNotAllowed("nvidia-gpu".into()))
            }
            (None, Some(params)) if params.required => {
                return Err(AttestationError::NvidiaGpuRequired)
            }
            (bundle, Some(params)) => {
                if let Some(bundle) = bundle {
                    platforms::nvidia_gpu::verify::check_preconditions(bundle, params)?;
                }
                // The GPU nonce must be the CPU report data, so one challenge
                // binds both.
                if let Some(un) = params.user_nonce.as_deref() {
                    let rd = policies
                        .report_data(envelope.platform)
                        .ok_or(AttestationError::NvidiaGpuReportDataRequired)?;
                    if rd != un {
                        return Err(AttestationError::InvalidParams(
                            "the GPU user_nonce differs from the platform report_data".into(),
                        ));
                    }
                }
            }
            (None, None) => {}
        }

        let platform = self
            .verify_platform(envelope.platform, envelope.evidence, policies)
            .await?;

        #[cfg(feature = "nvidia-gpu")]
        let gpu = match (envelope.nvidia_gpu, &policies.gpu) {
            (Some(bundle), Some(params)) => Some(
                platforms::nvidia_gpu::verify_bundle(
                    &bundle,
                    params,
                    self.ctx.nras(),
                    self.ctx.now(),
                )
                .await?,
            ),
            _ => None,
        };

        Ok(Verified {
            platform,
            #[cfg(feature = "nvidia-gpu")]
            gpu,
        })
    }

    #[allow(unused_variables)]
    async fn verify_platform(
        &self,
        platform: PlatformType,
        evidence: serde_json::Value,
        policies: &Policies,
    ) -> Result<PlatformResult> {
        let ctx = &self.ctx;
        match platform {
            #[cfg(feature = "snp")]
            PlatformType::Snp => run::<platforms::snp::Snp>(evidence, policies.snp.as_ref(), ctx)
                .await
                .map(PlatformResult::Snp),
            #[cfg(feature = "tdx")]
            PlatformType::Tdx => run::<platforms::tdx::Tdx>(evidence, policies.tdx.as_ref(), ctx)
                .await
                .map(PlatformResult::Tdx),
            #[cfg(feature = "az-snp")]
            PlatformType::AzSnp => {
                run::<platforms::az_snp::AzSnp>(evidence, policies.az_snp.as_ref(), ctx)
                    .await
                    .map(PlatformResult::AzSnp)
            }
            #[cfg(feature = "az-tdx")]
            PlatformType::AzTdx => {
                run::<platforms::az_tdx::AzTdx>(evidence, policies.az_tdx.as_ref(), ctx)
                    .await
                    .map(PlatformResult::AzTdx)
            }
            #[cfg(feature = "gcp-snp")]
            PlatformType::GcpSnp => {
                run::<platforms::gcp_snp::GcpSnp>(evidence, policies.gcp_snp.as_ref(), ctx)
                    .await
                    .map(PlatformResult::GcpSnp)
            }
            #[cfg(feature = "gcp-tdx")]
            PlatformType::GcpTdx => {
                run::<platforms::gcp_tdx::GcpTdx>(evidence, policies.gcp_tdx.as_ref(), ctx)
                    .await
                    .map(PlatformResult::GcpTdx)
            }
            #[cfg(feature = "dstack")]
            PlatformType::Dstack => {
                run::<platforms::dstack::Dstack>(evidence, policies.dstack.as_ref(), ctx)
                    .await
                    .map(PlatformResult::Dstack)
            }
            #[cfg(not(all(
                feature = "snp",
                feature = "tdx",
                feature = "az-snp",
                feature = "az-tdx",
                feature = "gcp-snp",
                feature = "gcp-tdx",
                feature = "dstack"
            )))]
            other => Err(AttestationError::PlatformNotEnabled(other.to_string())),
        }
    }
}

/// Run one platform: refuse it when the caller gave no params for it, then
/// decode its evidence and verify.
#[allow(dead_code)]
async fn run<P: Platform>(
    evidence: serde_json::Value,
    params: Option<&P::Params>,
    ctx: &Context,
) -> Result<P::Result> {
    let params = params.ok_or_else(|| AttestationError::PlatformNotAllowed(P::KIND.to_string()))?;
    let evidence: P::Evidence = serde_json::from_value(evidence)
        .map_err(|e| AttestationError::EvidenceDeserialize(e.to_string()))?;
    P::verify(&evidence, params, ctx).await
}

impl Default for Verifier {
    fn default() -> Self {
        Self::new(Context::new())
    }
}

/// Verify attestation evidence from a self-describing JSON envelope with the
/// default network-backed [`Context`].
///
/// For custom providers (e.g. cached certs), construct a [`Verifier`] instead.
///
/// # Errors
///
/// See [`Verifier::verify`].
pub async fn verify(evidence_json: &[u8], policies: &Policies) -> Result<Verified> {
    Verifier::default().verify(evidence_json, policies).await
}

#[cfg(all(test, feature = "tdx"))]
mod tests {
    use super::*;
    use base64::Engine;

    const V5_QUOTE: &[u8] = include_bytes!("../test_data/tdx_quote_5.dat");

    fn tdx_envelope() -> Vec<u8> {
        serde_json::to_vec(&serde_json::json!({
            "platform": "tdx",
            "evidence": {
                "quote": base64::engine::general_purpose::STANDARD.encode(V5_QUOTE),
            },
        }))
        .unwrap()
    }

    // Which `Policies` fields exist depends on the platform features.
    #[allow(clippy::needless_update)]
    fn tdx_policies(params: TdxParams) -> Policies {
        Policies {
            tdx: Some(params),
            ..Default::default()
        }
    }

    /// Fails the test if verification reaches for collateral.
    struct NoFetch;

    #[async_trait::async_trait]
    impl TdxCollateralProvider for NoFetch {
        async fn get_tcb_info(&self, _: &str) -> Result<Vec<u8>> {
            panic!("fetched collateral")
        }
        async fn get_qe_identity(&self) -> Result<Vec<u8>> {
            panic!("fetched collateral")
        }
        async fn get_td_qe_identity(&self) -> Result<Vec<u8>> {
            panic!("fetched collateral")
        }
        async fn get_root_ca_crl(&self) -> Result<Vec<u8>> {
            panic!("fetched collateral")
        }
        async fn get_pck_crl(&self, _: &str) -> Result<Vec<u8>> {
            panic!("fetched collateral")
        }
    }

    #[tokio::test]
    async fn invalid_params_are_refused_before_any_fetch() {
        let verifier = Verifier::new(Context::offline().with_tdx_provider(NoFetch));
        let refused = |params| async {
            verifier
                .verify(&tdx_envelope(), &tdx_policies(params))
                .await
                .expect_err("invalid params")
        };
        let err = refused(TdxParams {
            report_data: Some(vec![0; 65]),
            ..Default::default()
        })
        .await;
        assert!(matches!(err, AttestationError::ReportDataTooLarge { .. }));
        let err = refused(TdxParams {
            accepted_tcb_statuses: vec![],
            ..Default::default()
        })
        .await;
        assert!(matches!(err, AttestationError::InvalidParams(_)));
    }

    #[cfg(not(feature = "nvidia-gpu"))]
    #[tokio::test]
    async fn a_gpu_bundle_without_the_gpu_feature_is_refused() {
        let mut envelope: serde_json::Value = serde_json::from_slice(&tdx_envelope()).unwrap();
        envelope["nvidia_gpu"] = serde_json::json!({ "devices": [] });
        let err = Verifier::new(Context::offline())
            .verify(
                &serde_json::to_vec(&envelope).unwrap(),
                &tdx_policies(TdxParams::default()),
            )
            .await
            .expect_err("a bundle that cannot be verified");
        assert!(matches!(err, AttestationError::PlatformNotEnabled(_)));
    }

    #[tokio::test]
    async fn evidence_that_is_not_genuine_is_refused_before_any_fetch() {
        let mut envelope: serde_json::Value = serde_json::from_slice(&tdx_envelope()).unwrap();
        envelope["evidence"]["cc_eventlog"] = base64::engine::general_purpose::STANDARD
            .encode([0u8; 64])
            .into();
        let err = Verifier::new(Context::offline().with_tdx_provider(NoFetch))
            .verify(
                &serde_json::to_vec(&envelope).unwrap(),
                &tdx_policies(TdxParams::default()),
            )
            .await
            .expect_err("an event log that does not replay");
        assert!(matches!(err, AttestationError::EventlogIntegrityFailed(_)));
    }

    #[tokio::test]
    async fn evidence_for_a_platform_without_policy_is_refused() {
        let err = Verifier::new(Context::offline())
            .verify(&tdx_envelope(), &Policies::default())
            .await
            .expect_err("no policy for tdx");
        assert!(matches!(err, AttestationError::PlatformNotAllowed(_)));
    }

    #[tokio::test]
    async fn verified_passes_only_when_every_rule_holds() {
        let verifier = Verifier::new(Context::offline());
        let mrtd = platforms::tdx::verify::parse_tdx_quote(V5_QUOTE)
            .unwrap()
            .body
            .mr_td;

        let verified = verifier
            .verify(
                &tdx_envelope(),
                &tdx_policies(TdxParams {
                    mrtd: Some(vec![mrtd]),
                    ..Default::default()
                }),
            )
            .await
            .unwrap();
        assert_eq!(verified.platform.platform(), PlatformType::Tdx);
        assert!(verified.passed());

        let verified = verifier
            .verify(
                &tdx_envelope(),
                &tdx_policies(TdxParams {
                    mrtd: Some(vec![[0; 48]]),
                    ..Default::default()
                }),
            )
            .await
            .expect("a pin mismatch is a value, not an error");
        assert!(!verified.passed());
    }

    #[tokio::test]
    async fn all_accepts_any_platform_and_with_report_data_pins_the_nonce() {
        let verifier = Verifier::new(Context::offline());
        let nonce = platforms::tdx::verify::parse_tdx_quote(V5_QUOTE)
            .unwrap()
            .body
            .report_data;

        let verified = verifier
            .verify(&tdx_envelope(), &Policies::all())
            .await
            .unwrap();
        assert!(verified.passed());

        let verified = verifier
            .verify(&tdx_envelope(), &Policies::all().with_report_data(&nonce))
            .await
            .unwrap();
        assert!(verified.passed());

        let verified = verifier
            .verify(
                &tdx_envelope(),
                &Policies::all().with_report_data(b"another nonce"),
            )
            .await
            .expect("a nonce mismatch is a value, not an error");
        assert!(!verified.passed());
    }

    #[cfg(feature = "az-tdx")]
    #[test]
    fn with_report_data_reaches_the_cloud_platforms() {
        let policies = Policies::all().with_report_data(b"nonce");
        assert_eq!(
            policies.az_tdx.unwrap().tdx.report_data.as_deref(),
            Some(&b"nonce"[..])
        );
    }
}
