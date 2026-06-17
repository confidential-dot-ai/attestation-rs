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
//! **Verifier** (any machine, including WASM):
//! ```rust,ignore
//! use attestation::types::VerifyParams;
//!
//! let result = attestation::verify(&evidence_json, &VerifyParams::default()).await?;
//! assert!(result.signature_valid);
//! ```
//!
//! **Attester** (inside TEE, with `attest` feature):
//! ```rust,ignore
//! let platform = attestation::detect()?;
//! let evidence_json = attestation::attest(platform, b"nonce", &attestation::AttestOptions::default()).await?;
//! ```

#[cfg(all(feature = "attest", target_os = "linux"))]
use std::sync::OnceLock;

pub mod collateral;
pub mod error;
pub mod platforms;
pub mod types;
pub mod utils;

pub use collateral::{
    snp_crl_url, CertProvider, DefaultCertProvider, DefaultTdxCollateralProvider, HttpTimeouts,
    TdxCollateralProvider, AMD_KDS_VCEK_BASE, AMD_KDS_VLEK_BASE, INTEL_CERTS_BASE,
    INTEL_PCS_V4_BASE, INTEL_QE_IDENTITY_URL, INTEL_ROOT_CA_CRL_URL, INTEL_TDX_PCS_V4_BASE,
    INTEL_TD_QE_IDENTITY_URL,
};
pub use error::{AttestationError, Result};
#[cfg(all(feature = "attest", feature = "tdx", target_os = "linux"))]
pub use platforms::tdx::attest::TdxQuoteMethod;
#[cfg(feature = "tdx")]
pub use platforms::tdx::dcap::{
    check_cert_revocation, check_intermediate_ca_revocation, determine_ca_type,
};
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
        #[cfg(feature = "nvidia-gpu")]
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

/// Reusable verifier with pluggable cert/collateral providers.
///
/// Construct once (e.g. at service startup), store, and call `.verify()`
/// for each request. Uses default providers for any platform not explicitly
/// overridden.
///
/// ```rust,ignore
/// let verifier = Verifier::new()
///     .with_cert_provider(my_cached_provider);
/// let result = verifier.verify(&evidence_json, &VerifyParams::default()).await?;
/// ```
pub struct Verifier {
    cert_provider: Box<dyn CertProvider>,
    tdx_provider: Box<dyn TdxCollateralProvider>,
    #[cfg(feature = "nvidia-gpu")]
    nras_provider: Box<dyn platforms::nvidia_gpu::NrasProvider>,
}

impl Verifier {
    #[must_use]
    pub fn new() -> Self {
        Self {
            cert_provider: Box::new(DefaultCertProvider::new()),
            tdx_provider: Box::new(DefaultTdxCollateralProvider::new()),
            #[cfg(feature = "nvidia-gpu")]
            nras_provider: Box::new(platforms::nvidia_gpu::DefaultNrasProvider::new()),
        }
    }

    #[must_use]
    pub fn with_cert_provider(mut self, provider: impl CertProvider + 'static) -> Self {
        self.cert_provider = Box::new(provider);
        self
    }

    #[must_use]
    pub fn with_tdx_provider(mut self, provider: impl TdxCollateralProvider + 'static) -> Self {
        self.tdx_provider = Box::new(provider);
        self
    }

    #[cfg(feature = "nvidia-gpu")]
    #[must_use]
    pub fn with_nras_provider(
        mut self,
        provider: impl platforms::nvidia_gpu::NrasProvider + 'static,
    ) -> Self {
        self.nras_provider = Box::new(provider);
        self
    }

    /// Verify attestation evidence from a self-describing JSON envelope.
    ///
    /// The evidence JSON must be an [`AttestationEvidence`] envelope containing
    /// a `platform` field and an `evidence` payload. The platform is auto-detected
    /// from the envelope and the correct verifier is dispatched automatically.
    ///
    /// # Errors
    ///
    /// Returns an error if the evidence is too large, malformed, targets a
    /// platform not compiled in, or fails signature/collateral verification.
    pub async fn verify(
        &self,
        evidence_json: &[u8],
        params: &VerifyParams,
    ) -> Result<VerificationResult> {
        if evidence_json.len() > MAX_EVIDENCE_SIZE {
            return Err(AttestationError::EvidenceTooLarge {
                size: evidence_json.len(),
                max: MAX_EVIDENCE_SIZE,
            });
        }

        if let Some(ref data) = params.expected_report_data {
            if data.len() > 64 {
                return Err(AttestationError::ReportDataTooLarge { max: 64 });
            }
        }

        let envelope: AttestationEvidence = serde_json::from_slice(evidence_json)
            .map_err(|e| AttestationError::EvidenceDeserialize(e.to_string()))?;

        #[cfg(feature = "nvidia-gpu")]
        if let Some(un) = params.nvidia_gpu_user_nonce.as_deref() {
            let rd = params
                .expected_report_data
                .as_deref()
                .ok_or(AttestationError::NvidiaGpuReportDataRequired)?;
            if rd != un {
                return Err(AttestationError::NvidiaGpuBindingMismatch);
            }
        }

        let result = self
            .verify_platform(envelope.platform, envelope.evidence, params)
            .await?;

        #[cfg(feature = "nvidia-gpu")]
        let result = self
            .verify_nvidia_gpu(result, envelope.nvidia_gpu, params)
            .await?;

        Ok(result)
    }

    #[allow(unused_variables)]
    async fn verify_platform(
        &self,
        platform: PlatformType,
        evidence: serde_json::Value,
        params: &VerifyParams,
    ) -> Result<VerificationResult> {
        match platform {
            #[cfg(feature = "snp")]
            PlatformType::Snp => {
                let ev: platforms::snp::evidence::SnpEvidence = serde_json::from_value(evidence)
                    .map_err(|e| AttestationError::EvidenceDeserialize(e.to_string()))?;
                platforms::snp::verify::verify_evidence(&ev, params, self.cert_provider.as_ref())
                    .await
            }
            #[cfg(feature = "tdx")]
            PlatformType::Tdx => {
                let ev: platforms::tdx::evidence::TdxEvidence = serde_json::from_value(evidence)
                    .map_err(|e| AttestationError::EvidenceDeserialize(e.to_string()))?;
                platforms::tdx::verify::verify_evidence(
                    &ev,
                    params,
                    Some(self.tdx_provider.as_ref()),
                )
                .await
            }
            #[cfg(feature = "az-snp")]
            PlatformType::AzSnp => {
                let ev: platforms::az_snp::evidence::AzSnpEvidence =
                    serde_json::from_value(evidence)
                        .map_err(|e| AttestationError::EvidenceDeserialize(e.to_string()))?;
                platforms::az_snp::verify::verify_evidence(&ev, params, self.cert_provider.as_ref())
                    .await
            }
            #[cfg(feature = "az-tdx")]
            PlatformType::AzTdx => {
                let ev: platforms::az_tdx::evidence::AzTdxEvidence =
                    serde_json::from_value(evidence)
                        .map_err(|e| AttestationError::EvidenceDeserialize(e.to_string()))?;
                platforms::az_tdx::verify::verify_evidence(
                    &ev,
                    params,
                    Some(self.tdx_provider.as_ref()),
                )
                .await
            }
            #[cfg(feature = "gcp-snp")]
            PlatformType::GcpSnp => {
                let ev: platforms::snp::evidence::SnpEvidence = serde_json::from_value(evidence)
                    .map_err(|e| AttestationError::EvidenceDeserialize(e.to_string()))?;
                platforms::gcp_snp::verify::verify_evidence(
                    &ev,
                    params,
                    self.cert_provider.as_ref(),
                )
                .await
            }
            #[cfg(feature = "gcp-tdx")]
            PlatformType::GcpTdx => {
                let ev: platforms::tdx::evidence::TdxEvidence = serde_json::from_value(evidence)
                    .map_err(|e| AttestationError::EvidenceDeserialize(e.to_string()))?;
                platforms::gcp_tdx::verify::verify_evidence(
                    &ev,
                    params,
                    Some(self.tdx_provider.as_ref()),
                )
                .await
            }
            #[cfg(feature = "dstack")]
            PlatformType::Dstack => {
                let ev: platforms::dstack::evidence::DstackEvidence =
                    serde_json::from_value(evidence)
                        .map_err(|e| AttestationError::EvidenceDeserialize(e.to_string()))?;
                platforms::dstack::verify::verify_evidence(
                    &ev,
                    params,
                    Some(self.tdx_provider.as_ref()),
                )
                .await
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

    #[cfg(feature = "nvidia-gpu")]
    async fn verify_nvidia_gpu(
        &self,
        mut result: VerificationResult,
        gpu_bundle: Option<NvidiaGpuEvidenceBundle>,
        params: &VerifyParams,
    ) -> Result<VerificationResult> {
        match gpu_bundle {
            Some(bundle) => {
                let gpu_claims = platforms::nvidia_gpu::verify_bundle(
                    &bundle,
                    params,
                    self.nras_provider.as_ref(),
                )
                .await?;
                result.claims.nvidia_gpu = Some(gpu_claims);
                Ok(result)
            }
            None if params.nvidia_gpu_required => Err(AttestationError::NvidiaGpuRequired),
            None => Ok(result),
        }
    }
}

impl Default for Verifier {
    fn default() -> Self {
        Self::new()
    }
}

/// Verify attestation evidence from a self-describing JSON envelope.
///
/// Convenience wrapper around [`Verifier`] with default providers.
/// For custom providers (e.g. cached certs), construct a [`Verifier`] instead.
///
/// # Errors
///
/// Returns an error if the evidence is too large, malformed, targets a
/// platform not compiled in, or fails signature/collateral verification.
pub async fn verify(evidence_json: &[u8], params: &VerifyParams) -> Result<VerificationResult> {
    Verifier::new().verify(evidence_json, params).await
}
