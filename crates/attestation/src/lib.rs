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
//! assert!(result.signature_valid && !result.policy_failed());
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
// When `attest` is enabled without any platform feature, every match arm
// below is cfg'd out and the catch-all `_other` arm is the only one left,
// making the let-binding and trailing code formally unreachable. That is
// the intended runtime behavior (return PlatformNotEnabled), so silence
// the warnings instead of complicating the structure.
#[allow(unreachable_code, unused_variables)]
pub async fn attest(
    platform: PlatformType,
    report_data: &[u8],
    options: &AttestOptions,
) -> Result<Vec<u8>> {
    #[allow(unreachable_patterns)]
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
        _other => {
            let _ = (report_data, options);
            return Err(AttestationError::PlatformNotEnabled(_other.to_string()));
        }
    };

    let envelope = AttestationEvidence {
        platform,
        evidence: evidence_value,
    };

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
}

impl Verifier {
    #[must_use]
    pub fn new() -> Self {
        Self {
            cert_provider: Box::new(DefaultCertProvider::new()),
            tdx_provider: Box::new(DefaultTdxCollateralProvider::new()),
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
    ) -> Result<VerifyResult> {
        // Bounded deserialization — reject oversized evidence before parsing
        if evidence_json.len() > MAX_EVIDENCE_SIZE {
            return Err(AttestationError::EvidenceTooLarge {
                size: evidence_json.len(),
                max: MAX_EVIDENCE_SIZE,
            });
        }

        // Validate report_data / nonce sizes (all platforms cap at 64 bytes)
        if let Some(ref data) = params.report_data {
            if data.len() > 64 {
                return Err(AttestationError::ReportDataTooLarge { max: 64 });
            }
        }
        if let Some(ref data) = params.nonce {
            if data.len() > 64 {
                return Err(AttestationError::ReportDataTooLarge { max: 64 });
            }
        }

        let envelope: AttestationEvidence = serde_json::from_slice(evidence_json)
            .map_err(|e| AttestationError::EvidenceDeserialize(e.to_string()))?;

        // If the caller pinned a specific vendor, reject envelopes that
        // disagree. Vendor-specific params would otherwise be silently
        // ignored on an envelope-driven dispatch, which is a footgun.
        if let Some(expected) = params.vendor.platform_tag() {
            if expected != envelope.platform {
                return Err(AttestationError::PlatformMismatch {
                    expected: expected.to_string(),
                    actual: envelope.platform.to_string(),
                });
            }
        }

        #[allow(unreachable_patterns)]
        match envelope.platform {
            #[cfg(feature = "snp")]
            PlatformType::Snp => {
                let evidence: platforms::snp::evidence::SnpEvidence =
                    serde_json::from_value(envelope.evidence)
                        .map_err(|e| AttestationError::EvidenceDeserialize(e.to_string()))?;
                platforms::snp::verify::verify_evidence(
                    &evidence,
                    params,
                    self.cert_provider.as_ref(),
                )
                .await
            }
            #[cfg(feature = "tdx")]
            PlatformType::Tdx => {
                let evidence: platforms::tdx::evidence::TdxEvidence =
                    serde_json::from_value(envelope.evidence)
                        .map_err(|e| AttestationError::EvidenceDeserialize(e.to_string()))?;
                platforms::tdx::verify::verify_evidence(
                    &evidence,
                    params,
                    Some(self.tdx_provider.as_ref()),
                )
                .await
            }
            #[cfg(feature = "az-snp")]
            PlatformType::AzSnp => {
                let evidence: platforms::az_snp::evidence::AzSnpEvidence =
                    serde_json::from_value(envelope.evidence)
                        .map_err(|e| AttestationError::EvidenceDeserialize(e.to_string()))?;
                platforms::az_snp::verify::verify_evidence(
                    &evidence,
                    params,
                    self.cert_provider.as_ref(),
                )
                .await
            }
            #[cfg(feature = "az-tdx")]
            PlatformType::AzTdx => {
                let evidence: platforms::az_tdx::evidence::AzTdxEvidence =
                    serde_json::from_value(envelope.evidence)
                        .map_err(|e| AttestationError::EvidenceDeserialize(e.to_string()))?;
                platforms::az_tdx::verify::verify_evidence(
                    &evidence,
                    params,
                    Some(self.tdx_provider.as_ref()),
                )
                .await
            }
            #[cfg(feature = "gcp-snp")]
            PlatformType::GcpSnp => {
                let evidence: platforms::snp::evidence::SnpEvidence =
                    serde_json::from_value(envelope.evidence)
                        .map_err(|e| AttestationError::EvidenceDeserialize(e.to_string()))?;
                platforms::gcp_snp::verify::verify_evidence(
                    &evidence,
                    params,
                    self.cert_provider.as_ref(),
                )
                .await
            }
            #[cfg(feature = "gcp-tdx")]
            PlatformType::GcpTdx => {
                let evidence: platforms::tdx::evidence::TdxEvidence =
                    serde_json::from_value(envelope.evidence)
                        .map_err(|e| AttestationError::EvidenceDeserialize(e.to_string()))?;
                platforms::gcp_tdx::verify::verify_evidence(
                    &evidence,
                    params,
                    Some(self.tdx_provider.as_ref()),
                )
                .await
            }
            #[cfg(feature = "dstack")]
            PlatformType::Dstack => {
                let evidence: platforms::dstack::evidence::DstackEvidence =
                    serde_json::from_value(envelope.evidence)
                        .map_err(|e| AttestationError::EvidenceDeserialize(e.to_string()))?;
                platforms::dstack::verify::verify_evidence(
                    &evidence,
                    params,
                    Some(self.tdx_provider.as_ref()),
                )
                .await
            }
            other => {
                let _ = params;
                Err(AttestationError::PlatformNotEnabled(other.to_string()))
            }
        }
    }
}

/// Cheap, side-effect-free helper that just reads the envelope `platform` tag.
///
/// Useful for callers that want to inspect the platform before deciding
/// whether to fetch collateral, surface a vendor-specific UI, etc. The
/// reading is bounded by [`MAX_EVIDENCE_SIZE`] and uses the same JSON
/// parser as [`Verifier::verify`].
pub fn detect_platform(evidence_json: &[u8]) -> Result<PlatformType> {
    if evidence_json.len() > MAX_EVIDENCE_SIZE {
        return Err(AttestationError::EvidenceTooLarge {
            size: evidence_json.len(),
            max: MAX_EVIDENCE_SIZE,
        });
    }
    let envelope: AttestationEvidence = serde_json::from_slice(evidence_json)
        .map_err(|e| AttestationError::EvidenceDeserialize(e.to_string()))?;
    Ok(envelope.platform)
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
pub async fn verify(evidence_json: &[u8], params: &VerifyParams) -> Result<VerifyResult> {
    Verifier::new().verify(evidence_json, params).await
}

#[cfg(test)]
mod tests {
    use super::*;

    fn envelope(platform: PlatformType) -> Vec<u8> {
        let env = AttestationEvidence {
            platform,
            evidence: serde_json::json!({}),
        };
        serde_json::to_vec(&env).unwrap()
    }

    #[test]
    fn detect_platform_reads_envelope_tag() {
        let bytes = envelope(PlatformType::Tdx);
        let p = detect_platform(&bytes).unwrap();
        assert_eq!(p, PlatformType::Tdx);
    }

    #[test]
    fn detect_platform_rejects_oversized_evidence() {
        let bytes = vec![b'{'; MAX_EVIDENCE_SIZE + 1];
        let err = detect_platform(&bytes).unwrap_err();
        assert!(matches!(err, AttestationError::EvidenceTooLarge { .. }));
    }

    #[tokio::test]
    async fn verify_rejects_vendor_mismatch() {
        // Envelope claims Snp, caller pins VendorParams::Tdx. The dispatcher
        // must reject before invoking any per-vendor verifier so that
        // vendor-specific params are not silently ignored.
        let bytes = envelope(PlatformType::Snp);
        let params = VerifyParams {
            vendor: VendorParams::Tdx(VerifyTdx::default()),
            ..Default::default()
        };
        let err = Verifier::new().verify(&bytes, &params).await.unwrap_err();
        match err {
            AttestationError::PlatformMismatch { expected, actual } => {
                assert_eq!(expected, "tdx");
                assert_eq!(actual, "snp");
            }
            other => panic!("expected PlatformMismatch, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn verify_auto_dispatches_by_envelope() {
        // VendorParams::Auto accepts whatever the envelope says — confirmed
        // by reaching the per-vendor verifier (which will fail on the empty
        // evidence body, but not with PlatformMismatch).
        let bytes = envelope(PlatformType::Snp);
        let params = VerifyParams::default();
        let err = Verifier::new().verify(&bytes, &params).await.unwrap_err();
        // The dispatcher passed through to the per-vendor SNP verifier, which
        // failed on the malformed body — NOT a PlatformMismatch.
        assert!(
            !matches!(err, AttestationError::PlatformMismatch { .. }),
            "Auto must not reject envelope-driven dispatch"
        );
    }
}
