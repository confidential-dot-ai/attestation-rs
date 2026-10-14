//! The contract every platform verifier implements, and the generic verifier's
//! policy and result types.
//!
//! Error rule: an `Err` means the library could not do its job (malformed
//! evidence, invalid params, platform not compiled in or not allowed,
//! collateral unavailable) or the evidence is not genuine (bad signature, cert
//! chain, QE binding, event log, GPU nonce binding). A genuine answer the
//! caller may not like — a measurement mismatch, debug enabled, a low TCB — is
//! a value in the result, and `passed()` says whether every rule held.

use std::future::Future;

use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};

use crate::context::Context;
use crate::error::{AttestationError, Result};
use crate::types::{Claims, PlatformType};

#[cfg(feature = "az-snp")]
use crate::platforms::az_snp::{AzSnpParams, AzSnpResult};
#[cfg(feature = "az-tdx")]
use crate::platforms::az_tdx::{AzTdxParams, AzTdxResult};
#[cfg(feature = "dstack")]
use crate::platforms::dstack::{DstackParams, DstackResult};
#[cfg(feature = "gcp-snp")]
use crate::platforms::gcp_snp::{GcpSnpParams, GcpSnpResult};
#[cfg(feature = "gcp-tdx")]
use crate::platforms::gcp_tdx::{GcpTdxParams, GcpTdxResult};
#[cfg(feature = "snp")]
use crate::platforms::snp::{SnpParams, SnpResult};
#[cfg(feature = "tdx")]
use crate::platforms::tdx::{TdxParams, TdxResult};
#[cfg(feature = "nvidia-gpu")]
use crate::types::{NvidiaGpuParams, NvidiaGpuResult};

/// One TEE platform: its evidence, what a caller can ask of it, and what it
/// answers.
pub trait Platform {
    const KIND: PlatformType;
    type Evidence: DeserializeOwned + Sync;
    type Params: Default + Sync;
    type Result: Serialize;

    /// Verify `evidence` and evaluate every rule in `params`.
    ///
    /// `Ok` means the evidence is genuine; whether it satisfied the params is
    /// in the result (`passed()`).
    fn verify(
        evidence: &Self::Evidence,
        params: &Self::Params,
        ctx: &Context,
    ) -> impl Future<Output = Result<Self::Result>> + Send;
}

/// The platforms a caller accepts, each with its params. Evidence for a
/// platform left at `None` is rejected with
/// [`AttestationError::PlatformNotAllowed`](crate::AttestationError::PlatformNotAllowed).
#[derive(Debug, Clone, Default)]
pub struct Policies {
    #[cfg(feature = "tdx")]
    pub tdx: Option<TdxParams>,
    #[cfg(feature = "snp")]
    pub snp: Option<SnpParams>,
    #[cfg(feature = "az-tdx")]
    pub az_tdx: Option<AzTdxParams>,
    #[cfg(feature = "az-snp")]
    pub az_snp: Option<AzSnpParams>,
    #[cfg(feature = "gcp-tdx")]
    pub gcp_tdx: Option<GcpTdxParams>,
    #[cfg(feature = "gcp-snp")]
    pub gcp_snp: Option<GcpSnpParams>,
    #[cfg(feature = "dstack")]
    pub dstack: Option<DstackParams>,
    /// Params for an NVIDIA GPU bundle carried next to the CPU evidence.
    /// Evidence that carries a bundle is rejected when this is `None`.
    #[cfg(feature = "nvidia-gpu")]
    pub gpu: Option<NvidiaGpuParams>,
}

impl Policies {
    /// `Ok` when `platform` is compiled in and has params here.
    #[allow(unreachable_patterns)]
    pub(crate) fn check_allowed(&self, platform: PlatformType) -> Result<()> {
        let has_params = match platform {
            #[cfg(feature = "tdx")]
            PlatformType::Tdx => Some(self.tdx.is_some()),
            #[cfg(feature = "snp")]
            PlatformType::Snp => Some(self.snp.is_some()),
            #[cfg(feature = "az-tdx")]
            PlatformType::AzTdx => Some(self.az_tdx.is_some()),
            #[cfg(feature = "az-snp")]
            PlatformType::AzSnp => Some(self.az_snp.is_some()),
            #[cfg(feature = "gcp-tdx")]
            PlatformType::GcpTdx => Some(self.gcp_tdx.is_some()),
            #[cfg(feature = "gcp-snp")]
            PlatformType::GcpSnp => Some(self.gcp_snp.is_some()),
            #[cfg(feature = "dstack")]
            PlatformType::Dstack => Some(self.dstack.is_some()),
            _ => None,
        };
        match has_params {
            Some(true) => Ok(()),
            Some(false) => Err(AttestationError::PlatformNotAllowed(platform.to_string())),
            None => Err(AttestationError::PlatformNotEnabled(platform.to_string())),
        }
    }

    /// The `report_data` the params for `platform` expect, if any.
    #[cfg(feature = "nvidia-gpu")]
    #[allow(unreachable_patterns)]
    pub(crate) fn report_data(&self, platform: PlatformType) -> Option<&[u8]> {
        match platform {
            #[cfg(feature = "tdx")]
            PlatformType::Tdx => self.tdx.as_ref()?.report_data.as_deref(),
            #[cfg(feature = "snp")]
            PlatformType::Snp => self.snp.as_ref()?.report_data.as_deref(),
            #[cfg(feature = "az-tdx")]
            PlatformType::AzTdx => self.az_tdx.as_ref()?.tdx.report_data.as_deref(),
            #[cfg(feature = "az-snp")]
            PlatformType::AzSnp => self.az_snp.as_ref()?.snp.report_data.as_deref(),
            #[cfg(feature = "gcp-tdx")]
            PlatformType::GcpTdx => self.gcp_tdx.as_ref()?.tdx.report_data.as_deref(),
            #[cfg(feature = "gcp-snp")]
            PlatformType::GcpSnp => self.gcp_snp.as_ref()?.snp.report_data.as_deref(),
            #[cfg(feature = "dstack")]
            PlatformType::Dstack => self.dstack.as_ref()?.tdx.report_data.as_deref(),
            _ => None,
        }
    }
}

/// The result of whichever platform produced the evidence.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[must_use]
#[serde(tag = "platform")]
pub enum PlatformResult {
    #[cfg(feature = "tdx")]
    #[serde(rename = "tdx")]
    Tdx(TdxResult),
    #[cfg(feature = "snp")]
    #[serde(rename = "snp")]
    Snp(SnpResult),
    #[cfg(feature = "az-tdx")]
    #[serde(rename = "az-tdx")]
    AzTdx(AzTdxResult),
    #[cfg(feature = "az-snp")]
    #[serde(rename = "az-snp")]
    AzSnp(AzSnpResult),
    #[cfg(feature = "gcp-tdx")]
    #[serde(rename = "gcp-tdx")]
    GcpTdx(GcpTdxResult),
    #[cfg(feature = "gcp-snp")]
    #[serde(rename = "gcp-snp")]
    GcpSnp(GcpSnpResult),
    #[cfg(feature = "dstack")]
    #[serde(rename = "dstack")]
    Dstack(DstackResult),
}

impl PlatformResult {
    /// The platform that produced the evidence.
    ///
    /// For the cloud variants this comes from the envelope (an attester
    /// claim), not from hardware-proven cloud identity.
    pub fn platform(&self) -> PlatformType {
        match *self {
            #[cfg(feature = "tdx")]
            PlatformResult::Tdx(_) => PlatformType::Tdx,
            #[cfg(feature = "snp")]
            PlatformResult::Snp(_) => PlatformType::Snp,
            #[cfg(feature = "az-tdx")]
            PlatformResult::AzTdx(_) => PlatformType::AzTdx,
            #[cfg(feature = "az-snp")]
            PlatformResult::AzSnp(_) => PlatformType::AzSnp,
            #[cfg(feature = "gcp-tdx")]
            PlatformResult::GcpTdx(_) => PlatformType::GcpTdx,
            #[cfg(feature = "gcp-snp")]
            PlatformResult::GcpSnp(_) => PlatformType::GcpSnp,
            #[cfg(feature = "dstack")]
            PlatformResult::Dstack(_) => PlatformType::Dstack,
        }
    }

    /// The normalized claims of the verified evidence.
    pub fn claims(&self) -> &Claims {
        match *self {
            #[cfg(feature = "tdx")]
            PlatformResult::Tdx(ref r) => &r.claims,
            #[cfg(feature = "snp")]
            PlatformResult::Snp(ref r) => &r.claims,
            #[cfg(feature = "az-tdx")]
            PlatformResult::AzTdx(ref r) => &r.tdx.claims,
            #[cfg(feature = "az-snp")]
            PlatformResult::AzSnp(ref r) => &r.snp.claims,
            #[cfg(feature = "gcp-tdx")]
            PlatformResult::GcpTdx(ref r) => &r.tdx.claims,
            #[cfg(feature = "gcp-snp")]
            PlatformResult::GcpSnp(ref r) => &r.snp.claims,
            #[cfg(feature = "dstack")]
            PlatformResult::Dstack(ref r) => &r.tdx.claims,
        }
    }

    /// True when the evidence satisfied every rule in the platform's params.
    pub fn passed(&self) -> bool {
        match *self {
            #[cfg(feature = "tdx")]
            PlatformResult::Tdx(ref r) => r.passed(),
            #[cfg(feature = "snp")]
            PlatformResult::Snp(ref r) => r.passed(),
            #[cfg(feature = "az-tdx")]
            PlatformResult::AzTdx(ref r) => r.passed(),
            #[cfg(feature = "az-snp")]
            PlatformResult::AzSnp(ref r) => r.passed(),
            #[cfg(feature = "gcp-tdx")]
            PlatformResult::GcpTdx(ref r) => r.passed(),
            #[cfg(feature = "gcp-snp")]
            PlatformResult::GcpSnp(ref r) => r.passed(),
            #[cfg(feature = "dstack")]
            PlatformResult::Dstack(ref r) => r.passed(),
        }
    }
}

/// What [`Verifier::verify`](crate::Verifier::verify) returns: the platform
/// result and, when the evidence carried one, the GPU result.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[must_use]
pub struct Verified {
    #[serde(flatten)]
    pub platform: PlatformResult,
    #[cfg(feature = "nvidia-gpu")]
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub gpu: Option<NvidiaGpuResult>,
}

impl Verified {
    /// True when the platform result and the GPU result (if any) both passed.
    pub fn passed(&self) -> bool {
        #[cfg(feature = "nvidia-gpu")]
        if self.gpu.as_ref().is_some_and(|gpu| !gpu.passed()) {
            return false;
        }
        self.platform.passed()
    }
}

/// True unless a requested check came back `Some(false)`.
#[cfg(any(feature = "snp", feature = "tdx"))]
pub(crate) fn all_held(checks: &[Option<bool>]) -> bool {
    checks.iter().all(|c| *c != Some(false))
}
