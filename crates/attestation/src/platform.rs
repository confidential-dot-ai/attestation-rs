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

use crate::collateral::{CollateralUsed, Store, VersionFloors};
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

/// One TEE platform: its evidence, what a caller can ask of it, its
/// collateral set, and what it answers.
pub trait Platform {
    const KIND: PlatformType;
    type Evidence: DeserializeOwned + Sync;
    type Params: Default + Sync;
    type Result: Serialize;
    type CollateralSet: Send + Sync;

    /// Reject params that cannot be applied. Runs before any collateral is
    /// fetched, so caller misuse is never reported as a retryable error.
    fn validate(params: &Self::Params) -> Result<()>;

    /// Get the collateral set for `evidence` from `store`, at `now` (Unix
    /// seconds), and what the verdict should say about each piece. Checks
    /// that need no collateral run first; the store is the only I/O.
    fn gather(
        evidence: &Self::Evidence,
        store: &Store,
        now: i64,
    ) -> impl Future<Output = Result<(Self::CollateralSet, Vec<CollateralUsed>)>> + Send;

    /// Verify `evidence` and evaluate every rule in `params`, at `now` (Unix
    /// seconds). Pure: no network, no cache, no clock.
    ///
    /// `Ok` means the evidence is genuine; whether it satisfied the params is
    /// in the result (`passed()`).
    fn verify(
        evidence: &Self::Evidence,
        params: &Self::Params,
        collateral: &Self::CollateralSet,
        now: i64,
    ) -> Result<Self::Result>;
}

/// The platforms a caller accepts, each with its params. Evidence for a
/// platform left at `None` is rejected with
/// [`AttestationError::PlatformNotAllowed`].
///
/// In JSON, an object keyed by platform tag (`tdx`, `az-tdx`, ...), plus
/// `nvidia_gpu` and `floors`; an unknown key is refused.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields, rename_all = "kebab-case")]
pub struct Policies {
    #[cfg(feature = "tdx")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tdx: Option<TdxParams>,
    #[cfg(feature = "snp")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub snp: Option<SnpParams>,
    #[cfg(feature = "az-tdx")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub az_tdx: Option<AzTdxParams>,
    #[cfg(feature = "az-snp")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub az_snp: Option<AzSnpParams>,
    #[cfg(feature = "gcp-tdx")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub gcp_tdx: Option<GcpTdxParams>,
    #[cfg(feature = "gcp-snp")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub gcp_snp: Option<GcpSnpParams>,
    #[cfg(feature = "dstack")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub dstack: Option<DstackParams>,
    /// Params for an NVIDIA GPU bundle carried next to the CPU evidence.
    /// Evidence that carries a bundle is rejected when this is `None`.
    #[cfg(feature = "nvidia-gpu")]
    #[serde(rename = "nvidia_gpu", skip_serializing_if = "Option::is_none")]
    pub gpu: Option<NvidiaGpuParams>,
    /// The lowest collateral versions accepted.
    pub floors: VersionFloors,
}

impl Policies {
    /// Every platform compiled into this build, each with its default params.
    ///
    /// Use it when any platform is acceptable. The envelope's tag then picks
    /// the platform, and that platform's default checks apply. GPU bundles
    /// stay refused until `gpu` is set.
    pub fn all() -> Self {
        Self {
            #[cfg(feature = "tdx")]
            tdx: Some(TdxParams::default()),
            #[cfg(feature = "snp")]
            snp: Some(SnpParams::default()),
            #[cfg(feature = "az-tdx")]
            az_tdx: Some(AzTdxParams::default()),
            #[cfg(feature = "az-snp")]
            az_snp: Some(AzSnpParams::default()),
            #[cfg(feature = "gcp-tdx")]
            gcp_tdx: Some(GcpTdxParams::default()),
            #[cfg(feature = "gcp-snp")]
            gcp_snp: Some(GcpSnpParams::default()),
            #[cfg(feature = "dstack")]
            dstack: Some(DstackParams::default()),
            #[cfg(feature = "nvidia-gpu")]
            gpu: None,
            floors: VersionFloors::default(),
        }
    }

    /// Require `report_data` (the caller's nonce) on every platform present.
    // A build with no CPU platform feature has nothing to set.
    #[cfg_attr(
        not(any(feature = "tdx", feature = "snp")),
        allow(unused_mut, unused_variables)
    )]
    pub fn with_report_data(mut self, report_data: &[u8]) -> Self {
        #[cfg(feature = "tdx")]
        if let Some(p) = &mut self.tdx {
            p.report_data = Some(report_data.to_vec());
        }
        #[cfg(feature = "snp")]
        if let Some(p) = &mut self.snp {
            p.report_data = Some(report_data.to_vec());
        }
        #[cfg(feature = "az-tdx")]
        if let Some(p) = &mut self.az_tdx {
            p.tdx.report_data = Some(report_data.to_vec());
        }
        #[cfg(feature = "az-snp")]
        if let Some(p) = &mut self.az_snp {
            p.snp.report_data = Some(report_data.to_vec());
        }
        #[cfg(feature = "gcp-tdx")]
        if let Some(p) = &mut self.gcp_tdx {
            p.tdx.report_data = Some(report_data.to_vec());
        }
        #[cfg(feature = "gcp-snp")]
        if let Some(p) = &mut self.gcp_snp {
            p.snp.report_data = Some(report_data.to_vec());
        }
        #[cfg(feature = "dstack")]
        if let Some(p) = &mut self.dstack {
            p.tdx.report_data = Some(report_data.to_vec());
        }
        self
    }

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

    /// The TDX params of every TDX-based platform present.
    #[cfg(feature = "tdx")]
    pub fn tdx_params(&self) -> impl Iterator<Item = &TdxParams> {
        [
            self.tdx.as_ref(),
            #[cfg(feature = "az-tdx")]
            self.az_tdx.as_ref().map(|p| &p.tdx),
            #[cfg(feature = "gcp-tdx")]
            self.gcp_tdx.as_ref().map(|p| &p.tdx),
            #[cfg(feature = "dstack")]
            self.dstack.as_ref().map(|p| &p.tdx),
        ]
        .into_iter()
        .flatten()
    }

    /// The SNP params of every SNP-based platform present.
    #[cfg(feature = "snp")]
    pub fn snp_params(&self) -> impl Iterator<Item = &SnpParams> {
        [
            self.snp.as_ref(),
            #[cfg(feature = "az-snp")]
            self.az_snp.as_ref().map(|p| &p.snp),
            #[cfg(feature = "gcp-snp")]
            self.gcp_snp.as_ref().map(|p| &p.snp),
        ]
        .into_iter()
        .flatten()
    }

    /// The `report_data` the params for `platform` expect, if any.
    #[allow(unreachable_patterns)]
    pub fn report_data(&self, platform: PlatformType) -> Option<&[u8]> {
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
    /// Every piece of collateral the verdict used.
    #[serde(default)]
    pub collateral: Vec<CollateralUsed>,
}

impl Verified {
    /// True when the platform result and the GPU result (if any) both
    /// passed, and every piece of collateral was current (or stale, inside
    /// the grace period) and not below its version floor.
    pub fn passed(&self) -> bool {
        #[cfg(feature = "nvidia-gpu")]
        if self.gpu.as_ref().is_some_and(|gpu| !gpu.passed()) {
            return false;
        }
        self.platform.passed() && self.collateral.iter().all(CollateralUsed::acceptable)
    }
}

/// True unless a requested check came back `Some(false)`.
#[cfg(any(feature = "snp", feature = "tdx"))]
pub(crate) fn all_held(checks: &[Option<bool>]) -> bool {
    checks.iter().all(|c| *c != Some(false))
}

#[cfg(all(test, feature = "az-tdx", feature = "az-snp"))]
mod tests {
    use super::*;

    #[test]
    fn policies_json_round_trips_and_refuses_what_it_cannot_hold() {
        let d48 = "A".repeat(64);
        let pin = format!("{}=", "A".repeat(43));
        let json = serde_json::json!({
            "az-tdx": { "report_data": "AQIDBA==", "mrtd": d48, "rtmr3": [d48], "pcrs": { "4": pin } },
            "snp": { "launch_digest": [d48], "min_tcb": { "bootloader": 1, "tee": 0, "snp": 1, "microcode": 1 } },
            "floors": { "intel_tcb_info": 21 },
        });
        let policies: Policies = serde_json::from_value(json).unwrap();
        let az = policies.az_tdx.as_ref().unwrap();
        assert_eq!(az.tdx.report_data.as_deref(), Some(&[1, 2, 3, 4][..]));
        assert_eq!(az.tdx.mrtd, Some(vec![[0; 48]]));
        assert_eq!(az.tdx.rtmr3, Some(vec![[0; 48]]));
        assert_eq!(az.pcrs[&4], [0; 32]);
        assert_eq!(
            az.tdx.accepted_tcb_statuses,
            TdxParams::default().accepted_tcb_statuses
        );
        assert_eq!(
            policies.snp.as_ref().unwrap().min_tcb.unwrap().bootloader,
            1
        );
        assert_eq!(policies.floors.intel_tcb_info, 21);
        assert_eq!(
            policies.floors.amd_crl_milan,
            VersionFloors::default().amd_crl_milan
        );
        // A claim names only the platforms it accepts, so a build with fewer
        // features reads it back.
        let claim = serde_json::to_value(&policies).unwrap();
        let mut keys: Vec<_> = claim.as_object().unwrap().keys().collect();
        keys.sort();
        assert_eq!(keys, ["az-tdx", "floors", "snp"]);
        let again: Policies = serde_json::from_value(claim.clone()).unwrap();
        assert_eq!(serde_json::to_value(&again).unwrap(), claim);

        for refused in [
            format!(r#"{{"az-snp":{{"pcrs":{{"4":"{pin}","4":"{pin}"}}}}}}"#),
            format!(r#"{{"tdx":{{"pcrs":{{"4":"{pin}"}}}}}}"#),
            r#"{"az-tdx":{"host_data":"AA=="}}"#.into(),
            r#"{"gcp-snp":{"mrtd":null}}"#.into(),
            r#"{"tdx":{"mrtd":[]}}"#.into(),
            r#"{"tdx":{"rtmr0":"AAAA"}}"#.into(),
            r#"{"floors":{"amd_crl":1}}"#.into(),
            r#"{"sgx":{}}"#.into(),
        ] {
            assert!(
                serde_json::from_str::<Policies>(&refused).is_err(),
                "{refused}"
            );
        }
    }
}
