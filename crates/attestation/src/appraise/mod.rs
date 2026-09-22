//! Section 6 of the profile: the normative verification procedure over the
//! profile types, producing an EAR appraisal (section 5).
//!
//! `appraise` orchestrates the platform primitives the crate already has
//! (report parsing, signature and chain verification, DCAP, revocation) and
//! adds what the profile defines on top: the anchor binding, guest policy
//! bits, TCB floors and machine allowlists, reference values, backing floors,
//! normalized claims, the trustworthiness vector and the collateral outcomes.
//! Every step fails closed.

#[cfg(feature = "nvidia-gpu")]
mod device;
pub mod inline;
pub mod legacy;
#[cfg(any(feature = "snp", feature = "tdx"))]
mod vector;
#[cfg(any(feature = "az-snp", feature = "az-tdx"))]
mod vtpm;

#[cfg(feature = "snp")]
mod snp;
#[cfg(feature = "tdx")]
mod tdx;

use crate::error::{AttestationError, RefusalCode, Result};
use crate::profile::binding::anchor;
#[cfg(any(feature = "snp", feature = "tdx"))]
use crate::profile::binding::pad64;
#[cfg(any(feature = "snp", feature = "tdx"))]
use crate::profile::Tee;
use crate::profile::{
    Appraisal, Binding, BindingMode, CpuEvidence, Evidence, FreshnessPattern, GpuDeviceEvidence,
    KeyBinding, Submod, SubmodAppraisal, TcbFloor, VerifierId, VerifyPolicy, EAR_PROFILE_URI,
    PROFILE_URI,
};
use crate::Verifier;
use chrono::{DateTime, Utc};
use std::collections::BTreeMap;

use inline::InlineCollateral;

/// What every submodule appraiser works from.
#[cfg_attr(not(any(feature = "snp", feature = "tdx")), allow(dead_code))]
pub(crate) struct Ctx<'a> {
    /// The relying party's binding input (section 4.5).
    pub anchor: Vec<u8>,
    pub policy: &'a VerifyPolicy,
    /// The evaluation time every validity window is judged against (section 14).
    pub now: DateTime<Utc>,
    /// The HCL `var_data` a verified vtpm submodule established, which the CPU
    /// report must bind in `vtpm-extradata` mode.
    pub vtpm_var_data: Option<Vec<u8>>,
}

impl<'a> Ctx<'a> {
    fn new(
        nonce: &[u8],
        binding: &Binding,
        policy: &'a VerifyPolicy,
        now: DateTime<Utc>,
    ) -> Result<Self> {
        let key = binding.key.as_ref();
        if let Some(required) = &policy.freshness.key {
            if Some(required) != key {
                return Err(refuse(
                    RefusalCode::BindingMismatch,
                    "cvm_binding.key does not match the key the policy requires",
                ));
            }
        } else if binding.pattern == FreshnessPattern::Certificate {
            // Section 4.5.1: the verifier compares the certificate it was
            // presented with, which reaches it as the policy's key. Without
            // it the evidence would vouch for a certificate nobody saw.
            return Err(refuse(RefusalCode::BindingMismatch,
                "the certificate pattern needs the presented certificate's key in policy.freshness.key",
            ));
        }
        let anchor = anchor(nonce, key.map(|k| (k.kind.as_str(), k.value.as_slice())))
            .ok_or_else(|| invalid("anchor inputs are out of range"))?;
        Ok(Ctx {
            anchor,
            now,
            policy,
            vtpm_var_data: None,
        })
    }

    /// The 64-byte value a report's `report_data` must carry in `report-data` mode.
    #[cfg(any(feature = "snp", feature = "tdx"))]
    pub fn expected_report_data(&self) -> [u8; 64] {
        pad64(&self.anchor).expect("an anchor is at most 48 bytes")
    }
}

/// One submodule's appraisal plus whether its freshness binding held.
#[derive(Debug)]
pub(crate) struct Outcome {
    pub appraisal: SubmodAppraisal,
    pub bound: bool,
}

pub(crate) fn invalid(msg: impl Into<String>) -> AttestationError {
    AttestationError::ProfileEvidenceInvalid(msg.into())
}

/// A refusal with its section 14.4 code; `invalid` is the `envelope-invalid` case.
pub(crate) fn refuse(code: RefusalCode, reason: impl Into<String>) -> AttestationError {
    AttestationError::refused(code, reason)
}

impl Verifier {
    /// Parse a profile envelope and appraise it.
    pub async fn appraise_json(&self, json: &[u8], policy: &VerifyPolicy) -> Result<Appraisal> {
        let evidence = Evidence::from_json(json)?;
        self.appraise(&evidence, policy).await
    }

    /// Map a pre-profile envelope (`{platform, evidence}`) to the profile with
    /// the relying party's nonce and optional key binding, then appraise it.
    pub async fn appraise_legacy_json(
        &self,
        json: &[u8],
        nonce: &[u8],
        key: Option<KeyBinding>,
        policy: &VerifyPolicy,
    ) -> Result<Appraisal> {
        let evidence = Evidence::from_legacy(json, nonce, key)?;
        self.appraise(&evidence, policy).await
    }

    /// Appraise a validated envelope against a policy (section 6).
    pub async fn appraise(&self, evidence: &Evidence, policy: &VerifyPolicy) -> Result<Appraisal> {
        evidence.validate()?;
        policy.validate()?;
        let now = (self.clock)();
        let nonce = evidence.eat_nonce.as_slice();
        let mut submods = BTreeMap::new();
        let mut all_bound = true;

        // A CPU bound through a vTPM needs the vtpm submodule appraised first:
        // it yields the var_data the CPU report must carry the digest of.
        let mut var_data: Option<Vec<u8>> = None;
        if let Some(Submod::Cpu(cpu)) = evidence.submods.get("cpu") {
            if cpu.cvm_binding.mode == BindingMode::VtpmExtradata {
                let Some(Submod::Vtpm(v)) = evidence.submods.get("vtpm") else {
                    return Err(invalid(
                        "cpu binds through vtpm-extradata but there is no vtpm submodule",
                    ));
                };
                let out = self.appraise_vtpm(v, cpu, nonce, policy, now)?;
                var_data = Some(out.var_data);
                all_bound &= out.outcome.bound;
                submods.insert("vtpm".to_string(), out.outcome.appraisal);
            }
        }

        let mut devices = Vec::new();
        for (name, submod) in &evidence.submods {
            let outcome = match submod {
                Submod::Cpu(cpu) => {
                    let mut ctx = Ctx::new(nonce, &cpu.cvm_binding, policy, now)?;
                    ctx.vtpm_var_data = var_data.clone();
                    let collateral = InlineCollateral::new(
                        cpu.cvm_endorsements.as_ref(),
                        self.cert_provider.as_ref(),
                        self.tdx_collateral(),
                        now,
                    );
                    appraise_cpu(cpu, &ctx, &collateral).await?
                }
                Submod::CcaToken(_) => {
                    return Err(AttestationError::PlatformNotEnabled(
                        "Arm CCA appraisal".to_string(),
                    ))
                }
                Submod::Vtpm(_) => {
                    if submods.contains_key("vtpm") {
                        continue;
                    }
                    return Err(invalid(
                        "a vtpm submodule needs a cpu bound through vtpm-extradata",
                    ));
                }
                Submod::Device(d) => {
                    devices.push((name.clone(), d));
                    continue;
                }
            };
            all_bound &= outcome.bound;
            submods.insert(name.clone(), outcome.appraisal);
        }

        // A pin that nothing checked is a pin that failed.
        if !policy.reference.pcrs.is_empty() && !submods.contains_key("vtpm") {
            return Err(refuse(
                RefusalCode::ReferenceMismatch,
                "policy pins vTPM PCRs but the evidence carries no vtpm submodule",
            ));
        }

        // Devices go to NRAS in one request per architecture (section 6).
        for (name, outcome) in self.appraise_devices(devices, nonce, policy, now).await? {
            all_bound &= outcome.bound;
            submods.insert(name, outcome.appraisal);
        }

        // The profile names the procedure; the policy's own id names what was
        // required, so two results are comparable exactly when both match.
        let policy_ids = vec![PROFILE_URI.to_string(), policy.id()];
        for sub in submods.values_mut() {
            sub.ear_appraisal_policy_ids = policy_ids.clone();
        }
        let appraisal = Appraisal {
            eat_profile: EAR_PROFILE_URI.to_string(),
            iat: now.timestamp(),
            ear_verifier_id: VerifierId {
                developer: "https://confidential.ai".to_string(),
                build: format!("attestation-rs {}", env!("CARGO_PKG_VERSION")),
            },
            eat_nonce: evidence.eat_nonce.clone(),
            ear_raw_evidence: None,
            ear_all_submods_bound: all_bound,
            submods,
        };
        appraisal.validate()?;
        Ok(appraisal)
    }
}

impl Verifier {
    #[cfg(any(feature = "az-snp", feature = "az-tdx"))]
    fn appraise_vtpm(
        &self,
        v: &crate::profile::VtpmEvidence,
        cpu: &CpuEvidence,
        nonce: &[u8],
        policy: &VerifyPolicy,
        now: DateTime<Utc>,
    ) -> Result<vtpm::VtpmOutcome> {
        let ctx = Ctx::new(nonce, &cpu.cvm_binding, policy, now)?;
        vtpm::appraise(v, cpu.cvm_platform.tee, &cpu.cvm_binding, &ctx)
    }

    #[cfg(not(any(feature = "az-snp", feature = "az-tdx")))]
    fn appraise_vtpm(
        &self,
        _v: &crate::profile::VtpmEvidence,
        _cpu: &CpuEvidence,
        _nonce: &[u8],
        _policy: &VerifyPolicy,
        _now: DateTime<Utc>,
    ) -> Result<VtpmOutcome> {
        Err(AttestationError::PlatformNotEnabled(
            "Azure (vtpm submodule) appraisal".to_string(),
        ))
    }
}

#[cfg(not(any(feature = "az-snp", feature = "az-tdx")))]
struct VtpmOutcome {
    var_data: Vec<u8>,
    outcome: Outcome,
}

impl Verifier {
    #[cfg(feature = "nvidia-gpu")]
    async fn appraise_devices(
        &self,
        devices: Vec<(String, &GpuDeviceEvidence)>,
        nonce: &[u8],
        policy: &VerifyPolicy,
        now: DateTime<Utc>,
    ) -> Result<Vec<(String, Outcome)>> {
        device::appraise_devices(devices, nonce, policy, self.nras_provider.as_ref(), now).await
    }

    #[cfg(not(feature = "nvidia-gpu"))]
    async fn appraise_devices(
        &self,
        devices: Vec<(String, &GpuDeviceEvidence)>,
        _nonce: &[u8],
        policy: &VerifyPolicy,
        _now: DateTime<Utc>,
    ) -> Result<Vec<(String, Outcome)>> {
        if devices.is_empty() && !policy.gpu.required {
            return Ok(Vec::new());
        }
        Err(AttestationError::PlatformNotEnabled(
            "NVIDIA device appraisal".to_string(),
        ))
    }
}

/// The floor a machine is held to: its allowlist entry's, else the default.
/// `identity` is the value the hardware chain authenticated (section 7).
#[cfg_attr(
    not(any(feature = "snp", feature = "tdx", feature = "nvidia-gpu")),
    allow(dead_code)
)]
pub(crate) fn resolve_floor<'p>(
    policy: &'p VerifyPolicy,
    identity: &[u8],
) -> Result<(Option<&'p TcbFloor>, Option<i8>)> {
    let Some(allow) = &policy.identity else {
        return Ok((
            policy
                .tcb
                .default_floor
                .as_deref()
                .and_then(|f| policy.tcb.floors.get(f)),
            None,
        ));
    };
    let Some(entry) = allow
        .machines
        .iter()
        .find(|m| crate::utils::constant_time_eq(m.id.as_slice(), identity))
    else {
        // AR4SI 97: the attester is not recognized, and policy says it should be.
        return Err(refuse(
            RefusalCode::MachineNotAllowed,
            format!(
                "identity {} is not on the machine allowlist",
                hex::encode(identity)
            ),
        ));
    };
    let floor_name = entry
        .tcb_floor
        .as_deref()
        .or(policy.tcb.default_floor.as_deref());
    Ok((floor_name.and_then(|f| policy.tcb.floors.get(f)), Some(2)))
}

/// Dispatch on the TEE the envelope names; a TEE this build was compiled
/// without is refused, never silently skipped.
#[cfg_attr(not(any(feature = "snp", feature = "tdx")), allow(unused_variables))]
async fn appraise_cpu(
    cpu: &CpuEvidence,
    ctx: &Ctx<'_>,
    collateral: &InlineCollateral<'_>,
) -> Result<Outcome> {
    match cpu.cvm_platform.tee {
        #[cfg(feature = "snp")]
        Tee::SevSnp => snp::appraise(cpu, ctx, collateral).await,
        #[cfg(feature = "tdx")]
        Tee::Tdx => tdx::appraise(cpu, ctx, collateral).await,
        other => Err(AttestationError::PlatformNotEnabled(format!(
            "{other:?} appraisal"
        ))),
    }
}
