//! Section 6 of the profile: the normative verification procedure over the
//! profile types, producing an EAR appraisal (section 5).
//!
//! `appraise` orchestrates the platform primitives the crate already has
//! (report parsing, signature and chain verification, DCAP, revocation) and
//! adds what the profile defines on top: the anchor binding, guest policy
//! bits, TCB floors and machine allowlists, reference values, backing floors,
//! normalized claims, the trustworthiness vector and the collateral outcomes.
//! Every step fails closed.

pub mod inline;
pub mod legacy;
#[cfg(any(feature = "snp", feature = "tdx"))]
mod vector;

#[cfg(feature = "snp")]
mod snp;
#[cfg(feature = "tdx")]
mod tdx;

use crate::error::{AttestationError, Result};
use crate::profile::binding::anchor;
#[cfg(any(feature = "snp", feature = "tdx"))]
use crate::profile::binding::pad64;
#[cfg(any(feature = "snp", feature = "tdx"))]
use crate::profile::Tee;
use crate::profile::{
    Appraisal, CpuEvidence, Evidence, KeyBinding, Submod, SubmodAppraisal, VerifierId,
    VerifyPolicy, EAR_PROFILE_URI,
};
use crate::Verifier;
use chrono::Utc;
use std::collections::BTreeMap;

use inline::InlineCollateral;

/// What every submodule appraiser works from.
#[cfg_attr(not(any(feature = "snp", feature = "tdx")), allow(dead_code))]
pub(crate) struct Ctx<'a> {
    /// The relying party's binding input (section 4.5).
    pub anchor: Vec<u8>,
    pub policy: &'a VerifyPolicy,
}

impl<'a> Ctx<'a> {
    fn new(nonce: &[u8], key: Option<&KeyBinding>, policy: &'a VerifyPolicy) -> Result<Self> {
        if let Some(required) = &policy.freshness.key {
            if Some(required) != key {
                return Err(invalid(
                    "cvm_binding.key does not match the key the policy requires",
                ));
            }
        }
        let anchor = anchor(nonce, key.map(|k| (k.kind.as_str(), k.value.as_slice())))
            .ok_or_else(|| invalid("anchor inputs are out of range"))?;
        Ok(Ctx { anchor, policy })
    }

    /// The 64-byte value a report's `report_data` must carry in `report-data` mode.
    #[cfg(any(feature = "snp", feature = "tdx"))]
    pub fn expected_report_data(&self) -> [u8; 64] {
        pad64(&self.anchor).expect("an anchor is at most 48 bytes")
    }
}

/// One submodule's appraisal plus whether its freshness binding held.
pub(crate) struct Outcome {
    pub appraisal: SubmodAppraisal,
    pub bound: bool,
}

pub(crate) fn invalid(msg: impl Into<String>) -> AttestationError {
    AttestationError::ProfileEvidenceInvalid(msg.into())
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
        let now = Utc::now();
        let nonce = evidence.eat_nonce.as_slice();
        let mut submods = BTreeMap::new();
        let mut all_bound = true;

        for (name, submod) in &evidence.submods {
            let outcome = match submod {
                Submod::Cpu(cpu) => {
                    let ctx = Ctx::new(nonce, cpu.cvm_binding.key.as_ref(), policy)?;
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
                    return Err(AttestationError::PlatformNotEnabled(
                        "vtpm submodule appraisal".to_string(),
                    ))
                }
                Submod::Device(_) => {
                    return Err(AttestationError::PlatformNotEnabled(
                        "device submodule appraisal".to_string(),
                    ))
                }
            };
            all_bound &= outcome.bound;
            submods.insert(name.clone(), outcome.appraisal);
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
