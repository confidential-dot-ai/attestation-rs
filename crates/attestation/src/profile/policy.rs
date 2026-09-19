//! Section 7: the verifier's policy. Every default fails closed.

use super::appraisal::Digest;
use super::bytes::{Bytes, FixedBytes};
use super::evidence::{Backing, GpuArch, KeyBinding};
use super::registers::{HEADER16, SEED};
use crate::error::{AttestationError, Result};
use crate::types::{SnpTcb, TdxTcbStatus};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

fn policy_err(msg: impl Into<String>) -> AttestationError {
    AttestationError::PolicyInvalid(msg.into())
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields, default)]
pub struct VerifyPolicy {
    pub reference: ReferenceValues,
    /// The weakest backing any verified register may have.
    pub min_backing: Backing,
    pub freshness: FreshnessPolicy,
    pub commitment: CommitmentPolicy,
    pub tcb: TcbPolicy,
    pub policy_bits: PolicyBitsPolicy,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub identity: Option<IdentityPolicy>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub owner: Option<OwnerPolicy>,
    pub gpu: GpuPolicy,
}

impl Default for VerifyPolicy {
    fn default() -> Self {
        VerifyPolicy {
            reference: ReferenceValues::default(),
            min_backing: Backing::Hardware,
            freshness: FreshnessPolicy::default(),
            commitment: CommitmentPolicy::default(),
            tcb: TcbPolicy::default(),
            policy_bits: PolicyBitsPolicy::default(),
            identity: None,
            owner: None,
            gpu: GpuPolicy::default(),
        }
    }
}

/// Reference values, from confos manifests (flat JSON or CoRIM).
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields, default)]
pub struct ReferenceValues {
    /// Any of these launch measurements is acceptable. Empty means unpinned.
    pub launch_measurement: Vec<Digest>,
    /// Acceptable values per slot. A slot absent here is not pinned.
    #[serde(skip_serializing_if = "BTreeMap::is_empty")]
    pub registers: BTreeMap<u16, Vec<Digest>>,
    /// Required `owner` of a workload slot's claim record (section 4.9).
    #[serde(skip_serializing_if = "BTreeMap::is_empty")]
    pub slot_owners: BTreeMap<u16, String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields, default)]
pub struct FreshnessPolicy {
    /// When set, the evidence must bind exactly this key.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub key: Option<KeyBinding>,
}

/// The pinned commitment parameters (section 4.9).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields, default)]
pub struct CommitmentPolicy {
    pub header16: FixedBytes<16>,
    pub seed: FixedBytes<48>,
}

impl Default for CommitmentPolicy {
    fn default() -> Self {
        CommitmentPolicy {
            header16: FixedBytes(HEADER16),
            seed: FixedBytes(SEED),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields, default)]
pub struct TcbPolicy {
    /// Named floors; a machine entry or `default_floor` selects one.
    #[serde(skip_serializing_if = "BTreeMap::is_empty")]
    pub floors: BTreeMap<String, TcbFloor>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub default_floor: Option<String>,
    pub tdx_allowed_status: Vec<TdxTcbStatus>,
    pub require_revocation: bool,
    pub require_signed_collateral: bool,
}

impl Default for TcbPolicy {
    fn default() -> Self {
        TcbPolicy {
            floors: BTreeMap::new(),
            default_floor: None,
            tdx_allowed_status: vec![TdxTcbStatus::UpToDate],
            require_revocation: true,
            require_signed_collateral: true,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields, default)]
pub struct TcbFloor {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub snp: Option<SnpTcb>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tdx: Option<TdxFloor>,
}

#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields, default)]
pub struct TdxFloor {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub min_tee_tcb_svn: Option<FixedBytes<16>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub min_tcb_evaluation_data_number: Option<u32>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields, default)]
pub struct PolicyBitsPolicy {
    pub allow_debug: bool,
    pub allow_migration: bool,
    pub require_vmpl0: bool,
    pub require_sept_ve_disable: bool,
    pub require_zero_reserved_attributes: bool,
    pub allow_service_td: bool,
}

impl Default for PolicyBitsPolicy {
    fn default() -> Self {
        PolicyBitsPolicy {
            allow_debug: false,
            allow_migration: false,
            require_vmpl0: true,
            require_sept_ve_disable: true,
            require_zero_reserved_attributes: true,
            allow_service_td: false,
        }
    }
}

/// Machine allowlist (section 7). An identity absent from `machines` fails.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct IdentityPolicy {
    pub machines: Vec<MachineEntry>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct MachineEntry {
    /// The `cvm_identity` value: SNP `chip_id`, TDX `ppid`, CCA `instance_id`,
    /// or a GPU `ueid` as UTF-8.
    pub id: Bytes,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tcb_floor: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct OwnerPolicy {
    /// SNP `id_key_digest` values that make `cvm_owner` trustworthy.
    pub id_key_digests: Vec<FixedBytes<48>>,
}

/// NVIDIA device policy (section 7, `gpu`). Defined without a feature gate so
/// the policy schema is one schema; the `nvidia-gpu` verifier converts it to
/// its own parameter types.
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields, default)]
pub struct GpuPolicy {
    /// Reject envelopes without a device submodule.
    pub required: bool,
    /// Accepted architectures, as NRAS names them (`HOPPER`, `BLACKWELL`, `LS10`).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub expected_archs: Option<Vec<GpuArch>>,
    pub device_policy: GpuDevicePolicy,
}

/// Per-device gates evaluated against each NRAS submodule; defaults fail closed.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields, default)]
pub struct GpuDevicePolicy {
    pub allow_debug: bool,
    pub require_secboot: bool,
    pub require_nonce_match: bool,
    pub require_measres_success: bool,
}

impl Default for GpuDevicePolicy {
    fn default() -> Self {
        GpuDevicePolicy {
            allow_debug: false,
            require_secboot: true,
            require_nonce_match: true,
            require_measres_success: true,
        }
    }
}

#[cfg(feature = "nvidia-gpu")]
impl From<&GpuDevicePolicy> for crate::types::NvidiaGpuDevicePolicy {
    fn from(p: &GpuDevicePolicy) -> Self {
        crate::types::NvidiaGpuDevicePolicy {
            allow_debug: p.allow_debug,
            require_secboot: p.require_secboot,
            require_nonce_match: p.require_nonce_match,
            require_measres_success: p.require_measres_success,
        }
    }
}

impl VerifyPolicy {
    pub fn from_json(json: &[u8]) -> Result<Self> {
        let p: VerifyPolicy =
            serde_json::from_slice(json).map_err(|e| policy_err(e.to_string()))?;
        p.validate()?;
        Ok(p)
    }

    pub fn validate(&self) -> Result<()> {
        for d in &self.reference.launch_measurement {
            d.validate()
                .map_err(|e| policy_err(format!("reference.launch_measurement: {e}")))?;
        }
        for (slot, ds) in &self.reference.registers {
            if ds.is_empty() {
                return Err(policy_err(format!("reference.registers[{slot}]: empty")));
            }
            for d in ds {
                d.validate()
                    .map_err(|e| policy_err(format!("reference.registers[{slot}]: {e}")))?;
            }
        }
        for (slot, owner) in &self.reference.slot_owners {
            if owner.is_empty() || owner.len() > super::registers::CLAIM_STRING_MAX {
                return Err(policy_err(format!(
                    "reference.slot_owners[{slot}]: empty or too long"
                )));
            }
        }
        if let Some(k) = &self.freshness.key {
            k.validate()
                .map_err(|e| policy_err(format!("freshness.key: {e}")))?;
        }
        if self.tcb.tdx_allowed_status.is_empty() {
            return Err(policy_err("tcb.tdx_allowed_status: empty"));
        }
        if self.tcb.tdx_allowed_status.contains(&TdxTcbStatus::Revoked) {
            return Err(policy_err(
                "tcb.tdx_allowed_status: Revoked can never be allowed",
            ));
        }
        let floor_exists = |name: &str| self.tcb.floors.contains_key(name);
        if let Some(f) = &self.tcb.default_floor {
            if !floor_exists(f) {
                return Err(policy_err(format!(
                    "tcb.default_floor {f:?} is not in tcb.floors"
                )));
            }
        }
        if let Some(id) = &self.identity {
            if id.machines.is_empty() {
                return Err(policy_err(
                    "identity.machines: empty allowlist admits nothing; omit identity to disable",
                ));
            }
            for m in &id.machines {
                if m.id.is_empty() {
                    return Err(policy_err("identity.machines: empty id"));
                }
                if let Some(f) = &m.tcb_floor {
                    if !floor_exists(f) {
                        return Err(policy_err(format!(
                            "identity.machines: floor {f:?} is not in tcb.floors"
                        )));
                    }
                }
            }
        }
        if let Some(o) = &self.owner {
            if o.id_key_digests.is_empty() {
                return Err(policy_err("owner.id_key_digests: empty"));
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn defaults_fail_closed() {
        let p = VerifyPolicy::default();
        assert_eq!(p.min_backing, Backing::Hardware);
        assert!(!p.policy_bits.allow_debug);
        assert!(!p.policy_bits.allow_migration);
        assert!(p.policy_bits.require_vmpl0);
        assert!(p.policy_bits.require_sept_ve_disable);
        assert!(p.policy_bits.require_zero_reserved_attributes);
        assert!(!p.policy_bits.allow_service_td);
        assert!(p.tcb.require_revocation);
        assert!(p.tcb.require_signed_collateral);
        assert!(!p.gpu.required);
        assert!(!p.gpu.device_policy.allow_debug);
        assert!(p.gpu.device_policy.require_secboot);
        assert!(p.gpu.device_policy.require_nonce_match);
        assert!(p.gpu.device_policy.require_measres_success);
        assert_eq!(p.tcb.tdx_allowed_status, vec![TdxTcbStatus::UpToDate]);
        assert_eq!(p.commitment.header16.0, HEADER16);
        assert_eq!(p.commitment.seed.0, SEED);
        p.validate().unwrap();
        let empty = VerifyPolicy::from_json(b"{}").unwrap();
        assert_eq!(empty, p);
    }

    #[test]
    fn floors_and_allowlists_are_checked() {
        let bad = json!({"tcb": {"default_floor": "genoa-2026-09"}});
        assert!(VerifyPolicy::from_json(&serde_json::to_vec(&bad).unwrap())
            .unwrap_err()
            .to_string()
            .contains("not in tcb.floors"));
        let good = json!({
            "tcb": {"floors": {"genoa-2026-09": {"snp": {"bootloader": 4, "tee": 0, "snp": 23, "microcode": 209}}}, "default_floor": "genoa-2026-09"},
            "identity": {"machines": [{"id": Bytes(vec![1; 64]).encode(), "tcb_floor": "genoa-2026-09"}]}
        });
        VerifyPolicy::from_json(&serde_json::to_vec(&good).unwrap()).unwrap();
        let unknown = json!({"identity": {"machines": [{"id": "AQ", "tcb_floor": "missing"}]}});
        assert!(VerifyPolicy::from_json(&serde_json::to_vec(&unknown).unwrap()).is_err());
        let empty_list = json!({"identity": {"machines": []}});
        assert!(VerifyPolicy::from_json(&serde_json::to_vec(&empty_list).unwrap()).is_err());
        let revoked = json!({"tcb": {"tdx_allowed_status": ["Revoked"]}});
        assert!(VerifyPolicy::from_json(&serde_json::to_vec(&revoked).unwrap()).is_err());
        let extra = json!({"surprise": true});
        assert!(VerifyPolicy::from_json(&serde_json::to_vec(&extra).unwrap()).is_err());
        let short =
            json!({"reference": {"launch_measurement": [{"alg": "sha384", "value": "AQ"}]}});
        assert!(VerifyPolicy::from_json(&serde_json::to_vec(&short).unwrap()).is_err());
    }
}
