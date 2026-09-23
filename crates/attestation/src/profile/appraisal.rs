//! Section 5: results, as EAR draft-ietf-rats-ear-04 claims sets.
//!
//! The library produces the claims; the relying party signs. Layout follows the
//! EAR CDDL: nonce, verifier id and raw evidence at the top, one appraisal
//! record per evidence submodule under `submods`.

use super::bytes::{Bytes, FixedBytes};
use super::cmw::CmwRecord;
use super::evidence::{
    Backing, BindingMode, DebugStatus, FreshnessPattern, HashAlg, Hosting, KeyBinding,
    RegisterSource, Tee, Vendor,
};
use super::{invalid, EAR_PROFILE_URI};
use crate::error::Result;
use crate::types::{SnpTcb, TdxTcbStatus};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

/// Media type of a CMW collection carried inside a CMW record (RFC 9999).
pub const MEDIA_TYPE_CMW_JSON: &str = "application/cmw+json";

/// The EAR claims set.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct Appraisal {
    /// Always [`EAR_PROFILE_URI`].
    pub eat_profile: String,
    /// Seconds since the epoch when the appraisal was produced.
    pub iat: i64,
    pub ear_verifier_id: VerifierId,
    /// The nonce that was bound.
    pub eat_nonce: Bytes,
    /// A record of type `application/cmw+json` whose value is a CMW collection
    /// carrying the envelope as appraised (indicator bit 2) and the endorsement
    /// snapshot the verifier used (bit 1).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ear_raw_evidence: Option<CmwRecord>,
    /// Every submodule's freshness binding held (section 5.3). The TDX and
    /// confidential-GPU EAR profile defines the claim with a text value.
    pub ear_all_submods_bound: AllBound,
    /// One appraisal per evidence submodule, same names.
    pub submods: BTreeMap<String, SubmodAppraisal>,
}

/// `ear_all_submods_bound` as draft-kykdxy-rats-tdx-cgpu-ear-profile-02
/// defines it: text, `"true"` or `"false"`. Its `"unknown"` never applies
/// here, since every binding is checked.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "lowercase")]
pub enum AllBound {
    True,
    False,
}

impl From<bool> for AllBound {
    fn from(bound: bool) -> Self {
        if bound {
            AllBound::True
        } else {
            AllBound::False
        }
    }
}

impl AllBound {
    pub fn is_true(self) -> bool {
        self == AllBound::True
    }
}

impl std::fmt::Display for AllBound {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(if self.is_true() { "true" } else { "false" })
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct VerifierId {
    pub developer: String,
    pub build: String,
}

/// One EAR appraisal record.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct SubmodAppraisal {
    pub ear_status: Tier,
    pub ear_trustworthiness_vector: TrustVector,
    pub ear_appraisal_policy_ids: Vec<String>,
    pub ear_attester_claims: AttesterClaims,
    pub ear_verifier_claims: VerifierClaims,
}

/// AR4SI trustworthiness tier. JSON carries the names, CBOR the values.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "lowercase")]
pub enum Tier {
    None,
    Affirming,
    Warning,
    Contraindicated,
}

impl Tier {
    /// The tier a trustworthiness claim value falls in (AR4SI section 2.3.2):
    /// the standard values 0 to 127 and the non-standard negative ones.
    pub fn of(value: i8) -> Tier {
        match value {
            -1..=1 => Tier::None,
            2..=31 | -32..=-2 => Tier::Affirming,
            32..=95 | -96..=-33 => Tier::Warning,
            96..=127 | -128..=-97 => Tier::Contraindicated,
        }
    }
    pub fn value(self) -> u8 {
        match self {
            Tier::None => 0,
            Tier::Affirming => 2,
            Tier::Warning => 32,
            Tier::Contraindicated => 96,
        }
    }
    fn rank(self) -> u8 {
        match self {
            Tier::None => 0,
            Tier::Affirming => 1,
            Tier::Warning => 2,
            Tier::Contraindicated => 3,
        }
    }
}

/// AR4SI trustworthiness vector (section 5.2). Absent categories are "no claim".
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct TrustVector {
    #[serde(
        rename = "instance-identity",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub instance_identity: Option<i8>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub configuration: Option<i8>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub executables: Option<i8>,
    #[serde(
        rename = "file-system",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub file_system: Option<i8>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub hardware: Option<i8>,
    #[serde(
        rename = "runtime-opaque",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub runtime_opaque: Option<i8>,
    #[serde(
        rename = "storage-opaque",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub storage_opaque: Option<i8>,
    #[serde(
        rename = "sourced-data",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub sourced_data: Option<i8>,
}

impl TrustVector {
    pub fn values(&self) -> [Option<i8>; 8] {
        [
            self.instance_identity,
            self.configuration,
            self.executables,
            self.file_system,
            self.hardware,
            self.runtime_opaque,
            self.storage_opaque,
            self.sourced_data,
        ]
    }

    /// The worst tier any claim reaches, which is what `ear_status` reports.
    pub fn status(&self) -> Tier {
        self.values()
            .into_iter()
            .flatten()
            .map(Tier::of)
            .max_by_key(|t| t.rank())
            .unwrap_or(Tier::None)
    }
}

/// `ear_attester_claims`, shaped by the submodule kind.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(untagged)]
pub enum AttesterClaims {
    Cpu(Box<CpuClaims>),
    Vtpm(Box<VtpmClaims>),
    /// NVIDIA device claims with the NRAS and `ear_nvidia_*` names unchanged (section 5.3).
    Device(DeviceClaims),
}

/// Normalized `cpu` claims (section 5.1). `compat` carries the `tdx_*` claims of
/// section 5.3 and the `snp` object of section 5.4 beside them.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct CpuClaims {
    pub cvm_platform: VerifiedPlatform,
    pub cvm_launch_measurement: Digest,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cvm_registers: Option<Vec<VerifiedRegister>>,
    pub cvm_freshness: Freshness,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cvm_host_data: Option<HostData>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cvm_owner: Option<Owner>,
    pub cvm_policy: PolicyBits,
    /// EAT `dbgstat` derived from the guest policy, which is fixed at launch:
    /// `enabled`, or `disabled-since-boot`.
    pub dbgstat: DebugStatus,
    pub cvm_tcb: Tcb,
    pub cvm_identity: Identity,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cvm_chain: Option<super::evidence::ChainInfo>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub bootseed: Option<FixedBytes<32>>,
    #[serde(flatten)]
    pub compat: BTreeMap<String, serde_json::Value>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct VerifiedPlatform {
    pub vendor: Vendor,
    pub tee: Tee,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub generation: Option<String>,
    /// As reported by the attester; never hardware-proven (section 4.2).
    pub hosting: Hosting,
}

/// `{alg, value}` with the value the length of the algorithm's digest.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct Digest {
    pub alg: HashAlg,
    pub value: Bytes,
}

impl Digest {
    pub fn validate(&self) -> Result<()> {
        if self.value.len() != self.alg.digest_len() {
            return Err(invalid(format!(
                "digest: {} bytes is not a {} digest",
                self.value.len(),
                self.alg.as_str()
            )));
        }
        Ok(())
    }
}

/// A register the verifier established, plus what the log said about it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct VerifiedRegister {
    pub index: u16,
    pub alg: HashAlg,
    pub value: Bytes,
    pub source: RegisterSource,
    pub backing: Backing,
    pub replayed: bool,
    /// From the slot's claim record (section 4.9), workload slots only.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub owner: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub purpose: Option<String>,
}

/// `cvm_freshness`: presence means the binding check passed.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct Freshness {
    pub pattern: FreshnessPattern,
    pub mode: BindingMode,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub key: Option<KeyBinding>,
    /// RFC 3339, certificate pattern only.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub not_before: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub not_after: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct HostData {
    pub semantics: HostDataSemantics,
    pub value: Bytes,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "kebab-case")]
pub enum HostDataSemantics {
    SnpHostData,
    TdxMrconfigid,
    CcaRpv,
}

impl HostDataSemantics {
    /// Length of the value the semantics imply.
    pub fn byte_len(self) -> usize {
        match self {
            HostDataSemantics::SnpHostData => 32,
            HostDataSemantics::TdxMrconfigid => 48,
            HostDataSemantics::CcaRpv => 64,
        }
    }
}

/// `cvm_owner`, distinguished by its fields.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(untagged)]
pub enum Owner {
    Snp {
        family_id: FixedBytes<16>,
        image_id: FixedBytes<16>,
        id_key_digest: FixedBytes<48>,
        author_key_digest: FixedBytes<48>,
    },
    Tdx {
        mr_owner: FixedBytes<48>,
        mr_owner_config: FixedBytes<48>,
    },
}

/// `cvm_policy`: normalized guest policy.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct PolicyBits {
    pub debug: bool,
    pub migratable: bool,
    /// SNP only; a TD carries no SMT policy.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub smt: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub single_socket: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub vmpl: Option<u8>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sept_ve_disable: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub service_td: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reserved_bits_zero: Option<bool>,
}

/// `cvm_tcb`, distinguished by its fields.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(untagged)]
pub enum Tcb {
    Snp(Box<SnpTcbSet>),
    Tdx(Box<TdxTcb>),
    Cca {
        lifecycle: u16,
        sw_components: Vec<CcaSwComponent>,
    },
    Gpu {
        driver: String,
        vbios: String,
    },
}

/// All four SNP TCB values: what the platform runs, what is committed, what
/// the guest launched with, and what was reported.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct SnpTcbSet {
    pub reported: SnpTcb,
    pub committed: SnpTcb,
    pub current: SnpTcb,
    pub launch: SnpTcb,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct TdxTcb {
    pub tee_tcb_svn: FixedBytes<16>,
    /// CPUSVN of the PCK certificate's TCB level.
    pub pck_tcb: FixedBytes<16>,
    pub pcesvn: u16,
    /// Twelve lowercase hex characters.
    pub fmspc: String,
    /// Absent only when policy allowed the collateral checks to be skipped.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub status: Option<TdxTcbStatus>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub advisories: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct CcaSwComponent {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub measurement_type: Option<String>,
    pub measurement_value: Bytes,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub version: Option<String>,
    pub signer_id: Bytes,
}

/// `cvm_identity`, distinguished by its fields.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(untagged)]
pub enum Identity {
    Snp {
        chip_id: FixedBytes<64>,
    },
    /// The 16-byte PPID from the PCK certificate (OID 1.2.840.113741.1.13.1.1).
    Tdx {
        ppid: FixedBytes<16>,
    },
    Cca {
        instance_id: Bytes,
    },
    Gpu {
        ueid: String,
    },
}

/// Normalized `vtpm` claims: the projected PCRs and the AK binding that held.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct VtpmClaims {
    pub cvm_registers: Vec<VerifiedRegister>,
    pub cvm_freshness: Freshness,
    pub cvm_tpm_ak: super::evidence::TpmAkBinding,
    #[serde(flatten)]
    pub compat: BTreeMap<String, serde_json::Value>,
}

/// Device claims are the NRAS EAT claims verbatim.
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize, JsonSchema)]
pub struct DeviceClaims {
    #[serde(flatten)]
    pub claims: BTreeMap<String, serde_json::Value>,
}

/// `ear_verifier_claims` (section 5.1).
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct VerifierClaims {
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub cvm_collateral: BTreeMap<CollateralCheck, CollateralOutcome>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cvm_reference: Option<ReferenceOutcome>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cvm_backing_min: Option<BackingMin>,
    /// Device submodules only: the composing draft's `ear_nvidia_evidence`
    /// (section 5.3), derived from NRAS's signed per-device claims.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ear_nvidia_evidence: Option<NvidiaEvidenceOutcome>,
}

/// `ear_nvidia_evidence` of draft-kykdxy-rats-tdx-cgpu-ear-profile: what the
/// verifier established about the device evidence. NRAS reports these; the
/// chain and key details the draft also lists stay with NRAS.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct NvidiaEvidenceOutcome {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub signature_verified: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub parsed: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub nonce_match: Option<bool>,
}

#[derive(
    Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize, JsonSchema,
)]
#[serde(rename_all = "snake_case")]
pub enum CollateralCheck {
    SnpCrl,
    TdxPckCrl,
    TdxRootCrl,
    TdxTcbInfo,
    TdxQeIdentity,
    NrasJwks,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct CollateralOutcome {
    pub status: CollateralStatus,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
    /// RFC 3339.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub this_update: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub next_update: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub signed: Option<bool>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "kebab-case")]
pub enum CollateralStatus {
    Checked,
    Skipped,
    NotApplicable,
}

/// Which reference values matched. `launch_measurement` is absent for a
/// submodule that has none (the vtpm).
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ReferenceOutcome {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub launch_measurement: Option<bool>,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub registers: BTreeMap<u16, bool>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct BackingMin {
    pub required: Backing,
    pub weakest_seen: Backing,
}

impl Appraisal {
    pub fn validate(&self) -> Result<()> {
        if self.eat_profile != EAR_PROFILE_URI {
            return Err(invalid(format!(
                "appraisal eat_profile {:?} is not {EAR_PROFILE_URI}",
                self.eat_profile
            )));
        }
        if self.submods.is_empty() {
            return Err(invalid("appraisal has no submods"));
        }
        if let Some(raw) = &self.ear_raw_evidence {
            if raw.media_type != MEDIA_TYPE_CMW_JSON {
                return Err(invalid(format!(
                    "ear_raw_evidence: type must be {MEDIA_TYPE_CMW_JSON}"
                )));
            }
        }
        for (name, s) in &self.submods {
            super::evidence::SubmodName::parse(name)?;
            if s.ear_status != s.ear_trustworthiness_vector.status() {
                return Err(invalid(format!(
                    "submodule {name:?}: ear_status disagrees with the vector"
                )));
            }
            if let AttesterClaims::Cpu(c) = &s.ear_attester_claims {
                c.cvm_launch_measurement.validate()?;
                if let Some(h) = &c.cvm_host_data {
                    if h.value.len() != h.semantics.byte_len() {
                        return Err(invalid(format!("submodule {name:?}: cvm_host_data length")));
                    }
                }
                if let Tcb::Tdx(t) = &c.cvm_tcb {
                    let fmspc = &t.fmspc;
                    if fmspc.len() != 12
                        || !fmspc
                            .bytes()
                            .all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase())
                    {
                        return Err(invalid(format!(
                            "submodule {name:?}: fmspc is twelve lowercase hex characters"
                        )));
                    }
                }
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
    fn tiers_and_status() {
        assert_eq!(Tier::of(0), Tier::None);
        assert_eq!(Tier::of(1), Tier::None);
        assert_eq!(Tier::of(2), Tier::Affirming);
        assert_eq!(Tier::of(31), Tier::Affirming);
        assert_eq!(Tier::of(32), Tier::Warning);
        assert_eq!(Tier::of(95), Tier::Warning);
        assert_eq!(Tier::of(96), Tier::Contraindicated);
        assert_eq!(Tier::of(97), Tier::Contraindicated);
        assert_eq!(Tier::of(99), Tier::Contraindicated);
        assert_eq!(Tier::of(127), Tier::Contraindicated);
        assert_eq!(Tier::of(-1), Tier::None);
        assert_eq!(Tier::of(-2), Tier::Affirming);
        assert_eq!(Tier::of(-32), Tier::Affirming);
        assert_eq!(Tier::of(-33), Tier::Warning);
        assert_eq!(Tier::of(-96), Tier::Warning);
        assert_eq!(Tier::of(-97), Tier::Contraindicated);
        assert_eq!(Tier::of(-128), Tier::Contraindicated);
        let v = TrustVector {
            hardware: Some(2),
            executables: Some(33),
            ..Default::default()
        };
        assert_eq!(v.status(), Tier::Warning);
        assert_eq!(TrustVector::default().status(), Tier::None);
        assert_eq!(
            serde_json::to_value(v).unwrap(),
            json!({"executables": 33, "hardware": 2})
        );
        assert_eq!(
            serde_json::to_string(&Tier::Contraindicated).unwrap(),
            "\"contraindicated\""
        );
        let parsed: TrustVector =
            serde_json::from_value(json!({"instance-identity": 97, "runtime-opaque": 2})).unwrap();
        assert_eq!(parsed.instance_identity, Some(97));
        assert!(serde_json::from_value::<TrustVector>(json!({"instance_identity": 2})).is_err());
    }

    #[test]
    fn verifier_claims_keys() {
        let mut vc = VerifierClaims::default();
        vc.cvm_collateral.insert(
            CollateralCheck::TdxTcbInfo,
            CollateralOutcome {
                status: CollateralStatus::Checked,
                reason: None,
                this_update: None,
                next_update: Some("2026-10-01T00:00:00Z".into()),
                signed: Some(true),
            },
        );
        vc.cvm_reference = Some(ReferenceOutcome {
            launch_measurement: Some(true),
            registers: BTreeMap::from([(0u16, true), (3, false)]),
        });
        let j = serde_json::to_value(&vc).unwrap();
        assert_eq!(j["cvm_collateral"]["tdx_tcb_info"]["status"], "checked");
        assert_eq!(j["cvm_reference"]["registers"]["3"], false);
        let back: VerifierClaims = serde_json::from_value(j).unwrap();
        assert_eq!(back, vc);
    }

    #[test]
    fn cpu_claims_carry_compat_objects() {
        let j = json!({
            "cvm_platform": {"vendor": "amd", "tee": "sev-snp", "hosting": "bare"},
            "cvm_launch_measurement": {"alg": "sha384", "value": Bytes(vec![1; 48]).encode()},
            "cvm_freshness": {"pattern": "challenge", "mode": "report-data"},
            "cvm_policy": {"debug": false, "migratable": false, "smt": true, "vmpl": 0},
            "dbgstat": "disabled-since-boot",
            "cvm_tcb": {"reported": {"bootloader": 1, "tee": 2, "snp": 3, "microcode": 4},
                        "committed": {"bootloader": 1, "tee": 2, "snp": 3, "microcode": 4},
                        "current": {"bootloader": 1, "tee": 2, "snp": 3, "microcode": 4},
                        "launch": {"bootloader": 1, "tee": 2, "snp": 3, "microcode": 4}},
            "cvm_identity": {"chip_id": FixedBytes([9u8; 64]).encode()},
            "snp": {"measurement": "00", "chip_id": "09"}
        });
        let c: CpuClaims = serde_json::from_value(j.clone()).unwrap();
        assert!(matches!(c.cvm_identity, Identity::Snp { .. }));
        assert!(matches!(c.cvm_tcb, Tcb::Snp(_)));
        assert_eq!(c.compat["snp"]["chip_id"], "09");
        assert_eq!(serde_json::to_value(&c).unwrap(), j);
        let claims: AttesterClaims = serde_json::from_value(j).unwrap();
        assert!(matches!(claims, AttesterClaims::Cpu(_)));
        let dev: AttesterClaims =
            serde_json::from_value(json!({"ueid": "x", "measres": "success"})).unwrap();
        assert!(matches!(dev, AttesterClaims::Device(d) if d.claims.len() == 2));
    }
}
