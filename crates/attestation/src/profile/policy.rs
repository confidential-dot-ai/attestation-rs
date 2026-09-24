//! Section 13: the verifier's policy. Every default fails closed.

use super::appraisal::Digest;
use super::bytes::{Bytes, FixedBytes};
use super::evidence::{Backing, GpuArch, KeyBinding};
use super::registers::{HEADER16, SEED};
use crate::error::{AttestationError, Result};
use crate::types::{SnpTcb, TdxTcbStatus};
use schemars::{json_schema, JsonSchema, Schema, SchemaGenerator};
use serde::de::{self, MapAccess, Visitor};
use serde::{Deserialize, Deserializer, Serialize};
use std::collections::BTreeMap;
use std::fmt;
use std::marker::PhantomData;

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
    #[serde(
        default,
        deserialize_with = "super::strict::present",
        skip_serializing_if = "Option::is_none"
    )]
    pub identity: Option<IdentityPolicy>,
    #[serde(
        default,
        deserialize_with = "super::strict::present",
        skip_serializing_if = "Option::is_none"
    )]
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
    #[serde(deserialize_with = "index_map")]
    #[schemars(schema_with = "register_digests_schema")]
    pub registers: BTreeMap<u16, Vec<Digest>>,
    /// Acceptable values per vTPM PCR, for the `vtpm` submodule; a PCR absent
    /// here is not pinned. Azure's initdata convention pins PCR 8 to
    /// `SHA-256(zeros32 || initdata_hash)`.
    #[serde(deserialize_with = "index_map")]
    #[schemars(schema_with = "pcr_digests_schema")]
    pub pcrs: BTreeMap<u16, Vec<Digest>>,
    /// Required `owner` of a workload slot's claim record (section 8.3).
    #[serde(deserialize_with = "index_map")]
    #[schemars(schema_with = "slot_owners_schema")]
    pub slot_owners: BTreeMap<u16, String>,
    /// The value `cvm_host_data` must carry, zero-padded to the platform's
    /// length (32 bytes on SNP, 48 on TDX): the Kata initdata gate.
    #[serde(
        default,
        deserialize_with = "super::strict::present",
        skip_serializing_if = "Option::is_none"
    )]
    #[schemars(extend("minLength" = 2, "maxLength" = 64))]
    pub host_data: Option<Bytes>,
}

/// A register index as decimal text, 0 to 65535 without a sign or a leading
/// zero: the RFC 9741 `.base10` of the CDDL `register-index`.
pub(crate) const REGISTER_INDEX_PATTERN: &str =
    "^(0|[1-9][0-9]{0,3}|[1-5][0-9]{4}|6[0-4][0-9]{3}|65[0-4][0-9]{2}|655[0-2][0-9]|6553[0-5])$";
/// A PCR number 0 to 23 as decimal text (the CDDL `pcr-index`).
const PCR_INDEX_PATTERN: &str = "^([0-9]|1[0-9]|2[0-3])$";

/// A register index in the one text form `.base10` admits.
fn parse_index(key: &str) -> Option<u16> {
    let canonical = key == "0"
        || (!key.is_empty() && !key.starts_with('0') && key.bytes().all(|b| b.is_ascii_digit()));
    canonical.then(|| key.parse().ok()).flatten()
}

/// A map keyed by register index, one key per index: serde_json keeps the
/// last of two equal keys, a second encoding of the map.
fn index_map<'de, D, V>(d: D) -> std::result::Result<BTreeMap<u16, V>, D::Error>
where
    D: Deserializer<'de>,
    V: Deserialize<'de>,
{
    struct IndexMap<V>(PhantomData<V>);
    impl<'de, V: Deserialize<'de>> Visitor<'de> for IndexMap<V> {
        type Value = BTreeMap<u16, V>;
        fn expecting(&self, f: &mut fmt::Formatter) -> fmt::Result {
            f.write_str("an object keyed by register index in decimal")
        }
        fn visit_map<A: MapAccess<'de>>(
            self,
            mut map: A,
        ) -> std::result::Result<Self::Value, A::Error> {
            let mut out = BTreeMap::new();
            while let Some(key) = map.next_key::<String>()? {
                let index = parse_index(&key).ok_or_else(|| {
                    de::Error::custom(format!(
                        "{key:?} is not a register index: decimal 0 to 65535 without a leading zero"
                    ))
                })?;
                if out.insert(index, map.next_value()?).is_some() {
                    return Err(de::Error::custom(format!("index {index} appears twice")));
                }
            }
            Ok(out)
        }
    }
    d.deserialize_map(IndexMap(PhantomData))
}

fn index_map_schema(pattern: &str, value: Schema) -> Schema {
    let mut properties = serde_json::Map::new();
    properties.insert(pattern.to_string(), value.to_value());
    json_schema!({
        "type": "object",
        "patternProperties": properties,
        "additionalProperties": false
    })
}

fn digests_schema(g: &mut SchemaGenerator) -> Schema {
    json_schema!({"type": "array", "items": g.subschema_for::<Digest>(), "minItems": 1})
}

fn register_digests_schema(g: &mut SchemaGenerator) -> Schema {
    index_map_schema(REGISTER_INDEX_PATTERN, digests_schema(g))
}

fn pcr_digests_schema(g: &mut SchemaGenerator) -> Schema {
    index_map_schema(PCR_INDEX_PATTERN, digests_schema(g))
}

fn slot_owners_schema(_: &mut SchemaGenerator) -> Schema {
    // Characters bound UTF-8 bytes from above, so this admits every CDDL owner.
    index_map_schema(
        REGISTER_INDEX_PATTERN,
        json_schema!({"type": "string", "minLength": 1, "maxLength": 255}),
    )
}

#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields, default)]
pub struct FreshnessPolicy {
    /// When set, the evidence must bind exactly this key.
    #[serde(
        default,
        deserialize_with = "super::strict::present",
        skip_serializing_if = "Option::is_none"
    )]
    pub key: Option<KeyBinding>,
}

/// The pinned commitment parameters (section 8.1).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields, default)]
pub struct CommitmentPolicy {
    #[schemars(extend("const" = HEADER16_B64U))]
    pub header16: FixedBytes<16>,
    #[schemars(extend("const" = SEED_B64U))]
    pub seed: FixedBytes<48>,
}

/// [`HEADER16`] and [`SEED`] as the policy writes them; version 1 admits no other value.
const HEADER16_B64U: &str = "QVRTLU1SLTEBARAAAAAAAA";
const SEED_B64U: &str = "YM3K6sPxWpbLKhuF1CxaTRKfztZUNQRMklD9_--YmEzDvUIJcsOvWCleD2G6IeSn";

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
    pub floors: BTreeMap<String, TcbFloor>,
    #[serde(
        default,
        deserialize_with = "super::strict::present",
        skip_serializing_if = "Option::is_none"
    )]
    pub default_floor: Option<String>,
    #[schemars(schema_with = "allowed_status_schema")]
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

/// A TDX status a policy may accept: every status but `Revoked`.
fn allowed_status_schema(_: &mut SchemaGenerator) -> Schema {
    json_schema!({
        "type": "array",
        "items": {
            "type": "string",
            "enum": [
                "UpToDate",
                "SWHardeningNeeded",
                "ConfigurationNeeded",
                "ConfigurationAndSWHardeningNeeded",
                "OutOfDate",
                "OutOfDateConfigurationNeeded"
            ]
        },
        "minItems": 1
    })
}

/// A named floor constrains at least one platform (section 13.2).
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields, default)]
#[schemars(extend("minProperties" = 1))]
pub struct TcbFloor {
    #[serde(
        default,
        deserialize_with = "super::strict::present",
        skip_serializing_if = "Option::is_none"
    )]
    pub snp: Option<SnpFloor>,
    #[serde(
        default,
        deserialize_with = "super::strict::present",
        skip_serializing_if = "Option::is_none"
    )]
    pub tdx: Option<TdxFloor>,
}

/// An SEV-SNP floor: `min` bounds each report TCB value named in `values`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct SnpFloor {
    pub min: SnpTcb,
    /// The TCB values held to `min`; all four when omitted.
    #[serde(default = "SnpTcbValue::all")]
    #[schemars(length(min = 1, max = 4))]
    pub values: Vec<SnpTcbValue>,
}

/// The four TCB values an SEV-SNP report carries.
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize, JsonSchema,
)]
#[serde(rename_all = "kebab-case")]
pub enum SnpTcbValue {
    /// The TCB the VCEK that signed the report was derived for.
    Reported,
    /// The TCB of the firmware running when the report was signed.
    Current,
    /// The anti-rollback floor: SNP_COMMIT refuses firmware below it.
    Committed,
    /// The current TCB when the guest was launched or imported.
    Launch,
}

impl SnpTcbValue {
    pub fn all() -> Vec<SnpTcbValue> {
        vec![
            SnpTcbValue::Reported,
            SnpTcbValue::Current,
            SnpTcbValue::Committed,
            SnpTcbValue::Launch,
        ]
    }

    pub fn as_str(self) -> &'static str {
        match self {
            SnpTcbValue::Reported => "reported",
            SnpTcbValue::Current => "current",
            SnpTcbValue::Committed => "committed",
            SnpTcbValue::Launch => "launch",
        }
    }
}

impl VerifyPolicy {
    /// This policy's identifier for `ear_appraisal_policy_ids` (section 12.5):
    /// `ni:///sha-384;<base64url>` (RFC 6920) over the JCS (RFC 8785)
    /// serialization of the effective policy, every member present with its
    /// value or default and null members omitted.
    pub fn id(&self) -> String {
        use base64::Engine;
        use sha2::{Digest as _, Sha384};
        let digest = Sha384::digest(self.canonical_json().as_bytes());
        format!(
            "ni:///sha-384;{}",
            base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(digest)
        )
    }

    /// The JCS serialization the id digests.
    pub fn canonical_json(&self) -> String {
        let value = serde_json::to_value(self).expect("a policy always serializes");
        let mut out = String::new();
        jcs(&value, &mut out);
        out
    }
}

/// RFC 8785 for the values a policy holds: members sorted by UTF-16 code
/// units, no whitespace, integers in decimal, the ECMAScript string escapes.
fn jcs(v: &serde_json::Value, out: &mut String) {
    use serde_json::Value;
    match v {
        Value::Null => out.push_str("null"),
        Value::Bool(b) => out.push_str(if *b { "true" } else { "false" }),
        Value::Number(n) => {
            debug_assert!(n.is_u64() || n.is_i64(), "a policy holds integers only");
            out.push_str(&n.to_string());
        }
        Value::String(s) => jcs_string(s, out),
        Value::Array(items) => {
            out.push('[');
            for (i, item) in items.iter().enumerate() {
                if i > 0 {
                    out.push(',');
                }
                jcs(item, out);
            }
            out.push(']');
        }
        Value::Object(members) => {
            let mut keys: Vec<&String> = members.keys().collect();
            keys.sort_by(|a, b| a.encode_utf16().cmp(b.encode_utf16()));
            out.push('{');
            for (i, key) in keys.into_iter().enumerate() {
                if i > 0 {
                    out.push(',');
                }
                jcs_string(key, out);
                out.push(':');
                jcs(&members[key], out);
            }
            out.push('}');
        }
    }
}

fn jcs_string(s: &str, out: &mut String) {
    out.push('"');
    for c in s.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\u{8}' => out.push_str("\\b"),
            '\u{c}' => out.push_str("\\f"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if u32::from(c) < 0x20 => out.push_str(&format!("\\u{:04x}", u32::from(c))),
            c => out.push(c),
        }
    }
    out.push('"');
}

/// A TDX floor names at least one bound.
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields, default)]
#[schemars(extend("minProperties" = 1))]
pub struct TdxFloor {
    #[serde(
        default,
        deserialize_with = "super::strict::present",
        skip_serializing_if = "Option::is_none"
    )]
    pub min_tee_tcb_svn: Option<FixedBytes<16>>,
    #[serde(
        default,
        deserialize_with = "super::strict::present",
        skip_serializing_if = "Option::is_none"
    )]
    #[schemars(extend("maximum" = u32::MAX))]
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

/// The longest machine identity: a GPU ueid, which the name form bounds at
/// 128 characters; chip ids are 64 bytes, PPIDs 16.
pub const MAX_MACHINE_ID: usize = 128;

/// Machine allowlist (section 13.3). An identity absent from `machines` fails.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct IdentityPolicy {
    #[schemars(length(min = 1))]
    pub machines: Vec<MachineEntry>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct MachineEntry {
    /// The `cvm_identity` value: SNP `chip_id`, TDX `ppid`, CCA `instance_id`,
    /// or a GPU `ueid` as UTF-8. 1 to 128 bytes: 2 to 171 base64url characters.
    #[schemars(extend("minLength" = 2, "maxLength" = 171))]
    pub id: Bytes,
    #[serde(
        default,
        deserialize_with = "super::strict::present",
        skip_serializing_if = "Option::is_none"
    )]
    pub tcb_floor: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct OwnerPolicy {
    /// SNP `id_key_digest` values that make `cvm_owner` trustworthy.
    #[schemars(length(min = 1))]
    pub id_key_digests: Vec<FixedBytes<48>>,
}

/// NVIDIA device policy (section 13.5, `gpu`). Defined without a feature gate so
/// the policy schema is one schema; the `nvidia-gpu` verifier converts it to
/// its own parameter types.
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields, default)]
pub struct GpuPolicy {
    /// Reject envelopes without a device submodule.
    pub required: bool,
    /// Accepted architectures, as NRAS names them (`HOPPER`, `BLACKWELL`, `LS10`).
    #[serde(
        default,
        deserialize_with = "super::strict::present",
        skip_serializing_if = "Option::is_none"
    )]
    #[schemars(extend("minItems" = 1))]
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
            super::strict::from_slice(json).map_err(|e| policy_err(e.to_string()))?;
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
        if self
            .reference
            .host_data
            .as_ref()
            .is_some_and(|h| h.is_empty() || h.len() > 48)
        {
            return Err(policy_err("reference.host_data: 1 to 48 bytes"));
        }
        for (pcr, ds) in &self.reference.pcrs {
            if *pcr > 23 || ds.is_empty() {
                return Err(policy_err(format!(
                    "reference.pcrs[{pcr}]: PCRs are 0 to 23 and need a value"
                )));
            }
            for d in ds {
                d.validate()
                    .map_err(|e| policy_err(format!("reference.pcrs[{pcr}]: {e}")))?;
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
        for (name, f) in &self.tcb.floors {
            if f.snp.is_none() && f.tdx.is_none() {
                return Err(policy_err(format!(
                    "tcb.floors[{name:?}]: constrains nothing"
                )));
            }
            if f.tdx.as_ref().is_some_and(|t| {
                t.min_tee_tcb_svn.is_none() && t.min_tcb_evaluation_data_number.is_none()
            }) {
                return Err(policy_err(format!(
                    "tcb.floors[{name:?}].tdx: constrains nothing"
                )));
            }
            if let Some(snp) = &f.snp {
                let mut values = snp.values.clone();
                values.sort();
                values.dedup();
                if snp.values.is_empty() || values.len() != snp.values.len() {
                    return Err(policy_err(format!(
                        "tcb.floors[{name:?}].snp.values: empty or repeated"
                    )));
                }
            }
        }
        if self.commitment.header16.0 != HEADER16 {
            return Err(policy_err(
                "commitment.header16: v1 pins ATS-MR-1, version 1, alg 1, reg_count 16, flags 0",
            ));
        }
        if self.commitment.seed.0 != SEED {
            return Err(policy_err(
                "commitment.seed: v1 pins SHA-384(\"ats-mr-v1/seed\")",
            ));
        }
        if self.gpu.expected_archs.as_ref().is_some_and(Vec::is_empty) {
            return Err(policy_err("gpu.expected_archs: an empty list admits no device; omit it to accept every architecture"));
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
                if m.id.is_empty() || m.id.len() > MAX_MACHINE_ID {
                    return Err(policy_err(format!(
                        "identity.machines: an id is 1 to {MAX_MACHINE_ID} bytes"
                    )));
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
        // The schema's constants are these values' encodings.
        assert_eq!(FixedBytes(HEADER16).encode(), HEADER16_B64U);
        assert_eq!(FixedBytes(SEED).encode(), SEED_B64U);
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
            "tcb": {"floors": {"genoa-2026-09": {"snp": {"min": {"bootloader": 4, "tee": 0, "snp": 23, "microcode": 209}}}}, "default_floor": "genoa-2026-09"},
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
        let msg = |v: serde_json::Value| {
            VerifyPolicy::from_json(&serde_json::to_vec(&v).unwrap())
                .unwrap_err()
                .to_string()
        };
        assert!(msg(json!({"tcb": {"floors": {"f": {}}}})).contains("constrains nothing"));
        assert!(msg(json!({"gpu": {"expected_archs": []}})).contains("admits no device"));
        assert!(
            msg(json!({"commitment": {"header16": Bytes(vec![0; 16]).encode()}}))
                .contains("header16")
        );
        assert!(msg(json!({"commitment": {"seed": Bytes(vec![0; 48]).encode()}})).contains("seed"));
        let pinned = json!({"commitment": {"header16": FixedBytes(HEADER16).encode(), "seed": FixedBytes(SEED).encode()}});
        VerifyPolicy::from_json(&serde_json::to_vec(&pinned).unwrap()).unwrap();
    }

    #[test]
    fn a_policy_id_names_the_effective_policy() {
        let id = VerifyPolicy::default().id();
        assert!(id.starts_with("ni:///sha-384;"), "{id}");
        // Absent members take their defaults, and member order is immaterial.
        let empty: VerifyPolicy = serde_json::from_str("{}").unwrap();
        assert_eq!(empty.id(), id);
        let spelled: VerifyPolicy = serde_json::from_str(
            r#"{"tcb":{"require_signed_collateral":true,"tdx_allowed_status":["UpToDate"],
                "require_revocation":true},"min_backing":"hardware","reference":{"pcrs":{}}}"#,
        )
        .unwrap();
        assert_eq!(spelled.id(), id);
        // Any change to what is required is a different policy.
        let mut changed = VerifyPolicy::default();
        changed.policy_bits.allow_debug = true;
        assert_ne!(changed.id(), id);
        let mut pinned = VerifyPolicy::default();
        pinned.reference.host_data = Some(Bytes(vec![0; 32]));
        assert_ne!(pinned.id(), id);
    }

    #[test]
    fn canonical_json_is_jcs() {
        let floor = |values| TcbFloor {
            snp: Some(SnpFloor {
                min: SnpTcb {
                    bootloader: 1,
                    tee: 0,
                    snp: 2,
                    microcode: 3,
                    fmc: None,
                },
                values,
            }),
            tdx: None,
        };
        let mut p = VerifyPolicy::default();
        p.tcb
            .floors
            .insert("b\"\n\u{1}\u{e9}".into(), floor(vec![SnpTcbValue::Launch]));
        p.tcb.floors.insert("a".into(), floor(SnpTcbValue::all()));
        let j = p.canonical_json();
        // `"` and control characters escape; non-ASCII stays literal.
        assert!(j.contains("\"b\\\"\\n\\u0001\u{e9}\""), "{j}");
        assert!(j.find("\"a\":").unwrap() < j.find("\"b").unwrap(), "{j}");
        assert!(!j.contains(": ") && !j.contains(", "), "{j}");
        let back: serde_json::Value = serde_json::from_str(&j).unwrap();
        assert_eq!(back, serde_json::to_value(&p).unwrap());
    }

    #[test]
    fn snp_floor_values_default_to_all_four_and_are_distinct() {
        let p: VerifyPolicy = serde_json::from_str(
            r#"{"tcb":{"floors":{"f":{"snp":{"min":{"bootloader":1,"tee":0,"snp":1,"microcode":1}}}}}}"#,
        )
        .unwrap();
        assert_eq!(
            p.tcb.floors["f"].snp.as_ref().unwrap().values,
            SnpTcbValue::all()
        );
        p.validate().unwrap();
        for values in [r#"[]"#, r#"["reported","reported"]"#] {
            let json = format!(
                r#"{{"tcb":{{"floors":{{"f":{{"snp":{{"min":{{"bootloader":1,"tee":0,"snp":1,"microcode":1}},"values":{values}}}}}}}}}}}"#
            );
            let p: VerifyPolicy = serde_json::from_str(&json).unwrap();
            assert!(p.validate().is_err(), "{values}");
        }
    }

    #[test]
    fn a_floor_with_an_empty_tdx_object_constrains_nothing() {
        let msg = |v: serde_json::Value| {
            VerifyPolicy::from_json(&serde_json::to_vec(&v).unwrap())
                .unwrap_err()
                .to_string()
        };
        let err = msg(json!({"tcb": {"floors": {"f": {"tdx": {}}}}}));
        assert!(err.contains("tdx: constrains nothing"), "{err}");
        let snp = json!({"min": {"bootloader": 1, "tee": 0, "snp": 1, "microcode": 1}});
        let err = msg(json!({"tcb": {"floors": {"f": {"snp": snp, "tdx": {}}}}}));
        assert!(err.contains("tdx: constrains nothing"), "{err}");
        let ok = json!({"tcb": {"floors": {"f": {"tdx": {"min_tcb_evaluation_data_number": 1}}}}});
        VerifyPolicy::from_json(&serde_json::to_vec(&ok).unwrap()).unwrap();
    }

    #[test]
    fn register_indexes_have_one_text_form() {
        let pin = json!([{"alg": "sha384", "value": FixedBytes([0u8; 48]).encode()}]);
        let parse = |key: &str| {
            let text = format!(r#"{{"reference":{{"registers":{{"{key}":{pin}}}}}}}"#);
            VerifyPolicy::from_json(text.as_bytes())
        };
        for key in ["0", "7", "65535"] {
            let p = parse(key).unwrap_or_else(|e| panic!("{key}: {e}"));
            assert_eq!(p.reference.registers.len(), 1);
        }
        for key in ["01", "00", "-0", "+1", " 1", "1.0", "1e0", "65536", ""] {
            let err = parse(key).expect_err(key).to_string();
            assert!(err.contains("not a register index"), "{key}: {err}");
        }
        let twice = format!(r#"{{"reference":{{"pcrs":{{"8":{pin},"8":{pin}}}}}}}"#);
        let err = VerifyPolicy::from_json(twice.as_bytes()).unwrap_err();
        assert!(err.to_string().contains("appears twice"), "{err}");
        // What serde_json alone admits, and this parser refuses.
        use std::collections::BTreeMap;
        assert!(serde_json::from_str::<BTreeMap<u16, u8>>(r#"{"1":1,"1":2}"#).is_ok());
    }
}
