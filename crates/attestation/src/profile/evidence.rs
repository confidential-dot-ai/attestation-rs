//! Section 4: the evidence envelope and its submodules.
//!
//! `Evidence::from_json` is the only entry point a verifier should use: it
//! bounds the input, dispatches each submodule by its name form (section 4.3),
//! and runs every structural rule of section 4 before returning.

use super::bytes::{Bytes, FixedBytes};
use super::cmw::{CmwCollection, CmwEntry, CmwRecord};
use super::registers::REG_COUNT;
use super::{
    invalid, CMW_IND_ENDORSEMENTS, CMW_IND_EVIDENCE, CMW_IND_REFERENCE_VALUES, CVM_VERSION,
    ENDORSEMENTS_COLLECTION_TAG, MAX_REGISTERS, MEDIA_TYPE_JWK_SET, MEDIA_TYPE_PCS_SIGNED,
    MEDIA_TYPE_PKIX_CERT, MEDIA_TYPE_PKIX_CRL, MEDIA_TYPE_SNP_REPORT, MEDIA_TYPE_TDX_QUOTE,
    MEDIA_TYPE_TSM_REPORT, NONCE_MAX, NONCE_MIN, PROFILE_URI,
};
use crate::error::{AttestationError, Result};
use crate::utils::MAX_EVIDENCE_FIELD_SIZE;
use schemars::{json_schema, JsonSchema, Schema, SchemaGenerator};
use serde::de::value::{MapAccessDeserializer, SeqAccessDeserializer};
use serde::de::{self, DeserializeSeed, IntoDeserializer, MapAccess, SeqAccess, Visitor};
use serde::ser::SerializeSeq;
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use std::borrow::Cow;
use std::collections::{BTreeMap, BTreeSet};
use std::fmt;

/// Upper bound on submodules in one envelope: one CPU, one vTPM, and devices.
pub const MAX_SUBMODS: usize = 66;
/// A device `<ueid>` is printable ASCII without `/`, at most this long.
pub const MAX_UEID_LEN: usize = 128;

/// The reserved submodule name forms (section 4.3).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SubmodName {
    Cpu,
    Vtpm,
    Gpu(String),
    NvSwitch(String),
}

impl SubmodName {
    pub fn parse(name: &str) -> Result<Self> {
        if name == "cpu" {
            return Ok(SubmodName::Cpu);
        }
        if name == "vtpm" {
            return Ok(SubmodName::Vtpm);
        }
        for (prefix, ctor) in [
            ("gpu/", SubmodName::Gpu as fn(String) -> SubmodName),
            (
                "nvswitch/",
                SubmodName::NvSwitch as fn(String) -> SubmodName,
            ),
        ] {
            if let Some(ueid) = name.strip_prefix(prefix) {
                let ok = !ueid.is_empty()
                    && ueid.len() <= MAX_UEID_LEN
                    && ueid.bytes().all(|b| b.is_ascii_graphic() && b != b'/');
                if !ok {
                    return Err(invalid(format!(
                        "submodule {name:?}: malformed device ueid"
                    )));
                }
                return Ok(ctor(ueid.to_string()));
            }
        }
        Err(invalid(format!(
            "submodule {name:?}: not a reserved name form"
        )))
    }
}

/// The envelope (section 4.3). Unknown top-level claims are ignored, as EAT
/// extensibility requires; everything the profile defines is checked.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, JsonSchema)]
pub struct Evidence {
    /// Always [`PROFILE_URI`].
    pub eat_profile: String,
    /// The relying party's challenge, 16 to 64 bytes.
    pub eat_nonce: Bytes,
    /// Always [`CVM_VERSION`].
    pub cvm_version: u32,
    /// Keyed by the reserved name forms; see [`SubmodName`].
    #[schemars(schema_with = "submods_schema")]
    pub submods: BTreeMap<String, Submod>,
}

/// The schema says which shape each name form carries, as the parser does.
fn submods_schema(g: &mut SchemaGenerator) -> Schema {
    let cpu = g.subschema_for::<CpuEvidence>();
    let token = g.subschema_for::<NestedToken>();
    let vtpm = g.subschema_for::<VtpmEvidence>();
    let device = g.subschema_for::<GpuDeviceEvidence>();
    json_schema!({
        "type": "object",
        "description": "one entry per attester, keyed by the reserved name forms of section 4.3",
        "properties": {
            "cpu": { "anyOf": [cpu, token] },
            "vtpm": vtpm
        },
        "patternProperties": { "^(gpu|nvswitch)/[!-.0-~]{1,128}$": device },
        "additionalProperties": false,
        "required": ["cpu"],
        "maxProperties": MAX_SUBMODS
    })
}

impl<'de> Deserialize<'de> for Evidence {
    fn deserialize<D: Deserializer<'de>>(d: D) -> std::result::Result<Self, D::Error> {
        struct V;
        impl<'de> Visitor<'de> for V {
            type Value = Evidence;
            fn expecting(&self, f: &mut fmt::Formatter) -> fmt::Result {
                f.write_str("an evidence envelope object")
            }
            fn visit_map<A: MapAccess<'de>>(
                self,
                mut map: A,
            ) -> std::result::Result<Evidence, A::Error> {
                let mut eat_profile: Option<String> = None;
                let mut eat_nonce: Option<Bytes> = None;
                let mut cvm_version: Option<u32> = None;
                let mut submods: Option<BTreeMap<String, Submod>> = None;
                let mut seen = BTreeSet::new();
                fn dup<E: de::Error>(field: &'static str) -> E {
                    E::duplicate_field(field)
                }
                while let Some(key) = map.next_key::<String>()? {
                    if !seen.insert(key.clone()) {
                        return Err(de::Error::custom(format!(
                            "envelope: duplicate member {key:?}"
                        )));
                    }
                    match key.as_str() {
                        "eat_profile" => {
                            if eat_profile.is_some() {
                                return Err(dup("eat_profile"));
                            }
                            eat_profile = Some(map.next_value()?);
                        }
                        "eat_nonce" => {
                            if eat_nonce.is_some() {
                                return Err(dup("eat_nonce"));
                            }
                            eat_nonce = Some(map.next_value()?);
                        }
                        "cvm_version" => {
                            if cvm_version.is_some() {
                                return Err(dup("cvm_version"));
                            }
                            cvm_version = Some(map.next_value()?);
                        }
                        "submods" => {
                            if submods.is_some() {
                                return Err(dup("submods"));
                            }
                            submods = Some(map.next_value_seed(SubmodsSeed)?);
                        }
                        // Unknown top-level claims are ignored, as EAT extensibility requires.
                        _ => {
                            map.next_value::<de::IgnoredAny>()?;
                        }
                    }
                }
                Ok(Evidence {
                    eat_profile: eat_profile
                        .ok_or_else(|| de::Error::missing_field("eat_profile"))?,
                    eat_nonce: eat_nonce.ok_or_else(|| de::Error::missing_field("eat_nonce"))?,
                    cvm_version: cvm_version
                        .ok_or_else(|| de::Error::missing_field("cvm_version"))?,
                    submods: submods.ok_or_else(|| de::Error::missing_field("submods"))?,
                })
            }
        }
        d.deserialize_map(V)
    }
}

/// A map adapter that rejects a member name it has already seen, so a claims
/// set cannot carry two values under one name even when the name is one the
/// profile ignores. Nested `cvm_*` objects reject duplicates on their own
/// (`deny_unknown_fields` plus serde's duplicate-field check).
struct DupCheckMap<A> {
    inner: A,
    seen: BTreeSet<String>,
    what: &'static str,
}

impl<A> DupCheckMap<A> {
    fn new(inner: A, what: &'static str) -> Self {
        DupCheckMap {
            inner,
            seen: BTreeSet::new(),
            what,
        }
    }
}

impl<'de, A: MapAccess<'de>> MapAccess<'de> for DupCheckMap<A> {
    type Error = A::Error;
    fn next_key_seed<K: DeserializeSeed<'de>>(
        &mut self,
        seed: K,
    ) -> std::result::Result<Option<K::Value>, A::Error> {
        let Some(key) = self.inner.next_key::<String>()? else {
            return Ok(None);
        };
        if !self.seen.insert(key.clone()) {
            return Err(de::Error::custom(format!(
                "{}: duplicate member {key:?}",
                self.what
            )));
        }
        seed.deserialize(IntoDeserializer::<A::Error>::into_deserializer(key))
            .map(Some)
    }
    fn next_value_seed<V: DeserializeSeed<'de>>(
        &mut self,
        seed: V,
    ) -> std::result::Result<V::Value, A::Error> {
        self.inner.next_value_seed(seed)
    }
    fn size_hint(&self) -> Option<usize> {
        self.inner.size_hint()
    }
}

/// Deserializes a claims-set struct through [`DupCheckMap`].
struct StrictStructVisitor<T> {
    what: &'static str,
    marker: std::marker::PhantomData<T>,
}

impl<T> StrictStructVisitor<T> {
    fn new(what: &'static str) -> Self {
        StrictStructVisitor {
            what,
            marker: std::marker::PhantomData,
        }
    }
}

impl<'de, T: Deserialize<'de>> Visitor<'de> for StrictStructVisitor<T> {
    type Value = T;
    fn expecting(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "a {} claims set", self.what)
    }
    fn visit_map<A: MapAccess<'de>>(self, map: A) -> std::result::Result<T, A::Error> {
        T::deserialize(MapAccessDeserializer::new(DupCheckMap::new(map, self.what)))
    }
}

/// The `submods` map: each value is parsed straight from the stream into the
/// type its name form selects, so a duplicate name or an over-long map is an
/// error before any further bytes are read.
struct SubmodsSeed;

impl<'de> DeserializeSeed<'de> for SubmodsSeed {
    type Value = BTreeMap<String, Submod>;
    fn deserialize<D: Deserializer<'de>>(self, d: D) -> std::result::Result<Self::Value, D::Error> {
        struct V;
        impl<'de> Visitor<'de> for V {
            type Value = BTreeMap<String, Submod>;
            fn expecting(&self, f: &mut fmt::Formatter) -> fmt::Result {
                f.write_str("a submods object keyed by reserved name forms")
            }
            fn visit_map<A: MapAccess<'de>>(
                self,
                mut map: A,
            ) -> std::result::Result<Self::Value, A::Error> {
                let mut out = BTreeMap::new();
                while let Some(name) = map.next_key::<String>()? {
                    if out.len() >= MAX_SUBMODS {
                        return Err(de::Error::custom(format!(
                            "submods: more than {MAX_SUBMODS} submodules"
                        )));
                    }
                    let kind = SubmodName::parse(&name).map_err(de::Error::custom)?;
                    let value = map
                        .next_value_seed(SubmodSeed { kind })
                        .map_err(|e| de::Error::custom(format!("submodule {name:?}: {e}")))?;
                    if out.insert(name.clone(), value).is_some() {
                        return Err(de::Error::custom(format!(
                            "submods: duplicate submodule {name:?}"
                        )));
                    }
                }
                Ok(out)
            }
        }
        d.deserialize_map(V)
    }
}

struct SubmodSeed {
    kind: SubmodName,
}

impl<'de> DeserializeSeed<'de> for SubmodSeed {
    type Value = Submod;
    fn deserialize<D: Deserializer<'de>>(self, d: D) -> std::result::Result<Submod, D::Error> {
        match self.kind {
            SubmodName::Cpu => d.deserialize_any(CpuOrTokenVisitor),
            SubmodName::Vtpm => d
                .deserialize_map(StrictStructVisitor::<VtpmEvidence>::new("vtpm"))
                .map(Submod::Vtpm),
            SubmodName::Gpu(_) | SubmodName::NvSwitch(_) => d
                .deserialize_map(StrictStructVisitor::<GpuDeviceEvidence>::new("device"))
                .map(Submod::Device),
        }
    }
}

/// `cpu` is a claims set (object) or, for Arm CCA, a nested token (array).
struct CpuOrTokenVisitor;

impl<'de> Visitor<'de> for CpuOrTokenVisitor {
    type Value = Submod;
    fn expecting(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.write_str("a cpu claims set or a nested token selector")
    }
    fn visit_seq<A: SeqAccess<'de>>(self, seq: A) -> std::result::Result<Submod, A::Error> {
        NestedToken::deserialize(SeqAccessDeserializer::new(seq)).map(Submod::CcaToken)
    }
    fn visit_map<A: MapAccess<'de>>(self, map: A) -> std::result::Result<Submod, A::Error> {
        CpuEvidence::deserialize(MapAccessDeserializer::new(DupCheckMap::new(map, "cpu")))
            .map(Submod::Cpu)
    }
}

/// One attester's submodule (section 4.4).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, JsonSchema)]
#[serde(untagged)]
pub enum Submod {
    Cpu(CpuEvidence),
    /// Arm CCA: the token as the RMM emits it, nested per RFC 9711 section 4.2.18.3.
    CcaToken(NestedToken),
    Vtpm(VtpmEvidence),
    Device(GpuDeviceEvidence),
}

/// A CBOR token nested in a JSON EAT: the JSON selector `["CBOR", base64url]`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NestedToken {
    pub token: Bytes,
}

const SELECTOR_CBOR: &str = "CBOR";

impl Serialize for NestedToken {
    fn serialize<S: Serializer>(&self, s: S) -> std::result::Result<S::Ok, S::Error> {
        let mut seq = s.serialize_seq(Some(2))?;
        seq.serialize_element(SELECTOR_CBOR)?;
        seq.serialize_element(&self.token)?;
        seq.end()
    }
}

impl<'de> Deserialize<'de> for NestedToken {
    fn deserialize<D: Deserializer<'de>>(d: D) -> std::result::Result<Self, D::Error> {
        struct V;
        impl<'de> Visitor<'de> for V {
            type Value = NestedToken;
            fn expecting(&self, f: &mut fmt::Formatter) -> fmt::Result {
                f.write_str("a nested token selector [\"CBOR\", base64url]")
            }
            fn visit_seq<A: SeqAccess<'de>>(
                self,
                mut seq: A,
            ) -> std::result::Result<NestedToken, A::Error> {
                let kind: String = seq
                    .next_element()?
                    .ok_or_else(|| de::Error::custom("selector: missing type"))?;
                if kind != SELECTOR_CBOR {
                    return Err(de::Error::custom(format!(
                        "selector type {kind:?}: only CBOR nested tokens are accepted"
                    )));
                }
                let token: Bytes = seq
                    .next_element()?
                    .ok_or_else(|| de::Error::custom("selector: missing token"))?;
                if seq.next_element::<de::IgnoredAny>()?.is_some() {
                    return Err(de::Error::custom("selector: more than two items"));
                }
                Ok(NestedToken { token })
            }
        }
        d.deserialize_seq(V)
    }
}

impl JsonSchema for NestedToken {
    fn schema_name() -> Cow<'static, str> {
        "NestedToken".into()
    }
    fn json_schema(g: &mut SchemaGenerator) -> Schema {
        let bytes = g.subschema_for::<Bytes>();
        json_schema!({
            "type": "array",
            "description": "RFC 9711 JSON selector for a nested CBOR token",
            "prefixItems": [ { "const": "CBOR" }, bytes ],
            "minItems": 2,
            "maxItems": 2
        })
    }
}

/// `cpu` submodule claims set (section 4.4). Unknown claims are ignored;
/// unknown fields inside any `cvm_*` object are rejected by the field types.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct CpuEvidence {
    pub cvm_platform: PlatformHint,
    pub cvm_report: CmwRecord,
    pub cvm_binding: Binding,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cvm_endorsements: Option<CmwCollection>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cvm_registers: Option<Vec<Register>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cvm_log: Option<EventLog>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cvm_chain: Option<ChainInfo>,
    /// EAT `bootseed` (key 268): 32 random bytes chosen at boot (section 4.9).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub bootseed: Option<FixedBytes<32>>,
    /// EAT `dbgstat` (key 263), a hint; the verifier derives the real value
    /// and refuses a hint that contradicts the signed report.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub dbgstat: Option<DebugStatus>,
    /// Reserved (section 4.4): carried through, never interpreted in v1.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cvm_provenance: Option<serde_json::Value>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct PlatformHint {
    pub vendor: Vendor,
    pub tee: Tee,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub generation: Option<String>,
    pub hosting: Hosting,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "kebab-case")]
pub enum Vendor {
    Amd,
    Intel,
    Arm,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "kebab-case")]
pub enum Tee {
    SevSnp,
    Tdx,
    Cca,
}

impl Tee {
    pub fn vendor(self) -> Vendor {
        match self {
            Tee::SevSnp => Vendor::Amd,
            Tee::Tdx => Vendor::Intel,
            Tee::Cca => Vendor::Arm,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "kebab-case")]
pub enum Hosting {
    Bare,
    Azure,
    Gcp,
    Dstack,
}

/// `cvm_binding` (section 4.5).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct Binding {
    pub pattern: FreshnessPattern,
    pub mode: BindingMode,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub key: Option<KeyBinding>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "kebab-case")]
pub enum FreshnessPattern {
    Challenge,
    Certificate,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "kebab-case")]
pub enum BindingMode {
    ReportData,
    Commitment,
    VtpmExtradata,
    CcaChallenge,
    NrasNonce,
}

/// `cvm_binding.key`. The `tls-exporter` kind is reserved for v2 and, being
/// absent here, is rejected as unknown.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct KeyBinding {
    pub kind: KeyKind,
    pub value: Bytes,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "kebab-case")]
pub enum KeyKind {
    SpkiSha256,
    X509TbsSha256,
    Raw,
}

impl KeyKind {
    /// The wire string, which is also the `kind` input of the anchor derivation.
    pub fn as_str(self) -> &'static str {
        match self {
            KeyKind::SpkiSha256 => super::binding::KEY_KIND_SPKI_SHA256,
            KeyKind::X509TbsSha256 => super::binding::KEY_KIND_X509_TBS_SHA256,
            KeyKind::Raw => super::binding::KEY_KIND_RAW,
        }
    }
}

impl KeyBinding {
    pub fn validate(&self) -> Result<()> {
        let n = self.value.len();
        let ok = match self.kind {
            KeyKind::SpkiSha256 | KeyKind::X509TbsSha256 => n == 32,
            KeyKind::Raw => n <= 65535,
        };
        if !ok {
            return Err(invalid(format!(
                "cvm_binding.key: {} value has {n} bytes",
                self.kind.as_str()
            )));
        }
        Ok(())
    }
}

/// One register (section 4.7).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct Register {
    pub index: u16,
    pub alg: HashAlg,
    pub value: Bytes,
    pub source: RegisterSource,
    pub backing: Backing,
}

impl Register {
    /// Structural rules of section 4.7. `backing` in evidence is a hint: the
    /// sources with a hardware-signed value are `hardware`, a vTPM is
    /// `privileged-service`, and an SNP register can never claim `hardware`;
    /// the verifier reports what the pinned image establishes, never more.
    pub fn validate(&self) -> Result<()> {
        let (alg_ok, backing_ok, alg_rule, backing_rule) = match self.source {
            RegisterSource::TdxRtmr => (
                self.alg == HashAlg::Sha384,
                self.backing == Backing::Hardware,
                "sha384",
                "hardware",
            ),
            RegisterSource::CcaRem => (
                matches!(self.alg, HashAlg::Sha256 | HashAlg::Sha512),
                self.backing == Backing::Hardware,
                "sha256 or sha512",
                "hardware",
            ),
            RegisterSource::VtpmPcr => (
                true,
                self.backing == Backing::PrivilegedService,
                "the quoted bank",
                "privileged-service",
            ),
            RegisterSource::SnpVmr => (
                self.alg == HashAlg::Sha384,
                self.backing != Backing::Hardware,
                "sha384",
                "below hardware",
            ),
        };
        if !alg_ok {
            return Err(invalid(format!(
                "register {}/{}: alg must be {alg_rule}",
                self.source.as_str(),
                self.index
            )));
        }
        if !backing_ok {
            return Err(invalid(format!(
                "register {}/{}: backing must be {backing_rule}",
                self.source.as_str(),
                self.index
            )));
        }
        if self.value.len() != self.alg.digest_len() {
            return Err(invalid(format!(
                "register {}/{}: value has {} bytes, {} needs {}",
                self.source.as_str(),
                self.index,
                self.value.len(),
                self.alg.as_str(),
                self.alg.digest_len()
            )));
        }
        if self.index > self.source.max_index() {
            return Err(invalid(format!(
                "register {}/{}: index above {}",
                self.source.as_str(),
                self.index,
                self.source.max_index()
            )));
        }
        Ok(())
    }
}

/// TPM 2.0 algorithm names, as CEL uses them.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "lowercase")]
pub enum HashAlg {
    Sha256,
    Sha384,
    Sha512,
}

impl HashAlg {
    pub fn digest_len(self) -> usize {
        match self {
            HashAlg::Sha256 => 32,
            HashAlg::Sha384 => 48,
            HashAlg::Sha512 => 64,
        }
    }
    /// TPM_ALG_ID.
    pub fn tpm_alg_id(self) -> u16 {
        match self {
            HashAlg::Sha256 => 0x000B,
            HashAlg::Sha384 => 0x000C,
            HashAlg::Sha512 => 0x000D,
        }
    }
    pub fn as_str(self) -> &'static str {
        match self {
            HashAlg::Sha256 => "sha256",
            HashAlg::Sha384 => "sha384",
            HashAlg::Sha512 => "sha512",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "kebab-case")]
pub enum RegisterSource {
    TdxRtmr,
    SnpVmr,
    VtpmPcr,
    CcaRem,
}

impl RegisterSource {
    pub fn max_index(self) -> u16 {
        match self {
            RegisterSource::TdxRtmr | RegisterSource::CcaRem => 3,
            RegisterSource::SnpVmr => (REG_COUNT - 1) as u16,
            RegisterSource::VtpmPcr => 23,
        }
    }
    pub fn as_str(self) -> &'static str {
        match self {
            RegisterSource::TdxRtmr => "tdx-rtmr",
            RegisterSource::SnpVmr => "snp-vmr",
            RegisterSource::VtpmPcr => "vtpm-pcr",
            RegisterSource::CcaRem => "cca-rem",
        }
    }
}

/// Who holds a register's value. Ordered weakest first so a policy floor is a
/// plain comparison: `seen >= required`.
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize, JsonSchema,
)]
#[serde(rename_all = "kebab-case")]
pub enum Backing {
    Virtualized,
    KernelService,
    PrivilegedService,
    Hardware,
}

/// `cvm_log` (section 4.8).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct EventLog {
    pub format: LogFormat,
    pub data: Bytes,
}

impl EventLog {
    pub fn validate(&self) -> Result<()> {
        if self.data.is_empty() {
            return Err(invalid("cvm_log: empty"));
        }
        if self.data.len() > MAX_EVIDENCE_FIELD_SIZE {
            return Err(invalid(format!(
                "cvm_log: {} bytes exceeds {MAX_EVIDENCE_FIELD_SIZE}",
                self.data.len()
            )));
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "kebab-case")]
pub enum LogFormat {
    TcgCelCbor,
    TcgCelJson,
    TdxCcel,
    Tpm2EventLog,
    DstackJson,
    Aael,
}

/// EAT `dbgstat` (RFC 9711 section 4.2.9): the text value in JSON, the
/// integer in CBOR.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "kebab-case")]
#[repr(u8)]
pub enum DebugStatus {
    Enabled = 0,
    Disabled = 1,
    DisabledSinceBoot = 2,
    DisabledPermanently = 3,
    DisabledFullyAndPermanently = 4,
}

impl DebugStatus {
    /// The CBOR encoding.
    pub fn cbor(self) -> u8 {
        self as u8
    }

    /// Whether the debug facility is off, whatever the qualifier.
    pub fn is_disabled(self) -> bool {
        self != DebugStatus::Enabled
    }
}

/// `cvm_chain` (section 4.9).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ChainInfo {
    pub chain_len: u64,
}

/// `vtpm` submodule (section 4.4).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct VtpmEvidence {
    pub cvm_tpm_quote: TpmQuote,
    pub cvm_tpm_ak: TpmAkBinding,
    pub cvm_registers: Vec<Register>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cvm_log: Option<EventLog>,
}

/// `cvm_tpm_quote`: TPMS_ATTEST bytes, its signature, the 24 PCRs of the quoted bank.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct TpmQuote {
    pub message: Bytes,
    pub signature: Bytes,
    pub pcrs: Vec<Bytes>,
    pub bank: HashAlg,
}

impl TpmQuote {
    pub fn validate(&self) -> Result<()> {
        if self.message.is_empty() || self.signature.is_empty() {
            return Err(invalid("cvm_tpm_quote: empty message or signature"));
        }
        if self.pcrs.len() != 24 {
            return Err(invalid(format!(
                "cvm_tpm_quote: {} PCRs, expected 24",
                self.pcrs.len()
            )));
        }
        if let Some(bad) = self
            .pcrs
            .iter()
            .position(|p| p.len() != self.bank.digest_len())
        {
            return Err(invalid(format!(
                "cvm_tpm_quote: PCR {bad} is not a {} digest",
                self.bank.as_str()
            )));
        }
        Ok(())
    }
}

/// `cvm_tpm_ak`: how the AK is bound into the CPU report.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct TpmAkBinding {
    pub method: TpmAkMethod,
    /// For `hcl-report`: the Azure HCL report. Its `var_data` carries the AK
    /// public key, `SHA-256(var_data)` is `report_data[0..32]` of the CPU
    /// report, and its report type must name the same TEE.
    pub data: Bytes,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "kebab-case")]
pub enum TpmAkMethod {
    HclReport,
}

/// NVIDIA device architecture as NRAS names it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "UPPERCASE")]
pub enum GpuArch {
    Hopper,
    Blackwell,
    Ls10,
}

#[cfg(feature = "nvidia-gpu")]
impl From<crate::types::NvidiaGpuArch> for GpuArch {
    fn from(a: crate::types::NvidiaGpuArch) -> Self {
        match a {
            crate::types::NvidiaGpuArch::Hopper => GpuArch::Hopper,
            crate::types::NvidiaGpuArch::Blackwell => GpuArch::Blackwell,
            crate::types::NvidiaGpuArch::Ls10 => GpuArch::Ls10,
        }
    }
}

#[cfg(feature = "nvidia-gpu")]
impl From<GpuArch> for crate::types::NvidiaGpuArch {
    fn from(a: GpuArch) -> Self {
        match a {
            GpuArch::Hopper => crate::types::NvidiaGpuArch::Hopper,
            GpuArch::Blackwell => crate::types::NvidiaGpuArch::Blackwell,
            GpuArch::Ls10 => crate::types::NvidiaGpuArch::Ls10,
        }
    }
}

/// `gpu/<ueid>` and `nvswitch/<ueid>` submodules: the NRAS device evidence
/// plus the nonce binding (section 4.4).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct GpuDeviceEvidence {
    pub arch: GpuArch,
    pub uuid: String,
    /// Base64 SPDM blob, as the SDK and NRAS exchange it.
    pub evidence_b64: String,
    /// Base64 PEM certificate chain, leaf first.
    pub cert_chain_b64: String,
    pub cvm_binding: Binding,
}

#[cfg(feature = "nvidia-gpu")]
impl From<&GpuDeviceEvidence> for crate::types::NvidiaGpuDeviceEvidence {
    fn from(d: &GpuDeviceEvidence) -> Self {
        crate::types::NvidiaGpuDeviceEvidence {
            arch: d.arch.into(),
            uuid: d.uuid.clone(),
            evidence_b64: d.evidence_b64.clone(),
            cert_chain_b64: d.cert_chain_b64.clone(),
        }
    }
}

fn check_registers(regs: &[Register], expected_source: RegisterSource, what: &str) -> Result<()> {
    if regs.is_empty() {
        return Err(invalid(format!("{what}: cvm_registers is empty")));
    }
    if regs.len() > MAX_REGISTERS {
        return Err(invalid(format!(
            "{what}: {} registers exceeds {MAX_REGISTERS}",
            regs.len()
        )));
    }
    let mut seen = BTreeSet::new();
    for r in regs {
        r.validate()?;
        if r.source != expected_source {
            return Err(invalid(format!(
                "{what}: register source {} where {} is required",
                r.source.as_str(),
                expected_source.as_str()
            )));
        }
        if !seen.insert(r.index) {
            return Err(invalid(format!(
                "{what}: duplicate register {}/{}",
                r.source.as_str(),
                r.index
            )));
        }
    }
    Ok(())
}

impl CpuEvidence {
    pub fn validate(&self) -> Result<()> {
        let p = &self.cvm_platform;
        if p.tee == Tee::Cca {
            return Err(invalid(
                "cpu: Arm CCA evidence is a nested token, not a claims set",
            ));
        }
        if p.tee.vendor() != p.vendor {
            return Err(invalid("cvm_platform: vendor and tee disagree"));
        }
        if let Some(g) = &p.generation {
            if g.is_empty() || g.len() > 64 {
                return Err(invalid("cvm_platform.generation: empty or too long"));
            }
        }

        let r = &self.cvm_report;
        if r.value.is_empty() {
            return Err(invalid("cvm_report: empty value"));
        }
        if r.value.len() > MAX_EVIDENCE_FIELD_SIZE {
            return Err(invalid("cvm_report: value too large"));
        }
        if r.ind != Some(CMW_IND_EVIDENCE) {
            return Err(invalid(
                "cvm_report: indicator must be exactly 4 (evidence)",
            ));
        }
        let azure = p.hosting == Hosting::Azure;
        // On Azure the report is the SNP report the HCL report wraps, or the
        // TD quote; the HCL report itself rides in the vtpm submodule.
        let report_ok = match r.media_type.as_str() {
            MEDIA_TYPE_SNP_REPORT => p.tee == Tee::SevSnp,
            MEDIA_TYPE_TDX_QUOTE => p.tee == Tee::Tdx,
            MEDIA_TYPE_TSM_REPORT => !azure && p.hosting != Hosting::Dstack,
            _ => {
                return Err(invalid(format!(
                    "cvm_report: unknown media type {:?}",
                    r.media_type
                )))
            }
        };
        if !report_ok {
            return Err(invalid(format!(
                "cvm_report: media type {:?} does not fit tee {:?} on {:?}",
                r.media_type, p.tee, p.hosting
            )));
        }

        let b = &self.cvm_binding;
        match b.mode {
            BindingMode::ReportData if azure => {
                return Err(invalid(
                    "cvm_binding: Azure evidence binds through vtpm-extradata",
                ))
            }
            BindingMode::ReportData => {}
            BindingMode::Commitment if p.tee != Tee::SevSnp || azure => {
                return Err(invalid(
                    "cvm_binding: commitment mode is SEV-SNP with the register driver",
                ))
            }
            BindingMode::Commitment => {}
            BindingMode::VtpmExtradata if !azure => {
                return Err(invalid(
                    "cvm_binding: vtpm-extradata mode needs Azure hosting",
                ))
            }
            BindingMode::VtpmExtradata => {}
            BindingMode::CcaChallenge | BindingMode::NrasNonce => {
                return Err(invalid(format!(
                    "cvm_binding: mode {:?} is not a cpu binding",
                    b.mode
                )))
            }
        }
        match (b.pattern, b.key.as_ref().map(|k| k.kind)) {
            (FreshnessPattern::Certificate, Some(KeyKind::X509TbsSha256)) => {}
            (FreshnessPattern::Certificate, _) => {
                return Err(invalid(
                    "cvm_binding: the certificate pattern binds an x509-tbs-sha256 key",
                ))
            }
            (FreshnessPattern::Challenge, Some(KeyKind::X509TbsSha256)) => {
                return Err(invalid(
                    "cvm_binding: x509-tbs-sha256 belongs to the certificate pattern",
                ))
            }
            (FreshnessPattern::Challenge, _) => {}
        }
        if let Some(k) = &b.key {
            k.validate()?;
        }

        let commitment = b.mode == BindingMode::Commitment;
        if p.tee == Tee::SevSnp && self.cvm_registers.is_some() && !commitment {
            return Err(invalid(
                "cpu: snp-vmr registers bind only through the commitment (section 4.7)",
            ));
        }
        if let Some(regs) = &self.cvm_registers {
            let source = if p.tee == Tee::SevSnp {
                RegisterSource::SnpVmr
            } else {
                RegisterSource::TdxRtmr
            };
            check_registers(regs, source, "cpu")?;
            if commitment {
                let full = regs.len() == REG_COUNT
                    && regs.iter().all(|r| r.alg == HashAlg::Sha384)
                    && (0..REG_COUNT as u16).all(|i| regs.iter().any(|r| r.index == i));
                if !full {
                    return Err(invalid(
                        "cpu: commitment mode carries all 16 snp-vmr registers as sha384",
                    ));
                }
            }
        } else if commitment {
            return Err(invalid("cpu: commitment mode requires cvm_registers"));
        }
        if let Some(log) = &self.cvm_log {
            log.validate()?;
            if self.cvm_registers.is_none() {
                return Err(invalid("cpu: cvm_log requires cvm_registers"));
            }
        }
        match (commitment, &self.cvm_chain, &self.bootseed) {
            (true, Some(c), Some(_)) if c.chain_len == 0 => {
                return Err(invalid(
                    "cvm_chain: chain_len is 0 but the boot record is always extended",
                ))
            }
            (true, Some(_), Some(_)) => {}
            (true, _, _) => {
                return Err(invalid(
                    "cpu: commitment mode requires cvm_chain and bootseed",
                ))
            }
            (false, None, None) => {}
            (false, _, _) => {
                return Err(invalid(
                    "cpu: cvm_chain and bootseed belong to commitment mode",
                ))
            }
        }
        if let Some(e) = &self.cvm_endorsements {
            validate_endorsements(e, p.tee)?;
        }
        Ok(())
    }
}

fn validate_endorsements(c: &CmwCollection, tee: Tee) -> Result<()> {
    if c.collection_type.as_deref() != Some(ENDORSEMENTS_COLLECTION_TAG) {
        return Err(invalid(format!(
            "cvm_endorsements: __cmwc_t must be {ENDORSEMENTS_COLLECTION_TAG}"
        )));
    }
    for (label, entry) in &c.entries {
        let CmwEntry::Record(rec) = entry else {
            return Err(invalid(format!(
                "cvm_endorsements.{label}: nested collections are not accepted"
            )));
        };
        let (expected_type, for_tee) = match label.as_str() {
            "snp.vek" => (MEDIA_TYPE_PKIX_CERT, Some(Tee::SevSnp)),
            "snp.crl" => (MEDIA_TYPE_PKIX_CRL, Some(Tee::SevSnp)),
            "tdx.tcb_info" | "tdx.qe_identity" => (MEDIA_TYPE_PCS_SIGNED, Some(Tee::Tdx)),
            "tdx.pck_crl" | "tdx.root_crl" => (MEDIA_TYPE_PKIX_CRL, Some(Tee::Tdx)),
            "nras.jwks" => (MEDIA_TYPE_JWK_SET, None),
            _ => {
                return Err(invalid(format!(
                    "cvm_endorsements: unknown entry {label:?}"
                )))
            }
        };
        if for_tee.is_some_and(|t| t != tee) {
            return Err(invalid(format!(
                "cvm_endorsements.{label}: does not belong to {tee:?}"
            )));
        }
        if rec.media_type != expected_type {
            return Err(invalid(format!(
                "cvm_endorsements.{label}: type must be {expected_type}"
            )));
        }
        if rec.value.is_empty() || rec.value.len() > MAX_EVIDENCE_FIELD_SIZE {
            return Err(invalid(format!(
                "cvm_endorsements.{label}: empty or too large"
            )));
        }
        if !(rec.ind == Some(CMW_IND_ENDORSEMENTS) || rec.ind == Some(CMW_IND_REFERENCE_VALUES)) {
            return Err(invalid(format!(
                "cvm_endorsements.{label}: indicator must be exactly 2 (endorsements) or 1 (reference values)"
            )));
        }
    }
    Ok(())
}

impl VtpmEvidence {
    pub fn validate(&self) -> Result<()> {
        self.cvm_tpm_quote.validate()?;
        if self.cvm_tpm_ak.data.is_empty() || self.cvm_tpm_ak.data.len() > MAX_EVIDENCE_FIELD_SIZE {
            return Err(invalid("cvm_tpm_ak: empty or too large"));
        }
        check_registers(&self.cvm_registers, RegisterSource::VtpmPcr, "vtpm")?;
        if self.cvm_registers.len() > 24 {
            return Err(invalid("vtpm: more than 24 PCR registers"));
        }
        let bank = self.cvm_tpm_quote.bank;
        for r in &self.cvm_registers {
            if r.alg != bank {
                return Err(invalid(format!(
                    "vtpm: register {} is not in the quoted {} bank",
                    r.index,
                    bank.as_str()
                )));
            }
            let quoted = &self.cvm_tpm_quote.pcrs[usize::from(r.index)];
            if quoted != &r.value {
                return Err(invalid(format!(
                    "vtpm: register {} differs from the quoted PCR",
                    r.index
                )));
            }
        }
        if let Some(log) = &self.cvm_log {
            log.validate()?;
        }
        Ok(())
    }
}

impl NestedToken {
    pub fn validate(&self) -> Result<()> {
        if self.token.is_empty() {
            return Err(invalid("cpu: empty nested token"));
        }
        if self.token.len() > MAX_EVIDENCE_FIELD_SIZE {
            return Err(invalid("cpu: nested token too large"));
        }
        Ok(())
    }
}

impl GpuDeviceEvidence {
    pub fn validate(&self, name: &SubmodName) -> Result<()> {
        let (ueid, is_switch) = match name {
            SubmodName::Gpu(u) => (u, false),
            SubmodName::NvSwitch(u) => (u, true),
            _ => return Err(invalid("device evidence under a non-device name")),
        };
        if &self.uuid != ueid {
            return Err(invalid(format!(
                "device {ueid}: uuid {:?} differs from the submodule name",
                self.uuid
            )));
        }
        if (self.arch == GpuArch::Ls10) != is_switch {
            return Err(invalid(format!(
                "device {ueid}: arch {:?} under the wrong name form",
                self.arch
            )));
        }
        if self.evidence_b64.is_empty() || self.cert_chain_b64.is_empty() {
            return Err(invalid(format!(
                "device {ueid}: empty evidence or certificate chain"
            )));
        }
        if self.evidence_b64.len() > MAX_EVIDENCE_FIELD_SIZE
            || self.cert_chain_b64.len() > MAX_EVIDENCE_FIELD_SIZE
        {
            return Err(invalid(format!(
                "device {ueid}: evidence or certificate chain too large"
            )));
        }
        let b = &self.cvm_binding;
        if b.mode != BindingMode::NrasNonce
            || b.pattern != FreshnessPattern::Challenge
            || b.key.is_some()
        {
            return Err(invalid(format!("device {ueid}: binding must be the challenge pattern in nras-nonce mode with no key")));
        }
        Ok(())
    }
}

impl Evidence {
    /// Parse and validate an envelope. Bounds the input first.
    pub fn from_json(json: &[u8]) -> Result<Self> {
        if json.len() > crate::MAX_EVIDENCE_SIZE {
            return Err(AttestationError::EvidenceTooLarge {
                size: json.len(),
                max: crate::MAX_EVIDENCE_SIZE,
            });
        }
        let e: Evidence =
            serde_json::from_slice(json).map_err(|e| invalid(format!("envelope: {e}")))?;
        e.validate()?;
        Ok(e)
    }

    pub fn to_json(&self) -> Result<Vec<u8>> {
        serde_json::to_vec(self).map_err(|e| invalid(format!("envelope: {e}")))
    }

    /// Every structural rule of section 4 that does not need the report parsed.
    pub fn validate(&self) -> Result<()> {
        if self.eat_profile != PROFILE_URI {
            return Err(invalid(format!(
                "eat_profile {:?} is not {PROFILE_URI}",
                self.eat_profile
            )));
        }
        if self.cvm_version != CVM_VERSION {
            return Err(invalid(format!(
                "cvm_version {} is not {CVM_VERSION}",
                self.cvm_version
            )));
        }
        let n = self.eat_nonce.len();
        if !(NONCE_MIN..=NONCE_MAX).contains(&n) {
            return Err(invalid(format!(
                "eat_nonce: {n} bytes, must be {NONCE_MIN} to {NONCE_MAX}"
            )));
        }
        if self.submods.len() > MAX_SUBMODS {
            return Err(invalid(format!(
                "submods: {} exceeds {MAX_SUBMODS}",
                self.submods.len()
            )));
        }
        let mut cpu_mode = None;
        let mut have_vtpm = false;
        for (name, submod) in &self.submods {
            let kind = SubmodName::parse(name)?;
            match (&kind, submod) {
                (SubmodName::Cpu, Submod::Cpu(c)) => {
                    c.validate()?;
                    cpu_mode = Some(c.cvm_binding.mode);
                }
                (SubmodName::Cpu, Submod::CcaToken(t)) => {
                    t.validate()?;
                    cpu_mode = Some(BindingMode::CcaChallenge);
                }
                (SubmodName::Vtpm, Submod::Vtpm(v)) => {
                    v.validate()?;
                    have_vtpm = true;
                }
                (SubmodName::Gpu(_) | SubmodName::NvSwitch(_), Submod::Device(d)) => {
                    d.validate(&kind)?
                }
                _ => {
                    return Err(invalid(format!(
                        "submodule {name:?}: value does not match its name form"
                    )))
                }
            }
        }
        let Some(mode) = cpu_mode else {
            return Err(invalid("submods: no cpu submodule"));
        };
        if mode == BindingMode::VtpmExtradata && !have_vtpm {
            return Err(invalid(
                "cpu binds through vtpm-extradata but there is no vtpm submodule",
            ));
        }
        Ok(())
    }

    pub fn cpu(&self) -> Option<&Submod> {
        self.submods.get("cpu")
    }

    pub fn vtpm(&self) -> Option<&VtpmEvidence> {
        match self.submods.get("vtpm") {
            Some(Submod::Vtpm(v)) => Some(v),
            _ => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::{json, Value};

    fn b64(bytes: &[u8]) -> String {
        Bytes(bytes.to_vec()).encode()
    }

    fn snp_envelope() -> Value {
        json!({
            "eat_profile": PROFILE_URI,
            "eat_nonce": b64(&[7u8; 32]),
            "cvm_version": 1,
            "submods": {
                "cpu": {
                    "cvm_platform": {"vendor": "amd", "tee": "sev-snp", "hosting": "bare", "generation": "Genoa"},
                    "cvm_report": [MEDIA_TYPE_SNP_REPORT, b64(&[1u8; 1184]), 4],
                    "cvm_binding": {"pattern": "challenge", "mode": "report-data",
                                    "key": {"kind": "spki-sha256", "value": b64(&[0x11; 32])}}
                }
            }
        })
    }

    fn tdx_envelope() -> Value {
        json!({
            "eat_profile": PROFILE_URI,
            "eat_nonce": b64(&[7u8; 16]),
            "cvm_version": 1,
            "submods": {
                "cpu": {
                    "cvm_platform": {"vendor": "intel", "tee": "tdx", "hosting": "bare"},
                    "cvm_report": [MEDIA_TYPE_TDX_QUOTE, b64(&[2u8; 5000]), 4],
                    "cvm_binding": {"pattern": "challenge", "mode": "report-data"}
                }
            }
        })
    }

    fn tdx_registers() -> Value {
        Value::Array((0..4).map(|i| json!({
            "index": i, "alg": "sha384", "value": b64(&[i as u8; 48]), "source": "tdx-rtmr", "backing": "hardware"
        })).collect())
    }

    fn snp_registers() -> Value {
        Value::Array((0..16).map(|i| json!({
            "index": i, "alg": "sha384", "value": b64(&[i as u8; 48]), "source": "snp-vmr", "backing": "kernel-service"
        })).collect())
    }

    fn parse(v: &Value) -> Result<Evidence> {
        Evidence::from_json(&serde_json::to_vec(v).unwrap())
    }

    fn err(v: &Value) -> String {
        match parse(v) {
            Err(e) => e.to_string(),
            Ok(_) => panic!("expected an error"),
        }
    }

    #[test]
    fn snp_round_trip_and_unknown_claims_ignored() {
        let mut v = snp_envelope();
        v["unknown_top_level"] = json!(1);
        v["submods"]["cpu"]["vendor_extension"] = json!({"x": 1});
        let e = parse(&v).unwrap();
        assert_eq!(e.eat_profile, PROFILE_URI);
        assert!(matches!(e.cpu(), Some(Submod::Cpu(_))));
        let again = Evidence::from_json(&e.to_json().unwrap()).unwrap();
        assert_eq!(again, e);
    }

    #[test]
    fn unknown_field_inside_cvm_object_rejected() {
        let mut v = snp_envelope();
        v["submods"]["cpu"]["cvm_binding"]["extra"] = json!(true);
        assert!(err(&v).contains("extra"));
        let mut v = snp_envelope();
        v["submods"]["cpu"]["cvm_binding"]["key"]["kind"] = json!("tls-exporter");
        assert!(err(&v).contains("tls-exporter"));
    }

    #[test]
    fn profile_version_nonce_checks() {
        let mut v = snp_envelope();
        v["eat_profile"] = json!("tag:confidential.ai,2026:cvm#2");
        assert!(err(&v).contains("eat_profile"));
        let mut v = snp_envelope();
        v["cvm_version"] = json!(2);
        assert!(err(&v).contains("cvm_version"));
        let mut v = snp_envelope();
        v["eat_nonce"] = json!(b64(&[1u8; 15]));
        assert!(err(&v).contains("eat_nonce"));
        let mut v = snp_envelope();
        v["eat_nonce"] = json!(format!("{}=", b64(&[1u8; 16])));
        assert!(err(&v).contains("base64url"));
        let mut v = snp_envelope();
        v.as_object_mut().unwrap().remove("submods");
        assert!(err(&v).contains("missing field `submods`"));
    }

    #[test]
    fn duplicate_members_rejected() {
        let cpu = serde_json::to_string(&snp_envelope()["submods"]["cpu"]).unwrap();
        let nonce = b64(&[7u8; 16]);
        let dup_submod = format!(
            r#"{{"eat_profile":"{PROFILE_URI}","eat_nonce":"{nonce}","cvm_version":1,"submods":{{"cpu":{cpu},"cpu":["CBOR","AQ"]}}}}"#
        );
        let e = Evidence::from_json(dup_submod.as_bytes())
            .unwrap_err()
            .to_string();
        assert!(e.contains("duplicate submodule"), "{e}");
        let dup_top = format!(
            r#"{{"eat_profile":"{PROFILE_URI}","eat_nonce":"{nonce}","eat_nonce":"{nonce}","cvm_version":1,"submods":{{"cpu":{cpu}}}}}"#
        );
        let e = Evidence::from_json(dup_top.as_bytes())
            .unwrap_err()
            .to_string();
        assert!(e.contains("duplicate member \"eat_nonce\""), "{e}");
        let dup_inner = format!(
            r#"{{"eat_profile":"{PROFILE_URI}","eat_nonce":"{nonce}","cvm_version":1,"submods":{{"cpu":{}}}}}"#,
            cpu.replacen(
                "\"cvm_binding\"",
                "\"cvm_version\":1,\"cvm_version\":2,\"cvm_binding\"",
                1
            )
        );
        let e = Evidence::from_json(dup_inner.as_bytes())
            .unwrap_err()
            .to_string();
        assert!(e.contains("duplicate member \"cvm_version\""), "{e}");
        let dup_nested = format!(
            r#"{{"eat_profile":"{PROFILE_URI}","eat_nonce":"{nonce}","cvm_version":1,"submods":{{"cpu":{}}}}}"#,
            cpu.replacen("\"pattern\"", "\"mode\":\"report-data\",\"pattern\"", 1)
        );
        let e = Evidence::from_json(dup_nested.as_bytes())
            .unwrap_err()
            .to_string();
        assert!(e.contains("duplicate field `mode`"), "{e}");
        let dup_unknown_top = format!(
            r#"{{"x":1,"x":2,"eat_profile":"{PROFILE_URI}","eat_nonce":"{nonce}","cvm_version":1,"submods":{{"cpu":{cpu}}}}}"#
        );
        let e = Evidence::from_json(dup_unknown_top.as_bytes())
            .unwrap_err()
            .to_string();
        assert!(e.contains("duplicate member \"x\""), "{e}");
    }

    #[test]
    fn submodule_names_and_shapes() {
        let mut v = snp_envelope();
        v["submods"]["gpu"] = json!({});
        assert!(err(&v).contains("not a reserved name form"));
        let mut v = snp_envelope();
        v["submods"].as_object_mut().unwrap().remove("cpu");
        assert!(err(&v).contains("no cpu submodule"));
        let mut v = snp_envelope();
        v["submods"]["cpu"] = json!(["JWT", "abc"]);
        assert!(err(&v).contains("only CBOR"));
        let mut v = snp_envelope();
        v["submods"]["cpu"] = json!("string");
        assert!(err(&v).contains("cpu claims set or a nested token"));
        assert!(SubmodName::parse("gpu/GPU-1234").is_ok());
        assert!(SubmodName::parse("nvswitch/abc").is_ok());
        assert!(SubmodName::parse("gpu/").is_err());
        assert!(SubmodName::parse("gpu/a/b").is_err());
        assert!(SubmodName::parse("cpu2").is_err());
    }

    #[test]
    fn submodule_count_capped_while_streaming() {
        let cpu = serde_json::to_string(&snp_envelope()["submods"]["cpu"]).unwrap();
        let mut submods = format!(r#""cpu":{cpu}"#);
        for i in 0..MAX_SUBMODS {
            submods.push_str(&format!(r#","gpu/GPU-{i}":{{"arch":"HOPPER","uuid":"GPU-{i}","evidence_b64":"AA","cert_chain_b64":"AA","cvm_binding":{{"pattern":"challenge","mode":"nras-nonce"}}}}"#));
        }
        let nonce = b64(&[7u8; 16]);
        let doc = format!(
            r#"{{"eat_profile":"{PROFILE_URI}","eat_nonce":"{nonce}","cvm_version":1,"submods":{{{submods}}}}}"#
        );
        let e = Evidence::from_json(doc.as_bytes()).unwrap_err().to_string();
        assert!(e.contains("more than"), "{e}");
    }

    #[test]
    fn cca_nested_token() {
        let mut v = snp_envelope();
        v["submods"]["cpu"] = json!(["CBOR", b64(&[0xd9, 0x03, 0x8b, 0xa2])]);
        let e = parse(&v).unwrap();
        assert!(matches!(e.cpu(), Some(Submod::CcaToken(t)) if t.token.len() == 4));
        assert_eq!(
            serde_json::to_value(&e).unwrap()["submods"]["cpu"],
            v["submods"]["cpu"]
        );
    }

    #[test]
    fn report_record_rules() {
        let mut v = snp_envelope();
        v["submods"]["cpu"]["cvm_report"][0] = json!(MEDIA_TYPE_TDX_QUOTE);
        assert!(err(&v).contains("does not fit"));
        let mut v = snp_envelope();
        v["submods"]["cpu"]["cvm_report"][0] = json!("application/octet-stream");
        assert!(err(&v).contains("unknown media type"));
        let mut v = snp_envelope();
        v["submods"]["cpu"]["cvm_report"][2] = json!(2);
        assert!(err(&v).contains("exactly 4"));
        let mut v = snp_envelope();
        v["submods"]["cpu"]["cvm_report"]
            .as_array_mut()
            .unwrap()
            .pop();
        assert!(err(&v).contains("exactly 4"));
        let mut v = snp_envelope();
        v["submods"]["cpu"]["cvm_report"][2] = json!(4294967295u32);
        assert!(err(&v).contains("indicator above 15"));
        let mut v = snp_envelope();
        v["submods"]["cpu"]["cvm_platform"]["vendor"] = json!("intel");
        assert!(err(&v).contains("disagree"));
    }

    #[test]
    fn binding_pattern_rules() {
        let mut v = snp_envelope();
        v["submods"]["cpu"]["cvm_binding"]["pattern"] = json!("certificate");
        assert!(err(&v).contains("x509-tbs-sha256"));
        v["submods"]["cpu"]["cvm_binding"]["key"] =
            json!({"kind": "x509-tbs-sha256", "value": b64(&[0x22; 32])});
        parse(&v).unwrap();
        v["submods"]["cpu"]["cvm_binding"]["pattern"] = json!("challenge");
        assert!(err(&v).contains("certificate pattern"));
        let mut v = snp_envelope();
        v["submods"]["cpu"]["cvm_binding"]["key"]["value"] = json!(b64(&[0x11; 31]));
        assert!(err(&v).contains("31 bytes"));
        let mut v = snp_envelope();
        v["submods"]["cpu"]["cvm_binding"]["mode"] = json!("nras-nonce");
        assert!(err(&v).contains("not a cpu binding"));
    }

    #[test]
    fn commitment_mode_requirements() {
        let mut v = snp_envelope();
        v["submods"]["cpu"]["cvm_binding"]["mode"] = json!("commitment");
        assert!(err(&v).contains("requires cvm_registers"));
        v["submods"]["cpu"]["cvm_registers"] = snp_registers();
        assert!(err(&v).contains("requires cvm_chain and bootseed"));
        v["submods"]["cpu"]["cvm_chain"] = json!({"chain_len": 0});
        v["submods"]["cpu"]["bootseed"] = json!(b64(&[0x33; 32]));
        assert!(err(&v).contains("chain_len is 0"));
        v["submods"]["cpu"]["cvm_chain"] = json!({"chain_len": 1});
        parse(&v).unwrap();
        v["submods"]["cpu"]["cvm_log"] = json!({"format": "tcg-cel-cbor", "data": b64(&[0xa4])});
        parse(&v).unwrap();
        v["submods"]["cpu"]["cvm_registers"]
            .as_array_mut()
            .unwrap()
            .pop();
        assert!(err(&v).contains("all 16"));
        let mut v = snp_envelope();
        v["submods"]["cpu"]["cvm_chain"] = json!({"chain_len": 1});
        assert!(err(&v).contains("belong to commitment mode"));
        let mut v = snp_envelope();
        v["submods"]["cpu"]["bootseed"] = json!(b64(&[0x33; 31]));
        assert!(err(&v).contains("expected 32 bytes"));
    }

    #[test]
    fn snp_registers_bind_only_through_the_commitment() {
        let mut v = snp_envelope();
        v["submods"]["cpu"]["cvm_registers"] = snp_registers();
        assert!(err(&v).contains("only through the commitment"));
    }

    #[test]
    fn backing_and_alg_pinned_per_source() {
        let reg = |source: &str, alg: &str, backing: &str, len: usize| -> Register {
            serde_json::from_value(json!({
                "index": 0, "alg": alg, "value": b64(&vec![0u8; len]), "source": source, "backing": backing
            }))
            .unwrap()
        };
        assert!(reg("snp-vmr", "sha384", "hardware", 48)
            .validate()
            .unwrap_err()
            .to_string()
            .contains("below hardware"));
        assert!(reg("snp-vmr", "sha384", "privileged-service", 48)
            .validate()
            .is_ok());
        assert!(reg("snp-vmr", "sha256", "kernel-service", 32)
            .validate()
            .unwrap_err()
            .to_string()
            .contains("sha384"));
        assert!(reg("tdx-rtmr", "sha384", "kernel-service", 48)
            .validate()
            .unwrap_err()
            .to_string()
            .contains("hardware"));
        assert!(reg("tdx-rtmr", "sha256", "hardware", 32)
            .validate()
            .unwrap_err()
            .to_string()
            .contains("sha384"));
        assert!(reg("cca-rem", "sha384", "hardware", 48)
            .validate()
            .unwrap_err()
            .to_string()
            .contains("sha256 or sha512"));
        assert!(reg("cca-rem", "sha512", "hardware", 64).validate().is_ok());
        assert!(reg("vtpm-pcr", "sha256", "hardware", 32)
            .validate()
            .unwrap_err()
            .to_string()
            .contains("privileged-service"));
        assert!(reg("tdx-rtmr", "sha384", "hardware", 32)
            .validate()
            .unwrap_err()
            .to_string()
            .contains("needs 48"));
    }

    #[test]
    fn registers_and_logs() {
        let mut v = tdx_envelope();
        v["submods"]["cpu"]["cvm_log"] = json!({"format": "tdx-ccel", "data": b64(&[0xa4])});
        assert!(err(&v).contains("requires cvm_registers"));
        v["submods"]["cpu"]["cvm_registers"] = tdx_registers();
        parse(&v).unwrap();
        v["submods"]["cpu"]["cvm_registers"][0]["source"] = json!("snp-vmr");
        v["submods"]["cpu"]["cvm_registers"][0]["backing"] = json!("kernel-service");
        assert!(err(&v).contains("tdx-rtmr is required"));
        let mut v = tdx_envelope();
        v["submods"]["cpu"]["cvm_registers"] = json!([{"index": 4, "alg": "sha384", "value": b64(&[0; 48]), "source": "tdx-rtmr", "backing": "hardware"}]);
        assert!(err(&v).contains("index above 3"));
        let mut v = tdx_envelope();
        v["submods"]["cpu"]["cvm_registers"] = json!([]);
        assert!(err(&v).contains("empty"));
        let mut v = tdx_envelope();
        let mut regs = tdx_registers();
        regs[1]["index"] = json!(0);
        v["submods"]["cpu"]["cvm_registers"] = regs;
        assert!(err(&v).contains("duplicate"));
        let mut v = tdx_envelope();
        v["submods"]["cpu"]["cvm_registers"] = tdx_registers();
        v["submods"]["cpu"]["cvm_log"] = json!({"format": "tdx-ccel", "data": ""});
        assert!(err(&v).contains("cvm_log: empty"));
        assert!(Backing::Virtualized < Backing::KernelService);
        assert!(Backing::KernelService < Backing::PrivilegedService);
        assert!(Backing::PrivilegedService < Backing::Hardware);
    }

    #[test]
    fn endorsements() {
        let mut v = snp_envelope();
        v["submods"]["cpu"]["cvm_endorsements"] = json!({
            "__cmwc_t": ENDORSEMENTS_COLLECTION_TAG,
            "snp.vek": [MEDIA_TYPE_PKIX_CERT, b64(&[0x30, 0x82]), 2],
            "snp.crl": [MEDIA_TYPE_PKIX_CRL, b64(&[0x30, 0x82]), 1]
        });
        parse(&v).unwrap();
        v["submods"]["cpu"]["cvm_endorsements"]["tdx.pck_crl"] =
            json!([MEDIA_TYPE_PKIX_CRL, b64(&[1]), 2]);
        assert!(err(&v).contains("does not belong"));
        let mut v = snp_envelope();
        v["submods"]["cpu"]["cvm_endorsements"] = json!({"__cmwc_t": ENDORSEMENTS_COLLECTION_TAG, "snp.vek": [MEDIA_TYPE_PKIX_CERT, b64(&[1])]});
        assert!(err(&v).contains("exactly 2"));
        let mut v = snp_envelope();
        v["submods"]["cpu"]["cvm_endorsements"] = json!({"__cmwc_t": ENDORSEMENTS_COLLECTION_TAG, "snp.vek": [MEDIA_TYPE_PKIX_CERT, b64(&[1]), 3]});
        assert!(err(&v).contains("exactly 2"));
        let mut v = snp_envelope();
        v["submods"]["cpu"]["cvm_endorsements"] =
            json!({"__cmwc_t": "tag:other", "snp.vek": [MEDIA_TYPE_PKIX_CERT, b64(&[1]), 2]});
        assert!(err(&v).contains("__cmwc_t"));
        let mut v = snp_envelope();
        v["submods"]["cpu"]["cvm_endorsements"] = json!({"__cmwc_t": ENDORSEMENTS_COLLECTION_TAG, "snp.vek": [MEDIA_TYPE_PKIX_CRL, b64(&[1]), 2]});
        assert!(err(&v).contains("type must be"));
        let mut v = snp_envelope();
        v["submods"]["cpu"]["cvm_endorsements"] = json!({"__cmwc_t": ENDORSEMENTS_COLLECTION_TAG, "snp.vek": {"x": [MEDIA_TYPE_PKIX_CERT, b64(&[1]), 2]}});
        assert!(err(&v).contains("nested collections"));
    }

    fn azure_envelope() -> Value {
        let pcrs: Vec<String> = (0..24).map(|i| b64(&[i as u8; 32])).collect();
        json!({
            "eat_profile": PROFILE_URI,
            "eat_nonce": b64(&[7u8; 16]),
            "cvm_version": 1,
            "submods": {
                "cpu": {
                    "cvm_platform": {"vendor": "amd", "tee": "sev-snp", "hosting": "azure"},
                    "cvm_report": [MEDIA_TYPE_SNP_REPORT, b64(&[1u8; 1184]), 4],
                    "cvm_binding": {"pattern": "challenge", "mode": "vtpm-extradata"}
                },
                "vtpm": {
                    "cvm_tpm_quote": {"message": b64(&[1, 2]), "signature": b64(&[3, 4]), "pcrs": pcrs, "bank": "sha256"},
                    "cvm_tpm_ak": {"method": "hcl-report", "data": b64(&[0x48u8; 3000])},
                    "cvm_registers": [
                        {"index": 0, "alg": "sha256", "value": b64(&[0u8; 32]), "source": "vtpm-pcr", "backing": "privileged-service"},
                        {"index": 7, "alg": "sha256", "value": b64(&[7u8; 32]), "source": "vtpm-pcr", "backing": "privileged-service"}
                    ]
                }
            }
        })
    }

    #[test]
    fn azure_vtpm_rules() {
        let e = parse(&azure_envelope()).unwrap();
        assert_eq!(e.vtpm().unwrap().cvm_registers.len(), 2);
        let mut v = azure_envelope();
        v["submods"].as_object_mut().unwrap().remove("vtpm");
        assert!(err(&v).contains("no vtpm submodule"));
        let mut v = azure_envelope();
        v["submods"]["cpu"]["cvm_binding"]["mode"] = json!("report-data");
        assert!(err(&v).contains("vtpm-extradata"));
        let mut v = azure_envelope();
        v["submods"]["vtpm"]["cvm_registers"][1]["value"] = json!(b64(&[8u8; 32]));
        assert!(err(&v).contains("differs from the quoted PCR"));
        let mut v = azure_envelope();
        v["submods"]["vtpm"]["cvm_registers"][1]["backing"] = json!("hardware");
        assert!(err(&v).contains("privileged-service"));
        let mut v = azure_envelope();
        v["submods"]["vtpm"]["cvm_registers"][1]["alg"] = json!("sha384");
        v["submods"]["vtpm"]["cvm_registers"][1]["value"] = json!(b64(&[7u8; 48]));
        assert!(err(&v).contains("not in the quoted"));
        let mut v = azure_envelope();
        v["submods"]["vtpm"]["cvm_tpm_quote"]["pcrs"]
            .as_array_mut()
            .unwrap()
            .pop();
        assert!(err(&v).contains("expected 24"));
        let mut v = azure_envelope();
        v["submods"]["cpu"]["cvm_report"][0] = json!(MEDIA_TYPE_TSM_REPORT);
        assert!(err(&v).contains("does not fit"));
    }

    #[test]
    fn device_submodules() {
        let mut v = snp_envelope();
        v["submods"]["gpu/GPU-abc"] = json!({
            "arch": "HOPPER", "uuid": "GPU-abc", "evidence_b64": "AAAA", "cert_chain_b64": "AAAA",
            "cvm_binding": {"pattern": "challenge", "mode": "nras-nonce"}
        });
        parse(&v).unwrap();
        v["submods"]["gpu/GPU-abc"]["uuid"] = json!("GPU-def");
        assert!(err(&v).contains("differs from the submodule name"));
        v["submods"]["gpu/GPU-abc"]["uuid"] = json!("GPU-abc");
        v["submods"]["gpu/GPU-abc"]["arch"] = json!("LS10");
        assert!(err(&v).contains("wrong name form"));
        v["submods"]["gpu/GPU-abc"]["arch"] = json!("HOPPER");
        v["submods"]["gpu/GPU-abc"]["cvm_binding"]["mode"] = json!("report-data");
        assert!(err(&v).contains("nras-nonce"));
    }

    #[test]
    fn size_bound() {
        let big = vec![b' '; crate::MAX_EVIDENCE_SIZE + 1];
        assert!(matches!(
            Evidence::from_json(&big),
            Err(AttestationError::EvidenceTooLarge { .. })
        ));
    }
}
