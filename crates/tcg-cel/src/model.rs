//! The CEL information model (CEL v1.1 section 4).

use crate::alg::HashAlg;
use crate::error::{record, Result};
use crate::pcclient::{event_type_code, EV_NO_ACTION};

/// Byte and text strings in a record are at most this long (the PC Client
/// profile's recommended event size limit).
pub const MAX_BYTES: usize = 1 << 20;
/// Digests per record.
pub const MAX_DIGESTS: usize = 16;
/// The longest digest accepted for an algorithm the CEL CDDL does not name.
pub const MAX_DIGEST_LEN: usize = 128;
/// Records per log.
pub const MAX_RECORDS: usize = 65_536;

/// `content_type` values of CEL v1.1 Table 2.
pub const CONTENT_CEL: u64 = 4;
pub const CONTENT_PCCLIENT_STD: u64 = 5;
pub const CONTENT_IMA_TEMPLATE: u64 = 7;
pub const CONTENT_IMA_TLV: u64 = 8;
pub const CONTENT_SYSTEMD: u64 = 9;
/// Values Table 2 reserves.
pub(crate) const CONTENT_RESERVED: [u64; 2] = [6, 10];

/// A Canonical Event Log Record (section 4.2, `TPMS_CEL_EVENT`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Record {
    /// The record's sequence number within its index (section 4.2.2): 0 for
    /// the first record of an index, one more for each later record of it,
    /// measured or not.
    pub recnum: u64,
    pub index: Index,
    /// The `TPML_DIGEST_VALUES` of the extend, at most one entry per bank.
    pub digests: Vec<Digest>,
    pub content: Content,
}

/// The PCR or NV index a record names (section 4.2.3).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Index {
    /// A PCR, 0 to 0x00FF_FFFF.
    Pcr(u32),
    /// An NV index, 0x2000_0000 to 0x20FF_FFFF.
    Nv(u32),
}

impl Index {
    pub const PCR_MAX: u32 = 0x00FF_FFFF;
    pub const NV_MIN: u32 = 0x2000_0000;
    pub const NV_MAX: u32 = 0x20FF_FFFF;

    pub fn is_valid(self) -> bool {
        match self {
            Index::Pcr(n) => n <= Self::PCR_MAX,
            Index::Nv(n) => (Self::NV_MIN..=Self::NV_MAX).contains(&n),
        }
    }
}

impl std::fmt::Display for Index {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Index::Pcr(n) => write!(f, "pcr {n}"),
            Index::Nv(n) => write!(f, "nv_index 0x{n:08X}"),
        }
    }
}

/// One `TPMT_HA`: a bank and the digest extended into it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Digest {
    pub alg: HashAlg,
    pub value: Vec<u8>,
}

/// A record's content (Tables 2 and 3).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Content {
    /// `cel` (4): CEL management.
    Cel(CelMgmt),
    /// `pcclient_std` (5): a `TCG_PCR_EVENT2` event type and its data.
    PcClientStd {
        event_type: EventType,
        event_data: Vec<u8>,
    },
    /// `ima_template` (7).
    ImaTemplate {
        template_name: String,
        template_data: Vec<u8>,
    },
    /// `ima_tlv` (8).
    ImaTlv(Vec<u8>),
    /// `systemd` (9): the string systemd measured.
    Systemd(Vec<u8>),
    /// A content type taken through the CDDL's `$TPMS_CEL_EVENT-extension` socket.
    Extension {
        ty: &'static ContentType,
        value: Value,
    },
    /// A CBOR content type no registration covers, kept as its deterministic
    /// CBOR item. It replays like any other record and cannot be written as
    /// CEL-JSON, which names content types.
    Unknown { content_type: u64, cbor: Vec<u8> },
}

impl Content {
    /// The CBOR `content_type` value.
    pub fn content_type(&self) -> u64 {
        match self {
            Content::Cel(_) => CONTENT_CEL,
            Content::PcClientStd { .. } => CONTENT_PCCLIENT_STD,
            Content::ImaTemplate { .. } => CONTENT_IMA_TEMPLATE,
            Content::ImaTlv(_) => CONTENT_IMA_TLV,
            Content::Systemd(_) => CONTENT_SYSTEMD,
            Content::Extension { ty, .. } => ty.value,
            Content::Unknown { content_type, .. } => *content_type,
        }
    }
}

/// CEL management content (section 4.4, `TPMS_EVENT_CELMGT`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CelMgmt {
    /// `cel_version` (1), not measured.
    Version { major: u16, minor: u16 },
    /// `firmware_end` (2), not measured.
    FirmwareEnd,
    /// `cel_timestamp` (80), measured. CEL v1.1 gives this value two units
    /// (seconds in Table 6, milliseconds in section 4.4.3); it is kept as recorded.
    Timestamp(u64),
    /// `state_trans` (81), measured.
    StateTrans(StateTrans),
}

pub(crate) const CELMGT_VERSION: u64 = 1;
pub(crate) const CELMGT_FIRMWARE_END: u64 = 2;
pub(crate) const CELMGT_TIMESTAMP: u64 = 80;
pub(crate) const CELMGT_STATE_TRANS: u64 = 81;

/// `TPMI_STATE_TRANS` (Table 8).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StateTrans {
    Suspend,
    Hibernate,
    Kexec,
}

impl StateTrans {
    pub(crate) const ALL: [(Self, u64, &'static str); 3] = [
        (Self::Suspend, 0, "suspend"),
        (Self::Hibernate, 1, "hibernate"),
        (Self::Kexec, 2, "kexec"),
    ];

    pub(crate) fn value(self) -> u64 {
        Self::ALL.iter().find(|(s, _, _)| *s == self).unwrap().1
    }

    pub(crate) fn name(self) -> &'static str {
        Self::ALL.iter().find(|(s, _, _)| *s == self).unwrap().2
    }

    pub(crate) fn from_value(v: u64) -> Option<Self> {
        Self::ALL.iter().find(|(_, n, _)| *n == v).map(|e| e.0)
    }

    pub(crate) fn from_name(s: &str) -> Option<Self> {
        Self::ALL.iter().find(|(_, _, n)| *n == s).map(|e| e.0)
    }
}

/// A PC Client event type, CDDL `text / uint .size 4`. Decoders turn a Table
/// 27 label into its code, so only labels outside the table stay text.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EventType {
    Code(u32),
    Name(String),
}

impl EventType {
    pub(crate) fn from_text(s: &str) -> Self {
        match event_type_code(s) {
            Some(c) => EventType::Code(c),
            None => EventType::Name(s.to_string()),
        }
    }

    /// The `TCG_PCR_EVENT2.eventType` code.
    pub fn code(&self) -> Option<u32> {
        match self {
            EventType::Code(c) => Some(*c),
            EventType::Name(_) => None,
        }
    }
}

/// A content type taken through `$TPMS_CEL_EVENT-extension`: its CBOR value,
/// its CEL-JSON name and the shape of its content. Decoders only interpret
/// extension content they are given a registration for.
#[derive(Debug, PartialEq, Eq)]
pub struct ContentType {
    pub value: u64,
    pub name: &'static str,
    pub schema: Schema,
}

/// The shape of extension content, in the CEL encoding convention: a map has
/// unsigned integer keys in CBOR and the field names in JSON, and a byte
/// string is a CBOR byte string and hex text in JSON.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Schema {
    Uint,
    Text,
    Bytes,
    /// Fields in ascending key order.
    Map(&'static [Field]),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Field {
    pub key: u64,
    pub name: &'static str,
    pub schema: Schema,
    pub optional: bool,
}

/// Extension content, shaped by its [`Schema`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Value {
    Uint(u64),
    Text(String),
    Bytes(Vec<u8>),
    /// Present fields in ascending key order.
    Map(Vec<(u64, Value)>),
}

impl Value {
    /// The value of a map field.
    pub fn get(&self, key: u64) -> Option<&Value> {
        match self {
            Value::Map(m) => m.iter().find(|(k, _)| *k == key).map(|(_, v)| v),
            _ => None,
        }
    }

    pub fn as_uint(&self) -> Option<u64> {
        match self {
            Value::Uint(v) => Some(*v),
            _ => None,
        }
    }

    pub fn as_bytes(&self) -> Option<&[u8]> {
        match self {
            Value::Bytes(v) => Some(v),
            _ => None,
        }
    }

    pub fn as_text(&self) -> Option<&str> {
        match self {
            Value::Text(v) => Some(v),
            _ => None,
        }
    }

    pub(crate) fn check(&self, schema: Schema) -> std::result::Result<(), String> {
        match (schema, self) {
            (Schema::Uint, Value::Uint(_)) => Ok(()),
            (Schema::Text, Value::Text(s)) if s.len() <= MAX_BYTES => Ok(()),
            (Schema::Bytes, Value::Bytes(b)) if b.len() <= MAX_BYTES => Ok(()),
            (Schema::Map(fields), Value::Map(entries)) => {
                let mut entries = entries.iter().peekable();
                for f in fields {
                    match entries.peek() {
                        Some((k, v)) if *k == f.key => {
                            v.check(f.schema).map_err(|e| format!("{}: {e}", f.name))?;
                            entries.next();
                        }
                        _ if f.optional => {}
                        _ => return Err(format!("missing field {}", f.name)),
                    }
                }
                match entries.next() {
                    None => Ok(()),
                    Some((k, _)) => Err(format!("unexpected or out of order key {k}")),
                }
            }
            (Schema::Text | Schema::Bytes, _) => Err("string too long or of the wrong type".into()),
            _ => Err("value does not match the schema".into()),
        }
    }
}

impl ContentType {
    /// A registration decoders can use: a value outside Table 2 and map
    /// fields with ascending keys and distinct names.
    pub(crate) fn check(&self) -> std::result::Result<(), String> {
        if (CONTENT_CEL..=10).contains(&self.value) {
            return Err(format!(
                "extension {} takes content_type {}, which CEL v1.1 Table 2 assigns",
                self.name, self.value
            ));
        }
        fn fields_ok(s: Schema) -> bool {
            match s {
                Schema::Map(fields) => {
                    fields.windows(2).all(|w| w[0].key < w[1].key)
                        && fields
                            .iter()
                            .enumerate()
                            .all(|(i, f)| fields[i + 1..].iter().all(|g| g.name != f.name))
                        && fields.iter().all(|f| fields_ok(f.schema))
                }
                _ => true,
            }
        }
        if !fields_ok(self.schema) {
            return Err(format!("extension {}: malformed schema", self.name));
        }
        Ok(())
    }
}

impl Record {
    /// The digest this record carries for `alg`'s bank.
    pub fn digest(&self, alg: HashAlg) -> Option<&[u8]> {
        self.digests
            .iter()
            .find(|d| d.alg == alg)
            .map(|d| d.value.as_slice())
    }

    /// Whether the record extends its index (section 4.2.3: some events are
    /// unmeasured). Unmeasured: `pcclient_std` EV_NO_ACTION, and the
    /// `cel_version` and `firmware_end` management events.
    pub fn is_measured(&self) -> bool {
        match &self.content {
            Content::Cel(CelMgmt::Version { .. } | CelMgmt::FirmwareEnd) => false,
            Content::PcClientStd { event_type, .. } => event_type.code() != Some(EV_NO_ACTION),
            _ => true,
        }
    }

    /// The information model's constraints on one record.
    pub(crate) fn validate(&self, position: usize) -> Result<()> {
        if !self.index.is_valid() {
            return Err(record(position, format!("{} out of range", self.index)));
        }
        if self.digests.is_empty() || self.digests.len() > MAX_DIGESTS {
            return Err(record(
                position,
                format!("{} digests; 1 to {MAX_DIGESTS} allowed", self.digests.len()),
            ));
        }
        for (i, d) in self.digests.iter().enumerate() {
            if self.digests[..i].iter().any(|e| e.alg == d.alg) {
                return Err(record(position, format!("two digests in bank {}", d.alg)));
            }
            let ok = match d.alg.digest_size() {
                Some(n) => d.value.len() == n,
                None => (1..=MAX_DIGEST_LEN).contains(&d.value.len()),
            };
            if !ok {
                return Err(record(
                    position,
                    format!("{} digest is {} bytes", d.alg, d.value.len()),
                ));
            }
        }
        let long = |n: usize| n > MAX_BYTES;
        let bad = match &self.content {
            Content::Cel(_) => None,
            Content::PcClientStd {
                event_type,
                event_data,
            } => match event_type {
                EventType::Name(n) if n.is_empty() || long(n.len()) => Some("event_type name"),
                _ if long(event_data.len()) => Some("event_data too long"),
                _ => None,
            },
            Content::ImaTemplate {
                template_name,
                template_data,
            } => (long(template_name.len()) || long(template_data.len()))
                .then_some("ima_template too long"),
            Content::ImaTlv(b) | Content::Systemd(b) => long(b.len()).then_some("content too long"),
            Content::Extension { ty, value } => {
                ty.check().map_err(|e| record(position, e))?;
                value
                    .check(ty.schema)
                    .map_err(|e| record(position, format!("{} content: {e}", ty.name)))?;
                None
            }
            Content::Unknown { content_type, cbor } => {
                let mut r = crate::cbor::Reader::new(cbor);
                if (CONTENT_CEL..=10).contains(content_type) {
                    Some("an unknown content type cannot take a Table 2 value")
                } else if long(cbor.len()) || r.item().is_err() || !r.at_end() {
                    Some("unknown content is not one deterministic CBOR item")
                } else {
                    None
                }
            }
        };
        match bad {
            Some(reason) => Err(record(position, reason)),
            None => Ok(()),
        }
    }
}

/// Section 4.2.2: per index, `recnum` starts at 0 and increases by one with
/// each record, measured or not.
pub(crate) fn check_recnums(records: &[Record]) -> Result<()> {
    let mut next: std::collections::BTreeMap<Index, u64> = Default::default();
    for (position, r) in records.iter().enumerate() {
        let expected = next.entry(r.index).or_insert(0);
        if r.recnum != *expected {
            return Err(record(
                position,
                format!(
                    "recnum {} where {} expects {expected}; recnum counts from 0 per index",
                    r.recnum, r.index
                ),
            ));
        }
        *expected += 1;
    }
    Ok(())
}

/// Set every `recnum` from the records' order: from 0, per index.
pub fn renumber(records: &mut [Record]) {
    let mut next: std::collections::BTreeMap<Index, u64> = Default::default();
    for r in records {
        let n = next.entry(r.index).or_insert(0);
        r.recnum = *n;
        *n += 1;
    }
}
