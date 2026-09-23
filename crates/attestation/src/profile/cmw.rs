//! RFC 9999 Conceptual Message Wrappers in their JSON serialization.
//!
//! Collections are parsed by a streaming visitor, never through an untagged
//! enum: untagged deserialization buffers every remaining byte once per
//! nesting level, which turns an 8 MB envelope into gigabytes of heap.

use super::bytes::Bytes;
use schemars::{json_schema, JsonSchema, Schema, SchemaGenerator};
use serde::de::value::SeqAccessDeserializer;
use serde::de::{self, DeserializeSeed, MapAccess, SeqAccess, Visitor};
use serde::ser::{SerializeMap, SerializeSeq};
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use std::borrow::Cow;
use std::collections::BTreeMap;
use std::fmt;

/// A collection may contain a collection, and no deeper.
pub const MAX_CMW_DEPTH: u8 = 2;
/// Entries per collection; the profile defines seven labels.
pub const MAX_CMW_ENTRIES: usize = 32;
/// RFC 9999 section 3.1 registers five indicator bits, so an indicator is 1
/// to 31; zero is not a value.
pub const MAX_CMW_IND: u32 = 0b1_1111;

/// `json-record = [type: media-type, value: base64url-string, ? ind: uint]`
/// (RFC 9999 section 3.1).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CmwRecord {
    pub media_type: String,
    pub value: Bytes,
    pub ind: Option<u32>,
}

impl CmwRecord {
    pub fn new(media_type: impl Into<String>, value: impl Into<Bytes>, ind: Option<u32>) -> Self {
        CmwRecord {
            media_type: media_type.into(),
            value: value.into(),
            ind,
        }
    }
    /// True when `ind` is present and carries `bit`.
    pub fn has_ind(&self, bit: u32) -> bool {
        self.ind.is_some_and(|i| i & bit != 0)
    }
}

impl Serialize for CmwRecord {
    fn serialize<S: Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        let n = if self.ind.is_some() { 3 } else { 2 };
        let mut seq = s.serialize_seq(Some(n))?;
        seq.serialize_element(&self.media_type)?;
        seq.serialize_element(&self.value)?;
        if let Some(ind) = self.ind {
            seq.serialize_element(&ind)?;
        }
        seq.end()
    }
}

impl<'de> Deserialize<'de> for CmwRecord {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        struct V;
        impl<'de> Visitor<'de> for V {
            type Value = CmwRecord;
            fn expecting(&self, f: &mut fmt::Formatter) -> fmt::Result {
                f.write_str("a CMW record [type, value, ?ind]")
            }
            fn visit_seq<A: SeqAccess<'de>>(self, mut seq: A) -> Result<CmwRecord, A::Error> {
                let media_type: String = seq
                    .next_element()?
                    .ok_or_else(|| de::Error::custom("CMW record: missing type"))?;
                let value: Bytes = seq
                    .next_element()?
                    .ok_or_else(|| de::Error::custom("CMW record: missing value"))?;
                let ind: Option<u32> = seq.next_element()?;
                if seq.next_element::<de::IgnoredAny>()?.is_some() {
                    return Err(de::Error::custom("CMW record: more than three items"));
                }
                if media_type.is_empty() || !media_type.contains('/') {
                    return Err(de::Error::custom("CMW record: type is not a media type"));
                }
                if ind.is_some_and(|i| i == 0 || i > MAX_CMW_IND) {
                    return Err(de::Error::custom(
                        "CMW record: an indicator is 1 to 31 (RFC 9999 section 3.1)",
                    ));
                }
                Ok(CmwRecord {
                    media_type,
                    value,
                    ind,
                })
            }
        }
        d.deserialize_seq(V)
    }
}

impl JsonSchema for CmwRecord {
    fn schema_name() -> Cow<'static, str> {
        "CmwRecord".into()
    }
    fn json_schema(g: &mut SchemaGenerator) -> Schema {
        let bytes = g.subschema_for::<Bytes>();
        json_schema!({
            "type": "array",
            "description": "RFC 9999 record: [media type, base64url value, optional indicator bits]",
            "prefixItems": [
                { "type": "string", "pattern": "^[^/]+/.+$" },
                bytes,
                { "type": "integer", "minimum": 1, "maximum": MAX_CMW_IND }
            ],
            "minItems": 2,
            "maxItems": 3
        })
    }
}

/// One member of a collection: a record (JSON array) or a nested collection
/// (JSON object).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, JsonSchema)]
#[serde(untagged)]
pub enum CmwEntry {
    Record(CmwRecord),
    Collection(CmwCollection),
}

/// `json-collection = { ? "__cmwc_t": ~uri / oid, + label => json-cmw }`
/// (RFC 9999 section 3.3). Labels are kept sorted so serialization is stable.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct CmwCollection {
    pub collection_type: Option<String>,
    pub entries: BTreeMap<String, CmwEntry>,
}

const CMWC_T: &str = "__cmwc_t";

impl Serialize for CmwCollection {
    fn serialize<S: Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        let n = self.entries.len() + usize::from(self.collection_type.is_some());
        let mut m = s.serialize_map(Some(n))?;
        if let Some(t) = &self.collection_type {
            m.serialize_entry(CMWC_T, t)?;
        }
        for (k, v) in &self.entries {
            m.serialize_entry(k, v)?;
        }
        m.end()
    }
}

/// Deserializes one entry at nesting `depth` (the depth of the collection it
/// sits in) by dispatching on the JSON shape, without buffering.
struct EntrySeed {
    depth: u8,
}

impl<'de> DeserializeSeed<'de> for EntrySeed {
    type Value = CmwEntry;
    fn deserialize<D: Deserializer<'de>>(self, d: D) -> Result<CmwEntry, D::Error> {
        d.deserialize_any(EntryVisitor { depth: self.depth })
    }
}

struct EntryVisitor {
    depth: u8,
}

impl<'de> Visitor<'de> for EntryVisitor {
    type Value = CmwEntry;
    fn expecting(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.write_str("a CMW record (array) or collection (object)")
    }
    fn visit_seq<A: SeqAccess<'de>>(self, seq: A) -> Result<CmwEntry, A::Error> {
        CmwRecord::deserialize(SeqAccessDeserializer::new(seq)).map(CmwEntry::Record)
    }
    fn visit_map<A: MapAccess<'de>>(self, map: A) -> Result<CmwEntry, A::Error> {
        if self.depth >= MAX_CMW_DEPTH {
            return Err(de::Error::custom(format!(
                "CMW collection nested deeper than {MAX_CMW_DEPTH}"
            )));
        }
        collection_from_map(map, self.depth + 1).map(CmwEntry::Collection)
    }
}

fn collection_from_map<'de, A: MapAccess<'de>>(
    mut map: A,
    depth: u8,
) -> Result<CmwCollection, A::Error> {
    let mut out = CmwCollection::default();
    while let Some(key) = map.next_key::<String>()? {
        if key == CMWC_T {
            if out.collection_type.is_some() {
                return Err(de::Error::duplicate_field(CMWC_T));
            }
            out.collection_type = Some(map.next_value::<String>()?);
            continue;
        }
        if out.entries.len() >= MAX_CMW_ENTRIES {
            return Err(de::Error::custom(format!(
                "CMW collection has more than {MAX_CMW_ENTRIES} entries"
            )));
        }
        let entry = map.next_value_seed(EntrySeed { depth })?;
        if out.entries.insert(key.clone(), entry).is_some() {
            return Err(de::Error::custom(format!(
                "CMW collection: duplicate label {key:?}"
            )));
        }
    }
    if out.entries.is_empty() {
        return Err(de::Error::custom("CMW collection has no entries"));
    }
    Ok(out)
}

impl<'de> Deserialize<'de> for CmwCollection {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        struct V;
        impl<'de> Visitor<'de> for V {
            type Value = CmwCollection;
            fn expecting(&self, f: &mut fmt::Formatter) -> fmt::Result {
                f.write_str("a CMW collection object")
            }
            fn visit_map<A: MapAccess<'de>>(self, map: A) -> Result<CmwCollection, A::Error> {
                collection_from_map(map, 1)
            }
        }
        d.deserialize_map(V)
    }
}

impl<'de> Deserialize<'de> for CmwEntry {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        EntrySeed { depth: 0 }.deserialize(d)
    }
}

impl JsonSchema for CmwCollection {
    fn schema_name() -> Cow<'static, str> {
        "CmwCollection".into()
    }
    fn json_schema(g: &mut SchemaGenerator) -> Schema {
        let entry = g.subschema_for::<CmwEntry>();
        json_schema!({
            "type": "object",
            "description": "RFC 9999 collection: optional __cmwc_t plus labeled records or collections",
            "properties": { "__cmwc_t": { "type": "string" } },
            "additionalProperties": entry,
            "minProperties": 1,
            "maxProperties": MAX_CMW_ENTRIES + 1
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn record_round_trip() {
        let r = CmwRecord::new("application/pkix-cert", vec![1, 2, 3], Some(2));
        let j = serde_json::to_string(&r).unwrap();
        assert_eq!(j, r#"["application/pkix-cert","AQID",2]"#);
        assert_eq!(serde_json::from_str::<CmwRecord>(&j).unwrap(), r);
        let two: CmwRecord = serde_json::from_str(r#"["a/b","AQID"]"#).unwrap();
        assert_eq!(two.ind, None);
        assert!(serde_json::from_str::<CmwRecord>(r#"["a/b","AQID",2,9]"#).is_err());
        assert!(serde_json::from_str::<CmwRecord>(r#"["notatype","AQID"]"#).is_err());
        assert!(serde_json::from_str::<CmwRecord>(r#"["a/b","AQID=="]"#).is_err());
        // RFC 9999 section 3.1: non-zero, five registered bits.
        assert!(serde_json::from_str::<CmwRecord>(r#"["a/b","AQID",0]"#).is_err());
        assert!(serde_json::from_str::<CmwRecord>(r#"["a/b","AQID",32]"#).is_err());
        assert!(serde_json::from_str::<CmwRecord>(r#"["a/b","AQID",16]"#).is_ok());
        assert!(serde_json::from_str::<CmwRecord>(r#"["a/b","AQID",31]"#).is_ok());
    }

    #[test]
    fn collection_round_trip() {
        let j = r#"{"__cmwc_t":"tag:x,2026:y","a":["a/b","AQID",2],"n":{"c":["c/d","AQ"]}}"#;
        let c: CmwCollection = serde_json::from_str(j).unwrap();
        assert_eq!(c.collection_type.as_deref(), Some("tag:x,2026:y"));
        assert_eq!(c.entries.len(), 2);
        assert!(matches!(c.entries["n"], CmwEntry::Collection(_)));
        assert_eq!(serde_json::to_string(&c).unwrap(), j);
        assert!(serde_json::from_str::<CmwCollection>(r#"{"__cmwc_t":"t"}"#).is_err());
        assert!(serde_json::from_str::<CmwCollection>(r#"{"a":"str"}"#).is_err());
        assert!(serde_json::from_str::<CmwCollection>(
            r#"{"__cmwc_t":["a/b","AQ"],"a":["a/b","AQ"]}"#
        )
        .is_err());
        let e: CmwEntry = serde_json::from_str(r#"["a/b","AQ"]"#).unwrap();
        assert!(matches!(e, CmwEntry::Record(_)));
    }

    #[test]
    fn bounded_and_strict() {
        let deep = r#"{"a":{"b":{"c":["x/y","AQ"]}}}"#;
        let err = serde_json::from_str::<CmwCollection>(deep)
            .unwrap_err()
            .to_string();
        assert!(err.contains("nested deeper"), "{err}");
        let ok = r#"{"a":{"c":["x/y","AQ"]}}"#;
        serde_json::from_str::<CmwCollection>(ok).unwrap();
        let dup = r#"{"a":["x/y","AQ"],"a":["x/y","Ag"]}"#;
        let err = serde_json::from_str::<CmwCollection>(dup)
            .unwrap_err()
            .to_string();
        assert!(err.contains("duplicate label"), "{err}");
        let dup_t = r#"{"__cmwc_t":"t","__cmwc_t":"u","a":["x/y","AQ"]}"#;
        assert!(serde_json::from_str::<CmwCollection>(dup_t).is_err());
        let mut many = String::from("{");
        for i in 0..=MAX_CMW_ENTRIES {
            many.push_str(&format!(r#""e{i}":["x/y","AQ"],"#));
        }
        many.pop();
        many.push('}');
        let err = serde_json::from_str::<CmwCollection>(&many)
            .unwrap_err()
            .to_string();
        assert!(err.contains("more than"), "{err}");
    }
}
