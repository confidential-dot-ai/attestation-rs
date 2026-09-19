//! RFC 9999 Conceptual Message Wrappers in their JSON serialization.

use super::bytes::Bytes;
use schemars::{json_schema, JsonSchema, Schema, SchemaGenerator};
use serde::de::{self, SeqAccess, Visitor};
use serde::ser::{SerializeMap, SerializeSeq};
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use std::borrow::Cow;
use std::collections::BTreeMap;
use std::fmt;

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
                { "type": "integer", "minimum": 0, "maximum": 15 }
            ],
            "minItems": 2,
            "maxItems": 3
        })
    }
}

/// One member of a collection: a record (JSON array) or a nested collection
/// (JSON object).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
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

impl<'de> Deserialize<'de> for CmwCollection {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        #[derive(Deserialize)]
        #[serde(untagged)]
        enum Raw {
            Type(String),
            Entry(CmwEntry),
        }
        let raw: BTreeMap<String, Raw> = BTreeMap::deserialize(d)?;
        let mut out = CmwCollection::default();
        for (k, v) in raw {
            match (k.as_str(), v) {
                (CMWC_T, Raw::Type(t)) => out.collection_type = Some(t),
                (CMWC_T, Raw::Entry(_)) => {
                    return Err(de::Error::custom("__cmwc_t must be a string"))
                }
                (_, Raw::Type(_)) => {
                    return Err(de::Error::custom(format!(
                        "CMW collection entry {k:?} is not a record or collection"
                    )))
                }
                (_, Raw::Entry(e)) => {
                    out.entries.insert(k, e);
                }
            }
        }
        if out.entries.is_empty() {
            return Err(de::Error::custom("CMW collection has no entries"));
        }
        Ok(out)
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
            "minProperties": 1
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
    }
}
