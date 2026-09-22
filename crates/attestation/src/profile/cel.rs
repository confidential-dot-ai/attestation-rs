//! TCG Canonical Event Log v1.1 records in CBOR and JSON (section 4.8), the
//! c8s event they carry, the dstack runtime log mapped onto the same records,
//! and the replay that reproduces registers from them (sections 4.8 and 4.9).
//!
//! Parsing is strict: deterministic CBOR only (definite lengths, minimal
//! integer encodings, keys in order), one SHA-384 digest per record, bounded
//! sizes and counts, and every `cvm` record's digest recomputed from its
//! sequence number, index and content bytes before it is extended.

use super::registers::{
    extend, record_digest, BOOT_SLOT, CEL_CONTENT_NAME_CVM, CEL_CONTENT_TYPE_CVM, CLAIM_STRING_MAX,
    DOMAIN_ATS, FIRST_WORKLOAD_SLOT, OP_BOOT, OP_CLAIM, TPM_ALG_SHA384,
};
use crate::error::{AttestationError, Result};
use sha2::{Digest, Sha384};
use std::collections::BTreeMap;

/// Records per log.
pub const MAX_RECORDS: usize = 65_536;
/// Bytes of content per record.
pub const MAX_CONTENT: usize = 1 << 20;
const MAX_DEPTH: usize = 6;

fn bad(msg: impl Into<String>) -> AttestationError {
    AttestationError::EventlogIntegrityFailed(msg.into())
}

/// One record: `recnum`, the register index (the CEL `pcr` field), its single
/// SHA-384 digest and its content.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CelRecord {
    pub recnum: u64,
    pub index: u16,
    pub digest: [u8; 48],
    pub content: CelContent,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CelContent {
    /// Content type `cvm` (200): the c8s event bytes, hashed with recnum and index.
    Cvm(Vec<u8>),
    /// A content type this verifier does not interpret; the digest is
    /// extended as recorded.
    Other { content_type: u64 },
}

/// A c8s event (section 4.8): `{0: domain, 1: operation, 2: content_digest, 3: content?}`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CvmEvent {
    pub domain: String,
    pub operation: String,
    pub content_digest: [u8; 48],
    pub content: Option<Vec<u8>>,
}

mod cbor {
    use super::{bad, MAX_DEPTH};
    use crate::error::Result;

    pub struct Reader<'a> {
        data: &'a [u8],
        pub pos: usize,
    }

    impl<'a> Reader<'a> {
        pub fn new(data: &'a [u8]) -> Self {
            Reader { data, pos: 0 }
        }

        pub fn at_end(&self) -> bool {
            self.pos >= self.data.len()
        }

        fn byte(&mut self) -> Result<u8> {
            let b = *self
                .data
                .get(self.pos)
                .ok_or_else(|| bad("CBOR: truncated"))?;
            self.pos += 1;
            Ok(b)
        }

        /// Major type and argument, rejecting indefinite lengths and
        /// non-minimal integer encodings (deterministic CBOR, RFC 8949 4.2).
        pub fn head(&mut self) -> Result<(u8, u64)> {
            let b = self.byte()?;
            let major = b >> 5;
            let info = b & 0x1f;
            let arg = match info {
                0..=23 => u64::from(info),
                24 => {
                    let v = u64::from(self.byte()?);
                    if v < 24 {
                        return Err(bad("CBOR: non-minimal integer"));
                    }
                    v
                }
                25 => {
                    let v = u64::from(u16::from_be_bytes(self.take(2)?.try_into().unwrap()));
                    if v <= 0xff {
                        return Err(bad("CBOR: non-minimal integer"));
                    }
                    v
                }
                26 => {
                    let v = u64::from(u32::from_be_bytes(self.take(4)?.try_into().unwrap()));
                    if v <= 0xffff {
                        return Err(bad("CBOR: non-minimal integer"));
                    }
                    v
                }
                27 => {
                    let v = u64::from_be_bytes(self.take(8)?.try_into().unwrap());
                    if v <= 0xffff_ffff {
                        return Err(bad("CBOR: non-minimal integer"));
                    }
                    v
                }
                _ => return Err(bad("CBOR: indefinite length or reserved additional info")),
            };
            Ok((major, arg))
        }

        pub fn take(&mut self, n: usize) -> Result<&'a [u8]> {
            let end = self
                .pos
                .checked_add(n)
                .filter(|&e| e <= self.data.len())
                .ok_or_else(|| bad("CBOR: truncated"))?;
            let s = &self.data[self.pos..end];
            self.pos = end;
            Ok(s)
        }

        pub fn uint(&mut self) -> Result<u64> {
            match self.head()? {
                (0, v) => Ok(v),
                (m, _) => Err(bad(format!(
                    "CBOR: expected unsigned integer, got major {m}"
                ))),
            }
        }

        /// A length that fits `usize` on every target and the caller's cap.
        fn len(n: u64, max: usize, what: &str) -> Result<usize> {
            match usize::try_from(n) {
                Ok(n) if n <= max => Ok(n),
                _ => Err(bad(format!("CBOR: {what} too large"))),
            }
        }

        pub fn bstr(&mut self, max: usize) -> Result<&'a [u8]> {
            match self.head()? {
                (2, n) => self.take(Self::len(n, max, "byte string")?),
                (m, _) => Err(bad(format!("CBOR: expected byte string, got major {m}"))),
            }
        }

        pub fn tstr(&mut self, max: usize) -> Result<&'a str> {
            match self.head()? {
                (3, n) => std::str::from_utf8(self.take(Self::len(n, max, "text string")?)?)
                    .map_err(|_| bad("CBOR: text string is not UTF-8")),
                (m, _) => Err(bad(format!("CBOR: expected text string, got major {m}"))),
            }
        }

        pub fn array(&mut self, max: usize) -> Result<usize> {
            match self.head()? {
                (4, n) => Self::len(n, max, "array"),
                (m, _) => Err(bad(format!("CBOR: expected array, got major {m}"))),
            }
        }

        pub fn map(&mut self, max: usize) -> Result<usize> {
            match self.head()? {
                (5, n) => Self::len(n, max, "map"),
                (m, _) => Err(bad(format!("CBOR: expected map, got major {m}"))),
            }
        }

        /// Skip one data item of any type, bounded in depth and size.
        pub fn skip(&mut self, depth: usize) -> Result<()> {
            if depth > MAX_DEPTH {
                return Err(bad("CBOR: nesting too deep"));
            }
            let (major, arg) = self.head()?;
            match major {
                0 | 1 => Ok(()),
                2 | 3 => self.take(Self::len(arg, usize::MAX, "string")?).map(|_| ()),
                4 => (0..arg).try_for_each(|_| self.skip(depth + 1)),
                5 => (0..arg).try_for_each(|_| {
                    self.skip(depth + 1)?;
                    self.skip(depth + 1)
                }),
                6 => self.skip(depth + 1),
                _ => Err(bad("CBOR: simple values and floats are not used")),
            }
        }
    }
}

fn digest48(b: &[u8]) -> Result<[u8; 48]> {
    b.try_into().map_err(|_| bad("digest is not 48 bytes"))
}

/// Parse `cvm` content bytes into the c8s event.
pub fn parse_cvm_event(content: &[u8]) -> Result<CvmEvent> {
    let mut r = cbor::Reader::new(content);
    let n = r.map(4)?;
    if n < 3 {
        return Err(bad("cvm event: fewer than three members"));
    }
    if r.uint()? != 0 {
        return Err(bad("cvm event: key 0 expected"));
    }
    let domain = r.tstr(CLAIM_STRING_MAX)?.to_string();
    if r.uint()? != 1 {
        return Err(bad("cvm event: key 1 expected"));
    }
    let operation = r.tstr(CLAIM_STRING_MAX)?.to_string();
    if r.uint()? != 2 {
        return Err(bad("cvm event: key 2 expected"));
    }
    let content_digest = digest48(r.bstr(48)?)?;
    let inner = if n == 4 {
        if r.uint()? != 3 {
            return Err(bad("cvm event: key 3 expected"));
        }
        Some(r.bstr(MAX_CONTENT)?.to_vec())
    } else {
        None
    };
    if !r.at_end() {
        return Err(bad("cvm event: trailing bytes"));
    }
    Ok(CvmEvent {
        domain,
        operation,
        content_digest,
        content: inner,
    })
}

/// The claim body `{0: owner, 1: purpose}` (section 4.9).
pub fn parse_claim_body(body: &[u8]) -> Result<(String, String)> {
    let mut r = cbor::Reader::new(body);
    if r.map(2)? != 2 {
        return Err(bad("claim body: two members expected"));
    }
    if r.uint()? != 0 {
        return Err(bad("claim body: key 0 expected"));
    }
    let owner = r.tstr(CLAIM_STRING_MAX)?.to_string();
    if r.uint()? != 1 {
        return Err(bad("claim body: key 1 expected"));
    }
    let purpose = r.tstr(CLAIM_STRING_MAX)?.to_string();
    if !r.at_end() {
        return Err(bad("claim body: trailing bytes"));
    }
    Ok((owner, purpose))
}

fn parse_record(r: &mut cbor::Reader<'_>) -> Result<CelRecord> {
    // {0: recnum, 1: pcr, 3: [{0: alg, 1: digest}], <type>: content}
    if r.map(4)? != 4 {
        return Err(bad("CEL record: four members expected"));
    }
    if r.uint()? != 0 {
        return Err(bad("CEL record: recnum expected first"));
    }
    let recnum = r.uint()?;
    if r.uint()? != 1 {
        return Err(bad("CEL record: pcr expected second"));
    }
    let index = u16::try_from(r.uint()?).map_err(|_| bad("CEL record: pcr out of range"))?;
    if r.uint()? != 3 {
        return Err(bad("CEL record: digests expected third"));
    }
    if r.array(1)? != 1 {
        return Err(bad("CEL record: exactly one digest"));
    }
    if r.map(2)? != 2 {
        return Err(bad("CEL record: digest entry has two members"));
    }
    if r.uint()? != 0 {
        return Err(bad("CEL record: hashAlg expected"));
    }
    if r.uint()? != TPM_ALG_SHA384 {
        return Err(bad("CEL record: digest algorithm is not SHA-384"));
    }
    if r.uint()? != 1 {
        return Err(bad("CEL record: digest expected"));
    }
    let digest = digest48(r.bstr(48)?)?;
    let content_type = r.uint()?;
    if content_type <= 3 {
        return Err(bad("CEL record: content type collides with a record field"));
    }
    let content = if content_type == CEL_CONTENT_TYPE_CVM {
        CelContent::Cvm(r.bstr(MAX_CONTENT)?.to_vec())
    } else {
        r.skip(0)?;
        CelContent::Other { content_type }
    };
    Ok(CelRecord {
        recnum,
        index,
        digest,
        content,
    })
}

/// A `tcg-cel-cbor` log: the CBOR sequence (RFC 8742) of records.
pub fn parse_cbor(data: &[u8]) -> Result<Vec<CelRecord>> {
    let mut r = cbor::Reader::new(data);
    let mut out = Vec::new();
    while !r.at_end() {
        if out.len() >= MAX_RECORDS {
            return Err(bad(format!("more than {MAX_RECORDS} records")));
        }
        out.push(parse_record(&mut r)?);
    }
    Ok(out)
}

/// One JSON record, read with every member name checked for repetition
/// (section 4.10) and the content keyed by its type name.
struct JsonRecord {
    recnum: u64,
    index: u16,
    digest: [u8; 48],
    content: CelContent,
}

#[derive(serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct JsonDigest {
    #[serde(rename = "hashAlg")]
    hash_alg: String,
    digest: String,
}

impl<'de> serde::Deserialize<'de> for JsonRecord {
    fn deserialize<D: serde::Deserializer<'de>>(d: D) -> std::result::Result<Self, D::Error> {
        struct V;
        impl<'de> serde::de::Visitor<'de> for V {
            type Value = JsonRecord;
            fn expecting(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                f.write_str("a CEL record")
            }
            fn visit_map<A: serde::de::MapAccess<'de>>(
                self,
                mut map: A,
            ) -> std::result::Result<JsonRecord, A::Error> {
                use serde::de::Error;
                let mut recnum = None;
                let mut index = None;
                let mut digest = None;
                let mut content = None;
                while let Some(key) = map.next_key::<String>()? {
                    match key.as_str() {
                        "recnum" => {
                            if recnum.replace(map.next_value::<u64>()?).is_some() {
                                return Err(A::Error::custom("duplicate member recnum"));
                            }
                        }
                        "pcr" => {
                            let v = map.next_value::<u64>()?;
                            let v = u16::try_from(v)
                                .map_err(|_| A::Error::custom("pcr out of range"))?;
                            if index.replace(v).is_some() {
                                return Err(A::Error::custom("duplicate member pcr"));
                            }
                        }
                        "digests" => {
                            let list = map.next_value::<Vec<JsonDigest>>()?;
                            let [entry] = list.as_slice() else {
                                return Err(A::Error::custom("exactly one digest"));
                            };
                            if entry.hash_alg != "sha384" {
                                return Err(A::Error::custom("digest algorithm is not sha384"));
                            }
                            let bytes = hex::decode(&entry.digest)
                                .map_err(|e| A::Error::custom(format!("digest: {e}")))?;
                            let d: [u8; 48] = bytes
                                .try_into()
                                .map_err(|_| A::Error::custom("digest is not 48 bytes"))?;
                            if digest.replace(d).is_some() {
                                return Err(A::Error::custom("duplicate member digests"));
                            }
                        }
                        name => {
                            let value = map.next_value::<String>()?;
                            let c = if name == CEL_CONTENT_NAME_CVM {
                                let bytes = hex::decode(&value)
                                    .map_err(|e| A::Error::custom(format!("cvm content: {e}")))?;
                                if bytes.len() > MAX_CONTENT {
                                    return Err(A::Error::custom("content too large"));
                                }
                                CelContent::Cvm(bytes)
                            } else {
                                let content_type = match name {
                                    "cel" => 4,
                                    "pcclient_std" => 5,
                                    "ima_template" => 7,
                                    "ima_tlv" => 8,
                                    "systemd" => 9,
                                    other => {
                                        return Err(A::Error::custom(format!(
                                            "unknown content type {other:?}"
                                        )))
                                    }
                                };
                                CelContent::Other { content_type }
                            };
                            if content.replace(c).is_some() {
                                return Err(A::Error::custom("a record carries one content"));
                            }
                        }
                    }
                }
                Ok(JsonRecord {
                    recnum: recnum.ok_or_else(|| A::Error::missing_field("recnum"))?,
                    index: index.ok_or_else(|| A::Error::missing_field("pcr"))?,
                    digest: digest.ok_or_else(|| A::Error::missing_field("digests"))?,
                    content: content.ok_or_else(|| A::Error::custom("no content"))?,
                })
            }
        }
        d.deserialize_map(V)
    }
}

/// A `tcg-cel-json` log: a JSON array of records
/// `{"recnum", "pcr", "digests": [{"hashAlg": "sha384", "digest": hex}], "<type name>": hex}`.
pub fn parse_json(data: &[u8]) -> Result<Vec<CelRecord>> {
    let records: Vec<JsonRecord> =
        serde_json::from_slice(data).map_err(|e| bad(format!("CEL JSON: {e}")))?;
    if records.len() > MAX_RECORDS {
        return Err(bad(format!("more than {MAX_RECORDS} records")));
    }
    Ok(records
        .into_iter()
        .map(|r| CelRecord {
            recnum: r.recnum,
            index: r.index,
            digest: r.digest,
            content: r.content,
        })
        .collect())
}

/// The dstack runtime log (section 4.8): an array of
/// `{imr, event_type, digest, event, event_payload}`; each digest must
/// reproduce from the record (version 1 or version 2 rule) before it counts.
pub fn parse_dstack_json(data: &[u8]) -> Result<Vec<CelRecord>> {
    #[derive(serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    struct Ev {
        imr: u16,
        event_type: u32,
        digest: String,
        event: String,
        event_payload: String,
    }
    let events: Vec<Ev> =
        serde_json::from_slice(data).map_err(|e| bad(format!("dstack log: {e}")))?;
    if events.len() > MAX_RECORDS {
        return Err(bad(format!("more than {MAX_RECORDS} records")));
    }
    let mut out = Vec::with_capacity(events.len());
    for (i, ev) in events.into_iter().enumerate() {
        let digest =
            digest48(&hex::decode(&ev.digest).map_err(|e| bad(format!("dstack digest: {e}")))?)?;
        let payload = hex::decode(&ev.event_payload)
            .map_err(|e| bad(format!("dstack event_payload: {e}")))?;
        if payload.len() > MAX_CONTENT {
            return Err(bad("dstack log: payload too large"));
        }
        let v1 = {
            let mut h = Sha384::new();
            h.update(ev.event_type.to_le_bytes());
            h.update(b":");
            h.update(ev.event.as_bytes());
            h.update(b":");
            h.update(&payload);
            <[u8; 48]>::from(h.finalize())
        };
        let v2 = {
            // JCS (RFC 8785): members in code point order, no whitespace.
            let jcs = format!(
                "{{\"name\":{},\"payload\":{},\"type\":{}}}",
                serde_json::to_string(&ev.event).map_err(|e| bad(e.to_string()))?,
                serde_json::to_string(&ev.event_payload.to_lowercase())
                    .map_err(|e| bad(e.to_string()))?,
                ev.event_type
            );
            <[u8; 48]>::from(Sha384::digest(jcs.as_bytes()))
        };
        if !crate::utils::constant_time_eq(&digest, &v1)
            && !crate::utils::constant_time_eq(&digest, &v2)
        {
            return Err(bad(format!(
                "dstack record {i} ({:?}): digest does not reproduce from the record",
                ev.event
            )));
        }
        out.push(CelRecord {
            recnum: i as u64,
            index: ev.imr,
            digest,
            content: CelContent::Other { content_type: 0 },
        });
    }
    Ok(out)
}

/// What a replay established for one register.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SlotReplay {
    pub value: [u8; 48],
    pub records: u64,
    /// From the slot's claim record (workload slots).
    pub claim: Option<(String, String)>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Replay {
    pub slots: BTreeMap<u16, SlotReplay>,
    /// `content_digest` of an `ats`/`boot` record at record 0, when present.
    pub boot_digest: Option<[u8; 48]>,
}

/// Replay records in order from `initial(index)`. `recnum` must run from 0
/// without gaps; every `cvm` digest must bind its recnum, index and content.
/// With `workload_rules`, only `cvm` records are accepted and slots from [`FIRST_WORKLOAD_SLOT`] up must open with
/// a claim record and take no second one (section 4.9).
pub fn replay(
    records: &[CelRecord],
    initial: impl Fn(u16) -> Option<[u8; 48]>,
    workload_rules: bool,
) -> Result<Replay> {
    let mut slots: BTreeMap<u16, SlotReplay> = BTreeMap::new();
    let mut boot_digest = None;
    for (pos, rec) in records.iter().enumerate() {
        if rec.recnum != pos as u64 {
            return Err(bad(format!(
                "record {pos} carries recnum {}; records run from 0 without gaps",
                rec.recnum
            )));
        }
        let event = match &rec.content {
            CelContent::Cvm(bytes) => {
                if !crate::utils::constant_time_eq(
                    &record_digest(rec.recnum, rec.index, bytes),
                    &rec.digest,
                ) {
                    return Err(bad(format!(
                        "record {pos}: digest does not reproduce from the content"
                    )));
                }
                Some(parse_cvm_event(bytes)?)
            }
            CelContent::Other { .. } if workload_rules => {
                return Err(bad(format!(
                    "record {pos}: commitment logs require cvm content to authenticate ordering"
                )));
            }
            CelContent::Other { .. } => None,
        };
        let slot = match slots.get_mut(&rec.index) {
            Some(s) => s,
            None => {
                let value = initial(rec.index).ok_or_else(|| {
                    bad(format!(
                        "record {pos}: register {} is not on this platform",
                        rec.index
                    ))
                })?;
                slots.entry(rec.index).or_insert(SlotReplay {
                    value,
                    records: 0,
                    claim: None,
                })
            }
        };
        let ats_op = event
            .as_ref()
            .filter(|e| e.domain == DOMAIN_ATS)
            .map(|e| e.operation.as_str());
        match ats_op {
            Some(op) if op == OP_BOOT => {
                if pos != 0 || rec.index != u16::from(BOOT_SLOT) {
                    return Err(bad(format!(
                        "record {pos}: a boot record is only record 0 into slot {BOOT_SLOT}"
                    )));
                }
                boot_digest = Some(event.as_ref().unwrap().content_digest);
            }
            Some(op) if op == OP_CLAIM => {
                let e = event.as_ref().unwrap();
                if !workload_rules || rec.index < u16::from(FIRST_WORKLOAD_SLOT) {
                    return Err(bad(format!(
                        "record {pos}: a claim record outside a workload slot"
                    )));
                }
                if slot.records != 0 {
                    return Err(bad(format!(
                        "record {pos}: slot {} is already claimed",
                        rec.index
                    )));
                }
                let body = e
                    .content
                    .as_deref()
                    .ok_or_else(|| bad(format!("record {pos}: claim record without a body")))?;
                let body_digest = <[u8; 48]>::from(Sha384::digest(body));
                if !crate::utils::constant_time_eq(&body_digest, &e.content_digest) {
                    return Err(bad(format!("record {pos}: claim content_digest mismatch")));
                }
                slot.claim = Some(parse_claim_body(body)?);
            }
            _ => {
                if workload_rules
                    && rec.index >= u16::from(FIRST_WORKLOAD_SLOT)
                    && slot.records == 0
                {
                    return Err(bad(format!(
                        "record {pos}: extend into unclaimed slot {}",
                        rec.index
                    )));
                }
            }
        }
        slot.value = extend(&slot.value, &rec.digest);
        slot.records += 1;
    }
    Ok(Replay { slots, boot_digest })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::profile::registers::{cel_record, event_content, genesis, SEED};

    fn vectors() -> serde_json::Value {
        serde_json::from_str(include_str!(
            "../../../../docs/design/vectors/cvm_profile_vectors.json"
        ))
        .unwrap()
    }

    fn hexv(v: &serde_json::Value, k: &str) -> Vec<u8> {
        hex::decode(v[k].as_str().unwrap()).unwrap()
    }

    #[test]
    fn the_appendix_b_records_parse_and_replay() {
        let v = vectors();
        let boot = hexv(&v, "boot_cel_record");
        let claim = hexv(&v, "claim_cel_record");
        let log = [boot.clone(), claim.clone()].concat();
        let records = parse_cbor(&log).unwrap();
        assert_eq!(records.len(), 2);
        assert_eq!(records[0].recnum, 0);
        assert_eq!(records[0].index, 3);
        assert_eq!(records[0].digest.to_vec(), hexv(&v, "boot_digest"));
        assert_eq!(
            records[0].content,
            CelContent::Cvm(hexv(&v, "boot_content"))
        );
        assert_eq!(records[1].index, 4);
        assert_eq!(
            records[1].content,
            CelContent::Cvm(hexv(&v, "claim_content"))
        );

        let out = replay(&records, |i| Some(genesis(i as u8, &SEED)), true).unwrap();
        assert_eq!(out.slots[&3].value.to_vec(), hexv(&v, "boot_r3"));
        assert_eq!(out.slots[&4].value.to_vec(), hexv(&v, "claim_r4"));
        assert_eq!(
            out.slots[&4].claim,
            Some(("c8s".to_string(), "workload".to_string()))
        );
        let bootseed = hexv(&v, "bootseed");
        assert_eq!(
            out.boot_digest.unwrap(),
            <[u8; 48]>::from(Sha384::digest(&bootseed))
        );

        // The JSON form carries the same records.
        let json = serde_json::to_vec(&serde_json::json!([
            {"recnum": 0, "pcr": 3, "digests": [{"hashAlg": "sha384", "digest": v["boot_digest"]}], "cvm": v["boot_content"]},
            {"recnum": 1, "pcr": 4, "digests": [{"hashAlg": "sha384", "digest": v["claim_digest"]}], "cvm": v["claim_content"]}
        ]))
        .unwrap();
        assert_eq!(parse_json(&json).unwrap(), records);
        // a repeated member name is refused, whichever value comes last
        let dup = format!(
            "[{{\"recnum\": 0, \"recnum\": 0, \"pcr\": 3, \"digests\": [{{\"hashAlg\": \"sha384\", \"digest\": \"{}\"}}], \"cvm\": \"{}\"}}]",
            v["boot_digest"].as_str().unwrap(),
            v["boot_content"].as_str().unwrap()
        );
        assert!(parse_json(dup.as_bytes()).is_err());
    }

    #[test]
    fn replay_refuses_gaps_forged_digests_and_slot_misuse() {
        let v = vectors();
        let boot_content = hexv(&v, "boot_content");
        let claim_content = hexv(&v, "claim_content");
        let record = |n, i, c: &[u8]| cel_record(n, i, &record_digest(n, u16::from(i), c), c);
        let init = |i: u16| Some(genesis(i as u8, &SEED));

        // recnum gap
        let log = [record(0, 3, &boot_content), record(2, 4, &claim_content)].concat();
        assert!(replay(&parse_cbor(&log).unwrap(), init, true).is_err());
        // a digest that does not reproduce from the content
        let log = cel_record(0, 3, &[9u8; 48], &boot_content);
        assert!(replay(&parse_cbor(&log).unwrap(), init, true).is_err());
        // an extend into slot 4 before its claim
        let extend_content = event_content("c8s", "start-container", &[1u8; 48], None);
        let log = record(0, 4, &extend_content);
        assert!(replay(&parse_cbor(&log).unwrap(), init, true).is_err());
        // a second claim on an open slot
        let log = [record(0, 4, &claim_content), record(1, 4, &claim_content)].concat();
        assert!(replay(&parse_cbor(&log).unwrap(), init, true).is_err());
        // a boot record into a workload slot
        let log = record(0, 4, &boot_content);
        assert!(replay(&parse_cbor(&log).unwrap(), init, true).is_err());
        // a boot record after record 0
        let log = [record(0, 4, &claim_content), record(1, 3, &boot_content)].concat();
        assert!(replay(&parse_cbor(&log).unwrap(), init, true).is_err());
        // a register the platform does not have
        let log = record(0, 16, &extend_content);
        assert!(replay(
            &parse_cbor(&log).unwrap(),
            |i| (i < 16).then(|| genesis(i as u8, &SEED)),
            true
        )
        .is_err());
        // without workload rules (TDX), slot 3 replays from zero
        let log = record(0, 3, &extend_content);
        let out = replay(
            &parse_cbor(&log).unwrap(),
            |i| (i < 4).then_some([0u8; 48]),
            false,
        )
        .unwrap();
        assert_eq!(
            out.slots[&3].value,
            extend(&[0u8; 48], &record_digest(0, 3, &extend_content))
        );
    }

    #[test]
    fn cross_register_reordering_cannot_preserve_the_commitment() {
        use crate::profile::registers::{boot_record, claim_record, commit, REG_COUNT};
        let record = |n, i, c: Vec<u8>| cel_record(n, i, &record_digest(n, u16::from(i), &c), &c);
        let log = [
            record(0, 3, boot_record(&[7; 32])),
            record(1, 4, claim_record("c8s", "workload-a").unwrap()),
            record(2, 5, claim_record("c8s", "workload-b").unwrap()),
            record(
                3,
                4,
                event_content("c8s", "start-container", &[1; 48], None),
            ),
            record(
                4,
                5,
                event_content("c8s", "start-container", &[2; 48], None),
            ),
        ]
        .concat();
        let records = parse_cbor(&log).unwrap();
        let init = |i: u16| (i < REG_COUNT as u16).then(|| genesis(i as u8, &SEED));
        let bank = |out: Replay| {
            let mut regs = std::array::from_fn::<_, REG_COUNT, _>(|i| genesis(i as u8, &SEED));
            for (i, slot) in out.slots {
                regs[usize::from(i)] = slot.value;
            }
            regs
        };
        let original = bank(replay(&records, init, true).unwrap());
        let mut reordered = records.clone();
        reordered.swap(3, 4);
        reordered[3].recnum = 3;
        reordered[4].recnum = 4;
        // Renumbering two otherwise unchanged records fails digest validation.
        assert!(replay(&reordered, init, true)
            .unwrap_err()
            .to_string()
            .contains("digest"));
        // Recomputing the two digests gives a valid log, but changes the
        // committed registers, so it cannot match the original signed report.
        for r in &mut reordered[3..] {
            let CelContent::Cvm(content) = &r.content else {
                panic!()
            };
            r.digest = record_digest(r.recnum, r.index, content);
        }
        let changed = bank(replay(&reordered, init, true).unwrap());
        assert_ne!(
            commit(&original, 5, &[3; 64]),
            commit(&changed, 5, &[3; 64])
        );
        // Relabeling the records as an uninterpreted CEL type must not bypass
        // the position binding in an SNP commitment log.
        let mut opaque = records.clone();
        opaque.swap(3, 4);
        for (n, r) in opaque.iter_mut().enumerate().skip(3) {
            r.recnum = n as u64;
            r.content = CelContent::Other { content_type: 201 };
        }
        assert!(replay(&opaque, init, true)
            .unwrap_err()
            .to_string()
            .contains("require cvm"));
        // Moving a record to another register is authenticated too.
        let mut moved = records;
        moved[3].index = 5;
        assert!(replay(&moved, init, true)
            .unwrap_err()
            .to_string()
            .contains("digest"));
    }

    #[test]
    fn cbor_is_deterministic_or_rejected() {
        let v = vectors();
        let boot = hexv(&v, "boot_cel_record");
        // recnum 0 encoded as 0x18 0x00 (non-minimal) in place of 0x00
        let mut non_minimal = boot.clone();
        assert_eq!(non_minimal[2], 0x00);
        non_minimal.splice(2..3, [0x18, 0x00]);
        assert!(parse_cbor(&non_minimal).is_err());
        // an indefinite-length map head
        let mut indefinite = boot.clone();
        indefinite[0] = 0xbf;
        assert!(parse_cbor(&indefinite).is_err());
        // trailing garbage after the last record
        let mut trailing = boot.clone();
        trailing.push(0xa0);
        assert!(parse_cbor(&trailing).is_err());
        // truncated
        assert!(parse_cbor(&boot[..boot.len() - 1]).is_err());
    }

    #[test]
    fn dstack_records_reproduce_their_digests() {
        let payload = hex::encode(b"sha256:abc");
        let v1 = {
            let mut h = Sha384::new();
            h.update(134217729u32.to_le_bytes());
            h.update(b":compose-hash:");
            h.update(b"sha256:abc");
            hex::encode(h.finalize())
        };
        let v2 = hex::encode(Sha384::digest(
            format!("{{\"name\":\"key-provider\",\"payload\":\"{payload}\",\"type\":134217729}}")
                .as_bytes(),
        ));
        let log = serde_json::to_vec(&serde_json::json!([
            {"imr": 3, "event_type": 134217729, "digest": v1, "event": "compose-hash", "event_payload": payload},
            {"imr": 3, "event_type": 134217729, "digest": v2, "event": "key-provider", "event_payload": payload}
        ]))
        .unwrap();
        let records = parse_dstack_json(&log).unwrap();
        assert_eq!(records.len(), 2);
        let out = replay(&records, |i| (i < 4).then_some([0u8; 48]), false).unwrap();
        let mut r = [0u8; 48];
        for rec in &records {
            r = extend(&r, &rec.digest);
        }
        assert_eq!(out.slots[&3].value, r);
        // a digest that is neither rule fails
        let forged = serde_json::to_vec(&serde_json::json!([
            {"imr": 3, "event_type": 134217729, "digest": hex::encode([7u8; 48]), "event": "compose-hash", "event_payload": payload}
        ]))
        .unwrap();
        assert!(parse_dstack_json(&forged).is_err());
    }
}
