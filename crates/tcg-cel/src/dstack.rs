//! dstack's event log as its guest agent returns it (the GetQuote
//! `event_log` string): a JSON array of
//! `{imr, event_type, digest, event, event_payload, version?, preimage?}` with
//! hex byte strings, where `imr` is the TDX RTMR ordinal.
//!
//! Boot events come from the CCEL and keep their TCG digest; each becomes a
//! `pcclient_std` record of its event type and payload (dstack strips most
//! payloads, and its names for boot events are its own labels, which are not
//! carried). Runtime events have event type 0x08000001 and a digest dstack
//! hashes from the event's fields, so it is recomputed here: version 1 is
//! `SHA-384(u32le(type) || ":" || name || ":" || payload)`, version 2 is
//! `SHA-384` of the RFC 8785 object `{"name", "payload": hex, "type"}`, which
//! the event also carries as `preimage`. A runtime event becomes a
//! `pcclient_std` record whose `event_data` is that hash input, so the record
//! verifies on its own and [`runtime_event`] recovers the fields.

use crate::error::{Error, Result};
use crate::json::{hex_bytes, narrow, string, text, uint, Members, J};
use crate::model::{renumber, Content, Digest, EventType, Index, Record, MAX_BYTES, MAX_RECORDS};
use crate::HashAlg;

/// The event type of every dstack runtime event.
pub const RUNTIME_EVENT_TYPE: u32 = 0x0800_0001;

/// A runtime event's fields.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RuntimeEvent {
    /// 1 or 2: how the digest is computed.
    pub version: u32,
    pub name: String,
    pub payload: Vec<u8>,
}

impl RuntimeEvent {
    /// The bytes dstack hashes for this event.
    pub fn preimage(&self) -> Vec<u8> {
        if self.version == 2 {
            let mut s = String::from("{\"name\":");
            string(&self.name, &mut s);
            s.push_str(&format!(
                ",\"payload\":\"{}\",\"type\":{RUNTIME_EVENT_TYPE}}}",
                hex::encode(&self.payload)
            ));
            s.into_bytes()
        } else {
            let mut v = RUNTIME_EVENT_TYPE.to_le_bytes().to_vec();
            v.push(b':');
            v.extend_from_slice(self.name.as_bytes());
            v.push(b':');
            v.extend_from_slice(&self.payload);
            v
        }
    }
}

fn err(position: usize, reason: impl Into<String>) -> Error {
    Error::Dstack {
        position,
        reason: reason.into(),
    }
}

/// Convert a dstack event log to CEL records, recomputing every runtime
/// event's digest. A version 1 event whose name contains `:` is refused,
/// since its hash input would not split back into one name.
pub fn to_cel(data: &[u8]) -> Result<Vec<Record>> {
    let J::Arr(items) = crate::json::parse(data).map_err(|e| err(0, e.to_string()))? else {
        return Err(err(0, "the log is not a JSON array"));
    };
    if items.len() > MAX_RECORDS {
        return Err(err(items.len(), format!("more than {MAX_RECORDS} events")));
    }
    let mut out = Vec::with_capacity(items.len());
    for (position, item) in items.iter().enumerate() {
        out.push(event(item, position).map_err(|e| match e {
            Error::Json(reason) => err(position, reason),
            other => other,
        })?);
    }
    renumber(&mut out);
    for (i, r) in out.iter().enumerate() {
        r.validate(i)?;
    }
    Ok(out)
}

fn event(v: &J, position: usize) -> Result<Record> {
    let mut m = Members::new(v, "event".into())?;
    let imr: u32 = narrow(m.req("imr")?, "imr")?;
    if imr > 3 {
        return Err(err(position, format!("imr {imr} is not an RTMR")));
    }
    let event_type: u32 = narrow(m.req("event_type")?, "event_type")?;
    let digest = hex_bytes(m.req("digest")?, "digest", 48)?;
    if digest.len() != 48 {
        return Err(err(position, "digest is not 48 bytes"));
    }
    let name = text(m.req("event")?, "event")?.to_string();
    let payload = hex_bytes(m.req("event_payload")?, "event_payload", MAX_BYTES)?;
    let version = match m.take("version") {
        None => 1,
        Some(v) => match uint(v, "version")? {
            n @ (1 | 2) => n as u32,
            n => return Err(err(position, format!("version {n}"))),
        },
    };
    let preimage = m
        .take("preimage")
        .map(|p| hex_bytes(p, "preimage", MAX_BYTES + 256))
        .transpose()?;
    m.finish()?;

    let event_data = if event_type == RUNTIME_EVENT_TYPE {
        if version == 1 && name.contains(':') {
            return Err(err(position, "a version 1 event name contains ':'"));
        }
        let ev = RuntimeEvent {
            version,
            name,
            payload,
        };
        let expected = ev.preimage();
        match (version, preimage) {
            (1, None) => {}
            (2, Some(p)) if p == expected => {}
            (2, Some(_)) => return Err(err(position, "preimage is not the canonical form")),
            (2, None) => return Err(err(position, "a version 2 event carries no preimage")),
            (_, Some(_)) => return Err(err(position, "a version 1 event carries a preimage")),
            _ => unreachable!("version is 1 or 2"),
        }
        if HashAlg::SHA384.hash(&expected).as_deref() != Some(digest.as_slice()) {
            return Err(Error::Digest {
                position,
                reason: format!(
                    "dstack event {:?}: digest does not reproduce from the event",
                    ev.name
                ),
            });
        }
        expected
    } else {
        if version != 1 || preimage.is_some() {
            return Err(err(position, "a boot event carries a version or preimage"));
        }
        payload
    };
    Ok(Record {
        recnum: 0,
        index: Index::Pcr(imr),
        digests: vec![Digest {
            alg: HashAlg::SHA384,
            value: digest,
        }],
        content: Content::PcClientStd {
            event_type: EventType::Code(event_type),
            event_data,
        },
    })
}

/// The runtime event `record` carries, after its SHA-384 digest is checked
/// against the hash input. `None` for a record of any other event type. To
/// list a register's events use [`runtime_events_in`]: the event type lies
/// outside the digest, so a relabeled event is `None` here while the register
/// still replays.
pub fn runtime_event(record: &Record, position: usize) -> Option<Result<RuntimeEvent>> {
    let Content::PcClientStd {
        event_type,
        event_data,
    } = &record.content
    else {
        return None;
    };
    if event_type.code() != Some(RUNTIME_EVENT_TYPE) {
        return None;
    }
    Some(decode_runtime(record, event_data, position))
}

fn decode_runtime(record: &Record, data: &[u8], position: usize) -> Result<RuntimeEvent> {
    let malformed = |reason: &str| Error::Record {
        position,
        reason: format!("dstack runtime event: {reason}"),
    };
    let ev = if data.first() == Some(&b'{') {
        let v = crate::json::parse(data).map_err(|e| malformed(&e.to_string()))?;
        let mut m = Members::new(&v, "preimage".into())?;
        let name = text(m.req("name")?, "name")?.to_string();
        let payload = hex_bytes(m.req("payload")?, "payload", MAX_BYTES)?;
        if uint(m.req("type")?, "type")? != u64::from(RUNTIME_EVENT_TYPE) {
            return Err(malformed("type is not the runtime event type"));
        }
        m.finish()?;
        RuntimeEvent {
            version: 2,
            name,
            payload,
        }
    } else {
        let rest = data
            .strip_prefix(RUNTIME_EVENT_TYPE.to_le_bytes().as_slice())
            .and_then(|r| r.strip_prefix(b":"))
            .ok_or_else(|| malformed("neither a version 1 nor a version 2 hash input"))?;
        let colon = rest
            .iter()
            .position(|&b| b == b':')
            .ok_or_else(|| malformed("no payload separator"))?;
        RuntimeEvent {
            version: 1,
            name: std::str::from_utf8(&rest[..colon])
                .map_err(|_| malformed("name is not UTF-8"))?
                .to_string(),
            payload: rest[colon + 1..].to_vec(),
        }
    };
    if ev.preimage() != data {
        return Err(malformed("hash input is not in canonical form"));
    }
    match record.digest(HashAlg::SHA384) {
        Some(d) if HashAlg::SHA384.hash(data).as_deref() == Some(d) => Ok(ev),
        _ => Err(Error::Digest {
            position,
            reason: format!(
                "dstack event {:?}: SHA-384 digest does not reproduce",
                ev.name
            ),
        }),
    }
}

/// Every runtime event extended into `index` (`Index::Pcr(3)`, RTMR 3, on
/// TDX), with its position. Each measured record naming `index` must be a
/// runtime event whose digest reproduces, so no event can drop out of the list
/// by relabeling while the register still replays.
pub fn runtime_events_in(records: &[Record], index: Index) -> Result<Vec<(usize, RuntimeEvent)>> {
    let mut out = Vec::new();
    for (i, r) in records.iter().enumerate() {
        if r.index != index || !r.is_measured() {
            continue;
        }
        match runtime_event(r, i) {
            Some(e) => out.push((i, e?)),
            None => {
                return Err(Error::Record {
                    position: i,
                    reason: format!("a measured record in {index} is not a dstack runtime event"),
                })
            }
        }
    }
    Ok(out)
}
