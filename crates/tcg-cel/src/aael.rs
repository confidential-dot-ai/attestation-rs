//! Confidential Containers attestation-agent event log (AAEL) entries.
//!
//! Since guest-components v0.15.0 the agent appends one `TCG_PCR_EVENT2`
//! record per entry to the CCEL it reports: an EV_EVENT_TAG event whose data
//! is a `TCG_PCClientTaggedEvent` with tag 0x4141454C (the bytes `LEAA` on
//! the wire) around the UTF-8 text `domain operation content`, and whose one
//! digest is the hash of that whole tagged event. On TDX the default register
//! is RTMR 3 (MrIndex 4). The line-based format of earlier releases is not read.

use crate::error::{Error, Result};
use crate::model::{Content, Index, Record};
use crate::pcclient::EV_EVENT_TAG;

/// `taggedEventID` of an AAEL entry.
pub const AAEL_TAG: u32 = 0x4141_454C;

/// One entry, split at its first two spaces as the agent and Trustee split it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Entry {
    pub domain: String,
    pub operation: String,
    pub content: String,
}

/// The entry `record` carries, after every digest it has in a bank this crate
/// can hash is checked against the tagged event. `None` for a record that is
/// not tagged AAEL. To list a register's entries use [`entries_in`]: a record's
/// event type and tag lie outside its digest, so an entry relabeled as another
/// event is `None` here while the register still replays.
pub fn entry(record: &Record, position: usize) -> Option<Result<Entry>> {
    let Content::PcClientStd {
        event_type,
        event_data,
    } = &record.content
    else {
        return None;
    };
    if event_type.code() != Some(EV_EVENT_TAG) || !event_data.starts_with(&AAEL_TAG.to_le_bytes()) {
        return None;
    }
    Some(decode(record, event_data, position))
}

/// Every entry extended into `index`, with its position. Each measured record
/// naming `index` must be an entry whose digests reproduce, so no entry can
/// drop out of the list by relabeling while the register still replays.
pub fn entries_in(records: &[Record], index: Index) -> Result<Vec<(usize, Entry)>> {
    let mut out = Vec::new();
    for (i, r) in records.iter().enumerate() {
        if r.index != index || !r.is_measured() {
            continue;
        }
        match entry(r, i) {
            Some(e) => out.push((i, e?)),
            None => {
                return Err(Error::Record {
                    position: i,
                    reason: format!("a measured record in {index} is not an AAEL entry"),
                })
            }
        }
    }
    Ok(out)
}

fn decode(record: &Record, data: &[u8], position: usize) -> Result<Entry> {
    let malformed = |reason: &str| Error::Record {
        position,
        reason: format!("AAEL entry: {reason}"),
    };
    let size = data
        .get(4..8)
        .map(|b| u32::from_le_bytes(b.try_into().unwrap()) as usize)
        .ok_or_else(|| malformed("truncated tagged event"))?;
    if data.len() - 8 != size {
        return Err(malformed(
            "taggedEventDataSize disagrees with the event size",
        ));
    }
    let text = std::str::from_utf8(&data[8..]).map_err(|_| malformed("not UTF-8"))?;
    let (domain, rest) = text.split_once(' ').ok_or_else(|| malformed("no domain"))?;
    let (operation, content) = rest
        .split_once(' ')
        .ok_or_else(|| malformed("no operation"))?;
    let mut checked = 0;
    for d in &record.digests {
        if let Some(h) = d.alg.hash(data) {
            if h != d.value {
                return Err(Error::Digest {
                    position,
                    reason: format!("AAEL entry does not reproduce its {} digest", d.alg),
                });
            }
            checked += 1;
        }
    }
    if checked == 0 {
        return Err(Error::Digest {
            position,
            reason: "AAEL entry has no digest in a bank this crate can hash".into(),
        });
    }
    Ok(Entry {
        domain: domain.to_string(),
        operation: operation.to_string(),
        content: content.to_string(),
    })
}
