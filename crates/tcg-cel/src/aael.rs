//! Confidential Containers attestation-agent event log (AAEL) entries.
//!
//! Since guest-components v0.15.0 the agent appends one `TCG_PCR_EVENT2`
//! record per entry to the CCEL it reports: an EV_EVENT_TAG event whose data
//! is a `TCG_PCClientTaggedEvent` with tag 0x4141454C (the bytes `LEAA` on
//! the wire) around the UTF-8 text `domain operation content`, and whose one
//! digest is the hash of that whole tagged event. On TDX the default register
//! is RTMR 3 (MrIndex 4). The line-based format of earlier releases is not read.

use crate::error::{Error, Result};
use crate::model::{Content, Record};
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
/// not tagged AAEL.
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

/// Every AAEL entry in `records`, with its position.
pub fn entries(records: &[Record]) -> Result<Vec<(usize, Entry)>> {
    records
        .iter()
        .enumerate()
        .filter_map(|(i, r)| entry(r, i).map(|e| e.map(|e| (i, e))))
        .collect()
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
