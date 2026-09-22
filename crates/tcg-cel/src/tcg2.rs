//! TCG2 crypto-agile logs (PC Client PFP section 10.2): a `TCG_PCClientPCREvent`
//! header carrying the Spec ID event, then `TCG_PCR_EVENT2` records. This is
//! a TPM's firmware log, the TDX CCEL, and the CCEL with Confidential
//! Containers attestation-agent records appended.

use crate::error::{Error, Result};
use crate::model::{
    renumber, Content, Digest, EventType, Index, Record, MAX_BYTES, MAX_DIGESTS, MAX_DIGEST_LEN,
    MAX_RECORDS,
};
use crate::pcclient::EV_NO_ACTION;
use crate::HashAlg;

const SPEC_ID_SIGNATURE: &[u8; 16] = b"Spec ID Event03\0";

/// The fixed header guest-components writes before its records when the
/// platform has no CCEL (`EL_HEADER` in attester/src/utils.rs): a zero
/// signature, then SHA-256, SHA-384 and SM3 digest sizes.
pub const COCO_SYNTHETIC_HEADER: [u8; 73] = [
    0x00, 0x00, 0x00, 0x00, 0x03, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x29, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x03, 0x00, 0x00, 0x00, 0x0B, 0x00, 0x20, 0x00,
    0x0C, 0x00, 0x30, 0x00, 0x12, 0x00, 0x20, 0x00, 0x00,
];

/// The `TCG_EfiSpecIdEvent` (PFP 10.4.5.1).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SpecId {
    pub platform_class: u32,
    pub family_version_minor: u8,
    pub family_version_major: u8,
    pub spec_revision: u8,
    pub uintn_size: u8,
    /// `digestSizes`: each bank the log records and its digest length.
    pub algorithms: Vec<(HashAlg, u16)>,
    pub vendor_info: Vec<u8>,
}

/// One event: the header or a `TCG_PCR_EVENT2`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Tcg2Event {
    /// The PCR, or the CC measurement register index (MrIndex) in a CCEL.
    pub index: u32,
    pub event_type: u32,
    pub digests: Vec<Digest>,
    pub event_data: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Tcg2Log {
    /// The `TCG_PCClientPCREvent` header: EV_NO_ACTION, a zero SHA-1 digest,
    /// the Spec ID event as data.
    pub header: Tcg2Event,
    pub spec_id: SpecId,
    pub events: Vec<Tcg2Event>,
}

fn err(offset: usize, reason: impl Into<String>) -> Error {
    Error::Tcg2 {
        offset,
        reason: reason.into(),
    }
}

fn u32_at(data: &[u8], at: usize) -> Result<u32> {
    at.checked_add(4)
        .and_then(|end| data.get(at..end))
        .map(|b| u32::from_le_bytes(b.try_into().unwrap()))
        .ok_or_else(|| err(at, "truncated"))
}

fn u16_at(data: &[u8], at: usize) -> Result<u16> {
    at.checked_add(2)
        .and_then(|end| data.get(at..end))
        .map(|b| u16::from_le_bytes(b.try_into().unwrap()))
        .ok_or_else(|| err(at, "truncated"))
}

fn bytes_at(data: &[u8], at: usize, n: usize) -> Result<&[u8]> {
    at.checked_add(n)
        .and_then(|end| data.get(at..end))
        .ok_or_else(|| err(at, "truncated"))
}

fn parse_spec_id(d: &[u8], base: usize) -> Result<SpecId> {
    let at = |o: usize| base + o;
    let fixed = bytes_at(d, 0, 28).map_err(|_| err(base, "Spec ID event too short"))?;
    let n = u32::from_le_bytes(fixed[24..28].try_into().unwrap()) as usize;
    if n == 0 || n > MAX_DIGESTS {
        return Err(err(
            at(24),
            format!("{n} algorithms; 1 to {MAX_DIGESTS} allowed"),
        ));
    }
    let mut algorithms = Vec::with_capacity(n);
    for i in 0..n {
        let o = 28 + 4 * i;
        let alg = HashAlg(u16_at(d, o).map_err(|_| err(at(o), "truncated digestSizes"))?);
        let size = u16_at(d, o + 2).map_err(|_| err(at(o), "truncated digestSizes"))?;
        let ok = match alg.digest_size() {
            Some(s) => usize::from(size) == s,
            None => (1..=MAX_DIGEST_LEN).contains(&usize::from(size)),
        };
        if !ok {
            return Err(err(
                at(o),
                format!("{alg} declared with {size}-byte digests"),
            ));
        }
        if algorithms.iter().any(|&(a, _)| a == alg) {
            return Err(err(at(o), format!("{alg} declared twice")));
        }
        algorithms.push((alg, size));
    }
    let o = 28 + 4 * n;
    let vendor_len = *d
        .get(o)
        .ok_or_else(|| err(at(o), "truncated vendorInfoSize"))? as usize;
    let vendor_info = bytes_at(d, o + 1, vendor_len)
        .map_err(|_| err(at(o), "truncated vendorInfo"))?
        .to_vec();
    if o + 1 + vendor_len != d.len() {
        return Err(err(at(o), "Spec ID event size disagrees with its contents"));
    }
    Ok(SpecId {
        platform_class: u32::from_le_bytes(fixed[16..20].try_into().unwrap()),
        family_version_minor: fixed[20],
        family_version_major: fixed[21],
        spec_revision: fixed[22],
        uintn_size: fixed[23],
        algorithms,
        vendor_info,
    })
}

/// Parse a log whole. The header must be the Spec ID event (any index, as
/// TDVF records it at MrIndex 1) or guest-components' synthetic header;
/// every record's digests must be in banks the header declares; the data
/// ends at the last record or at a filler tail of one repeated byte, 0x00 or
/// 0xFF (the unused part of an ACPI table, or the agent's end marker).
/// Anything else, including a truncated record, is an error: a log that
/// cannot be replayed whole is no evidence.
pub fn parse(data: &[u8]) -> Result<Tcg2Log> {
    let index = u32_at(data, 0)?;
    let event_type = u32_at(data, 4)?;
    let sha1 = bytes_at(data, 8, 20)?;
    let size = u32_at(data, 28)? as usize;
    let spec = bytes_at(data, 32, size)?;
    if event_type != EV_NO_ACTION {
        return Err(err(4, "the header is not an EV_NO_ACTION event"));
    }
    if sha1.iter().any(|&b| b != 0) {
        return Err(err(8, "the header's SHA-1 digest is not zero"));
    }
    let header_len = 32 + size;
    if !spec.starts_with(SPEC_ID_SIGNATURE) && data[..header_len] != COCO_SYNTHETIC_HEADER[..] {
        return Err(err(32, "the header is not the Spec ID event"));
    }
    let spec_id = parse_spec_id(spec, 32)?;
    let header = Tcg2Event {
        index,
        event_type,
        digests: vec![Digest {
            alg: HashAlg::SHA1,
            value: sha1.to_vec(),
        }],
        event_data: spec.to_vec(),
    };

    let mut events = Vec::new();
    let mut offset = header_len;
    while offset < data.len() {
        let rest = &data[offset..];
        if (rest[0] == 0x00 || rest[0] == 0xFF) && rest.iter().all(|&b| b == rest[0]) {
            break;
        }
        if events.len() == MAX_RECORDS {
            return Err(err(offset, format!("more than {MAX_RECORDS} events")));
        }
        let index = u32_at(data, offset)?;
        let event_type = u32_at(data, offset + 4)?;
        let count = u32_at(data, offset + 8)? as usize;
        if count == 0 || count > spec_id.algorithms.len() {
            return Err(err(
                offset + 8,
                format!(
                    "{count} digests; the header declares {}",
                    spec_id.algorithms.len()
                ),
            ));
        }
        let mut pos = offset + 12;
        let mut digests: Vec<Digest> = Vec::with_capacity(count);
        for _ in 0..count {
            let alg = HashAlg(u16_at(data, pos)?);
            let size = spec_id
                .algorithms
                .iter()
                .find(|&&(a, _)| a == alg)
                .map(|&(_, s)| usize::from(s))
                .ok_or_else(|| err(pos, format!("{alg} is not declared by the header")))?;
            if digests.iter().any(|d| d.alg == alg) {
                return Err(err(pos, format!("two {alg} digests")));
            }
            let value = bytes_at(data, pos + 2, size)?.to_vec();
            digests.push(Digest { alg, value });
            pos += 2 + size;
        }
        let size = u32_at(data, pos)? as usize;
        if size > MAX_BYTES {
            return Err(err(pos, format!("event data of {size} bytes")));
        }
        let event_data = bytes_at(data, pos + 4, size)?.to_vec();
        events.push(Tcg2Event {
            index,
            event_type,
            digests,
            event_data,
        });
        offset = pos + 4 + size;
    }
    Ok(Tcg2Log {
        header,
        spec_id,
        events,
    })
}

/// How a log's index becomes a CEL index.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IndexMap {
    /// The log's index is a PCR (a TPM log).
    Pcr,
    /// The log's index is a UEFI CC measurement register index (MrIndex) and
    /// the CEL `pcr` is the TDX RTMR ordinal: MrIndex 1 to 4 become 0 to 3.
    /// MrIndex 0 is MRTD, which no event extends; records there (the header
    /// of older TDVF builds, and informative events some firmware logs) are
    /// left out, as dstack's CCEL replay leaves them.
    CcMrToRtmr,
}

impl IndexMap {
    /// `Ok(None)` for a record the mapping leaves out.
    fn map(self, index: u32) -> std::result::Result<Option<Index>, ()> {
        match self {
            IndexMap::Pcr => Some(Index::Pcr(index))
                .filter(|i| i.is_valid())
                .map(Some)
                .ok_or(()),
            IndexMap::CcMrToRtmr => match index {
                0 => Ok(None),
                1..=4 => Ok(Some(Index::Pcr(index - 1))),
                _ => Err(()),
            },
        }
    }
}

impl Tcg2Log {
    /// The CEL form (CEL v1.1 section 5.1.7): the header and every event the
    /// mapping keeps, as `pcclient_std` records with all their digests,
    /// numbered per index.
    pub fn to_cel(&self, map: IndexMap) -> Result<Vec<Record>> {
        let mut out = Vec::with_capacity(1 + self.events.len());
        for (i, ev) in std::iter::once(&self.header)
            .chain(&self.events)
            .enumerate()
        {
            let index = match map.map(ev.index) {
                Ok(Some(index)) => index,
                Ok(None) => continue,
                Err(()) => {
                    return Err(crate::error::record(
                        i,
                        format!("index {} has no {map:?} mapping", ev.index),
                    ))
                }
            };
            out.push(Record {
                recnum: 0,
                index,
                digests: ev.digests.clone(),
                content: Content::PcClientStd {
                    event_type: EventType::Code(ev.event_type),
                    event_data: ev.event_data.clone(),
                },
            });
        }
        renumber(&mut out);
        for (i, r) in out.iter().enumerate() {
            r.validate(i)?;
        }
        Ok(out)
    }
}

/// Parse a TCG2 log and convert it to CEL records.
pub fn to_cel(data: &[u8], map: IndexMap) -> Result<Vec<Record>> {
    parse(data)?.to_cel(map)
}
