//! TCG PC Client TCG_PCR_EVENT2 logs (`tpm2-event-log`, and the TDX CCEL,
//! section 4.8): parsing over one digest bank and the PCR replay.

use crate::error::{AttestationError, Result};
use sha2::Digest;

/// TPM_ALG_SHA256, the bank a vTPM quote covers.
pub const TPM_ALG_SHA256: u16 = 0x000B;
/// TPM_ALG_SHA384, the bank the TDX CCEL carries for the RTMRs.
pub const TPM_ALG_SHA384: u16 = 0x000C;
/// EV_NO_ACTION: informative records that are never extended.
pub const EV_NO_ACTION: u32 = 0x0000_0003;
const MAX_DIGESTS: u32 = 16;
const MAX_EVENTS: usize = 65_536;
const MAX_EVENT_DATA: usize = 1 << 20;

fn bad(msg: impl Into<String>) -> AttestationError {
    AttestationError::EventlogIntegrityFailed(msg.into())
}

/// One event with the digest of the requested bank.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Tcg2Event {
    /// The PCR (or CC_EVENT MrIndex) the event names, unconverted.
    pub index: u32,
    pub event_type: u32,
    pub digest: Vec<u8>,
    pub event_data: Vec<u8>,
}

fn le_u32(data: &[u8], at: usize) -> Option<u32> {
    data.get(at..at + 4)
        .map(|b| u32::from_le_bytes(b.try_into().unwrap()))
}

fn le_u16(data: &[u8], at: usize) -> Option<u16> {
    data.get(at..at + 2)
        .map(|b| u16::from_le_bytes(b.try_into().unwrap()))
}

fn digest_size(alg: u16) -> Result<usize> {
    Ok(match alg {
        0x0004 => 20,
        0x000B => 32,
        0x000C => 48,
        0x000D => 64,
        other => return Err(bad(format!("unsupported digest algorithm 0x{other:04X}"))),
    })
}

/// Parse a log: the TCG_PCR_EVENT Spec ID header first (EV_NO_ACTION with
/// the `Spec ID Event03` signature), then TCG_PCR_EVENT2 records to the end of the data or to
/// the filler tail an ACPI table carries (0x00 or 0xFF to the end). Anything
/// else (a truncated record, a record without a digest in `bank`, bytes after
/// the tail) is an error: a log that cannot be replayed whole is no evidence.
pub fn parse(data: &[u8], bank: u16) -> Result<Vec<Tcg2Event>> {
    if data.len() < 32 {
        return Err(bad(format!("TCG2 log too short: {} bytes", data.len())));
    }
    // The header is an EV_NO_ACTION record whose data opens with the Spec ID
    // signature; its index is 0 in a TPM log and 1 in a CCEL.
    if le_u32(data, 4) != Some(EV_NO_ACTION) || !data[32..].starts_with(b"Spec ID Event03\0") {
        return Err(bad("TCG2 log does not start with the Spec ID event"));
    }
    let header_size = le_u32(data, 28).ok_or_else(|| bad("Spec ID event size"))? as usize;
    let mut offset = 32usize
        .checked_add(header_size)
        .filter(|&o| o <= data.len())
        .ok_or_else(|| bad("Spec ID event exceeds the log"))?;
    digest_size(bank)?;
    let truncated = || bad("TCG2 log: truncated record");
    let mut events = Vec::new();
    while offset < data.len() {
        // The unused tail of an ACPI table: one filler byte (0x00 or 0xFF)
        // to the end. Anything else must parse as a record.
        let filler = data[offset];
        if (filler == 0x00 || filler == 0xFF) && data[offset..].iter().all(|&b| b == filler) {
            break;
        }
        let index = le_u32(data, offset).ok_or_else(truncated)?;
        let event_type = le_u32(data, offset + 4).ok_or_else(truncated)?;
        let digest_count = le_u32(data, offset + 8).ok_or_else(truncated)?;
        if digest_count == 0 || digest_count > MAX_DIGESTS {
            return Err(bad(format!("TCG2 log: digest count {digest_count}")));
        }
        let mut pos = offset + 12;
        let mut digest = None;
        for _ in 0..digest_count {
            let alg = le_u16(data, pos).ok_or_else(truncated)?;
            pos += 2;
            let size = digest_size(alg)?;
            let bytes = data.get(pos..pos + size).ok_or_else(truncated)?;
            if alg == bank {
                digest = Some(bytes.to_vec());
            }
            pos += size;
        }
        let size = le_u32(data, pos).ok_or_else(truncated)? as usize;
        pos += 4;
        if size > MAX_EVENT_DATA {
            return Err(bad("TCG2 log: event data too large"));
        }
        let event_data = data.get(pos..pos + size).ok_or_else(truncated)?;
        let digest = digest.ok_or_else(|| {
            bad(format!(
                "TCG2 log: event at offset {offset} carries no digest in bank 0x{bank:04X}"
            ))
        })?;
        if events.len() >= MAX_EVENTS {
            return Err(bad(format!("more than {MAX_EVENTS} events")));
        }
        events.push(Tcg2Event {
            index,
            event_type,
            digest,
            event_data: event_data.to_vec(),
        });
        offset = pos + size;
    }
    Ok(events)
}

/// Replay into the registers the events name: `R = H(R || digest)` from
/// zero, skipping EV_NO_ACTION. `H` is the bank's hash; the digest length
/// selects it.
pub fn replay<const N: usize>(
    events: &[Tcg2Event],
    index_of: impl Fn(u32) -> Option<u16>,
) -> Result<std::collections::BTreeMap<u16, [u8; N]>> {
    let mut regs: std::collections::BTreeMap<u16, [u8; N]> = Default::default();
    for ev in events {
        if ev.event_type == EV_NO_ACTION {
            continue;
        }
        let Some(index) = index_of(ev.index) else {
            continue;
        };
        if ev.digest.len() != N {
            return Err(bad("event digest is not the bank's length"));
        }
        let r = regs.entry(index).or_insert([0u8; N]);
        let next: Vec<u8> = match N {
            32 => {
                let mut h = sha2::Sha256::new();
                h.update(*r);
                h.update(&ev.digest);
                h.finalize().to_vec()
            }
            48 => {
                let mut h = sha2::Sha384::new();
                h.update(*r);
                h.update(&ev.digest);
                h.finalize().to_vec()
            }
            _ => return Err(bad("unsupported register width")),
        };
        r.copy_from_slice(&next);
    }
    Ok(regs)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn spec_id_header() -> Vec<u8> {
        // TCG_PCR_EVENT: pcr(4) type(4) sha1 digest(20) size(4) + data
        let data = b"Spec ID Event03\0";
        let mut v = Vec::new();
        v.extend_from_slice(&0u32.to_le_bytes());
        v.extend_from_slice(&EV_NO_ACTION.to_le_bytes());
        v.extend_from_slice(&[0u8; 20]);
        v.extend_from_slice(&(data.len() as u32).to_le_bytes());
        v.extend_from_slice(data);
        v
    }

    fn event(pcr: u32, event_type: u32, sha256: [u8; 32], data: &[u8]) -> Vec<u8> {
        let mut v = Vec::new();
        v.extend_from_slice(&pcr.to_le_bytes());
        v.extend_from_slice(&event_type.to_le_bytes());
        v.extend_from_slice(&2u32.to_le_bytes());
        v.extend_from_slice(&0x0004u16.to_le_bytes());
        v.extend_from_slice(&[0xAAu8; 20]);
        v.extend_from_slice(&TPM_ALG_SHA256.to_le_bytes());
        v.extend_from_slice(&sha256);
        v.extend_from_slice(&(data.len() as u32).to_le_bytes());
        v.extend_from_slice(data);
        v
    }

    #[test]
    fn a_sha256_log_replays_its_pcrs_and_skips_no_action_events() {
        let log = [
            spec_id_header(),
            event(0, 0x8000_0001, [1u8; 32], b"a"),
            event(0, EV_NO_ACTION, [9u8; 32], b"StartupLocality"),
            event(7, 0x8000_0002, [2u8; 32], b"b"),
            event(0, 0x0000_000D, [3u8; 32], b"c"),
        ]
        .concat();
        let events = parse(&log, TPM_ALG_SHA256).unwrap();
        assert_eq!(events.len(), 4);
        let regs = replay::<32>(&events, |i| u16::try_from(i).ok()).unwrap();
        let mut p0 = [0u8; 32];
        for d in [[1u8; 32], [3u8; 32]] {
            let mut h = sha2::Sha256::new();
            h.update(p0);
            h.update(d);
            p0 = h.finalize().into();
        }
        assert_eq!(regs[&0], p0);
        assert!(regs.contains_key(&7));
        assert_eq!(regs.len(), 2);
        // The SHA-384 bank is absent from these events: not replayable there.
        assert!(parse(&log, TPM_ALG_SHA384).is_err());
        // A truncated record, or bytes after the zero tail, is no log at all.
        assert!(parse(&log[..log.len() - 3], TPM_ALG_SHA256).is_err());
        for filler in [0x00u8, 0xFF] {
            let mut padded = log.clone();
            padded.extend_from_slice(&[filler; 40]);
            assert_eq!(parse(&padded, TPM_ALG_SHA256).unwrap().len(), 4);
            padded.push(1);
            assert!(parse(&padded, TPM_ALG_SHA256).is_err());
        }
        let mut no_header = log.clone();
        no_header[4] = 0x01;
        assert!(parse(&no_header, TPM_ALG_SHA256).is_err());
    }
}
