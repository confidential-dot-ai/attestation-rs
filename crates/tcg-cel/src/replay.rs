//! Replay: reproduce register values from a log in one bank.

use crate::error::{record, Error, Result};
use crate::model::{check_recnums, Content, Index, Record};
use crate::pcclient::{startup_locality, EV_NO_ACTION};
use crate::HashAlg;
use std::collections::btree_map::{BTreeMap, Entry};

/// One register after replay.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Register {
    pub value: Vec<u8>,
    /// Records naming the index.
    pub records: u64,
    /// Records extended into it.
    pub extended: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct Replay {
    pub registers: BTreeMap<Index, Register>,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct ReplayOptions {
    /// TPM PCR semantics for PCR 0: a `StartupLocality` EV_NO_ACTION event
    /// (PC Client PFP 10.4.5.3) sets its starting value to the locality, as
    /// TPM2_Startup and an H-CRTM sequence do (TPM 2.0 Part 1, section 34.3).
    pub startup_locality: bool,
}

/// The value a PC Client TPM's PCR holds after TPM2_Startup(CLEAR) with no
/// S-HCRTM sequence (Platform TPM Profile v1.05 Table 7): PCR 17 to 22 all
/// ones, the others zero; PCR 0 then takes the locality of a
/// `StartupLocality` event when [`ReplayOptions::startup_locality`] is set.
/// `None` above PCR 23 and for NV indices. D-RTM resets are not modeled.
pub fn pc_client_initial(index: Index, bank: HashAlg) -> Option<Vec<u8>> {
    let size = bank.digest_size()?;
    match index {
        Index::Pcr(17..=22) => Some(vec![0xFF; size]),
        Index::Pcr(0..=23) => Some(vec![0; size]),
        _ => None,
    }
}

/// Replay `records` in `bank`: every index starts at `initial(index)`
/// (`None` refuses an index the platform does not have) and each measured
/// record extends `value = H(value || digest)`. The log must follow section
/// 4.2.2 numbering, and every measured record must carry a digest in `bank`.
/// Replay authenticates digests only; a record's content is bound to its
/// digest only where its content type defines how (see the `aael` and
/// `dstack` modules, and the caller's own extension types).
pub fn replay(
    records: &[Record],
    bank: HashAlg,
    initial: impl Fn(Index) -> Option<Vec<u8>>,
    options: ReplayOptions,
) -> Result<Replay> {
    let size = bank
        .digest_size()
        .filter(|_| bank.hash(&[]).is_some())
        .ok_or_else(|| Error::Replay(format!("bank {bank} cannot be replayed by this crate")))?;
    check_recnums(records)?;
    let mut registers: BTreeMap<Index, Register> = BTreeMap::new();
    let mut locality_seen = false;
    for (position, rec) in records.iter().enumerate() {
        rec.validate(position)?;
        let reg = match registers.entry(rec.index) {
            Entry::Occupied(e) => e.into_mut(),
            Entry::Vacant(e) => {
                let value = initial(rec.index).ok_or_else(|| {
                    record(position, format!("{} is not a register here", rec.index))
                })?;
                if value.len() != size {
                    return Err(Error::Replay(format!(
                        "{} starts at {} bytes; bank {bank} digests are {size}",
                        rec.index,
                        value.len()
                    )));
                }
                e.insert(Register {
                    value,
                    records: 0,
                    extended: 0,
                })
            }
        };
        reg.records += 1;
        if options.startup_locality && rec.index == Index::Pcr(0) {
            if let Content::PcClientStd {
                event_type,
                event_data,
            } = &rec.content
            {
                if event_type.code() == Some(EV_NO_ACTION) {
                    if let Some(locality) = startup_locality(event_data) {
                        let locality = locality.map_err(|e| record(position, e))?;
                        if locality_seen || reg.extended != 0 {
                            return Err(record(
                                position,
                                "a startup locality event must come once, before any PCR 0 extend",
                            ));
                        }
                        locality_seen = true;
                        reg.value = vec![0; size];
                        reg.value[size - 1] = locality;
                    }
                }
            }
        }
        if !rec.is_measured() {
            continue;
        }
        let digest = rec
            .digest(bank)
            .ok_or_else(|| record(position, format!("no digest in bank {bank}")))?;
        reg.value = bank
            .extend(&reg.value, digest)
            .expect("the bank was checked above");
        reg.extended += 1;
    }
    Ok(Replay { registers })
}
