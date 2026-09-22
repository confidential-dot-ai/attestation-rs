//! Section 4.8: the `cvm` CEL content type, whose custodian this profile is,
//! the logs that carry it, and the replay that reproduces registers from them
//! (sections 4.8 and 4.9). CEL parsing, record numbering and register
//! arithmetic are `tcg_cel`'s; this module adds what `cvm` defines.
//!
//! A `cvm` record's content is `{0: seq, 1: event}`: `seq` is its place among
//! the log's `cvm` records and `event` the deterministic CBOR c8s event. Its
//! one digest, SHA-384, must equal `record_digest(seq, index, event)` before it
//! is extended, and the event bytes are never re-encoded.

use super::registers::{
    record_digest, BOOT_SLOT, CLAIM_STRING_MAX, CVM, DOMAIN_ATS, FIRST_WORKLOAD_SLOT, OP_BOOT,
    OP_CLAIM,
};
use crate::error::{AttestationError, Result};
use sha2::{Digest, Sha384};
use std::collections::BTreeMap;
use tcg_cel::{Content, HashAlg, Index, Record};

/// Bytes of a c8s event's own content.
pub const MAX_CONTENT: usize = tcg_cel::MAX_BYTES;

fn bad(msg: impl Into<String>) -> AttestationError {
    AttestationError::EventlogIntegrityFailed(msg.into())
}

fn cel_err(e: tcg_cel::Error) -> AttestationError {
    bad(e.to_string())
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
    use super::bad;
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

        pub fn map(&mut self, max: usize) -> Result<usize> {
            match self.head()? {
                (5, n) => Self::len(n, max, "map"),
                (m, _) => Err(bad(format!("CBOR: expected map, got major {m}"))),
            }
        }
    }
}

fn digest48(b: &[u8]) -> Result<[u8; 48]> {
    b.try_into().map_err(|_| bad("digest is not 48 bytes"))
}

/// Parse the event bytes of a `cvm` record into the c8s event.
pub fn parse_cvm_event(event: &[u8]) -> Result<CvmEvent> {
    let mut r = cbor::Reader::new(event);
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

/// A `tcg-cel-cbor` log: the CEL CDDL's array of records.
pub fn parse_cbor(data: &[u8]) -> Result<Vec<Record>> {
    tcg_cel::decode_cbor(data, &[&CVM]).map_err(cel_err)
}

/// A `tcg-cel-json` log.
pub fn parse_json(data: &[u8]) -> Result<Vec<Record>> {
    tcg_cel::decode_json(data, &[&CVM]).map_err(cel_err)
}

/// The dstack runtime log (section 4.8), each runtime event's digest
/// recomputed from its fields by its declared version's rule.
pub fn parse_dstack_json(data: &[u8]) -> Result<Vec<Record>> {
    tcg_cel::dstack::to_cel(data).map_err(cel_err)
}

/// The `seq` and event bytes of a `cvm` record.
fn cvm_parts(rec: &Record) -> Option<(u64, &[u8])> {
    match &rec.content {
        Content::Extension { ty, value } if **ty == CVM => {
            Some((value.get(0)?.as_uint()?, value.get(1)?.as_bytes()?))
        }
        _ => None,
    }
}

/// What a replay established for one register.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SlotReplay {
    pub value: [u8; 48],
    /// Records naming the slot.
    pub records: u64,
    /// Records extended into it; unmeasured records (EV_NO_ACTION) name a
    /// register without changing it.
    pub extended: u64,
    /// From the slot's claim record (workload slots).
    pub claim: Option<(String, String)>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Replay {
    pub slots: BTreeMap<u16, SlotReplay>,
    /// `content_digest` of an `ats`/`boot` record at record 0, when present.
    pub boot_digest: Option<[u8; 48]>,
}

fn slot_of(rec: &Record, pos: usize) -> Result<u16> {
    match rec.index {
        Index::Pcr(i) => {
            u16::try_from(i).map_err(|_| bad(format!("record {pos}: register {i} is out of range")))
        }
        Index::Nv(_) => Err(bad(format!("record {pos}: an NV index is not a register"))),
    }
}

/// Replay records from `initial(index)` in the SHA-384 bank. Every `cvm`
/// record's `seq` must count the log's `cvm` records from 0 and its digest
/// must reproduce. With `workload_rules` (an SNP commitment log), every record
/// must be `cvm`, since other content carries no sequence binding, and slots
/// from [`FIRST_WORKLOAD_SLOT`] up must open with a claim record and take no
/// second one (section 4.9).
pub fn replay(
    records: &[Record],
    initial: impl Fn(u16) -> Option<[u8; 48]>,
    workload_rules: bool,
) -> Result<Replay> {
    let mut claims: BTreeMap<u16, (String, String)> = BTreeMap::new();
    let mut seen: BTreeMap<u16, u64> = BTreeMap::new();
    let mut boot_digest = None;
    let mut next_seq = 0u64;
    for (pos, rec) in records.iter().enumerate() {
        let index = slot_of(rec, pos)?;
        if initial(index).is_none() {
            return Err(bad(format!(
                "record {pos}: register {index} is not on this platform"
            )));
        }
        let event = match cvm_parts(rec) {
            Some((seq, event)) => {
                if seq != next_seq {
                    return Err(bad(format!(
                        "record {pos}: seq {seq} where the log's cvm records give {next_seq}"
                    )));
                }
                next_seq += 1;
                let reproduces = match rec.digests.as_slice() {
                    [d] => {
                        d.alg == HashAlg::SHA384
                            && crate::utils::constant_time_eq(
                                &record_digest(seq, index, event),
                                &d.value,
                            )
                    }
                    _ => false,
                };
                if !reproduces {
                    return Err(bad(format!(
                        "record {pos}: digest does not reproduce from the content"
                    )));
                }
                Some(parse_cvm_event(event)?)
            }
            None if workload_rules => {
                return Err(bad(format!(
                    "record {pos}: commitment logs require cvm content to authenticate ordering"
                )));
            }
            None => None,
        };
        let earlier = seen.entry(index).or_insert(0);
        match event.as_ref().filter(|e| e.domain == DOMAIN_ATS) {
            Some(e) if e.operation == OP_BOOT => {
                if pos != 0 || index != u16::from(BOOT_SLOT) {
                    return Err(bad(format!(
                        "record {pos}: a boot record is only record 0 into slot {BOOT_SLOT}"
                    )));
                }
                boot_digest = Some(e.content_digest);
            }
            Some(e) if e.operation == OP_CLAIM => {
                if !workload_rules || index < u16::from(FIRST_WORKLOAD_SLOT) {
                    return Err(bad(format!(
                        "record {pos}: a claim record outside a workload slot"
                    )));
                }
                if *earlier != 0 {
                    return Err(bad(format!(
                        "record {pos}: slot {index} is already claimed"
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
                claims.insert(index, parse_claim_body(body)?);
            }
            _ => {
                if workload_rules && index >= u16::from(FIRST_WORKLOAD_SLOT) && *earlier == 0 {
                    return Err(bad(format!(
                        "record {pos}: extend into unclaimed slot {index}"
                    )));
                }
            }
        }
        *earlier += 1;
    }
    let out = tcg_cel::replay(
        records,
        HashAlg::SHA384,
        |i| match i {
            Index::Pcr(i) => u16::try_from(i).ok().and_then(&initial).map(|v| v.to_vec()),
            Index::Nv(_) => None,
        },
        tcg_cel::ReplayOptions::default(),
    )
    .map_err(cel_err)?;
    let mut slots = BTreeMap::new();
    for (i, reg) in out.registers {
        let Index::Pcr(i) = i else {
            unreachable!("NV indices were refused above")
        };
        let index = u16::try_from(i).expect("checked above");
        let value = <[u8; 48]>::try_from(reg.value.as_slice()).expect("the SHA-384 bank");
        slots.insert(
            index,
            SlotReplay {
                value,
                records: reg.records,
                extended: reg.extended,
                claim: claims.remove(&index),
            },
        );
    }
    Ok(Replay { slots, boot_digest })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::profile::registers::{
        boot_record, cel_record, claim_record, commit, event_content, extend, genesis, REG_COUNT,
        SEED,
    };

    fn vectors() -> serde_json::Value {
        serde_json::from_str(include_str!(
            "../../../../docs/design/vectors/cvm_profile_vectors.json"
        ))
        .unwrap()
    }

    fn hexv(v: &serde_json::Value, k: &str) -> Vec<u8> {
        hex::decode(v[k].as_str().unwrap()).unwrap()
    }

    fn event_of(r: &Record) -> Vec<u8> {
        cvm_parts(r).unwrap().1.to_vec()
    }

    /// A cvm record whose digest reproduces, numbered later by `log`.
    fn rec(seq: u64, slot: u8, event: &[u8]) -> Record {
        cel_record(
            0,
            slot,
            seq,
            &record_digest(seq, u16::from(slot), event),
            event,
        )
    }

    fn log(mut records: Vec<Record>) -> Vec<Record> {
        tcg_cel::renumber(&mut records);
        records
    }

    fn init(i: u16) -> Option<[u8; 48]> {
        (usize::from(i) < REG_COUNT).then(|| genesis(i as u8, &SEED))
    }

    #[test]
    fn the_appendix_b_log_parses_and_replays() {
        let v = vectors();
        let records = parse_cbor(&hexv(&v, "cel_log")).unwrap();
        assert_eq!(records.len(), 2);
        assert_eq!(
            tcg_cel::encode_cbor(&records[..1]).unwrap()[1..],
            hexv(&v, "boot_cel_record")
        );
        assert_eq!((records[0].recnum, records[0].index), (0, Index::Pcr(3)));
        assert_eq!((records[1].recnum, records[1].index), (0, Index::Pcr(4)));
        assert_eq!(records[0].digests[0].value, hexv(&v, "boot_digest"));
        assert_eq!(event_of(&records[0]), hexv(&v, "boot_content"));
        assert_eq!(cvm_parts(&records[1]).unwrap().0, 1);
        assert_eq!(event_of(&records[1]), hexv(&v, "claim_content"));

        let out = replay(&records, init, true).unwrap();
        assert_eq!(out.slots[&3].value.to_vec(), hexv(&v, "boot_r3"));
        assert_eq!(out.slots[&4].value.to_vec(), hexv(&v, "claim_r4"));
        assert_eq!(
            out.slots[&4].claim,
            Some(("c8s".to_string(), "workload".to_string()))
        );
        assert_eq!(
            out.boot_digest.unwrap(),
            <[u8; 48]>::from(Sha384::digest(hexv(&v, "bootseed")))
        );

        // The JSON form carries the same records, and writes to the vector.
        let json = v["cel_log_json"].as_str().unwrap();
        assert_eq!(parse_json(json.as_bytes()).unwrap(), records);
        assert_eq!(tcg_cel::encode_json(&records).unwrap(), json);
        // a repeated member name is refused, whichever value comes last
        let dup = json.replacen(r#""recnum":0,"#, r#""recnum":0,"recnum":0,"#, 1);
        assert!(parse_json(dup.as_bytes()).is_err());
    }

    #[test]
    fn replay_refuses_gaps_forged_digests_and_slot_misuse() {
        let v = vectors();
        let boot = hexv(&v, "boot_content");
        let claim = hexv(&v, "claim_content");
        let start = event_content("c8s", "start-container", &[1u8; 48], None);
        let refused = |records: Vec<Record>, why: &str| {
            let e = replay(&log(records), init, true).unwrap_err().to_string();
            assert!(e.contains(why), "expected {why:?}, got {e:?}");
        };

        refused(vec![rec(0, 3, &boot), rec(2, 4, &claim)], "seq 2");
        refused(vec![cel_record(0, 3, 0, &[9u8; 48], &boot)], "digest");
        refused(
            vec![rec(0, 3, &boot), rec(1, 4, &start)],
            "unclaimed slot 4",
        );
        refused(
            vec![rec(0, 4, &claim), rec(1, 4, &claim)],
            "already claimed",
        );
        refused(vec![rec(0, 4, &boot)], "boot record");
        refused(vec![rec(0, 4, &claim), rec(1, 3, &boot)], "boot record");
        refused(vec![rec(0, 3, &claim)], "outside a workload slot");
        // a register the platform does not have
        refused(
            vec![rec(0, 16, &start)],
            "register 16 is not on this platform",
        );

        // Without workload rules (TDX), slot 3 replays from zero and other
        // content types are extended as recorded.
        let tdx = log(vec![
            rec(0, 3, &start),
            Record {
                recnum: 0,
                index: Index::Pcr(3),
                digests: vec![tcg_cel::Digest {
                    alg: HashAlg::SHA384,
                    value: vec![5; 48],
                }],
                content: Content::Systemd(b"x".to_vec()),
            },
        ]);
        let out = replay(&tdx, |i| (i < 4).then_some([0u8; 48]), false).unwrap();
        let r3 = extend(&extend(&[0u8; 48], &record_digest(0, 3, &start)), &[5; 48]);
        assert_eq!(out.slots[&3].value, r3);
        assert_eq!(out.slots[&3].records, 2);
    }

    #[test]
    fn cross_register_reordering_cannot_preserve_the_commitment() {
        let records = log(vec![
            rec(0, 3, &boot_record(&[7; 32])),
            rec(1, 4, &claim_record("c8s", "workload-a").unwrap()),
            rec(2, 5, &claim_record("c8s", "workload-b").unwrap()),
            rec(
                3,
                4,
                &event_content("c8s", "start-container", &[1; 48], None),
            ),
            rec(
                4,
                5,
                &event_content("c8s", "start-container", &[2; 48], None),
            ),
        ]);
        let bank = |out: Replay| {
            let mut regs = std::array::from_fn::<_, REG_COUNT, _>(|i| genesis(i as u8, &SEED));
            for (i, slot) in out.slots {
                regs[usize::from(i)] = slot.value;
            }
            regs
        };
        let original = bank(replay(&records, init, true).unwrap());

        // Swapping the last two records keeps each slot's own order, so the
        // per-slot record numbers still hold; the sequence does not.
        let mut swapped = records.clone();
        swapped.swap(3, 4);
        let swapped = log(swapped);
        assert!(replay(&swapped, init, true)
            .unwrap_err()
            .to_string()
            .contains("seq"));
        // Renumbering the sequence breaks both digests.
        let resequenced: Vec<Record> = swapped
            .iter()
            .enumerate()
            .map(|(n, r)| {
                let mut r = r.clone();
                if let Content::Extension { value, .. } = &mut r.content {
                    *value = tcg_cel::Value::Map(vec![
                        (0, tcg_cel::Value::Uint(n as u64)),
                        (1, value.get(1).unwrap().clone()),
                    ]);
                }
                r
            })
            .collect();
        assert!(replay(&resequenced, init, true)
            .unwrap_err()
            .to_string()
            .contains("digest"));
        // Recomputing the digests gives a valid log, but changes the
        // committed registers, so it cannot match the original signed report.
        let recomputed: Vec<Record> = resequenced
            .iter()
            .map(|r| {
                let (seq, event) = cvm_parts(r).unwrap();
                let Index::Pcr(slot) = r.index else { panic!() };
                rec(seq, slot as u8, event)
            })
            .collect();
        let changed = bank(replay(&log(recomputed), init, true).unwrap());
        assert_ne!(
            commit(&original, 5, &[3; 64]),
            commit(&changed, 5, &[3; 64])
        );
        // Relabeling records as an uninterpreted CEL type must not bypass the
        // sequence binding in an SNP commitment log.
        let mut opaque = swapped.clone();
        for r in &mut opaque[3..] {
            r.content = Content::Unknown {
                content_type: 201,
                cbor: vec![0x40],
            };
        }
        assert!(replay(&opaque, init, true)
            .unwrap_err()
            .to_string()
            .contains("require cvm"));
        // Moving a record to another register is authenticated too.
        let mut moved = records;
        moved[3].index = Index::Pcr(5);
        assert!(replay(&log(moved), init, true)
            .unwrap_err()
            .to_string()
            .contains("digest"));
    }

    #[test]
    fn logs_are_deterministic_cel_or_rejected() {
        let v = vectors();
        let good = hexv(&v, "cel_log");
        assert!(parse_cbor(&good).is_ok());
        // record 0's recnum 0 encoded as 0x18 0x00
        let mut non_minimal = good.clone();
        assert_eq!(non_minimal[1..4], [0xa5, 0x00, 0x00]);
        non_minimal.splice(3..4, [0x18, 0x00]);
        assert!(parse_cbor(&non_minimal).is_err());
        // the pre-conformance sequence of bare records is no log
        let sequence = [hexv(&v, "boot_cel_record"), hexv(&v, "claim_cel_record")].concat();
        assert!(parse_cbor(&sequence).is_err());
        // a global record number across slots breaks CEL numbering
        let mut global = good.clone();
        let second = 1 + hexv(&v, "boot_cel_record").len();
        assert_eq!(global[second..second + 3], [0xa5, 0x00, 0x00]);
        global[second + 2] = 0x01;
        assert!(parse_cbor(&global)
            .unwrap_err()
            .to_string()
            .contains("recnum"));
    }

    #[test]
    fn dstack_logs_reproduce_their_digests() {
        let payload = b"sha256:abc";
        let v1 = {
            let mut h = Sha384::new();
            h.update(tcg_cel::dstack::RUNTIME_EVENT_TYPE.to_le_bytes());
            h.update(b":compose-hash:");
            h.update(payload);
            hex::encode(h.finalize())
        };
        let preimage = format!(
            "{{\"name\":\"key-provider\",\"payload\":\"{}\",\"type\":134217729}}",
            hex::encode(payload)
        );
        let v2 = hex::encode(Sha384::digest(preimage.as_bytes()));
        let events = serde_json::json!([
            {"imr": 3, "event_type": 134217729, "digest": v1, "event": "compose-hash", "event_payload": hex::encode(payload)},
            {"imr": 3, "event_type": 134217729, "digest": v2, "event": "key-provider", "event_payload": hex::encode(payload),
             "version": 2, "preimage": hex::encode(&preimage)}
        ]);
        let records = parse_dstack_json(&serde_json::to_vec(&events).unwrap()).unwrap();
        let out = replay(&records, |i| (i < 4).then_some([0u8; 48]), false).unwrap();
        let mut r = [0u8; 48];
        for rec in &records {
            r = extend(&r, rec.digests[0].value.as_slice().try_into().unwrap());
        }
        assert_eq!(out.slots[&3].value, r);
        // a digest that does not reproduce under the event's version fails
        let mut forged = events.clone();
        forged[0]["digest"] = hex::encode([7u8; 48]).into();
        assert!(parse_dstack_json(&serde_json::to_vec(&forged).unwrap()).is_err());
        // a version 2 digest on an event that claims version 1 fails
        let mut mislabeled = events.clone();
        mislabeled[1].as_object_mut().unwrap().remove("version");
        mislabeled[1].as_object_mut().unwrap().remove("preimage");
        assert!(parse_dstack_json(&serde_json::to_vec(&mislabeled).unwrap()).is_err());
    }
}
