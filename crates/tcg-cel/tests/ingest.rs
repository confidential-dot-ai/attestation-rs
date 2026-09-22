use tcg_cel::tcg2::{self, IndexMap};
use tcg_cel::*;

const TRUSTEE_CCEL: &[u8] = include_bytes!("data/ccel_aael_alibabacloud.bin");
const DSTACK_GETQUOTE: &str = include_str!("data/dstack_tdx_getquote.json");

fn zeros(i: Index) -> Option<Vec<u8>> {
    matches!(i, Index::Pcr(0..=3)).then(|| vec![0; 48])
}

#[test]
fn a_ccel_with_attestation_agent_entries() {
    let log = tcg2::parse(TRUSTEE_CCEL).unwrap();
    assert_eq!(log.header.index, 1, "TDVF records the header at MrIndex 1");
    assert_eq!(log.spec_id.algorithms, vec![(HashAlg::SHA384, 48)]);
    assert_eq!(log.events.len(), 87);

    let records = log.to_cel(IndexMap::CcMrToRtmr).unwrap();
    assert_eq!(records.len(), 88);
    assert_eq!(records[0].index, Index::Pcr(0));
    assert!(records.iter().all(|r| matches!(r.index, Index::Pcr(0..=3))));
    let entries = aael::entries(&records).unwrap();
    let texts: Vec<_> = entries
        .iter()
        .map(|(i, e)| {
            assert_eq!(records[*i].index, Index::Pcr(3), "AAEL lands in RTMR 3");
            (e.domain.as_str(), e.operation.as_str(), e.content.as_str())
        })
        .collect();
    assert_eq!(
        texts,
        [
            ("coco.com", "some-operation", "some-content"),
            (
                "coco.com",
                "some-operation",
                r#"{"key": "value", "nested-key": {"sub-key": "value"}}"#
            ),
        ]
    );
    let out = replay(&records, HashAlg::SHA384, zeros, ReplayOptions::default()).unwrap();
    assert_eq!(out.registers.len(), 4);
    assert_eq!(out.registers[&Index::Pcr(3)].extended, 2);

    // The CEL form carries every byte: it round-trips through both encodings.
    assert_eq!(
        decode_cbor(&encode_cbor(&records).unwrap(), &[]).unwrap(),
        records
    );
    let json = encode_json(&records).unwrap();
    assert_eq!(decode_json(json.as_bytes(), &[]).unwrap(), records);

    // An entry whose text changed no longer reproduces its digest.
    let (i, _) = entries[0];
    let mut forged = records.clone();
    if let Content::PcClientStd { event_data, .. } = &mut forged[i].content {
        *event_data.last_mut().unwrap() ^= 1;
    }
    assert!(matches!(aael::entries(&forged), Err(Error::Digest { .. })));

    // As a TPM log, MrIndex 4 would be PCR 4: the mapping is the caller's.
    let as_pcrs = log.to_cel(IndexMap::Pcr).unwrap();
    assert_eq!(as_pcrs[entries[0].0].index, Index::Pcr(4));
}

fn aael_record(mr: u32, text: &str) -> Vec<u8> {
    let mut tagged = aael::AAEL_TAG.to_le_bytes().to_vec();
    tagged.extend_from_slice(&(text.len() as u32).to_le_bytes());
    tagged.extend_from_slice(text.as_bytes());
    let mut out = Vec::new();
    out.extend_from_slice(&mr.to_le_bytes());
    out.extend_from_slice(&EV_EVENT_TAG.to_le_bytes());
    out.extend_from_slice(&1u32.to_le_bytes());
    out.extend_from_slice(&HashAlg::SHA384.0.to_le_bytes());
    out.extend_from_slice(&HashAlg::SHA384.hash(&tagged).unwrap());
    out.extend_from_slice(&(tagged.len() as u32).to_le_bytes());
    out.extend_from_slice(&tagged);
    out
}

#[test]
fn the_agent_log_without_a_ccel_uses_its_fixed_header() {
    // guest-components: its fixed header, the entries, then eight 0xFF bytes.
    let log = [
        tcg2::COCO_SYNTHETIC_HEADER.to_vec(),
        aael_record(4, "domain operation content"),
        vec![0xFF; 8],
    ]
    .concat();
    let parsed = tcg2::parse(&log).unwrap();
    assert_eq!(
        parsed.spec_id.algorithms,
        [
            (HashAlg::SHA256, 32),
            (HashAlg::SHA384, 48),
            (HashAlg::SM3_256, 32)
        ]
    );
    let records = parsed.to_cel(IndexMap::CcMrToRtmr).unwrap();
    let (_, e) = &aael::entries(&records).unwrap()[0];
    assert_eq!(
        (e.domain.as_str(), e.content.as_str()),
        ("domain", "content")
    );
    // The upstream digest vector for this entry.
    assert_eq!(
        hex::encode(records[1].digest(HashAlg::SHA384).unwrap()),
        "dad5f0e226318ffa9839b75a472c6aa7fdb5834949d0a0a22990cf04d5692440fb00f3aa0609db7e49cd8d793f670d02"
    );
    // Only that exact header stands in for the Spec ID event.
    let mut other = log.clone();
    other[36] = 1;
    assert!(tcg2::parse(&other).is_err());
}

fn header(algorithms: &[(u16, u16)]) -> Vec<u8> {
    let mut spec = b"Spec ID Event03\0".to_vec();
    spec.extend_from_slice(&[0, 0, 0, 0, 0, 2, 0, 2]);
    spec.extend_from_slice(&(algorithms.len() as u32).to_le_bytes());
    for (a, s) in algorithms {
        spec.extend_from_slice(&a.to_le_bytes());
        spec.extend_from_slice(&s.to_le_bytes());
    }
    spec.push(0);
    let mut out = vec![0, 0, 0, 0, 3, 0, 0, 0];
    out.extend_from_slice(&[0; 20]);
    out.extend_from_slice(&(spec.len() as u32).to_le_bytes());
    out.extend_from_slice(&spec);
    out
}

fn event(index: u32, event_type: u32, digests: &[(u16, Vec<u8>)], data: &[u8]) -> Vec<u8> {
    let mut out = Vec::new();
    out.extend_from_slice(&index.to_le_bytes());
    out.extend_from_slice(&event_type.to_le_bytes());
    out.extend_from_slice(&(digests.len() as u32).to_le_bytes());
    for (a, d) in digests {
        out.extend_from_slice(&a.to_le_bytes());
        out.extend_from_slice(d);
    }
    out.extend_from_slice(&(data.len() as u32).to_le_bytes());
    out.extend_from_slice(data);
    out
}

#[test]
fn tcg2_parsing_is_whole_or_nothing() {
    let hdr = header(&[(0x000B, 32)]);
    let ev = event(7, 0x8000_0001, &[(0x000B, vec![1; 32])], b"x");
    let good = [hdr.clone(), ev.clone(), ev.clone()].concat();
    assert_eq!(tcg2::parse(&good).unwrap().events.len(), 2);
    for filler in [0x00u8, 0xFF] {
        let padded = [good.clone(), vec![filler; 64]].concat();
        assert_eq!(tcg2::parse(&padded).unwrap().events.len(), 2);
        let mut dirty = padded.clone();
        *dirty.last_mut().unwrap() = 1;
        assert!(tcg2::parse(&dirty).is_err(), "bytes after the filler");
    }
    let cases: Vec<(Vec<u8>, &str)> = vec![
        (good[..good.len() - 1].to_vec(), "truncated"),
        (
            [hdr.clone(), event(7, 4, &[(0x000C, vec![1; 48])], b"")].concat(),
            "not declared",
        ),
        (
            [
                hdr.clone(),
                event(7, 4, &[(0x000B, vec![1; 32]), (0x000B, vec![1; 32])], b""),
            ]
            .concat(),
            "digests; the header declares 1",
        ),
        ([hdr.clone(), event(7, 4, &[], b"")].concat(), "0 digests"),
        (header(&[(0x000B, 48)]), "declared with 48-byte"),
        (header(&[(0x000B, 32), (0x000B, 32)]), "declared twice"),
        (
            {
                let mut h = hdr.clone();
                h[8] = 1;
                h
            },
            "SHA-1 digest is not zero",
        ),
        (
            {
                let mut h = hdr.clone();
                h[4] = 1;
                h
            },
            "not an EV_NO_ACTION",
        ),
        (
            {
                let mut h = hdr.clone();
                h[32] = b's';
                h
            },
            "not the Spec ID event",
        ),
        (
            {
                let mut h = hdr.clone();
                h.push(0);
                h[28] += 1;
                h
            },
            "size disagrees",
        ),
    ];
    for (bytes, reason) in cases {
        let e = tcg2::parse(&bytes).unwrap_err().to_string();
        assert!(e.contains(reason), "expected {reason:?}, got {e:?}");
    }
    // MrIndex 5 names no RTMR; MrIndex 0 only for EV_NO_ACTION.
    let log = [hdr.clone(), event(5, 4, &[(0x000B, vec![1; 32])], b"")].concat();
    assert!(tcg2::to_cel(&log, IndexMap::CcMrToRtmr).is_err());
    let log = [hdr.clone(), event(0, 4, &[(0x000B, vec![1; 32])], b"")].concat();
    assert!(tcg2::to_cel(&log, IndexMap::CcMrToRtmr).is_err());
    let log = [hdr, event(0, EV_NO_ACTION, &[(0x000B, vec![0; 32])], b"")].concat();
    assert!(tcg2::to_cel(&log, IndexMap::CcMrToRtmr).is_ok());
}

fn getquote() -> (String, Vec<Vec<u8>>) {
    let v: serde_json::Value = serde_json::from_str(DSTACK_GETQUOTE).unwrap();
    let quote = hex::decode(v["quote"].as_str().unwrap()).unwrap();
    // TDX quote v4: 48-byte header, then the TD report body with RTMR 0 at 328.
    let rtmrs = (0..4)
        .map(|i| quote[376 + 48 * i..424 + 48 * i].to_vec())
        .collect();
    (v["event_log"].as_str().unwrap().to_string(), rtmrs)
}

#[test]
fn a_dstack_log_replays_to_the_rtmrs_of_its_quote() {
    let (log, rtmrs) = getquote();
    let records = dstack::to_cel(log.as_bytes()).unwrap();
    assert_eq!(records.len(), 29);
    let out = replay(&records, HashAlg::SHA384, zeros, ReplayOptions::default()).unwrap();
    for (i, rtmr) in rtmrs.iter().enumerate() {
        assert_eq!(
            &out.registers[&Index::Pcr(i as u32)].value,
            rtmr,
            "RTMR {i}"
        );
    }
    let names: Vec<_> = records
        .iter()
        .enumerate()
        .filter_map(|(i, r)| dstack::runtime_event(r, i))
        .map(|e| e.unwrap().name)
        .collect();
    assert_eq!(
        names,
        [
            "system-preparing",
            "app-id",
            "compose-hash",
            "gpu-policy-hash",
            "instance-id",
            "boot-mr-done",
            "key-provider",
            "storage-fs",
            "system-ready"
        ]
    );
    // The CEL form verifies on its own after a round trip.
    let back = decode_cbor(&encode_cbor(&records).unwrap(), &[]).unwrap();
    assert!(back
        .iter()
        .enumerate()
        .filter_map(|(i, r)| dstack::runtime_event(r, i))
        .all(|e| e.is_ok()));
}

#[test]
fn dstack_events_must_reproduce_their_digests() {
    let (log, _) = getquote();
    let events: Vec<serde_json::Value> = serde_json::from_str(&log).unwrap();
    let runtime = events
        .iter()
        .find(|e| e["event"] == "compose-hash")
        .unwrap()
        .clone();
    let one = |e: serde_json::Value| serde_json::to_vec(&vec![e]).unwrap();
    assert!(dstack::to_cel(&one(runtime.clone())).is_ok());

    // Version 2, with dstack's own vector.
    let preimage = br#"{"name":"compose-hash","payload":"abcd","type":134217729}"#;
    let v2 = serde_json::json!({
        "imr": 3, "event_type": dstack::RUNTIME_EVENT_TYPE,
        "digest": hex::encode(HashAlg::SHA384.hash(preimage).unwrap()),
        "event": "compose-hash", "event_payload": "abcd",
        "version": 2, "preimage": hex::encode(preimage),
    });
    let records = dstack::to_cel(&one(v2.clone())).unwrap();
    let ev = dstack::runtime_event(&records[0], 0).unwrap().unwrap();
    assert_eq!(
        (ev.version, ev.name.as_str(), ev.payload.as_slice()),
        (2, "compose-hash", &[0xab, 0xcd][..])
    );

    let with = |base: &serde_json::Value, k: &str, v: serde_json::Value| {
        let mut e = base.clone();
        e[k] = v;
        e
    };
    let without = |base: &serde_json::Value, k: &str| {
        let mut e = base.clone();
        e.as_object_mut().unwrap().remove(k);
        e
    };
    let cases = [
        (
            with(&runtime, "digest", hex::encode([7u8; 48]).into()),
            "does not reproduce",
        ),
        (
            with(&runtime, "event_payload", "00".into()),
            "does not reproduce",
        ),
        (with(&runtime, "version", 3.into()), "version 3"),
        (
            with(&runtime, "preimage", "00".into()),
            "carries a preimage",
        ),
        (
            with(&runtime, "event", "compose:hash".into()),
            "contains ':'",
        ),
        (with(&runtime, "imr", 4.into()), "not an RTMR"),
        (with(&runtime, "note", "x".into()), "unexpected member"),
        (without(&v2, "preimage"), "no preimage"),
        (
            with(
                &v2,
                "preimage",
                hex::encode(br#"{"name": "compose-hash","payload":"abcd","type":134217729}"#)
                    .into(),
            ),
            "canonical",
        ),
    ];
    for (e, reason) in cases {
        let err = dstack::to_cel(&one(e)).unwrap_err().to_string();
        assert!(err.contains(reason), "expected {reason:?}, got {err:?}");
    }
    let repeated = log.replacen(r#""imr":3,"#, r#""imr":3,"imr":3,"#, 1);
    assert_ne!(repeated, log);
    assert!(dstack::to_cel(repeated.as_bytes()).is_err());
}
