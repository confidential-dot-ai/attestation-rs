use tcg_cel::*;

fn h(s: &str) -> Vec<u8> {
    hex::decode(s).unwrap()
}

// The PC Client example of CEL v1.1 section 5.1.7 (the Spec ID event and an
// EV_S_CRTM_VERSION event whose SHA-1 and SHA-256 digests both reproduce from
// its data), as a TCG2 log and as CEL-CBOR from an independent encoder
// (Python cbor2, canonical mode).
const EXAMPLE_TCG2: &str = "000000000300000000000000000000000000000000000000000000002500000053706563204944204576656e74303300000000000002000202000000040014000b002000000000000008000000020000000400c42fedad268200cb1d15f97841c344e79dae33200b00d4720b4009438213b803568017f903093f6bea8ab47d283db32b6eabedbbf155100000001efb6b540c1d5540a4ad4ef4bf17b83a";
const EXAMPLE_CBOR: &str = "82a5000001000381a200040154000000000000000000000000000000000000000009050aa2000301582553706563204944204576656e74303300000000000002000202000000040014000b00200000a5000101000382a200040154c42fedad268200cb1d15f97841c344e79dae3320a2000b015820d4720b4009438213b803568017f903093f6bea8ab47d283db32b6eabedbbf15509050aa2000801501efb6b540c1d5540a4ad4ef4bf17b83a";

const CVM_FIELDS: [Field; 2] = [
    Field {
        key: 0,
        name: "seq",
        schema: Schema::Uint,
        optional: false,
    },
    Field {
        key: 1,
        name: "event",
        schema: Schema::Bytes,
        optional: false,
    },
];
static CVM: ContentType = ContentType {
    value: 200,
    name: "cvm",
    schema: Schema::Map(&CVM_FIELDS),
};

fn zeros(n: usize) -> impl Fn(Index) -> Option<Vec<u8>> {
    move |_| Some(vec![0; n])
}

#[test]
fn the_cel_spec_pc_client_example_converts_to_its_cbor_vector() {
    let records = tcg2::to_cel(&h(EXAMPLE_TCG2), tcg2::IndexMap::Pcr).unwrap();
    assert_eq!(records.len(), 2);
    assert_eq!(records[0].recnum, 0);
    assert_eq!(records[1].recnum, 1);
    assert!(!records[0].is_measured());
    assert_eq!(encode_cbor(&records).unwrap(), h(EXAMPLE_CBOR));
    assert_eq!(decode_cbor(&h(EXAMPLE_CBOR), &[]).unwrap(), records);

    let json = encode_json(&records).unwrap();
    assert!(
        json.contains(r#""event_type":"EV_S_CRTM_VERSION""#),
        "{json}"
    );
    assert!(json.contains(r#""event_type":"EV_NO_ACTION""#), "{json}");
    assert_eq!(decode_json(json.as_bytes(), &[]).unwrap(), records);

    // PCR 0 in the SHA-256 bank: the header is not extended, the event is.
    let out = replay(
        &records,
        HashAlg::SHA256,
        zeros(32),
        ReplayOptions::default(),
    )
    .unwrap();
    let pcr0 = &out.registers[&Index::Pcr(0)];
    let d = h("d4720b4009438213b803568017f903093f6bea8ab47d283db32b6eabedbbf155");
    assert_eq!(
        pcr0.value,
        HashAlg::SHA256.hash(&[vec![0; 32], d].concat()).unwrap()
    );
    assert_eq!((pcr0.records, pcr0.extended), (2, 1));
    // The header has no SHA-384 digest, but it is not extended; the event is.
    assert!(replay(
        &records,
        HashAlg::SHA384,
        zeros(48),
        ReplayOptions::default()
    )
    .is_err());
}

#[test]
fn cel_json_reads_the_v1_0_spec_example_record() {
    // The CEL v1.0 section 5.3 example is record 2 of PCR 6; two records precede it.
    let prior = |n: u64| {
        format!(
            r#"{{"recnum":{n},"pcr":6,"digests":[{{"hashAlg":"sha1","digest":"{}"}},{{"hashAlg":"0x000B","digest":"{}"}}],"content_type":"pcclient_std","content":{{"event_type":12,"event_data":""}}}}"#,
            "11".repeat(20),
            "22".repeat(32)
        )
    };
    let example = r#"{"content":{"event_type":"EV_COMPACT_HASH","event_data":"44656c6c20436f6e66696775726174696f6e20496e666f726d6174696f6e2032"},"content_type":"pcclient_std","pcr":6,"recnum":2,"digests":[{"hashAlg":"sha1","digest":"bac9a8935b720760bcdea2faae75152f5d1e4bea"},{"hashAlg":"sha256","digest":"d18bf8d221a3a3b08774c8d077328c4b2ca205e4f1618ad4bac2b5786f453bc7"}]}"#;
    let log = format!("[{},{},{example}]", prior(0), prior(1));
    let records = decode_json(log.as_bytes(), &[]).unwrap();
    assert_eq!(records[2].index, Index::Pcr(6));
    assert_eq!(
        records[2].content,
        Content::PcClientStd {
            event_type: EventType::Code(0xC),
            event_data: b"Dell Configuration Information 2".to_vec(),
        }
    );
    assert_eq!(records[0].digests[1].alg, HashAlg::SHA256);
    // Alone, the example breaks section 4.2.2 numbering.
    assert!(decode_json(format!("[{example}]").as_bytes(), &[]).is_err());
}

fn every_kind() -> Vec<Record> {
    let d = |alg: HashAlg, b: u8| Digest {
        alg,
        value: vec![b; alg.digest_size().unwrap()],
    };
    let mut records = vec![
        Record {
            recnum: 0,
            index: Index::Pcr(15),
            digests: vec![d(HashAlg::SHA256, 1)],
            content: Content::Cel(CelMgmt::Version { major: 1, minor: 1 }),
        },
        Record {
            recnum: 0,
            index: Index::Pcr(15),
            digests: vec![d(HashAlg::SHA256, 2), d(HashAlg::SHA384, 3)],
            content: Content::Cel(CelMgmt::FirmwareEnd),
        },
        Record {
            recnum: 0,
            index: Index::Pcr(15),
            digests: vec![d(HashAlg::SHA256, 4)],
            content: Content::Cel(CelMgmt::Timestamp(1_758_000_000_000)),
        },
        Record {
            recnum: 0,
            index: Index::Pcr(15),
            digests: vec![d(HashAlg::SHA256, 5)],
            content: Content::Cel(CelMgmt::StateTrans(StateTrans::Kexec)),
        },
        Record {
            recnum: 0,
            index: Index::Pcr(0),
            digests: vec![d(HashAlg::SHA1, 6), d(HashAlg::SM3_256, 7)],
            content: Content::PcClientStd {
                event_type: EventType::Code(0x8000_0001),
                event_data: b"var".to_vec(),
            },
        },
        Record {
            recnum: 0,
            index: Index::Pcr(0),
            digests: vec![d(HashAlg::SHA3_512, 8)],
            content: Content::PcClientStd {
                event_type: EventType::Name("EV_VENDOR_THING".into()),
                event_data: vec![],
            },
        },
        Record {
            recnum: 0,
            index: Index::Pcr(0),
            digests: vec![d(HashAlg::SHA256, 8)],
            content: Content::PcClientStd {
                event_type: EventType::Code(0x0800_0001),
                event_data: vec![0xff; 3],
            },
        },
        Record {
            recnum: 0,
            index: Index::Pcr(10),
            digests: vec![d(HashAlg::SHA1, 9)],
            content: Content::ImaTemplate {
                template_name: "ima-ng".into(),
                template_data: vec![1, 2, 3],
            },
        },
        Record {
            recnum: 0,
            index: Index::Pcr(10),
            digests: vec![d(HashAlg::SHA256, 10)],
            content: Content::ImaTlv(vec![0, 0, 0, 0, 4]),
        },
        Record {
            recnum: 0,
            index: Index::Pcr(15),
            digests: vec![d(HashAlg::SHA256, 11)],
            content: Content::Systemd(b"machine-id:e9642bb2ab6448408be3585ef997d962".to_vec()),
        },
        Record {
            recnum: 0,
            index: Index::Nv(0x2000_0010),
            digests: vec![Digest {
                alg: HashAlg(0x00F0),
                value: vec![12; 40],
            }],
            content: Content::Extension {
                ty: &CVM,
                value: Value::Map(vec![(0, Value::Uint(7)), (1, Value::Bytes(vec![0xa0]))]),
            },
        },
    ];
    renumber(&mut records);
    records
}

#[test]
fn every_content_type_round_trips_through_both_encodings() {
    let records = every_kind();
    assert_eq!(records[3].recnum, 3);
    assert_eq!(records[7].recnum, 0);
    let cbor = encode_cbor(&records).unwrap();
    assert_eq!(decode_cbor(&cbor, &[&CVM]).unwrap(), records);
    let json = encode_json(&records).unwrap();
    assert_eq!(decode_json(json.as_bytes(), &[&CVM]).unwrap(), records);
    for piece in [
        r#""content_type":"cvm","content":{"seq":7,"event":"a0"}"#,
        r#""nv_index":536870928"#,
        r#""hashAlg":"0x00F0""#,
        r#""content":{"type":"state_trans","data":"kexec"}"#,
        r#""content":{"type":"firmware_end"}"#,
        r#""event_type":"EV_VENDOR_THING""#,
        r#""event_type":134217729"#,
    ] {
        assert!(json.contains(piece), "{piece} missing from {json}");
    }

    // A sequence file of the same records decodes to the same log.
    let seq: Vec<u8> = records
        .iter()
        .flat_map(|r| encode_cbor_record(r).unwrap())
        .collect();
    assert_eq!(decode_cbor_sequence(&seq, &[&CVM]).unwrap(), records);

    // Without the registration, the extension record survives CBOR as an
    // unknown item, and CEL-JSON has no name for it.
    let plain = decode_cbor(&cbor, &[]).unwrap();
    let Content::Unknown {
        content_type,
        cbor: item,
    } = &plain[10].content
    else {
        panic!("{:?}", plain[10].content)
    };
    assert_eq!(*content_type, 200);
    assert_eq!(item, &h("a200070141a0"));
    assert_eq!(encode_cbor(&plain).unwrap(), cbor);
    assert!(matches!(encode_json(&plain), Err(Error::Usage(_))));
    assert!(decode_json(json.as_bytes(), &[]).is_err());
}

/// One record, CEL-CBOR, with `f` applied to its bytes.
fn mutated(f: impl Fn(&mut Vec<u8>)) -> Vec<u8> {
    let mut b = h(EXAMPLE_CBOR);
    f(&mut b);
    b
}

#[test]
fn cbor_decoding_refuses_what_the_cddl_or_determinism_forbids() {
    let log = h(EXAMPLE_CBOR);
    assert!(decode_cbor(&log, &[]).is_ok());
    // (mutation, the reason the decoder must give)
    let cases: Vec<(Vec<u8>, &str)> = vec![
        // the first recnum, 0, as 0x18 0x00
        (
            mutated(|b| drop(b.splice(3..4, [0x18, 0x00]))),
            "non-minimal",
        ),
        (mutated(|b| b[0] = 0x9f), "indefinite"),
        (mutated(|b| b.push(0x00)), "bytes after the log"),
        (
            mutated(|b| {
                b.pop();
            }),
            "truncated",
        ),
        // the first record's content_type key 9 becomes 11
        (
            mutated(|b| {
                let i = b.windows(2).position(|w| w == [0x09, 0x05]).unwrap();
                b[i] = 0x0b;
            }),
            "expected key 9",
        ),
        // the second record's SHA-1 digest loses a byte
        (
            mutated(|b| {
                let i = b.windows(3).position(|w| w == [0x01, 0x54, 0xc4]).unwrap();
                b[i + 1] = 0x53;
                b.remove(i + 2);
            }),
            "sha1 digest is 19 bytes",
        ),
        // content_type 5 becomes the reserved 6
        (
            mutated(|b| {
                let i = b.windows(2).position(|w| w == [0x09, 0x05]).unwrap();
                b[i + 1] = 0x06;
            }),
            "reserved",
        ),
        // record 1's recnum 1 becomes 2
        (
            mutated(|b| {
                let i = b
                    .windows(4)
                    .position(|w| w == [0xa5, 0x00, 0x01, 0x01])
                    .unwrap();
                b[i + 2] = 0x02;
            }),
            "recnum 2 where pcr 0 expects 1",
        ),
    ];
    for (bytes, reason) in cases {
        let e = decode_cbor(&bytes, &[]).unwrap_err().to_string();
        assert!(e.contains(reason), "expected {reason:?}, got {e:?}");
    }

    let rec = |recnum: u64, pcr: u32| Record {
        recnum,
        index: Index::Pcr(pcr),
        digests: vec![Digest {
            alg: HashAlg::SHA384,
            value: vec![0; 48],
        }],
        content: Content::Systemd(vec![]),
    };
    // Numbering is per index: a global counter across two PCRs is refused.
    assert!(encode_cbor(&[rec(0, 0), rec(1, 1)]).is_err());
    assert!(encode_cbor(&[rec(0, 0), rec(0, 1), rec(1, 0)]).is_ok());
    assert!(encode_cbor(&[rec(1, 0)]).is_err());
    // Index ranges, digest shape and duplicate banks.
    assert!(encode_cbor(&[rec(0, 0x0100_0000)]).is_err());
    let mut nv = rec(0, 0);
    nv.index = Index::Nv(0x1FFF_FFFF);
    assert!(encode_cbor(&[nv]).is_err());
    let mut twice = rec(0, 0);
    twice.digests.push(twice.digests[0].clone());
    assert!(encode_cbor(&[twice]).is_err());
    let mut none = rec(0, 0);
    none.digests.clear();
    assert!(encode_cbor(&[none]).is_err());
    // firmware_end with data: {0: 2, 1: 0}
    let mut fe = encode_cbor(&[Record {
        content: Content::Cel(CelMgmt::FirmwareEnd),
        ..rec(0, 0)
    }])
    .unwrap();
    let i = fe.len() - 3;
    assert_eq!(fe[i..], [0xa1, 0x00, 0x02]);
    fe.splice(i.., [0xa2, 0x00, 0x02, 0x01, 0x00]);
    assert!(decode_cbor(&fe, &[]).is_err());
    // An unknown content item must itself be deterministic: {1: 0, 0: 0}.
    let mut unknown = encode_cbor(&[Record {
        content: Content::Unknown {
            content_type: 300,
            cbor: h("a0"),
        },
        ..rec(0, 0)
    }])
    .unwrap();
    unknown.pop();
    unknown.extend_from_slice(&h("a201000000"));
    assert!(decode_cbor(&unknown, &[]).is_err());
    // Registering a Table 2 value, or one value twice, is a usage error.
    static BAD: ContentType = ContentType {
        value: 9,
        name: "systemd2",
        schema: Schema::Bytes,
    };
    assert!(matches!(decode_cbor(&log, &[&BAD]), Err(Error::Usage(_))));
    assert!(matches!(
        decode_cbor(&log, &[&CVM, &CVM]),
        Err(Error::Usage(_))
    ));
}

#[test]
fn json_decoding_refuses_repeats_strays_and_wrong_kinds() {
    let good = r#"[{"recnum":0,"pcr":3,"digests":[{"hashAlg":"sha384","digest":"__D__"}],"content_type":"cvm","content":{"seq":0,"event":"a0"}}]"#
        .replace("__D__", &"ab".repeat(48));
    assert!(decode_json(good.as_bytes(), &[&CVM]).is_ok());
    let cases = [
        (
            "repeated member",
            good.replace(r#""recnum":0,"#, r#""recnum":0,"recnum":0,"#),
        ),
        (
            "repeated nested member",
            good.replace(r#""seq":0,"#, r#""seq":0,"seq":0,"#),
        ),
        (
            "stray member",
            good.replace(r#""recnum":0,"#, r#""recnum":0,"note":"x","#),
        ),
        (
            "pcr and nv_index",
            good.replace(r#""pcr":3,"#, r#""pcr":3,"nv_index":536870912,"#),
        ),
        (
            "numeric content_type",
            good.replace(r#""content_type":"cvm""#, r#""content_type":200"#),
        ),
        ("unknown hashAlg", good.replace("sha384", "sha385")),
        (
            "negative recnum",
            good.replace(r#""recnum":0"#, r#""recnum":-1"#),
        ),
        ("fractional pcr", good.replace(r#""pcr":3"#, r#""pcr":3.0"#)),
        (
            "odd hex",
            good.replace(r#""event":"a0""#, r#""event":"a0b""#),
        ),
        ("missing field", good.replace(r#""seq":0,"#, "")),
        (
            "digest too short",
            good.replace(&"ab".repeat(48), &"ab".repeat(47)),
        ),
        (
            "not an array",
            good.trim_start_matches('[')
                .trim_end_matches(']')
                .to_string(),
        ),
    ];
    for (what, json) in cases {
        assert!(
            decode_json(json.as_bytes(), &[&CVM]).is_err(),
            "{what} was accepted"
        );
    }
}

fn locality_record(locality: u8) -> Record {
    let mut data = b"StartupLocality\0".to_vec();
    data.push(locality);
    Record {
        recnum: 0,
        index: Index::Pcr(0),
        digests: vec![Digest {
            alg: HashAlg::SHA256,
            value: vec![0; 32],
        }],
        content: Content::PcClientStd {
            event_type: EventType::Code(EV_NO_ACTION),
            event_data: data,
        },
    }
}

fn measured(pcr: u32, byte: u8) -> Record {
    Record {
        recnum: 0,
        index: Index::Pcr(pcr),
        digests: vec![Digest {
            alg: HashAlg::SHA256,
            value: vec![byte; 32],
        }],
        content: Content::PcClientStd {
            event_type: EventType::Code(0x8),
            event_data: vec![],
        },
    }
}

#[test]
fn replay_follows_tpm_startup_locality_when_asked() {
    let tpm = ReplayOptions {
        startup_locality: true,
    };
    let mut log = vec![locality_record(3), measured(0, 1), measured(7, 2)];
    renumber(&mut log);
    let out = replay(&log, HashAlg::SHA256, zeros(32), tpm).unwrap();
    let mut start = vec![0; 32];
    start[31] = 3;
    let pcr0 = HashAlg::SHA256
        .hash(&[start, vec![1; 32]].concat())
        .unwrap();
    assert_eq!(out.registers[&Index::Pcr(0)].value, pcr0);
    // Without PC Client semantics the event is only an EV_NO_ACTION record.
    let plain = replay(&log, HashAlg::SHA256, zeros(32), ReplayOptions::default()).unwrap();
    assert_ne!(plain.registers[&Index::Pcr(0)].value, pcr0);

    for bad in [
        vec![measured(0, 1), locality_record(3)],
        vec![locality_record(0), locality_record(3)],
        vec![locality_record(2)],
    ] {
        let mut bad = bad;
        renumber(&mut bad);
        assert!(replay(&bad, HashAlg::SHA256, zeros(32), tpm).is_err());
    }
}

#[test]
fn pc_client_pcrs_start_at_their_table_7_values() {
    let v = |i| pc_client_initial(Index::Pcr(i), HashAlg::SHA256);
    assert_eq!(v(0), Some(vec![0; 32]));
    assert_eq!(v(16), Some(vec![0; 32]));
    assert_eq!(v(17), Some(vec![0xFF; 32]));
    assert_eq!(v(22), Some(vec![0xFF; 32]));
    assert_eq!(v(23), Some(vec![0; 32]));
    assert_eq!(v(24), None);
    assert_eq!(
        pc_client_initial(Index::Nv(0x2000_0000), HashAlg::SHA256),
        None
    );
    let mut log = vec![measured(17, 1)];
    renumber(&mut log);
    let out = replay(
        &log,
        HashAlg::SHA256,
        |i| pc_client_initial(i, HashAlg::SHA256),
        ReplayOptions::default(),
    )
    .unwrap();
    assert_eq!(
        out.registers[&Index::Pcr(17)].value,
        HashAlg::SHA256
            .hash(&[vec![0xFF; 32], vec![1; 32]].concat())
            .unwrap()
    );
}

#[test]
fn replay_refuses_what_it_cannot_reproduce() {
    let mut log = vec![measured(0, 1), measured(1, 2)];
    renumber(&mut log);
    let opts = ReplayOptions::default();
    assert!(matches!(
        replay(&log, HashAlg::SHA1, zeros(20), opts),
        Err(Error::Replay(_))
    ));
    assert!(replay(&log, HashAlg::SHA384, zeros(48), opts).is_err());
    assert!(matches!(
        replay(&log, HashAlg::SHA256, zeros(31), opts),
        Err(Error::Replay(_))
    ));
    let only_pcr0 = |i: Index| (i == Index::Pcr(0)).then(|| vec![0; 32]);
    assert!(replay(&log, HashAlg::SHA256, only_pcr0, opts).is_err());
    log[1].recnum = 1;
    assert!(replay(&log, HashAlg::SHA256, zeros(32), opts).is_err());
}
