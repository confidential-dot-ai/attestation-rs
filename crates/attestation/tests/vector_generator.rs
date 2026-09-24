//! Generates the standard's test vectors (Appendix B) from first principles and
//! checks them against `docs/standard/vectors/cvm_profile_vectors.json`.
//!
//! This file deliberately shares no code with the library: every formula is
//! written out over the exact byte strings the standard specifies, with its own
//! CBOR and JCS encoders, so the fixture is pinned by two independent
//! computations (this one and `profile_vectors.rs`, which runs the library).
//! `UPDATE_VECTORS=1` rewrites the fixture from this file.

use base64::Engine as _;
use serde_json::{json, Value};
use sha2::{Digest as _, Sha256, Sha384};
use std::collections::BTreeMap;

const FIXTURE: &str = concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../../docs/standard/vectors/cvm_profile_vectors.json"
);

fn sha384(parts: &[&[u8]]) -> Vec<u8> {
    let mut h = Sha384::new();
    for p in parts {
        h.update(p);
    }
    h.finalize().to_vec()
}

fn sha256(parts: &[&[u8]]) -> Vec<u8> {
    let mut h = Sha256::new();
    for p in parts {
        h.update(p);
    }
    h.finalize().to_vec()
}

fn pad64(x: &[u8]) -> Vec<u8> {
    assert!(x.len() <= 64);
    let mut out = x.to_vec();
    out.resize(64, 0);
    out
}

/// Section 5.2: the relying party's binding input.
fn anchor(nonce: &[u8], key: Option<(&str, &[u8])>) -> Vec<u8> {
    let Some((kind, value)) = key else {
        return nonce.to_vec();
    };
    assert!((16..=64).contains(&nonce.len()) && kind.len() <= 255 && value.len() <= 65535);
    sha384(&[
        b"ats-anchor-v1",
        &[nonce.len() as u8],
        nonce,
        &[kind.len() as u8],
        kind.as_bytes(),
        &(value.len() as u16).to_be_bytes(),
        value,
    ])
}

const REG_COUNT: usize = 16;

fn seed() -> Vec<u8> {
    sha384(&[b"ats-mr-v1/seed"])
}

fn header16() -> Vec<u8> {
    let mut h = b"ATS-MR-1".to_vec();
    h.extend_from_slice(&[1, 1, REG_COUNT as u8, 0, 0, 0, 0, 0]);
    h
}

fn genesis(i: u8) -> Vec<u8> {
    sha384(&[&[0u8; 48], b"ats-mr-v1/genesis", &seed(), &[i]])
}

fn extend(r: &[u8], d: &[u8]) -> Vec<u8> {
    sha384(&[r, d])
}

fn record_digest(seq: u64, index: u16, event: &[u8]) -> Vec<u8> {
    sha384(&[
        b"ats-mr-v1/record",
        &seq.to_le_bytes(),
        &index.to_le_bytes(),
        event,
    ])
}

fn commit(regs: &[Vec<u8>], chain_len: u64, caller_data: &[u8]) -> Vec<u8> {
    assert!(regs.len() == REG_COUNT && regs.iter().all(|r| r.len() == 48));
    assert_eq!(caller_data.len(), 64);
    let mut input = b"ats-mr-v1/commit".to_vec();
    for r in regs {
        input.extend_from_slice(r);
    }
    input.extend_from_slice(&chain_len.to_le_bytes());
    input.extend_from_slice(caller_data);
    sha384(&[&input])
}

/// Shortest-form head, RFC 8949 section 4.2.1.
fn cbor_head(major: u8, n: usize) -> Vec<u8> {
    match n {
        0..=23 => vec![major << 5 | n as u8],
        24..=0xff => vec![major << 5 | 24, n as u8],
        0x100..=0xffff => {
            let mut v = vec![major << 5 | 25];
            v.extend_from_slice(&(n as u16).to_be_bytes());
            v
        }
        _ => panic!("no vector needs a longer length"),
    }
}

fn cbor_uint(n: usize) -> Vec<u8> {
    cbor_head(0, n)
}

fn cbor_tstr(s: &str) -> Vec<u8> {
    [cbor_head(3, s.len()), s.as_bytes().to_vec()].concat()
}

fn cbor_bstr(b: &[u8]) -> Vec<u8> {
    [cbor_head(2, b.len()), b.to_vec()].concat()
}

/// A map with unsigned integer keys, which deterministic encoding orders by
/// the encoded key bytes: ascending numeric order for these keys.
fn cbor_map(pairs: &[(usize, Vec<u8>)]) -> Vec<u8> {
    assert!(pairs
        .windows(2)
        .all(|w| cbor_uint(w[0].0) < cbor_uint(w[1].0)));
    let mut out = cbor_head(5, pairs.len());
    for (k, v) in pairs {
        out.extend(cbor_uint(*k));
        out.extend_from_slice(v);
    }
    out
}

/// The `event` bytes of one cvm record.
fn cvm_event(
    domain: &str,
    operation: &str,
    content_digest: &[u8],
    content: Option<&[u8]>,
) -> Vec<u8> {
    let mut pairs = vec![
        (0, cbor_tstr(domain)),
        (1, cbor_tstr(operation)),
        (2, cbor_bstr(content_digest)),
    ];
    if let Some(c) = content {
        pairs.push((3, cbor_bstr(c)));
    }
    cbor_map(&pairs)
}

const CVM_CONTENT_TYPE: usize = 200;
const TPM_ALG_SHA384: usize = 0x000C;

/// One CEL-CBOR record (CEL v1.1 section 5.2) with cvm content.
fn cel_record(recnum: usize, slot: usize, seq: usize, d: &[u8], event: &[u8]) -> Vec<u8> {
    let digests = [
        cbor_head(4, 1),
        cbor_map(&[(0, cbor_uint(TPM_ALG_SHA384)), (1, cbor_bstr(d))]),
    ]
    .concat();
    let content = cbor_map(&[(0, cbor_uint(seq)), (1, cbor_bstr(event))]);
    cbor_map(&[
        (0, cbor_uint(recnum)),
        (1, cbor_uint(slot)),
        (3, digests),
        (9, cbor_uint(CVM_CONTENT_TYPE)),
        (10, content),
    ])
}

/// The same record in CEL-JSON, members in CDDL order.
fn cel_json_record(recnum: usize, slot: usize, seq: usize, d: &[u8], event: &[u8]) -> String {
    format!(
        r#"{{"recnum":{recnum},"pcr":{slot},"digests":[{{"hashAlg":"sha384","digest":"{}"}}],"content_type":"cvm","content":{{"seq":{seq},"event":"{}"}}}}"#,
        hex::encode(d),
        hex::encode(event)
    )
}

/// RFC 8785 for the values the default policy holds: objects with ASCII keys,
/// arrays, ASCII strings and booleans. Keys sort by UTF-16 code unit, which
/// for ASCII is byte order.
fn jcs(v: &Value) -> String {
    match v {
        Value::Object(m) => {
            let sorted: BTreeMap<_, _> = m.iter().collect();
            let members: Vec<_> = sorted
                .into_iter()
                .map(|(k, v)| format!("{}:{}", Value::String(k.clone()), jcs(v)))
                .collect();
            format!("{{{}}}", members.join(","))
        }
        Value::Array(a) => format!("[{}]", a.iter().map(jcs).collect::<Vec<_>>().join(",")),
        Value::String(s) => {
            assert!(s.is_ascii());
            v.to_string()
        }
        Value::Bool(_) => v.to_string(),
        _ => panic!("the default policy holds no {v}"),
    }
}

fn b64u(b: &[u8]) -> String {
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(b)
}

/// The effective default policy, every member with its default.
fn default_policy() -> Value {
    json!({
        "commitment": {"header16": b64u(&header16()), "seed": b64u(&seed())},
        "freshness": {},
        "gpu": {
            "device_policy": {
                "allow_debug": false,
                "require_measres_success": true,
                "require_nonce_match": true,
                "require_secboot": true
            },
            "required": false
        },
        "min_backing": "hardware",
        "policy_bits": {
            "allow_debug": false,
            "allow_migration": false,
            "allow_service_td": false,
            "require_sept_ve_disable": true,
            "require_vmpl0": true,
            "require_zero_reserved_attributes": true
        },
        "reference": {"launch_measurement": [], "pcrs": {}, "registers": {}, "slot_owners": {}},
        "tcb": {
            "floors": {},
            "require_revocation": true,
            "require_signed_collateral": true,
            "tdx_allowed_status": ["UpToDate"]
        }
    })
}

fn generate() -> BTreeMap<&'static str, String> {
    let mut out = BTreeMap::new();
    let mut emit = |k: &'static str, v: &[u8]| {
        out.insert(k, hex::encode(v));
    };

    let nonce: Vec<u8> = (0u8..16).collect();
    let spki = [0x11u8; 32];
    let x509 = [0x22u8; 32];
    let a = anchor(&nonce, Some(("spki-sha256", &spki)));
    emit("nonce", &nonce);
    emit("key_spki_value", &spki);
    emit("key_x509_value", &x509);
    emit("anchor_key", &a);
    emit(
        "anchor_x509",
        &anchor(&nonce, Some(("x509-tbs-sha256", &x509))),
    );
    emit("pad64_anchor_key", &pad64(&a));
    emit("nras_gpu_nonce", &sha256(&[&nonce, b"NVIDIA-GPU-EAT-v1"]));
    emit(
        "nras_switch_nonce",
        &sha256(&[&nonce, b"NVIDIA-SWITCH-EAT-v1"]),
    );

    emit("seed", &seed());
    emit("header16", &header16());
    let mut regs: Vec<_> = (0..REG_COUNT as u8).map(genesis).collect();
    emit("genesis_0", &regs[0]);
    emit("genesis_3", &regs[3]);
    emit("genesis_4", &regs[4]);
    emit("genesis_15", &regs[15]);
    let c0 = commit(&regs, 0, &pad64(&nonce));
    emit("commit_chain0", &c0);
    emit("report_data_chain0", &[header16(), c0].concat());

    // Any bytes serve as the event of this vector.
    let content =
        hex::decode("a3006373386301706d73746172742d636f6e7461696e65720258300102").unwrap();
    let d = record_digest(0, 3, &content);
    regs[3] = extend(&regs[3], &d);
    emit("extend_content", &content);
    emit("extend_digest", &d);
    emit("extend_r3", &regs[3]);
    let c1 = commit(&regs, 1, &pad64(&a));
    emit("commit_chain1", &c1);
    emit("report_data_chain1", &[header16(), c1].concat());

    // The boot record: seq 0, recnum 0, slot 3.
    let bootseed = [0x33u8; 32];
    let boot = cvm_event("ats", "boot", &sha384(&[&bootseed]), None);
    let db = record_digest(0, 3, &boot);
    let boot_rec = cel_record(0, 3, 0, &db, &boot);
    emit("bootseed", &bootseed);
    emit("boot_content", &boot);
    emit("boot_digest", &db);
    emit("boot_r3", &extend(&genesis(3), &db));
    emit("boot_cel_record", &boot_rec);

    // The claim record: seq 1 of the log, recnum 0 of workload slot 4.
    let claim_body = cbor_map(&[(0, cbor_tstr("c8s")), (1, cbor_tstr("workload"))]);
    let claim = cvm_event("ats", "claim", &sha384(&[&claim_body]), Some(&claim_body));
    let dc = record_digest(1, 4, &claim);
    let claim_rec = cel_record(0, 4, 1, &dc, &claim);
    emit("claim_body", &claim_body);
    emit("claim_content", &claim);
    emit("claim_digest", &dc);
    emit("claim_r4", &extend(&genesis(4), &dc));
    emit("claim_cel_record", &claim_rec);
    emit("cel_log", &[cbor_head(4, 2), boot_rec, claim_rec].concat());

    // The commitment over that log: slots 3 and 4 replayed, the rest at
    // genesis, chain_len 2, caller_data = pad64(anchor) for the spki-sha256 key.
    let mut chain: Vec<_> = (0..REG_COUNT as u8).map(genesis).collect();
    chain[3] = extend(&chain[3], &db);
    chain[4] = extend(&chain[4], &dc);
    let c_log = commit(&chain, 2, &pad64(&a));
    emit("commit_b3_log", &c_log);
    emit("report_data_b3_log", &[header16(), c_log].concat());

    // Section 9.3: a dstack runtime event (type 0x08000001) under both versions.
    let (name, payload) = ("app-id", [0xde, 0xad, 0xbe, 0xef]);
    emit("dstack_name", name.as_bytes());
    emit("dstack_payload", &payload);
    let v1 = [
        &0x0800_0001u32.to_le_bytes()[..],
        b":",
        name.as_bytes(),
        b":",
        &payload,
    ]
    .concat();
    emit("dstack_v1_digest", &sha384(&[&v1]));
    let v2 = format!(
        r#"{{"name":"{name}","payload":"{}","type":134217729}}"#,
        hex::encode(payload)
    );
    emit("dstack_v2_preimage", v2.as_bytes());
    emit("dstack_v2_digest", &sha384(&[v2.as_bytes()]));

    let policy = jcs(&default_policy());
    emit("policy_jcs_default", policy.as_bytes());
    emit("policy_digest_default", &sha384(&[policy.as_bytes()]));

    out.insert(
        "cel_log_json",
        format!(
            "[{},{}]",
            cel_json_record(0, 3, 0, &db, &boot),
            cel_json_record(0, 4, 1, &dc, &claim)
        ),
    );
    out
}

/// Appendix B prints every vector; hex values may be split by spaces there.
#[test]
fn the_standard_prints_every_vector() {
    let doc = include_str!("../../../docs/standard/cvm-attestation-v1.md");
    let appendix = doc
        .split("## Appendix B. Test vectors")
        .nth(1)
        .and_then(|a| a.split("## Appendix C.").next())
        .expect("the standard has appendix B");
    let squeezed: String = appendix.chars().filter(|c| !c.is_whitespace()).collect();
    for (key, value) in generate() {
        let shown = match key {
            "policy_jcs_default" => String::from_utf8(hex::decode(&value).unwrap()).unwrap(),
            _ => value,
        };
        assert!(squeezed.contains(&shown), "appendix B does not print {key}");
    }
}

#[test]
fn vectors_reproduce_from_first_principles() {
    let generated = serde_json::to_string_pretty(&generate()).unwrap() + "\n";
    if std::env::var_os("UPDATE_VECTORS").is_some() {
        std::fs::write(FIXTURE, &generated).unwrap();
        return;
    }
    let committed = std::fs::read_to_string(FIXTURE).unwrap();
    assert!(
        committed == generated,
        "the vector fixture differs from what this generator produces; rerun with UPDATE_VECTORS=1 and review the diff"
    );
}
