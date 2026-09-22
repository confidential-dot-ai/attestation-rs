//! Appendix B vectors, from `docs/design/vectors/cvm_profile_vectors.json`.
//! Every key in the fixture must be consumed, so a vector added to the script
//! without a check here fails the test.

use attestation::profile::binding::{anchor, nras_gpu_nonce, nras_switch_nonce, pad64};
use attestation::profile::registers::{
    boot_record, cel_record, claim_body, claim_record, commit, extend, genesis, record_digest,
    report_data, HEADER16, REG_COUNT, SEED,
};
use std::collections::BTreeMap;

const FIXTURE: &str = include_str!("../../../docs/design/vectors/cvm_profile_vectors.json");

struct Vectors(BTreeMap<String, String>, std::cell::RefCell<Vec<String>>);

impl Vectors {
    fn get(&self, key: &str) -> Vec<u8> {
        self.1.borrow_mut().push(key.to_string());
        hex::decode(
            self.0
                .get(key)
                .unwrap_or_else(|| panic!("vector {key} missing")),
        )
        .unwrap()
    }
    fn check(&self, key: &str, actual: &[u8]) {
        assert_eq!(
            hex::encode(actual),
            hex::encode(self.get(key)),
            "vector {key}"
        );
    }
}

#[test]
fn appendix_b_vectors() {
    let v = Vectors(serde_json::from_str(FIXTURE).unwrap(), Default::default());
    let nonce = v.get("nonce");
    assert_eq!(nonce, (0u8..16).collect::<Vec<_>>());

    let spki = v.get("key_spki_value");
    let a = anchor(&nonce, Some(("spki-sha256", &spki))).unwrap();
    v.check("anchor_key", &a);
    v.check("pad64_anchor_key", &pad64(&a).unwrap());
    let x509 = v.get("key_x509_value");
    v.check(
        "anchor_x509",
        &anchor(&nonce, Some(("x509-tbs-sha256", &x509))).unwrap(),
    );
    v.check("nras_gpu_nonce", &nras_gpu_nonce(&nonce));
    v.check("nras_switch_nonce", &nras_switch_nonce(&nonce));

    v.check("seed", &SEED);
    v.check("header16", &HEADER16);
    let mut regs = [[0u8; 48]; REG_COUNT];
    for (i, r) in regs.iter_mut().enumerate() {
        *r = genesis(i as u8, &SEED);
    }
    for i in [0usize, 3, 15] {
        v.check(&format!("genesis_{i}"), &regs[i]);
    }
    let c0 = commit(&regs, 0, &pad64(&nonce).unwrap());
    v.check("commit_chain0", &c0);
    v.check("report_data_chain0", &report_data(&HEADER16, &c0));

    let content = v.get("extend_content");
    let d = record_digest(0, 3, &content);
    v.check("extend_digest", &d);
    regs[3] = extend(&regs[3], &d);
    v.check("extend_r3", &regs[3]);
    let c1 = commit(&regs, 1, &pad64(&a).unwrap());
    v.check("commit_chain1", &c1);
    v.check("report_data_chain1", &report_data(&HEADER16, &c1));

    let bootseed: [u8; 32] = v.get("bootseed").try_into().unwrap();
    let boot = boot_record(&bootseed);
    v.check("boot_content", &boot);
    let db = record_digest(0, 3, &boot);
    v.check("boot_digest", &db);
    v.check("boot_r3", &extend(&genesis(3, &SEED), &db));
    v.check("boot_cel_record", &cel_record(0, 3, &db, &boot));

    v.check("claim_body", &claim_body("c8s", "workload").unwrap());
    let claim = claim_record("c8s", "workload").unwrap();
    v.check("claim_content", &claim);
    let dc = record_digest(1, 4, &claim);
    v.check("claim_digest", &dc);
    v.check("claim_r4", &extend(&genesis(4, &SEED), &dc));
    v.check("claim_cel_record", &cel_record(1, 4, &dc, &claim));

    // Section 5.1: the default policy's identifier.
    let policy = attestation::profile::VerifyPolicy::default();
    let canonical = policy.canonical_json();
    v.check("policy_jcs_default", canonical.as_bytes());
    {
        use sha2::Digest as _;
        v.check(
            "policy_digest_default",
            &sha2::Sha384::digest(canonical.as_bytes()),
        );
    }
    {
        use base64::Engine;
        let digest = v.get("policy_digest_default");
        assert_eq!(
            policy.id(),
            format!(
                "ni:///sha-384;{}",
                base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(digest)
            )
        );
    }

    let used: std::collections::BTreeSet<_> = v.1.borrow().iter().cloned().collect();
    let unused: Vec<_> = v.0.keys().filter(|k| !used.contains(*k)).collect();
    assert!(unused.is_empty(), "vectors without a check: {unused:?}");
}
