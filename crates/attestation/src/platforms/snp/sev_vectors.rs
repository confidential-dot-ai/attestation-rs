//! Inputs for the differential test against sev 7.1.0's `crypto_nossl`
//! verifier. `test_data/snp/sev-7.1.0-verdicts.json` records, per vector id,
//! whether sev accepted it; the ids and inputs are derived here by fixed
//! rules so the recording and the comparison see identical bytes.
//!
//! The verdicts were recorded at 212f98f, where sev 7.1.0 still had
//! `crypto_nossl`, by running each [`Input`] through the sev call it names.
//! sev cannot be a dev-dependency with that feature: it would put p384 0.13,
//! and crypto-bigint 0.5 with it, back into Cargo.lock. Changing a vector
//! means re-recording: in a worktree at 212f98f, copy this file in, add the
//! following to `snp/mod.rs`, and run
//! `SEV_VERDICTS_OUT=<path> cargo test -p attestation --lib record_sev_verdicts`.
//!
//! ```text
//! #[cfg(test)]
//! mod sev_vectors;
//!
//! #[cfg(test)]
//! #[test]
//! fn record_sev_verdicts() {
//!     use sev::certs::snp::{Certificate, Chain, Verifiable};
//!     use sev::firmware::guest::AttestationReport;
//!     use sev::parser::ByteParser;
//!     use sev_vectors::{vectors, Input};
//!     let mut out = serde_json::Map::new();
//!     for v in vectors() {
//!         let ok = match &v.input {
//!             Input::Chain(a, b, c) => Chain::from_der(a, b, c)
//!                 .and_then(|ch| (&ch).verify().map(|_| ()))
//!                 .is_ok(),
//!             Input::Pair(a, b) => Certificate::from_der(a)
//!                 .and_then(|a| Certificate::from_der(b).and_then(|b| (&a, &b).verify()))
//!                 .is_ok(),
//!             Input::Report(r, k) => AttestationReport::from_bytes(r)
//!                 .and_then(|r| Certificate::from_der(k).and_then(|k| (&k, &r).verify()))
//!                 .is_ok(),
//!         };
//!         assert!(out.insert(v.id.clone(), ok.into()).is_none(), "dup {}", v.id);
//!     }
//!     let path = std::env::var("SEV_VERDICTS_OUT").unwrap();
//!     std::fs::write(path, serde_json::to_string_pretty(&out).unwrap() + "\n").unwrap();
//! }
//! ```

use crate::platforms::snp::certs;
use crate::types::ProcessorGeneration;

pub(crate) enum Input {
    /// ARK, ASK/ASVK, VEK: `sev::certs::snp::Chain::from_der(..).verify()`.
    Chain(Vec<u8>, Vec<u8>, Vec<u8>),
    /// Signer, signee: `(&Certificate, &Certificate).verify()`.
    Pair(Vec<u8>, Vec<u8>),
    /// Report bytes, VEK: `(&Certificate, &AttestationReport).verify()`.
    Report(Vec<u8>, Vec<u8>),
}

pub(crate) struct Vector {
    pub id: String,
    pub input: Input,
}

const GENS: [(&str, ProcessorGeneration); 3] = [
    ("milan", ProcessorGeneration::Milan),
    ("genoa", ProcessorGeneration::Genoa),
    ("turin", ProcessorGeneration::Turin),
];

pub(crate) const TEST_VCEK: &[u8] = include_bytes!("../../../test_data/snp/test-vcek.der");
pub(crate) const LIVE_VCEK_GENOA: &[u8] =
    include_bytes!("../../../test_data/snp/live-vcek-genoa.der");
const TEST_VLEK: &[u8] = include_bytes!("../../../test_data/snp/test-vlek.der");
const KMR_VCEK: &[u8] = include_bytes!("../../../test_data/snp/kmr-vcek.der");
const IMDS_VCEK: &[u8] = include_bytes!("../../../test_data/az_snp/imds-vcek.der");
const INVALID_LEGACY: &[u8] = include_bytes!("../../../test_data/snp/test-vcek-invalid-legacy.der");
const INVALID_NEW: &[u8] = include_bytes!("../../../test_data/snp/test-vcek-invalid-new.der");
pub(crate) const INTEL_ROOT: &[u8] = include_bytes!("../../../certs/intel/sgx-root-ca.der");

pub(crate) const TEST_REPORT: &[u8] = include_bytes!("../../../test_data/snp/test-report.bin");
const LIVE_REPORT_V5: &[u8] = include_bytes!("../../../test_data/snp/live-report-v5-genoa.bin");
const TEST_VLEK_REPORT: &[u8] = include_bytes!("../../../test_data/snp/test-vlek-report.bin");
const KMR_REPORT: &[u8] = include_bytes!("../../../test_data/snp/kmr-full-report.bin");
const KMR_FORGE_REPORT: &[u8] = include_bytes!("../../../test_data/snp/kmr-forge/report.bin");
const KMR_VMPL1_REPORT: &[u8] = include_bytes!("../../../test_data/snp/kmr-vmpl/vmpl1.report.bin");

/// Every VEK-position certificate, including ones of the wrong kind.
fn veks() -> Vec<(&'static str, &'static [u8])> {
    vec![
        ("test-vcek", TEST_VCEK),
        ("live-vcek-genoa", LIVE_VCEK_GENOA),
        ("test-vlek", TEST_VLEK),
        ("kmr-vcek", KMR_VCEK),
        ("imds-vcek", IMDS_VCEK),
        ("invalid-legacy", INVALID_LEGACY),
        ("invalid-new", INVALID_NEW),
        // RSA key where a P-384 key belongs.
        ("milan-ark", certs::get_ark(ProcessorGeneration::Milan)),
        // P-256 key where a P-384 key belongs.
        ("intel-root", INTEL_ROOT),
        ("garbage", &[0x30, 0x03, 0x02, 0x01, 0x00]),
    ]
}

fn reports() -> Vec<(&'static str, &'static [u8])> {
    vec![
        ("test-report", TEST_REPORT),
        ("live-report-v5-genoa", LIVE_REPORT_V5),
        ("test-vlek-report", TEST_VLEK_REPORT),
        ("kmr-full-report", KMR_REPORT),
        ("kmr-forge-report", KMR_FORGE_REPORT),
        ("kmr-vmpl1-report", KMR_VMPL1_REPORT),
    ]
}

/// The report/VEK pairs that verify, the base for report tampering.
fn good_reports() -> Vec<(&'static str, &'static [u8], &'static [u8])> {
    vec![
        ("test-report", TEST_REPORT, TEST_VCEK),
        ("live-report-v5-genoa", LIVE_REPORT_V5, LIVE_VCEK_GENOA),
        ("test-vlek-report", TEST_VLEK_REPORT, TEST_VLEK),
        ("kmr-full-report", KMR_REPORT, KMR_VCEK),
    ]
}

/// Good chains (ARK, issuer, VEK), the base for certificate tampering.
fn good_chains() -> Vec<(&'static str, [&'static [u8]; 3])> {
    use ProcessorGeneration::{Genoa, Milan};
    vec![
        (
            "milan/test-vcek",
            [certs::get_ark(Milan), certs::get_ask(Milan), TEST_VCEK],
        ),
        (
            "genoa/live-vcek-genoa",
            [
                certs::get_ark(Genoa),
                certs::get_ask(Genoa),
                LIVE_VCEK_GENOA,
            ],
        ),
        (
            "milan/test-vlek",
            [certs::get_ark(Milan), certs::get_asvk(Milan), TEST_VLEK],
        ),
    ]
}

const RSA_PSS_OID: [u8; 11] = [
    0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x0a,
];

fn flip(bytes: &[u8], at: usize, mask: u8) -> Vec<u8> {
    let mut out = bytes.to_vec();
    out[at] ^= mask;
    out
}

/// Rewrite the last byte of every occurrence of the RSASSA-PSS OID that
/// `pick` selects (index among occurrences) to `last`.
fn rewrite_pss_oid(der: &[u8], pick: impl Fn(usize, usize) -> bool, last: u8) -> Vec<u8> {
    let at: Vec<usize> = der
        .windows(RSA_PSS_OID.len())
        .enumerate()
        .filter(|(_, w)| *w == RSA_PSS_OID)
        .map(|(i, _)| i)
        .collect();
    let mut out = der.to_vec();
    for (n, i) in at.iter().enumerate() {
        if pick(n, at.len()) {
            out[i + RSA_PSS_OID.len() - 1] = last;
        }
    }
    out
}

/// Ways to tamper with a certificate, by name.
fn cert_tampers(der: &[u8]) -> Vec<(&'static str, Vec<u8>)> {
    let n = der.len();
    vec![
        ("sig-last-byte", flip(der, n - 1, 0x01)),
        ("sig-first-bytes", flip(der, n - 400.min(n / 4), 0x80)),
        ("tbs-mid", flip(der, n / 3, 0x01)),
        ("tbs-early", flip(der, 40, 0x01)),
        // The outer signatureAlgorithm becomes sha512WithRSAEncryption (…1.1.13).
        (
            "outer-alg-sha512-rsa",
            rewrite_pss_oid(der, |i, c| i + 1 == c, 0x0d),
        ),
        // The signed (inner) signature algorithm only.
        (
            "inner-alg-sha512-rsa",
            rewrite_pss_oid(der, |i, _| i == 0, 0x0d),
        ),
        ("truncated", der[..n - 1].to_vec()),
    ]
}

/// The signed report occupies 0x000..0x2A0, the signature R at 0x2A0 and S at
/// 0x2E8 (72 little-endian bytes each, 48 significant for P-384). Written out
/// rather than taken from `signatures`, so the vectors do not move with it.
fn report_tampers(report: &[u8]) -> Vec<(&'static str, Vec<u8>)> {
    const R: usize = 0x2A0;
    const S: usize = 0x2E8;
    let set = |range: std::ops::Range<usize>, v: u8| {
        let mut out = report.to_vec();
        out[range].iter_mut().for_each(|b| *b = v);
        out
    };
    let swap_rs = {
        let mut out = report.to_vec();
        let (r, s) = (report[R..R + 72].to_vec(), report[S..S + 72].to_vec());
        out[R..R + 72].copy_from_slice(&s);
        out[S..S + 72].copy_from_slice(&r);
        out
    };
    vec![
        ("sig-algo-2", set(0x34..0x35, 2)),
        ("report-data", flip(report, 0x50, 0x01)),
        ("measurement", flip(report, 0x90, 0xff)),
        ("chip-id", flip(report, 0x1A0, 0x01)),
        ("last-signed-byte", flip(report, R - 1, 0x01)),
        ("r-byte-0", flip(report, R, 0x01)),
        ("r-byte-47", flip(report, R + 47, 0x01)),
        ("r-pad-48", flip(report, R + 48, 0x01)),
        ("r-pad-71", flip(report, R + 71, 0x80)),
        ("s-byte-0", flip(report, S, 0x01)),
        ("s-byte-47", flip(report, S + 47, 0x01)),
        ("s-pad-48", flip(report, S + 48, 0x01)),
        ("sig-reserved", flip(report, S + 72, 0x01)),
        ("sig-reserved-last", flip(report, report.len() - 1, 0x01)),
        ("r-zero", set(R..R + 72, 0)),
        ("s-zero", set(S..S + 72, 0)),
        ("r-max", set(R..R + 48, 0xff)),
        ("s-max", set(S..S + 48, 0xff)),
        ("swap-r-s", swap_rs),
        ("truncated", report[..report.len() - 1].to_vec()),
    ]
}

pub(crate) fn vectors() -> Vec<Vector> {
    let mut out = Vec::new();
    let mut push = |id: String, input: Input| out.push(Vector { id, input });

    // Every bundled AMD CA pairing, within and across generations.
    for (g, gen) in GENS {
        let (ark, ask) = certs::get_bundled_certs(gen);
        let asvk = certs::get_asvk(gen);
        for (h, other) in GENS {
            let (oark, oask) = certs::get_bundled_certs(other);
            let oasvk = certs::get_asvk(other);
            for (sname, signer) in [("ark", ark), ("ask", ask)] {
                for (ename, signee) in [("ark", oark), ("ask", oask), ("asvk", oasvk)] {
                    push(
                        format!("pair/{g}-{sname}/{h}-{ename}"),
                        Input::Pair(signer.to_vec(), signee.to_vec()),
                    );
                }
            }
        }
        // Every VEK under every issuer of every generation.
        for (vname, vek) in veks() {
            for (iname, issuer) in [("ask", ask), ("asvk", asvk)] {
                push(
                    format!("chain/{g}-{iname}/{vname}"),
                    Input::Chain(ark.to_vec(), issuer.to_vec(), vek.to_vec()),
                );
            }
            push(
                format!("vek-pair/{g}-ask/{vname}"),
                Input::Pair(ask.to_vec(), vek.to_vec()),
            );
        }
    }

    // Each good chain with its members reordered and each member tampered.
    for (name, chain) in good_chains() {
        let [ark, issuer, vek] = chain;
        let orders = [
            ("issuer-ark-vek", [issuer, ark, vek]),
            ("ark-vek-issuer", [ark, vek, issuer]),
            ("vek-issuer-ark", [vek, issuer, ark]),
            ("ark-ark-vek", [ark, ark, vek]),
            ("ark-issuer-issuer", [ark, issuer, issuer]),
        ];
        for (oname, [a, b, c]) in orders {
            push(
                format!("order/{name}/{oname}"),
                Input::Chain(a.to_vec(), b.to_vec(), c.to_vec()),
            );
        }
        for (slot, sname) in ["ark", "issuer", "vek"].into_iter().enumerate() {
            for (tname, t) in cert_tampers(chain[slot]) {
                let mut c = chain.map(<[u8]>::to_vec);
                c[slot] = t;
                let [a, b, c] = c;
                push(
                    format!("tamper/{name}/{sname}/{tname}"),
                    Input::Chain(a, b, c),
                );
            }
        }
    }

    // Every report against every VEK-position certificate.
    for (rname, report) in reports() {
        for (vname, vek) in veks() {
            push(
                format!("report/{rname}/{vname}"),
                Input::Report(report.to_vec(), vek.to_vec()),
            );
        }
    }

    // Each good report tampered.
    for (rname, report, vek) in good_reports() {
        for (tname, t) in report_tampers(report) {
            push(
                format!("report-tamper/{rname}/{tname}"),
                Input::Report(t, vek.to_vec()),
            );
        }
    }

    out
}
