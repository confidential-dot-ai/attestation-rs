use base64::Engine;
use criterion::{black_box, criterion_group, criterion_main, Criterion};

use attestation::platforms::snp::certs::get_bundled_certs;
use attestation::platforms::snp::claims::extract_claims;
use attestation::platforms::snp::verify::{
    parse_report, verify_cert_chain, verify_report_signature,
};
use attestation::types::ProcessorGeneration;

static SNP_REPORT_BYTES: &[u8] = include_bytes!("../test_data/snp/test-report.bin");
static SNP_VCEK: &[u8] = include_bytes!("../test_data/snp/test-vcek.der");
static IMDS_VCEK: &[u8] = include_bytes!("../test_data/az_snp/imds-vcek.der");
static IMDS_ASK: &[u8] = include_bytes!("../test_data/az_snp/imds-chain-0.der");
static IMDS_ARK: &[u8] = include_bytes!("../test_data/az_snp/imds-chain-1.der");

fn bench_report_parse(c: &mut Criterion) {
    c.bench_function("snp/report_parse", |b| {
        b.iter(|| {
            let report = parse_report(black_box(SNP_REPORT_BYTES)).unwrap();
            black_box(&report);
        });
    });
}

fn bench_claim_extraction(c: &mut Criterion) {
    let report = parse_report(SNP_REPORT_BYTES).unwrap();
    c.bench_function("snp/claim_extraction", |b| {
        b.iter(|| {
            let claims = extract_claims(black_box(&report));
            black_box(&claims);
        });
    });
}

fn bench_cert_chain_verify_rsa_pss(c: &mut Criterion) {
    let (ark_der, ask_der) = get_bundled_certs(ProcessorGeneration::Milan);
    c.bench_function("snp/cert_chain_verify_rsa_pss", |b| {
        b.iter(|| {
            verify_cert_chain(black_box(ark_der), black_box(ask_der), black_box(SNP_VCEK)).unwrap();
        });
    });
}

fn bench_cert_chain_verify_imds(c: &mut Criterion) {
    c.bench_function("snp/cert_chain_verify_imds", |b| {
        b.iter(|| {
            verify_cert_chain(
                black_box(IMDS_ARK),
                black_box(IMDS_ASK),
                black_box(IMDS_VCEK),
            )
            .unwrap();
        });
    });
}

fn bench_evidence_deserialize(c: &mut Criterion) {
    let evidence = attestation::platforms::snp::evidence::SnpEvidence {
        attestation_report: base64::engine::general_purpose::STANDARD.encode(SNP_REPORT_BYTES),
        cert_chain: None,
        event_log: None,
    };
    let json = serde_json::to_string(&evidence).unwrap();

    c.bench_function("snp/evidence_deserialize", |b| {
        b.iter(|| {
            let e: attestation::platforms::snp::evidence::SnpEvidence =
                serde_json::from_str(black_box(&json)).unwrap();
            black_box(&e);
        });
    });
}

fn bench_report_signature_ecdsa(c: &mut Criterion) {
    c.bench_function("snp/report_signature_ecdsa", |b| {
        b.iter(|| {
            verify_report_signature(black_box(SNP_REPORT_BYTES), black_box(SNP_VCEK)).unwrap();
        });
    });
}

criterion_group!(
    benches,
    bench_report_parse,
    bench_claim_extraction,
    bench_cert_chain_verify_rsa_pss,
    bench_cert_chain_verify_imds,
    bench_evidence_deserialize,
    bench_report_signature_ecdsa,
);
criterion_main!(benches);
