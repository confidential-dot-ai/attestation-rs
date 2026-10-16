use base64::Engine;
use criterion::{black_box, criterion_group, criterion_main, Criterion};

use attestation::platforms::az_snp::verify::verify_report;
use attestation::AzSnpParams;

static AZ_SNP_HCL_REPORT: &[u8] = include_bytes!("../test_data/az_snp/hcl-report.bin");
static AZ_SNP_EVIDENCE_JSON: &str = include_str!("../test_data/az_snp/evidence-v1.json");
static AZ_SNP_LIVE_EVIDENCE_JSON: &str = include_str!("../test_data/az_snp/live-evidence.json");

fn bench_hcl_report_parse(c: &mut Criterion) {
    c.bench_function("az_snp/hcl_report_parse", |b| {
        b.iter(|| {
            let parsed =
                attestation::platforms::tpm_common::parse_hcl_report(black_box(AZ_SNP_HCL_REPORT))
                    .unwrap();
            black_box(&parsed);
        });
    });
}

fn bench_jwk_ak_extraction(c: &mut Criterion) {
    let parsed = attestation::platforms::tpm_common::parse_hcl_report(AZ_SNP_HCL_REPORT).unwrap();
    c.bench_function("az_snp/jwk_ak_extraction", |b| {
        b.iter(|| {
            let result = attestation::platforms::tpm_common::extract_ak_pub_from_jwk_json(
                black_box(&parsed.var_data),
            )
            .unwrap();
            black_box(&result);
        });
    });
}

fn bench_tpm_ak_pub_extraction(c: &mut Criterion) {
    // Build a synthetic TPM2B_PUBLIC for benchmarking
    let mut var_data = Vec::new();
    let mut content = Vec::new();
    content.extend_from_slice(&[0x00, 0x01]); // RSA
    content.extend_from_slice(&[0x00, 0x0B]); // SHA-256
    content.extend_from_slice(&[0x00; 4]); // objectAttributes
    content.extend_from_slice(&[0x00, 0x20]); // authPolicy size=32
    content.extend_from_slice(&[0xAA; 32]); // authPolicy data
    content.extend_from_slice(&[0x00, 0x10]); // symmetric=NULL
    content.extend_from_slice(&[0x00, 0x10]); // scheme=NULL
    content.extend_from_slice(&[0x08, 0x00]); // keyBits=2048
    content.extend_from_slice(&[0x00, 0x00, 0x00, 0x00]); // exponent=0
    let modulus = vec![0xAB; 256];
    content.extend_from_slice(&(modulus.len() as u16).to_be_bytes());
    content.extend_from_slice(&modulus);
    var_data.extend_from_slice(&(content.len() as u16).to_be_bytes());
    var_data.extend_from_slice(&content);

    c.bench_function("az_snp/tpm_ak_pub_extraction", |b| {
        b.iter(|| {
            let result = attestation::platforms::tpm_common::extract_ak_pub_from_var_data(
                black_box(&var_data),
            )
            .unwrap();
            black_box(&result);
        });
    });
}

fn bench_tpm_quote_decode(c: &mut Criterion) {
    let quote = attestation::platforms::tpm_common::TpmQuote {
        signature: "ab".repeat(256),
        message: "cd".repeat(200),
        pcrs: (0..24).map(|_| "00".repeat(32)).collect(),
    };

    c.bench_function("az_snp/tpm_quote_decode", |b| {
        b.iter(|| {
            let result =
                attestation::platforms::tpm_common::decode_tpm_quote(black_box(&quote)).unwrap();
            black_box(&result);
        });
    });
}

fn bench_tpm_signature_verify(c: &mut Criterion) {
    let envelope: attestation::types::AttestationEvidence =
        serde_json::from_str(AZ_SNP_EVIDENCE_JSON).unwrap();
    let evidence: attestation::platforms::az_snp::evidence::AzSnpEvidence =
        serde_json::from_value(envelope.evidence).unwrap();
    let hcl_bytes = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(evidence.hcl_report.trim_end_matches('='))
        .unwrap();
    let parsed = attestation::platforms::tpm_common::parse_hcl_report(&hcl_bytes).unwrap();
    let sig = hex::decode(&evidence.tpm_quote.signature).unwrap();
    let msg = hex::decode(&evidence.tpm_quote.message).unwrap();

    c.bench_function("az_snp/tpm_signature_verify", |b| {
        b.iter(|| {
            attestation::platforms::tpm_common::verify_tpm_signature(
                black_box(&sig),
                black_box(&msg),
                black_box(&parsed.var_data),
            )
            .unwrap();
        });
    });
}

fn bench_evidence_deserialize(c: &mut Criterion) {
    c.bench_function("az_snp/evidence_deserialize", |b| {
        b.iter(|| {
            let envelope: attestation::types::AttestationEvidence =
                serde_json::from_str(black_box(AZ_SNP_EVIDENCE_JSON)).unwrap();
            let e: attestation::platforms::az_snp::evidence::AzSnpEvidence =
                serde_json::from_value(envelope.evidence).unwrap();
            black_box(&e);
        });
    });
}

fn bench_full_pipeline(c: &mut Criterion) {
    let envelope: attestation::types::AttestationEvidence =
        serde_json::from_str(AZ_SNP_EVIDENCE_JSON).unwrap();
    let evidence: attestation::platforms::az_snp::evidence::AzSnpEvidence =
        serde_json::from_value(envelope.evidence).unwrap();
    let params = AzSnpParams::default();
    let now = chrono::Utc::now().timestamp();

    c.bench_function("az_snp/full_pipeline", |b| {
        b.iter(|| {
            let result = verify_report(black_box(&evidence), black_box(&params), now).unwrap();
            black_box(&result.result);
        });
    });
}

fn bench_full_pipeline_live(c: &mut Criterion) {
    let envelope: attestation::types::AttestationEvidence =
        serde_json::from_str(AZ_SNP_LIVE_EVIDENCE_JSON).unwrap();
    let evidence: attestation::platforms::az_snp::evidence::AzSnpEvidence =
        serde_json::from_value(envelope.evidence).unwrap();
    let params = AzSnpParams::default();
    let now = chrono::Utc::now().timestamp();

    c.bench_function("az_snp/full_pipeline_live", |b| {
        b.iter(|| {
            let result = verify_report(black_box(&evidence), black_box(&params), now).unwrap();
            black_box(&result.result);
        });
    });
}

fn bench_tpm_checks_only(c: &mut Criterion) {
    let envelope: attestation::types::AttestationEvidence =
        serde_json::from_str(AZ_SNP_EVIDENCE_JSON).unwrap();
    let evidence: attestation::platforms::az_snp::evidence::AzSnpEvidence =
        serde_json::from_value(envelope.evidence).unwrap();
    let hcl_bytes = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(evidence.hcl_report.trim_end_matches('='))
        .unwrap();
    let parsed = attestation::platforms::tpm_common::parse_hcl_report(&hcl_bytes).unwrap();
    let (tpm_sig, tpm_msg, tpm_pcrs) =
        attestation::platforms::tpm_common::decode_tpm_quote(&evidence.tpm_quote).unwrap();

    c.bench_function("az_snp/tpm_checks_only", |b| {
        b.iter(|| {
            attestation::platforms::tpm_common::verify_tpm_signature(
                black_box(&tpm_sig),
                black_box(&tpm_msg),
                black_box(&parsed.var_data),
            )
            .unwrap();
            attestation::platforms::tpm_common::verify_tpm_pcrs(
                black_box(&tpm_msg),
                black_box(&tpm_pcrs),
            )
            .unwrap();
        });
    });
}

criterion_group!(
    benches,
    bench_hcl_report_parse,
    bench_jwk_ak_extraction,
    bench_tpm_ak_pub_extraction,
    bench_tpm_quote_decode,
    bench_tpm_signature_verify,
    bench_evidence_deserialize,
    bench_full_pipeline,
    bench_full_pipeline_live,
    bench_tpm_checks_only,
);
criterion_main!(benches);
