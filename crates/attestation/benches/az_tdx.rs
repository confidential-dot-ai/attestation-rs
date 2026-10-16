use criterion::{black_box, criterion_group, criterion_main, Criterion};

use attestation::{Context, Policies, Verifier};

static AZ_TDX_HCL_REPORT: &[u8] = include_bytes!("../test_data/az_tdx/hcl-report.bin");
static AZ_TDX_EVIDENCE_JSON: &str = include_str!("../test_data/az_tdx/evidence-v1.json");

fn bench_hcl_report_parse(c: &mut Criterion) {
    c.bench_function("az_tdx/hcl_report_parse", |b| {
        b.iter(|| {
            let parsed =
                attestation::platforms::tpm_common::parse_hcl_report(black_box(AZ_TDX_HCL_REPORT))
                    .unwrap();
            black_box(&parsed);
        });
    });
}

fn bench_evidence_deserialize(c: &mut Criterion) {
    c.bench_function("az_tdx/evidence_deserialize", |b| {
        b.iter(|| {
            let envelope: attestation::types::AttestationEvidence =
                serde_json::from_str(black_box(AZ_TDX_EVIDENCE_JSON)).unwrap();
            let e: attestation::platforms::az_tdx::evidence::AzTdxEvidence =
                serde_json::from_value(envelope.evidence).unwrap();
            black_box(&e);
        });
    });
}

fn bench_full_pipeline(c: &mut Criterion) {
    let policies = Policies::all();
    let verifier = Verifier::new(Context::new());
    let rt = tokio::runtime::Runtime::new().unwrap();

    c.bench_function("az_tdx/full_pipeline", |b| {
        b.to_async(&rt).iter(|| async {
            let result = verifier
                .verify(black_box(AZ_TDX_EVIDENCE_JSON.as_bytes()), &policies)
                .await
                .unwrap();
            black_box(&result);
        });
    });
}

criterion_group!(
    benches,
    bench_hcl_report_parse,
    bench_evidence_deserialize,
    bench_full_pipeline,
);
criterion_main!(benches);
