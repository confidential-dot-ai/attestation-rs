#[cfg(not(target_os = "linux"))]
fn main() {}

#[cfg(target_os = "linux")]
use criterion::{black_box, criterion_group, criterion_main, Criterion};

#[cfg(target_os = "linux")]
use attestation::{Context, Policies, Verifier};

#[cfg(target_os = "linux")]
fn bench_generate_evidence_with_data(c: &mut Criterion) {
    let rt = tokio::runtime::Runtime::new().unwrap();
    let custom_data = b"benchmark-custom-report-data";

    c.bench_function("az_snp_attest/generate_with_data", |b| {
        b.to_async(&rt).iter(|| async {
            let evidence =
                attestation::platforms::az_snp::attest::generate_evidence(black_box(custom_data))
                    .await
                    .unwrap();
            black_box(&evidence);
        });
    });
}

#[cfg(target_os = "linux")]
fn bench_generate_evidence_empty(c: &mut Criterion) {
    let rt = tokio::runtime::Runtime::new().unwrap();

    c.bench_function("az_snp_attest/generate_empty", |b| {
        b.to_async(&rt).iter(|| async {
            let evidence =
                attestation::platforms::az_snp::attest::generate_evidence(black_box(b""))
                    .await
                    .unwrap();
            black_box(&evidence);
        });
    });
}

#[cfg(target_os = "linux")]
fn bench_roundtrip(c: &mut Criterion) {
    let rt = tokio::runtime::Runtime::new().unwrap();
    let custom_data = b"benchmark-roundtrip-data";
    let policies = Policies::all();
    let verifier = Verifier::new(Context::new());

    c.bench_function("az_snp_attest/roundtrip", |b| {
        b.to_async(&rt).iter(|| async {
            let evidence =
                attestation::platforms::az_snp::attest::generate_evidence(black_box(custom_data))
                    .await
                    .unwrap();
            let envelope = serde_json::json!({ "platform": "az-snp", "evidence": evidence });
            let result = verifier
                .verify(black_box(envelope.to_string().as_bytes()), &policies)
                .await
                .unwrap();
            black_box(&result);
        });
    });
}

#[cfg(target_os = "linux")]
criterion_group!(
    benches,
    bench_generate_evidence_with_data,
    bench_generate_evidence_empty,
    bench_roundtrip,
);
#[cfg(target_os = "linux")]
criterion_main!(benches);
