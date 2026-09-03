//! Manual smoke test against live AMD KDS. Run on demand:
//! `LOCAL_EVIDENCE=<chainless bare-SNP evidence envelope JSON> cargo test --test kds_live -- --ignored --nocapture`

use std::sync::Arc;

use attestation_api::certs::cache::CertCache;
use attestation_api::certs::enrich::enrich_snp_evidence;
use attestation_api::certs::snp_provider::CachedCertProvider;
use base64::Engine;

#[tokio::test]
#[ignore = "hits live AMD KDS (rate-limited); needs LOCAL_EVIDENCE"]
async fn enriches_real_chainless_evidence_via_kds() {
    let path = std::env::var("LOCAL_EVIDENCE").expect("set LOCAL_EVIDENCE to an evidence file");
    let envelope: serde_json::Value =
        serde_json::from_slice(&std::fs::read(path).unwrap()).unwrap();
    assert_eq!(envelope["platform"], "snp");
    let evidence = envelope["evidence"].clone();
    assert!(evidence["cert_chain"].is_null(), "sample must be chainless");

    let cache = Arc::new(CertCache::new(&Default::default()));
    let provider = Arc::new(CachedCertProvider::new(cache.clone(), false));
    let enriched = enrich_snp_evidence(provider.clone(), evidence).await;

    let vcek_der = base64::engine::general_purpose::STANDARD
        .decode(
            enriched["cert_chain"]["vcek"]
                .as_str()
                .expect("enriched evidence must carry cert_chain.vcek"),
        )
        .unwrap();
    println!("fetched VCEK: {} bytes DER", vcek_der.len());

    // KDS returned the right cert: the report signature must verify.
    let report_bytes = base64::engine::general_purpose::STANDARD
        .decode(enriched["attestation_report"].as_str().unwrap())
        .unwrap();
    attestation::platforms::snp::verify::verify_report_signature(&report_bytes, &vcek_der)
        .expect("report signature must verify against enriched VCEK");

    // Second call is served from the cache.
    let evidence2 = envelope["evidence"].clone();
    let t0 = std::time::Instant::now();
    let enriched2 = enrich_snp_evidence(provider, evidence2).await;
    assert_eq!(enriched2, enriched);
    println!("second enrichment (cache hit) took {:?}", t0.elapsed());
}
