use std::sync::Arc;

use async_trait::async_trait;

use crate::certs::cache::CertCache;

/// A CertProvider backed by the service's moka cache with background refresh.
/// This wraps our CertCache and implements the attestation library's CertProvider trait.
pub struct CachedCertProvider {
    pub cache: Arc<CertCache>,
    /// False only under `certs.skip_snp_crl`: the CRL is then never fetched.
    pub check_crl: bool,
}

impl CachedCertProvider {
    pub fn new(cache: Arc<CertCache>, check_crl: bool) -> Self {
        Self { cache, check_crl }
    }
}

#[async_trait]
impl attestation::CertProvider for CachedCertProvider {
    async fn get_snp_vcek(
        &self,
        processor_gen: attestation::ProcessorGeneration,
        chip_id: &[u8; 64],
        reported_tcb: &attestation::SnpTcb,
    ) -> attestation::Result<Vec<u8>> {
        self.cache
            .get_vcek(processor_gen, chip_id, reported_tcb)
            .await
            .map_err(|e| {
                attestation::AttestationError::CollateralUnavailable(format!(
                    "cached VCEK fetch: {e}"
                ))
            })
    }

    async fn get_snp_cert_chain(
        &self,
        processor_gen: attestation::ProcessorGeneration,
    ) -> attestation::Result<(Vec<u8>, Vec<u8>)> {
        self.cache
            .get_cert_chain(processor_gen.product_name())
            .await
            .map_err(|e| {
                attestation::AttestationError::CollateralUnavailable(format!(
                    "cached cert chain fetch: {e}"
                ))
            })
    }

    async fn get_snp_crl(
        &self,
        gen: attestation::ProcessorGeneration,
    ) -> attestation::Result<Option<Vec<u8>>> {
        if !self.check_crl {
            return Ok(None);
        }
        let crl_url = attestation::snp_crl_url(gen);
        let issuer = format!("snp_{}", gen.product_name().to_lowercase());
        let entry = self.cache.get_crl(&issuer, &crl_url).await.map_err(|e| {
            attestation::AttestationError::CollateralUnavailable(format!("cached CRL fetch: {e}"))
        })?;
        Ok(Some(entry.data))
    }
}

#[cfg(test)]
mod tests {
    use std::sync::atomic::{AtomicUsize, Ordering};

    use axum::body::Body;
    use axum::http::{Request, StatusCode};
    use tokio::io::AsyncWriteExt;
    use tower::ServiceExt;

    use super::*;
    use crate::config::Config;
    use crate::AppState;

    /// An AMD KDS stand-in that is down: it counts connections and answers 500.
    async fn kds_outage() -> (String, Arc<AtomicUsize>) {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let hits = Arc::new(AtomicUsize::new(0));
        let counter = hits.clone();
        tokio::spawn(async move {
            while let Ok((mut sock, _)) = listener.accept().await {
                counter.fetch_add(1, Ordering::SeqCst);
                let _ = sock
                    .write_all(b"HTTP/1.1 500 Internal Server Error\r\nContent-Length: 0\r\nConnection: close\r\n\r\n")
                    .await;
            }
        });
        (format!("http://{addr}"), hits)
    }

    /// POSTs the Genoa fixture (VCEK inline, so only the CRL is fetched) to
    /// `/verify` on a service whose AMD KDS is `kds`.
    async fn verify_genoa(kds: String, check_crl: bool) -> (StatusCode, serde_json::Value) {
        let config = Config::default();
        let cache = Arc::new(CertCache::with_client_and_upstream(
            &config.certs,
            reqwest::Client::new(),
            Some(kds),
        ));
        let verifier = attestation::Verifier::new(
            attestation::Context::new()
                .with_cert_provider(CachedCertProvider::new(cache.clone(), check_crl)),
        );
        let state = AppState {
            config: Arc::new(config),
            cert_cache: cache,
            token_issuer: None,
            verifier: Arc::new(verifier),
        };
        let fixture: serde_json::Value = serde_json::from_str(include_str!(
            "../../../attestation/test_data/snp/live-evidence-genoa.json"
        ))
        .unwrap();
        let body = serde_json::json!({
            "platform": "snp",
            "evidence": fixture["evidence"],
            "policies": { "snp": {} }
        });
        let resp = crate::server::build_api_router(state)
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/verify")
                    .header("content-type", "application/json")
                    .body(Body::from(body.to_string()))
                    .unwrap(),
            )
            .await
            .unwrap();
        let status = resp.status();
        let body = axum::body::to_bytes(resp.into_body(), usize::MAX)
            .await
            .unwrap();
        (status, serde_json::from_slice(&body).unwrap())
    }

    #[tokio::test]
    async fn a_crl_outage_is_collateral_unavailable_not_a_pass() {
        let (kds, hits) = kds_outage().await;
        let (status, json) = verify_genoa(kds, true).await;

        assert_eq!(status, StatusCode::BAD_GATEWAY);
        assert_eq!(json["error"], "collateral_unavailable");
        assert_eq!(hits.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn skipping_the_crl_never_fetches_it() {
        let (kds, hits) = kds_outage().await;
        let (status, json) = verify_genoa(kds, false).await;

        assert_eq!(status, StatusCode::OK);
        assert_eq!(json["passed"], true);
        assert_eq!(json["result"]["platform"], "snp");
        assert_eq!(json["result"].get("crl_ok"), Some(&serde_json::Value::Null));
        assert_eq!(hits.load(Ordering::SeqCst), 0);
    }
}
