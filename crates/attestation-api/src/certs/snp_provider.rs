use std::sync::Arc;

use async_trait::async_trait;

use crate::certs::cache::CertCache;

/// A CertProvider backed by the service's moka cache with background refresh.
/// This wraps our CertCache and implements the attestation library's CertProvider trait.
pub struct CachedCertProvider {
    pub cache: Arc<CertCache>,
    pub require_crl: bool,
}

impl CachedCertProvider {
    pub fn new(cache: Arc<CertCache>, require_crl: bool) -> Self {
        Self { cache, require_crl }
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
                attestation::AttestationError::CertFetchError(format!("cached VCEK fetch: {e}"))
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
                attestation::AttestationError::CertFetchError(format!(
                    "cached cert chain fetch: {e}"
                ))
            })
    }

    async fn get_snp_crl(
        &self,
        gen: attestation::ProcessorGeneration,
    ) -> attestation::Result<Option<Vec<u8>>> {
        let crl_url = attestation::snp_crl_url(gen);
        let issuer = format!("snp_{}", gen.product_name().to_lowercase());
        match self.cache.get_crl(&issuer, &crl_url).await {
            Ok(entry) => Ok(Some(entry.data)),
            Err(e) => {
                if self.require_crl {
                    Err(attestation::AttestationError::CertFetchError(format!(
                        "CRL fetch failed (require_crl=true): {e}"
                    )))
                } else {
                    tracing::warn!(%issuer, error = %e, "CRL unavailable, skipping revocation check");
                    Ok(None)
                }
            }
        }
    }
}
