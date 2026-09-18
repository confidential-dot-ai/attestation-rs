use std::sync::Arc;

use async_trait::async_trait;

use crate::certs::cache::{
    CertCache, QE_IDENTITY_SIGNING_CHAIN, TCB_SIGNING_CHAIN, TD_QE_IDENTITY_SIGNING_CHAIN,
};

/// A TdxCollateralProvider backed by the service's moka cache.
pub struct CachedTdxProvider {
    pub cache: Arc<CertCache>,
}

impl CachedTdxProvider {
    pub fn new(cache: Arc<CertCache>) -> Self {
        Self { cache }
    }
}

#[async_trait]
impl attestation::TdxCollateralProvider for CachedTdxProvider {
    async fn get_tcb_info(&self, fmspc: &str) -> attestation::Result<Vec<u8>> {
        self.cache
            .get_tdx_collateral("tcb_info", fmspc)
            .await
            .map_err(|e| {
                attestation::AttestationError::CertFetchError(format!(
                    "cached TDX tcb_info fetch: {e}"
                ))
            })
    }

    async fn get_qe_identity(&self) -> attestation::Result<Vec<u8>> {
        self.cache
            .get_tdx_collateral("qe_identity", "default")
            .await
            .map_err(|e| {
                attestation::AttestationError::CertFetchError(format!(
                    "cached TDX qe_identity fetch: {e}"
                ))
            })
    }

    async fn get_td_qe_identity(&self) -> attestation::Result<Vec<u8>> {
        self.cache
            .get_tdx_collateral("td_qe_identity", "default")
            .await
            .map_err(|e| {
                attestation::AttestationError::CertFetchError(format!(
                    "cached TDX td_qe_identity fetch: {e}"
                ))
            })
    }

    async fn get_root_ca_crl(&self) -> attestation::Result<Vec<u8>> {
        self.cache
            .get_tdx_collateral("root_ca_crl", "default")
            .await
            .map_err(|e| {
                attestation::AttestationError::CertFetchError(format!(
                    "cached TDX root_ca_crl fetch: {e}"
                ))
            })
    }

    async fn get_pck_crl(&self, ca: &str) -> attestation::Result<Vec<u8>> {
        self.cache
            .get_tdx_collateral("pck_crl", ca)
            .await
            .map_err(|e| {
                attestation::AttestationError::CertFetchError(format!(
                    "cached TDX pck_crl fetch: {e}"
                ))
            })
    }

    // The library verifies TCB Info and QE Identity signatures only when
    // handed the chain; Ok(None) makes it skip. The cache captures the chain
    // with each body, so these hand it over or fail.
    async fn get_tcb_signing_chain(&self) -> attestation::Result<Option<Vec<u8>>> {
        self.signing_chain(TCB_SIGNING_CHAIN).await
    }

    async fn get_qe_identity_signing_chain(&self) -> attestation::Result<Option<Vec<u8>>> {
        self.signing_chain(QE_IDENTITY_SIGNING_CHAIN).await
    }

    async fn get_td_qe_identity_signing_chain(&self) -> attestation::Result<Option<Vec<u8>>> {
        self.signing_chain(TD_QE_IDENTITY_SIGNING_CHAIN).await
    }

    async fn check_pck_revocation(&self, pck_pem: &[u8]) -> attestation::Result<()> {
        let ca_type = attestation::determine_ca_type(pck_pem)?;
        let pck_crl = self
            .cache
            .get_tdx_collateral("pck_crl", &ca_type)
            .await
            .map_err(|e| attestation::AttestationError::CertFetchError(format!("pck_crl: {e}")))?;
        attestation::check_cert_revocation(pck_pem, &pck_crl)?;
        let root_crl = self
            .cache
            .get_tdx_collateral("root_ca_crl", "default")
            .await
            .map_err(|e| {
                attestation::AttestationError::CertFetchError(format!("root_ca_crl: {e}"))
            })?;
        attestation::check_intermediate_ca_revocation(pck_pem, &root_crl)?;
        Ok(())
    }
}

impl CachedTdxProvider {
    async fn signing_chain(&self, kind: &str) -> attestation::Result<Option<Vec<u8>>> {
        self.cache
            .get_tdx_signing_chain(kind)
            .await
            .map(Some)
            .map_err(|e| {
                attestation::AttestationError::CertFetchError(format!("cached TDX {kind}: {e}"))
            })
    }
}
