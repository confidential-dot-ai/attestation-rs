use std::sync::Arc;

use async_trait::async_trait;

use attestation::platforms::nvidia_gpu::{
    jwks_url_for_endpoint, DefaultNrasProvider, Jwks, NrasProvider, NrasRequest,
};
use attestation::NvidiaGpuArch;

use crate::certs::cache::CertCache;

/// An [`NrasProvider`] backed by the service's moka cache.
///
/// `attest()` is per-request and nonce-tied, so it passes through to the
/// inner [`DefaultNrasProvider`]. `jwks()` is served from the shared
/// [`CertCache`] (TTL configured via `certs.jwks_ttl_hours`), so all
/// concurrent verifications share a single JWKS fetch.
pub struct CachedNrasProvider {
    pub cache: Arc<CertCache>,
    inner: DefaultNrasProvider,
    gpu_jwks_url: String,
    switch_jwks_url: String,
}

impl CachedNrasProvider {
    pub fn new(
        cache: Arc<CertCache>,
        gpu_url: String,
        switch_url: String,
    ) -> attestation::Result<Self> {
        let gpu_jwks_url = jwks_url_for_endpoint(&gpu_url)?;
        let switch_jwks_url = jwks_url_for_endpoint(&switch_url)?;
        let inner = DefaultNrasProvider::with_urls(gpu_url, switch_url);
        Ok(Self {
            cache,
            inner,
            gpu_jwks_url,
            switch_jwks_url,
        })
    }

    fn jwks_url_for(&self, arch: NvidiaGpuArch) -> &str {
        match arch {
            NvidiaGpuArch::Ls10 => &self.switch_jwks_url,
            _ => &self.gpu_jwks_url,
        }
    }
}

#[async_trait]
impl NrasProvider for CachedNrasProvider {
    fn url_for(&self, arch: NvidiaGpuArch) -> &str {
        self.inner.url_for(arch)
    }

    async fn attest(&self, request: &NrasRequest) -> attestation::Result<serde_json::Value> {
        // Per-request, nonce-tied: never cache.
        self.inner.attest(request).await
    }

    async fn jwks(&self, arch: NvidiaGpuArch) -> attestation::Result<Jwks> {
        let url = self.jwks_url_for(arch);
        self.cache.get_jwks(url, false).await.map_err(|e| {
            attestation::AttestationError::JwksFetch(format!("cached JWKS fetch: {e}"))
        })
    }

    async fn jwks_force(&self, arch: NvidiaGpuArch) -> attestation::Result<Jwks> {
        let url = self.jwks_url_for(arch);
        self.cache.get_jwks(url, true).await.map_err(|e| {
            attestation::AttestationError::JwksFetch(format!("cached JWKS force-refresh: {e}"))
        })
    }
}

/// A pair of JWKS URLs (GPU and switch endpoints) plus a cache handle. The
/// background refresh loop uses this so it doesn't need to own a
/// `CachedNrasProvider` (the verifier consumes that).
#[derive(Clone)]
pub struct JwksRefreshHandle {
    pub cache: Arc<CertCache>,
    pub urls: Vec<String>,
}

impl JwksRefreshHandle {
    pub async fn prefetch(&self) -> Vec<(String, anyhow::Result<()>)> {
        let mut out = Vec::with_capacity(self.urls.len());
        for url in &self.urls {
            let r = self.cache.get_jwks(url, false).await.map(|_| ());
            out.push((url.clone(), r));
        }
        out
    }

    pub async fn refresh(&self) {
        for url in &self.urls {
            if let Err(e) = self.cache.get_jwks(url, true).await {
                tracing::warn!(%url, error = %e, "periodic JWKS refresh failed");
            }
        }
    }
}

impl CachedNrasProvider {
    /// Return a [`JwksRefreshHandle`] covering both NRAS endpoints. Used by
    /// the background refresh loop so the verifier can consume the provider.
    pub fn refresh_handle(&self) -> JwksRefreshHandle {
        let mut urls = vec![self.gpu_jwks_url.clone()];
        if self.switch_jwks_url != self.gpu_jwks_url {
            urls.push(self.switch_jwks_url.clone());
        }
        JwksRefreshHandle {
            cache: self.cache.clone(),
            urls,
        }
    }
}
