//! `NrasProvider` trait + default implementation.
//!
//! Implementations are pluggable so embedders can pre-stage NRAS responses
//! and JWKS for offline / air-gapped operation.

use async_trait::async_trait;
use serde::{Deserialize, Serialize};

use crate::error::{AttestationError, Result};
use crate::types::NvidiaGpuArch;

/// The production NRAS origin: the `iss` of every token it signs, and the
/// host of its JWKS.
pub const NRAS_BASE_URL: &str = "https://nras.attestation.nvidia.com";

/// Default NRAS GPU endpoint (API v4). Override via `NV_NRAS_GPU_URL`.
pub const NRAS_GPU_URL: &str = "https://nras.attestation.nvidia.com/v4/attest/gpu";

/// Default NRAS NVSwitch endpoint (API v4). Override via `NV_NRAS_SWITCH_URL`.
pub const NRAS_SWITCH_URL: &str = "https://nras.attestation.nvidia.com/v4/attest/switch";

/// The claims schema the v4 endpoints answer with, and the one NVIDIA's own
/// SDK requests from them: the `x-nvidia-ver` of the overall token.
pub const NRAS_CLAIMS_VERSION: &str = "3.0";

/// Header name nvtrust uses to opt in to "certificate hold" OCSP statuses.
pub const HEADER_OCSP_ALLOW_CERT_HOLD: &str = "X-NVIDIA-OCSP-ALLOW-CERT-HOLD";

/// NRAS POST body: the `NRASAttestRequestV4` of NVIDIA's attestation SDK,
/// unchanged from the v3 body.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NrasRequest {
    /// Hex-encoded SPDM nonce. All entries in `evidence_list` were collected
    /// with this nonce.
    pub nonce: String,
    pub evidence_list: Vec<NrasEvidenceEntry>,
    pub arch: NvidiaGpuArch,
    /// Claims schema version; the v4 endpoints take `"3.0"`.
    pub claims_version: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NrasEvidenceEntry {
    /// Base64 SPDM blob.
    pub evidence: String,
    /// Base64-encoded PEM cert chain.
    pub certificate: String,
}

/// JWKS (JSON Web Key Set) returned by `/.well-known/jwks.json`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Jwks {
    pub keys: Vec<JwksKey>,
}

/// One key entry inside a JWKS. NRAS serves ES384 keys with `x5c` cert
/// chains; the verifier consumes the public point from the leaf certificate.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JwksKey {
    pub kid: String,
    pub kty: String,
    #[serde(default)]
    pub alg: Option<String>,
    #[serde(default)]
    pub crv: Option<String>,
    #[serde(default)]
    pub x: Option<String>,
    #[serde(default)]
    pub y: Option<String>,
    /// Base64 (standard) DER-encoded X.509 certs. Leaf first.
    #[serde(default)]
    pub x5c: Option<Vec<String>>,
}

/// Pluggable NRAS access. Implementors can hit the live service, replay a
/// recorded fixture, or fan out to a cache.
///
/// On `wasm32` the future returned by the trait methods is `!Send` because
/// `reqwest`'s wasm response futures hold `js-sys` `Rc` types. Native callers
/// retain `Send` bounds; embedders that build for both targets should keep
/// provider calls on a single task or use a runtime that doesn't require
/// `Send` (e.g. tokio's current-thread or `wasm_bindgen_futures`).
#[cfg_attr(not(target_arch = "wasm32"), async_trait)]
#[cfg_attr(target_arch = "wasm32", async_trait(?Send))]
pub trait NrasProvider: Send + Sync {
    /// Which URL to use for a given arch. GPU vs. switch endpoints differ.
    fn url_for(&self, arch: NvidiaGpuArch) -> &str;

    /// Claims schema version to request from NRAS (the `claims_version` field
    /// of the POST body); the verifier requires the overall token's
    /// `x-nvidia-ver` to equal it. Defaults to [`NRAS_CLAIMS_VERSION`].
    fn claims_version(&self) -> &str {
        NRAS_CLAIMS_VERSION
    }

    /// The `iss` every token from `arch`'s endpoint must carry. Defaults to
    /// the endpoint's origin, which is what NRAS issues; a provider that
    /// routes through a proxy overrides this with the real NRAS origin.
    fn issuer(&self, arch: NvidiaGpuArch) -> Result<String> {
        origin_of(self.url_for(arch))
    }

    /// Whether requests ask NRAS to accept device certificates whose OCSP
    /// status is on hold. The profile appraisal refuses such a provider; a
    /// provider that wraps another must forward this.
    fn accepts_certificate_hold(&self) -> bool {
        false
    }

    /// POST `request` to the appropriate NRAS endpoint and return the raw
    /// response body. NRAS returns a JSON value that is either a single JWT
    /// string or a "detached EAT" 2-tuple `[ ["JWT", "<top>"], { sub: "<jwt>" } ]`.
    async fn attest(&self, request: &NrasRequest) -> Result<serde_json::Value>;

    /// Fetch (and ideally cache) the JWKS associated with the endpoint that
    /// signed responses.
    async fn jwks(&self, arch: NvidiaGpuArch) -> Result<Jwks>;

    /// Force a refetch, bypassing any cache. Default impl just calls
    /// [`Self::jwks`]; provider implementations that cache should override
    /// this so the verify path can recover from a `kid` rotation.
    async fn jwks_force(&self, arch: NvidiaGpuArch) -> Result<Jwks> {
        self.jwks(arch).await
    }
}

/// Default NRAS provider.
///
/// Works on every target `reqwest` supports — native (tokio + rustls) and
/// `wasm32` (browser `fetch` / Workers / Node / Deno). JWKS is cached in
/// memory; on a `kid` miss the cache is bypassed and refetched.
///
/// Browser caveat: NRAS's attest endpoints did not respond to CORS preflight
/// on v3 (`OPTIONS` returned 403; v4 is unchecked), so browser callers must
/// route attest requests through a same-origin proxy or inject a custom
/// [`NrasProvider`], setting `issuer` to the real NRAS origin. The JWKS
/// endpoint *is* CORS-open (`access-control-allow-origin: *`) and works
/// directly from browsers.
pub struct DefaultNrasProvider {
    pub gpu_url: String,
    pub switch_url: String,
    pub claims_version: String,
    /// The `iss` to require, when the endpoints are not NRAS's own origin
    /// (a proxy). `None` requires each endpoint's origin. Override via
    /// `NV_NRAS_ISSUER`.
    pub issuer: Option<String>,
    pub allow_hold_cert: bool,
    pub service_key: Option<String>,
    client: reqwest::Client,
    // NRAS serves a single JWKS at `/.well-known/jwks.json` per host, and both
    // the GPU and switch endpoints (per `with_urls`) share that host in
    // practice. A single slot is enough — reconfiguring to a different host
    // simply evicts the prior entry on the next fetch.
    jwks_cache: std::sync::Arc<std::sync::RwLock<Option<JwksCacheEntry>>>,
}

/// TTL for cached JWKS entries.
#[cfg(not(target_arch = "wasm32"))]
pub const JWKS_TTL: std::time::Duration = std::time::Duration::from_secs(3600);

struct JwksCacheEntry {
    url: String,
    jwks: Jwks,
    #[cfg(not(target_arch = "wasm32"))]
    fetched_at: std::time::Instant,
}

impl JwksCacheEntry {
    fn is_fresh(&self) -> bool {
        #[cfg(not(target_arch = "wasm32"))]
        {
            self.fetched_at.elapsed() < JWKS_TTL
        }
        #[cfg(target_arch = "wasm32")]
        {
            true
        }
    }
}

impl Default for DefaultNrasProvider {
    fn default() -> Self {
        Self::new()
    }
}

impl DefaultNrasProvider {
    #[must_use]
    pub fn new() -> Self {
        Self::with_urls(default_gpu_url(), default_switch_url())
    }

    pub fn with_urls(gpu_url: String, switch_url: String) -> Self {
        #[cfg(not(target_arch = "wasm32"))]
        let builder = reqwest::Client::builder()
            .timeout(std::time::Duration::from_secs(30))
            .connect_timeout(std::time::Duration::from_secs(10));
        #[cfg(target_arch = "wasm32")]
        let builder = reqwest::Client::builder();
        let client = builder
            .build()
            .expect("reqwest client builder with default config never fails");
        Self {
            gpu_url,
            switch_url,
            claims_version: NRAS_CLAIMS_VERSION.into(),
            issuer: env_issuer(),
            allow_hold_cert: env_allow_hold_cert(),
            service_key: env_service_key(),
            client,
            jwks_cache: std::sync::Arc::new(std::sync::RwLock::new(None)),
        }
    }

    fn jwks_url_for(&self, arch: NvidiaGpuArch) -> Result<String> {
        jwks_url_for_endpoint(self.url_for(arch))
    }

    async fn fetch_jwks_uncached(&self, arch: NvidiaGpuArch) -> Result<Jwks> {
        let url = self.jwks_url_for(arch)?;
        let jwks: Jwks = self
            .client
            .get(&url)
            .send()
            .await
            .map_err(|e| AttestationError::JwksFetch(format!("HTTP: {e}")))?
            .error_for_status()
            .map_err(|e| AttestationError::JwksFetch(format!("status: {e}")))?
            .json()
            .await
            .map_err(|e| AttestationError::JwksFetch(format!("parse: {e}")))?;
        let entry = JwksCacheEntry {
            url,
            jwks: jwks.clone(),
            #[cfg(not(target_arch = "wasm32"))]
            fetched_at: std::time::Instant::now(),
        };
        match self.jwks_cache.write() {
            Ok(mut slot) => *slot = Some(entry),
            Err(poisoned) => {
                // A prior holder panicked. The cached `Option<JwksCacheEntry>`
                // has no invariants that a partial write could violate, so
                // recover the lock and overwrite with the fresh entry.
                log::warn!("JWKS cache lock was poisoned; recovering and continuing");
                *poisoned.into_inner() = Some(entry);
            }
        }
        Ok(jwks)
    }
}

/// The origin (`scheme://host`) of an NRAS endpoint URL.
///
/// Hand-rolled to avoid pulling in the `url` crate (keeps the WASM bundle
/// small); the input space is the tightly controlled NRAS endpoint URLs.
pub fn origin_of(endpoint: &str) -> Result<String> {
    let (scheme, rest) = endpoint
        .split_once("://")
        .ok_or_else(|| AttestationError::JwksFetch(format!("invalid NRAS URL: {endpoint}")))?;
    let host = rest
        .split('/')
        .next()
        .filter(|h| !h.is_empty())
        .ok_or_else(|| AttestationError::JwksFetch(format!("invalid NRAS URL: {endpoint}")))?;
    Ok(format!("{scheme}://{host}"))
}

/// Derive the JWKS URL for a given NRAS endpoint by replacing the path with
/// `/.well-known/jwks.json` and dropping any query/fragment.
pub fn jwks_url_for_endpoint(endpoint: &str) -> Result<String> {
    Ok(format!("{}/.well-known/jwks.json", origin_of(endpoint)?))
}

fn default_gpu_url() -> String {
    #[cfg(not(target_arch = "wasm32"))]
    {
        std::env::var("NV_NRAS_GPU_URL").unwrap_or_else(|_| NRAS_GPU_URL.into())
    }
    #[cfg(target_arch = "wasm32")]
    {
        NRAS_GPU_URL.into()
    }
}

fn default_switch_url() -> String {
    #[cfg(not(target_arch = "wasm32"))]
    {
        std::env::var("NV_NRAS_SWITCH_URL").unwrap_or_else(|_| NRAS_SWITCH_URL.into())
    }
    #[cfg(target_arch = "wasm32")]
    {
        NRAS_SWITCH_URL.into()
    }
}

fn env_issuer() -> Option<String> {
    #[cfg(not(target_arch = "wasm32"))]
    {
        std::env::var("NV_NRAS_ISSUER")
            .ok()
            .filter(|s| !s.is_empty())
    }
    #[cfg(target_arch = "wasm32")]
    {
        None
    }
}

fn env_allow_hold_cert() -> bool {
    #[cfg(not(target_arch = "wasm32"))]
    {
        std::env::var("NV_ALLOW_HOLD_CERT").ok().as_deref() == Some("true")
    }
    #[cfg(target_arch = "wasm32")]
    {
        false
    }
}

fn env_service_key() -> Option<String> {
    #[cfg(not(target_arch = "wasm32"))]
    {
        std::env::var("NVIDIA_ATTESTATION_SERVICE_KEY").ok()
    }
    #[cfg(target_arch = "wasm32")]
    {
        None
    }
}

#[cfg_attr(not(target_arch = "wasm32"), async_trait)]
#[cfg_attr(target_arch = "wasm32", async_trait(?Send))]
impl NrasProvider for DefaultNrasProvider {
    fn url_for(&self, arch: NvidiaGpuArch) -> &str {
        match arch {
            NvidiaGpuArch::Ls10 => &self.switch_url,
            _ => &self.gpu_url,
        }
    }

    fn claims_version(&self) -> &str {
        &self.claims_version
    }

    fn issuer(&self, arch: NvidiaGpuArch) -> Result<String> {
        match &self.issuer {
            Some(issuer) => Ok(issuer.clone()),
            None => origin_of(self.url_for(arch)),
        }
    }

    fn accepts_certificate_hold(&self) -> bool {
        self.allow_hold_cert
    }

    async fn attest(&self, request: &NrasRequest) -> Result<serde_json::Value> {
        let url = self.url_for(request.arch).to_string();
        let mut req = self
            .client
            .post(&url)
            .header("Content-Type", "application/json")
            .json(request);
        if self.allow_hold_cert {
            req = req.header(HEADER_OCSP_ALLOW_CERT_HOLD, "true");
        }
        if let Some(key) = &self.service_key {
            req = req.header("Authorization", format!("Bearer {key}"));
        }
        let resp = req
            .send()
            .await
            .map_err(|e| AttestationError::NrasRequestFailed(format!("HTTP send: {e}")))?;
        let status = resp.status();
        let bytes = resp
            .bytes()
            .await
            .map_err(|e| AttestationError::NrasRequestFailed(format!("read body: {e}")))?;
        if !status.is_success() {
            let body_preview = String::from_utf8_lossy(&bytes[..bytes.len().min(512)]);
            return Err(AttestationError::NrasRequestFailed(format!(
                "status {status}: {body_preview}"
            )));
        }
        serde_json::from_slice(&bytes)
            .map_err(|e| AttestationError::NrasResponseParse(e.to_string()))
    }

    async fn jwks(&self, arch: NvidiaGpuArch) -> Result<Jwks> {
        let url = self.jwks_url_for(arch)?;
        let cached = match self.jwks_cache.read() {
            Ok(slot) => slot
                .as_ref()
                .and_then(|e| (e.url == url && e.is_fresh()).then(|| e.jwks.clone())),
            Err(poisoned) => {
                log::warn!("JWKS cache lock was poisoned; recovering and continuing");
                poisoned
                    .into_inner()
                    .as_ref()
                    .and_then(|e| (e.url == url && e.is_fresh()).then(|| e.jwks.clone()))
            }
        };
        if let Some(jwks) = cached {
            return Ok(jwks);
        }
        self.fetch_jwks_uncached(arch).await
    }

    async fn jwks_force(&self, arch: NvidiaGpuArch) -> Result<Jwks> {
        self.fetch_jwks_uncached(arch).await
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn jwks_url_replaces_path_with_well_known() {
        for endpoint in [NRAS_GPU_URL, NRAS_SWITCH_URL] {
            assert_eq!(
                jwks_url_for_endpoint(endpoint).unwrap(),
                "https://nras.attestation.nvidia.com/.well-known/jwks.json"
            );
            assert_eq!(origin_of(endpoint).unwrap(), NRAS_BASE_URL);
        }
        assert_eq!(
            origin_of("https://nras.attestation-stg.nvidia.com/v4/attest/switch?x=1").unwrap(),
            "https://nras.attestation-stg.nvidia.com"
        );
    }

    #[test]
    fn jwks_url_rejects_missing_scheme_or_host() {
        assert!(jwks_url_for_endpoint("nras.attestation.nvidia.com/x").is_err());
        assert!(origin_of("https:///v4/attest/gpu").is_err());
    }

    #[test]
    fn the_default_provider_requires_its_endpoints_origin_unless_told_otherwise() {
        let mut p = DefaultNrasProvider::with_urls(
            "https://proxy.example/nras/gpu".into(),
            "https://proxy.example/nras/switch".into(),
        );
        p.issuer = None;
        assert_eq!(
            p.issuer(NvidiaGpuArch::Hopper).unwrap(),
            "https://proxy.example"
        );
        p.issuer = Some(NRAS_BASE_URL.into());
        assert_eq!(p.issuer(NvidiaGpuArch::Ls10).unwrap(), NRAS_BASE_URL);
        assert_eq!(p.claims_version(), "3.0");
    }

    #[cfg(not(target_arch = "wasm32"))]
    #[test]
    fn jwks_cache_entry_expires_after_ttl() {
        let stale = JwksCacheEntry {
            url: "https://example.invalid/.well-known/jwks.json".into(),
            jwks: Jwks { keys: vec![] },
            fetched_at: std::time::Instant::now()
                .checked_sub(JWKS_TTL + std::time::Duration::from_secs(1))
                .expect("instant arithmetic underflow"),
        };
        assert!(!stale.is_fresh(), "entry older than JWKS_TTL must be stale");

        let fresh = JwksCacheEntry {
            url: "https://example.invalid/.well-known/jwks.json".into(),
            jwks: Jwks { keys: vec![] },
            fetched_at: std::time::Instant::now(),
        };
        assert!(fresh.is_fresh(), "just-inserted entry must be fresh");
    }
}
