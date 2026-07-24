use std::time::Duration;

use async_trait::async_trait;
#[cfg(not(target_arch = "wasm32"))]
use base64::Engine;

use crate::error::Result;
use crate::types::{ProcessorGeneration, SnpTcb};

// ── AMD KDS (Key Distribution Service) ──
/// Base URL for AMD VCEK certificate downloads.
pub const AMD_KDS_VCEK_BASE: &str = "https://kdsintf.amd.com/vcek/v1";
/// Base URL for AMD VLEK certificate downloads.
pub const AMD_KDS_VLEK_BASE: &str = "https://kdsintf.amd.com/vlek/v1";

// ── Intel PCS v4 (Provisioning Certification Service) ──
/// Base URL for Intel SGX certification API v4.
pub const INTEL_PCS_V4_BASE: &str = "https://api.trustedservices.intel.com/sgx/certification/v4";
/// Base URL for Intel TDX certification API v4.
pub const INTEL_TDX_PCS_V4_BASE: &str =
    "https://api.trustedservices.intel.com/tdx/certification/v4";
/// Base URL for Intel SGX certificate infrastructure.
pub const INTEL_CERTS_BASE: &str = "https://certificates.trustedservices.intel.com";
/// Intel PCS v4 SGX QE Identity endpoint.
pub const INTEL_QE_IDENTITY_URL: &str =
    "https://api.trustedservices.intel.com/sgx/certification/v4/qe/identity";
/// Intel PCS v4 TDX (TD_QE) Identity endpoint.
pub const INTEL_TD_QE_IDENTITY_URL: &str =
    "https://api.trustedservices.intel.com/tdx/certification/v4/qe/identity";
/// Intel SGX Root CA CRL (DER format).
pub const INTEL_ROOT_CA_CRL_URL: &str =
    "https://certificates.trustedservices.intel.com/IntelSGXRootCA.der";

/// Build the AMD KDS CRL URL for a given processor generation.
pub fn snp_crl_url(processor_gen: ProcessorGeneration) -> String {
    format!("{}/{}/crl", AMD_KDS_VCEK_BASE, processor_gen.product_name())
}

/// Default HTTP request timeout (total).
const DEFAULT_HTTP_TIMEOUT: Duration = Duration::from_secs(30);

/// Default HTTP connection timeout.
const DEFAULT_HTTP_CONNECT_TIMEOUT: Duration = Duration::from_secs(10);

/// Maximum allowed HTTP response body size (5 MiB).
#[cfg(not(target_arch = "wasm32"))]
const MAX_RESPONSE_SIZE: usize = 5 * 1024 * 1024;

/// Configuration for HTTP client timeouts.
#[derive(Debug, Clone)]
pub struct HttpTimeouts {
    /// Total HTTP request timeout. Default: 30s.
    pub request_timeout: Duration,
    /// TCP connection timeout. Default: 10s.
    pub connect_timeout: Duration,
}

impl Default for HttpTimeouts {
    fn default() -> Self {
        Self {
            request_timeout: DEFAULT_HTTP_TIMEOUT,
            connect_timeout: DEFAULT_HTTP_CONNECT_TIMEOUT,
        }
    }
}

/// Trait for providing platform vendor certificates.
/// The library ships a default impl that does HTTP fetch with in-memory caching.
/// Users can plug in their own (Redis, disk, etc.).
#[async_trait]
pub trait CertProvider: Send + Sync {
    /// Fetch the VCEK/VLEK cert for an SNP report.
    async fn get_snp_vcek(
        &self,
        processor_gen: ProcessorGeneration,
        chip_id: &[u8; 64],
        reported_tcb: &SnpTcb,
    ) -> Result<Vec<u8>>;

    /// Fetch the AMD certificate chain (ARK + ASK) for a processor generation.
    async fn get_snp_cert_chain(
        &self,
        processor_gen: ProcessorGeneration,
    ) -> Result<(Vec<u8>, Vec<u8>)>;

    /// Fetch the AMD CRL for a processor generation (DER-encoded).
    /// Returns `None` if CRL is not available (revocation check will be skipped).
    async fn get_snp_crl(&self, _processor_gen: ProcessorGeneration) -> Result<Option<Vec<u8>>> {
        Ok(None)
    }
}

/// Default implementation: try cache first, fetch from vendor on miss.
pub struct DefaultCertProvider {
    #[cfg(not(target_arch = "wasm32"))]
    client: reqwest::Client,
    cache: std::sync::Arc<std::sync::RwLock<std::collections::HashMap<String, CachedCert>>>,
}

#[derive(Clone)]
struct CachedCert {
    data: Vec<u8>,
    fetched_at: std::time::Instant,
}

impl CachedCert {
    fn is_expired(&self, ttl: std::time::Duration) -> bool {
        self.fetched_at.elapsed() > ttl
    }
}

const CACHE_TTL: std::time::Duration = std::time::Duration::from_secs(3600); // 1 hour

impl DefaultCertProvider {
    pub fn new() -> Self {
        Self::with_timeouts(HttpTimeouts::default())
    }

    /// Create a new provider with custom HTTP timeouts.
    pub fn with_timeouts(timeouts: HttpTimeouts) -> Self {
        #[cfg(target_arch = "wasm32")]
        let _ = timeouts;

        Self {
            #[cfg(not(target_arch = "wasm32"))]
            client: reqwest::Client::builder()
                .timeout(timeouts.request_timeout)
                .connect_timeout(timeouts.connect_timeout)
                .build()
                .expect("failed to build HTTP client"),
            cache: std::sync::Arc::new(std::sync::RwLock::new(std::collections::HashMap::new())),
        }
    }

    fn get_cached(&self, key: &str) -> Option<Vec<u8>> {
        let cache = self.cache.read().ok()?;
        let entry = cache.get(key)?;
        if entry.is_expired(CACHE_TTL) {
            None
        } else {
            Some(entry.data.clone())
        }
    }

    #[allow(dead_code)] // Only used in native (non-WASM) builds
    fn set_cached(&self, key: String, data: Vec<u8>) {
        if let Ok(mut cache) = self.cache.write() {
            cache.insert(
                key,
                CachedCert {
                    data,
                    fetched_at: std::time::Instant::now(),
                },
            );
        }
    }

    /// Build AMD KDS URL for VCEK certificate.
    fn vcek_url(processor_gen: ProcessorGeneration, chip_id: &[u8; 64], tcb: &SnpTcb) -> String {
        // Turin uses only the first 8 bytes of chip_id for KDS lookup
        let chip_id_hex = if processor_gen == ProcessorGeneration::Turin {
            hex::encode(&chip_id[..8])
        } else {
            hex::encode(chip_id)
        };
        let mut url = format!(
            "{}/{}/{}?blSPL={:02}&teeSPL={:02}&snpSPL={:02}&ucodeSPL={:02}",
            AMD_KDS_VCEK_BASE,
            processor_gen.product_name(),
            chip_id_hex,
            tcb.bootloader,
            tcb.tee,
            tcb.snp,
            tcb.microcode,
        );
        // Turin processors have an additional FMC SPL parameter
        if let Some(fmc) = tcb.fmc {
            url.push_str(&format!("&fmcSPL={fmc:02}"));
        }
        url
    }

    /// Build AMD KDS URL for cert chain (ARK + ASK).
    pub fn cert_chain_url(processor_gen: ProcessorGeneration) -> String {
        format!(
            "{}/{}/cert_chain",
            AMD_KDS_VCEK_BASE,
            processor_gen.product_name()
        )
    }
}

/// Read response body with size limit enforcement.
#[cfg(not(target_arch = "wasm32"))]
async fn read_response_with_limit(response: reqwest::Response) -> Result<Vec<u8>> {
    if let Some(len) = response.content_length() {
        if len as usize > MAX_RESPONSE_SIZE {
            return Err(crate::error::AttestationError::CertFetchError(format!(
                "response too large: Content-Length {len} exceeds {MAX_RESPONSE_SIZE} byte limit",
            )));
        }
    }

    let bytes = response
        .bytes()
        .await
        .map_err(|e| crate::error::AttestationError::CertFetchError(format!("read body: {e}")))?
        .to_vec();

    if bytes.len() > MAX_RESPONSE_SIZE {
        let len = bytes.len();
        return Err(crate::error::AttestationError::CertFetchError(format!(
            "response body too large: {len} bytes exceeds {MAX_RESPONSE_SIZE} byte limit",
        )));
    }

    Ok(bytes)
}

/// Send a GET request and return the response with status check.
#[cfg(not(target_arch = "wasm32"))]
async fn send_get(client: &reqwest::Client, url: &str) -> Result<reqwest::Response> {
    client
        .get(url)
        .send()
        .await
        .map_err(|e| crate::error::AttestationError::CertFetchError(format!("HTTP request: {e}")))?
        .error_for_status()
        .map_err(|e| crate::error::AttestationError::CertFetchError(format!("HTTP status: {e}")))
}

#[cfg(not(target_arch = "wasm32"))]
impl DefaultCertProvider {
    /// Fetch a certificate from AMD KDS, with cache lookup first.
    async fn fetch_cert(&self, url: &str) -> Result<Vec<u8>> {
        if let Some(cached) = self.get_cached(url) {
            return Ok(cached);
        }

        let response = send_get(&self.client, url).await?;
        let bytes = read_response_with_limit(response).await?;

        self.set_cached(url.to_string(), bytes.clone());
        Ok(bytes)
    }
}

#[cfg(not(target_arch = "wasm32"))]
#[async_trait]
impl CertProvider for DefaultCertProvider {
    async fn get_snp_vcek(
        &self,
        processor_gen: ProcessorGeneration,
        chip_id: &[u8; 64],
        reported_tcb: &SnpTcb,
    ) -> Result<Vec<u8>> {
        let url = Self::vcek_url(processor_gen, chip_id, reported_tcb);
        self.fetch_cert(&url).await
    }

    async fn get_snp_cert_chain(
        &self,
        processor_gen: ProcessorGeneration,
    ) -> Result<(Vec<u8>, Vec<u8>)> {
        let url = Self::cert_chain_url(processor_gen);
        let pem_data = self.fetch_cert(&url).await?;

        // The cert chain response is PEM with two certificates (ARK + ASK)
        // Parse them into DER
        let pem_str = String::from_utf8(pem_data).map_err(|e| {
            crate::error::AttestationError::CertFetchError(format!("cert chain not UTF-8: {e}"))
        })?;

        let mut certs = Vec::new();
        let mut current = String::new();
        let mut in_cert = false;

        for line in pem_str.lines() {
            if line.contains("BEGIN CERTIFICATE") {
                in_cert = true;
                current.clear();
            } else if line.contains("END CERTIFICATE") {
                in_cert = false;
                let der = base64::engine::general_purpose::STANDARD
                    .decode(current.trim())
                    .map_err(|e| {
                        crate::error::AttestationError::CertFetchError(format!("cert base64: {e}"))
                    })?;
                certs.push(der);
            } else if in_cert {
                current.push_str(line.trim());
            }
        }

        if certs.len() < 2 {
            return Err(crate::error::AttestationError::CertFetchError(format!(
                "expected 2 certs in chain, got {}",
                certs.len()
            )));
        }

        // First cert is typically VCEK/ASK, second is ARK
        // The AMD KDS returns ASK first, ARK second
        Ok((certs[1].clone(), certs[0].clone()))
    }
}

/// WASM implementation: uses bundled certs for chain, no HTTP fetch for VCEK.
/// In a browser environment, callers should provide their own CertProvider
/// implementation that uses fetch() or similar for VCEK resolution.
#[cfg(target_arch = "wasm32")]
#[async_trait]
impl CertProvider for DefaultCertProvider {
    async fn get_snp_vcek(
        &self,
        processor_gen: ProcessorGeneration,
        chip_id: &[u8; 64],
        reported_tcb: &SnpTcb,
    ) -> Result<Vec<u8>> {
        // Check cache first
        let url = Self::vcek_url(processor_gen, chip_id, reported_tcb);
        if let Some(cached) = self.get_cached(&url) {
            return Ok(cached);
        }

        Err(crate::error::AttestationError::CertFetchError(
            "VCEK fetch requires a custom CertProvider implementation in WASM".to_string(),
        ))
    }

    async fn get_snp_cert_chain(
        &self,
        processor_gen: ProcessorGeneration,
    ) -> Result<(Vec<u8>, Vec<u8>)> {
        #[cfg(feature = "snp")]
        {
            let (ark, ask) = crate::platforms::snp::certs::get_bundled_certs(processor_gen);
            Ok((ark.to_vec(), ask.to_vec()))
        }
        #[cfg(not(feature = "snp"))]
        {
            let _ = processor_gen;
            Err(crate::error::AttestationError::CertFetchError(
                "SNP cert chain requires the `snp` feature in WASM".to_string(),
            ))
        }
    }
}

impl Default for DefaultCertProvider {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// TDX DCAP collateral provider (Intel PCS v4)
// ---------------------------------------------------------------------------

/// Trait for fetching Intel TDX DCAP collateral (TCB Info, QE Identity, CRLs).
///
/// The library ships a default impl that fetches from Intel PCS v4.
/// Users can plug in their own (offline bundles, caching proxies, etc.).
#[async_trait]
pub trait TdxCollateralProvider: Send + Sync {
    /// Fetch TDX TCB Info JSON for a given FMSPC.
    async fn get_tcb_info(&self, fmspc: &str) -> Result<Vec<u8>>;

    /// Fetch the SGX QE Identity JSON.
    async fn get_qe_identity(&self) -> Result<Vec<u8>>;

    /// Fetch the TDX TD_QE Identity JSON.
    ///
    /// TDX quotes are produced by a TD QE with a different MRSIGNER than the
    /// SGX QE. Implementors must fetch from the TDX-specific Intel PCS
    /// endpoint (`/tdx/certification/v4/qe/identity`), not the SGX one.
    async fn get_td_qe_identity(&self) -> Result<Vec<u8>>;

    /// Fetch the Intel SGX Root CA CRL (DER-encoded).
    async fn get_root_ca_crl(&self) -> Result<Vec<u8>>;

    /// Fetch the PCK CRL for a given CA type ("platform" or "processor").
    async fn get_pck_crl(&self, ca: &str) -> Result<Vec<u8>>;

    /// Fetch the TCB Info signing certificate chain (PEM).
    ///
    /// This is the `TCB-Info-Issuer-Chain` response header from Intel PCS,
    /// containing the Intel SGX TCB Signing Certificate → Root CA chain.
    /// Used to verify the Intel ECDSA signature on TCB Info JSON.
    ///
    /// Returns `None` if the signing chain is not available (signature
    /// verification will be skipped).
    async fn get_tcb_signing_chain(&self) -> Result<Option<Vec<u8>>> {
        Ok(None)
    }

    /// Fetch the QE Identity signing certificate chain (PEM).
    ///
    /// This is the `SGX-Enclave-Identity-Issuer-Chain` response header from
    /// Intel PCS. Used to verify the Intel ECDSA signature on QE Identity JSON.
    ///
    /// Returns `None` if the signing chain is not available (signature
    /// verification will be skipped).
    async fn get_qe_identity_signing_chain(&self) -> Result<Option<Vec<u8>>> {
        Ok(None)
    }

    /// Fetch the TD QE Identity signing certificate chain (PEM).
    async fn get_td_qe_identity_signing_chain(&self) -> Result<Option<Vec<u8>>> {
        Ok(None)
    }

    /// Check PCK cert chain against CRLs (leaf + intermediate CA revocation).
    ///
    /// Default implementation fetches CRL data via `get_pck_crl` + `get_root_ca_crl`
    /// and checks both the PCK leaf and Intermediate CA certificates.
    /// Override to use pre-cached CRL data in a service context.
    ///
    /// The default body requires the `tdx` cargo feature (for the DCAP parsers).
    /// Without `tdx`, the trait can still be implemented by users, but the
    /// default implementation returns an error.
    async fn check_pck_revocation(&self, pck_cert_chain_pem: &[u8]) -> Result<()> {
        #[cfg(feature = "tdx")]
        {
            // Preparse PEM once to avoid redundant parsing across multiple checks
            let der_certs = crate::platforms::tdx::dcap::parse_pem_to_der(pck_cert_chain_pem)?;
            let ca_type = crate::platforms::tdx::dcap::determine_ca_type_from_der(&der_certs)?;
            let pck_crl_der = self.get_pck_crl(&ca_type).await?;
            crate::platforms::tdx::dcap::check_cert_revocation_from_der(&der_certs, &pck_crl_der)?;
            let root_crl_der = self.get_root_ca_crl().await?;
            crate::platforms::tdx::dcap::check_intermediate_ca_revocation_from_der(
                &der_certs,
                &root_crl_der,
            )?;
            Ok(())
        }
        #[cfg(not(feature = "tdx"))]
        {
            let _ = pck_cert_chain_pem;
            Err(crate::error::AttestationError::PlatformNotEnabled(
                "default PCK revocation check requires the `tdx` cargo feature".to_string(),
            ))
        }
    }
}

/// Default TDX collateral provider: fetches from Intel PCS v4 with caching.
pub struct DefaultTdxCollateralProvider {
    #[cfg(not(target_arch = "wasm32"))]
    client: reqwest::Client,
    cache: std::sync::Arc<std::sync::RwLock<std::collections::HashMap<String, CachedCert>>>,
}

impl DefaultTdxCollateralProvider {
    pub fn new() -> Self {
        Self::with_timeouts(HttpTimeouts::default())
    }

    /// Create a new provider with custom HTTP timeouts.
    pub fn with_timeouts(timeouts: HttpTimeouts) -> Self {
        #[cfg(target_arch = "wasm32")]
        let _ = timeouts;

        Self {
            #[cfg(not(target_arch = "wasm32"))]
            client: reqwest::Client::builder()
                .timeout(timeouts.request_timeout)
                .connect_timeout(timeouts.connect_timeout)
                .build()
                .expect("failed to build HTTP client"),
            cache: std::sync::Arc::new(std::sync::RwLock::new(std::collections::HashMap::new())),
        }
    }

    fn get_cached(&self, key: &str) -> Option<Vec<u8>> {
        let cache = self.cache.read().ok()?;
        let entry = cache.get(key)?;
        if entry.is_expired(CACHE_TTL) {
            None
        } else {
            Some(entry.data.clone())
        }
    }

    #[allow(dead_code)]
    fn set_cached(&self, key: String, data: Vec<u8>) {
        if let Ok(mut cache) = self.cache.write() {
            cache.insert(
                key,
                CachedCert {
                    data,
                    fetched_at: std::time::Instant::now(),
                },
            );
        }
    }

    /// Intel PCS v4 TDX TCB Info URL.
    ///
    /// Uses the `/tdx/certification/v4` endpoint which returns TCB Info
    /// with `tdxtcbcomponents` needed for TDX TCB evaluation. The SGX
    /// endpoint (`/sgx/...`) omits these components.
    pub fn tcb_info_url(fmspc: &str) -> String {
        format!("{INTEL_TDX_PCS_V4_BASE}/tcb?fmspc={fmspc}")
    }

    /// Intel PCS v4 TDX QE Identity URL.
    ///
    /// Uses the `/tdx/certification/v4` endpoint which returns the TD_QE
    /// identity with the correct MRSIGNER for TDX quoting enclaves.
    pub fn qe_identity_url() -> String {
        INTEL_TD_QE_IDENTITY_URL.to_string()
    }

    /// Intel PCS v4 TDX TD_QE Identity URL.
    pub fn td_qe_identity_url() -> String {
        INTEL_TD_QE_IDENTITY_URL.to_string()
    }

    /// Intel SGX Root CA CRL URL (DER format).
    pub fn root_ca_crl_url() -> String {
        INTEL_ROOT_CA_CRL_URL.to_string()
    }

    /// Intel PCS v4 PCK CRL URL.
    pub fn pck_crl_url(ca: &str) -> String {
        format!("{INTEL_PCS_V4_BASE}/pckcrl?ca={ca}")
    }
}

#[cfg(not(target_arch = "wasm32"))]
impl DefaultTdxCollateralProvider {
    async fn fetch(&self, url: &str) -> Result<Vec<u8>> {
        if let Some(cached) = self.get_cached(url) {
            return Ok(cached);
        }

        let response = send_get(&self.client, url).await?;
        let bytes = read_response_with_limit(response).await?;

        self.set_cached(url.to_string(), bytes.clone());
        Ok(bytes)
    }

    /// Fetch a URL and capture a specific response header as PEM cert chain.
    ///
    /// Intel PCS returns signing cert chains as URL-encoded PEM in response
    /// headers (`TCB-Info-Issuer-Chain`, `SGX-Enclave-Identity-Issuer-Chain`).
    async fn fetch_with_signing_chain(
        &self,
        url: &str,
        header_name: &str,
        chain_cache_key: &str,
    ) -> Result<(Vec<u8>, Option<Vec<u8>>)> {
        if let Some(cached_body) = self.get_cached(url) {
            let chain = self.get_cached(chain_cache_key);
            return Ok((cached_body, chain));
        }

        let response = send_get(&self.client, url).await?;

        // Extract signing chain from response header (URL-encoded PEM)
        let chain_pem = response
            .headers()
            .get(header_name)
            .and_then(|v| v.to_str().ok())
            .map(|v| percent_decode(v).into_bytes());

        let body = read_response_with_limit(response).await?;

        self.set_cached(url.to_string(), body.clone());
        if let Some(ref chain) = chain_pem {
            self.set_cached(chain_cache_key.to_string(), chain.clone());
        }

        Ok((body, chain_pem))
    }
}

#[cfg(not(target_arch = "wasm32"))]
#[async_trait]
impl TdxCollateralProvider for DefaultTdxCollateralProvider {
    async fn get_tcb_info(&self, fmspc: &str) -> Result<Vec<u8>> {
        let url = Self::tcb_info_url(fmspc);
        let (body, chain) = self
            .fetch_with_signing_chain(&url, "tcb-info-issuer-chain", "tcb_signing_chain")
            .await?;
        if let Some(ref chain_pem) = chain {
            self.set_cached("tcb_signing_chain".to_string(), chain_pem.clone());
        }
        Ok(body)
    }

    async fn get_qe_identity(&self) -> Result<Vec<u8>> {
        let url = Self::qe_identity_url();
        let (body, chain) = self
            .fetch_with_signing_chain(
                &url,
                "sgx-enclave-identity-issuer-chain",
                "qe_identity_signing_chain",
            )
            .await?;
        if let Some(ref chain_pem) = chain {
            self.set_cached("qe_identity_signing_chain".to_string(), chain_pem.clone());
        }
        Ok(body)
    }

    async fn get_td_qe_identity(&self) -> Result<Vec<u8>> {
        let url = Self::td_qe_identity_url();
        let (body, chain) = self
            .fetch_with_signing_chain(
                &url,
                "sgx-enclave-identity-issuer-chain",
                "td_qe_identity_signing_chain",
            )
            .await?;
        if let Some(ref chain_pem) = chain {
            self.set_cached(
                "td_qe_identity_signing_chain".to_string(),
                chain_pem.clone(),
            );
        }
        Ok(body)
    }

    async fn get_root_ca_crl(&self) -> Result<Vec<u8>> {
        self.fetch(&Self::root_ca_crl_url()).await
    }

    async fn get_pck_crl(&self, ca: &str) -> Result<Vec<u8>> {
        let bytes = self.fetch(&Self::pck_crl_url(ca)).await?;
        // Intel PCS v4 returns PEM-encoded CRL; convert to DER if needed.
        if crate::utils::is_pem(&bytes) {
            crate::utils::decode_pem_to_der(&bytes)
        } else {
            Ok(bytes)
        }
    }

    async fn get_tcb_signing_chain(&self) -> Result<Option<Vec<u8>>> {
        Ok(self.get_cached("tcb_signing_chain"))
    }

    async fn get_qe_identity_signing_chain(&self) -> Result<Option<Vec<u8>>> {
        Ok(self.get_cached("qe_identity_signing_chain"))
    }

    async fn get_td_qe_identity_signing_chain(&self) -> Result<Option<Vec<u8>>> {
        Ok(self.get_cached("td_qe_identity_signing_chain"))
    }
}

#[cfg(target_arch = "wasm32")]
#[async_trait]
impl TdxCollateralProvider for DefaultTdxCollateralProvider {
    async fn get_tcb_info(&self, fmspc: &str) -> Result<Vec<u8>> {
        let url = Self::tcb_info_url(fmspc);
        if let Some(cached) = self.get_cached(&url) {
            return Ok(cached);
        }
        Err(crate::error::AttestationError::CertFetchError(
            "TDX collateral fetch requires a custom TdxCollateralProvider in WASM".to_string(),
        ))
    }

    async fn get_qe_identity(&self) -> Result<Vec<u8>> {
        let url = Self::qe_identity_url();
        if let Some(cached) = self.get_cached(&url) {
            return Ok(cached);
        }
        Err(crate::error::AttestationError::CertFetchError(
            "TDX collateral fetch requires a custom TdxCollateralProvider in WASM".to_string(),
        ))
    }

    async fn get_td_qe_identity(&self) -> Result<Vec<u8>> {
        let url = Self::td_qe_identity_url();
        if let Some(cached) = self.get_cached(&url) {
            return Ok(cached);
        }
        Err(crate::error::AttestationError::CertFetchError(
            "TDX collateral fetch requires a custom TdxCollateralProvider in WASM".to_string(),
        ))
    }

    async fn get_root_ca_crl(&self) -> Result<Vec<u8>> {
        let url = Self::root_ca_crl_url();
        if let Some(cached) = self.get_cached(&url) {
            return Ok(cached);
        }
        Err(crate::error::AttestationError::CertFetchError(
            "TDX collateral fetch requires a custom TdxCollateralProvider in WASM".to_string(),
        ))
    }

    async fn get_pck_crl(&self, ca: &str) -> Result<Vec<u8>> {
        let url = Self::pck_crl_url(ca);
        if let Some(cached) = self.get_cached(&url) {
            return Ok(cached);
        }
        Err(crate::error::AttestationError::CertFetchError(
            "TDX collateral fetch requires a custom TdxCollateralProvider in WASM".to_string(),
        ))
    }
}

impl Default for DefaultTdxCollateralProvider {
    fn default() -> Self {
        Self::new()
    }
}

/// Simple percent-decoding for URL-encoded PEM strings from Intel PCS headers.
///
/// Decodes percent-encoded bytes and pushes them as raw bytes into a `Vec<u8>`,
/// which is then losslessly converted to a UTF-8 `String` (PEM data is ASCII).
#[cfg(not(target_arch = "wasm32"))]
pub fn percent_decode(input: &str) -> String {
    let mut result = Vec::with_capacity(input.len());
    let mut chars = input.bytes();
    while let Some(b) = chars.next() {
        if b == b'%' {
            if let (Some(h), Some(l)) = (chars.next(), chars.next()) {
                if let (Some(hv), Some(lv)) = (hex_val(h), hex_val(l)) {
                    result.push(hv << 4 | lv);
                    continue;
                }
            }
            result.push(b'%');
        } else if b == b'+' {
            result.push(b' ');
        } else {
            result.push(b);
        }
    }
    String::from_utf8(result).unwrap_or_else(|e| String::from_utf8_lossy(e.as_bytes()).into_owned())
}

#[cfg(not(target_arch = "wasm32"))]
fn hex_val(b: u8) -> Option<u8> {
    match b {
        b'0'..=b'9' => Some(b - b'0'),
        b'a'..=b'f' => Some(b - b'a' + 10),
        b'A'..=b'F' => Some(b - b'A' + 10),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_vcek_url_construction_milan() {
        let chip_id = [0xAA; 64];
        let tcb = SnpTcb {
            bootloader: 3,
            tee: 0,
            snp: 8,
            microcode: 115,
            fmc: None,
        };
        let url = DefaultCertProvider::vcek_url(ProcessorGeneration::Milan, &chip_id, &tcb);

        assert!(url.starts_with("https://kdsintf.amd.com/vcek/v1/Milan/"));
        assert!(url.contains(&hex::encode(chip_id)));
        assert!(url.contains("blSPL=03"));
        assert!(url.contains("teeSPL=00"));
        assert!(url.contains("snpSPL=08"));
        assert!(url.contains("ucodeSPL=115"));
        assert!(!url.contains("fmcSPL"), "Milan should not include fmcSPL");
    }

    #[test]
    fn test_vcek_url_construction_turin() {
        let chip_id = [0xCC; 64];
        let tcb = SnpTcb {
            bootloader: 0,
            tee: 0,
            snp: 0,
            microcode: 0,
            fmc: Some(10),
        };
        let url = DefaultCertProvider::vcek_url(ProcessorGeneration::Turin, &chip_id, &tcb);

        assert!(url.starts_with("https://kdsintf.amd.com/vcek/v1/Turin/"));
        // Turin uses only first 8 bytes of chip_id
        assert!(url.contains(&hex::encode(&chip_id[..8])));
        assert!(
            !url.contains(&hex::encode(chip_id)),
            "Turin should NOT use full 64-byte chip_id"
        );
        assert!(url.contains("blSPL=00"));
        assert!(url.contains("teeSPL=00"));
        assert!(url.contains("snpSPL=00"));
        assert!(url.contains("ucodeSPL=00"));
        assert!(url.contains("fmcSPL=10"), "Turin should include fmcSPL");
    }

    #[test]
    fn test_cache_operations() {
        let provider = DefaultCertProvider::new();

        // Cache should be empty initially
        assert!(provider.get_cached("test-key").is_none());

        // Set a value
        provider.set_cached("test-key".to_string(), vec![1, 2, 3]);

        // Should retrieve the value
        let cached = provider.get_cached("test-key");
        assert!(cached.is_some());
        assert_eq!(cached.unwrap(), vec![1, 2, 3]);
    }

    #[test]
    fn test_cached_cert_is_expired() {
        let cert = CachedCert {
            data: vec![1, 2, 3],
            fetched_at: std::time::Instant::now(),
        };

        // Should not be expired with a 1-hour TTL
        assert!(!cert.is_expired(std::time::Duration::from_secs(3600)));

        // Should be expired with a zero TTL
        assert!(cert.is_expired(std::time::Duration::from_secs(0)));
    }
}
