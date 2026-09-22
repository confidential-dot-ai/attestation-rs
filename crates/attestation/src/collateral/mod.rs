//! Vendor collateral: what a verifier needs beside the report (AMD VCEKs,
//! chains and CRLs; Intel TCB Info, QE Identity and CRLs; NVIDIA JWKS).
//!
//! `key`, `artifact` and `error` are the vocabulary; on native targets `fetch`,
//! `store` and `cache` are the one implementation every verifier shares. The
//! `CertProvider` and `TdxCollateralProvider` traits remain the seam a caller
//! can replace, and the default providers are handles on the shared cache.

#[cfg(feature = "nvidia-gpu")]
pub use crate::platforms::nvidia_gpu::provider::{
    jwks_url_for_endpoint, origin_of, DefaultNrasProvider, Jwks, JwksKey, NrasEvidenceEntry,
    NrasProvider, NrasRequest, HEADER_OCSP_ALLOW_CERT_HOLD, NRAS_BASE_URL, NRAS_CLAIMS_VERSION,
    NRAS_GPU_URL, NRAS_SWITCH_URL,
};
use std::time::Duration;

use async_trait::async_trait;

use crate::error::Result;
use crate::types::{ProcessorGeneration, SnpTcb};

pub mod artifact;
#[cfg(not(target_arch = "wasm32"))]
pub mod cache;
pub mod error;
#[cfg(not(target_arch = "wasm32"))]
pub mod fetch;
pub mod key;
#[cfg(not(target_arch = "wasm32"))]
pub mod store;

pub use artifact::{Collateral, Origin, SharedCollateral};
#[cfg(not(target_arch = "wasm32"))]
pub use cache::{
    Backoff, CachePolicy, CacheStatus, Clock, CollateralCache, EntryStatus, RefreshReport,
};
pub use error::{CollateralError, CollateralResult};
#[cfg(not(target_arch = "wasm32"))]
pub use fetch::{Endpoints, Fetcher};
pub use key::{CollateralKey, CollateralKind, Fmspc, PckCa};
#[cfg(not(target_arch = "wasm32"))]
pub use store::DiskStore;

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
/// Intel PCS response header carrying the TCB Info signing chain
/// (percent-encoded PEM). Decode with [`pcs_issuer_chain_from_header`].
pub const INTEL_TCB_INFO_ISSUER_CHAIN_HEADER: &str = "tcb-info-issuer-chain";
/// Intel PCS response header carrying the Enclave Identity signing chain
/// (percent-encoded PEM). Decode with [`pcs_issuer_chain_from_header`].
pub const INTEL_ENCLAVE_IDENTITY_ISSUER_CHAIN_HEADER: &str = "sgx-enclave-identity-issuer-chain";

/// Build the AMD KDS CRL URL for a given processor generation.
pub fn snp_crl_url(processor_gen: ProcessorGeneration) -> String {
    format!("{}/{}/crl", AMD_KDS_VCEK_BASE, processor_gen.product_name())
}

/// Build the AMD KDS cert chain (ASK + ARK) URL for a processor generation.
pub fn snp_cert_chain_url(processor_gen: ProcessorGeneration) -> String {
    format!(
        "{}/{}/cert_chain",
        AMD_KDS_VCEK_BASE,
        processor_gen.product_name()
    )
}

/// Build the AMD KDS VCEK URL for a report's generation, chip id and TCB.
///
/// Turin keys the lookup on the first 8 bytes of `chip_id` and requires the
/// FMC SPL: a Turin TCB without one cannot name a VCEK, so it is refused
/// rather than looked up without the parameter. Every VCEK fetch must build
/// its URL here so those rules live once.
pub fn snp_vcek_url(
    processor_gen: ProcessorGeneration,
    chip_id: &[u8; 64],
    tcb: &SnpTcb,
) -> Result<String> {
    if processor_gen == ProcessorGeneration::Turin && tcb.fmc.is_none() {
        return Err(crate::error::AttestationError::QuoteParseFailed(
            "Turin TCB carries no FMC SPL; cannot build the VCEK lookup".to_string(),
        ));
    }
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
    if let Some(fmc) = tcb.fmc {
        url.push_str(&format!("&fmcSPL={fmc:02}"));
    }
    Ok(url)
}

/// Default HTTP request timeout (total).
const DEFAULT_HTTP_TIMEOUT: Duration = Duration::from_secs(30);

/// Default HTTP connection timeout.
const DEFAULT_HTTP_CONNECT_TIMEOUT: Duration = Duration::from_secs(10);

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
/// The library ships a default impl backed by the shared collateral cache.
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

#[async_trait]
impl<T: CertProvider + ?Sized> CertProvider for std::sync::Arc<T> {
    async fn get_snp_vcek(
        &self,
        processor_gen: ProcessorGeneration,
        chip_id: &[u8; 64],
        reported_tcb: &SnpTcb,
    ) -> Result<Vec<u8>> {
        (**self)
            .get_snp_vcek(processor_gen, chip_id, reported_tcb)
            .await
    }

    async fn get_snp_cert_chain(
        &self,
        processor_gen: ProcessorGeneration,
    ) -> Result<(Vec<u8>, Vec<u8>)> {
        (**self).get_snp_cert_chain(processor_gen).await
    }

    async fn get_snp_crl(&self, processor_gen: ProcessorGeneration) -> Result<Option<Vec<u8>>> {
        (**self).get_snp_crl(processor_gen).await
    }
}

/// The zero-configuration provider. On native targets it is a handle on a
/// [`CollateralCache`], so the CLI and the default [`crate::Verifier`] get
/// single flight, validity-driven serving and failure backoff; on wasm it
/// serves the bundled AMD roots and nothing that needs the network.
pub struct DefaultCertProvider {
    #[cfg(not(target_arch = "wasm32"))]
    shared: std::sync::Arc<CollateralCache>,
}

#[cfg(not(target_arch = "wasm32"))]
impl DefaultCertProvider {
    pub fn new() -> Self {
        Self::with_timeouts(HttpTimeouts::default())
    }

    /// A private cache with these HTTP timeouts.
    pub fn with_timeouts(timeouts: HttpTimeouts) -> Self {
        Self::with_shared(std::sync::Arc::new(CollateralCache::new(
            CachePolicy::default(),
            &timeouts,
            Endpoints::default(),
            None,
        )))
    }

    /// A handle on a cache shared with other providers or a service.
    pub fn with_shared(shared: std::sync::Arc<CollateralCache>) -> Self {
        Self { shared }
    }

    pub fn shared(&self) -> &std::sync::Arc<CollateralCache> {
        &self.shared
    }
}

#[cfg(target_arch = "wasm32")]
impl DefaultCertProvider {
    pub fn new() -> Self {
        Self::with_timeouts(HttpTimeouts::default())
    }

    /// Timeouts are irrelevant on wasm: nothing here reaches the network.
    pub fn with_timeouts(timeouts: HttpTimeouts) -> Self {
        let _ = timeouts;
        Self {}
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
        self.shared
            .get_snp_vcek(processor_gen, chip_id, reported_tcb)
            .await
    }

    async fn get_snp_cert_chain(
        &self,
        processor_gen: ProcessorGeneration,
    ) -> Result<(Vec<u8>, Vec<u8>)> {
        self.shared.get_snp_cert_chain(processor_gen).await
    }

    async fn get_snp_crl(&self, processor_gen: ProcessorGeneration) -> Result<Option<Vec<u8>>> {
        self.shared.get_snp_crl(processor_gen).await
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
        let _ = (processor_gen, chip_id, reported_tcb);
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

/// A signed Intel PCS body together with the issuer chain it was served with
/// (the `TCB-Info-Issuer-Chain` or `SGX-Enclave-Identity-Issuer-Chain`
/// header, PEM). The chain travels with the body it signs, so a verifier can
/// never pair a body with another fetch's chain, and never skip the check.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SignedCollateral {
    pub body: Vec<u8>,
    pub signing_chain: Vec<u8>,
}

/// Trait for fetching Intel TDX DCAP collateral (TCB Info, QE Identity, CRLs).
///
/// The library ships a default impl backed by the shared collateral cache.
/// Users can plug in their own (offline bundles, caching proxies, etc.).
#[async_trait]
pub trait TdxCollateralProvider: Send + Sync {
    /// TDX TCB Info for an FMSPC, with the chain that signs it.
    async fn get_tcb_info(&self, fmspc: &str) -> Result<SignedCollateral>;

    /// The SGX QE Identity, with the chain that signs it.
    async fn get_qe_identity(&self) -> Result<SignedCollateral>;

    /// The TDX TD_QE Identity, with the chain that signs it.
    ///
    /// TDX quotes are produced by a TD QE with a different MRSIGNER than the
    /// SGX QE. Implementors must fetch from the TDX-specific Intel PCS
    /// endpoint (`/tdx/certification/v4/qe/identity`), not the SGX one.
    async fn get_td_qe_identity(&self) -> Result<SignedCollateral>;

    /// Fetch the Intel SGX Root CA CRL (DER-encoded).
    async fn get_root_ca_crl(&self) -> Result<Vec<u8>>;

    /// Fetch the PCK CRL for a given CA type ("platform" or "processor").
    async fn get_pck_crl(&self, ca: &str) -> Result<Vec<u8>>;

    /// The clock this provider serves by (a cache's refetch and serving
    /// decisions). The appraisal judges every window against the verifier's
    /// own clock (`Verifier::with_clock`), never this one.
    fn now(&self) -> chrono::DateTime<chrono::Utc> {
        chrono::Utc::now()
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
            crate::platforms::tdx::dcap::check_cert_revocation_from_der_at(
                &der_certs,
                &pck_crl_der,
                self.now(),
            )?;
            let root_crl_der = self.get_root_ca_crl().await?;
            crate::platforms::tdx::dcap::check_intermediate_ca_revocation_from_der_at(
                &der_certs,
                &root_crl_der,
                self.now(),
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

#[async_trait]
impl<T: TdxCollateralProvider + ?Sized> TdxCollateralProvider for std::sync::Arc<T> {
    async fn get_tcb_info(&self, fmspc: &str) -> Result<SignedCollateral> {
        (**self).get_tcb_info(fmspc).await
    }
    async fn get_qe_identity(&self) -> Result<SignedCollateral> {
        (**self).get_qe_identity().await
    }
    async fn get_td_qe_identity(&self) -> Result<SignedCollateral> {
        (**self).get_td_qe_identity().await
    }
    async fn get_root_ca_crl(&self) -> Result<Vec<u8>> {
        (**self).get_root_ca_crl().await
    }
    async fn get_pck_crl(&self, ca: &str) -> Result<Vec<u8>> {
        (**self).get_pck_crl(ca).await
    }
    fn now(&self) -> chrono::DateTime<chrono::Utc> {
        (**self).now()
    }
    async fn check_pck_revocation(&self, pck_cert_chain_pem: &[u8]) -> Result<()> {
        (**self).check_pck_revocation(pck_cert_chain_pem).await
    }
}

#[cfg(feature = "nvidia-gpu")]
#[cfg_attr(not(target_arch = "wasm32"), async_trait)]
#[cfg_attr(target_arch = "wasm32", async_trait(?Send))]
impl<T: crate::platforms::nvidia_gpu::NrasProvider + ?Sized>
    crate::platforms::nvidia_gpu::NrasProvider for std::sync::Arc<T>
{
    fn url_for(&self, arch: crate::types::NvidiaGpuArch) -> &str {
        (**self).url_for(arch)
    }
    fn claims_version(&self) -> &str {
        (**self).claims_version()
    }
    fn issuer(&self, arch: crate::types::NvidiaGpuArch) -> Result<String> {
        (**self).issuer(arch)
    }
    async fn attest(
        &self,
        request: &crate::platforms::nvidia_gpu::NrasRequest,
    ) -> Result<serde_json::Value> {
        (**self).attest(request).await
    }
    async fn jwks(
        &self,
        arch: crate::types::NvidiaGpuArch,
    ) -> Result<crate::platforms::nvidia_gpu::Jwks> {
        (**self).jwks(arch).await
    }
    async fn jwks_force(
        &self,
        arch: crate::types::NvidiaGpuArch,
    ) -> Result<crate::platforms::nvidia_gpu::Jwks> {
        (**self).jwks_force(arch).await
    }
}

/// The zero-configuration TDX provider: a handle on a [`CollateralCache`] on
/// native targets; on wasm it serves only what a caller pre-loaded.
pub struct DefaultTdxCollateralProvider {
    #[cfg(not(target_arch = "wasm32"))]
    shared: std::sync::Arc<CollateralCache>,
}

#[cfg(not(target_arch = "wasm32"))]
impl DefaultTdxCollateralProvider {
    pub fn new() -> Self {
        Self::with_timeouts(HttpTimeouts::default())
    }

    /// A private cache with these HTTP timeouts.
    pub fn with_timeouts(timeouts: HttpTimeouts) -> Self {
        Self::with_shared(std::sync::Arc::new(CollateralCache::new(
            CachePolicy::default(),
            &timeouts,
            Endpoints::default(),
            None,
        )))
    }

    /// A handle on a cache shared with other providers or a service.
    pub fn with_shared(shared: std::sync::Arc<CollateralCache>) -> Self {
        Self { shared }
    }

    pub fn shared(&self) -> &std::sync::Arc<CollateralCache> {
        &self.shared
    }
}

#[cfg(target_arch = "wasm32")]
impl DefaultTdxCollateralProvider {
    pub fn new() -> Self {
        Self::with_timeouts(HttpTimeouts::default())
    }

    /// Timeouts are irrelevant on wasm: nothing here reaches the network.
    pub fn with_timeouts(timeouts: HttpTimeouts) -> Self {
        let _ = timeouts;
        Self {}
    }
}

impl DefaultTdxCollateralProvider {
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
#[async_trait]
impl TdxCollateralProvider for DefaultTdxCollateralProvider {
    async fn get_tcb_info(&self, fmspc: &str) -> Result<SignedCollateral> {
        self.shared.get_tcb_info(fmspc).await
    }

    async fn get_qe_identity(&self) -> Result<SignedCollateral> {
        self.shared.get_qe_identity().await
    }

    async fn get_td_qe_identity(&self) -> Result<SignedCollateral> {
        self.shared.get_td_qe_identity().await
    }

    async fn get_root_ca_crl(&self) -> Result<Vec<u8>> {
        self.shared.get_root_ca_crl().await
    }

    async fn get_pck_crl(&self, ca: &str) -> Result<Vec<u8>> {
        self.shared.get_pck_crl(ca).await
    }

    fn now(&self) -> chrono::DateTime<chrono::Utc> {
        TdxCollateralProvider::now(&*self.shared)
    }

    async fn check_pck_revocation(&self, pck_cert_chain_pem: &[u8]) -> Result<()> {
        self.shared.check_pck_revocation(pck_cert_chain_pem).await
    }
}

#[cfg(target_arch = "wasm32")]
#[async_trait]
impl TdxCollateralProvider for DefaultTdxCollateralProvider {
    async fn get_tcb_info(&self, _fmspc: &str) -> Result<SignedCollateral> {
        Err(wasm_needs_provider())
    }

    async fn get_qe_identity(&self) -> Result<SignedCollateral> {
        Err(wasm_needs_provider())
    }

    async fn get_td_qe_identity(&self) -> Result<SignedCollateral> {
        Err(wasm_needs_provider())
    }

    async fn get_root_ca_crl(&self) -> Result<Vec<u8>> {
        Err(wasm_needs_provider())
    }

    async fn get_pck_crl(&self, _ca: &str) -> Result<Vec<u8>> {
        Err(wasm_needs_provider())
    }
}

#[cfg(target_arch = "wasm32")]
fn wasm_needs_provider() -> crate::error::AttestationError {
    crate::error::AttestationError::CertFetchError(
        "TDX collateral fetch requires a custom TdxCollateralProvider in WASM".to_string(),
    )
}

impl Default for DefaultTdxCollateralProvider {
    fn default() -> Self {
        Self::new()
    }
}

/// Decode an Intel PCS issuer-chain header value
/// ([`INTEL_TCB_INFO_ISSUER_CHAIN_HEADER`],
/// [`INTEL_ENCLAVE_IDENTITY_ISSUER_CHAIN_HEADER`]) into the PEM bytes it
/// carries. PCS percent-encodes the PEM; this reverses that and nothing else.
pub fn pcs_issuer_chain_from_header(value: &str) -> Vec<u8> {
    percent_decode(value).into_bytes()
}

/// Simple percent-decoding for URL-encoded PEM strings from Intel PCS headers.
///
/// Decodes percent-encoded bytes and pushes them as raw bytes into a `Vec<u8>`,
/// which is then losslessly converted to a UTF-8 `String` (PEM data is ASCII).
fn percent_decode(input: &str) -> String {
    let bytes = input.as_bytes();
    let mut result = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        match bytes[i] {
            b'%' => {
                // A valid escape needs two hex digits; anything else is kept as is.
                let hi = bytes.get(i + 1).and_then(|h| hex_val(*h));
                let lo = bytes.get(i + 2).and_then(|l| hex_val(*l));
                match (hi, lo) {
                    (Some(hv), Some(lv)) => {
                        result.push(hv << 4 | lv);
                        i += 3;
                    }
                    _ => {
                        result.push(b'%');
                        i += 1;
                    }
                }
            }
            b'+' => {
                result.push(b' ');
                i += 1;
            }
            other => {
                result.push(other);
                i += 1;
            }
        }
    }
    String::from_utf8(result).unwrap_or_else(|e| String::from_utf8_lossy(e.as_bytes()).into_owned())
}

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
        let url = snp_vcek_url(ProcessorGeneration::Milan, &chip_id, &tcb).unwrap();

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
        let url = snp_vcek_url(ProcessorGeneration::Turin, &chip_id, &tcb).unwrap();
        assert!(url.starts_with("https://kdsintf.amd.com/vcek/v1/Turin/"));
        assert!(url.contains(&hex::encode(&chip_id[..8])));
        assert!(!url.contains(&hex::encode(chip_id)));
        assert!(url.contains("fmcSPL=10"));
        let no_fmc = SnpTcb { fmc: None, ..tcb };
        assert!(snp_vcek_url(ProcessorGeneration::Turin, &chip_id, &no_fmc).is_err());
    }

    #[test]
    fn percent_decoding_reverses_pcs_encoding() {
        assert_eq!(
            pcs_issuer_chain_from_header("-----BEGIN%20CERTIFICATE-----%0AMIIB%0A"),
            b"-----BEGIN CERTIFICATE-----\nMIIB\n"
        );
        assert_eq!(percent_decode("a+b%2"), "a b%2");
    }
}
