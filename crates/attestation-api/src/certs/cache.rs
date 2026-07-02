use chrono::{DateTime, Duration as ChronoDuration, Utc};
use moka::future::Cache;
use reqwest::Client;
use serde::Serialize;
use serde_json::{json, Map, Value};
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::RwLock;

use crate::certs::hours_to_duration;
use crate::config::{normalize_generation, CertsConfig, KNOWN_GENERATIONS};

/// Key for VCEK cache: (processor_gen, chip_id_hex, tcb_version)
type VcekKey = (String, String, String);

/// Key for TDX collateral cache
type TdxCollateralKey = (String, String);

#[derive(Debug, Clone, Serialize)]
pub struct CrlEntry {
    pub data: Vec<u8>,
    pub last_fetched: DateTime<Utc>,
    pub next_refresh: DateTime<Utc>,
    pub entry_count: u64,
}

pub struct CertCache {
    vcek_cache: Cache<VcekKey, Vec<u8>>,
    chain_cache: Cache<String, (Vec<u8>, Vec<u8>)>,
    tdx_cache: Cache<TdxCollateralKey, Vec<u8>>,
    crl_cache: Cache<String, CrlEntry>,
    /// JWKS cache keyed by the full JWKS URL (NVIDIA NRAS).
    jwks_cache: Cache<String, attestation::platforms::nvidia_gpu::Jwks>,
    last_crl_refresh: Arc<RwLock<Option<DateTime<Utc>>>>,
    http_client: Client,
    /// Normalized processor generation names from config (used for refresh operations).
    configured_generations: Vec<String>,
    /// Configured CRL refresh interval in hours (used for CrlEntry.next_refresh).
    crl_refresh_hours: u64,
}

impl CertCache {
    pub fn new(config: &CertsConfig) -> Self {
        let vcek_cache = Cache::builder()
            .max_capacity(config.cache_max_entries)
            .time_to_live(hours_to_duration(config.vcek_ttl_hours))
            .build();

        let chain_cache = Cache::builder()
            .max_capacity(16)
            .time_to_live(hours_to_duration(config.chain_ttl_hours))
            .build();

        let tdx_cache = Cache::builder()
            .max_capacity(config.cache_max_entries)
            .time_to_live(hours_to_duration(config.tdx_collateral_ttl_hours))
            .build();

        let crl_cache = Cache::builder()
            .max_capacity(64)
            .time_to_live(hours_to_duration(config.crl_refresh_hours))
            .build();

        // NRAS publishes a small key set (~5-10 keys). A handful of slots is
        // enough even if GPU and switch endpoints diverge in the future.
        let jwks_cache = Cache::builder()
            .max_capacity(8)
            .time_to_live(hours_to_duration(config.jwks_ttl_hours))
            .build();

        let configured_generations = config
            .prefetch_chains
            .iter()
            .filter_map(|g| normalize_generation(g).map(String::from))
            .collect();

        Self {
            vcek_cache,
            chain_cache,
            tdx_cache,
            crl_cache,
            jwks_cache,
            last_crl_refresh: Arc::new(RwLock::new(None)),
            http_client: Client::builder()
                .connect_timeout(Duration::from_secs(10))
                .timeout(Duration::from_secs(30))
                .build()
                .expect("failed to build HTTP client"),
            configured_generations,
            crl_refresh_hours: config.crl_refresh_hours,
        }
    }

    /// Returns the list of configured processor generations (normalized to canonical form).
    pub fn configured_generations(&self) -> &[String] {
        &self.configured_generations
    }

    // --- SNP cert operations ---

    pub async fn get_vcek(
        &self,
        processor_gen: &str,
        chip_id: &[u8; 64],
        tcb: &attestation::SnpTcb,
    ) -> anyhow::Result<Vec<u8>> {
        let chip_id_hex = hex::encode(chip_id);
        let tcb_str = format!(
            "{:02X}{:02X}{:02X}{:02X}",
            tcb.bootloader, tcb.tee, tcb.snp, tcb.microcode
        );
        let key = (
            processor_gen.to_string(),
            chip_id_hex.clone(),
            tcb_str.clone(),
        );

        if let Some(cert) = self.vcek_cache.get(&key).await {
            return Ok(cert);
        }

        let url = format!(
            "{}/{}/{}?blSPL={:02}&teeSPL={:02}&snpSPL={:02}&ucodeSPL={:02}",
            attestation::AMD_KDS_VCEK_BASE,
            processor_gen,
            chip_id_hex,
            tcb.bootloader,
            tcb.tee,
            tcb.snp,
            tcb.microcode
        );

        tracing::info!(%url, "fetching VCEK from AMD KDS");
        let resp = self.http_client.get(&url).send().await?;
        let cert = resp.error_for_status()?.bytes().await?.to_vec();
        self.vcek_cache.insert(key, cert.clone()).await;
        Ok(cert)
    }

    pub async fn get_cert_chain(&self, processor_gen: &str) -> anyhow::Result<(Vec<u8>, Vec<u8>)> {
        if let Some(chain) = self.chain_cache.get(processor_gen).await {
            return Ok(chain);
        }

        let url = format!(
            "{}/{}/cert_chain",
            attestation::AMD_KDS_VCEK_BASE,
            processor_gen
        );

        tracing::info!(%url, "fetching cert chain from AMD KDS");
        let resp = self.http_client.get(&url).send().await?;
        let pem_data = resp.error_for_status()?.bytes().await?;

        // The cert chain PEM contains two certificates: ASK then ARK
        let chain = parse_cert_chain_pem(&pem_data)?;
        self.chain_cache
            .insert(processor_gen.to_string(), chain.clone())
            .await;
        Ok(chain)
    }

    // --- TDX collateral operations ---

    pub async fn get_tdx_collateral(
        &self,
        collateral_type: &str,
        identifier: &str,
    ) -> anyhow::Result<Vec<u8>> {
        let key = (collateral_type.to_string(), identifier.to_string());

        if let Some(data) = self.tdx_cache.get(&key).await {
            return Ok(data);
        }

        let url = match collateral_type {
            "tcb_info" => {
                attestation::collateral::DefaultTdxCollateralProvider::tcb_info_url(identifier)
            }
            "qe_identity" => {
                attestation::collateral::DefaultTdxCollateralProvider::qe_identity_url()
            }
            "td_qe_identity" => {
                attestation::collateral::DefaultTdxCollateralProvider::td_qe_identity_url()
            }
            "root_ca_crl" => {
                attestation::collateral::DefaultTdxCollateralProvider::root_ca_crl_url()
            }
            "pck_crl" => {
                attestation::collateral::DefaultTdxCollateralProvider::pck_crl_url(identifier)
            }
            other => anyhow::bail!("unknown collateral type: {other}"),
        };

        tracing::info!(%url, "fetching TDX collateral");
        let resp = self.http_client.get(&url).send().await?;
        let mut data = resp.error_for_status()?.bytes().await?.to_vec();

        // Intel PCS returns PCK CRL as PEM; convert to DER for the library.
        if collateral_type == "pck_crl" && data.starts_with(b"-----BEGIN") {
            data = pem::parse(&data)?.into_contents();
        }

        self.tdx_cache.insert(key, data.clone()).await;
        Ok(data)
    }

    // --- CRL operations ---

    pub async fn get_crl(&self, issuer: &str, url: &str) -> anyhow::Result<CrlEntry> {
        if let Some(entry) = self.crl_cache.get(issuer).await {
            return Ok(entry);
        }

        tracing::info!(%url, %issuer, "fetching CRL");
        let resp = self.http_client.get(url).send().await?;
        let data = resp.error_for_status()?.bytes().await?.to_vec();

        let now = Utc::now();
        let entry = build_crl_entry(data, now, self.crl_refresh_hours);

        self.crl_cache
            .insert(issuer.to_string(), entry.clone())
            .await;
        *self.last_crl_refresh.write().await = Some(now);
        Ok(entry)
    }

    // --- NRAS JWKS operations ---

    /// Fetch and cache a JWKS document.
    ///
    /// When `force_refresh` is true, the cache is bypassed and the freshly
    /// fetched JWKS overwrites any existing entry (used by the verifier on
    /// `kid` rotation).
    pub async fn get_jwks(
        &self,
        url: &str,
        force_refresh: bool,
    ) -> anyhow::Result<attestation::platforms::nvidia_gpu::Jwks> {
        if !force_refresh {
            if let Some(jwks) = self.jwks_cache.get(url).await {
                return Ok(jwks);
            }
        }
        tracing::info!(%url, "fetching NRAS JWKS");
        let jwks: attestation::platforms::nvidia_gpu::Jwks = self
            .http_client
            .get(url)
            .send()
            .await?
            .error_for_status()?
            .json()
            .await?;
        // `insert` overwrites any existing entry for `url`.
        self.jwks_cache.insert(url.to_string(), jwks.clone()).await;
        Ok(jwks)
    }

    // --- Stats ---

    pub fn vcek_entry_count(&self) -> u64 {
        self.vcek_cache.entry_count()
    }

    pub fn chain_entry_count(&self) -> u64 {
        self.chain_cache.entry_count()
    }

    pub fn tdx_entry_count(&self) -> u64 {
        self.tdx_cache.entry_count()
    }

    pub fn jwks_entry_count(&self) -> u64 {
        self.jwks_cache.entry_count()
    }

    /// Returns the names of all known processor generations currently in the chain cache.
    pub async fn cached_chain_names(&self) -> Vec<String> {
        let mut names = Vec::new();
        for gen in KNOWN_GENERATIONS {
            if self.chain_cache.get(&gen.to_string()).await.is_some() {
                names.push(gen.to_string());
            }
        }
        names
    }

    /// Returns a JSON object with status information for all cached CRL entries.
    pub async fn crl_status_json(&self) -> Value {
        let known_issuers = ["snp_milan", "snp_genoa", "snp_turin", "tdx_root_ca"];
        let mut status = Map::new();
        for issuer in &known_issuers {
            if let Some(entry) = self.crl_cache.get(&issuer.to_string()).await {
                status.insert(
                    issuer.to_string(),
                    json!({
                        "last_fetched": entry.last_fetched.to_rfc3339(),
                        "next_refresh": entry.next_refresh.to_rfc3339(),
                    }),
                );
            }
        }
        Value::Object(status)
    }

    pub async fn last_crl_refresh(&self) -> Option<DateTime<Utc>> {
        *self.last_crl_refresh.read().await
    }

    pub async fn refresh_all(&self) -> anyhow::Result<()> {
        // Invalidate all caches to force re-fetch on next access
        self.vcek_cache.invalidate_all();
        self.chain_cache.invalidate_all();
        self.tdx_cache.invalidate_all();
        self.crl_cache.invalidate_all();
        self.jwks_cache.invalidate_all();

        // Pre-fetch configured chain types, collecting any failures
        let mut failures = Vec::new();
        for gen in &self.configured_generations {
            if let Err(e) = self.get_cert_chain(gen).await {
                tracing::error!(gen = gen.as_str(), error = %e, "failed to refresh cert chain after cache invalidation");
                failures.push(format!("{gen}: {e}"));
            }
        }

        anyhow::ensure!(
            failures.is_empty(),
            "cache invalidated but {} chain(s) failed to refresh: {}",
            failures.len(),
            failures.join("; ")
        );

        Ok(())
    }
}

/// Build a CRL entry with the given refresh interval (in hours).
pub(crate) fn build_crl_entry(data: Vec<u8>, now: DateTime<Utc>, refresh_hours: u64) -> CrlEntry {
    CrlEntry {
        data,
        last_fetched: now,
        next_refresh: now + ChronoDuration::hours(refresh_hours as i64),
        entry_count: 0,
    }
}

/// Parse an AMD PEM cert chain (ASK first, ARK second) into (ARK DER, ASK DER).
/// Requires at least 2 certs; extra certs are logged and ignored.
pub(crate) fn parse_cert_chain_pem(pem_data: &[u8]) -> anyhow::Result<(Vec<u8>, Vec<u8>)> {
    let certs = pem::parse_many(pem_data)?;
    anyhow::ensure!(
        certs.len() >= 2,
        "cert chain must contain at least 2 certificates"
    );
    if certs.len() > 2 {
        tracing::warn!(
            cert_count = certs.len(),
            "cert chain contains more than 2 certificates; only ASK and ARK will be used"
        );
    }
    // AMD cert chain PEM: ASK first, then ARK
    let ask_der = certs[0].contents().to_vec();
    let ark_der = certs[1].contents().to_vec();
    Ok((ark_der, ask_der))
}

#[cfg(test)]
mod tests {
    use super::*;

    // Minimal PEM with valid base64 body (content is arbitrary, just needs to decode)
    const FAKE_CERT: &str = "-----BEGIN CERTIFICATE-----\naGVsbG8=\n-----END CERTIFICATE-----\n";

    fn make_pem_chain(count: usize) -> Vec<u8> {
        FAKE_CERT.repeat(count).into_bytes()
    }

    #[test]
    fn parse_chain_rejects_single_cert() {
        let result = parse_cert_chain_pem(&make_pem_chain(1));
        assert!(
            result.is_err(),
            "single cert should not be accepted as a chain"
        );
    }

    #[test]
    fn parse_chain_rejects_empty() {
        let result = parse_cert_chain_pem(b"no certs here");
        assert!(result.is_err());
    }

    #[test]
    fn parse_chain_returns_ark_first_ask_second() {
        // Use two distinct certs so we can verify ordering
        let ask_pem = "-----BEGIN CERTIFICATE-----\naGVsbG8=\n-----END CERTIFICATE-----\n";
        let ark_pem = "-----BEGIN CERTIFICATE-----\nd29ybGQ=\n-----END CERTIFICATE-----\n";
        // AMD cert chain PEM has ASK first, then ARK
        let chain_pem = format!("{ask_pem}{ark_pem}");

        let (ark_der, ask_der) = parse_cert_chain_pem(chain_pem.as_bytes()).unwrap();

        // "hello" = ASK (first in PEM), "world" = ARK (second in PEM)
        assert_eq!(
            ask_der, b"hello",
            "second element should be ASK (first cert in PEM)"
        );
        assert_eq!(
            ark_der, b"world",
            "first element should be ARK (second cert in PEM)"
        );
    }

    #[test]
    fn build_crl_entry_uses_configured_refresh_interval() {
        let now = Utc::now();
        let entry = build_crl_entry(vec![1, 2, 3], now, 6);
        let diff = entry.next_refresh - entry.last_fetched;
        assert_eq!(
            diff.num_hours(),
            6,
            "CRL next_refresh should be 6 hours ahead"
        );
        assert_eq!(entry.data, vec![1, 2, 3]);

        // Verify non-default interval is respected
        let entry12 = build_crl_entry(vec![], now, 12);
        let diff12 = entry12.next_refresh - entry12.last_fetched;
        assert_eq!(diff12.num_hours(), 12);
    }
}
