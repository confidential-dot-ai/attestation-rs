use chrono::{DateTime, Duration as ChronoDuration, Utc};
use moka::future::Cache;
use reqwest::Client;
use serde::Serialize;
use serde_json::{json, Map, Value};
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::RwLock;

use crate::certs::hours_to_duration;
use crate::certs::store::CollateralStore;
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
    /// Issuers whose CRL fetch failed recently. Only successes were cached
    /// before, so an unreachable distribution point was re-dialled on every
    /// verify and each one paid the full connect timeout.
    /// Consecutive-failure state per issuer, driving the retry backoff.
    crl_failure_cache: Cache<String, CrlBackoff>,
    /// JWKS cache keyed by the full JWKS URL (NVIDIA NRAS).
    jwks_cache: Cache<String, attestation::platforms::nvidia_gpu::Jwks>,
    last_crl_refresh: Arc<RwLock<Option<DateTime<Utc>>>>,
    http_client: Client,
    /// Normalized processor generation names from config (used for refresh operations).
    configured_generations: Vec<String>,
    /// Configured CRL refresh interval in hours (used for CrlEntry.next_refresh).
    crl_refresh_hours: u64,
    crl_backoff_base_secs: u64,
    crl_backoff_max_secs: u64,
    /// Disk-backed VCEK/chain store. `None` keeps collateral in memory only.
    store: Option<CollateralStore>,
}

impl CertCache {
    pub fn new(config: &CertsConfig) -> Self {
        let http_client = Client::builder()
            .connect_timeout(Duration::from_secs(10))
            .timeout(Duration::from_secs(30))
            .build()
            .expect("failed to build HTTP client");
        Self::with_client(config, http_client)
    }

    pub(crate) fn with_client(config: &CertsConfig, http_client: Client) -> Self {
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
        // Fail-closed deployments do NOT get the negative cache. Under
        // require_crl a remembered failure refuses verification outright, so a
        // one-second blip would become a full-backoff outage even after
        // the endpoint recovers. Fail-open is the case worth caching: the CRL
        // result is discarded anyway, so the only thing repeated dialling buys
        // is the stall this fixes.
        // 0 disables it; moka treats a zero TTL as "expire immediately".
        // Under require_crl a suppressed retry means a refused verification, so
        // fail-closed always dials.
        let crl_backoff_base_secs = if config.require_crl {
            0
        } else {
            config.crl_backoff_base_secs
        };
        // Outlive the longest backoff so an outage does not keep resetting the
        // consecutive count back to the base delay.
        let crl_failure_cache = Cache::builder()
            .max_capacity(64)
            .time_to_live(Duration::from_secs(
                config.crl_backoff_max_secs.saturating_mul(4).max(60),
            ))
            .build();

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
            crl_failure_cache,
            jwks_cache,
            last_crl_refresh: Arc::new(RwLock::new(None)),
            http_client,
            configured_generations,
            crl_refresh_hours: config.crl_refresh_hours,
            crl_backoff_base_secs,
            crl_backoff_max_secs: config.crl_backoff_max_secs,
            store: config
                .local_collateral_dir
                .as_ref()
                .filter(|d| !d.is_empty())
                .map(CollateralStore::new),
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

        // A VCEK never changes for this key, so a stored copy is authoritative
        // and lets a cold process verify while KDS is unreachable.
        if let Some(store) = &self.store {
            if let Some(cert) = store.get_vcek(processor_gen, &chip_id_hex, &tcb_str) {
                self.vcek_cache.insert(key, cert.clone()).await;
                return Ok(cert);
            }
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
        if let Some(store) = &self.store {
            store.put_vcek(processor_gen, &chip_id_hex, &tcb_str, &cert);
        }
        self.vcek_cache.insert(key, cert.clone()).await;
        Ok(cert)
    }

    pub async fn get_cert_chain(&self, processor_gen: &str) -> anyhow::Result<(Vec<u8>, Vec<u8>)> {
        if let Some(chain) = self.chain_cache.get(processor_gen).await {
            return Ok(chain);
        }

        if let Some(store) = &self.store {
            if let Some(chain) = store.get_chain(processor_gen) {
                self.chain_cache
                    .insert(processor_gen.to_string(), chain.clone())
                    .await;
                return Ok(chain);
            }
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
        if let Some(store) = &self.store {
            store.put_chain(processor_gen, &chain.0, &chain.1);
        }
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

        // Suppression is best-effort: moka applies writes asynchronously, so a
        // verify racing the failure that recorded it may still dial. The cost of
        // a miss is one extra connect, never a wrong verification result.
        let prior = self.crl_failure_cache.get(issuer).await;
        if let Some(state) = &prior {
            let now = Utc::now();
            if now < state.retry_at {
                anyhow::bail!(
                    "CRL fetch for {issuer} is backing off after {} consecutive failures; next retry in {}s (certs.crl_backoff_*)",
                    state.consecutive,
                    (state.retry_at - now).num_seconds().max(0)
                );
            }
        }

        tracing::info!(%url, %issuer, "fetching CRL");
        let fetched = async {
            let resp = self.http_client.get(url).send().await?;
            let data = resp.error_for_status()?.bytes().await?.to_vec();
            Ok::<Vec<u8>, anyhow::Error>(data)
        }
        .await;

        let data = match fetched {
            Ok(data) => data,
            Err(e) => {
                // Grow the retry window per consecutive failure so a blip costs
                // one base delay and a real outage stops being dialled.
                let consecutive = prior.map_or(0, |s| s.consecutive).saturating_add(1);
                let delay = backoff_delay(
                    self.crl_backoff_base_secs,
                    self.crl_backoff_max_secs,
                    consecutive,
                );
                if !delay.is_zero() {
                    self.crl_failure_cache
                        .insert(
                            issuer.to_string(),
                            CrlBackoff {
                                consecutive,
                                retry_at: Utc::now() + delay,
                            },
                        )
                        .await;
                }
                return Err(e);
            }
        };

        let now = Utc::now();
        let entry = build_crl_entry(data, now, self.crl_refresh_hours);

        self.crl_cache
            .insert(issuer.to_string(), entry.clone())
            .await;
        self.crl_failure_cache.invalidate(issuer).await;
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

/// Retry state for a CRL distribution point that is currently failing.
#[derive(Debug, Clone)]
pub(crate) struct CrlBackoff {
    pub consecutive: u32,
    pub retry_at: DateTime<Utc>,
}

/// Doubles from `base` per consecutive failure, capped at `max`. A zero base
/// disables the backoff entirely.
pub(crate) fn backoff_delay(base_secs: u64, max_secs: u64, consecutive: u32) -> ChronoDuration {
    if base_secs == 0 {
        return ChronoDuration::zero();
    }
    let shift = consecutive.saturating_sub(1).min(63);
    let secs = base_secs
        .saturating_mul(1u64 << shift)
        .min(max_secs.max(base_secs));
    ChronoDuration::seconds(secs as i64)
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

    /// Every request is routed through a closed local port, so any code path that
    /// reaches for the network fails. A call that still succeeds provably did not.
    fn offline_client() -> Client {
        Client::builder()
            .proxy(reqwest::Proxy::all("http://127.0.0.1:1").unwrap())
            .connect_timeout(Duration::from_secs(2))
            .timeout(Duration::from_secs(2))
            .build()
            .unwrap()
    }

    fn cfg_with_store(dir: Option<&std::path::Path>) -> CertsConfig {
        CertsConfig {
            local_collateral_dir: dir.map(|d| d.to_string_lossy().to_string()),
            ..Default::default()
        }
    }

    const TEST_CHIP: [u8; 64] = [0xAB; 64];

    fn test_tcb() -> attestation::SnpTcb {
        attestation::SnpTcb {
            fmc: None,
            bootloader: 3,
            tee: 0,
            snp: 10,
            microcode: 27,
        }
    }

    #[tokio::test]
    async fn vcek_is_served_from_the_store_with_no_network() {
        let dir = tempfile::tempdir().unwrap();
        let cache = CertCache::with_client(&cfg_with_store(Some(dir.path())), offline_client());

        // Seed through the same key derivation the lookup uses.
        let tcb = test_tcb();
        let store = crate::certs::store::CollateralStore::new(dir.path());
        store.put_vcek(
            "Genoa",
            &hex::encode(TEST_CHIP),
            &format!(
                "{:02X}{:02X}{:02X}{:02X}",
                tcb.bootloader, tcb.tee, tcb.snp, tcb.microcode
            ),
            b"stored-vcek",
        );

        let cert = cache
            .get_vcek("Genoa", &TEST_CHIP, &tcb)
            .await
            .expect("a stored VCEK must be served while the network is unreachable");
        assert_eq!(cert, b"stored-vcek");
    }

    #[tokio::test]
    async fn vcek_without_a_stored_copy_needs_the_network() {
        // Control for the test above: same offline client, empty store. If this
        // ever passes, the network block is not blocking and the test above proves
        // nothing.
        let dir = tempfile::tempdir().unwrap();
        let cache = CertCache::with_client(&cfg_with_store(Some(dir.path())), offline_client());
        assert!(cache
            .get_vcek("Genoa", &TEST_CHIP, &test_tcb())
            .await
            .is_err());
    }

    #[tokio::test]
    async fn a_second_cold_process_reads_the_stored_vcek() {
        let dir = tempfile::tempdir().unwrap();
        let tcb = test_tcb();
        let tcb_str = format!(
            "{:02X}{:02X}{:02X}{:02X}",
            tcb.bootloader, tcb.tee, tcb.snp, tcb.microcode
        );

        // Populate via one cache, then read with a second one that shares only the
        // directory: that is exactly the cold-process path.
        let first = CertCache::with_client(&cfg_with_store(Some(dir.path())), offline_client());
        crate::certs::store::CollateralStore::new(dir.path()).put_vcek(
            "Genoa",
            &hex::encode(TEST_CHIP),
            &tcb_str,
            b"written-back",
        );
        drop(first);

        let second = CertCache::with_client(&cfg_with_store(Some(dir.path())), offline_client());
        assert_eq!(
            second.get_vcek("Genoa", &TEST_CHIP, &tcb).await.unwrap(),
            b"written-back"
        );
    }

    #[tokio::test]
    async fn without_a_configured_directory_nothing_is_persisted() {
        let dir = tempfile::tempdir().unwrap();
        let cache = CertCache::with_client(&cfg_with_store(None), offline_client());
        assert!(cache
            .get_vcek("Genoa", &TEST_CHIP, &test_tcb())
            .await
            .is_err());
        assert_eq!(
            fs_count(dir.path()),
            0,
            "an unset collateral dir must leave the filesystem untouched"
        );
    }

    fn fs_count(p: &std::path::Path) -> usize {
        std::fs::read_dir(p).map(|d| d.count()).unwrap_or(0)
    }

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
    fn backoff_doubles_from_the_base_then_holds_at_the_cap() {
        let seq: Vec<i64> = (1..=12)
            .map(|n| backoff_delay(1, 300, n).num_seconds())
            .collect();
        assert_eq!(
            seq,
            vec![1, 2, 4, 8, 16, 32, 64, 128, 256, 300, 300, 300],
            "delay must double per consecutive failure and then hold at the cap"
        );
    }

    #[test]
    fn a_zero_base_yields_no_delay() {
        assert!(backoff_delay(0, 300, 9).is_zero());
    }

    #[test]
    fn a_cap_below_the_base_never_shrinks_the_base() {
        assert_eq!(backoff_delay(30, 5, 1).num_seconds(), 30);
    }

    #[test]
    fn a_huge_failure_count_does_not_overflow() {
        assert_eq!(backoff_delay(1, 300, u32::MAX).num_seconds(), 300);
    }

    // The property the flat TTL got wrong: once a window passes the endpoint must
    // be dialled again, so a brief outage is not held open for the full cap.
    // Drives the clock by seeding an already-elapsed window instead of sleeping,
    // so the test cannot flake on a loaded machine.
    #[tokio::test]
    async fn a_window_that_has_elapsed_is_re_dialled() {
        let (url, hits) = counting_crl_endpoint().await;
        let cache = CertCache::new(&CertsConfig {
            crl_backoff_base_secs: 300,
            ..Default::default()
        });

        assert!(cache.get_crl("snp_genoa", &url).await.is_err());
        assert_eq!(hits_of(&hits), 1);
        assert!(cache.get_crl("snp_genoa", &url).await.is_err());
        assert_eq!(hits_of(&hits), 1, "a retry inside the window must not dial");

        // Same state the code would hold once the window has passed.
        cache
            .crl_failure_cache
            .insert(
                "snp_genoa".to_string(),
                CrlBackoff {
                    consecutive: 1,
                    retry_at: Utc::now() - ChronoDuration::seconds(1),
                },
            )
            .await;

        assert!(cache.get_crl("snp_genoa", &url).await.is_err());
        assert_eq!(
            hits_of(&hits),
            2,
            "once the window passes the endpoint must be dialled again"
        );
    }

    // A repeated failure must lengthen the window rather than reset it.
    #[tokio::test]
    async fn consecutive_failures_accumulate() {
        let (url, hits) = counting_crl_endpoint().await;
        let cache = CertCache::new(&CertsConfig {
            crl_backoff_base_secs: 1,
            crl_backoff_max_secs: 300,
            ..Default::default()
        });

        assert!(cache.get_crl("snp_genoa", &url).await.is_err());
        for expected in 2..=4u32 {
            cache
                .crl_failure_cache
                .insert(
                    "snp_genoa".to_string(),
                    CrlBackoff {
                        consecutive: expected - 1,
                        retry_at: Utc::now() - ChronoDuration::seconds(1),
                    },
                )
                .await;
            assert!(cache.get_crl("snp_genoa", &url).await.is_err());
            // moka writes are asynchronous; settle them before reading back so the
            // assertion tests the counter and not the write buffer.
            cache.crl_failure_cache.run_pending_tasks().await;
            let state = cache.crl_failure_cache.get("snp_genoa").await.unwrap();
            assert_eq!(state.consecutive, expected);
        }
        assert_eq!(hits_of(&hits), 4);
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

    // The property under test is "does it dial the distribution point again",
    // not what the error says. So stand up a listener that COUNTS connections
    // and answers 500: the negative cache is working iff the second get_crl
    // adds no connection. Asserting on the error text would pass even if the
    // fetch were repeated.
    async fn counting_crl_endpoint() -> (String, std::sync::Arc<std::sync::atomic::AtomicUsize>) {
        use std::sync::atomic::AtomicUsize;
        use tokio::io::AsyncWriteExt;

        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let hits = std::sync::Arc::new(AtomicUsize::new(0));
        let counter = hits.clone();

        tokio::spawn(async move {
            while let Ok((mut sock, _)) = listener.accept().await {
                counter.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                // 500 so the fetch fails without the connect timeout. Connection:
                // close stops reqwest pooling the socket, which would let a second
                // request reuse one accept() and undercount the dials.
                let _ = sock
                    .write_all(
                        b"HTTP/1.1 500 Internal Server Error\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
                    )
                    .await;
            }
        });

        (format!("http://{addr}/crl"), hits)
    }

    fn hits_of(c: &std::sync::Arc<std::sync::atomic::AtomicUsize>) -> usize {
        c.load(std::sync::atomic::Ordering::SeqCst)
    }

    #[tokio::test]
    async fn a_failed_crl_fetch_is_dialled_once_not_once_per_verify() {
        let (url, hits) = counting_crl_endpoint().await;
        let cache = CertCache::new(&CertsConfig {
            crl_backoff_base_secs: 300,
            ..Default::default()
        });

        assert!(cache.get_crl("snp_genoa", &url).await.is_err());
        assert_eq!(hits_of(&hits), 1, "the first fetch should dial once");

        assert!(cache.get_crl("snp_genoa", &url).await.is_err());
        assert_eq!(
            hits_of(&hits),
            1,
            "the second verify must be served by the negative cache, not re-dialled"
        );
    }

    #[tokio::test]
    async fn a_zero_base_dials_every_time() {
        let (url, hits) = counting_crl_endpoint().await;
        let cache = CertCache::new(&CertsConfig {
            crl_backoff_base_secs: 0,
            ..Default::default()
        });

        assert!(cache.get_crl("snp_genoa", &url).await.is_err());
        assert!(cache.get_crl("snp_genoa", &url).await.is_err());
        assert_eq!(
            hits_of(&hits),
            2,
            "base=0 must disable the backoff and retry per request"
        );
    }

    // Guards the regression the negative cache would otherwise introduce: under
    // require_crl a remembered failure REFUSES verification, so caching it would
    // extend a momentary blip into a full-TTL outage. Fail-closed must keep
    // retrying.
    #[tokio::test]
    async fn fail_closed_keeps_retrying_and_is_never_negatively_cached() {
        let (url, hits) = counting_crl_endpoint().await;
        let cache = CertCache::new(&CertsConfig {
            require_crl: true,
            crl_backoff_base_secs: 300,
            ..Default::default()
        });

        assert!(cache.get_crl("snp_genoa", &url).await.is_err());
        assert!(cache.get_crl("snp_genoa", &url).await.is_err());
        assert_eq!(
            hits_of(&hits),
            2,
            "require_crl must re-dial so recovery is picked up immediately"
        );
    }

    #[tokio::test]
    async fn the_negative_cache_is_per_issuer() {
        let (url, hits) = counting_crl_endpoint().await;
        let cache = CertCache::new(&CertsConfig {
            crl_backoff_base_secs: 300,
            ..Default::default()
        });

        assert!(cache.get_crl("snp_genoa", &url).await.is_err());
        assert!(cache.get_crl("snp_milan", &url).await.is_err());
        assert_eq!(
            hits_of(&hits),
            2,
            "a failure for one generation must not suppress another's fetch"
        );
    }
}
