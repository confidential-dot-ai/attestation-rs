//! One cache for every collateral kind: single flight per key, validity-driven
//! serving, failure backoff, an optional disk store, and a refresher that keeps
//! held and pinned artifacts warm. It implements the three provider traits, so
//! a verifier is wired with one call and a service needs no adapters.
//!
//! Serving rule (profile section 10): a copy is served while it is inside the
//! artifact's own validity window. The per-kind max age is a refresh trigger,
//! never a reason to refuse a copy that the vendor still says is valid. Kinds
//! without a window (a JWKS) are bounded by their max age alone.

use super::artifact::{Collateral, SharedCollateral};
use super::error::{CollateralError, CollateralResult};
use super::fetch::{Endpoints, Fetcher};
use super::key::{CollateralKey, CollateralKind, PckCa};
use super::store::DiskStore;
use super::{CertProvider, HttpTimeouts, TdxCollateralProvider};
use crate::error::{AttestationError, Result};
use crate::types::{ProcessorGeneration, SnpTcb};
use async_trait::async_trait;
use chrono::{DateTime, Duration as ChronoDuration, Utc};
use serde::Serialize;
use std::collections::{BTreeSet, HashMap};
use std::sync::{Arc, Mutex, RwLock, Weak};
use std::time::{Duration, Instant};
use tokio::sync::{Mutex as AsyncMutex, Semaphore};

/// Refreshes in flight at once. Under vendor rate limits, above one round trip deep.
pub const REFRESH_CONCURRENCY: usize = 8;

/// The cache's notion of now; injectable so validity logic is testable.
pub type Clock = Arc<dyn Fn() -> DateTime<Utc> + Send + Sync>;

/// Per-kind refresh triggers and the failure backoff.
#[derive(Debug, Clone)]
pub struct CachePolicy {
    /// In-memory entries kept; the least recently used unpinned entry goes first.
    pub max_entries: usize,
    /// Refetch a copy older than this, even inside its window. A refresher
    /// starts refetching at half of it.
    pub max_age_vcek: Duration,
    pub max_age_chain: Duration,
    pub max_age_crl: Duration,
    pub max_age_tdx: Duration,
    pub max_age_jwks: Duration,
    /// Failure backoff: doubles per consecutive failure from the base, capped at
    /// the max. A zero base disables it and every request dials again.
    pub backoff_base: Duration,
    pub backoff_max: Duration,
    /// When an SNP CRL cannot be obtained: refuse (true) or skip revocation
    /// with a warning (false), as `CertProvider::get_snp_crl` allows.
    pub snp_crl_required: bool,
}

impl Default for CachePolicy {
    fn default() -> Self {
        CachePolicy {
            max_entries: 1024,
            max_age_vcek: Duration::from_secs(24 * 3600),
            max_age_chain: Duration::from_secs(7 * 24 * 3600),
            max_age_crl: Duration::from_secs(6 * 3600),
            max_age_tdx: Duration::from_secs(24 * 3600),
            max_age_jwks: Duration::from_secs(3600),
            backoff_base: Duration::from_secs(1),
            backoff_max: Duration::from_secs(300),
            snp_crl_required: false,
        }
    }
}

impl CachePolicy {
    pub fn max_age(&self, kind: CollateralKind) -> ChronoDuration {
        let d = match kind {
            CollateralKind::SnpVcek => self.max_age_vcek,
            CollateralKind::SnpCertChain => self.max_age_chain,
            CollateralKind::SnpCrl | CollateralKind::TdxPckCrl | CollateralKind::TdxRootCrl => {
                self.max_age_crl
            }
            CollateralKind::TdxTcbInfo | CollateralKind::TdxQeIdentity => self.max_age_tdx,
            CollateralKind::NrasJwks => self.max_age_jwks,
        };
        ChronoDuration::from_std(d).unwrap_or(ChronoDuration::MAX)
    }

    /// Doubles from the base per consecutive failure, capped at the max.
    pub fn backoff_delay(&self, consecutive: u32) -> ChronoDuration {
        if self.backoff_base.is_zero() {
            return ChronoDuration::zero();
        }
        let base = self.backoff_base.as_secs();
        let shift = consecutive.saturating_sub(1).min(63);
        let secs = base
            .saturating_mul(1u64 << shift)
            .min(self.backoff_max.as_secs().max(base));
        ChronoDuration::seconds(secs as i64)
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct Backoff {
    pub consecutive: u32,
    pub retry_at: DateTime<Utc>,
}

struct Entry {
    value: SharedCollateral,
    last_used: Instant,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Freshness {
    /// Inside its window and younger than the max age.
    Fresh,
    /// Inside its window, older than the max age: serve, and refetch.
    Stale,
}

/// One entry of [`CacheStatus`].
#[derive(Debug, Clone, Serialize)]
pub struct EntryStatus {
    pub key: String,
    pub kind: CollateralKind,
    pub origin: super::artifact::Origin,
    pub bytes: usize,
    pub fetched_at: DateTime<Utc>,
    pub valid_until: Option<DateTime<Utc>>,
    /// When the copy stops being served without a refresh.
    pub expires_at: DateTime<Utc>,
    pub stale: bool,
    pub pinned: bool,
}

#[derive(Debug, Clone, Serialize)]
pub struct CacheStatus {
    pub entries: Vec<EntryStatus>,
    pub pinned: Vec<String>,
    pub failures: Vec<(String, Backoff)>,
    pub last_refresh: Option<DateTime<Utc>>,
}

/// Outcome of a refresh pass.
#[derive(Debug, Default)]
pub struct RefreshReport {
    pub attempted: usize,
    pub failed: Vec<(CollateralKey, CollateralError)>,
}

pub struct CollateralCache {
    fetcher: Fetcher,
    policy: CachePolicy,
    store: Option<DiskStore>,
    entries: RwLock<HashMap<CollateralKey, Entry>>,
    inflight: Mutex<HashMap<CollateralKey, Weak<AsyncMutex<()>>>>,
    failures: Mutex<HashMap<CollateralKey, Backoff>>,
    pinned: RwLock<BTreeSet<CollateralKey>>,
    /// The Intel signing chain last captured with each signed kind, for the
    /// chain accessors of [`TdxCollateralProvider`], which take no key.
    signing_chains: RwLock<HashMap<&'static str, Vec<u8>>>,
    last_refresh: RwLock<Option<DateTime<Utc>>>,
    clock: Clock,
    #[cfg(feature = "nvidia-gpu")]
    nras: crate::platforms::nvidia_gpu::DefaultNrasProvider,
}

impl Default for CollateralCache {
    fn default() -> Self {
        Self::new(
            CachePolicy::default(),
            &HttpTimeouts::default(),
            Endpoints::default(),
            None,
        )
    }
}

impl CollateralCache {
    pub fn new(
        policy: CachePolicy,
        timeouts: &HttpTimeouts,
        endpoints: Endpoints,
        store: Option<DiskStore>,
    ) -> Self {
        Self::with_fetcher(policy, Fetcher::new(timeouts, endpoints), store)
    }

    pub fn with_fetcher(policy: CachePolicy, fetcher: Fetcher, store: Option<DiskStore>) -> Self {
        CollateralCache {
            fetcher,
            policy,
            store,
            entries: RwLock::new(HashMap::new()),
            inflight: Mutex::new(HashMap::new()),
            failures: Mutex::new(HashMap::new()),
            pinned: RwLock::new(BTreeSet::new()),
            signing_chains: RwLock::new(HashMap::new()),
            last_refresh: RwLock::new(None),
            clock: Arc::new(Utc::now),
            #[cfg(feature = "nvidia-gpu")]
            nras: crate::platforms::nvidia_gpu::DefaultNrasProvider::new(),
        }
    }

    /// Replace the clock (tests pin it to a fixture's capture time).
    pub fn with_clock(mut self, clock: Clock) -> Self {
        self.clock = clock;
        self
    }

    pub fn now(&self) -> DateTime<Utc> {
        (self.clock)()
    }

    /// NRAS endpoints for GPU and switch attestation; JWKS keys derive from them.
    #[cfg(feature = "nvidia-gpu")]
    pub fn with_nras_urls(mut self, gpu_url: String, switch_url: String) -> Self {
        self.nras =
            crate::platforms::nvidia_gpu::DefaultNrasProvider::with_urls(gpu_url, switch_url);
        self
    }

    pub fn policy(&self) -> &CachePolicy {
        &self.policy
    }

    pub fn endpoints(&self) -> &Endpoints {
        self.fetcher.endpoints()
    }

    /// Keep this artifact warm: fetched by the refresher when absent, refreshed
    /// before it goes stale, never evicted.
    pub fn pin(&self, key: CollateralKey) {
        self.pinned.write().expect("pinned set").insert(key);
    }

    pub fn pinned(&self) -> Vec<CollateralKey> {
        self.pinned
            .read()
            .expect("pinned set")
            .iter()
            .cloned()
            .collect()
    }

    fn freshness(&self, c: &Collateral, now: DateTime<Utc>) -> Option<Freshness> {
        let max_age = self.policy.max_age(c.kind());
        match c.valid_until {
            Some(until) if now >= until => None,
            Some(_) => Some(if now < c.fetched_at + max_age {
                Freshness::Fresh
            } else {
                Freshness::Stale
            }),
            None => (now < c.fetched_at + max_age).then_some(Freshness::Fresh),
        }
    }

    fn lookup(
        &self,
        key: &CollateralKey,
        now: DateTime<Utc>,
    ) -> Option<(SharedCollateral, Freshness)> {
        let mut entries = self.entries.write().expect("entries");
        let entry = entries.get_mut(key)?;
        let freshness = self.freshness(&entry.value, now)?;
        entry.last_used = Instant::now();
        Some((entry.value.clone(), freshness))
    }

    fn remember_signing_chain(&self, c: &Collateral) {
        let name = match &c.key {
            CollateralKey::TdxTcbInfo { .. } => "tcb",
            CollateralKey::TdxQeIdentity { td: true } => "qe_td",
            CollateralKey::TdxQeIdentity { td: false } => "qe_sgx",
            _ => return,
        };
        if let Some(chain) = &c.signing_chain {
            self.signing_chains
                .write()
                .expect("signing chains")
                .insert(name, chain.clone());
        }
    }

    /// Lock order everywhere: `pinned` before `entries`, never the reverse.
    fn insert(&self, c: SharedCollateral, persist: bool) {
        self.remember_signing_chain(&c);
        if persist {
            if let Some(store) = &self.store {
                store.put(&c);
            }
        }
        let pinned = self.pinned.read().expect("pinned set");
        let mut entries = self.entries.write().expect("entries");
        entries.insert(
            c.key.clone(),
            Entry {
                value: c,
                last_used: Instant::now(),
            },
        );
        if entries.len() > self.policy.max_entries {
            let victim = entries
                .iter()
                .filter(|(k, _)| !pinned.contains(*k))
                .min_by_key(|(_, e)| e.last_used)
                .map(|(k, _)| k.clone());
            if let Some(k) = victim {
                entries.remove(&k);
            }
        }
    }

    fn flight(&self, key: &CollateralKey) -> Arc<AsyncMutex<()>> {
        let mut inflight = self.inflight.lock().expect("inflight");
        if let Some(existing) = inflight.get(key).and_then(Weak::upgrade) {
            return existing;
        }
        if inflight.len() > 256 {
            inflight.retain(|_, w| w.strong_count() > 0);
        }
        let lock = Arc::new(AsyncMutex::new(()));
        inflight.insert(key.clone(), Arc::downgrade(&lock));
        lock
    }

    fn backoff_for(&self, key: &CollateralKey, now: DateTime<Utc>) -> Option<Backoff> {
        let failures = self.failures.lock().expect("failures");
        failures.get(key).filter(|b| now < b.retry_at).cloned()
    }

    fn record_failure(&self, key: &CollateralKey) {
        let mut failures = self.failures.lock().expect("failures");
        let consecutive = failures
            .get(key)
            .map_or(0, |b| b.consecutive)
            .saturating_add(1);
        let delay = self.policy.backoff_delay(consecutive);
        if delay.is_zero() {
            failures.remove(key);
            return;
        }
        failures.insert(
            key.clone(),
            Backoff {
                consecutive,
                retry_at: self.now() + delay,
            },
        );
    }

    fn clear_failure(&self, key: &CollateralKey) {
        self.failures.lock().expect("failures").remove(key);
    }

    /// The artifact, from memory, disk or the vendor, in that order. A copy
    /// inside its window is always served; one older than its max age is
    /// refetched first and served if the refetch fails.
    pub async fn get(&self, key: &CollateralKey) -> CollateralResult<SharedCollateral> {
        let now = self.now();
        let fallback = match self.lookup(key, now) {
            Some((c, Freshness::Fresh)) => return Ok(c),
            Some((c, Freshness::Stale)) => Some(c),
            None => {
                let stored = self
                    .store
                    .as_ref()
                    .and_then(|s| s.get(key, now))
                    .map(Arc::new);
                if let Some(c) = &stored {
                    self.insert(c.clone(), false);
                    if self.freshness(c, now) == Some(Freshness::Fresh) {
                        return Ok(c.clone());
                    }
                }
                stored
            }
        };
        self.fetch_into(key, fallback).await
    }

    /// Fetch under the key's single-flight lock. `fallback` is a copy still
    /// inside its window, served when the vendor cannot be reached.
    async fn fetch_into(
        &self,
        key: &CollateralKey,
        fallback: Option<SharedCollateral>,
    ) -> CollateralResult<SharedCollateral> {
        let now = self.now();
        if let Some(b) = self.backoff_for(key, now) {
            return fallback.ok_or(CollateralError::Backoff {
                key: key.clone(),
                consecutive: b.consecutive,
                retry_at: b.retry_at,
            });
        }
        let flight = self.flight(key);
        let _guard = flight.lock().await;
        if let Some((c, Freshness::Fresh)) = self.lookup(key, self.now()) {
            return Ok(c);
        }
        match self.fetcher.fetch(key, self.now()).await {
            Ok(c) => {
                let c = Arc::new(c);
                self.insert(c.clone(), true);
                self.clear_failure(key);
                Ok(c)
            }
            Err(e) => {
                self.record_failure(key);
                match fallback {
                    Some(c) => {
                        log::warn!("{e}; serving the copy valid until {:?}", c.valid_until);
                        Ok(c)
                    }
                    None => Err(e),
                }
            }
        }
    }

    /// Refetch now, regardless of age or backoff, replacing the copy on
    /// success and keeping it on failure.
    pub async fn refresh(&self, key: &CollateralKey) -> CollateralResult<SharedCollateral> {
        let flight = self.flight(key);
        let _guard = flight.lock().await;
        match self.fetcher.fetch(key, self.now()).await {
            Ok(c) => {
                let c = Arc::new(c);
                self.insert(c.clone(), true);
                self.clear_failure(key);
                Ok(c)
            }
            Err(e) => {
                self.record_failure(key);
                Err(e)
            }
        }
    }

    /// Keys the refresher should fetch now: pinned keys with no usable copy,
    /// and held copies past half their max age or past their window.
    fn due(&self, now: DateTime<Utc>) -> Vec<CollateralKey> {
        let pinned = self.pinned.read().expect("pinned set");
        let entries = self.entries.read().expect("entries");
        let mut due: BTreeSet<CollateralKey> = BTreeSet::new();
        for (key, entry) in entries.iter() {
            let lead = self.policy.max_age(entry.value.kind()) / 2;
            let refresh_at = entry
                .value
                .expires_at(self.policy.max_age(entry.value.kind()))
                - lead;
            if now >= refresh_at {
                due.insert(key.clone());
            }
        }
        for key in pinned.iter() {
            match entries.get(key) {
                Some(e) if self.freshness(&e.value, now).is_some() => {}
                _ => {
                    due.insert(key.clone());
                }
            }
        }
        due.into_iter().collect()
    }

    /// Refresh what is due (see [`Self::due`]), bounded concurrency.
    pub async fn refresh_due(self: &Arc<Self>) -> RefreshReport {
        let due = self.due(self.now());
        self.refresh_keys(due).await
    }

    /// Refetch every held and pinned artifact, replacing each only on success.
    pub async fn refresh_all(self: &Arc<Self>) -> RefreshReport {
        let mut keys: BTreeSet<CollateralKey> = self
            .entries
            .read()
            .expect("entries")
            .keys()
            .cloned()
            .collect();
        keys.extend(self.pinned());
        self.refresh_keys(keys.into_iter().collect()).await
    }

    async fn refresh_keys(self: &Arc<Self>, keys: Vec<CollateralKey>) -> RefreshReport {
        let semaphore = Arc::new(Semaphore::new(REFRESH_CONCURRENCY));
        let mut set = tokio::task::JoinSet::new();
        let attempted = keys.len();
        for key in keys {
            let cache = self.clone();
            let semaphore = semaphore.clone();
            set.spawn(async move {
                let _permit = semaphore.acquire().await.expect("semaphore open");
                let outcome = cache.refresh(&key).await.map(drop);
                (key, outcome)
            });
        }
        let mut failed = Vec::new();
        while let Some(joined) = set.join_next().await {
            match joined {
                Ok((key, Err(e))) => failed.push((key, e)),
                Ok((_, Ok(()))) => {}
                Err(e) => log::error!("collateral refresh task failed: {e}"),
            }
        }
        failed.sort_by(|a, b| a.0.cmp(&b.0));
        for (key, e) in &failed {
            log::warn!("refresh of {key} failed, keeping the held copy: {e}");
        }
        *self.last_refresh.write().expect("last refresh") = Some(self.now());
        RefreshReport { attempted, failed }
    }

    /// A background task that runs [`Self::refresh_due`] every `interval`.
    pub fn spawn_refresher(self: Arc<Self>, interval: Duration) -> tokio::task::JoinHandle<()> {
        tokio::spawn(async move {
            loop {
                tokio::time::sleep(interval).await;
                let report = self.refresh_due().await;
                log::debug!(
                    "collateral refresh: {} attempted, {} failed",
                    report.attempted,
                    report.failed.len()
                );
            }
        })
    }

    pub fn status(&self) -> CacheStatus {
        let now = self.now();
        let pinned = self.pinned.read().expect("pinned set");
        let entries = self.entries.read().expect("entries");
        let mut out: Vec<EntryStatus> = entries
            .iter()
            .map(|(k, e)| {
                let max_age = self.policy.max_age(e.value.kind());
                EntryStatus {
                    key: k.to_string(),
                    kind: e.value.kind(),
                    origin: e.value.origin,
                    bytes: e.value.bytes.len(),
                    fetched_at: e.value.fetched_at,
                    valid_until: e.value.valid_until,
                    expires_at: e.value.expires_at(max_age),
                    stale: self.freshness(&e.value, now) != Some(Freshness::Fresh),
                    pinned: pinned.contains(k),
                }
            })
            .collect();
        out.sort_by(|a, b| a.key.cmp(&b.key));
        let mut failures: Vec<(String, Backoff)> = self
            .failures
            .lock()
            .expect("failures")
            .iter()
            .map(|(k, b)| (k.to_string(), b.clone()))
            .collect();
        failures.sort_by(|a, b| a.0.cmp(&b.0));
        CacheStatus {
            entries: out,
            pinned: pinned.iter().map(ToString::to_string).collect(),
            failures,
            last_refresh: *self.last_refresh.read().expect("last refresh"),
        }
    }

    /// Entries held in memory for a kind.
    pub fn count(&self, kind: CollateralKind) -> usize {
        self.entries
            .read()
            .expect("entries")
            .values()
            .filter(|e| e.value.kind() == kind)
            .count()
    }

    fn signing_chain(&self, name: &'static str, what: &str) -> Result<Option<Vec<u8>>> {
        self.signing_chains
            .read()
            .expect("signing chains")
            .get(name)
            .cloned()
            .map(Some)
            .ok_or_else(|| {
                AttestationError::CertFetchError(format!(
                    "{what} signing chain is not held; fetch the {what} body first"
                ))
            })
    }
}

#[async_trait]
impl CertProvider for CollateralCache {
    async fn get_snp_vcek(
        &self,
        processor_gen: ProcessorGeneration,
        chip_id: &[u8; 64],
        reported_tcb: &SnpTcb,
    ) -> Result<Vec<u8>> {
        let key = CollateralKey::SnpVcek {
            generation: processor_gen,
            chip_id: *chip_id,
            tcb: *reported_tcb,
        };
        Ok(self.get(&key).await?.bytes.clone())
    }

    async fn get_snp_cert_chain(
        &self,
        processor_gen: ProcessorGeneration,
    ) -> Result<(Vec<u8>, Vec<u8>)> {
        let key = CollateralKey::SnpCertChain {
            generation: processor_gen,
        };
        Ok(self.get(&key).await?.snp_chain_parts()?)
    }

    async fn get_snp_crl(&self, processor_gen: ProcessorGeneration) -> Result<Option<Vec<u8>>> {
        let key = CollateralKey::SnpCrl {
            generation: processor_gen,
        };
        match self.get(&key).await {
            Ok(c) => Ok(Some(c.bytes.clone())),
            Err(e) if self.policy.snp_crl_required => Err(e.into()),
            Err(e) => {
                log::warn!("{e}; skipping SNP revocation (snp_crl_required is false)");
                Ok(None)
            }
        }
    }
}

#[async_trait]
impl TdxCollateralProvider for CollateralCache {
    async fn get_tcb_info(&self, fmspc: &str) -> Result<Vec<u8>> {
        let key = CollateralKey::tdx_tcb_info(fmspc).ok_or_else(|| {
            AttestationError::QuoteParseFailed(format!(
                "FMSPC {fmspc:?} is not twelve hex characters"
            ))
        })?;
        Ok(self.get(&key).await?.bytes.clone())
    }

    async fn get_qe_identity(&self) -> Result<Vec<u8>> {
        Ok(self
            .get(&CollateralKey::TdxQeIdentity { td: false })
            .await?
            .bytes
            .clone())
    }

    async fn get_td_qe_identity(&self) -> Result<Vec<u8>> {
        Ok(self
            .get(&CollateralKey::TdxQeIdentity { td: true })
            .await?
            .bytes
            .clone())
    }

    async fn get_root_ca_crl(&self) -> Result<Vec<u8>> {
        Ok(self.get(&CollateralKey::TdxRootCrl).await?.bytes.clone())
    }

    async fn get_pck_crl(&self, ca: &str) -> Result<Vec<u8>> {
        let ca = PckCa::parse(ca)
            .ok_or_else(|| AttestationError::QuoteParseFailed(format!("unknown PCK CA {ca:?}")))?;
        Ok(self
            .get(&CollateralKey::TdxPckCrl { ca })
            .await?
            .bytes
            .clone())
    }

    async fn get_tcb_signing_chain(&self) -> Result<Option<Vec<u8>>> {
        self.signing_chain("tcb", "TCB Info")
    }

    async fn get_qe_identity_signing_chain(&self) -> Result<Option<Vec<u8>>> {
        self.signing_chain("qe_sgx", "QE Identity")
    }

    async fn get_td_qe_identity_signing_chain(&self) -> Result<Option<Vec<u8>>> {
        self.signing_chain("qe_td", "TD QE Identity")
    }
}

#[cfg(feature = "nvidia-gpu")]
#[async_trait]
impl crate::platforms::nvidia_gpu::NrasProvider for CollateralCache {
    fn url_for(&self, arch: crate::types::NvidiaGpuArch) -> &str {
        self.nras.url_for(arch)
    }

    async fn attest(
        &self,
        request: &crate::platforms::nvidia_gpu::NrasRequest,
    ) -> Result<serde_json::Value> {
        // Per request and nonce-bound: never cached.
        self.nras.attest(request).await
    }

    async fn jwks(
        &self,
        arch: crate::types::NvidiaGpuArch,
    ) -> Result<crate::platforms::nvidia_gpu::Jwks> {
        let url = crate::platforms::nvidia_gpu::jwks_url_for_endpoint(self.nras.url_for(arch))?;
        let c = self.get(&CollateralKey::NrasJwks { url }).await?;
        serde_json::from_slice(&c.bytes)
            .map_err(|e| AttestationError::JwksFetch(format!("JWKS parse: {e}")))
    }

    async fn jwks_force(
        &self,
        arch: crate::types::NvidiaGpuArch,
    ) -> Result<crate::platforms::nvidia_gpu::Jwks> {
        let url = crate::platforms::nvidia_gpu::jwks_url_for_endpoint(self.nras.url_for(arch))?;
        let c = self.refresh(&CollateralKey::NrasJwks { url }).await?;
        serde_json::from_slice(&c.bytes)
            .map_err(|e| AttestationError::JwksFetch(format!("JWKS parse: {e}")))
    }
}
