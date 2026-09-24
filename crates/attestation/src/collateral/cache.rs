//! One cache for every collateral kind: single flight per key, validity-driven
//! serving, failure backoff, an optional disk store, and a refresher that keeps
//! held and pinned artifacts warm. It implements the three provider traits, so
//! a verifier is wired with one call and a service needs no adapters.
//!
//! Serving rule (profile section 10.2): a copy is served while it is inside the
//! artifact's own validity window. The per-kind max age is a refresh trigger,
//! never a reason to refuse a copy that the vendor still says is valid. Kinds
//! without a window (a JWKS) are bounded by their max age alone.
//!
//! Lock order: `pinned` before `entries`; `failures`, `inflight`,
//! `last_refresh` and `last_report` are only ever taken alone.

use super::artifact::{Collateral, SharedCollateral};
use super::error::{CollateralError, CollateralResult};
use super::fetch::{Endpoints, Fetcher};
use super::key::{CollateralKey, CollateralKind, Fmspc, PckCa};
use super::store::DiskStore;
use super::{CertProvider, HttpTimeouts, SignedCollateral, TdxCollateralProvider};
use crate::error::{AttestationError, Result};
use crate::types::{ProcessorGeneration, SnpTcb};
use async_trait::async_trait;
use chrono::{DateTime, Duration as ChronoDuration, Utc};
use serde::Serialize;
use std::collections::{BTreeSet, HashMap};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, MutexGuard, RwLock, RwLockReadGuard, RwLockWriteGuard, Weak};
use std::time::{Duration, Instant};
use tokio::sync::{Mutex as AsyncMutex, Semaphore};

/// Refreshes in flight at once, across every refresh pass of one cache.
pub const REFRESH_CONCURRENCY: usize = 8;
/// Failure records kept; the oldest retry time goes first. A verify with a
/// random chip id would otherwise grow this map without bound.
pub const MAX_FAILURES: usize = 256;
/// No max age above this; it keeps the date arithmetic in range.
pub const MAX_AGE_CAP: Duration = Duration::from_secs(10 * 365 * 24 * 3600);

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
        ChronoDuration::from_std(d.min(MAX_AGE_CAP)).unwrap_or_else(|_| ChronoDuration::days(3650))
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
    /// Monotonic use counter for LRU eviction, bumped under the read lock.
    use_seq: AtomicU64,
    inserted: Instant,
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

/// Outcome of a refresh pass. Failures carry the error text, so a report can
/// be shared with callers that coalesced onto one pass.
#[derive(Debug, Clone, Default)]
pub struct RefreshReport {
    pub attempted: usize,
    pub failed: Vec<(CollateralKey, String)>,
}

fn read<T>(lock: &RwLock<T>) -> RwLockReadGuard<'_, T> {
    lock.read().unwrap_or_else(|e| e.into_inner())
}

fn write<T>(lock: &RwLock<T>) -> RwLockWriteGuard<'_, T> {
    lock.write().unwrap_or_else(|e| e.into_inner())
}

fn lock<T>(m: &Mutex<T>) -> MutexGuard<'_, T> {
    m.lock().unwrap_or_else(|e| e.into_inner())
}

pub struct CollateralCache {
    fetcher: Fetcher,
    policy: CachePolicy,
    store: Option<DiskStore>,
    entries: RwLock<HashMap<CollateralKey, Entry>>,
    use_counter: AtomicU64,
    inflight: Mutex<HashMap<CollateralKey, Weak<AsyncMutex<()>>>>,
    failures: Mutex<HashMap<CollateralKey, Backoff>>,
    pinned: RwLock<BTreeSet<CollateralKey>>,
    last_refresh: RwLock<Option<DateTime<Utc>>>,
    /// Coalesces refresh passes: a caller that finds one running waits for it
    /// and takes its report instead of starting another.
    refresh_gate: AsyncMutex<()>,
    last_report: RwLock<Option<RefreshReport>>,
    refresh_slots: Arc<Semaphore>,
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
            use_counter: AtomicU64::new(1),
            inflight: Mutex::new(HashMap::new()),
            failures: Mutex::new(HashMap::new()),
            pinned: RwLock::new(BTreeSet::new()),
            last_refresh: RwLock::new(None),
            refresh_gate: AsyncMutex::new(()),
            last_report: RwLock::new(None),
            refresh_slots: Arc::new(Semaphore::new(REFRESH_CONCURRENCY)),
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

    /// NRAS endpoints for GPU and switch attestation; JWKS keys derive from them.
    #[cfg(feature = "nvidia-gpu")]
    pub fn with_nras_urls(mut self, gpu_url: String, switch_url: String) -> Self {
        self.nras =
            crate::platforms::nvidia_gpu::DefaultNrasProvider::with_urls(gpu_url, switch_url);
        self
    }

    pub fn now(&self) -> DateTime<Utc> {
        (self.clock)()
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
        write(&self.pinned).insert(key);
    }

    pub fn pinned(&self) -> Vec<CollateralKey> {
        read(&self.pinned).iter().cloned().collect()
    }

    fn freshness(&self, c: &Collateral, now: DateTime<Utc>) -> Option<Freshness> {
        let cap = c.age_cap(self.policy.max_age(c.kind()));
        match c.valid_until {
            Some(until) if now >= until => None,
            Some(_) => Some(if now < cap {
                Freshness::Fresh
            } else {
                Freshness::Stale
            }),
            None => (now < cap).then_some(Freshness::Fresh),
        }
    }

    fn lookup(
        &self,
        key: &CollateralKey,
        now: DateTime<Utc>,
    ) -> Option<(SharedCollateral, Freshness)> {
        let entries = read(&self.entries);
        let entry = entries.get(key)?;
        let freshness = self.freshness(&entry.value, now)?;
        entry.use_seq.store(
            self.use_counter.fetch_add(1, Ordering::Relaxed),
            Ordering::Relaxed,
        );
        Some((entry.value.clone(), freshness))
    }

    /// The copy inserted after `since`, if it is servable: the refresh path uses
    /// it to skip a dial another task just made.
    fn inserted_after(&self, key: &CollateralKey, since: Instant) -> Option<SharedCollateral> {
        let entries = read(&self.entries);
        let entry = entries.get(key)?;
        (entry.inserted > since && self.freshness(&entry.value, self.now()).is_some())
            .then(|| entry.value.clone())
    }

    fn insert(&self, c: SharedCollateral, persist: bool) {
        if persist {
            if let Some(store) = &self.store {
                store.put(&c);
            }
        }
        let pinned = read(&self.pinned);
        let mut entries = write(&self.entries);
        entries.insert(
            c.key.clone(),
            Entry {
                value: c,
                use_seq: AtomicU64::new(self.use_counter.fetch_add(1, Ordering::Relaxed)),
                inserted: Instant::now(),
            },
        );
        while entries.len() > self.policy.max_entries {
            let victim = entries
                .iter()
                .filter(|(k, _)| !pinned.contains(*k))
                .min_by_key(|(_, e)| e.use_seq.load(Ordering::Relaxed))
                .map(|(k, _)| k.clone());
            match victim {
                Some(k) => {
                    entries.remove(&k);
                }
                None => break,
            }
        }
    }

    fn flight(&self, key: &CollateralKey) -> Arc<AsyncMutex<()>> {
        let mut inflight = lock(&self.inflight);
        if let Some(existing) = inflight.get(key).and_then(Weak::upgrade) {
            return existing;
        }
        if inflight.len() > 256 {
            inflight.retain(|_, w| w.strong_count() > 0);
        }
        let flight = Arc::new(AsyncMutex::new(()));
        inflight.insert(key.clone(), Arc::downgrade(&flight));
        flight
    }

    fn backoff_for(&self, key: &CollateralKey, now: DateTime<Utc>) -> Option<Backoff> {
        lock(&self.failures)
            .get(key)
            .filter(|b| now < b.retry_at)
            .cloned()
    }

    fn record_failure(&self, key: &CollateralKey) {
        let now = self.now();
        let mut failures = lock(&self.failures);
        let consecutive = failures
            .get(key)
            .map_or(0, |b| b.consecutive)
            .saturating_add(1);
        let delay = self.policy.backoff_delay(consecutive);
        if delay.is_zero() {
            failures.remove(key);
            return;
        }
        failures.retain(|_, b| b.retry_at > now);
        if failures.len() >= MAX_FAILURES {
            let oldest = failures
                .iter()
                .min_by_key(|(_, b)| b.retry_at)
                .map(|(k, _)| k.clone());
            if let Some(k) = oldest {
                failures.remove(&k);
            }
        }
        failures.insert(
            key.clone(),
            Backoff {
                consecutive,
                retry_at: now
                    .checked_add_signed(delay)
                    .unwrap_or(DateTime::<Utc>::MAX_UTC),
            },
        );
    }

    fn clear_failure(&self, key: &CollateralKey) {
        lock(&self.failures).remove(key);
    }

    /// A fallback copy is served only if it is still inside its window at the
    /// moment it is served; the fetch it stood in for may have taken seconds.
    fn serve_fallback(
        &self,
        fallback: Option<SharedCollateral>,
        err: CollateralError,
    ) -> CollateralResult<SharedCollateral> {
        match fallback {
            Some(c) if self.freshness(&c, self.now()).is_some() => {
                log::warn!("{err}; serving the copy valid until {:?}", c.valid_until);
                Ok(c)
            }
            _ => Err(err),
        }
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

    /// Fetch under the key's single-flight lock. `fallback` is a copy inside
    /// its window, served when the vendor cannot be reached.
    async fn fetch_into(
        &self,
        key: &CollateralKey,
        fallback: Option<SharedCollateral>,
    ) -> CollateralResult<SharedCollateral> {
        let backoff_err = |b: Backoff| CollateralError::Backoff {
            key: key.clone(),
            consecutive: b.consecutive,
            retry_at: b.retry_at,
        };
        if let Some(b) = self.backoff_for(key, self.now()) {
            return self.serve_fallback(fallback, backoff_err(b));
        }
        let flight = self.flight(key);
        let _guard = flight.lock().await;
        if let Some((c, Freshness::Fresh)) = self.lookup(key, self.now()) {
            return Ok(c);
        }
        // A waiter behind a leader that just failed must not dial again.
        if let Some(b) = self.backoff_for(key, self.now()) {
            return self.serve_fallback(fallback, backoff_err(b));
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
                self.serve_fallback(fallback, e)
            }
        }
    }

    /// Refetch now, regardless of age or backoff, replacing the copy on
    /// success and keeping it on failure. A copy another task inserted while
    /// this call waited for the lock is returned instead of dialling again.
    pub async fn refresh(&self, key: &CollateralKey) -> CollateralResult<SharedCollateral> {
        let started = Instant::now();
        let flight = self.flight(key);
        let _guard = flight.lock().await;
        if let Some(c) = self.inserted_after(key, started) {
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
                Err(e)
            }
        }
    }

    /// Keys the refresher should fetch now: pinned keys with no usable copy,
    /// and held copies past half their max age or past their window.
    fn due(&self, now: DateTime<Utc>) -> Vec<CollateralKey> {
        let pinned = read(&self.pinned);
        let entries = read(&self.entries);
        let mut due: BTreeSet<CollateralKey> = BTreeSet::new();
        for (key, entry) in entries.iter() {
            let max_age = self.policy.max_age(entry.value.kind());
            let refresh_at = entry
                .value
                .expires_at(max_age)
                .checked_sub_signed(max_age / 2)
                .unwrap_or(DateTime::<Utc>::MIN_UTC);
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

    /// Refresh what is due (see [`Self::due`]). Skipped when a pass is running.
    pub async fn refresh_due(self: &Arc<Self>) -> RefreshReport {
        let Ok(_gate) = self.refresh_gate.try_lock() else {
            return RefreshReport::default();
        };
        let due = self.due(self.now());
        self.refresh_keys(due).await
    }

    /// Refetch every held and pinned artifact, replacing each only on success.
    /// Concurrent callers coalesce onto the running pass and share its report.
    pub async fn refresh_all(self: &Arc<Self>) -> RefreshReport {
        match self.refresh_gate.try_lock() {
            Ok(_gate) => {
                let mut keys: BTreeSet<CollateralKey> =
                    read(&self.entries).keys().cloned().collect();
                keys.extend(self.pinned());
                let report = self.refresh_keys(keys.into_iter().collect()).await;
                *write(&self.last_report) = Some(report.clone());
                report
            }
            Err(_) => {
                let _gate = self.refresh_gate.lock().await;
                read(&self.last_report).clone().unwrap_or_default()
            }
        }
    }

    async fn refresh_keys(self: &Arc<Self>, keys: Vec<CollateralKey>) -> RefreshReport {
        let mut set = tokio::task::JoinSet::new();
        let attempted = keys.len();
        for key in keys {
            let cache = self.clone();
            let slots = self.refresh_slots.clone();
            set.spawn(async move {
                let _permit = slots.acquire().await.expect("semaphore open");
                let outcome = cache.refresh(&key).await.map(drop);
                (key, outcome)
            });
        }
        let mut failed = Vec::new();
        while let Some(joined) = set.join_next().await {
            match joined {
                Ok((key, Err(e))) => failed.push((key, e.to_string())),
                Ok((_, Ok(()))) => {}
                Err(e) => log::error!("collateral refresh task failed: {e}"),
            }
        }
        failed.sort_by(|a, b| a.0.cmp(&b.0));
        for (key, e) in &failed {
            log::warn!("refresh of {key} failed, keeping the held copy: {e}");
        }
        *write(&self.last_refresh) = Some(self.now());
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
        let pinned = read(&self.pinned);
        let entries = read(&self.entries);
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
        let mut failures: Vec<(String, Backoff)> = lock(&self.failures)
            .iter()
            .map(|(k, b)| (k.to_string(), b.clone()))
            .collect();
        failures.sort_by(|a, b| a.0.cmp(&b.0));
        CacheStatus {
            entries: out,
            pinned: pinned.iter().map(ToString::to_string).collect(),
            failures,
            last_refresh: *read(&self.last_refresh),
        }
    }

    /// Entries held in memory for a kind.
    pub fn count(&self, kind: CollateralKind) -> usize {
        read(&self.entries)
            .values()
            .filter(|e| e.value.kind() == kind)
            .count()
    }

    /// Failure records currently held.
    pub fn failure_count(&self) -> usize {
        lock(&self.failures).len()
    }

    /// A signed PCS body with the chain that arrived with it. The fetcher and
    /// the store refuse such a body without a chain, so a missing one here is
    /// an invariant violation and fails closed.
    async fn signed(&self, key: &CollateralKey) -> Result<SignedCollateral> {
        let c = self.get(key).await?;
        let signing_chain = c.signing_chain.clone().ok_or_else(|| {
            AttestationError::CertFetchError(format!("{key}: held without its signing chain"))
        })?;
        Ok(SignedCollateral {
            body: c.bytes.clone(),
            signing_chain,
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
    async fn get_tcb_info(&self, fmspc: &str) -> Result<SignedCollateral> {
        let fmspc = Fmspc::new(fmspc).ok_or_else(|| {
            AttestationError::QuoteParseFailed(format!(
                "FMSPC {fmspc:?} is not twelve hex characters"
            ))
        })?;
        self.signed(&CollateralKey::TdxTcbInfo { fmspc }).await
    }

    async fn get_qe_identity(&self) -> Result<SignedCollateral> {
        self.signed(&CollateralKey::TdxQeIdentity { td: false })
            .await
    }

    async fn get_td_qe_identity(&self) -> Result<SignedCollateral> {
        self.signed(&CollateralKey::TdxQeIdentity { td: true })
            .await
    }

    async fn get_root_ca_crl(&self) -> Result<Vec<u8>> {
        Ok(self.get(&CollateralKey::TdxRootCrl).await?.bytes.clone())
    }

    fn now(&self) -> DateTime<Utc> {
        CollateralCache::now(self)
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
}

#[cfg(feature = "nvidia-gpu")]
#[async_trait]
impl crate::platforms::nvidia_gpu::NrasProvider for CollateralCache {
    fn url_for(&self, arch: crate::types::NvidiaGpuArch) -> &str {
        self.nras.url_for(arch)
    }

    fn accepts_certificate_hold(&self) -> bool {
        self.nras.accepts_certificate_hold()
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
        let url =
            crate::platforms::nvidia_gpu::provider::jwks_url_for_endpoint(self.nras.url_for(arch))?;
        let c = self.get(&CollateralKey::NrasJwks { url }).await?;
        serde_json::from_slice(&c.bytes)
            .map_err(|e| AttestationError::JwksFetch(format!("JWKS parse: {e}")))
    }

    async fn jwks_force(
        &self,
        arch: crate::types::NvidiaGpuArch,
    ) -> Result<crate::platforms::nvidia_gpu::Jwks> {
        let url =
            crate::platforms::nvidia_gpu::provider::jwks_url_for_endpoint(self.nras.url_for(arch))?;
        let c = self.refresh(&CollateralKey::NrasJwks { url }).await?;
        serde_json::from_slice(&c.bytes)
            .map_err(|e| AttestationError::JwksFetch(format!("JWKS parse: {e}")))
    }
}
