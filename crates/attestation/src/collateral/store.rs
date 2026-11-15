//! The store: the only place collateral is fetched, verified and kept.
//!
//! Every piece comes in through its `verify` (signature against the
//! compiled-in roots, binding to what the evidence names), whatever the
//! source: held by the caller, memory, disk, or the vendor. The cache is keyed
//! by the vendor URL. In memory a piece is kept until a newer valid copy
//! replaces it; a failed refetch keeps the old copy.

use std::any::Any;
use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use serde::{Deserialize, Serialize};

use super::{Collateral, Dates, VersionFloors, GRACE};
use crate::context::HeldResponse;
use crate::error::{AttestationError, Result, Unavailable};

/// Where a piece of collateral used for a verdict came from.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Source {
    /// Supplied by the caller (WASM, tests).
    Held,
    /// Attached to the evidence by the attester.
    Attached,
    /// This process already held it.
    Memory,
    /// The disk cache.
    Disk,
    /// Fetched from the vendor by this call, or by a concurrent call it
    /// waited for.
    Vendor,
    /// Fetched, as [`Source::Vendor`], from an upstream collateral cache.
    Cache,
}

impl std::fmt::Display for Source {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Source::Held => "held",
            Source::Attached => "attached",
            Source::Memory => "memory",
            Source::Disk => "disk",
            Source::Vendor => "vendor",
            Source::Cache => "cache",
        })
    }
}

/// A piece of collateral a verdict used: which, from where, its version and
/// nextUpdate, whether it was current at the evaluation time, and the lowest
/// version the policies accept.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CollateralUsed {
    /// For example `amd-crl genoa`, `tcb-info 70a06d070000`.
    pub name: String,
    pub from: Source,
    pub version: Option<u64>,
    pub next_update: Option<i64>,
    pub current: bool,
    /// Past its nextUpdate, but by less than [`GRACE`]: it still passes.
    #[serde(default)]
    pub stale: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub floor: Option<u64>,
}

impl CollateralUsed {
    fn new(name: String, from: Source, dates: Dates, floor: Option<u64>, now: i64) -> Self {
        let current = dates.current(now);
        let in_grace = Dates {
            next_update: dates.next_update.map(|n| n.saturating_add(GRACE)),
            ..dates
        };
        Self {
            name,
            from,
            version: dates.version,
            next_update: dates.next_update,
            current,
            stale: !current && in_grace.current(now),
            floor,
        }
    }

    /// True when the piece is current or stale, and not below its floor.
    pub fn acceptable(&self) -> bool {
        (self.current || self.stale)
            && self
                .floor
                .is_none_or(|f| self.version.is_some_and(|v| v >= f))
    }
}

#[derive(Clone)]
#[cfg_attr(target_arch = "wasm32", allow(dead_code))]
struct Entry {
    body: Vec<u8>,
    issuer_chain: Option<String>,
    /// The id and piece `body` verified as, so a lookup need not verify it
    /// again.
    checked: Checked,
    dates: Dates,
    origin: Source,
    /// When to ask the upstream for a newer copy (Unix seconds).
    refresh_at: i64,
    #[cfg(not(target_arch = "wasm32"))]
    checked_at: std::time::Instant,
}

/// A random time in the last quarter of the window of a piece, and at least
/// a day before its nextUpdate, so that copies made together are not all
/// refreshed together.
#[cfg_attr(target_arch = "wasm32", allow(dead_code))]
fn refresh_at(dates: &Dates) -> i64 {
    const DAY: i64 = 24 * 3600;
    let Some(next) = dates.next_update else {
        return i64::MAX;
    };
    let latest = next - DAY;
    let earliest = dates
        .this_update
        .map_or(latest, |this| this + (next - this) / 4 * 3);
    if earliest >= latest {
        return latest;
    }
    let random = std::hash::BuildHasher::hash_one(&std::hash::RandomState::new(), next);
    earliest + (random % (latest - earliest) as u64) as i64
}

#[derive(Clone)]
pub(crate) enum Failure {
    Unavailable(Unavailable),
    /// Why the piece does not verify.
    Refused(String),
    /// The vendor does not publish the piece the evidence names.
    #[cfg_attr(target_arch = "wasm32", allow(dead_code))]
    NotPublished(String),
}

impl Failure {
    fn refused(e: AttestationError) -> Self {
        Failure::Refused(match e {
            AttestationError::CertChainError(why) => why,
            e => e.to_string(),
        })
    }

    fn into_error(self, name: &str) -> AttestationError {
        match self {
            Failure::Unavailable(e) => e.into_error(name),
            Failure::Refused(why) | Failure::NotPublished(why) => {
                AttestationError::CertChainError(format!("{name} refused: {why}"))
            }
        }
    }
}

#[cfg_attr(target_arch = "wasm32", allow(dead_code))]
fn check<C: Collateral>(
    id: &C::Id,
    body: Vec<u8>,
    issuer_chain: Option<String>,
    origin: Source,
) -> std::result::Result<Entry, Failure> {
    let piece = C::verify(&body, issuer_chain.as_deref(), id).map_err(Failure::refused)?;
    let dates = piece.dates();
    Ok(Entry {
        body,
        issuer_chain,
        checked: Arc::new((id.clone(), piece)),
        refresh_at: refresh_at(&dates),
        dates,
        origin,
        #[cfg(not(target_arch = "wasm32"))]
        checked_at: std::time::Instant::now(),
    })
}

/// A verified piece with the id it was verified for: `(C::Id, C)`.
type Checked = Arc<dyn Any + Send + Sync>;

/// `body` as the piece `id` names: the copy `checked` holds when it was
/// verified for `id`, else verified now.
fn piece<C: Collateral>(
    checked: Option<&Checked>,
    body: &[u8],
    chain: Option<&str>,
    id: &C::Id,
) -> std::result::Result<C, Failure> {
    match checked.and_then(|c| c.downcast_ref::<(C::Id, C)>()) {
        Some((for_id, piece)) if for_id == id => Ok(piece.clone()),
        _ => C::verify(body, chain, id).map_err(Failure::refused),
    }
}

/// Vendor responses by URL: body and issuer chain.
type Responses = HashMap<String, (Vec<u8>, Option<String>)>;

/// Collateral for verifiers, from held copies, memory, disk and the vendors.
pub struct Store {
    /// Vendor responses supplied by the caller, by URL.
    held: Arc<Responses>,
    /// Vendor responses attached to the evidence of one verdict, by URL.
    attached: Responses,
    /// The URLs a held-only store was asked for and did not hold.
    missing: Arc<Mutex<Vec<String>>>,
    floors: VersionFloors,
    /// When set, every response a lookup used, each once.
    used: Option<Arc<Mutex<Vec<HeldResponse>>>>,
    #[cfg(not(target_arch = "wasm32"))]
    native: Option<Arc<native::Native>>,
    /// When set, the view is cached-only (see [`Self::view_cached`]).
    #[cfg(not(target_arch = "wasm32"))]
    cached: Option<Arc<Cached>>,
}

/// What a cached-only view put off, and what earlier fetches for the same
/// verification gave.
#[cfg(not(target_arch = "wasm32"))]
pub(crate) struct Cached {
    deferred: Mutex<Vec<Deferred>>,
    fetched: Fetched,
}

/// A vendor request a cached-only view put off: the URL, and the fetch
/// (and check), with what it gave.
#[cfg(not(target_arch = "wasm32"))]
pub(crate) type Deferred = (
    String,
    std::pin::Pin<Box<dyn std::future::Future<Output = Outcome> + Send>>,
);

/// What a put-off vendor request gave.
#[cfg(not(target_arch = "wasm32"))]
#[derive(Clone)]
pub(crate) enum Outcome {
    /// The piece is in memory, from there.
    Stored(Source),
    /// An answer for this verification only (NRAS's, bound to its nonce).
    Answer(Vec<u8>),
    Failed(Failure),
    /// NRAS refused the request.
    Refused(String),
}

/// What the vendor requests put off for one verification gave, by URL: a
/// cached-only view answers from it as a lookup that asked would have.
#[cfg(not(target_arch = "wasm32"))]
#[derive(Clone, Default)]
pub struct Fetched(pub(crate) Arc<HashMap<String, Outcome>>);

impl Store {
    /// Holds only what the caller supplies: no memory, disk or network.
    pub(crate) fn held_only() -> Self {
        Self {
            held: Arc::default(),
            attached: HashMap::new(),
            missing: Arc::default(),
            floors: VersionFloors::default(),
            used: None,
            #[cfg(not(target_arch = "wasm32"))]
            native: None,
            #[cfg(not(target_arch = "wasm32"))]
            cached: None,
        }
    }

    /// This store for one verdict: with the `attached` pieces, judged
    /// against `floors`, and recording what it used when `record`.
    pub(crate) fn view(
        &self,
        attached: Vec<HeldResponse>,
        floors: &VersionFloors,
        record: bool,
    ) -> Self {
        Self {
            held: self.held.clone(),
            attached: attached
                .into_iter()
                .map(|(url, body, chain)| (url, (body, chain)))
                .collect(),
            missing: self.missing.clone(),
            floors: floors.clone(),
            used: record.then(Arc::default),
            #[cfg(not(target_arch = "wasm32"))]
            native: self.native.clone(),
            #[cfg(not(target_arch = "wasm32"))]
            cached: None,
        }
    }

    /// As [`Self::view`], but it never waits on a vendor. A vendor request
    /// a lookup would make is put off for [`Self::take_deferred`] (the
    /// lookup fails as unavailable), unless `fetched` has its outcome: then
    /// the lookup answers as it would have after asking. CPU-bound callers
    /// verify with this view and fetch outside their threads.
    #[cfg(not(target_arch = "wasm32"))]
    pub(crate) fn view_cached(
        &self,
        attached: Vec<HeldResponse>,
        floors: &VersionFloors,
        fetched: &Fetched,
    ) -> Self {
        let fetches = self.native.as_ref().is_some_and(|n| n.vendor.is_some());
        Self {
            cached: fetches.then(|| {
                Arc::new(Cached {
                    deferred: Mutex::default(),
                    fetched: fetched.clone(),
                })
            }),
            ..self.view(attached, floors, false)
        }
    }

    /// The vendor requests a cached-only view put off, each URL once.
    #[cfg(not(target_arch = "wasm32"))]
    pub(crate) fn take_deferred(&self) -> Vec<Deferred> {
        self.cached.as_ref().map_or_else(Vec::new, |c| {
            std::mem::take(&mut *c.deferred.lock().unwrap_or_else(|e| e.into_inner()))
        })
    }

    /// Put off `fetch` of `url`, unless already put off.
    #[cfg(not(target_arch = "wasm32"))]
    fn defer(
        cached: &Cached,
        url: String,
        fetch: impl std::future::Future<Output = Outcome> + Send + 'static,
    ) -> Failure {
        let mut deferred = cached.deferred.lock().unwrap_or_else(|e| e.into_inner());
        if !deferred.iter().any(|(u, _)| *u == url) {
            deferred.push((url, Box::pin(fetch)));
        }
        Failure::Unavailable(Unavailable::detail("not in memory yet"))
    }

    /// NRAS's answer to `request` (held under `key`), asked now, or put off
    /// in a cached-only view.
    #[cfg(feature = "nvidia-gpu")]
    pub(crate) async fn nras_attest(
        &self,
        key: String,
        request: &crate::platforms::nvidia_gpu::provider::NrasRequest,
    ) -> Result<Vec<u8>> {
        const NAME: &str = "NRAS attestation";
        #[cfg(not(target_arch = "wasm32"))]
        if let Some(native) = self.native.as_ref().filter(|n| n.vendor.is_some()) {
            let Some(cached) = &self.cached else {
                return native.nras_attest(request).await;
            };
            match cached.fetched.0.get(&key) {
                Some(Outcome::Answer(body)) => return Ok(body.clone()),
                Some(Outcome::Failed(f)) => return Err(f.clone().into_error(NAME)),
                Some(Outcome::Refused(why)) => {
                    return Err(AttestationError::NrasRequestFailed(why.clone()))
                }
                Some(Outcome::Stored(_)) | None => {}
            }
            let (native, request) = (native.clone(), request.clone());
            let ask = async move {
                match native.nras_attest(&request).await {
                    Ok(body) => Outcome::Answer(body),
                    Err(AttestationError::CollateralUnavailable {
                        retry_after,
                        detail,
                        ..
                    }) => Outcome::Failed(Failure::Unavailable(Unavailable {
                        status: None,
                        retry_after,
                        detail,
                    })),
                    Err(AttestationError::NrasRequestFailed(why)) => Outcome::Refused(why),
                    Err(e) => Outcome::Refused(e.to_string()),
                }
            };
            return Err(Self::defer(cached, key, ask).into_error(NAME));
        }
        Err(Unavailable::offline().into_error(NAME))
    }

    /// Keep `url`'s response in what a recording view used.
    pub(crate) fn record(&self, url: String, body: Vec<u8>, chain: Option<String>) {
        if let Some(record) = &self.used {
            let mut record = record.lock().unwrap_or_else(|e| e.into_inner());
            if !record.iter().any(|(u, _, _)| *u == url) {
                record.push((url, body, chain));
            }
        }
    }

    /// The held or attached body for `url`, if any.
    #[cfg(feature = "nvidia-gpu")]
    pub(crate) fn held_body(&self, url: &str) -> Option<&[u8]> {
        self.held
            .get(url)
            .or_else(|| self.attached.get(url))
            .map(|(body, _)| body.as_slice())
    }

    /// The responses a recording view used, in the order first used.
    pub(crate) fn used(&self) -> Vec<HeldResponse> {
        self.used.as_ref().map_or_else(Vec::new, |u| {
            u.lock().unwrap_or_else(|e| e.into_inner()).clone()
        })
    }

    pub(crate) fn hold(&mut self, url: String, body: Vec<u8>, issuer_chain: Option<String>) {
        Arc::make_mut(&mut self.held).insert(url, (body, issuer_chain));
    }

    /// The vendor URLs a held-only store was asked for and did not hold,
    /// each once. A store with memory or a network records nothing.
    pub fn missing(&self) -> Vec<String> {
        self.missing
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .clone()
    }

    /// The piece `id` names, verified, and what the verdict should say about
    /// it at `now` (Unix seconds). Any copy on hand that does not verify
    /// refuses the piece, even when another copy is good: a bad attached
    /// piece makes the evidence not genuine.
    pub async fn get<C: Collateral>(&self, id: &C::Id, now: i64) -> Result<(C, CollateralUsed)> {
        self.lookup(id, now)
            .await
            .map_err(|e| e.into_error(&C::name(id)))
    }

    /// As [`Self::get`], but `None` when the vendor publishes no such piece
    /// (a GCE endorsement for a measurement Google never built).
    #[cfg(any(feature = "gcp-tdx", feature = "gcp-snp"))]
    pub(crate) async fn get_if_published<C: Collateral>(
        &self,
        id: &C::Id,
        now: i64,
    ) -> Result<Option<(C, CollateralUsed)>> {
        match self.lookup(id, now).await {
            Ok(got) => Ok(Some(got)),
            Err(Failure::Unavailable(e)) if e.not_found() => Ok(None),
            Err(e) => Err(e.into_error(&C::name(id))),
        }
    }

    pub(super) async fn lookup<C: Collateral>(
        &self,
        id: &C::Id,
        now: i64,
    ) -> std::result::Result<(C, CollateralUsed), Failure> {
        let url = C::url(id);
        let floor = C::floor(id, &self.floors);
        // The newest of the copies on hand; on a tie, the first of held,
        // cached, attached. Attached pieces never push the verifier back.
        let mut best: Option<(C, Vec<u8>, Option<String>, Source)> = None;
        for (body, chain, from, checked) in self.on_hand::<C>(&url, id).await {
            let piece = piece::<C>(checked.as_ref(), &body, chain.as_deref(), id)?;
            if best
                .as_ref()
                .is_none_or(|(b, ..)| !b.dates().not_older_than(&piece.dates()))
            {
                best = Some((piece, body, chain, from));
            }
        }
        let acceptable = |p: &C| {
            CollateralUsed::new(String::new(), Source::Held, p.dates(), floor, now).acceptable()
        };
        // Nothing on hand, or nothing that passes (a piece in grace passes):
        // the fallback may have better. A held-only store lists the URL as
        // missing, so the caller can fetch it.
        if best.as_ref().is_none_or(|(p, ..)| !acceptable(p)) {
            match self.load::<C>(url.clone(), id, now).await {
                Ok((entry, from)) => {
                    if best
                        .as_ref()
                        .is_none_or(|(b, ..)| !b.dates().not_older_than(&entry.dates))
                    {
                        let piece = piece::<C>(
                            Some(&entry.checked),
                            &entry.body,
                            entry.issuer_chain.as_deref(),
                            id,
                        )?;
                        best = Some((piece, entry.body, entry.issuer_chain, from));
                    }
                }
                Err(e) if best.is_none() => return Err(e),
                // The kept copy already verified; it just does not pass.
                Err(_) => {}
            }
        }
        let (piece, body, chain, from) = best.expect("a copy or an error");
        let dates = piece.dates();
        self.record(url, body, chain);
        let used = CollateralUsed::new(C::name(id), from, dates, floor, now);
        Ok((piece, used))
    }

    /// The copies of `url` this store has without asking anyone: held,
    /// cached in memory or on disk, attached.
    #[cfg_attr(target_arch = "wasm32", allow(unused_variables))]
    async fn on_hand<C: Collateral>(
        &self,
        url: &str,
        id: &C::Id,
    ) -> Vec<(Vec<u8>, Option<String>, Source, Option<Checked>)> {
        let mut copies = Vec::new();
        if let Some((body, chain)) = self.held.get(url) {
            copies.push((body.clone(), chain.clone(), Source::Held, None));
        }
        if let Some((body, chain)) = self.attached.get(url) {
            #[cfg(not(target_arch = "wasm32"))]
            if let Some(native) = &self.native {
                if let Some(e) = native.cached::<C>(url, id).await {
                    copies.push((e.body, e.issuer_chain, e.origin, Some(e.checked)));
                }
            }
            copies.push((body.clone(), chain.clone(), Source::Attached, None));
        }
        copies
    }

    #[cfg_attr(target_arch = "wasm32", allow(unused_variables))]
    async fn load<C: Collateral>(
        &self,
        url: String,
        id: &C::Id,
        now: i64,
    ) -> std::result::Result<(Entry, Source), Failure> {
        #[cfg(not(target_arch = "wasm32"))]
        if let Some(native) = &self.native {
            if let Some(cached) = &self.cached {
                let held = native.mem.get(&url).await;
                match (cached.fetched.0.get(&url), held) {
                    (Some(Outcome::Failed(f)), _) => return Err(f.clone()),
                    (Some(Outcome::Stored(from)), Some(entry)) => return Ok((entry, *from)),
                    (_, Some(entry)) if !native.due(&entry, now, false) => {
                        return Ok((entry, Source::Memory))
                    }
                    // Due, but it still passes: served as a failed refresh
                    // would leave it, while the refresh runs on its own.
                    (_, Some(entry))
                        if CollateralUsed::new(
                            String::new(),
                            Source::Memory,
                            entry.dates,
                            C::floor(id, &self.floors),
                            now,
                        )
                        .acceptable() =>
                    {
                        native.refresh_detached::<C>(&url, id, now);
                        return Ok((entry, Source::Memory));
                    }
                    _ => {}
                }
                let (native, id) = (native.clone(), id.clone());
                let fetch = {
                    let url = url.clone();
                    async move {
                        match native.entry::<C>(url, &id, now).await {
                            Ok((_, from)) => Outcome::Stored(from),
                            Err(f) => Outcome::Failed(f),
                        }
                    }
                };
                return Err(Self::defer(cached, url, fetch));
            }
            return native.entry::<C>(url, id, now).await;
        }
        let mut missing = self.missing.lock().unwrap_or_else(|e| e.into_inner());
        if !missing.contains(&url) {
            missing.push(url);
        }
        Err(Failure::Unavailable(Unavailable::offline()))
    }

    /// Where NRAS publishes its key set, from the configured NRAS URL.
    #[cfg(feature = "nvidia-gpu")]
    pub(crate) fn nras_jwks_url(&self) -> Result<String> {
        #[cfg(not(target_arch = "wasm32"))]
        let gpu_url = self.vendor().map(|v| v.nras.gpu_url.as_str());
        #[cfg(target_arch = "wasm32")]
        let gpu_url = None;
        let gpu_url = gpu_url.unwrap_or(crate::platforms::nvidia_gpu::provider::NRAS_GPU_URL);
        crate::platforms::nvidia_gpu::jwks_url_for_endpoint(gpu_url)
            .map_err(|_| AttestationError::InvalidParams(format!("invalid NRAS URL {gpu_url:?}")))
    }

    /// Refetch the piece `id` names (the NRAS key set when a token names an
    /// unknown key), unless it was checked with the vendor in the last few
    /// minutes; replace the copy in memory only with a valid copy that is
    /// not older. `Err` says why the refetch failed (the old copy, if any,
    /// is kept). A piece not in memory is left alone.
    #[cfg_attr(target_arch = "wasm32", allow(unused_variables))]
    pub async fn refresh<C: Collateral>(&self, id: &C::Id, now: i64) -> Result<()> {
        #[cfg(not(target_arch = "wasm32"))]
        if let Some(native) = &self.native {
            let url = C::url(id);
            if let Some(cached) = &self.cached {
                match cached.fetched.0.get(&url) {
                    Some(Outcome::Failed(f)) => return Err(f.clone().into_error(&C::name(id))),
                    Some(_) => return Ok(()),
                    None => {}
                }
                // As the refresh would: nothing within recheck of the last
                // time the vendor was asked.
                match native.mem.get(&url).await {
                    Some(entry) if native.due(&entry, now, true) => {
                        let (native, piece) = (native.clone(), id.clone());
                        let fetch = {
                            let url = url.clone();
                            async move {
                                match native.refresh::<C>(&url, &piece, true, now).await {
                                    (_, _, Some(f)) => Outcome::Failed(f),
                                    (_, _, None) => Outcome::Stored(Source::Memory),
                                }
                            }
                        };
                        return Err(Self::defer(cached, url, fetch).into_error(&C::name(id)));
                    }
                    _ => return Ok(()),
                }
            }
            if native.mem.contains_key(&url) {
                let (_, _, failure) = native.refresh::<C>(&url, id, true, now).await;
                return failure.map_or(Ok(()), |e| Err(e.into_error(&C::name(id))));
            }
            return Ok(());
        }
        Err(Failure::Unavailable(Unavailable::offline()).into_error(&C::name(id)))
    }
}

#[cfg(not(target_arch = "wasm32"))]
impl Store {
    /// Memory, and the vendors unless `offline`.
    pub(crate) fn new(offline: bool) -> Self {
        let vendor = (!offline).then(crate::collateral::vendor::Vendor::new);
        Self {
            native: Some(Arc::new(native::Native::new(vendor))),
            ..Self::held_only()
        }
    }

    /// Only while the context is being built, before any view shares it.
    pub(crate) fn native_mut(&mut self) -> Option<&mut native::Native> {
        self.native.as_mut().and_then(Arc::get_mut)
    }

    #[cfg(feature = "nvidia-gpu")]
    pub(crate) fn vendor(&self) -> Option<&crate::collateral::vendor::Vendor> {
        self.native.as_ref()?.vendor.as_ref()
    }

    /// Whether the piece at vendor `url` is in memory.
    pub fn holds(&self, url: &str) -> bool {
        self.native
            .as_ref()
            .is_some_and(|n| n.mem.contains_key(url))
    }

    /// About how many pieces are held in memory.
    pub fn count(&self) -> u64 {
        self.native.as_ref().map_or(0, |n| n.mem.entry_count())
    }
}

#[cfg(not(target_arch = "wasm32"))]
mod native {
    use std::time::{Duration, Instant};

    use moka::ops::compute::Op;

    use super::*;
    use crate::collateral::disk::Disk;
    use crate::collateral::vendor::Vendor;

    /// How long a failed fetch stands before the upstream is asked again
    /// (never longer than `recheck`).
    const OUTAGE: Duration = Duration::from_secs(10);
    /// Refetch a piece without a nextUpdate (the NRAS key set) this often.
    const MAX_AGE: Duration = Duration::from_secs(3600);
    /// After a 429 or 503 without a Retry-After, leave that vendor host
    /// alone this long (never longer than `recheck`).
    const HOST_PAUSE: Duration = Duration::from_secs(10);
    /// At most this many pieces not held anywhere are fetched from one
    /// vendor host per second.
    pub(crate) const COLD_PER_SECOND: u32 = 10;

    /// One vendor host: until when it asked to be left alone, and the cold
    /// fetches started in the current second.
    #[derive(Default)]
    struct Host {
        paused_until: Option<Instant>,
        second: Option<Instant>,
        cold: u32,
        in_flight: u32,
    }

    /// At most this many requests to one vendor host at once.
    pub(crate) const MAX_IN_FLIGHT: u32 = 16;

    /// A request in flight to `host`, counted until dropped.
    pub(super) struct InFlight<'a> {
        native: &'a Native,
        host: String,
    }

    impl Drop for InFlight<'_> {
        fn drop(&mut self) {
            if let Some(h) = self.native.lock_hosts().get_mut(&self.host) {
                h.in_flight -= 1;
            }
        }
    }

    /// The vendor host of `url`.
    fn host(url: &str) -> &str {
        let rest = url.strip_prefix("https://").unwrap_or(url);
        rest.split(['/', '?']).next().unwrap_or(rest)
    }

    fn wait(seconds: u64, detail: &str) -> Failure {
        Failure::Unavailable(Unavailable {
            status: None,
            retry_after: Some(seconds.max(1)),
            detail: detail.into(),
        })
    }

    pub(crate) struct Native {
        pub(super) mem: moka::future::Cache<String, Entry>,
        /// Pieces the evidence names that the vendor answered "not
        /// published" for, and pieces the upstream failed to send, with the
        /// answer and when.
        failed: moka::future::Cache<String, (Instant, Failure)>,
        pub(crate) disk: Option<Disk>,
        pub(crate) vendor: Option<Vendor>,
        /// Do not ask the vendor about one piece more often than this.
        pub(crate) recheck: Duration,
        hosts: Mutex<HashMap<String, Host>>,
        /// The URLs a [`Self::refresh_detached`] is running for.
        refreshing: Arc<Mutex<std::collections::HashSet<String>>>,
    }

    impl Native {
        pub(crate) fn new(vendor: Option<Vendor>) -> Self {
            Self {
                mem: moka::future::Cache::new(4096),
                failed: moka::future::Cache::new(4096),
                disk: None,
                vendor,
                recheck: Duration::from_secs(300),
                hosts: Mutex::default(),
                refreshing: Arc::default(),
            }
        }

        /// [`Self::refresh`] the piece at `url` on a task of its own, unless
        /// one is running for it.
        pub(super) fn refresh_detached<C: Collateral>(
            self: &Arc<Self>,
            url: &str,
            id: &C::Id,
            now: i64,
        ) {
            /// Removes the URL when the task ends, however it ends.
            struct Running(Arc<Mutex<std::collections::HashSet<String>>>, String);
            impl Drop for Running {
                fn drop(&mut self) {
                    self.0
                        .lock()
                        .unwrap_or_else(|e| e.into_inner())
                        .remove(&self.1);
                }
            }
            if !self
                .refreshing
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .insert(url.to_string())
            {
                return;
            }
            let running = Running(self.refreshing.clone(), url.to_string());
            let (native, id) = (self.clone(), id.clone());
            tokio::spawn(async move {
                native.refresh::<C>(&running.1, &id, false, now).await;
                drop(running);
            });
        }

        /// POST `request` to NRAS, within the limits of its host as for
        /// collateral: [`MAX_IN_FLIGHT`] and a pause after a 429 or 503.
        #[cfg(feature = "nvidia-gpu")]
        pub(crate) async fn nras_attest(
            &self,
            request: &crate::platforms::nvidia_gpu::provider::NrasRequest,
        ) -> Result<Vec<u8>> {
            const NAME: &str = "NRAS attestation";
            let vendor = self
                .vendor
                .as_ref()
                .ok_or_else(|| Unavailable::offline().into_error(NAME))?;
            let url = vendor.nras_url(request.arch);
            self.check_pause(url).map_err(|f| f.into_error(NAME))?;
            let in_flight = self.in_flight(url).map_err(|f| f.into_error(NAME))?;
            let answer = vendor.nras_attest(request).await;
            drop(in_flight);
            match answer {
                Ok(body) => Ok(body),
                Err(Failure::Unavailable(mut e)) => {
                    self.pause_after(url, &mut e);
                    Err(e.into_error(NAME))
                }
                Err(Failure::Refused(why) | Failure::NotPublished(why)) => {
                    Err(AttestationError::NrasRequestFailed(why))
                }
            }
        }

        /// Whether to ask the upstream about `entry` again: never within
        /// `recheck` of the last time; otherwise from its refresh time (or,
        /// for the key set, when old), or always when `force`d.
        pub(super) fn due(&self, entry: &Entry, now: i64, force: bool) -> bool {
            let age = entry.checked_at.elapsed();
            age >= self.recheck
                && (force
                    || match entry.dates.next_update {
                        Some(_) => now >= entry.refresh_at,
                        None => age >= MAX_AGE,
                    })
        }

        pub(super) async fn entry<C: Collateral>(
            &self,
            url: String,
            id: &C::Id,
            now: i64,
        ) -> std::result::Result<(Entry, Source), Failure> {
            match self.mem.get(&url).await {
                Some(entry) if self.due(&entry, now, false) => {
                    let (held, replaced, _) = self.refresh::<C>(&url, id, false, now).await;
                    let held = held.unwrap_or(entry);
                    let source = if replaced {
                        held.origin
                    } else {
                        Source::Memory
                    };
                    Ok((held, source))
                }
                Some(entry) => Ok((entry, Source::Memory)),
                None => self
                    .mem
                    .try_get_with(url.clone(), self.load::<C>(&url, id, now))
                    .await
                    .map(|e| {
                        let origin = e.origin;
                        (e, origin)
                    })
                    .map_err(|e| (*e).clone()),
            }
        }

        /// The copy in memory, else a valid copy on disk; nothing fetched.
        pub(super) async fn cached<C: Collateral>(&self, url: &str, id: &C::Id) -> Option<Entry> {
            if let Some(mut e) = self.mem.get(url).await {
                e.origin = Source::Memory;
                return Some(e);
            }
            let (body, chain) = self.disk.as_ref()?.read(url)?;
            check::<C>(id, body, chain, Source::Disk).ok()
        }

        async fn fetch<C: Collateral>(
            &self,
            url: &str,
            id: &C::Id,
            cold: bool,
        ) -> std::result::Result<Entry, Failure> {
            let in_flight = self.admit(url, cold).await?;
            self.ask::<C>(url, id, in_flight).await
        }

        /// Whether `url` may be asked now: no outage or refusal on record,
        /// its host not paused, under [`MAX_IN_FLIGHT`] and, when `cold`,
        /// [`COLD_PER_SECOND`]. A refusal here asks no one.
        async fn admit(&self, url: &str, cold: bool) -> std::result::Result<InFlight<'_>, Failure> {
            if self.vendor.is_none() {
                return Err(Failure::Unavailable(Unavailable::offline()));
            }
            if let Some((at, failure)) = self.failed.get(url).await {
                let stands = match &failure {
                    Failure::Unavailable(e) => self.recheck.min(
                        e.retry_after
                            .map_or(OUTAGE, |s| Duration::from_secs(s.max(1))),
                    ),
                    _ => self.recheck,
                };
                if at.elapsed() < stands {
                    return Err(failure);
                }
            }
            self.check_pause(url)?;
            let in_flight = self.in_flight(url)?;
            if cold {
                self.admit_cold(url)?;
            }
            Ok(in_flight)
        }

        /// Ask the vendor for `url`, admitted with `in_flight`.
        async fn ask<C: Collateral>(
            &self,
            url: &str,
            id: &C::Id,
            in_flight: InFlight<'_>,
        ) -> std::result::Result<Entry, Failure> {
            let vendor = self
                .vendor
                .as_ref()
                .ok_or_else(|| Failure::Unavailable(Unavailable::offline()))?;
            let (direct, mut fetched) = Box::pin(vendor.fetch(url)).await;
            drop(in_flight);
            if let Err(e) = &mut fetched {
                if direct {
                    self.pause_after(url, e);
                }
            }
            let (body, chain) = match fetched {
                Ok(fetched) => fetched,
                Err(e) if e.not_found() || (C::NAMED_BY_EVIDENCE && e.status == Some(400)) => {
                    // The vendor does not know the chip or platform the
                    // evidence names: for a piece the evidence names, the
                    // evidence is at fault and retrying will not help. Only
                    // the vendor itself can say so, not a cache in between.
                    if !C::NAMED_BY_EVIDENCE || !direct {
                        return Err(Failure::Unavailable(e));
                    }
                    let failure = Failure::NotPublished(format!(
                        "the vendor does not publish it ({})",
                        e.detail
                    ));
                    self.failed
                        .insert(url.to_string(), (Instant::now(), failure.clone()))
                        .await;
                    return Err(failure);
                }
                Err(e) => {
                    // The upstream is down or overloaded: let its clients
                    // wait out an outage rather than each try again.
                    let outage = e.status.is_none_or(|s| s >= 500 || matches!(s, 408 | 429));
                    let failure = Failure::Unavailable(e);
                    if outage {
                        self.failed
                            .insert(url.to_string(), (Instant::now(), failure.clone()))
                            .await;
                    }
                    return Err(failure);
                }
            };
            let from = if direct {
                Source::Vendor
            } else {
                Source::Cache
            };
            check::<C>(id, body, chain, from)
        }

        /// Refuse `url` while its host asked to be left alone.
        fn check_pause(&self, url: &str) -> std::result::Result<(), Failure> {
            if let Some(until) = self
                .lock_hosts()
                .get(host(url))
                .and_then(|h| h.paused_until)
            {
                if let Some(left) = until.checked_duration_since(Instant::now()) {
                    return Err(wait(left.as_secs(), "the vendor asked to wait"));
                }
            }
            Ok(())
        }

        /// After a 429 or 503 from `url`'s host itself, leave the host alone
        /// for its Retry-After (else [`HOST_PAUSE`], at most `recheck`), and
        /// tell the caller.
        fn pause_after(&self, url: &str, e: &mut Unavailable) {
            if matches!(e.status, Some(429 | 503)) {
                let pause = self.recheck.min(
                    e.retry_after
                        .map_or(HOST_PAUSE, |s| Duration::from_secs(s.max(1))),
                );
                self.lock_hosts()
                    .entry(host(url).to_string())
                    .or_default()
                    .paused_until = Some(Instant::now() + pause);
                e.retry_after.get_or_insert(pause.as_secs().max(1));
            }
        }

        fn lock_hosts(&self) -> std::sync::MutexGuard<'_, HashMap<String, Host>> {
            self.hosts.lock().unwrap_or_else(|e| e.into_inner())
        }

        /// Count a request to `url`'s host against [`MAX_IN_FLIGHT`].
        pub(super) fn in_flight(&self, url: &str) -> std::result::Result<InFlight<'_>, Failure> {
            let host = host(url).to_string();
            let mut hosts = self.lock_hosts();
            let h = hosts.entry(host.clone()).or_default();
            if h.in_flight >= MAX_IN_FLIGHT {
                return Err(wait(1, "too many requests to this vendor at once"));
            }
            h.in_flight += 1;
            Ok(InFlight { native: self, host })
        }

        /// Count a fetch of a piece held nowhere against its vendor host's
        /// [`COLD_PER_SECOND`].
        fn admit_cold(&self, url: &str) -> std::result::Result<(), Failure> {
            let mut hosts = self.lock_hosts();
            let h = hosts.entry(host(url).to_string()).or_default();
            if h.second
                .is_none_or(|s| s.elapsed() >= Duration::from_secs(1))
            {
                h.second = Some(Instant::now());
                h.cold = 0;
            }
            if h.cold >= COLD_PER_SECOND {
                return Err(wait(1, "too many new pieces from this vendor at once"));
            }
            h.cold += 1;
            Ok(())
        }

        fn store(&self, url: &str, entry: &Entry) {
            if let Some(disk) = &self.disk {
                disk.write(url, &entry.body, entry.issuer_chain.as_deref());
            }
        }

        /// A miss: the disk copy if it is current, else the vendor's, else
        /// the disk copy anyway.
        async fn load<C: Collateral>(
            &self,
            url: &str,
            id: &C::Id,
            now: i64,
        ) -> std::result::Result<Entry, Failure> {
            let on_disk =
                self.disk.as_ref().and_then(|d| d.read(url)).and_then(
                    |(body, chain)| match check::<C>(id, body, chain, Source::Disk) {
                        Ok(e) => Some(e),
                        Err(_) => {
                            log::warn!(
                                "collateral cache: ignoring {}: it does not verify",
                                C::name(id)
                            );
                            None
                        }
                    },
                );
            // A current disk copy is served as is: a process that only loads
            // (the CLI) would otherwise ask the vendor on every run near
            // nextUpdate. Refresh-ahead applies once it is in memory.
            if let Some(e) = &on_disk {
                if e.dates.current(now) {
                    return Ok(e.clone());
                }
            }
            let fetched = self.fetch::<C>(url, id, on_disk.is_none()).await;
            match (fetched, on_disk) {
                (Ok(new), Some(old)) if !new.dates.not_older_than(&old.dates) => Ok(old),
                (Ok(new), _) => {
                    self.store(url, &new);
                    Ok(new)
                }
                (Err(_), Some(old)) => Ok(old),
                (Err(e), None) => Err(e),
            }
        }

        /// Refetch the piece when [`Self::due`] and replace the held copy
        /// with it when it verifies and is not older. Concurrent refreshes of
        /// one piece run one at a time. Returns the copy now held, whether it
        /// was replaced, and why a fetch failed.
        pub(super) async fn refresh<C: Collateral>(
            &self,
            url: &str,
            id: &C::Id,
            force: bool,
            now: i64,
        ) -> (Option<Entry>, bool, Option<Failure>) {
            let failure = Mutex::new(None);
            let replaced = Mutex::new(false);
            let result = self
                .mem
                .entry(url.to_string())
                .and_compute_with(|current| async {
                    let current = current.map(|e| e.into_value());
                    if current.as_ref().is_some_and(|c| !self.due(c, now, force)) {
                        return Op::Nop;
                    }
                    // Refused here without asking (outage on record, host
                    // paused or busy): the vendor was not asked, so the
                    // copy stays due rather than waiting out `recheck`.
                    let in_flight = match self.admit(url, false).await {
                        Ok(in_flight) => in_flight,
                        Err(e) => {
                            *failure.lock().unwrap() = Some(e);
                            return Op::Nop;
                        }
                    };
                    match self.ask::<C>(url, id, in_flight).await {
                        Ok(new)
                            if current
                                .as_ref()
                                .is_none_or(|c| new.dates.not_older_than(&c.dates)) =>
                        {
                            self.store(url, &new);
                            *replaced.lock().unwrap() = true;
                            Op::Put(new)
                        }
                        fetched => {
                            if let Err(e) = fetched {
                                *failure.lock().unwrap() = Some(e);
                            }
                            match current {
                                Some(mut current) => {
                                    current.checked_at = Instant::now();
                                    Op::Put(current)
                                }
                                None => Op::Nop,
                            }
                        }
                    }
                })
                .await;
            let entry = result.into_entry().map(|e| e.into_value());
            (
                entry,
                replaced.into_inner().unwrap(),
                failure.into_inner().unwrap(),
            )
        }
    }

    #[cfg(test)]
    mod tests {
        use super::*;

        #[test]
        fn requests_to_one_vendor_host_are_bounded() {
            let native = Native::new(None);
            let url = "https://kdsintf.amd.com/vcek/v1/Genoa/crl";
            let held: Vec<_> = (0..MAX_IN_FLIGHT)
                .map(|_| native.in_flight(url).ok().unwrap())
                .collect();
            assert!(native.in_flight(url).is_err());
            assert!(native
                .in_flight("https://api.trustedservices.intel.com/x")
                .is_ok());
            drop(held);
            assert!(native.in_flight(url).is_ok());
        }
    }
}

#[cfg(all(test, feature = "tdx", not(target_arch = "wasm32")))]
mod tests {
    use std::collections::VecDeque;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::Arc;
    use std::time::{Duration, Instant};

    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    use super::*;
    use crate::collateral::{PckCa, PckCrl, QeIdentity, Source, TcbInfo};
    use crate::context::Context;
    use crate::testing::{raw, NOW};

    /// One scripted response: status, extra headers, body.
    type Reply = (u16, Vec<(&'static str, String)>, Vec<u8>);

    /// A vendor on localhost that answers each request with the next scripted
    /// reply (repeating the last), after `delay`, and counts requests.
    struct Vendor {
        base: String,
        hits: Arc<AtomicUsize>,
    }

    async fn vendor(replies: Vec<Reply>, delay: Duration) -> Vendor {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let base = format!("http://{}", listener.local_addr().unwrap());
        let hits = Arc::new(AtomicUsize::new(0));
        let replies = Arc::new(Mutex::new(VecDeque::from(replies)));
        let counter = hits.clone();
        tokio::spawn(async move {
            loop {
                let (mut sock, _) = listener.accept().await.unwrap();
                let replies = replies.clone();
                let counter = counter.clone();
                tokio::spawn(async move {
                    let mut buf = vec![0; 8192];
                    let _ = sock.read(&mut buf).await;
                    counter.fetch_add(1, Ordering::SeqCst);
                    tokio::time::sleep(delay).await;
                    let (status, headers, body) = {
                        let mut q = replies.lock().unwrap();
                        if q.len() > 1 {
                            q.pop_front().unwrap()
                        } else {
                            q.front().cloned().unwrap()
                        }
                    };
                    let mut head = format!(
                        "HTTP/1.1 {status} X\r\nContent-Length: {}\r\nConnection: close\r\n",
                        body.len()
                    );
                    for (k, v) in headers {
                        head.push_str(&format!("{k}: {v}\r\n"));
                    }
                    head.push_str("\r\n");
                    let _ = sock.write_all(head.as_bytes()).await;
                    let _ = sock.write_all(&body).await;
                });
            }
        });
        Vendor { base, hits }
    }

    const CHAIN: &str = "2026-10-14/tcb_signing_chain.pem";

    /// A PCS reply for a TCB Info or QE Identity fixture: body plus its
    /// issuer chain header.
    fn pcs(file: &str) -> Reply {
        let (body, chain) = raw(file, Some(CHAIN));
        let header = chain.unwrap().replace('\n', "%0A").replace(' ', "%20");
        (
            200,
            vec![
                ("TCB-Info-Issuer-Chain", header.clone()),
                ("SGX-Enclave-Identity-Issuer-Chain", header),
            ],
            body,
        )
    }

    fn status(code: u16, headers: Vec<(&'static str, String)>) -> Reply {
        (code, headers, Vec::new())
    }

    const FMSPC: crate::collateral::Fmspc = [0x70, 0xa0, 0x6d, 0x07, 0x00, 0x00];

    /// TCB Info for [`FMSPC`]: its version and source.
    async fn tcb_info(ctx: &Context, now: i64) -> Result<(Option<u64>, Source)> {
        let (_, used) = ctx.store().get::<TcbInfo>(&FMSPC, now).await?;
        Ok((used.version, used.from))
    }

    async fn qe_identity(ctx: &Context) -> Result<(Option<u64>, Source)> {
        let (_, used) = ctx.store().get::<QeIdentity>(&(), NOW).await?;
        Ok((used.version, used.from))
    }

    fn tcb_info_url() -> String {
        TcbInfo::url(&FMSPC)
    }

    /// A store fetching from `v` that may ask it about a piece any time.
    fn ctx(v: &Vendor) -> Context {
        Context::new()
            .with_test_vendor(&v.base)
            .with_recheck(Duration::ZERO)
    }

    #[test]
    fn refresh_is_random_in_the_last_quarter_and_a_day_before_next_update() {
        let day = 24 * 3600;
        let dates = Dates::window(0, 40 * day, None);
        let times: Vec<i64> = (0..50).map(|_| refresh_at(&dates)).collect();
        assert!(times.iter().all(|t| (30 * day..39 * day).contains(t)));
        assert!(times.iter().any(|t| *t != times[0]));
        // Too short a window for both rules: a day before nextUpdate wins.
        assert_eq!(refresh_at(&Dates::window(0, 2 * day, None)), day);
        assert_eq!(refresh_at(&Dates::default()), i64::MAX);
    }

    #[tokio::test]
    async fn a_vendor_that_says_wait_is_left_alone_for_every_piece() {
        let v = vendor(vec![status(429, vec![])], Duration::ZERO).await;
        let ctx = Context::new().with_test_vendor(&v.base);
        for i in 0..20u8 {
            let err = ctx
                .store()
                .get::<TcbInfo>(&[0, 0, 0, 0, 0, i], NOW)
                .await
                .err()
                .unwrap();
            assert!(err.is_retryable(), "{err}");
        }
        // The first piece: one try and its retry.
        assert_eq!(v.hits.load(Ordering::SeqCst), 2);
    }

    #[tokio::test]
    async fn cached_refusals_keep_their_classification_and_do_not_spend_cold_budget() {
        let v = vendor(vec![status(404, vec![])], Duration::ZERO).await;
        let ctx = Context::new().with_test_vendor(&v.base);
        for _ in 0..30 {
            let err = ctx
                .store()
                .get::<TcbInfo>(&[0; 6], NOW)
                .await
                .err()
                .unwrap();
            assert!(!err.is_retryable());
        }
        assert_eq!(v.hits.load(Ordering::SeqCst), 1);
        let err = ctx
            .store()
            .get::<TcbInfo>(&[1; 6], NOW)
            .await
            .err()
            .unwrap();
        assert!(!err.is_retryable());
        assert_eq!(v.hits.load(Ordering::SeqCst), 2);
    }

    #[tokio::test]
    async fn zero_retry_after_still_holds_an_outage() {
        let v = vendor(
            vec![status(503, vec![("Retry-After", "0".into())])],
            Duration::ZERO,
        )
        .await;
        let ctx = Context::new().with_upstream(&v.base).unwrap();
        assert!(tcb_info(&ctx, NOW).await.is_err());
        let hits = v.hits.load(Ordering::SeqCst);
        assert!(hits > 0);
        for _ in 0..20 {
            assert!(tcb_info(&ctx, NOW).await.is_err());
        }
        assert_eq!(v.hits.load(Ordering::SeqCst), hits);
    }

    #[tokio::test]
    async fn an_upstream_cache_outage_does_not_pause_other_pieces() {
        let v = vendor(
            vec![
                status(503, vec![]),
                status(503, vec![]),
                pcs("2026-10-14/tcb_info_70a06d070000.json"),
            ],
            Duration::ZERO,
        )
        .await;
        let ctx = Context::new().with_upstream(&v.base).unwrap();
        assert!(ctx
            .store()
            .get::<TcbInfo>(&[0; 6], NOW)
            .await
            .err()
            .unwrap()
            .is_retryable());
        assert!(tcb_info(&ctx, NOW).await.is_ok());
        assert_eq!(v.hits.load(Ordering::SeqCst), 3);
    }

    #[tokio::test]
    async fn new_pieces_are_fetched_from_one_vendor_host_at_a_bounded_rate() {
        let v = vendor(vec![status(404, vec![])], Duration::ZERO).await;
        let ctx = ctx(&v);
        let gets = (0..30u8).map(|i| {
            let ctx = &ctx;
            async move { ctx.store().get::<TcbInfo>(&[0, 0, 0, 0, 1, i], NOW).await }
        });
        let refused = futures_util::future::join_all(gets)
            .await
            .into_iter()
            .filter(|r| r.as_ref().is_err_and(|e| !e.is_retryable()))
            .count();
        let limit = native::COLD_PER_SECOND as usize;
        assert_eq!((refused, v.hits.load(Ordering::SeqCst)), (limit, limit));
    }

    #[tokio::test]
    async fn concurrent_misses_fetch_once_then_memory_serves() {
        let v = vendor(
            vec![pcs("2026-10-14/tcb_info_70a06d070000.json")],
            Duration::from_millis(200),
        )
        .await;
        let ctx = ctx(&v);
        let gets = (0..20).map(|_| tcb_info(&ctx, NOW));
        for doc in futures_util::future::join_all(gets).await {
            assert_eq!(doc.unwrap().0, Some(20));
        }
        assert_eq!(v.hits.load(Ordering::SeqCst), 1);
        assert_eq!(tcb_info(&ctx, NOW).await.unwrap().1, Source::Memory);
        assert_eq!(v.hits.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn a_piece_past_next_update_is_refetched_and_a_failed_refetch_keeps_it() {
        let v = vendor(
            vec![
                pcs("2026-10-14/td_qe_identity_2026-03-16_eval18_expired.json"),
                status(503, vec![]),
                status(503, vec![]),
                pcs("2026-10-14/td_qe_identity.json"),
            ],
            Duration::ZERO,
        )
        .await;
        let ctx = ctx(&v);
        let old = qe_identity(&ctx).await.unwrap();
        assert_eq!(old.0, Some(18));
        // Past nextUpdate: refetched, the vendor fails (two tries), the
        // old copy is served.
        let kept = qe_identity(&ctx).await.unwrap();
        assert_eq!((kept.0, kept.1), (Some(18), Source::Memory));
        assert_eq!(v.hits.load(Ordering::SeqCst), 3);
        // Still due: refetched again, and replaced.
        let new = qe_identity(&ctx).await.unwrap();
        assert_eq!((new.0, new.1), (Some(20), Source::Vendor));
        // Memory now serves the new piece, not the one verified before.
        let held = qe_identity(&ctx).await.unwrap();
        assert_eq!((held.0, held.1), (Some(20), Source::Memory));
    }

    #[tokio::test]
    async fn a_cached_view_puts_off_vendor_requests_until_fetched() {
        let v = vendor(vec![pcs("2026-10-14/td_qe_identity.json")], Duration::ZERO).await;
        let ctx = ctx(&v);
        let floors = VersionFloors::default();
        let fetched = Fetched::default();
        let view = ctx.store().view_cached(vec![], &floors, &fetched);
        assert!(view
            .get::<QeIdentity>(&(), NOW)
            .await
            .unwrap_err()
            .is_retryable());
        let deferred = view.take_deferred();
        assert_eq!(deferred.len(), 1);
        assert_eq!(v.hits.load(Ordering::SeqCst), 0);
        let mut outcomes = HashMap::new();
        for (url, fetch) in deferred {
            outcomes.insert(url, fetch.await);
        }
        assert_eq!(v.hits.load(Ordering::SeqCst), 1);
        let fetched = Fetched(Arc::new(outcomes));
        let view = ctx.store().view_cached(vec![], &floors, &fetched);
        let (_, used) = view.get::<QeIdentity>(&(), NOW).await.unwrap();
        assert_eq!((used.version, used.from), (Some(20), Source::Vendor));
        assert!(view.take_deferred().is_empty());
        // Another verification finds it in memory.
        let view = ctx
            .store()
            .view_cached(vec![], &floors, &Fetched::default());
        let (_, used) = view.get::<QeIdentity>(&(), NOW).await.unwrap();
        assert_eq!(used.from, Source::Memory);
    }

    /// A failed fetch is answered as a lookup that asked: a 404 for a piece
    /// the evidence does not name stays "not found", and a retry of the
    /// verification does not ask again.
    #[tokio::test]
    async fn a_cached_view_answers_a_failed_fetch_as_the_lookup_would() {
        let v = vendor(vec![status(404, vec![])], Duration::ZERO).await;
        let ctx = ctx(&v);
        let floors = VersionFloors::default();
        let view = ctx
            .store()
            .view_cached(vec![], &floors, &Fetched::default());
        assert!(view.lookup::<QeIdentity>(&(), NOW).await.is_err());
        let mut outcomes = HashMap::new();
        for (url, fetch) in view.take_deferred() {
            outcomes.insert(url, fetch.await);
        }
        let view = ctx
            .store()
            .view_cached(vec![], &floors, &Fetched(Arc::new(outcomes)));
        match view.lookup::<QeIdentity>(&(), NOW).await {
            Err(Failure::Unavailable(e)) => assert!(e.not_found()),
            _ => panic!("a 404"),
        }
        assert!(view.take_deferred().is_empty());
        assert_eq!(v.hits.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn an_older_copy_never_replaces_a_newer_one() {
        let v = vendor(
            vec![
                pcs("2026-10-14/tcb_info_70a06d070000_early.json"),
                pcs("2026-10-14/tcb_info_70a06d070000_eval21.json"),
            ],
            Duration::ZERO,
        )
        .await;
        let ctx = ctx(&v);
        assert_eq!(tcb_info(&ctx, NOW).await.unwrap().0, Some(22));
        ctx.store().refresh::<TcbInfo>(&FMSPC, NOW).await.unwrap();
        assert_eq!(v.hits.load(Ordering::SeqCst), 2);
        assert_eq!(tcb_info(&ctx, NOW).await.unwrap().0, Some(22));
    }

    #[tokio::test]
    async fn a_bad_signature_is_refused_and_does_not_replace_a_good_copy() {
        let mut bad = pcs("2026-10-14/tcb_info_70a06d070000.json");
        bad.2 = String::from_utf8(bad.2)
            .unwrap()
            .replacen("\"UpToDate\"", "\"OutOfDate\"", 1)
            .into_bytes();
        let v = vendor(vec![bad.clone()], Duration::ZERO).await;
        let err = tcb_info(&ctx(&v), NOW).await.err().unwrap();
        assert!(matches!(err, AttestationError::CertChainError(_)), "{err}");
        assert!(!err.is_retryable());

        let v = vendor(
            vec![pcs("2026-10-14/tcb_info_70a06d070000.json"), bad],
            Duration::ZERO,
        )
        .await;
        let ctx = ctx(&v);
        tcb_info(&ctx, NOW).await.unwrap();
        assert!(ctx.store().refresh::<TcbInfo>(&FMSPC, NOW).await.is_err());
        assert_eq!(tcb_info(&ctx, NOW).await.unwrap().0, Some(20));
    }

    #[tokio::test]
    async fn not_found_is_not_retried_and_5xx_is() {
        for (code, hits) in [(404, 1), (410, 1), (503, 2), (500, 2), (408, 2), (403, 1)] {
            let v = vendor(vec![status(code, vec![])], Duration::ZERO).await;
            let err = qe_identity(&ctx(&v)).await.err().unwrap();
            assert!(err.is_retryable(), "{code}: {err}");
            assert_eq!(v.hits.load(Ordering::SeqCst), hits, "{code}");
        }
    }

    #[tokio::test]
    async fn a_piece_the_evidence_names_and_the_vendor_does_not_know_is_refused() {
        for code in [404, 410] {
            let v = vendor(vec![status(code, vec![])], Duration::ZERO).await;
            let err = tcb_info(&ctx(&v), NOW).await.err().unwrap();
            assert!(matches!(err, AttestationError::CertChainError(_)), "{err}");
        }
        #[cfg(feature = "snp")]
        for code in [400, 404] {
            let v = vendor(vec![status(code, vec![])], Duration::ZERO).await;
            let err = vcek(&ctx(&v)).await.err().unwrap();
            assert!(matches!(err, AttestationError::CertChainError(_)), "{err}");
            assert_eq!(v.hits.load(Ordering::SeqCst), 1);
        }
    }

    #[tokio::test]
    async fn a_not_found_from_a_cache_is_retryable_and_cache_answers_say_cache() {
        for code in [400, 404, 410] {
            let v = vendor(vec![status(code, vec![])], Duration::ZERO).await;
            let cache = Context::new().with_upstream(&v.base).unwrap();
            let err = tcb_info(&cache, NOW).await.err().unwrap();
            assert!(err.is_retryable(), "{code}: {err}");
        }
        let v = vendor(
            vec![pcs("2026-10-14/tcb_info_70a06d070000.json")],
            Duration::ZERO,
        )
        .await;
        let cache = Context::new().with_upstream(&v.base).unwrap();
        assert_eq!(tcb_info(&cache, NOW).await.unwrap().1, Source::Cache);
    }

    #[tokio::test]
    async fn a_piece_the_evidence_does_not_name_is_asked_for_again_after_a_404() {
        let v = vendor(vec![status(404, vec![])], Duration::ZERO).await;
        let ctx = ctx(&v).with_recheck(Duration::from_secs(300));
        for _ in 0..2 {
            assert!(qe_identity(&ctx).await.err().unwrap().is_retryable());
        }
        assert_eq!(v.hits.load(Ordering::SeqCst), 2);
    }

    #[cfg(feature = "snp")]
    #[tokio::test]
    async fn the_vendor_is_asked_about_an_unpublished_piece_once_per_recheck() {
        let v = vendor(vec![status(404, vec![])], Duration::ZERO).await;
        let ctx = Context::new()
            .with_test_vendor(&v.base)
            .with_recheck(Duration::from_secs(300));
        for _ in 0..2 {
            let err = vcek(&ctx).await.err().unwrap();
            assert!(matches!(err, AttestationError::CertChainError(_)), "{err}");
        }
        assert_eq!(v.hits.load(Ordering::SeqCst), 1);
        let ctx = ctx.with_recheck(Duration::ZERO);
        vcek(&ctx).await.err().unwrap();
        assert_eq!(v.hits.load(Ordering::SeqCst), 2);
    }

    #[tokio::test]
    async fn a_short_retry_after_is_waited_out_and_a_long_one_returned() {
        let v = vendor(
            vec![
                status(429, vec![("Retry-After", "1".into())]),
                pcs("2026-10-14/tcb_info_70a06d070000.json"),
            ],
            Duration::ZERO,
        )
        .await;
        let start = Instant::now();
        tcb_info(&ctx(&v), NOW).await.unwrap();
        assert!(start.elapsed() >= Duration::from_secs(1));

        let v = vendor(
            vec![status(429, vec![("Retry-After", "120".into())])],
            Duration::ZERO,
        )
        .await;
        let err = tcb_info(&ctx(&v), NOW).await.err().unwrap();
        assert_eq!(err.retry_after(), Some(120));
        assert_eq!(v.hits.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn a_hung_vendor_is_unavailable_after_two_tries_in_about_ten_seconds() {
        let v = vendor(
            vec![pcs("2026-10-14/tcb_info_70a06d070000.json")],
            Duration::from_secs(60),
        )
        .await;
        let start = Instant::now();
        let err = tcb_info(&ctx(&v), NOW).await.err().unwrap();
        let took = start.elapsed();
        assert!(err.is_retryable(), "{err}");
        assert_eq!(v.hits.load(Ordering::SeqCst), 2);
        assert!(
            took >= Duration::from_secs(10) && took < Duration::from_secs(12),
            "{took:?}"
        );
    }

    #[tokio::test]
    async fn attaching_keeps_partial_collateral_after_the_vendor_retry() {
        use base64::{engine::general_purpose::STANDARD, Engine};
        let quote = std::fs::read(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/test_data/tdx_quote_00a06d080000.dat"
        ))
        .unwrap();
        let evidence = serde_json::to_vec(&serde_json::json!({
            "platform": "tdx",
            "evidence": { "quote": STANDARD.encode(quote) },
        }))
        .unwrap();
        let qe = QeIdentity::url(&());
        let held: Vec<_> = crate::testing::intel()
            .into_iter()
            .filter(|(url, ..)| *url != qe)
            .collect();
        let attach = |v: &Vendor| {
            let attester = crate::Verifier::new(ctx(v).with_held(held.clone()).at(NOW).unwrap());
            let evidence = evidence.clone();
            async move {
                let with = attester.attach_collateral(&evidence, &[]).await.unwrap();
                serde_json::from_slice::<crate::AttestationEvidence>(&with)
                    .unwrap()
                    .collateral
                    .into_iter()
                    .map(|c| c.url)
                    .collect::<Vec<_>>()
            }
        };
        let busy = || status(429, vec![("Retry-After", "1".into())]);

        let v = vendor(
            vec![busy(), pcs("2026-10-14/td_qe_identity.json")],
            Duration::ZERO,
        )
        .await;
        assert!(attach(&v).await.contains(&qe));
        assert_eq!(v.hits.load(Ordering::SeqCst), 2);

        let v = vendor(vec![busy()], Duration::ZERO).await;
        let urls = attach(&v).await;
        assert!(!urls.is_empty() && !urls.contains(&qe), "{urls:?}");
        assert_eq!(v.hits.load(Ordering::SeqCst), 2);
    }

    #[tokio::test]
    async fn a_short_retry_after_is_honoured_once_then_returned() {
        let v = vendor(
            vec![status(429, vec![("Retry-After", "1".into())])],
            Duration::ZERO,
        )
        .await;
        let err = tcb_info(&ctx(&v), NOW).await.err().unwrap();
        assert_eq!(err.retry_after(), Some(1));
        assert_eq!(v.hits.load(Ordering::SeqCst), 2);
    }

    /// The single file the store keeps `dir`'s one piece in.
    fn only_file(dir: &std::path::Path) -> std::path::PathBuf {
        let files: Vec<_> = std::fs::read_dir(dir)
            .unwrap()
            .map(|e| e.unwrap().path())
            .collect();
        assert_eq!(files.len(), 1, "one file per piece, no temporary files");
        files[0].clone()
    }

    fn offline(dir: &std::path::Path) -> Context {
        Context::offline().with_cache_dir(dir)
    }

    #[tokio::test]
    async fn the_disk_copy_survives_a_restart_and_a_corrupt_one_is_refetched() {
        let dir = tempfile::tempdir().unwrap();
        let v = vendor(
            vec![pcs("2026-10-14/tcb_info_70a06d070000.json")],
            Duration::ZERO,
        )
        .await;
        let online = || ctx(&v).with_cache_dir(dir.path());
        tcb_info(&online(), NOW).await.unwrap();
        let doc = tcb_info(&offline(dir.path()), NOW).await.unwrap();
        assert_eq!((doc.0, doc.1), (Some(20), Source::Disk));

        let file = only_file(dir.path());
        let good = std::fs::read(&file).unwrap();
        for corrupt in [
            good[..good.len() / 2].to_vec(),
            String::from_utf8(good.clone())
                .unwrap()
                .replacen("\"body\":\"", "\"body\":\"AAAA", 1)
                .into_bytes(),
            vec![b' '; 9 << 20],
        ] {
            std::fs::write(&file, corrupt).unwrap();
            let err = tcb_info(&offline(dir.path()), NOW).await.err().unwrap();
            assert!(err.is_retryable(), "{err}");
        }
        let doc = tcb_info(&online(), NOW).await.unwrap();
        assert_eq!(doc.1, Source::Vendor);
        assert_eq!(v.hits.load(Ordering::SeqCst), 2);
        assert_eq!(std::fs::read(only_file(dir.path())).unwrap(), good);
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn the_cache_dir_is_private() {
        use std::os::unix::fs::PermissionsExt;
        let parent = tempfile::tempdir().unwrap();
        let dir = parent.path().join("attestation");
        let v = vendor(
            vec![pcs("2026-10-14/tcb_info_70a06d070000.json")],
            Duration::ZERO,
        )
        .await;
        tcb_info(&ctx(&v).with_cache_dir(&dir), NOW).await.unwrap();
        let mode = |p: &std::path::Path| std::fs::metadata(p).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode(&dir), 0o700);
        assert_eq!(mode(&only_file(&dir)), 0o600);

        let open = parent.path().join("existing");
        std::fs::create_dir(&open).unwrap();
        std::fs::set_permissions(&open, std::fs::Permissions::from_mode(0o755)).unwrap();
        tcb_info(&ctx(&v).with_cache_dir(&open), NOW).await.unwrap();
        assert_eq!(mode(&open), 0o755);
        assert_eq!(mode(&only_file(&open)), 0o600);
    }

    #[tokio::test]
    async fn a_current_disk_copy_is_served_without_asking_the_vendor() {
        let dir = tempfile::tempdir().unwrap();
        let (body, chain) = raw("2026-10-14/tcb_info_70a06d070000.json", Some(CHAIN));
        crate::collateral::save_to_cache_dir(dir.path(), &tcb_info_url(), &body, chain.as_deref());
        let v = vendor(vec![status(503, vec![])], Duration::ZERO).await;
        let doc = tcb_info(&ctx(&v).with_cache_dir(dir.path()), NOW)
            .await
            .unwrap();
        assert_eq!(doc.1, Source::Disk);
        assert_eq!(v.hits.load(Ordering::SeqCst), 0);
    }

    #[tokio::test]
    async fn a_stale_disk_copy_is_served_when_the_vendor_fails() {
        let dir = tempfile::tempdir().unwrap();
        let expired = "2026-10-14/td_qe_identity_2026-03-16_eval18_expired.json";
        let (body, chain) = raw(expired, Some(CHAIN));
        let url = QeIdentity::url(&());
        crate::collateral::save_to_cache_dir(dir.path(), &url, &body, chain.as_deref());
        let v = vendor(vec![status(503, vec![])], Duration::ZERO).await;
        let doc = qe_identity(&ctx(&v).with_cache_dir(dir.path()))
            .await
            .unwrap();
        assert_eq!((doc.0, doc.1), (Some(18), Source::Disk));
        assert_eq!(v.hits.load(Ordering::SeqCst), 2);
    }

    #[tokio::test]
    async fn callers_of_a_piece_due_for_refresh_wait_for_one_fetch() {
        let v = vendor(
            vec![pcs("2026-10-14/tcb_info_70a06d070000.json")],
            Duration::from_millis(200),
        )
        .await;
        let ctx = Context::new()
            .with_test_vendor(&v.base)
            .with_recheck(Duration::from_secs(2));
        tcb_info(&ctx, NOW).await.unwrap();
        tokio::time::sleep(Duration::from_millis(2100)).await;
        // A day before nextUpdate: due for refresh.
        let (info, _) = ctx.store().get::<TcbInfo>(&FMSPC, NOW).await.unwrap();
        let ending = info.next_update - 3600;
        let gets = (0..20).map(|_| tcb_info(&ctx, ending));
        for doc in futures_util::future::join_all(gets).await {
            doc.unwrap();
        }
        assert_eq!(v.hits.load(Ordering::SeqCst), 2);
    }

    #[tokio::test]
    async fn a_forced_refresh_respects_the_recheck_interval() {
        let v = vendor(
            vec![pcs("2026-10-14/tcb_info_70a06d070000.json")],
            Duration::ZERO,
        )
        .await;
        let ctx = Context::new()
            .with_test_vendor(&v.base)
            .with_recheck(Duration::from_secs(300));
        tcb_info(&ctx, NOW).await.unwrap();
        for _ in 0..5 {
            ctx.store().refresh::<TcbInfo>(&FMSPC, NOW).await.unwrap();
        }
        assert_eq!(v.hits.load(Ordering::SeqCst), 1);
    }

    #[cfg(feature = "nvidia-gpu")]
    #[tokio::test]
    async fn a_token_under_a_key_not_yet_published_is_retryable() {
        use crate::types::{
            NvidiaGpuArch, NvidiaGpuDeviceEvidence, NvidiaGpuEvidenceBundle, NvidiaGpuParams,
        };
        use base64::Engine;
        let header = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(r#"{"kid":"next"}"#);
        let eat = serde_json::json!([["JWT", format!("{header}.e30.sig")], {}]);
        let (jwks, _) = raw("2026-10-14/nras_jwks.json", None);
        let v = vendor(
            vec![
                (200, vec![], eat.to_string().into_bytes()),
                (200, vec![], jwks),
            ],
            Duration::ZERO,
        )
        .await;
        let nras = format!("{}/v3/attest/gpu", v.base);
        let ctx = Context::new()
            .with_nras_urls(nras.clone(), nras)
            .unwrap()
            .with_recheck(Duration::from_secs(300));
        let bundle = NvidiaGpuEvidenceBundle {
            devices: vec![NvidiaGpuDeviceEvidence {
                arch: NvidiaGpuArch::Hopper,
                uuid: "GPU-0".into(),
                evidence_b64: String::new(),
                cert_chain_b64: String::new(),
            }],
            binding: Default::default(),
        };
        let params = NvidiaGpuParams {
            user_nonce: Some(vec![7; 32]),
            ..Default::default()
        };
        let err = crate::platforms::nvidia_gpu::gather_bundle(&bundle, &params, ctx.store(), NOW)
            .await
            .err()
            .unwrap();
        assert!(err.is_retryable(), "{err}");
    }

    #[cfg(feature = "snp")]
    async fn vcek(ctx: &Context) -> Result<(crate::collateral::Vcek, CollateralUsed)> {
        let chip_id: [u8; 64] = hex::decode(
            "b5f9a4c8280e63c97d288db6648577dc2b848884aa682d7a227ba40e50deb2b0\
             d112b599d87aaccda78d06f4254b1e81c4d953ef3c699db39d4e06013e9fa4ce",
        )
        .unwrap()
        .try_into()
        .unwrap();
        let tcb = crate::types::SnpTcb {
            bootloader: 10,
            tee: 0,
            snp: 27,
            microcode: 28,
            fmc: None,
        };
        let genoa = crate::types::ProcessorGeneration::Genoa;
        ctx.store().get(&(genoa, chip_id, tcb), NOW).await
    }

    #[tokio::test]
    async fn an_attached_piece_that_does_not_pass_is_replaced_by_a_fetched_one() {
        let expired = raw(
            "2026-10-14/td_qe_identity_2026-03-16_eval18_expired.json",
            Some(CHAIN),
        );
        let attached = || vec![(QeIdentity::url(&()), expired.0.clone(), expired.1.clone())];
        let floors = VersionFloors::default();

        let v = vendor(vec![pcs("2026-10-14/td_qe_identity.json")], Duration::ZERO).await;
        let view = ctx(&v).store().view(attached(), &floors, false);
        let (_, used) = view.get::<QeIdentity>(&(), NOW).await.unwrap();
        assert_eq!((used.version, used.from), (Some(20), Source::Vendor));
        assert!(used.acceptable());

        let v = vendor(vec![status(503, vec![])], Duration::ZERO).await;
        let view = ctx(&v).store().view(attached(), &floors, false);
        let (_, used) = view.get::<QeIdentity>(&(), NOW).await.unwrap();
        assert_eq!((used.version, used.from), (Some(18), Source::Attached));
        assert!(!used.acceptable());
    }

    #[tokio::test]
    async fn offline_without_a_copy_is_retryable_unavailable() {
        let err = Context::offline()
            .store()
            .get::<PckCrl>(&PckCa::Platform, NOW)
            .await
            .err()
            .unwrap();
        assert!(err.is_retryable(), "{err}");
        assert_eq!(err.retry_after(), None);
    }

    #[tokio::test]
    async fn only_a_held_only_store_records_what_it_was_missing() {
        let held = Context::held([]);
        for _ in 0..3 {
            let _ = tcb_info(&held, NOW).await;
        }
        assert_eq!(held.store().missing(), vec![tcb_info_url()]);
        let native = Context::offline();
        let _ = tcb_info(&native, NOW).await;
        assert!(native.store().missing().is_empty());
    }

    /// Verifications of [`Counted`] so far.
    static COUNTED: AtomicUsize = AtomicUsize::new(0);

    /// A piece that counts its verifications. Its URL names only the first
    /// half of its id, as a Turin VCEK's URL names only part of CHIP_ID.
    #[derive(Clone)]
    struct Counted;

    impl Collateral for Counted {
        type Id = (u8, u8);
        fn name(_: &(u8, u8)) -> String {
            "counted".into()
        }
        fn url(id: &(u8, u8)) -> String {
            format!("https://counted.example/{}", id.0)
        }
        fn verify(body: &[u8], _: Option<&str>, id: &(u8, u8)) -> Result<Self> {
            COUNTED.fetch_add(1, Ordering::SeqCst);
            if body != [id.0, id.1] {
                return Err(AttestationError::CertChainError("not this piece".into()));
            }
            Ok(Counted)
        }
        fn dates(&self) -> Dates {
            Dates::default()
        }
    }

    #[tokio::test]
    async fn a_piece_in_memory_is_verified_once_and_only_for_its_own_id() {
        let v = vendor(vec![(200, vec![], vec![1, 2])], Duration::ZERO).await;
        let ctx = Context::new().with_test_vendor(&v.base);
        let mut from = Vec::new();
        for _ in 0..3 {
            let (_, used) = ctx.store().get::<Counted>(&(1, 2), NOW).await.unwrap();
            from.push(used.from);
        }
        assert_eq!(from, [Source::Vendor, Source::Memory, Source::Memory]);
        assert_eq!(v.hits.load(Ordering::SeqCst), 1);
        assert_eq!(COUNTED.load(Ordering::SeqCst), 1);
        // Another id at the same URL: the copy is verified for it, and refused.
        let err = ctx
            .store()
            .get::<Counted>(&(1, 3), NOW)
            .await
            .err()
            .unwrap();
        assert!(err.to_string().contains("not this piece"), "{err}");
        assert_eq!(COUNTED.load(Ordering::SeqCst), 2);
    }

    /// A vendor that answers the first request with `reply` and leaves every
    /// later one hanging.
    async fn answers_once(reply: Reply) -> Vendor {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let base = format!("http://{}", listener.local_addr().unwrap());
        let hits = Arc::new(AtomicUsize::new(0));
        let counter = hits.clone();
        tokio::spawn(async move {
            loop {
                let (mut sock, _) = listener.accept().await.unwrap();
                let (counter, (status, headers, body)) = (counter.clone(), reply.clone());
                tokio::spawn(async move {
                    let mut buf = vec![0; 8192];
                    let _ = sock.read(&mut buf).await;
                    if counter.fetch_add(1, Ordering::SeqCst) > 0 {
                        return std::future::pending::<()>().await;
                    }
                    let mut head = format!(
                        "HTTP/1.1 {status} X\r\nContent-Length: {}\r\nConnection: close\r\n",
                        body.len()
                    );
                    for (k, v) in headers {
                        head.push_str(&format!("{k}: {v}\r\n"));
                    }
                    head.push_str("\r\n");
                    let _ = sock.write_all(head.as_bytes()).await;
                    let _ = sock.write_all(&body).await;
                });
            }
        });
        Vendor { base, hits }
    }

    /// A piece due for refresh that still passes is served from memory by a
    /// cached view at once, while one refresh asks a hung vendor on a task of
    /// its own: the verification puts nothing off and waits for nothing.
    #[tokio::test]
    async fn a_cached_view_serves_a_due_piece_while_its_vendor_hangs() {
        let v = answers_once(pcs("2026-10-14/tcb_info_70a06d070000.json")).await;
        let ctx = ctx(&v);
        let (info, _) = ctx.store().get::<TcbInfo>(&FMSPC, NOW).await.unwrap();
        let ending = info.next_update - 3600;
        let floors = VersionFloors::default();
        for _ in 0..3 {
            let view = ctx
                .store()
                .view_cached(vec![], &floors, &Fetched::default());
            let started = Instant::now();
            let (_, used) = view.get::<TcbInfo>(&FMSPC, ending).await.unwrap();
            assert_eq!(used.from, Source::Memory);
            assert!(started.elapsed() < Duration::from_secs(1));
            assert!(view.take_deferred().is_empty());
        }
        tokio::time::sleep(Duration::from_millis(200)).await;
        assert_eq!(v.hits.load(Ordering::SeqCst), 2);
    }

    /// A piece due that no longer passes is not served: the view puts its
    /// fetch off, as before.
    #[tokio::test]
    async fn a_cached_view_puts_off_a_due_piece_that_no_longer_passes() {
        let v = vendor(
            vec![pcs(
                "2026-10-14/td_qe_identity_2026-03-16_eval18_expired.json",
            )],
            Duration::ZERO,
        )
        .await;
        let ctx = ctx(&v);
        assert_eq!(qe_identity(&ctx).await.unwrap().0, Some(18));
        let view = ctx
            .store()
            .view_cached(vec![], &VersionFloors::default(), &Fetched::default());
        assert!(view.get::<QeIdentity>(&(), NOW).await.is_err());
        assert_eq!(view.take_deferred().len(), 1);
    }

    /// A put-off fetch its caller stopped waiting for still runs to the end:
    /// the piece is in memory for the next verification.
    #[tokio::test]
    async fn a_fetch_its_caller_stopped_waiting_for_still_fills_memory() {
        let v = vendor(
            vec![pcs("2026-10-14/td_qe_identity.json")],
            Duration::from_millis(300),
        )
        .await;
        let ctx = ctx(&v);
        let view = ctx
            .store()
            .view_cached(vec![], &VersionFloors::default(), &Fetched::default());
        assert!(view.get::<QeIdentity>(&(), NOW).await.is_err());
        let fetch = crate::Fetch(view.take_deferred());
        let mut fetched = Fetched::default();
        let cut = tokio::time::timeout(Duration::from_millis(50), fetch.run(&mut fetched)).await;
        assert!(cut.is_err());
        tokio::time::sleep(Duration::from_millis(600)).await;
        assert!(ctx.store().holds(&QeIdentity::url(&())));
    }

    /// A refresh refused here, without asking the vendor (as many requests
    /// to its host as allowed are in flight), leaves the piece due: the next
    /// lookup asks, rather than one `recheck` later.
    #[tokio::test]
    async fn a_refresh_refused_here_does_not_put_off_the_next() {
        let v = vendor(
            vec![pcs("2026-10-14/tcb_info_70a06d070000.json")],
            Duration::ZERO,
        )
        .await;
        let ctx = Context::new()
            .with_test_vendor(&v.base)
            .with_recheck(Duration::from_secs(1));
        let (info, _) = ctx.store().get::<TcbInfo>(&FMSPC, NOW).await.unwrap();
        let ending = info.next_update - 3600;
        tokio::time::sleep(Duration::from_millis(1100)).await;
        let native = ctx.store().native.clone().unwrap();
        let url = tcb_info_url();
        let busy: Vec<_> = (0..native::MAX_IN_FLIGHT)
            .map(|_| native.in_flight(&url).ok().unwrap())
            .collect();
        assert_eq!(tcb_info(&ctx, ending).await.unwrap().1, Source::Memory);
        assert_eq!(v.hits.load(Ordering::SeqCst), 1);
        drop(busy);
        tcb_info(&ctx, ending).await.unwrap();
        assert_eq!(v.hits.load(Ordering::SeqCst), 2);
    }

    /// NRAS POSTs count against their host's requests in flight, and a 429
    /// leaves the host alone for a while.
    #[cfg(feature = "nvidia-gpu")]
    #[tokio::test]
    async fn nras_requests_keep_to_the_host_limits() {
        use crate::platforms::nvidia_gpu::provider::NrasRequest;
        let v = vendor(vec![status(429, vec![])], Duration::ZERO).await;
        let nras = format!("{}/v3/attest/gpu", v.base);
        let ctx = Context::new()
            .with_nras_urls(nras.clone(), nras.clone())
            .unwrap();
        let native = ctx.store().native.clone().unwrap();
        let request = NrasRequest {
            nonce: String::new(),
            evidence_list: vec![],
            arch: crate::types::NvidiaGpuArch::Hopper,
            claims_version: "2.0".into(),
        };
        let busy: Vec<_> = (0..native::MAX_IN_FLIGHT)
            .map(|_| native.in_flight(&nras).ok().unwrap())
            .collect();
        let err = native.nras_attest(&request).await.unwrap_err();
        assert!(err.is_retryable(), "{err}");
        assert_eq!(v.hits.load(Ordering::SeqCst), 0);
        drop(busy);
        for _ in 0..3 {
            let err = native.nras_attest(&request).await.unwrap_err();
            assert!(err.is_retryable(), "{err}");
        }
        assert_eq!(v.hits.load(Ordering::SeqCst), 1);
    }
}
