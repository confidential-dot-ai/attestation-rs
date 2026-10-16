//! The store: the only place collateral is fetched, verified and kept.
//!
//! Every piece comes in through its `verify` (signature against the
//! compiled-in roots, binding to what the evidence names), whatever the
//! source: held by the caller, memory, disk, or the vendor. The cache is keyed
//! by the vendor URL. In memory a piece is kept until a newer valid copy
//! replaces it; a failed refetch keeps the old copy.

use std::collections::HashMap;
use std::sync::Mutex;

use serde::{Deserialize, Serialize};

use super::{Collateral, Dates};
use crate::error::{AttestationError, Result, Unavailable};

/// Where a piece of collateral used for a verdict came from.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Source {
    /// Supplied by the caller (WASM, tests).
    Held,
    /// This process already held it.
    Memory,
    /// The disk cache.
    Disk,
    /// Fetched from the vendor by this call, or by a concurrent call it
    /// waited for.
    Vendor,
}

impl std::fmt::Display for Source {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Source::Held => "held",
            Source::Memory => "memory",
            Source::Disk => "disk",
            Source::Vendor => "vendor",
        })
    }
}

/// A piece of collateral a verdict used: which, from where, its version and
/// nextUpdate, and whether it was current at the evaluation time.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CollateralUsed {
    /// For example `amd-crl genoa`, `tcb-info 70a06d070000`.
    pub name: String,
    pub from: Source,
    pub version: Option<u64>,
    pub next_update: Option<i64>,
    pub current: bool,
}

impl CollateralUsed {
    fn new(name: String, from: Source, dates: Dates, now: i64) -> Self {
        Self {
            name,
            from,
            version: dates.version,
            next_update: dates.next_update,
            current: dates.current(now),
        }
    }
}

#[derive(Clone)]
#[cfg_attr(target_arch = "wasm32", allow(dead_code))]
struct Entry {
    body: Vec<u8>,
    issuer_chain: Option<String>,
    dates: Dates,
    origin: Source,
    #[cfg(not(target_arch = "wasm32"))]
    checked_at: std::time::Instant,
}

#[derive(Clone)]
enum Failure {
    Unavailable(Unavailable),
    /// Why the piece does not verify.
    Refused(String),
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
            Failure::Refused(why) => {
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
    let dates = C::verify(&body, issuer_chain.as_deref(), id)
        .map_err(Failure::refused)?
        .dates();
    Ok(Entry {
        body,
        issuer_chain,
        dates,
        origin,
        #[cfg(not(target_arch = "wasm32"))]
        checked_at: std::time::Instant::now(),
    })
}

/// Collateral for verifiers, from held copies, memory, disk and the vendors.
pub struct Store {
    /// Vendor responses supplied by the caller, by URL.
    held: HashMap<String, (Vec<u8>, Option<String>)>,
    /// The URLs a held-only store was asked for and did not hold.
    missing: Mutex<Vec<String>>,
    #[cfg(not(target_arch = "wasm32"))]
    native: Option<native::Native>,
}

impl Store {
    /// Holds only what the caller supplies: no memory, disk or network.
    pub(crate) fn held_only() -> Self {
        Self {
            held: HashMap::new(),
            missing: Mutex::default(),
            #[cfg(not(target_arch = "wasm32"))]
            native: None,
        }
    }

    pub(crate) fn hold(&mut self, url: String, body: Vec<u8>, issuer_chain: Option<String>) {
        self.held.insert(url, (body, issuer_chain));
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
    /// it at `now` (Unix seconds). A copy that does not verify is refused
    /// when no good copy exists.
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

    async fn lookup<C: Collateral>(
        &self,
        id: &C::Id,
        now: i64,
    ) -> std::result::Result<(C, CollateralUsed), Failure> {
        let url = C::url(id);
        let (body, chain, from) = match self.held.get(&url) {
            Some((body, chain)) => (body.clone(), chain.clone(), Source::Held),
            None => {
                let (entry, from) = self.load::<C>(url, id, now).await?;
                (entry.body, entry.issuer_chain, from)
            }
        };
        let piece = C::verify(&body, chain.as_deref(), id).map_err(Failure::refused)?;
        let used = CollateralUsed::new(C::name(id), from, piece.dates(), now);
        Ok((piece, used))
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
            native: Some(native::Native::new(vendor)),
            ..Self::held_only()
        }
    }

    pub(crate) fn native_mut(&mut self) -> Option<&mut native::Native> {
        self.native.as_mut()
    }

    #[cfg(feature = "nvidia-gpu")]
    pub(crate) fn vendor(&self) -> Option<&crate::collateral::vendor::Vendor> {
        self.native.as_ref()?.vendor.as_ref()
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

    /// Refetch a piece this long before its nextUpdate.
    const REFRESH_AHEAD: i64 = 24 * 3600;
    /// Refetch a piece without a nextUpdate (the NRAS key set) this often.
    const MAX_AGE: Duration = Duration::from_secs(3600);

    pub(crate) struct Native {
        pub(super) mem: moka::future::Cache<String, Entry>,
        /// URLs the vendor answered "not published" for, and when.
        not_published: moka::future::Cache<String, (Instant, Failure)>,
        pub(crate) disk: Option<Disk>,
        pub(crate) vendor: Option<Vendor>,
        /// Do not ask the vendor about one piece more often than this.
        pub(crate) recheck: Duration,
    }

    impl Native {
        pub(crate) fn new(vendor: Option<Vendor>) -> Self {
            Self {
                mem: moka::future::Cache::new(4096),
                not_published: moka::future::Cache::new(4096),
                disk: None,
                vendor,
                recheck: Duration::from_secs(300),
            }
        }

        /// Whether to ask the vendor about `entry` again: never within
        /// `recheck` of the last time; otherwise when it is within a day of
        /// its nextUpdate (or, for the key set, old), or always when
        /// `force`d.
        fn due(&self, entry: &Entry, now: i64, force: bool) -> bool {
            let age = entry.checked_at.elapsed();
            age >= self.recheck
                && (force
                    || match entry.dates.next_update {
                        Some(next) => now >= next - REFRESH_AHEAD,
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
                    let source = if replaced {
                        Source::Vendor
                    } else {
                        Source::Memory
                    };
                    Ok((held.unwrap_or(entry), source))
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

        async fn fetch<C: Collateral>(
            &self,
            url: &str,
            id: &C::Id,
        ) -> std::result::Result<Entry, Failure> {
            let vendor = self
                .vendor
                .as_ref()
                .ok_or_else(|| Failure::Unavailable(Unavailable::offline()))?;
            if let Some((at, failure)) = self.not_published.get(url).await {
                if at.elapsed() < self.recheck {
                    return Err(failure);
                }
            }
            let (body, chain) = match vendor.fetch(url).await {
                Ok(fetched) => fetched,
                Err(e) if e.not_found() || (C::NAMED_BY_EVIDENCE && e.status == Some(400)) => {
                    // The vendor does not know the chip or platform the
                    // evidence names: for a piece the evidence names, the
                    // evidence is at fault and retrying will not help.
                    let failure = if C::NAMED_BY_EVIDENCE {
                        Failure::Refused(format!("the vendor does not publish it ({})", e.detail))
                    } else {
                        Failure::Unavailable(e)
                    };
                    self.not_published
                        .insert(url.to_string(), (Instant::now(), failure.clone()))
                        .await;
                    return Err(failure);
                }
                Err(e) => return Err(Failure::Unavailable(e)),
            };
            check::<C>(id, body, chain, Source::Vendor)
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
            match (self.fetch::<C>(url, id).await, on_disk) {
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
                    match self.fetch::<C>(url, id).await {
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
            .with_vendor_base(&v.base)
            .with_recheck(Duration::ZERO)
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

    #[cfg(feature = "snp")]
    #[tokio::test]
    async fn the_vendor_is_asked_about_an_unpublished_piece_once_per_recheck() {
        let v = vendor(vec![status(404, vec![])], Duration::ZERO).await;
        let ctx = Context::new()
            .with_vendor_base(&v.base)
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
        assert_eq!(mode(&open), 0o700);
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
            .with_vendor_base(&v.base)
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
            .with_vendor_base(&v.base)
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
        let ctx = Context::new()
            .with_vendor_base(&v.base)
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
}
