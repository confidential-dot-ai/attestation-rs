//! The store: the only place collateral is fetched, checked and kept.
//!
//! Every document comes in through [`DocKey::check`] (signature against the
//! compiled-in roots, binding to its key), whatever the source: held by the
//! caller, memory, disk, or the vendor. In memory it is kept until a newer
//! valid copy replaces it; a failed refetch keeps the old copy.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use serde::{Deserialize, Serialize};

use super::document::{Checked, DocKey, Document, Info, Raw};
use crate::error::{AttestationError, Result, Unavailable};

/// Where a document used for a verdict came from.
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

/// A checked document. Only the store makes one, so every `Doc` a verifier
/// sees went through [`Document::check`].
pub struct Doc<D: Document> {
    pub(crate) key: D,
    pub(crate) value: Arc<D::Value>,
    pub(crate) info: Info,
    pub(crate) source: Source,
}

/// What a verdict used: a document, where it came from, and its window.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Provenance {
    #[serde(flatten)]
    pub document: DocKey,
    pub source: Source,
    #[serde(flatten)]
    pub info: Info,
}

impl<D: Document> Doc<D> {
    /// The checked document.
    pub fn value(&self) -> &D::Value {
        &self.value
    }

    pub fn provenance(&self) -> Provenance {
        Provenance {
            document: self.key.clone().into(),
            source: self.source,
            info: self.info,
        }
    }
}

#[derive(Clone)]
#[cfg_attr(target_arch = "wasm32", allow(dead_code))]
struct Entry {
    raw: Raw,
    value: Checked,
    info: Info,
    origin: Source,
    #[cfg(not(target_arch = "wasm32"))]
    checked_at: std::time::Instant,
}

#[derive(Clone)]
enum LoadError {
    Unavailable(Unavailable),
    Refused(String),
}

impl LoadError {
    fn into_error(self, key: &DocKey) -> AttestationError {
        match self {
            LoadError::Unavailable(reason) => AttestationError::CollateralUnavailable {
                document: key.to_string(),
                reason,
            },
            LoadError::Refused(why) => {
                AttestationError::CertChainError(format!("{key} refused: {why}"))
            }
        }
    }
}

fn check(key: &DocKey, raw: Raw, origin: Source) -> std::result::Result<Entry, LoadError> {
    let (value, info) = key.check(&raw).map_err(LoadError::Refused)?;
    Ok(Entry {
        raw,
        value,
        info,
        origin,
        #[cfg(not(target_arch = "wasm32"))]
        checked_at: std::time::Instant::now(),
    })
}

/// Collateral documents for verifiers, from held copies, memory, disk and
/// the vendors.
pub struct Store {
    held: HashMap<DocKey, Raw>,
    /// What a held-only store was asked for and did not hold.
    missing: Mutex<Vec<DocKey>>,
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

    pub(crate) fn hold(&mut self, key: DocKey, raw: Raw) {
        self.held.insert(key, raw);
    }

    /// The documents a held-only store was asked for and did not hold, each
    /// once. A store with memory or a network records nothing.
    pub fn missing(&self) -> Vec<DocKey> {
        self.missing
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .clone()
    }

    /// The checked document `key`, judged at `now` (Unix seconds) for
    /// refreshes. A copy that does not check is refused (`CertChainError`)
    /// when no good copy exists; no copy anywhere is
    /// [`AttestationError::CollateralUnavailable`].
    pub async fn get<D: Document>(&self, key: D, now: i64) -> Result<Doc<D>> {
        let k: DocKey = key.clone().into();
        let (entry, source) = self.entry(&k, now).await.map_err(|e| e.into_error(&k))?;
        let value = entry
            .value
            .downcast::<D::Value>()
            .map_err(|_| AttestationError::Other(anyhow::anyhow!("{k}: wrong document type")))?;
        Ok(Doc {
            key,
            value,
            info: entry.info,
            source,
        })
    }

    /// Refetch `key`, unless it was checked with the vendor in the last
    /// few minutes; replace the copy in memory only with a valid copy that
    /// is not older. `Err` says why the refetch failed (the old copy, if
    /// any, is kept).
    #[cfg_attr(target_arch = "wasm32", allow(unused_variables))]
    pub async fn refresh(&self, key: &DocKey, now: i64) -> Result<()> {
        #[cfg(not(target_arch = "wasm32"))]
        if let Some(native) = &self.native {
            return match native.refresh(key, true, now).await {
                (_, _, Some(e)) => Err(e.into_error(key)),
                _ => Ok(()),
            };
        }
        Err(LoadError::Unavailable(Unavailable::Offline).into_error(key))
    }

    #[cfg_attr(target_arch = "wasm32", allow(unused_variables))]
    async fn entry(
        &self,
        key: &DocKey,
        now: i64,
    ) -> std::result::Result<(Entry, Source), LoadError> {
        if let Some(raw) = self.held.get(key) {
            return check(key, raw.clone(), Source::Held).map(|e| (e, Source::Held));
        }
        #[cfg(not(target_arch = "wasm32"))]
        if let Some(native) = &self.native {
            return native.entry(key, now).await;
        }
        let mut missing = self.missing.lock().unwrap_or_else(|e| e.into_inner());
        if !missing.contains(key) {
            missing.push(key.clone());
        }
        Err(LoadError::Unavailable(Unavailable::Offline))
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

    /// [`Self::refresh`] every shared document in memory (CRLs, TCB Info,
    /// QE Identity, the NRAS key set; not per-machine VCEKs or
    /// endorsements), a few at a time. Returns the failures.
    pub async fn refresh_all(&self, now: i64) -> Vec<AttestationError> {
        use futures_util::StreamExt;
        let keys: Vec<DocKey> = self
            .documents()
            .into_iter()
            .map(|p| p.document)
            .filter(|k| !k.per_machine())
            .collect();
        futures_util::stream::iter(keys)
            .map(|k| async move { self.refresh(&k, now).await })
            .buffer_unordered(4)
            .filter_map(|r| async { r.err() })
            .collect()
            .await
    }

    /// Every document held in memory.
    pub fn documents(&self) -> Vec<Provenance> {
        let Some(native) = &self.native else {
            return Vec::new();
        };
        native
            .mem
            .iter()
            .map(|(key, e)| Provenance {
                document: (*key).clone(),
                source: e.origin,
                info: e.info,
            })
            .collect()
    }

    /// About how many documents are held in memory.
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

    /// Refetch a document this long before its nextUpdate.
    const REFRESH_AHEAD: i64 = 24 * 3600;
    /// Refetch a document without a nextUpdate (the NRAS key set) this often.
    const MAX_AGE: Duration = Duration::from_secs(3600);

    pub(crate) struct Native {
        pub(super) mem: moka::future::Cache<DocKey, Entry>,
        pub(crate) disk: Option<Disk>,
        pub(crate) vendor: Option<Vendor>,
        /// Do not ask the vendor about one document more often than this.
        pub(crate) recheck: Duration,
    }

    impl Native {
        pub(crate) fn new(vendor: Option<Vendor>) -> Self {
            Self {
                mem: moka::future::Cache::new(4096),
                disk: None,
                vendor,
                recheck: Duration::from_secs(300),
            }
        }

        /// Close to (or past) its nextUpdate at `now`.
        fn ending(info: &Info, now: i64) -> bool {
            info.next_update
                .is_some_and(|next| now >= next - REFRESH_AHEAD)
        }

        /// Whether to ask the vendor about `entry` again: never within
        /// `recheck` of the last time; otherwise when it is ending (or, for
        /// the key set, old), or always when `force`d.
        fn due(&self, entry: &Entry, now: i64, force: bool) -> bool {
            let age = entry.checked_at.elapsed();
            age >= self.recheck
                && (force
                    || match entry.info.next_update {
                        Some(_) => Self::ending(&entry.info, now),
                        None => age >= MAX_AGE,
                    })
        }

        pub(super) async fn entry(
            &self,
            key: &DocKey,
            now: i64,
        ) -> std::result::Result<(Entry, Source), LoadError> {
            match self.mem.get(key).await {
                Some(entry) if self.due(&entry, now, false) => {
                    let (held, replaced, _) = self.refresh(key, false, now).await;
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
                    .try_get_with(key.clone(), self.load(key, now))
                    .await
                    .map(|e| {
                        let origin = e.origin;
                        (e, origin)
                    })
                    .map_err(|e| (*e).clone()),
            }
        }

        async fn fetch(&self, key: &DocKey) -> std::result::Result<Entry, LoadError> {
            let vendor = self
                .vendor
                .as_ref()
                .ok_or(LoadError::Unavailable(Unavailable::Offline))?;
            let raw = vendor.fetch(key).await.map_err(|e| match (key, e) {
                // The vendor does not know the chip or platform the evidence
                // names: the evidence is at fault, retrying will not help.
                (
                    DocKey::AmdVcek(_) | DocKey::IntelTcbInfo(_),
                    e @ (Unavailable::NotFound { .. } | Unavailable::Status { status: 400 }),
                ) => LoadError::Refused(format!("the vendor does not publish it ({e})")),
                (_, e) => LoadError::Unavailable(e),
            })?;
            check(key, raw, Source::Vendor)
        }

        fn store(&self, key: &DocKey, entry: &Entry) {
            if let Some(disk) = &self.disk {
                disk.write(key, &entry.raw);
            }
        }

        /// A miss: the disk copy if it is current, else the vendor's, else
        /// the disk copy anyway.
        async fn load(&self, key: &DocKey, now: i64) -> std::result::Result<Entry, LoadError> {
            let on_disk = self
                .disk
                .as_ref()
                .and_then(|d| d.read(key))
                .and_then(|raw| match check(key, raw, Source::Disk) {
                    Ok(e) => Some(e),
                    Err(LoadError::Refused(why)) => {
                        log::warn!("collateral cache: ignoring {key}: {why}");
                        None
                    }
                    Err(LoadError::Unavailable(_)) => None,
                });
            // A current disk copy is served as is: a process that only loads
            // (the CLI) would otherwise ask the vendor on every run near
            // nextUpdate. Refresh-ahead applies once it is in memory.
            if let Some(e) = &on_disk {
                if e.info.freshness(now) == crate::collateral::Freshness::Current {
                    return Ok(e.clone());
                }
            }
            match (self.fetch(key).await, on_disk) {
                (Ok(new), Some(old)) if !new.info.not_older_than(&old.info) => Ok(old),
                (Ok(new), _) => {
                    self.store(key, &new);
                    Ok(new)
                }
                (Err(_), Some(old)) => Ok(old),
                (Err(e), None) => Err(e),
            }
        }

        /// Refetch `key` when [`Self::due`] and replace the held copy with it
        /// when it checks and is not older. Concurrent refreshes of one key
        /// run one at a time. Returns the copy now held, whether it was
        /// replaced, and why a fetch failed.
        pub(super) async fn refresh(
            &self,
            key: &DocKey,
            force: bool,
            now: i64,
        ) -> (Option<Entry>, bool, Option<LoadError>) {
            let failure = Mutex::new(None);
            let replaced = Mutex::new(false);
            let result = self
                .mem
                .entry(key.clone())
                .and_compute_with(|current| async {
                    let current = current.map(|e| e.into_value());
                    if current.as_ref().is_some_and(|c| !self.due(c, now, force)) {
                        return Op::Nop;
                    }
                    match self.fetch(key).await {
                        Ok(new)
                            if current
                                .as_ref()
                                .is_none_or(|c| new.info.not_older_than(&c.info)) =>
                        {
                            self.store(key, &new);
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
    use std::time::{Duration, Instant};

    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    use super::*;
    use crate::collateral::{IntelPckCrl, IntelQeIdentity, IntelTcbInfo, PckCa, Source};
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
        let doc = raw(file, Some(CHAIN));
        let header = doc
            .issuer_chain
            .unwrap()
            .replace('\n', "%0A")
            .replace(' ', "%20");
        (
            200,
            vec![
                ("TCB-Info-Issuer-Chain", header.clone()),
                ("SGX-Enclave-Identity-Issuer-Chain", header),
            ],
            doc.body,
        )
    }

    fn status(code: u16, headers: Vec<(&'static str, String)>) -> Reply {
        (code, headers, Vec::new())
    }

    fn tcb_info() -> IntelTcbInfo {
        IntelTcbInfo {
            fmspc: "70a06d070000".into(),
        }
    }

    /// A store fetching from `v` that may ask it about a document any time.
    fn ctx(v: &Vendor) -> Context {
        Context::new()
            .with_vendor_base(&v.base)
            .with_recheck(Duration::ZERO)
    }

    fn version(doc: &Doc<IntelTcbInfo>) -> Option<u64> {
        doc.info.version
    }

    #[tokio::test]
    async fn concurrent_misses_fetch_once_then_memory_serves() {
        let v = vendor(
            vec![pcs("2026-10-14/tcb_info_70a06d070000.json")],
            Duration::from_millis(200),
        )
        .await;
        let ctx = ctx(&v);
        let gets = (0..20).map(|_| ctx.store().get(tcb_info(), NOW));
        for doc in futures_util::future::join_all(gets).await {
            assert_eq!(doc.unwrap().info.version, Some(20));
        }
        assert_eq!(v.hits.load(Ordering::SeqCst), 1);
        assert_eq!(
            ctx.store().get(tcb_info(), NOW).await.unwrap().source,
            Source::Memory
        );
        assert_eq!(v.hits.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn a_document_past_next_update_is_refetched_and_a_failed_refetch_keeps_it() {
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
        let old = ctx.store().get(IntelQeIdentity {}, NOW).await.unwrap();
        assert_eq!(old.info.version, Some(18));
        // Past nextUpdate: refetched, the vendor fails (two tries), the
        // old copy is served.
        let kept = ctx.store().get(IntelQeIdentity {}, NOW).await.unwrap();
        assert_eq!((kept.info.version, kept.source), (Some(18), Source::Memory));
        assert_eq!(v.hits.load(Ordering::SeqCst), 3);
        // Still due: refetched again, and replaced.
        let new = ctx.store().get(IntelQeIdentity {}, NOW).await.unwrap();
        assert_eq!((new.info.version, new.source), (Some(20), Source::Vendor));
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
        assert_eq!(
            version(&ctx.store().get(tcb_info(), NOW).await.unwrap()),
            Some(22)
        );
        ctx.store().refresh(&tcb_info().into(), NOW).await.unwrap();
        assert_eq!(v.hits.load(Ordering::SeqCst), 2);
        assert_eq!(
            version(&ctx.store().get(tcb_info(), NOW).await.unwrap()),
            Some(22)
        );
    }

    #[tokio::test]
    async fn a_bad_signature_is_refused_and_does_not_replace_a_good_copy() {
        let mut bad = pcs("2026-10-14/tcb_info_70a06d070000.json");
        bad.2 = String::from_utf8(bad.2)
            .unwrap()
            .replacen("\"UpToDate\"", "\"OutOfDate\"", 1)
            .into_bytes();
        let v = vendor(vec![bad.clone()], Duration::ZERO).await;
        let err = ctx(&v).store().get(tcb_info(), NOW).await.err().unwrap();
        assert!(matches!(err, AttestationError::CertChainError(_)), "{err}");
        assert!(!err.is_retryable());

        let v = vendor(
            vec![pcs("2026-10-14/tcb_info_70a06d070000.json"), bad],
            Duration::ZERO,
        )
        .await;
        let ctx = ctx(&v);
        ctx.store().get(tcb_info(), NOW).await.unwrap();
        assert!(ctx.store().refresh(&tcb_info().into(), NOW).await.is_err());
        assert_eq!(ctx.store().refresh_all(NOW).await.len(), 1);
        assert_eq!(
            version(&ctx.store().get(tcb_info(), NOW).await.unwrap()),
            Some(20)
        );
    }

    #[tokio::test]
    async fn not_found_is_not_retried_and_5xx_is() {
        for (code, hits) in [(404, 1), (410, 1), (503, 2), (500, 2), (408, 2), (403, 1)] {
            let v = vendor(vec![status(code, vec![])], Duration::ZERO).await;
            let err = ctx(&v)
                .store()
                .get(IntelQeIdentity {}, NOW)
                .await
                .err()
                .unwrap();
            assert!(err.is_retryable(), "{code}: {err}");
            assert_eq!(v.hits.load(Ordering::SeqCst), hits, "{code}");
        }
    }

    #[tokio::test]
    async fn a_document_the_evidence_names_and_the_vendor_does_not_know_is_refused() {
        for code in [404, 410] {
            let v = vendor(vec![status(code, vec![])], Duration::ZERO).await;
            let err = ctx(&v).store().get(tcb_info(), NOW).await.err().unwrap();
            assert!(matches!(err, AttestationError::CertChainError(_)), "{err}");
        }
        #[cfg(feature = "snp")]
        for code in [400, 404] {
            let v = vendor(vec![status(code, vec![])], Duration::ZERO).await;
            let err = ctx(&v).store().get(vcek(), NOW).await.err().unwrap();
            assert!(matches!(err, AttestationError::CertChainError(_)), "{err}");
            assert_eq!(v.hits.load(Ordering::SeqCst), 1);
        }
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
        ctx(&v).store().get(tcb_info(), NOW).await.unwrap();
        assert!(start.elapsed() >= Duration::from_secs(1));

        let v = vendor(
            vec![status(429, vec![("Retry-After", "120".into())])],
            Duration::ZERO,
        )
        .await;
        let err = ctx(&v).store().get(tcb_info(), NOW).await.err().unwrap();
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
        let err = ctx(&v).store().get(tcb_info(), NOW).await.err().unwrap();
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
        let err = ctx(&v).store().get(tcb_info(), NOW).await.err().unwrap();
        assert_eq!(err.retry_after(), Some(1));
        assert_eq!(v.hits.load(Ordering::SeqCst), 2);
    }

    /// The single file the store keeps `dir`'s one document in.
    fn only_file(dir: &std::path::Path) -> std::path::PathBuf {
        let files: Vec<_> = std::fs::read_dir(dir)
            .unwrap()
            .map(|e| e.unwrap().path())
            .collect();
        assert_eq!(files.len(), 1, "one file per document, no temporary files");
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
        online().store().get(tcb_info(), NOW).await.unwrap();
        let doc = offline(dir.path())
            .store()
            .get(tcb_info(), NOW)
            .await
            .unwrap();
        assert_eq!((doc.info.version, doc.source), (Some(20), Source::Disk));

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
            let err = offline(dir.path())
                .store()
                .get(tcb_info(), NOW)
                .await
                .err()
                .unwrap();
            assert!(err.is_retryable(), "{err}");
        }
        let doc = online().store().get(tcb_info(), NOW).await.unwrap();
        assert_eq!(doc.source, Source::Vendor);
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
        ctx(&v)
            .with_cache_dir(&dir)
            .store()
            .get(tcb_info(), NOW)
            .await
            .unwrap();
        let mode = |p: &std::path::Path| std::fs::metadata(p).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode(&dir), 0o700);
        assert_eq!(mode(&only_file(&dir)), 0o600);
    }

    #[tokio::test]
    async fn a_current_disk_copy_is_served_without_asking_the_vendor() {
        let dir = tempfile::tempdir().unwrap();
        let (key, raw) = (
            tcb_info().into(),
            raw("2026-10-14/tcb_info_70a06d070000.json", Some(CHAIN)),
        );
        crate::collateral::save_to_cache_dir(dir.path(), &key, &raw);
        let v = vendor(vec![status(503, vec![])], Duration::ZERO).await;
        let doc = ctx(&v)
            .with_cache_dir(dir.path())
            .store()
            .get(tcb_info(), NOW)
            .await
            .unwrap();
        assert_eq!(doc.source, Source::Disk);
        assert_eq!(v.hits.load(Ordering::SeqCst), 0);
    }

    #[tokio::test]
    async fn a_stale_disk_copy_is_served_when_the_vendor_fails() {
        let dir = tempfile::tempdir().unwrap();
        let expired = "2026-10-14/td_qe_identity_2026-03-16_eval18_expired.json";
        crate::collateral::save_to_cache_dir(
            dir.path(),
            &IntelQeIdentity {}.into(),
            &raw(expired, Some(CHAIN)),
        );
        let v = vendor(vec![status(503, vec![])], Duration::ZERO).await;
        let doc = ctx(&v)
            .with_cache_dir(dir.path())
            .store()
            .get(IntelQeIdentity {}, NOW)
            .await
            .unwrap();
        assert_eq!((doc.info.version, doc.source), (Some(18), Source::Disk));
        assert_eq!(v.hits.load(Ordering::SeqCst), 2);
    }

    #[tokio::test]
    async fn callers_of_a_document_due_for_refresh_wait_for_one_fetch() {
        let v = vendor(
            vec![pcs("2026-10-14/tcb_info_70a06d070000.json")],
            Duration::from_millis(200),
        )
        .await;
        let ctx = Context::new()
            .with_vendor_base(&v.base)
            .with_recheck(Duration::from_millis(300));
        ctx.store().get(tcb_info(), NOW).await.unwrap();
        tokio::time::sleep(Duration::from_millis(400)).await;
        // A day before nextUpdate: due for refresh.
        let ending = ctx
            .store()
            .get(tcb_info(), NOW)
            .await
            .unwrap()
            .info
            .next_update
            .unwrap()
            - 3600;
        let gets = (0..20).map(|_| ctx.store().get(tcb_info(), ending));
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
        ctx.store().get(tcb_info(), NOW).await.unwrap();
        for _ in 0..5 {
            ctx.store().refresh(&tcb_info().into(), NOW).await.unwrap();
            assert!(ctx.store().refresh_all(NOW).await.is_empty());
        }
        assert_eq!(v.hits.load(Ordering::SeqCst), 1);
    }

    #[cfg(feature = "snp")]
    fn vcek() -> crate::collateral::AmdVcek {
        crate::collateral::AmdVcek {
            generation: crate::types::ProcessorGeneration::Genoa,
            chip_id: "b5f9a4c8280e63c97d288db6648577dc2b848884aa682d7a227ba40e50deb2b0\
                      d112b599d87aaccda78d06f4254b1e81c4d953ef3c699db39d4e06013e9fa4ce"
                .into(),
            tcb: crate::types::SnpTcb {
                bootloader: 10,
                tee: 0,
                snp: 27,
                microcode: 28,
                fmc: None,
            },
        }
    }

    #[cfg(feature = "snp")]
    #[tokio::test]
    async fn refresh_all_leaves_per_machine_documents_alone() {
        let v = vendor(
            vec![
                (200, vec![], raw("2026-10-14/amd_vcek_genoa.der", None).body),
                pcs("2026-10-14/tcb_info_70a06d070000.json"),
            ],
            Duration::ZERO,
        )
        .await;
        let ctx = ctx(&v);
        ctx.store().get(vcek(), NOW).await.unwrap();
        ctx.store().get(tcb_info(), NOW).await.unwrap();
        assert!(ctx.store().refresh_all(NOW).await.is_empty());
        assert_eq!(v.hits.load(Ordering::SeqCst), 3);
    }

    #[tokio::test]
    async fn offline_without_a_copy_is_unavailable_offline() {
        let err = Context::offline()
            .store()
            .get(
                IntelPckCrl {
                    ca: PckCa::Platform,
                },
                NOW,
            )
            .await
            .err()
            .unwrap();
        assert!(matches!(
            err,
            AttestationError::CollateralUnavailable {
                reason: Unavailable::Offline,
                ..
            }
        ));
    }

    #[tokio::test]
    async fn only_a_held_only_store_records_what_it_was_missing() {
        let held = Context::held([]);
        for _ in 0..3 {
            let _ = held.store().get(tcb_info(), NOW).await;
        }
        assert_eq!(held.store().missing(), vec![tcb_info().into()]);
        let native = Context::offline();
        let _ = native.store().get(tcb_info(), NOW).await;
        assert!(native.store().missing().is_empty());
    }
}
