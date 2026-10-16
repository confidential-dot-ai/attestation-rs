//! The store: the only place collateral is fetched, verified and kept.
//!
//! Every piece comes in through its `verify` (signature against the
//! compiled-in roots, binding to what the evidence names), whatever the
//! source: held by the caller, memory, disk, or the vendor. The cache is keyed
//! by the vendor URL. In memory a piece is kept until a newer valid copy
//! replaces it; a failed refetch keeps the old copy.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use serde::{Deserialize, Serialize};

#[cfg(feature = "nvidia-gpu")]
use super::NrasJwks;
#[cfg(feature = "snp")]
use super::{AmdCrl, AmdSigner, Vcek};
use super::{Dates, Refused};
#[cfg(feature = "tdx")]
use super::{Fmspc, PckCa, PckCrl, QeIdentity, RootCrl, TcbInfo};
#[cfg(any(feature = "gcp-tdx", feature = "gcp-snp"))]
use super::{GceEndorsement, GceTee};
use crate::error::{AttestationError, Result, Unavailable};
#[cfg(feature = "snp")]
use crate::types::{ProcessorGeneration as Gen, SnpTcb};

/// A piece and what the verdict should say about it.
type Got<T> = Result<(T, CollateralUsed)>;

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

/// What the store knows about a piece before it has it.
#[derive(Clone)]
struct Spec {
    url: String,
    name: String,
    /// The evidence names it: a vendor 404 means the evidence is at fault.
    named_by_evidence: bool,
    verify: VerifyFn,
}

/// A piece's `verify` with its identity bound: body and issuer chain in,
/// dates out.
type VerifyFn =
    Arc<dyn Fn(&[u8], Option<&str>) -> std::result::Result<Dates, Refused> + Send + Sync>;

#[derive(Clone)]
#[cfg_attr(target_arch = "wasm32", allow(dead_code))]
struct Entry {
    spec: Spec,
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
    Refused(Refused),
}

impl Failure {
    fn into_error(self, name: &str) -> AttestationError {
        match self {
            Failure::Unavailable(e) => e.into_error(name),
            Failure::Refused(why) => {
                AttestationError::CertChainError(format!("{name} refused: {why}"))
            }
        }
    }
}

fn check(
    spec: &Spec,
    body: Vec<u8>,
    issuer_chain: Option<String>,
    origin: Source,
) -> std::result::Result<Entry, Failure> {
    let dates = (spec.verify)(&body, issuer_chain.as_deref()).map_err(Failure::Refused)?;
    Ok(Entry {
        spec: spec.clone(),
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

    /// The piece at `url`, verified with `verify`, and what the verdict
    /// should say about it at `now` (Unix seconds); `dates` reads its window
    /// and version. For `named_by_evidence` see [`Spec`]. A copy that does
    /// not verify is refused when no good copy exists.
    #[cfg_attr(target_arch = "wasm32", allow(unused_variables))]
    async fn get<T: 'static>(
        &self,
        url: String,
        name: &str,
        named_by_evidence: bool,
        now: i64,
        verify: impl Fn(&[u8], Option<&str>) -> std::result::Result<T, Refused>
            + Clone
            + Send
            + Sync
            + 'static,
        dates: fn(&T) -> Dates,
    ) -> std::result::Result<(T, CollateralUsed), Failure> {
        let (body, chain, from) = match self.held.get(&url) {
            Some((body, chain)) => (body.clone(), chain.clone(), Source::Held),
            None => {
                let spec = Spec {
                    url,
                    name: name.to_string(),
                    named_by_evidence,
                    verify: Arc::new({
                        let verify = verify.clone();
                        move |body, chain| verify(body, chain).map(|p| dates(&p))
                    }),
                };
                let (entry, from) = self.load(spec, now).await?;
                (entry.body, entry.issuer_chain, from)
            }
        };
        let piece = verify(&body, chain.as_deref()).map_err(Failure::Refused)?;
        let used = CollateralUsed::new(name.to_string(), from, dates(&piece), now);
        Ok((piece, used))
    }

    #[cfg_attr(target_arch = "wasm32", allow(unused_variables))]
    async fn load(&self, spec: Spec, now: i64) -> std::result::Result<(Entry, Source), Failure> {
        #[cfg(not(target_arch = "wasm32"))]
        if let Some(native) = &self.native {
            return native.entry(spec, now).await;
        }
        let mut missing = self.missing.lock().unwrap_or_else(|e| e.into_inner());
        if !missing.contains(&spec.url) {
            missing.push(spec.url);
        }
        Err(Failure::Unavailable(Unavailable::offline()))
    }

    /// The VCEK for a chip at a TCB.
    #[cfg(feature = "snp")]
    pub async fn vcek(&self, gen: Gen, chip_id: &[u8; 64], tcb: &SnpTcb, now: i64) -> Got<Vcek> {
        let (chip_id, tcb) = (*chip_id, *tcb);
        let name = format!("vcek {gen:?} {}", hex::encode(&chip_id[..8])).to_lowercase();
        let verify = move |b: &[u8], _: Option<&str>| Vcek::verify(b, gen, &chip_id, &tcb);
        let url = Vcek::url(gen, &chip_id, &tcb);
        let dates = |v: &Vcek| Dates::window(v.not_before, v.not_after, None);
        self.get(url, &name, true, now, verify, dates)
            .await
            .map_err(|e| e.into_error(&name))
    }

    /// AMD's CRL for a generation and signer.
    #[cfg(feature = "snp")]
    pub async fn amd_crl(&self, gen: Gen, signer: AmdSigner, now: i64) -> Got<AmdCrl> {
        let vlek = if signer == AmdSigner::Asvk {
            " vlek"
        } else {
            ""
        };
        let name = format!("amd-crl {gen:?}{vlek}").to_lowercase();
        let verify = move |b: &[u8], _: Option<&str>| AmdCrl::verify(b, gen, signer);
        let url = AmdCrl::url(gen, signer);
        let dates = |c: &AmdCrl| Dates::window(c.this_update, c.next_update, c.number);
        self.get(url, &name, false, now, verify, dates)
            .await
            .map_err(|e| e.into_error(&name))
    }

    /// Intel's TCB Info for a platform.
    #[cfg(feature = "tdx")]
    pub async fn tcb_info(&self, fmspc: &Fmspc, now: i64) -> Got<TcbInfo> {
        let fmspc = *fmspc;
        let name = format!("tcb-info {}", hex::encode(fmspc));
        let verify = move |b: &[u8], c: Option<&str>| TcbInfo::verify(b, c, &fmspc);
        let url = TcbInfo::url(&fmspc);
        let dates =
            |t: &TcbInfo| Dates::window(t.issue_date, t.next_update, Some(t.evaluation_number));
        self.get(url, &name, true, now, verify, dates)
            .await
            .map_err(|e| e.into_error(&name))
    }

    /// Intel's TD QE Identity.
    #[cfg(feature = "tdx")]
    pub async fn qe_identity(&self, now: i64) -> Got<QeIdentity> {
        let (url, name) = (QeIdentity::url(), String::from("qe-identity"));
        let dates =
            |q: &QeIdentity| Dates::window(q.issue_date, q.next_update, Some(q.evaluation_number));
        self.get(url, &name, false, now, QeIdentity::verify, dates)
            .await
            .map_err(|e| e.into_error(&name))
    }

    /// The CRL of an Intel PCK CA.
    #[cfg(feature = "tdx")]
    pub async fn pck_crl(&self, ca: PckCa, now: i64) -> Got<PckCrl> {
        let (url, name) = (PckCrl::url(ca), format!("pck-crl {}", ca.name()));
        let verify = move |b: &[u8], c: Option<&str>| PckCrl::verify(b, c, ca);
        let dates = |c: &PckCrl| Dates::window(c.this_update, c.next_update, c.number);
        self.get(url, &name, false, now, verify, dates)
            .await
            .map_err(|e| e.into_error(&name))
    }

    /// The CRL of the Intel SGX Root CA.
    #[cfg(feature = "tdx")]
    pub async fn root_crl(&self, now: i64) -> Got<RootCrl> {
        let (url, name) = (RootCrl::url(), String::from("root-crl"));
        let verify = |b: &[u8], _: Option<&str>| RootCrl::verify(b);
        let dates = |c: &RootCrl| Dates::window(c.this_update, c.next_update, c.number);
        self.get(url, &name, false, now, verify, dates)
            .await
            .map_err(|e| e.into_error(&name))
    }

    /// Google's endorsement of a GCE firmware build; `None` when Google
    /// publishes none for the measurement.
    #[cfg(any(feature = "gcp-tdx", feature = "gcp-snp"))]
    pub async fn gce_endorsement(
        &self,
        tee: GceTee,
        m: &[u8],
        now: i64,
    ) -> Result<Option<(GceEndorsement, CollateralUsed)>> {
        let (url, m) = (GceEndorsement::url(tee, m), m.to_vec());
        let name = format!(
            "gce-endorsement {tee:?} {}",
            hex::encode(&m[..m.len().min(8)])
        );
        let name = name.to_lowercase();
        let verify = move |b: &[u8], _: Option<&str>| GceEndorsement::verify(b, tee, &m);
        let dates = |e: &GceEndorsement| Dates::window(e.not_before, e.not_after, None);
        match self.get(url, &name, false, now, verify, dates).await {
            Ok(got) => Ok(Some(got)),
            Err(Failure::Unavailable(e)) if e.not_found() => Ok(None),
            Err(e) => Err(e.into_error(&name)),
        }
    }

    /// The keys NRAS signs its tokens with.
    #[cfg(feature = "nvidia-gpu")]
    pub async fn nras_jwks(&self, now: i64) -> Got<NrasJwks> {
        let (url, name) = (self.nras_jwks_url(), String::from("nras-jwks"));
        let verify = |b: &[u8], _: Option<&str>| NrasJwks::verify(b);
        self.get(url, &name, false, now, verify, |_| Dates::default())
            .await
            .map_err(|e| e.into_error(&name))
    }

    #[cfg(feature = "nvidia-gpu")]
    pub(crate) fn nras_jwks_url(&self) -> String {
        #[cfg(not(target_arch = "wasm32"))]
        if let Some(vendor) = self.vendor() {
            return NrasJwks::url(&vendor.nras.gpu_url);
        }
        NrasJwks::url(crate::platforms::nvidia_gpu::provider::NRAS_GPU_URL)
    }

    /// Refetch the piece at `url` (the NRAS key set when a token names an
    /// unknown key), unless it was checked with the vendor in the last few
    /// minutes; replace the copy in memory only with a valid
    /// copy that is not older. `Err` says why the refetch failed (the old
    /// copy, if any, is kept). A piece not in memory is left alone.
    #[cfg_attr(target_arch = "wasm32", allow(unused_variables))]
    pub async fn refresh(&self, url: &str, now: i64) -> Result<()> {
        #[cfg(not(target_arch = "wasm32"))]
        if let Some(native) = &self.native {
            return match native.refresh_url(url, true, now).await {
                Some((name, e)) => Err(e.into_error(&name)),
                None => Ok(()),
            };
        }
        Err(Failure::Unavailable(Unavailable::offline()).into_error(url))
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
        pub(crate) disk: Option<Disk>,
        pub(crate) vendor: Option<Vendor>,
        /// Do not ask the vendor about one piece more often than this.
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

        pub(super) async fn entry(
            &self,
            spec: Spec,
            now: i64,
        ) -> std::result::Result<(Entry, Source), Failure> {
            match self.mem.get(&spec.url).await {
                Some(entry) if self.due(&entry, now, false) => {
                    let (held, replaced, _) = self.refresh(&spec, false, now).await;
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
                    .try_get_with(spec.url.clone(), self.load(&spec, now))
                    .await
                    .map(|e| {
                        let origin = e.origin;
                        (e, origin)
                    })
                    .map_err(|e| (*e).clone()),
            }
        }

        async fn fetch(&self, spec: &Spec) -> std::result::Result<Entry, Failure> {
            let vendor = self
                .vendor
                .as_ref()
                .ok_or_else(|| Failure::Unavailable(Unavailable::offline()))?;
            let (body, chain) = vendor.fetch(&spec.url).await.map_err(|e| match e {
                // The vendor does not know the chip or platform the evidence
                // names: the evidence is at fault, retrying will not help.
                e if spec.named_by_evidence && (e.not_found() || e.status == Some(400)) => {
                    Failure::Refused(Refused(format!(
                        "the vendor does not publish it ({})",
                        e.detail
                    )))
                }
                e => Failure::Unavailable(e),
            })?;
            check(spec, body, chain, Source::Vendor)
        }

        fn store(&self, entry: &Entry) {
            if let Some(disk) = &self.disk {
                disk.write(&entry.spec.url, &entry.body, entry.issuer_chain.as_deref());
            }
        }

        /// A miss: the disk copy if it is current, else the vendor's, else
        /// the disk copy anyway.
        async fn load(&self, spec: &Spec, now: i64) -> std::result::Result<Entry, Failure> {
            let on_disk =
                self.disk
                    .as_ref()
                    .and_then(|d| d.read(&spec.url))
                    .and_then(
                        |(body, chain)| match check(spec, body, chain, Source::Disk) {
                            Ok(e) => Some(e),
                            Err(_) => {
                                log::warn!(
                                    "collateral cache: ignoring {}: it does not verify",
                                    spec.name
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
            match (self.fetch(spec).await, on_disk) {
                (Ok(new), Some(old)) if !new.dates.not_older_than(&old.dates) => Ok(old),
                (Ok(new), _) => {
                    self.store(&new);
                    Ok(new)
                }
                (Err(_), Some(old)) => Ok(old),
                (Err(e), None) => Err(e),
            }
        }

        /// [`Self::refresh`] the piece in memory at `url`. Returns its name
        /// and why the fetch failed, if it did.
        pub(super) async fn refresh_url(
            &self,
            url: &str,
            force: bool,
            now: i64,
        ) -> Option<(String, Failure)> {
            let spec = self.mem.get(url).await?.spec;
            let (_, _, failure) = self.refresh(&spec, force, now).await;
            failure.map(|f| (spec.name, f))
        }

        /// Refetch the piece when [`Self::due`] and replace the held copy
        /// with it when it verifies and is not older. Concurrent refreshes of
        /// one piece run one at a time. Returns the copy now held, whether it
        /// was replaced, and why a fetch failed.
        async fn refresh(
            &self,
            spec: &Spec,
            force: bool,
            now: i64,
        ) -> (Option<Entry>, bool, Option<Failure>) {
            let failure = Mutex::new(None);
            let replaced = Mutex::new(false);
            let result = self
                .mem
                .entry(spec.url.clone())
                .and_compute_with(|current| async {
                    let current = current.map(|e| e.into_value());
                    if current.as_ref().is_some_and(|c| !self.due(c, now, force)) {
                        return Op::Nop;
                    }
                    match self.fetch(spec).await {
                        Ok(new)
                            if current
                                .as_ref()
                                .is_none_or(|c| new.dates.not_older_than(&c.dates)) =>
                        {
                            self.store(&new);
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
    use crate::collateral::{PckCa, Source, TcbInfo};
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
        let (_, used) = ctx.store().tcb_info(&FMSPC, now).await?;
        Ok((used.version, used.from))
    }

    async fn qe_identity(ctx: &Context) -> Result<(Option<u64>, Source)> {
        let (_, used) = ctx.store().qe_identity(NOW).await?;
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
        ctx.store().refresh(&tcb_info_url(), NOW).await.unwrap();
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
        assert!(ctx.store().refresh(&tcb_info_url(), NOW).await.is_err());
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
        let url = crate::collateral::QeIdentity::url();
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
        let (info, _) = ctx.store().tcb_info(&FMSPC, NOW).await.unwrap();
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
            ctx.store().refresh(&tcb_info_url(), NOW).await.unwrap();
        }
        assert_eq!(v.hits.load(Ordering::SeqCst), 1);
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
        ctx.store().vcek(genoa, &chip_id, &tcb, NOW).await
    }

    #[tokio::test]
    async fn offline_without_a_copy_is_retryable_unavailable() {
        let err = Context::offline()
            .store()
            .pck_crl(PckCa::Platform, NOW)
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
