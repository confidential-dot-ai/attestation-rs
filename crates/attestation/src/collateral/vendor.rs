//! Fetching collateral from the vendors over HTTPS.

use std::time::Duration;

use crate::error::Unavailable;

const CONNECT_TIMEOUT: Duration = Duration::from_secs(3);
const REQUEST_TIMEOUT: Duration = Duration::from_secs(5);
const MAX_BODY: usize = 5 * 1024 * 1024;
/// The longest Retry-After waited out inside one call; a longer one is
/// returned to the caller.
const MAX_RETRY_AFTER: u64 = 5;
/// Wait before the one retry: 200 ms plus up to 200 ms of jitter.
const RETRY_DELAY_MS: u64 = 200;
/// The response headers Intel PCS sends a TCB Info's, QE Identity's or PCK
/// CRL's issuer chain in.
const ISSUER_CHAIN_HEADERS: [&str; 3] = [
    "TCB-Info-Issuer-Chain",
    "SGX-Enclave-Identity-Issuer-Chain",
    "SGX-PCK-CRL-Issuer-Chain",
];

/// Where collateral is fetched from.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum Upstream {
    /// The vendors, over HTTPS.
    Vendors,
    /// A collateral cache: `https://{host}/{path}` is fetched as
    /// `{base}/{host}/{path}`. Its answers are verified like the vendors'.
    Cache(String),
    /// A cache at this vsock address (CID, port).
    #[cfg_attr(not(target_os = "linux"), allow(dead_code))]
    Vsock(u32, u32),
    /// Inside a confidential VM, the host's cache at [`VSOCK_PORT`] once it
    /// accepts a connection (then for good), else the vendors.
    Auto,
    /// A fake vendor at this base, for tests: its answers count as the
    /// vendor's own.
    #[cfg(any(test, feature = "test-vendor"))]
    TestVendor(String),
}

/// The vsock port a host's attestation-cache listens on, found by guests
/// without configuration.
pub const VSOCK_PORT: u32 = 8455;
/// The host, as a guest addresses it over vsock.
#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
const HOST_CID: u32 = 2;
/// While no host cache has answered, look for it again after this long.
const REPROBE: Duration = Duration::from_secs(60);

impl Upstream {
    /// `vsock://CID:PORT`, or a cache base URL: `https://`, or plain
    /// `http://` only to a loopback address.
    pub(crate) fn parse(url: &str) -> Option<Self> {
        if let Some(address) = url.strip_prefix("vsock://") {
            let (cid, port) = address.split_once(':')?;
            return Some(Upstream::Vsock(cid.parse().ok()?, port.parse().ok()?));
        }
        let bare = reqwest::Url::parse(url).is_ok_and(|u| {
            u.query().is_none()
                && u.fragment().is_none()
                && u.username().is_empty()
                && u.password().is_none()
        });
        (bare && allowed(url)).then(|| Upstream::Cache(url.trim_end_matches('/').to_string()))
    }

    /// Whether an answer from here is the vendor's own.
    fn is_vendor(&self) -> bool {
        match self {
            Upstream::Vendors => true,
            #[cfg(any(test, feature = "test-vendor"))]
            Upstream::TestVendor(_) => true,
            _ => false,
        }
    }
}

impl std::fmt::Display for Upstream {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Upstream::Vendors => f.write_str("the vendors"),
            Upstream::Cache(base) => write!(f, "the cache at {base}"),
            Upstream::Vsock(cid, port) => write!(f, "the cache at vsock://{cid}:{port}"),
            Upstream::Auto => f.write_str("a host cache if found, else the vendors"),
            #[cfg(any(test, feature = "test-vendor"))]
            Upstream::TestVendor(base) => write!(f, "the test vendor at {base}"),
        }
    }
}

/// What [`Upstream::Auto`] found: the host cache once it answered, kept for
/// good (a CVM with a cache never asks the vendors); until then the vendors,
/// probing again every `reprobe`.
struct Discovery {
    host: std::sync::OnceLock<Upstream>,
    last_probe: tokio::sync::Mutex<Option<std::time::Instant>>,
    reprobe: Duration,
}

impl Discovery {
    fn new(reprobe: Duration) -> Self {
        Self {
            host: std::sync::OnceLock::new(),
            last_probe: tokio::sync::Mutex::new(None),
            reprobe,
        }
    }

    async fn upstream<F: std::future::Future<Output = bool>>(
        &self,
        host: Upstream,
        probe: impl FnOnce() -> F,
    ) -> Upstream {
        if let Some(found) = self.host.get() {
            return found.clone();
        }
        let mut last = self.last_probe.lock().await;
        if let Some(found) = self.host.get() {
            return found.clone();
        }
        if last.is_some_and(|t| t.elapsed() < self.reprobe) {
            return Upstream::Vendors;
        }
        *last = Some(std::time::Instant::now());
        if probe().await {
            log::info!("collateral: using the host cache at {host}");
            return self.host.get_or_init(|| host).clone();
        }
        log::info!(
            "collateral: no host cache at {host}, using the vendors (looking again in {}s)",
            self.reprobe.as_secs()
        );
        Upstream::Vendors
    }
}

/// Whether this is a confidential VM guest, where a host cache may be.
/// Azure vTPM guests and dstack containers show none of these files (a TPM
/// alone does not mark a CVM, and a container rarely reaches the host's
/// vsock), so they use the vendors unless an upstream is set.
fn in_cvm() -> bool {
    cfg!(target_os = "linux")
        && [
            "/dev/tdx_guest",
            "/dev/sev-guest",
            "/sys/kernel/config/tsm/report",
        ]
        .iter()
        .any(|p| std::path::Path::new(p).exists())
}

/// `https` with a host, or `http` to a loopback address.
pub(crate) fn allowed(url: &str) -> bool {
    let Ok(url) = reqwest::Url::parse(url) else {
        return false;
    };
    match (url.scheme(), url.host()) {
        ("https", Some(url::Host::Domain(d))) => !d.is_empty(),
        ("https", Some(_)) => true,
        ("http", Some(url::Host::Ipv4(ip))) => ip.is_loopback(),
        ("http", Some(url::Host::Ipv6(ip))) => ip.is_loopback(),
        ("http", Some(url::Host::Domain(d))) => d == "localhost",
        _ => false,
    }
}

pub(crate) struct Vendor {
    /// HTTPS only.
    client: reqwest::Client,
    /// Also plain HTTP, only for loopback URLs ([`allowed`]).
    loopback: reqwest::Client,
    pub(crate) upstream: Upstream,
    found: Discovery,
    /// Sent as a bearer token to a [`Upstream::Cache`].
    pub(crate) upstream_key: Option<String>,
    not_in_cvm: std::sync::Once,
    #[cfg(feature = "nvidia-gpu")]
    pub(crate) nras: Nras,
}

impl Vendor {
    pub(crate) fn new() -> Self {
        let client = |https_only| {
            reqwest::Client::builder()
                .redirect(reqwest::redirect::Policy::none())
                .connect_timeout(CONNECT_TIMEOUT)
                .timeout(REQUEST_TIMEOUT)
                .https_only(https_only)
                .build()
                .expect("HTTP client with static config")
        };
        Self {
            client: client(true),
            loopback: client(false),
            upstream: Upstream::Auto,
            found: Discovery::new(REPROBE),
            upstream_key: None,
            not_in_cvm: std::sync::Once::new(),
            #[cfg(feature = "nvidia-gpu")]
            nras: Nras::from_env(),
        }
    }

    /// The HTTPS-only client, unless `url` is plain HTTP to loopback.
    fn client_for(&self, url: &str) -> &reqwest::Client {
        if url.starts_with("http://") && allowed(url) {
            &self.loopback
        } else {
            &self.client
        }
    }

    async fn upstream(&self) -> Upstream {
        if self.upstream != Upstream::Auto {
            return self.upstream.clone();
        }
        if !in_cvm() {
            self.not_in_cvm.call_once(|| {
                log::info!("collateral: not in a confidential VM, using the vendors")
            });
            return Upstream::Vendors;
        }
        self.found
            .upstream(Upstream::Vsock(HOST_CID, VSOCK_PORT), || async {
                #[cfg(target_os = "linux")]
                return tokio::time::timeout(
                    REQUEST_TIMEOUT,
                    vsock::get(HOST_CID, VSOCK_PORT, "health"),
                )
                .await
                .is_ok_and(|r| r.is_ok());
                #[cfg(not(target_os = "linux"))]
                false
            })
            .await
    }

    /// GET `url` and the issuer chain Intel PCS sends in a header, from the
    /// upstream, retrying once on network errors, 408, 429 and 5xx
    /// (honouring a short Retry-After), never on 404/410. A hung upstream
    /// costs about 10 s. Also says whether the answer is the vendor's own
    /// rather than a cache's.
    pub(crate) async fn fetch(
        &self,
        url: &str,
    ) -> (bool, Result<(Vec<u8>, Option<String>), Unavailable>) {
        let upstream = self.upstream().await;
        let fetched = Box::pin(self.fetch_from(&upstream, url)).await;
        let fetched = fetched.map_err(|mut e| {
            e.detail = format!("{} (from {upstream})", e.detail);
            e
        });
        (upstream.is_vendor(), fetched)
    }

    async fn fetch_from(
        &self,
        upstream: &Upstream,
        url: &str,
    ) -> Result<(Vec<u8>, Option<String>), Unavailable> {
        let err = match Box::pin(self.get_once(upstream, url)).await {
            Ok(raw) => return Ok(raw),
            Err(e) => e,
        };
        let wait = match (err.status, err.retry_after) {
            _ if err.not_found() => return Err(err),
            (_, Some(s)) if s > MAX_RETRY_AFTER => return Err(err),
            (_, Some(s)) => Duration::from_secs(s),
            (None | Some(408 | 429), None) => retry_delay(),
            (Some(s), None) if s >= 500 => retry_delay(),
            _ => return Err(err),
        };
        tokio::time::sleep(wait).await;
        Box::pin(self.get_once(upstream, url)).await
    }

    async fn get_once(
        &self,
        upstream: &Upstream,
        url: &str,
    ) -> Result<(Vec<u8>, Option<String>), Unavailable> {
        let path = url.strip_prefix("https://");
        let url = match (upstream, path) {
            (Upstream::Cache(base), Some(path)) => format!("{base}/{path}"),
            #[cfg(any(test, feature = "test-vendor"))]
            (Upstream::TestVendor(base), Some(path)) => format!("{base}/{path}"),
            #[cfg(target_os = "linux")]
            (Upstream::Vsock(cid, port), Some(path)) => {
                return tokio::time::timeout(
                    REQUEST_TIMEOUT,
                    Box::pin(vsock::get(*cid, *port, path)),
                )
                .await
                .unwrap_or_else(|_| Err(Unavailable::detail("host cache: timed out")));
            }
            _ => url.to_string(),
        };
        let unreachable = |e: reqwest::Error| Unavailable::detail(format!("unreachable ({e})"));
        let mut request = self.client_for(&url).get(url);
        if let (Upstream::Cache(_), Some(key)) = (upstream, &self.upstream_key) {
            request = request.bearer_auth(key);
        }
        let response = request.send().await.map_err(unreachable)?;
        let headers = response.headers().clone();
        check_status(response.status().as_u16(), &headers)?;
        let body = read_body(response).await?;
        Ok((body, issuer_chain(&headers)))
    }
}

/// The issuer chain Intel PCS sends in one of its headers, decoded.
fn issuer_chain(headers: &reqwest::header::HeaderMap) -> Option<String> {
    ISSUER_CHAIN_HEADERS
        .iter()
        .find_map(|h| headers.get(*h))
        .and_then(|v| v.to_str().ok())
        .map(percent_decode)
}

fn check_status(status: u16, headers: &reqwest::header::HeaderMap) -> Result<(), Unavailable> {
    let retry_after = headers
        .get(reqwest::header::RETRY_AFTER)
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.trim().parse::<u64>().ok());
    let detail = match (status, retry_after) {
        (200..=299, _) => return Ok(()),
        (404 | 410, _) => format!("not found (HTTP {status})"),
        (_, Some(s)) => format!("HTTP {status}, retry after {s}s"),
        _ => format!("HTTP {status}"),
    };
    Err(Unavailable {
        status: Some(status),
        retry_after,
        detail,
    })
}

async fn read_body(mut response: reqwest::Response) -> Result<Vec<u8>, Unavailable> {
    let too_large = || Unavailable::detail(format!("body exceeds {MAX_BODY} bytes"));
    if response
        .content_length()
        .is_some_and(|l| l > MAX_BODY as u64)
    {
        return Err(too_large());
    }
    let mut body = Vec::new();
    while let Some(chunk) = response
        .chunk()
        .await
        .map_err(|e| Unavailable::detail(format!("body: {e}")))?
    {
        if body.len() + chunk.len() > MAX_BODY {
            return Err(too_large());
        }
        body.extend_from_slice(&chunk);
    }
    Ok(body)
}

/// Intel PCS percent-encodes the PEM in its issuer-chain headers.
fn percent_decode(input: &str) -> String {
    let bytes = input.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        let hex = bytes
            .get(i + 1..i + 3)
            .and_then(|h| std::str::from_utf8(h).ok())
            .and_then(|h| u8::from_str_radix(h, 16).ok());
        match (bytes[i], hex) {
            (b'%', Some(b)) => {
                out.push(b);
                i += 3;
            }
            (b, _) => {
                out.push(b);
                i += 1;
            }
        }
    }
    String::from_utf8_lossy(&out).into_owned()
}

/// NVIDIA's remote attestation service. Its verdict is per evidence, so it
/// is called, not stored.
#[cfg(feature = "nvidia-gpu")]
pub(crate) struct Nras {
    pub(crate) gpu_url: String,
    pub(crate) switch_url: String,
    allow_hold_cert: bool,
    service_key: Option<String>,
}

#[cfg(feature = "nvidia-gpu")]
impl Nras {
    fn from_env() -> Self {
        Self::from_vars(|name| std::env::var(name).ok())
    }

    /// From these variables; an NRAS URL that is not `https` (or plain
    /// `http` on loopback) is ignored, so the service key never goes out in
    /// clear.
    fn from_vars(env: impl Fn(&str) -> Option<String>) -> Self {
        use crate::platforms::nvidia_gpu::provider::{NRAS_GPU_URL, NRAS_SWITCH_URL};
        let url = |name: &str, default: &str| match env(name) {
            Some(url) if allowed(&url) => url,
            Some(url) => {
                log::error!("ignoring {name}={url:?}: not https");
                default.into()
            }
            None => default.into(),
        };
        Self {
            gpu_url: url("NV_NRAS_GPU_URL", NRAS_GPU_URL),
            switch_url: url("NV_NRAS_SWITCH_URL", NRAS_SWITCH_URL),
            allow_hold_cert: env("NV_ALLOW_HOLD_CERT").as_deref() == Some("true"),
            service_key: env("NVIDIA_ATTESTATION_SERVICE_KEY"),
        }
    }
}

#[cfg(feature = "nvidia-gpu")]
impl Vendor {
    /// POST evidence to NRAS. 429 and 5xx are `CollateralUnavailable`; any
    /// other failure status is final.
    pub(crate) async fn nras_attest(
        &self,
        request: &crate::platforms::nvidia_gpu::provider::NrasRequest,
    ) -> crate::error::Result<Vec<u8>> {
        use crate::error::AttestationError;
        let url = match request.arch {
            crate::types::NvidiaGpuArch::Ls10 => &self.nras.switch_url,
            _ => &self.nras.gpu_url,
        };
        let mut req = self.client_for(url).post(url).json(request);
        if self.nras.allow_hold_cert {
            req = req.header(
                crate::platforms::nvidia_gpu::provider::HEADER_OCSP_ALLOW_CERT_HOLD,
                "true",
            );
        }
        if let Some(key) = &self.nras.service_key {
            req = req.header("Authorization", format!("Bearer {key}"));
        }
        let unavailable = |e: Unavailable| e.into_error("NRAS attestation");
        let response = req
            .send()
            .await
            .map_err(|e| unavailable(Unavailable::detail(format!("unreachable ({e})"))))?;
        let status = response.status();
        match check_status(status.as_u16(), response.headers()) {
            Ok(()) => {}
            Err(e) if status.is_server_error() || status.as_u16() == 429 => {
                return Err(unavailable(e))
            }
            Err(_) => {
                let body = read_body(response).await.unwrap_or_default();
                let preview = String::from_utf8_lossy(&body[..body.len().min(512)]).into_owned();
                return Err(AttestationError::NrasRequestFailed(format!(
                    "status {status}: {preview}"
                )));
            }
        }
        read_body(response).await.map_err(unavailable)
    }
}

/// HTTP to the host's cache over vsock.
#[cfg(target_os = "linux")]
mod vsock {
    use http_body_util::BodyExt;
    use tokio_vsock::{VsockAddr, VsockStream};

    use super::{check_status, issuer_chain, Unavailable, CONNECT_TIMEOUT, MAX_BODY};

    pub(super) async fn connect(cid: u32, port: u32) -> std::io::Result<VsockStream> {
        tokio::time::timeout(
            CONNECT_TIMEOUT,
            VsockStream::connect(VsockAddr::new(cid, port)),
        )
        .await
        .map_err(|_| std::io::ErrorKind::TimedOut)?
    }

    /// GET `/{path}` (vendor host, path and query) from the cache at
    /// `cid`:`port`.
    pub(super) async fn get(
        cid: u32,
        port: u32,
        path: &str,
    ) -> Result<(Vec<u8>, Option<String>), Unavailable> {
        let unreachable = |e: &dyn std::fmt::Display| {
            Unavailable::detail(format!("host cache unreachable ({e})"))
        };
        let stream = connect(cid, port).await.map_err(|e| unreachable(&e))?;
        let (mut sender, connection) =
            hyper::client::conn::http1::handshake(hyper_util::rt::TokioIo::new(stream))
                .await
                .map_err(|e| unreachable(&e))?;
        tokio::spawn(connection);
        let request = hyper::Request::get(format!("/{path}"))
            .header(hyper::header::HOST, "attestation-cache")
            .body(http_body_util::Empty::<hyper::body::Bytes>::new())
            .map_err(|e| unreachable(&e))?;
        let response = sender
            .send_request(request)
            .await
            .map_err(|e| unreachable(&e))?;
        check_status(response.status().as_u16(), response.headers())?;
        let chain = issuer_chain(response.headers());
        let body = http_body_util::Limited::new(response.into_body(), MAX_BODY)
            .collect()
            .await
            .map_err(|e| Unavailable::detail(format!("body: {e}")))?
            .to_bytes()
            .to_vec();
        Ok((body, chain))
    }
}

fn retry_delay() -> Duration {
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| d.subsec_nanos());
    Duration::from_millis(RETRY_DELAY_MS + u64::from(nanos) % RETRY_DELAY_MS)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn issuer_chain_headers_are_percent_decoded() {
        let encoded = "-----BEGIN%20CERTIFICATE-----%0AMIIB%2BzCC%0A-----END%20CERTIFICATE-----%0A";
        assert_eq!(
            percent_decode(encoded),
            "-----BEGIN CERTIFICATE-----\nMIIB+zCC\n-----END CERTIFICATE-----\n"
        );
    }

    #[tokio::test]
    async fn auto_probes_again_until_a_host_cache_answers_then_keeps_it() {
        use std::sync::atomic::{AtomicUsize, Ordering};
        let host = Upstream::Vsock(HOST_CID, VSOCK_PORT);
        let probes = AtomicUsize::new(0);
        let probe = |answers: bool| {
            probes.fetch_add(1, Ordering::SeqCst);
            async move { answers }
        };

        let waits = Discovery::new(Duration::from_secs(3600));
        for _ in 0..3 {
            assert_eq!(
                waits.upstream(host.clone(), || probe(false)).await,
                Upstream::Vendors
            );
        }
        assert_eq!(probes.swap(0, Ordering::SeqCst), 1);

        let found = Discovery::new(Duration::ZERO);
        assert_eq!(
            found.upstream(host.clone(), || probe(false)).await,
            Upstream::Vendors
        );
        assert_eq!(found.upstream(host.clone(), || probe(true)).await, host);
        // Found: kept, never back to the vendors, not probed again.
        assert_eq!(found.upstream(host.clone(), || probe(false)).await, host);
        assert_eq!(probes.load(Ordering::SeqCst), 2);
    }

    #[tokio::test]
    async fn plain_http_goes_out_only_to_loopback() {
        let v = Vendor::new();
        for url in ["http://192.0.2.1/x", "http://cache.example/x"] {
            let err = v.client_for(url).get(url).send().await.unwrap_err();
            assert!(err.is_builder(), "{url}: {err}");
        }
    }

    /// vsock loopback (CID 1) needs the vsock_loopback module, which the
    /// Linux Docker gate loads. Run explicitly with --ignored.
    #[cfg(target_os = "linux")]
    #[tokio::test]
    #[ignore = "requires Linux vsock_loopback; run explicitly in the Docker gate"]
    async fn the_vsock_client_reads_status_chain_and_caps_the_body() {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        use tokio_vsock::{VsockAddr, VsockListener};
        let listener = VsockListener::bind(VsockAddr::new(1, u32::MAX))
            .expect("vsock_loopback must be loaded for this gate");
        let port = listener.local_addr().unwrap().port();
        tokio::spawn(async move {
            while let Ok((mut sock, _)) = listener.accept().await {
                tokio::spawn(async move {
                    let mut buf = Vec::new();
                    while !buf.ends_with(b"\r\n\r\n") {
                        buf.push(sock.read_u8().await.unwrap());
                    }
                    let request = String::from_utf8(buf).unwrap();
                    let (status, header, body) = match request.split(' ').nth(1) {
                        Some("/health") => (200, "", b"ok".to_vec()),
                        Some("/chain") => {
                            (200, "TCB-Info-Issuer-Chain: a%20b\r\n", b"body".to_vec())
                        }
                        Some("/big") => (200, "", vec![0; MAX_BODY + 1]),
                        Some("/busy") => (503, "Retry-After: 7\r\n", Vec::new()),
                        _ => (404, "", Vec::new()),
                    };
                    let head = format!(
                        "HTTP/1.1 {status} X\r\nContent-Length: {}\r\n{header}Connection: close\r\n\r\n",
                        body.len()
                    );
                    let _ = sock.write_all(head.as_bytes()).await;
                    let _ = sock.write_all(&body).await;
                });
            }
        });
        if vsock::connect(1, port).await.is_err() {
            return;
        }
        assert!(vsock::get(1, port, "health").await.is_ok());
        assert_eq!(
            vsock::get(1, port, "chain").await.unwrap(),
            (b"body".to_vec(), Some("a b".to_string()))
        );
        assert_eq!(
            vsock::get(1, port, "missing").await.unwrap_err().status,
            Some(404)
        );
        let busy = vsock::get(1, port, "busy").await.unwrap_err();
        assert_eq!((busy.status, busy.retry_after), (Some(503), Some(7)));
        assert_eq!(vsock::get(1, port, "big").await.unwrap_err().status, None);
    }

    #[cfg(feature = "nvidia-gpu")]
    #[test]
    fn nras_urls_from_the_environment_must_be_https() {
        use crate::platforms::nvidia_gpu::provider::NRAS_GPU_URL;
        let nras = |url: &'static str| {
            Nras::from_vars(move |name| (name == "NV_NRAS_GPU_URL").then(|| url.to_string()))
                .gpu_url
        };
        assert_eq!(nras("http://nras.example/v3/attest/gpu"), NRAS_GPU_URL);
        assert_eq!(
            nras("https://nras.example/v3/attest/gpu"),
            "https://nras.example/v3/attest/gpu"
        );
        assert_eq!(nras("http://127.0.0.1:1/gpu"), "http://127.0.0.1:1/gpu");
    }

    #[test]
    fn an_upstream_cache_is_https_or_plain_http_on_loopback() {
        for good in [
            "https://cache.example",
            "https://10.0.0.1:8455/",
            "http://127.0.0.1:8455",
            "http://[::1]:8455",
            "http://localhost:8455",
        ] {
            assert!(
                matches!(Upstream::parse(good), Some(Upstream::Cache(_))),
                "{good}"
            );
        }
        assert_eq!(
            Upstream::parse("vsock://2:8455"),
            Some(Upstream::Vsock(2, 8455))
        );
        for bad in [
            "http://cache.example",
            "http://10.0.0.1:8455",
            "ftp://cache.example",
            "https://",
            "cache.example",
            "vsock://host",
            "vsock://8455",
            "https://cache.example/?x=1",
            "https://cache.example/#x",
            "https://user:secret@cache.example",
            "https://user@cache.example",
        ] {
            assert_eq!(Upstream::parse(bad), None, "{bad}");
        }
    }
}
