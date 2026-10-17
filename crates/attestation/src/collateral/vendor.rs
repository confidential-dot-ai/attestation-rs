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
    /// The host's cache at [`VSOCK_PORT`] when it accepts a connection the
    /// first time collateral is fetched, else the vendors.
    Auto,
}

/// The vsock port a host's attestation-cache listens on, found by guests
/// without configuration.
pub const VSOCK_PORT: u32 = 8455;
/// The host, as a guest addresses it over vsock.
#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
const HOST_CID: u32 = 2;

impl Upstream {
    /// `vsock://CID:PORT`, or a cache base URL: `https://`, or plain
    /// `http://` only to a loopback address.
    pub(crate) fn parse(url: &str) -> Option<Self> {
        if let Some(address) = url.strip_prefix("vsock://") {
            let (cid, port) = address.split_once(':')?;
            return Some(Upstream::Vsock(cid.parse().ok()?, port.parse().ok()?));
        }
        allowed(url).then(|| Upstream::Cache(url.trim_end_matches('/').to_string()))
    }
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
    client: reqwest::Client,
    pub(crate) upstream: Upstream,
    /// What [`Upstream::Auto`] found.
    found: tokio::sync::OnceCell<Upstream>,
    #[cfg(feature = "nvidia-gpu")]
    pub(crate) nras: Nras,
}

impl Vendor {
    pub(crate) fn new() -> Self {
        Self {
            client: reqwest::Client::builder()
                .redirect(reqwest::redirect::Policy::none())
                .connect_timeout(CONNECT_TIMEOUT)
                .timeout(REQUEST_TIMEOUT)
                .build()
                .expect("HTTP client with static config"),
            upstream: Upstream::Auto,
            found: tokio::sync::OnceCell::new(),
            #[cfg(feature = "nvidia-gpu")]
            nras: Nras::from_env(),
        }
    }

    async fn upstream(&self) -> &Upstream {
        if self.upstream != Upstream::Auto {
            return &self.upstream;
        }
        self.found
            .get_or_init(|| async {
                #[cfg(target_os = "linux")]
                if vsock::connect(HOST_CID, VSOCK_PORT).await.is_ok() {
                    log::info!("collateral: using the host cache at vsock port {VSOCK_PORT}");
                    return Upstream::Vsock(HOST_CID, VSOCK_PORT);
                }
                Upstream::Vendors
            })
            .await
    }

    /// GET `url` and the issuer chain Intel PCS sends in a header, from the
    /// upstream, retrying once on network errors, 408, 429 and 5xx
    /// (honouring a short Retry-After), never on 404/410. A hung upstream
    /// costs about 10 s.
    pub(crate) async fn fetch(&self, url: &str) -> Result<(Vec<u8>, Option<String>), Unavailable> {
        let err = match Box::pin(self.get_once(url)).await {
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
        Box::pin(self.get_once(url)).await
    }

    async fn get_once(&self, url: &str) -> Result<(Vec<u8>, Option<String>), Unavailable> {
        let path = url.strip_prefix("https://");
        let url = match (self.upstream().await, path) {
            (Upstream::Cache(base), Some(path)) => format!("{base}/{path}"),
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
        let response = self.client.get(url).send().await.map_err(unreachable)?;
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
        use crate::platforms::nvidia_gpu::provider::{NRAS_GPU_URL, NRAS_SWITCH_URL};
        let env = |name: &str| std::env::var(name).ok();
        Self {
            gpu_url: env("NV_NRAS_GPU_URL").unwrap_or_else(|| NRAS_GPU_URL.into()),
            switch_url: env("NV_NRAS_SWITCH_URL").unwrap_or_else(|| NRAS_SWITCH_URL.into()),
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
        let mut req = self.client.post(url).json(request);
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
        let request = http::Request::get(format!("/{path}"))
            .header(http::header::HOST, "attestation-cache")
            .body(http_body_util::Empty::<bytes::Bytes>::new())
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
        ] {
            assert_eq!(Upstream::parse(bad), None, "{bad}");
        }
    }
}
