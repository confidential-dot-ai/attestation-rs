//! attestation-cache: keeps verified vendor collateral on disk and serves it
//! at `GET /{vendor host}/{vendor path}`, the vendor's bytes and headers, to
//! attesters, verifiers and other caches. Its upstream is the vendors or
//! another attestation-cache; every piece is verified against the roots
//! compiled into the attestation library before it is kept or served.

use std::collections::{BTreeSet, HashSet};
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use attestation::collateral::{Served, Source};
use attestation::Context;
use axum::body::Body;
use axum::extract::{Request, State};
use axum::http::{header, HeaderValue, Method, StatusCode};
use axum::response::Response;
use serde::Deserialize;

/// The operator's configuration file (TOML).
#[derive(Clone, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct Config {
    /// Where verified collateral is kept across restarts.
    pub dir: PathBuf,
    /// Another attestation-cache to fetch from (`https://`, `http://` on
    /// loopback, or `vsock://CID:PORT`); absent: the vendors.
    pub upstream: Option<String>,
    /// HTTP listen address.
    pub listen: String,
    /// Also listen on this vsock port, for the guests of this host (Linux).
    pub vsock_port: Option<u32>,
    /// Vendor URLs fetched at start and kept fresh.
    pub warm: Vec<String>,
    /// The bearer key to send to `upstream` when it asks for one.
    pub upstream_key: Option<String>,
    /// Bearer keys a client must send (`Authorization: Bearer KEY`); empty:
    /// anyone may fetch. `/health` and `/ready` are always open.
    pub keys: Vec<String>,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            dir: "/var/lib/attestation-cache".into(),
            upstream: None,
            listen: "127.0.0.1:8455".into(),
            vsock_port: None,
            warm: Vec::new(),
            keys: Vec::new(),
            upstream_key: None,
        }
    }
}

impl Config {
    /// The collateral context this configuration describes.
    pub fn context(&self) -> anyhow::Result<Context> {
        let ctx = Context::new().with_cache_dir(&self.dir);
        Ok(match &self.upstream {
            Some(upstream) => ctx
                .with_upstream(upstream)?
                .with_upstream_key(self.upstream_key.clone()),
            None => ctx.with_vendors(),
        })
    }
}

/// The headers Intel PCS sends issuer chains in, by the path they come with.
const ISSUER_CHAIN_HEADERS: [(&str, &str); 3] = [
    ("/tcb?", "TCB-Info-Issuer-Chain"),
    ("/qe/identity", "SGX-Enclave-Identity-Issuer-Chain"),
    ("/pckcrl?", "SGX-PCK-CRL-Issuer-Chain"),
];

/// How often pieces are looked at again; each is refetched when its own
/// refresh time has come.
const SWEEP: Duration = Duration::from_secs(600);
/// At most this many shared pieces served are kept fresh, besides `warm`.
const MAX_KNOWN: usize = 1024;
/// At most this many pieces not in memory are fetched at once; requests for
/// more are answered 503 with `Retry-After: 5`.
pub const MAX_COLD: usize = 16;
const BUSY_RETRY_AFTER: u32 = 5;
/// A connection may take this long to send its request headers, and stay
/// open this long in all.
const HEADER_TIMEOUT: Duration = Duration::from_secs(10);
const CONNECTION_TIMEOUT: Duration = Duration::from_secs(60);

#[derive(Clone)]
pub struct Cache {
    ctx: Arc<Context>,
    /// Warmed URLs and shared pieces served, looked at again on each sweep.
    known: Arc<Mutex<BTreeSet<String>>>,
    /// URLs not in memory being fetched now.
    cold: Arc<Mutex<HashSet<String>>>,
    keys: Arc<Vec<String>>,
    /// The warm pieces were looked at once, or a piece was served.
    ready: Arc<std::sync::atomic::AtomicBool>,
}

impl Cache {
    pub fn new(ctx: Context, warm: &[String]) -> Self {
        Self {
            ctx: Arc::new(ctx),
            known: Arc::new(Mutex::new(warm.iter().cloned().collect())),
            cold: Arc::default(),
            keys: Arc::default(),
            ready: Arc::default(),
        }
    }

    /// Answer only clients that send one of `keys` (none: everyone).
    pub fn with_keys(mut self, keys: Vec<String>) -> Self {
        self.keys = Arc::new(keys);
        self
    }

    fn set_ready(&self) {
        self.ready.store(true, std::sync::atomic::Ordering::Relaxed);
    }

    /// The HTTP service.
    pub fn router(&self) -> axum::Router {
        axum::Router::new()
            .fallback(handle)
            .with_state(self.clone())
    }

    /// Fetch every known piece now and then on every sweep; each is
    /// refetched when its refresh time has come. Ready once a piece was
    /// served, or there is nothing to warm.
    pub async fn keep_fresh(self) {
        loop {
            let urls: Vec<String> = lock(&self.known).iter().cloned().collect();
            let mut any = urls.is_empty();
            for url in urls {
                match self.ctx.store().serve(&url, self.ctx.now()).await {
                    Served::Piece(..) => any = true,
                    Served::Unavailable { detail, .. } => {
                        tracing::warn!(%url, %detail, "could not refresh")
                    }
                    _ => {}
                }
            }
            if any {
                self.set_ready();
            }
            tokio::time::sleep(SWEEP).await;
        }
    }

    /// Keep `url` fresh on every sweep, up to [`MAX_KNOWN`] pieces.
    fn remember(&self, url: &str) {
        let mut known = lock(&self.known);
        if known.len() < MAX_KNOWN {
            known.insert(url.to_string());
        }
    }
}

fn lock<T>(mutex: &Mutex<T>) -> std::sync::MutexGuard<'_, T> {
    mutex.lock().unwrap_or_else(|e| e.into_inner())
}

async fn handle(State(cache): State<Cache>, request: Request) -> Response {
    let started = std::time::Instant::now();
    let ready = cache.ready.load(std::sync::atomic::Ordering::Relaxed);
    let path = request.uri().path();
    let mut from = None;
    let mut response = if request.method() == Method::OPTIONS {
        let mut response = status(StatusCode::NO_CONTENT, String::new());
        response.headers_mut().insert(
            header::ACCESS_CONTROL_ALLOW_METHODS,
            HeaderValue::from_static("GET"),
        );
        response.headers_mut().insert(
            header::ACCESS_CONTROL_ALLOW_HEADERS,
            HeaderValue::from_static("Authorization"),
        );
        response
    } else if request.method() != Method::GET {
        status(StatusCode::METHOD_NOT_ALLOWED, "GET only".into())
    } else if path == "/health" {
        status(StatusCode::OK, "ok".into())
    } else if path == "/ready" {
        match ready {
            true => status(StatusCode::OK, "ready".into()),
            false => status(StatusCode::SERVICE_UNAVAILABLE, "warming up".into()),
        }
    } else if !authorized(&cache.keys, request.headers()) {
        tracing::warn!(target: "attestation_cache::request", path = %request.uri(), "no valid bearer key");
        status(StatusCode::UNAUTHORIZED, "a bearer key is required".into())
    } else {
        let (response, source) = answer(&cache, request.uri()).await;
        from = source;
        response
    };
    tracing::info!(
        target: "attestation_cache::request",
        method = %request.method(),
        path = %request.uri(),
        status = response.status().as_u16(),
        from = from.map(|f| f.to_string()),
        ms = started.elapsed().as_millis() as u64,
    );
    let headers = response.headers_mut();
    headers.insert(
        header::ACCESS_CONTROL_ALLOW_ORIGIN,
        HeaderValue::from_static("*"),
    );
    headers.insert(
        header::ACCESS_CONTROL_EXPOSE_HEADERS,
        HeaderValue::from_static(
            "TCB-Info-Issuer-Chain, SGX-Enclave-Identity-Issuer-Chain, SGX-PCK-CRL-Issuer-Chain",
        ),
    );
    response
}

/// The answer for a vendor URL, and where the piece came from when served.
async fn answer(cache: &Cache, uri: &axum::http::Uri) -> (Response, Option<Source>) {
    let url = match uri.query() {
        Some(query) => format!("https:/{}?{query}", uri.path()),
        None => format!("https:/{}", uri.path()),
    };
    let store = cache.ctx.store();
    let _fetching = if store.holds(&url) {
        None
    } else {
        let mut fetching = lock(&cache.cold);
        if fetching.len() >= MAX_COLD && !fetching.contains(&url) {
            let mut response = status(StatusCode::SERVICE_UNAVAILABLE, "busy".into());
            response
                .headers_mut()
                .insert(header::RETRY_AFTER, HeaderValue::from(BUSY_RETRY_AFTER));
            return (response, None);
        }
        // A second request for a URL being fetched waits for that fetch.
        fetching
            .insert(url.clone())
            .then(|| Fetching(&cache.cold, url.clone()))
    };
    let response = match store.serve(&url, cache.ctx.now()).await {
        Served::Piece((_, body, chain), shared, from) => {
            cache.set_ready();
            if shared {
                cache.remember(&url);
            }
            let mut response = Response::new(Body::from(body));
            let name = ISSUER_CHAIN_HEADERS
                .iter()
                .find(|(path, _)| url.contains(path))
                .map(|(_, name)| *name);
            if let (Some(name), Some(chain)) = (name, chain) {
                let value = HeaderValue::from_str(&percent_encode(&chain))
                    .expect("percent-encoded text is a header value");
                response.headers_mut().insert(name, value);
            }
            return (response, Some(from));
        }
        Served::NotPublished(why) => status(StatusCode::NOT_FOUND, why),
        Served::Unknown => status(StatusCode::NOT_FOUND, "not a collateral URL".into()),
        Served::Refused(why) => {
            tracing::warn!(%url, %why, "refused");
            status(StatusCode::BAD_GATEWAY, why)
        }
        Served::Unavailable {
            retry_after,
            detail,
        } => {
            let mut response = status(StatusCode::SERVICE_UNAVAILABLE, detail);
            if let Some(seconds) = retry_after {
                response
                    .headers_mut()
                    .insert(header::RETRY_AFTER, HeaderValue::from(seconds));
            }
            response
        }
    };
    (response, None)
}

/// Whether the request carries one of `keys`, or no key is needed.
fn authorized(keys: &[String], headers: &axum::http::HeaderMap) -> bool {
    if keys.is_empty() {
        return true;
    }
    let sent = headers
        .get(header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.strip_prefix("Bearer "))
        .unwrap_or("");
    keys.iter().fold(false, |found, key| {
        found | attestation::utils::constant_time_eq(key.as_bytes(), sent.as_bytes())
    })
}

/// A URL in [`Cache::cold`] until dropped.
struct Fetching<'a>(&'a Mutex<HashSet<String>>, String);

impl Drop for Fetching<'_> {
    fn drop(&mut self) {
        lock(self.0).remove(&self.1);
    }
}

fn status(code: StatusCode, detail: String) -> Response {
    let mut response = Response::new(Body::from(detail));
    *response.status_mut() = code;
    response
}

/// As Intel PCS encodes PEM in its issuer-chain headers.
fn percent_encode(text: &str) -> String {
    text.bytes()
        .map(|b| match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'.' | b'_' | b'~' => {
                (b as char).to_string()
            }
            _ => format!("%{b:02X}"),
        })
        .collect()
}

/// Serve `router` on `listener`, dropping connections that are slow to send
/// their headers or open too long.
pub async fn serve<L: axum::serve::Listener>(mut listener: L, router: axum::Router) {
    use hyper_util::rt::{TokioIo, TokioTimer};
    loop {
        let (io, _) = listener.accept().await;
        let service = hyper_util::service::TowerToHyperService::new(router.clone());
        tokio::spawn(async move {
            let connection = hyper::server::conn::http1::Builder::new()
                .timer(TokioTimer::new())
                .header_read_timeout(HEADER_TIMEOUT)
                .serve_connection(TokioIo::new(io), service);
            let _ = tokio::time::timeout(CONNECTION_TIMEOUT, connection).await;
        });
    }
}

/// Serve `router` to the guests of this host on vsock `port`.
#[cfg(target_os = "linux")]
pub async fn serve_vsock(router: axum::Router, port: u32) -> std::io::Result<()> {
    use tokio_vsock::{VsockAddr, VsockListener, VMADDR_CID_ANY};

    struct Listener(VsockListener);

    impl axum::serve::Listener for Listener {
        type Io = tokio_vsock::VsockStream;
        type Addr = VsockAddr;

        async fn accept(&mut self) -> (Self::Io, Self::Addr) {
            loop {
                match self.0.accept().await {
                    Ok(accepted) => return accepted,
                    Err(e) => {
                        tracing::warn!(%e, "vsock accept");
                        tokio::time::sleep(Duration::from_millis(100)).await;
                    }
                }
            }
        }

        fn local_addr(&self) -> std::io::Result<Self::Addr> {
            self.0.local_addr()
        }
    }

    let listener = VsockListener::bind(VsockAddr::new(VMADDR_CID_ANY, port))?;
    serve(Listener(listener), router).await;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn at_most_max_known_pieces_are_kept_fresh() {
        let cache = Cache::new(Context::offline(), &[]);
        for i in 0..MAX_KNOWN + 10 {
            cache.remember(&format!("https://example/{i}"));
        }
        assert_eq!(lock(&cache.known).len(), MAX_KNOWN);
    }

    #[test]
    fn the_example_config_loads_and_unknown_keys_are_refused() {
        let example = include_str!("../config.example.toml");
        let config: Config = toml::from_str(example).unwrap();
        assert_eq!(config.dir, Config::default().dir);
        assert!(config.context().is_ok());
        assert!(toml::from_str::<Config>("upstrem = \"https://x\"").is_err());
        let insecure: Config = toml::from_str("upstream = \"http://cache.example\"").unwrap();
        assert!(insecure.context().is_err());
    }
}
