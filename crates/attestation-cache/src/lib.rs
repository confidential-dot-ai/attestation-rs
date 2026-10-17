//! attestation-cache: keeps verified vendor collateral on disk and serves it
//! at `GET /{vendor host}/{vendor path}`, the vendor's bytes and headers, to
//! attesters, verifiers and other caches. Its upstream is the vendors or
//! another attestation-cache; every piece is verified against the roots
//! compiled into the attestation library before it is kept or served.

use std::collections::{BTreeSet, HashSet};
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use attestation::collateral::Served;
use attestation::Context;
use axum::body::Body;
use axum::extract::{Request, State};
use axum::http::{header, HeaderValue, Method, StatusCode};
use axum::response::Response;
use serde::Deserialize;

/// The operator's configuration file (TOML).
#[derive(Debug, Clone, Deserialize)]
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
/// more are answered 503 with [`BUSY_RETRY_AFTER`].
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
    /// refetched when its refresh time has come.
    pub async fn keep_fresh(self) {
        loop {
            let urls: Vec<String> = self.known.lock().unwrap().iter().cloned().collect();
            for url in urls {
                if let Served::Unavailable { detail, .. } =
                    self.ctx.store().serve(&url, self.ctx.now()).await
                {
                    tracing::warn!(%url, %detail, "could not refresh");
                }
            }
            self.set_ready();
            tokio::time::sleep(SWEEP).await;
        }
    }
}

async fn handle(State(cache): State<Cache>, request: Request) -> Response {
    let ready = cache.ready.load(std::sync::atomic::Ordering::Relaxed);
    let mut response = if request.method() != Method::GET {
        status(StatusCode::METHOD_NOT_ALLOWED, "GET only".into())
    } else if request.uri().path() == "/health" {
        status(StatusCode::OK, "ok".into())
    } else if request.uri().path() == "/ready" {
        match ready {
            true => status(StatusCode::OK, "ready".into()),
            false => status(StatusCode::SERVICE_UNAVAILABLE, "warming up".into()),
        }
    } else if !authorized(&cache.keys, request.headers()) {
        status(StatusCode::UNAUTHORIZED, "a bearer key is required".into())
    } else {
        answer(&cache, request.uri()).await
    };
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

async fn answer(cache: &Cache, uri: &axum::http::Uri) -> Response {
    let url = match uri.query() {
        Some(query) => format!("https:/{}?{query}", uri.path()),
        None => format!("https:/{}", uri.path()),
    };
    let store = cache.ctx.store();
    let _fetching = if store.holds(&url) {
        None
    } else {
        let mut fetching = cache.cold.lock().unwrap();
        if fetching.len() >= MAX_COLD && !fetching.contains(&url) {
            let mut response = status(StatusCode::SERVICE_UNAVAILABLE, "busy".into());
            response
                .headers_mut()
                .insert(header::RETRY_AFTER, HeaderValue::from(BUSY_RETRY_AFTER));
            return response;
        }
        fetching.insert(url.clone());
        Some(Fetching(&cache.cold, url.clone()))
    };
    match store.serve(&url, cache.ctx.now()).await {
        Served::Piece((_, body, chain), shared) => {
            cache.set_ready();
            let mut known = cache.known.lock().unwrap();
            if shared && known.len() < MAX_KNOWN {
                known.insert(url.clone());
            }
            drop(known);
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
            response
        }
        Served::NotPublished(why) => status(StatusCode::NOT_FOUND, why),
        Served::Unknown => status(StatusCode::NOT_FOUND, "not a collateral URL".into()),
        Served::Refused(why) => status(StatusCode::BAD_GATEWAY, why),
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
    }
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
        found | same(key.as_bytes(), sent.as_bytes())
    })
}

/// `a == b` in time that depends only on the lengths.
fn same(a: &[u8], b: &[u8]) -> bool {
    a.len() == b.len() && a.iter().zip(b).fold(0u8, |d, (x, y)| d | (x ^ y)) == 0
}

/// A URL in [`Cache::cold`] until dropped.
struct Fetching<'a>(&'a Mutex<HashSet<String>>, String);

impl Drop for Fetching<'_> {
    fn drop(&mut self) {
        self.0.lock().unwrap().remove(&self.1);
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
    use super::Config;

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
