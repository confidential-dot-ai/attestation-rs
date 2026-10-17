//! attestation-cache: keeps verified vendor collateral on disk and serves it
//! at `GET /{vendor host}/{vendor path}`, the vendor's bytes and headers, to
//! attesters, verifiers and other caches. Its upstream is the vendors or
//! another attestation-cache; every piece is verified against the roots
//! compiled into the attestation library before it is kept or served.

use std::collections::BTreeSet;
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
}

impl Default for Config {
    fn default() -> Self {
        Self {
            dir: "/var/lib/attestation-cache".into(),
            upstream: None,
            listen: "127.0.0.1:8455".into(),
            vsock_port: None,
            warm: Vec::new(),
        }
    }
}

impl Config {
    /// The collateral context this configuration describes.
    pub fn context(&self) -> anyhow::Result<Context> {
        let ctx = Context::new().with_cache_dir(&self.dir);
        Ok(match &self.upstream {
            Some(upstream) => ctx.with_upstream(upstream)?,
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

#[derive(Clone)]
pub struct Cache {
    ctx: Arc<Context>,
    /// Every URL served or warmed, looked at again on each sweep.
    known: Arc<Mutex<BTreeSet<String>>>,
}

impl Cache {
    pub fn new(ctx: Context, warm: &[String]) -> Self {
        Self {
            ctx: Arc::new(ctx),
            known: Arc::new(Mutex::new(warm.iter().cloned().collect())),
        }
    }

    /// The HTTP service.
    pub fn router(&self) -> axum::Router {
        axum::Router::new().fallback(serve).with_state(self.clone())
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
            tokio::time::sleep(SWEEP).await;
        }
    }
}

async fn serve(State(cache): State<Cache>, request: Request) -> Response {
    let mut response = if request.method() == Method::GET {
        answer(&cache, request.uri()).await
    } else {
        status(StatusCode::METHOD_NOT_ALLOWED, "GET only".into())
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
    match cache.ctx.store().serve(&url, cache.ctx.now()).await {
        Served::Piece((_, body, chain)) => {
            cache.known.lock().unwrap().insert(url.clone());
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
    axum::serve(Listener(listener), router).await
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
