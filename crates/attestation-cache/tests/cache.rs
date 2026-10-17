//! The cache as its clients see it: vendor bytes and headers at the vendor's
//! paths, one upstream fetch per piece, chained caches, and copies kept
//! across an upstream outage and a restart.

use std::sync::Arc;
use std::time::Duration;

use attestation::Context;
use attestation_cache::Cache;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

const DATA: &str = concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../attestation/test_data/collateral/2026-10-14/"
);
/// 2026-10-16T00:00:00Z: the fixtures are current.
const NOW: i64 = 1_792_108_800;
const TCB_INFO: &str = "/api.trustedservices.intel.com/tdx/certification/v4/tcb?fmspc=70a06d070000";
const AMD_CRL: &str = "/kdsintf.amd.com/vcek/v1/Genoa/crl";

fn read(file: &str) -> Vec<u8> {
    std::fs::read(format!("{DATA}{file}")).unwrap()
}

fn chain() -> String {
    String::from_utf8(read("tcb_signing_chain.pem")).unwrap()
}

/// A vendor on loopback serving the TCB Info and the Genoa CRL at
/// `/{host}/{path}`, after `delay`, counting requests per path.
struct Vendor {
    base: String,
    hits: Arc<std::sync::Mutex<Vec<String>>>,
}

impl Vendor {
    fn hits(&self, path: &str) -> usize {
        self.hits
            .lock()
            .unwrap()
            .iter()
            .filter(|p| *p == path)
            .count()
    }
}

async fn vendor(delay: Duration) -> Vendor {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let base = format!("http://{}", listener.local_addr().unwrap());
    let hits = Arc::new(std::sync::Mutex::new(Vec::new()));
    let counter = hits.clone();
    tokio::spawn(async move {
        loop {
            let (mut sock, _) = listener.accept().await.unwrap();
            let counter = counter.clone();
            tokio::spawn(async move {
                let mut buf = vec![0; 8192];
                let n = sock.read(&mut buf).await.unwrap_or(0);
                let request = String::from_utf8_lossy(&buf[..n]).to_string();
                let path = request.split(' ').nth(1).unwrap_or("").to_string();
                counter.lock().unwrap().push(path.clone());
                tokio::time::sleep(delay).await;
                let (status, headers, body) = if path == TCB_INFO {
                    let encoded = chain().replace('\n', "%0A").replace(' ', "%20");
                    (
                        200,
                        format!("TCB-Info-Issuer-Chain: {encoded}\r\n"),
                        read("tcb_info_70a06d070000.json"),
                    )
                } else if path == AMD_CRL {
                    (200, String::new(), read("amd_crl_genoa.der"))
                } else {
                    (404, String::new(), Vec::new())
                };
                let head = format!(
                    "HTTP/1.1 {status} X\r\nContent-Length: {}\r\nConnection: close\r\n{headers}\r\n",
                    body.len()
                );
                let _ = sock.write_all(head.as_bytes()).await;
                let _ = sock.write_all(&body).await;
            });
        }
    });
    Vendor { base, hits }
}

/// A running cache over `dir` fetching from `upstream`, at [`NOW`] or `at`.
async fn cache(dir: &std::path::Path, upstream: &str, at: i64) -> String {
    let ctx = Context::new()
        .with_cache_dir(dir)
        .with_upstream(upstream)
        .unwrap()
        .at(at)
        .unwrap();
    let router = Cache::new(ctx, &[]).router();
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let base = format!("http://{}", listener.local_addr().unwrap());
    tokio::spawn(async move { axum::serve(listener, router).await.unwrap() });
    base
}

async fn get(base: &str, path: &str) -> reqwest::Response {
    reqwest::get(format!("{base}{path}")).await.unwrap()
}

/// An upstream nothing listens on.
async fn dead_upstream() -> String {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let base = format!("http://{}", listener.local_addr().unwrap());
    drop(listener);
    base
}

#[tokio::test]
async fn it_serves_the_vendors_bytes_and_issuer_chain_to_any_origin() {
    let v = vendor(Duration::ZERO).await;
    let dir = tempfile::tempdir().unwrap();
    let cache = cache(dir.path(), &v.base, NOW).await;

    let response = get(&cache, TCB_INFO).await;
    assert_eq!(response.status(), 200);
    let headers = response.headers().clone();
    assert_eq!(headers["access-control-allow-origin"], "*");
    let exposed = headers["access-control-expose-headers"].to_str().unwrap();
    for name in [
        "TCB-Info-Issuer-Chain",
        "SGX-Enclave-Identity-Issuer-Chain",
        "SGX-PCK-CRL-Issuer-Chain",
    ] {
        assert!(exposed.contains(name));
    }
    let header = headers["tcb-info-issuer-chain"].to_str().unwrap();
    assert_eq!(decode(header), chain());
    assert_eq!(
        response.bytes().await.unwrap().as_ref(),
        read("tcb_info_70a06d070000.json")
    );

    let crl = get(&cache, AMD_CRL).await;
    assert_eq!(crl.status(), 200);
    assert_eq!(
        crl.bytes().await.unwrap().as_ref(),
        read("amd_crl_genoa.der")
    );

    let unknown = get(&cache, "/example.com/anything").await;
    assert_eq!(unknown.status(), 404);
    assert_eq!(unknown.headers()["access-control-allow-origin"], "*");
}

fn decode(header: &str) -> String {
    let mut out = Vec::new();
    let bytes = header.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'%' {
            out.push(u8::from_str_radix(&header[i + 1..i + 3], 16).unwrap());
            i += 3;
        } else {
            out.push(bytes[i]);
            i += 1;
        }
    }
    String::from_utf8(out).unwrap()
}

#[tokio::test]
async fn a_host_cache_chained_to_a_site_cache_fetches_each_piece_once_for_20_cold_clients() {
    let v = vendor(Duration::from_millis(200)).await;
    let (site_dir, host_dir) = (tempfile::tempdir().unwrap(), tempfile::tempdir().unwrap());
    let site = cache(site_dir.path(), &v.base, NOW).await;
    let host = cache(host_dir.path(), &site, NOW).await;

    let clients = (0..20).flat_map(|_| {
        [TCB_INFO, AMD_CRL].map(|path| {
            let host = host.clone();
            tokio::spawn(async move { get(&host, path).await.status() })
        })
    });
    for client in clients.collect::<Vec<_>>() {
        assert_eq!(client.await.unwrap(), 200);
    }
    assert_eq!((v.hits(TCB_INFO), v.hits(AMD_CRL)), (1, 1));
}

#[tokio::test]
async fn after_a_restart_with_the_upstream_down_the_disk_copy_is_served() {
    let v = vendor(Duration::ZERO).await;
    let dir = tempfile::tempdir().unwrap();
    let first = cache(dir.path(), &v.base, NOW).await;
    let fetched = get(&first, TCB_INFO).await.bytes().await.unwrap();

    let down = dead_upstream().await;
    let restarted = cache(dir.path(), &down, NOW).await;
    let response = get(&restarted, TCB_INFO).await;
    assert_eq!(response.status(), 200);
    assert!(response.headers().contains_key("tcb-info-issuer-chain"));
    assert_eq!(response.bytes().await.unwrap(), fetched);
    assert_eq!(v.hits(TCB_INFO), 1);

    // Past its nextUpdate the cache asks the upstream again; it is down, so
    // the last good copy is served.
    let late = cache(dir.path(), &down, NOW + 40 * 86_400).await;
    let response = get(&late, TCB_INFO).await;
    assert_eq!(response.status(), 200);
    assert_eq!(response.bytes().await.unwrap(), fetched);

    // Nothing kept and the upstream down: unavailable.
    let empty = tempfile::tempdir().unwrap();
    let cold = cache(empty.path(), &down, NOW).await;
    assert_eq!(get(&cold, AMD_CRL).await.status(), 503);
}

#[tokio::test]
async fn what_the_upstream_does_not_publish_is_404() {
    let v = vendor(Duration::ZERO).await;
    let dir = tempfile::tempdir().unwrap();
    let cache = cache(dir.path(), &v.base, NOW).await;
    let response = get(&cache, "/kdsintf.amd.com/vcek/v1/Milan/crl").await;
    assert_eq!(response.status(), 404);
}
