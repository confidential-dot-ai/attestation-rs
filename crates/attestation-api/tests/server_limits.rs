//! The listener's limits: a connection slow to send its headers is dropped,
//! and connections past `max_connections` wait.
use std::sync::Arc;
use std::time::{Duration, Instant};

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

use attestation_api::config::Config;
use attestation_api::server::{build_api_router, serve};
use attestation_api::AppState;

const HEALTH: &[u8] = b"GET /health HTTP/1.1\r\nHost: x\r\n\r\n";

async fn listen(max_connections: usize) -> std::net::SocketAddr {
    let state = AppState::new(
        Arc::new(Config::default()),
        None,
        Arc::new(attestation::Verifier::new(attestation::Context::offline())),
    );
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(serve(
        listener,
        build_api_router(state),
        max_connections,
        std::future::pending(),
    ));
    addr
}

#[tokio::test]
async fn a_connection_slow_to_send_its_headers_is_dropped() {
    let addr = listen(16).await;
    let mut sock = TcpStream::connect(addr).await.unwrap();
    sock.write_all(b"POST /verify HTTP/1.1\r\nHost: x\r\n")
        .await
        .unwrap();
    let started = Instant::now();
    let mut answer = Vec::new();
    let closed = tokio::time::timeout(Duration::from_secs(30), sock.read_to_end(&mut answer)).await;
    assert!(closed.is_ok(), "still open after 30 s");
    assert!(started.elapsed() < Duration::from_secs(15));
}

#[tokio::test]
async fn connections_past_the_limit_wait_for_one_to_close() {
    let addr = listen(1).await;
    let mut buf = [0; 64];
    let mut first = TcpStream::connect(addr).await.unwrap();
    first.write_all(HEALTH).await.unwrap();
    assert!(first.read(&mut buf).await.unwrap() > 0);
    let mut second = TcpStream::connect(addr).await.unwrap();
    second.write_all(HEALTH).await.unwrap();
    let waiting = tokio::time::timeout(Duration::from_millis(500), second.read(&mut buf)).await;
    assert!(waiting.is_err(), "served past the limit");
    drop(first);
    let n = tokio::time::timeout(Duration::from_secs(5), second.read(&mut buf))
        .await
        .unwrap()
        .unwrap();
    assert!(buf[..n].starts_with(b"HTTP/1.1 200"), "{:?}", &buf[..n]);
}
