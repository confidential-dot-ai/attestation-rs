#![cfg(unix)]

use std::os::unix::fs::PermissionsExt;
use std::sync::Arc;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::UnixStream;

use attestation_api::config::{Config, ServerConfig};
use attestation_api::server::{bind, build_router, serve};
use attestation_api::AppState;

#[tokio::test]
async fn unix_socket_lifecycle() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("api.sock");
    let config = Config {
        server: ServerConfig {
            bind: format!("unix://{}", path.display()),
            socket_mode: Some("0660".to_string()),
            ..ServerConfig::default()
        },
        ..Config::default()
    };
    let target = config.server.bind().unwrap();

    std::fs::write(&path, "not a socket").unwrap();
    let err = bind(&target)
        .await
        .err()
        .expect("a regular file must not be replaced");
    assert!(err.to_string().contains("not a socket"), "bind() = {err}");
    assert_eq!(std::fs::read(&path).unwrap(), b"not a socket");
    std::fs::remove_file(&path).unwrap();

    drop(std::os::unix::net::UnixListener::bind(&path).unwrap());
    let listener = bind(&target).await.expect("a stale socket is replaced");
    let mode = std::fs::metadata(&path).unwrap().permissions().mode() & 0o777;
    assert_eq!(mode, 0o660, "socket mode = {mode:o}, want 660");

    let state = AppState {
        config: Arc::new(config),
        token_issuer: None,
        verifier: Arc::new(attestation::Verifier::new(attestation::Context::new())),
    };
    let (stop, stopped) = tokio::sync::oneshot::channel::<()>();
    let server = tokio::spawn(serve(listener, build_router(state), async {
        let _ = stopped.await;
    }));

    let mut stream = UnixStream::connect(&path).await.unwrap();
    stream
        .write_all(b"GET /health HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n")
        .await
        .unwrap();
    let mut response = String::new();
    stream.read_to_string(&mut response).await.unwrap();
    assert!(
        response.starts_with("HTTP/1.1 200"),
        "GET /health = {response:?}, want 200"
    );

    stop.send(()).unwrap();
    server.await.unwrap().unwrap();
    assert!(!path.exists(), "socket file remains after shutdown");
    let leftovers: Vec<_> = std::fs::read_dir(dir.path()).unwrap().collect();
    assert!(leftovers.is_empty(), "leftover files: {leftovers:?}");
}

/// The effective gid, which chown always accepts. None where std offers no
/// way to read it; the chgrp assertions are then skipped.
fn effective_gid() -> Option<u32> {
    if !cfg!(target_os = "linux") {
        return None;
    }
    let status = std::fs::read_to_string("/proc/self/status").ok()?;
    let gids = status.lines().find_map(|l| l.strip_prefix("Gid:"))?;
    gids.split_whitespace().nth(1)?.parse().ok()
}

#[tokio::test]
async fn unix_socket_group_and_replacement() {
    use attestation_api::config::Bind;
    use std::os::unix::fs::MetadataExt;

    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("api.sock");
    let missing = Bind::Unix {
        path: dir.path().join("missing/api.sock"),
        mode: 0o660,
        group: None,
    };
    assert!(bind(&missing).await.is_err(), "missing parent must fail");

    let gid = effective_gid();
    let target = Bind::Unix {
        path: path.clone(),
        mode: 0o600,
        group: gid,
    };
    let first = bind(&target).await.unwrap();
    let meta = std::fs::metadata(&path).unwrap();
    if let Some(gid) = gid {
        assert_eq!(meta.gid(), gid);
    }
    assert_eq!(meta.permissions().mode() & 0o777, 0o600);

    let err = bind(&target)
        .await
        .err()
        .expect("a live socket must not be replaced");
    assert!(err.to_string().contains("in use"), "second bind() = {err}");
    assert!(
        std::fs::read_dir(dir.path()).unwrap().count() == 1,
        "failed bind left files behind"
    );

    // Something else took over the path: dropping the old listener must not
    // remove the newcomer's socket.
    std::fs::remove_file(&path).unwrap();
    let newcomer = std::os::unix::net::UnixListener::bind(&path).unwrap();
    drop(first);
    assert!(
        path.exists(),
        "dropping a replaced listener removed the new socket"
    );
    drop(newcomer);
    std::fs::remove_file(&path).unwrap();
}
