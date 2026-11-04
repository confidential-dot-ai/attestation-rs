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

fn proc_status_ids(key: &str) -> Option<Vec<u32>> {
    if !cfg!(target_os = "linux") {
        return None;
    }
    let status = std::fs::read_to_string("/proc/self/status").ok()?;
    let line = status.lines().find_map(|l| l.strip_prefix(key))?;
    Some(
        line.split_whitespace()
            .filter_map(|f| f.parse().ok())
            .collect(),
    )
}

/// A supplementary gid other than the effective gid, so a passing chgrp
/// assertion proves the chown happened. None where there is no such group
/// or std offers no way to read it; the chgrp assertions are then skipped.
fn other_gid() -> Option<u32> {
    let egid = *proc_status_ids("Gid:")?.get(1)?;
    proc_status_ids("Groups:")?.into_iter().find(|g| *g != egid)
}

fn is_root() -> bool {
    proc_status_ids("Uid:").is_some_and(|ids| ids.get(1) == Some(&0))
}

#[tokio::test]
async fn unix_socket_unreachable_is_refused() {
    use attestation_api::config::Bind;

    if is_root() {
        eprintln!("skipping: root can connect to any socket");
        return;
    }
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("api.sock");
    let other = std::os::unix::net::UnixListener::bind(&path).unwrap();
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o000)).unwrap();
    let target = Bind::Unix {
        path: path.clone(),
        mode: 0o660,
        group: None,
    };
    let err = bind(&target)
        .await
        .err()
        .expect("a socket the probe cannot reach must not be replaced");
    assert!(err.to_string().contains("probing"), "bind() = {err}");
    assert!(path.exists(), "the unreachable socket was removed");
    drop(other);
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

    let gid = other_gid();
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
