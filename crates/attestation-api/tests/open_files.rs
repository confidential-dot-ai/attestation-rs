//! The service raises its soft open-files limit to the hard limit at start,
//! so that a launcher's low default (Docker's 1024) does not cap connections.
#![cfg(target_os = "linux")]

use std::process::{Child, Command};
use std::time::{Duration, Instant};

use rustix::process::{getrlimit, setrlimit, Resource, Rlimit};

/// The soft open-files limit of `child`, once it is not `from` or after 10 s.
fn soft_limit(child: &Child, from: &str) -> String {
    let deadline = Instant::now() + Duration::from_secs(10);
    loop {
        let limits = std::fs::read_to_string(format!("/proc/{}/limits", child.id())).unwrap();
        let line = limits
            .lines()
            .find(|l| l.starts_with("Max open files"))
            .unwrap();
        let soft = line.split_whitespace().nth(3).unwrap().to_string();
        if soft != from || Instant::now() > deadline {
            return soft;
        }
        std::thread::sleep(Duration::from_millis(50));
    }
}

#[test]
fn the_service_raises_its_open_files_limit() {
    // Children inherit this process's limits: lower the soft one.
    let limit = getrlimit(Resource::Nofile);
    let hard = limit.maximum.expect("a finite hard limit").to_string();
    setrlimit(
        Resource::Nofile,
        Rlimit {
            current: Some(64),
            ..limit
        },
    )
    .unwrap();

    // Control: a program that does not raise it keeps 64.
    let mut control = Command::new("sleep").arg("30").spawn().unwrap();
    let control_soft = soft_limit(&control, "");
    control.kill().unwrap();
    control.wait().unwrap();
    assert_eq!(control_soft, "64");

    let dir = tempfile::tempdir().unwrap();
    let config = dir.path().join("config.toml");
    std::fs::write(&config, "[server]\nbind = \"127.0.0.1:0\"\n").unwrap();
    let mut service = Command::new(env!("CARGO_BIN_EXE_attestation-api"))
        .arg("--config")
        .arg(&config)
        .spawn()
        .unwrap();
    let soft = soft_limit(&service, "64");
    service.kill().unwrap();
    service.wait().unwrap();
    assert_eq!(soft, hard);
}
