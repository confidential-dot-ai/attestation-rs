//! Load tester for the attestation service.
//!
//! Measures throughput and latency for the `/attest` and `/verify` endpoints
//! under controlled request rates. Intended to run inside the same VM as the
//! service (localhost) to avoid network overhead skewing results.
//!
//! Usage:
//!   `cargo run --release --bin loadtest -- [OPTIONS]`
//!
//! Examples:
//!   # Verify at 1000 RPS for 10s
//!   loadtest --endpoint verify --rps 1000 --duration 10
//!
//!   # Attest at 500 RPS for 5s
//!   loadtest --endpoint attest --rps 500 --duration 5
//!
//!   # Both endpoints sequentially
//!   loadtest --endpoint both --rps 200 --duration 10

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use clap::{Parser, ValueEnum};
use reqwest::Client;
use serde_json::{json, Value};
use tokio::sync::{Mutex, Semaphore};
use tokio::time;

#[derive(Parser)]
#[command(name = "loadtest", about = "Attestation service load tester")]
struct Cli {
    /// Service base URL.
    #[arg(long, default_value = "http://127.0.0.1:8400")]
    url: String,

    /// Target requests per second.
    #[arg(long, default_value_t = 100)]
    rps: u64,

    /// Test duration in seconds.
    #[arg(long, default_value_t = 10)]
    duration: u64,

    /// Which endpoint to benchmark.
    #[arg(long, default_value = "verify")]
    endpoint: Endpoint,

    /// Max concurrent in-flight requests. Defaults to rps * 2.
    #[arg(long)]
    concurrency: Option<u64>,

    /// Send `allow_debug = true` in the verify policy so debug-mode TEEs
    /// are accepted. Only enable when load-testing against a debug VM.
    #[arg(long)]
    allow_debug: bool,
}

#[derive(Clone, ValueEnum)]
enum Endpoint {
    Verify,
    Attest,
    Both,
}

#[derive(Clone)]
struct Stats {
    ok: Arc<AtomicU64>,
    err: Arc<AtomicU64>,
    latencies_us: Arc<Mutex<Vec<u64>>>,
}

impl Stats {
    fn new() -> Self {
        Self {
            ok: Arc::new(AtomicU64::new(0)),
            err: Arc::new(AtomicU64::new(0)),
            latencies_us: Arc::new(Mutex::new(Vec::new())),
        }
    }

    async fn record(&self, ok: bool, latency: Duration) {
        if ok {
            self.ok.fetch_add(1, Ordering::Relaxed);
        } else {
            self.err.fetch_add(1, Ordering::Relaxed);
        }
        self.latencies_us
            .lock()
            .await
            .push(latency.as_micros() as u64);
    }

    async fn report(&self, label: &str, elapsed: Duration) {
        let ok = self.ok.load(Ordering::Relaxed);
        let err = self.err.load(Ordering::Relaxed);
        let total = ok + err;
        let rps = total as f64 / elapsed.as_secs_f64();

        let mut lats = self.latencies_us.lock().await;
        lats.sort_unstable();

        let p = |pct: f64| -> f64 {
            if lats.is_empty() {
                return 0.0;
            }
            let idx = ((pct / 100.0) * lats.len() as f64) as usize;
            let idx = idx.min(lats.len() - 1);
            lats[idx] as f64 / 1000.0
        };

        let avg = if lats.is_empty() {
            0.0
        } else {
            lats.iter().sum::<u64>() as f64 / lats.len() as f64 / 1000.0
        };

        println!("\n=== {label} Results ===");
        println!(
            "  Total:    {total} requests in {:.1}s",
            elapsed.as_secs_f64()
        );
        println!("  OK:       {ok}  Errors: {err}");
        println!("  RPS:      {rps:.1} req/s");
        println!("  Latency:");
        println!("    avg:    {avg:.1} ms");
        println!("    p50:    {:.1} ms", p(50.0));
        println!("    p90:    {:.1} ms", p(90.0));
        println!("    p95:    {:.1} ms", p(95.0));
        println!("    p99:    {:.1} ms", p(99.0));
        println!("    max:    {:.1} ms", p(100.0));
    }
}

/// Fire requests at a fixed rate, recording latencies.
async fn run_load(
    client: &Client,
    url: &str,
    body: Option<&str>,
    rps: u64,
    duration_secs: u64,
    concurrency: u64,
) -> Stats {
    let stats = Stats::new();
    let sem = Arc::new(Semaphore::new(concurrency as usize));
    let interval = Duration::from_secs_f64(1.0 / rps as f64);
    let deadline = Instant::now() + Duration::from_secs(duration_secs);

    println!("  Firing at {rps} req/s for {duration_secs}s (concurrency cap: {concurrency})");

    let mut ticker = time::interval(interval);
    let mut spawned = 0u64;

    loop {
        ticker.tick().await;
        if Instant::now() >= deadline {
            break;
        }

        let permit = sem.clone().acquire_owned().await.unwrap();
        let client = client.clone();
        let url = url.to_string();
        let body = body.map(|s| s.to_string());
        let stats = stats.clone();
        spawned += 1;

        tokio::spawn(async move {
            let t0 = Instant::now();
            let mut req = client.post(&url).header("content-type", "application/json");
            if let Some(b) = body {
                req = req.body(b);
            } else {
                req = req.json(&json!({"platform": "auto"}));
            }
            let result = req.send().await;

            let latency = t0.elapsed();
            let ok = match result {
                Ok(resp) => resp.status().is_success(),
                Err(_) => false,
            };
            stats.record(ok, latency).await;
            drop(permit);
        });
    }

    // Wait for in-flight requests
    let _ = sem.acquire_many(concurrency as u32).await;

    println!("  Spawned {spawned} requests");
    stats
}

/// Fetch evidence from /attest and build a verify request body.
async fn get_verify_payload(
    client: &Client,
    base_url: &str,
    allow_debug: bool,
) -> Result<String, String> {
    let resp = client
        .post(format!("{base_url}/attest"))
        .json(&json!({"platform": "auto"}))
        .send()
        .await
        .map_err(|e| format!("attest request failed: {e}"))?;

    if !resp.status().is_success() {
        let status = resp.status();
        let body = resp.text().await.unwrap_or_default();
        return Err(format!("attest returned {status}: {body}"));
    }

    let json: Value = resp
        .json()
        .await
        .map_err(|e| format!("parse attest response: {e}"))?;

    // Accept the platform the service attested on, with no pins.
    let platform = json["platform"]
        .as_str()
        .ok_or("attest response has no platform")?;
    let verify_body = json!({
        "platform": platform,
        "evidence": json["evidence"],
        "policies": { platform: { "allow_debug": allow_debug } },
    });

    serde_json::to_string(&verify_body).map_err(|e| format!("serialize: {e}"))
}

#[tokio::main]
async fn main() {
    let cli = Cli::parse();
    let concurrency = cli.concurrency.unwrap_or(cli.rps * 2);

    println!("Attestation Service Load Test");
    println!("  URL:         {}", cli.url);
    let endpoint_name = match cli.endpoint {
        Endpoint::Verify => "verify",
        Endpoint::Attest => "attest",
        Endpoint::Both => "both",
    };
    println!("  Endpoint:    {endpoint_name}");
    println!("  Target RPS:  {}", cli.rps);
    println!("  Duration:    {}s", cli.duration);
    println!("  Concurrency: {concurrency}");

    let client = Client::builder()
        .timeout(Duration::from_secs(30))
        .pool_max_idle_per_host(concurrency as usize)
        .build()
        .expect("failed to build HTTP client");

    // Health check
    let health = client
        .get(format!("{}/health", cli.url))
        .send()
        .await
        .expect("service not reachable — is it running?");
    assert!(
        health.status().is_success(),
        "health check failed: {}",
        health.status()
    );
    println!("  Health:      OK\n");

    let run_verify = matches!(cli.endpoint, Endpoint::Verify | Endpoint::Both);
    let run_attest = matches!(cli.endpoint, Endpoint::Attest | Endpoint::Both);

    if run_verify {
        println!("Generating attestation evidence for verify payload...");
        let body = get_verify_payload(&client, &cli.url, cli.allow_debug)
            .await
            .expect("failed to get evidence");
        println!("  Evidence size: {} bytes", body.len());

        // Warmup: single request to prime caches
        println!("  Warming up (1 request)...");
        let _ = client
            .post(format!("{}/verify", cli.url))
            .header("content-type", "application/json")
            .body(body.clone())
            .send()
            .await;

        println!("\nRunning VERIFY load test...");
        let verify_url = format!("{}/verify", cli.url);
        let start = Instant::now();
        let stats = run_load(
            &client,
            &verify_url,
            Some(&body),
            cli.rps,
            cli.duration,
            concurrency,
        )
        .await;
        stats.report("VERIFY", start.elapsed()).await;
    }

    if run_attest {
        println!("\nRunning ATTEST load test...");
        let attest_url = format!("{}/attest", cli.url);
        let start = Instant::now();
        let stats = run_load(
            &client,
            &attest_url,
            None,
            cli.rps,
            cli.duration,
            concurrency,
        )
        .await;
        stats.report("ATTEST", start.elapsed()).await;
    }

    // Final cache status
    println!("\n--- Cache Status ---");
    if let Ok(resp) = client.get(format!("{}/health", cli.url)).send().await {
        if let Ok(json) = resp.json::<Value>().await {
            println!(
                "  {}",
                serde_json::to_string_pretty(&json["cache"]).unwrap_or_default()
            );
        }
    }
}
