//! Negative tests from the second performance review (PERF-REREVIEW.md).
use axum::body::Body;
use axum::http::{Request, StatusCode};
use base64::engine::general_purpose::STANDARD as BASE64;
use base64::Engine;
use std::sync::Arc;
use std::time::Duration;
use tower::ServiceExt;

use attestation_api::config::Config;
use attestation_api::server::build_api_router;
use attestation_api::AppState;

const DIR: &str = concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../attestation/test_data/collateral/2026-10-14/"
);
const TDX_V4_QUOTE: &[u8] = include_bytes!("../../attestation/test_data/tdx_quote_4.dat");
const GCP_QUOTE: &[u8] = include_bytes!("../../attestation/test_data/gcp_tdx/boot-quote.dat");
const AT: i64 = 1_792_108_800;

fn held_tdx() -> Vec<(String, Vec<u8>, Option<String>)> {
    use attestation::collateral::*;
    let held = |url: String, file: &str, chain: Option<&str>| {
        let body = std::fs::read(format!("{DIR}{file}")).unwrap();
        let chain = chain.map(|c| std::fs::read_to_string(format!("{DIR}{c}")).unwrap());
        (url, body, chain)
    };
    let signing = Some("tcb_signing_chain.pem");
    let fmspc = |f: &str| TcbInfo::url(&hex::decode(f).unwrap().try_into().unwrap());
    vec![
        held(fmspc("50806f000000"), "tcb_info_50806f000000.json", signing),
        held(fmspc("00806f050000"), "tcb_info_00806f050000.json", signing),
        held(QeIdentity::url(&()), "td_qe_identity.json", signing),
        held(
            PckCrl::url(&PckCa::Platform),
            "pck_crl_platform.der",
            Some("pck_crl_platform_chain.pem"),
        ),
        held(
            PckCrl::url(&PckCa::Processor),
            "pck_crl_processor.pem",
            Some("pck_crl_processor_chain.pem"),
        ),
        held(RootCrl::url(&()), "root_ca_crl.der", None),
    ]
}

fn state(ctx: attestation::Context, f: impl FnOnce(&mut Config)) -> AppState {
    let mut config = Config::default();
    config.attestation.allow_debug = true;
    f(&mut config);
    AppState::new(
        Arc::new(config),
        None,
        Arc::new(attestation::Verifier::new(ctx)),
    )
}

fn send(
    app: &axum::Router,
    body: serde_json::Value,
) -> tokio::task::JoinHandle<axum::response::Response> {
    let request = Request::builder()
        .method("POST")
        .uri("/verify")
        .header("content-type", "application/json")
        .body(Body::from(serde_json::to_vec(&body).unwrap()))
        .unwrap();
    let app = app.clone();
    tokio::spawn(async move { app.oneshot(request).await.unwrap() })
}

async fn json(resp: axum::response::Response) -> (StatusCode, serde_json::Value) {
    let status = resp.status();
    let body = axum::body::to_bytes(resp.into_body(), usize::MAX)
        .await
        .unwrap();
    (status, serde_json::from_slice(&body).unwrap())
}

fn report_data() -> String {
    BASE64.encode(&TDX_V4_QUOTE[568..632])
}

fn tdx_body() -> serde_json::Value {
    serde_json::json!({
        "platform": "tdx",
        "evidence": { "quote": BASE64.encode(TDX_V4_QUOTE) },
        "policies": { "tdx": { "allow_debug": true, "report_data": report_data() } }
    })
}

/// The genuine TDX quote with a GPU bundle no NRAS answer is attached for.
fn tdx_gpu_body(uuid: &str) -> serde_json::Value {
    tdx_bundle_body(&[(attestation::NvidiaGpuArch::Hopper, uuid)])
}

/// As [`tdx_gpu_body`], with these devices.
fn tdx_bundle_body(devices: &[(attestation::NvidiaGpuArch, &str)]) -> serde_json::Value {
    let bundle = attestation::NvidiaGpuEvidenceBundle {
        devices: devices
            .iter()
            .map(|&(arch, uuid)| attestation::NvidiaGpuDeviceEvidence {
                arch,
                uuid: uuid.into(),
                evidence_b64: BASE64.encode(uuid),
                cert_chain_b64: String::new(),
            })
            .collect(),
        binding: Default::default(),
    };
    serde_json::json!({
        "platform": "tdx",
        "evidence": { "quote": BASE64.encode(TDX_V4_QUOTE) },
        "nvidia_gpu": serde_json::to_value(&bundle).unwrap(),
        "policies": {
            "tdx": { "allow_debug": true, "report_data": report_data() },
            "nvidia_gpu": { "user_nonce": report_data() }
        }
    })
}

/// A localhost vendor: `reply(request line)` gives status and body, or
/// `None` to never answer. Counts requests per path fragment via `hits`.
async fn vendor(
    reply: impl Fn(&str) -> Option<(u16, Vec<u8>, u64)> + Send + Sync + 'static,
) -> (String, Arc<std::sync::Mutex<Vec<String>>>) {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let base = format!("http://{}", listener.local_addr().unwrap());
    let seen = Arc::new(std::sync::Mutex::new(Vec::new()));
    let reply = Arc::new(reply);
    let log = seen.clone();
    tokio::spawn(async move {
        while let Ok((mut sock, _)) = listener.accept().await {
            let (reply, log) = (reply.clone(), log.clone());
            tokio::spawn(async move {
                let mut buf = vec![0; 65536];
                let n = sock.read(&mut buf).await.unwrap_or(0);
                let line = String::from_utf8_lossy(&buf[..n])
                    .lines()
                    .next()
                    .unwrap_or_default()
                    .to_string();
                log.lock().unwrap().push(line.clone());
                match reply(&line) {
                    Some((status, body, delay)) => {
                        tokio::time::sleep(Duration::from_millis(delay)).await;
                        let head = format!(
                            "HTTP/1.1 {status} X\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                            body.len()
                        );
                        let _ = sock.write_all(head.as_bytes()).await;
                        let _ = sock.write_all(&body).await;
                    }
                    None => std::future::pending::<()>().await,
                }
            });
        }
    });
    (base, seen)
}

fn count(seen: &std::sync::Mutex<Vec<String>>, fragment: &str) -> usize {
    seen.lock()
        .unwrap()
        .iter()
        .filter(|l| l.contains(fragment))
        .count()
}

/// MAJOR-1 is not fixed for GPU evidence: the NRAS POST runs inside
/// `verify_cached`, on a verification thread. Genuine TDX evidence with a
/// bogus GPU bundle (no NRAS answer attached) and a silent NRAS holds every
/// thread, so genuine TDX requests that need no fetch are not answered.
#[tokio::test]
async fn rereview_gpu_bundles_waiting_on_nras_do_not_hold_verification_threads() {
    let (base, seen) = vendor(|_| None).await;
    let nras = format!("{base}/v3/attest/gpu");
    let ctx = attestation::Context::new()
        .with_nras_urls(nras.clone(), nras)
        .unwrap()
        .with_held(held_tdx())
        .at(AT)
        .unwrap();
    let threads = 2;
    let app = build_api_router(state(ctx, |c| {
        c.server.verify_threads = threads;
        c.server.queue_deadline_ms = 5_000;
    }));
    assert_eq!(
        send(&app, tdx_body()).await.unwrap().status(),
        StatusCode::OK
    );
    let forged: Vec<_> = (0..threads)
        .map(|i| send(&app, tdx_gpu_body(&format!("GPU-{i}"))))
        .collect();
    for _ in 0..100 {
        if count(&seen, "/v3/attest/gpu") >= threads {
            break;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    assert_eq!(
        count(&seen, "/v3/attest/gpu"),
        threads,
        "each bundle asks NRAS"
    );
    let genuine: Vec<_> = (0..threads + 4).map(|_| send(&app, tdx_body())).collect();
    let mut answered = 0;
    for g in genuine {
        if let Ok(resp) = tokio::time::timeout(Duration::from_secs(2), g).await {
            if resp.unwrap().status() == StatusCode::OK {
                answered += 1;
            }
        }
    }
    for f in forged {
        f.abort();
    }
    assert_eq!(
        answered,
        threads + 4,
        "genuine requests starved by NRAS waits on the pool"
    );
}

/// With the default 200 ms `queue_deadline_ms`, which now bounds the job's
/// whole run, a legitimate GPU verification whose NRAS call takes longer
/// is cut off at the deadline every time (on 954e5ff the deadline only
/// bounded the time in the queue).
#[tokio::test]
async fn rereview_a_slow_nras_answer_is_not_cut_off_by_the_queue_deadline() {
    let (base, seen) = vendor(|line| {
        if line.contains("/v3/attest/gpu") {
            Some((500, Vec::new(), 400))
        } else {
            Some((404, Vec::new(), 0))
        }
    })
    .await;
    let nras = format!("{base}/v3/attest/gpu");
    let ctx = attestation::Context::new()
        .with_nras_urls(nras.clone(), nras)
        .unwrap()
        .with_held(held_tdx())
        .at(AT)
        .unwrap();
    let app = build_api_router(state(ctx, |_| {}));
    let (status, body) = json(send(&app, tdx_gpu_body("GPU-0")).await.unwrap()).await;
    assert!(count(&seen, "/v3/attest/gpu") >= 1);
    // NRAS answered (with 500); the answer should be NRAS's, not the pool's.
    assert_ne!(body["error"], "overloaded", "{status} {body}");
}

/// An NRAS token under a key not in the published set: the library answers
/// CollateralUnavailable after one NRAS call. Through `verify_cached`, the
/// forced key-set refresh is put off every round (the set is in memory),
/// within recheck the refresh does nothing, and the loop runs to
/// MAX_FETCHES: 9 pool jobs, 9 NRAS POSTs, then 503 "overloaded".
#[tokio::test]
async fn rereview_an_unknown_nras_key_is_answered_like_the_library() {
    use base64::engine::general_purpose::URL_SAFE_NO_PAD;
    let header = URL_SAFE_NO_PAD.encode(r#"{"kid":"next"}"#);
    let eat = serde_json::json!([["JWT", format!("{header}.e30.sig")], {}]).to_string();
    let jwks = std::fs::read(format!("{DIR}nras_jwks.json")).unwrap();
    let (base, seen) = vendor(move |line| {
        if line.contains("/v3/attest/gpu") {
            Some((200, eat.clone().into_bytes(), 0))
        } else if line.contains("jwks") {
            Some((200, jwks.clone(), 0))
        } else {
            Some((404, Vec::new(), 0))
        }
    })
    .await;
    let nras = format!("{base}/v3/attest/gpu");
    let ctx = || {
        attestation::Context::new()
            .with_nras_urls(nras.clone(), nras.clone())
            .unwrap()
            .with_held(held_tdx())
            .at(AT)
            .unwrap()
    };
    // The library's answer.
    let lib_body = tdx_gpu_body("GPU-0");
    let envelope = serde_json::json!({
        "platform": "tdx",
        "evidence": lib_body["evidence"],
        "nvidia_gpu": lib_body["nvidia_gpu"],
    });
    let policies: attestation::Policies =
        serde_json::from_value(lib_body["policies"].clone()).unwrap();
    let lib = attestation::Verifier::new(ctx())
        .verify(envelope.to_string().as_bytes(), &policies)
        .await
        .err()
        .unwrap();
    assert!(lib.is_retryable(), "{lib}");
    let lib_posts = count(&seen, "/v3/attest/gpu");
    assert_eq!(lib_posts, 1);

    let st = state(ctx(), |_| {});
    let app = build_api_router(st.clone());
    let (status, body) = json(send(&app, lib_body).await.unwrap()).await;
    let api_posts = count(&seen, "/v3/attest/gpu") - lib_posts;
    let jobs = st.verify_pool.stats().done;
    eprintln!("api: {status} {body}; NRAS POSTs {api_posts}; pool jobs {jobs}");
    assert_eq!(body["error"], "collateral_unavailable", "{status} {body}");
    assert!(api_posts <= 2, "NRAS POSTs per request: {api_posts}");
}

/// GCE does not publish an endorsement for this measurement (404). The
/// library verdict is "no endorsement" (`get_if_published` gives `None`);
/// through `verify_cached` the deferred fetch turns the 404 into
/// CollateralUnavailable, so the API answers a retryable 502 for good.
#[tokio::test]
async fn rereview_an_unpublished_gce_endorsement_is_answered_like_the_library() {
    let (base, seen) = vendor(|_| Some((404, Vec::new(), 0))).await;
    let ctx = || {
        attestation::Context::new()
            .with_test_vendor(&base)
            .with_held(held_tdx())
            .at(AT)
            .unwrap()
    };
    let evidence = serde_json::json!({ "quote": BASE64.encode(GCP_QUOTE) });
    let policies = attestation::Policies {
        gcp_tdx: Some(Default::default()),
        ..Default::default()
    };
    let envelope = serde_json::json!({ "platform": "gcp-tdx", "evidence": evidence });
    let lib = attestation::Verifier::new(ctx())
        .verify(envelope.to_string().as_bytes(), &policies)
        .await;
    let lib = lib.expect("the library gives a verdict");
    assert_eq!(
        serde_json::to_value(&lib).unwrap()["endorsement_match"],
        false
    );

    let app = build_api_router(state(ctx(), |_| {}));
    let body = serde_json::json!({
        "platform": "gcp-tdx",
        "evidence": evidence,
        "policies": { "gcp-tdx": {} },
    });
    let (status, json) = json(send(&app, body).await.unwrap()).await;
    eprintln!(
        "api: {status} {json}; vendor requests {}",
        seen.lock().unwrap().len()
    );
    assert_ne!(json["error"], "collateral_unavailable", "{status} {json}");
}

/// b78d44c: a job back from a fetch skips admission. A client-made NRAS
/// answer (attached; its signature is checked only after the kid lookup)
/// under an unknown kid needs no vendor at all once the key set is in
/// memory: every request then costs 9 pool jobs, 8 of them not admitted,
/// and ends in 503 instead of the library's CollateralUnavailable.
#[tokio::test]
async fn rereview_one_admitted_request_runs_at_most_twice_on_the_pool() {
    use base64::engine::general_purpose::URL_SAFE_NO_PAD;
    let jwks = std::fs::read(format!("{DIR}nras_jwks.json")).unwrap();
    let (base, seen) = vendor(move |line| {
        if line.contains("jwks") {
            Some((200, jwks.clone(), 0))
        } else {
            Some((404, Vec::new(), 0))
        }
    })
    .await;
    let nras = format!("{base}/v3/attest/gpu");
    let ctx = attestation::Context::new()
        .with_nras_urls(nras.clone(), nras)
        .unwrap()
        .with_held(held_tdx())
        .at(AT)
        .unwrap();
    let st = state(ctx, |_| {});
    let app = build_api_router(st.clone());
    let header = URL_SAFE_NO_PAD.encode(r#"{"alg":"ES384","kid":"made-up"}"#);
    let claims = URL_SAFE_NO_PAD.encode(format!(r#"{{"exp":{}}}"#, AT + 3600));
    let eat = serde_json::json!([["JWT", format!("{header}.{claims}.sig")], {}]).to_string();
    let user_nonce = &TDX_V4_QUOTE[568..632];
    let nonce = hex::encode(attestation::platforms::nvidia_gpu::gpu_nonce(
        user_nonce,
        &Default::default(),
    ));
    let mut body = tdx_gpu_body("GPU-0");
    body["collateral"] = serde_json::json!([{
        "url": format!("{}#nonce={nonce}", attestation::platforms::nvidia_gpu::provider::NRAS_GPU_URL),
        "body": BASE64.encode(eat),
    }]);
    // Warm: the key set is fetched once.
    let _ = json(send(&app, body.clone()).await.unwrap()).await;
    let before = (st.verify_pool.stats().done, seen.lock().unwrap().len());
    let (status, json) = json(send(&app, body).await.unwrap()).await;
    let jobs = st.verify_pool.stats().done - before.0;
    let vendor_requests = seen.lock().unwrap().len() - before.1;
    eprintln!("api: {status} {json}; pool jobs {jobs}; vendor requests {vendor_requests}");
    assert!(jobs <= 2, "pool jobs for one request: {jobs}");
}

/// A cold verification of TDX evidence with a GPU bundle needs the most
/// vendor rounds of any platform: the platform collateral, then NRAS (every
/// arch group at once), then NRAS's key set. It ends within MAX_FETCHES with
/// the library's answer.
#[tokio::test]
async fn a_cold_tdx_verification_with_a_gpu_bundle_ends_within_the_fetch_rounds() {
    cold_tdx_rounds(&[(attestation::NvidiaGpuArch::Hopper, "GPU-0")]).await;
}

/// GPUs and NVSwitches go to two NRAS endpoints with two nonces: both are
/// asked in the same round.
#[tokio::test]
async fn a_cold_tdx_verification_with_gpus_and_switches_ends_within_the_fetch_rounds() {
    use attestation::NvidiaGpuArch::{Hopper, Ls10};
    cold_tdx_rounds(&[(Hopper, "GPU-0"), (Ls10, "SWITCH-0")]).await;
}

async fn cold_tdx_rounds(devices: &[(attestation::NvidiaGpuArch, &str)]) {
    use attestation::collateral::*;
    use base64::engine::general_purpose::URL_SAFE_NO_PAD;
    let file = |f: &str| std::fs::read(format!("{DIR}{f}")).unwrap();
    let chain = |f: &str| {
        String::from_utf8(file(f))
            .unwrap()
            .replace('\n', "%0A")
            .replace(' ', "%20")
    };
    let path = |url: String| url.split_once("://").unwrap().1.to_string();
    let kid = serde_json::from_slice::<serde_json::Value>(&file("nras_jwks.json")).unwrap()["keys"]
        [0]["kid"]
        .as_str()
        .unwrap()
        .to_string();
    let header = URL_SAFE_NO_PAD.encode(format!(r#"{{"alg":"ES384","kid":"{kid}"}}"#));
    let claims = URL_SAFE_NO_PAD.encode(format!(r#"{{"exp":{}}}"#, AT + 3600));
    let eat = serde_json::json!([["JWT", format!("{header}.{claims}.sig")], {}]).to_string();
    let fmspc = |f: &str| TcbInfo::url(&hex::decode(f).unwrap().try_into().unwrap());
    let signing = chain("tcb_signing_chain.pem");
    let replies: Vec<(String, &str, String, Vec<u8>)> = vec![
        (
            path(fmspc("50806f000000")),
            "TCB-Info-Issuer-Chain",
            signing.clone(),
            file("tcb_info_50806f000000.json"),
        ),
        (
            path(QeIdentity::url(&())),
            "SGX-Enclave-Identity-Issuer-Chain",
            signing,
            file("td_qe_identity.json"),
        ),
        (
            path(PckCrl::url(&PckCa::Platform)),
            "SGX-PCK-CRL-Issuer-Chain",
            chain("pck_crl_platform_chain.pem"),
            file("pck_crl_platform.der"),
        ),
        (
            path(PckCrl::url(&PckCa::Processor)),
            "SGX-PCK-CRL-Issuer-Chain",
            chain("pck_crl_processor_chain.pem"),
            file("pck_crl_processor.pem"),
        ),
        (
            path(RootCrl::url(&())),
            "X-None",
            String::new(),
            file("root_ca_crl.der"),
        ),
        (
            "/v3/attest/gpu".into(),
            "X-None",
            String::new(),
            eat.clone().into_bytes(),
        ),
        (
            "/v3/attest/switch".into(),
            "X-None",
            String::new(),
            eat.into_bytes(),
        ),
        (
            "jwks".into(),
            "X-None",
            String::new(),
            file("nras_jwks.json"),
        ),
    ];
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let base = format!("http://{}", listener.local_addr().unwrap());
    let seen = Arc::new(std::sync::Mutex::new(Vec::<String>::new()));
    let log = seen.clone();
    let replies = Arc::new(replies);
    tokio::spawn(async move {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        while let Ok((mut sock, _)) = listener.accept().await {
            let (replies, log) = (replies.clone(), log.clone());
            tokio::spawn(async move {
                let mut buf = vec![0; 65536];
                let n = sock.read(&mut buf).await.unwrap_or(0);
                let line = String::from_utf8_lossy(&buf[..n])
                    .lines()
                    .next()
                    .unwrap_or_default()
                    .to_string();
                log.lock().unwrap().push(line.clone());
                let reply = replies.iter().find(|(p, ..)| line.contains(p.as_str()));
                let (status, header, value, body) = match reply {
                    Some((_, h, v, b)) => (200, *h, v.clone(), b.clone()),
                    None => (404, "X-None", String::new(), Vec::new()),
                };
                let head = format!(
                    "HTTP/1.1 {status} X\r\nContent-Length: {}\r\n{header}: {value}\r\nConnection: close\r\n\r\n",
                    body.len()
                );
                let _ = sock.write_all(head.as_bytes()).await;
                let _ = sock.write_all(&body).await;
            });
        }
    });
    let nras = format!("{base}/v3/attest/gpu");
    let switch = format!("{base}/v3/attest/switch");
    let ctx = || {
        attestation::Context::new()
            .with_test_vendor(&base)
            .with_nras_urls(nras.clone(), switch.clone())
            .unwrap()
            .at(AT)
            .unwrap()
    };
    let body = tdx_bundle_body(devices);
    let envelope = serde_json::json!({
        "platform": "tdx",
        "evidence": body["evidence"],
        "nvidia_gpu": body["nvidia_gpu"],
    });
    let policies: attestation::Policies = serde_json::from_value(body["policies"].clone()).unwrap();
    let lib = attestation::Verifier::new(ctx())
        .verify(envelope.to_string().as_bytes(), &policies)
        .await
        .expect_err("the made-up NRAS token does not verify");
    let lib_requests = seen.lock().unwrap().len();

    let st = state(ctx(), |_| {});
    let app = build_api_router(st.clone());
    let (status, json) = json(send(&app, body).await.unwrap()).await;
    let api_requests = seen.lock().unwrap().len() - lib_requests;
    eprintln!("api: {status} {json}; vendor requests {api_requests}");
    assert!(
        json["message"]
            .as_str()
            .unwrap()
            .ends_with(&lib.to_string()),
        "{status} {json}"
    );
    assert_eq!(api_requests, lib_requests);
    // Three rounds of vendor requests, then the verdict.
    assert_eq!(st.verify_pool.stats().done, 4);
}
