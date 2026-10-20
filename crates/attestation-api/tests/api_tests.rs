use axum::body::Body;
use axum::http::{Request, StatusCode};
use base64::engine::general_purpose::{STANDARD as BASE64, URL_SAFE_NO_PAD};
use base64::Engine;
use std::sync::Arc;
use tower::ServiceExt;

use attestation_api::config::Config;
use attestation_api::server::{build_api_router, build_router};
use attestation_api::AppState;

/// Build a test state with no auth and attestation enabled (default).
fn test_state() -> AppState {
    test_state_with(|_| {})
}

/// Build a test state, applying the given customisation closure to the config.
fn test_state_with(f: impl FnOnce(&mut Config)) -> AppState {
    let mut config = Config::default();
    f(&mut config);
    AppState {
        config: Arc::new(config),
        token_issuer: None,
        verifier: Arc::new(attestation::Verifier::new(attestation::Context::new())),
    }
}

/// A verifier that holds Intel's collateral for the TDX fixtures and Google's
/// endorsement of the GCP TDX quote's firmware, evaluated while they are
/// current, and fetches nothing.
fn held_verifier(endorsement_body: &[u8]) -> Arc<attestation::Verifier> {
    use attestation::collateral::*;
    const DIR: &str = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../attestation/test_data/collateral/2026-10-14/"
    );
    let held = |url: String, file: &str, chain: Option<&str>| {
        let body = std::fs::read(format!("{DIR}{file}")).unwrap();
        let chain = chain.map(|c| std::fs::read_to_string(format!("{DIR}{c}")).unwrap());
        (url, body, chain)
    };
    let signing = Some("tcb_signing_chain.pem");
    let tcb_info = |fmspc: &str| {
        let url = TcbInfo::url(&hex::decode(fmspc).unwrap().try_into().unwrap());
        held(url, &format!("tcb_info_{fmspc}.json"), signing)
    };
    let mrtd = hex::decode("c1ee9c16e3afc506cfe042c5b846a368528f3b37618eafb27469bc114cf914e9222c91618470e7f2b28ac360968270a5").unwrap();
    let held = vec![
        tcb_info("50806f000000"),
        tcb_info("00806f050000"),
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
        (
            GceEndorsement::url(&(attestation::PlatformType::GcpTdx, mrtd)),
            endorsement_body.to_vec(),
            None,
        ),
    ];
    // 2026-10-16T00:00:00Z.
    let ctx = attestation::Context::offline()
        .with_held(held)
        .at(1_792_108_800)
        .unwrap();
    Arc::new(attestation::Verifier::new(ctx))
}

const GCP_ENDORSEMENT: &[u8] =
    include_bytes!("../../attestation/test_data/gcp_tdx/endorsement-c1ee9c16.binarypb");

/// A verifier that holds the fixtures' collateral, with a token issuer.
fn offline_state_with(f: impl FnOnce(&mut Config)) -> AppState {
    let mut state = test_state_with(f);
    state.verifier = held_verifier(GCP_ENDORSEMENT);
    let signing_key = p256::ecdsa::SigningKey::random(&mut rand::thread_rng());
    let issuer = attestation_api::token::issuer::TokenIssuer::new(
        signing_key,
        "test-issuer".to_string(),
        std::time::Duration::from_secs(300),
    )
    .unwrap();
    state.token_issuer = Some(Arc::new(issuer));
    state
}

/// A TDX v4 quote minted with the TD debug attribute set.
const TDX_V4_QUOTE: &[u8] = include_bytes!("../../attestation/test_data/tdx_quote_4.dat");

/// The quote's `report_data`: TD report body offset 520, after the 48-byte header.
fn tdx_v4_report_data() -> String {
    BASE64.encode(&TDX_V4_QUOTE[568..632])
}

fn tdx_v4_evidence() -> serde_json::Value {
    serde_json::json!({ "quote": BASE64.encode(TDX_V4_QUOTE) })
}

async fn post_verify(state: AppState, body: serde_json::Value) -> (StatusCode, serde_json::Value) {
    let resp = build_api_router(state)
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/verify")
                .header("content-type", "application/json")
                .body(Body::from(serde_json::to_vec(&body).unwrap()))
                .unwrap(),
        )
        .await
        .unwrap();
    let status = resp.status();
    let body = axum::body::to_bytes(resp.into_body(), usize::MAX)
        .await
        .unwrap();
    (status, serde_json::from_slice(&body).unwrap())
}

fn has_tee() -> bool {
    #[cfg(target_os = "linux")]
    {
        attestation::detect().is_ok()
    }
    #[cfg(not(target_os = "linux"))]
    {
        false
    }
}

// --- Basic endpoint tests (no auth) ---

#[tokio::test]
async fn health_returns_ok() {
    let state = test_state();
    let app = build_api_router(state);

    let resp = app
        .oneshot(
            Request::builder()
                .uri("/health")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(resp.status(), StatusCode::OK);

    let body = axum::body::to_bytes(resp.into_body(), usize::MAX)
        .await
        .unwrap();
    let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(json["status"], "ok");
    assert_eq!(json["token_issuer"], false);
}

#[tokio::test]
async fn platform_endpoint() {
    let state = test_state();
    let app = build_api_router(state);

    let resp = app
        .oneshot(
            Request::builder()
                .uri("/platform")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    if has_tee() {
        assert_eq!(resp.status(), StatusCode::OK);
        let body = axum::body::to_bytes(resp.into_body(), usize::MAX)
            .await
            .unwrap();
        let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert!(json["platform"].is_string());
    } else {
        assert_eq!(resp.status(), StatusCode::SERVICE_UNAVAILABLE);
    }
}

#[tokio::test]
async fn verify_rejects_invalid_evidence() {
    let state = test_state();
    let app = build_api_router(state);

    let body = serde_json::json!({
        "platform": "snp",
        "evidence": {},
        "policies": { "snp": {} }
    });

    let resp = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/verify")
                .header("content-type", "application/json")
                .body(Body::from(serde_json::to_vec(&body).unwrap()))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(resp.status(), StatusCode::UNPROCESSABLE_ENTITY);
    let body = axum::body::to_bytes(resp.into_body(), usize::MAX)
        .await
        .unwrap();
    let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(json["error"], "verification_failed");
}

#[tokio::test]
async fn verify_rejects_expected_measurement_of_wrong_length() {
    let state = test_state();
    let app = build_api_router(state);

    let body = serde_json::json!({
        "platform": "snp",
        "evidence": {},
        "policies": { "snp": { "launch_digest": "AAAA" } }
    });

    let resp = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/verify")
                .header("content-type", "application/json")
                .body(Body::from(serde_json::to_vec(&body).unwrap()))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    let body = axum::body::to_bytes(resp.into_body(), usize::MAX)
        .await
        .unwrap();
    let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(json["error"], "bad_request");
}

#[tokio::test]
async fn verify_refuses_evidence_for_a_platform_without_policy() {
    for policies in [
        serde_json::json!({"snp": {}}),
        serde_json::json!({"tdx": null}),
        serde_json::json!({}),
    ] {
        let (status, json) = post_verify(
            offline_state_with(|_| {}),
            serde_json::json!({
                "platform": "tdx",
                "evidence": tdx_v4_evidence(),
                "policies": policies
            }),
        )
        .await;

        assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY);
        assert_eq!(json["error"], "platform_not_allowed");
    }
}

#[tokio::test]
async fn verify_passes_the_tdx_fixture_offline() {
    let (status, json) = post_verify(
        offline_state_with(|c| c.attestation.allow_debug = true),
        serde_json::json!({
            "platform": "tdx",
            "evidence": tdx_v4_evidence(),
            "policies": { "tdx": { "allow_debug": true, "report_data": tdx_v4_report_data() } }
        }),
    )
    .await;

    assert_eq!(status, StatusCode::OK);
    assert_eq!(json["passed"], true);
    assert!(json.get("token").is_none());
}

#[tokio::test]
async fn verify_returns_400_on_invalid_params() {
    let state = offline_state_with(|c| c.attestation.allow_debug = true);
    for tdx in [
        serde_json::json!({ "allow_debug": true, "accepted_tcb_statuses": [] }),
        serde_json::json!({ "allow_debug": true, "report_data": BASE64.encode([0u8; 65]) }),
    ] {
        let (status, json) = post_verify(
            state.clone(),
            serde_json::json!({
                "platform": "tdx",
                "evidence": tdx_v4_evidence(),
                "policies": { "tdx": tdx }
            }),
        )
        .await;

        assert_eq!(status, StatusCode::BAD_REQUEST);
        assert_eq!(json["error"], "bad_request");
    }
}

fn enable_all_floors(c: &mut Config) {
    c.attestation.allow_debug = true;
    c.attestation.allow_revoked_or_unlisted_tcb = true;
    c.attestation.allow_nonzero_vmpl = true;
}

/// `policies` is refused when only `close_floor` is off, and accepted when
/// every floor is open.
async fn assert_floor(close_floor: fn(&mut Config), policies: serde_json::Value) {
    let body = serde_json::json!({
        "platform": "tdx",
        "evidence": tdx_v4_evidence(),
        "policies": policies
    });
    let refusing = offline_state_with(|c| {
        enable_all_floors(c);
        close_floor(c);
    });
    let (status, json) = post_verify(refusing, body.clone()).await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "{policies}");
    assert_eq!(json["error"], "bad_request");

    let (status, _) = post_verify(offline_state_with(enable_all_floors), body).await;
    assert_eq!(status, StatusCode::OK, "{policies}");
}

#[tokio::test]
async fn verify_refuses_policies_below_the_server_floors_unless_enabled() {
    assert_floor(
        |c| c.attestation.allow_debug = false,
        serde_json::json!({ "tdx": { "allow_debug": true } }),
    )
    .await;
    assert_floor(
        |c| c.attestation.allow_revoked_or_unlisted_tcb = false,
        serde_json::json!({ "tdx": { "accepted_tcb_statuses": ["UpToDate", "Revoked"] } }),
    )
    .await;
    assert_floor(
        |c| c.attestation.allow_revoked_or_unlisted_tcb = false,
        serde_json::json!({ "tdx": { "accepted_tcb_statuses": ["NoMatchingLevel"] } }),
    )
    .await;
    assert_floor(
        |c| c.attestation.allow_nonzero_vmpl = false,
        serde_json::json!({ "tdx": {}, "snp": { "max_vmpl": 1 } }),
    )
    .await;
    assert_floor(
        |c| c.attestation.allow_debug = false,
        serde_json::json!({ "tdx": { "allow_debug": true }, "nvidia_gpu": { "device_policy": { "allow_debug": true } } }),
    )
    .await;
}

#[tokio::test]
async fn verify_refuses_collateral_floors_or_gpu_checks_below_the_defaults() {
    let shipped = attestation::collateral::VersionFloors::default().intel_tcb_info;
    for (policies, status) in [
        (
            serde_json::json!({ "floors": { "intel_tcb_info": shipped - 1 } }),
            StatusCode::BAD_REQUEST,
        ),
        (
            serde_json::json!({ "nvidia_gpu": { "device_policy": { "require_secboot": false } } }),
            StatusCode::BAD_REQUEST,
        ),
        (
            serde_json::json!({ "floors": { "intel_tcb_info": shipped + 1 } }),
            StatusCode::OK,
        ),
    ] {
        let mut policies = policies;
        policies["tdx"] = serde_json::json!({ "allow_debug": true });
        let (got, json) = post_verify(
            offline_state_with(enable_all_floors),
            serde_json::json!({ "platform": "tdx", "evidence": tdx_v4_evidence(), "policies": policies }),
        )
        .await;
        assert_eq!(got, status, "{policies}: {json}");
    }
}

#[tokio::test]
async fn verify_refuses_a_token_request_without_report_data() {
    for policies in [
        serde_json::json!({ "tdx": { "allow_debug": true }, "snp": { "report_data": "AA==" } }),
        serde_json::json!({ "tdx": { "allow_debug": true, "report_data": "" } }),
    ] {
        let (status, json) = post_verify(
            offline_state_with(|c| c.attestation.allow_debug = true),
            serde_json::json!({
                "platform": "tdx",
                "evidence": tdx_v4_evidence(),
                "policies": policies,
                "issue_token": true
            }),
        )
        .await;

        assert_eq!(status, StatusCode::BAD_REQUEST, "{policies}");
        assert_eq!(json["error"], "bad_request");
    }
}

#[tokio::test]
async fn token_carries_the_policy_it_was_issued_under() {
    let (status, json) = post_verify(
        offline_state_with(|c| c.attestation.allow_debug = true),
        serde_json::json!({
            "platform": "tdx",
            "evidence": tdx_v4_evidence(),
            "policies": { "tdx": { "allow_debug": true, "report_data": tdx_v4_report_data() } },
            "issue_token": true
        }),
    )
    .await;

    assert_eq!(status, StatusCode::OK);
    assert_eq!(json["passed"], true);
    let token = json["token"].as_str().expect("token issued");
    let claims: serde_json::Value = serde_json::from_slice(
        &URL_SAFE_NO_PAD
            .decode(token.split('.').nth(1).unwrap())
            .unwrap(),
    )
    .unwrap();
    assert_eq!(claims["platform"], "tdx");
    assert_eq!(claims["result"], json["result"]);
    let policy = &claims["policy"]["tdx"];
    assert_eq!(policy["report_data"], tdx_v4_report_data());
    assert_eq!(policy["allow_debug"], true);
    assert_eq!(
        policy["accepted_tcb_statuses"],
        serde_json::to_value(attestation::TdxParams::default().accepted_tcb_statuses).unwrap()
    );
}

#[tokio::test]
async fn verify_does_not_issue_a_token_when_verification_did_not_pass() {
    let (status, json) = post_verify(
        offline_state_with(|c| c.attestation.allow_debug = true),
        serde_json::json!({
            "platform": "tdx",
            "evidence": tdx_v4_evidence(),
            "policies": { "tdx": { "allow_debug": true, "report_data": "AA==" } },
            "issue_token": true
        }),
    )
    .await;

    assert_eq!(status, StatusCode::OK);
    assert_eq!(json["passed"], false);
    assert!(json.get("token").is_none());
}

// The real GCP TDX quote with Google's endorsement of its OVMF build, and
// with another build's endorsement in its place.
#[tokio::test]
async fn verify_checks_gcp_launch_endorsement() {
    const QUOTE: &[u8] = include_bytes!("../../attestation/test_data/gcp_tdx/boot-quote.dat");
    const OTHER_BUILD: &[u8] =
        include_bytes!("../../attestation/test_data/gcp_snp/endorsement-0e017d2f.binarypb");
    let body = serde_json::json!({
        "platform": "gcp-tdx",
        "evidence": { "quote": BASE64.encode(QUOTE) },
        "policies": { "gcp-tdx": {} },
    });
    let mut state = test_state();
    state.verifier = held_verifier(GCP_ENDORSEMENT);
    let (status, json) = post_verify(state.clone(), body.clone()).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(json["result"]["endorsement_match"], true);
    assert_eq!(json["passed"], true);

    state.verifier = held_verifier(OTHER_BUILD);
    let (status, json) = post_verify(state, body).await;
    assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY);
    assert_eq!(json["error"], "verification_failed");
}

#[tokio::test]
async fn collateral_held_nowhere_is_a_502() {
    let mut state = test_state();
    state.verifier = Arc::new(attestation::Verifier::new(attestation::Context::offline()));
    let (status, json) = post_verify(
        state,
        serde_json::json!({
            "platform": "tdx",
            "evidence": tdx_v4_evidence(),
            "policies": { "tdx": { "allow_debug": false } },
        }),
    )
    .await;
    assert_eq!(status, StatusCode::BAD_GATEWAY);
    assert_eq!(json["error"], "collateral_unavailable");
}

/// A vendor on localhost: each request gets the reply of the first route
/// whose path fragment its request line contains, else 404.
async fn vendor(routes: Vec<(&'static str, u16, Vec<u8>)>) -> String {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let base = format!("http://{}", listener.local_addr().unwrap());
    tokio::spawn(async move {
        while let Ok((mut sock, _)) = listener.accept().await {
            let mut buf = Vec::new();
            let mut chunk = [0; 1024];
            while !buf.windows(2).any(|w| w == b"\r\n") {
                match sock.read(&mut chunk).await {
                    Ok(0) | Err(_) => break,
                    Ok(n) => buf.extend_from_slice(&chunk[..n]),
                }
            }
            let line = String::from_utf8_lossy(&buf);
            let line = line.lines().next().unwrap_or_default();
            let (status, body) = routes
                .iter()
                .find(|(path, _, _)| line.contains(path))
                .map_or((404, &[][..]), |(_, s, b)| (*s, &b[..]));
            let head = format!(
                "HTTP/1.1 {status} X\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                body.len()
            );
            let _ = sock.write_all(head.as_bytes()).await;
            let _ = sock.write_all(body).await;
        }
    });
    base
}

const SNP_REPORT: &[u8] =
    include_bytes!("../../attestation/test_data/snp/live-report-v5-genoa.bin");
const SNP_VCEK: &[u8] = include_bytes!("../../attestation/test_data/snp/live-vcek-genoa.der");
const GENOA_CRL: &[u8] =
    include_bytes!("../../attestation/test_data/collateral/2026-10-14/amd_crl_genoa.der");

/// A state whose verifier fetches from the vendor at `base`, at a time the
/// fixture CRL is current.
fn online_state(base: &str) -> AppState {
    let mut state = test_state();
    let ctx = attestation::Context::new()
        .with_test_vendor(base)
        .at(1_792_108_800)
        .unwrap();
    state.verifier = Arc::new(attestation::Verifier::new(ctx));
    state
}

/// The Genoa SEV-SNP evidence, with or without its VCEK inline.
fn snp_body(with_vcek: bool) -> serde_json::Value {
    let mut evidence = serde_json::json!({ "attestation_report": BASE64.encode(SNP_REPORT) });
    if with_vcek {
        evidence["cert_chain"] = serde_json::json!({ "vcek": BASE64.encode(SNP_VCEK) });
    }
    serde_json::json!({
        "platform": "snp",
        "evidence": evidence,
        "policies": { "snp": {} },
    })
}

#[tokio::test]
async fn collateral_that_is_not_the_vendors_is_a_422() {
    let mut crl = GENOA_CRL.to_vec();
    *crl.last_mut().unwrap() ^= 1;
    let base = vendor(vec![("/crl", 200, crl)]).await;
    let (status, json) = post_verify(online_state(&base), snp_body(true)).await;
    assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY);
    assert_eq!(json["error"], "verification_failed");
}

#[tokio::test]
async fn a_vcek_the_vendor_does_not_publish_is_a_422() {
    let base = vendor(vec![("/crl", 200, GENOA_CRL.to_vec())]).await;
    let (status, json) = post_verify(online_state(&base), snp_body(false)).await;
    assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY);
    assert_eq!(json["error"], "verification_failed");
}

#[tokio::test]
async fn the_answer_is_the_librarys() {
    const QUOTE: &[u8] = include_bytes!("../../attestation/test_data/gcp_tdx/boot-quote.dat");
    let evidence = serde_json::json!({ "quote": BASE64.encode(QUOTE) });
    let mut state = test_state();
    state.verifier = held_verifier(GCP_ENDORSEMENT);
    let (status, json) = post_verify(
        state,
        serde_json::json!({
            "platform": "gcp-tdx",
            "evidence": evidence,
            "policies": { "gcp-tdx": {} },
        }),
    )
    .await;
    assert_eq!(status, StatusCode::OK);

    let envelope = serde_json::json!({ "platform": "gcp-tdx", "evidence": evidence });
    let policies = attestation::Policies {
        gcp_tdx: Some(Default::default()),
        ..Default::default()
    };
    let lib = held_verifier(GCP_ENDORSEMENT)
        .verify(envelope.to_string().as_bytes(), &policies)
        .await
        .unwrap();
    assert_eq!(json["result"], serde_json::to_value(&lib).unwrap());
    assert_eq!(json["passed"], lib.passed());
}

#[tokio::test]
async fn verify_accepts_mrtd_in_allowed_set() {
    use base64::{engine::general_purpose::STANDARD as BASE64, Engine};
    // A real GCP TDX quote; it verifies offline (no collateral fetch).
    const QUOTE: &[u8] = include_bytes!("../../attestation/test_data/gcp_tdx/boot-quote.dat");
    const MRTD: &str = "c1ee9c16e3afc506cfe042c5b846a368528f3b37618eafb27469bc114cf914e9222c91618470e7f2b28ac360968270a5";
    let mut state = test_state();
    state.verifier = held_verifier(GCP_ENDORSEMENT);

    for (allowed, passed) in [
        (vec![[0xAA; 48].to_vec(), hex::decode(MRTD).unwrap()], true),
        (vec![[0xAA; 48].to_vec(), [0xBB; 48].to_vec()], false),
    ] {
        let allowed: Vec<String> = allowed.iter().map(|v| BASE64.encode(v)).collect();
        let body = serde_json::json!({
            "platform": "tdx",
            "evidence": { "quote": BASE64.encode(QUOTE) },
            "policies": { "tdx": { "mrtd": allowed } },
        });
        let resp = build_api_router(state.clone())
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/verify")
                    .header("content-type", "application/json")
                    .body(Body::from(serde_json::to_vec(&body).unwrap()))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let body = axum::body::to_bytes(resp.into_body(), usize::MAX)
            .await
            .unwrap();
        let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(json["result"]["mrtd_match"], passed);
        assert_eq!(json["passed"], passed);
    }
}

#[tokio::test]
async fn verify_rejects_full_envelope_evidence() {
    let state = test_state();
    let app = build_api_router(state);

    let body = serde_json::json!({
        "platform": "snp",
        "evidence": {"platform": "snp", "evidence": {}},
        "policies": { "snp": {} }
    });

    let resp = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/verify")
                .header("content-type", "application/json")
                .body(Body::from(serde_json::to_vec(&body).unwrap()))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    let body = axum::body::to_bytes(resp.into_body(), usize::MAX)
        .await
        .unwrap();
    let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(json["error"], "bad_request");
}

#[tokio::test]
#[ignore = "requires an accessible TEE attestation device"]
async fn attest_endpoint() {
    let state = test_state();
    let app = build_api_router(state);

    let body = serde_json::json!({
        "platform": "auto"
    });

    let resp = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/attest")
                .header("content-type", "application/json")
                .body(Body::from(serde_json::to_vec(&body).unwrap()))
                .unwrap(),
        )
        .await
        .unwrap();

    if has_tee() {
        assert_eq!(resp.status(), StatusCode::OK);
        let body = axum::body::to_bytes(resp.into_body(), usize::MAX)
            .await
            .unwrap();
        let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert!(json["platform"].is_string());
        assert!(json["evidence"].is_object());
    } else {
        assert!(resp.status().is_client_error() || resp.status().is_server_error());
    }
}

#[cfg(target_os = "linux")]
#[tokio::test]
async fn attest_rejects_disallowed_platform_before_hardware_access() {
    let state = test_state_with(|c| {
        c.attestation.platforms = vec!["tdx".to_string()];
    });
    let app = build_router(state);

    let body = serde_json::json!({
        "platform": "snp"
    });

    let resp = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/attest")
                .header("content-type", "application/json")
                .body(Body::from(serde_json::to_vec(&body).unwrap()))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    let body = axum::body::to_bytes(resp.into_body(), usize::MAX)
        .await
        .unwrap();
    let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(json["error"], "bad_request");
}

// --- Attestation disabled tests ---

#[tokio::test]
async fn attest_rejected_when_disabled() {
    let state = test_state_with(|c| {
        c.attestation.enabled = false;
    });
    let app = build_router(state);

    let body = serde_json::json!({
        "platform": "auto"
    });

    let resp = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/attest")
                .header("content-type", "application/json")
                .body(Body::from(serde_json::to_vec(&body).unwrap()))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    let body = axum::body::to_bytes(resp.into_body(), usize::MAX)
        .await
        .unwrap();
    let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(json["error"], "attest_not_available");
}

// --- Auth tests ---

#[tokio::test]
async fn health_does_not_require_api_key() {
    let state = test_state_with(|c| {
        c.auth.api_keys = vec!["test-key-123".to_string()];
    });
    let app = build_router(state);

    let resp = app
        .oneshot(
            Request::builder()
                .uri("/health")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(resp.status(), StatusCode::OK);
    let body = axum::body::to_bytes(resp.into_body(), usize::MAX)
        .await
        .unwrap();
    let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(json["status"], "ok");
}

#[tokio::test]
async fn rejects_without_api_key() {
    let state = test_state_with(|c| {
        c.auth.api_keys = vec!["test-key-123".to_string()];
    });
    let app = build_router(state);

    let resp = app
        .oneshot(
            Request::builder()
                .uri("/platform")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
    let body = axum::body::to_bytes(resp.into_body(), usize::MAX)
        .await
        .unwrap();
    let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(json["error"], "unauthorized");
}

#[tokio::test]
async fn accepts_valid_api_key() {
    let state = test_state_with(|c| {
        c.auth.api_keys = vec!["test-key-123".to_string()];
    });
    let app = build_router(state);

    let resp = app
        .oneshot(
            Request::builder()
                .uri("/platform")
                .header("authorization", "Bearer test-key-123")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_ne!(resp.status(), StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn rejects_invalid_api_key() {
    let state = test_state_with(|c| {
        c.auth.api_keys = vec!["test-key-123".to_string()];
    });
    let app = build_router(state);

    let resp = app
        .oneshot(
            Request::builder()
                .uri("/platform")
                .header("authorization", "Bearer wrong-key")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
    let body = axum::body::to_bytes(resp.into_body(), usize::MAX)
        .await
        .unwrap();
    let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(json["error"], "unauthorized");
}

#[tokio::test]
async fn no_auth_allows_all_requests() {
    let state = test_state();
    let app = build_router(state);

    let resp = app
        .oneshot(
            Request::builder()
                .uri("/platform")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_ne!(resp.status(), StatusCode::UNAUTHORIZED);
}

// --- Input validation tests ---

#[tokio::test]
async fn verify_rejects_non_json_body() {
    let state = test_state();
    let app = build_api_router(state);

    let resp = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/verify")
                .header("content-type", "application/json")
                .body(Body::from("not json"))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    let body = axum::body::to_bytes(resp.into_body(), usize::MAX)
        .await
        .unwrap();
    let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(json["error"], "bad_request");
}

async fn post_verify_raw(
    content_type: Option<&str>,
    body: Vec<u8>,
) -> (StatusCode, serde_json::Value) {
    let mut req = Request::builder().method("POST").uri("/verify");
    if let Some(content_type) = content_type {
        req = req.header("content-type", content_type);
    }
    let resp = build_api_router(test_state())
        .oneshot(req.body(Body::from(body)).unwrap())
        .await
        .unwrap();
    let status = resp.status();
    let body = axum::body::to_bytes(resp.into_body(), usize::MAX)
        .await
        .unwrap();
    (status, serde_json::from_slice(&body).unwrap())
}

#[tokio::test]
async fn verify_refuses_an_oversized_body_as_payload_too_large() {
    let (status, json) =
        post_verify_raw(Some("application/json"), vec![b' '; 2 * 1024 * 1024]).await;

    assert_eq!(status, StatusCode::PAYLOAD_TOO_LARGE);
    assert_eq!(json["error"], "payload_too_large");
}

#[tokio::test]
async fn verify_refuses_a_body_that_is_not_declared_json_as_unsupported_media_type() {
    for content_type in [None, Some("text/plain")] {
        let (status, json) = post_verify_raw(content_type, b"{}".to_vec()).await;

        assert_eq!(
            status,
            StatusCode::UNSUPPORTED_MEDIA_TYPE,
            "{content_type:?}"
        );
        assert_eq!(json["error"], "unsupported_media_type");
    }
}

#[tokio::test]
async fn verify_refuses_json_of_the_wrong_shape_as_a_bad_request() {
    let (status, json) = post_verify_raw(
        Some("application/json"),
        br#"{"evidence": 1, "nope": 1}"#.to_vec(),
    )
    .await;

    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(json["error"], "bad_request");
}

#[tokio::test]
async fn verify_rejects_a_pin_the_platform_does_not_have() {
    let (status, json) = post_verify(
        test_state(),
        serde_json::json!({
            "platform": "snp",
            "evidence": {},
            "policies": { "snp": { "mrtd": BASE64.encode([0u8; 48]) } }
        }),
    )
    .await;

    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(json["error"], "bad_request");
}

// --- Token issuer tests ---

#[tokio::test]
async fn health_reflects_token_issuer_configured() {
    let mut state = test_state();
    let signing_key = p256::ecdsa::SigningKey::random(&mut rand::thread_rng());
    let issuer = attestation_api::token::issuer::TokenIssuer::new(
        signing_key,
        "test-issuer".to_string(),
        std::time::Duration::from_secs(300),
    )
    .unwrap();
    state.token_issuer = Some(Arc::new(issuer));

    let app = build_api_router(state);

    let resp = app
        .oneshot(
            Request::builder()
                .uri("/health")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(resp.status(), StatusCode::OK);
    let body = axum::body::to_bytes(resp.into_body(), usize::MAX)
        .await
        .unwrap();
    let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(json["token_issuer"], true);
}

// --- JWKS endpoint tests ---

#[tokio::test]
async fn jwks_returns_keys_when_token_configured() {
    let mut state = test_state();
    let signing_key = p256::ecdsa::SigningKey::random(&mut rand::thread_rng());
    let issuer = attestation_api::token::issuer::TokenIssuer::new(
        signing_key,
        "test-issuer".to_string(),
        std::time::Duration::from_secs(300),
    )
    .unwrap();
    state.token_issuer = Some(Arc::new(issuer));

    let app = build_api_router(state);

    let resp = app
        .oneshot(
            Request::builder()
                .uri("/token/jwks")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(resp.status(), StatusCode::OK);
    let body = axum::body::to_bytes(resp.into_body(), usize::MAX)
        .await
        .unwrap();
    let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert!(json["keys"].is_array());
    let keys = json["keys"].as_array().unwrap();
    assert_eq!(keys.len(), 1);
    assert_eq!(keys[0]["kty"], "EC");
    assert_eq!(keys[0]["crv"], "P-256");
    assert_eq!(keys[0]["alg"], "ES256");
    assert!(keys[0]["kid"].is_string());
    assert!(keys[0]["x"].is_string());
    assert!(keys[0]["y"].is_string());
}

#[tokio::test]
async fn jwks_returns_error_when_token_not_configured() {
    let state = test_state();
    let app = build_api_router(state);

    let resp = app
        .oneshot(
            Request::builder()
                .uri("/token/jwks")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    let body = axum::body::to_bytes(resp.into_body(), usize::MAX)
        .await
        .unwrap();
    let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(json["error"], "token_not_configured");
}

// --- End-to-end test: attest then verify ---

#[tokio::test]
#[ignore = "requires an accessible TEE attestation device"]
async fn attest_then_verify_roundtrip() {
    if !has_tee() {
        // Skip on non-TEE machines
        return;
    }

    let state = test_state();

    // Step 1: Attest
    let app = build_api_router(state.clone());
    let attest_body = serde_json::json!({
        "platform": "auto",
        "report_data": "AQIDBA=="  // [1,2,3,4] in base64
    });

    let resp = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/attest")
                .header("content-type", "application/json")
                .body(Body::from(serde_json::to_vec(&attest_body).unwrap()))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(resp.status(), StatusCode::OK);
    let body = axum::body::to_bytes(resp.into_body(), usize::MAX)
        .await
        .unwrap();
    let attest_json: serde_json::Value = serde_json::from_slice(&body).unwrap();
    let platform = &attest_json["platform"];
    let evidence = &attest_json["evidence"];

    // Step 2: Verify
    let app = build_api_router(state);
    let verify_body = serde_json::json!({
        "platform": platform,
        "evidence": evidence,
        "policies": { platform.as_str().unwrap(): {} }
    });

    let resp = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/verify")
                .header("content-type", "application/json")
                .body(Body::from(serde_json::to_vec(&verify_body).unwrap()))
                .unwrap(),
        )
        .await
        .unwrap();

    let status = resp.status();
    let body = axum::body::to_bytes(resp.into_body(), usize::MAX)
        .await
        .unwrap();
    if status != StatusCode::OK {
        let body_str = String::from_utf8_lossy(&body);
        panic!("verify returned {status}: {body_str}");
    }
    let verify_json: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(verify_json["passed"], true);
}

#[tokio::test]
async fn verify_refuses_unsupported_policy_keys_even_with_open_server_rules() {
    for value in [
        serde_json::json!({}),
        serde_json::Value::Null,
        serde_json::json!({"allow_debug": true}),
    ] {
        let (status, json) = post_verify(
            offline_state_with(enable_all_floors),
            serde_json::json!({"platform": "tdx", "evidence": tdx_v4_evidence(), "policies": {"tdx": {}, "dstack": value}}),
        ).await;
        assert_eq!(status, StatusCode::BAD_REQUEST);
        assert_eq!(json["error"], "bad_request");
    }
}

#[tokio::test]
async fn verify_requires_a_gpu_bundle_when_policy_requires_it() {
    let (status, json) = post_verify(
        offline_state_with(enable_all_floors),
        serde_json::json!({"platform": "tdx", "evidence": tdx_v4_evidence(), "policies": {"tdx": {}, "nvidia_gpu": {"required": true}}}),
    ).await;
    assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY);
    assert_eq!(json["error"], "verification_failed");
}
