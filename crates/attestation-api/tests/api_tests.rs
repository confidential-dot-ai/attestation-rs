use axum::body::Body;
use axum::http::{Request, StatusCode};
use std::sync::Arc;
use tower::ServiceExt;

use attestation_api::certs::cache::CertCache;
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
    let cert_cache = Arc::new(CertCache::new(&Default::default()));
    let cert_provider =
        attestation_api::certs::snp_provider::CachedCertProvider::new(cert_cache.clone(), false);
    let tdx_provider =
        attestation_api::certs::tdx_provider::CachedTdxProvider::new(cert_cache.clone());
    let verifier = Arc::new(
        attestation::Verifier::new()
            .with_cert_provider(cert_provider)
            .with_tdx_provider(tdx_provider),
    );
    AppState {
        config: Arc::new(config),
        cert_cache,
        token_issuer: None,
        verifier,
    }
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
        "params": {}
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
async fn verify_rejects_full_envelope_evidence() {
    let state = test_state();
    let app = build_api_router(state);

    let body = serde_json::json!({
        "platform": "snp",
        "evidence": {"platform": "snp", "evidence": {}},
        "params": {}
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
    assert!(json["message"]
        .as_str()
        .unwrap()
        .contains("platform-specific evidence"));
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
    assert!(json["message"].as_str().unwrap().contains("not allowed"));
}

#[tokio::test]
async fn certs_status_returns_ok() {
    let state = test_state();
    let app = build_api_router(state);

    let resp = app
        .oneshot(
            Request::builder()
                .uri("/certs/status")
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
    assert_eq!(json["vcek_count"], 0);
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
                .uri("/certs/status")
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
    assert!(json["message"].as_str().unwrap().contains("Authorization"));
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
                .uri("/certs/status")
                .header("authorization", "Bearer test-key-123")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(resp.status(), StatusCode::OK);
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
                .uri("/certs/status")
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
    assert!(json["message"].as_str().unwrap().contains("invalid"));
}

#[tokio::test]
async fn no_auth_allows_all_requests() {
    let state = test_state();
    let app = build_router(state);

    let resp = app
        .oneshot(
            Request::builder()
                .uri("/certs/status")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(resp.status(), StatusCode::OK);
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

    assert!(resp.status().is_client_error());
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
        "params": {}
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
    assert_eq!(verify_json["result"]["signature_valid"], true);
}
