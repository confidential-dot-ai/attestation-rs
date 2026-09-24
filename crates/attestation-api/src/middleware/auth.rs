use axum::body::Body;
use axum::extract::State;
use axum::http::{Request, StatusCode};
use axum::middleware::Next;
use axum::response::{IntoResponse, Response};
use axum::Json;
use hmac::{Hmac, Mac};
use serde_json::json;
use sha2::Sha256;
use std::sync::OnceLock;
use subtle::ConstantTimeEq;

use crate::AppState;

/// The key API keys are compared under, drawn once per process.
fn comparison_key() -> &'static [u8; 32] {
    static KEY: OnceLock<[u8; 32]> = OnceLock::new();
    KEY.get_or_init(rand::random)
}

fn comparison_tag(value: &str) -> [u8; 32] {
    let mut mac =
        Hmac::<Sha256>::new_from_slice(comparison_key()).expect("HMAC accepts a key of any length");
    mac.update(value.as_bytes());
    mac.finalize().into_bytes().into()
}

/// Whether `provided` is one of the configured keys, compared as HMAC tags
/// under a per-process key: constant time whatever the keys' lengths, and the
/// tags are never stored or shown, so a slow password hash would add nothing.
fn verify_api_key(provided: &str, keys: &[String]) -> bool {
    let provided_tag = comparison_tag(provided);
    let mut found = subtle::Choice::from(0);
    for expected in keys {
        found |= comparison_tag(expected).ct_eq(&provided_tag);
    }
    bool::from(found)
}

pub async fn api_key_auth(
    State(state): State<AppState>,
    request: Request<Body>,
    next: Next,
) -> Response {
    let header_value = match request.headers().get("authorization") {
        Some(v) => v,
        None => {
            tracing::warn!("rejected request without Authorization header");
            return error_response(
                StatusCode::UNAUTHORIZED,
                "unauthorized",
                "missing Authorization header",
            );
        }
    };

    let header_str = match header_value.to_str() {
        Ok(s) => s,
        Err(_) => {
            tracing::warn!("rejected request with non-ASCII Authorization header");
            return error_response(
                StatusCode::UNAUTHORIZED,
                "unauthorized",
                "malformed Authorization header",
            );
        }
    };

    match header_str.strip_prefix("Bearer ") {
        Some(key) if verify_api_key(key, &state.config.auth.api_keys) => next.run(request).await,
        Some(_) => {
            tracing::warn!("rejected request with invalid API key");
            error_response(StatusCode::UNAUTHORIZED, "unauthorized", "invalid API key")
        }
        None => {
            tracing::warn!("rejected request with unsupported Authorization scheme");
            error_response(
                StatusCode::UNAUTHORIZED,
                "unauthorized",
                "Authorization header must use Bearer scheme",
            )
        }
    }
}

fn error_response(status: StatusCode, error: &str, message: &str) -> Response {
    (
        status,
        Json(json!({
            "error": error,
            "message": message,
        })),
    )
        .into_response()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rejects_prefix_of_valid_key() {
        let keys = vec!["secret_extended".to_string()];
        assert!(!verify_api_key("secret", &keys));
    }

    #[test]
    fn rejects_longer_key_containing_valid() {
        let keys = vec!["abc".to_string()];
        assert!(!verify_api_key("abcdef", &keys));
    }

    #[test]
    fn accepts_exact_match() {
        let keys = vec!["my-secret-key".to_string()];
        assert!(verify_api_key("my-secret-key", &keys));
    }

    #[test]
    fn rejects_empty_provided_key() {
        let keys = vec!["nonempty".to_string()];
        assert!(!verify_api_key("", &keys));
    }

    #[test]
    fn rejects_when_no_keys_configured() {
        let keys: Vec<String> = vec![];
        assert!(!verify_api_key("anything", &keys));
    }

    #[test]
    fn keys_are_compared_as_tags_under_the_process_key() {
        use sha2::Digest;
        assert_eq!(comparison_tag("k"), comparison_tag("k"));
        assert_ne!(comparison_tag("k"), comparison_tag("k2"));
        // A tag is keyed: without the process key it cannot be recomputed.
        let bare: [u8; 32] = Sha256::digest(b"k").into();
        assert_ne!(comparison_tag("k"), bare);
    }

    #[test]
    fn accepts_second_key_in_list() {
        let keys = vec!["first-key".to_string(), "second-key".to_string()];
        assert!(verify_api_key("second-key", &keys));
        assert!(verify_api_key("first-key", &keys));
        assert!(!verify_api_key("third-key", &keys));
    }
}
