use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use serde::Serialize;

#[derive(Debug, thiserror::Error)]
pub enum ApiError {
    #[error("verification failed: {0}")]
    Verification(#[from] attestation::AttestationError),

    #[error("no TEE platform detected")]
    NoPlatform,

    #[error("attestation is disabled")]
    AttestNotAvailable,

    #[error("invalid request: {0}")]
    BadRequest(String),

    #[error("cert fetch failed: {0}")]
    CertFetch(String),

    #[error("token issuer not configured")]
    TokenNotConfigured,

    #[error("internal error: {0}")]
    Internal(String),
}

#[derive(Serialize)]
struct ErrorBody {
    error: &'static str,
    message: String,
}

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        let (status, error_key) = match &self {
            // Collateral this service could not fetch, so it is the upstream that
            // failed and not the submitted evidence.
            ApiError::Verification(attestation::AttestationError::CertFetchError(_)) => {
                (StatusCode::BAD_GATEWAY, "cert_fetch_failed")
            }
            ApiError::Verification(_) => (StatusCode::UNPROCESSABLE_ENTITY, "verification_failed"),
            ApiError::NoPlatform => (StatusCode::SERVICE_UNAVAILABLE, "no_platform"),
            ApiError::AttestNotAvailable => (StatusCode::BAD_REQUEST, "attest_not_available"),
            ApiError::BadRequest(_) => (StatusCode::BAD_REQUEST, "bad_request"),
            ApiError::CertFetch(_) => (StatusCode::BAD_GATEWAY, "cert_fetch_failed"),
            ApiError::TokenNotConfigured => (StatusCode::BAD_REQUEST, "token_not_configured"),
            ApiError::Internal(_) => (StatusCode::INTERNAL_SERVER_ERROR, "internal_error"),
        };

        let message = match &self {
            ApiError::Internal(detail) => {
                tracing::error!(detail, "internal error");
                "an internal error occurred".to_string()
            }
            // The inner error alone: `Verification`'s "verification failed" prefix
            // would name the evidence this status exists to stop naming.
            ApiError::Verification(inner @ attestation::AttestationError::CertFetchError(_)) => {
                inner.to_string()
            }
            other => other.to_string(),
        };

        let body = ErrorBody {
            error: error_key,
            message,
        };

        (status, axum::Json(body)).into_response()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use attestation::AttestationError;

    async fn error_key(resp: Response) -> String {
        let body = axum::body::to_bytes(resp.into_body(), usize::MAX)
            .await
            .expect("read error body");
        let json: serde_json::Value = serde_json::from_slice(&body).expect("error body is JSON");
        json["error"].as_str().expect("error key").to_string()
    }

    #[tokio::test]
    async fn collateral_this_service_could_not_fetch_is_an_upstream_failure() {
        let resp = ApiError::Verification(AttestationError::CertFetchError(
            "cached VCEK fetch: error sending request for url (https://kdsintf.amd.com/vcek/v1/Genoa/…)"
                .to_string(),
        ))
        .into_response();

        assert_eq!(resp.status(), StatusCode::BAD_GATEWAY);
        assert_eq!(error_key(resp).await, "cert_fetch_failed");
    }

    #[tokio::test]
    async fn a_chain_that_does_not_validate_is_still_a_verdict() {
        let resp = ApiError::Verification(AttestationError::CertChainError(
            "VCEK is not signed by the ASK".to_string(),
        ))
        .into_response();

        assert_eq!(resp.status(), StatusCode::UNPROCESSABLE_ENTITY);
        assert_eq!(error_key(resp).await, "verification_failed");
    }
}
