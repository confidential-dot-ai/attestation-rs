use attestation::AttestationError;
use axum::extract::rejection::JsonRejection;
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use serde::Serialize;

#[derive(Debug, thiserror::Error)]
pub enum ApiError {
    #[error("verification failed: {0}")]
    Verification(#[from] AttestationError),

    #[error("no TEE platform detected")]
    NoPlatform,

    #[error("attestation is disabled")]
    AttestNotAvailable,

    #[error("invalid request: {0}")]
    BadRequest(String),

    #[error("invalid request: {0}")]
    Body(#[from] JsonRejection),

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
            // failed and not the submitted evidence. Retryable.
            ApiError::Verification(AttestationError::CollateralUnavailable(_)) => {
                (StatusCode::BAD_GATEWAY, "collateral_unavailable")
            }
            ApiError::Verification(e) if e.is_invalid_params() => {
                (StatusCode::BAD_REQUEST, "bad_request")
            }
            ApiError::Verification(AttestationError::PlatformNotAllowed(_)) => {
                (StatusCode::UNPROCESSABLE_ENTITY, "platform_not_allowed")
            }
            ApiError::Verification(_) => (StatusCode::UNPROCESSABLE_ENTITY, "verification_failed"),
            ApiError::NoPlatform => (StatusCode::SERVICE_UNAVAILABLE, "no_platform"),
            ApiError::AttestNotAvailable => (StatusCode::BAD_REQUEST, "attest_not_available"),
            ApiError::BadRequest(_) => (StatusCode::BAD_REQUEST, "bad_request"),
            ApiError::Body(rejection) => match rejection.status() {
                StatusCode::PAYLOAD_TOO_LARGE => {
                    (StatusCode::PAYLOAD_TOO_LARGE, "payload_too_large")
                }
                StatusCode::UNSUPPORTED_MEDIA_TYPE => {
                    (StatusCode::UNSUPPORTED_MEDIA_TYPE, "unsupported_media_type")
                }
                _ => (StatusCode::BAD_REQUEST, "bad_request"),
            },
            ApiError::CertFetch(_) => (StatusCode::BAD_GATEWAY, "cert_fetch_failed"),
            ApiError::TokenNotConfigured => (StatusCode::BAD_REQUEST, "token_not_configured"),
            ApiError::Internal(_) => (StatusCode::INTERNAL_SERVER_ERROR, "internal_error"),
        };

        let message = match &self {
            ApiError::Internal(detail) => {
                tracing::error!(detail, "internal error");
                "an internal error occurred".to_string()
            }
            // The inner error alone: these are not verdicts on the evidence, so
            // `Verification`'s "verification failed" prefix would mislead.
            ApiError::Verification(inner) if inner.is_retryable() || inner.is_invalid_params() => {
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

    async fn error_key(resp: Response) -> String {
        let body = axum::body::to_bytes(resp.into_body(), usize::MAX)
            .await
            .expect("read error body");
        let json: serde_json::Value = serde_json::from_slice(&body).expect("error body is JSON");
        json["error"].as_str().expect("error key").to_string()
    }

    #[tokio::test]
    async fn collateral_this_service_could_not_fetch_is_an_upstream_failure() {
        let resp = ApiError::Verification(AttestationError::CollateralUnavailable(
            "cached VCEK fetch: error sending request for url (https://kdsintf.amd.com/vcek/v1/Genoa/…)"
                .to_string(),
        ))
        .into_response();

        assert_eq!(resp.status(), StatusCode::BAD_GATEWAY);
        assert_eq!(error_key(resp).await, "collateral_unavailable");
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

    #[tokio::test]
    async fn invalid_params_are_a_bad_request() {
        for err in [
            AttestationError::InvalidParams("accepted_tcb_statuses is empty".to_string()),
            AttestationError::ReportDataTooLarge { max: 64 },
        ] {
            let resp = ApiError::Verification(err).into_response();
            assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
            assert_eq!(error_key(resp).await, "bad_request");
        }
    }
}
