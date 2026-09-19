//! Typed collateral failures. Every variant names the key, so a log line or
//! an API error says which artifact failed and why without string parsing.

use super::key::CollateralKey;
use chrono::{DateTime, Utc};
use thiserror::Error;

#[derive(Debug, Error)]
pub enum CollateralError {
    #[error("{key}: cannot name a URL: {reason}")]
    NoUrl { key: CollateralKey, reason: String },

    #[error("{key}: fetch failed: {reason}")]
    Fetch { key: CollateralKey, reason: String },

    #[error("{key}: response is {size} bytes, above the {max} byte limit")]
    TooLarge {
        key: CollateralKey,
        size: usize,
        max: usize,
    },

    #[error("{key}: Intel PCS response carries no {header} header; refusing unsigned collateral")]
    Unsigned {
        key: CollateralKey,
        header: &'static str,
    },

    #[error("{key}: not a valid artifact: {reason}")]
    Parse { key: CollateralKey, reason: String },

    #[error("{key}: expired at {valid_until}")]
    Expired {
        key: CollateralKey,
        valid_until: DateTime<Utc>,
    },

    #[error(
        "{key}: backing off after {consecutive} consecutive failures; next retry at {retry_at}"
    )]
    Backoff {
        key: CollateralKey,
        consecutive: u32,
        retry_at: DateTime<Utc>,
    },

    #[error("{key}: the cache holds no copy and fetching is disabled")]
    Offline { key: CollateralKey },
}

pub type CollateralResult<T> = std::result::Result<T, CollateralError>;

impl CollateralError {
    pub fn key(&self) -> &CollateralKey {
        match self {
            CollateralError::NoUrl { key, .. }
            | CollateralError::Fetch { key, .. }
            | CollateralError::TooLarge { key, .. }
            | CollateralError::Unsigned { key, .. }
            | CollateralError::Parse { key, .. }
            | CollateralError::Expired { key, .. }
            | CollateralError::Backoff { key, .. }
            | CollateralError::Offline { key } => key,
        }
    }
}
