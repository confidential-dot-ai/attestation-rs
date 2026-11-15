use std::sync::Arc;

use tokio::sync::Semaphore;

pub mod api;
pub mod config;
pub mod error;
pub mod middleware;
pub mod server;
pub mod token;

use attestation::Verifier;
use config::Config;
use token::issuer::TokenIssuer;

#[derive(Clone)]
pub struct AppState {
    pub config: Arc<Config>,
    pub token_issuer: Option<Arc<TokenIssuer>>,
    pub verifier: Arc<Verifier>,
    /// One permit per verification in progress
    /// (`server.max_concurrent_verifications`).
    pub verifications: Arc<Semaphore>,
}

impl AppState {
    pub fn new(
        config: Arc<Config>,
        token_issuer: Option<Arc<TokenIssuer>>,
        verifier: Arc<Verifier>,
    ) -> Self {
        let verifications = Arc::new(Semaphore::new(config.server.max_concurrent_verifications));
        Self {
            config,
            token_issuer,
            verifier,
            verifications,
        }
    }
}
