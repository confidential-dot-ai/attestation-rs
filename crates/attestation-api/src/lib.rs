use std::sync::Arc;
use std::time::Duration;

pub mod api;
pub mod config;
pub mod error;
pub mod middleware;
pub mod pool;
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
    /// Runs `/verify`'s verifications.
    pub verify_pool: Arc<pool::Pool>,
}

impl AppState {
    pub fn new(
        config: Arc<Config>,
        token_issuer: Option<Arc<TokenIssuer>>,
        verifier: Arc<Verifier>,
    ) -> Self {
        let server = &config.server;
        let verify_pool = Arc::new(pool::Pool::new(
            server.verify_threads(),
            Duration::from_millis(server.max_queue_wait_ms),
            Duration::from_millis(server.queue_deadline_ms),
        ));
        Self {
            config,
            token_issuer,
            verifier,
            verify_pool,
        }
    }
}
