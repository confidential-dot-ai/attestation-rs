use std::sync::Arc;

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
}
