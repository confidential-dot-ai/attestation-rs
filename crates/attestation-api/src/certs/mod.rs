pub mod cache;
pub mod manager;
pub mod nras_provider;
pub mod revocation;
pub mod snp_provider;
pub mod tdx_provider;

use std::time::Duration;

/// Convert hours to a `Duration` with overflow protection and a 60-second floor.
pub(crate) fn hours_to_duration(hours: u64) -> Duration {
    Duration::from_secs(hours.saturating_mul(3600).max(60))
}
