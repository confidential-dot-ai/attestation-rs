//! Everything a platform verifier gets from outside: the collateral store
//! and the evaluation time.

use crate::collateral::Store;
use crate::error::{AttestationError, Result};

/// A vendor response the caller already has: the URL it came from, the body,
/// and the issuer chain Intel PCS sent in a header (PEM), if any.
pub type HeldResponse = (String, Vec<u8>, Option<String>);

/// The collateral store and evaluation time shared by every platform
/// verifier. Construct once and reuse: the store keeps what it fetched.
pub struct Context {
    store: Store,
    /// Fixed evaluation time in Unix seconds; `None` = the current time.
    time: Option<i64>,
}

impl Context {
    /// Collateral from memory and the vendors, evaluated at the current time.
    /// On wasm32 there is no network: only held responses ([`Self::with_held`]).
    #[must_use]
    pub fn new() -> Self {
        #[cfg(not(target_arch = "wasm32"))]
        let store = Store::new(false);
        #[cfg(target_arch = "wasm32")]
        let store = Store::held_only();
        Self { store, time: None }
    }

    /// No network: collateral only from what is held, in memory or on disk. A
    /// piece held nowhere is
    /// [`CollateralUnavailable`](AttestationError::CollateralUnavailable).
    #[must_use]
    pub fn offline() -> Self {
        #[cfg(not(target_arch = "wasm32"))]
        let store = Store::new(true);
        #[cfg(target_arch = "wasm32")]
        let store = Store::held_only();
        Self { store, time: None }
    }

    /// Only `responses`: no memory, disk or network. The store records the
    /// URLs it was asked for and did not hold ([`Store::missing`]).
    #[must_use]
    pub fn held(responses: impl IntoIterator<Item = HeldResponse>) -> Self {
        Self {
            store: Store::held_only(),
            time: None,
        }
        .with_held(responses)
    }

    /// Keep collateral in `dir` across processes, and read it from there.
    #[cfg(not(target_arch = "wasm32"))]
    #[must_use]
    pub fn with_cache_dir(mut self, dir: impl Into<std::path::PathBuf>) -> Self {
        if let Some(native) = self.store.native_mut() {
            native.disk = Some(crate::collateral::disk::Disk::new(dir));
        }
        self
    }

    /// Use these vendor responses before any other source. Each is verified
    /// like a fetched one.
    #[must_use]
    pub fn with_held(mut self, responses: impl IntoIterator<Item = HeldResponse>) -> Self {
        for (url, body, issuer_chain) in responses {
            self.store.hold(url, body, issuer_chain);
        }
        self
    }

    /// Fetch all collateral from `{base}/{vendor host}/{path}`, plain HTTP
    /// allowed. Only for tests.
    #[cfg(all(any(test, feature = "test-vendor"), not(target_arch = "wasm32")))]
    #[must_use]
    pub fn with_vendor_base(mut self, base: &str) -> Self {
        if let Some(native) = self.store.native_mut() {
            native.vendor = native.vendor.take().map(|v| v.with_base(base));
        }
        self
    }

    #[cfg(all(test, feature = "tdx", not(target_arch = "wasm32")))]
    pub(crate) fn with_recheck(mut self, recheck: std::time::Duration) -> Self {
        if let Some(native) = self.store.native_mut() {
            native.recheck = recheck;
        }
        self
    }

    /// Send NVIDIA GPU evidence to these NRAS endpoints instead of the
    /// default ones (or `NV_NRAS_GPU_URL` / `NV_NRAS_SWITCH_URL`). A URL
    /// without a scheme and host is [`AttestationError::InvalidParams`].
    #[cfg(all(feature = "nvidia-gpu", not(target_arch = "wasm32")))]
    pub fn with_nras_urls(mut self, gpu_url: String, switch_url: String) -> Result<Self> {
        for url in [&gpu_url, &switch_url] {
            crate::platforms::nvidia_gpu::jwks_url_for_endpoint(url).map_err(|_| {
                AttestationError::InvalidParams(format!("invalid NRAS URL {url:?}"))
            })?;
        }
        if let Some(vendor) = self.store.native_mut().and_then(|n| n.vendor.as_mut()) {
            vendor.nras.gpu_url = gpu_url;
            vendor.nras.switch_url = switch_url;
        }
        Ok(self)
    }

    /// Evaluate certificate, CRL and token validity at a fixed time (Unix
    /// seconds) instead of the current time. A time outside years 1-9999 is
    /// [`AttestationError::InvalidParams`].
    pub fn at(mut self, unix_seconds: i64) -> Result<Self> {
        // 0001-01-01T00:00:00Z ..= 9999-12-31T23:59:59Z, the X.509 time range.
        if !(-62_135_596_800..=253_402_300_799).contains(&unix_seconds) {
            return Err(AttestationError::InvalidParams(format!(
                "evaluation time {unix_seconds} is out of range"
            )));
        }
        self.time = Some(unix_seconds);
        Ok(self)
    }

    /// The evaluation time in Unix seconds.
    pub fn now(&self) -> i64 {
        self.time.unwrap_or_else(|| chrono::Utc::now().timestamp())
    }

    pub fn store(&self) -> &Store {
        &self.store
    }
}
impl Default for Context {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[cfg(feature = "nvidia-gpu")]
    #[test]
    fn an_nras_url_that_names_no_host_is_refused_when_configured() {
        let good = "https://nras.attestation.nvidia.com/v3/attest/gpu".to_string();
        assert!(Context::new()
            .with_nras_urls(good.clone(), good.clone())
            .is_ok());
        for (gpu, switch) in [("nras", good.as_str()), (good.as_str(), "nras")] {
            assert!(matches!(
                Context::new().with_nras_urls(gpu.into(), switch.into()),
                Err(AttestationError::InvalidParams(_))
            ));
        }
    }

    #[test]
    fn an_evaluation_time_out_of_range_is_invalid_params() {
        assert!(Context::offline().at(1_791_244_800).is_ok());
        for t in [i64::MIN, i64::MAX, 253_402_300_800] {
            assert!(matches!(
                Context::offline().at(t),
                Err(AttestationError::InvalidParams(_))
            ));
        }
    }
}
