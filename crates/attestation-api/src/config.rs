use serde::Deserialize;
use std::fmt;
use std::net::SocketAddr;
use std::path::Path;

/// Canonical processor generation names supported by AMD SEV-SNP.
pub const KNOWN_GENERATIONS: &[&str] = &["Milan", "Genoa", "Turin"];

/// Platform names this service can generate evidence for.
pub const SUPPORTED_ATTESTATION_PLATFORMS: &[&str] =
    &["snp", "tdx", "az-snp", "az-tdx", "gcp-snp", "gcp-tdx"];

/// Normalize a generation name to its canonical form (case-insensitive match).
/// Returns `None` if the generation is not recognized.
pub fn normalize_generation(name: &str) -> Option<&'static str> {
    KNOWN_GENERATIONS
        .iter()
        .find(|g| g.eq_ignore_ascii_case(name))
        .copied()
}

/// Normalize a service platform name to its canonical form.
/// Returns `None` if the platform is not supported for service-side evidence generation.
pub fn normalize_platform(name: &str) -> Option<&'static str> {
    SUPPORTED_ATTESTATION_PLATFORMS
        .iter()
        .find(|p| p.eq_ignore_ascii_case(name))
        .copied()
}

/// Resolve the effective NRAS GPU endpoint URL.
///
/// Priority: config-file value (if non-empty) > `NV_NRAS_GPU_URL` env var >
/// library default.
pub fn resolve_nras_gpu_url(certs: &CertsConfig) -> String {
    if !certs.nras_gpu_url.is_empty() {
        return certs.nras_gpu_url.clone();
    }
    std::env::var("NV_NRAS_GPU_URL")
        .unwrap_or_else(|_| attestation::platforms::nvidia_gpu::provider::NRAS_GPU_URL.to_string())
}

/// Resolve the effective NRAS switch endpoint URL.
///
/// Priority: config-file value (if non-empty) > `NV_NRAS_SWITCH_URL` env var >
/// library default.
pub fn resolve_nras_switch_url(certs: &CertsConfig) -> String {
    if !certs.nras_switch_url.is_empty() {
        return certs.nras_switch_url.clone();
    }
    std::env::var("NV_NRAS_SWITCH_URL").unwrap_or_else(|_| {
        attestation::platforms::nvidia_gpu::provider::NRAS_SWITCH_URL.to_string()
    })
}

#[derive(Debug, Clone, Default, Deserialize)]
#[serde(default)]
pub struct Config {
    pub server: ServerConfig,
    pub auth: AuthConfig,
    pub certs: CertsConfig,
    pub token: TokenConfig,
    pub attestation: AttestationConfig,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(default)]
pub struct ServerConfig {
    pub bind: String,
    pub tls: TlsConfig,
}

#[derive(Debug, Clone, Default, Deserialize)]
#[serde(default)]
pub struct TlsConfig {
    pub enabled: bool,
    pub cert_path: String,
    pub key_path: String,
}

#[derive(Clone, Default, Deserialize)]
#[serde(default)]
pub struct AuthConfig {
    pub api_keys: Vec<String>,
}

impl fmt::Debug for AuthConfig {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("AuthConfig")
            .field("api_keys", &format!("[{} keys]", self.api_keys.len()))
            .finish()
    }
}

#[derive(Debug, Clone, Deserialize)]
#[serde(default)]
pub struct CertsConfig {
    pub cache_max_entries: u64,
    pub vcek_ttl_hours: u64,
    pub chain_ttl_hours: u64,
    pub crl_refresh_hours: u64,
    pub tdx_collateral_ttl_hours: u64,
    pub prefetch_chains: Vec<String>,
    /// If true, verification fails when CRL cannot be fetched (fail-closed).
    /// If false, CRL fetch failures are logged and revocation check is skipped (fail-open).
    pub require_crl: bool,

    // --- NVIDIA NRAS / GPU attestation ---
    /// TTL for cached NRAS JWKS entries (hours).
    pub jwks_ttl_hours: u64,
    /// If true, prefetch GPU+switch JWKS on startup and refresh in background.
    pub prefetch_nras_jwks: bool,
    /// Override the NRAS GPU endpoint. Falls back to library default
    /// (`https://nras.attestation.nvidia.com/v3/attest/gpu`, honoring
    /// `NV_NRAS_GPU_URL` env var) when empty.
    pub nras_gpu_url: String,
    /// Override the NRAS switch endpoint. Falls back to library default
    /// (`https://nras.attestation.nvidia.com/v3/attest/switch`, honoring
    /// `NV_NRAS_SWITCH_URL` env var) when empty.
    pub nras_switch_url: String,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(default)]
pub struct TokenConfig {
    pub enabled: bool,
    pub issuer: String,
    pub duration_minutes: u64,
    pub key_path: String,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(default)]
pub struct AttestationConfig {
    /// If true, the `/attest` endpoint is available.
    pub enabled: bool,
    pub platforms: Vec<String>,
    /// If false, requests with `allow_debug: true` are rejected.
    pub allow_debug: bool,
    /// TDX quote generation method: "auto", "vsock", or "configfs".
    /// - "auto": try vsock first (~2-4ms), fall back to ConfigFS TSM (~1015ms).
    /// - "vsock": direct AF_VSOCK to QGS only. Requires vhost-vsock-pci + QGS.
    /// - "configfs": kernel ConfigFS TSM only. Use on GCP and other cloud platforms.
    pub tdx_quote_method: String,
}

// --- Defaults ---

impl Default for ServerConfig {
    fn default() -> Self {
        Self {
            bind: "0.0.0.0:8400".to_string(),
            tls: TlsConfig::default(),
        }
    }
}

impl Default for CertsConfig {
    fn default() -> Self {
        Self {
            cache_max_entries: 1024,
            vcek_ttl_hours: 24,
            chain_ttl_hours: 168,
            crl_refresh_hours: 6,
            tdx_collateral_ttl_hours: 24,
            prefetch_chains: vec!["milan".to_string()],
            require_crl: false,
            jwks_ttl_hours: 1,
            prefetch_nras_jwks: true,
            nras_gpu_url: String::new(),
            nras_switch_url: String::new(),
        }
    }
}

impl Default for TokenConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            issuer: "attestation-api".to_string(),
            duration_minutes: 5,
            key_path: String::new(),
        }
    }
}

impl Default for AttestationConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            platforms: vec![
                "snp".to_string(),
                "tdx".to_string(),
                "az-snp".to_string(),
                "az-tdx".to_string(),
                "gcp-snp".to_string(),
                "gcp-tdx".to_string(),
            ],
            allow_debug: false,
            tdx_quote_method: "auto".to_string(),
        }
    }
}

#[cfg(target_os = "linux")]
impl AttestationConfig {
    /// Convert the `tdx_quote_method` config string to `AttestOptions`.
    pub fn attest_options(&self) -> attestation::AttestOptions {
        attestation::AttestOptions {
            tdx_quote_method: match self.tdx_quote_method.as_str() {
                "vsock" => attestation::TdxQuoteMethod::Vsock,
                "configfs" => attestation::TdxQuoteMethod::ConfigFs,
                _ => attestation::TdxQuoteMethod::Auto,
            },
        }
    }
}

impl Config {
    pub fn load(path: &Path) -> anyhow::Result<Self> {
        let contents = std::fs::read_to_string(path)?;
        let config: Config = toml::from_str(&contents)?;
        Ok(config)
    }

    /// Validate configuration at startup. Returns an error for invalid combinations.
    pub fn validate(&self) -> Result<(), String> {
        // Validate bind address is parseable
        self.server
            .bind
            .parse::<SocketAddr>()
            .map_err(|e| format!("invalid server.bind address '{}': {e}", self.server.bind))?;

        // Validate TLS paths when TLS is enabled
        if self.server.tls.enabled {
            if self.server.tls.cert_path.is_empty() {
                return Err("tls.enabled requires a non-empty tls.cert_path".to_string());
            }
            if self.server.tls.key_path.is_empty() {
                return Err("tls.enabled requires a non-empty tls.key_path".to_string());
            }
            if !Path::new(&self.server.tls.cert_path).exists() {
                return Err(format!(
                    "tls.cert_path '{}' does not exist",
                    self.server.tls.cert_path
                ));
            }
            if !Path::new(&self.server.tls.key_path).exists() {
                return Err(format!(
                    "tls.key_path '{}' does not exist",
                    self.server.tls.key_path
                ));
            }
        }

        // Validate token duration when token is enabled
        if self.token.enabled && self.token.duration_minutes == 0 {
            return Err("token.duration_minutes must be > 0 when token is enabled".to_string());
        }

        // Validate cache TTL values are non-zero to prevent tight refresh loops
        if self.certs.chain_ttl_hours == 0 {
            return Err("certs.chain_ttl_hours must be > 0".to_string());
        }
        if self.certs.crl_refresh_hours == 0 {
            return Err("certs.crl_refresh_hours must be > 0".to_string());
        }
        if self.certs.vcek_ttl_hours == 0 {
            return Err("certs.vcek_ttl_hours must be > 0".to_string());
        }
        if self.certs.tdx_collateral_ttl_hours == 0 {
            return Err("certs.tdx_collateral_ttl_hours must be > 0".to_string());
        }
        if self.certs.jwks_ttl_hours == 0 {
            return Err("certs.jwks_ttl_hours must be > 0".to_string());
        }

        // Validate tdx_quote_method
        match self.attestation.tdx_quote_method.as_str() {
            "auto" | "vsock" | "configfs" => {}
            other => {
                return Err(format!(
                    "invalid attestation.tdx_quote_method '{other}' (expected: auto, vsock, configfs)"
                ));
            }
        }

        // Validate prefetch_chains are known generations
        for chain in &self.certs.prefetch_chains {
            if normalize_generation(chain).is_none() {
                return Err(format!(
                    "unknown processor generation '{chain}' in certs.prefetch_chains (known: {KNOWN_GENERATIONS:?})"
                ));
            }
        }

        for platform in &self.attestation.platforms {
            if normalize_platform(platform).is_none() {
                return Err(format!(
                    "unknown platform '{platform}' in attestation.platforms (known: {SUPPORTED_ATTESTATION_PLATFORMS:?})"
                ));
            }
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn auth_config_debug_redacts_keys() {
        let config = AuthConfig {
            api_keys: vec![
                "super-secret-key-1".to_string(),
                "super-secret-key-2".to_string(),
            ],
        };
        let debug_output = format!("{config:?}");
        assert!(
            debug_output.contains("[2 keys]"),
            "Debug should show key count"
        );
        assert!(
            !debug_output.contains("super-secret"),
            "Debug must not contain actual key values"
        );
    }

    #[test]
    fn validate_rejects_zero_ttl_values() {
        let mut config = Config::default();
        config.certs.chain_ttl_hours = 0;
        assert!(
            config.validate().is_err(),
            "chain_ttl_hours = 0 should be rejected"
        );

        let mut config = Config::default();
        config.certs.crl_refresh_hours = 0;
        assert!(
            config.validate().is_err(),
            "crl_refresh_hours = 0 should be rejected"
        );

        let mut config = Config::default();
        config.certs.vcek_ttl_hours = 0;
        assert!(
            config.validate().is_err(),
            "vcek_ttl_hours = 0 should be rejected"
        );

        let mut config = Config::default();
        config.certs.tdx_collateral_ttl_hours = 0;
        assert!(
            config.validate().is_err(),
            "tdx_collateral_ttl_hours = 0 should be rejected"
        );
    }
}
