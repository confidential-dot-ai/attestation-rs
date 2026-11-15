use serde::Deserialize;
use std::fmt;
use std::net::SocketAddr;
use std::path::Path;

/// Platform names this service can generate evidence for.
pub const SUPPORTED_ATTESTATION_PLATFORMS: &[&str] =
    &["snp", "tdx", "az-snp", "az-tdx", "gcp-snp", "gcp-tdx"];

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
pub fn resolve_nras_gpu_url(nras: &NrasConfig) -> String {
    if !nras.gpu_url.is_empty() {
        return nras.gpu_url.clone();
    }
    std::env::var("NV_NRAS_GPU_URL")
        .unwrap_or_else(|_| attestation::platforms::nvidia_gpu::provider::NRAS_GPU_URL.to_string())
}

/// Resolve the effective NRAS switch endpoint URL.
///
/// Priority: config-file value (if non-empty) > `NV_NRAS_SWITCH_URL` env var >
/// library default.
pub fn resolve_nras_switch_url(nras: &NrasConfig) -> String {
    if !nras.switch_url.is_empty() {
        return nras.switch_url.clone();
    }
    std::env::var("NV_NRAS_SWITCH_URL").unwrap_or_else(|_| {
        attestation::platforms::nvidia_gpu::provider::NRAS_SWITCH_URL.to_string()
    })
}

#[derive(Debug, Clone, Default, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct Config {
    pub server: ServerConfig,
    pub auth: AuthConfig,
    pub nras: NrasConfig,
    pub token: TokenConfig,
    pub attestation: AttestationConfig,
    pub verify: VerifyConfig,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct ServerConfig {
    pub bind: String,
    pub tls: TlsConfig,
    /// Connections served at once; more wait in the listen backlog.
    pub max_connections: usize,
    /// Raise the soft open-files limit to this (at most the hard limit).
    pub max_open_files: u64,
}

/// Bounded verification: `workers` jobs at once (0: one per vCPU), and
/// `queue_per_worker` waiting per worker for at most `queue_deadline_ms`.
/// Evidence that needs a fetch is verified by one of `cold_workers`, within
/// `fetch_deadline_ms`.
#[derive(Debug, Clone, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct VerifyConfig {
    pub workers: usize,
    pub queue_per_worker: usize,
    pub queue_deadline_ms: u64,
    pub cold_workers: usize,
    pub fetch_deadline_ms: u64,
}

impl Default for VerifyConfig {
    fn default() -> Self {
        Self {
            workers: 0,
            queue_per_worker: 32,
            queue_deadline_ms: 50,
            cold_workers: 8,
            fetch_deadline_ms: 10_000,
        }
    }
}

impl VerifyConfig {
    pub fn workers(&self) -> usize {
        match self.workers {
            0 => std::thread::available_parallelism().map_or(1, |n| n.get()),
            n => n,
        }
    }
}

/// Deprecated: the API does not terminate TLS. The section still parses so
/// existing files with `enabled = false` load; `enabled = true` fails
/// [`Config::validate`].
#[derive(Debug, Clone, Default, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct TlsConfig {
    /// Deprecated: must be false.
    pub enabled: bool,
    /// Deprecated: ignored.
    pub cert_path: String,
    /// Deprecated: ignored.
    pub key_path: String,
}

#[derive(Clone, Default, Deserialize)]
#[serde(default, deny_unknown_fields)]
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

#[derive(Debug, Clone, Default, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct NrasConfig {
    /// NVIDIA's GPU attestation endpoint. Empty: `NV_NRAS_GPU_URL`, else
    /// `https://nras.attestation.nvidia.com/v3/attest/gpu`.
    pub gpu_url: String,
    /// NVIDIA's switch attestation endpoint. Empty: `NV_NRAS_SWITCH_URL`, else
    /// `https://nras.attestation.nvidia.com/v3/attest/switch`.
    pub switch_url: String,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct TokenConfig {
    pub enabled: bool,
    pub issuer: String,
    pub duration_minutes: u64,
    pub key_path: String,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct AttestationConfig {
    /// If true, the `/attest` endpoint is available.
    pub enabled: bool,
    pub platforms: Vec<String>,
    /// If false, requests with `allow_debug: true` are rejected.
    pub allow_debug: bool,
    /// If false, requests whose `accepted_tcb_statuses` include a status Intel
    /// does not consider valid (`Revoked`, `NoMatchingLevel`) are rejected.
    pub allow_revoked_or_unlisted_tcb: bool,
    /// If false, requests with `max_vmpl` above 0 are rejected.
    pub allow_nonzero_vmpl: bool,
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
            max_connections: 4096,
            max_open_files: 65_536,
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
            allow_revoked_or_unlisted_tcb: false,
            allow_nonzero_vmpl: false,
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
    /// Read the config file. An unknown key (a typo, or a knob that was
    /// removed) is an error naming it.
    pub fn load(path: &Path) -> anyhow::Result<Self> {
        let contents = std::fs::read_to_string(path)?;
        toml::from_str(&contents).map_err(|e| anyhow::anyhow!("{}: {e}", path.display()))
    }

    /// Validate configuration at startup. Returns an error for invalid combinations.
    pub fn validate(&self) -> Result<(), String> {
        // Validate bind address is parseable
        self.server
            .bind
            .parse::<SocketAddr>()
            .map_err(|e| format!("invalid server.bind address '{}': {e}", self.server.bind))?;

        // The listener is plaintext; accepting this flag would hide that.
        if self.server.tls.enabled {
            return Err("server.tls.enabled is not supported: attestation-api does not terminate TLS. \
                 Evidence endpoints must not be routable: terminate TLS in front of the service and \
                 bind to an address only the terminator reaches (loopback for a sidecar)"
                .to_string());
        }

        // Validate token duration when token is enabled
        if self.token.enabled && self.token.duration_minutes == 0 {
            return Err("token.duration_minutes must be > 0 when token is enabled".to_string());
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

        // A queued request must be able to wait for the queue ahead of it
        // (about a millisecond per verification); the open-files limit is
        // safe only with the connection cap below it.
        let (v, s) = (&self.verify, &self.server);
        if v.queue_deadline_ms < v.queue_per_worker.max(1) as u64
            || v.cold_workers == 0
            || v.fetch_deadline_ms == 0
            || !(1..s.max_open_files).contains(&(s.max_connections as u64))
        {
            return Err(
                "[verify] needs queue_deadline_ms >= queue_per_worker and nonzero \
                 cold_workers and fetch_deadline_ms; [server] needs \
                 0 < max_connections < max_open_files"
                    .to_string(),
            );
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
            !debug_output.contains("super-secret"),
            "Debug must not contain actual key values"
        );
    }

    #[test]
    fn unknown_keys_are_refused_and_the_example_config_loads() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("config.toml");
        let load = |text: &str| {
            std::fs::write(&path, text).unwrap();
            Config::load(&path)
        };
        for section in ["nras", "server"] {
            load(&format!("[{section}]\n")).expect("the section alone loads");
        }
        for refused in [
            "[certs]\n",
            "[certs]\nnras_gpu_url = \"https://nras.example\"\n",
            "[certs]\ncache_max_entries = 1024\n",
            "[nras]\nnras_gpu_url = \"https://nras.example\"\n",
            "[server]\nbnd = \"0.0.0.0:8400\"\n",
        ] {
            assert!(load(refused).is_err(), "{refused} must be refused");
        }
        let example = Path::new(env!("CARGO_MANIFEST_DIR")).join("config.example.toml");
        Config::load(&example).unwrap().validate().unwrap();
    }

    #[test]
    fn tls_enabled_is_refused() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("config.toml");
        let cases = [
            ("absent", "", true),
            ("disabled", "[server.tls]\nenabled = false\n", true),
            (
                "disabled with paths",
                "[server.tls]\nenabled = false\ncert_path = \"c.pem\"\nkey_path = \"k.pem\"\n",
                true,
            ),
            ("enabled", "[server.tls]\nenabled = true\n", false),
            (
                "enabled with paths",
                "[server.tls]\nenabled = true\ncert_path = \"c.pem\"\nkey_path = \"k.pem\"\n",
                false,
            ),
        ];
        for (name, text, ok) in cases {
            std::fs::write(&path, text).unwrap();
            let got = Config::load(&path).unwrap().validate();
            if ok {
                assert!(got.is_ok(), "{name}: validate() = {got:?}, want Ok");
            } else {
                let err = got.expect_err(name);
                assert!(
                    err.contains("TLS"),
                    "{name}: validate() = {err:?}, want TLS error"
                );
            }
        }
    }
}
