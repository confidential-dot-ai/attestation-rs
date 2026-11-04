use serde::Deserialize;
use std::fmt;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};

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
}

#[derive(Debug, Clone, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct ServerConfig {
    /// `host:port`, or `unix:` followed by an absolute socket path.
    pub bind: String,
    /// Octal mode of the Unix socket; Unix binds only. Default `"0660"`.
    pub socket_mode: Option<String>,
    /// Group (name or gid) the Unix socket is chgrp'd to; Unix binds only.
    pub socket_group: Option<GroupSpec>,
    pub tls: TlsConfig,
}

/// A group given by name or numeric gid.
#[derive(Debug, Clone, Deserialize, PartialEq, Eq)]
#[serde(untagged)]
pub enum GroupSpec {
    Id(u32),
    Name(String),
}

/// Where the server listens, parsed from [`ServerConfig`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Bind {
    Tcp(SocketAddr),
    Unix {
        path: PathBuf,
        mode: u32,
        /// Resolved gid; `None` keeps the process group.
        group: Option<u32>,
    },
}

impl fmt::Display for Bind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Bind::Tcp(addr) => write!(f, "{addr}"),
            Bind::Unix { path, .. } => write!(f, "unix:{}", path.display()),
        }
    }
}

const DEFAULT_SOCKET_MODE: u32 = 0o660;

/// Longest socket path `bind(2)` accepts: `sun_path` is 108 bytes on Linux and
/// 104 on the BSDs and macOS, including the trailing NUL.
#[cfg(target_os = "linux")]
pub(crate) const MAX_SOCKET_PATH: usize = 107;
#[cfg(not(target_os = "linux"))]
pub(crate) const MAX_SOCKET_PATH: usize = 103;

/// Bytes the server adds to the socket's directory while binding: it stages
/// the socket at `<dir>/.sock-<12 hex>/s` before moving it into place.
pub(crate) const STAGED_SUFFIX_LEN: usize = "/.sock-0123456789ab/s".len();

impl ServerConfig {
    /// Parse and check the listener settings. Resolves `socket_group` names
    /// against `/etc/group`.
    pub fn bind(&self) -> Result<Bind, String> {
        let Some(rest) = self.bind.strip_prefix("unix:") else {
            if self.socket_mode.is_some() || self.socket_group.is_some() {
                return Err(
                    "server.socket_mode and server.socket_group require a unix: bind".to_string(),
                );
            }
            return self
                .bind
                .parse()
                .map(Bind::Tcp)
                .map_err(|e| format!("invalid server.bind address '{}': {e}", self.bind));
        };
        let path = PathBuf::from(rest.strip_prefix("//").unwrap_or(rest));
        if !path.is_absolute() {
            return Err(format!(
                "server.bind '{}': the socket path must be absolute",
                self.bind
            ));
        }
        let parent = match (path.parent(), path.file_name()) {
            (Some(parent), Some(_)) if !rest.ends_with('/') && !rest.ends_with("/.") => parent,
            _ => {
                return Err(format!(
                    "server.bind '{}': the socket path must name a file",
                    self.bind
                ))
            }
        };
        let staged = parent.as_os_str().len() + STAGED_SUFFIX_LEN;
        if path.as_os_str().len().max(staged) > MAX_SOCKET_PATH {
            return Err(format!(
                "server.bind '{}': the socket path, as configured, is too long; the socket is staged at \
                 <dir>/.sock-<12 hex>/s, and both paths must fit in {MAX_SOCKET_PATH} bytes",
                self.bind
            ));
        }
        let mode = match &self.socket_mode {
            None => DEFAULT_SOCKET_MODE,
            Some(text) => parse_mode(text)?,
        };
        let group = self.socket_group.as_ref().map(resolve_group).transpose()?;
        Ok(Bind::Unix { path, mode, group })
    }
}

fn parse_mode(text: &str) -> Result<u32, String> {
    let mode = u32::from_str_radix(text, 8)
        .ok()
        .filter(|m| *m <= 0o777)
        .ok_or_else(|| format!("server.socket_mode '{text}' is not an octal mode like \"0660\""))?;
    if mode & 0o007 != 0 {
        return Err(format!(
            "server.socket_mode '{text}' grants access to other users; the socket must stay restricted"
        ));
    }
    // connect(2) needs write permission on the socket node.
    if mode & 0o200 == 0 {
        return Err(format!(
            "server.socket_mode '{text}' has no owner write bit, so no client could connect"
        ));
    }
    Ok(mode)
}

fn resolve_group(group: &GroupSpec) -> Result<u32, String> {
    let name = match group {
        GroupSpec::Id(gid) => return Ok(*gid),
        GroupSpec::Name(name) => name,
    };
    if let Ok(gid) = name.parse() {
        return Ok(gid);
    }
    // std has no getgrnam; /etc/group covers the local groups a CVM image
    // ships, which is where the socket group comes from.
    let groups = std::fs::read_to_string("/etc/group")
        .map_err(|e| format!("server.socket_group '{name}': reading /etc/group: {e}"))?;
    find_gid(name, &groups)
        .ok_or_else(|| format!("server.socket_group '{name}': no such group in /etc/group"))
}

/// Looks `name` up in `groups`, the contents of an `/etc/group` file.
fn find_gid(name: &str, groups: &str) -> Option<u32> {
    groups.lines().find_map(|line| {
        let mut fields = line.split(':');
        (fields.next() == Some(name))
            .then(|| fields.nth(1)?.parse().ok())
            .flatten()
    })
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
            socket_mode: None,
            socket_group: None,
            tls: TlsConfig::default(),
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
        self.server.bind()?;

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
    fn server_bind() {
        let server = |bind: &str, mode: Option<&str>, group: Option<GroupSpec>| ServerConfig {
            bind: bind.to_string(),
            socket_mode: mode.map(str::to_string),
            socket_group: group,
            tls: TlsConfig::default(),
        };
        let unix = |path: &str, mode: u32, group: Option<u32>| {
            Ok(Bind::Unix {
                path: PathBuf::from(path),
                mode,
                group,
            })
        };
        let name = |n: &str| Some(GroupSpec::Name(n.to_string()));
        // "/" + dir + "/.sock-<12 hex>/s" must fit MAX_SOCKET_PATH.
        let longest_dir = MAX_SOCKET_PATH - STAGED_SUFFIX_LEN - 1;
        let cases = [
            (
                "tcp",
                server("127.0.0.1:8400", None, None),
                Ok(Bind::Tcp("127.0.0.1:8400".parse().unwrap())),
            ),
            (
                "unix defaults",
                server("unix:///run/a/api.sock", None, None),
                unix("/run/a/api.sock", 0o660, None),
            ),
            (
                "unix single slash",
                server("unix:/run/a/api.sock", None, None),
                unix("/run/a/api.sock", 0o660, None),
            ),
            (
                "unix mode and numeric group",
                server(
                    "unix:///run/a/api.sock",
                    Some("0600"),
                    Some(GroupSpec::Id(65532)),
                ),
                unix("/run/a/api.sock", 0o600, Some(65532)),
            ),
            (
                "unix numeric group as string",
                server("unix:///run/a/api.sock", None, name("65532")),
                unix("/run/a/api.sock", 0o660, Some(65532)),
            ),
            (
                "bad scheme",
                server("tcp://127.0.0.1:8400", None, None),
                Err("invalid server.bind"),
            ),
            (
                "relative path",
                server("unix:run/api.sock", None, None),
                Err("absolute"),
            ),
            ("empty path", server("unix:", None, None), Err("absolute")),
            (
                "root path",
                server("unix:///", None, None),
                Err("name a file"),
            ),
            (
                "trailing slash",
                server("unix:///run/a/", None, None),
                Err("name a file"),
            ),
            (
                "trailing dot",
                server("unix:///run/a/.", None, None),
                Err("name a file"),
            ),
            (
                "longest path",
                server(
                    &format!("unix:///{}/s", "d".repeat(longest_dir)),
                    None,
                    None,
                ),
                unix(&format!("/{}/s", "d".repeat(longest_dir)), 0o660, None),
            ),
            (
                "directory too long to stage in",
                server(
                    &format!("unix:///{}/api.sock", "d".repeat(longest_dir + 1)),
                    None,
                    None,
                ),
                Err("too long"),
            ),
            (
                "path too long",
                server(
                    &format!("unix:///run/{}", "s".repeat(MAX_SOCKET_PATH - 4)),
                    None,
                    None,
                ),
                Err("too long"),
            ),
            (
                "mode without owner write",
                server("unix:///run/a/api.sock", Some("0440"), None),
                Err("owner write"),
            ),
            (
                "world-accessible mode",
                server("unix:///run/a/api.sock", Some("0666"), None),
                Err("other users"),
            ),
            (
                "socket_mode with tcp",
                server("127.0.0.1:8400", Some("0660"), None),
                Err("require a unix: bind"),
            ),
            (
                "socket_group with tcp",
                server("127.0.0.1:8400", None, Some(GroupSpec::Id(0))),
                Err("require a unix: bind"),
            ),
            (
                "non-octal mode",
                server("unix:///run/a/api.sock", Some("0680"), None),
                Err("not an octal mode"),
            ),
            (
                "mode out of range",
                server("unix:///run/a/api.sock", Some("4660"), None),
                Err("not an octal mode"),
            ),
        ];
        for (name, config, want) in cases {
            let got = config.bind();
            match (&got, &want) {
                (Ok(got), Ok(want)) => assert_eq!(got, want, "{name}"),
                (Err(err), Err(want)) => {
                    assert!(
                        err.contains(want),
                        "{name}: bind() = {err:?}, want {want:?}"
                    )
                }
                _ => panic!("{name}: bind() = {got:?}, want {want:?}"),
            }
        }
    }

    #[test]
    fn socket_group_parses_name_or_gid() {
        let parse = |text: &str| toml::from_str::<ServerConfig>(text).unwrap().socket_group;
        assert_eq!(parse("socket_group = 65532"), Some(GroupSpec::Id(65532)));
        assert_eq!(
            parse("socket_group = \"nonroot\""),
            Some(GroupSpec::Name("nonroot".to_string()))
        );
    }

    #[test]
    fn find_gid_in_group_file() {
        let groups = "root:x:0:\nnonroot:x:65532:\nbroken:x:notanumber:\n";
        let cases = [
            ("root", Some(0)),
            ("nonroot", Some(65532)),
            ("broken", None),
            ("missing", None),
            ("non", None),
        ];
        for (name, want) in cases {
            let got = find_gid(name, groups);
            assert_eq!(got, want, "find_gid({name:?}) = {got:?}, want {want:?}");
        }
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
