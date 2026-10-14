use serde::{Deserialize, Serialize};

/// Platform identifier enum.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum PlatformType {
    #[serde(rename = "tdx")]
    Tdx,
    #[serde(rename = "snp")]
    Snp,
    #[serde(rename = "az-tdx")]
    AzTdx,
    #[serde(rename = "az-snp")]
    AzSnp,
    /// GCP Confidential VM running AMD SEV-SNP.
    ///
    /// **Security note:** This tag reflects the *attester's claim*, not a
    /// cryptographic proof of GCP origin. The AMD SNP attestation report
    /// contains no cloud-provider identity. A valid `GcpSnp` result means the
    /// AMD hardware root-of-trust chain verified successfully — not that the
    /// machine is inside GCP. Policy decisions **must not** grant elevated trust
    /// based solely on this tag; use report fields (`measurement`, `chip_id`,
    /// `reported_tcb`) instead.
    #[serde(rename = "gcp-snp")]
    GcpSnp,
    /// GCP Confidential VM running Intel TDX.
    ///
    /// **Security note:** Same caveat as `GcpSnp`. This tag reflects the
    /// *attester's claim*, not a cryptographic proof of GCP origin. The Intel
    /// TDX DCAP quote contains no cloud-provider identity. A valid `GcpTdx`
    /// result means the Intel DCAP signature chain verified successfully — not
    /// that the machine is inside GCP. Policy decisions **must not** grant
    /// elevated trust based solely on this tag; use report fields (`mr_td`,
    /// `rtmr_*`, `tee_tcb_svn`) instead.
    #[serde(rename = "gcp-tdx")]
    GcpTdx,
    #[serde(rename = "dstack")]
    Dstack,
}

/// Self-describing attestation evidence envelope.
///
/// Wraps platform-specific evidence with a platform identifier so that
/// verifiers can auto-detect which platform produced the evidence.
///
/// Optionally carries a GPU evidence bundle when the workload runs on a
/// CC-mode NVIDIA GPU bound to the CPU TEE. The bundle is additive: pre-GPU
/// envelopes deserialize unchanged because the field is `Option` with default.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AttestationEvidence {
    /// Which platform produced this evidence.
    pub platform: PlatformType,
    /// Platform-specific evidence payload.
    pub evidence: serde_json::Value,
    /// Optional NVIDIA GPU attestation bundle bound to this CPU TEE evidence.
    #[cfg(feature = "nvidia-gpu")]
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub nvidia_gpu: Option<NvidiaGpuEvidenceBundle>,
    /// Without the `nvidia-gpu` feature a bundle cannot be verified; it is
    /// kept so the verifier refuses it instead of dropping it.
    #[cfg(not(feature = "nvidia-gpu"))]
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub nvidia_gpu: Option<serde_json::Value>,
}

impl std::fmt::Display for PlatformType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            PlatformType::Tdx => write!(f, "tdx"),
            PlatformType::Snp => write!(f, "snp"),
            PlatformType::AzTdx => write!(f, "az-tdx"),
            PlatformType::AzSnp => write!(f, "az-snp"),
            PlatformType::GcpSnp => write!(f, "gcp-snp"),
            PlatformType::GcpTdx => write!(f, "gcp-tdx"),
            PlatformType::Dstack => write!(f, "dstack"),
        }
    }
}

/// NVIDIA GPU verification parameters, applied when an envelope carries a GPU
/// bundle.
#[cfg(feature = "nvidia-gpu")]
#[derive(Debug, Clone, Default)]
pub struct NvidiaGpuParams {
    /// User nonce used to derive the GPU SPDM nonce. Required when verifying
    /// an envelope that carries a `gpu` bundle, and must equal the platform
    /// params' `report_data`.
    pub user_nonce: Option<Vec<u8>>,
    /// If true, reject envelopes that do not include an NVIDIA GPU bundle.
    pub required: bool,
    /// Optional allowlist of acceptable GPU/switch architectures. Result in
    /// [`NvidiaGpuResult::archs_allowed`].
    pub expected_archs: Option<Vec<NvidiaGpuArch>>,
    /// Allowed nonce-binding algorithms. If `None`, only the default
    /// (`Concat { Sha256 }`) is accepted. Set explicitly to permit future
    /// binding variants.
    pub allowed_bindings: Option<Vec<NvidiaGpuBinding>>,
    /// Per-device security policy applied to each NRAS submodule, independent of
    /// NRAS's opaque overall boolean. Defaults reject debug-enabled devices and
    /// require secure boot and a successful measurement result. Result in
    /// [`NvidiaGpuResult::device_policy_met`]. A device whose SPDM report does
    /// not match the nonce is an error, not a policy result.
    pub device_policy: NvidiaGpuDevicePolicy,
}

/// Per-device policy gates evaluated against each NRAS submodule's claims.
///
/// NRAS folds all device checks into a single opaque, `claims_version`-dependent
/// `x-nvidia-overall-att-result` boolean. These gates let a caller enforce the
/// individual per-device claims directly, so that (a) an unexpired NRAS-signed
/// submodule spliced from another session is rejected via its `eat_nonce`, and
/// (b) policy-relevant device state (debug, secure boot, measurement result) is
/// checked locally rather than trusted blindly.
///
/// Defaults mirror `allow_debug`'s security posture: fail closed.
#[cfg(feature = "nvidia-gpu")]
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NvidiaGpuDevicePolicy {
    /// If true, accept devices reporting `dbgstat != "disabled"`. Default false
    /// (debug-enabled GPUs fail the policy).
    pub allow_debug: bool,
    /// If true, require every device's `secboot` claim to be `true`. Default true.
    pub require_secboot: bool,
    /// If true, require every device's `measres` claim to equal `"success"`.
    /// Default true.
    pub require_measres_success: bool,
}

#[cfg(feature = "nvidia-gpu")]
impl Default for NvidiaGpuDevicePolicy {
    fn default() -> Self {
        Self {
            allow_debug: false,
            require_secboot: true,
            require_measres_success: true,
        }
    }
}

/// Normalized claims extracted from evidence.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Claims {
    /// Hex-encoded launch measurement (MRTD for TDX, measurement for SNP).
    pub launch_digest: String,
    /// The report_data field from inside the HW quote, raw bytes.
    #[serde(with = "hex_bytes")]
    pub report_data: Vec<u8>,
    /// The data requested to be signed by the attestation requester.
    /// For bare-metal platforms this equals report_data; for vTPM platforms
    /// this is the TPM nonce (the user's original challenge data).
    #[serde(with = "hex_bytes")]
    pub signed_data: Vec<u8>,
    /// Init data / host data from the quote, raw bytes.
    #[serde(with = "hex_bytes")]
    pub init_data: Vec<u8>,
    /// TCB version information, platform-specific.
    pub tcb: TcbInfo,
    /// All platform-specific claim fields as a JSON map.
    pub platform_data: serde_json::Value,
}

/// TCB version information, varies by platform.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type")]
pub enum TcbInfo {
    Snp {
        bootloader: u8,
        tee: u8,
        snp: u8,
        microcode: u8,
        /// FMC (Firmware Microcontroller) SPL — present only on Turin processors.
        #[serde(skip_serializing_if = "Option::is_none")]
        fmc: Option<u8>,
    },
    Tdx {
        /// Raw 16-byte TCB SVN from the quote body.
        #[serde(with = "hex_bytes")]
        tcb_svn: Vec<u8>,
    },
}

/// TDX TCB status from Intel DCAP collateral evaluation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum TdxTcbStatus {
    UpToDate,
    SWHardeningNeeded,
    ConfigurationNeeded,
    ConfigurationAndSWHardeningNeeded,
    OutOfDate,
    OutOfDateConfigurationNeeded,
    Revoked,
    /// The quote's TCB is below every level Intel lists for its platform.
    NoMatchingLevel,
}

impl std::fmt::Display for TdxTcbStatus {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            TdxTcbStatus::UpToDate => write!(f, "UpToDate"),
            TdxTcbStatus::SWHardeningNeeded => write!(f, "SWHardeningNeeded"),
            TdxTcbStatus::ConfigurationNeeded => write!(f, "ConfigurationNeeded"),
            TdxTcbStatus::ConfigurationAndSWHardeningNeeded => {
                write!(f, "ConfigurationAndSWHardeningNeeded")
            }
            TdxTcbStatus::OutOfDate => write!(f, "OutOfDate"),
            TdxTcbStatus::OutOfDateConfigurationNeeded => {
                write!(f, "OutOfDateConfigurationNeeded")
            }
            TdxTcbStatus::Revoked => write!(f, "Revoked"),
            TdxTcbStatus::NoMatchingLevel => write!(f, "NoMatchingLevel"),
        }
    }
}

/// DCAP verification status from Intel collateral evaluation.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DcapVerificationStatus {
    /// TCB status determined by matching against Intel TCB Info.
    pub tcb_status: TdxTcbStatus,
    /// FMSPC (Family-Model-Stepping-Platform-CustomSKU) extracted from PCK cert.
    pub fmspc: String,
    /// Security advisory IDs affecting this TCB level.
    pub advisory_ids: Vec<String>,
    /// Whether the TCB Info collateral has expired (nextUpdate in the past).
    #[serde(default)]
    pub collateral_expired: bool,
    /// The Quoting Enclave's own TCB status, already combined into
    /// `tcb_status` (`None` when the QE identity was not evaluated).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub qe_tcb_status: Option<TdxTcbStatus>,
}

/// AMD processor generation for SNP.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum ProcessorGeneration {
    Milan,
    Genoa,
    Turin,
}

impl ProcessorGeneration {
    /// Determine processor generation from CPUID family and model IDs.
    pub fn from_cpuid(family_id: u8, model_id: u8) -> Option<Self> {
        match (family_id, model_id) {
            (0x19, 0x00..=0x0F) => Some(ProcessorGeneration::Milan),
            (0x19, 0x10..=0x1F) | (0x19, 0xA0..=0xAF) => Some(ProcessorGeneration::Genoa),
            (0x1A, 0x00..=0x11) => Some(ProcessorGeneration::Turin),
            _ => None,
        }
    }

    /// Product name string used in AMD KDS URLs.
    pub fn product_name(&self) -> &'static str {
        match self {
            ProcessorGeneration::Milan => "Milan",
            ProcessorGeneration::Genoa => "Genoa",
            ProcessorGeneration::Turin => "Turin",
        }
    }
}

/// SNP TCB version components (used for KDS URL construction and TCB checks).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct SnpTcb {
    pub bootloader: u8,
    pub tee: u8,
    pub snp: u8,
    pub microcode: u8,
    /// FMC (Firmware Microcontroller) SPL — present only on Turin processors.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub fmc: Option<u8>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_processor_generation_from_cpuid() {
        // Milan range: family 0x19, model 0x00..0x0F
        assert_eq!(
            ProcessorGeneration::from_cpuid(0x19, 0x00),
            Some(ProcessorGeneration::Milan)
        );
        assert_eq!(
            ProcessorGeneration::from_cpuid(0x19, 0x0F),
            Some(ProcessorGeneration::Milan)
        );

        // Genoa range: family 0x19, model 0x10..0x1F or 0xA0..0xAF
        assert_eq!(
            ProcessorGeneration::from_cpuid(0x19, 0x10),
            Some(ProcessorGeneration::Genoa)
        );
        assert_eq!(
            ProcessorGeneration::from_cpuid(0x19, 0x1F),
            Some(ProcessorGeneration::Genoa)
        );
        assert_eq!(
            ProcessorGeneration::from_cpuid(0x19, 0xA0),
            Some(ProcessorGeneration::Genoa)
        );
        assert_eq!(
            ProcessorGeneration::from_cpuid(0x19, 0xAF),
            Some(ProcessorGeneration::Genoa)
        );

        // Turin range: family 0x1A, model 0x00..0x11
        assert_eq!(
            ProcessorGeneration::from_cpuid(0x1A, 0x00),
            Some(ProcessorGeneration::Turin)
        );
        assert_eq!(
            ProcessorGeneration::from_cpuid(0x1A, 0x11),
            Some(ProcessorGeneration::Turin)
        );

        // Unknown combinations
        assert_eq!(ProcessorGeneration::from_cpuid(0x00, 0x00), None);
        assert_eq!(ProcessorGeneration::from_cpuid(0xFF, 0xFF), None);
        assert_eq!(ProcessorGeneration::from_cpuid(0x18, 0x01), None);
        assert_eq!(ProcessorGeneration::from_cpuid(0x19, 0x20), None); // Gap between Milan/Genoa
        assert_eq!(ProcessorGeneration::from_cpuid(0x1A, 0x12), None); // Just past Turin range
    }
}

// ── NVIDIA GPU attestation types ─────────────────────────────────────────────

/// NVIDIA confidential-compute device architecture as advertised to NRAS.
#[cfg(feature = "nvidia-gpu")]
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "UPPERCASE")]
pub enum NvidiaGpuArch {
    Hopper,
    Blackwell,
    /// NVSwitch (LS10). Switches use a different NRAS endpoint and are
    /// modeled here so a bundle can co-locate GPU and switch evidence.
    Ls10,
}

#[cfg(feature = "nvidia-gpu")]
impl std::fmt::Display for NvidiaGpuArch {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            NvidiaGpuArch::Hopper => write!(f, "HOPPER"),
            NvidiaGpuArch::Blackwell => write!(f, "BLACKWELL"),
            NvidiaGpuArch::Ls10 => write!(f, "LS10"),
        }
    }
}

/// Hash algorithm used in GPU nonce / binding derivations.
#[cfg(feature = "nvidia-gpu")]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, Default)]
#[serde(rename_all = "kebab-case")]
pub enum NvidiaGpuHashAlgo {
    #[default]
    Sha256,
}

/// How the GPU nonce is derived from the user nonce.
///
/// `Concat` is the v1 binding: `gpu_nonce = H(user_nonce || domain_tag)` where
/// `domain_tag` is `b"NVIDIA-GPU-EAT-v1"` for GPU evidence and
/// `b"NVIDIA-SWITCH-EAT-v1"` for NVSwitch evidence.
#[cfg(feature = "nvidia-gpu")]
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "kebab-case", deny_unknown_fields)]
pub enum NvidiaGpuBinding {
    Concat {
        #[serde(default)]
        algo: NvidiaGpuHashAlgo,
    },
}

#[cfg(feature = "nvidia-gpu")]
impl Default for NvidiaGpuBinding {
    fn default() -> Self {
        NvidiaGpuBinding::Concat {
            algo: NvidiaGpuHashAlgo::Sha256,
        }
    }
}

/// Per-device evidence as it is sent to NRAS.
#[cfg(feature = "nvidia-gpu")]
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NvidiaGpuDeviceEvidence {
    pub arch: NvidiaGpuArch,
    pub uuid: String,
    /// Base64 SPDM blob.
    pub evidence_b64: String,
    /// Base64-encoded PEM cert chain (leaf first).
    pub cert_chain_b64: String,
}

/// A bundle of GPU/switch evidence bound to the enclosing CPU TEE quote.
#[cfg(feature = "nvidia-gpu")]
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NvidiaGpuEvidenceBundle {
    /// Devices, sorted by UUID for stable serialization.
    pub devices: Vec<NvidiaGpuDeviceEvidence>,
    /// How the SPDM nonce was derived from the user nonce.
    /// Required — the attester must declare the binding algorithm explicitly.
    pub binding: NvidiaGpuBinding,
}

/// Per-device claims as surfaced by NRAS in the detached EAT submodule JWT.
#[cfg(feature = "nvidia-gpu")]
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct NvidiaGpuDeviceClaims {
    pub arch: Option<NvidiaGpuArch>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ueid: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub hwmodel: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub measres: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub secboot: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub dbgstat: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub driver_version: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub vbios_version: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub arch_check: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub nonce_match: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub report_signature_verified: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub driver_rim_fetched: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub vbios_rim_fetched: Option<bool>,
    #[serde(default, skip_serializing_if = "serde_json::Value::is_null")]
    pub raw: serde_json::Value,
}

/// Aggregated GPU claims from NRAS.
#[cfg(feature = "nvidia-gpu")]
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct NvidiaGpuClaims {
    /// NRAS's `x-nvidia-overall-att-result` across every arch group.
    pub overall_ok: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub eat_nonce: Option<String>,
    pub devices: Vec<NvidiaGpuDeviceClaims>,
    #[serde(default, skip_serializing_if = "serde_json::Value::is_null")]
    pub overall_raw: serde_json::Value,
}

/// Result of verifying an NVIDIA GPU bundle against [`NvidiaGpuParams`].
#[cfg(feature = "nvidia-gpu")]
#[derive(Debug, Clone, Serialize, Deserialize)]
#[must_use]
pub struct NvidiaGpuResult {
    pub claims: NvidiaGpuClaims,
    /// Every device's arch is in `expected_archs` (`None` if no allowlist).
    pub archs_allowed: Option<bool>,
    /// NRAS returned one device claim per device in the bundle.
    pub device_count_match: bool,
    /// Every device satisfied the [`NvidiaGpuDevicePolicy`].
    pub device_policy_met: bool,
}

#[cfg(feature = "nvidia-gpu")]
impl NvidiaGpuResult {
    /// True when NRAS's overall result is true and every rule in the params
    /// held.
    pub fn passed(&self) -> bool {
        self.claims.overall_ok
            && self.archs_allowed != Some(false)
            && self.device_count_match
            && self.device_policy_met
    }
}

/// Helper module for serializing Vec<u8> as hex strings.
mod hex_bytes {
    use serde::{Deserialize, Deserializer, Serializer};

    pub fn serialize<S>(bytes: &[u8], serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&hex::encode(bytes))
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<Vec<u8>, D::Error>
    where
        D: Deserializer<'de>,
    {
        let s = String::deserialize(deserializer)?;
        hex::decode(&s).map_err(serde::de::Error::custom)
    }
}
