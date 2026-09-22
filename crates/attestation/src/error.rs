use thiserror::Error;

/// Unified error type for all attestation operations.
#[derive(Error, Debug)]
pub enum AttestationError {
    #[error("no supported TEE platform detected")]
    NoPlatformDetected,

    #[error("platform {0} is not enabled (enable the corresponding cargo feature)")]
    PlatformNotEnabled(String),

    #[error("report_data exceeds maximum size ({max} bytes)")]
    ReportDataTooLarge { max: usize },

    #[error("evidence deserialization failed: {0}")]
    EvidenceDeserialize(String),

    #[error("hardware signature verification failed: {0}")]
    SignatureVerificationFailed(String),

    #[error("certificate chain validation failed: {0}")]
    CertChainError(String),

    #[error("certificate fetch failed: {0}")]
    CertFetchError(String),

    #[error("quote parsing failed: {0}")]
    QuoteParseFailed(String),

    #[error("report version {version} not supported (min: {min}, max: {max})")]
    UnsupportedReportVersion { version: u32, min: u32, max: u32 },

    #[error("VMPL check failed: expected 0, got {0}")]
    VmplCheckFailed(u32),

    #[error("eventlog integrity check failed: {0}")]
    EventlogIntegrityFailed(String),

    #[error("eventlog cannot be parsed: {0}")]
    EventlogParseFailed(String),

    #[error("{reason}")]
    Refused { code: RefusalCode, reason: String },

    #[error("TEE hardware access failed: {0}")]
    HardwareAccessFailed(String),

    #[error("TCB version mismatch: {0}")]
    TcbMismatch(String),

    #[error("report_data mismatch")]
    ReportDataMismatch,

    #[error("init_data / host_data mismatch")]
    InitDataMismatch,

    #[error("guest launched with debug policy enabled")]
    DebugPolicyViolation,

    #[error("evidence too large: {size} bytes exceeds maximum {max} bytes")]
    EvidenceTooLarge { size: usize, max: usize },

    #[error("profile evidence invalid: {0}")]
    ProfileEvidenceInvalid(String),

    #[error("verify policy invalid: {0}")]
    PolicyInvalid(String),

    #[error("GPU evidence required but envelope has no gpu bundle")]
    #[cfg(feature = "nvidia-gpu")]
    NvidiaGpuRequired,

    #[error("GPU nonce binding mismatch (NRAS-attested nonce != derived from gpu_user_nonce)")]
    #[cfg(feature = "nvidia-gpu")]
    NvidiaGpuBindingMismatch,

    #[error("GPU submodule \"{name}\" eat_nonce does not bind to the derived SPDM nonce")]
    #[cfg(feature = "nvidia-gpu")]
    NvidiaGpuSubmoduleNonceMismatch { name: String },

    #[error("GPU device \"{name}\" failed policy: {reason}")]
    #[cfg(feature = "nvidia-gpu")]
    NvidiaGpuDevicePolicyFailed { name: String, reason: String },

    #[error("GPU bundle requires VerifyParams::nvidia_gpu_user_nonce")]
    #[cfg(feature = "nvidia-gpu")]
    NvidiaGpuUserNonceMissing,

    #[error("nvidia_gpu_user_nonce is set but expected_report_data is not; both are required for CPU-GPU binding")]
    #[cfg(feature = "nvidia-gpu")]
    NvidiaGpuReportDataRequired,

    #[error("GPU bundle binding algorithm not in allowed set")]
    #[cfg(feature = "nvidia-gpu")]
    NvidiaGpuBindingNotAllowed,

    #[error("nvidia_gpu_user_nonce too short ({0} bytes, minimum 16)")]
    #[cfg(feature = "nvidia-gpu")]
    NvidiaGpuNonceTooShort(usize),

    #[error("GPU device arch {0} not in expected_archs whitelist")]
    #[cfg(feature = "nvidia-gpu")]
    NvidiaGpuArchNotAllowed(String),

    #[error("GPU bundle is empty")]
    #[cfg(feature = "nvidia-gpu")]
    NvidiaGpuBundleEmpty,

    #[error("NRAS returned {got} device claims but bundle had {expected} devices")]
    #[cfg(feature = "nvidia-gpu")]
    NvidiaGpuDeviceCountMismatch { expected: usize, got: usize },

    #[error("GPU bundle has {0} devices, exceeding maximum of {1}")]
    #[cfg(feature = "nvidia-gpu")]
    NvidiaGpuTooManyDevices(usize, usize),

    #[error("NRAS request failed: {0}")]
    #[cfg(feature = "nvidia-gpu")]
    NrasRequestFailed(String),

    #[error("NRAS response parse failed: {0}")]
    #[cfg(feature = "nvidia-gpu")]
    NrasResponseParse(String),

    #[error("NRAS overall attestation result is false")]
    #[cfg(feature = "nvidia-gpu")]
    NrasOverallFailed,

    #[error("NRAS token issuer is {got:?}, expected {expected:?}")]
    #[cfg(feature = "nvidia-gpu")]
    NrasIssuerMismatch { expected: String, got: String },

    #[error("NRAS answered with claims version {got:?}, the request asked for {expected:?}")]
    #[cfg(feature = "nvidia-gpu")]
    NrasClaimsVersionMismatch { expected: String, got: String },

    #[error("NRAS submodule \"{name}\" is not the token the overall result digests")]
    #[cfg(feature = "nvidia-gpu")]
    NrasSubmoduleDigestMismatch { name: String },

    #[error("JWS verification failed: {0}")]
    #[cfg(feature = "nvidia-gpu")]
    JwsVerification(String),

    #[error("JWKS fetch failed: {0}")]
    #[cfg(feature = "nvidia-gpu")]
    JwksFetch(String),

    #[error("JWKS key with kid {0} not found")]
    #[cfg(feature = "nvidia-gpu")]
    JwksKidNotFound(String),

    #[error("GPU evidence collection failed: {0}")]
    #[cfg(all(feature = "nvidia-gpu-attest", target_os = "linux"))]
    NvidiaGpuEvidenceCollection(String),

    #[error(transparent)]
    Collateral(#[from] crate::collateral::CollateralError),

    #[error(transparent)]
    Other(#[from] anyhow::Error),
}

pub type Result<T> = std::result::Result<T, AttestationError>;

/// The rule family a refusal belongs to: the codes of design doc section 14.4,
/// which the conformance corpus compares across implementations.
#[derive(
    Debug,
    Clone,
    Copy,
    PartialEq,
    Eq,
    Hash,
    serde::Serialize,
    serde::Deserialize,
    schemars::JsonSchema,
)]
#[serde(rename_all = "kebab-case")]
pub enum RefusalCode {
    EnvelopeInvalid,
    PolicyInvalid,
    PlatformUnsupported,
    ReportInvalid,
    SignatureInvalid,
    ChainInvalid,
    MachineNotAllowed,
    GuestPolicy,
    BindingMismatch,
    CollateralUnavailable,
    CollateralInvalid,
    Revoked,
    TcbNotAllowed,
    RegisterMismatch,
    LogRequired,
    LogInvalid,
    ReplayMismatch,
    ReferenceMismatch,
    BackingBelowMinimum,
    DeviceRequired,
    DeviceNotAllowed,
    DeviceTokenInvalid,
    DevicePolicy,
    Unsupported,
}

impl RefusalCode {
    /// The kebab-case name of section 14.4.
    pub fn as_str(self) -> &'static str {
        match self {
            RefusalCode::EnvelopeInvalid => "envelope-invalid",
            RefusalCode::PolicyInvalid => "policy-invalid",
            RefusalCode::PlatformUnsupported => "platform-unsupported",
            RefusalCode::ReportInvalid => "report-invalid",
            RefusalCode::SignatureInvalid => "signature-invalid",
            RefusalCode::ChainInvalid => "chain-invalid",
            RefusalCode::MachineNotAllowed => "machine-not-allowed",
            RefusalCode::GuestPolicy => "guest-policy",
            RefusalCode::BindingMismatch => "binding-mismatch",
            RefusalCode::CollateralUnavailable => "collateral-unavailable",
            RefusalCode::CollateralInvalid => "collateral-invalid",
            RefusalCode::Revoked => "revoked",
            RefusalCode::TcbNotAllowed => "tcb-not-allowed",
            RefusalCode::RegisterMismatch => "register-mismatch",
            RefusalCode::LogRequired => "log-required",
            RefusalCode::LogInvalid => "log-invalid",
            RefusalCode::ReplayMismatch => "replay-mismatch",
            RefusalCode::ReferenceMismatch => "reference-mismatch",
            RefusalCode::BackingBelowMinimum => "backing-below-minimum",
            RefusalCode::DeviceRequired => "device-required",
            RefusalCode::DeviceNotAllowed => "device-not-allowed",
            RefusalCode::DeviceTokenInvalid => "device-token-invalid",
            RefusalCode::DevicePolicy => "device-policy",
            RefusalCode::Unsupported => "unsupported",
        }
    }
}

impl std::fmt::Display for RefusalCode {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

impl AttestationError {
    /// A refusal with its section 14.4 code.
    pub fn refused(code: RefusalCode, reason: impl Into<String>) -> Self {
        AttestationError::Refused {
            code,
            reason: reason.into(),
        }
    }

    /// The section 14.4 code of this error. Errors of the attester side and
    /// of collateral fetching map to the code a verifier would report.
    pub fn refusal_code(&self) -> RefusalCode {
        use AttestationError as E;
        use RefusalCode as C;
        match self {
            E::Refused { code, .. } => *code,
            E::NoPlatformDetected | E::PlatformNotEnabled(_) | E::HardwareAccessFailed(_) => {
                C::PlatformUnsupported
            }
            E::ReportDataTooLarge { .. }
            | E::EvidenceDeserialize(_)
            | E::EvidenceTooLarge { .. }
            | E::ProfileEvidenceInvalid(_) => C::EnvelopeInvalid,
            E::PolicyInvalid(_) => C::PolicyInvalid,
            E::SignatureVerificationFailed(_) => C::SignatureInvalid,
            E::CertChainError(_) => C::ChainInvalid,
            E::CertFetchError(_) => C::CollateralUnavailable,
            E::QuoteParseFailed(_) | E::UnsupportedReportVersion { .. } => C::ReportInvalid,
            E::VmplCheckFailed(_) | E::DebugPolicyViolation => C::GuestPolicy,
            E::EventlogIntegrityFailed(_) => C::ReplayMismatch,
            E::EventlogParseFailed(_) => C::LogInvalid,
            E::TcbMismatch(_) => C::TcbNotAllowed,
            E::ReportDataMismatch => C::BindingMismatch,
            E::InitDataMismatch => C::ReferenceMismatch,
            #[cfg(feature = "nvidia-gpu")]
            E::NvidiaGpuRequired => C::DeviceRequired,
            #[cfg(feature = "nvidia-gpu")]
            E::NvidiaGpuBindingMismatch
            | E::NvidiaGpuSubmoduleNonceMismatch { .. }
            | E::NvidiaGpuUserNonceMissing
            | E::NvidiaGpuReportDataRequired
            | E::NvidiaGpuBindingNotAllowed
            | E::NvidiaGpuNonceTooShort(_) => C::BindingMismatch,
            #[cfg(feature = "nvidia-gpu")]
            E::NvidiaGpuDevicePolicyFailed { .. }
            | E::NrasOverallFailed
            | E::NvidiaGpuDeviceCountMismatch { .. } => C::DevicePolicy,
            #[cfg(feature = "nvidia-gpu")]
            E::NvidiaGpuArchNotAllowed(_)
            | E::NvidiaGpuBundleEmpty
            | E::NvidiaGpuTooManyDevices(_, _) => C::DeviceNotAllowed,
            #[cfg(feature = "nvidia-gpu")]
            E::NrasRequestFailed(_) | E::JwksFetch(_) => C::CollateralUnavailable,
            #[cfg(feature = "nvidia-gpu")]
            E::NrasResponseParse(_)
            | E::NrasIssuerMismatch { .. }
            | E::NrasClaimsVersionMismatch { .. }
            | E::NrasSubmoduleDigestMismatch { .. }
            | E::JwsVerification(_)
            | E::JwksKidNotFound(_) => C::DeviceTokenInvalid,
            #[cfg(all(feature = "nvidia-gpu-attest", target_os = "linux"))]
            E::NvidiaGpuEvidenceCollection(_) => C::PlatformUnsupported,
            E::Collateral(e) => match e {
                crate::collateral::CollateralError::Parse { .. }
                | crate::collateral::CollateralError::Expired { .. }
                | crate::collateral::CollateralError::Unsigned { .. } => C::CollateralInvalid,
                _ => C::CollateralUnavailable,
            },
            E::Other(_) => C::EnvelopeInvalid,
        }
    }
}
