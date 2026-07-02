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

    #[error("nvidia_gpu_user_nonce is set but expected_report_data is not — both are required for CPU-GPU binding")]
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
    Other(#[from] anyhow::Error),
}

pub type Result<T> = std::result::Result<T, AttestationError>;
