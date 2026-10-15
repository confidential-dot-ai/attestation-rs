use thiserror::Error;

/// Why a piece of collateral could not be had.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
#[serde(tag = "reason", rename_all = "snake_case")]
pub enum Unavailable {
    /// No connection, a timeout, or a body that was cut off.
    Unreachable { detail: String },
    /// The vendor does not publish it (404, 410).
    NotFound { status: u16 },
    /// The vendor asked to be called later (429, or a Retry-After).
    RateLimited { retry_after: Option<u64> },
    /// Any other HTTP status.
    Status { status: u16 },
    /// Fetching is off and no copy is held.
    Offline,
}

impl std::fmt::Display for Unavailable {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Unavailable::Unreachable { detail } => write!(f, "unreachable ({detail})"),
            Unavailable::NotFound { status } => write!(f, "not found (HTTP {status})"),
            Unavailable::RateLimited {
                retry_after: Some(s),
            } => write!(f, "rate limited, retry after {s}s"),
            Unavailable::RateLimited { retry_after: None } => f.write_str("rate limited"),
            Unavailable::Status { status } => write!(f, "HTTP {status}"),
            Unavailable::Offline => f.write_str("not held, and fetching is off"),
        }
    }
}

/// Unified error type for all attestation operations.
#[derive(Error, Debug)]
pub enum AttestationError {
    #[error("no supported TEE platform detected")]
    NoPlatformDetected,

    #[error("platform {0} is not enabled (enable the corresponding cargo feature)")]
    PlatformNotEnabled(String),

    /// The evidence is for a platform the caller gave no policy for.
    #[error("evidence is for {0}, which the policies do not allow")]
    PlatformNotAllowed(String),

    /// The caller's parameters cannot be applied (for example a value of the
    /// wrong size).
    #[error("invalid params: {0}")]
    InvalidParams(String),

    #[error("report_data exceeds maximum size ({max} bytes)")]
    ReportDataTooLarge { max: usize },

    #[error("evidence deserialization failed: {0}")]
    EvidenceDeserialize(String),

    #[error("hardware signature verification failed: {0}")]
    SignatureVerificationFailed(String),

    #[error("certificate chain validation failed: {0}")]
    CertChainError(String),

    /// Collateral the verifier needed (certificates, CRLs, TCB info, NRAS
    /// results) is held nowhere and could not be fetched. The only retryable
    /// error: the evidence was not judged.
    #[error("collateral unavailable: {collateral}: {reason}")]
    CollateralUnavailable {
        collateral: String,
        reason: Unavailable,
    },

    #[error("quote parsing failed: {0}")]
    QuoteParseFailed(String),

    #[error("report version {version} not supported (min: {min}, max: {max})")]
    UnsupportedReportVersion { version: u32, min: u32, max: u32 },

    #[error("eventlog integrity check failed: {0}")]
    EventlogIntegrityFailed(String),

    #[error("TEE hardware access failed: {0}")]
    HardwareAccessFailed(String),

    #[error("TCB version mismatch: {0}")]
    TcbMismatch(String),

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

    #[error("GPU bundle requires NvidiaGpuParams::user_nonce")]
    #[cfg(feature = "nvidia-gpu")]
    NvidiaGpuUserNonceMissing,

    #[error("the GPU user_nonce is set but the platform report_data is not — both are required for CPU-GPU binding")]
    #[cfg(feature = "nvidia-gpu")]
    NvidiaGpuReportDataRequired,

    #[error("GPU bundle binding algorithm not in allowed set")]
    #[cfg(feature = "nvidia-gpu")]
    NvidiaGpuBindingNotAllowed,

    #[error("nvidia_gpu_user_nonce too short ({0} bytes, minimum 16)")]
    #[cfg(feature = "nvidia-gpu")]
    NvidiaGpuNonceTooShort(usize),

    #[error("GPU bundle is empty")]
    #[cfg(feature = "nvidia-gpu")]
    NvidiaGpuBundleEmpty,

    #[error("GPU bundle has {0} devices, exceeding maximum of {1}")]
    #[cfg(feature = "nvidia-gpu")]
    NvidiaGpuTooManyDevices(usize, usize),

    #[error("NRAS request failed: {0}")]
    #[cfg(feature = "nvidia-gpu")]
    NrasRequestFailed(String),

    #[error("NRAS response parse failed: {0}")]
    #[cfg(feature = "nvidia-gpu")]
    NrasResponseParse(String),

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

impl AttestationError {
    /// True for [`AttestationError::CollateralUnavailable`]: the verifier could
    /// not fetch what it needed, so retrying may succeed. Every other error is
    /// final for the given evidence and params.
    pub fn is_retryable(&self) -> bool {
        matches!(self, AttestationError::CollateralUnavailable { .. })
    }

    /// Seconds the vendor asked to wait before retrying, when it said.
    pub fn retry_after(&self) -> Option<u64> {
        match self {
            AttestationError::CollateralUnavailable {
                reason: Unavailable::RateLimited { retry_after },
                ..
            } => *retry_after,
            _ => None,
        }
    }

    /// True when the caller's params cannot be applied: fixing the params,
    /// not the evidence or the network, is what helps.
    pub fn is_invalid_params(&self) -> bool {
        #[cfg(feature = "nvidia-gpu")]
        if matches!(
            self,
            AttestationError::NvidiaGpuUserNonceMissing
                | AttestationError::NvidiaGpuReportDataRequired
                | AttestationError::NvidiaGpuNonceTooShort(_)
        ) {
            return true;
        }
        matches!(
            self,
            AttestationError::InvalidParams(_) | AttestationError::ReportDataTooLarge { .. }
        )
    }
}

pub type Result<T> = std::result::Result<T, AttestationError>;
