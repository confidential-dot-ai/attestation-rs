pub mod verify;

pub use verify::{GcpSnp, GcpSnpParams, GcpSnpResult};

#[cfg(all(feature = "attest", feature = "gcp-snp", target_os = "linux"))]
pub mod attest;
