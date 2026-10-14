pub mod evidence;
pub mod verify;

pub use verify::{AzSnp, AzSnpParams, AzSnpResult};

#[cfg(all(feature = "attest", feature = "az-snp", target_os = "linux"))]
pub mod attest;
