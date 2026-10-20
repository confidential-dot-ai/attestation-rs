pub mod certs;
pub mod claims;
pub mod evidence;
pub(crate) mod mr;
pub mod verify;

pub use mr::RuntimeRegisters;
pub use verify::{Snp, SnpParams, SnpResult};

#[cfg(all(feature = "attest", feature = "snp", target_os = "linux"))]
pub mod attest;
