pub mod evidence;
pub mod verify;

pub use verify::{AzTdx, AzTdxParams, AzTdxResult};

#[cfg(all(feature = "attest", feature = "az-tdx", target_os = "linux"))]
pub mod attest;
