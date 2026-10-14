pub mod verify;

pub use verify::{GcpTdx, GcpTdxParams, GcpTdxResult};

#[cfg(all(feature = "attest", feature = "gcp-tdx", target_os = "linux"))]
pub mod attest;
