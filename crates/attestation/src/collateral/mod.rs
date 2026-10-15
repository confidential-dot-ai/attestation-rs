//! Collateral: the vendor-signed documents a verifier needs besides the
//! evidence. Each is checked against the vendor roots compiled into this
//! crate on the way in, whatever its source ([`Store`]).

#[cfg(feature = "snp")]
mod amd;
#[cfg(not(target_arch = "wasm32"))]
pub(crate) mod disk;
pub(crate) mod document;
#[cfg(any(feature = "gcp-tdx", feature = "gcp-snp"))]
mod gce;
#[cfg(feature = "tdx")]
mod intel;
#[cfg(feature = "nvidia-gpu")]
mod nvidia;
mod store;
#[cfg(not(target_arch = "wasm32"))]
pub(crate) mod vendor;

pub use document::{
    AmdCrl, AmdSigner, AmdVcek, DocKey, Document, Freshness, GceEndorsement, GceTee, Info,
    IntelPckCrl, IntelQeIdentity, IntelRootCrl, IntelTcbInfo, NrasJwks, PckCa, Raw,
};
pub use store::{Doc, Provenance, Source, Store};

/// Save `raw` as `key` in a cache directory, as the store does after a
/// fetch. For tests of programs that read the cache.
#[cfg(not(target_arch = "wasm32"))]
#[doc(hidden)]
pub fn save_to_cache_dir(dir: &std::path::Path, key: &DocKey, raw: &Raw) {
    disk::Disk::new(dir).write(key, raw);
}
