//! GPU evidence collection on a CC-mode Linux host (attester side).
//!
//! Uses NVIDIA's official Rust attestation SDK (`nv-attestation-sdk`) to
//! collect SPDM evidence from two on-host sources:
//! - **GPUs** via NVML (CC-enabled Hopper/Blackwell).
//! - **NVSwitches** via NSCQ ethe fabric interconnect that links GPUs
//!   in HGX/DGX systems. Each switch attests independently of the GPUs and
//!   gets its own SPDM nonce (domain-separated; see `mod.rs`).
//!
//! See `README.md` for the C++ SDK build prereq this feature pulls in.

use std::fmt::Display;
use std::sync::Mutex;

use nv_attestation_sdk::{GpuEvidenceSource, Nonce, NvatSdk, SdkOptions, SwitchEvidenceSource};
use serde::Deserialize;
use sha2::{Digest, Sha256};

use crate::error::{AttestationError, Result};
use crate::platforms::nvidia_gpu::{gpu_nonce, switch_nonce};
use crate::types::{
    NvidiaGpuArch, NvidiaGpuBinding, NvidiaGpuDeviceEvidence, NvidiaGpuEvidenceBundle,
};

/// Wrap any `Display` error as `NvidiaGpuEvidenceCollection` with a static
/// label, mirroring the `anyhow::Context` pattern.
trait GpuCollectionCtx<T> {
    fn gpu_ctx(self, ctx: &'static str) -> Result<T>;
}

impl<T, E: Display> GpuCollectionCtx<T> for std::result::Result<T, E> {
    fn gpu_ctx(self, ctx: &'static str) -> Result<T> {
        self.map_err(|e| AttestationError::NvidiaGpuEvidenceCollection(format!("{ctx}: {e}")))
    }
}

/// Tracks whether the NVAT SDK has been successfully initialized. The SDK must
/// be initialized exactly once and its handle kept alive for the lifetime of
/// all subsequent calls, so we leak the handle and latch this flag to `true` on
/// success. Crucially we only cache *success*: a transient init failure (driver
/// not ready, NSCQ race) leaves the flag `false` so a later call can retry,
/// rather than poisoning the whole process.
static SDK_INITIALIZED: Mutex<bool> = Mutex::new(false);

fn ensure_sdk_init() -> Result<()> {
    let mut initialized = SDK_INITIALIZED
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    if *initialized {
        return Ok(());
    }
    let opts = SdkOptions::new().gpu_ctx("NVAT SDK init: SdkOptions::new")?;
    let sdk = NvatSdk::init(opts).gpu_ctx("NVAT SDK init: NvatSdk::init")?;
    // SDK handle must outlive every call — leak it on purpose.
    std::mem::forget(sdk);
    *initialized = true;
    Ok(())
}

/// Wire shape of one entry as the NVIDIA SDK serializes it via `to_json()`.
/// Matches the NRAS request body field names; we re-map into our envelope.
#[derive(Deserialize)]
struct SdkEvidenceEntry {
    arch: String,
    #[serde(default)]
    uuid: Option<String>,
    evidence: String,
    certificate: String,
}

/// Collect GPU + switch SPDM evidence on the local host.
///
/// The SPDM nonce passed to GPUs is `gpu_nonce(user_nonce, binding)`; the
/// nonce passed to NVSwitches is `switch_nonce(user_nonce, binding)`. Both
/// are deterministic from the caller's `user_nonce` so the verifier can
/// rederive them and confirm NRAS attested to the same values.
pub async fn collect_bundle(
    user_nonce: &[u8],
    binding: NvidiaGpuBinding,
) -> Result<NvidiaGpuEvidenceBundle> {
    // SDK calls are blocking; hand them to a blocking-pool worker so the
    // current async runtime stays responsive.
    let user_nonce = user_nonce.to_vec();
    tokio::task::spawn_blocking(move || collect_bundle_sync(&user_nonce, binding))
        .await
        .gpu_ctx("spawn_blocking")?
}

fn collect_bundle_sync(
    user_nonce: &[u8],
    binding: NvidiaGpuBinding,
) -> Result<NvidiaGpuEvidenceBundle> {
    ensure_sdk_init()?;

    // SDK only exposes `Nonce::from_hex`, so round-trip the raw 32-byte
    // nonces through hex. Both are domain-separated (see `mod.rs`).
    let gpu_n =
        Nonce::from_hex(&hex::encode(gpu_nonce(user_nonce, &binding))).gpu_ctx("Nonce gpu")?;
    let switch_n = Nonce::from_hex(&hex::encode(switch_nonce(user_nonce, &binding)))
        .gpu_ctx("Nonce switch")?;

    let mut entries = collect_gpu_entries(&gpu_n)?;
    entries.append(&mut collect_switch_entries(&switch_n)?);

    if entries.is_empty() {
        return Err(AttestationError::NvidiaGpuEvidenceCollection(
            "no CC GPUs or switches reported by NVAT SDK".into(),
        ));
    }

    let mut devices = entries
        .into_iter()
        .map(sdk_entry_to_device)
        .collect::<Result<Vec<_>>>()?;
    devices.sort_by(|a, b| a.uuid.cmp(&b.uuid));
    Ok(NvidiaGpuEvidenceBundle { devices, binding })
}

fn collect_gpu_entries(nonce: &Nonce) -> Result<Vec<SdkEvidenceEntry>> {
    let Ok(src) = GpuEvidenceSource::from_nvml() else {
        log::debug!("GpuEvidenceSource::from_nvml unavailable (no GPU?)");
        return Ok(Vec::new());
    };
    match src.collect(nonce) {
        Ok(ev) if !ev.is_empty() => {
            let json = ev.to_json().gpu_ctx("gpu to_json")?;
            serde_json::from_str(&json).gpu_ctx("parse gpu json")
        }
        Ok(_) => {
            log::debug!("no CC GPU evidence collected");
            Ok(Vec::new())
        }
        Err(e) => {
            // Absence vs. failure are both non-fatal here — the empty-bundle
            // check in `collect_bundle_sync` enforces that we collected
            // *something*.
            log::warn!("GPU evidence collect failed (continuing): {e}");
            Ok(Vec::new())
        }
    }
}

fn collect_switch_entries(nonce: &Nonce) -> Result<Vec<SdkEvidenceEntry>> {
    let Ok(src) = SwitchEvidenceSource::from_nscq() else {
        log::debug!("SwitchEvidenceSource::from_nscq unavailable (no switches?)");
        return Ok(Vec::new());
    };
    match src.collect(nonce) {
        Ok(ev) if !ev.is_empty() => {
            let json = ev.to_json().gpu_ctx("switch to_json")?;
            serde_json::from_str(&json).gpu_ctx("parse switch json")
        }
        Ok(_) => {
            log::debug!("no NVSwitch evidence collected");
            Ok(Vec::new())
        }
        Err(e) => {
            log::warn!("switch evidence collect failed (continuing): {e}");
            Ok(Vec::new())
        }
    }
}

fn sdk_entry_to_device(e: SdkEvidenceEntry) -> Result<NvidiaGpuDeviceEvidence> {
    let arch = match e.arch.to_ascii_uppercase().as_str() {
        "HOPPER" => NvidiaGpuArch::Hopper,
        "BLACKWELL" => NvidiaGpuArch::Blackwell,
        "LS10" => NvidiaGpuArch::Ls10,
        other => {
            return Err(AttestationError::NvidiaGpuEvidenceCollection(format!(
                "unknown arch from SDK: {other}"
            )));
        }
    };
    // The UUID is a stable, distinct per-device key used only for sorting/dedup
    // of the bundle — NRAS keys devices by submodule order, not by UUID. NVIDIA's
    // SDK (v1.2.0) does not serialize the GPU UUID in its evidence JSON (only
    // arch/nonce/evidence/certificate), so when it is absent derive a stable key
    // from the attestation cert chain, which is unique per physical GPU. This
    // keeps distinct, deterministic per-device keys instead of collapsing
    // multiple anonymous devices onto the same key.
    let cert_chain_b64 = e.certificate;
    let evidence_b64 = e.evidence;
    let uuid = e.uuid.unwrap_or_else(|| {
        let digest = Sha256::digest(cert_chain_b64.as_bytes());
        format!("gpu-cert:{}", hex::encode(&digest[..16]))
    });
    Ok(NvidiaGpuDeviceEvidence {
        arch,
        uuid,
        evidence_b64,
        cert_chain_b64,
    })
}
