// INVARIANT CLASS: Correctness
// This module detects the GCP platform and delegates TDX attestation to the
// bare-metal TDX implementation. GCP exposes the same ConfigFS TSM interface
// (or /dev/tdx_guest) and produces standard Intel DCAP quotes.

use crate::error::Result;
use crate::platforms::tdx::attest::TdxQuoteMethod;
use crate::platforms::tdx::evidence::TdxEvidence;

const DMI_BOARD_VENDOR_PATH: &str = "/sys/class/dmi/id/board_vendor";

/// Check if we are running on a GCP Confidential VM with TDX.
///
/// Detection: TDX hardware must be present AND the DMI board vendor must be Google.
/// This matches the approach used by Google's go-tpm-tools for GCP detection.
///
/// # Security
///
/// This is a **best-effort heuristic**, not a security boundary. DMI/SMBIOS
/// data is provided by the hypervisor and can be spoofed by a malicious host.
/// A compromised host that sets `board_vendor = "Google"` on non-GCP hardware
/// will cause this function to return `true`. The resulting attestation quote
/// is cryptographically valid Intel TDX DCAP evidence, but the `GcpTdx`
/// platform tag in the envelope reflects the attester's self-classification only.
pub fn is_available() -> bool {
    if !crate::platforms::tdx::attest::is_available() {
        return false;
    }
    match std::fs::read_to_string(DMI_BOARD_VENDOR_PATH) {
        Ok(vendor) => vendor.trim() == "Google",
        Err(e) => {
            log::debug!("GCP TDX detection: failed to read {DMI_BOARD_VENDOR_PATH}: {e}");
            false
        }
    }
}

/// Generate GCP TDX attestation evidence.
///
/// Defaults to [`TdxQuoteMethod::ConfigFs`] because GCP routes quote
/// requests through the hypervisor (QEMU `quote-generation-socket`), not
/// a guest-reachable QGS on vsock. Using `Auto` would waste ~10s on a
/// vsock connection timeout before falling back to ConfigFS.
// The crate calls generate_evidence_with; tests call this default.
#[cfg_attr(not(feature = "unstable-internals"), allow(dead_code))]
pub async fn generate_evidence(report_data: &[u8]) -> Result<TdxEvidence> {
    crate::platforms::tdx::attest::generate_evidence_with(report_data, TdxQuoteMethod::ConfigFs)
        .await
}

/// Generate GCP TDX attestation evidence with explicit quote method.
///
/// `Auto` is overridden to `ConfigFs` because GCP does not expose a
/// guest-reachable QGS on vsock. Pass `Vsock` explicitly only if you
/// have confirmed vsock is available in your environment.
pub async fn generate_evidence_with(
    report_data: &[u8],
    method: TdxQuoteMethod,
) -> Result<TdxEvidence> {
    let method = match method {
        TdxQuoteMethod::Auto => TdxQuoteMethod::ConfigFs,
        explicit => explicit,
    };
    crate::platforms::tdx::attest::generate_evidence_with(report_data, method).await
}
