use std::path::Path;

use base64::{engine::general_purpose::STANDARD as BASE64, Engine};

use sev::firmware::guest::Firmware;
use sev::firmware::host::{CertTableEntry, CertType};

use crate::error::{AttestationError, Result};
use crate::utils::pad_report_data;

use super::evidence::{SnpCertChain, SnpEvidence};

/// SNP guest attestation character device.
const SEV_GUEST_DEVICE_PATH: &str = "/dev/sev-guest";

/// The guest kernel's runtime-register event log (absent on kernels without
/// the provider).
const EVENT_LOG_PATH: &str = "/sys/class/misc/sev-guest/event_log";

/// Check if SNP hardware is available on this machine.
pub fn is_available() -> bool {
    Path::new(SEV_GUEST_DEVICE_PATH).exists()
}

/// Extract certificates from the sev crate's cert table entries.
fn certs_to_chain(certs: Vec<CertTableEntry>) -> Option<SnpCertChain> {
    let mut vcek = None;
    let mut ask = None;
    let mut ark = None;

    for entry in &certs {
        let encoded = BASE64.encode(entry.data());
        match entry.cert_type {
            CertType::VCEK | CertType::VLEK => vcek = Some(encoded),
            CertType::ASK => ask = Some(encoded),
            CertType::ARK => ark = Some(encoded),
            _ => {}
        }
    }

    vcek.map(|v| SnpCertChain { vcek: v, ask, ark })
}

/// Generate SNP attestation evidence.
pub async fn generate_evidence(report_data: &[u8]) -> Result<SnpEvidence> {
    let padded = pad_report_data(report_data, 64)?;
    let data: [u8; 64] = padded
        .try_into()
        .map_err(|_| AttestationError::ReportDataTooLarge { max: 64 })?;

    // Open the /dev/sev-guest device via the sev crate
    let mut firmware = Firmware::open().map_err(|e| {
        AttestationError::HardwareAccessFailed(format!("Firmware::open failed: {}", e))
    })?;

    // Get the extended report (attestation report + certificate table)
    let (report_bytes, certs) =
        firmware
            .get_ext_report(None, Some(data), Some(0))
            .map_err(|e| {
                AttestationError::HardwareAccessFailed(format!("get_ext_report failed: {}", e))
            })?;

    let cert_chain = certs.and_then(certs_to_chain);
    // Read after the report: the log then holds the prefix the report commits to.
    let event_log = std::fs::read(EVENT_LOG_PATH)
        .ok()
        .map(|log| BASE64.encode(log));

    Ok(SnpEvidence {
        attestation_report: BASE64.encode(&report_bytes),
        cert_chain,
        event_log,
    })
}
