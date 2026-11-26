use std::path::Path;

use base64::{engine::general_purpose::STANDARD as BASE64, Engine};

use sev::firmware::guest::Firmware;
use sev::firmware::host::{CertTableEntry, CertType};

use crate::error::{AttestationError, Result};
use crate::platforms::tsm;
use crate::utils::pad_report_data;

use super::evidence::{SnpCertChain, SnpEvidence};

/// SNP guest attestation character device.
const SEV_GUEST_DEVICE_PATH: &str = "/dev/sev-guest";

/// The guest kernel's measurement-register event log (absent on kernels without
/// the provider).
const EVENT_LOG_PATH: &str = "/sys/class/misc/sev-guest/event_log";

/// The name the SNP guest driver registers with the kernel's TSM interface.
const TSM_PROVIDER: &str = "sev_guest";

/// Check if SNP hardware is available on this machine: through the device
/// node, or through ConfigFS TSM where a container runtime passed no node.
pub fn is_available() -> bool {
    Path::new(SEV_GUEST_DEVICE_PATH).exists()
        || tsm::has_provider(Path::new(tsm::REPORT_PATH), TSM_PROVIDER)
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

/// The event log, base64 encoded; `None` only when the file does not exist
/// (a kernel without the provider). Any other read error is returned.
fn read_event_log(path: &Path) -> Result<Option<String>> {
    match std::fs::read(path) {
        Ok(log) => Ok(Some(BASE64.encode(log))),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(e) => Err(AttestationError::HardwareAccessFailed(format!(
            "read {}: {e}",
            path.display()
        ))),
    }
}

/// The extended report from `/dev/sev-guest`: the attestation report and the
/// certificate table the host supplied.
fn device_report(data: [u8; 64]) -> Result<(Vec<u8>, Option<SnpCertChain>)> {
    let mut firmware = Firmware::open().map_err(|e| {
        AttestationError::HardwareAccessFailed(format!("Firmware::open failed: {}", e))
    })?;
    let (report_bytes, certs) =
        firmware
            .get_ext_report(None, Some(data), Some(0))
            .map_err(|e| {
                AttestationError::HardwareAccessFailed(format!("get_ext_report failed: {}", e))
            })?;
    Ok((report_bytes, certs.and_then(certs_to_chain)))
}

/// Generate SNP attestation evidence.
pub async fn generate_evidence(report_data: &[u8]) -> Result<SnpEvidence> {
    let padded = pad_report_data(report_data, 64)?;
    let data: [u8; 64] = padded
        .try_into()
        .map_err(|_| AttestationError::ReportDataTooLarge { max: 64 })?;

    let (report_bytes, cert_chain) = if Path::new(SEV_GUEST_DEVICE_PATH).exists() {
        device_report(data)?
    } else {
        // The report alone: a verifier fetches the certificate chain the
        // device would have returned beside it.
        let report = tsm::report(Path::new(tsm::REPORT_PATH), TSM_PROVIDER, &data)?;
        log::info!("SNP report generated via ConfigFS TSM");
        (report, None)
    };
    // Read after the report: the log then holds the prefix the report commits to.
    let event_log = read_event_log(Path::new(EVENT_LOG_PATH))?;

    Ok(SnpEvidence {
        attestation_report: BASE64.encode(&report_bytes),
        cert_chain,
        event_log,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn only_a_missing_event_log_means_no_log() {
        let dir = tempfile::tempdir().unwrap();
        let log = dir.path().join("event_log");
        assert_eq!(read_event_log(&log).unwrap(), None);
        std::fs::write(&log, [1, 2, 3]).unwrap();
        assert_eq!(
            read_event_log(&log).unwrap(),
            Some(BASE64.encode([1, 2, 3]))
        );
        // A read that fails for another reason (here ENOTDIR) is an error.
        assert!(read_event_log(&log.join("child")).is_err());
    }
}
