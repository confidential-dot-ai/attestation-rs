use std::fs;
use std::path::Path;

use base64::{engine::general_purpose::STANDARD as BASE64, Engine};

use sev::firmware::guest::Firmware;
use sev::firmware::host::{CertTableEntry, CertType};

use crate::error::{AttestationError, Result};
use crate::utils::pad_report_data;

use super::evidence::{SnpCertChain, SnpEvidence};

/// SNP guest attestation character device.
const SEV_GUEST_DEVICE_PATH: &str = "/dev/sev-guest";

/// Linux ConfigFS TSM report interface, shared across SNP/TDX. A filesystem,
/// not a char device, so report generation works from an unprivileged container
/// (no device-cgroup rule needed, unlike /dev/sev-guest).
const TSM_REPORT_PATH: &str = "/sys/kernel/config/tsm/report";

/// SNP report struct size: the TSM outblob for the sev_guest provider is this
/// many bytes (an `AttestationReport`).
const SNP_REPORT_LEN: usize = 1184;

/// Check if SNP hardware is available on this machine, via either the TSM
/// configfs sev_guest provider or the /dev/sev-guest char device.
pub fn is_available() -> bool {
    tsm_provider_is_sev() || Path::new(SEV_GUEST_DEVICE_PATH).exists()
}

/// Whether the ConfigFS TSM provider on this node is `sev_guest`. The TSM
/// subsystem is shared (SNP, TDX, …), so the provider must be confirmed before
/// treating an outblob as an SNP report.
fn tsm_provider_is_sev() -> bool {
    let tsm_path = Path::new(TSM_REPORT_PATH);
    if !tsm_path.exists() {
        return false;
    }
    let Ok(dir) = tempfile::tempdir_in(tsm_path) else {
        return false;
    };
    let provider = fs::read_to_string(dir.path().join("provider")).unwrap_or_default();
    let is_sev = provider.trim().contains("sev_guest");
    // ConfigFS dirs need rmdir, not the recursive delete tempfile's Drop runs.
    let path = dir.keep();
    if let Err(e) = std::fs::remove_dir(&path) {
        log::warn!("failed to clean up ConfigFS TSM report dir {path:?}: {e}");
    }
    is_sev
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
///
/// Prefers the ConfigFS TSM report interface, which works unprivileged; falls
/// back to the /dev/sev-guest char device on nodes without TSM. The configfs
/// path returns no cert chain (the outblob carries only the report); the
/// verifier fetches VCEK from KDS using the report's chip_id + reported TCB.
pub async fn generate_evidence(report_data: &[u8]) -> Result<SnpEvidence> {
    let data: [u8; 64] = pad_report_data(report_data, 64)?
        .try_into()
        .map_err(|_| AttestationError::ReportDataTooLarge { max: 64 })?;

    if tsm_provider_is_sev() {
        match generate_evidence_tsm(&data) {
            Ok(evidence) => return Ok(evidence),
            Err(e) => log::warn!("TSM configfs SNP report failed, trying char device: {e}"),
        }
    }
    generate_evidence_device(data)
}

/// Generate evidence via the ConfigFS TSM report interface (unprivileged).
fn generate_evidence_tsm(report_data: &[u8; 64]) -> Result<SnpEvidence> {
    let dir = tempfile::tempdir_in(TSM_REPORT_PATH).map_err(|e| {
        AttestationError::HardwareAccessFailed(format!("create TSM report dir: {e}"))
    })?;
    let report_dir = dir.path();

    fs::write(report_dir.join("inblob"), report_data)
        .map_err(|e| AttestationError::HardwareAccessFailed(format!("write inblob: {e}")))?;
    let report = fs::read(report_dir.join("outblob"))
        .map_err(|e| AttestationError::HardwareAccessFailed(format!("read outblob: {e}")))?;

    // generation > 1 means inblob was written more than once before outblob was
    // read — a concurrent writer raced us, so the report may not match our data.
    let generation: u32 = fs::read_to_string(report_dir.join("generation"))
        .map_err(|e| AttestationError::HardwareAccessFailed(format!("read generation: {e}")))?
        .trim()
        .parse()
        .map_err(|e| AttestationError::HardwareAccessFailed(format!("parse generation: {e}")))?;
    if generation > 1 {
        return Err(AttestationError::HardwareAccessFailed(format!(
            "inblob write race detected: generation={generation}"
        )));
    }

    let path = dir.keep();
    if let Err(e) = std::fs::remove_dir(&path) {
        log::warn!("failed to clean up ConfigFS TSM report dir {path:?}: {e}");
    }

    if report.len() < SNP_REPORT_LEN {
        return Err(AttestationError::HardwareAccessFailed(format!(
            "TSM outblob too short for an SNP report: {} bytes",
            report.len()
        )));
    }

    Ok(SnpEvidence {
        attestation_report: BASE64.encode(&report),
        cert_chain: None,
    })
}

/// Generate evidence via the /dev/sev-guest char device (needs the device
/// cgroup, i.e. a privileged container). Returns the cert chain when the
/// hypervisor cached one in the extended report.
fn generate_evidence_device(data: [u8; 64]) -> Result<SnpEvidence> {
    let mut firmware = Firmware::open().map_err(|e| {
        AttestationError::HardwareAccessFailed(format!("Firmware::open failed: {e}"))
    })?;

    let (report_bytes, certs) =
        firmware
            .get_ext_report(None, Some(data), Some(0))
            .map_err(|e| {
                AttestationError::HardwareAccessFailed(format!("get_ext_report failed: {e}"))
            })?;

    Ok(SnpEvidence {
        attestation_report: BASE64.encode(&report_bytes),
        cert_chain: certs.and_then(certs_to_chain),
    })
}
