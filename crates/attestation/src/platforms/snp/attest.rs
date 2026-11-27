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

/// Certificate GUIDs of a certificate table, in the byte order the `sev`
/// crate reads them from the device.
const GUID_VCEK: [u8; 16] = [
    0x63, 0xda, 0x75, 0x8d, 0xe6, 0x64, 0x45, 0x64, 0xad, 0xc5, 0xf4, 0xb9, 0x3b, 0xe8, 0xac, 0xcd,
];
const GUID_VLEK: [u8; 16] = [
    0xa8, 0x07, 0x4b, 0xc2, 0xa2, 0x5a, 0x48, 0x3e, 0xaa, 0xe6, 0x39, 0xc0, 0x45, 0xa0, 0xb8, 0xa1,
];
const GUID_ASK: [u8; 16] = [
    0x4a, 0xb7, 0xb3, 0x79, 0xbb, 0xac, 0x4f, 0xe4, 0xa0, 0x2f, 0x05, 0xae, 0xf3, 0x27, 0xc7, 0x82,
];
const GUID_ARK: [u8; 16] = [
    0xc0, 0xb4, 0x06, 0xa4, 0xa8, 0x03, 0x49, 0x52, 0x97, 0x43, 0x3f, 0xb6, 0x01, 0x4c, 0xd0, 0xae,
];

/// The certificate chain in the table a TSM report carries beside it: entries
/// of a GUID, an offset and a length, ended by an all-zero entry, then the
/// certificates. The host writes the table, so every offset is checked
/// against it. A host that supplied none leaves it empty, and a verifier then
/// fetches the chain; a table that does not parse is treated the same way.
/// `vlek` says which key signed the report, and so which entry is its
/// certificate: a table may carry both.
fn aux_chain(table: &[u8], vlek: bool) -> Option<SnpCertChain> {
    const ENTRY: usize = 24;
    let signer = if vlek { GUID_VLEK } else { GUID_VCEK };
    let entries = table.as_chunks::<ENTRY>().0;
    let Some(end_entry) = entries.iter().position(|entry| entry[..16] == [0; 16]) else {
        if !table.is_empty() {
            log::warn!("ignoring an SNP certificate table with no end entry");
        }
        return None;
    };
    // Certificates follow the end entry; none may lie in the entries.
    let certificates = (end_entry + 1) * ENTRY;
    let (mut vcek, mut ask, mut ark) = (None, None, None);
    for entry in &entries[..end_entry] {
        let guid: [u8; 16] = entry[..16].try_into().ok()?;
        let offset = u32::from_le_bytes(entry[16..20].try_into().ok()?) as usize;
        let length = u32::from_le_bytes(entry[20..24].try_into().ok()?) as usize;
        let cert = offset
            .checked_add(length)
            .and_then(|end| table.get(offset..end))
            .filter(|cert| offset >= certificates && !cert.is_empty());
        let Some(cert) = cert else {
            log::warn!("ignoring an SNP certificate table whose entry names no certificate");
            return None;
        };
        let encoded = Some(BASE64.encode(cert));
        match guid {
            g if g == signer => vcek = encoded,
            GUID_ASK => ask = encoded,
            GUID_ARK => ark = encoded,
            _ => {}
        }
    }
    vcek.map(|v| SnpCertChain { vcek: v, ask, ark })
}

/// Whether a VLEK signed `report`: SIGNING_KEY, bits 4:2 of the key
/// information word at offset 0x48, is 1.
fn signed_by_vlek(report: &[u8]) -> Result<bool> {
    let word: [u8; 4] = report
        .get(0x48..0x4c)
        .and_then(|w| w.try_into().ok())
        .ok_or_else(|| {
            AttestationError::HardwareAccessFailed(format!(
                "ConfigFS TSM returned a {}-byte SNP report",
                report.len()
            ))
        })?;
    Ok((u32::from_le_bytes(word) >> 2) & 0b111 == 1)
}

/// Whether `report` names its chip: CHIP_ID, the 64 bytes at offset 0x1a0,
/// is all zero when the host masks it, and a verifier then has no VCEK to ask for.
fn names_its_chip(report: &[u8]) -> bool {
    report
        .get(0x1a0..0x1e0)
        .is_some_and(|id| id.iter().any(|b| *b != 0))
}

/// The certificate chain for a TSM report: the host's, when its certificate
/// signed the report and is within its validity period, as a verifier
/// requires. Evidence nobody can verify is an error here.
fn tsm_chain(report: &[u8], aux: &[u8]) -> Result<Option<SnpCertChain>> {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |since| since.as_secs() as i64);
    chain_that(report, aux, |report, cert| {
        super::verify::verify_report_signature(report, cert).is_ok()
            && super::verify::verify_vek_validity_period(cert, now).is_ok()
    })
}

/// [`tsm_chain`] with `signed` deciding whether a certificate, in DER, signed
/// the report.
///
/// A verifier checks a VCEK against the chip the report names and can fetch
/// it by that name; it can fetch no VLEK. So a VCEK-signed report must name
/// its chip, with or without a certificate beside it, and goes out without
/// one the host got wrong; a VLEK-signed report needs the one that signed it.
fn chain_that(
    report: &[u8],
    aux: &[u8],
    signed: impl Fn(&[u8], &[u8]) -> bool,
) -> Result<Option<SnpCertChain>> {
    let vlek = signed_by_vlek(report)?;
    if !vlek && !names_its_chip(report) {
        return Err(AttestationError::HardwareAccessFailed(
            "the SNP report is VCEK-signed and masks its chip ID, which a verifier checks the VCEK against"
                .to_string(),
        ));
    }
    let chain = aux_chain(aux, vlek).filter(|chain| {
        let usable = BASE64
            .decode(&chain.vcek)
            .is_ok_and(|cert| signed(report, &cert));
        if !usable {
            log::warn!(
                "ignoring an SNP certificate table whose certificate did not sign the report or is outside its validity period"
            );
        }
        usable
    });
    if vlek && chain.is_none() {
        return Err(AttestationError::HardwareAccessFailed(
            "the SNP report is signed with a VLEK and the host supplied no VLEK certificate that signed it"
                .to_string(),
        ));
    }
    Ok(chain)
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
        let tsm::Report { report, aux } =
            tsm::report(Path::new(tsm::REPORT_PATH), TSM_PROVIDER, &data)?;
        log::info!("SNP report generated via ConfigFS TSM");
        let chain = tsm_chain(&report, &aux)?;
        (report, chain)
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

    /// A certificate table of the given entries, laid out as a host writes it.
    fn cert_table(certs: &[([u8; 16], &[u8])]) -> Vec<u8> {
        let mut offset = (certs.len() + 1) * 24;
        let (mut head, mut body) = (Vec::new(), Vec::new());
        for (guid, cert) in certs {
            head.extend_from_slice(guid);
            head.extend_from_slice(&(offset as u32).to_le_bytes());
            head.extend_from_slice(&(cert.len() as u32).to_le_bytes());
            body.extend_from_slice(cert);
            offset += cert.len();
        }
        head.extend_from_slice(&[0; 24]);
        head.extend_from_slice(&body);
        head
    }

    #[test]
    fn a_tsm_certificate_table_becomes_the_chain() {
        let table = cert_table(&[(GUID_ARK, b"ark"), (GUID_VCEK, b"vcek"), (GUID_ASK, b"ask")]);
        let chain = aux_chain(&table, false).unwrap();
        assert_eq!(chain.vcek, BASE64.encode("vcek"));
        assert_eq!(chain.ask, Some(BASE64.encode("ask")));
        assert_eq!(chain.ark, Some(BASE64.encode("ark")));
        assert!(aux_chain(&cert_table(&[(GUID_ASK, b"ask")]), false).is_none());
    }

    #[test]
    fn an_empty_or_malformed_certificate_table_yields_no_chain() {
        assert!(aux_chain(&[], false).is_none());
        let table = cert_table(&[(GUID_VCEK, b"vcek")]);
        // No end entry, and an entry that points past the table.
        assert!(aux_chain(&table[..24], false).is_none());
        let mut past = table.clone();
        past[20..24].copy_from_slice(&u32::MAX.to_le_bytes());
        assert!(aux_chain(&past, false).is_none());
        let mut wrapped = table;
        wrapped[16..20].copy_from_slice(&u32::MAX.to_le_bytes());
        assert!(aux_chain(&wrapped, false).is_none());
    }

    /// A signature check that accepts every certificate.
    fn any(_: &[u8], _: &[u8]) -> bool {
        true
    }

    /// An SNP report whose key information word names `signing_key`.
    fn report_signed_by(signing_key: u32) -> Vec<u8> {
        let mut report = vec![0u8; 1184];
        report[0x1a0] = 7;
        report[0x48..0x4c].copy_from_slice(&(signing_key << 2 | 0b11).to_le_bytes());
        report
    }

    #[test]
    fn the_signing_key_picks_the_certificate_in_either_table_order() {
        for table in [
            cert_table(&[(GUID_VCEK, b"vcek"), (GUID_VLEK, b"vlek")]),
            cert_table(&[(GUID_VLEK, b"vlek"), (GUID_VCEK, b"vcek")]),
        ] {
            let by_vcek = chain_that(&report_signed_by(0), &table, any)
                .unwrap()
                .unwrap();
            assert_eq!(by_vcek.vcek, BASE64.encode("vcek"));
            let by_vlek = chain_that(&report_signed_by(1), &table, any)
                .unwrap()
                .unwrap();
            assert_eq!(by_vlek.vcek, BASE64.encode("vlek"));
        }
    }

    #[test]
    fn a_vlek_report_without_its_certificate_is_an_error() {
        let vcek_only = cert_table(&[(GUID_VCEK, b"vcek")]);
        assert!(chain_that(&report_signed_by(1), &[], any).is_err());
        assert!(chain_that(&report_signed_by(1), &vcek_only, any).is_err());
        // A VCEK-signed report leaves the chain to the verifier.
        assert!(chain_that(&report_signed_by(0), &[], any)
            .unwrap()
            .is_none());
        assert!(chain_that(&[0; 16], &[], any).is_err());
        // Unless it masks the chip the verifier would ask about.
        let mut masked = report_signed_by(0);
        masked[0x1a0] = 0;
        assert!(chain_that(&masked, &[], any).is_err());
        assert!(chain_that(&masked, &vcek_only, any).is_err());
    }

    #[test]
    fn a_certificate_that_did_not_sign_the_report_is_left_out() {
        let none = |_: &[u8], _: &[u8]| false;
        let table = cert_table(&[(GUID_VCEK, b"vcek"), (GUID_VLEK, b"vlek")]);
        // The verifier fetches the right VCEK by the chip the report names.
        assert!(chain_that(&report_signed_by(0), &table, none)
            .unwrap()
            .is_none());
        assert!(chain_that(&report_signed_by(1), &table, none).is_err());
        let only_vlek = |_: &[u8], cert: &[u8]| cert == b"vlek";
        assert!(chain_that(&report_signed_by(1), &table, only_vlek)
            .unwrap()
            .is_some());
    }

    #[test]
    fn a_certificate_entry_must_name_bytes_after_the_entries() {
        let table = cert_table(&[(GUID_VCEK, b"vcek")]);
        let mut empty = table.clone();
        empty[20..24].copy_from_slice(&0u32.to_le_bytes());
        assert!(aux_chain(&empty, false).is_none());
        let mut in_entries = table;
        in_entries[16..20].copy_from_slice(&0u32.to_le_bytes());
        assert!(aux_chain(&in_entries, false).is_none());
    }

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
