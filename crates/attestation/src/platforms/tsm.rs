//! Linux ConfigFS TSM reports: the kernel interface a guest asks for its
//! attestation report through when no device node is reachable, as in a
//! container whose runtime passes none.
//!
//! A report is one directory under [`REPORT_PATH`]. The kernel fills it with
//! attribute files when it is created: `provider` names the driver, `inblob`
//! takes the report data, `outblob` returns the report, and `generation`
//! counts writes so a reader can tell its request was the one answered.

use std::fs;
use std::path::Path;

use crate::error::{AttestationError, Result};

/// Where the kernel exposes TSM reports once configfs is mounted.
pub const REPORT_PATH: &str = "/sys/kernel/config/tsm/report";

fn hardware(context: &str, error: impl std::fmt::Display) -> AttestationError {
    AttestationError::HardwareAccessFailed(format!("{context}: {error}"))
}

/// Remove a report directory. ConfigFS directories take `rmdir`, not a
/// recursive delete, so a `TempDir` cannot drop them itself.
fn remove_entry(entry: tempfile::TempDir) {
    let path = entry.keep();
    if let Err(e) = fs::remove_dir(&path) {
        log::warn!("failed to clean up ConfigFS TSM report dir {path:?}: {e}");
    }
}

/// Whether the TSM driver under `base` is `provider`. The interface is shared
/// by every confidential-computing driver, so its presence alone names none.
pub fn has_provider(base: &Path, provider: &str) -> bool {
    let Ok(entry) = tempfile::tempdir_in(base) else {
        return false;
    };
    let found = fs::read_to_string(entry.path().join("provider")).unwrap_or_default();
    remove_entry(entry);
    found.trim() == provider
}

/// Request a report over `report_data` from the TSM driver under `base`,
/// which must be `provider`.
pub fn report(base: &Path, provider: &str, report_data: &[u8; 64]) -> Result<Vec<u8>> {
    let entry = tempfile::tempdir_in(base).map_err(|e| hardware("create TSM report dir", e))?;
    let result = read_entry(entry.path(), provider, report_data);
    remove_entry(entry);
    result
}

/// Fill one report directory and read the report back.
fn read_entry(entry: &Path, provider: &str, report_data: &[u8; 64]) -> Result<Vec<u8>> {
    let found =
        fs::read_to_string(entry.join("provider")).map_err(|e| hardware("read TSM provider", e))?;
    if found.trim() != provider {
        return Err(AttestationError::HardwareAccessFailed(format!(
            "TSM provider is '{}', not {provider}",
            found.trim()
        )));
    }
    fs::write(entry.join("inblob"), report_data).map_err(|e| hardware("write inblob", e))?;
    let report = fs::read(entry.join("outblob")).map_err(|e| hardware("read outblob", e))?;
    // The kernel reports a failed request as a zero-length read, not an error.
    if report.is_empty() {
        return Err(AttestationError::HardwareAccessFailed(
            "ConfigFS TSM returned an empty report".to_string(),
        ));
    }
    let generation: u32 = fs::read_to_string(entry.join("generation"))
        .map_err(|e| hardware("read generation", e))?
        .trim()
        .parse()
        .map_err(|e| hardware("parse generation", e))?;
    // Another writer to this directory would have replaced the report data.
    if generation > 1 {
        return Err(AttestationError::HardwareAccessFailed(format!(
            "inblob write race detected: generation={generation}"
        )));
    }
    Ok(report)
}

/// Mount configfs at `/sys/kernel/config` when nothing is mounted there, and
/// report whether this call mounted it. A container gets no configfs mount of
/// its own, so without one no TSM report is reachable and no platform is
/// detected. Needs `CAP_SYS_ADMIN`; call before [`crate::detect`], which
/// caches its answer.
#[cfg(target_os = "linux")]
pub fn mount_configfs() -> std::io::Result<bool> {
    const CONFIGFS: &std::ffi::CStr = c"configfs";
    const TARGET: &std::ffi::CStr = c"/sys/kernel/config";
    if Path::new("/sys/kernel/config/tsm").exists() {
        return Ok(false);
    }
    // SAFETY: both arguments are NUL-terminated constants, and the data
    // argument may be null for a filesystem that takes no options.
    let rc = unsafe {
        libc::mount(
            CONFIGFS.as_ptr(),
            TARGET.as_ptr(),
            CONFIGFS.as_ptr(),
            0,
            std::ptr::null(),
        )
    };
    if rc != 0 {
        return Err(std::io::Error::last_os_error());
    }
    Ok(true)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A report directory as the kernel would have filled it.
    fn entry(provider: &str, outblob: &[u8], generation: &str) -> tempfile::TempDir {
        let dir = tempfile::tempdir().unwrap();
        fs::write(dir.path().join("provider"), provider).unwrap();
        fs::write(dir.path().join("outblob"), outblob).unwrap();
        fs::write(dir.path().join("generation"), generation).unwrap();
        dir
    }

    #[test]
    fn a_report_is_read_from_the_named_provider() {
        let dir = entry("sev_guest\n", &[7; 1184], "1\n");
        let report = read_entry(dir.path(), "sev_guest", &[9; 64]).unwrap();
        assert_eq!(report, vec![7; 1184]);
        assert_eq!(fs::read(dir.path().join("inblob")).unwrap(), vec![9; 64]);
    }

    #[test]
    fn another_provider_is_refused_before_the_request() {
        let dir = entry("tdx_guest\n", &[7; 8], "1\n");
        let err = read_entry(dir.path(), "sev_guest", &[9; 64]).unwrap_err();
        assert!(err.to_string().contains("not sev_guest"), "{err}");
        assert!(!dir.path().join("inblob").exists());
    }

    #[test]
    fn an_empty_report_and_a_raced_request_are_errors() {
        let empty = entry("sev_guest", &[], "1");
        assert!(read_entry(empty.path(), "sev_guest", &[0; 64]).is_err());
        let raced = entry("sev_guest", &[7; 8], "2");
        let err = read_entry(raced.path(), "sev_guest", &[0; 64]).unwrap_err();
        assert!(err.to_string().contains("race"), "{err}");
    }

    #[test]
    fn a_directory_that_is_not_a_tsm_names_no_provider() {
        let base = tempfile::tempdir().unwrap();
        assert!(!has_provider(base.path(), "sev_guest"));
        assert!(!has_provider(&base.path().join("missing"), "sev_guest"));
    }
}
