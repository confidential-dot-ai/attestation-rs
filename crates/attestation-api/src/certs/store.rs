//! Durable collateral store.
//!
//! A VCEK is fixed for a (generation, chip, TCB) triple and an AMD cert chain is
//! fixed per generation, so both are safe to keep on disk indefinitely. Doing so
//! is what lets attestation survive a cold process or a KDS outage. CRLs are
//! deliberately absent: serving a stale CRL silently weakens revocation.

use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

use crate::config::normalize_generation;

static TMP_SEQ: AtomicU64 = AtomicU64::new(0);

pub struct CollateralStore {
    root: PathBuf,
}

impl CollateralStore {
    pub fn new(root: impl Into<PathBuf>) -> Self {
        Self { root: root.into() }
    }

    pub fn root(&self) -> &Path {
        &self.root
    }

    pub fn get_vcek(&self, processor_gen: &str, chip_id_hex: &str, tcb: &str) -> Option<Vec<u8>> {
        read_if_present(&self.vcek_path(processor_gen, chip_id_hex, tcb)?)
    }

    pub fn put_vcek(&self, processor_gen: &str, chip_id_hex: &str, tcb: &str, der: &[u8]) {
        let Some(path) = self.vcek_path(processor_gen, chip_id_hex, tcb) else {
            return;
        };
        write_atomic(&path, der);
    }

    /// Both halves must be present; a chain missing one file is treated as absent
    /// so a torn write can never yield a half-chain.
    pub fn get_chain(&self, processor_gen: &str) -> Option<(Vec<u8>, Vec<u8>)> {
        let dir = self.chain_dir(processor_gen)?;
        let ark = read_if_present(&dir.join("ark.der"))?;
        let ask = read_if_present(&dir.join("ask.der"))?;
        Some((ark, ask))
    }

    pub fn put_chain(&self, processor_gen: &str, ark_der: &[u8], ask_der: &[u8]) {
        let Some(dir) = self.chain_dir(processor_gen) else {
            return;
        };
        write_atomic(&dir.join("ark.der"), ark_der);
        write_atomic(&dir.join("ask.der"), ask_der);
    }

    /// Every path component is either a member of the fixed generation list or
    /// hex, so a caller cannot walk out of the store root.
    fn vcek_path(&self, processor_gen: &str, chip_id_hex: &str, tcb: &str) -> Option<PathBuf> {
        let generation = normalize_generation(processor_gen)?;
        if !is_hex(chip_id_hex) || !is_hex(tcb) {
            tracing::warn!(chip_id_hex, tcb, "refusing non-hex VCEK store key");
            return None;
        }
        Some(
            self.root
                .join("vcek")
                .join(generation)
                .join(format!("{chip_id_hex}-{tcb}.der")),
        )
    }

    fn chain_dir(&self, processor_gen: &str) -> Option<PathBuf> {
        Some(
            self.root
                .join("chain")
                .join(normalize_generation(processor_gen)?),
        )
    }
}

fn is_hex(s: &str) -> bool {
    !s.is_empty() && s.len() <= 256 && s.bytes().all(|b| b.is_ascii_hexdigit())
}

fn read_if_present(path: &Path) -> Option<Vec<u8>> {
    match fs::read(path) {
        Ok(bytes) if bytes.is_empty() => None,
        Ok(bytes) => Some(bytes),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => None,
        Err(e) => {
            tracing::warn!(path = %path.display(), error = %e, "collateral store read failed");
            None
        }
    }
}

/// Temp file plus rename, so a concurrent reader never observes a partial cert.
/// Failures are logged and swallowed: the store is a cache and must never be the
/// reason a verification fails.
fn write_atomic(path: &Path, bytes: &[u8]) {
    let Some(dir) = path.parent() else { return };
    if let Err(e) = fs::create_dir_all(dir) {
        tracing::warn!(path = %dir.display(), error = %e, "collateral store mkdir failed");
        return;
    }

    let seq = TMP_SEQ.fetch_add(1, Ordering::Relaxed);
    let tmp = dir.join(format!(".tmp.{}.{seq}", std::process::id()));

    let written = fs::File::create(&tmp).and_then(|mut f| {
        f.write_all(bytes)?;
        f.sync_all()
    });
    if let Err(e) = written {
        tracing::warn!(path = %tmp.display(), error = %e, "collateral store write failed");
        let _ = fs::remove_file(&tmp);
        return;
    }

    if let Err(e) = fs::rename(&tmp, path) {
        tracing::warn!(path = %path.display(), error = %e, "collateral store rename failed");
        let _ = fs::remove_file(&tmp);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn store() -> (tempfile::TempDir, CollateralStore) {
        let dir = tempfile::tempdir().unwrap();
        let store = CollateralStore::new(dir.path());
        (dir, store)
    }

    const CHIP: &str = "ab12cd34";
    const TCB: &str = "03000A1B";

    #[test]
    fn vcek_round_trips() {
        let (_dir, store) = store();
        store.put_vcek("Genoa", CHIP, TCB, b"der-bytes");
        assert_eq!(store.get_vcek("Genoa", CHIP, TCB).unwrap(), b"der-bytes");
    }

    #[test]
    fn vcek_is_keyed_by_generation_chip_and_tcb() {
        let (_dir, store) = store();
        store.put_vcek("Genoa", CHIP, TCB, b"genoa");
        assert!(store.get_vcek("Milan", CHIP, TCB).is_none());
        assert!(store.get_vcek("Genoa", "ffffffff", TCB).is_none());
        assert!(store.get_vcek("Genoa", CHIP, "04000A1B").is_none());
    }

    #[test]
    fn unknown_generation_touches_no_files() {
        let (dir, store) = store();
        store.put_vcek("Bogus", CHIP, TCB, b"nope");
        assert!(store.get_vcek("Bogus", CHIP, TCB).is_none());
        assert!(
            !dir.path().join("vcek").exists(),
            "an unknown generation must not create anything under the store root"
        );
    }

    #[test]
    fn traversal_keys_are_refused_and_write_nothing() {
        let (dir, store) = store();
        for bad in ["../../etc/passwd", "..", "ab/cd", "ab12cd34 "] {
            store.put_vcek("Genoa", bad, TCB, b"nope");
            assert!(store.get_vcek("Genoa", bad, TCB).is_none(), "{bad}");
        }
        // Nothing may exist outside the Genoa VCEK directory, and that directory
        // must not have been created either.
        assert!(!dir.path().join("vcek").exists());
    }

    #[test]
    fn half_written_chain_reads_as_absent() {
        let (dir, store) = store();
        let gen_dir = dir.path().join("chain").join("Genoa");
        fs::create_dir_all(&gen_dir).unwrap();
        fs::write(gen_dir.join("ark.der"), b"ark").unwrap();
        assert!(
            store.get_chain("Genoa").is_none(),
            "a chain missing its ASK half must not be served"
        );

        store.put_chain("Genoa", b"ark", b"ask");
        assert_eq!(
            store.get_chain("Genoa").unwrap(),
            (b"ark".to_vec(), b"ask".to_vec())
        );
    }

    #[test]
    fn empty_file_reads_as_absent() {
        let (dir, store) = store();
        let p = dir.path().join("vcek").join("Genoa");
        fs::create_dir_all(&p).unwrap();
        fs::write(p.join(format!("{CHIP}-{TCB}.der")), b"").unwrap();
        assert!(store.get_vcek("Genoa", CHIP, TCB).is_none());
    }

    #[test]
    fn write_leaves_no_temp_files_behind() {
        let (dir, store) = store();
        store.put_vcek("Genoa", CHIP, TCB, b"der");
        let leftovers: Vec<_> = fs::read_dir(dir.path().join("vcek").join("Genoa"))
            .unwrap()
            .filter_map(|e| e.ok())
            .map(|e| e.file_name().to_string_lossy().to_string())
            .filter(|n| n.starts_with(".tmp."))
            .collect();
        assert!(
            leftovers.is_empty(),
            "temp files left behind: {leftovers:?}"
        );
    }
}
