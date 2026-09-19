//! Durable copies of collateral across restarts.
//!
//! A stored copy is served only inside the artifact's own validity window, so
//! nothing here weakens revocation or TCB freshness. Paths are built from the
//! typed key, so no caller-supplied string reaches the filesystem.

use super::artifact::{validity, Collateral, Origin};
use super::key::{CollateralKey, CollateralKind};
use chrono::{DateTime, Utc};
use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

static TMP_SEQ: AtomicU64 = AtomicU64::new(0);

pub struct DiskStore {
    root: PathBuf,
}

/// Sidecar next to the bytes: when the copy was fetched and, for signed PCS
/// bodies, the signing chain that came with it.
#[derive(serde::Serialize, serde::Deserialize)]
struct Meta {
    fetched_at: DateTime<Utc>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    signing_chain_pem: Option<String>,
}

impl DiskStore {
    pub fn new(root: impl Into<PathBuf>) -> Self {
        DiskStore { root: root.into() }
    }

    pub fn root(&self) -> &Path {
        &self.root
    }

    fn base_path(&self, key: &CollateralKey) -> Option<PathBuf> {
        if !key.kind().durable() {
            return None;
        }
        // Legacy layout for the two kinds the previous store kept, so an
        // upgraded service reads what it wrote before.
        let rel = match key {
            CollateralKey::SnpVcek {
                generation,
                chip_id,
                tcb,
            } => format!(
                "vcek/{}/{}-{}",
                generation.product_name(),
                hex::encode(chip_id),
                CollateralKey::vcek_tcb_id(tcb)
            ),
            CollateralKey::SnpCertChain { generation } => {
                format!("chain/{}/chain", generation.product_name())
            }
            other => other.id(),
        };
        Some(self.root.join(rel))
    }

    fn ext(kind: CollateralKind) -> &'static str {
        match kind {
            CollateralKind::SnpVcek
            | CollateralKind::SnpCrl
            | CollateralKind::TdxPckCrl
            | CollateralKind::TdxRootCrl => "der",
            CollateralKind::SnpCertChain => "pem",
            CollateralKind::TdxTcbInfo
            | CollateralKind::TdxQeIdentity
            | CollateralKind::NrasJwks => "json",
        }
    }

    /// A stored copy, or `None` when there is none, it is malformed, or it
    /// is already outside its window at `now`.
    pub fn get(&self, key: &CollateralKey, now: DateTime<Utc>) -> Option<Collateral> {
        let base = self.base_path(key)?;
        let bytes_path = base.with_extension(Self::ext(key.kind()));
        let (bytes, meta) = match read_if_present(&bytes_path) {
            Some(bytes) => {
                let meta = read_if_present(&base.with_extension("meta.json"))
                    .and_then(|m| serde_json::from_slice::<Meta>(&m).ok());
                (bytes, meta)
            }
            None => (self.legacy_chain(key)?, None),
        };
        let valid_until = match validity::valid_until(key, &bytes) {
            Ok(v) => v,
            Err(e) => {
                log::warn!("collateral store: discarding {key}: {e}");
                return None;
            }
        };
        if valid_until.is_some_and(|until| now >= until) {
            return None;
        }
        let signing_chain = meta
            .as_ref()
            .and_then(|m| m.signing_chain_pem.clone())
            .map(String::into_bytes);
        if matches!(
            key.kind(),
            CollateralKind::TdxTcbInfo | CollateralKind::TdxQeIdentity
        ) && signing_chain.is_none()
        {
            return None;
        }
        Some(Collateral {
            key: key.clone(),
            bytes,
            signing_chain,
            fetched_at: meta.map_or(now, |m| m.fetched_at),
            valid_until,
            origin: Origin::Stored,
        })
    }

    /// The previous store wrote an AMD chain as `ark.der` and `ask.der`; both
    /// must be present, and they are re-joined as the PEM the cache holds.
    fn legacy_chain(&self, key: &CollateralKey) -> Option<Vec<u8>> {
        let CollateralKey::SnpCertChain { generation } = key else {
            return None;
        };
        let dir = self.root.join("chain").join(generation.product_name());
        let ark = read_if_present(&dir.join("ark.der"))?;
        let ask = read_if_present(&dir.join("ask.der"))?;
        let mut out = pem::encode(&pem::Pem::new("CERTIFICATE", ask)).into_bytes();
        out.extend(pem::encode(&pem::Pem::new("CERTIFICATE", ark)).into_bytes());
        Some(out)
    }

    /// Failures are logged and swallowed: the store is a cache and must never
    /// be the reason a verification fails.
    pub fn put(&self, c: &Collateral) {
        let Some(base) = self.base_path(&c.key) else {
            return;
        };
        write_atomic(&base.with_extension(Self::ext(c.kind())), &c.bytes);
        let meta = Meta {
            fetched_at: c.fetched_at,
            signing_chain_pem: c
                .signing_chain
                .as_ref()
                .map(|b| String::from_utf8_lossy(b).into_owned()),
        };
        if let Ok(m) = serde_json::to_vec(&meta) {
            write_atomic(&base.with_extension("meta.json"), &m);
        }
    }
}

fn read_if_present(path: &Path) -> Option<Vec<u8>> {
    match fs::read(path) {
        Ok(bytes) if bytes.is_empty() => None,
        Ok(bytes) => Some(bytes),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => None,
        Err(e) => {
            log::warn!("collateral store read {} failed: {e}", path.display());
            None
        }
    }
}

/// Temp file plus rename, so a concurrent reader never observes a partial file.
fn write_atomic(path: &Path, bytes: &[u8]) {
    let Some(dir) = path.parent() else { return };
    if let Err(e) = fs::create_dir_all(dir) {
        log::warn!("collateral store mkdir {} failed: {e}", dir.display());
        return;
    }
    let seq = TMP_SEQ.fetch_add(1, Ordering::Relaxed);
    let tmp = dir.join(format!(".tmp.{}.{seq}", std::process::id()));
    let written = fs::File::create(&tmp).and_then(|mut f| {
        f.write_all(bytes)?;
        f.sync_all()
    });
    if let Err(e) = written {
        log::warn!("collateral store write {} failed: {e}", tmp.display());
        let _ = fs::remove_file(&tmp);
        return;
    }
    if let Err(e) = fs::rename(&tmp, path) {
        log::warn!("collateral store rename {} failed: {e}", path.display());
        let _ = fs::remove_file(&tmp);
    }
}
