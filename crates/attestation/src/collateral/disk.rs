//! Documents on disk: one file per document holding its key and the vendor
//! bytes as served, written to a temporary file and renamed into place.

use std::io::{Read, Write};
use std::path::PathBuf;

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use super::document::{DocKey, Raw};

/// Larger files are not read: a document is at most 5 MiB, base64 in JSON.
const MAX_FILE: u64 = 8 << 20;

pub(crate) struct Disk {
    dir: PathBuf,
}

#[derive(Serialize, Deserialize)]
struct Stored {
    key: DocKey,
    #[serde(flatten)]
    raw: Raw,
}

impl Disk {
    pub(crate) fn new(dir: impl Into<PathBuf>) -> Self {
        Self { dir: dir.into() }
    }

    fn path(&self, key: &DocKey) -> PathBuf {
        let name = hex::encode(Sha256::digest(
            serde_json::to_vec(key).expect("keys serialize"),
        ));
        self.dir.join(&name[..32]).with_extension("json")
    }

    /// The stored copy of `key`, unless it is missing, too large, or not a
    /// copy of `key`.
    pub(crate) fn read(&self, key: &DocKey) -> Option<Raw> {
        let mut bytes = Vec::new();
        std::fs::File::open(self.path(key))
            .ok()?
            .take(MAX_FILE + 1)
            .read_to_end(&mut bytes)
            .ok()?;
        match serde_json::from_slice::<Stored>(&bytes) {
            Ok(stored) if bytes.len() as u64 <= MAX_FILE && &stored.key == key => Some(stored.raw),
            _ => {
                log::warn!("collateral cache: ignoring a corrupt copy of {key}");
                None
            }
        }
    }

    pub(crate) fn write(&self, key: &DocKey, raw: &Raw) {
        if let Err(e) = self.try_write(key, raw) {
            log::warn!("collateral cache: could not store {key}: {e}");
        }
    }

    fn try_write(&self, key: &DocKey, raw: &Raw) -> std::io::Result<()> {
        let mut dir = std::fs::DirBuilder::new();
        dir.recursive(true);
        #[cfg(unix)]
        std::os::unix::fs::DirBuilderExt::mode(&mut dir, 0o700);
        dir.create(&self.dir)?;
        let bytes = serde_json::to_vec(&Stored {
            key: key.clone(),
            raw: raw.clone(),
        })?;
        // A named temporary file is created 0600.
        let mut tmp = tempfile::NamedTempFile::new_in(&self.dir)?;
        tmp.write_all(&bytes)?;
        tmp.as_file().sync_all()?;
        tmp.persist(self.path(key)).map_err(|e| e.error)?;
        Ok(())
    }
}
