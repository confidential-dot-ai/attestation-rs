//! Collateral on disk: one file per vendor URL holding the URL and the
//! vendor response as served, written to a temporary file and renamed into
//! place.

use std::io::{Read, Write};
use std::path::PathBuf;

use base64::{engine::general_purpose::STANDARD as BASE64, Engine};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

/// Larger files are not read: a response is at most 5 MiB, base64 in JSON.
const MAX_FILE: u64 = 8 << 20;

pub(crate) struct Disk {
    dir: PathBuf,
}

#[derive(Serialize, Deserialize)]
struct Stored {
    url: String,
    /// Base64.
    body: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    issuer_chain: Option<String>,
}

impl Disk {
    pub(crate) fn new(dir: impl Into<PathBuf>) -> Self {
        Self { dir: dir.into() }
    }

    fn path(&self, url: &str) -> PathBuf {
        let name = hex::encode(Sha256::digest(url));
        self.dir.join(&name[..32]).with_extension("json")
    }

    /// The stored response for `url` and its issuer chain, unless missing,
    /// too large, or not for `url`.
    pub(crate) fn read(&self, url: &str) -> Option<(Vec<u8>, Option<String>)> {
        let mut bytes = Vec::new();
        std::fs::File::open(self.path(url))
            .ok()?
            .take(MAX_FILE + 1)
            .read_to_end(&mut bytes)
            .ok()?;
        let stored = serde_json::from_slice::<Stored>(&bytes)
            .ok()
            .filter(|s| bytes.len() as u64 <= MAX_FILE && s.url == url)
            .and_then(|s| Some((BASE64.decode(s.body).ok()?, s.issuer_chain)));
        if stored.is_none() {
            log::warn!("collateral cache: ignoring a corrupt copy of {url}");
        }
        stored
    }

    pub(crate) fn write(&self, url: &str, body: &[u8], issuer_chain: Option<&str>) {
        if let Err(e) = self.try_write(url, body, issuer_chain) {
            log::warn!("collateral cache: could not store {url}: {e}");
        }
    }

    fn try_write(&self, url: &str, body: &[u8], issuer_chain: Option<&str>) -> std::io::Result<()> {
        let mut dir = std::fs::DirBuilder::new();
        dir.recursive(true);
        #[cfg(unix)]
        std::os::unix::fs::DirBuilderExt::mode(&mut dir, 0o700);
        dir.create(&self.dir)?;
        let bytes = serde_json::to_vec(&Stored {
            url: url.to_string(),
            body: BASE64.encode(body),
            issuer_chain: issuer_chain.map(str::to_string),
        })?;
        // A named temporary file is created 0600.
        let mut tmp = tempfile::NamedTempFile::new_in(&self.dir)?;
        tmp.write_all(&bytes)?;
        tmp.as_file().sync_all()?;
        tmp.persist(self.path(url)).map_err(|e| e.error)?;
        Ok(())
    }
}
