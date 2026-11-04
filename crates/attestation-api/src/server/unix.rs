//! Unix socket listener.
//!
//! `bind` followed by `chmod` leaves a window in which the socket accepts
//! connections under the umask-derived mode, and std offers no way to bind
//! without listening or to set the umask. So the socket is bound inside a
//! fresh 0700 directory next to the target, gets its mode and group there,
//! and is then renamed into place. Nobody but the process owner (and root)
//! can traverse that directory, and the rename atomically replaces a stale
//! socket.

use std::fs::{self, DirBuilder};
use std::io;
use std::os::unix::fs::{chown, DirBuilderExt, FileTypeExt, MetadataExt, PermissionsExt};
use std::path::{Path, PathBuf};

use tokio::net::UnixListener;

/// The socket file of a bound listener. Dropping it removes the file, unless
/// something else has replaced it since.
pub struct SocketFile {
    path: PathBuf,
    id: (u64, u64),
}

impl Drop for SocketFile {
    fn drop(&mut self) {
        if let Ok(meta) = fs::symlink_metadata(&self.path) {
            if (meta.dev(), meta.ino()) == self.id {
                if let Err(e) = fs::remove_file(&self.path) {
                    tracing::warn!(path = %self.path.display(), error = %e, "removing socket file");
                }
            }
        }
    }
}

/// Removes the private bind directory and whatever is still in it.
struct BindDir(PathBuf);

impl Drop for BindDir {
    fn drop(&mut self) {
        // Best effort: a leftover hidden directory is harmless.
        let _ = fs::remove_dir_all(&self.0);
    }
}

/// Bind a listening socket at `path` with `mode`, chgrp'd to `group` when
/// set. A stale socket at `path` is replaced; anything else there is an
/// error. The parent directory must exist.
pub fn bind(path: &Path, mode: u32, group: Option<u32>) -> io::Result<(UnixListener, SocketFile)> {
    let context = |what: &str, e: io::Error| {
        io::Error::new(e.kind(), format!("{what} {}: {e}", path.display()))
    };
    let parent = path
        .parent()
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "socket path has no parent"))?;
    let suffix = uuid::Uuid::new_v4().simple().to_string();
    let dir = BindDir(parent.join(format!(".sock-{}", &suffix[..12])));
    DirBuilder::new()
        .mode(0o700)
        .create(&dir.0)
        .map_err(|e| context("creating bind directory for", e))?;

    let staged = dir.0.join("s");
    debug_assert!(
        staged.as_os_str().len() <= parent.as_os_str().len() + crate::config::STAGED_SUFFIX_LEN
    );
    let listener = UnixListener::bind(&staged).map_err(|e| context("binding", e))?;
    fs::set_permissions(&staged, fs::Permissions::from_mode(mode))
        .map_err(|e| context("chmod", e))?;
    if let Some(gid) = group {
        chown(&staged, None, Some(gid)).map_err(|e| context(&format!("chgrp {gid}"), e))?;
    }

    match fs::symlink_metadata(path) {
        Ok(meta) if !meta.file_type().is_socket() => {
            return Err(io::Error::new(
                io::ErrorKind::AlreadyExists,
                format!(
                    "{} exists and is not a socket; refusing to replace it",
                    path.display()
                ),
            ));
        }
        Ok(_) => {}
        Err(e) if e.kind() == io::ErrorKind::NotFound => {}
        Err(e) => return Err(context("inspecting", e)),
    }
    fs::rename(&staged, path).map_err(|e| context("moving socket to", e))?;
    let meta = fs::symlink_metadata(path).map_err(|e| context("inspecting", e))?;
    let file = SocketFile {
        path: path.to_path_buf(),
        id: (meta.dev(), meta.ino()),
    };
    Ok((listener, file))
}
