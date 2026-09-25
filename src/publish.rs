//! Local no-clobber publication. No networking or automatic repository mutation.
use crate::{Error, ErrorCode, Result};
use std::fs::{self, File, OpenOptions};
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
static SERIAL: AtomicU64 = AtomicU64::new(0);

pub fn read_bounded(path: &Path, limit: usize) -> Result<Vec<u8>> {
    let file = File::open(path)?;
    let cap = limit
        .checked_add(1)
        .ok_or_else(|| Error::limit("input_bytes"))?;
    let mut data = Vec::new();
    file.take(cap as u64).read_to_end(&mut data)?;
    if data.len() > limit {
        return Err(Error::limit("input_bytes"));
    }
    Ok(data)
}
#[derive(Debug)]
pub struct Publication {
    pub file_synced: bool,
    pub directory_synced: bool,
}
struct Temporary(PathBuf, bool);
impl Drop for Temporary {
    fn drop(&mut self) {
        if self.1 {
            let _ = fs::remove_file(&self.0);
        }
    }
}

/// Requires a trusted, stable parent directory on a filesystem supporting hard
/// links. A competing existing destination wins; it is never overwritten.
/// A failure after the link commit explicitly says the output was committed.
pub fn write_new(path: &Path, bytes: &[u8]) -> Result<Publication> {
    let parent = path
        .parent()
        .filter(|p| !p.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."));
    let parent = parent.canonicalize()?;
    let name = path
        .file_name()
        .ok_or_else(|| Error::new(ErrorCode::Usage, 0, "output", "output must name a file"))?;
    let destination = parent.join(name);
    match fs::symlink_metadata(&destination) {
        Ok(_) => {
            return Err(Error::new(
                ErrorCode::OutputExists,
                0,
                "output",
                "refusing to replace an existing file or link",
            ))
        }
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
        Err(e) => return Err(e.into()),
    }
    let mut opened = None;
    for _ in 0..16 {
        let serial = SERIAL.fetch_add(1, Ordering::Relaxed);
        let candidate = parent.join(format!(
            ".pcap-evidence-{}-{serial}.partial",
            std::process::id()
        ));
        let mut options = OpenOptions::new();
        options.write(true).create_new(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.mode(0o600);
        }
        match options.open(&candidate) {
            Ok(file) => {
                opened = Some((Temporary(candidate, true), file));
                break;
            }
            Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => continue,
            Err(e) => return Err(e.into()),
        }
    }
    let (mut temporary, mut file) = opened.ok_or_else(|| {
        Error::new(
            ErrorCode::Io,
            0,
            "output",
            "temporary-name budget exhausted",
        )
    })?;
    file.write_all(bytes)?;
    file.sync_all()?;
    drop(file);
    // Hard-link creation is the atomic commit/no-replace operation. No unsafe
    // rename fallback on filesystems where that guarantee is unavailable.
    if let Err(e) = fs::hard_link(&temporary.0, &destination) {
        return Err(if e.kind() == std::io::ErrorKind::AlreadyExists {
            Error::new(
                ErrorCode::OutputExists,
                0,
                "output",
                "another writer already published the destination",
            )
        } else {
            Error::io(e)
        });
    }
    fs::remove_file(&temporary.0).map_err(|e| {
        Error::new(
            ErrorCode::Io,
            0,
            "output_committed",
            format!("output committed; temporary cleanup failed: {e}"),
        )
    })?;
    temporary.1 = false;
    #[cfg(unix)]
    {
        File::open(&parent)
            .and_then(|file| file.sync_all())
            .map_err(|e| {
                Error::new(
                    ErrorCode::Io,
                    0,
                    "output_committed",
                    format!("output committed; directory durability unconfirmed: {e}"),
                )
            })?;
        Ok(Publication {
            file_synced: true,
            directory_synced: true,
        })
    }
    #[cfg(not(unix))]
    {
        Ok(Publication {
            file_synced: true,
            directory_synced: false,
        })
    }
}
