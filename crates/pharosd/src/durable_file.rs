//! Small, fail-closed durable JSON-file primitives used by Pharos stores.

use std::fmt;
use std::fs::{self, File, OpenOptions};
use std::io::{self, Write};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

use serde::de::DeserializeOwned;
use serde::Serialize;

static TEMP_SEQUENCE: AtomicU64 = AtomicU64::new(1);

#[derive(Debug)]
pub(crate) enum DurableFileError {
    Read(io::Error),
    Decode(serde_json::Error),
    Encode(serde_json::Error),
    CreateDirectory(io::Error),
    CreateTemporary(io::Error),
    Write(io::Error),
    Flush(io::Error),
    SyncFile(io::Error),
    Rename(io::Error),
    SyncDirectory(io::Error),
}

impl fmt::Display for DurableFileError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let (stage, detail): (&str, &dyn fmt::Display) = match self {
            Self::Read(error) => ("read", error),
            Self::Decode(error) => ("decode", error),
            Self::Encode(error) => ("encode", error),
            Self::CreateDirectory(error) => ("create parent directory", error),
            Self::CreateTemporary(error) => ("create temporary file", error),
            Self::Write(error) => ("write", error),
            Self::Flush(error) => ("flush", error),
            Self::SyncFile(error) => ("sync file", error),
            Self::Rename(error) => ("atomic rename", error),
            Self::SyncDirectory(error) => ("sync parent directory", error),
        };
        write!(formatter, "durable file {stage} failed: {detail}")
    }
}

impl std::error::Error for DurableFileError {}

impl DurableFileError {
    /// The final rename completed, but durability of the directory entry could
    /// not be confirmed. Callers must return an error while keeping memory
    /// aligned with the final file that is already visible.
    pub(crate) fn final_file_replaced(&self) -> bool {
        matches!(self, Self::SyncDirectory(_))
    }
}

pub(crate) fn load_optional_json<T: DeserializeOwned>(
    path: &Path,
) -> Result<Option<T>, DurableFileError> {
    let bytes = match fs::read(path) {
        Ok(bytes) => bytes,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(None),
        Err(error) => return Err(DurableFileError::Read(error)),
    };
    serde_json::from_slice(&bytes)
        .map(Some)
        .map_err(DurableFileError::Decode)
}

pub(crate) fn atomic_write_json<T: Serialize>(
    path: &Path,
    value: &T,
) -> Result<(), DurableFileError> {
    let encoded = serde_json::to_vec_pretty(value).map_err(DurableFileError::Encode)?;
    atomic_write(path, &encoded)
}

fn atomic_write(path: &Path, contents: &[u8]) -> Result<(), DurableFileError> {
    let parent = path.parent().unwrap_or_else(|| Path::new("."));
    fs::create_dir_all(parent).map_err(DurableFileError::CreateDirectory)?;
    let temporary = create_temporary_path(path);
    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }

    let result = (|| {
        let mut file = options
            .open(&temporary)
            .map_err(DurableFileError::CreateTemporary)?;
        file.write_all(contents).map_err(DurableFileError::Write)?;
        file.flush().map_err(DurableFileError::Flush)?;
        file.sync_all().map_err(DurableFileError::SyncFile)?;
        fs::rename(&temporary, path).map_err(DurableFileError::Rename)?;
        sync_directory(parent)
    })();

    if result.is_err() {
        let _ = fs::remove_file(&temporary);
    }
    result
}

fn create_temporary_path(path: &Path) -> PathBuf {
    let sequence = TEMP_SEQUENCE.fetch_add(1, Ordering::Relaxed);
    let nonce = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|duration| duration.as_nanos())
        .unwrap_or_default();
    let name = path
        .file_name()
        .and_then(|name| name.to_str())
        .unwrap_or("pharos-state");
    path.with_file_name(format!(
        ".{name}.tmp-{}-{nonce}-{sequence}",
        std::process::id()
    ))
}

fn sync_directory(path: &Path) -> Result<(), DurableFileError> {
    File::open(path)
        .and_then(|directory| directory.sync_all())
        .map_err(DurableFileError::SyncDirectory)
}
