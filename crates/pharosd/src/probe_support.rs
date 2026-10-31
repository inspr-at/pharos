//! Helpers shared by the beaconless probe modules: trusted runtime file reads and
//! host name validation.

use std::fs;
use std::io::Read;
use std::path::Path;

#[cfg(unix)]
use std::os::unix::fs::{MetadataExt, OpenOptionsExt};

use pharos_core::ServiceObservationState;
use serde::Serialize;

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub(super) struct ServerProbeObservation {
    pub(super) id: String,
    pub(super) service: String,
    pub(super) source: &'static str,
    pub(super) policy: &'static str,
    pub(super) kind: &'static str,
    pub(super) target: Option<String>,
    pub(super) state: ServiceObservationState,
    pub(super) server_reachable: Option<bool>,
    pub(super) client_reachable: Option<bool>,
    pub(super) summary: String,
    pub(super) checked_at: i64,
}

pub(super) fn open_trusted_runtime_file(
    path: &Path,
    maximum_bytes: u64,
    forbidden_mode: u32,
    executable: bool,
) -> Option<fs::File> {
    let path_metadata = fs::symlink_metadata(path).ok()?;
    if path_metadata.file_type().is_symlink()
        || !path_metadata.is_file()
        || path_metadata.len() == 0
        || path_metadata.len() > maximum_bytes
    {
        return None;
    }
    let mut options = fs::OpenOptions::new();
    options.read(true);
    #[cfg(unix)]
    options.custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC);
    let file = options.open(path).ok()?;
    let opened_metadata = file.metadata().ok()?;
    if !opened_metadata.is_file()
        || opened_metadata.len() == 0
        || opened_metadata.len() > maximum_bytes
    {
        return None;
    }
    #[cfg(unix)]
    {
        let effective_uid = unsafe { libc::geteuid() };
        if !trusted_runtime_owner_and_mode(
            opened_metadata.uid(),
            opened_metadata.mode(),
            effective_uid,
            forbidden_mode,
            executable,
        ) || opened_metadata.dev() != path_metadata.dev()
            || opened_metadata.ino() != path_metadata.ino()
        {
            return None;
        }
    }
    Some(file)
}

#[cfg(unix)]
pub(super) fn trusted_runtime_owner_and_mode(
    owner_uid: u32,
    mode: u32,
    effective_uid: u32,
    forbidden_mode: u32,
    executable: bool,
) -> bool {
    (owner_uid == 0 || owner_uid == effective_uid)
        && mode & (forbidden_mode | 0o7000) == 0
        && (!executable || mode & 0o111 != 0)
}

pub(super) fn read_trusted_runtime_file(
    path: &Path,
    maximum_bytes: u64,
    forbidden_mode: u32,
    executable: bool,
) -> Option<Vec<u8>> {
    let mut file = open_trusted_runtime_file(path, maximum_bytes, forbidden_mode, executable)?;
    let mut bytes = Vec::with_capacity(usize::try_from(maximum_bytes.min(1024 * 1024)).ok()?);
    std::io::Read::by_ref(&mut file)
        .take(maximum_bytes.saturating_add(1))
        .read_to_end(&mut bytes)
        .ok()?;
    (u64::try_from(bytes.len()).ok()? <= maximum_bytes).then_some(bytes)
}

pub(super) fn valid_bootstrap_name(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 128
        && value
            .chars()
            .next()
            .is_some_and(|ch| ch.is_ascii_alphanumeric())
        && value
            .chars()
            .all(|ch| ch.is_ascii_alphanumeric() || matches!(ch, '.' | '_' | '-'))
}

pub(super) fn valid_ssh_endpoint(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 253
        && value
            .chars()
            .next()
            .is_some_and(|ch| ch.is_ascii_alphanumeric())
        && value
            .chars()
            .all(|ch| ch.is_ascii_alphanumeric() || matches!(ch, '.' | '_' | '-'))
}
