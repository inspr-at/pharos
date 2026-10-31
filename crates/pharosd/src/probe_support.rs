//! Helpers shared by the beaconless probe modules: trusted runtime file reads,
//! host and SSH name validation, and bounded child processes.

use std::fs;
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::{Duration, Instant};

#[cfg(unix)]
use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
#[cfg(unix)]
use std::os::unix::process::CommandExt;

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

/// SSH identity for the read-only convergence marker probe. Both files are
/// operator-provided; without them the marker reads as unavailable.
#[derive(Clone, Debug, Default)]
pub(super) struct ProbeSshConfig {
    pub(super) identity_file: Option<PathBuf>,
    pub(super) known_hosts_file: Option<PathBuf>,
}

impl ProbeSshConfig {
    pub(super) fn from_env() -> Self {
        let path = |name: &str| {
            std::env::var(name)
                .ok()
                .map(|value| value.trim().to_string())
                .filter(|value| !value.is_empty())
                .map(PathBuf::from)
        };
        Self {
            identity_file: path("PHAROS_EXISTING_HOST_IDENTITY_FILE"),
            known_hosts_file: path("PHAROS_EXISTING_HOST_KNOWN_HOSTS_FILE"),
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum ChildRunError {
    Failed,
    TimedOut,
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

pub(super) fn valid_ssh_user(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 64
        && value
            .chars()
            .next()
            .is_some_and(|ch| ch.is_ascii_alphanumeric() || ch == '_')
        && value
            .chars()
            .all(|ch| ch.is_ascii_alphanumeric() || matches!(ch, '.' | '_' | '-'))
}

pub(super) fn run_child_with_deadline(
    command: &mut Command,
    stdin: Option<&[u8]>,
    total_timeout: Duration,
    maximum_stdout: usize,
) -> Result<Vec<u8>, ChildRunError> {
    #[cfg(unix)]
    command.process_group(0);
    let started = Instant::now();
    let mut child = command.spawn().map_err(|_| ChildRunError::Failed)?;

    let (stdout_sender, stdout_receiver) = std::sync::mpsc::sync_channel(1);
    let Some(mut stdout) = child.stdout.take() else {
        terminate_child_process_group(&mut child);
        return Err(ChildRunError::Failed);
    };
    std::thread::spawn(move || {
        let mut retained = Vec::with_capacity(maximum_stdout.min(4096));
        let mut oversized = false;
        let mut buffer = [0_u8; 4096];
        let result = loop {
            match stdout.read(&mut buffer) {
                Ok(0) => break Ok((retained, oversized)),
                Ok(read) => {
                    let remaining = maximum_stdout.saturating_sub(retained.len());
                    retained.extend_from_slice(&buffer[..read.min(remaining)]);
                    if read > remaining {
                        oversized = true;
                    }
                }
                Err(_) => break Err(()),
            }
        };
        let _ = stdout_sender.send(result);
    });

    let stdin_receiver = stdin.map(|input| {
        let (sender, receiver) = std::sync::mpsc::sync_channel(1);
        let mut child_stdin = child.stdin.take();
        let input = input.to_vec();
        std::thread::spawn(move || {
            let result = child_stdin
                .as_mut()
                .ok_or(())
                .and_then(|stream| stream.write_all(&input).map_err(|_| ()));
            let _ = sender.send(result);
        });
        receiver
    });

    let status = loop {
        match child.try_wait() {
            Ok(Some(status)) => break status,
            Ok(None) if started.elapsed() < total_timeout => {
                std::thread::sleep(Duration::from_millis(20));
            }
            Ok(None) => {
                terminate_child_process_group(&mut child);
                return Err(ChildRunError::TimedOut);
            }
            Err(_) => {
                terminate_child_process_group(&mut child);
                return Err(ChildRunError::Failed);
            }
        }
    };

    let remaining = total_timeout.saturating_sub(started.elapsed());
    let stdout = match stdout_receiver.recv_timeout(remaining) {
        Ok(Ok((stdout, false))) => stdout,
        Ok(Ok((_, true))) | Ok(Err(())) => {
            terminate_child_process_group(&mut child);
            return Err(ChildRunError::Failed);
        }
        Err(_) => {
            terminate_child_process_group(&mut child);
            return Err(ChildRunError::TimedOut);
        }
    };
    if let Some(receiver) = stdin_receiver {
        let remaining = total_timeout.saturating_sub(started.elapsed());
        match receiver.recv_timeout(remaining) {
            Ok(Ok(())) => {}
            Ok(Err(())) => {
                terminate_child_process_group(&mut child);
                return Err(ChildRunError::Failed);
            }
            Err(_) => {
                terminate_child_process_group(&mut child);
                return Err(ChildRunError::TimedOut);
            }
        }
    }
    if !status.success() {
        return Err(ChildRunError::Failed);
    }
    Ok(stdout)
}

pub(super) fn terminate_child_process_group(child: &mut std::process::Child) {
    #[cfg(unix)]
    if let Ok(pid) = i32::try_from(child.id()) {
        unsafe {
            libc::kill(-pid, libc::SIGKILL);
        }
    }
    let _ = child.kill();
    let _ = child.wait();
}
