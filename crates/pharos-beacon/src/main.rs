//! pharos-beacon — per-host agent (PHAROS-6 / PHAROS-15).
//!
//! Computes this host's Nix freshness (flake.lock age + commits behind nixcfg)
//! and reports it to pharosd. With PHAROS_INTERVAL set it loops as a recurring
//! service; otherwise it reports once and exits. Token auth via Janus is
//! PHAROS-8; the native (musl) Nix-module deployment is PHAROS-6/7.
//!
//! Env: PHAROS_URL (required pharosd base),
//!      PHAROS_INTERVAL (secs; loop if set), NIXCFG_DIR (flake checkout;
//!      auto-detected otherwise), PHAROS_HOSTNAME / PHAROS_ROLE (overrides),
//!      PHAROS_NIX_DEPLOYMENT_EVIDENCE_FILE (active-generation evidence),
//!      PHAROS_NIXCFG_REMOTE_URL / PHAROS_NIXCFG_REMOTE_REF (authoritative Git),
//!      PHAROS_NIXPKGS_CHANNEL_BASE_URL (authoritative channel publication),
//!      PHAROS_NIXPKGS_REMOTE_URL (legacy/custom authoritative Git fallback),
//!      PHAROS_TOKEN / PHAROS_TOKEN_FILE (per-host bearer token from /register),
//!      PHAROS_BACKUP_MODE (auto/off/restic/status-file/command).

use std::fs::{File, OpenOptions};
use std::io::{Read, Write};
#[cfg(unix)]
use std::os::unix::fs::OpenOptionsExt;
#[cfg(all(unix, test))]
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::{Command, ExitStatus, Stdio};
use std::sync::mpsc;
use std::thread;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use pharos_core::{
    BackupConfiguredState, BackupEngine, BackupObservation, BackupPostureState, BackupRunState,
    GitRevisionRelation, HostLocation, HostLocationSource, HostPreferences,
    HostPreferencesRegistry, HostReport, HostReportResponse, KernelPosture, NixDeploymentEvidence,
    NixFreshness, NixcfgGitComparison, NixpkgsGitComparison, NixpkgsInputFreshness,
    NixpkgsRevisionRelation, ServiceObservation, ServiceObservationState, HOST_REPORT_SCHEMA,
    HOST_REPORT_VERSION, MAX_HEARTBEAT_INTERVAL_SECS, MAX_INBOUND_RTT_MS,
    MIN_HEARTBEAT_INTERVAL_SECS,
};
use sha2::{Digest, Sha256};
use url::Url;

const MAX_REPORT_RESPONSE_BYTES: u64 = 64 * 1024;
const LOCATION_COMMAND_OUTPUT_LIMIT_BYTES: usize = 64 * 1024;
const GIT_COMPARISON_TIMEOUT: Duration = Duration::from_secs(12);
const NIXPKGS_CHANNEL_TIMEOUT: Duration = Duration::from_secs(12);
const MAX_NIXPKGS_REVISION_BYTES: u64 = 128;
const DEFAULT_NIXPKGS_CHANNEL_BASE_URL: &str = "https://channels.nixos.org/";
const OFFICIAL_NIXPKGS_GIT_REMOTE: &str = "https://github.com/NixOS/nixpkgs.git";
const MAX_DEPLOYMENT_EVIDENCE_BYTES: u64 = 4 * 1024;
const MAX_FLAKE_LOCK_BYTES: u64 = 8 * 1024 * 1024;
const BEACON_HEALTH_PATH: &str = "/tmp/pharos-beacon-health-v1";
const BEACON_HEALTH_PATH_ENV: &str = "PHAROS_BEACON_HEALTH_FILE";
const BEACON_HEALTH_STALE_INTERVALS: u64 = 3;

#[derive(Debug, Clone, PartialEq, Eq)]
struct ReportEndpoint {
    request_url: String,
    safe_origin: String,
}

fn report_endpoint(raw: &str) -> Result<ReportEndpoint, &'static str> {
    let mut base = Url::parse(raw.trim()).map_err(|_| "invalid_url")?;
    if !matches!(base.scheme(), "http" | "https")
        || base.host_str().is_none()
        || !base.username().is_empty()
        || base.password().is_some()
        || base.query().is_some()
        || base.fragment().is_some()
    {
        return Err("unsafe_url");
    }
    if !base.path().ends_with('/') {
        let mut path = base.path().to_string();
        path.push('/');
        base.set_path(&path);
    }
    let endpoint = base.join("report").map_err(|_| "invalid_url")?;
    Ok(ReportEndpoint {
        request_url: endpoint.as_str().to_string(),
        safe_origin: endpoint.origin().ascii_serialization(),
    })
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct RequestDeadlines {
    connect: Duration,
    read: Duration,
    write: Duration,
    overall: Duration,
}

impl RequestDeadlines {
    fn for_cadence(cadence_secs: u64) -> Result<Self, &'static str> {
        if !(MIN_HEARTBEAT_INTERVAL_SECS..=MAX_HEARTBEAT_INTERVAL_SECS).contains(&cadence_secs) {
            return Err("invalid_cadence");
        }
        let overall_secs = cadence_secs.saturating_sub(1).min(15);
        Ok(Self {
            connect: Duration::from_secs(overall_secs.min(5)),
            read: Duration::from_secs(overall_secs.min(10)),
            write: Duration::from_secs(overall_secs.min(10)),
            overall: Duration::from_secs(overall_secs),
        })
    }

    fn agent(self) -> ureq::Agent {
        ureq::Agent::config_builder()
            .timeout_connect(Some(self.connect))
            .timeout_send_request(Some(self.write))
            .timeout_send_body(Some(self.write))
            .timeout_recv_response(Some(self.read))
            .timeout_recv_body(Some(self.read))
            .timeout_global(Some(self.overall))
            .max_redirects(0)
            .build()
            .into()
    }
}

fn retry_delay(cadence_secs: u64, consecutive_failures: u32, jitter_seed: u64) -> Duration {
    let exponent = consecutive_failures.saturating_sub(1).min(6);
    let base_millis = 1_000_u64
        .saturating_mul(1_u64 << exponent)
        .min(cadence_secs.saturating_mul(500).max(1_000));
    let jitter_window = (base_millis / 2).max(1);
    let cap_millis = cadence_secs.saturating_mul(1_000).saturating_sub(1);
    Duration::from_millis(
        base_millis
            .saturating_add(jitter_seed % jitter_window)
            .min(cap_millis),
    )
}

fn jitter_seed() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_nanos() as u64)
        .unwrap_or(0)
        ^ u64::from(std::process::id())
}

#[cfg(target_os = "linux")]
fn systemd_notify(message: &str) {
    use std::os::linux::net::SocketAddrExt;
    use std::os::unix::net::{SocketAddr, UnixDatagram};

    let Some(socket_name) = std::env::var_os("NOTIFY_SOCKET") else {
        return;
    };
    let socket_name = socket_name.as_encoded_bytes();
    let Ok(socket) = UnixDatagram::unbound() else {
        return;
    };
    if let Some(abstract_name) = socket_name.strip_prefix(b"@") {
        if let Ok(address) = SocketAddr::from_abstract_name(abstract_name) {
            let _ = socket.send_to_addr(message.as_bytes(), &address);
        }
    } else if let Ok(path) = std::str::from_utf8(socket_name) {
        let _ = socket.send_to(message.as_bytes(), path);
    }
}

#[cfg(not(target_os = "linux"))]
fn systemd_notify(_message: &str) {}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum PreferencesApplyError {
    InvalidResponse,
    HostMismatch,
    NotConfigured,
    UnsupportedOnNix,
    WriteFailed,
}

impl PreferencesApplyError {
    fn code(self) -> &'static str {
        match self {
            Self::InvalidResponse => "invalid_response",
            Self::HostMismatch => "host_mismatch",
            Self::NotConfigured => "preferences_file_not_configured",
            Self::UnsupportedOnNix => "nix_host_uses_declarative_delivery",
            Self::WriteFailed => "atomic_write_failed",
        }
    }

    fn observation(self) -> ServiceObservation {
        ServiceObservation {
            id: "host-preferences".to_string(),
            label: "Host settings".to_string(),
            state: ServiceObservationState::Warning,
            summary: format!("settings apply failed: {}", self.code()),
        }
    }
}

fn now_unix() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| i64::try_from(d.as_secs()).unwrap_or(i64::MAX))
        .unwrap_or(0)
}

/// A hidden sibling of the marker, `.<marker>.<suffix>`, in the marker's own
/// directory so that renaming it over the marker stays on one filesystem.
fn beacon_health_sibling_path(path: &Path, suffix: &str) -> std::io::Result<PathBuf> {
    let parent = path.parent().ok_or_else(|| {
        std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "health path has no parent",
        )
    })?;
    let file_name = path
        .file_name()
        .and_then(|name| name.to_str())
        .ok_or_else(|| {
            std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "health path has no file name",
            )
        })?;
    Ok(parent.join(format!(".{file_name}.{suffix}")))
}

/// Sibling names are fixed, never unique per process or moment: a run that
/// is killed midway (the container healthcheck timeout, a beacon restart)
/// leaves at most one file per name, and the next run removes it before it
/// starts. Unique names would let such leftovers pile up without bound.
const BEACON_HEALTH_WRITE_TEMP: &str = "tmp";
const BEACON_HEALTH_PROBE_TEMP: &str = "probe-tmp";
const BEACON_HEALTH_PROBE_LINK: &str = "probe-link";
/// Lock shared by the beacon's marker writes and the container probe, so a
/// probe never recovers or replaces anything while a refresh is in flight.
/// It is the one artifact that stays: removing a lock file races its users.
const BEACON_HEALTH_LOCK: &str = "lock";
const BEACON_HEALTH_LOCK_WAIT: Duration = Duration::from_secs(2);
const MAX_BEACON_HEALTH_MARKER_BYTES: u64 = 256;

/// Identity of the beacon process that wrote a marker: its pid plus the
/// kernel's start token for that pid (Linux: boot id and start time in ticks
/// from `/proc/<pid>/stat`; macOS: the BSD process start time). A marker is
/// only ever trusted while that exact process is still running, so state left
/// by a previous run can never become healthy merely because an obstacle to
/// resetting it clears; only a successful report by the current process can
/// restore health (PHAROS-203).
#[derive(Debug, Clone, PartialEq, Eq)]
struct ProcessGeneration {
    pid: u32,
    start: String,
}

impl ProcessGeneration {
    fn current() -> std::io::Result<Self> {
        Self::for_pid(std::process::id())
    }

    fn for_pid(pid: u32) -> std::io::Result<Self> {
        Ok(Self {
            pid,
            start: process_start_token(pid)?,
        })
    }

    /// Whether the process this generation names is still the same process.
    fn is_running(&self) -> Result<(), String> {
        match process_start_token(self.pid) {
            Ok(start) if start == self.start => Ok(()),
            Ok(_) => Err(format!(
                "pid {} now belongs to a different process",
                self.pid
            )),
            Err(err) => Err(format!("pid {} is not running: {err}", self.pid)),
        }
    }
}

/// Whether `boot_id` is exactly what the kernel writes to
/// `/proc/sys/kernel/random/boot_id` (after the trailing newline is
/// trimmed): a canonical UUID of 8-4-4-4-12 hex digits with hyphens at
/// positions 8, 13, 18 and 23 and nothing else. The kernel formats it with
/// `%pU`, which only ever emits lowercase hex, so uppercase is rejected:
/// anything else did not come from the kernel.
#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
fn is_canonical_boot_id(boot_id: &str) -> bool {
    boot_id.len() == 36
        && boot_id
            .bytes()
            .enumerate()
            .all(|(index, byte)| match index {
                8 | 13 | 18 | 23 => byte == b'-',
                _ => byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte),
            })
}

/// Builds the Linux start token `<boot_id>:<starttime ticks>` from the raw
/// `/proc/<pid>/stat` line and the boot id read. The boot id is mandatory
/// and must be canonical: pid plus boot-relative ticks can repeat across
/// reboots, so an unreadable, empty or malformed boot id fails closed
/// instead of falling back to ticks alone.
#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
fn linux_start_token(stat: &str, boot_id: std::io::Result<String>) -> std::io::Result<String> {
    let invalid =
        |what: &str| std::io::Error::new(std::io::ErrorKind::InvalidData, what.to_string());
    let boot_id = boot_id?;
    let boot_id = boot_id.strip_suffix('\n').unwrap_or(&boot_id);
    if !is_canonical_boot_id(boot_id) {
        return Err(invalid("boot id is not a canonical lowercase UUID"));
    }
    // The command name is parenthesised and may contain spaces; fields after
    // it start with the state. starttime is field 22 overall.
    let after_comm = stat
        .rsplit_once(')')
        .map(|(_, rest)| rest)
        .ok_or_else(|| invalid("malformed stat"))?;
    let start_ticks = after_comm
        .split_ascii_whitespace()
        .nth(19)
        .filter(|ticks| ticks.bytes().all(|byte| byte.is_ascii_digit()))
        .ok_or_else(|| invalid("short or malformed stat"))?;
    Ok(format!("{boot_id}:{start_ticks}"))
}

#[cfg(target_os = "linux")]
fn process_start_token(pid: u32) -> std::io::Result<String> {
    let stat = std::fs::read_to_string(format!("/proc/{pid}/stat"))?;
    linux_start_token(
        &stat,
        std::fs::read_to_string("/proc/sys/kernel/random/boot_id"),
    )
}

#[cfg(target_os = "macos")]
fn process_start_token(pid: u32) -> std::io::Result<String> {
    let pid = i32::try_from(pid)
        .map_err(|_| std::io::Error::new(std::io::ErrorKind::InvalidInput, "pid out of range"))?;
    let mut info: libc::proc_bsdinfo = unsafe { std::mem::zeroed() };
    let size = std::mem::size_of::<libc::proc_bsdinfo>() as libc::c_int;
    // SAFETY: proc_pidinfo writes at most `size` bytes into `info`, a
    // correctly sized and aligned proc_bsdinfo, and returns the byte count.
    let written = unsafe {
        libc::proc_pidinfo(
            pid,
            libc::PROC_PIDTBSDINFO,
            0,
            (&mut info as *mut libc::proc_bsdinfo).cast(),
            size,
        )
    };
    if written != size {
        return Err(std::io::Error::last_os_error());
    }
    Ok(format!(
        "{}.{:06}",
        info.pbi_start_tvsec, info.pbi_start_tvusec
    ))
}

#[cfg(not(any(target_os = "linux", target_os = "macos")))]
fn process_start_token(_pid: u32) -> std::io::Result<String> {
    Err(std::io::Error::new(
        std::io::ErrorKind::Unsupported,
        "process start time is not available on this platform",
    ))
}

/// Takes the marker lock, waiting a bounded time for a concurrent writer or
/// probe. The lock file is opened without following symlinks; an immutable
/// or read-only lock file still locks, so only a missing or non-regular lock
/// path fails.
fn lock_beacon_health(path: &Path) -> Result<File, String> {
    lock_beacon_health_within(path, BEACON_HEALTH_LOCK_WAIT)
}

fn lock_beacon_health_within(path: &Path, wait: Duration) -> Result<File, String> {
    let lock_path =
        beacon_health_sibling_path(path, BEACON_HEALTH_LOCK).map_err(|err| err.to_string())?;
    let mut options = OpenOptions::new();
    options.read(true).write(true).create(true).truncate(false);
    #[cfg(unix)]
    options.mode(0o600).custom_flags(libc::O_NOFOLLOW);
    let file = match options.open(&lock_path) {
        Ok(file) => file,
        Err(create_err) => {
            let mut fallback = OpenOptions::new();
            fallback.read(true);
            #[cfg(unix)]
            fallback.custom_flags(libc::O_NOFOLLOW);
            fallback.open(&lock_path).map_err(|_| {
                format!(
                    "cannot open the marker lock {}: {create_err}",
                    lock_path.display()
                )
            })?
        }
    };
    if !file
        .metadata()
        .map_err(|err| {
            format!(
                "cannot inspect the marker lock {}: {err}",
                lock_path.display()
            )
        })?
        .is_file()
    {
        return Err(format!(
            "the marker lock {} is not a regular file",
            lock_path.display()
        ));
    }
    let deadline = Instant::now() + wait;
    loop {
        match file.try_lock() {
            Ok(()) => return Ok(file),
            Err(std::fs::TryLockError::WouldBlock) => {
                if Instant::now() >= deadline {
                    return Err(format!(
                        "the marker lock {} has been held by another beacon write or probe for over {:?}",
                        lock_path.display(),
                        wait
                    ));
                }
                thread::sleep(Duration::from_millis(20));
            }
            Err(std::fs::TryLockError::Error(err)) => {
                return Err(format!(
                    "cannot lock the marker lock {}: {err}",
                    lock_path.display()
                ));
            }
        }
    }
}

/// Removes a leftover artifact of an earlier run; a missing file is fine.
/// `remove_file` unlinks the name itself and never follows a symlink.
fn remove_beacon_health_leftover(path: &Path) -> std::io::Result<()> {
    match std::fs::remove_file(path) {
        Err(err) if err.kind() != std::io::ErrorKind::NotFound => Err(err),
        _ => Ok(()),
    }
}

/// Creates a private temporary file at a fixed sibling name, replacing any
/// leftover from a run that was killed before it could clean up.
fn create_beacon_health_temp(temporary: &Path) -> std::io::Result<File> {
    remove_beacon_health_leftover(temporary)?;
    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    options.mode(0o600);
    options.open(temporary)
}

/// Atomically publishes `v2 <last_success_at> <pid> <start>` under the
/// marker lock, replacing any leftover of its own fixed temp name first.
fn write_beacon_health(
    path: &Path,
    last_success_at: i64,
    generation: &ProcessGeneration,
) -> std::io::Result<()> {
    let lock = lock_beacon_health(path).map_err(std::io::Error::other)?;
    write_beacon_health_locked(path, last_success_at, generation, &lock)
}

/// The write itself; `_lock` is the caller's held marker lock, so this can
/// only be reached with the lock taken.
fn write_beacon_health_locked(
    path: &Path,
    last_success_at: i64,
    generation: &ProcessGeneration,
    _lock: &File,
) -> std::io::Result<()> {
    let temporary = beacon_health_sibling_path(path, BEACON_HEALTH_WRITE_TEMP)?;
    let write_result = (|| -> std::io::Result<()> {
        let mut file = create_beacon_health_temp(&temporary)?;
        writeln!(
            file,
            "v2 {last_success_at} {} {}",
            generation.pid, generation.start
        )?;
        file.sync_all()?;
        std::fs::rename(&temporary, path)?;
        Ok(())
    })();
    if write_result.is_err() {
        let _ = std::fs::remove_file(&temporary);
    }
    write_result
}

/// What sits at the marker path, opened without following a final symlink.
enum BeaconHealthMarker {
    Missing,
    NotRegular,
    Regular(File),
}

/// Opens the marker for reading with `O_NOFOLLOW` (and `O_NONBLOCK`, so a
/// FIFO cannot stall the probe). A symlink or any other non-regular file at
/// the marker path is never followed, read, linked, truncated or otherwise
/// reached through this path: the beacon only ever produces regular files by
/// rename, so anything else is not its state (PHAROS-203).
fn open_beacon_health_marker(path: &Path) -> std::io::Result<BeaconHealthMarker> {
    let mut options = OpenOptions::new();
    options.read(true);
    #[cfg(unix)]
    options.custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK);
    let file = match options.open(path) {
        Ok(file) => file,
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => {
            return Ok(BeaconHealthMarker::Missing);
        }
        #[cfg(unix)]
        Err(err) if err.raw_os_error() == Some(libc::ELOOP) => {
            return Ok(BeaconHealthMarker::NotRegular);
        }
        Err(err) => return Err(err),
    };
    if !file.metadata()?.is_file() {
        return Ok(BeaconHealthMarker::NotRegular);
    }
    Ok(BeaconHealthMarker::Regular(file))
}

/// Explains a refused hard link. `EPERM` is what immutable or append-only
/// markers produce, but also what filesystems without hard links return, so
/// both readings are offered; either way the verdict stays fail-closed.
fn beacon_health_link_refusal(err: &std::io::Error) -> String {
    let advisory = match err.raw_os_error() {
        Some(code) if code == libc::EMLINK => {
            "the marker has reached the filesystem's hard-link limit"
        }
        Some(code) if code == libc::ENOTSUP || code == libc::EOPNOTSUPP => {
            "this filesystem does not support hard links"
        }
        Some(code) if code == libc::EPERM => {
            "an immutable or append-only flag on the marker, or a filesystem without hard links, refused it"
        }
        _ => "the marker could not be linked",
    };
    format!(
        "the existing marker cannot be replaced (linking it was refused: {err}; {advisory}; point {BEACON_HEALTH_PATH_ENV} at a writable tmpfs if this location cannot take the probe)"
    )
}

/// Proves that this process can perform the marker's atomic temp+rename
/// write right now, without ever writing, moving or racing the marker's own
/// name (PHAROS-203):
///
/// 1. create+write+sync a sibling temp file, exactly what the beacon writes;
/// 2. when a regular-file marker exists, hard-link it to a sibling name and
///    rename the temp over that link. The link shares the marker's inode,
///    owner, flags and ACLs, so the kernel applies the checks
///    `rename(temp, marker)` would face: immutable or append-only flags
///    (`chflags uchg`, `chattr +i`), deny-delete ACLs or policies, and the
///    sticky-directory rule (target owner, directory owner, or root). A
///    marker that survives the beacon's reset and refresh says nothing about
///    the running beacon, however recent it reads.
///
/// All artifacts use fixed sibling names and are removed first and last, so
/// a probe killed midway is repaired by the next one; whatever cannot be
/// removed is reported by path.
fn probe_beacon_health_location(path: &Path) -> Result<(), String> {
    let _lock = lock_beacon_health(path)?;
    // Under the lock no write is in flight, so a writer temp is a leftover of
    // a killed or blocked write. It must go, or the beacon cannot refresh:
    // an immutable or foreign temp there blocks every future write.
    let writer_temp = beacon_health_sibling_path(path, BEACON_HEALTH_WRITE_TEMP)
        .map_err(|err| err.to_string())?;
    remove_beacon_health_leftover(&writer_temp).map_err(|err| {
        format!(
            "the beacon's write temporary {} cannot be removed, so the marker cannot be refreshed: {err}",
            writer_temp.display()
        )
    })?;
    let temporary = beacon_health_sibling_path(path, BEACON_HEALTH_PROBE_TEMP)
        .map_err(|err| err.to_string())?;
    let link = beacon_health_sibling_path(path, BEACON_HEALTH_PROBE_LINK)
        .map_err(|err| err.to_string())?;
    remove_beacon_health_leftover(&link).map_err(|err| {
        format!(
            "a previous probe link {} cannot be removed: {err}",
            link.display()
        )
    })?;
    let result = probe_beacon_health_location_with(path, &temporary, &link);
    let _ = std::fs::remove_file(&temporary);
    result
}

fn probe_beacon_health_location_with(
    path: &Path,
    temporary: &Path,
    link: &Path,
) -> Result<(), String> {
    let mut file = create_beacon_health_temp(temporary)
        .map_err(|err| format!("cannot create a temporary file next to the marker: {err}"))?;
    file.write_all(b"probe\n")
        .and_then(|()| file.sync_all())
        .map_err(|err| format!("cannot write a temporary file next to the marker: {err}"))?;
    drop(file);

    match open_beacon_health_marker(path) {
        // No marker: the rename would create the name, and creating a file
        // here was just proven. The read reports the missing state.
        Ok(BeaconHealthMarker::Missing) => return Ok(()),
        // A symlink, directory or device is never the beacon's state; the
        // read reports it as invalid, and nothing follows or links it.
        Ok(BeaconHealthMarker::NotRegular) => return Ok(()),
        Err(err) => return Err(format!("cannot inspect the marker: {err}")),
        Ok(BeaconHealthMarker::Regular(_)) => {}
    }

    std::fs::hard_link(path, link).map_err(|err| beacon_health_link_refusal(&err))?;
    let replaced = std::fs::rename(temporary, link).map_err(|err| {
        format!("the existing marker cannot be replaced (renaming over a link to it was refused): {err}")
    });
    // On success the link name now holds the probe file; on failure it is
    // still a second name for the marker. Remove it either way; a concurrent
    // probe (a manual `healthcheck` next to the container's own) may already
    // have removed it, which is fine.
    let removed = remove_beacon_health_leftover(link)
        .map_err(|err| format!("could not remove probe file {}: {err}", link.display()));
    replaced?;
    removed
}

/// Identity of whatever the marker name currently points at, read without
/// following symlinks: enough to tell later whether the very same file is
/// still there. `None` means no marker.
#[derive(Debug, Clone, PartialEq, Eq)]
struct MarkerObservation(Option<(u64, u64, u64, Option<SystemTime>)>);

fn observe_beacon_health_marker(path: &Path) -> std::io::Result<MarkerObservation> {
    match std::fs::symlink_metadata(path) {
        Ok(metadata) => {
            #[cfg(unix)]
            let (dev, ino) = {
                use std::os::unix::fs::MetadataExt;
                (metadata.dev(), metadata.ino())
            };
            #[cfg(not(unix))]
            let (dev, ino) = (0, 0);
            Ok(MarkerObservation(Some((
                dev,
                ino,
                metadata.len(),
                metadata.modified().ok(),
            ))))
        }
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => Ok(MarkerObservation(None)),
        Err(err) => Err(err),
    }
}

/// Removes the marker only if it is still exactly the file observed before
/// the failed reset, and only while the caller holds the marker lock. Unlink
/// only: the name goes away and nothing is ever written into an inode
/// reached through the marker path, so a symlink or foreign file placed
/// there can never be damaged.
fn invalidate_beacon_health_locked(
    path: &Path,
    observed: &MarkerObservation,
    _lock: &File,
) -> Result<&'static str, String> {
    let now = observe_beacon_health_marker(path)
        .map_err(|err| format!("previous state could not be re-inspected: {err}"))?;
    if now.0.is_none() {
        return Ok("no previous state present");
    }
    if now != *observed {
        return Ok("the marker changed during initialization and was left in place");
    }
    remove_beacon_health_leftover(path)
        .map(|()| "previous state removed")
        .map_err(|err| format!("previous state could not be removed either: {err}"))
}

/// Startup reset of the marker under one lock scope: take the marker lock,
/// remember what the marker name points at, attempt the sentinel write, and
/// if that fails unlink the marker only if it is still the very file that
/// was observed. A lock that cannot be taken touches nothing: another writer
/// may be mid-publish. No marker from a previous run may survive readable
/// when this beacon could reset it; the healthcheck never trusts one it
/// could not (PHAROS-203).
fn initialize_beacon_health(path: &Path, generation: &ProcessGeneration) -> Result<(), String> {
    initialize_beacon_health_within(path, generation, BEACON_HEALTH_LOCK_WAIT)
}

fn initialize_beacon_health_within(
    path: &Path,
    generation: &ProcessGeneration,
    wait: Duration,
) -> Result<(), String> {
    let lock = lock_beacon_health_within(path, wait).map_err(|err| {
        format!(
            "could not initialize container health state at {}: {err}; nothing was removed",
            path.display()
        )
    })?;
    let observed = observe_beacon_health_marker(path).map_err(|err| {
        format!(
            "could not initialize container health state at {}: cannot inspect the marker: {err}; nothing was removed",
            path.display()
        )
    })?;
    let Err(write_err) = write_beacon_health_locked(path, 0, generation, &lock) else {
        return Ok(());
    };
    match invalidate_beacon_health_locked(path, &observed, &lock) {
        Ok(outcome) => Err(format!(
            "could not initialize container health state at {}: {write_err}; {outcome}",
            path.display()
        )),
        Err(reason) => Err(format!(
            "could not initialize container health state at {}: {write_err}; {reason}",
            path.display()
        )),
    }
}

/// Where the beacon records its last successful report for the container
/// probe. Overridable so a deployment without a writable `/tmp` can still
/// publish truthful health (PHAROS-203).
fn beacon_health_path() -> PathBuf {
    env_value(BEACON_HEALTH_PATH_ENV)
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from(BEACON_HEALTH_PATH))
}

/// Every way the beacon container can be unhealthy, each with a reason an
/// operator can act on from `docker inspect` output alone (PHAROS-203).
#[derive(Debug, Clone, PartialEq, Eq)]
enum BeaconHealthProblem {
    OneShot,
    InvalidInterval,
    StateMissing(PathBuf),
    LocationUnwritable {
        path: PathBuf,
        error: String,
    },
    StateUnreadable {
        path: PathBuf,
        error: String,
    },
    StateInvalid(PathBuf),
    NotCurrentGeneration {
        path: PathBuf,
        pid: u32,
        detail: String,
    },
    NoSuccessfulReportYet,
    ClockSkew {
        last_success_at: i64,
        now: i64,
    },
    Stale {
        age_secs: u64,
        limit_secs: u64,
        cadence_secs: u64,
    },
}

impl std::fmt::Display for BeaconHealthProblem {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::OneShot => write!(
                f,
                "PHAROS_INTERVAL is not set, so this is a one-shot beacon that publishes no container health; \
                 set PHAROS_INTERVAL for a recurring beacon or disable the container healthcheck"
            ),
            Self::InvalidInterval => write!(
                f,
                "PHAROS_INTERVAL must be between {MIN_HEARTBEAT_INTERVAL_SECS} and {MAX_HEARTBEAT_INTERVAL_SECS} seconds"
            ),
            Self::StateMissing(path) => write!(
                f,
                "no report state at {}; the beacon has not started, or cannot write there (mount a writable tmpfs or set {BEACON_HEALTH_PATH_ENV})",
                path.display()
            ),
            Self::LocationUnwritable { path, error } => write!(
                f,
                "report state location for {} cannot be written ({error}); the beacon cannot reset or refresh its marker, so a recent one is not trusted (mount a writable tmpfs or set {BEACON_HEALTH_PATH_ENV})",
                path.display()
            ),
            Self::NotCurrentGeneration { path, pid, detail } => write!(
                f,
                "marker at {} was written by beacon process {pid}, which is not the running one ({detail}); only a successful report by the current beacon process restores health",
                path.display()
            ),
            Self::StateUnreadable { path, error } => write!(
                f,
                "report state at {} could not be read: {error}",
                path.display()
            ),
            Self::StateInvalid(path) => write!(
                f,
                "report state at {} is not a pharos-beacon health record",
                path.display()
            ),
            Self::NoSuccessfulReportYet => {
                write!(f, "no successful report to the control plane yet")
            }
            Self::ClockSkew {
                last_success_at,
                now,
            } => write!(
                f,
                "last successful report is stamped {last_success_at} but the clock reads {now}; refusing to trust a future report"
            ),
            Self::Stale {
                age_secs,
                limit_secs,
                cadence_secs,
            } => write!(
                f,
                "last successful report was {age_secs}s ago, beyond {limit_secs}s ({BEACON_HEALTH_STALE_INTERVALS} x PHAROS_INTERVAL={cadence_secs})"
            ),
        }
    }
}

/// Reads the recorded last-success timestamp. `Ok(None)` is the startup
/// marker: the beacon is running but has not reported successfully yet.
/// The marker's content: when the last report succeeded (`None` for the
/// startup sentinel) and which process wrote it.
#[derive(Debug, Clone, PartialEq, Eq)]
struct BeaconHealthRecord {
    last_success_at: Option<i64>,
    generation: ProcessGeneration,
}

fn read_beacon_health(path: &Path) -> Result<BeaconHealthRecord, BeaconHealthProblem> {
    let unreadable = |err: std::io::Error| BeaconHealthProblem::StateUnreadable {
        path: path.to_path_buf(),
        error: err.to_string(),
    };
    let invalid = || BeaconHealthProblem::StateInvalid(path.to_path_buf());
    let mut file = match open_beacon_health_marker(path) {
        Ok(BeaconHealthMarker::Regular(file)) => file,
        Ok(BeaconHealthMarker::Missing) => {
            return Err(BeaconHealthProblem::StateMissing(path.to_path_buf()));
        }
        Ok(BeaconHealthMarker::NotRegular) => return Err(invalid()),
        Err(err) => return Err(unreadable(err)),
    };
    if file.metadata().map_err(unreadable)?.len() > MAX_BEACON_HEALTH_MARKER_BYTES {
        return Err(invalid());
    }
    let mut raw = String::new();
    file.read_to_string(&mut raw).map_err(unreadable)?;
    let fields: Vec<&str> = raw.split_ascii_whitespace().collect();
    match fields.as_slice() {
        ["v2", stamp, pid, start] => {
            let last_success_at = stamp.parse::<i64>().map_err(|_| invalid())?;
            let pid = pid.parse::<u32>().map_err(|_| invalid())?;
            let last_success_at = match last_success_at {
                0 => None,
                stamp if stamp > 0 => Some(stamp),
                _ => return Err(invalid()),
            };
            Ok(BeaconHealthRecord {
                last_success_at,
                generation: ProcessGeneration {
                    pid,
                    start: (*start).to_string(),
                },
            })
        }
        // Markers from beacons before process generations existed: nothing
        // proves which process wrote them, so they are never trusted.
        ["v1", _] => Err(BeaconHealthProblem::NotCurrentGeneration {
            path: path.to_path_buf(),
            pid: 0,
            detail: "the marker predates process generations".to_string(),
        }),
        _ => Err(invalid()),
    }
}

/// Container health verdict for a recurring beacon: `Ok(age)` when the last
/// successful report is within the staleness window, otherwise the reason.
fn beacon_health_verdict(
    path: &Path,
    cadence_secs: u64,
    now: i64,
) -> Result<u64, BeaconHealthProblem> {
    beacon_health_verdict_with(path, cadence_secs, now, probe_beacon_health_location)
}

/// `beacon_health_verdict` with the location probe injected, so the
/// fail-closed decision is testable regardless of the test user's privileges.
fn beacon_health_verdict_with(
    path: &Path,
    cadence_secs: u64,
    now: i64,
    probe_location: impl Fn(&Path) -> Result<(), String>,
) -> Result<u64, BeaconHealthProblem> {
    if RequestDeadlines::for_cadence(cadence_secs).is_err() {
        return Err(BeaconHealthProblem::InvalidInterval);
    }
    probe_location(path).map_err(|error| BeaconHealthProblem::LocationUnwritable {
        path: path.to_path_buf(),
        error,
    })?;
    let record = read_beacon_health(path)?;
    record
        .generation
        .is_running()
        .map_err(|detail| BeaconHealthProblem::NotCurrentGeneration {
            path: path.to_path_buf(),
            pid: record.generation.pid,
            detail,
        })?;
    let last_success_at = record
        .last_success_at
        .ok_or(BeaconHealthProblem::NoSuccessfulReportYet)?;
    let age_secs = now
        .checked_sub(last_success_at)
        .and_then(|age| u64::try_from(age).ok())
        .ok_or(BeaconHealthProblem::ClockSkew {
            last_success_at,
            now,
        })?;
    let limit_secs = cadence_secs.saturating_mul(BEACON_HEALTH_STALE_INTERVALS);
    if age_secs > limit_secs {
        return Err(BeaconHealthProblem::Stale {
            age_secs,
            limit_secs,
            cadence_secs,
        });
    }
    Ok(age_secs)
}

fn beacon_container_healthcheck() -> Result<String, BeaconHealthProblem> {
    let cadence = match reporting_interval() {
        Ok(Some(cadence)) => cadence,
        Ok(None) => return Err(BeaconHealthProblem::OneShot),
        Err(_) => return Err(BeaconHealthProblem::InvalidInterval),
    };
    let path = beacon_health_path();
    let age_secs = beacon_health_verdict(&path, cadence, now_unix())?;
    Ok(format!(
        "healthy: last successful report {age_secs}s ago (limit {}s)",
        cadence.saturating_mul(BEACON_HEALTH_STALE_INTERVALS)
    ))
}

fn report_rtt_millis(duration: Duration) -> u64 {
    u64::try_from(duration.as_millis())
        .unwrap_or(MAX_INBOUND_RTT_MS)
        .clamp(1, MAX_INBOUND_RTT_MS)
}

fn hostname() -> String {
    std::env::var("PHAROS_HOSTNAME")
        .ok()
        .or_else(|| std::env::var("HOSTNAME").ok())
        .or_else(|| {
            std::fs::read_to_string("/etc/hostname")
                .ok()
                .map(|s| s.trim().to_string())
        })
        .filter(|s| !s.is_empty())
        .unwrap_or_else(|| "unknown".into())
}

fn bearer_token() -> Result<Option<String>, pharos_core::secret_input::SecretInputError> {
    pharos_core::secret_input::optional_secret("PHAROS_TOKEN")
}

fn parse_host_preferences(raw: &str, host: &str) -> Result<HostPreferences, &'static str> {
    let registry = serde_json::from_str::<HostPreferencesRegistry>(raw)
        .map_err(|_| "host preference registry is invalid")?;
    registry
        .validate_contract()
        .map_err(|_| "host preference registry is invalid")?;
    registry
        .preferences_for(host)
        .cloned()
        .ok_or("host preference registry does not contain this host")
}

fn read_host_preferences(path: &Path, host: &str) -> Result<HostPreferences, &'static str> {
    let raw =
        std::fs::read_to_string(path).map_err(|_| "host preference registry is unavailable")?;
    parse_host_preferences(&raw, host)
}

fn atomic_write_host_preferences(
    path: &Path,
    registry: &HostPreferencesRegistry,
) -> Result<(), PreferencesApplyError> {
    registry
        .validate_contract()
        .map_err(|_| PreferencesApplyError::InvalidResponse)?;
    let parent = path.parent().ok_or(PreferencesApplyError::WriteFailed)?;
    if !parent.is_dir() {
        return Err(PreferencesApplyError::WriteFailed);
    }
    let file_name = path
        .file_name()
        .and_then(|name| name.to_str())
        .ok_or(PreferencesApplyError::WriteFailed)?;
    let nonce = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| PreferencesApplyError::WriteFailed)?
        .as_nanos();
    let temporary = parent.join(format!(".{file_name}.{}.{}.tmp", std::process::id(), nonce));
    let mut bytes =
        serde_json::to_vec_pretty(registry).map_err(|_| PreferencesApplyError::InvalidResponse)?;
    bytes.push(b'\n');

    let write_result = (|| -> std::io::Result<()> {
        let mut options = OpenOptions::new();
        options.write(true).create_new(true);
        #[cfg(unix)]
        options.mode(0o600);
        let mut file = options.open(&temporary)?;
        file.write_all(&bytes)?;
        file.sync_all()?;
        std::fs::rename(&temporary, path)?;
        let _ = File::open(parent).and_then(|directory| directory.sync_all());
        Ok(())
    })();
    if write_result.is_err() {
        let _ = std::fs::remove_file(&temporary);
        return Err(PreferencesApplyError::WriteFailed);
    }
    Ok(())
}

fn apply_report_response(
    body: &str,
    host: &str,
    is_nix: bool,
    preferences_path: Option<&Path>,
) -> Result<Option<HostPreferences>, PreferencesApplyError> {
    let response = serde_json::from_str::<HostReportResponse>(body)
        .map_err(|_| PreferencesApplyError::InvalidResponse)?;
    if response
        .pending_preferences
        .as_ref()
        .is_some_and(|registry| registry.hosts.len() != 1 || !registry.hosts.contains_key(host))
    {
        return Err(PreferencesApplyError::HostMismatch);
    }
    response
        .validate_contract_for(host)
        .map_err(|_| PreferencesApplyError::InvalidResponse)?;
    let Some(registry) = response.pending_preferences.as_ref() else {
        return Ok(None);
    };
    if is_nix {
        return Err(PreferencesApplyError::UnsupportedOnNix);
    }
    let path = preferences_path.ok_or(PreferencesApplyError::NotConfigured)?;
    atomic_write_host_preferences(path, registry)?;
    Ok(registry.preferences_for(host).cloned())
}

fn apply_report_http_response(
    response: ureq::http::Response<ureq::Body>,
    host: &str,
    is_nix: bool,
    preferences_path: Option<&Path>,
) -> Result<Option<HostPreferences>, PreferencesApplyError> {
    if response.status() == 204 {
        return Ok(None);
    }
    if response.status() != 200 {
        return Err(PreferencesApplyError::InvalidResponse);
    }
    let body = read_bounded_report_response(response.into_body().into_reader())?;
    apply_report_response(&body, host, is_nix, preferences_path)
}

fn read_bounded_report_response(reader: impl Read) -> Result<String, PreferencesApplyError> {
    let mut body = String::new();
    reader
        .take(MAX_REPORT_RESPONSE_BYTES + 1)
        .read_to_string(&mut body)
        .map_err(|_| PreferencesApplyError::InvalidResponse)?;
    if body.len() as u64 > MAX_REPORT_RESPONSE_BYTES {
        return Err(PreferencesApplyError::InvalidResponse);
    }
    Ok(body)
}

/// Locate a flake checkout (one containing flake.lock).
fn nixcfg_dir() -> Option<String> {
    if let Ok(d) = std::env::var("NIXCFG_DIR") {
        return Some(d);
    }
    ["/etc/nixos"]
        .into_iter()
        .find(|d| Path::new(&format!("{d}/flake.lock")).exists())
        .map(String::from)
}

fn kernel_running_path() -> PathBuf {
    env_value("PHAROS_RUNNING_KERNEL_FILE")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("/proc/sys/kernel/osrelease"))
}

fn kernel_expected_modules_dir() -> PathBuf {
    if let Some(path) = env_value("PHAROS_CURRENT_KERNEL_MODULES_DIR") {
        return PathBuf::from(path);
    }
    [
        "/host/run/current-system/kernel-modules/lib/modules",
        "/run/current-system/kernel-modules/lib/modules",
    ]
    .into_iter()
    .map(PathBuf::from)
    .find(|path| path.is_dir())
    .unwrap_or_else(|| PathBuf::from("/run/current-system/kernel-modules/lib/modules"))
}

fn read_running_kernel(path: &Path) -> Option<String> {
    std::fs::read_to_string(path)
        .ok()
        .map(|value| value.trim().to_string())
        .filter(|value| !value.is_empty())
}

fn read_single_kernel_module_version(path: &Path) -> Option<String> {
    let mut entries = std::fs::read_dir(path)
        .ok()?
        .filter_map(Result::ok)
        .map(|entry| entry.file_name().to_string_lossy().into_owned());
    let version = entries.next()?;
    entries.next().is_none().then_some(version)
}

fn collect_kernel_posture_at(
    is_nix: bool,
    observed_at: i64,
    running_path: &Path,
    expected_modules_dir: &Path,
) -> KernelPosture {
    KernelPosture::observed(
        is_nix,
        read_running_kernel(running_path),
        is_nix
            .then(|| read_single_kernel_module_version(expected_modules_dir))
            .flatten(),
        observed_at,
    )
}

fn collect_kernel_posture(is_nix: bool, observed_at: i64) -> KernelPosture {
    collect_kernel_posture_at(
        is_nix,
        observed_at,
        &kernel_running_path(),
        &kernel_expected_modules_dir(),
    )
}

fn deployment_evidence_path() -> PathBuf {
    env_value("PHAROS_NIX_DEPLOYMENT_EVIDENCE_FILE")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("/host/pharos-deployment/evidence.json"))
}

fn read_deployment_evidence(path: &Path) -> Option<NixDeploymentEvidence> {
    let mut raw = String::new();
    File::open(path)
        .ok()?
        .take(MAX_DEPLOYMENT_EVIDENCE_BYTES + 1)
        .read_to_string(&mut raw)
        .ok()?;
    if raw.len() as u64 > MAX_DEPLOYMENT_EVIDENCE_BYTES {
        return None;
    }
    let evidence: NixDeploymentEvidence = serde_json::from_str(&raw).ok()?;
    evidence.validate_contract().ok()?;
    Some(evidence)
}

fn sha256_hex(raw: &[u8]) -> String {
    format!("{:x}", Sha256::digest(raw))
}

/// Read the checkout lock only when its digest and primary node exactly match
/// the active generation. A checkout may move independently after activation;
/// treating that newer mutable file as deployed state would be false evidence.
fn matching_flake_lock(dir: &str, evidence: &NixDeploymentEvidence) -> Option<serde_json::Value> {
    let path = format!("{dir}/flake.lock");
    if std::fs::metadata(&path).ok()?.len() > MAX_FLAKE_LOCK_BYTES {
        return None;
    }
    let raw = std::fs::read(path).ok()?;
    if sha256_hex(&raw) != evidence.flake_lock_sha256 {
        return None;
    }
    let value: serde_json::Value = serde_json::from_slice(&raw).ok()?;
    let nodes = value.get("nodes")?.as_object()?;
    let root_name = value
        .get("root")
        .and_then(|root| root.as_str())
        .unwrap_or("root");
    let target = nodes.get(root_name)?.get("inputs")?.get("nixpkgs")?;
    let node = nodes.get(input_target_name(target)?)?;
    if node.get("locked")?.get("rev")?.as_str()? != evidence.nixpkgs_revision
        || node.get("locked")?.get("lastModified")?.as_i64()? != evidence.nixpkgs_last_modified
        || nixpkgs_channel(node).as_deref() != Some(evidence.nixpkgs_channel.as_str())
    {
        return None;
    }
    Some(value)
}

/// Days since the newest input in the generation-matched flake.lock.
fn flake_lock_age_days(lock: &serde_json::Value) -> Option<u32> {
    let v = lock;
    let newest = v
        .get("nodes")?
        .as_object()?
        .values()
        .filter_map(|n| n.get("locked")?.get("lastModified")?.as_i64())
        .max()?;
    days_since(newest)
}

fn days_since(unix_seconds: i64) -> Option<u32> {
    u32::try_from((now_unix() - unix_seconds).max(0) / 86_400).ok()
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct CollectedNixpkgsFreshness {
    age_days: u32,
    channel: Option<String>,
    secondary: Option<NixpkgsInputFreshness>,
}

/// PHAROS-193/196/201: the system nixpkgs plus secondary root-input context.
///
/// `flake_lock_age_days` reports the newest input, so one freshly bumped helper
/// hides a frozen nixpkgs behind a reassuring `0d`. Security fixes arrive
/// through the system nixpkgs, so report that as primary posture and preserve
/// the stalest other root nixpkgs input as explicitly secondary context.
fn nixpkgs_freshness(
    v: &serde_json::Value,
    evidence: &NixDeploymentEvidence,
) -> Option<CollectedNixpkgsFreshness> {
    let nodes = v.get("nodes")?.as_object()?;
    // PHAROS-196: resolve the flake's own `nixpkgs` input rather than scanning
    // for the oldest node whose name happens to contain "nixpkgs". A lock mixes
    // the input the system is built from, other root inputs that may be
    // unreferenced, and transitive inputs of unrelated flakes. Reporting the
    // worst of all three describes the lock file, not the host.
    let root_name = v
        .get("root")
        .and_then(|root| root.as_str())
        .unwrap_or("root");
    let root_inputs = nodes.get(root_name)?.get("inputs")?.as_object()?;
    let target = root_inputs.get("nixpkgs")?;
    let node_name = input_target_name(target)?;
    let node = nodes.get(node_name)?;
    let modified = node.get("locked")?.get("lastModified")?.as_i64()?;
    let channel = nixpkgs_channel(node);
    if modified != evidence.nixpkgs_last_modified
        || channel.as_deref() != Some(evidence.nixpkgs_channel.as_str())
        || node.get("locked")?.get("rev")?.as_str()? != evidence.nixpkgs_revision
    {
        return None;
    }

    // Only other root inputs are secondary context. Transitive nixpkgs nodes
    // belong to unrelated flakes and must not be presented as this host's lock
    // maintenance. Aliases that resolve to the system node are excluded too.
    let secondary = root_inputs
        .iter()
        .filter(|(input, _)| {
            input.as_str() != "nixpkgs"
                && input.to_ascii_lowercase().contains("nixpkgs")
                && pharos_core::valid_nix_input_name(input)
        })
        .filter_map(|(input, target)| {
            let secondary_node_name = input_target_name(target)?;
            if secondary_node_name == node_name {
                return None;
            }
            let secondary_node = nodes.get(secondary_node_name)?;
            let modified = secondary_node
                .get("locked")?
                .get("lastModified")?
                .as_i64()?;
            Some(NixpkgsInputFreshness {
                input: input.clone(),
                age_days: days_since(modified)?,
                channel: nixpkgs_channel(secondary_node),
            })
        })
        .max_by(|left, right| {
            left.age_days
                .cmp(&right.age_days)
                .then_with(|| right.input.cmp(&left.input))
        });

    Some(CollectedNixpkgsFreshness {
        age_days: days_since(evidence.nixpkgs_last_modified)?,
        channel: Some(evidence.nixpkgs_channel.clone()),
        secondary,
    })
}

fn nixpkgs_channel(node: &serde_json::Value) -> Option<String> {
    node.get("original")
        .and_then(|original| original.get("ref"))
        .and_then(|reference| reference.as_str())
        .filter(|reference| pharos_core::valid_nix_channel(reference))
        .map(str::to_string)
}

/// An `inputs` entry is either a node name or, for a `follows`, the path to the
/// node being followed. Only the first element names a node.
fn input_target_name(target: &serde_json::Value) -> Option<&str> {
    match target {
        serde_json::Value::String(name) => Some(name.as_str()),
        serde_json::Value::Array(path) => path.first()?.as_str(),
        _ => None,
    }
}

fn safe_git_remote(raw: &str) -> Option<String> {
    let raw = raw.trim();
    if raw.len() > 2_048 {
        return None;
    }
    let url = Url::parse(raw).ok()?;
    (url.scheme() == "https"
        && url.host_str().is_some()
        && url.username().is_empty()
        && url.password().is_none()
        && url.query().is_none()
        && url.fragment().is_none())
    .then(|| url.to_string())
}

fn safe_git_branch_ref(raw: &str) -> Option<String> {
    let reference = raw.trim();
    let branch = reference.strip_prefix("refs/heads/")?;
    (!branch.is_empty()
        && reference.len() <= 256
        && !reference.contains("..")
        && !reference.contains("@{")
        && !reference.ends_with('/')
        && !reference.ends_with('.')
        && reference
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || b"-._/".contains(&byte)))
    .then(|| reference.to_string())
}

fn git_output(args: &[String]) -> Option<String> {
    run_location_command("git", args, GIT_COMPARISON_TIMEOUT).ok()
}

fn exact_revision(raw: &str) -> Option<String> {
    let revision = raw.trim();
    ((revision.len() == 40 || revision.len() == 64)
        && revision
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte)))
    .then(|| revision.to_string())
}

fn git_success(args: &[String]) -> bool {
    run_location_command("git", args, GIT_COMPARISON_TIMEOUT).is_ok()
}

fn nixcfg_reference_dir() -> PathBuf {
    PathBuf::from("/tmp/pharos-nixcfg-reference.git")
}

fn prepare_reference_repo(reference_dir: &Path, checkout: &str) -> Option<()> {
    if !reference_dir.is_absolute() || !reference_dir.starts_with(std::env::temp_dir()) {
        return None;
    }
    if std::fs::symlink_metadata(reference_dir)
        .ok()
        .is_some_and(|metadata| metadata.file_type().is_symlink())
    {
        return None;
    }
    if !reference_dir.join("HEAD").is_file() {
        let path = reference_dir.to_str()?.to_string();
        git_success(&["init".into(), "--bare".into(), "--quiet".into(), path]).then_some(())?;
    }
    let git_dir = git_output(&[
        "-C".into(),
        checkout.into(),
        "rev-parse".into(),
        "--absolute-git-dir".into(),
    ])?;
    let objects = PathBuf::from(git_dir.trim()).join("objects");
    if !objects.is_dir() {
        return None;
    }
    let info = reference_dir.join("objects/info");
    std::fs::create_dir_all(&info).ok()?;
    std::fs::write(info.join("alternates"), format!("{}\n", objects.display())).ok()?;
    Some(())
}

fn nixcfg_git_comparison(checkout: &str, deployed_revision: &str) -> Option<NixcfgGitComparison> {
    let remote = safe_git_remote(&env_value("PHAROS_NIXCFG_REMOTE_URL")?)?;
    let remote_ref = safe_git_branch_ref(&env_value("PHAROS_NIXCFG_REMOTE_REF")?)?;
    let reference_dir = nixcfg_reference_dir();
    nixcfg_git_comparison_from_remote(
        checkout,
        deployed_revision,
        &remote,
        &remote_ref,
        &reference_dir,
    )
}

fn nixcfg_git_comparison_from_remote(
    checkout: &str,
    deployed_revision: &str,
    remote: &str,
    remote_ref: &str,
    reference_dir: &Path,
) -> Option<NixcfgGitComparison> {
    prepare_reference_repo(reference_dir, checkout)?;
    let reference_dir = reference_dir.to_str()?.to_string();
    let local_ref = "refs/remotes/pharos/authoritative";
    let refspec = format!("+{remote_ref}:{local_ref}");
    git_success(&[
        "-C".into(),
        reference_dir.clone(),
        "fetch".into(),
        "--quiet".into(),
        "--force".into(),
        "--no-tags".into(),
        "--filter=blob:none".into(),
        remote.to_string(),
        refspec,
    ])
    .then_some(())?;
    let upstream_revision = exact_revision(&git_output(&[
        "-C".into(),
        reference_dir.clone(),
        "rev-parse".into(),
        format!("{local_ref}^{{commit}}"),
    ])?)?;
    let deployed_revision = exact_revision(deployed_revision)?;
    if upstream_revision == deployed_revision {
        return Some(NixcfgGitComparison {
            upstream_revision,
            relation: GitRevisionRelation::Current,
            commits_behind: Some(0),
        });
    }
    let merge_base = exact_revision(&git_output(&[
        "-C".into(),
        reference_dir.clone(),
        "merge-base".into(),
        deployed_revision.clone(),
        upstream_revision.clone(),
    ])?)?;
    if merge_base == deployed_revision {
        let count = git_output(&[
            "-C".into(),
            reference_dir.clone(),
            "rev-list".into(),
            "--count".into(),
            format!("{deployed_revision}..{upstream_revision}"),
        ])?
        .trim()
        .parse::<u32>()
        .ok()
        .filter(|count| *count > 0)?;
        return Some(NixcfgGitComparison {
            upstream_revision,
            relation: GitRevisionRelation::Behind,
            commits_behind: Some(count),
        });
    }
    let relation = if merge_base == upstream_revision {
        GitRevisionRelation::Ahead
    } else {
        GitRevisionRelation::Diverged
    };
    Some(NixcfgGitComparison {
        upstream_revision,
        relation,
        commits_behind: None,
    })
}

fn safe_nixpkgs_channel_base_url(raw: &str) -> Option<Url> {
    let mut url = Url::parse(raw.trim()).ok()?;
    if url.scheme() != "https"
        || url.host_str().is_none()
        || !url.username().is_empty()
        || url.password().is_some()
        || url.query().is_some()
        || url.fragment().is_some()
    {
        return None;
    }
    if !url.path().ends_with('/') {
        let mut path = url.path().to_string();
        path.push('/');
        url.set_path(&path);
    }
    Some(url)
}

fn nixpkgs_channel_revision_url(channel: &str, base_url: &str) -> Option<Url> {
    if !pharos_core::valid_nix_channel(channel) {
        return None;
    }
    let base = safe_nixpkgs_channel_base_url(base_url)?;
    base.join(&format!("{channel}/git-revision")).ok()
}

fn safe_nixpkgs_channel_redirect(source: &Url, location: &str) -> Option<Url> {
    let target = source.join(location).ok()?;
    if target.scheme() != "https"
        || target.host_str().is_none()
        || !target.username().is_empty()
        || target.password().is_some()
        || target.query().is_some()
        || target.fragment().is_some()
        || !target.path().ends_with("/git-revision")
    {
        return None;
    }
    let same_host = target.host_str() == source.host_str()
        && target.port_or_known_default() == source.port_or_known_default();
    let official_release_redirect = source.host_str() == Some("channels.nixos.org")
        && target.host_str() == Some("releases.nixos.org")
        && target.path().starts_with("/nixos/");
    (same_host || official_release_redirect).then_some(target)
}

fn read_bounded_nixpkgs_revision(reader: impl Read) -> Option<String> {
    let mut body = String::new();
    reader
        .take(MAX_NIXPKGS_REVISION_BYTES + 1)
        .read_to_string(&mut body)
        .ok()?;
    ((body.len() as u64) <= MAX_NIXPKGS_REVISION_BYTES)
        .then_some(())
        .and_then(|()| exact_revision(&body))
}

fn fetch_nixpkgs_channel_revision(url: &Url) -> Option<String> {
    let agent: ureq::Agent = ureq::Agent::config_builder()
        .timeout_connect(Some(Duration::from_secs(5)))
        .timeout_send_request(Some(Duration::from_secs(5)))
        .timeout_recv_response(Some(Duration::from_secs(10)))
        .timeout_recv_body(Some(Duration::from_secs(10)))
        .timeout_global(Some(NIXPKGS_CHANNEL_TIMEOUT))
        .max_redirects(0)
        .build()
        .into();
    let response = agent.get(url.as_str()).call().ok()?;
    if response.status().is_success() {
        return read_bounded_nixpkgs_revision(response.into_body().into_reader());
    }
    if !matches!(response.status().as_u16(), 301 | 302 | 307 | 308) {
        return None;
    }
    let location = response.headers().get("location")?.to_str().ok()?;
    let target = safe_nixpkgs_channel_redirect(url, location)?;
    let response = agent.get(target.as_str()).call().ok()?;
    response
        .status()
        .is_success()
        .then(|| read_bounded_nixpkgs_revision(response.into_body().into_reader()))?
}

fn nixpkgs_comparison_from_revision(
    evidence: &NixDeploymentEvidence,
    upstream_revision: &str,
) -> Option<NixpkgsGitComparison> {
    let upstream_revision = exact_revision(upstream_revision)?;
    Some(NixpkgsGitComparison {
        relation: if upstream_revision == evidence.nixpkgs_revision {
            NixpkgsRevisionRelation::Current
        } else {
            NixpkgsRevisionRelation::Different
        },
        upstream_revision,
    })
}

fn is_official_nixpkgs_git_remote(remote: &str) -> bool {
    safe_git_remote(remote).as_deref() == safe_git_remote(OFFICIAL_NIXPKGS_GIT_REMOTE).as_deref()
}

fn nixpkgs_comparison(evidence: &NixDeploymentEvidence) -> Option<NixpkgsGitComparison> {
    if let Some(base_url) = env_value("PHAROS_NIXPKGS_CHANNEL_BASE_URL") {
        let url = nixpkgs_channel_revision_url(&evidence.nixpkgs_channel, &base_url)?;
        let revision = fetch_nixpkgs_channel_revision(&url)?;
        return nixpkgs_comparison_from_revision(evidence, &revision);
    }

    let remote = safe_git_remote(&env_value("PHAROS_NIXPKGS_REMOTE_URL")?)?;
    if is_official_nixpkgs_git_remote(&remote) {
        let url = nixpkgs_channel_revision_url(
            &evidence.nixpkgs_channel,
            DEFAULT_NIXPKGS_CHANNEL_BASE_URL,
        )?;
        let revision = fetch_nixpkgs_channel_revision(&url)?;
        nixpkgs_comparison_from_revision(evidence, &revision)
    } else {
        nixpkgs_git_comparison_from_remote(evidence, &remote)
    }
}

fn nixpkgs_git_comparison_from_remote(
    evidence: &NixDeploymentEvidence,
    remote: &str,
) -> Option<NixpkgsGitComparison> {
    let remote_ref = safe_git_branch_ref(&format!("refs/heads/{}", evidence.nixpkgs_channel))?;
    let output = git_output(&[
        "ls-remote".into(),
        "--exit-code".into(),
        "--refs".into(),
        remote.to_string(),
        remote_ref.clone(),
    ])?;
    let mut fields = output.split_whitespace();
    let upstream_revision = exact_revision(fields.next()?)?;
    (fields.next()? == remote_ref && fields.next().is_none()).then_some(())?;
    Some(NixpkgsGitComparison {
        relation: if upstream_revision == evidence.nixpkgs_revision {
            NixpkgsRevisionRelation::Current
        } else {
            NixpkgsRevisionRelation::Different
        },
        upstream_revision,
    })
}

fn freshness_log_summary(freshness: &NixFreshness) -> String {
    if !freshness.applicable {
        return "nix=n/a".to_string();
    }

    let generation = if freshness.deployment_evidence.is_some() {
        "verified"
    } else {
        "unverified"
    };
    let nixcfg = match freshness
        .nixcfg_comparison
        .as_ref()
        .map(|comparison| comparison.relation)
    {
        Some(GitRevisionRelation::Current) => "current",
        Some(GitRevisionRelation::Behind) => "behind",
        Some(GitRevisionRelation::Ahead) => "ahead",
        Some(GitRevisionRelation::Diverged) => "diverged",
        None => "unknown",
    };
    let nixpkgs = match freshness
        .nixpkgs_comparison
        .as_ref()
        .map(|comparison| comparison.relation)
    {
        Some(NixpkgsRevisionRelation::Current) => "current",
        Some(NixpkgsRevisionRelation::Different) => "different",
        None => "unknown",
    };
    format!("generation={generation}; nixcfg={nixcfg}; nixpkgs={nixpkgs}")
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum LocationMode {
    Off,
    Env,
    IpApi,
    Command,
}

impl LocationMode {
    fn from_env_value(value: Option<String>) -> Self {
        match value
            .as_deref()
            .map(str::trim)
            .map(str::to_ascii_lowercase)
            .as_deref()
        {
            Some("env") => Self::Env,
            Some("ip") | Some("ip-api") | Some("ipapi") | Some("geoip") => Self::IpApi,
            Some("command") | Some("cmd") | Some("provider-command") => Self::Command,
            _ => Self::Off,
        }
    }
}

const LOCATION_COMMAND_TIMEOUT_MS: u64 = 2_000;

fn env_value(key: &str) -> Option<String> {
    std::env::var(key)
        .ok()
        .map(|value| value.trim().to_string())
        .filter(|value| !value.is_empty())
}

fn parse_f64(value: Option<String>) -> Option<f64> {
    value
        .and_then(|value| value.parse::<f64>().ok())
        .filter(|value| value.is_finite())
}

fn parse_location_source(value: Option<String>, default: HostLocationSource) -> HostLocationSource {
    match value
        .as_deref()
        .map(str::trim)
        .map(str::to_ascii_lowercase)
        .as_deref()
    {
        Some("wifi") => HostLocationSource::Wifi,
        Some("ip") => HostLocationSource::Ip,
        Some("provider") => HostLocationSource::Provider,
        Some("unknown") => HostLocationSource::Unknown,
        _ => default,
    }
}

fn parse_u64(value: Option<String>) -> Option<u64> {
    value.and_then(|value| value.parse::<u64>().ok())
}

fn location_command_args_from_raw(raw: &str) -> Option<Vec<String>> {
    serde_json::from_str::<Vec<String>>(raw).ok()
}

fn location_command_args() -> Vec<String> {
    let Some(raw) = env_value("PHAROS_LOCATION_COMMAND_ARGS") else {
        return Vec::new();
    };
    match location_command_args_from_raw(&raw) {
        Some(args) => args,
        None => {
            eprintln!("pharos-beacon: location command args invalid");
            Vec::new()
        }
    }
}

fn location_command_timeout() -> Duration {
    let millis = parse_u64(env_value("PHAROS_LOCATION_COMMAND_TIMEOUT_MS"))
        .filter(|millis| (100..=30_000).contains(millis))
        .unwrap_or(LOCATION_COMMAND_TIMEOUT_MS);
    Duration::from_millis(millis)
}

fn location_from_env(now: i64) -> Option<HostLocation> {
    let location = HostLocation {
        latitude: parse_f64(env_value("PHAROS_LOCATION_LATITUDE"))?,
        longitude: parse_f64(env_value("PHAROS_LOCATION_LONGITUDE"))?,
        source: parse_location_source(
            env_value("PHAROS_LOCATION_SOURCE"),
            HostLocationSource::Unknown,
        ),
        accuracy_meters: parse_f64(env_value("PHAROS_LOCATION_ACCURACY_METERS")),
        precision_meters: parse_f64(env_value("PHAROS_LOCATION_PRECISION_METERS"))
            .or(Some(25_000.0)),
        observed_at: Some(now),
        stale: false,
        manual_override: false,
        label: env_value("PHAROS_LOCATION_LABEL"),
    };
    location.validate_contract().ok()?;
    Some(location)
}

fn json_f64(value: &serde_json::Value, keys: &[&str]) -> Option<f64> {
    keys.iter()
        .find_map(|key| value.get(*key)?.as_f64())
        .filter(|value| value.is_finite())
}

fn json_optional_f64(value: &serde_json::Value, key: &str) -> Option<f64> {
    value
        .get(key)
        .and_then(|value| value.as_f64())
        .filter(|value| value.is_finite())
}

fn location_from_command_json(raw: &str, now: i64) -> Option<HostLocation> {
    let value: serde_json::Value = serde_json::from_str(raw).ok()?;
    let source = parse_location_source(
        value
            .get("source")
            .and_then(|source| source.as_str())
            .map(str::to_string),
        HostLocationSource::Provider,
    );
    let location = HostLocation {
        latitude: json_f64(&value, &["latitude", "lat"])?,
        longitude: json_f64(&value, &["longitude", "lon"])?,
        source,
        accuracy_meters: json_optional_f64(&value, "accuracy_meters"),
        precision_meters: json_optional_f64(&value, "precision_meters").or(Some(25_000.0)),
        observed_at: value
            .get("observed_at")
            .and_then(|observed_at| observed_at.as_i64())
            .or(Some(now)),
        stale: false,
        manual_override: false,
        label: value
            .get("label")
            .and_then(|label| label.as_str())
            .map(str::to_string),
    };
    location.validate_contract().ok()?;
    Some(location)
}

#[derive(Debug)]
struct BoundedOutput {
    bytes: Vec<u8>,
    truncated: bool,
}

fn drain_bounded(
    mut pipe: impl Read + Send + 'static,
    limit: usize,
) -> mpsc::Receiver<Result<BoundedOutput, &'static str>> {
    let (sender, receiver) = mpsc::sync_channel(1);
    thread::spawn(move || {
        let mut retained = Vec::with_capacity(limit.min(8 * 1024));
        let mut truncated = false;
        let mut chunk = [0_u8; 8 * 1024];
        let result = loop {
            match pipe.read(&mut chunk) {
                Ok(0) => {
                    break Ok(BoundedOutput {
                        bytes: retained,
                        truncated,
                    });
                }
                Ok(read) => {
                    let remaining = limit.saturating_sub(retained.len());
                    let keep = remaining.min(read);
                    retained.extend_from_slice(&chunk[..keep]);
                    truncated |= keep < read;
                }
                Err(_) => break Err("output_read"),
            }
        };
        let _ = sender.send(result);
    });
    receiver
}

fn collect_bounded(
    receiver: &mpsc::Receiver<Result<BoundedOutput, &'static str>>,
    deadline: Instant,
) -> Result<BoundedOutput, &'static str> {
    receiver
        .recv_timeout(deadline.saturating_duration_since(Instant::now()))
        .map_err(|_| "output_timeout")?
}

#[cfg(unix)]
fn isolate_process_group(command: &mut Command) {
    use std::os::unix::process::CommandExt;
    command.process_group(0);
}

#[cfg(not(unix))]
fn isolate_process_group(_command: &mut Command) {}

fn terminate_process_tree(child: &mut std::process::Child) {
    #[cfg(unix)]
    if let Ok(group) = i32::try_from(child.id()) {
        // The child is started as its own process group so inherited collector
        // pipes cannot survive in a background descendant past the deadline.
        unsafe {
            libc::kill(-group, libc::SIGKILL);
        }
    }
    let _ = child.kill();
    let _ = child.wait();
}

fn wait_for_child(
    child: &mut std::process::Child,
    deadline: Instant,
) -> Result<ExitStatus, &'static str> {
    loop {
        match child.try_wait() {
            Ok(Some(status)) => return Ok(status),
            Ok(None) if Instant::now() < deadline => {
                thread::sleep(Duration::from_millis(20));
            }
            Ok(None) => {
                terminate_process_tree(child);
                return Err("timeout");
            }
            Err(_) => {
                terminate_process_tree(child);
                return Err("wait");
            }
        }
    }
}

fn output_string(output: BoundedOutput) -> Result<String, &'static str> {
    if output.truncated {
        return Err("output_limit");
    }
    String::from_utf8(output.bytes).map_err(|_| "output_encoding")
}

fn run_location_command(
    command: &str,
    args: &[String],
    timeout: Duration,
) -> Result<String, &'static str> {
    let mut command = Command::new(command);
    command
        .args(args)
        .stdout(Stdio::piped())
        .stderr(Stdio::null());
    isolate_process_group(&mut command);
    let mut child = command.spawn().map_err(|_| "spawn")?;
    let output = child
        .stdout
        .take()
        .map(|pipe| drain_bounded(pipe, LOCATION_COMMAND_OUTPUT_LIMIT_BYTES))
        .ok_or("stdout")?;
    let deadline = Instant::now() + timeout;
    let status = wait_for_child(&mut child, deadline)?;
    let stdout = match collect_bounded(&output, deadline).and_then(output_string) {
        Ok(stdout) => stdout,
        Err(error) => {
            terminate_process_tree(&mut child);
            return Err(error);
        }
    };
    if status.success() {
        Ok(stdout)
    } else {
        Err("exit")
    }
}

fn location_from_command(now: i64) -> Option<HostLocation> {
    let Some(command) = env_value("PHAROS_LOCATION_COMMAND") else {
        eprintln!("pharos-beacon: location command not configured");
        return None;
    };
    let raw = match run_location_command(
        &command,
        &location_command_args(),
        location_command_timeout(),
    ) {
        Ok(raw) => raw,
        Err(reason) => {
            eprintln!("pharos-beacon: location command failed: {reason}");
            return None;
        }
    };
    match location_from_command_json(&raw, now) {
        Some(location) => Some(location),
        None => {
            eprintln!("pharos-beacon: location command returned invalid location");
            None
        }
    }
}

fn location_label_from_parts(
    city: Option<&str>,
    region: Option<&str>,
    country: Option<&str>,
) -> Option<String> {
    let mut parts = Vec::new();
    for part in [city, region, country].into_iter().flatten() {
        let part = part.trim();
        if !part.is_empty()
            && !parts
                .iter()
                .any(|existing: &&str| existing.eq_ignore_ascii_case(part))
        {
            parts.push(part);
        }
    }
    if parts.is_empty() {
        None
    } else {
        Some(parts.join(", "))
    }
}

fn location_from_ip_api_json(raw: &str, now: i64, precision_meters: f64) -> Option<HostLocation> {
    let value: serde_json::Value = serde_json::from_str(raw).ok()?;
    if value
        .get("status")
        .and_then(|status| status.as_str())
        .is_some_and(|status| status != "success")
    {
        return None;
    }
    let location = HostLocation {
        latitude: value.get("lat")?.as_f64()?,
        longitude: value.get("lon")?.as_f64()?,
        source: HostLocationSource::Ip,
        accuracy_meters: None,
        precision_meters: Some(precision_meters),
        observed_at: Some(now),
        stale: false,
        manual_override: false,
        label: location_label_from_parts(
            value.get("city").and_then(|v| v.as_str()),
            value.get("regionName").and_then(|v| v.as_str()),
            value.get("countryCode").and_then(|v| v.as_str()),
        ),
    };
    location.validate_contract().ok()?;
    Some(location)
}

fn location_from_ip_api(now: i64) -> Option<HostLocation> {
    let url = env_value("PHAROS_LOCATION_IP_API_URL").unwrap_or_else(|| {
        "http://ip-api.com/json/?fields=status,lat,lon,city,regionName,countryCode".to_string()
    });
    let precision = parse_f64(env_value("PHAROS_LOCATION_PRECISION_METERS")).unwrap_or(50_000.0);
    let mut response = ureq::get(&url)
        .config()
        .timeout_global(Some(std::time::Duration::from_secs(3)))
        .max_redirects(0)
        .build()
        .call()
        .ok()?;
    let raw = response.body_mut().read_to_string().ok()?;
    location_from_ip_api_json(&raw, now, precision)
}

fn collect_location(now: i64) -> Option<HostLocation> {
    match LocationMode::from_env_value(env_value("PHAROS_LOCATION_MODE")) {
        LocationMode::Off => None,
        LocationMode::Env => location_from_env(now),
        LocationMode::IpApi => location_from_ip_api(now),
        LocationMode::Command => location_from_command(now),
    }
}

fn location_log_summary(location: Option<&HostLocation>) -> String {
    let Some(location) = location else {
        return "location=off".to_string();
    };
    let source = match location.source {
        HostLocationSource::Wifi => "wifi",
        HostLocationSource::Ip => "ip",
        HostLocationSource::Provider => "provider",
        HostLocationSource::Declared
        | HostLocationSource::Fallback
        | HostLocationSource::Unknown => "unknown",
    };
    let accuracy = location
        .accuracy_meters
        .map(|meters| format!("{meters:.0}m"))
        .unwrap_or_else(|| "unknown".to_string());
    let precision = location
        .precision_meters
        .map(|meters| format!("{meters:.0}m"))
        .unwrap_or_else(|| "unknown".to_string());
    format!("location={source}; accuracy={accuracy}; precision={precision}")
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum BackupMode {
    Off,
    Auto,
    Restic,
    StatusFile,
    Command,
}

impl BackupMode {
    fn from_env_value(value: Option<String>) -> Self {
        match value
            .as_deref()
            .map(str::trim)
            .map(str::to_ascii_lowercase)
            .as_deref()
        {
            Some("off") | Some("none") | Some("disabled") => Self::Off,
            Some("restic") => Self::Restic,
            Some("status-file") | Some("file") => Self::StatusFile,
            Some("command") | Some("cmd") => Self::Command,
            _ => Self::Auto,
        }
    }
}

const BACKUP_COMMAND_TIMEOUT_MS: u64 = 5_000;
const BACKUP_COMMAND_OUTPUT_LIMIT_BYTES: usize = 128 * 1024;
const DEFAULT_BACKUP_STALE_AFTER_SECS: i64 = 36 * 60 * 60;

#[derive(Debug)]
struct CommandCapture {
    success: bool,
    stdout: String,
    stderr: String,
}

fn backup_stale_after_secs() -> i64 {
    parse_u64(env_value("PHAROS_BACKUP_STALE_AFTER_SECS"))
        .and_then(|seconds| i64::try_from(seconds).ok())
        .filter(|seconds| (60..=31_536_000).contains(seconds))
        .unwrap_or(DEFAULT_BACKUP_STALE_AFTER_SECS)
}

fn backup_command_timeout() -> Duration {
    let millis = parse_u64(env_value("PHAROS_BACKUP_COMMAND_TIMEOUT_MS"))
        .filter(|millis| (100..=120_000).contains(millis))
        .unwrap_or(BACKUP_COMMAND_TIMEOUT_MS);
    Duration::from_millis(millis)
}

fn backup_command_args() -> Vec<String> {
    let Some(raw) = env_value("PHAROS_BACKUP_COMMAND_ARGS") else {
        return Vec::new();
    };
    match location_command_args_from_raw(&raw) {
        Some(args) => args,
        None => {
            eprintln!("pharos-beacon: backup command args invalid");
            Vec::new()
        }
    }
}

fn safe_backup_text(value: &str) -> bool {
    let value = value.trim();
    let lowered = value.to_ascii_lowercase();
    !value.is_empty()
        && !value.contains('\n')
        && !value.contains('\r')
        && !value.contains("://")
        && !value.contains('?')
        && !value.contains('#')
        && !lowered.contains("password")
        && !lowered.contains("secret=")
        && !lowered.contains("pass=")
}

fn safe_backup_env(key: &str) -> Option<String> {
    env_value(key).filter(|value| safe_backup_text(value))
}

fn validated_backup_observation(observation: BackupObservation) -> Option<BackupObservation> {
    observation.validate_contract().ok()?;
    Some(observation)
}

fn restic_observation_base(state: BackupPostureState, summary: &str) -> BackupObservation {
    BackupObservation {
        id: safe_backup_env("PHAROS_BACKUP_ID").unwrap_or_else(|| "restic-main".to_string()),
        label: safe_backup_env("PHAROS_BACKUP_LABEL")
            .unwrap_or_else(|| "Restic backup".to_string()),
        engine: BackupEngine::Restic,
        state,
        configured: BackupConfiguredState::Enabled,
        summary: summary.to_string(),
        target_label: safe_backup_env("PHAROS_BACKUP_TARGET_LABEL")
            .or_else(|| Some("off-box repository".to_string())),
        repository_id: safe_backup_env("PHAROS_BACKUP_REPOSITORY_ID"),
        schedule: safe_backup_env("PHAROS_BACKUP_SCHEDULE"),
        next_run_at: None,
        last_attempt_at: None,
        last_attempt_state: None,
        last_success_at: None,
        snapshot_count: None,
        total_bytes: None,
        latest_snapshot_bytes: None,
        last_check_at: None,
        last_check_state: None,
        restore_validation: None,
    }
}

fn backup_observations_from_json(raw: &str) -> Result<Vec<BackupObservation>, &'static str> {
    let parsed = serde_json::from_str::<Vec<BackupObservation>>(raw)
        .or_else(|_| serde_json::from_str::<BackupObservation>(raw).map(|one| vec![one]))
        .map_err(|_| "json")?;
    let mut observations = Vec::new();
    for observation in parsed {
        observation.validate_contract().map_err(|_| "contract")?;
        observations.push(observation);
    }
    Ok(observations)
}

fn collect_backup_status_file() -> Vec<BackupObservation> {
    let Some(path) = env_value("PHAROS_BACKUP_STATUS_FILE") else {
        return Vec::new();
    };
    let Ok(raw) = std::fs::read_to_string(&path) else {
        eprintln!("pharos-beacon: backup status file unavailable");
        return vec![restic_observation_base(
            BackupPostureState::Unknown,
            "backup status file unavailable",
        )]
        .into_iter()
        .filter_map(validated_backup_observation)
        .collect();
    };
    match backup_observations_from_json(&raw) {
        Ok(observations) => observations,
        Err(reason) => {
            eprintln!("pharos-beacon: backup status file invalid: {reason}");
            vec![restic_observation_base(
                BackupPostureState::Unknown,
                "backup status file invalid",
            )]
            .into_iter()
            .filter_map(validated_backup_observation)
            .collect()
        }
    }
}

fn run_capture_command(
    command: &str,
    args: &[String],
    timeout: Duration,
) -> Result<CommandCapture, &'static str> {
    let mut command = Command::new(command);
    command
        .args(args)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    isolate_process_group(&mut command);
    let mut child = command.spawn().map_err(|_| "spawn")?;
    let stdout = child
        .stdout
        .take()
        .map(|pipe| drain_bounded(pipe, BACKUP_COMMAND_OUTPUT_LIMIT_BYTES))
        .ok_or("stdout")?;
    let stderr = child
        .stderr
        .take()
        .map(|pipe| drain_bounded(pipe, BACKUP_COMMAND_OUTPUT_LIMIT_BYTES))
        .ok_or("stderr")?;
    let deadline = Instant::now() + timeout;
    let status = wait_for_child(&mut child, deadline)?;
    let stdout = match collect_bounded(&stdout, deadline).and_then(output_string) {
        Ok(stdout) => stdout,
        Err(error) => {
            terminate_process_tree(&mut child);
            return Err(error);
        }
    };
    let stderr = match collect_bounded(&stderr, deadline).and_then(output_string) {
        Ok(stderr) => stderr,
        Err(error) => {
            terminate_process_tree(&mut child);
            return Err(error);
        }
    };
    Ok(CommandCapture {
        success: status.success(),
        stdout,
        stderr,
    })
}

fn collect_backup_command(now: i64) -> Vec<BackupObservation> {
    let Some(command) = env_value("PHAROS_BACKUP_COMMAND") else {
        return Vec::new();
    };
    let result = run_capture_command(&command, &backup_command_args(), backup_command_timeout());
    match result {
        Ok(output) if output.success => match backup_observations_from_json(&output.stdout) {
            Ok(observations) => observations,
            Err(reason) => {
                eprintln!("pharos-beacon: backup command returned invalid JSON: {reason}");
                vec![command_backup_observation(
                    BackupPostureState::Unknown,
                    "backup command returned invalid status",
                    now,
                )]
            }
        },
        Ok(_) => vec![command_backup_observation(
            BackupPostureState::Failed,
            "backup command failed",
            now,
        )],
        Err(reason) => {
            eprintln!("pharos-beacon: backup command failed: {reason}");
            vec![command_backup_observation(
                BackupPostureState::Unknown,
                "backup command unavailable",
                now,
            )]
        }
    }
}

fn command_backup_observation(
    state: BackupPostureState,
    summary: &str,
    now: i64,
) -> BackupObservation {
    BackupObservation {
        id: safe_backup_env("PHAROS_BACKUP_ID").unwrap_or_else(|| "backup-command".to_string()),
        label: safe_backup_env("PHAROS_BACKUP_LABEL")
            .unwrap_or_else(|| "Backup collector".to_string()),
        engine: BackupEngine::Unknown,
        state,
        configured: BackupConfiguredState::Unknown,
        summary: summary.to_string(),
        target_label: safe_backup_env("PHAROS_BACKUP_TARGET_LABEL"),
        repository_id: safe_backup_env("PHAROS_BACKUP_REPOSITORY_ID"),
        schedule: safe_backup_env("PHAROS_BACKUP_SCHEDULE"),
        next_run_at: None,
        last_attempt_at: Some(now),
        last_attempt_state: if state == BackupPostureState::Failed {
            Some(BackupRunState::Failed)
        } else {
            Some(BackupRunState::Unknown)
        },
        last_success_at: None,
        snapshot_count: None,
        total_bytes: None,
        latest_snapshot_bytes: None,
        last_check_at: None,
        last_check_state: None,
        restore_validation: None,
    }
}

fn restic_repository_args_from_backup_options(raw: &str) -> Vec<String> {
    let parts: Vec<&str> = raw.split_whitespace().collect();
    let mut args = Vec::new();
    let mut idx = 0;
    while idx < parts.len() {
        match parts[idx] {
            "-r" | "--repo" | "--repository" => {
                if let Some(repo) = parts.get(idx + 1) {
                    args.push("-r".to_string());
                    args.push((*repo).to_string());
                    idx += 2;
                    continue;
                }
            }
            "--repository-file" => {
                if let Some(repo) = parts.get(idx + 1) {
                    args.push("--repository-file".to_string());
                    args.push((*repo).to_string());
                    idx += 2;
                    continue;
                }
            }
            value if value.starts_with("-r=") => {
                args.push("-r".to_string());
                args.push(value.trim_start_matches("-r=").to_string());
            }
            value if value.starts_with("--repo=") => {
                args.push("-r".to_string());
                args.push(value.trim_start_matches("--repo=").to_string());
            }
            value if value.starts_with("--repository=") => {
                args.push("-r".to_string());
                args.push(value.trim_start_matches("--repository=").to_string());
            }
            value if value.starts_with("--repository-file=") => {
                args.push("--repository-file".to_string());
                args.push(value.trim_start_matches("--repository-file=").to_string());
            }
            _ => {}
        }
        idx += 1;
    }
    args
}

fn restic_repository_args() -> Vec<String> {
    if let Some(repo) = env_value("RESTIC_REPOSITORY") {
        return vec!["-r".to_string(), repo];
    }
    if let Some(repo_file) = env_value("RESTIC_REPOSITORY_FILE") {
        return vec!["--repository-file".to_string(), repo_file];
    }
    env_value("RESTIC_BACKUP_OPTIONS")
        .map(|raw| restic_repository_args_from_backup_options(&raw))
        .unwrap_or_default()
}

fn collect_restic_repository(now: i64, explicit: bool) -> Vec<BackupObservation> {
    let repository_args = restic_repository_args();
    if repository_args.is_empty() {
        if explicit {
            return vec![BackupObservation {
                configured: BackupConfiguredState::Missing,
                ..restic_observation_base(
                    BackupPostureState::NotConfigured,
                    "restic repository not configured",
                )
            }]
            .into_iter()
            .filter_map(validated_backup_observation)
            .collect();
        }
        return Vec::new();
    }

    let restic = env_value("PHAROS_RESTIC_COMMAND").unwrap_or_else(|| "restic".to_string());
    let mut args = repository_args;
    args.extend([
        "snapshots".to_string(),
        "--json".to_string(),
        "--latest".to_string(),
        "1".to_string(),
    ]);
    match run_capture_command(&restic, &args, backup_command_timeout()) {
        Ok(output) if output.success => {
            vec![restic_snapshot_observation(
                &output.stdout,
                now,
                backup_stale_after_secs(),
            )]
        }
        Ok(output) => vec![restic_error_observation(&output.stderr, now)],
        Err("spawn") if explicit => vec![BackupObservation {
            configured: BackupConfiguredState::Unknown,
            ..restic_observation_base(BackupPostureState::Unknown, "restic command unavailable")
        }]
        .into_iter()
        .filter_map(validated_backup_observation)
        .collect(),
        Err("spawn") => Vec::new(),
        Err(_) => vec![restic_error_observation("timeout", now)],
    }
}

fn restic_error_observation(stderr: &str, now: i64) -> BackupObservation {
    let lower = stderr.to_ascii_lowercase();
    let (state, summary) = if lower.contains("lock") {
        (BackupPostureState::Warning, "restic repository locked")
    } else if lower.contains("no repository")
        || lower.contains("repository does not exist")
        || lower.contains("unable to open config file")
    {
        (BackupPostureState::Missing, "restic repository missing")
    } else if lower.contains("password")
        || lower.contains("authentication")
        || lower.contains("permission denied")
        || lower.contains("wrong password")
    {
        (BackupPostureState::Failed, "restic authentication failed")
    } else {
        (BackupPostureState::Failed, "restic snapshot probe failed")
    };
    BackupObservation {
        last_attempt_at: Some(now),
        last_attempt_state: Some(BackupRunState::Failed),
        ..restic_observation_base(state, summary)
    }
}

fn parse_restic_latest_snapshot(raw: &str) -> Result<(i64, u64), &'static str> {
    let value: serde_json::Value = serde_json::from_str(raw).map_err(|_| "json")?;
    let snapshots = value.as_array().ok_or("array")?;
    let mut latest = None;
    for snapshot in snapshots {
        let Some(time) = snapshot.get("time").and_then(|time| time.as_str()) else {
            continue;
        };
        let parsed = parse_rfc3339_unix(time).ok_or("time")?;
        latest = Some(latest.map_or(parsed, |existing: i64| existing.max(parsed)));
    }
    let count = u64::try_from(snapshots.len()).unwrap_or(u64::MAX);
    latest.map(|time| (time, count)).ok_or("empty")
}

fn restic_snapshot_observation(raw: &str, now: i64, stale_after_secs: i64) -> BackupObservation {
    match parse_restic_latest_snapshot(raw) {
        Ok((last_success_at, snapshot_count)) => {
            let age = now.saturating_sub(last_success_at);
            let state = if age > stale_after_secs {
                BackupPostureState::Stale
            } else {
                BackupPostureState::Healthy
            };
            let summary = if state == BackupPostureState::Stale {
                "last restic snapshot is stale"
            } else {
                "last restic snapshot is fresh"
            };
            BackupObservation {
                state,
                summary: summary.to_string(),
                last_attempt_at: Some(last_success_at),
                last_attempt_state: Some(BackupRunState::Succeeded),
                last_success_at: Some(last_success_at),
                snapshot_count: Some(snapshot_count),
                ..restic_observation_base(state, summary)
            }
        }
        Err("empty") => BackupObservation {
            configured: BackupConfiguredState::Enabled,
            last_attempt_at: Some(now),
            last_attempt_state: Some(BackupRunState::Unknown),
            snapshot_count: Some(0),
            ..restic_observation_base(BackupPostureState::Missing, "no restic snapshots observed")
        },
        Err(_) => BackupObservation {
            configured: BackupConfiguredState::Unknown,
            last_attempt_at: Some(now),
            last_attempt_state: Some(BackupRunState::Unknown),
            ..restic_observation_base(
                BackupPostureState::Unknown,
                "restic snapshot metadata invalid",
            )
        },
    }
}

fn parse_rfc3339_unix(raw: &str) -> Option<i64> {
    let raw = raw.trim();
    if raw.len() < 20 {
        return None;
    }
    let year = raw.get(0..4)?.parse::<i64>().ok()?;
    let month = raw.get(5..7)?.parse::<i64>().ok()?;
    let day = raw.get(8..10)?.parse::<i64>().ok()?;
    let hour = raw.get(11..13)?.parse::<i64>().ok()?;
    let minute = raw.get(14..16)?.parse::<i64>().ok()?;
    let second = raw.get(17..19)?.parse::<i64>().ok()?;
    let after_time = raw.get(19..)?;
    let tz_start = after_time.find(['Z', '+', '-']).map(|index| 19 + index)?;
    let tz = raw.get(tz_start..)?;
    let offset_seconds = if tz == "Z" {
        0
    } else {
        let sign = match tz.as_bytes().first().copied()? {
            b'+' => 1,
            b'-' => -1,
            _ => return None,
        };
        let hours = tz.get(1..3)?.parse::<i64>().ok()?;
        let minutes = tz.get(4..6)?.parse::<i64>().ok()?;
        sign * ((hours * 60 + minutes) * 60)
    };
    if !(1..=12).contains(&month)
        || !(1..=31).contains(&day)
        || !(0..=23).contains(&hour)
        || !(0..=59).contains(&minute)
        || !(0..=60).contains(&second)
    {
        return None;
    }
    Some(
        days_from_civil(year, month, day) * 86_400 + hour * 3600 + minute * 60 + second
            - offset_seconds,
    )
}

fn days_from_civil(mut year: i64, month: i64, day: i64) -> i64 {
    year -= if month <= 2 { 1 } else { 0 };
    let era = if year >= 0 { year } else { year - 399 } / 400;
    let year_of_era = year - era * 400;
    let month_prime = month + if month > 2 { -3 } else { 9 };
    let day_of_year = (153 * month_prime + 2) / 5 + day - 1;
    let day_of_era = year_of_era * 365 + year_of_era / 4 - year_of_era / 100 + day_of_year;
    era * 146_097 + day_of_era - 719_468
}

fn collect_backup_observations(now: i64) -> Vec<BackupObservation> {
    match BackupMode::from_env_value(env_value("PHAROS_BACKUP_MODE")) {
        BackupMode::Off => Vec::new(),
        BackupMode::StatusFile => collect_backup_status_file(),
        BackupMode::Command => collect_backup_command(now),
        BackupMode::Restic => collect_restic_repository(now, true),
        BackupMode::Auto => {
            let mut observations = collect_backup_status_file();
            if observations.is_empty() {
                observations = collect_backup_command(now);
            }
            if observations.is_empty() {
                observations = collect_restic_repository(now, false);
            }
            observations
        }
    }
}

fn backup_log_summary(observations: &[BackupObservation]) -> String {
    if observations.is_empty() {
        return "backup=not-observed".to_string();
    }
    let state = if observations
        .iter()
        .any(|observation| observation.state == BackupPostureState::Failed)
    {
        "failed"
    } else if observations
        .iter()
        .any(|observation| observation.state == BackupPostureState::Missing)
    {
        "missing"
    } else if observations
        .iter()
        .any(|observation| observation.state == BackupPostureState::Stale)
    {
        "stale"
    } else if observations
        .iter()
        .any(|observation| observation.state == BackupPostureState::Warning)
    {
        "warning"
    } else if observations
        .iter()
        .any(|observation| observation.state == BackupPostureState::Healthy)
    {
        "healthy"
    } else {
        "unknown"
    };
    format!("backup={state}; backup_observations={}", observations.len())
}

fn success_log_line(
    host: &str,
    endpoint: &str,
    status: u16,
    freshness: &NixFreshness,
    location: Option<&HostLocation>,
    backup_observations: &[BackupObservation],
) -> String {
    format!(
        "pharos-beacon: reported {host} -> {endpoint} (HTTP {status}; {}; {}; {})",
        freshness_log_summary(freshness),
        location_log_summary(location),
        backup_log_summary(backup_observations)
    )
}

fn reporting_interval() -> Result<Option<u64>, &'static str> {
    match std::env::var("PHAROS_INTERVAL") {
        Ok(raw) => {
            let seconds = raw.parse::<u64>().map_err(|_| "invalid_interval")?;
            RequestDeadlines::for_cadence(seconds)?;
            Ok(Some(seconds))
        }
        Err(std::env::VarError::NotPresent) => Ok(None),
        Err(std::env::VarError::NotUnicode(_)) => Err("invalid_interval"),
    }
}

fn main() {
    if std::env::args_os().nth(1).as_deref() == Some(std::ffi::OsStr::new("healthcheck")) {
        // Container probe (PHAROS-203/204): healthy only if this beacon
        // reported successfully within the staleness window; every other
        // verdict prints its reason for `docker inspect`.
        match beacon_container_healthcheck() {
            Ok(detail) => {
                println!("pharos-beacon healthcheck: {detail}");
                std::process::exit(0);
            }
            Err(problem) => {
                eprintln!("pharos-beacon healthcheck: {problem}");
                std::process::exit(1);
            }
        }
    }

    let base = env_value("PHAROS_URL").unwrap_or_else(|| {
        eprintln!("pharos-beacon: PHAROS_URL is required");
        std::process::exit(2);
    });
    let endpoint = report_endpoint(&base).unwrap_or_else(|_| {
        eprintln!("pharos-beacon: PHAROS_URL is invalid or unsafe");
        std::process::exit(2);
    });
    let host = hostname();
    let is_nix = Path::new("/etc/NIXOS").exists();
    let dir = nixcfg_dir();
    let role = std::env::var("PHAROS_ROLE").unwrap_or_else(|_| "server".into());
    let token = bearer_token().unwrap_or_else(|error| {
        eprintln!("pharos-beacon: {error}");
        std::process::exit(2);
    });
    let preferences_path = env_value("PHAROS_PREFERENCES_FILE").map(std::path::PathBuf::from);
    let mut preferences = HostPreferences::default();
    let mut preferences_error_reported = false;
    let mut preferences_apply_error: Option<PreferencesApplyError> = None;

    // PHAROS_INTERVAL (secs) set => loop forever (recurring service);
    // unset => report once and exit (one-shot / timer-driven).
    let interval = reporting_interval().unwrap_or_else(|_| {
        eprintln!(
            "pharos-beacon: PHAROS_INTERVAL must be between {MIN_HEARTBEAT_INTERVAL_SECS} and {MAX_HEARTBEAT_INTERVAL_SECS} seconds"
        );
        std::process::exit(2);
    });
    let beat = interval.unwrap_or(60);
    let deadlines = RequestDeadlines::for_cadence(beat).expect("default cadence is valid");
    let agent = deadlines.agent();
    let mut last_report_rtt_ms: Option<u64> = None;
    let mut consecutive_failures = 0_u32;
    let health_path = beacon_health_path();
    let generation = match ProcessGeneration::current() {
        Ok(generation) => Some(generation),
        Err(err) => {
            if interval.is_some() {
                eprintln!(
                    "pharos-beacon: cannot determine this process's generation ({err}); the container healthcheck will stay unhealthy"
                );
            }
            None
        }
    };
    if let (Some(_), Some(generation)) = (interval, generation.as_ref()) {
        if let Err(reason) = initialize_beacon_health(&health_path, generation) {
            eprintln!("pharos-beacon: {reason}; the container healthcheck will stay unhealthy");
        }
    }
    systemd_notify("READY=1\nSTATUS=Waiting for first successful report");

    loop {
        if let Some(path) = preferences_path.as_deref() {
            match read_host_preferences(path, &host) {
                Ok(next) => {
                    preferences = next;
                    preferences_error_reported = false;
                }
                Err(error) if !preferences_error_reported => {
                    eprintln!("pharos-beacon: {error}; keeping last valid host preferences");
                    preferences_error_reported = true;
                }
                Err(_) => {}
            }
        }
        let freshness = if is_nix {
            let evidence = read_deployment_evidence(&deployment_evidence_path());
            let matching_lock = match (dir.as_deref(), evidence.as_ref()) {
                (Some(dir), Some(evidence)) => matching_flake_lock(dir, evidence),
                _ => None,
            };
            let nixpkgs = match (matching_lock.as_ref(), evidence.as_ref()) {
                (Some(lock), Some(evidence)) => nixpkgs_freshness(lock, evidence),
                _ => None,
            };
            let nixcfg_comparison = match (dir.as_deref(), evidence.as_ref()) {
                (Some(dir), Some(evidence)) => {
                    nixcfg_git_comparison(dir, &evidence.source_revision)
                }
                _ => None,
            };
            let channel_comparison = evidence.as_ref().and_then(nixpkgs_comparison);
            NixFreshness {
                applicable: true,
                flake_lock_age_days: matching_lock.as_ref().and_then(flake_lock_age_days),
                commits_behind: nixcfg_comparison
                    .as_ref()
                    .and_then(|comparison| comparison.commits_behind),
                nixpkgs_age_days: evidence
                    .as_ref()
                    .and_then(|evidence| days_since(evidence.nixpkgs_last_modified)),
                nixpkgs_channel: evidence
                    .as_ref()
                    .map(|evidence| evidence.nixpkgs_channel.clone()),
                secondary_nixpkgs: nixpkgs.and_then(|freshness| freshness.secondary),
                deployment_evidence: evidence,
                nixcfg_comparison,
                nixpkgs_comparison: channel_comparison,
            }
        } else {
            NixFreshness::default()
        };
        let mut service_observations = vec![ServiceObservation::nix_freshness(&freshness)];
        if let Some(error) = preferences_apply_error {
            service_observations.push(error.observation());
        }
        let observed_at = now_unix();
        let kernel = collect_kernel_posture(is_nix, observed_at);
        let location = collect_location(observed_at);
        let backup_observations = collect_backup_observations(observed_at);
        let report = HostReport {
            schema: HOST_REPORT_SCHEMA.to_string(),
            version: HOST_REPORT_VERSION,
            name: host.clone(),
            role: role.clone(),
            is_nix,
            heartbeat_interval_secs: beat,
            freshness,
            kernel: Some(kernel),
            service_observations,
            backup_observations,
            inbound_rtt_ms: last_report_rtt_ms,
            location,
            preferences: preferences.clone(),
        };
        if report.validate_contract().is_err() {
            eprintln!("pharos-beacon: locally collected report violates the report contract");
            std::process::exit(2);
        }
        let body = serde_json::to_string(&report).expect("serialize report");
        let mut request = agent
            .post(&endpoint.request_url)
            .header("Content-Type", "application/json");
        if let Some(token) = &token {
            request = request.header("Authorization", &format!("Bearer {token}"));
        }
        let started = Instant::now();
        let report_succeeded = match request.send(body.as_str()) {
            Ok(resp) if resp.status().is_success() => {
                let status = resp.status().as_u16();
                last_report_rtt_ms = Some(report_rtt_millis(started.elapsed()));
                consecutive_failures = 0;
                if generation.as_ref().is_some_and(|generation| {
                    write_beacon_health(&health_path, now_unix(), generation).is_err()
                }) {
                    eprintln!(
                        "pharos-beacon: could not refresh container health state at {}",
                        health_path.display()
                    );
                }
                systemd_notify("WATCHDOG=1\nSTATUS=Last report succeeded");
                println!(
                    "{}",
                    success_log_line(
                        &host,
                        &endpoint.safe_origin,
                        status,
                        &report.freshness,
                        report.location.as_ref(),
                        &report.backup_observations
                    )
                );
                match apply_report_http_response(resp, &host, is_nix, preferences_path.as_deref()) {
                    Ok(Some(applied)) => {
                        preferences = applied;
                        preferences_apply_error = None;
                        println!("pharos-beacon: applied pending host settings");
                    }
                    Ok(None) => {
                        preferences_apply_error = None;
                    }
                    Err(error) => {
                        preferences_apply_error = Some(error);
                        eprintln!(
                            "pharos-beacon: pending host settings were not applied ({})",
                            error.code()
                        );
                    }
                }
                true
            }
            Ok(_) => {
                last_report_rtt_ms = None;
                consecutive_failures = consecutive_failures.saturating_add(1);
                systemd_notify("STATUS=Report failed; retrying");
                eprintln!("pharos-beacon: report failed (unexpected HTTP status)");
                false
            }
            Err(_) => {
                last_report_rtt_ms = None;
                consecutive_failures = consecutive_failures.saturating_add(1);
                systemd_notify("STATUS=Report failed; retrying");
                eprintln!("pharos-beacon: report failed (transport or HTTP error)");
                false
            }
        };
        let Some(cadence) = interval else {
            if !report_succeeded {
                std::process::exit(1);
            }
            break;
        };
        if report_succeeded {
            thread::sleep(Duration::from_secs(cadence));
        } else {
            thread::sleep(retry_delay(cadence, consecutive_failures, jitter_seed()));
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn generation() -> ProcessGeneration {
        ProcessGeneration::current().expect("current process generation")
    }

    fn write_marker(path: &Path, last_success_at: i64) -> std::io::Result<()> {
        write_beacon_health(path, last_success_at, &generation())
    }

    /// Locked observe-then-unlink, as startup does after a failed reset.
    fn invalidate_marker(path: &Path) -> Result<&'static str, String> {
        let lock = lock_beacon_health(path)?;
        let observed = observe_beacon_health_marker(path).map_err(|err| err.to_string())?;
        invalidate_beacon_health_locked(path, &observed, &lock)
    }

    /// The marker's last-success field, whoever wrote it.
    fn marker_stamp(path: &Path) -> String {
        std::fs::read_to_string(path)
            .expect("marker readable")
            .split_whitespace()
            .nth(1)
            .expect("marker stamp")
            .to_string()
    }

    fn kernel_fixture(label: &str) -> PathBuf {
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("clock after epoch")
            .as_nanos();
        std::env::temp_dir().join(format!(
            "pharos-kernel-{}-{nonce}-{label}",
            std::process::id()
        ))
    }

    fn write_kernel_fixture(root: &Path, running: &str, expected: &[&str]) -> (PathBuf, PathBuf) {
        let running_path = root.join("osrelease");
        let expected_path = root.join("modules");
        std::fs::create_dir_all(&expected_path).expect("create module fixture");
        std::fs::write(&running_path, running).expect("write running version");
        for version in expected {
            std::fs::create_dir(expected_path.join(version)).expect("create version fixture");
        }
        (running_path, expected_path)
    }

    #[test]
    fn beacon_reads_exact_nixcfg_host_preferences_schema() {
        let raw = r##"{
          "schema": "inspr.pharos.host-preferences.v1",
          "version": 1,
          "hosts": {
            "gpc0": {
              "accent": "#9868d0",
              "kind": "workstation",
              "alerts": {
                "suppress_backup": false,
                "suppress_down": true,
                "suppress_nix_freshness": true
              }
            }
          }
        }"##;

        let preferences = parse_host_preferences(raw, "gpc0").expect("preferences parse");
        assert_eq!(preferences.accent.as_deref(), Some("#9868d0"));
        assert_eq!(preferences.kind, pharos_core::HostKind::Workstation);
        assert!(preferences.alerts.suppress_down);
        assert!(preferences.alerts.suppress_nix_freshness);
    }

    #[test]
    fn beacon_rejects_unknown_preferences_and_keeps_previous_state_available() {
        let extended = r##"{
          "schema": "inspr.pharos.host-preferences.v1",
          "version": 1,
          "hosts": {
            "gpc0": {
              "accent": "#9868d0",
              "kind": "workstation",
              "alerts": {
                "suppress_backup": false,
                "suppress_down": false,
                "suppress_nix_freshness": false
              },
              "command": "rebuild"
            }
          }
        }"##;
        let previous = HostPreferences::default();

        assert!(parse_host_preferences(extended, "gpc0").is_err());
        assert!(parse_host_preferences(
            r#"{"schema":"inspr.pharos.host-preferences.v1","version":1,"hosts":{}}"#,
            "gpc0"
        )
        .is_err());
        assert_eq!(previous, HostPreferences::default());
    }

    #[test]
    fn pending_preferences_are_atomically_written_as_the_shared_registry() {
        let root = kernel_fixture("pending-preferences");
        std::fs::create_dir(&root).expect("create preferences fixture");
        let path = root.join("host-preferences.json");
        let preferences = HostPreferences {
            accent: Some("#48b8a8".to_string()),
            kind: pharos_core::HostKind::Workstation,
            alerts: pharos_core::HostAlertPreferences {
                suppress_down: false,
                suppress_backup: true,
                suppress_nix_freshness: false,
            },
        };
        let response = HostReportResponse::pending("gpc0", preferences.clone())
            .expect("pending response validates");
        let body = serde_json::to_string(&response).expect("response serializes");

        let applied = apply_report_response(&body, "gpc0", false, Some(&path))
            .expect("pending preferences apply");
        assert_eq!(applied, Some(preferences.clone()));
        assert_eq!(
            read_host_preferences(&path, "gpc0").expect("written registry parses"),
            preferences
        );
        #[cfg(unix)]
        assert_eq!(
            std::fs::metadata(&path)
                .expect("preferences metadata")
                .permissions()
                .mode()
                & 0o777,
            0o600
        );
        assert_eq!(
            std::fs::read_dir(&root)
                .expect("fixture directory readable")
                .count(),
            1,
            "atomic apply must not leave temporary files behind"
        );
        std::fs::remove_dir_all(root).expect("remove preferences fixture");
    }

    #[test]
    fn invalid_or_misdirected_pending_preferences_keep_the_previous_file() {
        let root = kernel_fixture("invalid-pending-preferences");
        std::fs::create_dir(&root).expect("create preferences fixture");
        let path = root.join("host-preferences.json");
        let previous = HostPreferences {
            accent: Some("#1f7fb5".to_string()),
            ..Default::default()
        };
        let initial = HostReportResponse::pending("gpc0", previous.clone())
            .expect("initial response validates");
        apply_report_response(
            &serde_json::to_string(&initial).expect("initial response serializes"),
            "gpc0",
            false,
            Some(&path),
        )
        .expect("initial preferences apply");
        let previous_bytes = std::fs::read(&path).expect("read previous registry");

        let invalid = r##"{
          "schema":"inspr.pharos.report-response.v1",
          "version":1,
          "pending_preferences":{
            "schema":"inspr.pharos.host-preferences.v1",
            "version":1,
            "hosts":{
              "gpc0":{
                "accent":"#48b8a8",
                "kind":"workstation",
                "alerts":{},
                "command":"rebuild"
              }
            }
          }
        }"##;
        assert_eq!(
            apply_report_response(invalid, "gpc0", false, Some(&path)),
            Err(PreferencesApplyError::InvalidResponse)
        );

        let wrong_host = HostReportResponse::pending(
            "athena",
            HostPreferences {
                accent: Some("#48b8a8".to_string()),
                ..Default::default()
            },
        )
        .expect("other host response validates for its host");
        assert_eq!(
            apply_report_response(
                &serde_json::to_string(&wrong_host).expect("response serializes"),
                "gpc0",
                false,
                Some(&path),
            ),
            Err(PreferencesApplyError::HostMismatch)
        );
        assert_eq!(
            std::fs::read(&path).expect("previous registry remains"),
            previous_bytes
        );
        std::fs::remove_dir_all(root).expect("remove preferences fixture");
    }

    #[test]
    fn pending_preferences_require_a_non_nix_host_and_configured_file() {
        let response = HostReportResponse::pending(
            "gpc0",
            HostPreferences {
                accent: Some("#48b8a8".to_string()),
                ..Default::default()
            },
        )
        .expect("pending response validates");
        let body = serde_json::to_string(&response).expect("response serializes");

        assert_eq!(
            apply_report_response(&body, "gpc0", false, None),
            Err(PreferencesApplyError::NotConfigured)
        );
        assert_eq!(
            apply_report_response(
                &body,
                "gpc0",
                true,
                Some(Path::new("/unused/preferences.json")),
            ),
            Err(PreferencesApplyError::UnsupportedOnNix)
        );
        let observation = PreferencesApplyError::WriteFailed.observation();
        assert_eq!(observation.id, "host-preferences");
        assert_eq!(observation.state, ServiceObservationState::Warning);
        assert_eq!(
            observation.summary,
            "settings apply failed: atomic_write_failed"
        );
    }

    #[test]
    fn pending_preferences_response_body_is_bounded() {
        let at_limit = vec![b' '; MAX_REPORT_RESPONSE_BYTES as usize];
        assert_eq!(
            read_bounded_report_response(std::io::Cursor::new(at_limit))
                .expect("body at limit is accepted")
                .len(),
            MAX_REPORT_RESPONSE_BYTES as usize
        );
        let oversized = vec![b' '; MAX_REPORT_RESPONSE_BYTES as usize + 1];
        assert_eq!(
            read_bounded_report_response(std::io::Cursor::new(oversized)),
            Err(PreferencesApplyError::InvalidResponse)
        );
    }

    #[test]
    fn report_rtt_millis_is_protocol_bounded() {
        assert_eq!(report_rtt_millis(Duration::from_nanos(1)), 1);
        assert_eq!(report_rtt_millis(Duration::from_millis(42)), 42);
        assert_eq!(
            report_rtt_millis(Duration::from_millis(MAX_INBOUND_RTT_MS + 1)),
            MAX_INBOUND_RTT_MS
        );
    }

    #[test]
    fn kernel_collector_reports_current_and_staged_versions() {
        let current_root = kernel_fixture("current");
        let (running, expected) =
            write_kernel_fixture(&current_root, "7.0.14-nixos\n", &["7.0.14"]);
        let current = collect_kernel_posture_at(true, 100, &running, &expected);
        assert_eq!(current.state, pharos_core::KernelPostureState::Current);
        assert_eq!(current.running_version.as_deref(), Some("7.0.14-nixos"));
        assert_eq!(current.expected_version.as_deref(), Some("7.0.14"));
        current.validate_contract().expect("current posture valid");
        std::fs::remove_dir_all(current_root).expect("remove current fixture");

        let staged_root = kernel_fixture("staged");
        let (running, expected) = write_kernel_fixture(&staged_root, "6.18.26\n", &["7.0.14"]);
        let staged = collect_kernel_posture_at(true, 200, &running, &expected);
        assert_eq!(
            staged.state,
            pharos_core::KernelPostureState::RebootRequired
        );
        staged.validate_contract().expect("staged posture valid");
        std::fs::remove_dir_all(staged_root).expect("remove staged fixture");
    }

    #[test]
    fn kernel_collector_fails_multiple_missing_and_malformed_versions_safe() {
        let root = kernel_fixture("unknown");
        let (running, expected) = write_kernel_fixture(&root, "7.0.14\n", &["7.0.14", "7.1.0"]);
        let multiple = collect_kernel_posture_at(true, 300, &running, &expected);
        assert_eq!(multiple.state, pharos_core::KernelPostureState::Unknown);
        assert!(multiple.expected_version.is_none());

        let missing = collect_kernel_posture_at(true, 301, &running, &root.join("missing"));
        assert_eq!(missing.state, pharos_core::KernelPostureState::Unknown);

        std::fs::write(&running, "/nix/store/not-a-version\n").expect("write malformed version");
        let malformed = collect_kernel_posture_at(true, 302, &running, &expected);
        assert_eq!(malformed.state, pharos_core::KernelPostureState::Unknown);
        assert!(malformed.running_version.is_none());
        std::fs::remove_dir_all(root).expect("remove unknown fixture");
    }

    #[test]
    fn kernel_collector_marks_non_nix_hosts_not_applicable() {
        let posture = collect_kernel_posture_at(
            false,
            400,
            Path::new("/path/that/does/not/exist"),
            Path::new("/another/missing/path"),
        );

        assert_eq!(
            posture.state,
            pharos_core::KernelPostureState::NotApplicable
        );
        assert!(posture.expected_version.is_none());
        posture.validate_contract().expect("non-Nix posture valid");
    }

    #[test]
    fn success_log_line_keeps_operational_context_without_report_body() {
        let line = success_log_line(
            "hsb8",
            "http://pharos.example/report",
            204,
            &NixFreshness {
                applicable: true,
                flake_lock_age_days: Some(1),
                commits_behind: Some(0),
                nixpkgs_age_days: None,
                nixpkgs_channel: None,
                secondary_nixpkgs: None,
                deployment_evidence: None,
                nixcfg_comparison: None,
                nixpkgs_comparison: None,
            },
            None,
            &[],
        );

        assert!(line.contains("hsb8"));
        assert!(line.contains("http://pharos.example/report"));
        assert!(line.contains("HTTP 204"));
        assert!(line.contains("generation=unverified"));
        assert!(line.contains("nixcfg=unknown"));
        assert!(line.contains("nixpkgs=unknown"));
        assert!(line.contains("location=off"));
        assert!(!line.contains("\"name\""));
        assert!(!line.contains("heartbeat_interval_secs"));
        assert!(!line.contains("freshness"));
    }

    #[test]
    fn success_log_line_handles_non_nix_hosts() {
        let line = success_log_line(
            "hermes",
            "http://pharos.example/report",
            204,
            &NixFreshness::default(),
            None,
            &[],
        );

        assert!(line.contains("nix=n/a"));
        assert!(!line.contains("\"applicable\""));
    }

    #[test]
    fn backup_mode_defaults_to_auto_and_supports_explicit_collectors() {
        assert_eq!(BackupMode::from_env_value(None), BackupMode::Auto);
        assert_eq!(
            BackupMode::from_env_value(Some(" off ".to_string())),
            BackupMode::Off
        );
        assert_eq!(
            BackupMode::from_env_value(Some("restic".to_string())),
            BackupMode::Restic
        );
        assert_eq!(
            BackupMode::from_env_value(Some("status-file".to_string())),
            BackupMode::StatusFile
        );
        assert_eq!(
            BackupMode::from_env_value(Some("command".to_string())),
            BackupMode::Command
        );
    }

    #[test]
    fn restic_backup_options_extract_repository_only() {
        assert_eq!(
            restic_repository_args_from_backup_options(
                "-r sftp:backup.example.invalid:/ --host csb1 --verbose"
            ),
            vec![
                "-r".to_string(),
                "sftp:backup.example.invalid:/".to_string()
            ]
        );
        assert_eq!(
            restic_repository_args_from_backup_options(
                "--repository=sftp:backup.example.invalid:/ --password-file /run/secret"
            ),
            vec![
                "-r".to_string(),
                "sftp:backup.example.invalid:/".to_string()
            ]
        );
        assert_eq!(
            restic_repository_args_from_backup_options(
                "--repository-file /run/agenix/restic-repository --password-file /run/agenix/restic-password"
            ),
            vec![
                "--repository-file".to_string(),
                "/run/agenix/restic-repository".to_string()
            ]
        );
        assert_eq!(
            restic_repository_args_from_backup_options(
                "--repository-file=/run/agenix/restic-repository --password-file /run/agenix/restic-password"
            ),
            vec![
                "--repository-file".to_string(),
                "/run/agenix/restic-repository".to_string()
            ]
        );
        assert!(restic_repository_args_from_backup_options("--host csb1").is_empty());
    }

    #[test]
    fn rfc3339_parser_handles_utc_and_offsets() {
        assert_eq!(parse_rfc3339_unix("1970-01-01T00:00:00Z"), Some(0));
        assert_eq!(parse_rfc3339_unix("1970-01-01T01:00:00+01:00"), Some(0));
        assert_eq!(parse_rfc3339_unix("1969-12-31T23:00:00-01:00"), Some(0));
        assert!(parse_rfc3339_unix("not a timestamp").is_none());
    }

    #[test]
    fn restic_snapshot_metadata_classifies_healthy_stale_and_missing() {
        let raw = r#"[{
            "time": "2023-11-14T21:13:20Z",
            "hostname": "csb1",
            "paths": ["/backup/home"],
            "id": "abcdef"
        }]"#;

        let healthy = restic_snapshot_observation(raw, 1_700_000_000, 7_200);
        assert_eq!(healthy.state, BackupPostureState::Healthy);
        assert_eq!(healthy.last_success_at, Some(1_699_996_400));
        assert_eq!(healthy.last_attempt_state, Some(BackupRunState::Succeeded));
        assert_eq!(healthy.snapshot_count, Some(1));
        assert!(!serde_json::to_string(&healthy)
            .unwrap()
            .contains("/backup/home"));

        let stale = restic_snapshot_observation(raw, 1_700_000_000, 60);
        assert_eq!(stale.state, BackupPostureState::Stale);

        let missing = restic_snapshot_observation("[]", 1_700_000_000, 7_200);
        assert_eq!(missing.state, BackupPostureState::Missing);
        assert_eq!(missing.snapshot_count, Some(0));
    }

    #[test]
    fn restic_errors_are_coarse_and_do_not_leak_raw_output() {
        let locked = restic_error_observation(
            "repository is already locked by /tmp/restic-lock",
            1_700_000_000,
        );
        assert_eq!(locked.state, BackupPostureState::Warning);
        assert_eq!(locked.summary, "restic repository locked");
        assert!(!serde_json::to_string(&locked)
            .unwrap()
            .contains("/tmp/restic-lock"));

        let missing = restic_error_observation("Fatal: unable to open config file", 1_700_000_000);
        assert_eq!(missing.state, BackupPostureState::Missing);

        let failed = restic_error_observation("wrong password or no key found", 1_700_000_000);
        assert_eq!(failed.state, BackupPostureState::Failed);
        assert_eq!(failed.last_attempt_state, Some(BackupRunState::Failed));
    }

    #[test]
    fn backup_status_json_accepts_sanitized_observations_only() {
        let clean = r#"{
            "id":"restic-main",
            "label":"Restic main",
            "engine":"restic",
            "state":"healthy",
            "configured":"enabled",
            "summary":"last backup succeeded"
        }"#;
        let observations = backup_observations_from_json(clean).expect("clean observation");
        assert_eq!(observations.len(), 1);
        assert_eq!(observations[0].state, BackupPostureState::Healthy);

        let secret_shaped = r#"{
            "id":"restic-main",
            "label":"Restic main",
            "engine":"restic",
            "state":"healthy",
            "configured":"enabled",
            "summary":"last backup succeeded",
            "repository_id":"s3://user:password@example.invalid/bucket"
        }"#;
        assert_eq!(
            backup_observations_from_json(secret_shaped).expect_err("secret-shaped metadata"),
            "contract"
        );
    }

    #[test]
    fn location_mode_is_disabled_by_default_and_explicitly_selected() {
        assert_eq!(LocationMode::from_env_value(None), LocationMode::Off);
        assert_eq!(
            LocationMode::from_env_value(Some(" env ".to_string())),
            LocationMode::Env
        );
        assert_eq!(
            LocationMode::from_env_value(Some("ip-api".to_string())),
            LocationMode::IpApi
        );
        assert_eq!(
            LocationMode::from_env_value(Some("command".to_string())),
            LocationMode::Command
        );
        assert_eq!(
            LocationMode::from_env_value(Some("provider-command".to_string())),
            LocationMode::Command
        );
        assert_eq!(
            LocationMode::from_env_value(Some("wifi".to_string())),
            LocationMode::Off
        );
    }

    #[test]
    fn env_location_reports_quality_without_sensitive_log_details() {
        std::env::set_var("PHAROS_LOCATION_LATITUDE", "48.2082");
        std::env::set_var("PHAROS_LOCATION_LONGITUDE", "16.3738");
        std::env::set_var("PHAROS_LOCATION_SOURCE", "wifi");
        std::env::set_var("PHAROS_LOCATION_ACCURACY_METERS", "1200");
        std::env::set_var("PHAROS_LOCATION_PRECISION_METERS", "2500");
        std::env::set_var("PHAROS_LOCATION_LABEL", "Vienna area");

        let location = location_from_env(1_700_000_000).expect("env location");
        let summary = location_log_summary(Some(&location));

        assert_eq!(location.source, HostLocationSource::Wifi);
        assert_eq!(location.accuracy_meters, Some(1200.0));
        assert_eq!(location.precision_meters, Some(2500.0));
        assert_eq!(location.observed_at, Some(1_700_000_000));
        assert_eq!(location.label.as_deref(), Some("Vienna area"));
        assert!(summary.contains("location=wifi"));
        assert!(summary.contains("accuracy=1200m"));
        assert!(summary.contains("precision=2500m"));
        assert!(!summary.contains("48.2082"));
        assert!(!summary.contains("16.3738"));
        assert!(!summary.contains("Vienna"));

        for key in [
            "PHAROS_LOCATION_LATITUDE",
            "PHAROS_LOCATION_LONGITUDE",
            "PHAROS_LOCATION_SOURCE",
            "PHAROS_LOCATION_ACCURACY_METERS",
            "PHAROS_LOCATION_PRECISION_METERS",
            "PHAROS_LOCATION_LABEL",
        ] {
            std::env::remove_var(key);
        }
    }

    #[test]
    fn ip_api_location_uses_coarse_precision_and_not_raw_ip() {
        let raw = r#"{
            "status":"success",
            "lat":52.52,
            "lon":13.405,
            "city":"Berlin",
            "regionName":"Berlin",
            "countryCode":"DE",
            "query":"203.0.113.10"
        }"#;

        let location =
            location_from_ip_api_json(raw, 1_700_000_000, 50_000.0).expect("ip api location");
        let body = serde_json::to_string(&location).expect("location serializes");
        let summary = location_log_summary(Some(&location));

        assert_eq!(location.source, HostLocationSource::Ip);
        assert_eq!(location.accuracy_meters, None);
        assert_eq!(location.precision_meters, Some(50_000.0));
        assert_eq!(location.label.as_deref(), Some("Berlin, DE"));
        assert!(!body.contains("203.0.113.10"));
        assert!(summary.contains("location=ip"));
        assert!(summary.contains("precision=50000m"));
        assert!(!summary.contains("52.52"));
        assert!(!summary.contains("13.405"));
    }

    #[test]
    fn command_location_parses_sanitized_payload_only() {
        let raw = r#"{
            "latitude": 48.2082,
            "longitude": 16.3738,
            "source": "wifi",
            "accuracy_meters": 900,
            "precision_meters": 2500,
            "observed_at": 1700000000,
            "label": "Vienna area",
            "bssid": "aa:bb:cc:dd:ee:ff",
            "ssid": "private-network"
        }"#;

        let location = location_from_command_json(raw, 1_700_000_100).expect("command location");
        let body = serde_json::to_string(&location).expect("location serializes");
        let summary = location_log_summary(Some(&location));

        assert_eq!(location.source, HostLocationSource::Wifi);
        assert_eq!(location.accuracy_meters, Some(900.0));
        assert_eq!(location.precision_meters, Some(2500.0));
        assert_eq!(location.observed_at, Some(1_700_000_000));
        assert_eq!(location.label.as_deref(), Some("Vienna area"));
        assert!(!body.contains("aa:bb"));
        assert!(!body.contains("private-network"));
        assert!(summary.contains("location=wifi"));
        assert!(!summary.contains("48.2082"));
        assert!(!summary.contains("16.3738"));
        assert!(!summary.contains("Vienna"));
    }

    #[test]
    fn command_location_rejects_malformed_or_invalid_payload() {
        assert!(location_from_command_json("not json", 1_700_000_000).is_none());
        assert!(
            location_from_command_json(r#"{"latitude":99,"longitude":16}"#, 1_700_000_000)
                .is_none()
        );
        assert!(location_from_command_json(
            r#"{"latitude":48.2,"longitude":"bad"}"#,
            1_700_000_000
        )
        .is_none());
    }

    #[test]
    fn command_location_args_are_json_array_only() {
        assert_eq!(
            location_command_args_from_raw(r#"["--format","json"]"#),
            Some(vec!["--format".to_string(), "json".to_string()])
        );
        assert!(location_command_args_from_raw("--format json").is_none());
    }

    #[test]
    fn command_runner_reports_failure_without_leaking_output() {
        let args = vec![
            "-c".to_string(),
            "printf 'BSSID=aa:bb:cc:dd:ee:ff'; exit 7".to_string(),
        ];
        let error =
            run_location_command("/bin/sh", &args, Duration::from_secs(1)).expect_err("fails");
        assert_eq!(error, "exit");
        assert!(!error.contains("aa:bb"));
        assert!(!error.contains("BSSID"));
    }

    #[test]
    fn command_runner_times_out() {
        let args = vec!["-c".to_string(), "sleep 1".to_string()];
        let error =
            run_location_command("/bin/sh", &args, Duration::from_millis(10)).expect_err("timeout");
        assert_eq!(error, "timeout");
    }

    #[test]
    fn command_collectors_drain_large_stdout_and_stderr_concurrently() {
        let block = "x".repeat(60);
        let location_script =
            format!("i=0; while [ \"$i\" -lt 1000 ]; do printf '%s' '{block}'; i=$((i+1)); done");
        let output = run_location_command(
            "/bin/sh",
            &["-c".to_string(), location_script],
            Duration::from_secs(3),
        )
        .expect("large output below the limit drains without pipe deadlock");
        assert_eq!(output.len(), 60_000);

        let capture_script = format!(
            "i=0; while [ \"$i\" -lt 1500 ]; do printf '%s' '{block}'; i=$((i+1)); done; i=0; while [ \"$i\" -lt 1500 ]; do printf '%s' '{block}' >&2; i=$((i+1)); done"
        );
        let capture = run_capture_command(
            "/bin/sh",
            &["-c".to_string(), capture_script],
            Duration::from_secs(3),
        )
        .expect("both pipes drain concurrently");
        assert!(capture.success);
        assert_eq!(capture.stdout.len(), 90_000);
        assert_eq!(capture.stderr.len(), 90_000);
    }

    #[test]
    fn command_collectors_enforce_output_and_descendant_deadlines() {
        let block = "x".repeat(60);
        let oversized =
            format!("i=0; while [ \"$i\" -lt 1200 ]; do printf '%s' '{block}'; i=$((i+1)); done");
        assert_eq!(
            run_location_command(
                "/bin/sh",
                &["-c".to_string(), oversized],
                Duration::from_secs(3)
            )
            .expect_err("oversized output is rejected"),
            "output_limit"
        );

        let started = Instant::now();
        let inherited_pipe = vec!["-c".to_string(), "(sleep 2) & printf '{}'".to_string()];
        assert_eq!(
            run_location_command("/bin/sh", &inherited_pipe, Duration::from_millis(100))
                .expect_err("background descendants cannot hold the pipe forever"),
            "output_timeout"
        );
        assert!(started.elapsed() < Duration::from_secs(1));
    }

    #[test]
    fn report_endpoint_is_https_capable_and_never_exposes_unsafe_components() {
        let endpoint = report_endpoint("https://pharos.example/base").expect("https endpoint");
        assert_eq!(endpoint.request_url, "https://pharos.example/base/report");
        assert_eq!(endpoint.safe_origin, "https://pharos.example");
        assert!(!endpoint.safe_origin.contains("base"));

        for unsafe_url in [
            "ftp://pharos.example",
            "https://user@pharos.example",
            "https://pharos.example?token=hidden",
            "https://pharos.example/#fragment",
            "not a url",
        ] {
            assert!(report_endpoint(unsafe_url).is_err());
        }
    }

    #[test]
    fn request_deadlines_and_retry_delays_are_bounded_by_cadence() {
        for cadence in [MIN_HEARTBEAT_INTERVAL_SECS, 60, MAX_HEARTBEAT_INTERVAL_SECS] {
            let deadlines = RequestDeadlines::for_cadence(cadence).unwrap();
            for deadline in [
                deadlines.connect,
                deadlines.read,
                deadlines.write,
                deadlines.overall,
            ] {
                assert!(deadline < Duration::from_secs(cadence));
                assert!(!deadline.is_zero());
            }
            for failure in 1..=100 {
                assert!(retry_delay(cadence, failure, u64::MAX) < Duration::from_secs(cadence));
            }
        }
        assert!(RequestDeadlines::for_cadence(MIN_HEARTBEAT_INTERVAL_SECS - 1).is_err());
        assert!(RequestDeadlines::for_cadence(MAX_HEARTBEAT_INTERVAL_SECS + 1).is_err());
        assert!(retry_delay(60, 2, 0) > retry_delay(60, 1, 0));
        assert_ne!(retry_delay(60, 1, 0), retry_delay(60, 1, 499));
    }

    #[test]
    fn beacon_health_tracks_recent_success_and_stalled_reporting() {
        let path = kernel_fixture("container-health");
        write_marker(&path, 1_000).expect("write successful report health");

        assert_eq!(beacon_health_verdict(&path, 60, 1_000), Ok(0));
        assert_eq!(beacon_health_verdict(&path, 60, 1_180), Ok(180));
        let stale = beacon_health_verdict(&path, 60, 1_181).unwrap_err();
        assert_eq!(
            stale,
            BeaconHealthProblem::Stale {
                age_secs: 181,
                limit_secs: 180,
                cadence_secs: 60
            }
        );
        let reason = stale.to_string();
        assert!(reason.contains("181s ago"), "{reason}");
        assert!(reason.contains("beyond 180s"), "{reason}");
        assert!(reason.contains("PHAROS_INTERVAL=60"), "{reason}");

        std::fs::remove_file(path).expect("remove health fixture");
    }

    #[test]
    fn beacon_health_fails_closed_before_success_or_for_invalid_state() {
        let path = kernel_fixture("invalid-container-health");
        let missing = beacon_health_verdict(&path, 60, 1_000).unwrap_err();
        assert_eq!(missing, BeaconHealthProblem::StateMissing(path.clone()));
        let reason = missing.to_string();
        assert!(reason.contains(&path.display().to_string()), "{reason}");
        assert!(reason.contains(BEACON_HEALTH_PATH_ENV), "{reason}");

        write_marker(&path, 0).expect("write startup health state");
        assert_eq!(
            beacon_health_verdict(&path, 60, 1_000),
            Err(BeaconHealthProblem::NoSuccessfulReportYet)
        );
        assert_eq!(
            beacon_health_verdict(&path, MIN_HEARTBEAT_INTERVAL_SECS - 1, 1_000),
            Err(BeaconHealthProblem::InvalidInterval)
        );

        write_marker(&path, 1_000).expect("write successful report health");
        assert_eq!(
            beacon_health_verdict(&path, 60, 999),
            Err(BeaconHealthProblem::ClockSkew {
                last_success_at: 1_000,
                now: 999
            })
        );
        assert_eq!(
            beacon_health_verdict(&path, 60, -1),
            Err(BeaconHealthProblem::ClockSkew {
                last_success_at: 1_000,
                now: -1
            })
        );

        for invalid in [
            "not-health\n",
            "v2\n",
            "v2 1000\n",
            "v2 1000 7\n",
            "v2 abc 7 start\n",
            "v2 1000 pid start\n",
            "v2 -5 7 start\n",
            "v1 1000 7 start\n",
        ] {
            std::fs::write(&path, invalid).expect("write invalid health state");
            assert_eq!(
                beacon_health_verdict(&path, 60, 1_000),
                Err(BeaconHealthProblem::StateInvalid(path.clone())),
                "{invalid:?}"
            );
        }

        std::fs::remove_file(&path).expect("remove health fixture");
        std::fs::create_dir(&path).expect("create directory in place of health state");
        assert_eq!(
            beacon_health_verdict(&path, 60, 1_000),
            Err(BeaconHealthProblem::StateInvalid(path.clone()))
        );
        std::fs::remove_dir(path).expect("remove directory fixture");
    }

    /// Makes `dir` 0500 and returns whether that really stops the current
    /// user from creating files there. Root bypasses permission bits, so a
    /// `false` return tells callers to prove the fail-closed path another,
    /// non-vacuous way instead of asserting on a probe that cannot fail.
    #[cfg(unix)]
    fn make_location_unwritable(dir: &Path) -> bool {
        std::fs::set_permissions(dir, std::fs::Permissions::from_mode(0o500))
            .expect("read-only location");
        let probe = dir.join("writable-probe");
        let writable = std::fs::File::create(&probe).is_ok();
        if writable {
            let _ = std::fs::remove_file(&probe);
        }
        !writable
    }

    #[cfg(unix)]
    fn restore_location(dir: &Path, marker: &Path) {
        std::fs::set_permissions(dir, std::fs::Permissions::from_mode(0o700))
            .expect("restore location");
        if marker.exists() {
            std::fs::set_permissions(marker, std::fs::Permissions::from_mode(0o600))
                .expect("restore marker");
        }
    }

    #[test]
    fn beacon_health_rejects_recent_marker_when_location_probe_fails() {
        // Fail-closed decision, independent of the test user's privileges: a
        // readable, recent marker is rejected as soon as the atomic-write
        // probe reports that this process could not have written it.
        let path = kernel_fixture("probe-rejected-health");
        write_marker(&path, 1_000).expect("write recent marker");
        assert_eq!(
            beacon_health_verdict_with(&path, 60, 1_010, |_| Ok(())),
            Ok(10)
        );

        let verdict = beacon_health_verdict_with(&path, 60, 1_010, |probed| {
            Err(format!(
                "permission denied while probing {}",
                probed.display()
            ))
        })
        .unwrap_err();
        assert_eq!(
            verdict,
            BeaconHealthProblem::LocationUnwritable {
                path: path.clone(),
                error: format!("permission denied while probing {}", path.display()),
            }
        );
        let reason = verdict.to_string();
        assert!(reason.contains(&path.display().to_string()), "{reason}");
        assert!(reason.contains("cannot be written"), "{reason}");
        assert!(reason.contains("permission denied"), "{reason}");
        assert!(reason.contains(BEACON_HEALTH_PATH_ENV), "{reason}");

        // The probe outranks every marker-content verdict, including "no
        // successful report yet" and a missing marker.
        write_marker(&path, 0).expect("write startup marker");
        assert!(matches!(
            beacon_health_verdict_with(&path, 60, 1_010, |_| Err("read-only".into())),
            Err(BeaconHealthProblem::LocationUnwritable { .. })
        ));
        std::fs::remove_file(&path).expect("remove marker");
        assert!(matches!(
            beacon_health_verdict_with(&path, 60, 1_010, |_| Err("read-only".into())),
            Err(BeaconHealthProblem::LocationUnwritable { .. })
        ));
    }

    #[test]
    fn beacon_health_location_probe_performs_a_real_write() {
        // Writable location: probe passes and leaves nothing behind.
        let dir = kernel_fixture("probe-location");
        std::fs::create_dir(&dir).expect("create location");
        let path = dir.join("pharos-beacon-health-v1");
        write_marker(&path, 1_000).expect("write recent marker");
        assert_eq!(probe_beacon_health_location(&path), Ok(()));
        assert_eq!(entries(&dir).len(), 1, "probe must clean up its temp file");
        assert_eq!(beacon_health_verdict(&path, 60, 1_010), Ok(10));

        // Location that no user, root included, can create files in: the
        // configured parent is a regular file, not a directory.
        let blocker = kernel_fixture("probe-parent-is-a-file");
        std::fs::write(&blocker, "not a directory\n").expect("write blocking file");
        let inside = blocker.join("pharos-beacon-health-v1");
        let error = probe_beacon_health_location(&inside).unwrap_err();
        assert!(!error.is_empty(), "probe error must carry the io reason");
        assert!(matches!(
            beacon_health_verdict(&inside, 60, 1_010),
            Err(BeaconHealthProblem::LocationUnwritable { .. })
        ));
        std::fs::remove_file(&blocker).expect("remove blocking file");

        // Permission-denied location (0500 parent, 0400 marker): the recent,
        // readable marker must be rejected. Root bypasses permission bits and
        // can genuinely write there, in which case the probe truthfully passes
        // and the injected-probe test above carries the fail-closed proof.
        #[cfg(unix)]
        {
            std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o400))
                .expect("read-only marker");
            if make_location_unwritable(&dir) {
                let error = probe_beacon_health_location(&path).unwrap_err();
                assert!(!error.is_empty(), "probe error must carry the io reason");
                let verdict = beacon_health_verdict(&path, 60, 1_010).unwrap_err();
                assert!(
                    matches!(verdict, BeaconHealthProblem::LocationUnwritable { .. }),
                    "{verdict:?}"
                );
                assert!(verdict.to_string().contains(&path.display().to_string()));
            } else {
                assert_eq!(probe_beacon_health_location(&path), Ok(()));
                assert!(
                    write_marker(&path, 1_005).is_ok(),
                    "a user the probe passes for must really be able to write"
                );
            }
            restore_location(&dir, &path);
        }
        std::fs::remove_dir_all(&dir).expect("remove location");
    }

    /// Applies the platform's file-level no-change protection to `path`
    /// (`chflags uchg` on Darwin/BSD, `chattr +i` on Linux, which needs
    /// CAP_LINUX_IMMUTABLE and an extN/XFS/Btrfs file). Returns whether the
    /// protection is really in force, verified by a refused atomic replace.
    #[cfg(unix)]
    fn protect_marker(path: &Path) -> bool {
        let applied = if cfg!(any(target_os = "macos", target_os = "freebsd")) {
            Command::new("/usr/bin/chflags")
                .arg("uchg")
                .arg(path)
                .status()
        } else {
            Command::new("chattr").arg("+i").arg(path).status()
        };
        if !applied.map(|status| status.success()).unwrap_or(false) {
            return false;
        }
        if write_marker(path, 1_005).is_ok() {
            unprotect_marker(path);
            return false;
        }
        true
    }

    #[cfg(unix)]
    fn unprotect_marker(path: &Path) {
        let _ = if cfg!(any(target_os = "macos", target_os = "freebsd")) {
            Command::new("/usr/bin/chflags")
                .arg("nouchg")
                .arg(path)
                .status()
        } else {
            Command::new("chattr").arg("-i").arg(path).status()
        };
    }

    /// Directory entries except the persistent marker lock, which is the one
    /// artifact that legitimately stays.
    fn entries(dir: &Path) -> Vec<String> {
        let mut names: Vec<String> = std::fs::read_dir(dir)
            .expect("list location")
            .map(|entry| {
                entry
                    .expect("entry")
                    .file_name()
                    .to_string_lossy()
                    .into_owned()
            })
            .filter(|name| !name.ends_with(".lock"))
            .collect();
        names.sort();
        names
    }

    #[test]
    fn beacon_health_rejects_readable_recent_marker_that_cannot_be_replaced() {
        // Real regression: the directory is writable and the marker reads
        // fine, yet a file-level no-change flag refuses replacement,
        // truncation and removal alike. Root is subject to the flag too.
        let dir = kernel_fixture("immutable-marker");
        std::fs::create_dir(&dir).expect("create location");
        let path = dir.join("pharos-beacon-health-v1");
        write_marker(&path, 1_000).expect("write recent marker");

        #[cfg(unix)]
        if protect_marker(&path) {
            assert_eq!(marker_stamp(&path), "1000");
            let sibling = dir.join("sibling");
            assert!(
                std::fs::File::create(&sibling).is_ok(),
                "location is writable"
            );
            std::fs::remove_file(&sibling).expect("remove sibling");
            assert!(invalidate_marker(&path).is_err());

            let error = probe_beacon_health_location(&path).unwrap_err();
            assert!(error.contains("cannot be replaced"), "{error}");
            let verdict = beacon_health_verdict(&path, 60, 1_010).unwrap_err();
            assert!(
                matches!(verdict, BeaconHealthProblem::LocationUnwritable { .. }),
                "{verdict:?}"
            );
            assert!(verdict.to_string().contains(&path.display().to_string()));
            let reason = initialize_beacon_health(&path, &generation()).unwrap_err();
            assert!(reason.contains("could not be removed either"), "{reason}");

            // The marker was neither damaged nor moved, and nothing was left
            // behind next to it.
            assert_eq!(marker_stamp(&path), "1000");
            assert_eq!(entries(&dir), vec!["pharos-beacon-health-v1".to_string()]);

            unprotect_marker(&path);
            assert_eq!(beacon_health_verdict(&path, 60, 1_010), Ok(10));
            assert_eq!(entries(&dir), vec!["pharos-beacon-health-v1".to_string()]);
        } else {
            eprintln!(
                "note: no file-level immutability available for this user/filesystem; \
                 the injected-probe test carries the fail-closed proof here"
            );
        }
        std::fs::remove_dir_all(&dir).expect("remove location");
    }

    #[cfg(target_os = "macos")]
    fn set_deny_delete_acl(path: &Path, enable: bool) {
        // The platform chmod at /bin/chmod understands ACL entries; a GNU
        // chmod earlier on PATH would not, so never resolve it by name.
        let user = std::env::var("USER").expect("USER");
        let status = Command::new("/bin/chmod")
            .arg(if enable { "+a" } else { "-a" })
            .arg(format!("{user} deny delete"))
            .arg(path)
            .status()
            .expect("run /bin/chmod");
        assert!(status.success(), "/bin/chmod ACL change must succeed");
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn beacon_health_rejects_marker_protected_by_a_deny_delete_acl() {
        // ACL/policy analogue: linking the marker is allowed, replacing any
        // name of it is not. The probe must fail closed, leave the marker
        // intact, and clean up its own leftover once the policy is lifted.
        let dir = kernel_fixture("acl-marker");
        std::fs::create_dir(&dir).expect("create location");
        let path = dir.join("pharos-beacon-health-v1");
        write_marker(&path, 1_000).expect("write recent marker");
        set_deny_delete_acl(&path, true);
        assert!(
            write_marker(&path, 1_005).is_err(),
            "the ACL must really refuse replacing the marker"
        );

        let error = probe_beacon_health_location(&path).unwrap_err();
        assert!(error.contains("renaming over a link"), "{error}");
        assert!(matches!(
            beacon_health_verdict(&path, 60, 1_010),
            Err(BeaconHealthProblem::LocationUnwritable { .. })
        ));
        assert_eq!(marker_stamp(&path), "1000");
        // The deny-delete ACL also pins the probe link; a repeated probe
        // reports the leftover instead of piling up more.
        let error = probe_beacon_health_location(&path).unwrap_err();
        assert!(error.contains("previous probe link"), "{error}");
        assert_eq!(entries(&dir).len(), 2, "{:?}", entries(&dir));

        set_deny_delete_acl(&path, false);
        assert_eq!(beacon_health_verdict(&path, 60, 1_010), Ok(10));
        assert_eq!(entries(&dir), vec!["pharos-beacon-health-v1".to_string()]);
        std::fs::remove_dir_all(&dir).expect("remove location");
    }

    #[cfg(unix)]
    #[test]
    fn beacon_health_probe_passes_in_a_sticky_directory_the_beacon_owns() {
        // /tmp-style sticky directory: rename over an own marker is allowed
        // for the marker owner, the directory owner and root, so the kernel
        // rule the probe relies on must not reject the normal case.
        let dir = kernel_fixture("sticky-location");
        std::fs::create_dir(&dir).expect("create location");
        std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o1700))
            .expect("sticky location");
        let path = dir.join("pharos-beacon-health-v1");
        write_marker(&path, 1_000).expect("write recent marker");
        assert_eq!(probe_beacon_health_location(&path), Ok(()));
        assert_eq!(beacon_health_verdict(&path, 60, 1_010), Ok(10));
        assert_eq!(entries(&dir), vec!["pharos-beacon-health-v1".to_string()]);
        std::fs::remove_dir_all(&dir).expect("remove location");
    }

    #[test]
    fn failed_startup_reset_cannot_leave_trusted_prior_state() {
        // Reset that can write: marker becomes the startup sentinel.
        let dir = kernel_fixture("startup-reset");
        std::fs::create_dir(&dir).expect("create location");
        let path = dir.join("pharos-beacon-health-v1");
        write_marker(&path, 1_000).expect("write previous-run marker");
        assert_eq!(initialize_beacon_health(&path, &generation()), Ok(()));
        assert_eq!(
            beacon_health_verdict(&path, 60, 1_010),
            Err(BeaconHealthProblem::NoSuccessfulReportYet)
        );

        // Reset that cannot write but can still unlink: the prior state is
        // removed, never written into.
        write_marker(&path, 1_000).expect("write previous-run marker");
        assert!(invalidate_marker(&path).is_ok());
        assert!(matches!(
            read_beacon_health(&path),
            Err(BeaconHealthProblem::StateMissing(_))
        ));
        assert!(invalidate_marker(&path).is_ok());

        // Reset into a location nobody can write (parent is a file): the
        // error names the path, and the healthcheck fails closed on the
        // location probe rather than on marker contents.
        let blocker = kernel_fixture("startup-reset-parent-is-a-file");
        std::fs::write(&blocker, "not a directory\n").expect("write blocking file");
        let inside = blocker.join("pharos-beacon-health-v1");
        let reason = initialize_beacon_health(&inside, &generation()).unwrap_err();
        assert!(reason.contains(&inside.display().to_string()), "{reason}");
        assert!(
            reason.contains("could not initialize container health state"),
            "{reason}"
        );
        assert!(matches!(
            beacon_health_verdict(&inside, 60, 1_010),
            Err(BeaconHealthProblem::LocationUnwritable { .. })
        ));
        std::fs::remove_file(&blocker).expect("remove blocking file");

        // Permission-denied location with a readable recent marker: the reset
        // fails, the marker survives untouched, and the healthcheck still
        // refuses it. Skipped only when the user bypasses permission bits.
        #[cfg(unix)]
        {
            write_marker(&path, 1_000).expect("write previous-run marker");
            std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o400))
                .expect("read-only marker");
            if make_location_unwritable(&dir) {
                let reason = initialize_beacon_health(&path, &generation()).unwrap_err();
                assert!(reason.contains("could not be removed either"), "{reason}");
                assert_eq!(marker_stamp(&path), "1000");
                assert!(matches!(
                    beacon_health_verdict(&path, 60, 1_010),
                    Err(BeaconHealthProblem::LocationUnwritable { .. })
                ));
            }
            restore_location(&dir, &path);
        }
        std::fs::remove_dir_all(&dir).expect("remove location");
    }

    #[cfg(unix)]
    #[test]
    fn marker_handling_never_follows_a_symlink_or_touches_its_target() {
        use std::os::unix::fs::symlink;

        // An unrelated, valuable file that a symlink at the marker path points
        // to. No read, probe, reset or invalidation may change one byte of it.
        const VALUABLE: &str = "valuable-data-must-survive\n";
        let elsewhere = kernel_fixture("symlink-target-location");
        std::fs::create_dir(&elsewhere).expect("create target location");
        let valuable = elsewhere.join("valuable");
        std::fs::write(&valuable, VALUABLE).expect("write valuable file");
        let dir = kernel_fixture("symlinked-marker");
        std::fs::create_dir(&dir).expect("create location");
        let path = dir.join("pharos-beacon-health-v1");
        symlink(&valuable, &path).expect("plant symlink at marker path");

        // Reading never follows: a symlink is not the beacon's state.
        assert!(matches!(
            read_beacon_health(&path),
            Err(BeaconHealthProblem::StateInvalid(_))
        ));
        assert_eq!(probe_beacon_health_location(&path), Ok(()));
        assert!(matches!(
            beacon_health_verdict(&path, 60, 1_010),
            Err(BeaconHealthProblem::StateInvalid(_))
        ));
        assert_eq!(std::fs::read_to_string(&valuable).unwrap(), VALUABLE);
        assert_eq!(entries(&dir), vec!["pharos-beacon-health-v1".to_string()]);

        // Invalidation unlinks the symlink itself; the target is untouched.
        assert!(invalidate_marker(&path).is_ok());
        assert!(std::fs::symlink_metadata(&path).is_err(), "symlink removed");
        assert_eq!(std::fs::read_to_string(&valuable).unwrap(), VALUABLE);

        // A startup reset in a writable directory replaces the symlink name
        // with a real marker by rename; the target is untouched.
        symlink(&valuable, &path).expect("plant symlink at marker path");
        assert_eq!(initialize_beacon_health(&path, &generation()), Ok(()));
        assert!(std::fs::symlink_metadata(&path).unwrap().is_file());
        assert_eq!(marker_stamp(&path), "0");
        assert_eq!(std::fs::read_to_string(&valuable).unwrap(), VALUABLE);

        // The reported defect: symlink at the marker path inside a directory
        // the beacon cannot write. The reset fails, must not follow the link,
        // and the healthcheck fails closed. Root bypasses the directory bits,
        // in which case the rename above already replaced the symlink; the
        // target must be byte-identical either way.
        std::fs::remove_file(&path).expect("remove marker");
        symlink(&valuable, &path).expect("plant symlink at marker path");
        if make_location_unwritable(&dir) {
            let reason = initialize_beacon_health(&path, &generation()).unwrap_err();
            assert!(reason.contains("could not be removed either"), "{reason}");
            assert!(std::fs::symlink_metadata(&path).unwrap().is_symlink());
            assert!(matches!(
                beacon_health_verdict(&path, 60, 1_010),
                Err(BeaconHealthProblem::LocationUnwritable { .. })
            ));
        } else {
            assert_eq!(initialize_beacon_health(&path, &generation()), Ok(()));
        }
        assert_eq!(std::fs::read_to_string(&valuable).unwrap(), VALUABLE);
        restore_location(&dir, &path);
        std::fs::remove_dir_all(&dir).expect("remove location");
        std::fs::remove_dir_all(&elsewhere).expect("remove target location");
    }

    #[test]
    fn probe_artifacts_are_bounded_and_recovered_after_a_crash() {
        // A probe or write killed midway (healthcheck timeout during sync)
        // leaves its fixed-name artifacts behind. The next run must remove
        // them, never accumulate, and still judge the marker correctly.
        let dir = kernel_fixture("crash-leftovers");
        std::fs::create_dir(&dir).expect("create location");
        let path = dir.join("pharos-beacon-health-v1");
        write_marker(&path, 1_000).expect("write recent marker");
        let old_inode = dir.join("old-inode");
        std::fs::write(&old_inode, "stale\n").expect("write old inode");
        let leftovers = [
            beacon_health_sibling_path(&path, BEACON_HEALTH_WRITE_TEMP).unwrap(),
            beacon_health_sibling_path(&path, BEACON_HEALTH_PROBE_TEMP).unwrap(),
            beacon_health_sibling_path(&path, BEACON_HEALTH_PROBE_LINK).unwrap(),
        ];
        // Names carry no pid or timestamp, so a crash can leave at most one
        // file per name.
        for leftover in &leftovers {
            assert_eq!(
                leftover,
                &beacon_health_sibling_path(&path, leftover.extension().unwrap().to_str().unwrap())
                    .unwrap()
            );
        }
        std::fs::write(&leftovers[0], "partial v1 999\n").expect("stale write temp");
        std::fs::write(&leftovers[1], "pro").expect("stale probe temp");
        std::fs::hard_link(&old_inode, &leftovers[2]).expect("stale probe link");
        std::fs::remove_file(&old_inode).expect("drop old inode name");

        // Under the marker lock no write is in flight, so the probe recovers
        // all three artifacts, the beacon's write temp included.
        assert_eq!(probe_beacon_health_location(&path), Ok(()));
        assert_eq!(beacon_health_verdict(&path, 60, 1_010), Ok(10));
        assert_eq!(entries(&dir), vec!["pharos-beacon-health-v1".to_string()]);
        assert!(
            beacon_health_sibling_path(&path, BEACON_HEALTH_LOCK)
                .unwrap()
                .is_file(),
            "the lock is the only artifact that stays"
        );

        // A stale probe link to the current marker is recovered the same way,
        // and the marker itself is not affected.
        std::fs::hard_link(&path, &leftovers[2]).expect("stale probe link");
        std::fs::write(&leftovers[0], "partial").expect("stale write temp");
        write_marker(&path, 1_005).expect("write over leftovers");
        assert_eq!(probe_beacon_health_location(&path), Ok(()));
        assert_eq!(marker_stamp(&path), "1005");
        assert_eq!(entries(&dir), vec!["pharos-beacon-health-v1".to_string()]);
        std::fs::remove_dir_all(&dir).expect("remove location");
    }

    #[test]
    fn link_refusals_carry_a_fail_closed_advisory() {
        let limit = beacon_health_link_refusal(&std::io::Error::from_raw_os_error(libc::EMLINK));
        assert!(limit.contains("hard-link limit"), "{limit}");
        let unsupported =
            beacon_health_link_refusal(&std::io::Error::from_raw_os_error(libc::ENOTSUP));
        assert!(
            unsupported.contains("does not support hard links"),
            "{unsupported}"
        );
        let immutable = beacon_health_link_refusal(&std::io::Error::from_raw_os_error(libc::EPERM));
        assert!(
            immutable.contains("immutable or append-only"),
            "{immutable}"
        );
        assert!(immutable.contains("without hard links"), "{immutable}");
        let other = beacon_health_link_refusal(&std::io::Error::from_raw_os_error(libc::EIO));
        assert!(other.contains("linking it was refused"), "{other}");
        for reason in [&limit, &unsupported, &immutable, &other] {
            assert!(reason.contains("cannot be replaced"), "{reason}");
            assert!(reason.contains(BEACON_HEALTH_PATH_ENV), "{reason}");
        }
    }

    /// Child half of the sticky-directory ownership test: runs the probe as
    /// whatever uid the parent chose and reports the verdict by exit code.
    /// A no-op unless the parent set the environment.
    #[cfg(unix)]
    #[test]
    fn sticky_probe_child() {
        let Some(path) = std::env::var_os("PHAROS_TEST_STICKY_PROBE_PATH") else {
            return;
        };
        let expect_ok = std::env::var("PHAROS_TEST_STICKY_PROBE_EXPECT").as_deref() == Ok("ok");
        let result = probe_beacon_health_location(Path::new(&path));
        match (expect_ok, result) {
            (true, Ok(())) => {}
            (false, Err(reason)) => {
                assert!(reason.contains("cannot be replaced"), "{reason}");
            }
            (true, Err(reason)) => panic!("directory owner must be able to replace: {reason}"),
            (false, Ok(())) => panic!("neither owner nor root must not be able to replace"),
        }
    }

    /// Sticky-directory rule as the kernel applies it to rename: replacing a
    /// marker owned by someone else is allowed for the directory owner (and
    /// root) and refused for anyone else. Needs root to create files owned
    /// by other uids and to run the probe as them.
    #[cfg(unix)]
    #[test]
    fn sticky_directory_owner_may_replace_a_foreign_marker_others_may_not() {
        use std::os::unix::fs::{chown, MetadataExt};
        use std::os::unix::process::CommandExt;

        let probe = kernel_fixture("uid-probe");
        std::fs::write(&probe, "").expect("write uid probe");
        let own_uid = std::fs::metadata(&probe).expect("uid probe").uid();
        std::fs::remove_file(&probe).expect("remove uid probe");
        if own_uid != 0 {
            eprintln!("note: sticky foreign-marker case needs root to create foreign-owned files; skipped");
            return;
        }
        // Two unprivileged uids that exist on any Unix: "nobody" style ids.
        let (dir_owner, marker_owner) = (65534_u32, 65533_u32);
        let exe = std::env::current_exe().expect("test binary");
        let run_as = |uid: u32, path: &Path, expect_ok: bool| -> bool {
            Command::new(&exe)
                .args(["--exact", "tests::sticky_probe_child", "--nocapture"])
                .env("PHAROS_TEST_STICKY_PROBE_PATH", path)
                .env(
                    "PHAROS_TEST_STICKY_PROBE_EXPECT",
                    if expect_ok { "ok" } else { "refused" },
                )
                .uid(uid)
                .gid(uid)
                .status()
                .map(|status| status.success())
                .unwrap_or(false)
        };
        // World-writable sticky directory owned by `dir_owner`, marker owned
        // by `marker_owner`, readable and writable by everyone so that Linux
        // protected_hardlinks lets a non-owner link it: the directory owner
        // may replace it, a third uid may not.
        let dir = kernel_fixture("sticky-foreign-marker");
        std::fs::create_dir(&dir).expect("create location");
        std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o1777))
            .expect("sticky world-writable location");
        chown(&dir, Some(dir_owner), Some(dir_owner)).expect("chown directory");
        let path = dir.join("pharos-beacon-health-v1");
        write_marker(&path, 1_000).expect("write recent marker");
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o666))
            .expect("world read-write marker");
        chown(&path, Some(marker_owner), Some(marker_owner)).expect("chown marker");
        // Beacon and probe normally share one user; here root created the
        // lock, so let the switched uids open it as they would their own.
        let lock = beacon_health_sibling_path(&path, BEACON_HEALTH_LOCK).unwrap();
        std::fs::set_permissions(&lock, std::fs::Permissions::from_mode(0o666))
            .expect("shared lock");
        chown(&lock, Some(dir_owner), Some(dir_owner)).expect("chown lock");
        // The fixture directory's parent must be traversable by those uids.
        let parent = dir.parent().expect("fixture parent");
        let parent_mode = std::fs::metadata(parent).expect("parent").mode() & 0o7777;
        std::fs::set_permissions(parent, std::fs::Permissions::from_mode(parent_mode | 0o011))
            .expect("traversable parent");

        assert!(run_as(dir_owner, &path, true), "directory owner must pass");
        assert_eq!(entries(&dir), vec!["pharos-beacon-health-v1".to_string()]);
        assert!(run_as(marker_owner, &path, true), "marker owner must pass");
        assert_eq!(entries(&dir), vec!["pharos-beacon-health-v1".to_string()]);
        assert!(run_as(65532, &path, false), "third uid must be refused");
        assert_eq!(marker_stamp(&path), "1000");
        // The refused uid could link the marker but can neither rename over
        // nor unlink that link in the sticky directory: at most the one
        // fixed-name leftover remains, which the next permitted probe removes.
        let after_refusal = entries(&dir);
        assert!(after_refusal.len() <= 2, "{after_refusal:?}");
        assert!(
            run_as(dir_owner, &path, true),
            "directory owner recovers the leftover"
        );
        assert_eq!(entries(&dir), vec!["pharos-beacon-health-v1".to_string()]);

        std::fs::set_permissions(parent, std::fs::Permissions::from_mode(parent_mode))
            .expect("restore parent");
        std::fs::remove_dir_all(&dir).expect("remove location");
    }

    #[test]
    fn markers_are_trusted_only_while_their_writing_process_runs() {
        let dir = kernel_fixture("generation");
        std::fs::create_dir(&dir).expect("create location");
        let path = dir.join("pharos-beacon-health-v1");

        // Written by this process: healthy while it runs (it does).
        write_marker(&path, 1_000).expect("write own marker");
        assert_eq!(beacon_health_verdict(&path, 60, 1_010), Ok(10));
        assert_eq!(read_beacon_health(&path).unwrap().generation, generation());

        // Written by a beacon from before process generations: never trusted.
        std::fs::write(&path, "v1 1000\n").expect("write v1 marker");
        let old = beacon_health_verdict(&path, 60, 1_010).unwrap_err();
        assert!(
            matches!(
                old,
                BeaconHealthProblem::NotCurrentGeneration { pid: 0, .. }
            ),
            "{old:?}"
        );
        assert!(
            old.to_string().contains("predates process generations"),
            "{old}"
        );

        // Written by another live process: trusted exactly as long as that
        // process lives, and not one probe longer, whatever the timestamp.
        let mut child = Command::new("sleep")
            .arg("60")
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .expect("spawn sleeper");
        let other = ProcessGeneration::for_pid(child.id()).expect("child generation");
        assert_ne!(other, generation());
        write_beacon_health(&path, 1_000, &other).expect("write marker as child");
        assert_eq!(beacon_health_verdict(&path, 60, 1_010), Ok(10));
        child.kill().expect("kill sleeper");
        child.wait().expect("reap sleeper");
        let gone = beacon_health_verdict(&path, 60, 1_010).unwrap_err();
        match &gone {
            BeaconHealthProblem::NotCurrentGeneration { pid, detail, .. } => {
                assert_eq!(*pid, child.id());
                assert!(
                    detail.contains("not running") || detail.contains("different process"),
                    "{detail}"
                );
            }
            other => panic!("{other:?}"),
        }
        assert!(
            gone.to_string().contains("only a successful report"),
            "{gone}"
        );
        // Lifting every filesystem obstacle changes nothing: the pid is gone.
        assert_eq!(probe_beacon_health_location(&path), Ok(()));
        assert!(matches!(
            beacon_health_verdict(&path, 60, 1_010),
            Err(BeaconHealthProblem::NotCurrentGeneration { .. })
        ));
        // A successful write by the current process restores health.
        write_marker(&path, 1_005).expect("current process reports");
        assert_eq!(beacon_health_verdict(&path, 60, 1_010), Ok(5));
        std::fs::remove_dir_all(&dir).expect("remove location");
    }

    #[test]
    fn concurrent_writer_and_probe_never_race_or_report_falsely() {
        // A beacon refreshing as fast as it can while the container probe
        // runs back to back: every write and every probe succeeds, every
        // verdict is healthy, and nothing but the lock is left behind.
        let dir = kernel_fixture("concurrent");
        std::fs::create_dir(&dir).expect("create location");
        let path = dir.join("pharos-beacon-health-v1");
        write_marker(&path, 1_000).expect("write initial marker");
        let writer_path = path.clone();
        let writer = thread::spawn(move || {
            let generation = generation();
            (0..300).all(|i| write_beacon_health(&writer_path, 1_000 + i, &generation).is_ok())
        });
        let mut probes = 0;
        let mut healthy = 0;
        for _ in 0..300 {
            match beacon_health_verdict(&path, 120, 1_300) {
                Ok(_) => healthy += 1,
                Err(problem) => panic!("probe under concurrent writes failed: {problem}"),
            }
            probes += 1;
        }
        assert!(
            writer.join().expect("writer thread"),
            "every write must succeed"
        );
        assert_eq!(healthy, probes);
        assert_eq!(
            std::fs::read_to_string(&path)
                .unwrap()
                .split_whitespace()
                .nth(1),
            Some("1299")
        );
        assert_eq!(entries(&dir), vec!["pharos-beacon-health-v1".to_string()]);
        std::fs::remove_dir_all(&dir).expect("remove location");
    }

    #[cfg(unix)]
    #[test]
    fn a_blocked_writer_temp_makes_the_check_unhealthy() {
        // The writer's fixed temp is immutable: the beacon can neither reuse
        // nor remove it, so no refresh can ever land. A recent marker must
        // not read as healthy while that is the case.
        let dir = kernel_fixture("immutable-writer-temp");
        std::fs::create_dir(&dir).expect("create location");
        let path = dir.join("pharos-beacon-health-v1");
        write_marker(&path, 1_000).expect("write recent marker");
        let temp = beacon_health_sibling_path(&path, BEACON_HEALTH_WRITE_TEMP).unwrap();
        std::fs::write(&temp, "partial\n").expect("plant writer temp");
        if protect_marker(&temp) {
            assert!(
                write_marker(&path, 1_005).is_err(),
                "refresh must be blocked"
            );
            let verdict = beacon_health_verdict(&path, 60, 1_010).unwrap_err();
            match &verdict {
                BeaconHealthProblem::LocationUnwritable { error, .. } => {
                    assert!(error.contains(&temp.display().to_string()), "{error}");
                    assert!(error.contains("cannot be refreshed"), "{error}");
                }
                other => panic!("{other:?}"),
            }
            assert_eq!(
                std::fs::read_to_string(&path)
                    .unwrap()
                    .split_whitespace()
                    .nth(1),
                Some("1000")
            );
            unprotect_marker(&temp);
            assert_eq!(beacon_health_verdict(&path, 60, 1_010), Ok(10));
            assert_eq!(entries(&dir), vec!["pharos-beacon-health-v1".to_string()]);
            assert!(write_marker(&path, 1_005).is_ok());
        } else {
            eprintln!(
                "note: no file-level immutability available for this user/filesystem; \
                 skipping the immutable writer temp case"
            );
        }
        std::fs::remove_dir_all(&dir).expect("remove location");
    }

    #[cfg(unix)]
    #[test]
    fn a_symlinked_lock_path_fails_closed_without_following() {
        use std::os::unix::fs::symlink;

        let elsewhere = kernel_fixture("lock-target-location");
        std::fs::create_dir(&elsewhere).expect("create target location");
        let valuable = elsewhere.join("valuable");
        std::fs::write(&valuable, "valuable-data-must-survive\n").expect("write valuable");
        let dir = kernel_fixture("symlinked-lock");
        std::fs::create_dir(&dir).expect("create location");
        let path = dir.join("pharos-beacon-health-v1");
        symlink(
            &valuable,
            beacon_health_sibling_path(&path, BEACON_HEALTH_LOCK).unwrap(),
        )
        .expect("plant symlink at lock path");
        let error = lock_beacon_health(&path).unwrap_err();
        assert!(error.contains("marker lock"), "{error}");
        assert!(write_marker(&path, 1_000).is_err());
        assert!(matches!(
            beacon_health_verdict(&path, 60, 1_010),
            Err(BeaconHealthProblem::LocationUnwritable { .. })
        ));
        assert_eq!(
            std::fs::read_to_string(&valuable).unwrap(),
            "valuable-data-must-survive\n"
        );
        std::fs::remove_dir_all(&dir).expect("remove location");
        std::fs::remove_dir_all(&elsewhere).expect("remove target location");
    }

    #[test]
    fn linux_start_tokens_require_a_boot_id() {
        let stat = "1 (pharos beacon) S 0 1 1 0 -1 4194560 100 0 0 0 5 3 0 0 20 0 1 0 424242 1000 200 18446744073709551615 1 1 0 0 0 0 0 0 0 0 0 0 17 0 0 0 0 0 0 0 0 0 0 0 0 0 0\n";
        assert_eq!(
            linux_start_token(
                stat,
                Ok("a1b2c3d4-0000-4000-8000-000000000001\n".to_string())
            )
            .unwrap(),
            "a1b2c3d4-0000-4000-8000-000000000001:424242"
        );
        // The exact kernel form also without the trailing newline.
        assert_eq!(
            linux_start_token(stat, Ok("a1b2c3d4-0000-4000-8000-000000000001".to_string()))
                .unwrap(),
            "a1b2c3d4-0000-4000-8000-000000000001:424242"
        );
        // Unreadable boot ids fail closed: pid plus boot-relative ticks alone
        // can repeat after a reboot.
        let unreadable = linux_start_token(
            stat,
            Err(std::io::Error::new(
                std::io::ErrorKind::PermissionDenied,
                "denied",
            )),
        )
        .unwrap_err();
        assert_eq!(unreadable.kind(), std::io::ErrorKind::PermissionDenied);
        // Anything but a canonical lowercase UUID fails closed, one case per
        // way of being wrong. Uppercase is rejected on purpose: the kernel
        // prints the boot id with `%pU`, which is always lowercase.
        for (label, bad) in [
            ("empty", ""),
            ("newline only", "\n"),
            ("whitespace only", "   \n"),
            ("garbage", "garbage\n"),
            ("too short", "a1b2c3d4-0000-4000-8000-00000000000\n"),
            ("too long", "a1b2c3d4-0000-4000-8000-0000000000012\n"),
            ("missing hyphens", "a1b2c3d40000400080000000000000001abc\n"),
            ("misplaced hyphen", "a1b2c3d4-0000-4000-80000-00000000001\n"),
            ("non-hex", "g1b2c3d4-0000-4000-8000-000000000001\n"),
            ("uppercase", "A1B2C3D4-0000-4000-8000-000000000001\n"),
            ("embedded space", "a1b2c3d4 0000-4000-8000-000000000001\n"),
            ("leading space", " a1b2c3d4-0000-4000-8000-000000000001\n"),
            ("trailing char", "a1b2c3d4-0000-4000-8000-000000000001x\n"),
            ("two newlines", "a1b2c3d4-0000-4000-8000-000000000001\n\n"),
            ("crlf", "a1b2c3d4-0000-4000-8000-000000000001\r\n"),
        ] {
            let err = linux_start_token(stat, Ok(bad.to_string())).unwrap_err();
            assert_eq!(
                err.kind(),
                std::io::ErrorKind::InvalidData,
                "{label}: {bad:?}"
            );
            assert!(
                err.to_string().contains("canonical lowercase UUID"),
                "{label}"
            );
        }
        assert!(is_canonical_boot_id("00000000-0000-0000-0000-000000000000"));
        assert!(is_canonical_boot_id("ffffffff-ffff-ffff-ffff-ffffffffffff"));
        assert!(!is_canonical_boot_id(
            "FFFFFFFF-FFFF-FFFF-FFFF-FFFFFFFFFFFF"
        ));
        // Malformed stat lines fail too.
        let boot = || Ok("a1b2c3d4-0000-4000-8000-000000000001".to_string());
        assert!(linux_start_token("garbage", boot()).is_err());
        assert!(linux_start_token("1 (x) S 0 1", boot()).is_err());
        assert!(linux_start_token(
            "1 (x) S 0 1 1 0 -1 4194560 100 0 0 0 5 3 0 0 20 0 1 0 notanumber 1000",
            boot()
        )
        .is_err());
    }

    #[test]
    fn startup_reset_touches_nothing_while_another_party_holds_the_lock() {
        let dir = kernel_fixture("startup-lock-timeout");
        std::fs::create_dir(&dir).expect("create location");
        let path = dir.join("pharos-beacon-health-v1");
        write_marker(&path, 1_000).expect("write previous-run marker");
        let held = lock_beacon_health(&path).expect("hold the lock as a writer would");
        let reason =
            initialize_beacon_health_within(&path, &generation(), Duration::from_millis(150))
                .unwrap_err();
        assert!(
            reason.contains("held by another beacon write or probe"),
            "{reason}"
        );
        assert!(reason.contains("nothing was removed"), "{reason}");
        assert_eq!(marker_stamp(&path), "1000");
        drop(held);
        assert_eq!(
            initialize_beacon_health_within(&path, &generation(), Duration::from_millis(150)),
            Ok(())
        );
        assert_eq!(marker_stamp(&path), "0");
        std::fs::remove_dir_all(&dir).expect("remove location");
    }

    #[test]
    fn failed_startup_reset_unlinks_only_the_marker_it_observed() {
        // Deterministic reset failure on any platform and user: a directory
        // squats on the writer's fixed temp name, so the temp cannot be
        // created while the marker itself stays removable.
        let dir = kernel_fixture("startup-observed-state");
        std::fs::create_dir(&dir).expect("create location");
        let path = dir.join("pharos-beacon-health-v1");
        write_marker(&path, 1_000).expect("write previous-run marker");
        let temp = beacon_health_sibling_path(&path, BEACON_HEALTH_WRITE_TEMP).unwrap();
        std::fs::create_dir(&temp).expect("block the writer temp");

        // A writer holding the lock publishes while startup waits: startup
        // times out and removes nothing, so the publish stands.
        let publisher = lock_beacon_health(&path).expect("writer takes the lock");
        let startup_path = path.clone();
        let startup = thread::spawn(move || {
            initialize_beacon_health_within(
                &startup_path,
                &generation(),
                Duration::from_millis(200),
            )
        });
        std::fs::remove_dir(&temp).expect("unblock temp for the publisher");
        write_beacon_health_locked(&path, 1_005, &generation(), &publisher)
            .expect("publish under the held lock");
        std::fs::create_dir(&temp).expect("block the writer temp again");
        let reason = startup.join().expect("startup thread").unwrap_err();
        assert!(reason.contains("nothing was removed"), "{reason}");
        drop(publisher);
        assert_eq!(marker_stamp(&path), "1005");

        // Under one lock scope the reset fails and the observed marker is the
        // one removed; a publish after the scope stands.
        let reason = initialize_beacon_health(&path, &generation()).unwrap_err();
        assert!(reason.contains("previous state removed"), "{reason}");
        assert!(matches!(
            read_beacon_health(&path),
            Err(BeaconHealthProblem::StateMissing(_))
        ));
        std::fs::remove_dir(&temp).expect("unblock temp");
        write_marker(&path, 1_010).expect("later publish stands");
        assert_eq!(marker_stamp(&path), "1010");

        // The conditional unlink itself: if the marker is no longer the file
        // that was observed, it is left alone.
        let lock = lock_beacon_health(&path).expect("lock");
        let observed = observe_beacon_health_marker(&path).unwrap();
        std::fs::remove_file(&path).expect("swap the marker");
        std::fs::write(&path, "v2 1020 1 x\n").expect("swap the marker");
        assert_eq!(
            invalidate_beacon_health_locked(&path, &observed, &lock),
            Ok("the marker changed during initialization and was left in place")
        );
        assert!(path.exists());
        let observed = observe_beacon_health_marker(&path).unwrap();
        assert_eq!(
            invalidate_beacon_health_locked(&path, &observed, &lock),
            Ok("previous state removed")
        );
        assert_eq!(
            invalidate_beacon_health_locked(&path, &observed, &lock),
            Ok("no previous state present")
        );
        drop(lock);
        std::fs::remove_dir_all(&dir).expect("remove location");
    }

    #[test]
    fn beacon_health_problems_name_the_missing_configuration() {
        let one_shot = BeaconHealthProblem::OneShot.to_string();
        assert!(
            one_shot.contains("PHAROS_INTERVAL is not set"),
            "{one_shot}"
        );
        assert!(one_shot.contains("one-shot"), "{one_shot}");

        let invalid = BeaconHealthProblem::InvalidInterval.to_string();
        assert!(
            invalid.contains("PHAROS_INTERVAL must be between"),
            "{invalid}"
        );

        let never = BeaconHealthProblem::NoSuccessfulReportYet.to_string();
        assert!(never.contains("no successful report"), "{never}");

        let unreadable = BeaconHealthProblem::StateUnreadable {
            path: PathBuf::from("/tmp/pharos-beacon-health-v1"),
            error: "permission denied".to_string(),
        }
        .to_string();
        assert!(
            unreadable.contains("/tmp/pharos-beacon-health-v1"),
            "{unreadable}"
        );
        assert!(
            unreadable.contains("could not be read: permission denied"),
            "{unreadable}"
        );
    }

    #[test]
    fn shared_image_healthcheck_dispatches_beacon_and_server_roles() {
        let dockerfile = include_str!("../../../Dockerfile");

        assert!(dockerfile.contains(r#"if [ -n "${PHAROS_URL:-}" ]; then"#));
        assert!(dockerfile.contains("exec /usr/local/bin/pharos-beacon healthcheck"));
        assert!(dockerfile.contains("exec /usr/local/bin/pharosd healthcheck"));
    }

    #[test]
    fn stalled_report_connection_obeys_the_overall_deadline() {
        use std::net::TcpListener;

        let listener = TcpListener::bind("127.0.0.1:0").expect("bind fixture listener");
        let address = listener.local_addr().unwrap();
        let server = thread::spawn(move || {
            let (_stream, _) = listener.accept().expect("accept fixture request");
            thread::sleep(Duration::from_millis(250));
        });
        let deadline = Duration::from_millis(50);
        let agent: ureq::Agent = ureq::Agent::config_builder()
            .timeout_connect(Some(deadline))
            .timeout_send_request(Some(deadline))
            .timeout_send_body(Some(deadline))
            .timeout_recv_response(Some(deadline))
            .timeout_recv_body(Some(deadline))
            .timeout_global(Some(deadline))
            .max_redirects(0)
            .build()
            .into();
        let started = Instant::now();
        assert!(agent
            .post(&format!("http://{address}/report"))
            .send("{}")
            .is_err());
        assert!(started.elapsed() < Duration::from_millis(500));
        server.join().unwrap();
    }

    #[test]
    fn bearer_token_prefers_file_and_fails_closed() {
        let temp = std::env::temp_dir().join(format!("pharos-token-test-{}", std::process::id()));
        std::fs::write(&temp, "file-token\n").expect("write token fixture");
        std::env::set_var("PHAROS_TOKEN", " env-token ");
        std::env::set_var("PHAROS_TOKEN_FILE", &temp);

        assert_eq!(bearer_token().unwrap(), Some("file-token".to_string()));

        std::fs::remove_file(&temp).expect("remove token fixture");
        let error = bearer_token().expect_err("missing configured file must fail closed");
        assert!(error.to_string().contains("PHAROS_TOKEN_FILE"));
        assert!(!error.to_string().contains("env-token"));

        std::env::remove_var("PHAROS_TOKEN");
        std::env::remove_var("PHAROS_TOKEN_FILE");
    }

    // PHAROS-193 --------------------------------------------------------------

    /// Tests run in parallel and each removes its own directory, so the name
    /// needs a counter: a timestamp alone can collide and one test then deletes
    /// another's lock mid-run.
    static LOCK_FIXTURE_COUNTER: std::sync::atomic::AtomicU64 =
        std::sync::atomic::AtomicU64::new(0);

    fn write_lock_document(document: serde_json::Value) -> std::path::PathBuf {
        let dir = std::env::temp_dir().join(format!(
            "pharos-beacon-lock-{}-{}",
            std::process::id(),
            LOCK_FIXTURE_COUNTER.fetch_add(1, std::sync::atomic::Ordering::Relaxed)
        ));
        std::fs::create_dir_all(&dir).expect("temp flake dir");
        std::fs::write(
            dir.join("flake.lock"),
            serde_json::to_vec(&document).expect("lock serializes"),
        )
        .expect("write lock");
        dir
    }

    fn write_lock_with_root(
        root_inputs: serde_json::Value,
        nodes: serde_json::Value,
    ) -> std::path::PathBuf {
        let mut all = nodes.as_object().expect("nodes object").clone();
        all.insert(
            "root".to_string(),
            serde_json::json!({ "inputs": root_inputs }),
        );
        write_lock_document(serde_json::json!({
            "root": "root",
            "nodes": serde_json::Value::Object(all)
        }))
    }

    fn days_ago(days: i64) -> i64 {
        now_unix() - days * 86_400
    }

    fn fixture_lock_and_evidence(dir: &Path) -> Option<(serde_json::Value, NixDeploymentEvidence)> {
        let raw = std::fs::read(dir.join("flake.lock")).ok()?;
        let lock: serde_json::Value = serde_json::from_slice(&raw).ok()?;
        let nodes = lock.get("nodes")?.as_object()?;
        let root = lock.get("root")?.as_str()?;
        let target = nodes.get(root)?.get("inputs")?.get("nixpkgs")?;
        let node = nodes.get(input_target_name(target)?)?;
        let evidence = NixDeploymentEvidence {
            schema: pharos_core::NIX_DEPLOYMENT_EVIDENCE_SCHEMA.to_string(),
            version: pharos_core::NIX_DEPLOYMENT_EVIDENCE_VERSION,
            source_revision: "a".repeat(40),
            flake_lock_sha256: sha256_hex(&raw),
            nixpkgs_revision: node.get("locked")?.get("rev")?.as_str()?.to_string(),
            nixpkgs_last_modified: node.get("locked")?.get("lastModified")?.as_i64()?,
            nixpkgs_channel: nixpkgs_channel(node)?,
        };
        Some((matching_flake_lock(dir.to_str()?, &evidence)?, evidence))
    }

    /// The real csb1 lock shape. The system tracks nixos-unstable and is 21
    /// days old, while a separate root input sits 218 days stale on an expired
    /// channel and transitive inputs of nixos-hardware are older still.
    /// PHAROS-196: only the system input may drive the reported number.
    fn fleet_shaped_lock() -> std::path::PathBuf {
        write_lock_with_root(
            serde_json::json!({
                "nixpkgs": "nixpkgs_6",
                "nixpkgs-stable": "nixpkgs-stable_2",
                "nixos-hardware": "nixos-hardware"
            }),
            serde_json::json!({
                "nixpkgs_6": {
                    "locked":   { "lastModified": days_ago(21), "rev": "1111111111111111111111111111111111111111" },
                    "original": { "ref": "nixos-unstable" }
                },
                "nixpkgs-stable_2": {
                    "locked":   { "lastModified": days_ago(218) },
                    "original": { "ref": "nixos-25.05" }
                },
                "nixos-hardware": {
                    "inputs": { "nixpkgs": "nixpkgs_3" },
                    "locked": { "lastModified": days_ago(30) }
                },
                "nixpkgs_3": { "locked": { "lastModified": days_ago(211) } },
                "disko":   { "locked": { "lastModified": days_ago(0) } },
                "systems": { "locked": { "lastModified": days_ago(1217) } }
            }),
        )
    }

    #[test]
    fn nixpkgs_freshness_reports_the_system_input_not_the_oldest_lookalike() {
        let dir = fleet_shaped_lock();

        // The original signal reads as completely fresh because disko moved today.
        let (lock, evidence) = fixture_lock_and_evidence(&dir).expect("generation evidence");
        assert_eq!(flake_lock_age_days(&lock), Some(0));

        // PHAROS-193 replaced that with the oldest nixpkgs-family node, which
        // reported 218d on an expired channel and reads as a patching gap the
        // host does not have. The system input is what decides its posture.
        let freshness = nixpkgs_freshness(&lock, &evidence).expect("nixpkgs observed");
        assert_eq!(
            freshness.age_days, 21,
            "must report the flake's own nixpkgs input"
        );
        assert_eq!(freshness.channel.as_deref(), Some("nixos-unstable"));
        assert_eq!(
            freshness.secondary,
            Some(NixpkgsInputFreshness {
                input: "nixpkgs-stable".to_string(),
                age_days: 218,
                channel: Some("nixos-25.05".to_string()),
            }),
            "the stale root side input remains visible as secondary context"
        );

        // An unstable channel is rolling, so it is never flagged end of life.
        assert_eq!(
            pharos_core::nix_channel_state("nixos-unstable", 2026, 8),
            pharos_core::NixChannelState::Rolling
        );

        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn nixpkgs_freshness_still_flags_a_system_input_on_an_expired_channel() {
        // The case that must keep working: the system itself is on a dead release.
        let dir = write_lock_with_root(
            serde_json::json!({ "nixpkgs": "nixpkgs" }),
            serde_json::json!({
                "nixpkgs": {
                    "locked":   { "lastModified": days_ago(218), "rev": "2222222222222222222222222222222222222222" },
                    "original": { "ref": "nixos-25.05" }
                },
                "disko": { "locked": { "lastModified": days_ago(0) } }
            }),
        );
        let (lock, evidence) = fixture_lock_and_evidence(&dir).expect("generation evidence");
        let freshness = nixpkgs_freshness(&lock, &evidence).expect("observed");
        assert_eq!(freshness.age_days, 218);
        assert_eq!(freshness.channel.as_deref(), Some("nixos-25.05"));
        assert_eq!(freshness.secondary, None);
        assert_eq!(
            pharos_core::nix_channel_state("nixos-25.05", 2026, 8),
            pharos_core::NixChannelState::EndOfLife
        );
        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn nixpkgs_freshness_resolves_a_follows_target_and_tolerates_odd_locks() {
        // A `follows` entry is a path; only its first element names a node.
        let dir = write_lock_with_root(
            serde_json::json!({ "nixpkgs": ["nixpkgs_2"] }),
            serde_json::json!({
                "nixpkgs_2": {
                    "locked":   { "lastModified": days_ago(9), "rev": "3333333333333333333333333333333333333333" },
                    "original": { "ref": "nixos-26.05" }
                }
            }),
        );
        let (lock, evidence) = fixture_lock_and_evidence(&dir).expect("generation evidence");
        let freshness = nixpkgs_freshness(&lock, &evidence).expect("observed");
        assert_eq!(freshness.age_days, 9);
        assert_eq!(freshness.channel.as_deref(), Some("nixos-26.05"));
        let _ = std::fs::remove_dir_all(dir);

        // No nixpkgs input at all: report nothing rather than guess.
        let dir = write_lock_with_root(
            serde_json::json!({ "disko": "disko" }),
            serde_json::json!({ "disko": { "locked": { "lastModified": days_ago(3) } } }),
        );
        assert_eq!(fixture_lock_and_evidence(&dir), None);
        let _ = std::fs::remove_dir_all(dir);

        // An unsafe ref is dropped rather than propagated into the report.
        let dir = write_lock_with_root(
            serde_json::json!({ "nixpkgs": "nixpkgs" }),
            serde_json::json!({
                "nixpkgs": {
                    "locked":   { "lastModified": days_ago(4), "rev": "4444444444444444444444444444444444444444" },
                    "original": { "ref": "https://example.invalid/x?token=abc" }
                }
            }),
        );
        assert_eq!(fixture_lock_and_evidence(&dir), None);
        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn nixpkgs_freshness_is_absent_without_a_readable_lock() {
        assert_eq!(
            fixture_lock_and_evidence(Path::new("/nonexistent/pharos-193")),
            None
        );
    }

    fn test_git(dir: &Path, args: &[&str]) -> String {
        let output = Command::new("git")
            .arg("-C")
            .arg(dir)
            .args(args)
            .output()
            .expect("run fixture git");
        assert!(
            output.status.success(),
            "git {:?} failed: {}",
            args,
            String::from_utf8_lossy(&output.stderr)
        );
        String::from_utf8(output.stdout)
            .expect("git output utf-8")
            .trim()
            .to_string()
    }

    fn commit_fixture(checkout: &Path, name: &str, body: &str) -> String {
        std::fs::write(checkout.join(name), body).expect("write fixture file");
        test_git(checkout, &["add", name]);
        test_git(
            checkout,
            &[
                "-c",
                "user.name=Pharos Test",
                "-c",
                "user.email=pharos@example.invalid",
                "commit",
                "-m",
                name,
            ],
        );
        test_git(checkout, &["rev-parse", "HEAD"])
    }

    #[test]
    fn exact_git_comparison_proves_current_behind_ahead_and_diverged() {
        let root = std::env::temp_dir().join(format!(
            "pharos-git-proof-{}-{}",
            std::process::id(),
            LOCK_FIXTURE_COUNTER.fetch_add(1, std::sync::atomic::Ordering::Relaxed)
        ));
        let checkout = root.join("checkout");
        let remote = root.join("remote.git");
        let reference = root.join("reference.git");
        std::fs::create_dir_all(&checkout).expect("create checkout");
        test_git(&checkout, &["init", "--initial-branch=main"]);
        let first = commit_fixture(&checkout, "first", "one");
        std::fs::create_dir_all(&remote).expect("create remote");
        test_git(&remote, &["init", "--bare"]);
        test_git(
            &checkout,
            &[
                "remote",
                "add",
                "origin",
                remote.to_str().expect("remote path"),
            ],
        );
        test_git(&checkout, &["push", "-u", "origin", "main"]);

        let current = nixcfg_git_comparison_from_remote(
            checkout.to_str().expect("checkout path"),
            &first,
            remote.to_str().expect("remote path"),
            "refs/heads/main",
            &reference,
        )
        .expect("current comparison");
        assert_eq!(current.relation, GitRevisionRelation::Current);
        assert_eq!(current.commits_behind, Some(0));

        let second = commit_fixture(&checkout, "second", "two");
        test_git(&checkout, &["push", "origin", "main"]);
        let behind = nixcfg_git_comparison_from_remote(
            checkout.to_str().expect("checkout path"),
            &first,
            remote.to_str().expect("remote path"),
            "refs/heads/main",
            &reference,
        )
        .expect("behind comparison");
        assert_eq!(behind.upstream_revision, second);
        assert_eq!(behind.relation, GitRevisionRelation::Behind);
        assert_eq!(behind.commits_behind, Some(1));

        let ahead_revision = commit_fixture(&checkout, "ahead", "three");
        let ahead = nixcfg_git_comparison_from_remote(
            checkout.to_str().expect("checkout path"),
            &ahead_revision,
            remote.to_str().expect("remote path"),
            "refs/heads/main",
            &reference,
        )
        .expect("ahead comparison");
        assert_eq!(ahead.relation, GitRevisionRelation::Ahead);
        assert_eq!(ahead.commits_behind, None);

        test_git(&checkout, &["checkout", "-b", "divergent", &first]);
        let divergent_revision = commit_fixture(&checkout, "divergent", "other");
        let diverged = nixcfg_git_comparison_from_remote(
            checkout.to_str().expect("checkout path"),
            &divergent_revision,
            remote.to_str().expect("remote path"),
            "refs/heads/main",
            &reference,
        )
        .expect("diverged comparison");
        assert_eq!(diverged.relation, GitRevisionRelation::Diverged);
        assert_eq!(diverged.commits_behind, None);

        assert_eq!(
            nixcfg_git_comparison_from_remote(
                checkout.to_str().expect("checkout path"),
                &first,
                root.join("missing.git").to_str().expect("missing path"),
                "refs/heads/main",
                &reference,
            ),
            None,
            "a failed authoritative fetch must never reuse the previous success"
        );
        let _ = std::fs::remove_dir_all(root);
    }

    #[test]
    fn nixpkgs_comparison_is_exact_or_unknown_never_inferred() {
        let root = std::env::temp_dir().join(format!(
            "pharos-nixpkgs-proof-{}-{}",
            std::process::id(),
            LOCK_FIXTURE_COUNTER.fetch_add(1, std::sync::atomic::Ordering::Relaxed)
        ));
        let checkout = root.join("checkout");
        let remote = root.join("remote.git");
        std::fs::create_dir_all(&checkout).expect("create checkout");
        test_git(&checkout, &["init", "--initial-branch=main"]);
        let revision = commit_fixture(&checkout, "nixpkgs", "locked");
        std::fs::create_dir_all(&remote).expect("create remote");
        test_git(&remote, &["init", "--bare"]);
        test_git(
            &checkout,
            &[
                "remote",
                "add",
                "origin",
                remote.to_str().expect("remote path"),
            ],
        );
        test_git(&checkout, &["push", "origin", "main"]);

        let mut evidence = NixDeploymentEvidence {
            schema: pharos_core::NIX_DEPLOYMENT_EVIDENCE_SCHEMA.to_string(),
            version: pharos_core::NIX_DEPLOYMENT_EVIDENCE_VERSION,
            source_revision: "1".repeat(40),
            flake_lock_sha256: "2".repeat(64),
            nixpkgs_revision: revision,
            nixpkgs_last_modified: 1_700_000_000,
            nixpkgs_channel: "main".to_string(),
        };
        let current =
            nixpkgs_git_comparison_from_remote(&evidence, remote.to_str().expect("remote path"))
                .expect("exact comparison");
        assert_eq!(current.relation, NixpkgsRevisionRelation::Current);

        evidence.nixpkgs_revision = "9".repeat(40);
        let different =
            nixpkgs_git_comparison_from_remote(&evidence, remote.to_str().expect("remote path"))
                .expect("different comparison");
        assert_eq!(different.relation, NixpkgsRevisionRelation::Different);
        assert_eq!(
            nixpkgs_git_comparison_from_remote(
                &evidence,
                root.join("missing.git").to_str().expect("missing path")
            ),
            None
        );
        let _ = std::fs::remove_dir_all(root);
    }

    #[test]
    fn official_nixpkgs_channel_revision_is_bounded_exact_and_fail_closed() {
        let evidence = NixDeploymentEvidence {
            schema: pharos_core::NIX_DEPLOYMENT_EVIDENCE_SCHEMA.to_string(),
            version: pharos_core::NIX_DEPLOYMENT_EVIDENCE_VERSION,
            source_revision: "1".repeat(40),
            flake_lock_sha256: "2".repeat(64),
            nixpkgs_revision: "3".repeat(40),
            nixpkgs_last_modified: 1_700_000_000,
            nixpkgs_channel: "nixos-unstable".to_string(),
        };
        let current = nixpkgs_comparison_from_revision(&evidence, &format!("{}\n", "3".repeat(40)))
            .expect("exact channel revision");
        assert_eq!(current.relation, NixpkgsRevisionRelation::Current);
        let different = nixpkgs_comparison_from_revision(&evidence, &"4".repeat(40))
            .expect("different channel revision");
        assert_eq!(different.relation, NixpkgsRevisionRelation::Different);
        for malformed in ["", "3", &"G".repeat(40), &"3".repeat(129)] {
            assert_eq!(nixpkgs_comparison_from_revision(&evidence, malformed), None);
        }
        assert_eq!(
            read_bounded_nixpkgs_revision(format!("{}\n", "3".repeat(40)).as_bytes()),
            Some("3".repeat(40))
        );
        assert_eq!(
            read_bounded_nixpkgs_revision("3".repeat(129).as_bytes()),
            None
        );
    }

    #[test]
    fn official_nixpkgs_channel_urls_reject_unsafe_authorities_and_redirects() {
        let source =
            nixpkgs_channel_revision_url("nixos-unstable", DEFAULT_NIXPKGS_CHANNEL_BASE_URL)
                .expect("official channel URL");
        assert_eq!(
            source.as_str(),
            "https://channels.nixos.org/nixos-unstable/git-revision"
        );
        for base in [
            "http://channels.nixos.org/",
            "https://user:secret@channels.nixos.org/",
            "https://channels.nixos.org/?token=value",
            "file:///tmp/channels/",
        ] {
            assert!(nixpkgs_channel_revision_url("nixos-unstable", base).is_none());
        }
        for channel in ["", "../unstable", "nixos unstable", "nixos/unstable"] {
            assert!(
                nixpkgs_channel_revision_url(channel, DEFAULT_NIXPKGS_CHANNEL_BASE_URL).is_none()
            );
        }

        let release = safe_nixpkgs_channel_redirect(
            &source,
            "https://releases.nixos.org/nixos/unstable/nixos-test/git-revision",
        )
        .expect("official release redirect");
        assert_eq!(release.host_str(), Some("releases.nixos.org"));
        for location in [
            "http://releases.nixos.org/nixos/unstable/nixos-test/git-revision",
            "https://example.com/nixos/unstable/nixos-test/git-revision",
            "https://releases.nixos.org/other/git-revision",
            "https://releases.nixos.org/nixos/unstable/nixos-test/archive.tar.xz",
            "https://user:secret@releases.nixos.org/nixos/unstable/nixos-test/git-revision",
        ] {
            assert!(safe_nixpkgs_channel_redirect(&source, location).is_none());
        }
        assert!(is_official_nixpkgs_git_remote(OFFICIAL_NIXPKGS_GIT_REMOTE));
        assert!(!is_official_nixpkgs_git_remote(
            "https://github.com/example/nixpkgs.git"
        ));
    }

    #[test]
    fn generation_lock_and_remote_configuration_fail_closed() {
        assert!(safe_git_remote("https://github.com/markus-barta/nixcfg.git").is_some());
        for unsafe_remote in [
            "http://github.com/markus-barta/nixcfg.git",
            "https://user:secret@github.com/repo.git",
            "https://github.com/repo.git?token=value",
            "file:///tmp/repo.git",
        ] {
            assert!(safe_git_remote(unsafe_remote).is_none(), "{unsafe_remote}");
        }
        assert!(safe_git_branch_ref("refs/heads/main").is_some());
        for unsafe_ref in [
            "main",
            "refs/tags/main",
            "refs/heads/../main",
            "refs/heads/x@{1}",
        ] {
            assert!(safe_git_branch_ref(unsafe_ref).is_none(), "{unsafe_ref}");
        }

        let dir = fleet_shaped_lock();
        let (_, evidence) = fixture_lock_and_evidence(&dir).expect("fixture evidence");
        std::fs::write(dir.join("flake.lock"), b"{}").expect("replace mutable checkout lock");
        assert_eq!(
            matching_flake_lock(dir.to_str().expect("path"), &evidence),
            None,
            "a checkout lock that differs from the generation digest is not evidence"
        );
        let _ = std::fs::remove_dir_all(dir);
    }
}
