//! Reads the fleet data file and keeps the last good copy.
//!
//! The file arrives by atomic rename into a read-only directory, so a poll of
//! this one path sees every change and nothing else in that directory matters.
//! A missing or invalid file never stops pharosd: it keeps what it last read and
//! says what is wrong. There is no write path.

use std::io::Read;
use std::path::{Path, PathBuf};
use std::sync::{Arc, RwLock};
use std::time::Duration;

use pharos_core::fleet_data::{FleetData, MAX_FLEET_DATA_BYTES};
use sha2::{Digest, Sha256};

const POLL_INTERVAL: Duration = Duration::from_secs(15);

pub(crate) struct FleetDataRuntime {
    path: PathBuf,
    state: RwLock<LoadState>,
}

#[derive(Default)]
struct LoadState {
    data: Option<Arc<FleetData>>,
    problem: Option<String>,
    /// The content last judged, so an unchanged file is not parsed again.
    digest: Option<[u8; 32]>,
}

/// What the page and the API show about the file right now.
#[derive(Clone)]
pub(crate) struct FleetDataView {
    pub(crate) data: Option<Arc<FleetData>>,
    pub(crate) problem: Option<String>,
}

impl FleetDataRuntime {
    pub(crate) fn from_env() -> Option<Arc<Self>> {
        let path = std::env::var("PHAROS_FLEET_DATA_FILE").ok()?;
        let path = path.trim();
        (!path.is_empty()).then(|| {
            let runtime = Arc::new(Self::new(PathBuf::from(path)));
            runtime.refresh();
            runtime
        })
    }

    fn new(path: PathBuf) -> Self {
        Self {
            path,
            state: RwLock::new(LoadState::default()),
        }
    }

    pub(crate) fn view(&self) -> FleetDataView {
        let state = self.state.read().expect("fleet data lock");
        FleetDataView {
            data: state.data.clone(),
            problem: state.problem.clone(),
        }
    }

    /// Read the file once. Failures only ever add a problem to the last good data.
    pub(crate) fn refresh(&self) {
        let outcome = read_bounded(&self.path).map(|bytes| {
            let digest: [u8; 32] = Sha256::digest(&bytes).into();
            let unchanged = self.state.read().expect("fleet data lock").digest == Some(digest);
            (!unchanged).then(|| (digest, judge(&bytes)))
        });
        let mut state = self.state.write().expect("fleet data lock");
        match outcome {
            Ok(None) => {}
            Ok(Some((digest, Ok(data)))) => {
                tracing::info!(updated_at = %data.updated_at, "fleet data loaded");
                state.digest = Some(digest);
                state.data = Some(Arc::new(data));
                state.problem = None;
            }
            Ok(Some((digest, Err(problem)))) => {
                tracing::warn!(%problem, "fleet data refused; keeping the last good copy");
                state.digest = Some(digest);
                state.problem = Some(problem);
            }
            Err(problem) => {
                if state.problem.as_deref() != Some(problem.as_str()) {
                    tracing::warn!(%problem, "fleet data unavailable; keeping the last good copy");
                }
                // Forget the content, so the same file coming back is judged again.
                state.digest = None;
                state.problem = Some(problem);
            }
        }
    }
}

fn judge(bytes: &[u8]) -> Result<FleetData, String> {
    let raw = std::str::from_utf8(bytes).map_err(|_| "the file is not UTF-8 text".to_string())?;
    FleetData::parse(raw).map_err(|error| error.to_string())
}

fn read_bounded(path: &Path) -> Result<Vec<u8>, String> {
    let metadata = std::fs::metadata(path).map_err(|error| match error.kind() {
        std::io::ErrorKind::NotFound => "the file is missing".to_string(),
        _ => "the file cannot be read".to_string(),
    })?;
    if !metadata.is_file() {
        return Err("the path is not a regular file".to_string());
    }
    let mut bytes = Vec::new();
    std::fs::File::open(path)
        .and_then(|file| file.take(MAX_FLEET_DATA_BYTES + 1).read_to_end(&mut bytes))
        .map_err(|_| "the file cannot be read".to_string())?;
    if bytes.len() as u64 > MAX_FLEET_DATA_BYTES {
        return Err("the file is too large".to_string());
    }
    Ok(bytes)
}

pub(crate) fn spawn_fleet_data_loop(runtime: Arc<FleetDataRuntime>) {
    tokio::spawn(async move {
        let mut interval = tokio::time::interval(POLL_INTERVAL);
        interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        loop {
            interval.tick().await;
            let runtime = Arc::clone(&runtime);
            if tokio::task::spawn_blocking(move || runtime.refresh())
                .await
                .is_err()
            {
                tracing::error!("fleet data refresh stopped unexpectedly");
            }
        }
    });
}

#[cfg(test)]
pub(crate) const CONTRACT: &str = include_str!("../../../contracts/fleet-data-v3.json");

#[cfg(test)]
impl FleetDataRuntime {
    pub(crate) fn for_test(path: PathBuf) -> Arc<Self> {
        let runtime = Arc::new(Self::new(path));
        runtime.refresh();
        runtime
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    struct Directory(PathBuf);

    impl Directory {
        fn new(label: &str) -> Self {
            let path = std::env::temp_dir().join(format!(
                "pharos-fleet-data-{label}-{}-{}",
                std::process::id(),
                std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .expect("clock after epoch")
                    .as_nanos()
            ));
            std::fs::create_dir(&path).expect("directory created");
            Self(path)
        }

        fn file(&self) -> PathBuf {
            self.0.join("fleet.json")
        }

        /// How the file really arrives: a temp name in the same directory, then a rename.
        fn publish(&self, content: &[u8]) {
            let temporary = self.0.join("fleet.json.tmp-publish");
            std::fs::write(&temporary, content).expect("temporary written");
            std::fs::rename(&temporary, self.file()).expect("renamed into place");
        }
    }

    impl Drop for Directory {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    fn with_title(title: &str) -> String {
        let mut value: serde_json::Value = serde_json::from_str(CONTRACT).expect("contract");
        value["title"] = title.into();
        value.to_string()
    }

    #[test]
    fn a_valid_file_loads_and_each_change_is_picked_up() {
        let directory = Directory::new("change");
        directory.publish(with_title("First").as_bytes());
        let runtime = FleetDataRuntime::for_test(directory.file());
        let view = runtime.view();
        assert_eq!(view.data.expect("loaded").title, "First");
        assert_eq!(view.problem, None);

        directory.publish(with_title("Second").as_bytes());
        runtime.refresh();
        assert_eq!(runtime.view().data.expect("loaded").title, "Second");
    }

    #[test]
    fn a_missing_file_is_a_problem_not_a_failure() {
        let directory = Directory::new("missing");
        let runtime = FleetDataRuntime::for_test(directory.file());
        let view = runtime.view();
        assert!(view.data.is_none());
        assert_eq!(view.problem.as_deref(), Some("the file is missing"));

        directory.publish(CONTRACT.as_bytes());
        runtime.refresh();
        let view = runtime.view();
        assert!(view.data.is_some());
        assert_eq!(view.problem, None);
    }

    #[test]
    fn the_last_good_data_survives_every_kind_of_bad_file() {
        let directory = Directory::new("last-good");
        directory.publish(with_title("Good").as_bytes());
        let runtime = FleetDataRuntime::for_test(directory.file());

        let oversized = vec![b' '; MAX_FLEET_DATA_BYTES as usize + 1];
        let cases: [(&[u8], &str); 4] = [
            (b"not json", "not valid fleet data"),
            (br#"{"schema_version":2}"#, "unsupported schema_version 2"),
            (&[0xff, 0xfe], "not UTF-8"),
            (&oversized, "too large"),
        ];
        for (content, expected) in cases {
            directory.publish(content);
            runtime.refresh();
            let view = runtime.view();
            assert_eq!(view.data.expect("still has data").title, "Good");
            let problem = view.problem.expect("names the problem");
            assert!(problem.contains(expected), "{expected}: {problem}");
        }

        std::fs::remove_file(directory.file()).expect("file removed");
        runtime.refresh();
        let view = runtime.view();
        assert_eq!(view.data.expect("still has data").title, "Good");
        assert_eq!(view.problem.as_deref(), Some("the file is missing"));

        // The very same good file coming back clears the problem.
        directory.publish(with_title("Good").as_bytes());
        runtime.refresh();
        let view = runtime.view();
        assert_eq!(view.data.expect("has data").title, "Good");
        assert_eq!(view.problem, None);
    }

    #[test]
    fn a_problem_stays_until_the_file_really_changes() {
        let directory = Directory::new("stays");
        directory.publish(b"not json");
        let runtime = FleetDataRuntime::for_test(directory.file());
        for _ in 0..3 {
            runtime.refresh();
            assert!(runtime.view().problem.is_some());
        }
    }

    #[test]
    fn a_directory_at_the_path_is_a_problem() {
        let directory = Directory::new("not-a-file");
        std::fs::create_dir(directory.file()).expect("directory at the path");
        let runtime = FleetDataRuntime::for_test(directory.file());
        assert_eq!(
            runtime.view().problem.as_deref(),
            Some("the path is not a regular file")
        );
    }

    #[test]
    fn other_names_in_the_directory_are_ignored() {
        let directory = Directory::new("other-names");
        directory.publish(with_title("Good").as_bytes());
        let runtime = FleetDataRuntime::for_test(directory.file());
        for name in ["fleet.json.tmp-publish", "tmp.abc123", "fleet.json.bak"] {
            std::fs::write(directory.0.join(name), b"not json").expect("other file written");
        }
        runtime.refresh();
        let view = runtime.view();
        assert_eq!(view.data.expect("loaded").title, "Good");
        assert_eq!(view.problem, None);
    }

    #[test]
    fn reading_never_changes_the_file_or_adds_to_the_directory() {
        let directory = Directory::new("read-only");
        directory.publish(CONTRACT.as_bytes());
        let runtime = FleetDataRuntime::for_test(directory.file());
        runtime.refresh();
        assert_eq!(
            std::fs::read(directory.file()).expect("file reads"),
            CONTRACT.as_bytes()
        );
        assert_eq!(std::fs::read_dir(&directory.0).expect("lists").count(), 1);
    }
}
