//! Provisioning state, provider execution, paid-work review, and existing-host orchestration.

use super::*;

pub(super) const PROVISIONING_JOB_SNAPSHOT_SCHEMA: &str =
    "inspr.pharos.provisioning-jobs-snapshot.v1";
pub(super) const PROVISIONING_JOB_SNAPSHOT_VERSION: u16 = 1;
pub(super) const PROVISIONING_JOB_STORE_MARKER_SCHEMA: &str =
    "inspr.pharos.provisioning-jobs-store.v1";

#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct ProvisioningJobSnapshot {
    schema: String,
    version: u16,
    store_id: String,
    jobs: Vec<ProvisioningJob>,
    content_sha256: String,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct ProvisioningJobStoreMarker {
    schema: String,
    version: u16,
    store_id: String,
}

pub(super) fn provisioning_job_store_marker_path(path: &Path) -> PathBuf {
    let mut marker = path.as_os_str().to_os_string();
    marker.push(".initialized");
    PathBuf::from(marker)
}

pub(super) fn provisioning_snapshot_digest(
    store_id: &str,
    jobs: &[ProvisioningJob],
) -> Result<String, String> {
    let encoded = serde_json::to_vec(jobs)
        .map_err(|_| "provisioning jobs could not be encoded".to_string())?;
    let mut digest = Sha256::new();
    digest.update(b"pharos.provisioning-jobs-snapshot.v1\0");
    digest.update(store_id.as_bytes());
    digest.update(b"\0");
    digest.update(encoded);
    Ok(hex(&digest.finalize()))
}

pub(super) fn validate_provisioning_jobs(
    snapshot: Vec<ProvisioningJob>,
) -> Result<BTreeMap<String, ProvisioningJob>, String> {
    let mut jobs = BTreeMap::new();
    let valid = snapshot.into_iter().all(|job| {
        let valid = job.validate_contract().is_ok()
            && paid_job_integrity_valid(&job)
            && !jobs.contains_key(&job.id);
        if valid {
            jobs.insert(job.id.clone(), job);
        }
        valid
    });
    if valid {
        Ok(jobs)
    } else {
        Err("provisioning job snapshot failed validation".to_string())
    }
}

pub(super) fn new_provisioning_store_id() -> Result<String, String> {
    let mut bytes = [0_u8; 32];
    std::fs::File::open("/dev/urandom")
        .and_then(|mut source| source.read_exact(&mut bytes))
        .map_err(|_| "provisioning store identity could not be generated".to_string())?;
    Ok(hex(&bytes))
}

pub(super) fn atomic_write_provisioning_file(path: &Path, contents: &[u8]) -> Result<(), String> {
    if let Some(dir) = path.parent() {
        std::fs::create_dir_all(dir)
            .map_err(|_| "provisioning job directory is unavailable".to_string())?;
    }
    let nonce = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_nanos())
        .unwrap_or_default();
    let temporary = path.with_extension(format!("pharos-tmp-{}-{nonce}", std::process::id()));
    let result = (|| -> std::io::Result<()> {
        let mut options = std::fs::OpenOptions::new();
        options.write(true).create_new(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.mode(0o600);
        }
        let mut file = options.open(&temporary)?;
        file.write_all(contents)?;
        file.sync_all()?;
        std::fs::rename(&temporary, path)?;
        if let Some(parent) = path.parent() {
            std::fs::File::open(parent)?.sync_all()?;
        }
        Ok(())
    })();
    if result.is_err() {
        let _ = std::fs::remove_file(&temporary);
    }
    result.map_err(|_| "provisioning jobs could not be durably stored".to_string())
}

pub(super) fn write_provisioning_snapshot(
    path: &Path,
    store_id: &str,
    jobs: &BTreeMap<String, ProvisioningJob>,
) -> Result<(), String> {
    let jobs = jobs.values().cloned().collect::<Vec<_>>();
    let snapshot = ProvisioningJobSnapshot {
        schema: PROVISIONING_JOB_SNAPSHOT_SCHEMA.to_string(),
        version: PROVISIONING_JOB_SNAPSHOT_VERSION,
        store_id: store_id.to_string(),
        content_sha256: provisioning_snapshot_digest(store_id, &jobs)?,
        jobs,
    };
    let encoded = serde_json::to_vec_pretty(&snapshot)
        .map_err(|_| "provisioning jobs could not be encoded".to_string())?;
    atomic_write_provisioning_file(path, &encoded)
}

pub(super) fn ensure_provisioning_store_marker(path: &Path, store_id: &str) -> Result<(), String> {
    let marker_path = provisioning_job_store_marker_path(path);
    match std::fs::read(&marker_path) {
        Ok(bytes) => {
            let marker = serde_json::from_slice::<ProvisioningJobStoreMarker>(&bytes)
                .map_err(|_| "provisioning store marker is malformed".to_string())?;
            if marker.schema != PROVISIONING_JOB_STORE_MARKER_SCHEMA
                || marker.version != PROVISIONING_JOB_SNAPSHOT_VERSION
                || marker.store_id != store_id
                || !is_sha256_hex(&marker.store_id)
                || marker
                    .store_id
                    .bytes()
                    .any(|byte| byte.is_ascii_uppercase())
            {
                return Err("provisioning store marker failed validation".to_string());
            }
            Ok(())
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            let marker = ProvisioningJobStoreMarker {
                schema: PROVISIONING_JOB_STORE_MARKER_SCHEMA.to_string(),
                version: PROVISIONING_JOB_SNAPSHOT_VERSION,
                store_id: store_id.to_string(),
            };
            let encoded = serde_json::to_vec_pretty(&marker)
                .map_err(|_| "provisioning store marker could not be encoded".to_string())?;
            atomic_write_provisioning_file(&marker_path, &encoded)
        }
        Err(_) => Err("provisioning store marker is unreadable".to_string()),
    }
}

pub(super) fn decode_provisioning_snapshot(
    bytes: &[u8],
    expected_store_id: Option<&str>,
) -> Result<(BTreeMap<String, ProvisioningJob>, String), String> {
    let snapshot = serde_json::from_slice::<ProvisioningJobSnapshot>(bytes)
        .map_err(|_| "provisioning job snapshot is malformed".to_string())?;
    if snapshot.schema != PROVISIONING_JOB_SNAPSHOT_SCHEMA
        || snapshot.version != PROVISIONING_JOB_SNAPSHOT_VERSION
        || !is_sha256_hex(&snapshot.store_id)
        || snapshot
            .store_id
            .bytes()
            .any(|byte| byte.is_ascii_uppercase())
        || !is_sha256_hex(&snapshot.content_sha256)
        || snapshot
            .content_sha256
            .bytes()
            .any(|byte| byte.is_ascii_uppercase())
        || expected_store_id.is_some_and(|expected| expected != snapshot.store_id)
        || provisioning_snapshot_digest(&snapshot.store_id, &snapshot.jobs)?
            != snapshot.content_sha256
    {
        return Err("provisioning job snapshot failed integrity validation".to_string());
    }
    let store_id = snapshot.store_id;
    let jobs = validate_provisioning_jobs(snapshot.jobs)?;
    Ok((jobs, store_id))
}

pub(super) struct ProvisioningJobStore {
    path: Option<PathBuf>,
    store_id: Option<String>,
    durable_ready: AtomicBool,
    jobs: RwLock<BTreeMap<String, ProvisioningJob>>,
    persistence_lock: Mutex<()>,
    cleanup_claims: Mutex<BTreeSet<String>>,
    counter: AtomicU64,
}

pub(super) fn new_managed_identity(
    credential_ref: &str,
    executor_owner: &str,
) -> ProvisioningManagedIdentity {
    ProvisioningManagedIdentity {
        credential_ref: credential_ref.to_string(),
        executor_owner: executor_owner.to_string(),
        state: ProvisioningManagedIdentityState::AwaitingHostKey,
        host_key_fingerprint: None,
        host_key_operator_ref: None,
        host_key_attested_at: None,
        lease_until: None,
        credential_ready_at: None,
        bootstrap_completed_at: None,
        first_heartbeat_at: None,
        credential_retired_at: None,
        last_failure: None,
    }
}

impl ProvisioningJobStore {
    pub(super) fn new(path: Option<PathBuf>) -> Self {
        let (jobs, store_id, durable_ready) = match path.as_ref() {
            None => (BTreeMap::new(), None, false),
            Some(path) => {
                let marker_path = provisioning_job_store_marker_path(path);
                let loaded = (|| -> Result<(BTreeMap<String, ProvisioningJob>, String), String> {
                    let marker = match std::fs::read(&marker_path) {
                        Ok(bytes) => {
                            let marker =
                                serde_json::from_slice::<ProvisioningJobStoreMarker>(&bytes)
                                    .map_err(|_| {
                                        "provisioning store marker is malformed".to_string()
                                    })?;
                            if marker.schema != PROVISIONING_JOB_STORE_MARKER_SCHEMA
                                || marker.version != PROVISIONING_JOB_SNAPSHOT_VERSION
                                || !is_sha256_hex(&marker.store_id)
                                || marker
                                    .store_id
                                    .bytes()
                                    .any(|byte| byte.is_ascii_uppercase())
                            {
                                return Err(
                                    "provisioning store marker failed validation".to_string()
                                );
                            }
                            Some(marker)
                        }
                        Err(error) if error.kind() == std::io::ErrorKind::NotFound => None,
                        Err(_) => return Err("provisioning store marker is unreadable".to_string()),
                    };
                    let marker_expected = marker.as_ref().map(|marker| marker.store_id.as_str());
                    match std::fs::read(path) {
                        Ok(bytes) => {
                            decode_provisioning_snapshot(&bytes, marker_expected).or_else(|_| {
                                if marker.is_some() {
                                    return Err(
                                        "initialized snapshot is not a valid envelope".to_string()
                                    );
                                }
                                let legacy = serde_json::from_slice::<Vec<ProvisioningJob>>(&bytes)
                                    .map_err(|_| {
                                        "legacy provisioning snapshot is malformed".to_string()
                                    })?;
                                let jobs = validate_provisioning_jobs(legacy)?;
                                let store_id = new_provisioning_store_id()?;
                                write_provisioning_snapshot(path, &store_id, &jobs)?;
                                Ok((jobs, store_id))
                            })
                        }
                        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                            if marker.is_some() {
                                Err("initialized provisioning snapshot is missing".to_string())
                            } else {
                                let jobs = BTreeMap::new();
                                let store_id = new_provisioning_store_id()?;
                                write_provisioning_snapshot(path, &store_id, &jobs)?;
                                Ok((jobs, store_id))
                            }
                        }
                        Err(_) => Err("provisioning job snapshot is unreadable".to_string()),
                    }
                })();
                match loaded {
                    Ok((jobs, store_id)) => {
                        if ensure_provisioning_store_marker(path, &store_id).is_ok() {
                            (jobs, Some(store_id), true)
                        } else {
                            tracing::error!(path = %path.display(), "provisioning store marker could not be validated; paid provider actions are disabled");
                            (BTreeMap::new(), None, false)
                        }
                    }
                    Err(error) => {
                        tracing::error!(path = %path.display(), error = %error, "provisioning job snapshot failed validation; paid provider actions are disabled");
                        (BTreeMap::new(), None, false)
                    }
                }
            }
        };
        Self {
            path,
            store_id,
            durable_ready: AtomicBool::new(durable_ready),
            jobs: RwLock::new(jobs),
            persistence_lock: Mutex::new(()),
            cleanup_claims: Mutex::new(BTreeSet::new()),
            counter: AtomicU64::new(1),
        }
    }

    pub(super) fn durable_ready(&self) -> bool {
        self.path.is_some() && self.durable_ready.load(Ordering::Acquire)
    }

    fn require_durable(&self) -> Result<(), ProvisioningPaidStoreError> {
        if self.durable_ready() {
            Ok(())
        } else {
            Err(ProvisioningPaidStoreError::PersistenceFailed)
        }
    }

    pub(super) fn start(
        &self,
        request: &ProvisioningJobStartRequest,
        now: i64,
        provider_runtime: &ProviderRuntimeConfig,
    ) -> Result<ProvisioningJob, ProvisioningJobStartError> {
        if request.provider == "hetzner-cloud" && !self.durable_ready() {
            return Err(ProvisioningJobStartError::PersistenceFailed);
        }
        if !valid_setup_provider(&request.provider) {
            return Err(ProvisioningJobStartError::UnsupportedProvider);
        }
        if !valid_setup_template(&request.provider, &request.template) {
            return Err(ProvisioningJobStartError::UnsupportedTemplate);
        }
        let id = loop {
            let candidate = format!(
                "setup-{now}-{}",
                self.counter.fetch_add(1, Ordering::Relaxed)
            );
            if !self
                .jobs
                .read()
                .expect("provisioning job store lock")
                .contains_key(&candidate)
            {
                break candidate;
            }
        };
        let (state, progress) = provisioning_job_progress(request, provider_runtime, now);
        let handoff = provisioning_job_handoff(request);
        let setup_intent = provisioning_setup_intent(request);
        let backup_proposal = provisioning_backup_proposal(request);
        let existing_host_context = provisioning_existing_host_context(request);
        let host_name = request
            .host_name
            .as_deref()
            .map(str::trim)
            .filter(|value| !value.is_empty())
            .map(str::to_string);
        let role = request
            .role
            .as_deref()
            .map(str::trim)
            .filter(|value| !value.is_empty())
            .map(str::to_string);
        let job = ProvisioningJob {
            schema: PROVISIONING_JOB_SCHEMA.to_string(),
            version: PROVISIONING_JOB_VERSION,
            id,
            provider: request.provider.to_string(),
            template: request.template.to_string(),
            host_name,
            role,
            is_nix: request.is_nix,
            heartbeat_interval_secs: request.heartbeat_interval_secs.filter(|value| *value > 0),
            existing_host_context,
            state,
            terminal_outcome: None,
            created_at: now,
            updated_at: now,
            handoff,
            setup_intent,
            backup_proposal,
            reviewed_plan: None,
            paid_authorization: None,
            paid_execution: None,
            managed_identity: None,
            provider_resources: vec![],
            progress,
        };
        job.validate_contract()
            .map_err(|_| ProvisioningJobStartError::InvalidJob)?;
        let mut jobs = self.jobs.write().expect("provisioning job store lock");
        let previous = jobs.insert(job.id.clone(), job.clone());
        if self.persist_jobs(&jobs).is_err() {
            if let Some(previous) = previous {
                jobs.insert(job.id.clone(), previous);
            } else {
                jobs.remove(&job.id);
            }
            return Err(ProvisioningJobStartError::PersistenceFailed);
        }
        Ok(job)
    }

    pub(super) fn get(&self, id: &str) -> Option<ProvisioningJob> {
        self.jobs
            .read()
            .expect("provisioning job store lock")
            .get(id)
            .cloned()
    }

    pub(super) fn list(&self) -> Vec<ProvisioningJob> {
        self.jobs
            .read()
            .expect("provisioning job store lock")
            .values()
            .cloned()
            .collect()
    }

    pub(super) fn paid_project_blocked(&self, except_id: Option<&str>) -> bool {
        let jobs = self.jobs.read().expect("provisioning job store lock");
        paid_project_blocked_in(&jobs, except_id)
    }

    pub(super) fn attach_paid_review(
        &self,
        id: &str,
        reviewed_plan: ProvisioningReviewedPaidPlan,
        now: i64,
    ) -> Result<ProvisioningJob, ProvisioningPaidStoreError> {
        self.require_durable()?;
        let mut jobs = self.jobs.write().expect("provisioning job store lock");
        if paid_project_blocked_in(&jobs, Some(id)) {
            return Err(ProvisioningPaidStoreError::ProjectBusy);
        }
        let previous = jobs
            .get(id)
            .cloned()
            .ok_or(ProvisioningPaidStoreError::NotFound)?;
        if previous.provider != "hetzner-cloud"
            || previous.state != ProvisioningJobState::Planning
            || previous.reviewed_plan.is_some()
            || previous.paid_authorization.is_some()
            || previous.paid_execution.is_some()
        {
            return Err(ProvisioningPaidStoreError::InvalidState);
        }
        let mut updated = previous.clone();
        updated.reviewed_plan = Some(reviewed_plan);
        updated.updated_at = now.max(updated.created_at);
        updated.progress.push(ProvisioningProgressEntry {
            state: ProvisioningJobState::Planning,
            message: "Exact paid provider plan stored for separate attended approval; no provider resource was created.".to_string(),
            observed_at: now,
        });
        updated
            .validate_contract()
            .map_err(|_| ProvisioningPaidStoreError::ContractFailed)?;
        if !paid_job_integrity_valid(&updated) {
            return Err(ProvisioningPaidStoreError::ContractFailed);
        }
        jobs.insert(id.to_string(), updated.clone());
        if self.persist_jobs(&jobs).is_err() {
            jobs.insert(id.to_string(), previous);
            return Err(ProvisioningPaidStoreError::PersistenceFailed);
        }
        Ok(updated)
    }

    pub(super) fn confirm_paid_review(
        &self,
        id: &str,
        plan_sha256: &str,
        operator_ref: &str,
        operator_label: &str,
        now: i64,
    ) -> Result<ProvisioningJob, ProvisioningPaidStoreError> {
        self.require_durable()?;
        let mut jobs = self.jobs.write().expect("provisioning job store lock");
        if paid_project_blocked_in(&jobs, Some(id)) {
            return Err(ProvisioningPaidStoreError::ProjectBusy);
        }
        let previous = jobs
            .get(id)
            .cloned()
            .ok_or(ProvisioningPaidStoreError::NotFound)?;
        let reviewed = previous
            .reviewed_plan
            .as_ref()
            .ok_or(ProvisioningPaidStoreError::InvalidState)?;
        if reviewed.plan_sha256 != plan_sha256 || reviewed_paid_plan_digest(reviewed) != plan_sha256
        {
            return Err(ProvisioningPaidStoreError::PlanMismatch);
        }
        if now >= reviewed.expires_at {
            return Err(ProvisioningPaidStoreError::Expired);
        }
        if let Some(authorization) = &previous.paid_authorization {
            return if authorization.plan_sha256 == plan_sha256
                && authorization.operator_ref == operator_ref
            {
                Ok(previous)
            } else {
                Err(ProvisioningPaidStoreError::OperatorMismatch)
            };
        }
        if previous.state != ProvisioningJobState::Planning || previous.paid_execution.is_some() {
            return Err(ProvisioningPaidStoreError::InvalidState);
        }
        let mut updated = previous.clone();
        updated.paid_authorization = Some(ProvisioningPaidAuthorization {
            plan_sha256: plan_sha256.to_string(),
            operator_ref: operator_ref.to_string(),
            operator_label: operator_label.to_string(),
            confirmed_at: now,
            expires_at: reviewed.expires_at,
        });
        updated.updated_at = now;
        updated.progress.push(ProvisioningProgressEntry {
            state: ProvisioningJobState::Planning,
            message: "Attended authorization stored for this exact plan; no provider resource was created and billing has not started.".to_string(),
            observed_at: now,
        });
        updated
            .validate_contract()
            .map_err(|_| ProvisioningPaidStoreError::ContractFailed)?;
        if !paid_job_integrity_valid(&updated) {
            return Err(ProvisioningPaidStoreError::ContractFailed);
        }
        jobs.insert(id.to_string(), updated.clone());
        if self.persist_jobs(&jobs).is_err() {
            jobs.insert(id.to_string(), previous);
            return Err(ProvisioningPaidStoreError::PersistenceFailed);
        }
        Ok(updated)
    }

    pub(super) fn claim_paid_execution(
        &self,
        id: &str,
        plan_sha256: &str,
        operator_ref: &str,
        now: i64,
    ) -> Result<ProvisioningJob, ProvisioningPaidStoreError> {
        self.require_durable()?;
        let mut jobs = self.jobs.write().expect("provisioning job store lock");
        if paid_project_blocked_in(&jobs, Some(id)) {
            return Err(ProvisioningPaidStoreError::ProjectBusy);
        }
        let previous = jobs
            .get(id)
            .cloned()
            .ok_or(ProvisioningPaidStoreError::NotFound)?;
        let reviewed = previous
            .reviewed_plan
            .as_ref()
            .ok_or(ProvisioningPaidStoreError::InvalidState)?;
        let authorization = previous
            .paid_authorization
            .as_ref()
            .ok_or(ProvisioningPaidStoreError::InvalidState)?;
        if reviewed.plan_sha256 != plan_sha256
            || authorization.plan_sha256 != plan_sha256
            || reviewed_paid_plan_digest(reviewed) != plan_sha256
        {
            return Err(ProvisioningPaidStoreError::PlanMismatch);
        }
        if authorization.operator_ref != operator_ref {
            return Err(ProvisioningPaidStoreError::OperatorMismatch);
        }
        if now >= authorization.expires_at {
            return Err(ProvisioningPaidStoreError::Expired);
        }
        if previous.paid_execution.is_some() {
            return Ok(previous);
        }
        if previous.state != ProvisioningJobState::Planning {
            return Err(ProvisioningPaidStoreError::InvalidState);
        }
        let attempt_id = format!("{}-1", previous.id);
        let mut updated = previous.clone();
        updated.state = ProvisioningJobState::Provisioning;
        updated.updated_at = now;
        updated.paid_execution = Some(ProvisioningPaidExecution {
            plan_sha256: plan_sha256.to_string(),
            attempt_id,
            state: "claimed".to_string(),
            claimed_at: now,
            provider_request_started_at: None,
            provider_id: None,
        });
        updated.progress.push(ProvisioningProgressEntry {
            state: ProvisioningJobState::Provisioning,
            message: "Single-use paid create claimed durably; final live provider checks are running before any create request.".to_string(),
            observed_at: now,
        });
        updated
            .validate_contract()
            .map_err(|_| ProvisioningPaidStoreError::ContractFailed)?;
        if !paid_job_integrity_valid(&updated) {
            return Err(ProvisioningPaidStoreError::ContractFailed);
        }
        jobs.insert(id.to_string(), updated.clone());
        if self.persist_jobs(&jobs).is_err() {
            jobs.insert(id.to_string(), previous);
            return Err(ProvisioningPaidStoreError::PersistenceFailed);
        }
        Ok(updated)
    }

    pub(super) fn mark_paid_request_started(
        &self,
        id: &str,
        plan_sha256: &str,
        now: i64,
    ) -> Result<ProvisioningJob, ProvisioningPaidStoreError> {
        self.update_paid_execution(id, plan_sha256, now, true, |execution| {
            if execution.state != "claimed" {
                return Err(ProvisioningPaidStoreError::InvalidState);
            }
            execution.state = "request-started".to_string();
            execution.provider_request_started_at = Some(now);
            Ok((
                ProvisioningJobState::Provisioning,
                "Final checks passed; the one authorized provider create request has started."
                    .to_string(),
            ))
        })
    }

    pub(super) fn fail_paid_execution(
        &self,
        id: &str,
        plan_sha256: &str,
        uncertain: bool,
        message: String,
        now: i64,
    ) -> Result<ProvisioningJob, ProvisioningPaidStoreError> {
        self.update_paid_execution(id, plan_sha256, now, false, |execution| {
            execution.state = if uncertain {
                "uncertain"
            } else {
                "failed-closed"
            }
            .to_string();
            Ok((
                if uncertain {
                    ProvisioningJobState::CleanupNeeded
                } else {
                    ProvisioningJobState::Failed
                },
                message,
            ))
        })
    }

    fn update_paid_execution(
        &self,
        id: &str,
        plan_sha256: &str,
        now: i64,
        require_unexpired: bool,
        update: impl FnOnce(
            &mut ProvisioningPaidExecution,
        )
            -> Result<(ProvisioningJobState, String), ProvisioningPaidStoreError>,
    ) -> Result<ProvisioningJob, ProvisioningPaidStoreError> {
        self.require_durable()?;
        let mut jobs = self.jobs.write().expect("provisioning job store lock");
        let previous = jobs
            .get(id)
            .cloned()
            .ok_or(ProvisioningPaidStoreError::NotFound)?;
        let mut updated = previous.clone();
        if require_unexpired
            && updated
                .paid_authorization
                .as_ref()
                .is_none_or(|authorization| now >= authorization.expires_at)
        {
            return Err(ProvisioningPaidStoreError::Expired);
        }
        let execution = updated
            .paid_execution
            .as_mut()
            .ok_or(ProvisioningPaidStoreError::InvalidState)?;
        if execution.plan_sha256 != plan_sha256 {
            return Err(ProvisioningPaidStoreError::PlanMismatch);
        }
        let (state, message) = update(execution)?;
        updated.state = state;
        updated.updated_at = now;
        updated.progress.push(ProvisioningProgressEntry {
            state,
            message,
            observed_at: now,
        });
        updated
            .validate_contract()
            .map_err(|_| ProvisioningPaidStoreError::ContractFailed)?;
        if !paid_job_integrity_valid(&updated) {
            return Err(ProvisioningPaidStoreError::ContractFailed);
        }
        jobs.insert(id.to_string(), updated.clone());
        if self.persist_jobs(&jobs).is_err() {
            jobs.insert(id.to_string(), previous);
            return Err(ProvisioningPaidStoreError::PersistenceFailed);
        }
        Ok(updated)
    }

    pub(super) fn complete_paid_create(
        &self,
        id: &str,
        plan_sha256: &str,
        resource: ProvisioningProviderResource,
        handoff: Option<ProvisioningHandoff>,
        reconciled: bool,
        now: i64,
    ) -> Result<ProvisioningJob, ProvisioningPaidStoreError> {
        self.require_durable()?;
        let mut jobs = self.jobs.write().expect("provisioning job store lock");
        let previous = jobs
            .get(id)
            .cloned()
            .ok_or(ProvisioningPaidStoreError::NotFound)?;
        let mut updated = previous.clone();
        let execution = updated
            .paid_execution
            .as_mut()
            .ok_or(ProvisioningPaidStoreError::InvalidState)?;
        if execution.plan_sha256 != plan_sha256
            || !matches!(execution.state.as_str(), "request-started" | "uncertain")
        {
            return Err(ProvisioningPaidStoreError::InvalidState);
        }
        execution.state = if reconciled { "reconciled" } else { "created" }.to_string();
        execution.provider_id = Some(resource.provider_id.clone());
        updated.state = if handoff.is_some() {
            ProvisioningJobState::WaitingForHeartbeat
        } else {
            ProvisioningJobState::CleanupNeeded
        };
        updated.updated_at = now;
        updated.provider_resources.clear();
        updated.provider_resources.push(resource);
        if updated.managed_identity.is_none() {
            if let Some((owner, credential_ref)) = updated.reviewed_plan.as_ref().and_then(|plan| {
                Some((
                    plan.managed_executor_owner.as_deref()?,
                    plan.managed_credential_ref.as_deref()?,
                ))
            }) {
                updated.managed_identity = Some(new_managed_identity(credential_ref, owner));
            }
        }
        if handoff.is_some() {
            updated.handoff = handoff;
        }
        updated.progress.push(ProvisioningProgressEntry {
            state: updated.state,
            message: if reconciled {
                "The single provider server was reconciled by its required ownership labels and reviewed server facts; no duplicate request was sent."
            } else {
                "The single authorized provider server was created and durably recorded."
            }
            .to_string(),
            observed_at: now,
        });
        updated
            .validate_contract()
            .map_err(|_| ProvisioningPaidStoreError::ContractFailed)?;
        if !paid_job_integrity_valid(&updated) {
            return Err(ProvisioningPaidStoreError::ContractFailed);
        }
        jobs.insert(id.to_string(), updated.clone());
        if self.persist_jobs(&jobs).is_err() {
            jobs.insert(id.to_string(), previous);
            return Err(ProvisioningPaidStoreError::PersistenceFailed);
        }
        Ok(updated)
    }

    pub(super) fn append_progress(
        &self,
        id: &str,
        state: ProvisioningJobState,
        message: impl Into<String>,
        now: i64,
    ) -> Option<ProvisioningJob> {
        let mut jobs = self.jobs.write().expect("provisioning job store lock");
        let job = jobs.get_mut(id)?;
        job.state = state;
        job.updated_at = now;
        job.progress.push(ProvisioningProgressEntry {
            state,
            message: message.into(),
            observed_at: now,
        });
        if job.validate_contract().is_err() {
            return None;
        }
        let job = job.clone();
        let _ = self.persist_jobs(&jobs);
        Some(job)
    }

    fn claim_provider_cleanup(&self, id: &str) -> bool {
        self.cleanup_claims
            .lock()
            .expect("provider cleanup claim lock")
            .insert(id.to_string())
    }

    fn release_provider_cleanup(&self, id: &str) {
        self.cleanup_claims
            .lock()
            .expect("provider cleanup claim lock")
            .remove(id);
    }

    fn begin_provider_cleanup(
        &self,
        id: &str,
        provider_id: &str,
        now: i64,
    ) -> Result<ProvisioningJob, ProvisioningPaidStoreError> {
        let mut jobs = self.jobs.write().expect("provisioning job store lock");
        let current = jobs
            .get(id)
            .cloned()
            .ok_or(ProvisioningPaidStoreError::NotFound)?;
        if current.reviewed_plan.is_some() {
            self.require_durable()?;
        }
        if !matches!(
            current.state,
            ProvisioningJobState::WaitingForHeartbeat
                | ProvisioningJobState::BackupPending
                | ProvisioningJobState::Complete
                | ProvisioningJobState::CleanupNeeded
        ) {
            return Err(ProvisioningPaidStoreError::InvalidState);
        }
        let matching: Vec<&ProvisioningProviderResource> = current
            .provider_resources
            .iter()
            .filter(|resource| {
                resource.provider == "hetzner-cloud"
                    && resource.kind == "server"
                    && resource.provider_id == provider_id
                    && matches!(
                        resource.state.as_str(),
                        "created" | "created-address-pending"
                    )
            })
            .collect();
        if current.provider_resources.len() != 1 || matching.len() != 1 {
            return Err(ProvisioningPaidStoreError::InvalidState);
        }

        let mut updated = current.clone();
        updated.state = ProvisioningJobState::CleanupNeeded;
        updated.terminal_outcome = None;
        updated.updated_at = now;
        updated.progress.push(ProvisioningProgressEntry {
            state: ProvisioningJobState::CleanupNeeded,
            message:
                "Confirmed provider cleanup started; waiting for Hetzner Cloud to prove deletion."
                    .to_string(),
            observed_at: now,
        });
        updated
            .validate_contract()
            .map_err(|_| ProvisioningPaidStoreError::ContractFailed)?;
        if !paid_job_integrity_valid(&updated) {
            return Err(ProvisioningPaidStoreError::ContractFailed);
        }
        jobs.insert(id.to_string(), updated.clone());
        if self.persist_jobs(&jobs).is_err() {
            jobs.insert(id.to_string(), current);
            return Err(ProvisioningPaidStoreError::PersistenceFailed);
        }
        Ok(updated)
    }

    fn complete_provider_cleanup(
        &self,
        id: &str,
        resource: ProvisioningProviderResource,
        handoff: ProvisioningHandoff,
        now: i64,
    ) -> Result<ProvisioningJob, ProvisioningPaidStoreError> {
        let mut jobs = self.jobs.write().expect("provisioning job store lock");
        let current = jobs
            .get(id)
            .cloned()
            .ok_or(ProvisioningPaidStoreError::NotFound)?;
        if current.reviewed_plan.is_some() {
            self.require_durable()?;
        }
        if current.state != ProvisioningJobState::CleanupNeeded {
            return Err(ProvisioningPaidStoreError::InvalidState);
        }
        let mut updated = current.clone();
        let retirement_required = updated
            .managed_identity
            .as_ref()
            .is_some_and(|identity| identity.credential_ready_at.is_some());
        updated.state = if retirement_required {
            ProvisioningJobState::CleanupNeeded
        } else {
            ProvisioningJobState::Complete
        };
        updated.terminal_outcome =
            (!retirement_required).then_some(ProvisioningTerminalOutcome::RolledBack);
        updated.updated_at = now;
        updated.progress.push(ProvisioningProgressEntry {
            state: updated.state,
            message: if retirement_required {
                "Tracked Hetzner server deleted; the exact job-owned Janus credential is queued for retirement before cleanup can complete."
            } else {
                "Tracked Hetzner server deleted; setup ended without an active provider resource or issued host credential."
            }
            .to_string(),
            observed_at: now,
        });
        updated
            .provider_resources
            .retain(|existing| existing.provider_id != resource.provider_id);
        updated.provider_resources.push(resource);
        let mut handoff = handoff;
        if retirement_required {
            handoff.status = "provider-resource-deleted-identity-cleanup-pending".to_string();
            handoff.summary = "The provider server is deleted. The reviewed Janus owner is retiring the exact job-owned credential before Pharos removes any owned runtime host state.".to_string();
            handoff.token_policy = "The raw credential remains inside the Janus boundary while retirement is reconciled.".to_string();
            handoff.next_steps = vec![
                "Wait for the Janus retirement owner to report value-free completion evidence."
                    .to_string(),
                "If retirement remains pending, review the recorded safe reason; do not create a replacement credential blindly."
                    .to_string(),
            ];
        }
        updated.handoff = Some(handoff);
        if let Some(identity) = updated.managed_identity.as_mut() {
            identity.lease_until = None;
            identity.last_failure = None;
            if retirement_required {
                identity.state = ProvisioningManagedIdentityState::RetirementPending;
            } else {
                identity.state = ProvisioningManagedIdentityState::CredentialRetired;
                identity.credential_retired_at = Some(now);
            }
        }
        updated
            .validate_contract()
            .map_err(|_| ProvisioningPaidStoreError::ContractFailed)?;
        if !paid_job_integrity_valid(&updated) {
            return Err(ProvisioningPaidStoreError::ContractFailed);
        }
        jobs.insert(id.to_string(), updated.clone());
        if self.persist_jobs(&jobs).is_err() {
            jobs.insert(id.to_string(), current);
            return Err(ProvisioningPaidStoreError::PersistenceFailed);
        }
        Ok(updated)
    }

    pub(super) fn transition_existing_host(
        &self,
        id: &str,
        state: ProvisioningJobState,
        message: impl Into<String>,
        handoff_status: &str,
        handoff_summary: &str,
        now: i64,
    ) -> Option<ProvisioningJob> {
        let mut jobs = self.jobs.write().expect("provisioning job store lock");
        let job = jobs.get_mut(id)?;
        job.state = state;
        job.updated_at = now;
        job.progress.push(ProvisioningProgressEntry {
            state,
            message: message.into(),
            observed_at: now,
        });
        if let Some(handoff) = job.handoff.as_mut() {
            handoff.status = handoff_status.to_string();
            handoff.summary = handoff_summary.to_string();
        }
        if job.validate_contract().is_err() {
            return None;
        }
        let job = job.clone();
        let _ = self.persist_jobs(&jobs);
        Some(job)
    }

    fn persist_jobs(&self, jobs: &BTreeMap<String, ProvisioningJob>) -> Result<(), String> {
        let Some(path) = &self.path else {
            return Ok(());
        };
        let Some(store_id) = &self.store_id else {
            self.durable_ready.store(false, Ordering::Release);
            return Err("provisioning store identity is unavailable".to_string());
        };
        let _persistence = self
            .persistence_lock
            .lock()
            .map_err(|_| "provisioning persistence lock failed".to_string())?;
        let result = ensure_provisioning_store_marker(path, store_id)
            .and_then(|()| write_provisioning_snapshot(path, store_id, jobs));
        if result.is_err() {
            self.durable_ready.store(false, Ordering::Release);
        }
        result
    }
}

const MANAGED_PROVISIONING_LEASE_SECS: i64 = 60 * 60;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum ProvisioningAgentStoreError {
    NotFound,
    WrongOwner,
    InvalidTransition,
    InvalidContract,
    Persistence,
}

impl ProvisioningJobStore {
    pub(super) fn attest_managed_host_key(
        &self,
        id: &str,
        fingerprint: &str,
        operator_ref: &str,
        now: i64,
    ) -> Result<ProvisioningJob, ProvisioningAgentStoreError> {
        if !valid_ssh_host_fingerprint(fingerprint) || !is_sha256_hex(operator_ref) || now <= 0 {
            return Err(ProvisioningAgentStoreError::InvalidContract);
        }
        self.require_durable()
            .map_err(|_| ProvisioningAgentStoreError::Persistence)?;
        let mut jobs = self.jobs.write().expect("provisioning job store lock");
        let previous = jobs
            .get(id)
            .cloned()
            .ok_or(ProvisioningAgentStoreError::NotFound)?;
        let mut updated = previous.clone();
        let identity = updated
            .managed_identity
            .as_mut()
            .ok_or(ProvisioningAgentStoreError::InvalidTransition)?;
        if updated.state != ProvisioningJobState::WaitingForHeartbeat
            || !matches!(
                identity.state,
                ProvisioningManagedIdentityState::AwaitingHostKey
                    | ProvisioningManagedIdentityState::RetryRequired
            )
            || (identity.state == ProvisioningManagedIdentityState::RetryRequired
                && identity.last_failure != Some(ProvisioningManagedFailure::HostKeyMismatch))
        {
            return Err(ProvisioningAgentStoreError::InvalidTransition);
        }
        identity.host_key_fingerprint = Some(fingerprint.to_string());
        identity.host_key_operator_ref = Some(operator_ref.to_string());
        identity.host_key_attested_at = Some(now);
        identity.state = ProvisioningManagedIdentityState::Ready;
        identity.last_failure = None;
        updated.updated_at = now;
        updated.progress.push(ProvisioningProgressEntry {
            state: ProvisioningJobState::WaitingForHeartbeat,
            message: "The out-of-band SSH host-key fingerprint was attested; the reviewed Linux executor may now claim bootstrap work.".to_string(),
            observed_at: now,
        });
        if updated.validate_contract().is_err() || !paid_job_integrity_valid(&updated) {
            return Err(ProvisioningAgentStoreError::InvalidContract);
        }
        jobs.insert(id.to_string(), updated.clone());
        if self.persist_jobs(&jobs).is_err() {
            jobs.insert(id.to_string(), previous);
            return Err(ProvisioningAgentStoreError::Persistence);
        }
        Ok(updated)
    }

    pub(super) fn retry_managed_bootstrap(
        &self,
        id: &str,
        now: i64,
    ) -> Result<ProvisioningJob, ProvisioningAgentStoreError> {
        self.require_durable()
            .map_err(|_| ProvisioningAgentStoreError::Persistence)?;
        let mut jobs = self.jobs.write().expect("provisioning job store lock");
        let previous = jobs
            .get(id)
            .cloned()
            .ok_or(ProvisioningAgentStoreError::NotFound)?;
        let mut updated = previous.clone();
        let identity = updated
            .managed_identity
            .as_mut()
            .ok_or(ProvisioningAgentStoreError::InvalidTransition)?;
        if updated.state != ProvisioningJobState::CleanupNeeded
            || identity.state != ProvisioningManagedIdentityState::RetryRequired
            || identity.host_key_fingerprint.is_none()
        {
            return Err(ProvisioningAgentStoreError::InvalidTransition);
        }
        identity.state = ProvisioningManagedIdentityState::Ready;
        identity.last_failure = None;
        updated.state = ProvisioningJobState::WaitingForHeartbeat;
        updated.updated_at = now;
        updated.progress.push(ProvisioningProgressEntry {
            state: ProvisioningJobState::WaitingForHeartbeat,
            message: "The same job-owned credential and attested host key were queued for one bounded bootstrap retry.".to_string(),
            observed_at: now,
        });
        if updated.validate_contract().is_err() || !paid_job_integrity_valid(&updated) {
            return Err(ProvisioningAgentStoreError::InvalidContract);
        }
        jobs.insert(id.to_string(), updated.clone());
        if self.persist_jobs(&jobs).is_err() {
            jobs.insert(id.to_string(), previous);
            return Err(ProvisioningAgentStoreError::Persistence);
        }
        Ok(updated)
    }

    pub(super) fn queue_managed_bootstrap_reconciliation(
        &self,
        id: &str,
        now: i64,
    ) -> Result<ProvisioningJob, ProvisioningAgentStoreError> {
        if now <= 0 {
            return Err(ProvisioningAgentStoreError::InvalidContract);
        }
        self.require_durable()
            .map_err(|_| ProvisioningAgentStoreError::Persistence)?;
        let mut jobs = self.jobs.write().expect("provisioning job store lock");
        let previous = jobs
            .get(id)
            .cloned()
            .ok_or(ProvisioningAgentStoreError::NotFound)?;
        let mut updated = previous.clone();
        let identity = updated
            .managed_identity
            .as_mut()
            .ok_or(ProvisioningAgentStoreError::InvalidTransition)?;
        let created_server_present = updated.provider_resources.iter().any(|resource| {
            resource.provider == "hetzner-cloud"
                && resource.kind == "server"
                && resource.state == "created"
        });
        if updated.state != ProvisioningJobState::CleanupNeeded
            || identity.state != ProvisioningManagedIdentityState::Uncertain
            || identity.host_key_fingerprint.is_none()
            || identity.credential_ready_at.is_some()
            || identity.bootstrap_completed_at.is_some()
            || identity.first_heartbeat_at.is_some()
            || identity.last_failure.is_none()
            || !created_server_present
        {
            return Err(ProvisioningAgentStoreError::InvalidTransition);
        }
        identity.state = ProvisioningManagedIdentityState::ReconciliationPending;
        identity.lease_until = None;
        updated.updated_at = now;
        updated.progress.push(ProvisioningProgressEntry {
            state: ProvisioningJobState::CleanupNeeded,
            message: "An operator requested a read-only recovery proof; no install or credential action is authorized.".to_string(),
            observed_at: now,
        });
        if updated.validate_contract().is_err() || !paid_job_integrity_valid(&updated) {
            return Err(ProvisioningAgentStoreError::InvalidContract);
        }
        jobs.insert(id.to_string(), updated.clone());
        if self.persist_jobs(&jobs).is_err() {
            jobs.insert(id.to_string(), previous);
            return Err(ProvisioningAgentStoreError::Persistence);
        }
        Ok(updated)
    }

    pub(super) fn claim_managed_provisioning(
        &self,
        owner: &str,
        now: i64,
    ) -> Result<Option<ProvisioningAgentLease>, ProvisioningAgentStoreError> {
        if !valid_action_host_name(owner) || now <= 0 {
            return Err(ProvisioningAgentStoreError::InvalidContract);
        }
        self.require_durable()
            .map_err(|_| ProvisioningAgentStoreError::Persistence)?;
        let mut jobs = self.jobs.write().expect("provisioning job store lock");

        if let Some(expired_id) = jobs.values().find_map(|job| {
            job.managed_identity.as_ref().and_then(|identity| {
                (identity.executor_owner == owner
                    && identity.state == ProvisioningManagedIdentityState::BootstrapClaimed
                    && identity.lease_until.is_some_and(|until| until <= now))
                .then(|| job.id.clone())
            })
        }) {
            let previous = jobs.get(&expired_id).cloned().expect("expired job exists");
            let mut updated = previous.clone();
            let identity = updated.managed_identity.as_mut().expect("managed identity");
            identity.state = ProvisioningManagedIdentityState::Uncertain;
            identity.lease_until = None;
            identity.last_failure = Some(ProvisioningManagedFailure::UncertainExecution);
            updated.state = ProvisioningJobState::CleanupNeeded;
            updated.updated_at = now;
            updated.progress.push(ProvisioningProgressEntry {
                state: ProvisioningJobState::CleanupNeeded,
                message: "The bootstrap lease expired without a result; Pharos will not replay a potentially destructive install.".to_string(),
                observed_at: now,
            });
            jobs.insert(expired_id.clone(), updated);
            if self.persist_jobs(&jobs).is_err() {
                jobs.insert(expired_id, previous);
                return Err(ProvisioningAgentStoreError::Persistence);
            }
            return Ok(None);
        }

        if let Some(expired_id) = jobs.values().find_map(|job| {
            job.managed_identity.as_ref().and_then(|identity| {
                (identity.executor_owner == owner
                    && identity.state == ProvisioningManagedIdentityState::ReconciliationClaimed
                    && identity.lease_until.is_some_and(|until| until <= now))
                .then(|| job.id.clone())
            })
        }) {
            let previous = jobs.get(&expired_id).cloned().expect("expired job exists");
            let mut updated = previous.clone();
            let identity = updated.managed_identity.as_mut().expect("managed identity");
            identity.state = ProvisioningManagedIdentityState::Uncertain;
            identity.lease_until = None;
            identity.last_failure = Some(ProvisioningManagedFailure::UncertainExecution);
            updated.state = ProvisioningJobState::CleanupNeeded;
            updated.updated_at = now;
            updated.progress.push(ProvisioningProgressEntry {
                state: ProvisioningJobState::CleanupNeeded,
                message: "The read-only recovery proof expired without a result; Pharos kept the server fail-closed.".to_string(),
                observed_at: now,
            });
            jobs.insert(expired_id.clone(), updated);
            if self.persist_jobs(&jobs).is_err() {
                jobs.insert(expired_id, previous);
                return Err(ProvisioningAgentStoreError::Persistence);
            }
            return Ok(None);
        }

        let candidate = jobs
            .values()
            .filter_map(|job| {
                let identity = job.managed_identity.as_ref()?;
                if identity.executor_owner != owner {
                    return None;
                }
                let action = if job.state == ProvisioningJobState::CleanupNeeded
                    && identity.state == ProvisioningManagedIdentityState::ReconciliationPending
                {
                    ProvisioningAgentAction::ReconcileBootstrap
                } else if job.state == ProvisioningJobState::WaitingForHeartbeat
                    && identity.state == ProvisioningManagedIdentityState::Ready
                {
                    ProvisioningAgentAction::Bootstrap
                } else if job.state == ProvisioningJobState::CleanupNeeded
                    && (identity.state == ProvisioningManagedIdentityState::RetirementPending
                        || (identity.state == ProvisioningManagedIdentityState::RetirementClaimed
                            && identity.lease_until.is_some_and(|until| until <= now)))
                {
                    ProvisioningAgentAction::Retire
                } else {
                    return None;
                };
                Some((job.created_at, job.id.clone(), action))
            })
            .min_by_key(|(created_at, id, _)| (*created_at, id.clone()));
        let Some((_, id, action)) = candidate else {
            return Ok(None);
        };
        let previous = jobs.get(&id).cloned().expect("candidate exists");
        let mut updated = previous.clone();
        let resource = updated
            .provider_resources
            .iter()
            .find(|resource| resource.provider == "hetzner-cloud" && resource.kind == "server")
            .cloned()
            .ok_or(ProvisioningAgentStoreError::InvalidTransition)?;
        let plan = updated
            .reviewed_plan
            .clone()
            .ok_or(ProvisioningAgentStoreError::InvalidTransition)?;
        let host = updated
            .host_name
            .clone()
            .ok_or(ProvisioningAgentStoreError::InvalidTransition)?;
        let role = updated.role.clone().unwrap_or_else(|| "server".to_string());
        let identity = updated
            .managed_identity
            .as_mut()
            .ok_or(ProvisioningAgentStoreError::InvalidTransition)?;
        let (ssh_host, ssh_port, host_key_fingerprint) = match action {
            ProvisioningAgentAction::Bootstrap | ProvisioningAgentAction::ReconcileBootstrap => {
                let ssh = resource
                    .ssh
                    .as_ref()
                    .ok_or(ProvisioningAgentStoreError::InvalidTransition)?;
                (
                    ssh.host.clone(),
                    ssh.port,
                    identity.host_key_fingerprint.clone(),
                )
            }
            ProvisioningAgentAction::Retire => (None, None, None),
        };
        if matches!(
            action,
            ProvisioningAgentAction::Bootstrap | ProvisioningAgentAction::ReconcileBootstrap
        ) && (resource.state != "created"
            || ssh_host.is_none()
            || ssh_port.is_none()
            || host_key_fingerprint.is_none())
        {
            return Err(ProvisioningAgentStoreError::InvalidTransition);
        }
        if action == ProvisioningAgentAction::Retire && resource.state != "deleted" {
            return Err(ProvisioningAgentStoreError::InvalidTransition);
        }
        identity.state = match action {
            ProvisioningAgentAction::Bootstrap => {
                updated.state = ProvisioningJobState::Bootstrapping;
                ProvisioningManagedIdentityState::BootstrapClaimed
            }
            ProvisioningAgentAction::ReconcileBootstrap => {
                ProvisioningManagedIdentityState::ReconciliationClaimed
            }
            ProvisioningAgentAction::Retire => ProvisioningManagedIdentityState::RetirementClaimed,
        };
        identity.lease_until = Some(now.saturating_add(MANAGED_PROVISIONING_LEASE_SECS));
        if action != ProvisioningAgentAction::ReconcileBootstrap {
            identity.last_failure = None;
        }
        updated.updated_at = now;
        updated.progress.push(ProvisioningProgressEntry {
            state: updated.state,
            message: match action {
                ProvisioningAgentAction::Bootstrap => {
                    "The reviewed Linux executor claimed the exact server bootstrap lease."
                }
                ProvisioningAgentAction::ReconcileBootstrap => {
                    "The reviewed Linux executor claimed a read-only recovery proof; installation remains unauthorized."
                }
                ProvisioningAgentAction::Retire => {
                    "The reviewed Janus owner claimed retirement of the exact job-owned credential."
                }
            }
            .to_string(),
            observed_at: now,
        });
        let lease = ProvisioningAgentLease {
            schema: "inspr.pharos.provisioning-agent-lease.v1",
            version: 1,
            id: updated.id.clone(),
            host,
            ticket: "PHAROS-175",
            action,
            credential_ref: identity.credential_ref.clone(),
            provider_id: resource.provider_id,
            lease_until: identity
                .lease_until
                .expect("managed provisioning claim sets a lease deadline"),
            ssh_host,
            ssh_port,
            host_key_fingerprint,
            ssh_key_ref: plan.ssh_key_ref,
            role,
            heartbeat_interval_secs: updated.heartbeat_interval_secs.unwrap_or(60),
        };
        if updated.validate_contract().is_err() || !paid_job_integrity_valid(&updated) {
            return Err(ProvisioningAgentStoreError::InvalidContract);
        }
        jobs.insert(id.clone(), updated);
        if self.persist_jobs(&jobs).is_err() {
            jobs.insert(id, previous);
            return Err(ProvisioningAgentStoreError::Persistence);
        }
        Ok(Some(lease))
    }

    pub(super) fn record_managed_provisioning_result(
        &self,
        id: &str,
        request: &ProvisioningAgentResultRequest,
        now: i64,
    ) -> Result<ProvisioningJob, ProvisioningAgentStoreError> {
        if !request.valid() || now <= 0 {
            return Err(ProvisioningAgentStoreError::InvalidContract);
        }
        self.require_durable()
            .map_err(|_| ProvisioningAgentStoreError::Persistence)?;
        let mut jobs = self.jobs.write().expect("provisioning job store lock");
        let previous = jobs
            .get(id)
            .cloned()
            .ok_or(ProvisioningAgentStoreError::NotFound)?;
        let mut updated = previous.clone();
        if updated.host_name.as_deref() != Some(request.host.as_str()) {
            return Err(ProvisioningAgentStoreError::InvalidTransition);
        }
        let identity = updated
            .managed_identity
            .as_mut()
            .ok_or(ProvisioningAgentStoreError::InvalidTransition)?;
        if identity.executor_owner != request.owner {
            return Err(ProvisioningAgentStoreError::WrongOwner);
        }
        let expected_state = match request.action {
            ProvisioningAgentAction::Bootstrap => {
                ProvisioningManagedIdentityState::BootstrapClaimed
            }
            ProvisioningAgentAction::ReconcileBootstrap => {
                ProvisioningManagedIdentityState::ReconciliationClaimed
            }
            ProvisioningAgentAction::Retire => ProvisioningManagedIdentityState::RetirementClaimed,
        };
        if identity.state != expected_state || identity.lease_until.is_none() {
            if request.action == ProvisioningAgentAction::Retire
                && request.outcome == ProvisioningAgentOutcome::Succeeded
                && identity.state == ProvisioningManagedIdentityState::CredentialRetired
            {
                return Ok(previous);
            }
            return Err(ProvisioningAgentStoreError::InvalidTransition);
        }
        let previous_failure = identity.last_failure;
        identity.lease_until = None;
        identity.last_failure = request.reason;
        let message = match (request.action, request.outcome) {
            (ProvisioningAgentAction::Bootstrap, ProvisioningAgentOutcome::Succeeded) => {
                identity.state = ProvisioningManagedIdentityState::AwaitingHeartbeat;
                identity.credential_ready_at.get_or_insert(now);
                identity.bootstrap_completed_at = Some(now);
                updated.state = ProvisioningJobState::WaitingForHeartbeat;
                "Janus credential handoff and NixOS bootstrap completed; waiting for the first authenticated heartbeat."
            }
            (ProvisioningAgentAction::Bootstrap, ProvisioningAgentOutcome::Failed) => {
                if request.credential_created {
                    identity.credential_ready_at.get_or_insert(now);
                }
                identity.state = ProvisioningManagedIdentityState::RetryRequired;
                updated.state = ProvisioningJobState::CleanupNeeded;
                "Managed bootstrap stopped at a known boundary; review the recorded reason before retry or cleanup."
            }
            (ProvisioningAgentAction::Bootstrap, ProvisioningAgentOutcome::Uncertain) => {
                if request.credential_created {
                    identity.credential_ready_at.get_or_insert(now);
                }
                identity.state = ProvisioningManagedIdentityState::Uncertain;
                updated.state = ProvisioningJobState::CleanupNeeded;
                "Managed bootstrap ended without trustworthy completion evidence; Pharos will not replay it blindly."
            }
            (ProvisioningAgentAction::ReconcileBootstrap, ProvisioningAgentOutcome::Succeeded) => {
                identity.state = ProvisioningManagedIdentityState::RetryRequired;
                identity.last_failure = previous_failure;
                updated.state = ProvisioningJobState::CleanupNeeded;
                "Read-only recovery proved that neither NixOS installation nor the job-owned credential started; a bounded retry is available."
            }
            (
                ProvisioningAgentAction::ReconcileBootstrap,
                ProvisioningAgentOutcome::Failed | ProvisioningAgentOutcome::Uncertain,
            ) => {
                identity.state = ProvisioningManagedIdentityState::Uncertain;
                updated.state = ProvisioningJobState::CleanupNeeded;
                "Read-only recovery could not prove an unchanged server and absent credential; Pharos kept the server fail-closed."
            }
            (ProvisioningAgentAction::Retire, ProvisioningAgentOutcome::Succeeded) => {
                identity.state = ProvisioningManagedIdentityState::CredentialRetired;
                identity.credential_retired_at = Some(now);
                updated.state = ProvisioningJobState::CleanupNeeded;
                "Janus retired the exact job-owned credential; durable fleet cleanup is being finalized."
            }
            (ProvisioningAgentAction::Retire, ProvisioningAgentOutcome::Failed) => {
                identity.state = ProvisioningManagedIdentityState::RetirementPending;
                updated.state = ProvisioningJobState::CleanupNeeded;
                "Janus credential retirement stopped at a known boundary and remains queued for idempotent recovery."
            }
            (ProvisioningAgentAction::Retire, ProvisioningAgentOutcome::Uncertain) => {
                identity.state = ProvisioningManagedIdentityState::RetirementPending;
                updated.state = ProvisioningJobState::CleanupNeeded;
                "Janus credential retirement is uncertain; only the same ownership-bound reconciliation may retry."
            }
        };
        updated.updated_at = now;
        updated.progress.push(ProvisioningProgressEntry {
            state: updated.state,
            message: message.to_string(),
            observed_at: now,
        });
        if updated.validate_contract().is_err() || !paid_job_integrity_valid(&updated) {
            return Err(ProvisioningAgentStoreError::InvalidContract);
        }
        jobs.insert(id.to_string(), updated.clone());
        if self.persist_jobs(&jobs).is_err() {
            jobs.insert(id.to_string(), previous);
            return Err(ProvisioningAgentStoreError::Persistence);
        }
        Ok(updated)
    }

    pub(super) fn record_managed_first_heartbeat(
        &self,
        id: &str,
        next_state: ProvisioningJobState,
        message: &str,
        observed_at: i64,
        now: i64,
    ) -> Result<ProvisioningJob, ProvisioningAgentStoreError> {
        let mut jobs = self.jobs.write().expect("provisioning job store lock");
        let previous = jobs
            .get(id)
            .cloned()
            .ok_or(ProvisioningAgentStoreError::NotFound)?;
        let mut updated = previous.clone();
        let identity = updated
            .managed_identity
            .as_mut()
            .ok_or(ProvisioningAgentStoreError::InvalidTransition)?;
        if updated.state != ProvisioningJobState::WaitingForHeartbeat
            || identity.state != ProvisioningManagedIdentityState::AwaitingHeartbeat
            || identity
                .bootstrap_completed_at
                .is_none_or(|completed_at| observed_at < completed_at)
            || !matches!(
                next_state,
                ProvisioningJobState::BackupPending | ProvisioningJobState::Complete
            )
        {
            return Err(ProvisioningAgentStoreError::InvalidTransition);
        }
        identity.state = ProvisioningManagedIdentityState::HeartbeatObserved;
        identity.first_heartbeat_at = Some(observed_at);
        updated.state = next_state;
        updated.terminal_outcome = (next_state == ProvisioningJobState::Complete)
            .then_some(ProvisioningTerminalOutcome::Provisioned);
        updated.updated_at = now;
        updated.progress.push(ProvisioningProgressEntry {
            state: next_state,
            message: message.to_string(),
            observed_at: now,
        });
        if updated.validate_contract().is_err() || !paid_job_integrity_valid(&updated) {
            return Err(ProvisioningAgentStoreError::InvalidContract);
        }
        jobs.insert(id.to_string(), updated.clone());
        if self.persist_jobs(&jobs).is_err() {
            jobs.insert(id.to_string(), previous);
            return Err(ProvisioningAgentStoreError::Persistence);
        }
        Ok(updated)
    }

    pub(super) fn complete_managed_backup(
        &self,
        id: &str,
        now: i64,
    ) -> Result<ProvisioningJob, ProvisioningAgentStoreError> {
        let mut jobs = self.jobs.write().expect("provisioning job store lock");
        let previous = jobs
            .get(id)
            .cloned()
            .ok_or(ProvisioningAgentStoreError::NotFound)?;
        if previous.state != ProvisioningJobState::BackupPending
            || previous.managed_identity.as_ref().is_none_or(|identity| {
                identity.state != ProvisioningManagedIdentityState::HeartbeatObserved
            })
        {
            return Err(ProvisioningAgentStoreError::InvalidTransition);
        }
        let mut updated = previous.clone();
        updated.state = ProvisioningJobState::Complete;
        updated.terminal_outcome = Some(ProvisioningTerminalOutcome::Provisioned);
        updated.updated_at = now;
        updated.progress.push(ProvisioningProgressEntry {
            state: ProvisioningJobState::Complete,
            message: "Backup observation received; setup job complete.".to_string(),
            observed_at: now,
        });
        if updated.validate_contract().is_err() || !paid_job_integrity_valid(&updated) {
            return Err(ProvisioningAgentStoreError::InvalidContract);
        }
        jobs.insert(id.to_string(), updated.clone());
        if self.persist_jobs(&jobs).is_err() {
            jobs.insert(id.to_string(), previous);
            return Err(ProvisioningAgentStoreError::Persistence);
        }
        Ok(updated)
    }

    pub(super) fn complete_managed_retirement(
        &self,
        id: &str,
        now: i64,
    ) -> Result<ProvisioningJob, ProvisioningAgentStoreError> {
        let mut jobs = self.jobs.write().expect("provisioning job store lock");
        let previous = jobs
            .get(id)
            .cloned()
            .ok_or(ProvisioningAgentStoreError::NotFound)?;
        if previous.state != ProvisioningJobState::CleanupNeeded
            || previous.provider_resources.len() != 1
            || previous.provider_resources[0].state != "deleted"
            || previous.managed_identity.as_ref().is_none_or(|identity| {
                identity.state != ProvisioningManagedIdentityState::CredentialRetired
            })
        {
            return Err(ProvisioningAgentStoreError::InvalidTransition);
        }
        let mut updated = previous.clone();
        updated.state = ProvisioningJobState::Complete;
        updated.terminal_outcome = Some(ProvisioningTerminalOutcome::RolledBack);
        updated.updated_at = now;
        updated.progress.push(ProvisioningProgressEntry {
            state: ProvisioningJobState::Complete,
            message: "Provider resource, job-owned Janus credential, and owned runtime host state are retired.".to_string(),
            observed_at: now,
        });
        if updated.validate_contract().is_err() || !paid_job_integrity_valid(&updated) {
            return Err(ProvisioningAgentStoreError::InvalidContract);
        }
        jobs.insert(id.to_string(), updated.clone());
        if self.persist_jobs(&jobs).is_err() {
            jobs.insert(id.to_string(), previous);
            return Err(ProvisioningAgentStoreError::Persistence);
        }
        Ok(updated)
    }
}

#[derive(Debug, Clone, Deserialize)]
pub(super) struct ProvisioningJobStartRequest {
    pub(super) provider: String,
    pub(super) template: String,
    #[serde(default)]
    pub(super) apply: bool,
    #[serde(default)]
    pub(super) host_name: Option<String>,
    #[serde(default)]
    pub(super) role: Option<String>,
    #[serde(default)]
    pub(super) is_nix: Option<bool>,
    #[serde(default)]
    pub(super) heartbeat_interval_secs: Option<u64>,
    #[serde(default)]
    pub(super) backup_intent: Option<BackupSetupIntent>,
    #[serde(default)]
    pub(super) location_intent: Option<LocationSetupIntent>,
    #[serde(default)]
    pub(super) access_intent: Option<AccessSetupIntent>,
    #[serde(default)]
    pub(super) location: Option<String>,
    #[serde(default)]
    pub(super) server_type: Option<String>,
    #[serde(default)]
    pub(super) image: Option<String>,
    #[serde(default)]
    pub(super) ssh_key_ref: Option<String>,
    #[serde(default)]
    pub(super) ssh: Option<SshAccessIntent>,
    #[serde(default)]
    pub(super) preflight_summary: Option<ExistingHostPreflightSummary>,
    #[serde(default)]
    pub(super) preflight_checks: Vec<ExistingHostPreflightCheck>,
}

#[derive(Debug, Clone, Deserialize)]
pub(super) struct ProvisioningCleanupRequest {
    #[serde(default)]
    pub(super) confirm: bool,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct ProvisioningHostKeyAttestationRequest {
    pub(super) fingerprint: String,
    pub(super) attended: bool,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct ProvisioningBootstrapRetryRequest {
    pub(super) confirm: bool,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct ProvisioningBootstrapReconciliationRequest {
    pub(super) confirm: bool,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct ProvisioningAgentClaimRequest {
    pub(super) owner: String,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub(super) enum ProvisioningAgentAction {
    Bootstrap,
    ReconcileBootstrap,
    Retire,
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub(super) struct ProvisioningAgentLease {
    pub(super) schema: &'static str,
    pub(super) version: u16,
    pub(super) id: String,
    pub(super) host: String,
    pub(super) ticket: &'static str,
    pub(super) action: ProvisioningAgentAction,
    pub(super) credential_ref: String,
    pub(super) provider_id: String,
    pub(super) lease_until: i64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(super) ssh_host: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(super) ssh_port: Option<u16>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(super) host_key_fingerprint: Option<String>,
    pub(super) ssh_key_ref: String,
    pub(super) role: String,
    pub(super) heartbeat_interval_secs: u64,
}

#[derive(Debug, Clone, Copy, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub(super) enum ProvisioningAgentOutcome {
    Succeeded,
    Failed,
    Uncertain,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct ProvisioningAgentResultRequest {
    pub(super) owner: String,
    pub(super) host: String,
    pub(super) action: ProvisioningAgentAction,
    pub(super) outcome: ProvisioningAgentOutcome,
    #[serde(default)]
    pub(super) credential_created: bool,
    #[serde(default)]
    pub(super) reason: Option<ProvisioningManagedFailure>,
}

impl ProvisioningAgentResultRequest {
    fn valid(&self) -> bool {
        valid_action_host_name(&self.owner)
            && valid_action_host_name(&self.host)
            && match (self.action, self.outcome, self.reason) {
                (ProvisioningAgentAction::Bootstrap, ProvisioningAgentOutcome::Succeeded, None) => {
                    self.credential_created
                }
                (ProvisioningAgentAction::Retire, ProvisioningAgentOutcome::Succeeded, None) => {
                    !self.credential_created
                }
                (
                    ProvisioningAgentAction::ReconcileBootstrap,
                    ProvisioningAgentOutcome::Succeeded,
                    None,
                ) => !self.credential_created,
                (
                    ProvisioningAgentAction::ReconcileBootstrap,
                    ProvisioningAgentOutcome::Failed | ProvisioningAgentOutcome::Uncertain,
                    Some(_),
                ) => !self.credential_created,
                (
                    ProvisioningAgentAction::Bootstrap | ProvisioningAgentAction::Retire,
                    ProvisioningAgentOutcome::Failed | ProvisioningAgentOutcome::Uncertain,
                    Some(_),
                ) => true,
                _ => false,
            }
    }
}

pub(super) fn valid_ssh_host_fingerprint(value: &str) -> bool {
    value.len() == 50
        && value.starts_with("SHA256:")
        && value[7..]
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'+' | b'/'))
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct ProvisioningPaidConfirmRequest {
    plan_sha256: String,
    attended: bool,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct ProvisioningPaidCreateRequest {
    plan_sha256: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum ProvisioningPaidStoreError {
    NotFound,
    InvalidState,
    PlanMismatch,
    Expired,
    OperatorMismatch,
    ProjectBusy,
    ContractFailed,
    PersistenceFailed,
}

pub(super) fn reviewed_paid_plan_digest(plan: &ProvisioningReviewedPaidPlan) -> String {
    let mut material = plan.clone();
    material.plan_sha256 = "0".repeat(64);
    let encoded = serde_json::to_vec(&material).unwrap_or_default();
    hex(&Sha256::digest(encoded))
}

pub(super) fn paid_job_integrity_valid(job: &ProvisioningJob) -> bool {
    let Some(plan) = job.reviewed_plan.as_ref() else {
        return job.paid_authorization.is_none() && job.paid_execution.is_none();
    };
    if reviewed_paid_plan_digest(plan) != plan.plan_sha256
        || job.host_name.as_deref() != Some(plan.server_name.as_str())
        || plan.required_labels != paid_required_labels(&job.id, &plan.provider_project)
        || job.managed_identity.as_ref().is_some_and(|identity| {
            plan.managed_credential_ref.as_deref() != Some(identity.credential_ref.as_str())
                || plan.managed_executor_owner.as_deref() != Some(identity.executor_owner.as_str())
        })
    {
        return false;
    }
    let resources = job
        .provider_resources
        .iter()
        .filter(|resource| resource.provider == "hetzner-cloud" && resource.kind == "server")
        .collect::<Vec<_>>();
    match job.paid_execution.as_ref() {
        None => resources.is_empty(),
        Some(execution) if matches!(execution.state.as_str(), "created" | "reconciled") => {
            let Some(provider_id) = execution.provider_id.as_deref() else {
                return false;
            };
            provider_id.parse::<u64>().is_ok_and(|id| id > 0)
                && resources.len() == 1
                && resources[0].provider_id == provider_id
                && resources[0].name == plan.server_name
                && (plan.managed_executor_owner.is_some() == job.managed_identity.is_some())
        }
        Some(_) => resources.is_empty(),
    }
}

pub(super) fn paid_project_blocked_in(
    jobs: &BTreeMap<String, ProvisioningJob>,
    except_id: Option<&str>,
) -> bool {
    jobs.iter().any(|(id, job)| {
        if except_id == Some(id.as_str()) || job.provider != "hetzner-cloud" {
            return false;
        }
        job.paid_execution.as_ref().is_some_and(|execution| {
            matches!(
                execution.state.as_str(),
                "claimed" | "request-started" | "uncertain"
            )
        }) || job.provider_resources.iter().any(|resource| {
            resource.provider == "hetzner-cloud"
                && resource.kind == "server"
                && matches!(
                    resource.state.as_str(),
                    "created" | "created-address-pending"
                )
        })
    })
}

#[derive(Clone, Debug, Default)]
pub(super) struct ProviderRuntimeConfig {
    pub(super) hetzner_cloud: HetznerCloudRuntimeConfig,
    pub(super) existing_host: ExistingHostRuntimeConfig,
    pub(super) managed_provisioning: ManagedProvisioningRuntimeConfig,
    pub(super) janus_public_url: Option<Url>,
}

impl ProviderRuntimeConfig {
    pub(super) fn from_env() -> Self {
        Self {
            hetzner_cloud: HetznerCloudRuntimeConfig::from_env(),
            existing_host: ExistingHostRuntimeConfig::from_env(),
            managed_provisioning: ManagedProvisioningRuntimeConfig::from_env(),
            janus_public_url: env_nonempty("PHAROS_JANUS_PUBLIC_URL")
                .and_then(|value| provider_setup_base_url(&value)),
        }
    }
}

#[derive(Clone, Debug, Default)]
pub(super) struct ManagedProvisioningRuntimeConfig {
    pub(super) enabled: bool,
    pub(super) owner_host: Option<String>,
    scope: Option<ManagedProvisioningJanusScope>,
}

#[derive(Clone, Debug)]
struct ManagedProvisioningJanusScope {
    organization: String,
    project: String,
    repository: String,
    environment: String,
}

fn valid_janus_scope_component(value: &str) -> bool {
    let bytes = value.as_bytes();
    (1..=128).contains(&bytes.len())
        && bytes[0].is_ascii_alphanumeric()
        && bytes
            .iter()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'.' | b'-'))
}

fn hash_length_framed_field(digest: &mut Sha256, value: &str) {
    digest.update((value.len() as u64).to_be_bytes());
    digest.update(value.as_bytes());
}

fn janus_managed_credential_ref(scope: &ManagedProvisioningJanusScope, host: &str) -> String {
    let mut scope_digest = Sha256::new();
    for value in [
        "janus-scope-v1",
        scope.organization.as_str(),
        scope.project.as_str(),
        scope.repository.as_str(),
        scope.environment.as_str(),
    ] {
        hash_length_framed_field(&mut scope_digest, value);
    }
    scope_digest.update([0, 0]);
    let scope_ref = format!("scp_{}", &hex(&scope_digest.finalize())[..40]);
    let secret_name = format!(
        "PHAROS_BEACON_{}_TOKEN",
        host.replace('-', "_").to_ascii_uppercase()
    );
    let mut secret_digest = Sha256::new();
    secret_digest.update(b"janus-secret-ref-v2\0");
    secret_digest.update(scope_ref.as_bytes());
    secret_digest.update(b"\0");
    secret_digest.update(secret_name.as_bytes());
    format!("sec_{}", &hex(&secret_digest.finalize())[..20])
}

impl ManagedProvisioningRuntimeConfig {
    fn from_env() -> Self {
        let enabled = env_nonempty("PHAROS_PROVISIONING_EXECUTOR_READY")
            .and_then(|value| parse_bool(&value))
            .unwrap_or(false);
        let owner_host = env_nonempty("PHAROS_PROVISIONING_OWNER_HOST");
        let scope_parts = [
            env_nonempty("PHAROS_PROVISIONING_SCOPE_ORGANIZATION"),
            env_nonempty("PHAROS_PROVISIONING_SCOPE_PROJECT"),
            env_nonempty("PHAROS_PROVISIONING_SCOPE_REPOSITORY"),
            env_nonempty("PHAROS_PROVISIONING_SCOPE_ENVIRONMENT"),
        ];
        let any_scope = scope_parts.iter().any(Option::is_some);
        let scope = match scope_parts {
            [Some(organization), Some(project), Some(repository), Some(environment)] => {
                for value in [&organization, &project, &repository, &environment] {
                    assert!(
                        valid_janus_scope_component(value),
                        "PHAROS_PROVISIONING_SCOPE_* values must be valid Janus scope components"
                    );
                }
                Some(ManagedProvisioningJanusScope {
                    organization,
                    project,
                    repository,
                    environment,
                })
            }
            _ => {
                assert!(
                    !any_scope,
                    "all PHAROS_PROVISIONING_SCOPE_* values must be configured together"
                );
                None
            }
        };
        if let Some(owner) = owner_host.as_deref() {
            assert!(
                valid_action_host_name(owner),
                "PHAROS_PROVISIONING_OWNER_HOST must be a valid host name"
            );
            tracing::info!(owner = %owner, ready = enabled, "Pharos managed provisioning owner configured");
        }
        Self {
            enabled,
            owner_host,
            scope,
        }
    }

    pub(super) fn is_owner(&self, host: &str) -> bool {
        self.enabled && self.owner_host.as_deref() == Some(host)
    }

    pub(super) fn ready(&self) -> bool {
        self.enabled && self.owner_host.is_some() && self.scope.is_some()
    }

    fn credential_ref_for(&self, host: &str) -> Option<String> {
        self.ready()
            .then(|| janus_managed_credential_ref(self.scope.as_ref().expect("ready scope"), host))
    }
}

pub(super) fn provider_setup_base_url(value: &str) -> Option<Url> {
    let mut url = Url::parse(value).ok()?;
    let local_http = url.scheme() == "http"
        && url.host_str().is_some_and(|host| {
            host.eq_ignore_ascii_case("localhost")
                || host
                    .parse::<IpAddr>()
                    .is_ok_and(|address| address.is_loopback())
        });
    if !(url.scheme() == "https" || local_http)
        || url.host_str().is_none()
        || !url.username().is_empty()
        || url.password().is_some()
        || url.query().is_some()
        || url.fragment().is_some()
    {
        return None;
    }
    let path = url.path().trim_end_matches('/').to_string();
    url.set_path(&path);
    Some(url)
}

#[cfg(test)]
mod module_tests {
    use super::*;

    #[test]
    fn provider_setup_url_is_https_without_credentials_or_ambient_parameters() {
        assert_eq!(
            provider_setup_base_url("https://janus.example.test/setup/")
                .unwrap()
                .as_str(),
            "https://janus.example.test/setup"
        );
        assert!(provider_setup_base_url("https://user@janus.example.test").is_none());
        assert!(provider_setup_base_url("https://janus.example.test?token=value").is_none());
        assert!(provider_setup_base_url("http://janus.example.test").is_none());
        assert!(provider_setup_base_url("http://127.0.0.1:8080").is_some());
    }
}

#[derive(Clone, Debug)]
pub(super) struct ExistingHostRuntimeConfig {
    pub(super) execute_enabled: bool,
    pub(super) identity_file: Option<PathBuf>,
    pub(super) known_hosts_file: Option<PathBuf>,
    pub(super) beacon_binary_path: PathBuf,
    pub(super) installer_path: PathBuf,
    pub(super) pharos_url: Option<String>,
}

impl Default for ExistingHostRuntimeConfig {
    fn default() -> Self {
        Self {
            execute_enabled: false,
            identity_file: None,
            known_hosts_file: None,
            beacon_binary_path: PathBuf::from("/usr/local/bin/pharos-beacon"),
            installer_path: PathBuf::from(
                "/usr/local/share/pharos/install-pharos-beacon-systemd.sh",
            ),
            pharos_url: None,
        }
    }
}

impl ExistingHostRuntimeConfig {
    fn from_env() -> Self {
        Self {
            execute_enabled: env_nonempty("PHAROS_EXISTING_HOST_EXECUTE")
                .and_then(|value| parse_bool(&value))
                .unwrap_or(false),
            identity_file: env_nonempty("PHAROS_EXISTING_HOST_IDENTITY_FILE").map(PathBuf::from),
            known_hosts_file: env_nonempty("PHAROS_EXISTING_HOST_KNOWN_HOSTS_FILE")
                .map(PathBuf::from),
            beacon_binary_path: env_nonempty("PHAROS_EXISTING_HOST_BEACON_BINARY")
                .map(PathBuf::from)
                .unwrap_or_else(|| PathBuf::from("/usr/local/bin/pharos-beacon")),
            installer_path: env_nonempty("PHAROS_EXISTING_HOST_INSTALLER")
                .map(PathBuf::from)
                .unwrap_or_else(|| {
                    PathBuf::from("/usr/local/share/pharos/install-pharos-beacon-systemd.sh")
                }),
            pharos_url: env_nonempty("PHAROS_EXISTING_HOST_PHAROS_URL"),
        }
    }

    pub(super) fn validate_native_systemd(&self) -> Result<&str, ExistingHostExecutionError> {
        if !self.execute_enabled {
            return Err(ExistingHostExecutionError::RuntimeDisabled);
        }
        let known_hosts = self
            .known_hosts_file
            .as_deref()
            .ok_or(ExistingHostExecutionError::KnownHostsUnavailable)?;
        if open_trusted_runtime_file(known_hosts, 1024 * 1024, 0o022, false).is_none() {
            return Err(ExistingHostExecutionError::KnownHostsUnavailable);
        }
        if self
            .identity_file
            .as_deref()
            .is_some_and(|path| open_trusted_runtime_file(path, 64 * 1024, 0o077, false).is_none())
        {
            return Err(ExistingHostExecutionError::IdentityUnavailable);
        }
        if open_trusted_runtime_file(&self.beacon_binary_path, 128 * 1024 * 1024, 0o022, true)
            .is_none()
        {
            return Err(ExistingHostExecutionError::BeaconBinaryUnavailable);
        }
        if open_trusted_runtime_file(&self.installer_path, 1024 * 1024, 0o022, true).is_none() {
            return Err(ExistingHostExecutionError::InstallerUnavailable);
        }
        let pharos_url = self
            .pharos_url
            .as_deref()
            .ok_or(ExistingHostExecutionError::PharosUrlUnavailable)?;
        let parsed =
            Url::parse(pharos_url).map_err(|_| ExistingHostExecutionError::PharosUrlUnavailable)?;
        if !matches!(parsed.scheme(), "http" | "https")
            || parsed.host_str().is_none()
            || !parsed.username().is_empty()
            || parsed.password().is_some()
            || parsed.query().is_some()
            || parsed.fragment().is_some()
        {
            return Err(ExistingHostExecutionError::PharosUrlUnavailable);
        }
        Ok(pharos_url)
    }
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

#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) enum ExistingHostExecutionError {
    RuntimeDisabled,
    UnsupportedTokenMode,
    KnownHostsUnavailable,
    IdentityUnavailable,
    BeaconBinaryUnavailable,
    InstallerUnavailable,
    PharosUrlUnavailable,
    InvalidTarget,
    UnsupportedSshRoute,
    ArchitectureMismatch,
    RemoteCommandFailed,
    RemoteCommandTimedOut,
    RemoteResponseInvalid,
    ExistingTokenFile,
    TokenGenerationFailed,
    TokenPersistenceFailed,
    ExecutorTaskFailed,
}

impl ExistingHostExecutionError {
    fn safe_message(&self) -> &'static str {
        match self {
            Self::RuntimeDisabled => {
                "Existing-host execution is disabled; the safe handoff remains available"
            }
            Self::UnsupportedTokenMode => {
                "Existing-host execution needs local token issuance or a configured Janus credential broker"
            }
            Self::KnownHostsUnavailable => {
                "Existing-host execution needs a readable strict SSH known-hosts file"
            }
            Self::IdentityUnavailable => {
                "Existing-host SSH identity reference is configured but not readable"
            }
            Self::BeaconBinaryUnavailable => {
                "The pharos-beacon runtime artifact is not readable by the executor"
            }
            Self::InstallerUnavailable => {
                "The native systemd installer artifact is not readable by the executor"
            }
            Self::PharosUrlUnavailable => {
                "Existing-host execution needs a target-facing HTTP or HTTPS Pharos URL"
            }
            Self::InvalidTarget => "Existing-host SSH target contains unsupported characters",
            Self::UnsupportedSshRoute => {
                "This SSH route needs an external bastion handoff and cannot run directly"
            }
            Self::ArchitectureMismatch => {
                "The target architecture does not match the bundled pharos-beacon artifact"
            }
            Self::RemoteCommandFailed => {
                "The remote bootstrap command did not complete; inspect the target before retrying"
            }
            Self::RemoteCommandTimedOut => {
                "The remote bootstrap command exceeded its fixed deadline and was stopped"
            }
            Self::RemoteResponseInvalid => {
                "The remote bootstrap response was not recognized; no credential was exposed"
            }
            Self::ExistingTokenFile => {
                "The target already has a Pharos token file; explicit rotation is required"
            }
            Self::TokenGenerationFailed => "Pharos could not generate the one-time beacon token",
            Self::TokenPersistenceFailed => {
                "Pharos could not durably record the new beacon identity"
            }
            Self::ExecutorTaskFailed => {
                "The existing-host executor stopped before it could confirm the result"
            }
        }
    }
}

#[derive(Clone, Debug)]
pub(super) struct NativeSystemdBootstrapSpec {
    pub(super) host_name: String,
    pub(super) role: String,
    pub(super) interval: u64,
    pub(super) target: String,
    pub(super) port: u16,
}

impl NativeSystemdBootstrapSpec {
    fn from_request(
        request: &ProvisioningJobStartRequest,
    ) -> Result<Self, ExistingHostExecutionError> {
        if request.is_nix == Some(true) {
            return Err(ExistingHostExecutionError::InvalidTarget);
        }
        let host_name = request
            .host_name
            .as_deref()
            .map(str::trim)
            .filter(|value| valid_bootstrap_name(value))
            .ok_or(ExistingHostExecutionError::InvalidTarget)?;
        let role = request
            .role
            .as_deref()
            .map(str::trim)
            .filter(|value| safe_bootstrap_role(value))
            .unwrap_or("server");
        let ssh = request
            .ssh
            .as_ref()
            .ok_or(ExistingHostExecutionError::InvalidTarget)?;
        if !matches!(ssh.route, SshRoute::Direct | SshRoute::Tailnet) {
            return Err(ExistingHostExecutionError::UnsupportedSshRoute);
        }
        let ssh_host = ssh
            .host
            .as_deref()
            .map(str::trim)
            .filter(|value| valid_ssh_endpoint(value))
            .ok_or(ExistingHostExecutionError::InvalidTarget)?;
        let target = match ssh.user.as_deref().map(str::trim) {
            Some(user) if valid_ssh_user(user) => format!("{user}@{ssh_host}"),
            Some(_) => return Err(ExistingHostExecutionError::InvalidTarget),
            None => ssh_host.to_string(),
        };
        Ok(Self {
            host_name: host_name.to_string(),
            role: role.to_string(),
            interval: request
                .heartbeat_interval_secs
                .unwrap_or(60)
                .clamp(1, 86_400),
            target,
            port: ssh.port.unwrap_or(22),
        })
    }
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

pub(super) fn safe_bootstrap_role(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 80
        && !value.contains('\n')
        && !value.contains('\r')
        && !value.to_ascii_lowercase().contains("token=")
        && !value.to_ascii_lowercase().contains("bearer ")
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

pub(super) fn native_binary_matches_remote_arch(remote_arch: &str) -> bool {
    match std::env::consts::ARCH {
        "x86_64" => matches!(remote_arch, "x86_64" | "amd64"),
        "aarch64" => matches!(remote_arch, "aarch64" | "arm64"),
        local => remote_arch == local,
    }
}

#[derive(Clone, Debug)]
pub(super) struct PreparedNativeSystemdBootstrap {
    remote_dir: String,
    remote_binary: String,
    remote_installer: String,
}

pub(super) trait ExistingHostSshRunner {
    fn run(
        &self,
        config: &ExistingHostRuntimeConfig,
        spec: &NativeSystemdBootstrapSpec,
        remote_command: &str,
        stdin: Option<&[u8]>,
    ) -> Result<Vec<u8>, ExistingHostExecutionError>;
}

pub(super) struct SystemExistingHostSshRunner;

impl ExistingHostSshRunner for SystemExistingHostSshRunner {
    fn run(
        &self,
        config: &ExistingHostRuntimeConfig,
        spec: &NativeSystemdBootstrapSpec,
        remote_command: &str,
        stdin: Option<&[u8]>,
    ) -> Result<Vec<u8>, ExistingHostExecutionError> {
        let known_hosts = config
            .known_hosts_file
            .as_deref()
            .ok_or(ExistingHostExecutionError::KnownHostsUnavailable)?;
        if open_trusted_runtime_file(known_hosts, 1024 * 1024, 0o022, false).is_none() {
            return Err(ExistingHostExecutionError::KnownHostsUnavailable);
        }
        if config
            .identity_file
            .as_deref()
            .is_some_and(|path| open_trusted_runtime_file(path, 64 * 1024, 0o077, false).is_none())
        {
            return Err(ExistingHostExecutionError::IdentityUnavailable);
        }
        let mut command = Command::new("ssh");
        command
            .arg("-o")
            .arg("BatchMode=yes")
            .arg("-o")
            .arg("PasswordAuthentication=no")
            .arg("-o")
            .arg("KbdInteractiveAuthentication=no")
            .arg("-o")
            .arg("StrictHostKeyChecking=yes")
            .arg("-o")
            .arg(format!("UserKnownHostsFile={}", known_hosts.display()))
            .arg("-o")
            .arg("ConnectTimeout=8")
            .arg("-o")
            .arg("ServerAliveInterval=5")
            .arg("-o")
            .arg("ServerAliveCountMax=2")
            .arg("-o")
            .arg("LogLevel=ERROR");
        if let Some(identity_file) = &config.identity_file {
            command
                .arg("-o")
                .arg("IdentitiesOnly=yes")
                .arg("-i")
                .arg(identity_file);
        }
        command
            .arg("-p")
            .arg(spec.port.to_string())
            .arg(&spec.target)
            .arg(remote_command)
            .stdin(if stdin.is_some() {
                Stdio::piped()
            } else {
                Stdio::null()
            })
            .stdout(Stdio::piped())
            .stderr(Stdio::null());
        run_child_with_deadline(&mut command, stdin, EXISTING_HOST_SSH_TOTAL_TIMEOUT, 4096)
    }
}

pub(super) fn run_child_with_deadline(
    command: &mut Command,
    stdin: Option<&[u8]>,
    total_timeout: Duration,
    maximum_stdout: usize,
) -> Result<Vec<u8>, ExistingHostExecutionError> {
    #[cfg(unix)]
    command.process_group(0);
    let started = Instant::now();
    let mut child = command
        .spawn()
        .map_err(|_| ExistingHostExecutionError::RemoteCommandFailed)?;

    let (stdout_sender, stdout_receiver) = std::sync::mpsc::sync_channel(1);
    let Some(mut stdout) = child.stdout.take() else {
        terminate_child_process_group(&mut child);
        return Err(ExistingHostExecutionError::RemoteCommandFailed);
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
                return Err(ExistingHostExecutionError::RemoteCommandTimedOut);
            }
            Err(_) => {
                terminate_child_process_group(&mut child);
                return Err(ExistingHostExecutionError::RemoteCommandFailed);
            }
        }
    };

    let remaining = total_timeout.saturating_sub(started.elapsed());
    let stdout = match stdout_receiver.recv_timeout(remaining) {
        Ok(Ok((stdout, false))) => stdout,
        Ok(Ok((_, true))) | Ok(Err(())) => {
            terminate_child_process_group(&mut child);
            return Err(ExistingHostExecutionError::RemoteCommandFailed);
        }
        Err(_) => {
            terminate_child_process_group(&mut child);
            return Err(ExistingHostExecutionError::RemoteCommandTimedOut);
        }
    };
    if let Some(receiver) = stdin_receiver {
        let remaining = total_timeout.saturating_sub(started.elapsed());
        match receiver.recv_timeout(remaining) {
            Ok(Ok(())) => {}
            Ok(Err(())) => {
                terminate_child_process_group(&mut child);
                return Err(ExistingHostExecutionError::RemoteCommandFailed);
            }
            Err(_) => {
                terminate_child_process_group(&mut child);
                return Err(ExistingHostExecutionError::RemoteCommandTimedOut);
            }
        }
    }
    if !status.success() {
        return Err(ExistingHostExecutionError::RemoteCommandFailed);
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

#[derive(Clone, Debug)]
pub(super) struct HetznerCloudRuntimeConfig {
    pub(super) credential_source: Option<ProviderCredentialSource>,
    pub(super) execute_enabled: bool,
    pub(super) default_ssh_key_ref: Option<String>,
    pub(super) firewall_ref: Option<String>,
    pub(super) default_location: Option<String>,
    pub(super) api_base_url: String,
    pub(super) request_timeout: Duration,
    pub(super) evidence_ttl_secs: i64,
    pub(super) project_label: Option<String>,
    pub(super) approval_ttl_secs: i64,
}

impl Default for HetznerCloudRuntimeConfig {
    fn default() -> Self {
        Self {
            credential_source: None,
            execute_enabled: false,
            default_ssh_key_ref: None,
            firewall_ref: None,
            default_location: None,
            api_base_url: "https://api.hetzner.cloud/v1".to_string(),
            request_timeout: Duration::from_secs(20),
            evidence_ttl_secs: 60 * 60,
            project_label: None,
            approval_ttl_secs: 15 * 60,
        }
    }
}

impl HetznerCloudRuntimeConfig {
    fn from_env() -> Self {
        let credential_source = env_nonempty("PHAROS_HCLOUD_API_TOKEN_ENV_FILE")
            .map(|path| ProviderCredentialSource::EnvFile(PathBuf::from(path)))
            .or_else(|| {
                env_nonempty("PHAROS_HCLOUD_API_TOKEN_FILE")
                    .map(|path| ProviderCredentialSource::File(PathBuf::from(path)))
            })
            .or_else(|| {
                env_nonempty("PHAROS_HCLOUD_API_TOKEN")
                    .map(|_| ProviderCredentialSource::Environment("PHAROS_HCLOUD_API_TOKEN"))
            });
        let execute_enabled = env_nonempty("PHAROS_HCLOUD_EXECUTE")
            .and_then(|value| parse_bool(&value))
            .unwrap_or(false);
        let default_ssh_key_ref = env_nonempty("PHAROS_HCLOUD_SSH_KEY_REF");
        let firewall_ref = env_nonempty("PHAROS_HCLOUD_FIREWALL_REF");
        let default_location = env_nonempty("PHAROS_HCLOUD_DEFAULT_LOCATION");
        let api_base_url = env_nonempty("PHAROS_HCLOUD_API_BASE")
            .unwrap_or_else(|| "https://api.hetzner.cloud/v1".to_string());
        let request_timeout = env_nonempty("PHAROS_HCLOUD_TIMEOUT_SECS")
            .and_then(|value| value.parse::<u64>().ok())
            .filter(|seconds| *seconds >= 1)
            .map(Duration::from_secs)
            .unwrap_or(Duration::from_secs(20));
        let evidence_ttl_secs = env_nonempty("PHAROS_HCLOUD_EVIDENCE_TTL_SECS")
            .and_then(|value| value.parse::<i64>().ok())
            .filter(|seconds| (60..=86_400).contains(seconds))
            .unwrap_or(60 * 60);
        let project_label = env_nonempty("PHAROS_HCLOUD_PROJECT_LABEL")
            .filter(|value| safe_paid_display_text(value, 120));
        let approval_ttl_secs = env_nonempty("PHAROS_HCLOUD_APPROVAL_TTL_SECS")
            .and_then(|value| value.parse::<i64>().ok())
            .filter(|seconds| (60..=30 * 60).contains(seconds))
            .unwrap_or(15 * 60);
        Self {
            credential_source,
            execute_enabled,
            default_ssh_key_ref,
            firewall_ref,
            default_location,
            api_base_url,
            request_timeout,
            evidence_ttl_secs,
            project_label,
            approval_ttl_secs,
        }
    }

    fn is_configured(&self) -> bool {
        self.credential_source.is_some()
    }

    pub(super) fn credential_boundary_ready(&self) -> bool {
        matches!(
            self.credential_source,
            Some(ProviderCredentialSource::File(_) | ProviderCredentialSource::EnvFile(_))
        )
    }
}

/// One operation-scoped credential snapshot. The raw token stays in memory and
/// is never serialized or logged; only its domain-separated binding is stored
/// in the reviewed plan so a different provider project cannot be mutated.
pub(super) struct HetznerOperationContext {
    runtime: HetznerCloudRuntimeConfig,
    token: String,
    credential_binding_sha256: String,
}

impl HetznerOperationContext {
    pub(super) fn resolve(
        runtime: HetznerCloudRuntimeConfig,
    ) -> Result<Self, HetznerExecutionError> {
        let token = runtime.api_token()?;
        let credential_binding_sha256 = hetzner_credential_binding(&token);
        Ok(Self {
            runtime,
            token,
            credential_binding_sha256,
        })
    }

    pub(super) fn matches_reviewed_plan(&self, reviewed: &ProvisioningReviewedPaidPlan) -> bool {
        self.credential_binding_sha256 == reviewed.credential_binding_sha256
    }
}

pub(super) fn hetzner_credential_binding(token: &str) -> String {
    let mut digest = Sha256::new();
    digest.update(b"pharos.hetzner-cloud.credential-binding.v1\0");
    digest.update(token.as_bytes());
    hex(&digest.finalize())
}

pub(super) fn hetzner_http_client(
    runtime: &HetznerCloudRuntimeConfig,
) -> Result<reqwest::Client, HetznerExecutionError> {
    reqwest::Client::builder()
        .timeout(runtime.request_timeout)
        .redirect(reqwest::redirect::Policy::none())
        .retry(reqwest::retry::never())
        .build()
        .map_err(|_| HetznerExecutionError::ClientUnavailable)
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) enum ProviderCredentialSource {
    Environment(&'static str),
    File(PathBuf),
    EnvFile(PathBuf),
}

#[derive(Debug)]
pub(super) enum HetznerExecutionError {
    CredentialUnavailable,
    ClientUnavailable,
    PrerequisiteRequestFailed,
    ImageUnavailable,
    SshKeyUnavailable,
    FirewallUnavailable,
    ApprovalExpired,
    RequestFailed,
    HttpStatus(u16),
    InvalidResponse,
}

impl HetznerExecutionError {
    fn safe_message(&self) -> String {
        match self {
            Self::CredentialUnavailable => {
                "Hetzner Cloud credential source was configured but not readable".to_string()
            }
            Self::ClientUnavailable => "Hetzner Cloud HTTP client could not be prepared".to_string(),
            Self::PrerequisiteRequestFailed => {
                "Hetzner Cloud prerequisite checks did not complete; no provider resources were created"
                    .to_string()
            }
            Self::ImageUnavailable => {
                "The reviewed Hetzner Cloud image is no longer available; no provider resources were created"
                    .to_string()
            }
            Self::SshKeyUnavailable => {
                "The configured Hetzner Cloud SSH public key was not found; no provider resources were created"
                    .to_string()
            }
            Self::FirewallUnavailable => {
                "The configured Hetzner Cloud firewall was not found; no provider resources were created"
                    .to_string()
            }
            Self::ApprovalExpired => {
                "The paid authorization expired before the provider create request; no provider resources were created"
                    .to_string()
            }
            Self::RequestFailed => {
                "Hetzner Cloud request did not complete; verify provider console before retry"
                    .to_string()
            }
            Self::HttpStatus(status) => {
                format!("Hetzner Cloud API returned HTTP status {status}; verify provider console before retry")
            }
            Self::InvalidResponse => {
                "Hetzner Cloud API response could not be parsed; verify provider console before retry"
                    .to_string()
            }
        }
    }

    pub(super) fn resource_state_uncertain(&self) -> bool {
        matches!(
            self,
            Self::RequestFailed | Self::HttpStatus(_) | Self::InvalidResponse
        )
    }
}

impl HetznerCloudRuntimeConfig {
    pub(super) fn api_token(&self) -> Result<String, HetznerExecutionError> {
        let Some(source) = &self.credential_source else {
            return Err(HetznerExecutionError::CredentialUnavailable);
        };
        let token = match source {
            ProviderCredentialSource::Environment(name) => env_nonempty(name),
            ProviderCredentialSource::File(path) => read_provider_secret_file(path),
            ProviderCredentialSource::EnvFile(path) => {
                read_provider_env_file(path, "PHAROS_HCLOUD_API_TOKEN")
            }
        };
        token.ok_or(HetznerExecutionError::CredentialUnavailable)
    }
}

pub(super) fn read_provider_secret_file(path: &Path) -> Option<String> {
    let metadata = std::fs::metadata(path).ok()?;
    if metadata.len() == 0 || metadata.len() > 4096 {
        return None;
    }
    let value = std::fs::read_to_string(path).ok()?;
    provider_secret_value(value.trim())
}

pub(super) fn read_provider_env_file(path: &Path, expected_name: &str) -> Option<String> {
    let metadata = std::fs::metadata(path).ok()?;
    if metadata.len() == 0 || metadata.len() > 64 * 1024 {
        return None;
    }
    let contents = std::fs::read_to_string(path).ok()?;
    contents.lines().find_map(|line| {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            return None;
        }
        let line = line.strip_prefix("export ").unwrap_or(line);
        let (name, raw_value) = line.split_once('=')?;
        if name.trim() != expected_name {
            return None;
        }
        let raw_value = raw_value.trim();
        let value = if raw_value.len() >= 2
            && ((raw_value.starts_with('"') && raw_value.ends_with('"'))
                || (raw_value.starts_with('\'') && raw_value.ends_with('\'')))
        {
            &raw_value[1..raw_value.len() - 1]
        } else {
            raw_value
        };
        provider_secret_value(value)
    })
}

pub(super) fn provider_secret_value(value: &str) -> Option<String> {
    let value = value.trim();
    if value.is_empty()
        || value.len() > 2048
        || value.chars().any(|character| character.is_control())
    {
        return None;
    }
    Some(value.to_string())
}

#[derive(Debug, Serialize)]
pub(super) struct HetznerCreateServerRequest {
    name: String,
    server_type: String,
    image: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    location: Option<String>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    ssh_keys: Vec<u64>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    firewalls: Vec<HetznerCreateFirewall>,
    #[serde(default)]
    labels: BTreeMap<String, String>,
    start_after_create: bool,
}

#[derive(Debug, Serialize)]
pub(super) struct HetznerCreateFirewall {
    firewall: u64,
}

#[derive(Debug, Deserialize)]
pub(super) struct HetznerCreateServerResponse {
    server: HetznerCreatedServer,
}

#[derive(Debug, Deserialize)]
pub(super) struct HetznerServerListResponse {
    servers: Vec<HetznerListedServer>,
    meta: HetznerListMeta,
}

#[derive(Debug, Deserialize)]
pub(super) struct HetznerListMeta {
    pagination: HetznerPagination,
}

#[derive(Debug, Deserialize)]
pub(super) struct HetznerPagination {
    page: u32,
    next_page: Option<u32>,
    last_page: u32,
    total_entries: u32,
}

#[derive(Debug, Clone, Deserialize)]
pub(super) struct HetznerListedServer {
    id: u64,
    name: String,
    #[serde(default)]
    labels: BTreeMap<String, String>,
    #[serde(default)]
    server_type: Option<HetznerNamedServerFact>,
    #[serde(default)]
    image: Option<HetznerNamedServerFact>,
    #[serde(default)]
    location: Option<HetznerNamedServerFact>,
    #[serde(default)]
    datacenter: Option<HetznerDatacenterFact>,
    #[serde(default)]
    public_net: Option<HetznerPublicNet>,
}

impl HetznerListedServer {
    fn matches_labels(&self, required: &BTreeMap<String, String>) -> bool {
        hetzner_labels_match(&self.labels, required)
    }

    pub(super) fn matches_reviewed_plan(&self, reviewed: &ProvisioningReviewedPaidPlan) -> bool {
        hetzner_server_matches_reviewed_plan(
            &self.name,
            &self.labels,
            self.server_type.as_ref(),
            self.image.as_ref(),
            self.location.as_ref(),
            self.datacenter.as_ref(),
            reviewed,
        )
    }

    fn into_created(self) -> HetznerCreatedServer {
        HetznerCreatedServer {
            id: self.id,
            name: self.name,
            labels: self.labels,
            server_type: self.server_type,
            image: self.image,
            location: self.location,
            datacenter: self.datacenter,
            public_net: self.public_net,
        }
    }
}

#[derive(Debug, Deserialize)]
pub(super) struct HetznerCreatedServer {
    pub(super) id: u64,
    pub(super) name: String,
    #[serde(default)]
    pub(super) labels: BTreeMap<String, String>,
    #[serde(default)]
    pub(super) server_type: Option<HetznerNamedServerFact>,
    #[serde(default)]
    pub(super) image: Option<HetznerNamedServerFact>,
    #[serde(default)]
    pub(super) location: Option<HetznerNamedServerFact>,
    #[serde(default)]
    pub(super) datacenter: Option<HetznerDatacenterFact>,
    #[serde(default)]
    pub(super) public_net: Option<HetznerPublicNet>,
}

#[derive(Debug, Clone, Deserialize)]
pub(super) struct HetznerNamedServerFact {
    name: String,
}

#[derive(Debug, Clone, Deserialize)]
pub(super) struct HetznerDatacenterFact {
    location: HetznerNamedServerFact,
}

fn hetzner_labels_match(
    labels: &BTreeMap<String, String>,
    required: &BTreeMap<String, String>,
) -> bool {
    required
        .iter()
        .all(|(key, value)| labels.get(key) == Some(value))
}

fn hetzner_server_location_name<'a>(
    location: Option<&'a HetznerNamedServerFact>,
    datacenter: Option<&'a HetznerDatacenterFact>,
) -> Option<&'a str> {
    let current = location.map(|fact| fact.name.as_str());
    let legacy = datacenter.map(|fact| fact.location.name.as_str());
    match (current, legacy) {
        (Some(current), Some(legacy)) if current != legacy => None,
        (Some(current), _) => Some(current),
        (None, legacy) => legacy,
    }
}

fn hetzner_server_matches_reviewed_plan(
    name: &str,
    labels: &BTreeMap<String, String>,
    server_type: Option<&HetznerNamedServerFact>,
    image: Option<&HetznerNamedServerFact>,
    location: Option<&HetznerNamedServerFact>,
    datacenter: Option<&HetznerDatacenterFact>,
    reviewed: &ProvisioningReviewedPaidPlan,
) -> bool {
    name == reviewed.server_name
        && hetzner_labels_match(labels, &reviewed.required_labels)
        && server_type.map(|fact| fact.name.as_str()) == Some(reviewed.server_type.as_str())
        && image.map(|fact| fact.name.as_str()) == Some(reviewed.image.as_str())
        && hetzner_server_location_name(location, datacenter) == Some(reviewed.location.as_str())
}

impl HetznerCreatedServer {
    pub(super) fn matches_reviewed_plan(&self, reviewed: &ProvisioningReviewedPaidPlan) -> bool {
        hetzner_server_matches_reviewed_plan(
            &self.name,
            &self.labels,
            self.server_type.as_ref(),
            self.image.as_ref(),
            self.location.as_ref(),
            self.datacenter.as_ref(),
            reviewed,
        )
    }

    fn ssh_address(&self) -> Option<String> {
        self.public_net
            .as_ref()
            .and_then(|network| network.ipv4.as_ref())
            .and_then(|ipv4| ipv4.ip.parse::<IpAddr>().ok())
            .filter(IpAddr::is_ipv4)
            .map(|address| address.to_string())
    }
}

#[derive(Debug, Clone, Deserialize)]
pub(super) struct HetznerPublicNet {
    #[serde(default)]
    ipv4: Option<HetznerPublicIp>,
}

pub(super) async fn fetch_hetzner_servers(
    operation: &HetznerOperationContext,
) -> Result<Vec<HetznerListedServer>, HetznerExecutionError> {
    let client = hetzner_http_client(&operation.runtime)?;
    let endpoint = hetzner_api_endpoint(&operation.runtime, "servers")?;
    let mut page = 1_u32;
    let mut servers = Vec::new();
    for _ in 0..20 {
        let response = client
            .get(endpoint.clone())
            .bearer_auth(&operation.token)
            .query(&[("page", page), ("per_page", 50_u32)])
            .send()
            .await
            .map_err(|_| HetznerExecutionError::PrerequisiteRequestFailed)?;
        if !response.status().is_success() {
            return Err(HetznerExecutionError::PrerequisiteRequestFailed);
        }
        let payload = response
            .json::<HetznerServerListResponse>()
            .await
            .map_err(|_| HetznerExecutionError::InvalidResponse)?;
        if payload
            .servers
            .iter()
            .any(|server| server.id == 0 || !valid_bootstrap_name(server.name.trim()))
        {
            return Err(HetznerExecutionError::InvalidResponse);
        }
        let pagination_page = payload.meta.pagination.page;
        let last_page = payload.meta.pagination.last_page;
        let total_entries = usize::try_from(payload.meta.pagination.total_entries)
            .map_err(|_| HetznerExecutionError::InvalidResponse)?;
        let next_page = payload.meta.pagination.next_page;
        let observed_total = servers.len().saturating_add(payload.servers.len());
        if pagination_page != page
            || last_page == 0
            || pagination_page > last_page
            || observed_total > total_entries
        {
            return Err(HetznerExecutionError::InvalidResponse);
        }
        servers.extend(payload.servers);
        let Some(next_page) = next_page else {
            return if page == last_page && servers.len() == total_entries {
                Ok(servers)
            } else {
                Err(HetznerExecutionError::InvalidResponse)
            };
        };
        if next_page != page.saturating_add(1) || page >= last_page {
            return Err(HetznerExecutionError::InvalidResponse);
        }
        page = next_page;
    }
    Err(HetznerExecutionError::InvalidResponse)
}

#[derive(Debug, Clone, Deserialize)]
pub(super) struct HetznerPublicIp {
    ip: String,
}

#[derive(Debug, Deserialize)]
pub(super) struct HetznerSshKeyListResponse {
    #[serde(default)]
    ssh_keys: Vec<HetznerNamedResource>,
}

#[derive(Debug, Deserialize)]
pub(super) struct HetznerImageListResponse {
    #[serde(default)]
    images: Vec<HetznerNamedResource>,
}

#[derive(Debug, Deserialize)]
pub(super) struct HetznerFirewallListResponse {
    #[serde(default)]
    firewalls: Vec<HetznerNamedResource>,
}

#[derive(Debug, Deserialize)]
pub(super) struct HetznerNamedResource {
    id: u64,
    name: String,
}

pub(super) async fn resolve_hetzner_resource_id<T>(
    client: &reqwest::Client,
    endpoint: Url,
    token: &str,
    reference: &str,
    select: impl FnOnce(T) -> Vec<HetznerNamedResource>,
    missing: HetznerExecutionError,
) -> Result<u64, HetznerExecutionError>
where
    T: serde::de::DeserializeOwned,
{
    let response = client
        .get(endpoint)
        .bearer_auth(token)
        .query(&[("name", reference)])
        .send()
        .await
        .map_err(|_| HetznerExecutionError::PrerequisiteRequestFailed)?;
    if !response.status().is_success() {
        return Err(HetznerExecutionError::PrerequisiteRequestFailed);
    }
    let resources = response
        .json::<T>()
        .await
        .map(select)
        .map_err(|_| HetznerExecutionError::PrerequisiteRequestFailed)?;
    resources
        .into_iter()
        .find(|resource| resource.id > 0 && resource.name == reference)
        .map(|resource| resource.id)
        .ok_or(missing)
}

pub(super) async fn verify_hetzner_image(
    operation: &HetznerOperationContext,
    image: &str,
) -> Result<(), HetznerExecutionError> {
    let client = hetzner_http_client(&operation.runtime)?;
    resolve_hetzner_resource_id::<HetznerImageListResponse>(
        &client,
        hetzner_api_endpoint(&operation.runtime, "images")?,
        &operation.token,
        image,
        |response| response.images,
        HetznerExecutionError::ImageUnavailable,
    )
    .await
    .map(|_| ())
}

pub(super) fn hetzner_api_endpoint(
    config: &HetznerCloudRuntimeConfig,
    path: &str,
) -> Result<Url, HetznerExecutionError> {
    let mut endpoint = safe_hcloud_api_base(&config.api_base_url)
        .ok_or(HetznerExecutionError::ClientUnavailable)?;
    let base_path = endpoint.path().trim_end_matches('/').to_string();
    endpoint.set_path(&format!("{base_path}/{}", path.trim_start_matches('/')));
    Ok(endpoint)
}

#[derive(Debug, Clone, Copy)]
pub(super) struct HetznerCreatePrerequisites {
    ssh_key_id: u64,
    firewall_id: u64,
}

pub(super) async fn resolve_hetzner_create_prerequisites(
    plan: &ProvisioningReviewedPaidPlan,
    operation: &HetznerOperationContext,
) -> Result<HetznerCreatePrerequisites, HetznerExecutionError> {
    let client = hetzner_http_client(&operation.runtime)?;
    let ssh_key_ref = plan.ssh_key_ref.as_str();
    let firewall_ref = plan.firewall_ref.as_str();
    verify_hetzner_image(operation, &plan.image).await?;
    let ssh_key_id = resolve_hetzner_resource_id::<HetznerSshKeyListResponse>(
        &client,
        hetzner_api_endpoint(&operation.runtime, "ssh_keys")?,
        &operation.token,
        ssh_key_ref,
        |response| response.ssh_keys,
        HetznerExecutionError::SshKeyUnavailable,
    )
    .await?;
    let firewall_id = resolve_hetzner_resource_id::<HetznerFirewallListResponse>(
        &client,
        hetzner_api_endpoint(&operation.runtime, "firewalls")?,
        &operation.token,
        firewall_ref,
        |response| response.firewalls,
        HetznerExecutionError::FirewallUnavailable,
    )
    .await?;
    Ok(HetznerCreatePrerequisites {
        ssh_key_id,
        firewall_id,
    })
}

pub(super) async fn send_hetzner_create(
    plan: &ProvisioningReviewedPaidPlan,
    prerequisites: HetznerCreatePrerequisites,
    operation: &HetznerOperationContext,
) -> Result<HetznerCreatedServer, HetznerExecutionError> {
    if now_unix() >= plan.expires_at {
        return Err(HetznerExecutionError::ApprovalExpired);
    }
    let client = hetzner_http_client(&operation.runtime)?;
    let endpoint = hetzner_api_endpoint(&operation.runtime, "servers")?;
    let payload = HetznerCreateServerRequest {
        name: plan.server_name.clone(),
        server_type: plan.server_type.clone(),
        image: plan.image.clone(),
        location: Some(plan.location.clone()),
        ssh_keys: vec![prerequisites.ssh_key_id],
        firewalls: vec![HetznerCreateFirewall {
            firewall: prerequisites.firewall_id,
        }],
        labels: plan.required_labels.clone(),
        start_after_create: true,
    };
    let response = client
        .post(endpoint)
        .bearer_auth(&operation.token)
        .json(&payload)
        .send()
        .await
        .map_err(|_| HetznerExecutionError::RequestFailed)?;
    let status = response.status();
    if !status.is_success() {
        return Err(HetznerExecutionError::HttpStatus(status.as_u16()));
    }
    let server = response
        .json::<HetznerCreateServerResponse>()
        .await
        .map(|payload| payload.server)
        .map_err(|_| HetznerExecutionError::InvalidResponse)?;
    if server.id == 0 || !server.matches_reviewed_plan(plan) {
        return Err(HetznerExecutionError::InvalidResponse);
    }
    Ok(server)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum HetznerDeleteResult {
    Deleted,
    AlreadyAbsent,
}

pub(super) async fn delete_hetzner_server(
    provider_id: u64,
    operation: &HetznerOperationContext,
) -> Result<HetznerDeleteResult, HetznerExecutionError> {
    let client = hetzner_http_client(&operation.runtime)?;
    let endpoint = hetzner_api_endpoint(&operation.runtime, &format!("servers/{provider_id}"))?;
    let response = client
        .delete(endpoint)
        .bearer_auth(&operation.token)
        .send()
        .await
        .map_err(|_| HetznerExecutionError::RequestFailed)?;
    if response.status() == reqwest::StatusCode::NOT_FOUND {
        return Ok(HetznerDeleteResult::AlreadyAbsent);
    }
    if response.status() == reqwest::StatusCode::NO_CONTENT {
        return Ok(HetznerDeleteResult::Deleted);
    }
    if response.status().is_success() {
        return Err(HetznerExecutionError::InvalidResponse);
    }
    Err(HetznerExecutionError::HttpStatus(
        response.status().as_u16(),
    ))
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum ProvisioningCleanupError {
    UnsupportedJob,
    CleanupNotAllowed,
    ResourceMissing,
    ResourceAmbiguous,
    ResourceInvalid,
    OwnershipMismatch,
    RuntimeDisabled,
    ProviderUnavailable,
    ProviderUncertain,
    CleanupInProgress,
    PersistenceFailed,
}

impl ProvisioningCleanupError {
    fn status_code(self) -> StatusCode {
        match self {
            Self::UnsupportedJob | Self::ResourceInvalid => StatusCode::BAD_REQUEST,
            Self::CleanupNotAllowed
            | Self::ResourceMissing
            | Self::ResourceAmbiguous
            | Self::OwnershipMismatch
            | Self::CleanupInProgress => StatusCode::CONFLICT,
            Self::RuntimeDisabled | Self::ProviderUnavailable => StatusCode::SERVICE_UNAVAILABLE,
            Self::ProviderUncertain => StatusCode::BAD_GATEWAY,
            Self::PersistenceFailed => StatusCode::INTERNAL_SERVER_ERROR,
        }
    }

    fn safe_message(self) -> &'static str {
        match self {
            Self::UnsupportedJob => {
                "Cleanup is available only for a tracked Hetzner Cloud setup job."
            }
            Self::CleanupNotAllowed => {
                "This setup job is no longer eligible for provider cleanup."
            }
            Self::ResourceMissing => {
                "The setup job has no tracked Hetzner server to delete."
            }
            Self::ResourceAmbiguous => {
                "The setup job does not identify exactly one provider server; no deletion was attempted."
            }
            Self::ResourceInvalid => {
                "The tracked provider server is not valid for guarded cleanup; no deletion was attempted."
            }
            Self::OwnershipMismatch => {
                "The live provider server does not match the reviewed ownership labels and name; no deletion was attempted."
            }
            Self::RuntimeDisabled => {
                "Hetzner Cloud execution is disabled; no deletion was attempted."
            }
            Self::ProviderUnavailable => {
                "Hetzner Cloud cleanup is unavailable; the server remains tracked for recovery."
            }
            Self::ProviderUncertain => {
                "Hetzner Cloud did not prove deletion; cleanup is still required."
            }
            Self::CleanupInProgress => {
                "Cleanup is already running for this setup job."
            }
            Self::PersistenceFailed => {
                "Provider cleanup could not be recorded safely; review the tracked job before retrying."
            }
        }
    }
}

#[derive(Debug)]
pub(super) struct ProvisioningCleanupFailure {
    pub(super) error: ProvisioningCleanupError,
    pub(super) job: Option<ProvisioningJob>,
}

impl ProvisioningCleanupFailure {
    fn new(error: ProvisioningCleanupError, job: Option<ProvisioningJob>) -> Self {
        Self { error, job }
    }
}

#[derive(Debug, Clone)]
pub(super) struct HetznerCleanupTarget {
    provider_id: u64,
    resource: ProvisioningProviderResource,
    already_deleted: bool,
}

pub(super) fn hetzner_cleanup_target(
    job: &ProvisioningJob,
) -> Result<HetznerCleanupTarget, ProvisioningCleanupError> {
    if job.provider != "hetzner-cloud" {
        return Err(ProvisioningCleanupError::UnsupportedJob);
    }
    if job.provider_resources.is_empty() {
        return Err(ProvisioningCleanupError::ResourceMissing);
    }
    if job.provider_resources.len() != 1 {
        return Err(ProvisioningCleanupError::ResourceAmbiguous);
    }
    let resource = job
        .provider_resources
        .first()
        .cloned()
        .ok_or(ProvisioningCleanupError::ResourceMissing)?;
    if resource.provider != "hetzner-cloud" || resource.kind != "server" {
        return Err(ProvisioningCleanupError::ResourceInvalid);
    }
    let provider_id = resource
        .provider_id
        .parse::<u64>()
        .ok()
        .filter(|value| *value > 0)
        .ok_or(ProvisioningCleanupError::ResourceInvalid)?;
    let completed_rollback = job.state == ProvisioningJobState::Complete
        && job.terminal_outcome == Some(ProvisioningTerminalOutcome::RolledBack);
    let managed_retirement_in_progress = job.state == ProvisioningJobState::CleanupNeeded
        && job.managed_identity.as_ref().is_some_and(|identity| {
            matches!(
                identity.state,
                ProvisioningManagedIdentityState::RetirementPending
                    | ProvisioningManagedIdentityState::RetirementClaimed
                    | ProvisioningManagedIdentityState::CredentialRetired
            )
        });
    let managed_reconciliation_in_progress = job.state == ProvisioningJobState::CleanupNeeded
        && job.managed_identity.as_ref().is_some_and(|identity| {
            matches!(
                identity.state,
                ProvisioningManagedIdentityState::ReconciliationPending
                    | ProvisioningManagedIdentityState::ReconciliationClaimed
            )
        });
    if resource.state == "deleted" && (completed_rollback || managed_retirement_in_progress) {
        return Ok(HetznerCleanupTarget {
            provider_id,
            resource,
            already_deleted: true,
        });
    }
    if !matches!(
        job.state,
        ProvisioningJobState::WaitingForHeartbeat
            | ProvisioningJobState::BackupPending
            | ProvisioningJobState::Complete
            | ProvisioningJobState::CleanupNeeded
    ) {
        return Err(ProvisioningCleanupError::CleanupNotAllowed);
    }
    if managed_reconciliation_in_progress {
        return Err(ProvisioningCleanupError::CleanupNotAllowed);
    }
    if !matches!(
        resource.state.as_str(),
        "created" | "created-address-pending"
    ) {
        return Err(ProvisioningCleanupError::ResourceInvalid);
    }
    Ok(HetznerCleanupTarget {
        provider_id,
        resource,
        already_deleted: false,
    })
}

pub(super) fn provisioning_job_progress(
    request: &ProvisioningJobStartRequest,
    provider_runtime: &ProviderRuntimeConfig,
    now: i64,
) -> (ProvisioningJobState, Vec<ProvisioningProgressEntry>) {
    let mut progress = vec![ProvisioningProgressEntry {
        state: ProvisioningJobState::Planning,
        message: "Plan accepted; tracked job created.".to_string(),
        observed_at: now,
    }];

    match request.provider.as_str() {
        "hetzner-cloud" => {
            let hetzner = &provider_runtime.hetzner_cloud;
            if !hetzner.is_configured() {
                progress.push(ProvisioningProgressEntry {
                    state: ProvisioningJobState::Failed,
                    message: "Hetzner Cloud executor is not configured; no provider resources were created.".to_string(),
                    observed_at: now,
                });
                return (ProvisioningJobState::Failed, progress);
            }
            if request.apply {
                progress.push(ProvisioningProgressEntry {
                    state: ProvisioningJobState::Failed,
                    message: "Direct Hetzner Cloud apply is not accepted; review, authorize, and create must be separate requests. No provider resources were created.".to_string(),
                    observed_at: now,
                });
                return (ProvisioningJobState::Failed, progress);
            }
            if !hetzner.execute_enabled {
                progress.push(ProvisioningProgressEntry {
                    state: ProvisioningJobState::Failed,
                    message: "Hetzner Cloud executor is configured but live execution is disabled; no provider resources were created.".to_string(),
                    observed_at: now,
                });
                return (ProvisioningJobState::Failed, progress);
            }
            if missing_hetzner_create_inputs(request, hetzner) {
                progress.push(ProvisioningProgressEntry {
                    state: ProvisioningJobState::Failed,
                    message: "Hetzner Cloud executor needs host, location, server type, image, an SSH public-key reference, and a configured firewall before create/apply; no provider resources were created.".to_string(),
                    observed_at: now,
                });
                return (ProvisioningJobState::Failed, progress);
            }
            if invalid_hetzner_create_inputs(request, hetzner) {
                progress.push(ProvisioningProgressEntry {
                    state: ProvisioningJobState::Failed,
                    message: "Hetzner Cloud create inputs contain unsupported characters; no provider resources were created.".to_string(),
                    observed_at: now,
                });
                return (ProvisioningJobState::Failed, progress);
            }
            progress.push(ProvisioningProgressEntry {
                state: ProvisioningJobState::Planning,
                message: "Hetzner Cloud inputs accepted for an immutable paid-plan review; no provider resource was created.".to_string(),
                observed_at: now,
            });
            (ProvisioningJobState::Planning, progress)
        }
        "manual-import" => {
            progress.push(ProvisioningProgressEntry {
                state: ProvisioningJobState::Failed,
                message: "Manual import is routed to the existing-host flow; no provider resources were created.".to_string(),
                observed_at: now,
            });
            (ProvisioningJobState::Failed, progress)
        }
        "existing-host" => existing_host_job_progress(request, now, progress),
        _ => (ProvisioningJobState::Failed, progress),
    }
}

pub(super) fn existing_host_job_progress(
    request: &ProvisioningJobStartRequest,
    now: i64,
    mut progress: Vec<ProvisioningProgressEntry>,
) -> (ProvisioningJobState, Vec<ProvisioningProgressEntry>) {
    if request
        .host_name
        .as_deref()
        .is_none_or(|host_name| host_name.trim().is_empty())
    {
        progress.push(ProvisioningProgressEntry {
            state: ProvisioningJobState::Failed,
            message: "Existing-host setup needs a host name; no token files or host services were changed.".to_string(),
            observed_at: now,
        });
        return (ProvisioningJobState::Failed, progress);
    }
    if !request.apply {
        progress.push(ProvisioningProgressEntry {
            state: ProvisioningJobState::Failed,
            message: "Existing-host setup needs explicit confirmation; no token files or host services were changed.".to_string(),
            observed_at: now,
        });
        return (ProvisioningJobState::Failed, progress);
    }

    match request.template.as_str() {
        "manual-deferred" => {
            progress.push(ProvisioningProgressEntry {
                state: ProvisioningJobState::Bootstrapping,
                message: "Manual existing-host path recorded; no automated host changes were made."
                    .to_string(),
                observed_at: now,
            });
            progress.push(ProvisioningProgressEntry {
                state: ProvisioningJobState::WaitingForHeartbeat,
                message: "Waiting for file/env-file beacon handoff and first heartbeat; keep existing token files unchanged unless rotation is explicit.".to_string(),
                observed_at: now,
            });
            (ProvisioningJobState::WaitingForHeartbeat, progress)
        }
        "nixos-anywhere" | "native-systemd" => {
            if let Some(message) = existing_host_automated_handoff_blocker(request) {
                progress.push(ProvisioningProgressEntry {
                    state: ProvisioningJobState::Failed,
                    message: message.to_string(),
                    observed_at: now,
                });
                return (ProvisioningJobState::Failed, progress);
            }
            progress.push(ProvisioningProgressEntry {
                state: ProvisioningJobState::Bootstrapping,
                message: "Existing-host bootstrap handoff prepared; no raw beacon credential was generated, rendered, or installed by Pharos.".to_string(),
                observed_at: now,
            });
            progress.push(ProvisioningProgressEntry {
                state: ProvisioningJobState::WaitingForHeartbeat,
                message: "Waiting for Janus-backed or dev-local runtime credential handoff, beacon start, and first heartbeat.".to_string(),
                observed_at: now,
            });
            (ProvisioningJobState::WaitingForHeartbeat, progress)
        }
        _ => (ProvisioningJobState::Failed, progress),
    }
}

pub(super) fn existing_host_has_ssh_target(request: &ProvisioningJobStartRequest) -> bool {
    request.ssh.as_ref().is_some_and(|ssh| {
        !matches!(ssh.route, SshRoute::None | SshRoute::Unknown)
            && ssh
                .host
                .as_deref()
                .is_some_and(|host| !host.trim().is_empty())
    })
}

pub(super) fn existing_host_automated_handoff_blocker(
    request: &ProvisioningJobStartRequest,
) -> Option<&'static str> {
    if !existing_host_has_ssh_target(request) {
        return Some(
            "Existing-host automated bootstrap needs a non-secret SSH target before any handoff is recorded.",
        );
    }
    let Some(summary) = &request.preflight_summary else {
        return Some(
            "Existing-host automated bootstrap needs a completed preflight before any handoff is recorded.",
        );
    };
    if summary.state == PreflightCheckState::Fail {
        return Some(
            "Existing-host automated bootstrap cannot proceed while preflight has failed checks.",
        );
    }

    const REQUIRED_CHECKS: &[&str] = &[
        "ssh-reachability",
        "ssh-authentication",
        "privilege",
        "os-family",
        "disk-space",
        "pharos-reachability",
    ];
    for key in REQUIRED_CHECKS {
        match request
            .preflight_checks
            .iter()
            .find(|check| check.key == *key)
            .map(|check| check.state)
        {
            Some(PreflightCheckState::Pass | PreflightCheckState::Warn) => {}
            Some(PreflightCheckState::Fail) => {
                return Some(
                    "Existing-host automated bootstrap cannot proceed while a blocking preflight check is failing.",
                );
            }
            Some(PreflightCheckState::Unknown) | None => {
                return Some(
                    "Existing-host automated bootstrap needs verified SSH, privilege, OS, disk, and outbound Pharos checks before handoff.",
                );
            }
        }
    }
    None
}

pub(super) const REMOTE_NATIVE_SYSTEMD_READINESS: &str = r#"set -eu
for tool in systemctl install getent groupadd useradd; do
  if ! command -v "$tool" >/dev/null 2>&1; then
    printf 'runtime-unavailable'
    exit 0
  fi
done
if [ "$(id -u)" -eq 0 ]; then
  if [ -e /etc/pharos/pharos-beacon.env ] || [ -e /etc/pharos/pharos-beacon.token ]; then
    printf 'existing-token'
  else
    printf 'ready:%s' "$(uname -m 2>/dev/null || printf unknown)"
  fi
elif command -v sudo >/dev/null 2>&1 && sudo -n true >/dev/null 2>&1; then
  if sudo -n test -e /etc/pharos/pharos-beacon.env || sudo -n test -e /etc/pharos/pharos-beacon.token; then
    printf 'existing-token'
  else
    printf 'ready:%s' "$(uname -m 2>/dev/null || printf unknown)"
  fi
else
  printf 'privilege-unavailable'
fi
"#;

pub(super) const REMOTE_NATIVE_SYSTEMD_TOKEN_WRITE: &str = r#"set -eu
if [ "$(id -u)" -eq 0 ]; then
  install -d -m 0700 -o root -g root /etc/pharos
  test ! -e /etc/pharos/pharos-beacon.env
  test ! -e /etc/pharos/pharos-beacon.token
  umask 077
  cat > /etc/pharos/pharos-beacon.env
  chmod 0600 /etc/pharos/pharos-beacon.env
elif command -v sudo >/dev/null 2>&1 && sudo -n true >/dev/null 2>&1; then
  sudo -n install -d -m 0700 -o root -g root /etc/pharos
  sudo -n sh -c 'set -eu; test ! -e /etc/pharos/pharos-beacon.env; test ! -e /etc/pharos/pharos-beacon.token; umask 077; cat > /etc/pharos/pharos-beacon.env; chmod 0600 /etc/pharos/pharos-beacon.env'
else
  exit 77
fi
"#;

pub(super) fn valid_remote_bootstrap_dir(value: &str) -> bool {
    value.starts_with("/tmp/pharos-bootstrap.")
        && value.len() <= 128
        && value
            .chars()
            .all(|ch| ch.is_ascii_alphanumeric() || matches!(ch, '/' | '.' | '_' | '-'))
}

pub(super) fn remote_upload_command(path: &str) -> String {
    let path = shell_single_quote(path);
    format!("set -eu; umask 077; cat > {path}; chmod 0700 {path}")
}

pub(super) fn cleanup_native_systemd_bootstrap<R: ExistingHostSshRunner>(
    runner: &R,
    config: &ExistingHostRuntimeConfig,
    spec: &NativeSystemdBootstrapSpec,
    prepared: &PreparedNativeSystemdBootstrap,
) {
    let binary = shell_single_quote(&prepared.remote_binary);
    let installer = shell_single_quote(&prepared.remote_installer);
    let dir = shell_single_quote(&prepared.remote_dir);
    let command =
        format!("rm -f {binary} {installer} 2>/dev/null || true; rmdir {dir} 2>/dev/null || true");
    let _ = runner.run(config, spec, &command, None);
}

pub(super) fn prepare_native_systemd_bootstrap<R: ExistingHostSshRunner>(
    runner: &R,
    config: &ExistingHostRuntimeConfig,
    spec: &NativeSystemdBootstrapSpec,
) -> Result<PreparedNativeSystemdBootstrap, ExistingHostExecutionError> {
    config.validate_native_systemd()?;
    let beacon_binary =
        read_trusted_runtime_file(&config.beacon_binary_path, 128 * 1024 * 1024, 0o022, true)
            .ok_or(ExistingHostExecutionError::BeaconBinaryUnavailable)?;
    let installer = read_trusted_runtime_file(&config.installer_path, 1024 * 1024, 0o022, true)
        .ok_or(ExistingHostExecutionError::InstallerUnavailable)?;
    let remote_dir = String::from_utf8(runner.run(
        config,
        spec,
        "set -eu; umask 077; mktemp -d /tmp/pharos-bootstrap.XXXXXX",
        None,
    )?)
    .map_err(|_| ExistingHostExecutionError::RemoteResponseInvalid)?;
    let remote_dir = remote_dir.trim();
    if !valid_remote_bootstrap_dir(remote_dir) {
        return Err(ExistingHostExecutionError::RemoteResponseInvalid);
    }
    let prepared = PreparedNativeSystemdBootstrap {
        remote_dir: remote_dir.to_string(),
        remote_binary: format!("{remote_dir}/pharos-beacon"),
        remote_installer: format!("{remote_dir}/install-pharos-beacon-systemd.sh"),
    };
    if runner
        .run(
            config,
            spec,
            &remote_upload_command(&prepared.remote_binary),
            Some(&beacon_binary),
        )
        .is_err()
        || runner
            .run(
                config,
                spec,
                &remote_upload_command(&prepared.remote_installer),
                Some(&installer),
            )
            .is_err()
    {
        cleanup_native_systemd_bootstrap(runner, config, spec, &prepared);
        return Err(ExistingHostExecutionError::RemoteCommandFailed);
    }
    let readiness = match runner.run(config, spec, REMOTE_NATIVE_SYSTEMD_READINESS, None) {
        Ok(readiness) => readiness,
        Err(error) => {
            cleanup_native_systemd_bootstrap(runner, config, spec, &prepared);
            return Err(error);
        }
    };
    match std::str::from_utf8(&readiness).map(str::trim) {
        Ok(value)
            if value
                .strip_prefix("ready:")
                .is_some_and(native_binary_matches_remote_arch) =>
        {
            Ok(prepared)
        }
        Ok(value) if value.starts_with("ready:") => {
            cleanup_native_systemd_bootstrap(runner, config, spec, &prepared);
            Err(ExistingHostExecutionError::ArchitectureMismatch)
        }
        Ok("existing-token") => {
            cleanup_native_systemd_bootstrap(runner, config, spec, &prepared);
            Err(ExistingHostExecutionError::ExistingTokenFile)
        }
        Ok("runtime-unavailable" | "privilege-unavailable") => {
            cleanup_native_systemd_bootstrap(runner, config, spec, &prepared);
            Err(ExistingHostExecutionError::RemoteCommandFailed)
        }
        _ => {
            cleanup_native_systemd_bootstrap(runner, config, spec, &prepared);
            Err(ExistingHostExecutionError::RemoteResponseInvalid)
        }
    }
}

pub(super) fn install_native_systemd_bootstrap<R: ExistingHostSshRunner>(
    runner: &R,
    config: &ExistingHostRuntimeConfig,
    spec: &NativeSystemdBootstrapSpec,
    prepared: &PreparedNativeSystemdBootstrap,
    token: &str,
) -> Result<(), ExistingHostExecutionError> {
    let pharos_url = config.validate_native_systemd()?;
    let token_payload = format!("PHAROS_TOKEN={token}\n");
    if runner
        .run(
            config,
            spec,
            REMOTE_NATIVE_SYSTEMD_TOKEN_WRITE,
            Some(token_payload.as_bytes()),
        )
        .is_err()
    {
        cleanup_native_systemd_bootstrap(runner, config, spec, prepared);
        return Err(ExistingHostExecutionError::RemoteCommandFailed);
    }

    let installer = shell_single_quote(&prepared.remote_installer);
    let binary = shell_single_quote(&prepared.remote_binary);
    let pharos_url = shell_single_quote(pharos_url);
    let host_name = shell_single_quote(&spec.host_name);
    let role = shell_single_quote(&spec.role);
    let interval = spec.interval;
    let install_command = format!(
        "{installer} --binary {binary} --token-env /etc/pharos/pharos-beacon.env --pharos-url {pharos_url} --host {host_name} --role {role} --interval {interval}"
    );
    let remote_command = format!(
        "set -eu; if [ \"$(id -u)\" -eq 0 ]; then exec {install_command}; elif command -v sudo >/dev/null 2>&1 && sudo -n true >/dev/null 2>&1; then exec sudo -n {install_command}; else exit 77; fi"
    );
    let result = runner.run(config, spec, &remote_command, None);
    cleanup_native_systemd_bootstrap(runner, config, spec, prepared);
    result.map(|_| ())
}

pub(super) fn provisioning_existing_host_context(
    request: &ProvisioningJobStartRequest,
) -> Option<ExistingHostSetupContext> {
    if request.provider != "existing-host" {
        return None;
    }
    let selected_bootstrap = match request.template.as_str() {
        "nixos-anywhere" => BootstrapMethod::NixosAnywhere,
        "native-systemd" => BootstrapMethod::NativeSystemd,
        "manual-deferred" => BootstrapMethod::Manual,
        _ => return None,
    };
    if matches!(
        selected_bootstrap,
        BootstrapMethod::NixosAnywhere | BootstrapMethod::NativeSystemd
    ) && !existing_host_has_ssh_target(request)
    {
        return None;
    }
    let ssh = request.ssh.clone().unwrap_or(SshAccessIntent {
        route: SshRoute::None,
        user: None,
        host: None,
        port: None,
    });
    let host = request
        .host_name
        .as_deref()
        .map(str::trim)
        .filter(|host| !host.is_empty())
        .unwrap_or("the host");
    let method_label = match selected_bootstrap {
        BootstrapMethod::NixosAnywhere => "NixOS declarative bootstrap",
        BootstrapMethod::NativeSystemd => "native systemd beacon install",
        BootstrapMethod::Manual | BootstrapMethod::Deferred => "manual beacon handoff",
    };
    let verification_steps = vec![
        format!("Confirm the selected path for {host}: {method_label}."),
        "Install or reference the beacon credential through the runtime secret target only."
            .to_string(),
        "Start pharos-beacon and wait until Pharos records the first heartbeat.".to_string(),
        "Finish backup and location decisions according to the recorded setup intent.".to_string(),
    ];
    Some(ExistingHostSetupContext {
        ssh,
        selected_bootstrap,
        preflight_summary: request.preflight_summary.clone(),
        preflight_checks: request.preflight_checks.iter().take(12).cloned().collect(),
        verification_steps,
    })
}

pub(super) fn provisioning_job_handoff(
    request: &ProvisioningJobStartRequest,
) -> Option<ProvisioningHandoff> {
    if request.provider != "existing-host" {
        return None;
    }
    let method = match request.template.as_str() {
        "nixos-anywhere" => BootstrapMethod::NixosAnywhere,
        "native-systemd" => BootstrapMethod::NativeSystemd,
        "manual-deferred" => BootstrapMethod::Manual,
        _ => return None,
    };
    if matches!(
        method,
        BootstrapMethod::NixosAnywhere | BootstrapMethod::NativeSystemd
    ) && existing_host_automated_handoff_blocker(request).is_some()
    {
        return None;
    }
    let interval = request.heartbeat_interval_secs.unwrap_or(60).max(1);
    let backup_steps = backup_enrollment_steps(request, method);
    match method {
        BootstrapMethod::NixosAnywhere => {
            let mut next_steps = vec![
                "Prepare the target flake so services.pharos-beacon imports the Pharos module and reads /etc/pharos/pharos-beacon.token for first bootstrap.".to_string(),
                "From a Linux executor, run scripts/bootstrap-pharos-nixos-anywhere.sh with a private token file and pinned SSH known-hosts file.".to_string(),
                "Wait for the first heartbeat, then migrate the bootstrap token file to the target's long-term agenix or Janus runtime secret path.".to_string(),
            ];
            next_steps.extend(backup_steps);
            Some(ProvisioningHandoff {
                method,
                status: "runtime-credential-required".to_string(),
                title: "NixOS bootstrap handoff".to_string(),
                summary: "Declarative bootstrap is selected; the helper copies the token through nixos-anywhere extra-files and Pharos waits for the first heartbeat.".to_string(),
                token_policy: "The helper accepts a private token file path and copies its value outside Nix evaluation; raw credentials never enter command arguments or the Nix store.".to_string(),
                secret_target: Some("/etc/pharos/pharos-beacon.token".to_string()),
                command_ref: Some("scripts/bootstrap-pharos-nixos-anywhere.sh".to_string()),
                next_steps,
            })
        }
        BootstrapMethod::NativeSystemd => {
            let mut next_steps = vec![
                "Create the env file through an approved secret channel before starting the service.".to_string(),
                format!(
                    "Run the native installer with the selected host, role, and {interval}s heartbeat interval."
                ),
                "Start pharos-beacon and wait for the first heartbeat before marking onboarding complete.".to_string(),
            ];
            next_steps.extend(backup_steps);
            Some(ProvisioningHandoff {
                method,
                status: "runtime-credential-required".to_string(),
                title: "Native systemd beacon handoff".to_string(),
                summary: "Portable beacon install is selected; Pharos prepared the non-secret handoff and is waiting for a root-owned runtime env file plus the first heartbeat.".to_string(),
                token_policy: "Beacon credentials belong in a root-owned env file or token file and must not be pasted into shell history.".to_string(),
                secret_target: Some("/etc/pharos/pharos-beacon.env".to_string()),
                command_ref: Some("scripts/install-pharos-beacon-systemd.sh".to_string()),
                next_steps,
            })
        }
        BootstrapMethod::Manual | BootstrapMethod::Deferred => {
            let mut next_steps = vec![
                "Install or enable pharos-beacon using the appropriate NixOS or native systemd path.".to_string(),
                format!("Configure the beacon to report with a {interval}s heartbeat interval."),
                "Confirm the first heartbeat appears in Pharos, then continue backup and location decisions.".to_string(),
            ];
            next_steps.extend(backup_steps);
            Some(ProvisioningHandoff {
                method: BootstrapMethod::Manual,
                status: "manual-handoff".to_string(),
                title: "Manual beacon handoff".to_string(),
                summary: "No automated host changes were made; Pharos is waiting for the operator-managed beacon install.".to_string(),
                token_policy: "Use a file or env-file secret handoff; never place the beacon credential in command arguments, chat, PPM, or logs.".to_string(),
                secret_target: Some("/etc/pharos/pharos-beacon.env".to_string()),
                command_ref: Some("scripts/install-pharos-beacon-systemd.sh or nixosModules.pharos-beacon".to_string()),
                next_steps,
            })
        }
    }
}

pub(super) fn backup_enrollment_steps(
    request: &ProvisioningJobStartRequest,
    method: BootstrapMethod,
) -> Vec<String> {
    let intent = request.backup_intent.unwrap_or(BackupSetupIntent::Deferred);
    let nix_path = request
        .is_nix
        .unwrap_or(matches!(method, BootstrapMethod::NixosAnywhere));
    match intent {
        BackupSetupIntent::Required => {
            let mut steps = vec![
                "Backup required: keep onboarding open after first heartbeat until Pharos observes a first successful backup or a concrete failure.".to_string(),
            ];
            if nix_path {
                steps.push("For NixOS, prepare a declarative backup module proposal that reads repository and password material from agenix or Janus-rendered runtime files; do not embed secret values in Nix options or the Nix store.".to_string());
            } else {
                steps.push("For non-Nix hosts, install or observe a native backup job through a runtime secret file, then let pharos-beacon report sanitized backup evidence.".to_string());
            }
            steps
        }
        BackupSetupIntent::Optional => vec![
            "Backup optional: offer enrollment after first heartbeat, but allow onboarding to finish if the operator explicitly defers protection.".to_string(),
        ],
        BackupSetupIntent::External => vec![
            "Backups managed elsewhere: keep Pharos read-only and observe external backup evidence when the beacon can detect it.".to_string(),
        ],
        BackupSetupIntent::EnrollLater => vec![
            "Backup enrollment later: create a backup-pending follow-up after first heartbeat and do not block beacon onboarding.".to_string(),
        ],
        BackupSetupIntent::Absent => vec![
            "No backups requested: record the host as intentionally unprotected until the operator changes backup intent.".to_string(),
        ],
        BackupSetupIntent::Deferred => vec![
            "Backup decision pending: ask for backup intent again before considering onboarding complete.".to_string(),
        ],
    }
}

pub(super) fn provisioning_setup_intent(
    request: &ProvisioningJobStartRequest,
) -> Option<ProvisioningSetupIntent> {
    Some(ProvisioningSetupIntent {
        backup: request.backup_intent.unwrap_or(BackupSetupIntent::Deferred),
        location: request.location_intent.unwrap_or(LocationSetupIntent::Auto),
        access: request
            .access_intent
            .unwrap_or(AccessSetupIntent::OperatorOnly),
    })
}

pub(super) fn provisioning_backup_proposal(
    request: &ProvisioningJobStartRequest,
) -> Option<ProvisioningBackupProposal> {
    let intent = request.backup_intent.unwrap_or(BackupSetupIntent::Deferred);
    if !matches!(
        intent,
        BackupSetupIntent::Required | BackupSetupIntent::Optional | BackupSetupIntent::EnrollLater
    ) {
        return None;
    }

    let nix_path = request.is_nix.unwrap_or_else(|| {
        request.provider == "hetzner-cloud" || request.template == "nixos-anywhere"
    });
    if !nix_path {
        return None;
    }

    let host_slug = request
        .host_name
        .as_deref()
        .map(secret_ref_slug)
        .filter(|slug| !slug.is_empty())
        .unwrap_or_else(|| "pharos-host".to_string());
    let repository_file = format!("/run/agenix/{host_slug}-restic-repository");
    let password_file = format!("/run/agenix/{host_slug}-restic-password");
    let nix_module = format!(
        r#"{{
  config,
  lib,
  ...
}}:

{{
  services.pharos-beacon.extraEnvironment = {{
    PHAROS_BACKUP_MODE = "restic";
    PHAROS_BACKUP_ID = "restic-main";
    PHAROS_BACKUP_LABEL = "Restic backup";
    PHAROS_BACKUP_TARGET_LABEL = "off-box repository";
    PHAROS_BACKUP_SCHEDULE = "daily";
    PHAROS_BACKUP_STALE_AFTER_SECS = "129600";
    RESTIC_REPOSITORY_FILE = "{repository_file}";
    RESTIC_PASSWORD_FILE = "{password_file}";
  }};

  systemd.services.pharos-beacon.serviceConfig.ReadOnlyPaths = [
    "{repository_file}"
    "{password_file}"
  ];
}}
"#
    );

    Some(ProvisioningBackupProposal {
        kind: ProvisioningBackupProposalKind::NixosResticBeaconObservation,
        title: "NixOS restic backup proposal".to_string(),
        summary: "Declarative beacon backup observation using runtime agenix files for repository and password material.".to_string(),
        module_attribute: "services.pharos-beacon.extraEnvironment".to_string(),
        nix_module,
        secret_files: vec![
            ProvisioningBackupSecretFile {
                key: "restic-repository-file".to_string(),
                owner: SecretOwner::Agenix,
                path: repository_file,
                purpose: "Restic repository location, stored outside the Nix store.".to_string(),
            },
            ProvisioningBackupSecretFile {
                key: "restic-password-file".to_string(),
                owner: SecretOwner::Agenix,
                path: password_file,
                purpose: "Restic repository password, readable only by pharos-beacon.".to_string(),
            },
        ],
        next_steps: vec![
            "Create or reference the agenix files before deployment.".to_string(),
            "Review the NixOS module snippet in nixcfg and keep raw values out of Nix options.".to_string(),
            "Deploy the host, wait for the first heartbeat, then verify first backup evidence in Pharos.".to_string(),
        ],
    })
}

pub(super) fn secret_ref_slug(value: &str) -> String {
    let mut out = String::new();
    let mut last_dash = false;
    for ch in value.trim().chars() {
        let next = if ch.is_ascii_alphanumeric() {
            last_dash = false;
            Some(ch.to_ascii_lowercase())
        } else if !last_dash {
            last_dash = true;
            Some('-')
        } else {
            None
        };
        if let Some(next) = next {
            out.push(next);
        }
    }
    out.trim_matches('-').to_string()
}

pub(super) fn missing_hetzner_create_inputs(
    request: &ProvisioningJobStartRequest,
    config: &HetznerCloudRuntimeConfig,
) -> bool {
    [
        request.host_name.as_deref(),
        request.location.as_deref(),
        request.server_type.as_deref(),
        request.image.as_deref(),
    ]
    .iter()
    .any(|value| value.is_none_or(|value| value.trim().is_empty()))
        || request
            .ssh_key_ref
            .as_deref()
            .or(config.default_ssh_key_ref.as_deref())
            .is_none_or(|value| value.trim().is_empty())
        || config
            .firewall_ref
            .as_deref()
            .is_none_or(|value| value.trim().is_empty())
}

pub(super) fn valid_provider_selector(value: &str) -> bool {
    let value = value.trim();
    !value.is_empty()
        && value.len() <= 160
        && value
            .chars()
            .next()
            .is_some_and(|ch| ch.is_ascii_alphanumeric())
        && value
            .chars()
            .all(|ch| ch.is_ascii_alphanumeric() || matches!(ch, '.' | '_' | '-' | ':' | '/'))
        && !value.to_ascii_lowercase().contains("token=")
        && !value.to_ascii_lowercase().contains("password=")
}

pub(super) fn valid_provider_resource_name(value: &str) -> bool {
    safe_paid_display_text(value, 160)
}

pub(super) fn safe_paid_display_text(value: &str, max_chars: usize) -> bool {
    let value = value.trim();
    let lowered = value.to_ascii_lowercase();
    !value.is_empty()
        && value.chars().count() <= max_chars
        && !value.chars().any(char::is_control)
        && !lowered.contains("bearer ")
        && !lowered.contains("token=")
        && !lowered.contains("token:")
        && !lowered.contains("password=")
        && !lowered.contains("secret=")
}

pub(super) fn valid_hcloud_server_name(value: &str) -> bool {
    let value = value.trim();
    !value.is_empty()
        && value.len() <= 63
        && value
            .bytes()
            .next()
            .is_some_and(|byte| byte.is_ascii_alphanumeric())
        && value
            .bytes()
            .last()
            .is_some_and(|byte| byte.is_ascii_alphanumeric())
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
}

pub(super) fn invalid_hetzner_create_inputs(
    request: &ProvisioningJobStartRequest,
    config: &HetznerCloudRuntimeConfig,
) -> bool {
    request
        .host_name
        .as_deref()
        .is_none_or(|value| !valid_hcloud_server_name(value))
        || request
            .role
            .as_deref()
            .is_some_and(|value| !safe_bootstrap_role(value.trim()))
        || [
            request.location.as_deref(),
            request.server_type.as_deref(),
            request.image.as_deref(),
        ]
        .iter()
        .any(|value| value.is_none_or(|value| !valid_provider_selector(value)))
        || request
            .ssh_key_ref
            .as_deref()
            .or(config.default_ssh_key_ref.as_deref())
            .is_none_or(|value| !valid_provider_resource_name(value))
        || config
            .firewall_ref
            .as_deref()
            .is_none_or(|value| !valid_provider_resource_name(value))
}

#[derive(Debug, PartialEq, Eq)]
pub(super) enum ProvisioningJobStartError {
    UnsupportedProvider,
    UnsupportedTemplate,
    InvalidJob,
    PersistenceFailed,
}

impl std::fmt::Display for ProvisioningJobStartError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::UnsupportedProvider => write!(f, "unsupported setup provider"),
            Self::UnsupportedTemplate => write!(f, "unsupported setup template"),
            Self::InvalidJob => write!(f, "provisioning job contract failed validation"),
            Self::PersistenceFailed => {
                write!(f, "provisioning job could not be durably stored")
            }
        }
    }
}

pub(super) fn valid_setup_provider(provider: &str) -> bool {
    matches!(
        provider,
        "hetzner-cloud" | "manual-import" | "existing-host"
    )
}

pub(super) fn valid_setup_template(provider: &str, template: &str) -> bool {
    matches!(
        (provider, template),
        ("hetzner-cloud", "hetzner-small-nixos")
            | ("hetzner-cloud", "hetzner-lab")
            | ("hetzner-cloud", "bring-own-plan")
            | ("manual-import", "manual-import")
            | ("manual-import", "netcup-manual-import")
            | ("manual-import", "oracle-always-free-lab")
            | ("manual-import", "gcp-free-tier-lab")
            | ("existing-host", "nixos-anywhere")
            | ("existing-host", "native-systemd")
            | ("existing-host", "manual-deferred")
    )
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub(super) struct SetupProviderPlan {
    pub(super) schema: &'static str,
    pub(super) version: u16,
    pub(super) provider: &'static str,
    pub(super) template: &'static str,
    pub(super) strategy: &'static str,
    pub(super) approach: &'static str,
    pub(super) summary: &'static str,
    pub(super) docs: Vec<SetupProviderPlanDoc>,
    pub(super) resources: Vec<SetupProviderPlanResource>,
    pub(super) steps: Vec<SetupProviderPlanStep>,
    pub(super) secret_boundary: Vec<SetupProviderPlanSecretBoundary>,
    pub(super) handoffs: Vec<SetupProviderPlanHandoff>,
    pub(super) runtime_checks: Vec<&'static str>,
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub(super) struct SetupProviderPlanDoc {
    pub(super) label: &'static str,
    pub(super) url: &'static str,
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub(super) struct SetupProviderPlanResource {
    pub(super) key: &'static str,
    pub(super) kind: &'static str,
    pub(super) required: bool,
    pub(super) api: &'static str,
    pub(super) detail: &'static str,
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub(super) struct SetupProviderPlanStep {
    pub(super) key: &'static str,
    pub(super) title: &'static str,
    pub(super) detail: &'static str,
    pub(super) status: &'static str,
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub(super) struct SetupProviderPlanSecretBoundary {
    pub(super) key: &'static str,
    pub(super) source: &'static str,
    pub(super) rule: &'static str,
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub(super) struct SetupProviderPlanHandoff {
    pub(super) key: &'static str,
    pub(super) target: &'static str,
    pub(super) detail: &'static str,
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub(super) struct SetupProviderRuntimeReadiness {
    pub(super) credential_configured: bool,
    pub(super) credential_boundary_ready: bool,
    pub(super) execution_enabled: bool,
    pub(super) project_label_configured: bool,
    pub(super) default_ssh_key_configured: bool,
    pub(super) firewall_configured: bool,
    pub(super) default_location_configured: bool,
    pub(super) connection_tested: bool,
    pub(super) evidence_fresh: bool,
    pub(super) api_access: bool,
    pub(super) connection_ready: bool,
    pub(super) provider_ready: bool,
    pub(super) ready_with_defaults: bool,
    pub(super) tested_at: Option<i64>,
    pub(super) message: String,
}

pub(super) fn effective_hetzner_runtime(
    config: &HetznerCloudRuntimeConfig,
    store: &ProviderConnectionStore,
) -> HetznerCloudRuntimeConfig {
    let preferences = store.preferences();
    let mut effective = config.clone();
    if preferences.default_location.is_some() {
        effective.default_location = preferences.default_location;
    }
    if preferences.ssh_key_ref.is_some() {
        effective.default_ssh_key_ref = preferences.ssh_key_ref;
    }
    if preferences.firewall_ref.is_some() {
        effective.firewall_ref = preferences.firewall_ref;
    }
    effective
}

pub(super) fn hetzner_runtime_readiness(
    config: &HetznerCloudRuntimeConfig,
    store: &ProviderConnectionStore,
    now: i64,
) -> SetupProviderRuntimeReadiness {
    let config = effective_hetzner_runtime(config, store);
    let credential_configured = config.api_token().is_ok();
    let credential_boundary_ready = config.credential_boundary_ready();
    let execution_enabled = config.execute_enabled;
    let project_label_configured = config
        .project_label
        .as_deref()
        .is_some_and(|value| safe_paid_display_text(value, 120));
    let default_ssh_key_configured = config
        .default_ssh_key_ref
        .as_deref()
        .is_some_and(valid_provider_resource_name);
    let firewall_configured = config
        .firewall_ref
        .as_deref()
        .is_some_and(valid_provider_resource_name);
    let default_location_configured = config
        .default_location
        .as_deref()
        .is_some_and(valid_provider_selector);
    let attempt = store.last_attempt();
    let connection_tested = attempt.is_some();
    let evidence_fresh = attempt
        .as_ref()
        .is_some_and(|attempt| evidence_is_fresh(attempt.tested_at, now, config.evidence_ttl_secs))
        && store.catalog().is_some_and(|catalog| {
            evidence_is_fresh(catalog.refreshed_at, now, config.evidence_ttl_secs)
        });
    let api_access = evidence_fresh && attempt.as_ref().is_some_and(|attempt| attempt.api_access);
    let connection_ready = credential_configured
        && credential_boundary_ready
        && project_label_configured
        && api_access
        && default_ssh_key_configured
        && firewall_configured
        && default_location_configured
        && attempt.as_ref().is_some_and(|attempt| {
            attempt.ssh_key_ready
                && attempt.firewall_ready
                && attempt.default_location_ready
                && attempt.catalog_ready
        });
    let provider_ready = credential_configured
        && credential_boundary_ready
        && execution_enabled
        && store.ready(now, config.evidence_ttl_secs);
    let ready_with_defaults = provider_ready
        && project_label_configured
        && default_ssh_key_configured
        && firewall_configured
        && default_location_configured;
    let message = if store.disconnected_at().is_some() {
        HetznerConnectionCode::Disconnected.safe_message()
    } else if !credential_configured {
        "Hetzner Cloud is not connected. Start secure setup before creating a server."
    } else if !credential_boundary_ready {
        HetznerConnectionCode::CredentialBoundaryRequired.safe_message()
    } else if !project_label_configured {
        "Set a safe provider project label before reviewing paid work."
    } else if !connection_tested {
        "The secure credential is available. Test the connection to continue."
    } else if !evidence_fresh {
        "The last connection test is stale. Test again before creating a server."
    } else if !execution_enabled
        && attempt
            .as_ref()
            .is_some_and(|attempt| attempt.code == HetznerConnectionCode::Ready)
    {
        HetznerConnectionCode::ExecutionDisabled.safe_message()
    } else if let Some(attempt) = attempt.as_ref() {
        attempt.code.safe_message()
    } else {
        HetznerConnectionCode::InvalidResponse.safe_message()
    };
    SetupProviderRuntimeReadiness {
        credential_configured,
        credential_boundary_ready,
        execution_enabled,
        project_label_configured,
        default_ssh_key_configured,
        firewall_configured,
        default_location_configured,
        connection_tested,
        evidence_fresh,
        api_access,
        connection_ready,
        provider_ready,
        ready_with_defaults,
        tested_at: attempt.map(|attempt| attempt.tested_at),
        message: message.to_string(),
    }
}

pub(super) const PROVIDER_CONNECTIONS_SCHEMA: &str = "inspr.pharos.provider-connections.v1";

#[derive(Debug, Clone, Copy, Serialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub(super) enum ProviderConnectionCapability {
    Managed,
    Guided,
}

impl ProviderConnectionCapability {
    pub(super) fn label(self) -> &'static str {
        match self {
            Self::Managed => "Managed",
            Self::Guided => "Guided",
        }
    }
}

#[derive(Debug, Clone, Copy, Serialize, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
pub(super) enum ProviderConnectionState {
    Ready,
    NeedsAttention,
    NotConnected,
    Guided,
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub(super) struct ProviderConnectionSummary {
    pub(super) key: &'static str,
    pub(super) name: &'static str,
    pub(super) description: &'static str,
    pub(super) capability: ProviderConnectionCapability,
    pub(super) state: ProviderConnectionState,
    pub(super) state_label: &'static str,
    pub(super) note: String,
    pub(super) detail_href: &'static str,
    pub(super) action_label: &'static str,
    pub(super) available_in_add_server: bool,
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub(super) struct ProviderConnectionsPayload {
    pub(super) schema: &'static str,
    pub(super) version: u16,
    pub(super) providers: Vec<ProviderConnectionSummary>,
}

pub(super) fn provider_connections(
    runtime: &ProviderRuntimeConfig,
    store: &ProviderConnectionStore,
    now: i64,
) -> ProviderConnectionsPayload {
    let hetzner = hetzner_runtime_readiness(&runtime.hetzner_cloud, store, now);
    let (hetzner_state, hetzner_label, hetzner_action) = if hetzner.ready_with_defaults {
        (ProviderConnectionState::Ready, "Ready", "Review")
    } else if hetzner.credential_configured {
        (
            ProviderConnectionState::NeedsAttention,
            "Needs attention",
            "Continue",
        )
    } else {
        (
            ProviderConnectionState::NotConnected,
            "Not connected",
            "Connect",
        )
    };
    ProviderConnectionsPayload {
        schema: PROVIDER_CONNECTIONS_SCHEMA,
        version: 1,
        providers: vec![
            ProviderConnectionSummary {
                key: "hetzner-cloud",
                name: "Hetzner Cloud",
                description: "Create and set up servers automatically.",
                capability: ProviderConnectionCapability::Managed,
                state: hetzner_state,
                state_label: hetzner_label,
                note: hetzner.message,
                detail_href: "/settings/providers/hetzner-cloud",
                action_label: hetzner_action,
                available_in_add_server: hetzner.ready_with_defaults,
            },
            ProviderConnectionSummary {
                key: "netcup",
                name: "netcup",
                description: "Order there, then continue setup in Pharos.",
                capability: ProviderConnectionCapability::Guided,
                state: ProviderConnectionState::Guided,
                state_label: "No connection needed",
                note: "Pharos does not claim unsupported server-order automation.".to_string(),
                detail_href: "/settings/providers/netcup",
                action_label: "Start",
                available_in_add_server: false,
            },
            ProviderConnectionSummary {
                key: "aws",
                name: "AWS",
                description: "Credits may cover initial use.",
                capability: ProviderConnectionCapability::Guided,
                state: ProviderConnectionState::Guided,
                state_label: "Credits expire",
                note: "AWS credits and free-plan eligibility are time-limited.".to_string(),
                detail_href: "/settings/providers/aws",
                action_label: "Start",
                available_in_add_server: false,
            },
            ProviderConnectionSummary {
                key: "google-cloud",
                name: "Google Cloud",
                description: "Eligible small servers in selected regions.",
                capability: ProviderConnectionCapability::Guided,
                state: ProviderConnectionState::Guided,
                state_label: "Eligibility varies",
                note: "Free-tier eligibility depends on region, machine, disk, and account."
                    .to_string(),
                detail_href: "/settings/providers/google-cloud",
                action_label: "Start",
                available_in_add_server: false,
            },
            ProviderConnectionSummary {
                key: "oracle-cloud",
                name: "Oracle Cloud",
                description: "Eligible capacity in your home region.",
                capability: ProviderConnectionCapability::Guided,
                state: ProviderConnectionState::Guided,
                state_label: "Capacity varies",
                note: "Always Free capacity is not guaranteed and has no paid fallback."
                    .to_string(),
                detail_href: "/settings/providers/oracle-cloud",
                action_label: "Start",
                available_in_add_server: false,
            },
        ],
    }
}

pub(super) fn provider_connection(
    runtime: &ProviderRuntimeConfig,
    store: &ProviderConnectionStore,
    key: &str,
    now: i64,
) -> Option<ProviderConnectionSummary> {
    provider_connections(runtime, store, now)
        .providers
        .into_iter()
        .find(|provider| provider.key == key)
}

pub(super) fn provider_official_destination(key: &str) -> Option<(&'static str, &'static str)> {
    match key {
        "netcup" => Some(("Open netcup", "https://www.netcup.com/en/server/")),
        "aws" => Some(("Open AWS Free Tier", "https://aws.amazon.com/free/")),
        "google-cloud" => Some((
            "Open Google Cloud free program",
            "https://cloud.google.com/free/docs/free-cloud-features",
        )),
        "oracle-cloud" => Some((
            "Open Oracle Cloud Free Tier",
            "https://www.oracle.com/cloud/free/",
        )),
        _ => None,
    }
}

pub(super) fn hetzner_janus_setup_url(
    runtime: &ProviderRuntimeConfig,
    host: &str,
) -> Option<String> {
    if !valid_action_host_name(host) {
        return None;
    }
    let mut url = runtime.janus_public_url.clone()?;
    url.set_path("/vault/new");
    url.query_pairs_mut()
        .append_pair("service", "Hetzner Cloud provider")
        .append_pair("host", host)
        .append_pair("env", "PHAROS_HCLOUD_API_TOKEN")
        .append_pair("display", "Hetzner Cloud API token for Pharos")
        .append_pair("classification", "high")
        .append_pair("rotation", "180")
        .append_pair("tags", "pharos,provider,hetzner");
    Some(url.to_string())
}

pub(super) fn setup_provider_plan(
    provider: &str,
    template: &str,
) -> Result<SetupProviderPlan, ProvisioningJobStartError> {
    if !valid_setup_provider(provider) {
        return Err(ProvisioningJobStartError::UnsupportedProvider);
    }
    if !valid_setup_template(provider, template) {
        return Err(ProvisioningJobStartError::UnsupportedTemplate);
    }
    match (provider, template) {
        ("hetzner-cloud", "hetzner-small-nixos")
        | ("hetzner-cloud", "hetzner-lab")
        | ("hetzner-cloud", "bring-own-plan") => Ok(hetzner_cloud_setup_plan(template)),
        ("manual-import", "manual-import")
        | ("manual-import", "netcup-manual-import")
        | ("manual-import", "oracle-always-free-lab")
        | ("manual-import", "gcp-free-tier-lab") => Ok(manual_import_setup_plan(template)),
        _ => Err(ProvisioningJobStartError::UnsupportedTemplate),
    }
}

pub(super) fn hetzner_cloud_setup_plan(template: &str) -> SetupProviderPlan {
    SetupProviderPlan {
        schema: "inspr.pharos.setup-provider-plan.v1",
        version: 1,
        provider: "hetzner-cloud",
        template: match template {
            "hetzner-lab" => "hetzner-lab",
            "bring-own-plan" => "bring-own-plan",
            _ => "hetzner-small-nixos",
        },
        strategy: "hcloud-api-plus-nixos-anywhere",
        approach: "Use direct Hetzner Cloud API execution for live jobs; keep the hcloud Terraform/OpenTofu provider as the plan-compatible reference, not as a required state backend.",
        summary: "Plan Hetzner Cloud resources through the Cloud API, then bootstrap NixOS with nixos-anywhere before waiting for the first beacon heartbeat.",
        docs: vec![
            SetupProviderPlanDoc {
                label: "Hetzner Cloud API reference",
                url: "https://docs.hetzner.cloud/reference/cloud",
            },
            SetupProviderPlanDoc {
                label: "Hetzner Cloud API getting started",
                url: "https://docs.hetzner.cloud/",
            },
            SetupProviderPlanDoc {
                label: "Hetzner Cloud Terraform provider",
                url: "https://registry.terraform.io/providers/hetznercloud/hcloud/latest/docs",
            },
            SetupProviderPlanDoc {
                label: "nixos-anywhere quickstart",
                url: "https://github.com/nix-community/nixos-anywhere/blob/main/docs/quickstart.md",
            },
        ],
        resources: vec![
            SetupProviderPlanResource {
                key: "server",
                kind: "hetzner-cloud-server",
                required: true,
                api: "GET /server_types, GET /locations, GET /images, POST /servers",
                detail: "Select server type, location, and bootstrap-capable base image at plan time, then create the server only after operator confirmation.",
            },
            SetupProviderPlanResource {
                key: "ssh_key",
                kind: "hetzner-cloud-ssh-key",
                required: true,
                api: "GET /ssh_keys",
                detail: "Resolve and attach an existing SSH public key before server creation; private key material stays outside provider state and Pharos job records.",
            },
            SetupProviderPlanResource {
                key: "firewall",
                kind: "hetzner-cloud-firewall",
                required: true,
                api: "GET /firewalls, POST /servers",
                detail: "Resolve a pre-reviewed firewall and attach it in the server create request; Pharos refuses to create an unprotected server when the firewall is missing.",
            },
            SetupProviderPlanResource {
                key: "volume",
                kind: "hetzner-cloud-volume",
                required: false,
                api: "GET /volumes, POST /volumes",
                detail: "Optional data volume; availability, size, attachment, and cost are verified at plan time before inclusion.",
            },
            SetupProviderPlanResource {
                key: "backup_or_snapshot",
                kind: "hetzner-cloud-backup-snapshot",
                required: false,
                api: "GET /pricing, POST /servers/{id}/actions/create_image",
                detail: "Optional provider backup or initial snapshot handoff; pricing and support are runtime checks, not hardcoded promises.",
            },
        ],
        steps: vec![
            SetupProviderPlanStep {
                key: "provider_resources",
                title: "Provider resources",
                detail: "Create the server with an existing SSH public key, reviewed firewall, and Pharos management labels through Hetzner Cloud API calls.",
                status: "planned",
            },
            SetupProviderPlanStep {
                key: "runtime_verify",
                title: "Runtime verification",
                detail: "Fetch server types, images, locations, and prices at plan time; do not hardcode price or availability promises.",
                status: "required",
            },
            SetupProviderPlanStep {
                key: "bootstrap",
                title: "NixOS bootstrap",
                detail: "Boot a runtime-verified Linux base with SSH access, then run nixos-anywhere from a Pharos/nixcfg flake profile.",
                status: "planned",
            },
            SetupProviderPlanStep {
                key: "beacon_handoff",
                title: "Beacon handoff",
                detail: "Install pharos-beacon using a token file or secret reference; raw tokens never appear in job progress, logs, or URLs.",
                status: "protected",
            },
            SetupProviderPlanStep {
                key: "observable_finish",
                title: "Observable finish",
                detail: "Wait for the first valid heartbeat, then mark backup enrollment and location source as complete or explicitly pending.",
                status: "waiting",
            },
        ],
        secret_boundary: vec![
            SetupProviderPlanSecretBoundary {
                key: "provider_api_token",
                source: "runtime secret reference",
                rule: "Use only for the provider executor call; never serialize into plan JSON, PPM notes, logs, progress messages, URLs, or OpenTofu state.",
            },
            SetupProviderPlanSecretBoundary {
                key: "ssh_private_key",
                source: "operator or agent runtime",
                rule: "Only public keys may be sent to Hetzner Cloud; private key material must stay in the runtime secret store.",
            },
            SetupProviderPlanSecretBoundary {
                key: "pharos_registration_and_beacon",
                source: "Pharos/Janus handoff",
                rule: "Registration and per-host beacon values are one-time or secret-store handoffs; job output may show refs and states only.",
            },
        ],
        handoffs: vec![
            SetupProviderPlanHandoff {
                key: "provider_executor",
                target: "Hetzner Cloud executor",
                detail: "Consumes this plan contract, validates required references before create, and persists safe resource identifiers plus cleanup guidance.",
            },
            SetupProviderPlanHandoff {
                key: "nixos_bootstrap",
                target: "nixos-anywhere",
                detail: "Runs against the freshly reachable server using a reviewed flake profile and generated hardware facts.",
            },
            SetupProviderPlanHandoff {
                key: "beacon_token",
                target: "Pharos/Janus",
                detail: "Installs pharos-beacon with a token file or managed secret ref, then waits for first heartbeat before live state.",
            },
            SetupProviderPlanHandoff {
                key: "backup_location",
                target: "PHAROS-83/86",
                detail: "Leaves backup enrollment and location source as explicit pending work when they are not completed during provisioning.",
            },
        ],
        runtime_checks: vec![
            "server_type availability",
            "location availability",
            "image/base OS availability",
            "current provider price",
            "SSH key and firewall compatibility",
            "backup/snapshot option availability",
        ],
    }
}

pub(super) fn manual_import_setup_plan(template: &str) -> SetupProviderPlan {
    let netcup = template == "netcup-manual-import";
    let oracle = template == "oracle-always-free-lab";
    let gcp = template == "gcp-free-tier-lab";
    let (strategy, approach, summary, docs, resources, steps, runtime_checks) = if netcup {
        (
            "netcup-manual-import",
            "Treat Netcup as an externally-created server first: buy/create and prepare the VPS or root server outside Pharos, then import it through existing-host onboarding.",
            "Use Netcup for the server, but keep ordering, cancellation, billing, image choice, rescue/ISO work, snapshots, and SSH preparation explicit operator steps before Pharos imports the host.",
            vec![
                SetupProviderPlanDoc {
                    label: "netcup server REST API",
                    url: "https://www.netcup.com/en/helpcenter/documentation/server/rest-api",
                },
                SetupProviderPlanDoc {
                    label: "nixos-anywhere quickstart",
                    url: "https://github.com/nix-community/nixos-anywhere/blob/main/docs/quickstart.md",
                },
            ],
            vec![
                SetupProviderPlanResource {
                    key: "netcup_server",
                    kind: "externally-created-netcup-server",
                    required: true,
                    api: "operator / Netcup SCP",
                    detail: "Create or select the Netcup VPS/root server outside Pharos; Pharos does not order, cancel, resize, or bill provider resources for this path.",
                },
                SetupProviderPlanResource {
                    key: "base_os_or_rescue",
                    kind: "provider-image-or-rescue",
                    required: true,
                    api: "operator / Netcup SCP",
                    detail: "Install a Debian/Ubuntu or NixOS-capable base, or prepare the rescue/ISO route before running Pharos preflight.",
                },
                SetupProviderPlanResource {
                    key: "ssh_access",
                    kind: "ssh-route",
                    required: true,
                    api: "preflight",
                    detail: "Verify SSH address, user, privilege level, and firewall/reachability before bootstrap; private keys remain outside Pharos records.",
                },
                SetupProviderPlanResource {
                    key: "backup_snapshot_expectation",
                    kind: "operator-decision",
                    required: true,
                    api: "runtime check",
                    detail: "Confirm current Netcup backup/snapshot options and pricing separately; Pharos records backup intent and later observes runtime backup evidence.",
                },
            ],
            vec![
                SetupProviderPlanStep {
                    key: "provider_resources",
                    title: "Netcup server prepared externally",
                    detail: "Buy/create or select the server in Netcup, verify current billing/pricing, choose the base image or rescue/ISO path, and keep provider credentials out of Pharos.",
                    status: "external",
                },
                SetupProviderPlanStep {
                    key: "bootstrap",
                    title: "Import through existing-host onboarding",
                    detail: "Run Pharos existing-host read-only preflight, then choose NixOS/nixos-anywhere, portable systemd beacon, or manual/deferred bootstrap.",
                    status: "handoff",
                },
                SetupProviderPlanStep {
                    key: "observable_finish",
                    title: "Observable finish",
                    detail: "Wait for first heartbeat, then record backup/snapshot expectation and location decisions explicitly.",
                    status: "waiting",
                },
            ],
            vec![
                "current Netcup product price and billing state",
                "SSH reachability and firewall access",
                "OS/bootstrap capability",
                "rescue or ISO path if reinstall is needed",
                "backup/snapshot availability and expectations",
                "Pharos endpoint reachability",
            ],
        )
    } else if oracle {
        (
            "oracle-always-free-lab-import",
            "Treat Oracle Always Free as an externally-created lab VM first: create the VM in Oracle Cloud, verify current free-tier eligibility, quota, and capacity, then import it through existing-host onboarding.",
            "Use Oracle Cloud only as a lab/demo host source. Pharos does not promise permanent zero cost, does not manage Oracle tenancy resources, and does not store Oracle credentials.",
            vec![
                SetupProviderPlanDoc {
                    label: "Oracle Always Free resources",
                    url: "https://docs.oracle.com/iaas/Content/FreeTier/freetier_topic-Always_Free_Resources.htm",
                },
                SetupProviderPlanDoc {
                    label: "nixos-anywhere quickstart",
                    url: "https://github.com/nix-community/nixos-anywhere/blob/main/docs/quickstart.md",
                },
            ],
            vec![
                SetupProviderPlanResource {
                    key: "oracle_vm",
                    kind: "externally-created-oracle-vm",
                    required: true,
                    api: "operator / Oracle Cloud Console",
                    detail: "Create or select an Oracle Cloud VM outside Pharos; verify Always Free eligibility, region capacity, shape availability, boot image, and current cost before import.",
                },
                SetupProviderPlanResource {
                    key: "network_access",
                    kind: "cloud-network-rule",
                    required: true,
                    api: "operator / Oracle Cloud Console",
                    detail: "Prepare ingress and egress rules for SSH and beacon reporting; Pharos records only the SSH route and runtime heartbeat.",
                },
                SetupProviderPlanResource {
                    key: "ssh_access",
                    kind: "ssh-route",
                    required: true,
                    api: "preflight",
                    detail: "Verify SSH user, host, privilege level, and bootstrap capability before install; private keys remain outside Pharos records.",
                },
                SetupProviderPlanResource {
                    key: "backup_expectation",
                    kind: "operator-decision",
                    required: true,
                    api: "runtime check",
                    detail: "Decide whether Oracle snapshots, external backup, or Pharos-observed backup jobs are expected; pricing and retention must be checked at setup time.",
                },
            ],
            vec![
                SetupProviderPlanStep {
                    key: "provider_resources",
                    title: "Oracle lab VM prepared externally",
                    detail: "Create the VM in Oracle Cloud, verify Always Free assumptions, region capacity, boot image, and billing before Pharos imports anything.",
                    status: "external",
                },
                SetupProviderPlanStep {
                    key: "bootstrap",
                    title: "Import through existing-host onboarding",
                    detail: "Run Pharos existing-host read-only preflight, then choose NixOS/nixos-anywhere, portable systemd beacon, or manual/deferred bootstrap.",
                    status: "handoff",
                },
                SetupProviderPlanStep {
                    key: "observable_finish",
                    title: "Observable finish",
                    detail: "Wait for first heartbeat, then record backup and location decisions explicitly.",
                    status: "waiting",
                },
            ],
            vec![
                "current Oracle Always Free eligibility",
                "region capacity and VM shape availability",
                "current billing and quota state",
                "SSH reachability and cloud firewall rules",
                "OS/bootstrap capability",
                "backup/snapshot expectation",
                "Pharos endpoint reachability",
            ],
        )
    } else if gcp {
        (
            "gcp-free-tier-lab-import",
            "Treat Google Cloud free tier as an externally-created lab VM first: create the VM in Google Cloud, verify current free-tier limits, region eligibility, and billing state, then import it through existing-host onboarding.",
            "Use Google Cloud only as a lab/demo host source. Pharos does not promise a permanently free VM, does not manage Google Cloud projects, and does not store Google Cloud credentials.",
            vec![
                SetupProviderPlanDoc {
                    label: "Google Cloud free program",
                    url: "https://cloud.google.com/free/docs/free-cloud-features",
                },
                SetupProviderPlanDoc {
                    label: "nixos-anywhere quickstart",
                    url: "https://github.com/nix-community/nixos-anywhere/blob/main/docs/quickstart.md",
                },
            ],
            vec![
                SetupProviderPlanResource {
                    key: "gcp_vm",
                    kind: "externally-created-gcp-vm",
                    required: true,
                    api: "operator / Google Cloud Console",
                    detail: "Create or select the Google Cloud VM outside Pharos; verify current free-tier eligibility, eligible region, machine type, boot image, and billing state before import.",
                },
                SetupProviderPlanResource {
                    key: "network_access",
                    kind: "cloud-firewall-rule",
                    required: true,
                    api: "operator / Google Cloud Console",
                    detail: "Prepare firewall and egress access for SSH and beacon reporting; Pharos stores no Google Cloud project credentials for this path.",
                },
                SetupProviderPlanResource {
                    key: "ssh_access",
                    kind: "ssh-route",
                    required: true,
                    api: "preflight",
                    detail: "Verify SSH user, host, privilege level, and bootstrap capability before install; private keys remain outside Pharos records.",
                },
                SetupProviderPlanResource {
                    key: "backup_expectation",
                    kind: "operator-decision",
                    required: true,
                    api: "runtime check",
                    detail: "Decide whether provider snapshots, external backup, or Pharos-observed backup jobs are expected; pricing and retention must be checked at setup time.",
                },
            ],
            vec![
                SetupProviderPlanStep {
                    key: "provider_resources",
                    title: "Google Cloud lab VM prepared externally",
                    detail: "Create the VM in Google Cloud, verify free-tier assumptions, eligible region, machine type, boot image, and billing before Pharos imports anything.",
                    status: "external",
                },
                SetupProviderPlanStep {
                    key: "bootstrap",
                    title: "Import through existing-host onboarding",
                    detail: "Run Pharos existing-host read-only preflight, then choose NixOS/nixos-anywhere, portable systemd beacon, or manual/deferred bootstrap.",
                    status: "handoff",
                },
                SetupProviderPlanStep {
                    key: "observable_finish",
                    title: "Observable finish",
                    detail: "Wait for first heartbeat, then record backup and location decisions explicitly.",
                    status: "waiting",
                },
            ],
            vec![
                "current Google Cloud free-tier limits",
                "eligible region and machine type",
                "current billing and quota state",
                "SSH reachability and cloud firewall rules",
                "OS/bootstrap capability",
                "backup/snapshot expectation",
                "Pharos endpoint reachability",
            ],
        )
    } else {
        (
            "operator-managed-import",
            "Keep provider creation external; Pharos plans the import/bootstrap checks and records only safe runtime observations.",
            "Keep provider creation outside Pharos, then import and bootstrap the already-created host.",
            vec![SetupProviderPlanDoc {
                label: "nixos-anywhere quickstart",
                url: "https://github.com/nix-community/nixos-anywhere/blob/main/docs/quickstart.md",
            }],
            vec![
                SetupProviderPlanResource {
                    key: "existing_server",
                    kind: "operator-owned-server",
                    required: true,
                    api: "external",
                    detail: "Operator supplies an already-created host and SSH route; Pharos does not create provider resources for this path.",
                },
                SetupProviderPlanResource {
                    key: "ssh_access",
                    kind: "ssh-route",
                    required: true,
                    api: "preflight",
                    detail: "Verify reachability and privilege level before bootstrap; private keys remain outside Pharos records.",
                },
            ],
            vec![
                SetupProviderPlanStep {
                    key: "provider_resources",
                    title: "Provider resources",
                    detail: "Operator creates or keeps the server with the external provider; Pharos stores no provider credentials for this path.",
                    status: "external",
                },
                SetupProviderPlanStep {
                    key: "bootstrap",
                    title: "Bootstrap",
                    detail: "Run existing-host preflight, then choose NixOS, portable beacon, or manual/deferred bootstrap.",
                    status: "handoff",
                },
                SetupProviderPlanStep {
                    key: "observable_finish",
                    title: "Observable finish",
                    detail: "Wait for first heartbeat and record backup/location decisions explicitly.",
                    status: "waiting",
                },
            ],
            vec![
                "SSH reachability",
                "OS/bootstrap capability",
                "Pharos endpoint reachability",
            ],
        )
    };

    SetupProviderPlan {
        schema: "inspr.pharos.setup-provider-plan.v1",
        version: 1,
        provider: "manual-import",
        template: if netcup {
            "netcup-manual-import"
        } else if oracle {
            "oracle-always-free-lab"
        } else if gcp {
            "gcp-free-tier-lab"
        } else {
            "manual-import"
        },
        strategy,
        approach,
        summary,
        docs,
        resources,
        steps,
        secret_boundary: vec![
            SetupProviderPlanSecretBoundary {
                key: "ssh_private_key",
                source: "operator runtime",
                rule: "Use only for preflight/bootstrap; never serialize private key material into Pharos job state.",
            },
            SetupProviderPlanSecretBoundary {
                key: "pharos_registration_and_beacon",
                source: "Pharos/Janus handoff",
                rule: "Registration and beacon values stay in runtime secret handling; UI and progress text show states only.",
            },
        ],
        handoffs: vec![
            SetupProviderPlanHandoff {
                key: "existing_host_preflight",
                target: "PHAROS-84/85",
                detail: "Chooses SSH/bootstrap method and validates the host before installing or configuring the beacon.",
            },
            SetupProviderPlanHandoff {
                key: "backup_location",
                target: "PHAROS-86",
                detail: "Records backup and location setup decisions after the imported host reports.",
            },
        ],
        runtime_checks,
    }
}

pub(super) fn provisioning_jobs_path(host_store_path: Option<&Path>) -> Option<PathBuf> {
    if let Ok(path) = std::env::var("PHAROS_PROVISIONING_JOBS_DB") {
        let path = path.trim();
        if !path.is_empty() {
            return Some(PathBuf::from(path));
        }
    }
    host_store_path.map(derived_provisioning_jobs_path)
}

pub(super) fn derived_provisioning_jobs_path(host_store_path: &Path) -> PathBuf {
    let file_name = host_store_path
        .file_name()
        .and_then(|name| name.to_str())
        .filter(|name| !name.trim().is_empty())
        .unwrap_or("pharos.json");
    host_store_path.with_file_name(format!("{file_name}.provisioning-jobs.json"))
}

#[derive(Clone, Debug, Deserialize)]
pub(super) struct SetupProviderPlanQuery {
    provider: String,
    template: String,
}

pub(super) fn hetzner_setup_defaults(state: &AppState, now: i64) -> Option<serde_json::Value> {
    let runtime = effective_hetzner_runtime(
        &state.provider_runtime.hetzner_cloud,
        &state.provider_connections,
    );
    let catalog = state
        .provider_connections
        .catalog_if_fresh(now, runtime.evidence_ttl_secs)?;
    let location = runtime
        .default_location
        .as_deref()
        .filter(|location| catalog.supports_location(location))
        .or_else(|| {
            catalog
                .locations
                .iter()
                .map(|location| location.name.as_str())
                .find(|location| catalog.supports_location(location))
        })?;
    let server_type = catalog.recommended_plan(location)?.name.as_str();
    Some(json!({
        "location": location,
        "server_type": server_type,
        "ssh_key_ref": runtime.default_ssh_key_ref,
    }))
}

pub(super) fn paid_setup_runtime_readiness(state: &AppState, now: i64) -> serde_json::Value {
    let readiness = hetzner_runtime_readiness(
        &state.provider_runtime.hetzner_cloud,
        &state.provider_connections,
        now,
    );
    let mut value = serde_json::to_value(readiness).unwrap_or_else(|_| json!({}));
    if let Some(object) = value.as_object_mut() {
        object.insert(
            "durable_job_store_ready".to_string(),
            json!(state.provisioning_jobs.durable_ready()),
        );
        object.insert(
            "paid_project_available".to_string(),
            json!(!state.provisioning_jobs.paid_project_blocked(None)),
        );
        object.insert(
            "managed_executor_ready".to_string(),
            json!(
                state.provider_runtime.managed_provisioning.ready()
                    && state.beacon_auth.report_token_mode == BeaconTokenMode::Janus
            ),
        );
    }
    value
}

pub(super) async fn setup_provider_plan_json(
    State(state): State<AppState>,
    headers: HeaderMap,
    Query(query): Query<SetupProviderPlanQuery>,
) -> impl IntoResponse {
    if !access_for_headers(&state.auth, &headers).can_agora() {
        return (
            StatusCode::FORBIDDEN,
            no_store_headers(),
            Json(json!({ "error": "Agora access is not granted for this account" })),
        );
    }
    let now = now_unix();
    match setup_provider_plan(&query.provider, &query.template) {
        Ok(plan) => (
            StatusCode::OK,
            no_store_headers(),
            Json(json!({
                "plan": plan,
                "runtime": if query.provider == "hetzner-cloud" {
                    Some(paid_setup_runtime_readiness(&state, now))
                } else {
                    None
                },
                "catalog": if query.provider == "hetzner-cloud" {
                    state.provider_connections.catalog_if_fresh(
                        now,
                        state.provider_runtime.hetzner_cloud.evidence_ttl_secs,
                    )
                } else {
                    None
                },
                "defaults": if query.provider == "hetzner-cloud" {
                    hetzner_setup_defaults(&state, now)
                } else {
                    None
                },
            })),
        ),
        Err(error) => (
            StatusCode::BAD_REQUEST,
            no_store_headers(),
            Json(json!({ "error": error.to_string() })),
        ),
    }
}

pub(super) async fn create_provisioning_job(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(request): Json<ProvisioningJobStartRequest>,
) -> impl IntoResponse {
    if request.provider == "hetzner-cloud" && request.apply {
        return (
            StatusCode::BAD_REQUEST,
            no_store_headers(),
            Json(json!({
                "error": "Direct apply is not allowed. Persist a reviewed plan, authorize that exact plan, then create it in a separate request."
            })),
        );
    }
    if !access_for_headers(&state.auth, &headers).can_agora() {
        return (
            StatusCode::FORBIDDEN,
            no_store_headers(),
            Json(json!({ "error": "Agora access is not granted for this account" })),
        );
    }
    let mut provider_runtime = state.provider_runtime.clone();
    if request.provider == "hetzner-cloud" {
        let _serialized_paid_review = state.paid_create_lock.lock().await;
        if let Err((status, message)) = paid_operator(&state, &headers) {
            return (
                status,
                no_store_headers(),
                Json(json!({ "error": message })),
            );
        }
        if !state.provisioning_jobs.durable_ready() {
            return (
                StatusCode::SERVICE_UNAVAILABLE,
                no_store_headers(),
                Json(json!({
                    "error": "Paid provider actions require a valid durable provisioning-job store. Configure PHAROS_DB or PHAROS_PROVISIONING_JOBS_DB and restart Pharos."
                })),
            );
        }
        if !state.provider_runtime.managed_provisioning.ready()
            || state.beacon_auth.report_token_mode != BeaconTokenMode::Janus
        {
            return (
                StatusCode::SERVICE_UNAVAILABLE,
                no_store_headers(),
                Json(json!({
                    "error": "Managed server creation is not ready on this Pharos installation. No paid action was started."
                })),
            );
        }
        let Some(host_name) = request
            .host_name
            .as_deref()
            .map(str::trim)
            .filter(|host| valid_action_host_name(host))
        else {
            return (
                StatusCode::BAD_REQUEST,
                no_store_headers(),
                Json(json!({ "error": "Choose a valid server name." })),
            );
        };
        if state.store.get(host_name).is_some()
            || host_is_declared(&state, host_name)
            || state.retired_hosts.is_retired(host_name)
            || state.provisioning_jobs.list().iter().any(|job| {
                job.host_name.as_deref() == Some(host_name)
                    && job.terminal_outcome != Some(ProvisioningTerminalOutcome::RolledBack)
            })
        {
            return (
                StatusCode::CONFLICT,
                no_store_headers(),
                Json(json!({
                    "error": "That server name is already owned by runtime, declared, retired, or provisioning state. No paid action was started."
                })),
            );
        }
        match state.beacon_auth.janus_manages_host(host_name) {
            Ok(false) => {}
            Ok(true) => {
                return (
                    StatusCode::CONFLICT,
                    no_store_headers(),
                    Json(json!({
                        "error": "That server name already has a Janus-managed identity. No paid action was started."
                    })),
                );
            }
            Err(_) => {
                return (
                    StatusCode::SERVICE_UNAVAILABLE,
                    no_store_headers(),
                    Json(json!({
                        "error": "Janus identity ownership could not be verified. No paid action was started."
                    })),
                );
            }
        }
        let managed_credential_ref = state
            .provider_runtime
            .managed_provisioning
            .credential_ref_for(host_name)
            .expect("managed provisioning readiness requires a Janus scope");
        if state.provisioning_jobs.paid_project_blocked(None) {
            return (
                StatusCode::CONFLICT,
                no_store_headers(),
                Json(json!({
                    "error": "Another paid server attempt or tracked server still owns the project gate. Resolve it before starting a new paid review."
                })),
            );
        }
        let now = now_unix();
        if let Err(error) = run_hetzner_connection_test_for(
            &state,
            now,
            request.ssh_key_ref.as_deref(),
            request.location.as_deref(),
        )
        .await
        {
            tracing::error!(error = %error, "paid review provider evidence could not be durably recorded");
            return (
                StatusCode::SERVICE_UNAVAILABLE,
                no_store_headers(),
                Json(
                    json!({ "error": "Provider evidence could not be durably recorded. No paid action was started." }),
                ),
            );
        }
        match guarded_hetzner_runtime(&state, &request, now) {
            Ok(runtime) => provider_runtime.hetzner_cloud = runtime,
            Err((status, message)) => {
                return (
                    status,
                    no_store_headers(),
                    Json(json!({ "error": message })),
                );
            }
        }
        let review_operation = match HetznerOperationContext::resolve(
            provider_runtime.hetzner_cloud.clone(),
        ) {
            Ok(operation) => operation,
            Err(_) => {
                return (
                    StatusCode::SERVICE_UNAVAILABLE,
                    no_store_headers(),
                    Json(json!({
                        "error": "The secure provider credential could not be pinned for this review. No provider resource was created."
                    })),
                );
            }
        };
        if verify_hetzner_image(
            &review_operation,
            request.image.as_deref().unwrap_or_default(),
        )
        .await
        .is_err()
        {
            return (
                StatusCode::CONFLICT,
                no_store_headers(),
                Json(json!({
                    "error": "The selected Hetzner Cloud image is not currently available. No provider resource was created."
                })),
            );
        }
        let active_servers = match fetch_hetzner_servers(&review_operation).await {
            Ok(servers) => servers,
            Err(_) => {
                return (
                    StatusCode::SERVICE_UNAVAILABLE,
                    no_store_headers(),
                    Json(json!({
                        "error": "Current Hetzner Cloud server inventory could not be verified. No provider resource was created."
                    })),
                );
            }
        };
        if !active_servers.is_empty() {
            return (
                StatusCode::CONFLICT,
                no_store_headers(),
                Json(json!({
                    "error": "This Hetzner Cloud project already has an active server; the Phase 1 maximum is one. No provider resource was created."
                })),
            );
        }
        let job = match state
            .provisioning_jobs
            .start(&request, now, &provider_runtime)
        {
            Ok(job) => job,
            Err(error) => {
                return (
                    StatusCode::BAD_REQUEST,
                    no_store_headers(),
                    Json(json!({ "error": error.to_string() })),
                );
            }
        };
        let reviewed_plan = match build_reviewed_paid_plan(
            &job,
            &request,
            &review_operation,
            &state.provider_connections,
            state
                .provider_runtime
                .managed_provisioning
                .owner_host
                .as_deref()
                .expect("managed provisioning readiness requires an owner"),
            &managed_credential_ref,
            now,
        ) {
            Ok(plan) => plan,
            Err((status, message)) => {
                return (
                    status,
                    no_store_headers(),
                    Json(json!({ "error": message })),
                );
            }
        };
        return match state
            .provisioning_jobs
            .attach_paid_review(&job.id, reviewed_plan, now)
        {
            Ok(job) => (
                StatusCode::CREATED,
                no_store_headers(),
                Json(json!({ "job": job })),
            ),
            Err(_) => (
                StatusCode::INTERNAL_SERVER_ERROR,
                no_store_headers(),
                Json(json!({
                    "error": "The reviewed plan could not be durably stored. No provider resource was created."
                })),
            ),
        };
    }
    match state
        .provisioning_jobs
        .start(&request, now_unix(), &provider_runtime)
    {
        Ok(job) => {
            let job = if should_run_existing_host_executor(&state, &request, &job) {
                execute_existing_host_setup_job(&state, &request, job).await
            } else {
                job
            };
            (
                StatusCode::CREATED,
                no_store_headers(),
                Json(json!({ "job": job })),
            )
        }
        Err(error) => (
            StatusCode::BAD_REQUEST,
            no_store_headers(),
            Json(json!({ "error": error.to_string() })),
        ),
    }
}

pub(super) fn paid_operator(
    state: &AppState,
    headers: &HeaderMap,
) -> Result<(String, String), (StatusCode, &'static str)> {
    if !action_request_header(headers) {
        return Err((
            StatusCode::FORBIDDEN,
            "A fresh attended action confirmation is required.",
        ));
    }
    if !access_for_headers(&state.auth, headers).can_manage_fleet() {
        return Err((
            StatusCode::FORBIDDEN,
            "Fleet management access is required for paid provider actions.",
        ));
    }
    let Some(auth) = state.auth.as_ref() else {
        return Err((
            StatusCode::SERVICE_UNAVAILABLE,
            "Paid provider actions require configured OIDC authentication.",
        ));
    };
    let Some(user) = auth.current_user(headers) else {
        return Err((
            StatusCode::UNAUTHORIZED,
            "Sign in again before reviewing or authorizing paid provider work.",
        ));
    };
    if !safe_paid_display_text(&user.display_name, 200) {
        return Err((
            StatusCode::FORBIDDEN,
            "The authenticated operator identity is not safe to record.",
        ));
    }
    Ok((user.operator_ref, user.display_name))
}

pub(super) fn build_reviewed_paid_plan(
    job: &ProvisioningJob,
    request: &ProvisioningJobStartRequest,
    operation: &HetznerOperationContext,
    connections: &ProviderConnectionStore,
    managed_executor_owner: &str,
    managed_credential_ref: &str,
    now: i64,
) -> Result<ProvisioningReviewedPaidPlan, (StatusCode, &'static str)> {
    let runtime = &operation.runtime;
    let catalog = connections
        .catalog_if_fresh(now, runtime.evidence_ttl_secs)
        .ok_or((
            StatusCode::CONFLICT,
            "Current Hetzner Cloud catalog evidence is not available.",
        ))?;
    let location = request
        .location
        .as_deref()
        .ok_or((StatusCode::BAD_REQUEST, "Choose a server location."))?;
    let server_type = request
        .server_type
        .as_deref()
        .ok_or((StatusCode::BAD_REQUEST, "Choose a current server plan."))?;
    let selection = catalog.exact_selection(location, server_type).ok_or((
        StatusCode::CONFLICT,
        "That exact server plan is no longer available at the reviewed price.",
    ))?;
    let project = runtime.project_label.as_deref().ok_or((
        StatusCode::SERVICE_UNAVAILABLE,
        "Set the safe Hetzner Cloud project label before paid plan review.",
    ))?;
    let ssh_key_ref = request
        .ssh_key_ref
        .as_deref()
        .or(runtime.default_ssh_key_ref.as_deref())
        .ok_or((StatusCode::CONFLICT, "Choose a current SSH public key."))?;
    let firewall_ref = runtime
        .firewall_ref
        .as_deref()
        .ok_or((StatusCode::CONFLICT, "Choose a current provider firewall."))?;
    let image = request
        .image
        .as_deref()
        .ok_or((StatusCode::BAD_REQUEST, "Choose the reviewed server image."))?;
    let required_labels = paid_required_labels(&job.id, project);
    let server_name = job.host_name.as_deref().ok_or((
        StatusCode::BAD_REQUEST,
        "Choose the exact provider server name.",
    ))?;
    let mut reviewed = ProvisioningReviewedPaidPlan {
        provider_project: project.to_string(),
        credential_binding_sha256: operation.credential_binding_sha256.clone(),
        server_name: server_name.to_string(),
        location: selection.location,
        location_label: selection.location_label,
        server_type: selection.server_type,
        server_type_label: format!(
            "{} · {}",
            selection.server_type_label, selection.hardware_summary
        ),
        image: image.to_string(),
        price_currency: selection.currency,
        price_hourly_gross: selection.hourly_gross.clone(),
        price_monthly_gross: selection.monthly_gross.clone(),
        max_hourly_gross: selection.hourly_gross,
        max_monthly_gross: selection.monthly_gross,
        observed_active_servers: 0,
        max_active_servers: 1,
        catalog_refreshed_at: selection.catalog_refreshed_at,
        expires_at: now.saturating_add(runtime.approval_ttl_secs),
        ssh_key_ref: ssh_key_ref.to_string(),
        firewall_ref: firewall_ref.to_string(),
        managed_executor_owner: Some(managed_executor_owner.to_string()),
        managed_credential_ref: Some(managed_credential_ref.to_string()),
        required_labels,
        allowed_operations: vec!["create-server".to_string(), "delete-server".to_string()],
        cleanup_policy: "No silent retry or automatic deletion. If setup fails, Pharos keeps the tracked server visible and requires separately confirmed cleanup.".to_string(),
        plan_sha256: "0".repeat(64),
    };
    reviewed.plan_sha256 = reviewed_paid_plan_digest(&reviewed);
    reviewed.validate_contract().map_err(|_| {
        (
            StatusCode::BAD_REQUEST,
            "The paid plan contract is invalid.",
        )
    })?;
    Ok(reviewed)
}

pub(super) fn paid_required_labels(job_id: &str, project: &str) -> BTreeMap<String, String> {
    let owner_digest = hex(&Sha256::digest(project.as_bytes()));
    BTreeMap::from([
        ("managed-by".to_string(), "pharos".to_string()),
        ("pharos-setup".to_string(), "tracked-job".to_string()),
        ("pharos-owner".to_string(), owner_digest[..16].to_string()),
        ("pharos-job".to_string(), job_id.to_string()),
        ("pharos-attempt".to_string(), format!("{job_id}-1")),
    ])
}

pub(super) fn paid_store_error_response(
    error: ProvisioningPaidStoreError,
) -> (StatusCode, &'static str) {
    match error {
        ProvisioningPaidStoreError::NotFound => {
            (StatusCode::NOT_FOUND, "The reviewed plan was not found.")
        }
        ProvisioningPaidStoreError::PlanMismatch => (
            StatusCode::CONFLICT,
            "The request does not match the exact persisted plan. Review current details again.",
        ),
        ProvisioningPaidStoreError::Expired => (
            StatusCode::CONFLICT,
            "This paid authorization has expired. Review current details again.",
        ),
        ProvisioningPaidStoreError::OperatorMismatch => (
            StatusCode::FORBIDDEN,
            "The authenticated operator does not match this paid authorization.",
        ),
        ProvisioningPaidStoreError::ProjectBusy => (
            StatusCode::CONFLICT,
            "Another paid attempt or tracked server still owns the provider project gate.",
        ),
        ProvisioningPaidStoreError::InvalidState => (
            StatusCode::CONFLICT,
            "This paid setup is not in the required state for that action.",
        ),
        ProvisioningPaidStoreError::ContractFailed
        | ProvisioningPaidStoreError::PersistenceFailed => (
            StatusCode::INTERNAL_SERVER_ERROR,
            "The paid action could not be durably recorded. No new provider request was sent.",
        ),
    }
}

pub(super) fn validate_paid_job_binding(
    job: &ProvisioningJob,
    plan_sha256: &str,
    operator_ref: &str,
) -> Result<(), ProvisioningPaidStoreError> {
    let plan = job
        .reviewed_plan
        .as_ref()
        .ok_or(ProvisioningPaidStoreError::InvalidState)?;
    let authorization = job
        .paid_authorization
        .as_ref()
        .ok_or(ProvisioningPaidStoreError::InvalidState)?;
    if plan.plan_sha256 != plan_sha256
        || authorization.plan_sha256 != plan_sha256
        || reviewed_paid_plan_digest(plan) != plan_sha256
    {
        return Err(ProvisioningPaidStoreError::PlanMismatch);
    }
    let recovery_only = job.paid_execution.as_ref().is_some_and(|execution| {
        matches!(
            execution.state.as_str(),
            "request-started" | "uncertain" | "created" | "reconciled" | "failed-closed"
        )
    });
    if !recovery_only && authorization.operator_ref != operator_ref {
        return Err(ProvisioningPaidStoreError::OperatorMismatch);
    }
    Ok(())
}

pub(super) async fn revalidate_reviewed_paid_plan(
    state: &AppState,
    job: &ProvisioningJob,
    now: i64,
) -> Result<(HetznerOperationContext, Vec<HetznerListedServer>), (StatusCode, &'static str)> {
    let reviewed = job.reviewed_plan.as_ref().ok_or((
        StatusCode::CONFLICT,
        "The immutable paid plan is missing. Review current details again.",
    ))?;
    if reviewed.validate_contract().is_err()
        || reviewed_paid_plan_digest(reviewed) != reviewed.plan_sha256
    {
        return Err((
            StatusCode::CONFLICT,
            "The persisted paid plan no longer validates. Review current details again.",
        ));
    }
    if reviewed
        .managed_executor_owner
        .as_deref()
        .is_none_or(|owner| !state.provider_runtime.managed_provisioning.is_owner(owner))
        || state.beacon_auth.report_token_mode != BeaconTokenMode::Janus
    {
        return Err((
            StatusCode::SERVICE_UNAVAILABLE,
            "The reviewed managed provisioning executor is not ready. No provider resource was created.",
        ));
    }
    if now >= reviewed.expires_at {
        return Err((
            StatusCode::CONFLICT,
            "This paid plan has expired. Review current details again.",
        ));
    }

    run_hetzner_connection_test_for(
        state,
        now,
        Some(&reviewed.ssh_key_ref),
        Some(&reviewed.location),
    )
    .await
    .map_err(|error| {
        tracing::error!(error = %error, "paid plan revalidation evidence could not be durably recorded");
        (
            StatusCode::SERVICE_UNAVAILABLE,
            "Provider evidence could not be durably recorded. No paid action was started.",
        )
    })?;
    let runtime = effective_hetzner_runtime(
        &state.provider_runtime.hetzner_cloud,
        &state.provider_connections,
    );
    if !runtime.credential_boundary_ready()
        || !runtime.execute_enabled
        || !state
            .provider_connections
            .ready(now, runtime.evidence_ttl_secs)
    {
        return Err((
            StatusCode::SERVICE_UNAVAILABLE,
            "The live Hetzner Cloud credential and execution gate are not ready. No provider resource was created.",
        ));
    }
    if runtime.project_label.as_deref() != Some(reviewed.provider_project.as_str()) {
        return Err((
            StatusCode::CONFLICT,
            "The configured provider project label changed. Review current details again.",
        ));
    }
    let catalog = state
        .provider_connections
        .catalog_if_fresh(now, runtime.evidence_ttl_secs)
        .ok_or((
            StatusCode::CONFLICT,
            "A fresh live provider catalog is not available. Review current details again.",
        ))?;
    let selection = catalog
        .exact_selection(&reviewed.location, &reviewed.server_type)
        .ok_or((
            StatusCode::CONFLICT,
            "The reviewed region and server type are no longer available. Review current details again.",
        ))?;
    let current_server_type_label = format!(
        "{} · {}",
        selection.server_type_label, selection.hardware_summary
    );
    if selection.location != reviewed.location
        || selection.location_label != reviewed.location_label
        || selection.server_type != reviewed.server_type
        || current_server_type_label != reviewed.server_type_label
        || selection.currency != reviewed.price_currency
        || selection.hourly_gross != reviewed.price_hourly_gross
        || selection.monthly_gross != reviewed.price_monthly_gross
        || compare_gross_prices(&selection.hourly_gross, &reviewed.max_hourly_gross)
            .is_none_or(|ordering| ordering == std::cmp::Ordering::Greater)
        || compare_gross_prices(&selection.monthly_gross, &reviewed.max_monthly_gross)
            .is_none_or(|ordering| ordering == std::cmp::Ordering::Greater)
    {
        return Err((
            StatusCode::CONFLICT,
            "Provider availability, hardware, currency, or exact gross price changed. Review current details again.",
        ));
    }
    if !catalog
        .ssh_keys
        .iter()
        .any(|value| value == &reviewed.ssh_key_ref)
        || !catalog
            .firewalls
            .iter()
            .any(|value| value == &reviewed.firewall_ref)
        || runtime.firewall_ref.as_deref() != Some(reviewed.firewall_ref.as_str())
    {
        return Err((
            StatusCode::CONFLICT,
            "The reviewed SSH key or firewall changed. Review current details again.",
        ));
    }
    if reviewed.required_labels != paid_required_labels(&job.id, reviewed.provider_project.as_str())
        || reviewed.allowed_operations
            != vec!["create-server".to_string(), "delete-server".to_string()]
    {
        return Err((
            StatusCode::CONFLICT,
            "The required ownership policy changed. Review current details again.",
        ));
    }
    let operation = HetznerOperationContext::resolve(runtime).map_err(|_| {
        (
            StatusCode::SERVICE_UNAVAILABLE,
            "The secure provider credential could not be pinned. No provider resource was created.",
        )
    })?;
    if !operation.matches_reviewed_plan(reviewed) {
        return Err((
            StatusCode::CONFLICT,
            "The provider credential/project binding changed. Review current details again.",
        ));
    }
    verify_hetzner_image(&operation, &reviewed.image)
        .await
        .map_err(|_| {
            (
                StatusCode::CONFLICT,
                "The reviewed provider image is no longer available. Review current details again.",
            )
        })?;
    let servers = fetch_hetzner_servers(&operation).await.map_err(|_| {
        (
            StatusCode::SERVICE_UNAVAILABLE,
            "Current provider server inventory could not be verified. No provider resource was created.",
        )
    })?;
    Ok((operation, servers))
}

pub(super) async fn paid_reconciliation_inventory(
    state: &AppState,
    reviewed: &ProvisioningReviewedPaidPlan,
) -> Result<Vec<HetznerListedServer>, (StatusCode, &'static str)> {
    let runtime = effective_hetzner_runtime(
        &state.provider_runtime.hetzner_cloud,
        &state.provider_connections,
    );
    if !runtime.credential_boundary_ready()
        || runtime.project_label.as_deref() != Some(reviewed.provider_project.as_str())
    {
        return Err((
            StatusCode::SERVICE_UNAVAILABLE,
            "The secure provider credential is unavailable for reconciliation. Pharos will not replay the paid request.",
        ));
    }
    let operation = HetznerOperationContext::resolve(runtime).map_err(|_| {
        (
            StatusCode::SERVICE_UNAVAILABLE,
            "The secure provider credential is unavailable for reconciliation. Pharos will not replay the paid request.",
        )
    })?;
    fetch_hetzner_servers(&operation).await.map_err(|_| {
        (
            StatusCode::SERVICE_UNAVAILABLE,
            "Provider inventory could not be read for reconciliation. Pharos will not replay the paid request.",
        )
    })
}

pub(super) async fn confirm_paid_provisioning_job(
    State(state): State<AppState>,
    headers: HeaderMap,
    AxumPath(id): AxumPath<String>,
    Json(request): Json<ProvisioningPaidConfirmRequest>,
) -> impl IntoResponse {
    let (operator_ref, operator_label) = match paid_operator(&state, &headers) {
        Ok(operator) => operator,
        Err((status, message)) => {
            return (
                status,
                no_store_headers(),
                Json(json!({ "error": message })),
            );
        }
    };
    if !state.provisioning_jobs.durable_ready() {
        return (
            StatusCode::SERVICE_UNAVAILABLE,
            no_store_headers(),
            Json(
                json!({ "error": "The durable provisioning-job store is unavailable; no paid action was taken." }),
            ),
        );
    }
    if state.provisioning_jobs.paid_project_blocked(Some(&id)) {
        return (
            StatusCode::CONFLICT,
            no_store_headers(),
            Json(
                json!({ "error": "Another paid attempt or tracked server still owns the provider project gate." }),
            ),
        );
    }
    if !request.attended {
        return (
            StatusCode::BAD_REQUEST,
            no_store_headers(),
            Json(json!({ "error": "Attended confirmation is required." })),
        );
    }
    let Some(job) = state.provisioning_jobs.get(&id) else {
        return (
            StatusCode::NOT_FOUND,
            no_store_headers(),
            Json(json!({ "error": "The reviewed plan was not found." })),
        );
    };
    if job.reviewed_plan.as_ref().is_none_or(|plan| {
        plan.plan_sha256 != request.plan_sha256
            || reviewed_paid_plan_digest(plan) != request.plan_sha256
    }) {
        return (
            StatusCode::CONFLICT,
            no_store_headers(),
            Json(json!({
                "error": "The confirmation does not match the exact persisted plan. Review current details again."
            })),
        );
    }
    let now = now_unix();
    let (_, servers) = match revalidate_reviewed_paid_plan(&state, &job, now).await {
        Ok(result) => result,
        Err((status, message)) => {
            return (
                status,
                no_store_headers(),
                Json(json!({ "error": message })),
            );
        }
    };
    if !servers.is_empty() {
        return (
            StatusCode::CONFLICT,
            no_store_headers(),
            Json(json!({
                "error": "The provider project already has an active server; the reviewed active-count limit no longer holds. Review current details again."
            })),
        );
    }
    match state.provisioning_jobs.confirm_paid_review(
        &id,
        &request.plan_sha256,
        &operator_ref,
        &operator_label,
        now,
    ) {
        Ok(job) => (
            StatusCode::OK,
            no_store_headers(),
            Json(json!({ "job": job })),
        ),
        Err(error) => {
            let (status, message) = paid_store_error_response(error);
            (
                status,
                no_store_headers(),
                Json(json!({ "error": message })),
            )
        }
    }
}

pub(super) fn reviewed_hetzner_provider_resource(
    plan: &ProvisioningReviewedPaidPlan,
    server: &HetznerCreatedServer,
) -> ProvisioningProviderResource {
    let ssh_address = server.ssh_address();
    ProvisioningProviderResource {
        provider: "hetzner-cloud".to_string(),
        kind: "server".to_string(),
        provider_id: server.id.to_string(),
        name: plan.server_name.clone(),
        state: if ssh_address.is_some() {
            "created".to_string()
        } else {
            "created-address-pending".to_string()
        },
        location: Some(plan.location.clone()),
        ssh: ssh_address.map(|address| SshAccessIntent {
            route: SshRoute::Direct,
            user: Some("root".to_string()),
            host: Some(address),
            port: Some(22),
        }),
    }
}

pub(super) async fn create_paid_provisioning_job(
    State(state): State<AppState>,
    headers: HeaderMap,
    AxumPath(id): AxumPath<String>,
    Json(request): Json<ProvisioningPaidCreateRequest>,
) -> impl IntoResponse {
    let (operator_ref, _) = match paid_operator(&state, &headers) {
        Ok(operator) => operator,
        Err((status, message)) => {
            return (
                status,
                no_store_headers(),
                Json(json!({ "error": message })),
            );
        }
    };
    let _serialized_create = state.paid_create_lock.lock().await;
    if !state.provisioning_jobs.durable_ready() {
        return (
            StatusCode::SERVICE_UNAVAILABLE,
            no_store_headers(),
            Json(
                json!({ "error": "The durable provisioning-job store is unavailable; no paid provider request was sent." }),
            ),
        );
    }
    if state.provisioning_jobs.paid_project_blocked(Some(&id)) {
        return (
            StatusCode::CONFLICT,
            no_store_headers(),
            Json(
                json!({ "error": "Another paid attempt or tracked server still owns the provider project gate." }),
            ),
        );
    }
    let Some(initial_job) = state.provisioning_jobs.get(&id) else {
        return (
            StatusCode::NOT_FOUND,
            no_store_headers(),
            Json(json!({ "error": "The reviewed plan was not found." })),
        );
    };
    if let Err(error) = validate_paid_job_binding(&initial_job, &request.plan_sha256, &operator_ref)
    {
        let (status, message) = paid_store_error_response(error);
        return (
            status,
            no_store_headers(),
            Json(json!({ "error": message })),
        );
    }
    if initial_job
        .paid_execution
        .as_ref()
        .is_some_and(|execution| matches!(execution.state.as_str(), "created" | "reconciled"))
    {
        return (
            StatusCode::OK,
            no_store_headers(),
            Json(json!({ "job": initial_job, "idempotent": true })),
        );
    }
    let reviewed = initial_job
        .reviewed_plan
        .as_ref()
        .expect("paid binding requires reviewed plan")
        .clone();
    if initial_job
        .paid_execution
        .as_ref()
        .is_some_and(|execution| {
            matches!(execution.state.as_str(), "request-started" | "uncertain")
        })
    {
        let servers = match paid_reconciliation_inventory(&state, &reviewed).await {
            Ok(servers) => servers,
            Err((status, message)) => {
                return (
                    status,
                    no_store_headers(),
                    Json(json!({ "error": message })),
                );
            }
        };
        let matches = servers
            .iter()
            .filter(|server| server.matches_reviewed_plan(&reviewed))
            .cloned()
            .collect::<Vec<_>>();
        if matches.len() == 1 {
            let server = matches.into_iter().next().expect("one reconciled server");
            let resource = reviewed_hetzner_provider_resource(&reviewed, &server.into_created());
            let handoff = hetzner_bootstrap_handoff(&resource);
            return match state.provisioning_jobs.complete_paid_create(
                &id,
                &request.plan_sha256,
                resource,
                handoff,
                true,
                now_unix(),
            ) {
                Ok(job) => (
                    StatusCode::OK,
                    no_store_headers(),
                    Json(json!({ "job": job, "idempotent": true })),
                ),
                Err(error) => {
                    let (status, message) = paid_store_error_response(error);
                    (
                        status,
                        no_store_headers(),
                        Json(json!({ "error": message })),
                    )
                }
            };
        }
        let message = if matches.is_empty() {
            "The earlier provider create result is uncertain and no server matching the exact ownership and reviewed facts was found. Pharos will not replay the paid request; inspect the provider project and check this same attempt again before any new review."
        } else {
            "Multiple servers match the exact paid-attempt ownership and reviewed facts. Pharos will not create or choose between them; manual provider review is required."
        };
        let job = state
            .provisioning_jobs
            .fail_paid_execution(
                &id,
                &request.plan_sha256,
                true,
                message.to_string(),
                now_unix(),
            )
            .unwrap_or(initial_job);
        return (
            StatusCode::CONFLICT,
            no_store_headers(),
            Json(json!({ "error": message, "job": job })),
        );
    }
    let now = now_unix();
    let authorization = initial_job
        .paid_authorization
        .as_ref()
        .expect("paid binding requires authorization");
    if now >= authorization.expires_at {
        if initial_job
            .paid_execution
            .as_ref()
            .is_some_and(|execution| execution.state == "claimed")
        {
            let message = "This paid authorization expired before the provider request started. The durable attempt was closed without creating a server; review current details again.";
            let job = state
                .provisioning_jobs
                .fail_paid_execution(&id, &request.plan_sha256, false, message.to_string(), now)
                .unwrap_or(initial_job);
            return (
                StatusCode::CONFLICT,
                no_store_headers(),
                Json(json!({ "error": message, "job": job })),
            );
        }
        return (
            StatusCode::CONFLICT,
            no_store_headers(),
            Json(
                json!({ "error": "This paid authorization expired. Review current details again." }),
            ),
        );
    }
    let (initial_runtime, _) = match revalidate_reviewed_paid_plan(&state, &initial_job, now).await
    {
        Ok(result) => result,
        Err((status, message)) => {
            return (
                status,
                no_store_headers(),
                Json(json!({ "error": message })),
            );
        }
    };
    let prerequisites =
        match resolve_hetzner_create_prerequisites(&reviewed, &initial_runtime).await {
            Ok(prerequisites) => prerequisites,
            Err(error) => {
                let message = format!(
                    "{}; the provider create request was not sent.",
                    error.safe_message()
                );
                return (
                    StatusCode::CONFLICT,
                    no_store_headers(),
                    Json(json!({ "error": message, "job": initial_job })),
                );
            }
        };
    let final_check_at = now_unix();
    let (runtime, servers) =
        match revalidate_reviewed_paid_plan(&state, &initial_job, final_check_at).await {
            Ok(result) => result,
            Err((status, message)) => {
                return (
                    status,
                    no_store_headers(),
                    Json(json!({ "error": message, "job": initial_job })),
                );
            }
        };
    let boundary_now = now_unix();
    if boundary_now >= authorization.expires_at {
        let message = "This paid authorization expired during the final live checks. No provider create request was sent; review current details again.";
        let job = if initial_job
            .paid_execution
            .as_ref()
            .is_some_and(|execution| execution.state == "claimed")
        {
            state
                .provisioning_jobs
                .fail_paid_execution(
                    &id,
                    &request.plan_sha256,
                    false,
                    message.to_string(),
                    boundary_now,
                )
                .unwrap_or(initial_job)
        } else {
            initial_job
        };
        return (
            StatusCode::CONFLICT,
            no_store_headers(),
            Json(json!({ "error": message, "job": job })),
        );
    }
    if let Some(execution) = initial_job.paid_execution.as_ref() {
        match execution.state.as_str() {
            "claimed" => {
                if !servers.is_empty() {
                    let message = "Provider inventory changed after authorization. The durable attempt was stopped before the provider create request; review current details again.";
                    let job = state
                        .provisioning_jobs
                        .fail_paid_execution(
                            &id,
                            &request.plan_sha256,
                            false,
                            message.to_string(),
                            now_unix(),
                        )
                        .unwrap_or(initial_job);
                    return (
                        StatusCode::CONFLICT,
                        no_store_headers(),
                        Json(json!({ "error": message, "job": job })),
                    );
                }
            }
            "failed-closed" => {
                return (
                    StatusCode::CONFLICT,
                    no_store_headers(),
                    Json(
                        json!({ "error": "The paid attempt is closed and cannot be replayed. Review current details again." }),
                    ),
                );
            }
            _ => {
                return (
                    StatusCode::CONFLICT,
                    no_store_headers(),
                    Json(json!({ "error": "The paid attempt is not safe to run." })),
                );
            }
        }
    } else {
        if !servers.is_empty() {
            return (
                StatusCode::CONFLICT,
                no_store_headers(),
                Json(json!({
                    "error": "The provider project already has an active server; the reviewed maximum no longer holds. Review current details again."
                })),
            );
        }
        if let Err(error) = state.provisioning_jobs.claim_paid_execution(
            &id,
            &request.plan_sha256,
            &operator_ref,
            boundary_now,
        ) {
            let (status, message) = paid_store_error_response(error);
            return (
                status,
                no_store_headers(),
                Json(json!({ "error": message })),
            );
        }
    }

    let started = match state.provisioning_jobs.mark_paid_request_started(
        &id,
        &request.plan_sha256,
        now_unix(),
    ) {
        Ok(job) => job,
        Err(error) => {
            let (status, message) = paid_store_error_response(error);
            return (
                status,
                no_store_headers(),
                Json(json!({ "error": message })),
            );
        }
    };
    match send_hetzner_create(&reviewed, prerequisites, &runtime).await {
        Ok(server) => {
            let resource = reviewed_hetzner_provider_resource(&reviewed, &server);
            let handoff = hetzner_bootstrap_handoff(&resource);
            match state.provisioning_jobs.complete_paid_create(
                &id,
                &request.plan_sha256,
                resource,
                handoff,
                false,
                now_unix(),
            ) {
                Ok(job) => (
                    StatusCode::CREATED,
                    no_store_headers(),
                    Json(json!({ "job": job })),
                ),
                Err(ProvisioningPaidStoreError::PersistenceFailed) => {
                    let message = "Hetzner accepted the create response, but Pharos could not durably record it. The result is uncertain; restart with the valid durable store and reconcile by exact ownership labels. Pharos will not replay the paid request.";
                    (
                        StatusCode::INTERNAL_SERVER_ERROR,
                        no_store_headers(),
                        Json(json!({
                            "error": message,
                            "job": state.provisioning_jobs.get(&id)
                        })),
                    )
                }
                Err(error) => {
                    let (status, message) = paid_store_error_response(error);
                    (
                        status,
                        no_store_headers(),
                        Json(json!({ "error": message })),
                    )
                }
            }
        }
        Err(error) => {
            let uncertain = error.resource_state_uncertain();
            let message = if uncertain {
                format!(
                    "{}. The result is uncertain; Pharos will reconcile by exact ownership labels and will not replay this paid request.",
                    error.safe_message()
                )
            } else {
                format!(
                    "{}; no provider create request was accepted.",
                    error.safe_message()
                )
            };
            let job = state
                .provisioning_jobs
                .fail_paid_execution(
                    &id,
                    &request.plan_sha256,
                    uncertain,
                    message.clone(),
                    now_unix(),
                )
                .unwrap_or(started);
            (
                StatusCode::BAD_GATEWAY,
                no_store_headers(),
                Json(json!({ "error": message, "job": job })),
            )
        }
    }
}

pub(super) fn guarded_hetzner_runtime(
    state: &AppState,
    request: &ProvisioningJobStartRequest,
    now: i64,
) -> Result<HetznerCloudRuntimeConfig, (StatusCode, &'static str)> {
    let runtime = effective_hetzner_runtime(
        &state.provider_runtime.hetzner_cloud,
        &state.provider_connections,
    );
    if runtime.api_token().is_err() || !runtime.credential_boundary_ready() {
        return Err((
            StatusCode::SERVICE_UNAVAILABLE,
            "The secure Hetzner Cloud connection is not available.",
        ));
    }
    if !runtime.execute_enabled {
        return Err((
            StatusCode::SERVICE_UNAVAILABLE,
            "Managed Hetzner Cloud execution is disabled.",
        ));
    }
    if runtime.project_label.is_none() {
        return Err((
            StatusCode::SERVICE_UNAVAILABLE,
            "Set the safe Hetzner Cloud project label before paid plan review.",
        ));
    }
    if missing_hetzner_create_inputs(request, &runtime)
        || invalid_hetzner_create_inputs(request, &runtime)
    {
        return Err((
            StatusCode::BAD_REQUEST,
            "Host, image, region, server type, SSH key, or firewall selection is invalid.",
        ));
    }
    if !state
        .provider_connections
        .ready(now, runtime.evidence_ttl_secs)
    {
        return Err((
            StatusCode::CONFLICT,
            "Test the Hetzner Cloud connection again before creating a server.",
        ));
    }
    let Some(catalog) = state
        .provider_connections
        .catalog_if_fresh(now, runtime.evidence_ttl_secs)
    else {
        return Err((
            StatusCode::CONFLICT,
            "Current Hetzner Cloud locations, server plans, and prices are not available.",
        ));
    };
    let Some(location) = request.location.as_deref() else {
        return Err((StatusCode::BAD_REQUEST, "Choose a server location."));
    };
    let Some(server_type) = request.server_type.as_deref() else {
        return Err((StatusCode::BAD_REQUEST, "Choose a current server plan."));
    };
    if !catalog.supports_plan(location, server_type) {
        return Err((
            StatusCode::CONFLICT,
            "That server plan is not currently available and priced in the selected location.",
        ));
    }
    let ssh_key = request
        .ssh_key_ref
        .as_deref()
        .or(runtime.default_ssh_key_ref.as_deref());
    if ssh_key.is_none_or(|reference| !catalog.ssh_keys.iter().any(|item| item == reference)) {
        return Err((
            StatusCode::CONFLICT,
            "The selected SSH public key is not in the current Hetzner Cloud catalog.",
        ));
    }
    if runtime
        .firewall_ref
        .as_deref()
        .is_none_or(|reference| !catalog.firewalls.iter().any(|item| item == reference))
    {
        return Err((
            StatusCode::CONFLICT,
            "The selected firewall is not in the current Hetzner Cloud catalog.",
        ));
    }
    Ok(runtime)
}

#[cfg(test)]
pub(super) fn should_run_hetzner_executor(
    request: &ProvisioningJobStartRequest,
    job: &ProvisioningJob,
) -> bool {
    request.provider == "hetzner-cloud"
        && request.apply
        && job.state == ProvisioningJobState::Provisioning
}

pub(super) fn should_run_existing_host_executor(
    state: &AppState,
    request: &ProvisioningJobStartRequest,
    job: &ProvisioningJob,
) -> bool {
    request.provider == "existing-host"
        && request.template == "native-systemd"
        && request.apply
        && job.state == ProvisioningJobState::WaitingForHeartbeat
        && state.provider_runtime.existing_host.execute_enabled
}

pub(super) fn fail_existing_host_setup_job(
    state: &AppState,
    job: ProvisioningJob,
    error: ExistingHostExecutionError,
) -> ProvisioningJob {
    state
        .provisioning_jobs
        .transition_existing_host(
            &job.id,
            ProvisioningJobState::Failed,
            format!("{}; no beacon credential was installed.", error.safe_message()),
            "bootstrap-failed",
            "Automated bootstrap stopped before credential installation; review the safe error and retry only after the target is ready.",
            now_unix(),
        )
        .unwrap_or(job)
}

pub(super) async fn execute_existing_host_setup_job(
    state: &AppState,
    request: &ProvisioningJobStartRequest,
    job: ProvisioningJob,
) -> ProvisioningJob {
    if matches!(state.beacon_auth.report_token_mode, BeaconTokenMode::Janus)
        || !state.beacon_auth.local_register_enabled
    {
        return fail_existing_host_setup_job(
            state,
            job,
            ExistingHostExecutionError::UnsupportedTokenMode,
        );
    }
    let spec = match NativeSystemdBootstrapSpec::from_request(request) {
        Ok(spec) => spec,
        Err(error) => return fail_existing_host_setup_job(state, job, error),
    };
    if let Err(error) = state
        .provider_runtime
        .existing_host
        .validate_native_systemd()
    {
        return fail_existing_host_setup_job(state, job, error);
    }

    let runtime = state.provider_runtime.existing_host.clone();
    let prepare_spec = spec.clone();
    let prepared = match tokio::task::spawn_blocking(move || {
        prepare_native_systemd_bootstrap(&SystemExistingHostSshRunner, &runtime, &prepare_spec)
    })
    .await
    {
        Ok(Ok(prepared)) => prepared,
        Ok(Err(error)) => return fail_existing_host_setup_job(state, job, error),
        Err(_) => {
            return fail_existing_host_setup_job(
                state,
                job,
                ExistingHostExecutionError::ExecutorTaskFailed,
            )
        }
    };

    let bootstrapping = state
        .provisioning_jobs
        .transition_existing_host(
            &job.id,
            ProvisioningJobState::Bootstrapping,
            "SSH trust, privilege, destination, and installer artifacts verified; installing the native beacon through the protected runtime channel.",
            "installing",
            "The target passed the fail-closed execution gate; Pharos is installing the beacon without placing its credential in command arguments or job output.",
            now_unix(),
        )
        .unwrap_or_else(|| job.clone());

    let token = match new_beacon_token() {
        Ok(token) => token,
        Err(_) => {
            let runtime = state.provider_runtime.existing_host.clone();
            let cleanup_spec = spec.clone();
            let cleanup_prepared = prepared.clone();
            let _ = tokio::task::spawn_blocking(move || {
                cleanup_native_systemd_bootstrap(
                    &SystemExistingHostSshRunner,
                    &runtime,
                    &cleanup_spec,
                    &cleanup_prepared,
                );
            })
            .await;
            return fail_existing_host_setup_job(
                state,
                bootstrapping,
                ExistingHostExecutionError::TokenGenerationFailed,
            );
        }
    };
    if state
        .store
        .register(
            HostRegistration {
                schema: pharos_core::HOST_REGISTRATION_SCHEMA.to_string(),
                version: pharos_core::HOST_REGISTRATION_VERSION,
                name: spec.host_name.clone(),
                role: spec.role.clone(),
                is_nix: false,
                heartbeat_interval_secs: spec.interval,
            },
            token_hash(&token),
        )
        .is_err()
    {
        return fail_existing_host_setup_job(
            state,
            bootstrapping,
            ExistingHostExecutionError::TokenPersistenceFailed,
        );
    }

    let runtime = state.provider_runtime.existing_host.clone();
    let install_spec = spec.clone();
    let install_prepared = prepared.clone();
    let install_result = tokio::task::spawn_blocking(move || {
        install_native_systemd_bootstrap(
            &SystemExistingHostSshRunner,
            &runtime,
            &install_spec,
            &install_prepared,
            &token,
        )
    })
    .await;
    match install_result {
        Ok(Ok(())) => state
            .provisioning_jobs
            .transition_existing_host(
                &bootstrapping.id,
                ProvisioningJobState::WaitingForHeartbeat,
                "Native pharos-beacon installation completed; waiting for the first authenticated heartbeat.",
                "installed-waiting-for-heartbeat",
                "The native beacon and root-owned runtime credential file were installed; onboarding will reconcile after the first authenticated heartbeat.",
                now_unix(),
            )
            .unwrap_or(bootstrapping),
        Ok(Err(error)) => state
            .provisioning_jobs
            .transition_existing_host(
                &bootstrapping.id,
                ProvisioningJobState::CleanupNeeded,
                format!(
                    "{}. The target may contain a matching root-owned token file; inspect service state before retrying.",
                    error.safe_message()
                ),
                "cleanup-needed",
                "Credential handoff began but installation was not confirmed; inspect the target and do not rotate or retry blindly.",
                now_unix(),
            )
            .unwrap_or(bootstrapping),
        Err(_) => state
            .provisioning_jobs
            .transition_existing_host(
                &bootstrapping.id,
                ProvisioningJobState::CleanupNeeded,
                "The executor stopped after credential handoff began; inspect the target service and token file before retrying.",
                "cleanup-needed",
                "Credential handoff may have completed but the result is unknown; inspect the target and do not rotate or retry blindly.",
                now_unix(),
            )
            .unwrap_or(bootstrapping),
    }
}

pub(super) fn hetzner_bootstrap_handoff(
    resource: &ProvisioningProviderResource,
) -> Option<ProvisioningHandoff> {
    let ssh = resource.ssh.as_ref()?;
    ssh.host.as_deref()?;
    Some(ProvisioningHandoff {
        method: BootstrapMethod::NixosAnywhere,
        status: "provider-created-host-key-required".to_string(),
        title: "Server created".to_string(),
        summary: "Confirm the server's SSH host-key fingerprint out of band. The reviewed Linux executor will then create the job-owned Janus credential, install NixOS, and wait for the first heartbeat.".to_string(),
        token_policy: "Janus generates and owns one job-bound beacon credential. Its raw value is never returned to Pharos, the browser, command arguments, logs, or the Nix store.".to_string(),
        secret_target: Some("Janus-managed runtime file".to_string()),
        command_ref: Some("managed Linux provisioning executor".to_string()),
        next_steps: vec![
            format!("Open the provider web console for {} and run: ssh-keygen -lf /etc/ssh/ssh_host_ed25519_key.pub -E sha256", resource.name),
            "Copy only the displayed SHA256 fingerprint into this assistant. A fingerprint is public verification data; never copy the private host key.".to_string(),
            "Keep setup open. The reviewed Linux executor proceeds automatically after the fingerprint is attested, and Pharos finishes only after an authenticated heartbeat.".to_string(),
        ],
    })
}

pub(super) fn provider_deleted_handoff(
    resource: &ProvisioningProviderResource,
) -> ProvisioningHandoff {
    ProvisioningHandoff {
        method: BootstrapMethod::Deferred,
        status: "provider-resource-deleted".to_string(),
        title: "Server deleted".to_string(),
        summary: format!(
            "{} was removed from Hetzner Cloud and is no longer an active provider resource.",
            resource.name
        ),
        token_policy: "No credential handoff remains because the provider resource was deleted."
            .to_string(),
        secret_target: None,
        command_ref: None,
        next_steps: vec![
            "Start a new setup only when the provider plan and bootstrap path are ready."
                .to_string(),
        ],
    }
}

pub(super) async fn execute_hetzner_cleanup_job(
    state: &AppState,
    job: ProvisioningJob,
) -> Result<(ProvisioningJob, bool), ProvisioningCleanupFailure> {
    let target = hetzner_cleanup_target(&job)
        .map_err(|error| ProvisioningCleanupFailure::new(error, Some(job.clone())))?;
    if target.already_deleted {
        return Ok((job, true));
    }
    let reviewed = job.reviewed_plan.clone().ok_or_else(|| {
        ProvisioningCleanupFailure::new(
            ProvisioningCleanupError::OwnershipMismatch,
            Some(job.clone()),
        )
    })?;
    if !state.provisioning_jobs.durable_ready()
        || job.validate_contract().is_err()
        || !paid_job_integrity_valid(&job)
    {
        return Err(ProvisioningCleanupFailure::new(
            ProvisioningCleanupError::OwnershipMismatch,
            Some(job),
        ));
    }
    if !state.provider_runtime.hetzner_cloud.execute_enabled {
        return Err(ProvisioningCleanupFailure::new(
            ProvisioningCleanupError::RuntimeDisabled,
            Some(job),
        ));
    }
    let runtime = effective_hetzner_runtime(
        &state.provider_runtime.hetzner_cloud,
        &state.provider_connections,
    );
    if !runtime.credential_boundary_ready()
        || runtime.project_label.as_deref() != Some(reviewed.provider_project.as_str())
        || target.resource.name != reviewed.server_name
    {
        return Err(ProvisioningCleanupFailure::new(
            ProvisioningCleanupError::OwnershipMismatch,
            Some(job),
        ));
    }
    let operation = HetznerOperationContext::resolve(runtime).map_err(|_| {
        ProvisioningCleanupFailure::new(
            ProvisioningCleanupError::ProviderUnavailable,
            Some(job.clone()),
        )
    })?;
    let credential_binding_matches = operation.matches_reviewed_plan(&reviewed);
    let servers = fetch_hetzner_servers(&operation).await.map_err(|_| {
        ProvisioningCleanupFailure::new(
            ProvisioningCleanupError::ProviderUnavailable,
            Some(job.clone()),
        )
    })?;
    let provider_already_absent = match servers
        .iter()
        .find(|server| server.id == target.provider_id)
    {
        None if credential_binding_matches => true,
        None => {
            return Err(ProvisioningCleanupFailure::new(
                ProvisioningCleanupError::ProviderUnavailable,
                Some(job),
            ));
        }
        Some(server)
            if server.name == reviewed.server_name
                && server.matches_labels(&reviewed.required_labels) =>
        {
            false
        }
        Some(_) => {
            return Err(ProvisioningCleanupFailure::new(
                ProvisioningCleanupError::OwnershipMismatch,
                Some(job),
            ));
        }
    };
    if !state.provisioning_jobs.claim_provider_cleanup(&job.id) {
        return Err(ProvisioningCleanupFailure::new(
            ProvisioningCleanupError::CleanupInProgress,
            state.provisioning_jobs.get(&job.id),
        ));
    }

    let started = match state.provisioning_jobs.begin_provider_cleanup(
        &job.id,
        &target.resource.provider_id,
        now_unix(),
    ) {
        Ok(started) => started,
        Err(error) => {
            state.provisioning_jobs.release_provider_cleanup(&job.id);
            return Err(ProvisioningCleanupFailure::new(
                if error == ProvisioningPaidStoreError::PersistenceFailed {
                    ProvisioningCleanupError::PersistenceFailed
                } else {
                    ProvisioningCleanupError::CleanupNotAllowed
                },
                state.provisioning_jobs.get(&job.id),
            ));
        }
    };

    let provider_result = if provider_already_absent {
        Ok(HetznerDeleteResult::AlreadyAbsent)
    } else {
        delete_hetzner_server(target.provider_id, &operation).await
    };
    let outcome = match provider_result {
        Ok(delete_result) => {
            let mut deleted_resource = target.resource;
            deleted_resource.state = "deleted".to_string();
            deleted_resource.ssh = None;
            let handoff = provider_deleted_handoff(&deleted_resource);
            state
                .provisioning_jobs
                .complete_provider_cleanup(&job.id, deleted_resource, handoff, now_unix())
                .map(|job| (job, delete_result == HetznerDeleteResult::AlreadyAbsent))
                .map_err(|_| {
                    ProvisioningCleanupFailure::new(
                        ProvisioningCleanupError::PersistenceFailed,
                        state.provisioning_jobs.get(&job.id),
                    )
                })
        }
        Err(error) => {
            let cleanup_error = match &error {
                HetznerExecutionError::CredentialUnavailable
                | HetznerExecutionError::ClientUnavailable => {
                    ProvisioningCleanupError::ProviderUnavailable
                }
                _ => ProvisioningCleanupError::ProviderUncertain,
            };
            let message = format!(
                "{}. Cleanup remains required because deletion was not proven; verify Hetzner Cloud before retrying.",
                error.safe_message()
            );
            let persisted = state
                .provisioning_jobs
                .append_progress(
                    &job.id,
                    ProvisioningJobState::CleanupNeeded,
                    message,
                    now_unix(),
                )
                .unwrap_or(started);
            Err(ProvisioningCleanupFailure::new(
                cleanup_error,
                Some(persisted),
            ))
        }
    };
    state.provisioning_jobs.release_provider_cleanup(&job.id);
    outcome
}

pub(super) async fn provisioning_job_json(
    State(state): State<AppState>,
    headers: HeaderMap,
    AxumPath(id): AxumPath<String>,
) -> impl IntoResponse {
    reconcile_provisioning_jobs_with_runtime(
        &state.provisioning_jobs,
        &state.store.list(),
        now_unix(),
    );
    let access = access_for_headers(&state.auth, &headers);
    match state.provisioning_jobs.get(&id) {
        Some(job)
            if provisioning_job_host_name(&job)
                .map(|host| access.allows_host(host))
                .unwrap_or_else(|| access.can_agora()) =>
        {
            (
                StatusCode::OK,
                no_store_headers(),
                Json(json!({ "job": job })),
            )
        }
        Some(_) => (
            StatusCode::FORBIDDEN,
            no_store_headers(),
            Json(json!({ "error": "this provisioning job is not granted to this account" })),
        ),
        None => (
            StatusCode::NOT_FOUND,
            no_store_headers(),
            Json(json!({ "error": "provisioning job not found" })),
        ),
    }
}

fn provisioning_agent_error_response(
    error: ProvisioningAgentStoreError,
) -> (StatusCode, &'static str) {
    match error {
        ProvisioningAgentStoreError::NotFound => {
            (StatusCode::NOT_FOUND, "Provisioning job not found.")
        }
        ProvisioningAgentStoreError::WrongOwner => (
            StatusCode::FORBIDDEN,
            "This executor does not own the provisioning job.",
        ),
        ProvisioningAgentStoreError::InvalidTransition => (
            StatusCode::CONFLICT,
            "The provisioning job is not ready for that action.",
        ),
        ProvisioningAgentStoreError::InvalidContract => (
            StatusCode::BAD_REQUEST,
            "The provisioning action did not satisfy the required contract.",
        ),
        ProvisioningAgentStoreError::Persistence => (
            StatusCode::SERVICE_UNAVAILABLE,
            "The provisioning action could not be durably recorded.",
        ),
    }
}

pub(super) async fn attest_provisioning_host_key(
    State(state): State<AppState>,
    headers: HeaderMap,
    AxumPath(id): AxumPath<String>,
    Json(request): Json<ProvisioningHostKeyAttestationRequest>,
) -> impl IntoResponse {
    let (operator_ref, _) = match paid_operator(&state, &headers) {
        Ok(operator) => operator,
        Err((status, message)) => {
            return (
                status,
                no_store_headers(),
                Json(json!({ "error": message })),
            );
        }
    };
    if !request.attended {
        return (
            StatusCode::BAD_REQUEST,
            no_store_headers(),
            Json(json!({ "error": "Attended host-key attestation is required." })),
        );
    }
    match state.provisioning_jobs.attest_managed_host_key(
        &id,
        request.fingerprint.trim(),
        &operator_ref,
        now_unix(),
    ) {
        Ok(job) => (
            StatusCode::OK,
            no_store_headers(),
            Json(json!({ "job": job })),
        ),
        Err(error) => {
            let (status, message) = provisioning_agent_error_response(error);
            (
                status,
                no_store_headers(),
                Json(json!({ "error": message })),
            )
        }
    }
}

pub(super) async fn retry_provisioning_bootstrap(
    State(state): State<AppState>,
    headers: HeaderMap,
    AxumPath(id): AxumPath<String>,
    Json(request): Json<ProvisioningBootstrapRetryRequest>,
) -> impl IntoResponse {
    if let Err((status, message)) = paid_operator(&state, &headers) {
        return (
            status,
            no_store_headers(),
            Json(json!({ "error": message })),
        );
    }
    if !request.confirm {
        return (
            StatusCode::BAD_REQUEST,
            no_store_headers(),
            Json(json!({ "error": "Explicit bootstrap retry confirmation is required." })),
        );
    }
    match state
        .provisioning_jobs
        .retry_managed_bootstrap(&id, now_unix())
    {
        Ok(job) => (
            StatusCode::OK,
            no_store_headers(),
            Json(json!({ "job": job })),
        ),
        Err(error) => {
            let (status, message) = provisioning_agent_error_response(error);
            (
                status,
                no_store_headers(),
                Json(json!({ "error": message })),
            )
        }
    }
}

pub(super) async fn reconcile_provisioning_bootstrap(
    State(state): State<AppState>,
    headers: HeaderMap,
    AxumPath(id): AxumPath<String>,
    Json(request): Json<ProvisioningBootstrapReconciliationRequest>,
) -> impl IntoResponse {
    if let Err((status, message)) = paid_operator(&state, &headers) {
        return (
            status,
            no_store_headers(),
            Json(json!({ "error": message })),
        );
    }
    if !request.confirm {
        return (
            StatusCode::BAD_REQUEST,
            no_store_headers(),
            Json(json!({ "error": "Explicit read-only recovery confirmation is required." })),
        );
    }
    match state
        .provisioning_jobs
        .queue_managed_bootstrap_reconciliation(&id, now_unix())
    {
        Ok(job) => (
            StatusCode::OK,
            no_store_headers(),
            Json(json!({ "job": job })),
        ),
        Err(error) => {
            let (status, message) = provisioning_agent_error_response(error);
            (
                status,
                no_store_headers(),
                Json(json!({ "error": message })),
            )
        }
    }
}

pub(super) async fn cleanup_provisioning_job(
    State(state): State<AppState>,
    headers: HeaderMap,
    AxumPath(id): AxumPath<String>,
    Json(request): Json<ProvisioningCleanupRequest>,
) -> impl IntoResponse {
    if !access_for_headers(&state.auth, &headers).can_agora() {
        return (
            StatusCode::FORBIDDEN,
            no_store_headers(),
            Json(json!({ "error": "Agora access is not granted for this account" })),
        );
    }
    if !request.confirm {
        return (
            StatusCode::BAD_REQUEST,
            no_store_headers(),
            Json(json!({ "error": "Explicit cleanup confirmation is required." })),
        );
    }
    reconcile_provisioning_jobs_with_runtime(
        &state.provisioning_jobs,
        &state.store.list(),
        now_unix(),
    );
    let Some(job) = state.provisioning_jobs.get(&id) else {
        return (
            StatusCode::NOT_FOUND,
            no_store_headers(),
            Json(json!({ "error": "Provisioning job not found." })),
        );
    };
    if let Err((status, message)) = paid_operator(&state, &headers) {
        return (
            status,
            no_store_headers(),
            Json(json!({ "error": message })),
        );
    }
    if !state.provisioning_jobs.durable_ready() {
        return (
            StatusCode::SERVICE_UNAVAILABLE,
            no_store_headers(),
            Json(
                json!({ "error": "The durable provisioning-job store is unavailable; no provider deletion was sent." }),
            ),
        );
    }

    match execute_hetzner_cleanup_job(&state, job).await {
        Ok((job, already_absent)) => (
            StatusCode::OK,
            no_store_headers(),
            Json(json!({
                "job": job,
                "cleanup": {
                    "state": "deleted",
                    "already_absent": already_absent
                }
            })),
        ),
        Err(failure) => (
            failure.error.status_code(),
            no_store_headers(),
            Json(json!({
                "error": failure.error.safe_message(),
                "job": failure.job
            })),
        ),
    }
}

pub(super) async fn existing_host_preflight_json(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(request): Json<ExistingHostPreflightRequest>,
) -> impl IntoResponse {
    if !access_for_headers(&state.auth, &headers).can_agora() {
        return (
            StatusCode::FORBIDDEN,
            no_store_headers(),
            Json(json!({ "error": "Agora access is not granted for this account" })),
        );
    }
    if let Err(error) = request.validate_contract() {
        return (
            StatusCode::BAD_REQUEST,
            no_store_headers(),
            Json(json!({ "error": error })),
        );
    }
    let report = existing_host_preflight_report(&request, now_unix()).await;
    match report.validate_contract() {
        Ok(()) => (
            StatusCode::OK,
            no_store_headers(),
            Json(json!({ "preflight": report })),
        ),
        Err(error) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            no_store_headers(),
            Json(json!({ "error": error })),
        ),
    }
}

pub(super) async fn existing_host_preflight_report(
    request: &ExistingHostPreflightRequest,
    now: i64,
) -> ExistingHostPreflightReport {
    let mut checks = Vec::new();
    let facts = if needs_existing_host_ssh_fact_probe(&request.facts) {
        merge_preflight_facts(
            request.facts.clone(),
            existing_host_ssh_fact_probe(request).await,
        )
    } else {
        request.facts.clone()
    };
    let ssh_tcp_state = match preflight_ssh_endpoint(request) {
        Some((host, port)) => {
            let started = Instant::now();
            match timeout(
                SERVER_PROBE_TIMEOUT,
                TcpStream::connect((host.as_str(), port)),
            )
            .await
            {
                Ok(Ok(_)) => {
                    let elapsed_ms = started.elapsed().as_millis().max(1);
                    PreflightCheckState::Pass.with_message(format!(
                        "SSH port is reachable from Pharos in {elapsed_ms} ms."
                    ))
                }
                Ok(Err(_)) => PreflightCheckState::Fail
                    .with_message("Pharos cannot open the SSH port for this host.".to_string()),
                Err(_) => PreflightCheckState::Fail
                    .with_message("Pharos timed out while checking the SSH port.".to_string()),
            }
        }
        None => PreflightCheckState::Unknown
            .with_message("Add an SSH target before automated bootstrap is offered.".to_string()),
    };
    checks.push(preflight_check(
        "ssh-reachability",
        "SSH reachability",
        ssh_tcp_state.0,
        ssh_tcp_state.1,
    ));
    checks.push(preflight_bool_check(
        "ssh-authentication",
        "SSH authentication",
        facts.ssh_authenticated,
        "SSH authentication has been verified.",
        "SSH authentication failed or is not available.",
        "Verify SSH login without sending any password or key material to Pharos.",
    ));
    checks.push(privilege_check(&facts));
    checks.push(os_family_check(&facts));
    checks.push(nix_capability_check(&facts));
    checks.push(disk_check(&facts));
    checks.push(preflight_bool_check(
        "pharos-reachability",
        "Host can reach Pharos",
        facts.pharos_reachable,
        "The host can reach the Pharos report endpoint.",
        "The host cannot reach Pharos yet.",
        "Confirm outbound HTTPS from the host to Pharos before registering a beacon.",
    ));
    checks.push(backup_observation_check(&facts));

    let bootstrap_options = bootstrap_options(&facts, &checks);
    let summary = preflight_summary(&checks);
    let next_action = preflight_next_action(&summary, &bootstrap_options).to_string();
    ExistingHostPreflightReport {
        schema: EXISTING_HOST_PREFLIGHT_SCHEMA.to_string(),
        version: EXISTING_HOST_PREFLIGHT_VERSION,
        host_name: request.host_name.trim().to_string(),
        checked_at: now,
        summary,
        checks,
        bootstrap_options,
        next_action,
    }
}

pub(super) fn preflight_ssh_endpoint(
    request: &ExistingHostPreflightRequest,
) -> Option<(String, u16)> {
    if matches!(request.ssh.route, SshRoute::None | SshRoute::Unknown) {
        return None;
    }
    request
        .ssh
        .host
        .as_deref()
        .and_then(|host| split_probe_host_port(host, request.ssh.port.unwrap_or(22)))
}

pub(super) fn needs_existing_host_ssh_fact_probe(facts: &ExistingHostPreflightFacts) -> bool {
    facts.ssh_authenticated.is_none()
        || facts.root.is_none()
        || facts.sudo.is_none()
        || facts.os_family.is_none()
        || facts.nixos.is_none()
        || facts.nix_available.is_none()
        || facts.free_disk_gib.is_none()
        || facts.pharos_reachable.is_none()
        || facts.backup_tools.is_empty()
}

pub(super) async fn existing_host_ssh_fact_probe(
    request: &ExistingHostPreflightRequest,
) -> ExistingHostPreflightFacts {
    let Some((host, port)) = preflight_ssh_endpoint(request) else {
        return ExistingHostPreflightFacts::default();
    };
    let user = request.ssh.user.clone();
    let pharos_url = request.pharos_url.clone();
    match timeout(
        EXISTING_HOST_SSH_PROBE_TIMEOUT,
        tokio::task::spawn_blocking(move || {
            run_existing_host_ssh_probe(host, port, user, pharos_url)
        }),
    )
    .await
    {
        Ok(Ok(facts)) => facts,
        _ => ExistingHostPreflightFacts {
            ssh_authenticated: Some(false),
            ..ExistingHostPreflightFacts::default()
        },
    }
}

pub(super) fn run_existing_host_ssh_probe(
    host: String,
    port: u16,
    user: Option<String>,
    pharos_url: Option<String>,
) -> ExistingHostPreflightFacts {
    let target = match user
        .as_deref()
        .map(str::trim)
        .filter(|user| !user.is_empty())
    {
        Some(user) => format!("{user}@{host}"),
        None => host,
    };
    let mut remote = String::new();
    if let Some(url) = pharos_url
        .as_deref()
        .map(str::trim)
        .filter(|url| !url.is_empty())
    {
        remote.push_str("PHAROS_PREFLIGHT_URL=");
        remote.push_str(&shell_single_quote(url));
        remote.push_str("; export PHAROS_PREFLIGHT_URL; ");
    }
    remote.push_str("sh -c ");
    remote.push_str(&shell_single_quote(EXISTING_HOST_SSH_PROBE_SCRIPT));

    let output = Command::new("ssh")
        .arg("-o")
        .arg("BatchMode=yes")
        .arg("-o")
        .arg("PasswordAuthentication=no")
        .arg("-o")
        .arg("KbdInteractiveAuthentication=no")
        .arg("-o")
        .arg("ConnectTimeout=4")
        .arg("-o")
        .arg("ServerAliveInterval=2")
        .arg("-o")
        .arg("ServerAliveCountMax=1")
        .arg("-p")
        .arg(port.to_string())
        .arg(target)
        .arg(remote)
        .output();

    match output {
        Ok(output) if output.status.success() => {
            parse_existing_host_ssh_probe_stdout(&output.stdout)
        }
        Ok(_) => ExistingHostPreflightFacts {
            ssh_authenticated: Some(false),
            ..ExistingHostPreflightFacts::default()
        },
        Err(_) => ExistingHostPreflightFacts::default(),
    }
}

pub(super) const EXISTING_HOST_SSH_PROBE_SCRIPT: &str = r#"uid=$(id -u 2>/dev/null || printf unknown)
case "$uid" in
  0) root=true ;;
  *) root=false ;;
esac
if command -v sudo >/dev/null 2>&1 && sudo -n true >/dev/null 2>&1; then
  sudo=true
else
  sudo=false
fi
if [ -r /etc/os-release ]; then
  os=$(. /etc/os-release >/dev/null 2>&1; printf '%s' "${ID:-linux}")
else
  os=$(uname -s 2>/dev/null || printf unknown)
fi
if [ -e /etc/NIXOS ]; then nixos=true; else nixos=false; fi
if command -v nix >/dev/null 2>&1; then nix=true; else nix=false; fi
disk=$(df -Pk / 2>/dev/null | awk 'NR==2 { printf "%d", $4 / 1048576 }')
case "$disk" in ''|*[!0-9]*) disk=0 ;; esac
pharos=unknown
if [ -n "${PHAROS_PREFLIGHT_URL:-}" ]; then
  if command -v curl >/dev/null 2>&1; then
    if curl -fsS --max-time 4 "${PHAROS_PREFLIGHT_URL%/}/healthz" >/dev/null 2>&1; then pharos=true; else pharos=false; fi
  elif command -v wget >/dev/null 2>&1; then
    if wget -q -T 4 -O /dev/null "${PHAROS_PREFLIGHT_URL%/}/healthz" >/dev/null 2>&1; then pharos=true; else pharos=false; fi
  fi
fi
backup_tools=
add_backup_tool() {
  case ",$backup_tools," in
    *,"$1",*) ;;
    *) if [ -n "$backup_tools" ]; then backup_tools="$backup_tools,$1"; else backup_tools="$1"; fi ;;
  esac
}
for tool in restic borg kopia duplicity duplicacy rclone; do
  if command -v "$tool" >/dev/null 2>&1; then add_backup_tool "$tool"; fi
done
if command -v systemctl >/dev/null 2>&1; then
  if systemctl list-timers --all --no-legend 2>/dev/null | grep -Eiq 'backup|restic|borg|kopia|duplicity|duplicacy|rclone'; then
    add_backup_tool systemd-timer
  fi
  if systemctl list-unit-files --type=service --no-legend 2>/dev/null | grep -Eiq 'backup|restic|borg|kopia|duplicity|duplicacy|rclone'; then
    add_backup_tool systemd-service
  fi
fi
printf 'ssh_authenticated=true\n'
printf 'root=%s\n' "$root"
printf 'sudo=%s\n' "$sudo"
printf 'os_family=%s\n' "$os"
printf 'nixos=%s\n' "$nixos"
printf 'nix_available=%s\n' "$nix"
printf 'free_disk_gib=%s\n' "$disk"
printf 'pharos_reachable=%s\n' "$pharos"
printf 'backup_tools=%s\n' "$backup_tools"
"#;

pub(super) fn parse_existing_host_ssh_probe_stdout(stdout: &[u8]) -> ExistingHostPreflightFacts {
    let mut facts = ExistingHostPreflightFacts::default();
    let text = String::from_utf8_lossy(stdout);
    for line in text.lines().take(32) {
        let Some((key, value)) = line.split_once('=') else {
            continue;
        };
        let value = value.trim();
        match key.trim() {
            "ssh_authenticated" => facts.ssh_authenticated = parse_probe_bool(value),
            "root" => facts.root = parse_probe_bool(value),
            "sudo" => facts.sudo = parse_probe_bool(value),
            "os_family" => facts.os_family = sanitize_probe_text(value),
            "nixos" => facts.nixos = parse_probe_bool(value),
            "nix_available" => facts.nix_available = parse_probe_bool(value),
            "free_disk_gib" => facts.free_disk_gib = value.parse::<u32>().ok(),
            "pharos_reachable" => facts.pharos_reachable = parse_probe_bool(value),
            "backup_tools" => facts.backup_tools = parse_backup_tools(value),
            _ => {}
        }
    }
    facts
}

pub(super) fn parse_probe_bool(value: &str) -> Option<bool> {
    match value.trim().to_ascii_lowercase().as_str() {
        "true" | "1" | "yes" => Some(true),
        "false" | "0" | "no" => Some(false),
        _ => None,
    }
}

pub(super) fn sanitize_probe_text(value: &str) -> Option<String> {
    let value = value.trim();
    if value.is_empty()
        || value.len() > 80
        || value.contains('\n')
        || value.contains('\r')
        || value.to_ascii_lowercase().contains("token=")
        || value.to_ascii_lowercase().contains("bearer ")
    {
        return None;
    }
    Some(value.to_string())
}

pub(super) fn parse_backup_tools(value: &str) -> Vec<String> {
    let mut tools = Vec::new();
    for raw in value.split(',').take(12) {
        let Some(tool) = sanitize_probe_text(raw) else {
            continue;
        };
        if tool
            .chars()
            .all(|ch| ch.is_ascii_lowercase() || ch.is_ascii_digit() || ch == '-')
            && !tools.iter().any(|existing| existing == &tool)
        {
            tools.push(tool);
        }
    }
    tools
}

pub(super) fn merge_preflight_facts(
    mut base: ExistingHostPreflightFacts,
    probe: ExistingHostPreflightFacts,
) -> ExistingHostPreflightFacts {
    base.ssh_authenticated = base.ssh_authenticated.or(probe.ssh_authenticated);
    base.root = base.root.or(probe.root);
    base.sudo = base.sudo.or(probe.sudo);
    base.os_family = base.os_family.or(probe.os_family);
    base.nixos = base.nixos.or(probe.nixos);
    base.nix_available = base.nix_available.or(probe.nix_available);
    base.free_disk_gib = base.free_disk_gib.or(probe.free_disk_gib);
    base.pharos_reachable = base.pharos_reachable.or(probe.pharos_reachable);
    if base.backup_tools.is_empty() {
        base.backup_tools = probe.backup_tools;
    }
    base
}

pub(super) fn shell_single_quote(value: &str) -> String {
    let mut quoted = String::from("'");
    for ch in value.chars() {
        if ch == '\'' {
            quoted.push_str("'\"'\"'");
        } else {
            quoted.push(ch);
        }
    }
    quoted.push('\'');
    quoted
}

pub(super) fn preflight_check(
    key: &str,
    label: &str,
    state: PreflightCheckState,
    message: String,
) -> ExistingHostPreflightCheck {
    ExistingHostPreflightCheck {
        key: key.to_string(),
        label: label.to_string(),
        state,
        message,
    }
}

pub(super) trait PreflightStateMessage {
    fn with_message(self, message: String) -> (PreflightCheckState, String);
}

impl PreflightStateMessage for PreflightCheckState {
    fn with_message(self, message: String) -> (PreflightCheckState, String) {
        (self, message)
    }
}

pub(super) fn preflight_bool_check(
    key: &str,
    label: &str,
    value: Option<bool>,
    pass: &str,
    fail: &str,
    unknown: &str,
) -> ExistingHostPreflightCheck {
    match value {
        Some(true) => preflight_check(key, label, PreflightCheckState::Pass, pass.to_string()),
        Some(false) => preflight_check(key, label, PreflightCheckState::Fail, fail.to_string()),
        None => preflight_check(
            key,
            label,
            PreflightCheckState::Unknown,
            unknown.to_string(),
        ),
    }
}

pub(super) fn privilege_check(facts: &ExistingHostPreflightFacts) -> ExistingHostPreflightCheck {
    match (facts.root, facts.sudo) {
        (Some(true), _) => preflight_check(
            "privilege",
            "Privilege model",
            PreflightCheckState::Pass,
            "Root access is available for bootstrap.".to_string(),
        ),
        (_, Some(true)) => preflight_check(
            "privilege",
            "Privilege model",
            PreflightCheckState::Pass,
            "The SSH user can elevate with sudo.".to_string(),
        ),
        (Some(false), Some(false)) => preflight_check(
            "privilege",
            "Privilege model",
            PreflightCheckState::Fail,
            "Automated bootstrap needs root or sudo access.".to_string(),
        ),
        _ => preflight_check(
            "privilege",
            "Privilege model",
            PreflightCheckState::Unknown,
            "Verify root or sudo capability before choosing an automated path.".to_string(),
        ),
    }
}

pub(super) fn os_family_check(facts: &ExistingHostPreflightFacts) -> ExistingHostPreflightCheck {
    let Some(os) = facts.os_family.as_deref().map(str::trim) else {
        return preflight_check(
            "os-family",
            "Operating system",
            PreflightCheckState::Unknown,
            "Identify the host operating system before bootstrap.".to_string(),
        );
    };
    let lowered = os.to_ascii_lowercase();
    if lowered.contains("linux") || lowered.contains("nixos") {
        preflight_check(
            "os-family",
            "Operating system",
            PreflightCheckState::Pass,
            format!("{os} is a supported existing-host target."),
        )
    } else if lowered.contains("darwin")
        || lowered.contains("macos")
        || lowered.contains("windows")
        || lowered.contains("bsd")
    {
        preflight_check(
            "os-family",
            "Operating system",
            PreflightCheckState::Fail,
            format!("{os} is not supported by the automated existing-host bootstrap path."),
        )
    } else {
        preflight_check(
            "os-family",
            "Operating system",
            PreflightCheckState::Warn,
            format!("{os} needs manual review before automated bootstrap."),
        )
    }
}

pub(super) fn nix_capability_check(
    facts: &ExistingHostPreflightFacts,
) -> ExistingHostPreflightCheck {
    match (facts.nixos, facts.nix_available) {
        (Some(true), _) => preflight_check(
            "nix-capability",
            "Nix capability",
            PreflightCheckState::Pass,
            "NixOS is already detected.".to_string(),
        ),
        (Some(false), Some(true)) => preflight_check(
            "nix-capability",
            "Nix capability",
            PreflightCheckState::Warn,
            "Nix is available, but the host is not confirmed as NixOS.".to_string(),
        ),
        (Some(false), Some(false)) => preflight_check(
            "nix-capability",
            "Nix capability",
            PreflightCheckState::Warn,
            "Nix is not detected; use native beacon or manual bootstrap unless converting the host.".to_string(),
        ),
        _ => preflight_check(
            "nix-capability",
            "Nix capability",
            PreflightCheckState::Unknown,
            "Check whether the host is NixOS or can run the portable beacon.".to_string(),
        ),
    }
}

pub(super) fn disk_check(facts: &ExistingHostPreflightFacts) -> ExistingHostPreflightCheck {
    match facts.free_disk_gib {
        Some(gib) if gib >= 8 => preflight_check(
            "disk-space",
            "Disk headroom",
            PreflightCheckState::Pass,
            format!("{gib} GiB free is enough for setup checks."),
        ),
        Some(gib) if gib >= 4 => preflight_check(
            "disk-space",
            "Disk headroom",
            PreflightCheckState::Warn,
            format!("{gib} GiB free is tight; review before bootstrap."),
        ),
        Some(gib) => preflight_check(
            "disk-space",
            "Disk headroom",
            PreflightCheckState::Fail,
            format!("{gib} GiB free is too little for a safe bootstrap."),
        ),
        None => preflight_check(
            "disk-space",
            "Disk headroom",
            PreflightCheckState::Unknown,
            "Check free disk space before installing or converting the host.".to_string(),
        ),
    }
}

pub(super) fn backup_observation_check(
    facts: &ExistingHostPreflightFacts,
) -> ExistingHostPreflightCheck {
    if facts.backup_tools.is_empty() {
        return preflight_check(
            "backup-observation",
            "Backup signal",
            PreflightCheckState::Warn,
            "No existing backup job was detected during read-only preflight; choose backup intent before finishing onboarding.".to_string(),
        );
    }

    preflight_check(
        "backup-observation",
        "Backup signal",
        PreflightCheckState::Pass,
        format!(
            "Detected backup signal: {}. Choose managed elsewhere to observe it, or required to enroll Pharos-managed backups.",
            facts.backup_tools.join(", ")
        ),
    )
}

pub(super) fn bootstrap_options(
    facts: &ExistingHostPreflightFacts,
    checks: &[ExistingHostPreflightCheck],
) -> Vec<ExistingHostBootstrapOption> {
    let ssh_reachable = check_passed(checks, "ssh-reachability");
    let auth_ok = facts.ssh_authenticated == Some(true);
    let privilege_ok = facts.root == Some(true) || facts.sudo == Some(true);
    let disk_ok = !check_failed(checks, "disk-space");
    let os_supported = check_passed(checks, "os-family") || facts.os_family.is_none();
    let linuxish = facts
        .os_family
        .as_deref()
        .map(|os| {
            let os = os.to_ascii_lowercase();
            os.contains("linux") || os.contains("nixos")
        })
        .unwrap_or(false);
    let automated_ready = ssh_reachable && auth_ok && privilege_ok && disk_ok && os_supported;
    vec![
        ExistingHostBootstrapOption {
            method: BootstrapMethod::NixosAnywhere,
            label: "NixOS / declarative".to_string(),
            available: automated_ready && linuxish,
            message: if automated_ready && linuxish {
                "Use this when the host should be managed declaratively.".to_string()
            } else {
                "Needs reachable SSH, authentication, privilege, Linux/NixOS facts, and enough disk."
                    .to_string()
            },
            changes: vec![
                "Review and apply a declarative NixOS bootstrap.".to_string(),
                "Install or update pharos-beacon through managed system configuration.".to_string(),
            ],
            token_handoff: Some(
                "Beacon token handoff uses a managed file or env-file, never a command-line argument."
                    .to_string(),
            ),
            existing_token_policy: Some(
                "Existing beacon token files are rotation-sensitive and must be reviewed before replacement."
                    .to_string(),
            ),
            next_state: Some("awaiting-first-heartbeat after setup starts".to_string()),
        },
        ExistingHostBootstrapOption {
            method: BootstrapMethod::NativeSystemd,
            label: "Native beacon".to_string(),
            available: automated_ready && linuxish,
            message: if automated_ready && linuxish {
                "Use this when the host should keep its current OS and only report to Pharos."
                    .to_string()
            } else {
                "Needs verified Linux SSH access with root or sudo.".to_string()
            },
            changes: vec![
                "Install the portable pharos-beacon service on the existing OS.".to_string(),
                "Create a least-surprise service environment file for beacon configuration.".to_string(),
            ],
            token_handoff: Some(
                "Beacon token handoff uses a local env-file path owned by the service user."
                    .to_string(),
            ),
            existing_token_policy: Some(
                "Existing token files are rotation-sensitive and preserved until explicit rotation is confirmed.".to_string(),
            ),
            next_state: Some("awaiting-first-heartbeat after setup starts".to_string()),
        },
        ExistingHostBootstrapOption {
            method: BootstrapMethod::Manual,
            label: "Manual / deferred".to_string(),
            available: true,
            message:
                "Always available; the operator completes setup without automated host changes."
                    .to_string(),
            changes: vec![
                "No automated host changes are made by Pharos.".to_string(),
                "Show manual instructions and wait for the first heartbeat.".to_string(),
            ],
            token_handoff: Some(
                "Token handoff stays file/env-file based; do not paste raw tokens into shell history."
                    .to_string(),
            ),
            existing_token_policy: Some(
                "If a token already exists, treat it as rotation-sensitive state.".to_string(),
            ),
            next_state: Some("manual setup or awaiting-first-heartbeat".to_string()),
        },
    ]
}

pub(super) fn check_passed(checks: &[ExistingHostPreflightCheck], key: &str) -> bool {
    checks
        .iter()
        .any(|check| check.key == key && check.state == PreflightCheckState::Pass)
}

pub(super) fn check_failed(checks: &[ExistingHostPreflightCheck], key: &str) -> bool {
    checks
        .iter()
        .any(|check| check.key == key && check.state == PreflightCheckState::Fail)
}

pub(super) fn preflight_summary(
    checks: &[ExistingHostPreflightCheck],
) -> ExistingHostPreflightSummary {
    if checks
        .iter()
        .any(|check| check.state == PreflightCheckState::Fail)
    {
        ExistingHostPreflightSummary {
            state: PreflightCheckState::Fail,
            label: "Needs attention".to_string(),
            message: "Fix failed checks before registering a beacon token.".to_string(),
        }
    } else if checks
        .iter()
        .any(|check| check.state == PreflightCheckState::Unknown)
    {
        ExistingHostPreflightSummary {
            state: PreflightCheckState::Unknown,
            label: "Needs details".to_string(),
            message: "Collect the missing read-only facts before automated bootstrap.".to_string(),
        }
    } else if checks
        .iter()
        .any(|check| check.state == PreflightCheckState::Warn)
    {
        ExistingHostPreflightSummary {
            state: PreflightCheckState::Warn,
            label: "Review first".to_string(),
            message: "Bootstrap may be possible, but one check needs operator review.".to_string(),
        }
    } else {
        ExistingHostPreflightSummary {
            state: PreflightCheckState::Pass,
            label: "Ready".to_string(),
            message: "Choose a bootstrap method; no token has been registered yet.".to_string(),
        }
    }
}

pub(super) fn preflight_next_action(
    summary: &ExistingHostPreflightSummary,
    options: &[ExistingHostBootstrapOption],
) -> &'static str {
    match summary.state {
        PreflightCheckState::Fail => "Fix failed checks, then run preflight again.",
        PreflightCheckState::Unknown => {
            "Collect SSH, privilege, OS, disk, and host-to-Pharos facts."
        }
        PreflightCheckState::Warn => "Review warnings, then choose a bootstrap method.",
        PreflightCheckState::Pass => {
            if options
                .iter()
                .any(|option| option.available && option.method != BootstrapMethod::Manual)
            {
                "Choose NixOS/declarative or native beacon bootstrap."
            } else {
                "Use manual/deferred setup or collect more automation facts."
            }
        }
    }
}
