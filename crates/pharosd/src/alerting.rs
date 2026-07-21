//! Alert delivery configuration, dispatch, and worker supervision.

use super::*;
use crate::alerts::AlertStoreError;

const ALERT_CHECK_INTERVAL: Duration = Duration::from_secs(60);
const ALERT_WEBHOOK_TIMEOUT: Duration = Duration::from_secs(5);

#[derive(Clone)]
pub(super) struct AlertNotifier {
    pub(super) webhook_url: Option<String>,
    pub(super) client: reqwest::Client,
    pub(super) outbox: Arc<AlertStore>,
    pub(super) health: AlertWorkerHealth,
    pub(super) check_interval: Duration,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum AlertNotifierConfigError {
    DurableStorageRequired,
    InvalidTarget,
    ClientBuild,
}

impl std::fmt::Display for AlertNotifierConfigError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(match self {
            Self::DurableStorageRequired => {
                "configured alert delivery requires PHAROS_DB or PHAROS_ALERT_DB"
            }
            Self::InvalidTarget => "configured alert target is invalid or unsupported",
            Self::ClientBuild => "bounded no-redirect alert client could not be built",
        })
    }
}

impl std::error::Error for AlertNotifierConfigError {}

impl AlertNotifier {
    pub(super) fn from_env(outbox: Arc<AlertStore>) -> Result<Self, AlertNotifierConfigError> {
        let webhook_url = alert_webhook_url(
            std::env::var("PHAROS_ALERT_WEBHOOK_URL").ok(),
            std::env::var("WATCHTOWER_NOTIFICATION_URL").ok(),
            std::env::var("PHAROS_ALERT_WEBHOOK_ENV_FILE").ok(),
        );
        if let Some(target) = webhook_url.as_deref() {
            let parsed = Url::parse(target).map_err(|_| AlertNotifierConfigError::InvalidTarget)?;
            let supported = match parsed.scheme() {
                "http" | "https" => parsed.host_str().is_some(),
                "telegram" => TelegramAlertTarget::from_url(&parsed).is_some(),
                _ => false,
            };
            if !supported {
                return Err(AlertNotifierConfigError::InvalidTarget);
            }
            if !outbox.is_durable() {
                return Err(AlertNotifierConfigError::DurableStorageRequired);
            }
        }
        let check_interval = std::env::var("PHAROS_ALERT_CHECK_SECS")
            .ok()
            .and_then(|value| value.parse::<u64>().ok())
            .filter(|seconds| *seconds >= 5)
            .map(Duration::from_secs)
            .unwrap_or(ALERT_CHECK_INTERVAL);
        let timeout = std::env::var("PHAROS_ALERT_WEBHOOK_TIMEOUT_SECS")
            .ok()
            .and_then(|value| value.parse::<u64>().ok())
            .filter(|seconds| *seconds >= 1)
            .map(Duration::from_secs)
            .unwrap_or(ALERT_WEBHOOK_TIMEOUT);
        let client = reqwest::Client::builder()
            .timeout(timeout)
            .redirect(reqwest::redirect::Policy::none())
            .build()
            .map_err(|_| AlertNotifierConfigError::ClientBuild)?;
        let health =
            AlertWorkerHealth::new(webhook_url.is_some(), now_unix(), check_interval.as_secs());
        Ok(Self {
            webhook_url,
            client,
            outbox,
            health,
            check_interval,
        })
    }

    fn enabled(&self) -> bool {
        self.webhook_url.is_some()
    }

    async fn check_store(&self, store: &Store, now: i64) -> Result<(), AlertStoreError> {
        self.outbox.reconcile_hosts(&store.list(), now)?;
        for event_id in self.outbox.due_event_ids(now) {
            let event = self.outbox.begin_attempt(&event_id, now)?;
            let delivered = self.send(&event).await;
            self.health.record_delivery(delivered);
            if delivered {
                self.outbox.mark_delivered(&event_id, now)?;
            }
        }
        Ok(())
    }

    pub(super) async fn send(&self, alert: &AlertEvent) -> bool {
        let Some(url) = self.webhook_url.as_deref() else {
            return false;
        };
        let Ok(parsed_url) = Url::parse(url) else {
            tracing::warn!(host = %alert.host, "silent beacon alert target URL is invalid");
            return false;
        };
        match parsed_url.scheme() {
            "http" | "https" => self.send_http_alert(url, alert).await,
            "telegram" => self.send_telegram_alert(&parsed_url, alert).await,
            _ => {
                tracing::warn!(
                    host = %alert.host,
                    scheme = %parsed_url.scheme(),
                    "silent beacon alert target URL scheme is unsupported"
                );
                false
            }
        }
    }

    async fn send_http_alert(&self, url: &str, alert: &AlertEvent) -> bool {
        match self
            .client
            .post(url)
            .header("Idempotency-Key", &alert.event_id)
            .json(alert)
            .send()
            .await
        {
            Ok(response) if response.status().is_success() => {
                tracing::warn!(
                    host = %alert.host,
                    event_id = %alert.event_id,
                    kind = alert.kind.label(),
                    "alert outbox event delivered"
                );
                true
            }
            Ok(response) => {
                tracing::warn!(
                    host = %alert.host,
                    status = %response.status(),
                    event_id = %alert.event_id,
                    "alert webhook returned non-success"
                );
                false
            }
            Err(_) => {
                tracing::warn!(
                    host = %alert.host,
                    event_id = %alert.event_id,
                    "alert webhook request failed"
                );
                false
            }
        }
    }

    async fn send_telegram_alert(&self, url: &Url, alert: &AlertEvent) -> bool {
        let Some(target) = TelegramAlertTarget::from_url(url) else {
            tracing::warn!(host = %alert.host, "silent beacon Telegram alert target is invalid");
            return false;
        };
        let endpoint = format!("https://api.telegram.org/bot{}/sendMessage", target.token);
        let text = telegram_alert_text(alert);
        let mut sent_all = true;

        for chat_id in target.chats {
            let payload = json!({
                "chat_id": chat_id,
                "text": text,
                "disable_web_page_preview": true,
            });
            match self
                .client
                .post(&endpoint)
                .header("Idempotency-Key", &alert.event_id)
                .json(&payload)
                .send()
                .await
            {
                Ok(response) if response.status().is_success() => {
                    tracing::warn!(
                        host = %alert.host,
                        event_id = %alert.event_id,
                        kind = alert.kind.label(),
                        "Telegram alert outbox event delivered"
                    );
                }
                Ok(response) => {
                    tracing::warn!(
                        host = %alert.host,
                        status = %response.status(),
                        "silent beacon Telegram alert returned non-success"
                    );
                    sent_all = false;
                }
                Err(_) => {
                    tracing::warn!(
                        host = %alert.host,
                        "silent beacon Telegram alert request failed"
                    );
                    sent_all = false;
                }
            }
        }

        sent_all
    }
}

pub(super) fn spawn_alert_loop(state: AppState, notifier: AlertNotifier) {
    if !notifier.enabled() {
        tracing::info!("silent beacon alert webhook not configured; notifications disabled");
        return;
    }
    let health = notifier.health.clone();
    tokio::spawn(supervise_alert_worker(
        health,
        Duration::from_secs(1),
        move || {
            let worker_state = state.clone();
            let worker_notifier = notifier.clone();
            tokio::spawn(async move {
                let mut interval = tokio::time::interval(worker_notifier.check_interval);
                interval.set_missed_tick_behavior(MissedTickBehavior::Delay);
                loop {
                    interval.tick().await;
                    let now = now_unix();
                    let succeeded =
                        match worker_notifier.check_store(&worker_state.store, now).await {
                            Ok(()) => true,
                            Err(error) => {
                                tracing::error!(error = %error, "alert worker cycle failed");
                                false
                            }
                        };
                    worker_notifier.health.record_cycle(
                        now,
                        succeeded,
                        worker_notifier.outbox.pending_count(),
                    );
                }
            })
        },
    ));
}

pub(super) async fn supervise_alert_worker<F>(
    health: AlertWorkerHealth,
    restart_delay: Duration,
    mut spawn_worker: F,
) where
    F: FnMut() -> tokio::task::JoinHandle<()>,
{
    loop {
        health.mark_running(true);
        let result = spawn_worker().await;
        health.mark_running(false);
        health.record_restart();
        match result {
            Ok(()) => tracing::error!("alert worker stopped unexpectedly; restarting"),
            Err(error) => tracing::error!(
                cancelled = error.is_cancelled(),
                panicked = error.is_panic(),
                "alert worker failed unexpectedly; restarting"
            ),
        }
        tokio::time::sleep(restart_delay).await;
    }
}

#[derive(Debug, PartialEq, Eq)]
pub(super) struct TelegramAlertTarget {
    pub(super) token: String,
    pub(super) chats: Vec<String>,
}

impl TelegramAlertTarget {
    pub(super) fn from_url(url: &Url) -> Option<Self> {
        if url.scheme() != "telegram" {
            return None;
        }
        let username = url.username();
        if username.is_empty() {
            return None;
        }
        let token = match url.password() {
            Some(password) if !password.is_empty() => format!("{username}:{password}"),
            _ => username.to_string(),
        };
        let chats = url
            .query_pairs()
            .find_map(|(key, value)| {
                if key == "chats" || key == "channels" {
                    Some(
                        value
                            .split(',')
                            .map(str::trim)
                            .filter(|chat| !chat.is_empty())
                            .map(ToString::to_string)
                            .collect::<Vec<_>>(),
                    )
                } else {
                    None
                }
            })
            .filter(|chats| !chats.is_empty())?;

        Some(Self { token, chats })
    }
}

pub(super) fn telegram_alert_text(alert: &AlertEvent) -> String {
    format!(
        "Pharos {} alert\nHost: {}\nProblem: {}\nAge: {}\nNext: {}\nEvent: {}",
        alert.level,
        alert.host,
        alert.summary,
        duration_label(alert.age_seconds),
        alert.next_action,
        alert.event_id
    )
}

fn non_empty_env_value(value: &str) -> Option<String> {
    let trimmed = value.trim();
    if trimmed.is_empty() {
        None
    } else {
        Some(trimmed.to_string())
    }
}

pub(super) fn alert_webhook_url(
    pharos_url: Option<String>,
    watchtower_url: Option<String>,
    env_file: Option<String>,
) -> Option<String> {
    pharos_url
        .as_deref()
        .and_then(non_empty_env_value)
        .or_else(|| watchtower_url.as_deref().and_then(non_empty_env_value))
        .or_else(|| {
            env_file
                .as_deref()
                .and_then(alert_webhook_url_from_env_file)
        })
}

fn alert_webhook_url_from_env_file(path: &str) -> Option<String> {
    let path = non_empty_env_value(path)?;
    let contents = fs::read_to_string(path).ok()?;
    env_file_value(&contents, "WATCHTOWER_NOTIFICATION_URL")
        .as_deref()
        .and_then(non_empty_env_value)
}

fn env_file_value(contents: &str, key: &str) -> Option<String> {
    contents.lines().find_map(|line| {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            return None;
        }
        let line = line.strip_prefix("export ").unwrap_or(line).trim_start();
        let (name, value) = line.split_once('=')?;
        if name.trim() != key {
            return None;
        }
        Some(unquote_env_value(value.trim()).to_string())
    })
}

fn unquote_env_value(value: &str) -> &str {
    if value.len() < 2 {
        return value;
    }
    let bytes = value.as_bytes();
    let quoted = (bytes[0] == b'"' && bytes[value.len() - 1] == b'"')
        || (bytes[0] == b'\'' && bytes[value.len() - 1] == b'\'');
    if quoted {
        &value[1..value.len() - 1]
    } else {
        value
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn target_selection_is_explicit_and_telegram_urls_are_structured() {
        assert_eq!(
            alert_webhook_url(
                Some(" https://alerts.example.test/hook ".to_string()),
                Some("https://fallback.example.test/hook".to_string()),
                None,
            )
            .as_deref(),
            Some("https://alerts.example.test/hook")
        );
        let target = TelegramAlertTarget::from_url(
            &Url::parse("telegram://bot:token@telegram?chats=one,two").unwrap(),
        )
        .unwrap();
        assert_eq!(target.token, "bot:token");
        assert_eq!(target.chats, ["one", "two"]);
    }
}
