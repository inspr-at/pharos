//! Read-only Pharos operator CLI (PHAROS-210, PHAROS-344). The page's data as plain
//! tables. No command changes anything.

use std::path::Path;
use std::time::Duration;

use reqwest::{Client, StatusCode};
use serde_json::Value;
use url::Url;

const USAGE: &str =
    "usage: pharos <health|version|hosts|beacon [HOST]|beacon last-seen [HOST]|cves|updates>";
const TOKEN_FILE_ENV: &str = "PHAROS_OPERATOR_TOKEN_FILE";
const FLEET_VIEW_SCHEMA: &str = "inspr.pharos.fleet-view.v1";

#[derive(Debug, PartialEq, Eq)]
enum Command {
    Health,
    Version,
    Hosts,
    Beacon(Option<String>),
    BeaconLastSeen(Option<String>),
    Cves,
    Updates,
}

impl Command {
    fn requires_auth(&self) -> bool {
        !matches!(self, Self::Health | Self::Version)
    }

    /// Where the command starts. Everything else comes from `/fleet.json`.
    fn path(&self) -> &'static str {
        match self {
            Self::Health => "healthz",
            Self::Version => "version",
            _ => "fleet.json",
        }
    }
}

fn parse_command(arguments: impl IntoIterator<Item = String>) -> Result<Command, String> {
    let values = arguments.into_iter().collect::<Vec<_>>();
    let values = values.iter().map(String::as_str).collect::<Vec<_>>();
    let host = |host: &str| valid_component(host).then(|| host.to_string());
    match values.as_slice() {
        ["health"] => Ok(Command::Health),
        ["version"] => Ok(Command::Version),
        ["hosts"] => Ok(Command::Hosts),
        ["cves"] => Ok(Command::Cves),
        ["updates"] => Ok(Command::Updates),
        ["beacon"] => Ok(Command::Beacon(None)),
        ["beacon", "last-seen"] => Ok(Command::BeaconLastSeen(None)),
        ["beacon", "last-seen", name] => host(name)
            .map(|name| Command::BeaconLastSeen(Some(name)))
            .ok_or_else(|| USAGE.to_string()),
        ["beacon", name] => host(name)
            .map(|name| Command::Beacon(Some(name)))
            .ok_or_else(|| USAGE.to_string()),
        _ => Err(USAGE.to_string()),
    }
}

fn valid_component(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 160
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.'))
}

/// `PHAROS_URL` may carry a mount; requests are made relative to it.
fn base_url() -> Result<Url, String> {
    let raw = std::env::var("PHAROS_URL").unwrap_or_else(|_| "http://127.0.0.1:8080".to_string());
    let mut url = Url::parse(&raw).map_err(|_| "PHAROS_URL is invalid".to_string())?;
    if !url.username().is_empty()
        || url.password().is_some()
        || url.query().is_some()
        || url.fragment().is_some()
        || !matches!(url.scheme(), "http" | "https")
        || (url.scheme() == "http"
            && !matches!(
                url.host_str(),
                Some("127.0.0.1" | "::1" | "[::1]" | "localhost")
            ))
    {
        return Err(
            "PHAROS_URL must be HTTPS, or HTTP on loopback, without credentials/query/fragment"
                .to_string(),
        );
    }
    if !url.path().ends_with('/') {
        let path = format!("{}/", url.path());
        url.set_path(&path);
    }
    Ok(url)
}

fn operator_token(path: &str) -> Result<String, String> {
    let path = Path::new(path);
    let metadata = std::fs::symlink_metadata(path)
        .map_err(|_| format!("{TOKEN_FILE_ENV} is not readable UTF-8"))?;
    if metadata.file_type().is_symlink() || !metadata.is_file() || metadata.len() > 4096 {
        return Err(format!("{TOKEN_FILE_ENV} is not a safe regular file"));
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        if metadata.permissions().mode() & 0o077 != 0 {
            return Err(format!(
                "{TOKEN_FILE_ENV} must not be accessible by group or others"
            ));
        }
    }
    let value = std::fs::read_to_string(path)
        .map_err(|_| format!("{TOKEN_FILE_ENV} is not readable UTF-8"))?;
    let value = value.trim_end_matches(['\r', '\n']).to_string();
    if value.is_empty() || value.len() > 4096 || value.chars().any(char::is_control) {
        return Err(format!("{TOKEN_FILE_ENV} contains an invalid credential"));
    }
    Ok(value)
}

/// The token when one is set up. Commands that need it fail without it.
fn configured_token(required: bool) -> Result<Option<String>, String> {
    match std::env::var(TOKEN_FILE_ENV) {
        Ok(path) => operator_token(&path).map(Some),
        Err(_) if required => Err(format!("{TOKEN_FILE_ENV} is required for this command")),
        Err(_) => Ok(None),
    }
}

async fn get(client: &Client, path: &str, token: Option<&str>) -> Result<String, String> {
    let url = base_url()?
        .join(path)
        .map_err(|_| "could not construct the Pharos request".to_string())?;
    let mut request = client.get(url);
    if let Some(token) = token {
        request = request.bearer_auth(token);
    }
    let response = request
        .send()
        .await
        .map_err(|_| "Pharos is unavailable".to_string())?;
    let status = response.status();
    if status == StatusCode::UNAUTHORIZED {
        return Err("Pharos rejected the operator token".to_string());
    }
    if !status.is_success() {
        return Err(format!(
            "Pharos request failed with HTTP {}",
            status.as_u16()
        ));
    }
    response
        .text()
        .await
        .map_err(|_| "Pharos returned an unreadable response".to_string())
}

fn parse_fleet(body: &str) -> Result<Value, String> {
    let mut fleet: Value =
        serde_json::from_str(body).map_err(|_| "Pharos returned malformed JSON".to_string())?;
    if fleet.get("schema").and_then(Value::as_str) != Some(FLEET_VIEW_SCHEMA) {
        return Err("Pharos returned an unknown fleet view".to_string());
    }
    without_controls(&mut fleet);
    Ok(fleet)
}

/// Text from the server reaches a terminal only without control characters.
fn printable(text: &str) -> String {
    text.chars()
        .map(|c| if c.is_control() { '?' } else { c })
        .collect()
}

fn without_controls(value: &mut Value) {
    match value {
        Value::String(text) => *text = printable(text),
        Value::Array(items) => items.iter_mut().for_each(without_controls),
        Value::Object(fields) => fields.values_mut().for_each(without_controls),
        _ => {}
    }
}

/// What to print, and whether the command succeeded.
struct Output {
    text: String,
    healthy: bool,
}

async fn run(command: &Command) -> Result<Output, String> {
    let client = Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .timeout(Duration::from_secs(15))
        .build()
        .map_err(|_| "could not initialize the HTTP client".to_string())?;
    let token = configured_token(command.requires_auth())?;
    let first = get(
        &client,
        command.path(),
        token.as_deref().filter(|_| command.requires_auth()),
    )
    .await?;
    let fleet = match (command.requires_auth(), &token) {
        (true, _) => Some(parse_fleet(&first)?),
        (false, Some(token)) => Some(parse_fleet(
            &get(&client, "fleet.json", Some(token)).await?,
        )?),
        (false, None) => None,
    };
    render(command, &first, fleet.as_ref())
}

fn render(command: &Command, first: &str, fleet: Option<&Value>) -> Result<Output, String> {
    let text = |text| {
        Ok(Output {
            text,
            healthy: true,
        })
    };
    match (command, fleet) {
        (Command::Health, fleet) => Ok(render_health(first, fleet)),
        (Command::Version, fleet) => text(render_version(first, fleet)?),
        (Command::Hosts, Some(fleet)) => text(render_hosts(fleet)),
        (Command::Beacon(host), Some(fleet)) => text(render_beacon(fleet, host.as_deref(), true)?),
        (Command::BeaconLastSeen(host), Some(fleet)) => {
            text(render_beacon(fleet, host.as_deref(), false)?)
        }
        (Command::Cves, Some(fleet)) => text(render_cves(fleet)),
        (Command::Updates, Some(fleet)) => text(render_updates(fleet)),
        _ => Err(USAGE.to_string()),
    }
}

fn field<'a>(value: &'a Value, key: &str) -> &'a str {
    value.get(key).and_then(Value::as_str).unwrap_or_default()
}

fn count(value: &Value, section: &str, key: &str) -> u64 {
    value
        .get(section)
        .and_then(|section| section.get(key))
        .and_then(Value::as_u64)
        .unwrap_or_default()
}

fn items<'a>(value: &'a Value, key: &str) -> &'a [Value] {
    value
        .get(key)
        .and_then(Value::as_array)
        .map_or(&[], Vec::as_slice)
}

fn or_dash(value: &str) -> String {
    if value.is_empty() {
        "-".to_string()
    } else {
        value.to_string()
    }
}

fn lower_first(value: &str) -> String {
    let mut chars = value.chars();
    chars.next().map_or_else(String::new, |first| {
        first.to_lowercase().chain(chars).collect()
    })
}

/// Columns padded to their widest cell. The server's words reach a terminal, so
/// control characters don't get through.
fn table(headers: &[&str], rows: &[Vec<String>]) -> String {
    let mut widths: Vec<usize> = headers
        .iter()
        .map(|header| header.chars().count())
        .collect();
    for row in rows {
        for (width, cell) in widths.iter_mut().zip(row) {
            *width = (*width).max(printable(cell).chars().count());
        }
    }
    let line = |cells: Vec<String>| {
        let last = cells.len().saturating_sub(1);
        cells
            .iter()
            .enumerate()
            .map(|(index, cell)| {
                if index == last {
                    cell.clone()
                } else {
                    format!("{cell:<width$}", width = widths[index])
                }
            })
            .collect::<Vec<_>>()
            .join("  ")
    };
    let mut lines = vec![line(headers.iter().map(ToString::to_string).collect())];
    lines.extend(
        rows.iter()
            .map(|row| line(row.iter().map(|cell| printable(cell)).collect())),
    );
    lines.join("\n")
}

fn render_health(status: &str, fleet: Option<&Value>) -> Output {
    let status = printable(status.trim());
    let Some(fleet) = fleet else {
        return Output {
            text: status.to_string(),
            healthy: status == "ok",
        };
    };
    let data = fleet.get("data_file").unwrap_or(&Value::Null);
    let updated = field(data, "updated_ago");
    let problem = field(data, "problem");
    let configured = data.get("configured").and_then(Value::as_bool) == Some(true);
    let (file, file_ok) = match (configured, problem.is_empty(), updated.is_empty()) {
        (false, _, _) => ("no data file configured".to_string(), true),
        (true, false, true) => (format!("data file can't be used: {problem}"), false),
        (true, false, false) => (
            format!("data file invalid: {problem}; showing the last good file from {updated}"),
            false,
        ),
        (true, true, true) => ("data file not loaded yet".to_string(), false),
        (true, true, false) => (format!("data file valid, updated {updated}"), true),
    };
    let text = format!(
        "{status} · server up {} · {file}\nbeacons: {} reporting · {} offline · {} never reported",
        field(fleet, "uptime"),
        count(fleet, "beacons", "reporting"),
        count(fleet, "beacons", "offline"),
        count(fleet, "beacons", "never_reported"),
    );
    Output {
        text,
        healthy: status == "ok" && file_ok,
    }
}

fn render_version(body: &str, fleet: Option<&Value>) -> Result<String, String> {
    let mut version: Value =
        serde_json::from_str(body).map_err(|_| "Pharos returned malformed JSON".to_string())?;
    validate_version_response(&version)?;
    without_controls(&mut version);
    let mut text = format!("pharos {}", field(&version, "version"));
    if let Some(fleet) = fleet {
        text.push_str(&format!(
            "\ndata file schema {} · {} hosts · {} watched CVEs",
            count(fleet, "data_file", "schema_version"),
            count(fleet, "data_file", "hosts"),
            count(fleet, "data_file", "watched_cves"),
        ));
    }
    Ok(text)
}

fn render_hosts(fleet: &Value) -> String {
    let rows: Vec<Vec<String>> = items(fleet, "hosts")
        .iter()
        .map(|host| {
            let mut security = lower_first(field(host, "security")).replace(" · ", ", ");
            for (key, word) in [
                ("reboot_due", "reboot due"),
                ("hand_declared", "declared"),
                ("stale", "stale"),
            ] {
                if host.get(key).and_then(Value::as_bool) == Some(true) {
                    security.push_str(" · ");
                    security.push_str(word);
                }
            }
            vec![
                field(host, "name").to_string(),
                or_dash(&field(host, "site").to_lowercase()),
                field(host, "source").to_lowercase(),
                field(host, "contact").to_string(),
                security,
            ]
        })
        .collect();
    format!(
        "{}\n{} hosts · {} affected · {} can't check",
        table(&["HOST", "SITE", "SOURCE", "CONTACT", "SECURITY"], &rows),
        count(fleet, "summary", "hosts"),
        count(fleet, "summary", "affected"),
        count(fleet, "summary", "cant_check"),
    )
}

fn render_beacon(fleet: &Value, only: Option<&str>, kernels: bool) -> Result<String, String> {
    let hosts: Vec<&Value> = items(fleet, "hosts")
        .iter()
        .filter(|host| host.get("beacon").and_then(Value::as_bool) == Some(true))
        .filter(|host| only.is_none_or(|name| field(host, "name") == name))
        .collect();
    if only.is_some() && hosts.is_empty() {
        return Err("host was not found".to_string());
    }
    let last_seen = |host: &Value| match field(host, "last_seen") {
        "" => "never".to_string(),
        seen => seen.to_string(),
    };
    if !kernels {
        let rows: Vec<Vec<String>> = hosts
            .iter()
            .map(|host| vec![field(host, "name").to_string(), last_seen(host)])
            .collect();
        return Ok(table(&["HOST", "LAST SEEN"], &rows));
    }
    let rows: Vec<Vec<String>> = hosts
        .iter()
        .map(|host| {
            vec![
                field(host, "name").to_string(),
                last_seen(host),
                or_dash(field(host, "running")),
                or_dash(field(host, "next_boot")),
            ]
        })
        .collect();
    Ok(table(&["HOST", "LAST SEEN", "RUNNING", "NEXT BOOT"], &rows))
}

fn render_cves(fleet: &Value) -> String {
    let rows: Vec<Vec<String>> = items(fleet, "cves")
        .iter()
        .map(|cve| {
            ["id", "severity", "state", "source", "hosts"]
                .iter()
                .map(|key| field(cve, key).to_string())
                .collect()
        })
        .collect();
    table(&["ID", "SEV", "STATE", "SOURCE", "HOSTS"], &rows)
}

fn render_updates(fleet: &Value) -> String {
    let updates = items(fleet, "updates");
    let in_state = |states: &[&str]| {
        updates
            .iter()
            .filter(|update| states.contains(&field(update, "state")))
            .count()
    };
    let rows: Vec<Vec<String>> = updates
        .iter()
        .filter(|update| field(update, "state") == "due")
        .map(|update| {
            let mut source = format!("{} {}", field(update, "source"), field(update, "age"))
                .trim_end()
                .to_string();
            if update.get("stale").and_then(Value::as_bool) == Some(true) {
                source.push_str(" · stale");
            }
            vec![
                field(update, "host").to_string(),
                field(update, "due")
                    .split(" · ")
                    .map(lower_first)
                    .collect::<Vec<_>>()
                    .join(" · "),
                source,
            ]
        })
        .collect();
    format!(
        "{}\n{} hand-declared · {} up to date · {} can't tell",
        table(&["HOST", "DUE", "SOURCE"], &rows),
        in_state(&["hand_declared"]),
        in_state(&["up_to_date"]),
        in_state(&["unknown", "last_known"]),
    )
}

fn validate_version_response(value: &Value) -> Result<(), String> {
    let scheme = value
        .get("version_scheme")
        .and_then(Value::as_str)
        .ok_or_else(|| "Pharos version response has no explicit version scheme".to_string())?;
    let version = value
        .get("version")
        .and_then(Value::as_str)
        .ok_or_else(|| "Pharos version response is missing version".to_string())?;
    let channel = value
        .get("release_channel")
        .and_then(Value::as_str)
        .ok_or_else(|| "Pharos version response is missing release channel".to_string())?;
    let sequence = value
        .get("release_sequence")
        .and_then(Value::as_u64)
        .ok_or_else(|| "Pharos version response is missing release sequence".to_string())?;
    if channel != "stable" {
        return Err("Pharos version response has an unknown release channel".to_string());
    }
    match scheme {
        "legacy" if sequence == 0 && valid_legacy_version(version) => Ok(()),
        "inspr-calendar-v1" if sequence > 0 && valid_calendar_version(version) => Ok(()),
        "inspr-calendar-v2" | "inspr-calver-3"
            if sequence > 0 && valid_calendar_v2_version(version) =>
        {
            Ok(())
        }
        "legacy" | "inspr-calendar-v1" | "inspr-calendar-v2" | "inspr-calver-3" => {
            Err("Pharos version response has invalid release metadata".to_string())
        }
        _ => Err("Pharos version response has an unknown version scheme".to_string()),
    }
}

fn valid_legacy_version(value: &str) -> bool {
    let parts = value.split('.').collect::<Vec<_>>();
    parts.len() == 3
        && parts.iter().all(|part| {
            !part.is_empty()
                && part.bytes().all(|byte| byte.is_ascii_digit())
                && (part == &"0" || !part.starts_with('0'))
        })
}

/// INSPR calendar v2 (PHAROS-259) and INSPR-CalVer3, which keep one format: exactly
/// `YYMMDDhhmmss.0.0` with a real UTC date. The CLI keeps its own copy so it stays independent of pharos-core.
fn valid_calendar_v2_version(value: &str) -> bool {
    let parts = value.split('.').collect::<Vec<_>>();
    let [stamp, minor, patch] = parts.as_slice() else {
        return false;
    };
    if *minor != "0" || *patch != "0" {
        return false;
    }
    if stamp.len() != 12
        || !stamp.bytes().all(|byte| byte.is_ascii_digit())
        || stamp.starts_with('0')
    {
        return false;
    }
    let field = |start: usize| stamp[start..start + 2].parse::<u32>().unwrap_or(u32::MAX);
    let (year, month, day, hour, minute, second) = (
        2000 + field(0),
        field(2),
        field(4),
        field(6),
        field(8),
        field(10),
    );
    let leap = year % 4 == 0 && (year % 100 != 0 || year % 400 == 0);
    let days = match month {
        1 | 3 | 5 | 7 | 8 | 10 | 12 => 31,
        4 | 6 | 9 | 11 => 30,
        2 if leap => 29,
        2 => 28,
        _ => return false,
    };
    (1..=days).contains(&day) && hour < 24 && minute < 60 && second < 60
}

fn valid_calendar_version(value: &str) -> bool {
    let parts = value.split('.').collect::<Vec<_>>();
    if parts.len() != 6
        || parts
            .iter()
            .any(|part| part.len() != 2 || !part.bytes().all(|byte| byte.is_ascii_digit()))
    {
        return false;
    }
    let numbers = parts
        .iter()
        .map(|part| part.parse::<u32>())
        .collect::<Result<Vec<_>, _>>();
    let Ok(numbers) = numbers else {
        return false;
    };
    let (year, month, day, hour, minute, second) = (
        2000 + numbers[0],
        numbers[1],
        numbers[2],
        numbers[3],
        numbers[4],
        numbers[5],
    );
    let leap = year % 4 == 0 && (year % 100 != 0 || year % 400 == 0);
    let days = match month {
        1 | 3 | 5 | 7 | 8 | 10 | 12 => 31,
        4 | 6 | 9 | 11 => 30,
        2 if leap => 29,
        2 => 28,
        _ => return false,
    };
    (1..=days).contains(&day) && hour < 24 && minute < 60 && second < 60
}

#[tokio::main]
async fn main() {
    let command = match parse_command(std::env::args().skip(1)) {
        Ok(command) => command,
        Err(error) => {
            eprintln!("{error}");
            std::process::exit(2);
        }
    };
    match run(&command).await {
        Ok(output) => {
            println!("{}", output.text);
            if !output.healthy {
                std::process::exit(1);
            }
        }
        Err(error) => {
            eprintln!("pharos: {error}");
            std::process::exit(1);
        }
    }
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;

    fn fleet() -> Value {
        json!({
            "schema": FLEET_VIEW_SCHEMA,
            "uptime": "3 d",
            "data_file": {
                "configured": true, "problem": null, "schema_version": 3,
                "updated_ago": "2 h ago", "hosts": 2, "watched_cves": 1
            },
            "summary": {"hosts": 2, "affected": 1, "cant_check": 1, "reboots_due": 1},
            "beacons": {"reporting": 1, "offline": 0, "never_reported": 1},
            "hosts": [
                {"name": "ares", "site": "Home", "source": "Beacon", "contact": "online 2m",
                 "beacon": true, "last_seen": "2m", "running": "6.18.52", "next_boot": "6.18.56",
                 "security": "1 critical · 1 high", "reboot_due": true, "hand_declared": false,
                 "stale": false},
                {"name": "hermes", "site": null, "source": "Hand-declared", "contact": "never",
                 "beacon": true, "last_seen": null, "running": null, "next_boot": null,
                 "security": "Can't check", "reboot_due": false, "hand_declared": true,
                 "stale": true}
            ],
            "cves": [{"id": "CVE-2000-1001", "severity": "critical", "state": "open",
                      "source": "kernel", "hosts": "1 affected · 1 can't check"}],
            "updates": [
                {"host": "ares", "state": "due", "due": "Reboot due · 3 commits behind · Lock 74 d old",
                 "source": "beacon", "age": "2m", "stale": true},
                {"host": "hermes", "state": "unknown", "due": "", "source": "nothing",
                 "age": null, "stale": false}
            ]
        })
    }

    fn command(words: &[&str]) -> Result<Command, String> {
        parse_command(words.iter().map(ToString::to_string))
    }

    #[test]
    fn the_command_surface_only_reads() {
        for (words, expected) in [
            (vec!["health"], Command::Health),
            (vec!["version"], Command::Version),
            (vec!["hosts"], Command::Hosts),
            (vec!["cves"], Command::Cves),
            (vec!["updates"], Command::Updates),
            (vec!["beacon"], Command::Beacon(None)),
            (vec!["beacon", "ares"], Command::Beacon(Some("ares".into()))),
            (vec!["beacon", "last-seen"], Command::BeaconLastSeen(None)),
            (
                vec!["beacon", "last-seen", "ares"],
                Command::BeaconLastSeen(Some("ares".into())),
            ),
        ] {
            assert_eq!(command(&words).unwrap(), expected);
        }
        for retired in [
            vec!["declared"],
            vec!["declared", "status"],
            vec!["proof", "ares"],
            vec!["job", "setup-1"],
            vec!["create"],
            vec!["beacon", "../etc"],
            vec![],
        ] {
            assert!(command(&retired).is_err(), "{retired:?}");
        }
    }

    #[test]
    fn only_health_and_version_work_without_a_token() {
        assert!(!Command::Health.requires_auth());
        assert!(!Command::Version.requires_auth());
        for command in [
            Command::Hosts,
            Command::Beacon(None),
            Command::BeaconLastSeen(None),
            Command::Cves,
            Command::Updates,
        ] {
            assert!(command.requires_auth(), "{command:?}");
            assert_eq!(command.path(), "fleet.json");
        }
    }

    #[test]
    fn hosts_are_a_table_with_every_row_and_a_summary() {
        assert_eq!(
            render_hosts(&fleet()),
            "HOST    SITE  SOURCE         CONTACT    SECURITY\n\
             ares    home  beacon         online 2m  1 critical, 1 high · reboot due\n\
             hermes  -     hand-declared  never      can't check · declared · stale\n\
             2 hosts · 1 affected · 1 can't check"
        );
    }

    #[test]
    fn beacons_show_last_seen_and_kernels_and_find_one_host() {
        assert_eq!(
            render_beacon(&fleet(), None, true).unwrap(),
            "HOST    LAST SEEN  RUNNING  NEXT BOOT\n\
             ares    2m         6.18.52  6.18.56\n\
             hermes  never      -        -"
        );
        assert_eq!(
            render_beacon(&fleet(), Some("ares"), false).unwrap(),
            "HOST  LAST SEEN\nares  2m"
        );
        assert_eq!(
            render_beacon(&fleet(), Some("nobody"), true).unwrap_err(),
            "host was not found"
        );
    }

    #[test]
    fn cves_and_updates_use_the_servers_words() {
        assert_eq!(
            render_cves(&fleet()),
            "ID             SEV       STATE  SOURCE  HOSTS\n\
             CVE-2000-1001  critical  open   kernel  1 affected · 1 can't check"
        );
        assert_eq!(
            render_updates(&fleet()),
            "HOST  DUE                                            SOURCE\n\
             ares  reboot due · 3 commits behind · lock 74 d old  beacon 2m · stale\n\
             0 hand-declared · 0 up to date · 1 can't tell"
        );
    }

    #[test]
    fn health_says_ok_only_when_the_data_file_is_fine() {
        let plain = render_health("ok\n", None);
        assert_eq!(plain.text, "ok");
        assert!(plain.healthy);

        let good = render_health("ok", Some(&fleet()));
        assert_eq!(
            good.text,
            "ok · server up 3 d · data file valid, updated 2 h ago\n\
             beacons: 1 reporting · 0 offline · 1 never reported"
        );
        assert!(good.healthy);

        let mut invalid = fleet();
        invalid["data_file"]["problem"] = json!("unsupported schema_version 9");
        let bad = render_health("ok", Some(&invalid));
        assert!(!bad.healthy);
        assert!(
            bad.text.contains("data file invalid: unsupported"),
            "{}",
            bad.text
        );
        assert!(
            bad.text.contains("last good file from 2 h ago"),
            "{}",
            bad.text
        );

        invalid["data_file"]["updated_ago"] = Value::Null;
        let none = render_health("ok", Some(&invalid));
        assert!(!none.healthy);
        assert!(none.text.contains("can't be used"), "{}", none.text);

        let mut loading = fleet();
        loading["data_file"]["updated_ago"] = Value::Null;
        assert!(!render_health("ok", Some(&loading)).healthy);

        let mut unconfigured = fleet();
        unconfigured["data_file"]["configured"] = json!(false);
        unconfigured["data_file"]["updated_ago"] = Value::Null;
        let quiet = render_health("ok", Some(&unconfigured));
        assert!(quiet.healthy);
        assert!(
            quiet.text.contains("no data file configured"),
            "{}",
            quiet.text
        );

        assert!(!render_health("starting", None).healthy);
    }

    #[test]
    fn version_adds_the_data_file_when_a_token_is_there() {
        let version = json!({
            "version_scheme": "inspr-calver-3",
            "version": "261101120000.0.0",
            "release_channel": "stable",
            "release_sequence": 28
        })
        .to_string();
        assert_eq!(
            render_version(&version, None).unwrap(),
            "pharos 261101120000.0.0"
        );
        assert_eq!(
            render_version(&version, Some(&fleet())).unwrap(),
            "pharos 261101120000.0.0\ndata file schema 3 · 2 hosts · 1 watched CVEs"
        );
    }

    #[test]
    fn an_unknown_fleet_view_is_refused() {
        assert!(parse_fleet(r#"{"schema":"other"}"#).is_err());
        assert!(parse_fleet("not json").is_err());
        assert!(parse_fleet(&fleet().to_string()).is_ok());
    }

    #[test]
    fn a_control_character_from_the_server_does_not_reach_the_terminal() {
        let printed = table(&["HOST"], &[vec!["ar\u{1b}[31mes".to_string()]]);
        assert!(!printed.contains('\u{1b}'), "{printed:?}");

        let fleet = parse_fleet(
            &json!({
                "schema": FLEET_VIEW_SCHEMA,
                "uptime": "1 h\u{1b}[2J",
                "data_file": { "configured": true, "problem": "bad\u{1b}[2J\nline" },
            })
            .to_string(),
        )
        .unwrap();
        for printed in [
            render_health("ok", Some(&fleet)).text,
            render_health("ok\u{1b}[2J", None).text,
        ] {
            assert!(!printed.contains('\u{1b}'), "{printed:?}");
            assert!(!printed.contains("\nline"), "{printed:?}");
        }
    }

    #[test]
    fn version_view_accepts_explicit_calendar_and_legacy_metadata() {
        for body in [
            json!({
                "version_scheme": "inspr-calendar-v1",
                "version": "26.09.01.13.29.31",
                "release_channel": "stable",
                "release_sequence": 1
            }),
            json!({
                "version_scheme": "legacy",
                "version": "0.2.0",
                "release_channel": "stable",
                "release_sequence": 0
            }),
            json!({
                "version_scheme": "inspr-calendar-v2",
                "version": "260909194540.0.0",
                "release_channel": "stable",
                "release_sequence": 6
            }),
        ] {
            assert!(render_version(&body.to_string(), None).is_ok());
        }
    }

    #[test]
    fn version_view_fails_closed_on_ambiguous_or_invalid_metadata() {
        for body in [
            json!({"version": "26.09.01"}),
            json!({
                "version_scheme": "inspr-calendar-v2",
                "version": "26.09.01.13.29.31",
                "release_channel": "stable",
                "release_sequence": 1
            }),
            json!({
                "version_scheme": "inspr-calendar-v1",
                "version": "260909194540.0.0",
                "release_channel": "stable",
                "release_sequence": 6
            }),
            json!({
                "version_scheme": "inspr-calendar-v3",
                "version": "260909194540.0.0",
                "release_channel": "stable",
                "release_sequence": 6
            }),
            json!({
                "version_scheme": "inspr-calendar-v2",
                "version": "260909194540.0.0-rc1",
                "release_channel": "stable",
                "release_sequence": 6
            }),
            json!({
                "version_scheme": "inspr-calendar-v1",
                "version": "26.02.29.13.29.31",
                "release_channel": "stable",
                "release_sequence": 1
            }),
            json!({
                "version_scheme": "inspr-calendar-v1",
                "version": "٢٦.09.01.13.29.31",
                "release_channel": "stable",
                "release_sequence": 1
            }),
        ] {
            assert!(render_version(&body.to_string(), None).is_err());
        }
    }
}
