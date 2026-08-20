//! Read-only Pharos operator CLI (PHAROS-210).

use std::path::Path;
use std::time::Duration;

use reqwest::{Client, StatusCode};
use serde_json::{json, Value};
use url::Url;

const USAGE: &str = "usage: pharos <health|version|hosts|declared [status]|beacon last-seen [HOST]|proof HOST|job ID>";

#[derive(Debug, PartialEq, Eq)]
enum Command {
    Health,
    Version,
    Hosts,
    DeclaredStatus,
    BeaconLastSeen(Option<String>),
    Proof(String),
    Job(String),
}

impl Command {
    fn requires_auth(&self) -> bool {
        !matches!(self, Self::Health | Self::Version)
    }

    fn path(&self) -> String {
        match self {
            Self::Health => "/healthz".to_string(),
            Self::Version => "/version".to_string(),
            Self::Hosts | Self::BeaconLastSeen(_) => "/hosts.json".to_string(),
            Self::DeclaredStatus => "/declared-hosts.json".to_string(),
            Self::Proof(host) => format!("/proof/{host}"),
            Self::Job(id) => format!("/setup/provisioning-jobs/{id}"),
        }
    }
}

fn parse_command(arguments: impl IntoIterator<Item = String>) -> Result<Command, String> {
    let values = arguments.into_iter().collect::<Vec<_>>();
    match values.as_slice() {
        [command] if command == "health" => Ok(Command::Health),
        [command] if command == "version" => Ok(Command::Version),
        [command] if command == "hosts" => Ok(Command::Hosts),
        [command] if command == "declared" => Ok(Command::DeclaredStatus),
        [command, subcommand] if command == "declared" && subcommand == "status" => {
            Ok(Command::DeclaredStatus)
        }
        [command, subcommand] if command == "beacon" && subcommand == "last-seen" => {
            Ok(Command::BeaconLastSeen(None))
        }
        [command, subcommand, host]
            if command == "beacon" && subcommand == "last-seen" && valid_component(host) =>
        {
            Ok(Command::BeaconLastSeen(Some(host.clone())))
        }
        [command, host] if command == "proof" && valid_component(host) => {
            Ok(Command::Proof(host.clone()))
        }
        [command, id] if command == "job" && valid_component(id) => Ok(Command::Job(id.clone())),
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

fn base_url() -> Result<Url, String> {
    let raw = std::env::var("PHAROS_URL").unwrap_or_else(|_| "http://127.0.0.1:8080".to_string());
    let mut url = Url::parse(&raw).map_err(|_| "PHAROS_URL is invalid".to_string())?;
    if !url.username().is_empty()
        || url.password().is_some()
        || url.query().is_some()
        || url.fragment().is_some()
        || !matches!(url.scheme(), "http" | "https")
        || (url.scheme() == "http"
            && !matches!(url.host_str(), Some("127.0.0.1" | "::1" | "localhost")))
    {
        return Err(
            "PHAROS_URL must be HTTPS, or HTTP on loopback, without credentials/query/fragment"
                .to_string(),
        );
    }
    url.set_path("/");
    Ok(url)
}

fn operator_token() -> Result<String, String> {
    let path = std::env::var("PHAROS_OPERATOR_TOKEN_FILE")
        .map_err(|_| "PHAROS_OPERATOR_TOKEN_FILE is required for this command".to_string())?;
    let path = Path::new(&path);
    let metadata = std::fs::symlink_metadata(path)
        .map_err(|_| "PHAROS_OPERATOR_TOKEN_FILE is not readable UTF-8".to_string())?;
    if metadata.file_type().is_symlink() || !metadata.is_file() || metadata.len() > 4096 {
        return Err("PHAROS_OPERATOR_TOKEN_FILE is not a safe regular file".to_string());
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        if metadata.permissions().mode() & 0o077 != 0 {
            return Err(
                "PHAROS_OPERATOR_TOKEN_FILE must not be accessible by group or others".to_string(),
            );
        }
    }
    let value = std::fs::read_to_string(path)
        .map_err(|_| "PHAROS_OPERATOR_TOKEN_FILE is not readable UTF-8".to_string())?;
    let value = value.trim_end_matches(['\r', '\n']).to_string();
    if value.is_empty() || value.len() > 4096 || value.chars().any(char::is_control) {
        return Err("PHAROS_OPERATOR_TOKEN_FILE contains an invalid credential".to_string());
    }
    Ok(value)
}

async fn request(command: &Command) -> Result<(StatusCode, String), String> {
    let client = Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .timeout(Duration::from_secs(15))
        .build()
        .map_err(|_| "could not initialize the HTTP client".to_string())?;
    let url = base_url()?
        .join(&command.path())
        .map_err(|_| "could not construct the Pharos request".to_string())?;
    let mut request = client.get(url);
    if command.requires_auth() {
        request = request.bearer_auth(operator_token()?);
    }
    let response = request
        .send()
        .await
        .map_err(|_| "Pharos is unavailable".to_string())?;
    let status = response.status();
    let body = response
        .text()
        .await
        .map_err(|_| "Pharos returned an unreadable response".to_string())?;
    Ok((status, body))
}

fn render(command: &Command, status: StatusCode, body: &str) -> Result<String, String> {
    if !status.is_success() {
        return Err(format!(
            "Pharos request failed with HTTP {}",
            status.as_u16()
        ));
    }
    if matches!(command, Command::Health) {
        return Ok(body.trim().to_string());
    }
    let value: Value =
        serde_json::from_str(body).map_err(|_| "Pharos returned malformed JSON".to_string())?;
    let value = match command {
        Command::BeaconLastSeen(host_filter) => {
            let hosts = value
                .get("hosts")
                .and_then(Value::as_array)
                .ok_or_else(|| "Pharos hosts response is missing hosts".to_string())?;
            let entries = hosts
                .iter()
                .filter(|host| {
                    host_filter.as_ref().is_none_or(|expected| {
                        host.get("name").and_then(Value::as_str) == Some(expected.as_str())
                    })
                })
                .map(|host| {
                    json!({
                        "host": host.get("name"),
                        "last_seen": host.get("last_seen"),
                        "liveness": host.get("liveness"),
                    })
                })
                .collect::<Vec<_>>();
            if host_filter.is_some() && entries.is_empty() {
                return Err("host was not found".to_string());
            }
            json!({ "beacons": entries })
        }
        _ => value,
    };
    serde_json::to_string_pretty(&value)
        .map_err(|_| "could not render the Pharos response".to_string())
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
    let result = match request(&command).await {
        Ok((status, body)) => render(&command, status, &body),
        Err(error) => Err(error),
    };
    match result {
        Ok(output) => println!("{output}"),
        Err(error) => {
            eprintln!("pharos: {error}");
            std::process::exit(1);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn command_surface_is_read_only_and_does_not_wrap_agent_routes() {
        let commands = [
            parse_command(["health".to_string()]).unwrap(),
            parse_command(["version".to_string()]).unwrap(),
            parse_command(["hosts".to_string()]).unwrap(),
            parse_command(["declared".to_string(), "status".to_string()]).unwrap(),
            parse_command([
                "beacon".to_string(),
                "last-seen".to_string(),
                "ares".to_string(),
            ])
            .unwrap(),
            parse_command(["proof".to_string(), "ares".to_string()]).unwrap(),
            parse_command(["job".to_string(), "setup-1".to_string()]).unwrap(),
        ];
        assert!(commands
            .iter()
            .all(|command| !command.path().starts_with("/agent/")));
        assert!(commands
            .iter()
            .all(|command| !command.path().contains("confirm")));
        assert!(parse_command(["create".to_string()]).is_err());
    }

    #[test]
    fn protected_commands_require_machine_operator_auth() {
        assert!(!Command::Health.requires_auth());
        assert!(!Command::Version.requires_auth());
        assert!(Command::Hosts.requires_auth());
        assert!(Command::Proof("ares".to_string()).requires_auth());
    }

    #[test]
    fn beacon_view_contains_only_observation_fields() {
        let body = serde_json::to_string(&json!({
            "hosts": [{
                "name": "ares",
                "last_seen": 42,
                "liveness": "live",
                "role": "server"
            }]
        }))
        .unwrap();
        let output = render(&Command::BeaconLastSeen(None), StatusCode::OK, &body).unwrap();
        assert!(output.contains("last_seen"));
        assert!(!output.contains("role"));
    }
}
