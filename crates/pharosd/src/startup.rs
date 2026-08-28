//! Fail-closed startup configuration and the container readiness probe.

use super::*;

pub(super) struct StartupConfig {
    pub(super) addr: SocketAddr,
    pub(super) auth: AuthConfig,
    pub(super) beacon_auth: BeaconAuth,
}

impl StartupConfig {
    pub(super) fn from_env() -> Result<Self, String> {
        let raw_addr = std::env::var("PHAROS_ADDR").unwrap_or_else(|_| "127.0.0.1:8080".into());
        let addr = raw_addr
            .parse::<SocketAddr>()
            .map_err(|err| format!("PHAROS_ADDR must be a numeric socket address: {err}"))?;
        let public_addr = env_nonempty("PHAROS_PUBLIC_ADDR")
            .map(|value| {
                value.parse::<SocketAddr>().map_err(|err| {
                    format!("PHAROS_PUBLIC_ADDR must be a numeric socket address: {err}")
                })
            })
            .transpose()?
            .unwrap_or(addr);
        let auth = AuthConfig::from_env(public_addr.ip().is_loopback())?;
        let beacon_auth = BeaconAuth::from_env()?;
        Ok(Self {
            addr,
            auth,
            beacon_auth,
        })
    }
}

pub(super) fn container_healthcheck_url(addr: SocketAddr) -> String {
    let loopback = match addr.ip() {
        IpAddr::V4(_) => IpAddr::V4(std::net::Ipv4Addr::LOCALHOST),
        IpAddr::V6(_) => IpAddr::V6(std::net::Ipv6Addr::LOCALHOST),
    };
    format!("http://{}/readyz", SocketAddr::new(loopback, addr.port()))
}

/// Resolves the readiness probe target from `PHAROS_ADDR`.
///
/// The daemon itself falls back to `127.0.0.1:8080` when the variable is
/// unset, but the container probe refuses to guess: a probe that silently
/// targets the default turns a misconfigured or non-daemon container into a
/// permanently red one with empty output (PHAROS-203).
pub(super) fn container_healthcheck_target(raw_addr: Option<&str>) -> Result<SocketAddr, String> {
    let raw = raw_addr
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .ok_or_else(|| {
            "PHAROS_ADDR is not set; refusing to probe the 127.0.0.1:8080 default. \
             Set PHAROS_ADDR to the daemon bind address, or give a non-daemon \
             container its own healthcheck (`pharos-beacon healthcheck`)"
                .to_string()
        })?;
    raw.parse::<SocketAddr>()
        .map_err(|err| format!("PHAROS_ADDR {raw:?} is not a numeric socket address: {err}"))
}

fn error_chain(error: &dyn std::error::Error) -> String {
    let mut message = error.to_string();
    let mut source = error.source();
    while let Some(cause) = source {
        message.push_str(": ");
        message.push_str(&cause.to_string());
        source = cause.source();
    }
    message
}

/// Probes one readiness URL and explains any failure so `docker inspect`
/// shows the reason instead of an empty log entry.
pub(super) async fn probe_readiness(url: &str) -> Result<String, String> {
    let client = reqwest::Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .connect_timeout(Duration::from_secs(1))
        .timeout(Duration::from_secs(2))
        .build()
        .map_err(|err| format!("could not build the readiness probe client: {err}"))?;
    match client.get(url).send().await {
        Ok(response) if response.status() == StatusCode::OK => {
            Ok(format!("ready: {url} answered 200"))
        }
        Ok(response) => Err(format!(
            "not ready: {url} answered HTTP {}",
            response.status().as_u16()
        )),
        Err(err) => Err(format!("unreachable: {url}: {}", error_chain(&err))),
    }
}

pub(super) async fn container_healthcheck() -> Result<String, String> {
    let raw_addr = std::env::var("PHAROS_ADDR").ok();
    let addr = container_healthcheck_target(raw_addr.as_deref())?;
    probe_readiness(&container_healthcheck_url(addr)).await
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn healthcheck_always_targets_the_matching_loopback_family() {
        let ipv4 = "0.0.0.0:8080".parse().unwrap();
        let ipv6 = "[::]:9090".parse().unwrap();

        assert_eq!(
            container_healthcheck_url(ipv4),
            "http://127.0.0.1:8080/readyz"
        );
        assert_eq!(container_healthcheck_url(ipv6), "http://[::1]:9090/readyz");
    }

    #[test]
    fn container_healthcheck_refuses_to_guess_the_bind_address() {
        let unset = container_healthcheck_target(None).unwrap_err();
        assert!(unset.contains("PHAROS_ADDR is not set"), "{unset}");
        assert!(unset.contains("127.0.0.1:8080"), "{unset}");
        assert!(unset.contains("pharos-beacon healthcheck"), "{unset}");

        let blank = container_healthcheck_target(Some("   ")).unwrap_err();
        assert!(blank.contains("PHAROS_ADDR is not set"), "{blank}");

        let invalid = container_healthcheck_target(Some("pharosd:8080")).unwrap_err();
        assert!(invalid.contains("\"pharosd:8080\""), "{invalid}");
        assert!(
            invalid.contains("not a numeric socket address"),
            "{invalid}"
        );

        assert_eq!(
            container_healthcheck_target(Some(" 0.0.0.0:8080 ")).unwrap(),
            "0.0.0.0:8080".parse::<SocketAddr>().unwrap()
        );
    }

    fn one_shot_http_fixture(status_line: &'static str) -> std::net::SocketAddr {
        use std::io::{Read, Write};

        let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("bind readiness fixture");
        let address = listener.local_addr().expect("fixture address");
        std::thread::spawn(move || {
            let (mut stream, _) = listener.accept().expect("accept readiness probe");
            let mut request = [0_u8; 1024];
            let _ = stream.read(&mut request);
            let _ = stream.write_all(
                format!("{status_line}\r\nContent-Length: 0\r\nConnection: close\r\n\r\n")
                    .as_bytes(),
            );
        });
        address
    }

    #[tokio::test]
    async fn readiness_probe_explains_every_verdict() {
        let ready = one_shot_http_fixture("HTTP/1.1 200 OK");
        let ready_url = container_healthcheck_url(ready);
        let detail = probe_readiness(&ready_url).await.unwrap();
        assert!(detail.contains("ready"), "{detail}");
        assert!(detail.contains(&ready_url), "{detail}");

        let draining = one_shot_http_fixture("HTTP/1.1 503 Service Unavailable");
        let draining_url = container_healthcheck_url(draining);
        let reason = probe_readiness(&draining_url).await.unwrap_err();
        assert!(reason.contains("HTTP 503"), "{reason}");
        assert!(reason.contains(&draining_url), "{reason}");

        let closed = std::net::TcpListener::bind("127.0.0.1:0").expect("reserve closed port");
        let closed_url = container_healthcheck_url(closed.local_addr().unwrap());
        drop(closed);
        let reason = probe_readiness(&closed_url).await.unwrap_err();
        assert!(reason.starts_with("unreachable: "), "{reason}");
        assert!(reason.contains(&closed_url), "{reason}");
    }
}
