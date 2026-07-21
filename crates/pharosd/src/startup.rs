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

pub(super) async fn container_healthcheck() -> bool {
    let addr = std::env::var("PHAROS_ADDR")
        .unwrap_or_else(|_| "127.0.0.1:8080".to_string())
        .parse::<SocketAddr>();
    let Ok(addr) = addr else {
        return false;
    };
    let Ok(client) = reqwest::Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .connect_timeout(Duration::from_secs(1))
        .timeout(Duration::from_secs(2))
        .build()
    else {
        return false;
    };
    client
        .get(container_healthcheck_url(addr))
        .send()
        .await
        .is_ok_and(|response| response.status() == StatusCode::OK)
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
}
