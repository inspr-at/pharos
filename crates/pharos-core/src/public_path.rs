//! Optional native public base path and public origin helpers (PHAROS-258).
//!
//! Empty base path means today's standalone origin-root. A configured value is
//! a canonical ASCII absolute path of one or more `[A-Za-z0-9_-]` segments.
//! `public_origin` is scheme+host separately and never carries a path.

use std::fmt;

const SEGMENT_ALPHABET: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789_-";

/// Canonical public mount: empty string or `/segment[/segment...]`.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct PublicBasePath(String);

/// Scheme and host of the customer address. Path, query, fragment, and
/// credentials are forbidden.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PublicOrigin {
    pub scheme: String,
    pub host: String,
}

impl PublicBasePath {
    pub const ROOT: Self = Self(String::new());
    pub const ROOT_REF: &'static Self = &Self::ROOT;

    pub fn root() -> Self {
        Self::ROOT
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }

    pub fn is_root(&self) -> bool {
        self.0.is_empty()
    }

    /// Standalone `/` or the configured prefix with no trailing slash.
    pub fn home(&self) -> &str {
        if self.0.is_empty() {
            "/"
        } else {
            &self.0
        }
    }

    pub fn parse(value: &str) -> Result<Self, String> {
        Ok(Self(normalize_public_base_path(value)?))
    }

    pub fn from_env_value(value: Option<&str>) -> Result<Self, String> {
        match value.map(str::trim).filter(|value| !value.is_empty()) {
            None => Ok(Self::root()),
            Some(value) => Self::parse(value),
        }
    }

    /// Join an app-relative endpoint onto this mount without duplicating it.
    pub fn join(&self, endpoint: &str) -> Result<String, String> {
        join_public_path(&self.0, endpoint)
    }

    pub fn href(&self, endpoint: &str) -> String {
        let (without_fragment, fragment) = match endpoint.split_once('#') {
            Some((path, fragment)) => (path, Some(fragment)),
            None => (endpoint, None),
        };
        let joined = self
            .join(without_fragment)
            .unwrap_or_else(|_| self.home().to_string());
        match fragment {
            Some(fragment) if !fragment.is_empty() => format!("{joined}#{fragment}"),
            _ => joined,
        }
    }

    /// Exact segment-boundary strip. `/pharos` matches `/pharos` and
    /// `/pharos/...`, never `/pharos-other`.
    pub fn strip(&self, pathname: &str) -> Option<String> {
        strip_mount_path(pathname, &self.0)
    }

    pub fn contains_path(&self, pathname: &str) -> bool {
        is_segment_prefix(pathname, &self.0)
    }
}

impl fmt::Display for PublicBasePath {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.home())
    }
}

impl PublicOrigin {
    pub fn parse(value: &str) -> Result<Self, String> {
        parse_public_origin(value)
    }

    pub fn from_env_value(value: Option<&str>) -> Result<Option<Self>, String> {
        match value.map(str::trim).filter(|value| !value.is_empty()) {
            None => Ok(None),
            Some(value) => Self::parse(value).map(Some),
        }
    }

    pub fn as_url(&self) -> String {
        format!("{}://{}", self.scheme, self.host)
    }
}

pub fn normalize_public_base_path(value: &str) -> Result<String, String> {
    if value.is_empty() {
        return Ok(String::new());
    }
    if !value.is_ascii() || !value.bytes().all(|byte| (0x21..=0x7e).contains(&byte)) {
        return Err("public base path must be a canonical ASCII path".to_string());
    }
    if value.contains('%')
        || value.contains('\\')
        || value.contains('?')
        || value.contains('#')
        || value.contains("://")
        || value.starts_with("//")
        || !value.starts_with('/')
        || value.ends_with('/')
        || value.contains('.')
    {
        return Err(
            "public base path must be a canonical absolute path without trailing slash, encoding, or dot segments"
                .to_string(),
        );
    }
    if value.as_bytes().iter().any(|byte| byte.is_ascii_control()) {
        return Err("public base path must not contain control characters".to_string());
    }
    let mut segments = Vec::new();
    for segment in value[1..].split('/') {
        if segment.is_empty() {
            return Err("public base path must not contain empty segments".to_string());
        }
        if !segment.bytes().all(|byte| SEGMENT_ALPHABET.contains(&byte)) {
            return Err("public base path segments must match [A-Za-z0-9_-]+".to_string());
        }
        segments.push(segment);
    }
    if segments.is_empty() {
        return Err("public base path must use one or more [A-Za-z0-9_-] segments".to_string());
    }
    Ok(value.to_string())
}

pub fn join_public_path(public_base_path: &str, endpoint: &str) -> Result<String, String> {
    let base = normalize_public_base_path(public_base_path)?;
    let (path, query) = split_query(endpoint);
    let relative = normalize_app_relative_path(path)?;
    let joined = if base.is_empty() {
        relative
    } else if relative == "/" {
        base
    } else if relative == base || relative.starts_with(&format!("{base}/")) {
        return Err("endpoint already includes the configured public base path".to_string());
    } else {
        format!("{base}{relative}")
    };
    Ok(match query {
        Some(query) => format!("{joined}?{query}"),
        None => joined,
    })
}

pub fn strip_mount_path(pathname: &str, public_base_path: &str) -> Option<String> {
    if pathname.contains('\\') || pathname.contains('\0') || !pathname.starts_with('/') {
        return None;
    }
    let base = normalize_public_base_path(public_base_path).ok()?;
    if base.is_empty() {
        return Some(pathname.to_string());
    }
    if pathname == base {
        return Some("/".to_string());
    }
    pathname
        .strip_prefix(&format!("{base}/"))
        .map(|rest| format!("/{rest}"))
}

pub fn is_segment_prefix(path: &str, prefix: &str) -> bool {
    let Ok(normalized_prefix) = normalize_public_base_path(prefix) else {
        return false;
    };
    let path = path.split(['?', '#']).next().unwrap_or(path);
    if normalized_prefix.is_empty() {
        return path.starts_with('/');
    }
    path == normalized_prefix || path.starts_with(&format!("{normalized_prefix}/"))
}

fn split_query(endpoint: &str) -> (&str, Option<&str>) {
    match endpoint.split_once('?') {
        Some((path, query)) => (path, Some(query)),
        None => (endpoint, None),
    }
}

fn normalize_app_relative_path(value: &str) -> Result<String, String> {
    if !value.starts_with('/') || value.starts_with("//") {
        return Err("app-relative path must start with /".to_string());
    }
    if value != "/" && value.ends_with('/') {
        return Err("app-relative path must not have a trailing slash".to_string());
    }
    if value.contains('\\')
        || value.contains('#')
        || value.chars().any(|ch| ch.is_control())
        || value.contains("/.")
        || value.contains("//")
    {
        return Err(
            "app-relative path must be canonical ASCII without encoding or dot segments"
                .to_string(),
        );
    }
    Ok(value.to_string())
}

fn parse_public_origin(value: &str) -> Result<PublicOrigin, String> {
    let value = value.trim();
    let (scheme, rest) = if let Some(rest) = value.strip_prefix("https://") {
        ("https", rest)
    } else if let Some(rest) = value.strip_prefix("http://") {
        ("http", rest)
    } else {
        return Err("public origin must be http or https scheme+host".to_string());
    };
    if rest.is_empty()
        || rest.contains('/')
        || rest.contains('?')
        || rest.contains('#')
        || rest.contains('\\')
        || rest.contains('@')
        || rest.contains('%')
        || rest.starts_with('[')
        || !rest.is_ascii()
        || rest.chars().any(|ch| ch.is_control())
    {
        return Err(
            "public origin must be scheme+host without path, query, fragment, or credentials"
                .to_string(),
        );
    }
    if !valid_origin_host(rest) {
        return Err("public origin host is invalid".to_string());
    }
    Ok(PublicOrigin {
        scheme: scheme.to_string(),
        host: rest.to_string(),
    })
}

fn valid_origin_host(host: &str) -> bool {
    let (name, port) = match host.rsplit_once(':') {
        Some((name, port))
            if !name.is_empty() && port.bytes().all(|byte| byte.is_ascii_digit()) =>
        {
            if port.is_empty() || port.len() > 5 {
                return false;
            }
            let Ok(port) = port.parse::<u32>() else {
                return false;
            };
            if port == 0 || port > 65535 {
                return false;
            }
            (name, true)
        }
        _ => (host, false),
    };
    if port && name.chars().all(|ch| ch.is_ascii_digit() || ch == '.') && name.contains('.') {
        // IPv4:port is allowed; a hostname cannot end up here as digits-only without dots
        // unless it is a single label. Reject a trailing colon already handled.
    }
    if name.is_empty() || name.len() > 253 {
        return false;
    }
    let labels: Vec<&str> = name.split('.').collect();
    if labels.iter().any(|label| {
        label.is_empty()
            || label.len() > 63
            || label.starts_with('-')
            || label.ends_with('-')
            || !label
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
    }) {
        return false;
    }
    true
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_default_is_standalone_root() {
        assert_eq!(PublicBasePath::from_env_value(None).unwrap().as_str(), "");
        assert_eq!(
            PublicBasePath::from_env_value(Some("")).unwrap().as_str(),
            ""
        );
        assert_eq!(
            PublicBasePath::from_env_value(Some("  ")).unwrap().as_str(),
            ""
        );
        assert_eq!(
            join_public_path("", "/auth/callback").unwrap(),
            "/auth/callback"
        );
        assert_eq!(PublicBasePath::root().home(), "/");
        assert_eq!(PublicBasePath::root().href("/map"), "/map");
        assert_eq!(
            PublicBasePath::parse("/pharos")
                .unwrap()
                .href("/activity?host=athena&workflow=run-1#workflow-run-1"),
            "/pharos/activity?host=athena&workflow=run-1#workflow-run-1"
        );
    }

    #[test]
    fn sample_connected_vocabulary_is_canonical() {
        for sample in ["/pharos", "/aithema", "/paimos", "/janus", "/ops/pharos"] {
            let parsed = PublicBasePath::parse(sample).expect(sample);
            assert_eq!(parsed.as_str(), sample);
            assert_eq!(parsed.home(), sample);
        }
        assert_eq!(
            join_public_path("/pharos", "/auth/callback").unwrap(),
            "/pharos/auth/callback"
        );
        assert_eq!(join_public_path("/pharos", "/").unwrap(), "/pharos");
    }

    #[test]
    fn rejects_non_canonical_base_paths() {
        for invalid in [
            "/",
            "/pharos/",
            "/pharos//ops",
            "/./pharos",
            "/pharos/../paimos",
            "/pharos%2Fops",
            "//pharos",
            "/pharos?x=1",
            "/pharos#frag",
            "/pharos other",
            "pharos",
            "/pharos\\ops",
            "/.hidden",
            "https://example.test/pharos",
        ] {
            assert!(
                PublicBasePath::parse(invalid).is_err(),
                "accepted {invalid:?}"
            );
        }
    }

    #[test]
    fn exact_segment_boundary() {
        let base = PublicBasePath::parse("/pharos").unwrap();
        assert!(base.contains_path("/pharos"));
        assert!(base.contains_path("/pharos/auth/callback"));
        assert!(!base.contains_path("/pharos-other"));
        assert!(!base.contains_path("/paimos"));
        assert_eq!(base.strip("/pharos").as_deref(), Some("/"));
        assert_eq!(
            base.strip("/pharos/auth/callback").as_deref(),
            Some("/auth/callback")
        );
        assert_eq!(base.strip("/pharos-other"), None);
        assert_eq!(base.strip("/paimos/projects/17"), None);
    }

    #[test]
    fn join_rejects_duplicate_prefix() {
        assert!(join_public_path("/pharos", "/pharos/auth/callback").is_err());
    }

    #[test]
    fn public_origin_is_scheme_and_host_only() {
        let origin = PublicOrigin::parse("https://apps.example.test:8443").unwrap();
        assert_eq!(origin.scheme, "https");
        assert_eq!(origin.host, "apps.example.test:8443");
        assert_eq!(origin.as_url(), "https://apps.example.test:8443");
        for invalid in [
            "https://apps.example.test/pharos",
            "https://apps.example.test/?q=1",
            "https://user:pass@apps.example.test",
            "https://apps.example.test#x",
            "//apps.example.test",
            "apps.example.test",
        ] {
            assert!(
                PublicOrigin::parse(invalid).is_err(),
                "accepted {invalid:?}"
            );
        }
    }
}
