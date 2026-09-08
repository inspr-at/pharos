//! Native public base path mounting and document URL production (PHAROS-258).

use pharos_core::{PublicBasePath, PublicOrigin};
use url::Url;

pub(crate) const PUBLIC_BASE_PATH_ENV: &str = "PHAROS_PUBLIC_BASE_PATH";
pub(crate) const PUBLIC_ORIGIN_ENV: &str = "PHAROS_PUBLIC_ORIGIN";

pub(crate) fn public_base_path_from_env() -> Result<PublicBasePath, String> {
    PublicBasePath::from_env_value(crate::env_nonempty(PUBLIC_BASE_PATH_ENV).as_deref())
        .map_err(|error| format!("{PUBLIC_BASE_PATH_ENV} {error}"))
}

pub(crate) fn public_origin_from_env() -> Result<Option<PublicOrigin>, String> {
    PublicOrigin::from_env_value(crate::env_nonempty(PUBLIC_ORIGIN_ENV).as_deref())
        .map_err(|error| format!("{PUBLIC_ORIGIN_ENV} {error}"))
}

pub(crate) fn validate_oidc_redirect_uri(
    redirect: &str,
    public_base_path: &PublicBasePath,
    public_origin: Option<&PublicOrigin>,
) -> Result<(), String> {
    let url = Url::parse(redirect)
        .map_err(|error| format!("PHAROS_OIDC_REDIRECT_URI is invalid: {error}"))?;
    if !url.username().is_empty()
        || url.password().is_some()
        || url.query().is_some()
        || url.fragment().is_some()
    {
        return Err(
            "PHAROS_OIDC_REDIRECT_URI must not include credentials, query, or fragment".to_string(),
        );
    }
    let expected_path = public_base_path
        .join("/auth/callback")
        .map_err(|error| format!("PHAROS_OIDC_REDIRECT_URI {error}"))?;
    if url.path() != expected_path {
        return Err(format!(
            "PHAROS_OIDC_REDIRECT_URI path must be {expected_path}"
        ));
    }
    if let Some(origin) = public_origin {
        if url.scheme() != origin.scheme {
            return Err(
                "PHAROS_OIDC_REDIRECT_URI scheme must match PHAROS_PUBLIC_ORIGIN".to_string(),
            );
        }
        let host = match url.port() {
            Some(port) => format!("{}:{port}", url.host_str().unwrap_or_default()),
            None => url.host_str().unwrap_or_default().to_string(),
        };
        if !host.eq_ignore_ascii_case(&origin.host) {
            return Err(
                "PHAROS_OIDC_REDIRECT_URI host must match PHAROS_PUBLIC_ORIGIN".to_string(),
            );
        }
    }
    Ok(())
}

pub(crate) fn localize_document(public_base_path: &PublicBasePath, html: &str) -> String {
    inject_public_base_meta(html, public_base_path)
}

fn inject_public_base_meta(html: &str, public_base_path: &PublicBasePath) -> String {
    if html.contains("name=\"pharos-public-base-path\"") {
        return html.to_string();
    }
    let marker = "<head>";
    let Some(index) = html.find(marker) else {
        return html.to_string();
    };
    let insert_at = index + marker.len();
    let content = html_escape_attr(public_base_path.as_str());
    let snippet = format!(
        r#"<meta name="pharos-public-base-path" content="{content}"><script>window.pharosPublicPath=function(p){{var b=document.querySelector('meta[name="pharos-public-base-path"]')&&document.querySelector('meta[name="pharos-public-base-path"]').content||'';if(!p||p==='/')return b||'/';if(typeof p!=='string'||p.charAt(0)!=='/'||p.slice(0,2)==='//')return p;if(b&&(p===b||p.indexOf(b+'/')===0||p.indexOf(b+'?')===0||p.indexOf(b+'#')===0))return p;return b+p;}};</script>"#
    );
    let mut output = String::with_capacity(html.len() + snippet.len());
    output.push_str(&html[..insert_at]);
    output.push_str(&snippet);
    output.push_str(&html[insert_at..]);
    output
}

fn html_escape_attr(value: &str) -> String {
    value.replace('&', "&amp;").replace('"', "&quot;")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_mount_keeps_root_document_urls() {
        let html = r#"<head></head><a href="/map">Map</a>"#;
        let localized = localize_document(&PublicBasePath::root(), html);
        assert!(localized.contains(r#"name="pharos-public-base-path" content="""#));
        assert!(localized.contains(r#"href="/map""#));
        assert!(!localized.contains("/pharos/map"));
    }

    #[test]
    fn localize_injects_routing_context_without_rewriting_quoted_urls() {
        let base = PublicBasePath::parse("/pharos").unwrap();
        let html = r#"<head></head><a href="/map">Map</a><a href="/paimos/projects/17">Paimos</a><a href="https://github.com/inspr-at/pharos">release</a><script>fetch('/hosts.json')</script><p>content /map stays text</p>"#;
        let localized = localize_document(&base, html);
        assert!(localized.contains(r#"content="/pharos""#));
        assert!(localized.contains("window.pharosPublicPath=function"));
        assert!(localized.contains(r#"href="/map""#));
        assert!(localized.contains(r#"href="/paimos/projects/17""#));
        assert!(localized.contains(r#"href="https://github.com/inspr-at/pharos""#));
        assert!(localized.contains("fetch('/hosts.json')"));
        assert!(localized.contains("content /map stays text"));
        assert!(!localized.contains(r#"href="/pharos/map""#));
        assert!(!localized.contains("/pharos/paimos"));
        assert_eq!(base.href("/map"), "/pharos/map");
        assert_eq!(base.href("/"), "/pharos");
    }

    #[test]
    fn exact_segment_boundary_is_not_confused_with_sibling_prefix() {
        let base = PublicBasePath::parse("/pharos").unwrap();
        assert!(base.contains_path("/pharos/auth/callback"));
        assert!(!base.contains_path("/pharos-other"));
        assert!(!base.contains_path("/paimos/projects/17"));
        assert_eq!(base.href("/pharos-other"), "/pharos/pharos-other");
    }

    #[test]
    fn oidc_callback_path_tracks_the_configured_mount() {
        validate_oidc_redirect_uri(
            "https://pharos.example.test/auth/callback",
            &PublicBasePath::root(),
            None,
        )
        .unwrap();
        validate_oidc_redirect_uri(
            "https://apps.example.test/pharos/auth/callback",
            &PublicBasePath::parse("/pharos").unwrap(),
            Some(&PublicOrigin::parse("https://apps.example.test").unwrap()),
        )
        .unwrap();
        assert!(validate_oidc_redirect_uri(
            "https://pharos.example.test/auth/callback",
            &PublicBasePath::parse("/pharos").unwrap(),
            None,
        )
        .is_err());
        assert!(validate_oidc_redirect_uri(
            "https://other.example.test/pharos/auth/callback",
            &PublicBasePath::parse("/pharos").unwrap(),
            Some(&PublicOrigin::parse("https://apps.example.test").unwrap()),
        )
        .is_err());
    }
}
