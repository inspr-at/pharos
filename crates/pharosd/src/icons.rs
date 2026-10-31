//! SVG icons, inlined once per page as a sprite. A few are Lucide (ISC,
//! https://lucide.dev), the rest are bespoke to match. Everything draws with
//! `currentColor`, so CSS sets the colour and size.

const ICONS: &[(&str, &str)] = &[
    (
        "lighthouse",
        r#"<path d="M10.5 5 12 2.5 13.5 5"/><rect x="10" y="5" width="4" height="3" rx=".5"/><path d="M10 8 8.6 20"/><path d="M14 8l1.4 12"/><path d="M9.2 13.5h5.6"/><path d="M7 20h10"/><path d="M6 22h12"/><path d="m16.6 6.4 2.4-1"/><path d="m7.4 6.4-2.4-1"/>"#,
    ),
    (
        "sun",
        r#"<circle cx="12" cy="12" r="4"/><path d="M12 2.8v2M12 19.2v2M5.5 5.5l1.4 1.4M17.1 17.1l1.4 1.4M2.8 12h2M19.2 12h2M5.5 18.5l1.4-1.4M17.1 6.9l1.4-1.4"/>"#,
    ),
    (
        "moon",
        r#"<path d="M19.5 14.2A7.8 7.8 0 0 1 9.8 4.5a7.8 7.8 0 1 0 9.7 9.7z"/>"#,
    ),
    (
        "info",
        r#"<circle cx="12" cy="12" r="9"/><path d="M12 11v5.5M12 7.8v.1"/>"#,
    ),
    (
        "online",
        r#"<circle cx="12" cy="12" r="8.5"/><circle cx="12" cy="12" r="3"/>"#,
    ),
    (
        "offline",
        r#"<circle cx="12" cy="12" r="8.5"/><path d="m9 9 6 6M15 9l-6 6"/>"#,
    ),
    (
        "paused",
        r#"<circle cx="12" cy="12" r="8.5"/><path d="M10 9v6M14 9v6"/>"#,
    ),
    (
        "no-contact",
        r#"<circle cx="12" cy="12" r="8.5" stroke-dasharray="2.6 3.2"/>"#,
    ),
    (
        "never",
        r#"<path d="M12 13v7.5"/><circle cx="12" cy="10.5" r="1.8"/><path d="M8.3 6.8a5.2 5.2 0 0 0 0 7.4M15.7 6.8a5.2 5.2 0 0 1 0 7.4M4 4l16 16"/>"#,
    ),
    (
        "hand",
        r#"<rect x="5.5" y="4.5" width="13" height="16" rx="2"/><path d="M9.5 4.5V3.5h5v1M9 10h6M9 14h4"/>"#,
    ),
    (
        "clock",
        r#"<circle cx="12" cy="12" r="8.5"/><path d="M12 7.5V12l3 2"/>"#,
    ),
    (
        "menu",
        r#"<path d="M4 6h16"/><path d="M4 12h16"/><path d="M4 18h16"/>"#,
    ),
    ("close", r#"<path d="M18 6 6 18M6 6l12 12"/>"#),
    (
        "grid",
        r#"<rect width="7" height="7" x="3" y="3" rx="1"/><rect width="7" height="7" x="14" y="3" rx="1"/><rect width="7" height="7" x="14" y="14" rx="1"/><rect width="7" height="7" x="3" y="14" rx="1"/>"#,
    ),
    (
        "archive",
        r#"<rect width="20" height="5" x="2" y="3" rx="1"/><path d="M4 8v11a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8"/><path d="M10 12h4"/>"#,
    ),
    (
        "sign-out",
        r#"<path d="m16 17 5-5-5-5"/><path d="M21 12H9"/><path d="M9 21H5a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2h4"/>"#,
    ),
    ("back", r#"<path d="M19 12H5M11 6l-6 6 6 6"/>"#),
    (
        "critical",
        r#"<path d="M8.3 3h7.4L21 8.3v7.4L15.7 21H8.3L3 15.7V8.3z"/><path d="M12 8v5M12 16.2v.1"/>"#,
    ),
    (
        "tip",
        r#"<path d="M9 18h6M10 21h4M12 3a6 6 0 0 0-3.6 10.8c.7.5 1.1 1.3 1.1 2.1V16h5v-.1c0-.8.4-1.6 1.1-2.1A6 6 0 0 0 12 3z"/>"#,
    ),
    (
        "beacon",
        r#"<path d="M12 13v7.5"/><circle cx="12" cy="10.5" r="1.8"/><path d="M8.3 6.8a5.2 5.2 0 0 0 0 7.4M15.7 6.8a5.2 5.2 0 0 1 0 7.4M5.5 4.3a8.8 8.8 0 0 0 0 12.4M18.5 4.3a8.8 8.8 0 0 1 0 12.4"/>"#,
    ),
    (
        "high",
        r#"<path d="M10.3 4.3 2.9 17.4a2 2 0 0 0 1.7 3h14.8a2 2 0 0 0 1.7-3L13.7 4.3a2 2 0 0 0-3.4 0z"/><path d="M12 9.5V14M12 17.1v.1"/>"#,
    ),
    (
        "pi",
        r#"<rect x="3.5" y="6" width="17" height="12" rx="2"/><rect x="7.5" y="9" width="5.5" height="5.5" rx="1"/><path d="M15.5 9.5h2M15.5 12h2M15.5 14.5h2M6 3.5v2.5M10 3.5v2.5M14 3.5v2.5"/>"#,
    ),
    (
        "server",
        r#"<rect x="3.5" y="4" width="17" height="7" rx="2"/><rect x="3.5" y="13" width="17" height="7" rx="2"/><path d="M7.5 7.5h.01M7.5 16.5h.01M11 7.5h6M11 16.5h6"/>"#,
    ),
    (
        "reboot",
        r#"<path d="M19.5 12a7.5 7.5 0 1 1-2.2-5.3"/><path d="M19.5 4.5v4.2h-4.2"/>"#,
    ),
    (
        "unknown",
        r#"<circle cx="12" cy="12" r="9"/><path d="M9.6 9.4a2.5 2.5 0 0 1 4.8.9c0 1.7-2.4 2.2-2.4 3.7M12 17h.01"/>"#,
    ),
    (
        "appliance",
        r#"<rect x="3.5" y="12" width="17" height="7.5" rx="2"/><path d="M7.5 15.75h.01M11 15.75h.01M8.5 12 6.5 6.5M15.5 12l2-5.5"/>"#,
    ),
    (
        "check",
        r#"<circle cx="12" cy="12" r="9"/><path d="m8 12.3 2.8 2.8 5.4-5.5"/>"#,
    ),
    (
        "stale",
        r#"<path d="M7 3.5h10M7 20.5h10M8 3.5v2.2a4 4 0 0 0 1.6 3.2L12 11l2.4-2.1A4 4 0 0 0 16 5.7V3.5M8 20.5v-2.2a4 4 0 0 1 1.6-3.2L12 13l2.4 2.1a4 4 0 0 1 1.6 3.2v2.2"/>"#,
    ),
    ("dash", r#"<path d="M7 12h10"/>"#),
    (
        "laptop",
        r#"<rect x="4.5" y="5" width="15" height="10.5" rx="1.5"/><path d="M2.5 19h19"/>"#,
    ),
    (
        "vm",
        r#"<path d="M7 18.5h10a4 4 0 0 0 .6-7.96A6 6 0 0 0 6.2 9.6 4.4 4.4 0 0 0 7 18.5z"/>"#,
    ),
    (
        "data-file",
        r#"<path d="M14 3.5H7A1.5 1.5 0 0 0 5.5 5v14A1.5 1.5 0 0 0 7 20.5h10a1.5 1.5 0 0 0 1.5-1.5V8z"/><path d="M14 3.5V8h4.5M9 12.5h6M9 16h4"/>"#,
    ),
    (
        "eye",
        r#"<path d="M2.5 12S6 5.5 12 5.5 21.5 12 21.5 12 18 18.5 12 18.5 2.5 12 2.5 12z"/><circle cx="12" cy="12" r="2.8"/>"#,
    ),
    (
        "medium",
        r#"<circle cx="12" cy="12" r="9"/><path d="M12 7.5v5.5M12 16.2v.1"/>"#,
    ),
    ("chevron-down", r#"<path d="m6 9 6 6 6-6"/>"#),
    (
        "site",
        r#"<path d="M20 10c0 6-8 12-8 12s-8-6-8-12a8 8 0 0 1 16 0"/><circle cx="12" cy="10" r="3"/>"#,
    ),
    (
        "tailnet",
        r#"<circle cx="6" cy="12" r="2.2"/><circle cx="18" cy="6" r="2.2"/><circle cx="18" cy="18" r="2.2"/><path d="M8 11 16 7M8 13l8 4"/>"#,
    ),
    (
        "no-tailnet",
        r#"<circle cx="6" cy="12" r="2.2"/><circle cx="18" cy="6" r="2.2"/><circle cx="18" cy="18" r="2.2"/><path d="M8 11 16 7M8 13l8 4"/><path d="M4 4l16 16"/>"#,
    ),
    (
        "commit",
        r#"<circle cx="12" cy="12" r="3.2"/><path d="M3 12h5.8M15.2 12H21"/>"#,
    ),
    (
        "unlisted",
        r#"<path d="M3.5 13.5 6 5.5h12l2.5 8V19a1 1 0 0 1-1 1h-15a1 1 0 0 1-1-1z"/><path d="M3.5 13.5h5l1.5 2.5h4l1.5-2.5h5"/>"#,
    ),
    ("chevron-right", r#"<path d="m9 5 7 7-7 7"/>"#),
    ("arrow-right", r#"<path d="M5 12h14M13 6l6 6-6 6"/>"#),
    (
        "file-warning",
        r#"<path d="M14 3.5H7A1.5 1.5 0 0 0 5.5 5v14A1.5 1.5 0 0 0 7 20.5h10a1.5 1.5 0 0 0 1.5-1.5V8z"/><path d="M14 3.5V8h4.5M12 11.5V15M12 17.6v.1"/>"#,
    ),
    (
        "package",
        r#"<path d="M12 3.2 19.8 7.6v8.8L12 20.8l-7.8-4.4V7.6z"/><path d="M4.2 7.6 12 12l7.8-4.4M12 12v8.8"/>"#,
    ),
    ("probe", r#"<path d="M3 12h4l2.5-6 5 12 2.5-6h4"/>"#),
    (
        "updates",
        r#"<path d="M21 12a9 9 0 0 1-9 9c-2.52 0-4.93-1.06-6.64-2.92L3 16"/><path d="M3 21v-5h5"/><path d="M3 12a9 9 0 0 1 9-9c2.52 0 4.93 1.06 6.64 2.92L21 8"/><path d="M16 8h5V3"/>"#,
    ),
    (
        "search",
        r#"<path d="m21 21-4.34-4.34"/><circle cx="11" cy="11" r="8"/>"#,
    ),
    (
        "mitigated",
        r#"<path d="M12 3.5 5 6.3v5.2c0 4.3 3 7.6 7 9 4-1.4 7-4.7 7-9V6.3z"/><path d="m9 12.2 2.2 2.2 4-4.2"/>"#,
    ),
];

/// One `<symbol>` per icon. Placed once, at the top of each page's body.
pub(crate) fn sprite() -> String {
    let symbols: String = ICONS
        .iter()
        .map(|(name, body)| format!(r#"<symbol id="i-{name}" viewBox="0 0 24 24">{body}</symbol>"#))
        .collect();
    format!(
        r#"<svg xmlns="http://www.w3.org/2000/svg" hidden aria-hidden="true" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">{symbols}</svg>"#
    )
}

/// An icon by name. The name must be in the table; a test checks every use.
pub(crate) fn icon(name: &str, class: &str) -> String {
    debug_assert!(ICONS.iter().any(|(known, _)| *known == name), "{name}");
    let class = if class.is_empty() {
        "icon".to_string()
    } else {
        format!("icon {class}")
    };
    format!(
        r##"<svg class="{class}" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><use href="#i-{name}"/></svg>"##
    )
}

pub(crate) const WAVE: &str = r#"<svg class="wave" viewBox="0 0 48 12" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" aria-hidden="true"><path d="M1 7c5-7 11 7 16 0s11 7 16 0 10 3 14 0"/></svg>"#;
