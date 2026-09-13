import { renderVersion } from './vendor/calendar-version-display/version.js';

const CONFIG_SELECTOR = 'meta[name="inspr-calendar-version-display"]';
const HOST_SELECTOR = '[data-calendar-display]';

export function hydrateVersionHost(host, config, renderer = renderVersion) {
  const canonical = host?.dataset?.canonical;
  const scheme = host?.dataset?.scheme;
  const brand = host?.dataset?.brand;
  if (!canonical || !scheme || !/^#[0-9a-fA-F]{6}$/.test(brand || '')) return false;
  const interactive = host.dataset.calendarInteractive !== 'false';
  renderer(host, `v${canonical}`, scheme, { config, mode: 'pretty', brand, interactive });
  // Keep machine identity independent from the decorative Pretty presentation.
  host.dataset.canonical = canonical;
  host.dataset.version = `v${canonical}`;
  return true;
}

export function hydrateCalendarVersions(root = document, renderer = renderVersion) {
  try {
    const config = JSON.parse(root.querySelector(CONFIG_SELECTOR)?.content || '');
    if (config?.schema !== 'inspr.calendar-version-display.v2' || config?.scheme !== 'inspr-calendar-v2') return 0;
    let hydrated = 0;
    for (const host of root.querySelectorAll(HOST_SELECTOR)) {
      if (hydrateVersionHost(host, config, renderer)) hydrated += 1;
    }
    return hydrated;
  } catch {
    return 0;
  }
}

if (typeof document !== 'undefined') hydrateCalendarVersions(document);
