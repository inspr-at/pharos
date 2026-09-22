// Fixed, reviewed Flow mounts. Runtime input cannot add an origin, auth route,
// or read permission. Application writes are denied by the shared guard.
export const FAMILY_ORIGIN = "https://flow.inspr.at";
export const FAMILY_SCHEMA = "inspr.uxqa.live-ui-evidence.v1";
export const FAMILY_VIEWPORTS = Object.freeze({
  desktop: Object.freeze({ width: 1440, height: 1000 }),
  mobile: Object.freeze({ width: 390, height: 844 }),
});
const APPS = Object.freeze({
  aithema: Object.freeze({
    base: "/aithema",
    login: "/aithema/login",
    callback: "/aithema/oidc/callback",
    shell: "#identity-access form[action='/aithema/logout']",
    routes: Object.freeze([{ name: "landing", path: "/aithema/" }]),
  }),
  paimos: Object.freeze({
    base: "/paimos",
    login: "/paimos/api/auth/oidc/login",
    callback: "/paimos/api/auth/oidc/callback",
    shell: ".layout button.logout-btn, .p6-shell.habitat-shell[data-shell='v6'] button[type='button'][aria-label='Log out']",
    routes: Object.freeze([{ name: "landing", path: "/paimos/" }]),
  }),
  pharos: Object.freeze({
    base: "/pharos",
    login: "/pharos/auth/login",
    callback: "/pharos/auth/callback",
    shell: "[data-can-manage-fleet='true'], [data-can-manage='true']",
    routes: Object.freeze([{ name: "landing", path: "/pharos/" }, { name: "list", path: "/pharos/?view=list" }]),
  }),
  janus: Object.freeze({
    base: "/janus",
    login: "/janus/login",
    callback: "/janus/oidc/callback",
    shell: "main[data-inspr-flow-reviewer] form[action='/janus/logout']",
    routes: Object.freeze([{ name: "landing", path: "/janus/" }]),
  }),
});
// Aithema project refs contain a literal colon. Its own links encode that one
// delimiter; no general URL decoding is permitted by the request guard.
export function normalizeFamilyPath(pathname) {
  return pathname.replace(/^\/aithema\/projects\/project%3[Aa]([A-Za-z0-9_-]{1,80})(\/flow-state)?$/, "/aithema/projects/project:$1$2");
}
export function familyApp(name) {
  return typeof name === "string" && Object.hasOwn(APPS, name) ? APPS[name] : null;
}
export function familyAppLocation(name, location) {
  const app = familyApp(name);
  return !!app && location?.origin === FAMILY_ORIGIN &&
    (location.pathname === app.base || location.pathname.startsWith(`${app.base}/`));
}
export function familyAuthPath(name, pathname) {
  const app = familyApp(name);
  return !!app && (pathname === app.login || pathname === app.callback ||
    /(?:^|\/)(?:login|logout|auth|oidc)(?:\/|$)/.test(pathname));
}
export function familyReadAllowed(name, pathname) {
  const app = familyApp(name);
  if (!app || !(pathname === app.base || pathname.startsWith(`${app.base}/`))) return false;
  if (pathname === app.login || pathname === app.callback) return true;
  if (/(?:^|\/)(?:logout|reset|revoke|export|download|activate|execute)(?:\/|$)/.test(pathname)) return false;
  // The Janus runner never traverses secret catalog, audit, posture, permit,
  // resolution, setup, credential, or secret-value routes, even with GET.
  if (name === "janus") {
    return ["/janus", "/janus/", "/janus/flow/shell-state.json", "/janus/favicon.ico"].includes(pathname) || pathname.startsWith("/janus/static/");
  }
  return true;
}
export function familyRoutes(name, projectRef = "") {
  const app = familyApp(name);
  if (!app) throw new Error("family-app");
  const routes = app.routes.map((route) => ({ ...route }));
  if (projectRef) {
    const valid = (name === "aithema" && /^project:[A-Za-z0-9_-]{1,80}$/.test(projectRef)) ||
      (name === "paimos" && /^[1-9][0-9]{0,15}$/.test(projectRef));
    if (!valid) throw new Error("family-project");
    routes.push({ name: "sandbox", path: `${app.base}/projects/${encodeURIComponent(projectRef)}` });
  }
  return routes;
}
export function classifyFamilyObservation({ app, location, status, probe, callbackConfirmed = false }) {
  if (probe?.accountSetup) return "account-setup-required";
  if (probe?.mfa) return "mfa-required";
  if (probe?.rateLimited || probe?.authRecovery || probe?.passwordCount > 0 || probe?.loginForm || probe?.authUiVisible || location?.origin === "https://auth.inspr.at" || familyAuthPath(app, location?.pathname || "")) return "auth-required";
  if (probe?.noAccess || probe?.accessDenied || probe?.accessRequest || status === 403) return "policy-denied";
  if (status === 401) return "auth-required";
  if (familyAppLocation(app, location) && callbackConfirmed && probe?.familyShell && (status === 0 || (status >= 200 && status < 400))) return "authenticated";
  return "broken-ui";
}
