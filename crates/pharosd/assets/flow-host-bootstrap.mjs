import '/assets/vendor/flow-shell/src/inspr-flow-shell.js';

const shell = document.querySelector('inspr-flow-shell[data-flow-host]');
if (shell) {
  const hostScope = shell.dataset.flowHostScope || '';
  const paimosOrigin = shell.dataset.flowPaimosOrigin || '';
  let generation = 0;
  let refreshTimer = null;

  function clearShell() {
    shell.shellState = {
      evaluatedAt: null,
      header: {},
      health: { status: 'unavailable', label: 'Flow unavailable' },
      delivery: { status: 'draft' },
      prerequisites: {},
      progress: {},
      executionModes: ['manual'],
      selectedExecutionMode: 'manual',
      selectedAction: 'build',
      identityContext: null,
    };
  }

  function shellStateUrl() {
    const url = new URL('/flow/shell-state.json', document.baseURI);
    if (hostScope) {
      url.searchParams.set('host', hostScope);
    }
    return url;
  }

  function intentsUrl() {
    const url = new URL('/flow/intents', document.baseURI);
    if (hostScope) {
      url.searchParams.set('host', hostScope);
    }
    return url;
  }

  function msUntilNextTenMinuteBoundary(now = Date.now()) {
    const seconds = Math.floor(now / 1000);
    const remainder = seconds % 600;
    const deltaSeconds = remainder === 0 ? 600 : 600 - remainder;
    return deltaSeconds * 1000 - (now % 1000);
  }

  function scheduleBoundaryRefresh() {
    if (refreshTimer !== null) {
      clearTimeout(refreshTimer);
    }
    refreshTimer = setTimeout(() => {
      refresh().finally(scheduleBoundaryRefresh);
    }, msUntilNextTenMinuteBoundary());
  }

  async function refresh() {
    const next = ++generation;
    try {
      const response = await fetch(shellStateUrl(), {
        credentials: 'same-origin',
        cache: 'no-store',
      });
      if (generation !== next) {
        return;
      }
      if (!response.ok) {
        clearShell();
        return;
      }
      const payload = await response.json();
      if (generation !== next) {
        return;
      }
      if (!payload.enabled || !payload.mountShell) {
        clearShell();
        return;
      }
      if (payload.unavailableReason) {
        clearShell();
        return;
      }
      if (payload.shellState) {
        shell.shellState = payload.shellState;
      } else {
        clearShell();
      }
    } catch {
      if (generation === next) {
        clearShell();
      }
    }
  }

  function navigationAllowed(location) {
    if (!location || typeof location !== 'string') {
      return false;
    }
    let target;
    try {
      target = new URL(location);
    } catch {
      return false;
    }
    if (!paimosOrigin) {
      return false;
    }
    let allowed;
    try {
      allowed = new URL(paimosOrigin);
    } catch {
      return false;
    }
    if (target.origin !== allowed.origin) {
      return false;
    }
    return /^\/projects\/\d+$/.test(target.pathname);
  }

  shell.addEventListener('flow-intent', async (event) => {
    const detail = event.detail ?? {};
    const intentType = detail.type ?? detail.intentType;
    try {
      const response = await fetch(intentsUrl(), {
        method: 'POST',
        credentials: 'same-origin',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          type: intentType,
          identity: detail.identity ?? null,
          detail,
        }),
      });
      const result = await response.json();
      if (result.notice && typeof result.notice === 'string') {
        shell.showNotice?.(result.notice);
      }
      if (result.error && typeof result.error === 'string') {
        shell.showNotice?.(result.error);
        return;
      }
      if (navigationAllowed(result.location)) {
        window.location.assign(result.location);
      }
    } catch {
      shell.showNotice?.('Flow intent could not be completed.');
    }
  });

  document.addEventListener('visibilitychange', () => {
    if (!document.hidden) {
      refresh();
    }
  });

  refresh();
  scheduleBoundaryRefresh();
}
