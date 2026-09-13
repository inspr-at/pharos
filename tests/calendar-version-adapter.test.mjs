import assert from 'node:assert/strict';
import test from 'node:test';
import { hydrateCalendarVersions, hydrateVersionHost } from '../crates/pharosd/assets/calendar-version-bootstrap.mjs';

const config = {
  schema: 'inspr.calendar-version-display.v2',
  scheme: 'inspr-calendar-v2',
  weights: { v: 0, yy: 1, mm: 0.9, dd: 0.8, hh: 0.7, mi: 0.6, ss: 0.5, tail: 0 },
};

test('Pharos binds Pretty mode and canonical copy identity without changing the machine value', () => {
  const host = { dataset: { canonical: '260913221718.0.0', scheme: 'inspr-calendar-v2', brand: '#1f7fb5' } };
  let invocation;
  assert.equal(hydrateVersionHost(host, config, (...args) => { invocation = args; }), true);
  assert.equal(invocation[1], 'v260913221718.0.0');
  assert.equal(invocation[2], 'inspr-calendar-v2');
  assert.deepEqual(invocation[3], { config, mode: 'pretty', brand: '#1f7fb5', interactive: true });
  assert.equal(host.dataset.canonical, '260913221718.0.0');
  assert.equal(host.dataset.version, 'v260913221718.0.0');
});

test('sidebar host retains surrounding release control ownership', () => {
  const host = { dataset: { canonical: '260913221718.0.0', scheme: 'inspr-calendar-v2', brand: '#1f7fb5', calendarInteractive: 'false' } };
  let invocation;
  assert.equal(hydrateVersionHost(host, config, (...args) => { invocation = args; }), true);
  assert.equal(invocation[3].interactive, false);
});

test('malformed configuration leaves the canonical server fallback untouched', () => {
  const host = { dataset: { canonical: '260913221718.0.0', scheme: 'inspr-calendar-v2', brand: '#1f7fb5' } };
  let called = false;
  const root = {
    querySelector: () => ({ content: '{not-json' }),
    querySelectorAll: () => [host],
  };
  assert.equal(hydrateCalendarVersions(root, () => { called = true; }), 0);
  assert.equal(called, false);
  assert.equal(host.dataset.version, undefined);
});
