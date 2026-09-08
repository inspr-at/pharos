export const LAYOUT_MODES = Object.freeze(['viewport', 'bounded']);

export function resolveLayoutMode(value) {
  return value === 'bounded' ? 'bounded' : 'viewport';
}

export function applyBoundedGeometry(host, rect) {
  host.style.setProperty('--shell-fixed-left', `${Math.round(rect.left)}px`);
  host.style.setProperty('--shell-fixed-width', `${Math.round(rect.width)}px`);
}

export function clearBoundedGeometry(host) {
  host.style.removeProperty('--shell-fixed-left');
  host.style.removeProperty('--shell-fixed-width');
}

export function applyFooterSpace(host, height) {
  host.style.setProperty('--shell-footer-space', `${Math.ceil(height)}px`);
}
