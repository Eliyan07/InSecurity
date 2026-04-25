/**
 * Vitest setup file for React component tests
 * 
 * This file runs before each test file and sets up:
 * - DOM matchers from @testing-library/jest-dom
 * - Mock for window.matchMedia (for CSS media queries)
 * - Mock for Tauri API (since we're in a browser environment during tests)
 */

import '@testing-library/jest-dom';
import { beforeAll, beforeEach, vi } from 'vitest';
import i18n from '../i18n';

// Mock window.matchMedia for components that use media queries
Object.defineProperty(window, 'matchMedia', {
  writable: true,
  value: (query: string) => ({
    matches: false,
    media: query,
    onchange: null,
    addListener: () => {},
    removeListener: () => {},
    addEventListener: () => {},
    removeEventListener: () => {},
    dispatchEvent: () => false,
  }),
});

// Mock ResizeObserver
class ResizeObserverMock {
  observe() {}
  unobserve() {}
  disconnect() {}
}
window.ResizeObserver = ResizeObserverMock;

// Mock IntersectionObserver
class IntersectionObserverMock {
  constructor(callback: IntersectionObserverCallback) {
    this.callback = callback;
  }
  callback: IntersectionObserverCallback;
  observe() {}
  unobserve() {}
  disconnect() {}
}
window.IntersectionObserver = IntersectionObserverMock as unknown as typeof IntersectionObserver;

// Mock Tauri API for frontend tests
vi.mock('@tauri-apps/api/core', () => ({
  invoke: vi.fn().mockResolvedValue({}),
}));

vi.mock('@tauri-apps/api/event', () => ({
  listen: vi.fn().mockResolvedValue(() => {}),
  emit: vi.fn(),
}));

vi.mock('@tauri-apps/plugin-notification', () => ({
  isPermissionGranted: vi.fn().mockResolvedValue(true),
  requestPermission: vi.fn().mockResolvedValue('granted'),
  sendNotification: vi.fn(),
}));

// Mock window.scrollTo
window.scrollTo = vi.fn();

async function ensureEnglishI18n() {
  if (!i18n.isInitialized) {
    await new Promise<void>((resolve) => {
      i18n.on('initialized', () => resolve());
    });
  }

  if (i18n.language !== 'en') {
    await i18n.changeLanguage('en');
  }
}

beforeAll(async () => {
  await ensureEnglishI18n();
});

beforeEach(async () => {
  await ensureEnglishI18n();
});

// Suppress console warnings during tests (optional)
// const originalWarn = console.warn;
// console.warn = (...args) => {
//   if (args[0]?.includes('act(')) return;
//   originalWarn(...args);
// };
