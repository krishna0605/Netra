import "@testing-library/jest-dom/vitest";

// Production fails closed when its public Supabase configuration is absent.
// Tests use inert values so modules that validate configuration at import time
// exercise their behavior without depending on a developer or CI environment.
import.meta.env.VITE_SUPABASE_URL ||= "https://test.supabase.co";
import.meta.env.VITE_SUPABASE_PUBLISHABLE_KEY ||= "sb_publishable_test";
import.meta.env.VITE_DEPLOYMENT_PROFILE ||= "local";

Object.defineProperty(window, "matchMedia", {
  writable: true,
  value: (query: string) => ({
    matches: false,
    media: query,
    onchange: null,
    addListener: () => undefined,
    removeListener: () => undefined,
    addEventListener: () => undefined,
    removeEventListener: () => undefined,
    dispatchEvent: () => false,
  }),
});

window.scrollTo = () => undefined;

class IntersectionObserverMock implements IntersectionObserver {
  readonly root = null;
  readonly rootMargin = "0px";
  readonly scrollMargin = "0px";
  readonly thresholds = [0];
  disconnect() { return undefined; }
  observe() { return undefined; }
  takeRecords() { return []; }
  unobserve() { return undefined; }
}

Object.defineProperty(window, "IntersectionObserver", { writable: true, value: IntersectionObserverMock });
Object.defineProperty(globalThis, "IntersectionObserver", { writable: true, value: IntersectionObserverMock });
