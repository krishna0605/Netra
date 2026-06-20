import "@testing-library/jest-dom/vitest";

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
