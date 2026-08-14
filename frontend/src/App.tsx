import { lazy, Suspense } from "react";
import { BrowserRouter } from "react-router-dom";

import { CapabilityProvider } from "./lib/CapabilityProvider";

const NetraConsole = lazy(() => import("./features/console/NetraConsole"));
const AuthApplication = lazy(() => import("./features/auth/AuthApplication"));
const PublicNotFoundPage = lazy(() => import("./public/PublicSite").then((module) => ({ default: module.PublicNotFoundPage })));

const AUTH_ROUTE_PATTERN = /^\/login(?:\/|$)/;

function AppLoadingScreen() {
  return (
    <main className="app-theme flex min-h-screen items-center justify-center bg-[var(--background)] p-6" aria-busy="true">
      <div className="surface-solid max-w-md rounded-3xl p-8 text-center" role="status" aria-live="polite">
        <p className="font-mono text-xs uppercase tracking-[0.28em] text-[var(--accent)]">Netra secure console</p>
        <h1 className="mt-4 text-2xl font-black text-strong">Loading the investigation workspace</h1>
        <p className="mt-2 text-sm leading-6 text-muted">Preparing the route without loading unrelated investigation tools.</p>
      </div>
    </main>
  );
}

export default function App() {
  const pathname = window.location.pathname;
  const RouteApplication = AUTH_ROUTE_PATTERN.test(pathname) ? AuthApplication : pathname === "/" ? NetraConsole : null;
  return (
    <>
      <a className="skip-link" href="#main-content">Skip to main content</a>
      <CapabilityProvider>
        <Suspense fallback={<AppLoadingScreen />}>
          {RouteApplication ? <RouteApplication /> : <BrowserRouter><PublicNotFoundPage /></BrowserRouter>}
        </Suspense>
      </CapabilityProvider>
    </>
  );
}
