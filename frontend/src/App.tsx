import { lazy, Suspense } from "react";
import { BrowserRouter } from "react-router-dom";

import { PageTransition } from "./components/PageTransition";
import { CapabilityProvider } from "./lib/CapabilityProvider";

const NetraConsole = lazy(() => import("./features/console/NetraConsole"));
const AuthApplication = lazy(() => import("./features/auth/AuthApplication"));
const PublicNotFoundPage = lazy(() => import("./public/PublicSite").then((module) => ({ default: module.PublicNotFoundPage })));

const AUTH_ROUTE_PATTERN = /^\/login(?:\/|$)/;

export default function App() {
  const pathname = window.location.pathname;
  const RouteApplication = AUTH_ROUTE_PATTERN.test(pathname) ? AuthApplication : pathname === "/" ? NetraConsole : null;
  return (
    <>
      <a className="skip-link" href="#main-content">Skip to main content</a>
      <CapabilityProvider>
        <Suspense fallback={<PageTransition />}>
          {RouteApplication ? <RouteApplication /> : <BrowserRouter><PublicNotFoundPage /></BrowserRouter>}
        </Suspense>
      </CapabilityProvider>
    </>
  );
}
