import { lazy, Suspense } from "react";

const ConsoleApplication = lazy(() => import("./ConsoleApplication"));

export default function NetraConsole() {
  return (
    <Suspense fallback={<main id="main-content" aria-busy="true" aria-label="Loading Netra console" />}>
      <ConsoleApplication />
    </Suspense>
  );
}
