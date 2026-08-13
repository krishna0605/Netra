import { AlertTriangle, RotateCw } from "lucide-react";
import { Component, type ErrorInfo, type ReactNode } from "react";

import { Button, Panel } from "./ui/primitives";
import { cn } from "../lib/utils";

/* ---------------------------------------------------------------------------
   Skeletons — shaped like the content they replace, so the layout does not
   jump when data lands.
   --------------------------------------------------------------------------- */

export function Shimmer({ className }: { className?: string }) {
  return <span className={cn("block animate-pulse rounded-chip bg-cream-primary/8", className)} aria-hidden="true" />;
}

export function SkeletonTable({ rows = 6, columns = 5 }: { rows?: number; columns?: number }) {
  return (
    <div className="px-5 py-4" aria-busy="true" aria-live="polite">
      <span className="sr-only">Loading</span>
      <div className="flex flex-col gap-4">
        {Array.from({ length: rows }).map((_, row) => (
          <div key={row} className="flex items-center gap-4">
            {Array.from({ length: columns }).map((_, column) => (
              <Shimmer
                key={column}
                className={cn("h-3.5", column === 0 ? "w-[22%]" : column === columns - 1 ? "w-[10%]" : "flex-1")}
              />
            ))}
          </div>
        ))}
      </div>
    </div>
  );
}

export function SkeletonTiles({ count = 5 }: { count?: number }) {
  return (
    <div className="grid gap-3 sm:grid-cols-2 lg:grid-cols-5" aria-busy="true">
      <span className="sr-only">Loading</span>
      {Array.from({ length: count }).map((_, index) => (
        <Panel key={index} className="px-4 py-4">
          <Shimmer className="h-3 w-24" />
          <Shimmer className="mt-3 h-7 w-14" />
          <Shimmer className="mt-3 h-2.5 w-20" />
        </Panel>
      ))}
    </div>
  );
}

export function SkeletonList({ rows = 5 }: { rows?: number }) {
  return (
    <ul className="divide-y divide-[color:var(--color-hairline)]" aria-busy="true">
      <span className="sr-only">Loading</span>
      {Array.from({ length: rows }).map((_, index) => (
        <li key={index} className="flex items-center gap-4 px-5 py-3.5">
          <Shimmer className="h-3 w-14" />
          <div className="flex-1">
            <Shimmer className="h-3.5 w-2/5" />
            <Shimmer className="mt-2 h-2.5 w-3/5" />
          </div>
        </li>
      ))}
    </ul>
  );
}

/* ---------------------------------------------------------------------------
   Failure — deliberately distinct from an empty result.
   --------------------------------------------------------------------------- */

/**
 * "No denied actions in this window" is reassuring; "we could not load denied
 * actions" is alarming. Rendering both as a blank table is the single most
 * misleading thing a console like this can do.
 */
export function ErrorState({
  title = "Could not load this",
  detail,
  onRetry,
  retrying = false,
}: {
  title?: string;
  detail: string;
  onRetry?: () => void;
  retrying?: boolean;
}) {
  return (
    <div role="alert" className="flex flex-col items-center gap-3 px-6 py-14 text-center">
      <span className="grid size-11 place-items-center rounded-control border border-state-crit/40 bg-state-crit/10 text-state-crit">
        <AlertTriangle className="size-5" strokeWidth={1.75} aria-hidden="true" />
      </span>
      <p className="text-[15px] font-medium text-cream-bright">{title}</p>
      <p className="max-w-md text-[13px] leading-relaxed text-sand-muted/80">{detail}</p>
      {onRetry ? (
        <Button variant="outline" size="sm" onClick={onRetry} disabled={retrying} className="mt-1">
          <RotateCw className={cn("size-3.5", retrying && "animate-spin")} strokeWidth={1.75} aria-hidden="true" />
          {retrying ? "Retrying…" : "Try again"}
        </Button>
      ) : null}
    </div>
  );
}

/**
 * Renders one of the four states a data-bearing region can be in. Centralised
 * so a failure looks identical on every screen.
 */
export function DataRegion({
  loading,
  error,
  empty,
  onRetry,
  skeleton,
  emptyState,
  children,
}: {
  loading: boolean;
  error: string;
  empty: boolean;
  onRetry?: () => void;
  skeleton: ReactNode;
  emptyState: ReactNode;
  children: ReactNode;
}) {
  if (loading) return <>{skeleton}</>;
  if (error) return <ErrorState detail={error} onRetry={onRetry} />;
  if (empty) return <>{emptyState}</>;
  return <>{children}</>;
}

/* ---------------------------------------------------------------------------
   Crash containment
   --------------------------------------------------------------------------- */

type BoundaryState = { failed: boolean; detail: string };

export class ErrorBoundary extends Component<{ children: ReactNode }, BoundaryState> {
  state: BoundaryState = { failed: false, detail: "" };

  static getDerivedStateFromError(error: unknown): BoundaryState {
    return { failed: true, detail: error instanceof Error ? error.message : "An unexpected error occurred." };
  }

  componentDidCatch(error: Error, info: ErrorInfo) {
    console.error("Admin console crashed", error, info.componentStack);
  }

  render() {
    if (!this.state.failed) return this.props.children;

    return (
      <div className="app-theme flex min-h-screen flex-col items-center justify-center gap-4 px-6 text-center">
        <img src="/brand/netra-logo-mark.svg" alt="" className="size-10 opacity-20" aria-hidden="true" />
        <h1 className="text-[19px] font-semibold text-cream-bright">Something went wrong</h1>
        <p className="max-w-md text-[13.5px] leading-relaxed text-sand-muted/80">
          The console stopped unexpectedly. Reloading usually clears it. Nothing you had open was submitted.
        </p>
        <Button variant="primary" size="sm" onClick={() => window.location.reload()}>
          Reload the console
        </Button>
      </div>
    );
  }
}
