/* eslint-disable react-refresh/only-export-components */
import { useEffect, useState } from "react";

import { Button } from "./ui/primitives";

/**
 * Incremental reveal rather than numbered pages.
 *
 * These lists are append-heavy: new events arrive at the top constantly. Under
 * offset paging, page two after an insert silently skips whatever was pushed
 * across the boundary — rows an operator would never know they had missed. A
 * keyset cursor avoids that, and "load more" is its natural interface.
 */
export function useIncremental<T>(rows: T[], step = 25) {
  const [visible, setVisible] = useState(step);

  // Any change to the filtered set starts the reveal over, so a narrower
  // filter never leaves a stale "showing 75 of 12".
  useEffect(() => {
    const reset = window.setTimeout(() => setVisible(step), 0);
    return () => window.clearTimeout(reset);
  }, [rows.length, step]);

  return {
    slice: rows.slice(0, visible),
    hasMore: rows.length > visible,
    remaining: rows.length - visible,
    showMore: () => setVisible((current) => current + step),
    shown: Math.min(visible, rows.length),
  };
}

export function LoadMore({
  shown,
  total,
  remaining,
  onMore,
  noun = "rows",
}: {
  shown: number;
  total: number;
  remaining: number;
  onMore: () => void;
  noun?: string;
}) {
  if (total === 0) return null;

  return (
    <div className="flex flex-wrap items-center justify-between gap-3 border-t border-hairline px-5 py-3">
      <p className="text-[12.5px] text-sand-muted/70">
        Showing {shown} of {total} {noun}
      </p>
      {remaining > 0 ? (
        <Button variant="outline" size="sm" onClick={onMore}>
          Load {Math.min(remaining, 25)} more
        </Button>
      ) : null}
    </div>
  );
}
