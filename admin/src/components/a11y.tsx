import { useEffect, useRef, useState } from "react";

/**
 * A link that only exists for keyboard users.
 *
 * The nav rail has eight destinations. Without this, reaching the table on
 * every screen means tabbing past all of them, every time.
 */
export function SkipLink() {
  return (
    <a
      href="#main"
      className="sr-only rounded-control bg-signal px-4 py-2 text-[13px] font-semibold text-charcoal-deep focus:not-sr-only focus:absolute focus:top-3 focus:left-3 focus:z-50"
    >
      Skip to content
    </a>
  );
}

/**
 * Announces state changes that are otherwise only visible.
 *
 * A sighted operator sees a table replace a skeleton. A screen-reader user
 * gets nothing unless it is said out loud — the region simply goes quiet and
 * then has different contents.
 */
export function useAnnounce(message: string) {
  const [announcement, setAnnouncement] = useState("");
  const previous = useRef("");

  useEffect(() => {
    if (message && message !== previous.current) {
      previous.current = message;
      // Clearing first forces re-announcement when the same text recurs.
      setAnnouncement("");
      const timer = window.setTimeout(() => setAnnouncement(message), 60);
      return () => window.clearTimeout(timer);
    }
  }, [message]);

  return announcement;
}

export function LiveRegion({ message }: { message: string }) {
  const announcement = useAnnounce(message);
  return (
    <p aria-live="polite" aria-atomic="true" className="sr-only">
      {announcement}
    </p>
  );
}

/**
 * Describes what a data region is doing, in the words a person would use.
 * Kept in one place so every screen announces the same way.
 */
export function regionStatus({
  loading,
  error,
  count,
  noun,
}: {
  loading: boolean;
  error: string;
  count: number;
  noun: string;
}) {
  if (loading) return `Loading ${noun}`;
  if (error) return `Could not load ${noun}. ${error}`;
  if (count === 0) return `No ${noun} match the current filters`;
  return `${count} ${count === 1 ? noun.replace(/s$/, "") : noun} shown`;
}
