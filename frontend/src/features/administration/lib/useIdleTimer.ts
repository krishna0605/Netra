import { useCallback, useEffect, useRef, useState } from "react";

const ACTIVITY_EVENTS = ["pointerdown", "keydown", "wheel", "touchstart"] as const;

type IdleOptions = {
  /** Total idle time before the session is dropped. */
  timeoutMs: number;
  /** How long the warning shows before that. */
  warnMs: number;
  onWarn?: () => void;
  onExpire: () => void;
  enabled?: boolean;
};

/**
 * Idle tracking for the administrative session.
 *
 * Fires a warning first rather than dropping the session without notice —
 * losing half-typed input on a console that requires a written reason for
 * every destructive action would be its own kind of failure.
 */
export function useIdleTimer({ timeoutMs, warnMs, onWarn, onExpire, enabled = true }: IdleOptions) {
  const [warning, setWarning] = useState(false);
  const [msRemaining, setMsRemaining] = useState(warnMs);

  const lastActive = useRef(0);
  const onWarnRef = useRef(onWarn);
  const onExpireRef = useRef(onExpire);

  useEffect(() => {
    lastActive.current = Date.now();
  }, []);

  useEffect(() => {
    onWarnRef.current = onWarn;
    onExpireRef.current = onExpire;
  }, [onExpire, onWarn]);

  const reset = useCallback(() => {
    lastActive.current = Date.now();
    setWarning(false);
    setMsRemaining(warnMs);
  }, [warnMs]);

  useEffect(() => {
    if (!enabled) return;

    const onActivity = () => {
      // While the warning is showing, ordinary activity must not silently
      // dismiss it — the operator has to make an explicit choice, otherwise a
      // stray scroll extends a session nobody is actually attending.
      if (!warning) lastActive.current = Date.now();
    };

    for (const event of ACTIVITY_EVENTS) {
      window.addEventListener(event, onActivity, { passive: true });
    }
    return () => {
      for (const event of ACTIVITY_EVENTS) window.removeEventListener(event, onActivity);
    };
  }, [enabled, warning]);

  useEffect(() => {
    if (!enabled) return;

    const tick = window.setInterval(() => {
      const idleFor = Date.now() - lastActive.current;
      const untilExpiry = timeoutMs - idleFor;

      if (untilExpiry <= 0) {
        window.clearInterval(tick);
        setWarning(false);
        onExpireRef.current();
        return;
      }

      if (untilExpiry <= warnMs) {
        setMsRemaining(untilExpiry);
        setWarning((was) => {
          if (!was) onWarnRef.current?.();
          return true;
        });
      }
    }, 1000);

    return () => window.clearInterval(tick);
  }, [enabled, timeoutMs, warnMs]);

  return { warning, msRemaining, reset };
}
