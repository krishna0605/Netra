import { useEffect, useRef, useState, type ClipboardEvent, type KeyboardEvent } from "react";

import { AuthLayout } from "./AuthLayout";
import { Button } from "../../components/ui/primitives";
import { cn } from "../../lib/utils";
import { useAuth } from "./AuthContext";

const LENGTH = 6;

/**
 * Six separate boxes rather than one field. Typing advances, backspace on an
 * empty box steps back, and pasting a whole code fills every box — the three
 * things people actually do with a code from an authenticator.
 */
export function VerifyPage() {
  const { verifyCode, error, busy, signOut, clearError } = useAuth();
  const [digits, setDigits] = useState<string[]>(Array(LENGTH).fill(""));
  const inputs = useRef<(HTMLInputElement | null)[]>([]);

  const code = digits.join("");
  const complete = code.length === LENGTH;

  useEffect(() => {
    inputs.current[0]?.focus();
  }, []);

  function write(index: number, raw: string) {
    const value = raw.replace(/\D/g, "");
    if (error) clearError();

    setDigits((current) => {
      const next = [...current];
      if (value.length === 0) {
        next[index] = "";
        return next;
      }
      // Typing over a filled box, or a multi-character input event, spills forward.
      for (let offset = 0; offset < value.length && index + offset < LENGTH; offset += 1) {
        next[index + offset] = value[offset];
      }
      return next;
    });

    const advanceTo = Math.min(index + value.length, LENGTH - 1);
    if (value.length > 0) inputs.current[advanceTo]?.focus();
  }

  function onKeyDown(index: number, event: KeyboardEvent<HTMLInputElement>) {
    if (event.key === "Backspace" && digits[index] === "" && index > 0) {
      event.preventDefault();
      inputs.current[index - 1]?.focus();
      setDigits((current) => {
        const next = [...current];
        next[index - 1] = "";
        return next;
      });
    }
    if (event.key === "ArrowLeft" && index > 0) inputs.current[index - 1]?.focus();
    if (event.key === "ArrowRight" && index < LENGTH - 1) inputs.current[index + 1]?.focus();
  }

  function onPaste(event: ClipboardEvent<HTMLInputElement>) {
    const pasted = event.clipboardData.getData("text").replace(/\D/g, "").slice(0, LENGTH);
    if (!pasted) return;
    event.preventDefault();
    setDigits(Array.from({ length: LENGTH }, (_, index) => pasted[index] ?? ""));
    inputs.current[Math.min(pasted.length, LENGTH - 1)]?.focus();
  }

  function submit() {
    if (complete && !busy) void verifyCode(code);
  }

  // Submit as soon as the sixth digit lands — nobody wants to press a button
  // after typing a code that is already complete.
  useEffect(() => {
    if (complete && !busy) void verifyCode(code);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [complete]);

  return (
    <AuthLayout
      title="Verification"
      subtitle="Enter the six-digit code from your authenticator."
      footer={
        <button type="button" onClick={() => void signOut()} className="underline underline-offset-2 hover:text-cream-bright">
          Use a different account
        </button>
      }
    >
      <div className="flex flex-col gap-4">
        <div className="flex justify-center gap-2" onPaste={onPaste}>
          {digits.map((digit, index) => (
            <input
              key={index}
              ref={(element) => {
                inputs.current[index] = element;
              }}
              value={digit}
              onChange={(event) => write(index, event.target.value)}
              onKeyDown={(event) => onKeyDown(index, event)}
              inputMode="numeric"
              autoComplete={index === 0 ? "one-time-code" : "off"}
              maxLength={1}
              aria-label={`Digit ${index + 1} of ${LENGTH}`}
              disabled={busy}
              className={cn(
                "h-14 w-11 rounded-control border bg-charcoal-deep text-center font-mono text-xl text-cream-bright",
                "focus:border-signal focus:outline-none disabled:opacity-50",
                digit ? "border-hairline-strong" : "border-hairline",
              )}
            />
          ))}
        </div>

        {error ? (
          <p role="alert" className="rounded-control border border-state-crit/50 bg-state-crit/10 px-3.5 py-2.5 text-center text-[13px] text-state-crit">
            {error}
          </p>
        ) : null}

        <Button type="button" variant="primary" disabled={!complete || busy} onClick={submit} className="w-full">
          {busy ? "Verifying…" : "Verify"}
        </Button>

        <p className="text-center text-[12.5px] text-sand-muted/70">
          Lost your authenticator? Contact your department administrator.
        </p>
      </div>
    </AuthLayout>
  );
}
