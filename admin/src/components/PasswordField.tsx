import { Check, Copy, Eye, EyeOff, RefreshCw } from "lucide-react";
import { useState } from "react";

import { Button, Input } from "./ui/primitives";
import { cn } from "../lib/utils";
import { generatePassword, passwordStrength } from "../data/store";

/**
 * Shared between creating an account and replacing a password. Generating is
 * the default path — an administrator inventing a password by hand is how weak
 * ones get into a system.
 */
export function PasswordField({
  value,
  onChange,
  label = "Password",
}: {
  value: string;
  onChange: (value: string) => void;
  label?: string;
}) {
  const [visible, setVisible] = useState(true);
  const [copied, setCopied] = useState(false);
  const strength = passwordStrength(value);

  async function copy() {
    try {
      await navigator.clipboard.writeText(value);
      setCopied(true);
      window.setTimeout(() => setCopied(false), 1600);
    } catch {
      // Clipboard permission denied — the value is visible on screen anyway.
    }
  }

  return (
    <div>
      <label className="mb-1.5 block text-[13px] text-sand-muted/80" htmlFor="password-field">
        {label}
      </label>
      <div className="flex gap-2">
        <div className="relative min-w-0 flex-1">
          <Input
            id="password-field"
            type={visible ? "text" : "password"}
            value={value}
            onChange={(event) => onChange(event.target.value)}
            placeholder="Generate or type a password"
            className="pr-10 font-mono"
            autoComplete="off"
            spellCheck={false}
          />
          <button
            type="button"
            onClick={() => setVisible((state) => !state)}
            className="absolute top-1/2 right-2 grid size-7 -translate-y-1/2 place-items-center rounded-control text-sand-muted/70 hover:text-cream-bright"
            aria-label={visible ? "Hide password" : "Show password"}
          >
            {visible ? <EyeOff className="size-4" strokeWidth={1.75} /> : <Eye className="size-4" strokeWidth={1.75} />}
          </button>
        </div>
        <Button type="button" variant="outline" onClick={() => onChange(generatePassword())} aria-label="Generate a password">
          <RefreshCw className="size-3.5" strokeWidth={1.75} aria-hidden="true" />
          Generate
        </Button>
        <Button type="button" variant="outline" onClick={copy} disabled={!value} aria-label="Copy password">
          {copied ? <Check className="size-3.5 text-state-ok" strokeWidth={2.5} /> : <Copy className="size-3.5" strokeWidth={1.75} />}
        </Button>
      </div>

      <div className="mt-2 flex items-center gap-2.5">
        <div className="flex h-1 flex-1 gap-1" role="presentation">
          {[1, 2, 3, 4, 5].map((step) => (
            <span
              key={step}
              className={cn(
                "flex-1 rounded-full transition-colors",
                step > strength.score
                  ? "bg-cream-primary/10"
                  : strength.score <= 2
                    ? "bg-state-crit"
                    : strength.score === 3
                      ? "bg-state-warn"
                      : "bg-state-ok",
              )}
            />
          ))}
        </div>
        <span
          className={cn(
            "w-20 text-right text-xs",
            strength.score <= 2 ? "text-state-crit" : strength.score === 3 ? "text-state-warn" : "text-state-ok",
          )}
        >
          {strength.label}
        </span>
      </div>
    </div>
  );
}
