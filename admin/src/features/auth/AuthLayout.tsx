import type { ReactNode } from "react";

/**
 * Shared frame for every pre-workspace screen.
 *
 * Deliberately gives no hint that a second console exists — no "administrator
 * sign-in" heading, no link to anything privileged. Someone holding a stolen
 * non-administrative password should learn nothing from these pages.
 */
export function AuthLayout({
  title,
  subtitle,
  children,
  footer,
  width = "narrow",
}: {
  title: string;
  subtitle?: ReactNode;
  children: ReactNode;
  footer?: ReactNode;
  width?: "narrow" | "wide";
}) {
  return (
    <div className="app-theme flex min-h-screen flex-col items-center justify-center px-5 py-12">
      <div className={width === "wide" ? "w-full max-w-2xl" : "w-full max-w-md"}>
        <div className="mb-8 flex items-center gap-3">
          <img src="/brand/netra-logo-mark.svg" alt="" className="size-9 shrink-0" aria-hidden="true" />
          <div className="min-w-0">
            <p className="font-mono text-[16px] leading-tight font-semibold tracking-[0.05em] text-cream-bright">NETRA</p>
            <p className="text-[12px] leading-tight text-sand-muted/70">Network evidence platform</p>
          </div>
        </div>

        <h1 className="text-[22px] font-semibold tracking-[-0.02em] text-cream-bright">{title}</h1>
        {subtitle ? <p className="mt-1.5 text-[13.5px] text-sand-muted/80">{subtitle}</p> : null}

        <div className="mt-7">{children}</div>

        {footer ? <div className="mt-6 text-center text-[12.5px] text-sand-muted/65">{footer}</div> : null}
      </div>
    </div>
  );
}
