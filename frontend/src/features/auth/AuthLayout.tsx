import type { ReactNode } from "react";

/**
 * One neutral frame for every pre-workspace screen.
 *
 * It intentionally does not advertise whether Administration exists. The
 * server reveals the workspace choices only after authentication, MFA and
 * permission resolution have all succeeded.
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
    <main className="app-theme auth-theme flex min-h-screen flex-col items-center justify-center px-5 py-12" id="main-content">
      <section className={width === "wide" ? "w-full max-w-2xl" : "w-full max-w-md"} aria-labelledby="auth-heading">
        <div className="mb-8 flex items-center gap-3">
          <img src="/brand/netra-logo-mark.svg" alt="" className="size-9 shrink-0" aria-hidden="true" />
          <div className="min-w-0">
            <p className="font-mono text-[16px] leading-tight font-semibold tracking-[0.05em] text-[var(--text-strong)]">NETRA</p>
            <p className="text-[12px] leading-tight text-[var(--muted)]">Network evidence platform</p>
          </div>
        </div>

        <h1 id="auth-heading" className="text-[22px] font-semibold tracking-[-0.02em] text-[var(--text-strong)]">{title}</h1>
        {subtitle ? <p className="mt-1.5 text-[13.5px] text-[var(--muted)]">{subtitle}</p> : null}
        <div className="mt-7">{children}</div>
        {footer ? <div className="mt-6 text-center text-[12.5px] text-[var(--muted)]">{footer}</div> : null}
      </section>
    </main>
  );
}
