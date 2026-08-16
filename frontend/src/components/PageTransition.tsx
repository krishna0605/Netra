export function PageTransition({ label = "Loading secure access" }: { label?: string }) {
  return (
    <main className="app-theme auth-theme flex min-h-screen items-center justify-center" id="main-content" aria-busy="true">
      <div role="status" aria-live="polite">
        <span className="block size-6 animate-spin rounded-full border-2 border-[var(--border-strong)] border-t-[var(--accent)] motion-reduce:animate-none" aria-hidden="true" />
        <span className="sr-only">{label}</span>
      </div>
    </main>
  );
}

export function InlineTransition({ label = "Loading view" }: { label?: string }) {
  return (
    <div className="flex min-h-40 items-center justify-center" aria-busy="true" role="status" aria-live="polite">
      <span className="block size-5 animate-spin rounded-full border-2 border-[var(--border-strong)] border-t-[var(--accent)] motion-reduce:animate-none" aria-hidden="true" />
      <span className="sr-only">{label}</span>
    </div>
  );
}
