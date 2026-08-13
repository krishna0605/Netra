import { useState } from "react";
import { CheckCircle2, Link2, ShieldAlert } from "lucide-react";
import { toast } from "sonner";

import { ApiFailure, verifyAuditChain, type ChainVerification } from "../data/client";
import { useDirectory } from "../data/store";
import { DataRegion, SkeletonList } from "../components/states";
import { LoadMore, useIncremental } from "../components/LoadMore";
import { Button, Panel, PanelHeader, Status, Tag } from "../components/ui/primitives";
import { PageBody, PageHeader } from "../components/common";
import { dateTimeLabel } from "../lib/utils";

export function AuditPage() {
  const { audit, loading, error, refetch } = useDirectory();
  const head = audit[0];
  const page = useIncremental(audit, 20);
  const [checking, setChecking] = useState(false);
  const [result, setResult] = useState<ChainVerification | null>(null);

  const verified = result?.verified === true;
  const broken = result?.verified === false;

  const check = async () => {
    setChecking(true);
    try {
      const report = await verifyAuditChain();
      setResult(report);
      if (report.verified) {
        toast.success("Trail verified", {
          description: `${report.eventCount} ${report.eventCount === 1 ? "entry" : "entries"}, no gaps, every link intact.`,
        });
      } else {
        // Deliberately not a toast that fades. A broken chain is a finding
        // somebody has to act on, so it stays on the panel until re-checked.
        toast.error("Trail verification failed", {
          description: `The chain stops agreeing at entry ${report.firstBrokenIndex}. Entries after it cannot be relied on.`,
        });
      }
    } catch (failure) {
      // An unreachable service is not a verified chain and not a broken one.
      // Saying either would be a lie in a different direction.
      setResult(null);
      toast.error("Could not verify", {
        description: failure instanceof ApiFailure ? failure.message : "The verification service did not respond.",
      });
    } finally {
      setChecking(false);
    }
  };

  return (
    <>
      <PageHeader
        title="Audit trail"
        summary={loading ? "Loading…" : `${audit.length} administrator actions · sequence ${head?.chainIndex ?? "—"}`}
        action={
          <Button variant="outline" size="sm" onClick={() => void check()} disabled={checking}>
            <CheckCircle2 className="size-3.5" strokeWidth={1.75} aria-hidden="true" />
            {checking ? "Verifying…" : "Verify"}
          </Button>
        }
      />

      <PageBody>
        {/* The badge reports what was actually checked, and says so until it
            has been. Claiming "Intact" before anyone verified anything is the
            reassurance a tamper-evident trail exists to withhold. */}
        <Panel className="flex flex-wrap items-center gap-4 px-5 py-4">
          <span
            className={
              broken
                ? "grid size-9 shrink-0 place-items-center rounded-control border border-state-crit/40 bg-state-crit/10 text-state-crit"
                : verified
                  ? "grid size-9 shrink-0 place-items-center rounded-control border border-state-ok/40 bg-state-ok/10 text-state-ok"
                  : "grid size-9 shrink-0 place-items-center rounded-control border border-[color:var(--color-control-edge)] bg-cream-primary/5 text-sand-muted/70"
            }
          >
            {broken ? (
              <ShieldAlert className="size-4" strokeWidth={1.75} aria-hidden="true" />
            ) : (
              <CheckCircle2 className="size-4" strokeWidth={1.75} aria-hidden="true" />
            )}
          </span>
          <p className="min-w-0 flex-1 text-[13px] leading-relaxed text-sand-muted/70">
            {broken
              ? `The chain stops agreeing at entry ${result?.firstBrokenIndex}. Entries before it are still sealed; everything after cannot be relied on.`
              : "Every administrator action is recorded here and cryptographically linked to the one before it. Entries cannot be edited or removed, including by the people they record."}
          </p>
          <Status tone={broken ? "crit" : verified ? "ok" : "neutral"}>
            {broken ? "Broken" : verified ? "Verified" : "Not verified"}
          </Status>
        </Panel>

        <Panel>
          <PanelHeader title="Entries" hint="Newest first" />
          <DataRegion
            loading={loading}
            error={error}
            empty={audit.length === 0}
            onRetry={() => void refetch()}
            skeleton={<SkeletonList rows={4} />}
            emptyState={<div className="px-5 py-14 text-center text-[13px] text-sand-muted">No administrator actions recorded yet.</div>}
          >
          <ol className="divide-y divide-[color:var(--color-hairline)]">
            {page.slice.map((event) => (
              <li key={event.id} className="px-5 py-5 transition-colors hover:bg-cream-primary/3">
                <div className="flex flex-wrap items-baseline gap-x-3 gap-y-2">
                  <Tag tone="accent" mono>
                    {event.chainIndex}
                  </Tag>
                  <span className="font-mono text-[15px] text-cream-bright">{event.action}</span>
                  <span className="font-mono text-xs text-sand-muted/70">
                    {event.targetType} · {event.targetId}
                  </span>
                  <time className="ml-auto text-xs whitespace-nowrap text-sand-muted/70">{dateTimeLabel(event.at)}</time>
                </div>

                <p className="mt-3 max-w-3xl border-l-2 border-hairline-strong pl-4 text-[13px] leading-relaxed text-sand-muted">
                  {event.reason}
                </p>

                <div className="mt-4 grid gap-2.5 sm:grid-cols-2">
                  <div className="rounded-control border border-hairline bg-charcoal-deep/50 px-4 py-3">
                    <p className="text-[11px] tracking-[0.08em] text-sand-muted/70 uppercase">Before</p>
                    <p className="mt-1 font-mono text-xs break-words text-sand-muted">{event.before}</p>
                  </div>
                  <div className="rounded-control border border-signal/35 bg-signal/6 px-4 py-3">
                    <p className="text-[11px] tracking-[0.08em] text-signal uppercase">After</p>
                    <p className="mt-1 font-mono text-xs break-words text-cream-primary">{event.after}</p>
                  </div>
                </div>

                <div className="mt-3 flex flex-wrap items-center gap-x-5 gap-y-1 text-xs text-sand-muted/70">
                  <span>{event.actor}</span>
                  <span className="flex items-center gap-1.5 font-mono">
                    <Link2 className="size-3" strokeWidth={2} aria-hidden="true" />
                    {event.previousHash}
                  </span>
                  <span className="font-mono">{event.eventHash}</span>
                </div>
              </li>
            ))}
          </ol>
          </DataRegion>
          {!loading && !error ? (
            <LoadMore shown={page.shown} total={audit.length} remaining={page.remaining} onMore={page.showMore} noun="entries" />
          ) : null}
        </Panel>
      </PageBody>
    </>
  );
}
