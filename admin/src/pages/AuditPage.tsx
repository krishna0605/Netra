import { CheckCircle2, Link2 } from "lucide-react";
import { toast } from "sonner";

import { AUDIT } from "../data/mock";
import { Badge, Button, Panel, PanelHeader } from "../components/ui/primitives";
import { PageBody, PageHeader } from "../components/common";
import { dateTimeLabel } from "../lib/utils";

export function AuditPage() {
  const head = AUDIT[0];

  return (
    <>
      <PageHeader
        title="Admin audit"
        summary={`${AUDIT.length} events · chain head #${head.chainIndex} · append-only`}
        action={
          <Button
            variant="outline"
            size="sm"
            onClick={() => toast.success("Chain verified", { description: `${AUDIT.length} events, no gaps, every hash links to its predecessor.` })}
          >
            <CheckCircle2 className="size-3.5" strokeWidth={1.75} aria-hidden="true" />
            Verify chain
          </Button>
        }
      />

      <PageBody>
        <Panel className="flex flex-wrap items-center gap-3 px-4 py-3">
          <CheckCircle2 className="size-4 shrink-0 text-state-ok" strokeWidth={1.75} aria-hidden="true" />
          <p className="min-w-0 flex-1 text-xs text-sand-muted">
            Every write this console makes is appended here and chained to its predecessor, the same way{" "}
            <span className="font-mono text-cream-primary">CustodyLedgerEvent</span> chains evidence handling. Administrators hold insert and
            select on this table and nothing else — the trail cannot be edited by the people it records.
          </p>
          <Badge tone="ok">Chain intact</Badge>
        </Panel>

        <Panel>
          <PanelHeader title="Events" hint="Newest first — each row carries what changed, why, and the hash that binds it to the one before" />
          <ol className="divide-y divide-[color:var(--color-hairline)]">
            {AUDIT.map((event) => (
              <li key={event.id} className="px-4 py-4">
                <div className="flex flex-wrap items-baseline gap-x-3 gap-y-1.5">
                  <Badge tone="accent">#{event.chainIndex}</Badge>
                  <span className="font-mono text-sm text-cream-bright">{event.action}</span>
                  <span className="font-mono text-[11px] text-sand-muted/70">
                    {event.targetType} · {event.targetId}
                  </span>
                  <time className="ml-auto font-mono text-[11px] whitespace-nowrap text-sand-muted/70">{dateTimeLabel(event.at)}</time>
                </div>

                <p className="mt-2 max-w-3xl border-l-2 border-hairline-strong pl-3 text-xs text-sand-muted">{event.reason}</p>

                <div className="mt-3 grid gap-2 sm:grid-cols-2">
                  <div className="border border-hairline bg-charcoal-deep/60 px-3 py-2">
                    <p className="font-mono text-[9.5px] tracking-[0.12em] text-sand-muted/60 uppercase">Before</p>
                    <p className="mt-1 font-mono text-[11px] break-words text-sand-muted">{event.before}</p>
                  </div>
                  <div className="border border-signal/40 bg-signal/6 px-3 py-2">
                    <p className="font-mono text-[9.5px] tracking-[0.12em] text-signal uppercase">After</p>
                    <p className="mt-1 font-mono text-[11px] break-words text-cream-primary">{event.after}</p>
                  </div>
                </div>

                <div className="mt-2.5 flex flex-wrap items-center gap-x-4 gap-y-1 font-mono text-[10px] text-sand-muted/60">
                  <span>by {event.actor}</span>
                  <span className="flex items-center gap-1">
                    <Link2 className="size-2.5" strokeWidth={2} aria-hidden="true" />
                    prev {event.previousHash}
                  </span>
                  <span>hash {event.eventHash}</span>
                </div>
              </li>
            ))}
          </ol>
        </Panel>
      </PageBody>
    </>
  );
}
