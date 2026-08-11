import { CheckCircle2, Link2 } from "lucide-react";
import { toast } from "sonner";

import { useDirectory } from "../data/store";
import { Button, Panel, PanelHeader, Status, Tag } from "../components/ui/primitives";
import { PageBody, PageHeader } from "../components/common";
import { dateTimeLabel } from "../lib/utils";

export function AuditPage() {
  const { audit } = useDirectory();
  const head = audit[0];

  return (
    <>
      <PageHeader
        title="Audit trail"
        summary={`${audit.length} administrator actions · sequence ${head.chainIndex}`}
        action={
          <Button
            variant="outline"
            size="sm"
            onClick={() => toast.success("Trail verified", { description: `${audit.length} entries, no gaps, every link intact.` })}
          >
            <CheckCircle2 className="size-3.5" strokeWidth={1.75} aria-hidden="true" />
            Verify
          </Button>
        }
      />

      <PageBody>
        <Panel className="flex flex-wrap items-center gap-4 px-5 py-4">
          <span className="grid size-9 shrink-0 place-items-center rounded-control border border-state-ok/40 bg-state-ok/10 text-state-ok">
            <CheckCircle2 className="size-4" strokeWidth={1.75} aria-hidden="true" />
          </span>
          <p className="min-w-0 flex-1 text-[13px] leading-relaxed text-sand-muted">
            Every administrator action is recorded here and cryptographically linked to the one before it. Entries cannot be edited or
            removed, including by the people they record.
          </p>
          <Status tone="ok">Intact</Status>
        </Panel>

        <Panel>
          <PanelHeader title="Entries" hint="Newest first" />
          <ol className="divide-y divide-[color:var(--color-hairline)]">
            {audit.map((event) => (
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
                    <p className="text-[11px] tracking-[0.08em] text-sand-muted/55 uppercase">Before</p>
                    <p className="mt-1 font-mono text-xs break-words text-sand-muted">{event.before}</p>
                  </div>
                  <div className="rounded-control border border-signal/35 bg-signal/6 px-4 py-3">
                    <p className="text-[11px] tracking-[0.08em] text-signal uppercase">After</p>
                    <p className="mt-1 font-mono text-xs break-words text-cream-primary">{event.after}</p>
                  </div>
                </div>

                <div className="mt-3 flex flex-wrap items-center gap-x-5 gap-y-1 text-xs text-sand-muted/60">
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
        </Panel>
      </PageBody>
    </>
  );
}
