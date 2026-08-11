import { Download, Search } from "lucide-react";
import { toast } from "sonner";
import { useMemo, useState } from "react";

import { ACTIVITY } from "../data/mock";
import { Badge, Button, EmptyState, Input, NativeSelect, Panel, PanelHeader, Table, TableWrap, Td, Th } from "../components/ui/primitives";
import { PageBody, PageHeader, ResultBadge } from "../components/common";
import { cn, timeLabel } from "../lib/utils";
import type { ActivityResult, ActivitySource } from "../data/types";

const SOURCES: ActivitySource[] = ["AccessLog", "AdminAudit", "Custody", "OperationalEvent", "CaseHistory"];

/** Each source keeps its own retention and integrity guarantees; the feed
 *  unions them at read time rather than copying rows. See plan §6. */
const SOURCE_NOTE: Record<ActivitySource, string> = {
  AccessLog: "Every permission check · 90 d",
  AdminAudit: "Administrator writes · hash-chained",
  Custody: "Evidence custody · immutable",
  OperationalEvent: "System and job events · 1 y",
  CaseHistory: "Case narrative · case lifetime",
};

export function ActivityPage() {
  // Denied-in-24-hours is the default because it turns a log into a triage
  // queue. Defaults matter more than features on this screen.
  const [result, setResult] = useState<ActivityResult | "all">("denied");
  const [source, setSource] = useState<ActivitySource | "all">("all");
  const [query, setQuery] = useState("");

  const rows = useMemo(() => {
    const needle = query.trim().toLowerCase();
    return ACTIVITY.filter((event) => {
      if (result !== "all" && event.result !== result) return false;
      if (source !== "all" && event.source !== source) return false;
      if (!needle) return true;
      return [event.actor, event.action, event.target, event.role].some((value) => value.toLowerCase().includes(needle));
    });
  }, [result, source, query]);

  const deniedTotal = ACTIVITY.filter((event) => event.result === "denied").length;

  return (
    <>
      <PageHeader
        title="Activity"
        summary={`All streams · ${ACTIVITY.length} events in window · ${deniedTotal} denied`}
        action={
          <Button
            variant="outline"
            size="sm"
            onClick={() => toast("Export CSV", { description: "Export runs through the compliance permission — phase 1." })}
          >
            <Download className="size-3.5" strokeWidth={1.75} aria-hidden="true" />
            Export CSV
          </Button>
        }
      />

      <PageBody>
        <Panel className="flex flex-wrap items-center gap-2 px-3 py-2.5">
          <div className="relative min-w-[13rem] flex-1">
            <Search className="pointer-events-none absolute top-1/2 left-2.5 size-3.5 -translate-y-1/2 text-sand-muted/60" strokeWidth={1.75} aria-hidden="true" />
            <Input
              value={query}
              onChange={(event) => setQuery(event.target.value)}
              placeholder="Search user, action or resource id"
              className="pl-8"
              aria-label="Search activity"
            />
          </div>

          <NativeSelect value={result} onChange={(event) => setResult(event.target.value as ActivityResult | "all")} aria-label="Filter by result">
            <option value="denied">Result: denied</option>
            <option value="allowed">Result: allowed</option>
            <option value="recorded">Result: recorded</option>
            <option value="all">Result: all</option>
          </NativeSelect>

          <NativeSelect value={source} onChange={(event) => setSource(event.target.value as ActivitySource | "all")} aria-label="Filter by source">
            <option value="all">Source: all</option>
            {SOURCES.map((entry) => (
              <option key={entry} value={entry}>
                {entry}
              </option>
            ))}
          </NativeSelect>

          <Badge tone="accent">Window: 24 h</Badge>
        </Panel>

        <Panel>
          {rows.length === 0 ? (
            <EmptyState title="No events match those filters" hint="Widen the result or source filter." />
          ) : (
            <TableWrap>
              <Table className="min-w-[56rem]">
                <thead>
                  <tr>
                    <Th className="w-24">Time</Th>
                    <Th>User</Th>
                    <Th>Role</Th>
                    <Th>Action</Th>
                    <Th>Target</Th>
                    <Th>Result</Th>
                    <Th>Source</Th>
                  </tr>
                </thead>
                <tbody>
                  {rows.map((event) => (
                    <tr key={event.id} className={cn("hover:bg-cream-primary/4", event.result === "denied" && "bg-state-crit/6")}>
                      <Td className="font-mono text-xs whitespace-nowrap text-sand-muted">{timeLabel(event.at)}</Td>
                      <Td>
                        <span className="block text-xs text-cream-bright">{event.actor}</span>
                        {event.actorEmail ? (
                          <span className="block font-mono text-[10px] text-sand-muted/60">{event.actorEmail}</span>
                        ) : null}
                      </Td>
                      <Td className="font-mono text-xs whitespace-nowrap text-sand-muted">{event.role}</Td>
                      <Td>
                        <span className={cn("font-mono text-xs", event.result === "denied" ? "text-state-crit" : "text-cream-primary")}>
                          {event.action}
                        </span>
                      </Td>
                      <Td className="font-mono text-xs text-sand-muted">{event.target}</Td>
                      <Td>
                        <ResultBadge result={event.result} />
                      </Td>
                      <Td>
                        <span className="font-mono text-[11px] text-sand-muted/80">{event.source}</span>
                        {event.chainIndex !== null ? (
                          <span className="mt-0.5 block font-mono text-[10px] text-signal">chain #{event.chainIndex}</span>
                        ) : null}
                      </Td>
                    </tr>
                  ))}
                </tbody>
              </Table>
            </TableWrap>
          )}
          <p className="border-t border-hairline px-4 py-2.5 font-mono text-[11px] text-sand-muted/70">
            Showing {rows.length} of {ACTIVITY.length}. Paged on (time, id) — offset paging over an append-heavy log skips rows.
          </p>
        </Panel>

        <Panel>
          <PanelHeader title="Where these events come from" hint="Unioned at read time — no copied rows, so each source stays authoritative over itself" />
          <ul className="divide-y divide-[color:var(--color-hairline)]">
            {SOURCES.map((entry) => (
              <li key={entry} className="flex flex-wrap items-center gap-3 px-4 py-2.5">
                <span className="min-w-[9rem] font-mono text-xs text-cream-primary">{entry}</span>
                <span className="flex-1 text-[11px] text-sand-muted/75">{SOURCE_NOTE[entry]}</span>
                <span className="font-mono text-[11px] text-sand-muted/60">
                  {ACTIVITY.filter((event) => event.source === entry).length} in window
                </span>
              </li>
            ))}
          </ul>
        </Panel>
      </PageBody>
    </>
  );
}
