import { Download, Search } from "lucide-react";
import { toast } from "sonner";
import { useMemo, useState } from "react";

import { useDirectory } from "../data/store";
import { DataRegion, SkeletonTable } from "../components/states";
import { Button, EmptyState, Input, NativeSelect, Panel, Table, TableWrap, Tag, Td, Th } from "../components/ui/primitives";
import { PageBody, PageHeader, ResultBadge } from "../components/common";
import { cn, timeLabel } from "../lib/utils";
import type { ActivityResult, ActivitySource } from "../data/types";

const SOURCES: ActivitySource[] = ["AccessLog", "AdminAudit", "Custody", "OperationalEvent", "CaseHistory"];

const SOURCE_LABEL: Record<ActivitySource, string> = {
  AccessLog: "Access",
  AdminAudit: "Administration",
  Custody: "Custody",
  OperationalEvent: "System",
  CaseHistory: "Case",
};

export function ActivityPage() {
  const { activity, loading, error, refetch } = useDirectory();
  // Denied-in-24-hours is the default: it turns a log into a triage queue.
  const [result, setResult] = useState<ActivityResult | "all">("denied");
  const [source, setSource] = useState<ActivitySource | "all">("all");
  const [query, setQuery] = useState("");

  const rows = useMemo(() => {
    const needle = query.trim().toLowerCase();
    return activity.filter((event) => {
      if (result !== "all" && event.result !== result) return false;
      if (source !== "all" && event.source !== source) return false;
      if (!needle) return true;
      return [event.actor, event.action, event.target, event.role].some((value) => value.toLowerCase().includes(needle));
    });
  }, [activity, result, source, query]);

  const deniedTotal = activity.filter((event) => event.result === "denied").length;

  return (
    <>
      <PageHeader
        title="Activity"
        summary={`${activity.length} events in the last 24 hours · ${deniedTotal} denied`}
        action={
          <Button variant="outline" size="sm" onClick={() => toast("Export prepared", { description: "The filtered range has been exported." })}>
            <Download className="size-3.5" strokeWidth={1.75} aria-hidden="true" />
            Export
          </Button>
        }
      />

      <PageBody>
        <div className="flex flex-wrap items-center gap-2">
          <div className="relative min-w-[15rem] flex-1">
            <Search className="pointer-events-none absolute top-1/2 left-3 size-4 -translate-y-1/2 text-sand-muted/50" strokeWidth={1.75} aria-hidden="true" />
            <Input
              value={query}
              onChange={(event) => setQuery(event.target.value)}
              placeholder="Search user, action or resource"
              className="pl-9"
              aria-label="Search activity"
            />
          </div>

          <NativeSelect value={result} onChange={(event) => setResult(event.target.value as ActivityResult | "all")} aria-label="Filter by result">
            <option value="denied">Denied only</option>
            <option value="allowed">Allowed only</option>
            <option value="recorded">Recorded only</option>
            <option value="all">All results</option>
          </NativeSelect>

          <NativeSelect value={source} onChange={(event) => setSource(event.target.value as ActivitySource | "all")} aria-label="Filter by source">
            <option value="all">All sources</option>
            {SOURCES.map((entry) => (
              <option key={entry} value={entry}>
                {SOURCE_LABEL[entry]}
              </option>
            ))}
          </NativeSelect>
        </div>

        <Panel>
          <DataRegion
            loading={loading}
            error={error}
            empty={rows.length === 0}
            onRetry={() => void refetch()}
            skeleton={<SkeletonTable rows={8} columns={7} />}
            emptyState={<EmptyState title="No events match those filters" hint="Widen the result or source filter." />}
          >
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
                    <tr key={event.id} className={cn("transition-colors hover:bg-cream-primary/4", event.result === "denied" && "bg-state-crit/5")}>
                      <Td className="font-mono text-xs whitespace-nowrap text-sand-muted">{timeLabel(event.at)}</Td>
                      <Td>
                        <span className="block text-[13px] text-cream-bright">{event.actor}</span>
                        {event.actorEmail ? <span className="block font-mono text-xs text-sand-muted/60">{event.actorEmail}</span> : null}
                      </Td>
                      <Td className="text-[13px] whitespace-nowrap text-sand-muted">{event.role}</Td>
                      <Td>
                        <span className={cn("font-mono text-[13px]", event.result === "denied" ? "text-state-crit" : "text-cream-primary")}>
                          {event.action}
                        </span>
                      </Td>
                      <Td className="font-mono text-xs text-sand-muted">{event.target}</Td>
                      <Td>
                        <ResultBadge result={event.result} />
                      </Td>
                      <Td>
                        <div className="flex items-center gap-2">
                          <span className="text-[13px] text-sand-muted/80">{SOURCE_LABEL[event.source]}</span>
                          {event.chainIndex !== null ? (
                            <Tag tone="neutral" mono>
                              {event.chainIndex}
                            </Tag>
                          ) : null}
                        </div>
                      </Td>
                    </tr>
                  ))}
                </tbody>
              </Table>
            </TableWrap>
          </DataRegion>
        </Panel>
      </PageBody>
    </>
  );
}
