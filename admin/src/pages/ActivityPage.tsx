import { Download, Search } from "lucide-react";
import { toast } from "sonner";
import { useMemo, useState } from "react";

import { Button, EmptyState, Input, NativeSelect, Panel, Table, TableWrap, Tag, Td, Th } from "../components/ui/primitives";
import { DataRegion, SkeletonTable } from "../components/states";
import { LoadMore, useIncremental } from "../components/LoadMore";
import { PageBody, PageHeader, ResultBadge } from "../components/common";
import { cn, dateTimeLabel, timeLabel } from "../lib/utils";
import { downloadCsv, stampedName, toCsv } from "../lib/csv";
import { useDirectory } from "../data/store";
import type { ActivityResult, ActivitySource } from "../data/types";

const SOURCES: ActivitySource[] = ["AccessLog", "AdminAudit", "Custody", "OperationalEvent", "CaseHistory"];

const SOURCE_LABEL: Record<ActivitySource, string> = {
  AccessLog: "Access",
  AdminAudit: "Administration",
  Custody: "Custody",
  OperationalEvent: "System",
  CaseHistory: "Case",
};

const WINDOWS = [
  { label: "Last hour", hours: 1 },
  { label: "Last 24 hours", hours: 24 },
  { label: "Last 7 days", hours: 24 * 7 },
  { label: "Last 30 days", hours: 24 * 30 },
  { label: "Everything", hours: 0 },
];

export function ActivityPage() {
  const { activity, loading, error, refetch } = useDirectory();

  // Denied-in-24-hours is the default: it turns a log into a triage queue.
  const [result, setResult] = useState<ActivityResult | "all">("denied");
  const [source, setSource] = useState<ActivitySource | "all">("all");
  const [hours, setHours] = useState(24);
  const [query, setQuery] = useState("");

  const inWindow = useMemo(() => {
    if (hours === 0) return activity;
    const cutoff = Date.now() - hours * 3600_000;
    return activity.filter((event) => Date.parse(event.at) >= cutoff);
  }, [activity, hours]);

  const rows = useMemo(() => {
    const needle = query.trim().toLowerCase();
    return inWindow.filter((event) => {
      if (result !== "all" && event.result !== result) return false;
      if (source !== "all" && event.source !== source) return false;
      if (!needle) return true;
      return [event.actor, event.action, event.target, event.role].some((value) => value.toLowerCase().includes(needle));
    });
  }, [inWindow, result, source, query]);

  const page = useIncremental(rows, 25);
  const deniedTotal = inWindow.filter((event) => event.result === "denied").length;
  const windowLabel = WINDOWS.find((entry) => entry.hours === hours)?.label ?? "";

  function exportRows() {
    // Exactly what is on screen, filters included. An export that quietly
    // returns more would be trusted without a second thought.
    const csv = toCsv(rows, [
      { header: "Time", value: (row) => dateTimeLabel(row.at) },
      { header: "User", value: (row) => row.actor },
      { header: "Email", value: (row) => row.actorEmail },
      { header: "Role", value: (row) => row.role },
      { header: "Action", value: (row) => row.action },
      { header: "Target", value: (row) => row.target },
      { header: "Result", value: (row) => row.result },
      { header: "Source", value: (row) => SOURCE_LABEL[row.source] },
      { header: "Chain index", value: (row) => row.chainIndex ?? "" },
    ]);
    downloadCsv(stampedName("activity"), csv);
    toast.success("Export ready", { description: `${rows.length} ${rows.length === 1 ? "row" : "rows"} downloaded.` });
  }

  return (
    <>
      <PageHeader
        title="Activity"
        summary={loading ? "Loading…" : `${inWindow.length} events · ${windowLabel.toLowerCase()} · ${deniedTotal} denied`}
        action={
          <Button variant="outline" size="sm" disabled={rows.length === 0} onClick={exportRows}>
            <Download className="size-3.5" strokeWidth={1.75} aria-hidden="true" />
            Export {rows.length > 0 ? `(${rows.length})` : ""}
          </Button>
        }
      />

      <PageBody>
        <div className="flex flex-wrap items-center gap-2">
          <div className="relative min-w-[15rem] flex-1">
            <Search
              className="pointer-events-none absolute top-1/2 left-3 size-4 -translate-y-1/2 text-sand-muted/50"
              strokeWidth={1.75}
              aria-hidden="true"
            />
            <Input
              value={query}
              onChange={(event) => setQuery(event.target.value)}
              placeholder="Search user, action or resource"
              className="pl-9"
              aria-label="Search activity"
            />
          </div>

          <NativeSelect value={hours} onChange={(event) => setHours(Number(event.target.value))} aria-label="Time window">
            {WINDOWS.map((entry) => (
              <option key={entry.label} value={entry.hours}>
                {entry.label}
              </option>
            ))}
          </NativeSelect>

          <NativeSelect
            value={result}
            onChange={(event) => setResult(event.target.value as ActivityResult | "all")}
            aria-label="Filter by result"
          >
            <option value="denied">Denied only</option>
            <option value="allowed">Allowed only</option>
            <option value="recorded">Recorded only</option>
            <option value="all">All results</option>
          </NativeSelect>

          <NativeSelect
            value={source}
            onChange={(event) => setSource(event.target.value as ActivitySource | "all")}
            aria-label="Filter by source"
          >
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
            emptyState={
              <EmptyState
                title="Nothing matches those filters"
                hint="Widen the time window, or switch the result filter to see allowed events too."
              />
            }
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
                  {page.slice.map((event) => (
                    <tr
                      key={event.id}
                      className={cn("transition-colors hover:bg-cream-primary/4", event.result === "denied" && "bg-state-crit/5")}
                    >
                      <Td className="font-mono text-xs whitespace-nowrap text-sand-muted">{timeLabel(event.at)}</Td>
                      <Td>
                        <span className="block text-[13px] text-cream-bright">{event.actor}</span>
                        {event.actorEmail ? <span className="block font-mono text-xs text-sand-muted/60">{event.actorEmail}</span> : null}
                      </Td>
                      <Td className="text-[13px] whitespace-nowrap text-sand-muted">{event.role}</Td>
                      <Td>
                        <span
                          className={cn("font-mono text-[13px]", event.result === "denied" ? "text-state-crit" : "text-cream-primary")}
                        >
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
          {!loading && !error ? (
            <LoadMore shown={page.shown} total={rows.length} remaining={page.remaining} onMore={page.showMore} noun="events" />
          ) : null}
        </Panel>
      </PageBody>
    </>
  );
}
