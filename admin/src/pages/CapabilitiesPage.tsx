import { useMemo, useState } from "react";

import { EmptyState, NativeSelect, Panel, Status, Table, TableWrap, Tag, Td, Th } from "../components/ui/primitives";
import { DataRegion, SkeletonTable, SkeletonTiles } from "../components/states";
import { PageBody, PageHeader, StatTile } from "../components/common";
import { useDirectory } from "../data/store";
import type { CapabilityState } from "../data/types";

const STATE: Record<CapabilityState, { label: string; tone: "ok" | "warn" | "neutral" | "crit" }> = {
  available: { label: "Available", tone: "ok" },
  disabled: { label: "Disabled", tone: "warn" },
  not_implemented: { label: "Not installed", tone: "neutral" },
  degraded: { label: "Degraded", tone: "crit" },
};

export function CapabilitiesPage() {
  const { capabilities, loading, error, refetch } = useDirectory();
  const [state, setState] = useState<CapabilityState | "all">("all");

  const rows = useMemo(() => capabilities.filter((flag) => state === "all" || flag.state === state), [capabilities, state]);
  const available = capabilities.filter((flag) => flag.state === "available").length;
  const disabled = capabilities.filter((flag) => flag.state === "disabled").length;
  const notInstalled = capabilities.filter((flag) => flag.state === "not_implemented").length;

  return (
    <>
      <PageHeader title="Capabilities" summary={loading ? "Loading…" : `${capabilities.length} features · ${available} available in this deployment`} />

      <PageBody>
        {loading ? (
          <SkeletonTiles count={3} />
        ) : (
        <div className="grid gap-3 sm:grid-cols-3">
          <StatTile label="Available" value={available} hint="Live in this deployment" />
          <StatTile label="Disabled" value={disabled} hint="Awaiting configuration" />
          <StatTile label="Not installed" value={notInstalled} hint="No reviewed adapter" />
        </div>
        )}

        <div className="flex flex-wrap items-center gap-2">
          <NativeSelect value={state} onChange={(event) => setState(event.target.value as CapabilityState | "all")} aria-label="Filter by state">
            <option value="all">All states</option>
            <option value="available">Available</option>
            <option value="disabled">Disabled</option>
            <option value="not_implemented">Not installed</option>
            <option value="degraded">Degraded</option>
          </NativeSelect>
        </div>

        <Panel>
          <DataRegion
            loading={loading}
            error={error}
            empty={rows.length === 0}
            onRetry={() => void refetch()}
            skeleton={<SkeletonTable rows={8} columns={5} />}
            emptyState={<EmptyState title="No features in that state" />}
          >
            <TableWrap>
              <Table className="min-w-[48rem]">
                <thead>
                  <tr>
                    <Th>Feature</Th>
                    <Th>State</Th>
                    <Th>Reason</Th>
                    <Th>Two factor</Th>
                    <Th>Worker</Th>
                  </tr>
                </thead>
                <tbody>
                  {rows.map((flag) => (
                    <tr key={flag.key} className="transition-colors hover:bg-cream-primary/4">
                      <Td className="font-mono text-[13px] whitespace-nowrap text-cream-bright">{flag.key}</Td>
                      <Td>
                        <Status tone={STATE[flag.state].tone}>{STATE[flag.state].label}</Status>
                      </Td>
                      <Td className="max-w-md text-[13px] leading-snug text-sand-muted">{flag.reason}</Td>
                      <Td>{flag.requiresAal2 ? <Tag tone="accent">Required</Tag> : <span className="text-[13px] text-sand-muted/70">—</span>}</Td>
                      <Td className="font-mono text-xs text-sand-muted/70">{flag.durableConsumer ?? "—"}</Td>
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
