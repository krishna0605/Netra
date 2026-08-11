import { useMemo, useState } from "react";

import { Badge, EmptyState, NativeSelect, Panel, Table, TableWrap, Td, Th } from "../components/ui/primitives";
import { CAPABILITIES } from "../data/mock";
import { PageBody, PageHeader, StatTile } from "../components/common";
import type { CapabilityState } from "../data/types";

const STATE_TONE: Record<CapabilityState, "ok" | "warn" | "neutral" | "crit"> = {
  available: "ok",
  disabled: "warn",
  not_implemented: "neutral",
  degraded: "crit",
};

export function CapabilitiesPage() {
  const [state, setState] = useState<CapabilityState | "all">("all");

  const rows = useMemo(() => CAPABILITIES.filter((flag) => state === "all" || flag.state === state), [state]);
  const available = CAPABILITIES.filter((flag) => flag.state === "available").length;
  const disabled = CAPABILITIES.filter((flag) => flag.state === "disabled").length;

  return (
    <>
      <PageHeader
        title="Capabilities"
        summary={`${CAPABILITIES.length} flags · ${available} available · ${disabled} disabled for this deployment profile`}
      />

      <PageBody>
        <div className="grid gap-3 sm:grid-cols-3">
          <StatTile label="Available" value={available} hint="live in this deployment" />
          <StatTile label="Disabled" value={disabled} hint="gated on configuration" />
          <StatTile label="Not implemented" value={CAPABILITIES.filter((flag) => flag.state === "not_implemented").length} hint="no reviewed adapter" />
        </div>

        <Panel className="flex flex-wrap items-center gap-2 px-3 py-2.5">
          <NativeSelect value={state} onChange={(event) => setState(event.target.value as CapabilityState | "all")} aria-label="Filter by state">
            <option value="all">State: all</option>
            <option value="available">Available</option>
            <option value="disabled">Disabled</option>
            <option value="not_implemented">Not implemented</option>
            <option value="degraded">Degraded</option>
          </NativeSelect>
        </Panel>

        <Panel>
          {rows.length === 0 ? (
            <EmptyState title="No capabilities in that state" />
          ) : (
            <TableWrap>
              <Table className="min-w-[48rem]">
                <thead>
                  <tr>
                    <Th>Capability</Th>
                    <Th>State</Th>
                    <Th>Reason</Th>
                    <Th>AAL2</Th>
                    <Th>Durable consumer</Th>
                  </tr>
                </thead>
                <tbody>
                  {rows.map((flag) => (
                    <tr key={flag.key} className="hover:bg-cream-primary/4">
                      <Td className="font-mono text-xs whitespace-nowrap text-cream-bright">{flag.key}</Td>
                      <Td>
                        <Badge tone={STATE_TONE[flag.state]}>{flag.state.replace("_", " ")}</Badge>
                      </Td>
                      <Td className="max-w-md text-[11px] leading-snug text-sand-muted">{flag.reason}</Td>
                      <Td>{flag.requiresAal2 ? <Badge tone="accent">required</Badge> : <span className="font-mono text-xs text-sand-muted/50">—</span>}</Td>
                      <Td className="font-mono text-[11px] text-sand-muted/70">{flag.durableConsumer ?? "—"}</Td>
                    </tr>
                  ))}
                </tbody>
              </Table>
            </TableWrap>
          )}
        </Panel>

        <Panel className="border-signal/40 bg-signal/6 px-4 py-3">
          <p className="text-xs text-sand-muted">
            <span className="font-mono text-signal">Why this screen exists.</span> It is the fastest possible answer to "why is that button
            greyed out". Every flag already carries its own reason string from{" "}
            <span className="font-mono text-cream-primary">capability_registry()</span>, so this is a read-only render of state the backend
            already publishes — no new source of truth.
          </p>
        </Panel>
      </PageBody>
    </>
  );
}
