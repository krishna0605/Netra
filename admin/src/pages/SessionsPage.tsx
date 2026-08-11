import { LogOut } from "lucide-react";
import { toast } from "sonner";
import { useMemo, useState } from "react";

import { Badge, Button, EmptyState, NativeSelect, Panel, Table, TableWrap, Td, Th } from "../components/ui/primitives";
import { PageBody, PageHeader, StatTile } from "../components/common";
import { SESSIONS } from "../data/mock";
import { relativeLabel } from "../lib/utils";

export function SessionsPage() {
  const [origin, setOrigin] = useState("all");
  const [aal, setAal] = useState("all");

  const origins = useMemo(() => [...new Set(SESSIONS.map((session) => session.origin))], []);

  const rows = useMemo(
    () =>
      SESSIONS.filter((session) => {
        if (origin !== "all" && session.origin !== origin) return false;
        if (aal !== "all" && session.aal !== aal) return false;
        return true;
      }),
    [origin, aal],
  );

  const aal1Count = SESSIONS.filter((session) => session.aal === "aal1").length;
  const adminOriginCount = SESSIONS.filter((session) => session.origin.startsWith("admin.")).length;

  return (
    <>
      <PageHeader
        title="Sessions"
        summary={`${SESSIONS.length} active across the organization · ${adminOriginCount} on the admin origin`}
        action={
          <Button
            variant="danger"
            size="sm"
            onClick={() => toast("Revoke all sessions", { description: "Organization-wide revocation requires step-up and a written reason. Phase 2." })}
          >
            <LogOut className="size-3.5" strokeWidth={1.75} aria-hidden="true" />
            Revoke all
          </Button>
        }
      />

      <PageBody>
        <div className="grid gap-3 sm:grid-cols-3">
          <StatTile label="Active sessions" value={SESSIONS.length} hint="across both origins" />
          <StatTile label="Single-factor" value={aal1Count} hint="aal1 — not step-up capable" alert={aal1Count > 0} />
          <StatTile label="Admin origin" value={adminOriginCount} hint="admin.netra.app" />
        </div>

        <Panel className="flex flex-wrap items-center gap-2 px-3 py-2.5">
          <NativeSelect value={origin} onChange={(event) => setOrigin(event.target.value)} aria-label="Filter by origin">
            <option value="all">Origin: all</option>
            {origins.map((entry) => (
              <option key={entry} value={entry}>
                {entry}
              </option>
            ))}
          </NativeSelect>
          <NativeSelect value={aal} onChange={(event) => setAal(event.target.value)} aria-label="Filter by assurance level">
            <option value="all">AAL: all</option>
            <option value="aal2">aal2</option>
            <option value="aal1">aal1</option>
          </NativeSelect>
        </Panel>

        <Panel>
          {rows.length === 0 ? (
            <EmptyState title="No sessions match those filters" />
          ) : (
            <TableWrap>
              <Table>
                <thead>
                  <tr>
                    <Th>User</Th>
                    <Th>Origin</Th>
                    <Th>AAL</Th>
                    <Th>Started</Th>
                    <Th>Last seen</Th>
                    <Th>Network</Th>
                    <Th className="text-right">Action</Th>
                  </tr>
                </thead>
                <tbody>
                  {rows.map((session) => (
                    <tr key={session.id} className="hover:bg-cream-primary/4">
                      <Td>
                        <span className="block text-xs text-cream-bright">{session.userName}</span>
                        <span className="block font-mono text-[10px] text-sand-muted/60">{session.userEmail}</span>
                      </Td>
                      <Td>
                        <span className="font-mono text-xs text-cream-primary">{session.origin}</span>
                        {session.origin.startsWith("admin.") ? (
                          <Badge tone="accent" className="ml-2">
                            admin
                          </Badge>
                        ) : null}
                      </Td>
                      <Td>
                        <Badge tone={session.aal === "aal2" ? "ok" : "warn"}>{session.aal}</Badge>
                      </Td>
                      <Td className="font-mono text-xs whitespace-nowrap text-sand-muted">{relativeLabel(session.startedAt)}</Td>
                      <Td className="font-mono text-xs whitespace-nowrap text-sand-muted">{relativeLabel(session.lastSeenAt)}</Td>
                      <Td className="font-mono text-xs text-sand-muted/70">{session.ipHint}</Td>
                      <Td className="text-right">
                        <Button
                          variant="ghost"
                          size="sm"
                          onClick={() => toast("Revoke session", { description: `${session.userName} would be signed out of ${session.origin}.` })}
                        >
                          Revoke
                        </Button>
                      </Td>
                    </tr>
                  ))}
                </tbody>
              </Table>
            </TableWrap>
          )}
        </Panel>

        <p className="font-mono text-[11px] text-sand-muted/60">
          Small screen, high value during an incident. Revoking a session kills its refresh token — a credential reset that leaves the token
          alive is not a reset.
        </p>
      </PageBody>
    </>
  );
}
