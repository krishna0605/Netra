import { LogOut } from "lucide-react";
import { toast } from "sonner";
import { useMemo, useState } from "react";

import { Avatar, Button, EmptyState, NativeSelect, Panel, Status, Table, TableWrap, Td, Th } from "../components/ui/primitives";
import { PageBody, PageHeader, StatTile } from "../components/common";
import { SESSIONS } from "../data/mock";
import { initials, relativeLabel } from "../lib/utils";

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

  const singleFactor = SESSIONS.filter((session) => session.aal === "aal1").length;
  const administration = SESSIONS.filter((session) => session.origin.startsWith("admin.")).length;

  return (
    <>
      <PageHeader
        title="Sessions"
        summary={`${SESSIONS.length} active across the organization`}
        action={
          <Button variant="danger" size="sm" onClick={() => toast("All sessions revoked", { description: "Everyone will be asked to sign in again." })}>
            <LogOut className="size-3.5" strokeWidth={1.75} aria-hidden="true" />
            Revoke all
          </Button>
        }
      />

      <PageBody>
        <div className="grid gap-3 sm:grid-cols-3">
          <StatTile label="Active sessions" value={SESSIONS.length} hint="Across both consoles" />
          <StatTile label="Single factor" value={singleFactor} hint="Cannot satisfy a step-up challenge" alert={singleFactor > 0} />
          <StatTile label="Administration" value={administration} hint="Signed in to this console" />
        </div>

        <div className="flex flex-wrap items-center gap-2">
          <NativeSelect value={origin} onChange={(event) => setOrigin(event.target.value)} aria-label="Filter by origin">
            <option value="all">All origins</option>
            {origins.map((entry) => (
              <option key={entry} value={entry}>
                {entry}
              </option>
            ))}
          </NativeSelect>
          <NativeSelect value={aal} onChange={(event) => setAal(event.target.value)} aria-label="Filter by assurance">
            <option value="all">All assurance levels</option>
            <option value="aal2">Two factor</option>
            <option value="aal1">Single factor</option>
          </NativeSelect>
        </div>

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
                    <Th>Assurance</Th>
                    <Th>Started</Th>
                    <Th>Last seen</Th>
                    <Th>Network</Th>
                    <Th className="text-right">Action</Th>
                  </tr>
                </thead>
                <tbody>
                  {rows.map((session) => (
                    <tr key={session.id} className="transition-colors hover:bg-cream-primary/4">
                      <Td>
                        <div className="flex items-center gap-3">
                          <Avatar initials={initials(session.userName)} />
                          <span className="min-w-0">
                            <span className="block truncate text-[13px] text-cream-bright">{session.userName}</span>
                            <span className="block truncate font-mono text-xs text-sand-muted/65">{session.userEmail}</span>
                          </span>
                        </div>
                      </Td>
                      <Td className="font-mono text-[13px] whitespace-nowrap text-cream-primary">{session.origin}</Td>
                      <Td>
                        <Status tone={session.aal === "aal2" ? "ok" : "warn"}>{session.aal === "aal2" ? "Two factor" : "Single factor"}</Status>
                      </Td>
                      <Td className="text-[13px] whitespace-nowrap text-sand-muted">{relativeLabel(session.startedAt)}</Td>
                      <Td className="text-[13px] whitespace-nowrap text-sand-muted">{relativeLabel(session.lastSeenAt)}</Td>
                      <Td className="font-mono text-xs text-sand-muted/70">{session.ipHint}</Td>
                      <Td className="text-right">
                        <Button
                          variant="ghost"
                          size="sm"
                          onClick={() => toast("Session revoked", { description: `${session.userName} signed out of ${session.origin}.` })}
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
      </PageBody>
    </>
  );
}
