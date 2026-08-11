import { ChevronRight, Search, UserPlus } from "lucide-react";
import { Link } from "react-router-dom";
import { useMemo, useState } from "react";
import { toast } from "sonner";

import { Badge, Button, EmptyState, Input, NativeSelect, Panel, Table, TableWrap, Td, Th } from "../components/ui/primitives";
import { MfaBadge, PageBody, PageHeader, RoleBadge, UserStatusBadge } from "../components/common";
import { ROLE_BY_SLUG, USERS } from "../data/mock";
import { relativeLabel } from "../lib/utils";

type StatusFilter = "all" | "active" | "invited" | "locked_out" | "deactivated";

export function UsersPage() {
  const [query, setQuery] = useState("");
  const [role, setRole] = useState("all");
  const [status, setStatus] = useState<StatusFilter>("all");
  const [mfaGapOnly, setMfaGapOnly] = useState(false);

  const rows = useMemo(() => {
    const needle = query.trim().toLowerCase();
    return USERS.filter((user) => {
      if (needle && !user.name.toLowerCase().includes(needle) && !user.email.toLowerCase().includes(needle)) return false;
      if (role !== "all" && user.roleSlug !== role) return false;
      if (status !== "all" && user.status !== status) return false;
      if (mfaGapOnly && user.mfa === "verified") return false;
      return true;
    });
  }, [query, role, status, mfaGapOnly]);

  const ownerCount = USERS.filter((user) => user.isOwner).length;
  const pending = USERS.filter((user) => user.status === "invited").length;

  return (
    <>
      <PageHeader
        title="Users"
        summary={`${USERS.length} accounts · ${ownerCount} owner · ${pending} pending invites`}
        action={
          <Button variant="primary" size="sm" onClick={() => toast("Invite user", { description: "Provisioning is phase 2 — this preview has no backend attached." })}>
            <UserPlus className="size-3.5" strokeWidth={2} aria-hidden="true" />
            Invite user
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
              placeholder="Search name or email"
              className="pl-8"
              aria-label="Search users"
            />
          </div>

          <NativeSelect value={role} onChange={(event) => setRole(event.target.value)} aria-label="Filter by role">
            <option value="all">Role: all</option>
            {[...ROLE_BY_SLUG.values()].map((entry) => (
              <option key={entry.slug} value={entry.slug}>
                {entry.name}
              </option>
            ))}
          </NativeSelect>

          <NativeSelect value={status} onChange={(event) => setStatus(event.target.value as StatusFilter)} aria-label="Filter by status">
            <option value="all">Status: all</option>
            <option value="active">Active</option>
            <option value="invited">Invited</option>
            <option value="locked_out">Locked out</option>
            <option value="deactivated">Deactivated</option>
          </NativeSelect>

          <Button
            variant={mfaGapOnly ? "primary" : "outline"}
            size="md"
            onClick={() => setMfaGapOnly((value) => !value)}
            aria-pressed={mfaGapOnly}
          >
            MFA gaps only
          </Button>
        </Panel>

        <Panel>
          {rows.length === 0 ? (
            <EmptyState title="No users match those filters" hint="Clear a filter to widen the result." />
          ) : (
            <TableWrap>
              <Table>
                <thead>
                  <tr>
                    <Th>User</Th>
                    <Th>Role</Th>
                    <Th>Status</Th>
                    <Th>MFA</Th>
                    <Th>Denied 24h</Th>
                    <Th>Last activity</Th>
                    <Th className="w-10" />
                  </tr>
                </thead>
                <tbody>
                  {rows.map((user) => (
                    <tr key={user.id} className="transition-colors hover:bg-cream-primary/4">
                      <Td>
                        <Link to={`/users/${user.id}`} className="group block min-w-0">
                          <span className="block text-sm font-medium text-cream-bright group-hover:text-signal">{user.name}</span>
                          <span className="block font-mono text-[11px] text-sand-muted/70">{user.email}</span>
                        </Link>
                      </Td>
                      <Td>
                        <div className="flex flex-wrap items-center gap-1.5">
                          <RoleBadge name={ROLE_BY_SLUG.get(user.roleSlug)?.name ?? user.roleSlug} isOwner={user.isOwner} />
                          {user.permissions
                            .filter((permission) => permission.source === "granted")
                            .map((permission) => (
                              <Badge key={permission.key} tone="accent">
                                +{permission.key}
                              </Badge>
                            ))}
                        </div>
                      </Td>
                      <Td>
                        <UserStatusBadge status={user.status} />
                      </Td>
                      <Td>
                        <MfaBadge state={user.mfa} />
                      </Td>
                      <Td>
                        {user.deniedLast24h > 0 ? (
                          <span className="font-mono text-xs text-state-crit">{user.deniedLast24h}</span>
                        ) : (
                          <span className="font-mono text-xs text-sand-muted/50">—</span>
                        )}
                      </Td>
                      <Td className="font-mono text-xs whitespace-nowrap text-sand-muted">
                        {user.lastActivityAt ? relativeLabel(user.lastActivityAt) : "Not yet"}
                      </Td>
                      <Td>
                        <Link
                          to={`/users/${user.id}`}
                          className="grid size-7 place-items-center text-sand-muted/60 hover:text-signal"
                          aria-label={`Open ${user.name}`}
                        >
                          <ChevronRight className="size-4" strokeWidth={1.75} aria-hidden="true" />
                        </Link>
                      </Td>
                    </tr>
                  ))}
                </tbody>
              </Table>
            </TableWrap>
          )}
        </Panel>

        <p className="font-mono text-[11px] text-sand-muted/60">
          Showing {rows.length} of {USERS.length}. Department and contact details live on the detail page — this view stays scannable.
        </p>
      </PageBody>
    </>
  );
}
