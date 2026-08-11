import { ChevronRight, Search, UserPlus } from "lucide-react";
import { Link } from "react-router-dom";
import { useMemo, useState } from "react";

import { Avatar, Button, EmptyState, Input, NativeSelect, Panel, Table, TableWrap, Tag, Td, Th } from "../components/ui/primitives";
import { MfaBadge, PageBody, PageHeader, RoleBadge, UserStatusBadge } from "../components/common";
import { AddUserDialog } from "../components/AddUserDialog";
import { ROLE_BY_SLUG } from "../data/mock";
import { useDirectory } from "../data/store";
import { initials, relativeLabel } from "../lib/utils";

type StatusFilter = "all" | "active" | "invited" | "locked_out" | "deactivated";

export function UsersPage() {
  const { users } = useDirectory();
  const [addOpen, setAddOpen] = useState(false);
  const [query, setQuery] = useState("");
  const [role, setRole] = useState("all");
  const [status, setStatus] = useState<StatusFilter>("all");
  const [mfaGapOnly, setMfaGapOnly] = useState(false);

  const rows = useMemo(() => {
    const needle = query.trim().toLowerCase();
    return users.filter((user) => {
      if (needle && !user.name.toLowerCase().includes(needle) && !user.email.toLowerCase().includes(needle)) return false;
      if (role !== "all" && user.roleSlug !== role) return false;
      if (status !== "all" && user.status !== status) return false;
      if (mfaGapOnly && user.mfa === "verified") return false;
      return true;
    });
  }, [users, query, role, status, mfaGapOnly]);

  const pending = users.filter((user) => user.status === "invited").length;

  return (
    <>
      <PageHeader
        title="Users"
        summary={`${users.length} accounts · ${pending} awaiting acceptance`}
        action={
          <Button variant="primary" size="sm" onClick={() => setAddOpen(true)}>
            <UserPlus className="size-3.5" strokeWidth={2} aria-hidden="true" />
            Add user
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
              placeholder="Search name or email"
              className="pl-9"
              aria-label="Search users"
            />
          </div>

          <NativeSelect value={role} onChange={(event) => setRole(event.target.value)} aria-label="Filter by role">
            <option value="all">All roles</option>
            {[...ROLE_BY_SLUG.values()].map((entry) => (
              <option key={entry.slug} value={entry.slug}>
                {entry.name}
              </option>
            ))}
          </NativeSelect>

          <NativeSelect value={status} onChange={(event) => setStatus(event.target.value as StatusFilter)} aria-label="Filter by status">
            <option value="all">All statuses</option>
            <option value="active">Active</option>
            <option value="invited">Invited</option>
            <option value="locked_out">Locked out</option>
            <option value="deactivated">Deactivated</option>
          </NativeSelect>

          <Button variant={mfaGapOnly ? "primary" : "outline"} onClick={() => setMfaGapOnly((value) => !value)} aria-pressed={mfaGapOnly}>
            Missing authenticator
          </Button>
        </div>

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
                    <Th>Authenticator</Th>
                    <Th>Denied 24h</Th>
                    <Th>Last activity</Th>
                    <Th className="w-12" />
                  </tr>
                </thead>
                <tbody>
                  {rows.map((user) => (
                    <tr key={user.id} className="group transition-colors hover:bg-cream-primary/4">
                      <Td>
                        <Link to={`/users/${user.id}`} className="flex min-w-0 items-center gap-3">
                          <Avatar initials={initials(user.name)} tone={user.isOwner ? "accent" : "neutral"} />
                          <span className="min-w-0">
                            <span className="block truncate text-sm font-medium text-cream-bright group-hover:text-signal">{user.name}</span>
                            <span className="block truncate font-mono text-xs text-sand-muted/70">{user.email}</span>
                          </span>
                        </Link>
                      </Td>
                      <Td>
                        <div className="flex flex-wrap items-center gap-1.5">
                          <RoleBadge name={ROLE_BY_SLUG.get(user.roleSlug)?.name ?? user.roleSlug} isOwner={user.isOwner} />
                          {user.permissions
                            .filter((permission) => permission.source === "granted")
                            .map((permission) => (
                              <Tag key={permission.key} tone="accent" mono>
                                +{permission.key}
                              </Tag>
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
                          <span className="font-mono text-[13px] text-state-crit">{user.deniedLast24h}</span>
                        ) : (
                          <span className="font-mono text-[13px] text-sand-muted/40">0</span>
                        )}
                      </Td>
                      <Td className="text-[13px] whitespace-nowrap text-sand-muted">
                        {user.lastActivityAt ? relativeLabel(user.lastActivityAt) : "—"}
                      </Td>
                      <Td>
                        <Link
                          to={`/users/${user.id}`}
                          className="grid size-7 place-items-center rounded-control text-sand-muted/50 transition-colors hover:text-signal"
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
      </PageBody>

      <AddUserDialog open={addOpen} onOpenChange={setAddOpen} />
    </>
  );
}
