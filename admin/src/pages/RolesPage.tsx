import { Check, Copy, Loader2, Lock, Minus } from "lucide-react";
import { toast } from "sonner";
import { useState } from "react";

import { Button, Panel, PanelHeader, TableWrap, Tag } from "../components/ui/primitives";
import { CloneRoleDialog } from "../components/CloneRoleDialog";
import { PERMISSIONS } from "../data/mock";
import { PageBody, PageHeader, RiskBadge } from "../components/common";
import { SkeletonTable } from "../components/states";
import { cn } from "../lib/utils";
import { useDirectory } from "../data/store";
import type { PermissionKey } from "../data/types";

export function RolesPage() {
  const { roles, setRolePermission, loading, error, refetch } = useDirectory();
  const [focusedRole, setFocusedRole] = useState<string | null>(null);
  const [cloneOpen, setCloneOpen] = useState(false);
  const [pending, setPending] = useState<string | null>(null);

  const systemCount = roles.filter((role) => role.isSystem).length;
  const customCount = roles.length - systemCount;

  async function toggle(slug: string, key: PermissionKey, held: boolean) {
    const cellId = `${slug}:${key}`;
    setPending(cellId);
    try {
      await setRolePermission(slug, key, !held);
    } catch (cause) {
      toast.error("Not changed", { description: cause instanceof Error ? cause.message : "Try again." });
    } finally {
      setPending(null);
    }
  }

  return (
    <>
      <PageHeader
        title="Roles & permissions"
        summary={`${systemCount} standard roles · ${customCount} custom · ${PERMISSIONS.length} permissions`}
        action={
          <Button variant="primary" size="sm" onClick={() => setCloneOpen(true)}>
            <Copy className="size-3.5" strokeWidth={2} aria-hidden="true" />
            Clone a role
          </Button>
        }
      />

      <PageBody>
        <Panel>
          <PanelHeader
            title="Permission matrix"
            hint="Standard roles are locked. Click a cell in a custom column to grant or remove."
          />
          {loading ? (
            <SkeletonTable rows={8} columns={6} />
          ) : error ? (
            <div className="px-5 py-10 text-center">
              <p className="text-[13px] text-state-crit">{error}</p>
              <Button variant="outline" size="sm" className="mt-3" onClick={() => void refetch()}>
                Try again
              </Button>
            </div>
          ) : (
            <TableWrap>
              <table className="w-full min-w-[54rem] border-collapse text-sm">
                <thead>
                  <tr>
                    <th className="sticky left-0 z-10 border-b border-hairline bg-charcoal-panel px-5 py-3 text-left text-[12px] font-medium text-sand-muted/70">
                      Permission
                    </th>
                    {roles.map((role) => (
                      <th
                        key={role.slug}
                        onMouseEnter={() => setFocusedRole(role.slug)}
                        onMouseLeave={() => setFocusedRole(null)}
                        className={cn(
                          "border-b border-hairline px-3 py-3 text-center align-bottom transition-colors",
                          focusedRole === role.slug && "bg-cream-primary/5",
                        )}
                      >
                        <span
                          className={cn(
                            "flex items-center justify-center gap-1 text-[13px] font-medium",
                            role.isSystem ? "text-cream-primary" : "text-signal",
                          )}
                        >
                          {role.isSystem ? <Lock className="size-3 opacity-50" strokeWidth={2.5} aria-hidden="true" /> : null}
                          {role.name}
                        </span>
                        <span className="mt-1 block text-[11px] font-normal text-sand-muted/70">
                          {role.memberCount === 1 ? "1 member" : `${role.memberCount} members`}
                        </span>
                      </th>
                    ))}
                  </tr>
                </thead>
                <tbody>
                  {PERMISSIONS.map((permission) => (
                    <tr key={permission.key} className="transition-colors hover:bg-cream-primary/3">
                      <th
                        scope="row"
                        className="sticky left-0 z-10 border-b border-hairline bg-charcoal-panel px-5 py-3 text-left align-top font-normal"
                      >
                        <span
                          className={cn(
                            "block font-mono text-[13px]",
                            permission.risk === "high" ? "text-state-crit" : "text-cream-primary",
                          )}
                        >
                          {permission.key}
                        </span>
                        <span className="mt-0.5 block max-w-[20rem] text-xs leading-snug text-sand-muted/70">
                          {permission.description}
                        </span>
                      </th>
                      {roles.map((role) => {
                        const held = role.permissions.includes(permission.key);
                        const cellId = `${role.slug}:${permission.key}`;
                        const busy = pending === cellId;

                        return (
                          <td
                            key={role.slug}
                            onMouseEnter={() => setFocusedRole(role.slug)}
                            onMouseLeave={() => setFocusedRole(null)}
                            className={cn(
                              "border-b border-hairline p-0 text-center transition-colors",
                              focusedRole === role.slug && "bg-cream-primary/5",
                            )}
                          >
                            <button
                              type="button"
                              disabled={role.isSystem || busy}
                              onClick={() => void toggle(role.slug, permission.key, held)}
                              title={
                                role.isSystem
                                  ? `${role.name} is a standard role and cannot be edited. Clone it to customise.`
                                  : held
                                    ? `Remove ${permission.key} from ${role.name}`
                                    : `Grant ${permission.key} to ${role.name}`
                              }
                              className={cn(
                                "grid h-full w-full place-items-center px-3 py-3",
                                role.isSystem ? "cursor-not-allowed" : "cursor-pointer hover:bg-signal/10",
                              )}
                            >
                              <span className="sr-only">
                                {held
                                  ? `${role.name} holds ${permission.key}`
                                  : `${role.name} does not hold ${permission.key}`}
                              </span>
                              {busy ? (
                                <Loader2 className="size-4 animate-spin text-signal" strokeWidth={2} aria-hidden="true" />
                              ) : held ? (
                                <Check
                                  className={cn("size-4", role.isSystem ? "text-state-ok" : "text-signal")}
                                  strokeWidth={2.5}
                                  aria-hidden="true"
                                />
                              ) : (
                                <Minus className="size-3.5 text-sand-muted/70" strokeWidth={2} aria-hidden="true" />
                              )}
                            </button>
                          </td>
                        );
                      })}
                    </tr>
                  ))}
                </tbody>
              </table>
            </TableWrap>
          )}
        </Panel>

        <div className="grid gap-6 lg:grid-cols-2">
          <Panel>
            <PanelHeader title="Roles" />
            <ul className="divide-y divide-[color:var(--color-hairline)]">
              {roles.map((role) => (
                <li key={role.slug} className="px-5 py-3.5 transition-colors hover:bg-cream-primary/3">
                  <div className="flex flex-wrap items-center gap-2.5">
                    <span className="text-[15px] font-medium text-cream-bright">{role.name}</span>
                    {role.isSystem ? <Tag tone="neutral">Standard</Tag> : <Tag tone="accent">Custom</Tag>}
                    <span className="ml-auto font-mono text-xs text-sand-muted/70">
                      {role.permissions.length} of {PERMISSIONS.length}
                    </span>
                  </div>
                  <p className="mt-1 text-[13px] text-sand-muted/80">{role.description}</p>
                </li>
              ))}
            </ul>
          </Panel>

          <Panel>
            <PanelHeader title="Permissions by risk" />
            <ul className="divide-y divide-[color:var(--color-hairline)]">
              {PERMISSIONS.map((permission) => (
                <li key={permission.key} className="flex flex-wrap items-center gap-3 px-5 py-3 transition-colors hover:bg-cream-primary/3">
                  <span className="font-mono text-[13px] text-cream-primary">{permission.key}</span>
                  <span className="text-xs text-sand-muted/70">{permission.category}</span>
                  <span className="ml-auto">
                    <RiskBadge risk={permission.risk} />
                  </span>
                </li>
              ))}
            </ul>
          </Panel>
        </div>
      </PageBody>

      <CloneRoleDialog
        open={cloneOpen}
        onOpenChange={setCloneOpen}
        onCreated={(slug) => {
          setFocusedRole(slug);
          toast.success("Role created", { description: "Click cells in its column to adjust permissions." });
        }}
      />
    </>
  );
}
