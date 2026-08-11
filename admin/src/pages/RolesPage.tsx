import { Copy, Lock } from "lucide-react";
import { toast } from "sonner";
import { useState } from "react";

import { Badge, Button, Panel, PanelHeader, TableWrap } from "../components/ui/primitives";
import { PageBody, PageHeader, RiskBadge } from "../components/common";
import { PERMISSIONS, ROLES } from "../data/mock";
import { cn } from "../lib/utils";

export function RolesPage() {
  const [focusedRole, setFocusedRole] = useState<string | null>(null);
  const systemCount = ROLES.filter((role) => role.isSystem).length;
  const customCount = ROLES.length - systemCount;

  return (
    <>
      <PageHeader
        title="Roles & permissions"
        summary={`${systemCount} system roles (locked) · ${customCount} custom · ${PERMISSIONS.length} permissions`}
        action={
          <Button
            variant="primary"
            size="sm"
            onClick={() => toast("Clone a role", { description: "Custom roles land in phase 3 with the database-backed resolver." })}
          >
            <Copy className="size-3.5" strokeWidth={2} aria-hidden="true" />
            Clone a role
          </Button>
        }
      />

      <PageBody>
        <Panel>
          <PanelHeader
            title="Permission matrix"
            hint="A grid is the only layout that answers “who can export?” and “what can an Analyst do?” in the same glance"
          />
          <TableWrap>
            <table className="w-full min-w-[52rem] border-collapse text-sm">
              <thead>
                <tr>
                  <th className="sticky left-0 z-10 border-r border-b border-hairline-strong bg-charcoal-deep px-4 py-2.5 text-left font-mono text-[10px] tracking-[0.1em] text-sand-muted/80 uppercase">
                    Permission
                  </th>
                  {ROLES.map((role) => (
                    <th
                      key={role.slug}
                      onMouseEnter={() => setFocusedRole(role.slug)}
                      onMouseLeave={() => setFocusedRole(null)}
                      className={cn(
                        "border-r border-b border-hairline-strong bg-charcoal-deep px-2 py-2.5 text-center font-mono text-[10px] tracking-[0.06em] uppercase last:border-r-0",
                        role.isSystem ? "text-sand-muted/80" : "text-signal",
                        focusedRole === role.slug && "bg-cream-primary/6",
                      )}
                    >
                      <span className="inline-flex items-center gap-1">
                        {role.isSystem ? <Lock className="size-2.5" strokeWidth={2.5} aria-hidden="true" /> : null}
                        {role.name}
                      </span>
                      <span className="mt-1 block text-[9px] font-normal tracking-normal normal-case opacity-60">
                        {role.memberCount} {role.memberCount === 1 ? "member" : "members"}
                      </span>
                    </th>
                  ))}
                </tr>
              </thead>
              <tbody>
                {PERMISSIONS.map((permission) => (
                  <tr key={permission.key} className="hover:bg-cream-primary/3">
                    <th
                      scope="row"
                      className="sticky left-0 z-10 border-r border-b border-hairline bg-charcoal-panel px-4 py-2.5 text-left align-top font-normal"
                    >
                      <span
                        className={cn(
                          "block font-mono text-xs",
                          permission.risk === "high" ? "text-state-crit" : "text-cream-primary",
                        )}
                      >
                        {permission.key}
                      </span>
                      <span className="mt-0.5 block max-w-[18rem] text-[11px] leading-snug text-sand-muted/65">
                        {permission.description}
                      </span>
                    </th>
                    {ROLES.map((role) => {
                      const held = role.permissions.includes(permission.key);
                      return (
                        <td
                          key={role.slug}
                          onMouseEnter={() => setFocusedRole(role.slug)}
                          onMouseLeave={() => setFocusedRole(null)}
                          className={cn(
                            "border-r border-b border-hairline px-2 py-2.5 text-center last:border-r-0",
                            focusedRole === role.slug && "bg-cream-primary/5",
                          )}
                        >
                          {held ? (
                            <span
                              className={cn("text-base leading-none", role.isSystem ? "text-state-ok" : "text-signal")}
                              title={`${role.name} holds ${permission.key}`}
                            >
                              ●
                            </span>
                          ) : (
                            <span className="text-base leading-none text-sand-muted/25" title={`${role.name} does not hold ${permission.key}`}>
                              –
                            </span>
                          )}
                        </td>
                      );
                    })}
                  </tr>
                ))}
              </tbody>
            </table>
          </TableWrap>
          <p className="border-t border-hairline px-4 py-2.5 text-[11px] text-sand-muted/75">
            Permissions in <span className="text-state-crit">red</span> are high-risk and require a written reason when granted. Locked columns
            are system roles — they are immutable by design, so there is always a known-good state to fall back to. Clone one to customise it.
          </p>
        </Panel>

        <div className="grid gap-5 lg:grid-cols-2">
          <Panel>
            <PanelHeader title="Roles" hint="System roles are seeded from ROLE_PERMISSIONS and cannot be edited" />
            <ul className="divide-y divide-[color:var(--color-hairline)]">
              {ROLES.map((role) => (
                <li key={role.slug} className="px-4 py-3">
                  <div className="flex flex-wrap items-center gap-2">
                    <span className="font-mono text-sm text-cream-bright">{role.name}</span>
                    {role.isSystem ? <Badge tone="neutral">System · locked</Badge> : <Badge tone="accent">Custom</Badge>}
                    <span className="ml-auto font-mono text-[11px] text-sand-muted/70">
                      {role.permissions.length} of {PERMISSIONS.length}
                    </span>
                  </div>
                  <p className="mt-1 text-xs text-sand-muted/80">{role.description}</p>
                </li>
              ))}
            </ul>
          </Panel>

          <Panel>
            <PanelHeader title="Permissions by risk" hint="Risk drives whether a grant needs a written justification" />
            <ul className="divide-y divide-[color:var(--color-hairline)]">
              {PERMISSIONS.map((permission) => (
                <li key={permission.key} className="flex flex-wrap items-center gap-2 px-4 py-2.5">
                  <span className="font-mono text-xs text-cream-primary">{permission.key}</span>
                  <span className="font-mono text-[10px] text-sand-muted/60">{permission.category}</span>
                  <span className="ml-auto">
                    <RiskBadge risk={permission.risk} />
                  </span>
                </li>
              ))}
            </ul>
          </Panel>
        </div>

        <Panel className="border-signal/40 bg-signal/6 px-4 py-3">
          <p className="text-xs text-sand-muted">
            <span className="font-mono text-signal">Ceiling rule.</span> An administrator can never grant a permission they do not themselves
            hold. Without that intersection, any account holding{" "}
            <span className="font-mono text-cream-primary">manage_users</span> could mint a superuser and the hierarchy above would be
            decorative.
          </p>
        </Panel>
      </PageBody>
    </>
  );
}
