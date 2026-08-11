import { Check, Copy, Lock, Minus } from "lucide-react";
import { toast } from "sonner";
import { useState } from "react";

import { Button, Panel, PanelHeader, TableWrap, Tag } from "../components/ui/primitives";
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
        summary={`${systemCount} standard roles · ${customCount} custom · ${PERMISSIONS.length} permissions`}
        action={
          <Button variant="primary" size="sm" onClick={() => toast("Clone a role", { description: "Start from a standard role and adjust its permissions." })}>
            <Copy className="size-3.5" strokeWidth={2} aria-hidden="true" />
            Clone a role
          </Button>
        }
      />

      <PageBody>
        <Panel>
          <PanelHeader title="Permission matrix" />
          <TableWrap>
            <table className="w-full min-w-[54rem] border-collapse text-sm">
              <thead>
                <tr>
                  <th className="sticky left-0 z-10 border-b border-hairline bg-charcoal-panel px-5 py-3 text-left text-[12px] font-medium text-sand-muted/70">
                    Permission
                  </th>
                  {ROLES.map((role) => (
                    <th
                      key={role.slug}
                      onMouseEnter={() => setFocusedRole(role.slug)}
                      onMouseLeave={() => setFocusedRole(null)}
                      className={cn(
                        "border-b border-hairline px-3 py-3 text-center align-bottom transition-colors",
                        focusedRole === role.slug && "bg-cream-primary/5",
                      )}
                    >
                      <span className={cn("flex items-center justify-center gap-1 text-[13px] font-medium", role.isSystem ? "text-cream-primary" : "text-signal")}>
                        {role.isSystem ? <Lock className="size-3 opacity-50" strokeWidth={2.5} aria-hidden="true" /> : null}
                        {role.name}
                      </span>
                      <span className="mt-1 block text-[11px] font-normal text-sand-muted/55">
                        {role.memberCount === 1 ? "1 member" : `${role.memberCount} members`}
                      </span>
                    </th>
                  ))}
                </tr>
              </thead>
              <tbody>
                {PERMISSIONS.map((permission) => (
                  <tr key={permission.key} className="transition-colors hover:bg-cream-primary/3">
                    <th scope="row" className="sticky left-0 z-10 border-b border-hairline bg-charcoal-panel px-5 py-3 text-left align-top font-normal">
                      <span className={cn("block font-mono text-[13px]", permission.risk === "high" ? "text-state-crit" : "text-cream-primary")}>
                        {permission.key}
                      </span>
                      <span className="mt-0.5 block max-w-[20rem] text-xs leading-snug text-sand-muted/65">{permission.description}</span>
                    </th>
                    {ROLES.map((role) => {
                      const held = role.permissions.includes(permission.key);
                      return (
                        <td
                          key={role.slug}
                          onMouseEnter={() => setFocusedRole(role.slug)}
                          onMouseLeave={() => setFocusedRole(null)}
                          className={cn("border-b border-hairline px-3 py-3 text-center transition-colors", focusedRole === role.slug && "bg-cream-primary/5")}
                        >
                          <span className="sr-only">{held ? `${role.name} holds ${permission.key}` : `${role.name} does not hold ${permission.key}`}</span>
                          {held ? (
                            <Check
                              className={cn("mx-auto size-4", role.isSystem ? "text-state-ok" : "text-signal")}
                              strokeWidth={2.5}
                              aria-hidden="true"
                            />
                          ) : (
                            <Minus className="mx-auto size-3.5 text-sand-muted/25" strokeWidth={2} aria-hidden="true" />
                          )}
                        </td>
                      );
                    })}
                  </tr>
                ))}
              </tbody>
            </table>
          </TableWrap>
        </Panel>

        <div className="grid gap-6 lg:grid-cols-2">
          <Panel>
            <PanelHeader title="Roles" />
            <ul className="divide-y divide-[color:var(--color-hairline)]">
              {ROLES.map((role) => (
                <li key={role.slug} className="px-5 py-3.5 transition-colors hover:bg-cream-primary/3">
                  <div className="flex flex-wrap items-center gap-2.5">
                    <span className="text-[15px] font-medium text-cream-bright">{role.name}</span>
                    {role.isSystem ? <Tag tone="neutral">Standard</Tag> : <Tag tone="accent">Custom</Tag>}
                    <span className="ml-auto font-mono text-xs text-sand-muted/65">
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
                  <span className="text-xs text-sand-muted/60">{permission.category}</span>
                  <span className="ml-auto">
                    <RiskBadge risk={permission.risk} />
                  </span>
                </li>
              ))}
            </ul>
          </Panel>
        </div>
      </PageBody>
    </>
  );
}
