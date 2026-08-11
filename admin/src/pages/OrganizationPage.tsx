import { ArrowLeftRight } from "lucide-react";
import { Link } from "react-router-dom";
import { toast } from "sonner";

import { Badge, Button, Field, Input, Panel, PanelHeader } from "../components/ui/primitives";
import { ORGANIZATION, ROLES, USERS } from "../data/mock";
import { PageBody, PageHeader } from "../components/common";
import { dateTimeLabel } from "../lib/utils";

export function OrganizationPage() {
  const owner = USERS.find((user) => user.id === ORGANIZATION.ownerUserId);

  return (
    <>
      <PageHeader title="Organization" summary={`${ORGANIZATION.name} · ${ORGANIZATION.slug} · created ${dateTimeLabel(ORGANIZATION.createdAt)}`} />

      <PageBody className="lg:grid lg:grid-cols-2 lg:items-start lg:gap-5">
        <div className="flex flex-col gap-5">
          <Panel>
            <PanelHeader title="Identity" />
            <dl className="px-4 py-2">
              <Field label="Name">{ORGANIZATION.name}</Field>
              <Field label="Slug">{ORGANIZATION.slug}</Field>
              <Field label="Organization id">{ORGANIZATION.id}</Field>
              <Field label="Created">{dateTimeLabel(ORGANIZATION.createdAt)}</Field>
              <Field label="Members">{USERS.length}</Field>
              <Field label="Roles">
                {ROLES.length} ({ROLES.filter((role) => role.isSystem).length} system)
              </Field>
            </dl>
          </Panel>

          <Panel>
            <PanelHeader title="Limits & policy" hint="max_queued_analyses already exists on the Organization model with no UI anywhere" />
            <div className="flex flex-col gap-4 px-4 py-4">
              <label className="flex flex-wrap items-center gap-3">
                <span className="min-w-[11rem] font-mono text-[10px] tracking-[0.1em] text-sand-muted/70 uppercase">Max queued analyses</span>
                <Input defaultValue={ORGANIZATION.maxQueuedAnalyses} className="w-24" type="number" min={1} />
              </label>
              <label className="flex flex-wrap items-center gap-3">
                <span className="min-w-[11rem] font-mono text-[10px] tracking-[0.1em] text-sand-muted/70 uppercase">Access log retention</span>
                <Input defaultValue={ORGANIZATION.accessLogRetentionDays} className="w-24" type="number" min={30} />
                <span className="font-mono text-[11px] text-sand-muted/60">days, then archived</span>
              </label>
              <div className="flex flex-wrap items-center gap-3">
                <span className="min-w-[11rem] font-mono text-[10px] tracking-[0.1em] text-sand-muted/70 uppercase">MFA policy</span>
                <Badge tone="ok">{ORGANIZATION.mfaPolicy.replace("_", " ")}</Badge>
                <span className="font-mono text-[11px] text-sand-muted/60">set by NETRA_MFA_POLICY</span>
              </div>
              <Button
                variant="primary"
                size="sm"
                className="self-start"
                onClick={() => toast("Save settings", { description: "Writes require step-up. Phase 2." })}
              >
                Save changes
              </Button>
            </div>
          </Panel>
        </div>

        <div className="mt-5 flex flex-col gap-5 lg:mt-0">
          <Panel>
            <PanelHeader title="Owner" hint="Exactly one, transferred rather than granted" />
            {owner ? (
              <div className="flex flex-wrap items-center gap-3 px-4 py-4">
                <div className="min-w-0 flex-1">
                  <Link to={`/users/${owner.id}`} className="text-sm text-cream-bright hover:text-signal">
                    {owner.name}
                  </Link>
                  <p className="mt-0.5 font-mono text-[11px] text-sand-muted/70">{owner.email}</p>
                </div>
                <Badge tone="accent">Owner</Badge>
              </div>
            ) : null}
            <p className="border-t border-hairline px-4 py-2.5 text-[11px] text-sand-muted/75">
              Ownership is separate from the Admin role. Admins administer; the owner is the single accountable identity for the
              organization, and there is always exactly one.
            </p>
          </Panel>

          <Panel className="border-state-crit/70">
            <PanelHeader title="Transfer ownership" className="border-state-crit/40" hint="Irreversible without the new owner's cooperation" />
            <div className="flex flex-col gap-3 px-4 py-4">
              <p className="text-xs text-sand-muted">
                Transferring ownership demotes the current owner to Admin and promotes the target in a single transaction. It requires a
                fresh TOTP challenge, a written reason of 10–1000 characters, and the organization name typed exactly.
              </p>
              <Input placeholder={`Type "${ORGANIZATION.name}" to confirm`} aria-label="Confirm organization name" />
              <Button
                variant="danger"
                size="sm"
                className="self-start"
                onClick={() => toast("Transfer ownership", { description: "Runs through transfer_administrator. Phase 3." })}
              >
                <ArrowLeftRight className="size-3.5" strokeWidth={1.75} aria-hidden="true" />
                Transfer ownership
              </Button>
            </div>
          </Panel>
        </div>
      </PageBody>
    </>
  );
}
