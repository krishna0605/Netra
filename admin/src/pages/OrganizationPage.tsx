import { ArrowLeftRight } from "lucide-react";
import { Link } from "react-router-dom";
import { toast } from "sonner";

import { Avatar, Button, Field, Input, Panel, PanelHeader, Status, Tag } from "../components/ui/primitives";
import { ORGANIZATION, ROLES, USERS } from "../data/mock";
import { PageBody, PageHeader } from "../components/common";
import { dateTimeLabel, initials } from "../lib/utils";

export function OrganizationPage() {
  const owner = USERS.find((user) => user.id === ORGANIZATION.ownerUserId);

  return (
    <>
      <PageHeader title="Organization" summary={`${ORGANIZATION.name} · established ${dateTimeLabel(ORGANIZATION.createdAt)}`} />

      <PageBody className="lg:grid lg:grid-cols-2 lg:items-start lg:gap-6">
        <div className="flex flex-col gap-6">
          <Panel>
            <PanelHeader title="Details" />
            <dl className="px-5 py-3">
              <Field label="Name" mono={false}>
                {ORGANIZATION.name}
              </Field>
              <Field label="Short name">{ORGANIZATION.slug}</Field>
              <Field label="Identifier">{ORGANIZATION.id}</Field>
              <Field label="Established">{dateTimeLabel(ORGANIZATION.createdAt)}</Field>
              <Field label="Members" mono={false}>
                {USERS.length} accounts across {ROLES.length} roles
              </Field>
            </dl>
          </Panel>

          <Panel>
            <PanelHeader title="Limits & policy" />
            <div className="flex flex-col gap-5 px-5 py-5">
              <label className="flex flex-wrap items-center gap-4">
                <span className="min-w-[12rem] text-[13px] text-sand-muted/80">Concurrent analyses</span>
                <Input defaultValue={ORGANIZATION.maxQueuedAnalyses} className="w-24" type="number" min={1} />
              </label>
              <label className="flex flex-wrap items-center gap-4">
                <span className="min-w-[12rem] text-[13px] text-sand-muted/80">Access record retention</span>
                <Input defaultValue={ORGANIZATION.accessLogRetentionDays} className="w-24" type="number" min={30} />
                <span className="text-[13px] text-sand-muted/60">days, then archived</span>
              </label>
              <div className="flex flex-wrap items-center gap-4">
                <span className="min-w-[12rem] text-[13px] text-sand-muted/80">Authenticator policy</span>
                <Status tone="ok">Required for administrators</Status>
              </div>
              <Button variant="primary" size="sm" className="self-start" onClick={() => toast("Settings saved")}>
                Save changes
              </Button>
            </div>
          </Panel>
        </div>

        <div className="mt-6 flex flex-col gap-6 lg:mt-0">
          <Panel>
            <PanelHeader title="Owner" hint="Exactly one, transferred rather than granted" />
            {owner ? (
              <div className="flex flex-wrap items-center gap-3 px-5 py-4">
                <Avatar initials={initials(owner.name)} tone="accent" />
                <div className="min-w-0 flex-1">
                  <Link to={`/users/${owner.id}`} className="text-[15px] text-cream-bright hover:text-signal">
                    {owner.name}
                  </Link>
                  <p className="mt-0.5 font-mono text-xs text-sand-muted/70">{owner.email}</p>
                </div>
                <Tag tone="accent">Owner</Tag>
              </div>
            ) : null}
            <p className="border-t border-hairline px-5 py-3.5 text-[13px] text-sand-muted/75">
              Ownership is separate from the administrator role. Administrators administer; the owner is the single accountable identity for
              this organization.
            </p>
          </Panel>

          <Panel className="border-state-crit/45">
            <PanelHeader title="Transfer ownership" className="border-state-crit/25" />
            <div className="flex flex-col gap-4 px-5 py-5">
              <p className="text-[13px] leading-relaxed text-sand-muted">
                Transferring ownership demotes the current owner to administrator and promotes the person you choose, in a single step. It
                requires a fresh authenticator code, a written reason, and the organization name typed exactly.
              </p>
              <Input placeholder={`Type "${ORGANIZATION.name}" to confirm`} aria-label="Confirm organization name" />
              <Button
                variant="danger"
                size="sm"
                className="self-start"
                onClick={() => toast("Confirmation required", { description: "Type the organization name exactly to continue." })}
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
