import { ArrowLeftRight } from "lucide-react";
import { Link } from "react-router-dom";
import { toast } from "sonner";
import { useEffect, useState } from "react";

import { Avatar, Button, Field, Input, Panel, PanelHeader, Status, Tag } from "../components/ui/primitives";
import { OwnerTransferDialog } from "../components/OwnerTransferDialog";
import { PageBody, PageHeader } from "../components/common";
import { SkeletonList } from "../components/states";
import { dateTimeLabel, initials } from "../lib/utils";
import { useDirectory } from "../data/store";

export function OrganizationPage() {
  const { users, roles, organization, updateOrganization, loading } = useDirectory();
  const owner = users.find((user) => user.id === organization.ownerUserId);

  const [transferOpen, setTransferOpen] = useState(false);
  const [saving, setSaving] = useState(false);
  const [form, setForm] = useState({
    name: organization.name,
    maxQueuedAnalyses: organization.maxQueuedAnalyses,
    accessLogRetentionDays: organization.accessLogRetentionDays,
  });

  // Re-seed when the record arrives or changes underneath, but never while the
  // operator is mid-edit — overwriting someone's typing is unforgivable.
  useEffect(() => {
    setForm({
      name: organization.name,
      maxQueuedAnalyses: organization.maxQueuedAnalyses,
      accessLogRetentionDays: organization.accessLogRetentionDays,
    });
  }, [organization]);

  const dirty =
    form.name !== organization.name ||
    form.maxQueuedAnalyses !== organization.maxQueuedAnalyses ||
    form.accessLogRetentionDays !== organization.accessLogRetentionDays;

  // Leaving with unsaved edits should cost a confirmation, not the work.
  useEffect(() => {
    if (!dirty) return;
    const warn = (event: BeforeUnloadEvent) => event.preventDefault();
    window.addEventListener("beforeunload", warn);
    return () => window.removeEventListener("beforeunload", warn);
  }, [dirty]);

  async function save() {
    setSaving(true);
    try {
      await updateOrganization(form);
      toast.success("Settings saved");
    } catch (cause) {
      toast.error("Not saved", { description: cause instanceof Error ? cause.message : "Try again." });
    } finally {
      setSaving(false);
    }
  }

  return (
    <>
      <PageHeader
        title="Organization"
        summary={loading ? "Loading…" : `${organization.name} · established ${dateTimeLabel(organization.createdAt)}`}
      />

      <PageBody className="lg:grid lg:grid-cols-2 lg:items-start lg:gap-6">
        <div className="flex flex-col gap-6">
          <Panel>
            <PanelHeader title="Details" />
            {loading ? (
              <SkeletonList rows={4} />
            ) : (
              <dl className="px-5 py-3">
                <Field label="Name" mono={false}>
                  {organization.name}
                </Field>
                <Field label="Short name">{organization.slug}</Field>
                <Field label="Identifier">{organization.id}</Field>
                <Field label="Established">{dateTimeLabel(organization.createdAt)}</Field>
                <Field label="Members" mono={false}>
                  {users.length} accounts across {roles.length} roles
                </Field>
              </dl>
            )}
          </Panel>

          <Panel>
            <PanelHeader title="Limits & policy" action={dirty ? <Tag tone="warn">Unsaved changes</Tag> : null} />
            <div className="flex flex-col gap-5 px-5 py-5">
              <label className="flex flex-wrap items-center gap-4">
                <span className="min-w-[12rem] text-[13px] text-sand-muted/80">Organization name</span>
                <Input
                  value={form.name}
                  onChange={(event) => setForm((current) => ({ ...current, name: event.target.value }))}
                  className="max-w-xs flex-1"
                />
              </label>

              <label className="flex flex-wrap items-center gap-4">
                <span className="min-w-[12rem] text-[13px] text-sand-muted/80">Concurrent analyses</span>
                <Input
                  type="number"
                  min={1}
                  value={form.maxQueuedAnalyses}
                  onChange={(event) =>
                    setForm((current) => ({ ...current, maxQueuedAnalyses: Math.max(1, Number(event.target.value) || 1) }))
                  }
                  className="w-24"
                />
              </label>

              <label className="flex flex-wrap items-center gap-4">
                <span className="min-w-[12rem] text-[13px] text-sand-muted/80">Access record retention</span>
                <Input
                  type="number"
                  min={30}
                  value={form.accessLogRetentionDays}
                  onChange={(event) =>
                    setForm((current) => ({
                      ...current,
                      accessLogRetentionDays: Math.max(30, Number(event.target.value) || 30),
                    }))
                  }
                  className="w-24"
                />
                <span className="text-[13px] text-sand-muted/60">days, then archived</span>
              </label>

              <div className="flex flex-wrap items-center gap-4">
                <span className="min-w-[12rem] text-[13px] text-sand-muted/80">Authenticator policy</span>
                <Status tone="ok">Required for administrators</Status>
              </div>

              <div className="flex items-center gap-2">
                <Button variant="primary" size="sm" disabled={!dirty || saving} onClick={() => void save()}>
                  {saving ? "Saving…" : "Save changes"}
                </Button>
                {dirty ? (
                  <Button
                    variant="ghost"
                    size="sm"
                    disabled={saving}
                    onClick={() =>
                      setForm({
                        name: organization.name,
                        maxQueuedAnalyses: organization.maxQueuedAnalyses,
                        accessLogRetentionDays: organization.accessLogRetentionDays,
                      })
                    }
                  >
                    Discard
                  </Button>
                ) : null}
              </div>
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
            ) : (
              <div className="px-5 py-6 text-center text-[13px] text-sand-muted">No owner is recorded.</div>
            )}
            <p className="border-t border-hairline px-5 py-3.5 text-[13px] text-sand-muted/75">
              Ownership is separate from the administrator role. Administrators administer; the owner is the single accountable identity
              for this organization.
            </p>
          </Panel>

          <Panel className="border-state-crit/45">
            <PanelHeader title="Transfer ownership" className="border-state-crit/25" />
            <div className="flex flex-col gap-4 px-5 py-5">
              <p className="text-[13px] leading-relaxed text-sand-muted">
                Transferring demotes the current owner to administrator and promotes the person you choose, in a single step. It requires
                a written reason, an authenticator code, and the organization name typed exactly.
              </p>
              <Button variant="danger" size="sm" className="self-start" onClick={() => setTransferOpen(true)}>
                <ArrowLeftRight className="size-3.5" strokeWidth={1.75} aria-hidden="true" />
                Transfer ownership
              </Button>
            </div>
          </Panel>
        </div>
      </PageBody>

      <OwnerTransferDialog open={transferOpen} onOpenChange={setTransferOpen} />
    </>
  );
}
