import "@xyflow/react/dist/style.css";
import { AccessLogTable } from "../reports/ReportPages";
import { API_BASE } from "../ConsoleCore";
import { apiGet } from "../ConsoleCore";
import { Background, Controls, type Edge, MiniMap, type Node, type NodeMouseHandler, ReactFlow } from "@xyflow/react";
import { Badge, Button, Sheet, SheetContent, SheetTitle, Switch } from "../../../components/ui/primitives";
import { CustodyLedgerTable } from "../reports/ReportPages";
import { DeliveryTable } from "../reports/ReportPages";
import { edgeStyle } from "../reports/ReportPages";
import { Field } from "../reports/ReportPages";
import { formatNumber } from "../../../lib/utils";
import { IntegrationTable } from "../reports/ReportPages";
import { MetadataRow } from "../reports/ReportPages";
import { MetricTile } from "../reports/ReportPages";
import { netraHeaders } from "../ConsoleCore";
import { nodeStyle } from "../reports/ReportPages";
import { PageFrame } from "../reports/ReportPages";
import { SelectField } from "../reports/ReportPages";
import { toast } from "sonner";
import { type IntegrationRecord } from "../../../lib/types";
import { useCallback, useEffect, useState } from "react";
import { useNetra } from "../ConsoleCore";

export function IntegrationsPage() {
  const { t, activeCaseId } = useNetra();
  const [records, setRecords] = useState<IntegrationRecord[]>([]);
  const [deliveries, setDeliveries] = useState<{ id: string; timestamp: string; caseId: string; type: string; result: string; response: string }[]>([]);
  const [systemName, setSystemName] = useState("");
  const [webhookUrl, setWebhookUrl] = useState("");
  const [secret, setSecret] = useState("");
  const loadRecords = useCallback(() => {
    apiGet<{ results: IntegrationRecord[] }>("/integrations").then((payload) => setRecords(payload.results)).catch(() => setRecords([]));
  }, []);
  useEffect(() => {
    loadRecords();
  }, [loadRecords]);
  async function createWebhook() {
    const response = await fetch(`${API_BASE}/integrations`, { method: "POST", headers: netraHeaders({ "Content-Type": "application/json" }), body: JSON.stringify({ systemName, mode: "webhook-json", url: webhookUrl, secret }) });
    const payload = await response.json();
    if (!response.ok) toast.error(payload.error ?? "Webhook could not be saved");
    else {
      toast.success("Webhook saved. Test it before sending alerts.");
      setSystemName("");
      setWebhookUrl("");
      setSecret("");
      loadRecords();
    }
  }
  async function testIntegration(id: string | number | undefined) {
    if (!id) return;
    const response = await fetch(`${API_BASE}/integrations/${id}/test`, { method: "POST", headers: netraHeaders({ "Content-Type": "application/json" }) });
    const payload = await response.json();
    if (!response.ok) toast.error(payload.error ?? "Integration test failed");
    else {
      toast.success(`Webhook reached successfully: ${payload.response}`);
      loadRecords();
    }
  }
  async function sendAlerts(id: string | number | undefined) {
    if (!id) return;
    const response = await fetch(`${API_BASE}/integrations/${id}/send-alerts`, { method: "POST", headers: netraHeaders({ "Content-Type": "application/json" }), body: JSON.stringify({ caseId: activeCaseId }) });
    const payload = await response.json();
    if (!response.ok) toast.error(payload.error ?? "Alert delivery failed");
    else {
      toast.success(`Delivered ${payload.delivered} of ${payload.attempted} alert(s).`);
      apiGet<{ results: typeof deliveries }>(`/integrations/${id}/deliveries`).then((data) => setDeliveries(data.results)).catch(() => undefined);
    }
  }
  async function exportSiem() {
    const response = await fetch(`${API_BASE}/integrations/siem/export`, { method: "POST", headers: netraHeaders({ "Content-Type": "application/json" }), body: JSON.stringify({ caseId: activeCaseId }) });
    const payload = await response.json();
    if (!response.ok) toast.error(payload.error ?? "SIEM export failed");
    else toast.success(`SIEM artifact ready: ${payload.filename}`);
  }
  return (
    <PageFrame title={t("integrations")} description={t("integrationsDesc")}>
      <div className="grid gap-4 md:grid-cols-2 xl:grid-cols-4">
        {records.map((item) => <MetricTile key={item.system} label={item.system} value={item.status} detail={item.apiMode} />)}
        {!records.length && <div className="surface rounded-[1.5rem] p-6 text-sm text-muted md:col-span-2 xl:col-span-4">No integrations yet. Create a SIEM or webhook integration when you are ready to deliver real alerts.</div>}
      </div>
      <div className="surface rounded-[1.5rem] p-5">
        <h2 className="text-xl font-black text-strong">Add webhook</h2>
        <p className="mt-1 text-sm text-muted">Netra sends an actual signed HTTP POST. A connection is marked connected only after the receiver responds successfully.</p>
        <div className="mt-4 grid gap-3 md:grid-cols-3">
          <Field label="Name" value={systemName} onChange={setSystemName} />
          <Field label="Webhook URL" value={webhookUrl} onChange={setWebhookUrl} />
          <Field label="HMAC secret" value={secret} onChange={setSecret} />
        </div>
        <Button className="mt-4" onClick={createWebhook} disabled={!systemName || !webhookUrl}>Save webhook</Button>
      </div>
      <div className="surface rounded-[1.5rem] p-5">
        <div className="flex flex-wrap items-center justify-between gap-3">
          <h2 className="text-xl font-black text-strong">SIEM delivery</h2>
          <Button onClick={exportSiem}>Export CEF</Button>
        </div>
        <div className="mt-4 grid gap-3 md:grid-cols-3">
          {records.slice(0, 3).map((item) => (
            <div key={item.system} className="rounded-xl border border-[var(--border)] bg-[var(--surface-muted)] p-4">
              <div className="font-bold text-strong">{item.system}</div>
              <div className="mt-1 text-sm text-muted">{item.apiMode}</div>
              <div className="mt-4 flex gap-2">
                <Button size="sm" variant="secondary" onClick={() => testIntegration((item as IntegrationRecord & { id?: string }).id)}>Test</Button>
                <Button size="sm" onClick={() => sendAlerts((item as IntegrationRecord & { id?: string }).id)}>Send Alerts</Button>
              </div>
            </div>
          ))}
        </div>
      </div>
      <IntegrationTable rows={records} />
      <DeliveryTable rows={deliveries} />
    </PageFrame>
  );
}

export function CompliancePage() {
  const { t, activeCaseId, complianceRecords } = useNetra();
  const [ledger, setLedger] = useState<{ verification?: { verified: boolean; eventCount: number; latestHash: string }; results?: { id: string; timestamp: string; actor: string; action: string; eventHash: string; previousHash: string }[] }>({});
  useEffect(() => {
    if (activeCaseId) apiGet<typeof ledger>(`/cases/${activeCaseId}/custody-ledger`).then(setLedger).catch(() => undefined);
  }, [activeCaseId]);
  return (
    <PageFrame title={t("compliance")} description={t("complianceDesc")}>
      <div className="grid gap-4 md:grid-cols-3">
        {complianceRecords.map((item) => <MetricTile key={item.item} label={item.item} value={item.status} detail={item.detail} />)}
        {!complianceRecords.length && <div className="surface rounded-[1.5rem] p-6 text-sm text-muted md:col-span-3">No compliance checklist rows yet. Custody, access-log, and integrity records will appear after setup and real evidence actions.</div>}
      </div>
      <div className="surface rounded-[1.5rem] p-5">
        <h2 className="text-xl font-black text-strong">Evidence controls</h2>
        <div className="mt-4 grid gap-2 md:grid-cols-3">
          <MetadataRow label="Ledger" value={ledger.verification?.verified ? "Verified" : "Pending"} />
          <MetadataRow label="Events" value={`${ledger.verification?.eventCount ?? 0}`} />
          <MetadataRow label="Latest hash" value={ledger.verification?.latestHash ?? "-"} />
        </div>
      </div>
      <CustodyLedgerTable rows={ledger.results ?? []} />
      <AccessLogTable />
    </PageFrame>
  );
}

export function GraphPage() {
  const { t, networkFlows } = useNetra();
  const [selectedNode, setSelectedNode] = useState<Node | null>(null);
  const nodeIds = Array.from(new Set(networkFlows.flatMap((flow) => [flow.source, flow.target]))).slice(0, 30);
  const nodes: Node[] = nodeIds.map((id, index) => ({
    id,
    position: { x: (index % 5) * 240, y: Math.floor(index / 5) * 150 + 60 },
    data: { label: `${id}\nRisk ${Math.max(...networkFlows.filter((flow) => flow.source === id || flow.target === id).map((flow) => flow.risk ?? 0), 0)}` },
    style: nodeStyle(Math.max(...networkFlows.filter((flow) => flow.source === id || flow.target === id).map((flow) => flow.risk ?? 0), 0)),
  }));
  const edges: Edge[] = networkFlows.slice(0, 50).map((flow) => ({
    id: flow.id,
    source: flow.source,
    target: flow.target,
    animated: flow.suspicious,
    label: `${flow.protocol} | ${flow.attackClass} | ${flow.packets} pkts`,
    style: edgeStyle(Math.min(5, Math.max(1, Math.ceil((flow.risk ?? flow.packets) / 30))), flow.risk ?? 0),
  }));
  const onNodeClick: NodeMouseHandler = (_, node) => setSelectedNode(node);
  return (
    <PageFrame title={t("graphTitle")} description={t("graphDesc")}>
      <div className="surface rounded-[1.5rem] p-4">
        <div className="grid gap-3 md:grid-cols-4">
          <SelectField label={t("protocol")} value="all" values={["all", "DNS", "TLS", "TCP", "ICMP"]} onChange={() => undefined} />
          <SelectField label={t("severity")} value="all" values={["all", "critical", "high", "medium"]} onChange={() => undefined} />
          <SelectField label={t("class")} value="all" values={["all", "DNS Tunnel", "Exfiltration", "Beaconing"]} onChange={() => undefined} />
          <label className="flex items-end gap-2 rounded-xl border border-[var(--border)] bg-[var(--surface-muted)] p-3 text-sm"><Switch checked disabled /> Show only suspicious paths</label>
        </div>
      </div>
      <div className="surface overflow-hidden rounded-[1.5rem] p-2">
        <div className="netra-flow-light h-[620px] overflow-hidden rounded-[1.25rem]">
          {nodes.length > 0 ? <ReactFlow nodes={nodes} edges={edges} fitView fitViewOptions={{ padding: 0.2 }} onNodeClick={onNodeClick}>
            <Background color="rgba(13, 13, 13, 0.14)" gap={22} />
            <Controls />
            <MiniMap />
          </ReactFlow> : <div className="flex h-full items-center justify-center text-sm text-muted">Upload a PCAP to build the network graph.</div>}
        </div>
      </div>
      <Sheet open={!!selectedNode} onOpenChange={(open) => !open && setSelectedNode(null)}>
        <SheetContent aria-describedby={undefined}>
          <SheetTitle>{t("nodeDetail")}</SheetTitle>
          <div className="mt-6 flex flex-col gap-4">
            <Badge>{t("highConfidence")}</Badge>
            <h3 className="whitespace-pre-line text-xl font-bold text-strong">{selectedNode?.data.label as string}</h3>
            <MetadataRow label={t("riskScore")} value={`${Math.max(...networkFlows.filter((flow) => flow.source === selectedNode?.id || flow.target === selectedNode?.id).map((flow) => flow.risk ?? 0), 0)} / 100`} />
            <MetadataRow label={t("attackClassification")} value={Array.from(new Set(networkFlows.filter((flow) => flow.source === selectedNode?.id || flow.target === selectedNode?.id).map((flow) => flow.attackClass))).join(", ") || "Normal Baseline"} />
            <MetadataRow label={t("relatedAlerts")} value={networkFlows.filter((flow) => flow.source === selectedNode?.id || flow.target === selectedNode?.id).flatMap((flow) => flow.alertIds).join(", ") || "none"} />
            <MetadataRow label={t("bytesTransferred")} value={formatNumber(networkFlows.filter((flow) => flow.source === selectedNode?.id || flow.target === selectedNode?.id).reduce((sum, flow) => sum + flow.bytes, 0))} />
            <MetadataRow label={t("metadataRisk")} value="Risk is calculated from related alerts, sessions, and protocol behavior." />
            <Button onClick={() => toast.success(t("nodeToast"))}>{t("addToCase")}</Button>
          </div>
        </SheetContent>
      </Sheet>
    </PageFrame>
  );
}
