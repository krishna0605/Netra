import { Alert, Badge, Button } from "../../../components/ui/primitives";
import { API_BASE } from "../ConsoleCore";
import { apiGet } from "../ConsoleCore";
import { appViewRoute } from "../ConsoleCore";
import { Area, AreaChart, CartesianGrid, Tooltip as ChartTooltip, ResponsiveContainer, XAxis, YAxis } from "recharts";
import { CaseContextSelector } from "../evidence/EvidenceShared";
import { ChartPanel } from "./ReportPages";
import { Download, FileText, Fingerprint, Upload } from "lucide-react";
import { downloadApiFile } from "../ConsoleCore";
import { formatBytes, formatNumber } from "../../../lib/utils";
import { Link } from "react-router-dom";
import { MetadataRow } from "./ReportPages";
import { MetricTile } from "./ReportPages";
import { netraHeaders } from "../ConsoleCore";
import { PageFrame } from "./ReportPages";
import { SeverityBadge } from "./ReportPages";
import { toast } from "sonner";
import { type AnomalyRecord, type DecodedProtocolRecord, type ExportRecord, type NetworkFlow, type PacketRecord, type PayloadFinding, type ReportRecord, type SessionRecord, type ZeekEvidence } from "../../../lib/types";
import { useCallback, useEffect, useState } from "react";
import { useNetra } from "../ConsoleCore";

export function EvidenceReportPage() {
  const { t, activeCaseId, caseRecords, language, reloadAnalysis, summary, setActiveCaseId } = useNetra();
  const [selectedCaseId, setSelectedCaseId] = useState(activeCaseId ?? caseRecords[0]?.id ?? "");
  const [reports, setReports] = useState<ReportRecord[]>([]);
  const [exports, setExports] = useState<ExportRecord[]>([]);
  const [legalReview, setLegalReview] = useState<{ status: string; items: { name: string; status: string; detail: string }[] } | null>(null);
  const [busyAction, setBusyAction] = useState<string | null>(null);
  const currentCase = caseRecords.find((record) => record.id === selectedCaseId) ?? caseRecords[0];

  useEffect(() => {
    if (selectedCaseId && caseRecords.some((record) => record.id === selectedCaseId)) return;
    const next = (activeCaseId && caseRecords.some((record) => record.id === activeCaseId) ? activeCaseId : caseRecords[0]?.id) ?? "";
    setSelectedCaseId(next);
    if (next) setActiveCaseId(next);
  }, [activeCaseId, caseRecords, selectedCaseId, setActiveCaseId]);

  const refreshArtifacts = useCallback(() => {
    apiGet<{ results: ReportRecord[] }>(selectedCaseId ? `/reports?caseId=${encodeURIComponent(selectedCaseId)}&limit=50` : "/reports?limit=50").then((payload) => setReports(payload.results)).catch(() => setReports([]));
    apiGet<{ results: ExportRecord[] }>(selectedCaseId ? `/exports?caseId=${encodeURIComponent(selectedCaseId)}&limit=50` : "/exports?limit=50").then((payload) => setExports(payload.results)).catch(() => setExports([]));
    if (selectedCaseId) {
      apiGet<{ status: string; items: { name: string; status: string; detail: string }[] }>(`/cases/${selectedCaseId}/legal-review/checklist`).then(setLegalReview).catch(() => setLegalReview(null));
    } else {
      setLegalReview(null);
    }
  }, [selectedCaseId]);

  useEffect(() => {
    refreshArtifacts();
  }, [refreshArtifacts]);

  function selectCase(caseId: string) {
    setSelectedCaseId(caseId);
    setActiveCaseId(caseId);
  }

  async function exportPdfReport() {
    if (!currentCase) return;
    if (!currentCase.reportEligible) {
      toast.error(currentCase.reportBlockedReason ?? "Report generation becomes available after analysis completes.");
      return;
    }
    setBusyAction("report");
    try {
      const response = await fetch(`${API_BASE}/reports/${currentCase.id}/generate-pdf`, { method: "POST", headers: netraHeaders({ "Content-Type": "application/json" }), body: JSON.stringify({ language, format: "pdf" }) });
      const payload = await response.json();
      if (!response.ok) {
        toast.error(payload.error ?? "PDF report generation failed");
        return;
      }
      await downloadApiFile(payload.downloadUrl, payload.filename ?? `${currentCase.id}-report.pdf`);
      toast.success(`PDF report downloaded: ${payload.filename}`);
      refreshArtifacts();
      await reloadAnalysis().catch(() => undefined);
    } catch (error) {
      toast.error(error instanceof Error ? error.message : "PDF report download failed");
    } finally {
      setBusyAction(null);
    }
  }

  async function createExport(type: string) {
    if (!currentCase) return;
    setBusyAction(type);
    try {
      const response = await fetch(`${API_BASE}/exports`, { method: "POST", headers: netraHeaders({ "Content-Type": "application/json" }), body: JSON.stringify({ type, caseId: currentCase.id }) });
      const payload = await response.json();
      if (!response.ok) {
        toast.error(payload.error ?? "Export failed");
        return;
      }
      toast.success(`${type} export ready: ${payload.filename ?? payload.id}`);
      refreshArtifacts();
    } finally {
      setBusyAction(null);
    }
  }

  async function verifyEvidence() {
    if (!currentCase?.evidenceFileId) {
      toast.error("No evidence file is available for the selected case.");
      return;
    }
    setBusyAction("verify");
    try {
      const response = await fetch(`${API_BASE}/evidence/${currentCase.evidenceFileId}/verify-integrity`, { method: "POST", headers: netraHeaders() });
      const payload = await response.json();
      if (!response.ok || !payload.verified) {
        toast.error(payload.error ?? "Evidence integrity could not be verified.");
        return;
      }
      toast.success("Evidence integrity verified.");
    } finally {
      setBusyAction(null);
    }
  }

  if (!currentCase) {
    return (
      <PageFrame title={t("evidenceReport")} description={t("evidenceReportDesc")}>
        <div className="surface mx-auto flex max-w-2xl flex-col items-center gap-4 rounded-[1.5rem] p-8 text-center">
          <FileText size={34} aria-hidden="true" />
          <div>
            <h2 className="text-xl font-black text-strong">No reports yet</h2>
            <p className="mt-2 text-sm leading-6 text-muted">Upload and analyze evidence first. Netra will create case-specific report artifacts here.</p>
          </div>
          <Button asChild><Link to={appViewRoute("upload")}><Upload size={16} />Start investigation</Link></Button>
        </div>
      </PageFrame>
    );
  }

  return (
    <PageFrame title={t("evidenceReport")} description="Generated report artifacts, downloads, exports, and legal readiness for officer cases.">
      <div className="surface rounded-[1.5rem] p-5">
        <div className="flex flex-wrap items-start justify-between gap-4">
          <div>
            <h2 className="text-xl font-black text-strong">Report center</h2>
            <p className="mt-2 max-w-3xl text-sm leading-6 text-muted">Choose a case, generate a structured PDF, and download previous report/export artifacts without leaving the officer workflow.</p>
          </div>
          <CaseContextSelector value={currentCase.id} onChange={selectCase} />
        </div>
        <div className="mt-5 grid gap-4 md:grid-cols-4">
          <MetricTile label="Case" value={currentCase.id} detail={currentCase.status} />
          <MetricTile label="Risk" value={(currentCase.riskLevel ?? summary.riskLevel).toUpperCase()} detail={currentCase.topAttackClass ?? summary.topAttackClass} />
          <MetricTile label="Reports" value={reports.length} detail="Generated PDF/HTML artifacts" />
          <MetricTile label="Exports" value={exports.length} detail="JSON, CSV, and CEF bundles" />
        </div>
        <div className="mt-5 flex flex-wrap gap-3">
          <Button className="whitespace-nowrap" onClick={exportPdfReport} disabled={busyAction !== null || !currentCase.reportEligible} title={currentCase.reportBlockedReason}><FileText className="size-4" />{busyAction === "report" ? "Generating..." : "Generate and download PDF"}</Button>
          <Button className="whitespace-nowrap" variant="secondary" onClick={() => createExport("Evidence JSON")} disabled={busyAction !== null}><Download className="size-4" />Export JSON bundle</Button>
          <Button className="whitespace-nowrap" variant="secondary" onClick={() => createExport("Alert CSV")} disabled={busyAction !== null}><Download className="size-4" />Export alert CSV</Button>
          <Button className="whitespace-nowrap" variant="secondary" onClick={verifyEvidence} disabled={busyAction !== null || !currentCase.evidenceFileId}><Fingerprint className="size-4" />Verify evidence hash</Button>
        </div>
        {!currentCase.reportEligible && <Alert>{currentCase.reportBlockedReason ?? "Report generation becomes available after analysis completes."}</Alert>}
      </div>

      <div className="surface-solid overflow-hidden rounded-[1.5rem]">
        <div className="p-5 pb-0">
          <h2 className="text-xl font-black text-strong">Generated reports</h2>
          <p className="mt-1 text-sm text-muted">Reports are backend-generated files stored as encrypted artifacts and downloaded through authenticated routes.</p>
        </div>
        <div className="overflow-x-auto p-4">
          <table className="w-full min-w-[980px] text-left text-sm">
            <thead className="border-b border-[var(--border)] text-xs uppercase text-muted"><tr><th className="py-3">Report</th><th>Case</th><th>Opened</th><th>Closed</th><th>Generated</th><th>Language</th><th>Status</th><th>Action</th></tr></thead>
            <tbody>{reports.map((report) => (
              <tr key={report.id} className="border-b border-[var(--border)]">
                <td className="py-3"><div className="font-bold text-strong">{report.title}</div><div className="text-xs text-muted">{report.filename}</div></td>
                <td>{report.caseId}</td>
                <td>{report.openedAt ? new Date(report.openedAt).toLocaleString() : "-"}</td>
                <td>{report.closedAt ? new Date(report.closedAt).toLocaleString() : "Open"}</td>
                <td>{new Date(report.generatedAt).toLocaleString()}</td>
                <td>{report.language}</td>
                <td><Badge>{report.status}</Badge></td>
                <td><Button size="sm" variant="secondary" onClick={() => downloadApiFile(report.downloadUrl, report.filename)}><Download className="size-4" />Download</Button></td>
              </tr>
            ))}</tbody>
          </table>
          {!reports.length && <div className="py-8 text-center text-sm text-muted">No generated reports for this case yet. Use Generate and download PDF to create one.</div>}
        </div>
      </div>

      <div className="surface-solid overflow-hidden rounded-[1.5rem]">
        <div className="p-5 pb-0">
          <h2 className="text-xl font-black text-strong">Generated exports</h2>
        </div>
        <div className="overflow-x-auto p-4">
          <table className="w-full min-w-[860px] text-left text-sm">
            <thead className="border-b border-[var(--border)] text-xs uppercase text-muted"><tr><th className="py-3">Export</th><th>Type</th><th>Case</th><th>Created</th><th>Status</th><th>Hash</th></tr></thead>
            <tbody>{exports.map((item) => <tr key={item.id} className="border-b border-[var(--border)]"><td className="py-3 font-bold text-strong">{item.id}</td><td>{item.type}</td><td>{item.caseId}</td><td>{item.timestamp}</td><td><Badge>{item.status}</Badge></td><td className="font-mono text-xs">{item.hash}</td></tr>)}</tbody>
          </table>
          {!exports.length && <div className="py-8 text-center text-sm text-muted">No exports for this case yet.</div>}
        </div>
      </div>

      <div className="surface-solid overflow-hidden rounded-[1.5rem]">
        <div className="p-5 pb-0">
          <h2 className="text-xl font-black text-strong">Legal review checklist</h2>
          <p className="mt-1 text-sm text-muted">Status: {legalReview?.status ?? "loading"}</p>
        </div>
        <div className="overflow-x-auto p-4">
          <table className="w-full min-w-[760px] text-left text-sm">
            <thead className="border-b border-[var(--border)] text-xs uppercase text-muted"><tr><th className="py-3">Control</th><th>Status</th><th>Detail</th></tr></thead>
            <tbody>{(legalReview?.items ?? []).map((item) => <tr key={item.name} className="border-b border-[var(--border)]"><td className="py-3 font-bold text-strong">{item.name}</td><td><Badge>{item.status}</Badge></td><td>{item.detail}</td></tr>)}</tbody>
          </table>
          {!legalReview?.items?.length && <div className="py-6 text-center text-sm text-muted">Legal checklist will appear after case evidence is available.</div>}
        </div>
      </div>
    </PageFrame>
  );
}

export function AnomalyReviewPanel({ anomalies: scopedAnomalies, timeline }: { anomalies?: AnomalyRecord[]; timeline?: { time: string; mb?: number; alerts?: number; packets?: number; anomalies?: number; value?: number }[] }) {
  const { anomalies, trafficTimelineData } = useNetra();
  const rows = scopedAnomalies ?? anomalies;
  const chartRows = (timeline?.length ? timeline : trafficTimelineData).map((row) => ({ ...row, mb: row.mb ?? 0, alerts: row.alerts ?? 0 }));
  return (
    <div className="grid gap-4 lg:grid-cols-[1fr_0.8fr]">
      <div className="surface-solid rounded-[1.5rem] p-5">
        <h3 className="text-lg font-black text-strong">AI-assisted anomaly review</h3>
        <p className="mt-1 text-sm text-muted">Netra explains unusual behavior using case features, baseline comparison, and model/fallback confidence.</p>
        <div className="mt-4 grid gap-3">
          {rows.map((item) => (
            <div key={item.id} className="rounded-xl border border-[var(--border)] bg-[var(--surface-muted)] p-4">
              <div className="flex flex-wrap items-start justify-between gap-3">
                <div className="min-w-0">
                  <div className="font-bold text-strong">{item.entity}</div>
                  <div className="mt-1 text-sm text-muted">{item.behaviour}</div>
                </div>
                <Badge>{item.confidence}% confidence</Badge>
              </div>
              <div className="mt-3 grid gap-3 md:grid-cols-2">
                <MetadataRow label="Observed" value={item.observed || "-"} />
                <MetadataRow label="Baseline" value={item.baseline || "-"} />
                <MetadataRow label="Deviation" value={item.deviation || "-"} />
                <MetadataRow label="Model" value={item.modelVersion || "fallback-scoring"} />
              </div>
              {item.topFeatures?.length ? <p className="mt-3 text-xs leading-5 text-muted">Evidence features: {item.topFeatures.join(", ")}</p> : null}
              {item.recommendedAction ? <p className="mt-2 text-xs leading-5 text-muted">Recommended action: {item.recommendedAction}</p> : null}
            </div>
          ))}
          {!rows.length && <div className="rounded-xl border border-dashed border-[var(--border)] p-8 text-center text-sm text-muted">No unusual behavioral patterns were detected in this evidence file.</div>}
        </div>
      </div>
      <ChartPanel title="Traffic pattern over time">
        {chartRows.length ? <ResponsiveContainer width="100%" height={280}><AreaChart data={chartRows}><CartesianGrid stroke="var(--border)" strokeDasharray="3 3" vertical={false} /><XAxis dataKey="time" fontSize={11} stroke="var(--muted)" /><YAxis fontSize={11} stroke="var(--muted)" /><ChartTooltip /><Area dataKey={timeline?.length ? "alerts" : "mb"} type="monotone" stroke="var(--accent)" fill="var(--accent-soft)" /></AreaChart></ResponsiveContainer> : <div className="flex min-h-[280px] items-center justify-center text-sm text-muted">No traffic pattern data found in this evidence file.</div>}
      </ChartPanel>
    </div>
  );
}

export function PacketEvidenceTable({ packets }: { packets: PacketRecord[] }) {
  return (
    <div className="surface-solid overflow-hidden rounded-[1.5rem]">
      <div className="overflow-x-auto p-4">
        <table className="w-full min-w-[920px] text-left text-sm">
          <thead className="border-b border-[var(--border)] text-xs uppercase text-muted"><tr><th className="py-3">Packet</th><th>Time</th><th>Source</th><th>Destination</th><th>Protocol</th><th>Session</th><th>Risk</th></tr></thead>
          <tbody>{packets.map((packet) => <tr key={packet.id} className="border-b border-[var(--border)]"><td className="py-3 font-bold text-strong">{packet.id}</td><td className="font-mono text-xs">{packet.timestamp}</td><td className="font-mono text-xs">{packet.sourceIp}:{packet.sourcePort}</td><td className="font-mono text-xs">{packet.destinationIp}:{packet.destinationPort}</td><td><Badge>{packet.protocol}</Badge></td><td>{packet.sessionId}</td><td>{packet.riskScore}</td></tr>)}</tbody>
        </table>
        {!packets.length && <div className="py-8 text-center text-sm text-muted">No packet rows found in this evidence file.</div>}
      </div>
      <div className="border-t border-[var(--border)] p-4"><Button asChild variant="secondary" size="sm"><Link to={appViewRoute("packets")}>Open advanced packet explorer</Link></Button></div>
    </div>
  );
}

export function SessionEvidenceTable({ sessions }: { sessions: SessionRecord[] }) {
  return (
    <div className="surface-solid overflow-hidden rounded-[1.5rem]">
      <div className="overflow-x-auto p-4">
        <table className="w-full min-w-[880px] text-left text-sm">
          <thead className="border-b border-[var(--border)] text-xs uppercase text-muted"><tr><th className="py-3">Session</th><th>Source</th><th>Destination</th><th>Protocol</th><th>Duration</th><th>Packets</th><th>Risk</th></tr></thead>
          <tbody>{sessions.map((session) => <tr key={session.id} className="border-b border-[var(--border)]"><td className="py-3 font-bold text-strong">{session.id}</td><td>{session.source}</td><td>{session.destination}</td><td><Badge>{session.protocol}</Badge></td><td>{session.duration}</td><td>{session.packetCount}</td><td>{session.riskScore}</td></tr>)}</tbody>
        </table>
        {!sessions.length && <div className="py-8 text-center text-sm text-muted">No sessions were reconstructed from this evidence file.</div>}
      </div>
      <div className="border-t border-[var(--border)] p-4"><Button asChild variant="secondary" size="sm"><Link to={appViewRoute("sessions")}>Open session drilldown</Link></Button></div>
    </div>
  );
}

export function ProtocolEvidenceTable({ protocols, zeek }: { protocols: DecodedProtocolRecord[]; zeek?: ZeekEvidence | null }) {
  return (
    <div className="grid gap-4">
      <div className="surface rounded-[1.5rem] p-4">
        <div className="flex flex-wrap items-center gap-2"><Badge>Zeek: {zeek?.status ?? "not-run"}</Badge>{(zeek?.logs ?? []).map((log) => <Badge key={log} variant="secondary">{log}</Badge>)}</div>
      </div>
      <div className="surface-solid overflow-hidden rounded-[1.5rem]">
        <div className="overflow-x-auto p-4">
          <table className="w-full min-w-[820px] text-left text-sm">
            <thead className="border-b border-[var(--border)] text-xs uppercase text-muted"><tr><th className="py-3">Protocol</th><th>Packets</th><th>Sessions</th><th>Suspicious</th><th>Status</th><th>Evidence note</th></tr></thead>
            <tbody>{protocols.map((record) => <tr key={record.protocol} className="border-b border-[var(--border)]"><td className="py-3 font-bold text-strong">{record.protocol}</td><td>{formatNumber(record.packetCount)}</td><td>{record.sessionCount}</td><td>{record.suspiciousCount}</td><td><Badge>{record.status}</Badge></td><td>{record.detail}</td></tr>)}</tbody>
          </table>
          {!protocols.length && <div className="py-8 text-center text-sm text-muted">No decoded protocol evidence found in this evidence file.</div>}
        </div>
        <div className="border-t border-[var(--border)] p-4"><Button asChild variant="secondary" size="sm"><Link to={appViewRoute("decoder")}>Open protocol decoder</Link></Button></div>
      </div>
    </div>
  );
}

export function PayloadEvidenceTable({ findings }: { findings: PayloadFinding[] }) {
  return (
    <div className="surface-solid overflow-hidden rounded-[1.5rem]">
      <div className="overflow-x-auto p-4">
        <table className="w-full min-w-[860px] text-left text-sm">
          <thead className="border-b border-[var(--border)] text-xs uppercase text-muted"><tr><th className="py-3">Finding</th><th>Packet</th><th>Session</th><th>Protocol</th><th>Type</th><th>Hidden</th><th>Risk</th><th>Pattern</th></tr></thead>
          <tbody>{findings.map((finding) => <tr key={finding.id} className="border-b border-[var(--border)]"><td className="py-3 font-bold text-strong">{finding.id}</td><td>{finding.packetId}</td><td>{finding.sessionId}</td><td><Badge>{finding.protocol}</Badge></td><td>{finding.payloadType}</td><td>{finding.hiddenData ? "yes" : "no"}</td><td><SeverityBadge severity={finding.risk} /></td><td>{finding.description ?? finding.matchedPattern}</td></tr>)}</tbody>
        </table>
        {!findings.length && <div className="py-8 text-center text-sm text-muted">No payload clues found in this evidence file.</div>}
      </div>
      <div className="border-t border-[var(--border)] p-4"><Button asChild variant="secondary" size="sm"><Link to={appViewRoute("payloads")}>Open payload drilldown</Link></Button></div>
    </div>
  );
}

export function FlowEvidenceTable({ flows }: { flows: NetworkFlow[] }) {
  return (
    <div className="surface-solid overflow-hidden rounded-[1.5rem]">
      <div className="overflow-x-auto p-4">
        <table className="w-full min-w-[860px] text-left text-sm">
          <thead className="border-b border-[var(--border)] text-xs uppercase text-muted"><tr><th className="py-3">Source</th><th>Destination</th><th>Protocol</th><th>Packets</th><th>Bytes</th><th>Risk</th><th>Finding</th></tr></thead>
          <tbody>{flows.map((flow) => <tr key={flow.id} className="border-b border-[var(--border)]"><td className="py-3 font-mono text-xs">{flow.source}</td><td className="font-mono text-xs">{flow.target}</td><td><Badge>{flow.protocol}</Badge></td><td>{formatNumber(flow.packets)}</td><td>{formatBytes(flow.bytes)}</td><td>{flow.risk ?? 0}</td><td>{flow.attackClass}</td></tr>)}</tbody>
        </table>
        {!flows.length && <div className="py-8 text-center text-sm text-muted">No communication paths found in this evidence file.</div>}
      </div>
      <div className="border-t border-[var(--border)] p-4"><Button asChild variant="secondary" size="sm"><Link to={appViewRoute("graph")}>Open full communication map</Link></Button></div>
    </div>
  );
}
