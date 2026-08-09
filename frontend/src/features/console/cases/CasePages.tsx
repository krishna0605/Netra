import { Alert, Badge, Button, Dialog, DialogContent, DialogTitle, DialogTrigger, Input, Progress, Select, SelectContent, SelectItem, SelectTrigger, SelectValue, Tabs, TabsContent, TabsList, TabsTrigger, Textarea } from "../../../components/ui/primitives";
import { AlertTable } from "../reports/ReportPages";
import { analysisStateLabel } from "../evidence/EvidenceShared";
import { AnomalyReviewPanel } from "../reports/EvidenceReportPages";
import { API_BASE } from "../ConsoleCore";
import { apiGet } from "../ConsoleCore";
import { apiWorkspace } from "../ConsoleCore";
import { appViewRoute } from "../ConsoleCore";
import { Area, AreaChart, CartesianGrid, Tooltip as ChartTooltip, ResponsiveContainer, XAxis, YAxis } from "recharts";
import { CASE_FLAG_OPTIONS } from "../ConsoleCore";
import { caseWorkspaceRoute } from "../ConsoleCore";
import { ChartPanel } from "../reports/ReportPages";
import { CustodyLedgerTable } from "../reports/ReportPages";
import { CustodyMetric } from "../reports/ReportPages";
import { downloadApiFile } from "../ConsoleCore";
import { FileText, Search, Upload } from "lucide-react";
import { FlowEvidenceTable } from "../reports/EvidenceReportPages";
import { formatBytes, formatNumber } from "../../../lib/utils";
import { graphEdgesToFlows } from "../ConsoleCore";
import { Link, useNavigate, useParams } from "react-router-dom";
import { MetadataRow } from "../reports/ReportPages";
import { MetricTile } from "../reports/ReportPages";
import { MiniBarList } from "../reports/ReportPages";
import { netraHeaders } from "../ConsoleCore";
import { PacketEvidenceTable } from "../reports/EvidenceReportPages";
import { PageFrame } from "../reports/ReportPages";
import { PayloadEvidenceTable } from "../reports/EvidenceReportPages";
import { ProtocolEvidenceTable } from "../reports/EvidenceReportPages";
import { SelectField } from "../reports/ReportPages";
import { SessionEvidenceTable } from "../reports/EvidenceReportPages";
import { SeverityBadge } from "../reports/ReportPages";
import { TimelineList } from "../reports/ReportPages";
import { toast } from "sonner";
import { type AlertRecord, type AnalysisStatus, type AnomalyRecord, type CaseChartsRecord, type CaseRecord, type CaseWorkspaceRecord, type CaseWorkspaceStatusRecord, type DashboardSummary, type DecodedProtocolRecord, type NetworkFlow, type PacketRecord, type PayloadFinding, type ReportRecord, type SessionRecord, type Severity } from "../../../lib/types";
import { useCallback, useEffect, useMemo, useRef, useState } from "react";
import { useNetra } from "../ConsoleCore";

export function CasesPage() {
  const { t, caseRecords, reloadAnalysis, setActiveCaseId } = useNetra();
  const [query, setQuery] = useState("");
  const [status, setStatus] = useState("all");
  const navigate = useNavigate();
  const filteredCases = caseRecords.filter((record) => {
    const text = query.trim().toLowerCase();
    return (!text || [record.id, record.title, record.investigator, record.sourceLocation ?? "", record.topAttackClass ?? ""].join(" ").toLowerCase().includes(text)) && (status === "all" || record.status === status);
  });
  async function generateCaseReport(caseId: string) {
    const record = caseRecords.find((item) => item.id === caseId);
    if (!record?.reportEligible) {
      toast.error(record?.reportBlockedReason ?? "Report generation becomes available after analysis completes.");
      return;
    }
    const response = await fetch(`${API_BASE}/reports/${caseId}/generate-pdf`, { method: "POST", headers: netraHeaders({ "Content-Type": "application/json" }), body: JSON.stringify({ language: "English", format: "pdf" }) });
    const payload = await response.json();
    if (!response.ok) {
      toast.error(payload.error ?? "PDF report generation failed");
      return;
    }
    await downloadApiFile(payload.downloadUrl, payload.filename ?? `${caseId}-report.pdf`);
    toast.success(`PDF report downloaded: ${payload.filename}`);
    await reloadAnalysis().catch(() => undefined);
  }
  function openCase(caseId: string) {
    const record = caseRecords.find((item) => item.id === caseId);
    if (!record?.routeRef) return;
    setActiveCaseId(caseId);
    navigate(caseWorkspaceRoute(record.routeRef));
  }
  return (
    <PageFrame title={t("cases")} description={t("caseQueueDesc")}>
      <div className="surface rounded-[1.5rem] p-5">
        <div className="flex flex-wrap items-start justify-between gap-4">
          <div>
            <h2 className="text-xl font-black text-strong">Case registry</h2>
            <p className="mt-2 max-w-3xl text-sm leading-6 text-muted">Only real officer-facing investigations are shown here. Validator and system-test cases are hidden from this list.</p>
          </div>
          <Button asChild><Link to={appViewRoute("upload")}><Upload className="size-4" />New investigation</Link></Button>
        </div>
        <div className="mt-5 grid gap-3 md:grid-cols-3">
          <Input value={query} onChange={(event) => setQuery(event.target.value)} placeholder="Search case, investigator, IP, finding" />
          <Select value={status} onValueChange={setStatus}>
            <SelectTrigger><SelectValue /></SelectTrigger>
            <SelectContent>{["all", "open", "closed"].map((item) => <SelectItem key={item} value={item}>{item}</SelectItem>)}</SelectContent>
          </Select>
          <Button variant="secondary" onClick={() => reloadAnalysis()}><Search className="size-4" />Refresh cases</Button>
        </div>
      </div>
      <div className="grid gap-3">
        {filteredCases.map((record) => (
          <CaseRegistryCard
            key={record.id}
            record={record}
            onOpen={() => openCase(record.id)}
            onGenerate={() => generateCaseReport(record.id)}
            onDownloadLatest={() => record.latestReportDownloadUrl && downloadApiFile(record.latestReportDownloadUrl, `${record.id}-report.pdf`)}
          />
        ))}
        {!filteredCases.length && <div className="surface-solid rounded-[1.5rem] p-8 text-center text-sm text-muted">No officer-facing cases found. Upload evidence to create the first real investigation.</div>}
      </div>
    </PageFrame>
  );
}

export function CaseRegistryCard({ record, onOpen, onGenerate, onDownloadLatest }: { record: CaseRecord; onOpen: () => void; onGenerate: () => void; onDownloadLatest: () => void }) {
  return (
    <article className="surface-solid rounded-[1.5rem] p-5">
      <div className="grid gap-5 xl:grid-cols-[minmax(16rem,1.25fr)_minmax(0,2fr)_auto]">
        <div className="min-w-0">
          <div className="text-xs font-bold uppercase tracking-[0.12em] text-muted">Case number</div>
          <h3 className="mt-2 break-words text-xl font-black text-strong">{record.id}</h3>
          <p className="mt-1 line-clamp-2 text-sm leading-6 text-muted">{record.title}</p>
          <div className="mt-3 flex flex-wrap gap-2">
            <Badge>{record.status}</Badge>
            <SeverityBadge severity={(record.riskLevel ?? "low") as Severity} />
            <Badge variant="secondary">{record.reportStatus}</Badge>
          </div>
        </div>
        <div className="grid min-w-0 gap-3 sm:grid-cols-2 lg:grid-cols-4">
          <CaseStat label="Priority" value={record.priority || "-"} />
          <CaseStat label="Top finding" value={record.topAttackClass ?? "Normal Baseline"} />
          <CaseStat label="Packets" value={formatNumber(record.packetCount ?? 0)} />
          <CaseStat label="Sessions" value={formatNumber(record.sessionCount ?? 0)} />
          <CaseStat label="Alerts" value={formatNumber(record.alertCount ?? 0)} />
          <CaseStat label="Opened" value={record.openedAt ? new Date(record.openedAt).toLocaleDateString() : "-"} />
          <CaseStat label="Updated" value={record.updatedAt ? new Date(record.updatedAt).toLocaleDateString() : "-"} />
          <CaseStat label="Investigator" value={record.investigator || "-"} />
        </div>
        <div className="flex min-w-[12rem] flex-col gap-2 xl:items-stretch">
          <Button size="sm" onClick={onOpen}>View full case</Button>
          <Button size="sm" variant="secondary" onClick={onGenerate} disabled={!record.reportEligible} title={record.reportBlockedReason}>Generate report</Button>
          {record.latestReportDownloadUrl && <Button size="sm" variant="secondary" onClick={onDownloadLatest}>Latest PDF</Button>}
        </div>
      </div>
      {record.flags?.length ? <div className="mt-4 flex flex-wrap gap-2 border-t border-[var(--border)] pt-4">{record.flags.slice(0, 6).map((flag) => <Badge key={flag} variant="secondary">{flag}</Badge>)}</div> : null}
    </article>
  );
}

export function CaseStat({ label, value }: { label: string; value: string | number }) {
  return (
    <div className="min-w-0 rounded-xl border border-[var(--border)] bg-[var(--surface-muted)] p-3">
      <div className="text-[11px] font-bold uppercase tracking-[0.1em] text-muted">{label}</div>
      <div className="mt-1 truncate text-sm font-bold text-strong" title={String(value)}>{value}</div>
    </div>
  );
}

export function CaseDetailPage() {
  const { t, caseRecords, activeUpload, addCaseNote, setActiveCaseId, setActiveUpload } = useNetra();
  const navigate = useNavigate();
  const { routeRef = "" } = useParams();
  const [workspace, setWorkspace] = useState<CaseWorkspaceRecord | null>(null);
  const [record, setRecord] = useState<CaseRecord | null>(caseRecords.find((caseRecord) => caseRecord.routeRef === routeRef) ?? null);
  const [summary, setSummary] = useState<DashboardSummary | null>(null);
  const [charts, setCharts] = useState<CaseChartsRecord | null>(null);
  const [alerts, setAlerts] = useState<AlertRecord[]>([]);
  const [anomalies, setAnomalies] = useState<AnomalyRecord[]>([]);
  const [packets, setPackets] = useState<PacketRecord[]>([]);
  const [sessions, setSessions] = useState<SessionRecord[]>([]);
  const [decodedProtocols, setDecodedProtocols] = useState<DecodedProtocolRecord[]>([]);
  const [payloadFindings, setPayloadFindings] = useState<PayloadFinding[]>([]);
  const [networkFlows, setNetworkFlows] = useState<NetworkFlow[]>([]);
  const [reports, setReports] = useState<ReportRecord[]>([]);
  const [ledger, setLedger] = useState<{ verification?: { verified: boolean; eventCount: number; latestHash: string }; results?: { id: string; timestamp: string; actor: string; action: string; eventHash: string; previousHash: string }[] }>({});
  const [activeTab, setActiveTab] = useState("overview");
  const [note, setNote] = useState("");
  const [flagInput, setFlagInput] = useState("");
  const [linkTarget, setLinkTarget] = useState("");
  const [linkRelation, setLinkRelation] = useState("manual_link");
  const [workspaceLoading, setWorkspaceLoading] = useState(true);
  const [workspaceError, setWorkspaceError] = useState("");
  const statusInFlightRef = useRef(false);
  const finalRefreshRef = useRef("");

  const applyWorkspace = useCallback((payload: CaseWorkspaceRecord) => {
    const data = payload.workspace;
    setWorkspace(payload);
    setRecord(data.case);
    setSummary(data.summary);
    setCharts(data.charts);
    setAlerts(data.suspiciousActivity.alerts ?? []);
    setAnomalies(data.suspiciousActivity.anomalies ?? []);
    setPackets(data.trafficEvidence.packetsPreview ?? []);
    setSessions(data.trafficEvidence.sessionsPreview ?? []);
    setDecodedProtocols(data.trafficEvidence.protocols ?? []);
    setPayloadFindings(data.trafficEvidence.payloadClues ?? []);
    setNetworkFlows(graphEdgesToFlows(data.trafficEvidence.communicationMap ?? {}));
    setReports(data.reports.items ?? []);
    setLedger({ verification: data.custody.verification, results: data.custody.eventsPreview ?? [] });
  }, []);

  const refreshWorkspace = useCallback(async (force = true) => {
    if (!routeRef) return;
    const payload = await apiWorkspace(routeRef, force);
    applyWorkspace(payload);
    setActiveCaseId(payload.caseId);
    setWorkspaceLoading(false);
    setWorkspaceError("");
  }, [applyWorkspace, routeRef, setActiveCaseId]);

  useEffect(() => {
    if (!routeRef) return;
    let cancelled = false;
    setWorkspaceLoading(true);
    apiWorkspace(routeRef, true)
      .then((payload) => {
        if (!cancelled) {
          applyWorkspace(payload);
          setActiveCaseId(payload.caseId);
          setWorkspaceLoading(false);
          setWorkspaceError("");
        }
      })
      .catch((error) => {
        if (!cancelled) {
          setWorkspaceLoading(false);
          setWorkspaceError(error instanceof Error ? error.message : "The case workspace could not be loaded.");
        }
      });
    return () => {
      cancelled = true;
    };
  }, [applyWorkspace, routeRef, setActiveCaseId]);

  const clientUpload = activeUpload?.routeRef === routeRef ? activeUpload : null;
  const serverAnalysis = workspace?.analysisStatus ?? record?.analysisStatus;
  const clientTransferActive = Boolean(clientUpload && ["accepted", "uploading", "finalizing"].includes(clientUpload.state));
  const analysisState: AnalysisStatus["state"] = clientTransferActive && clientUpload ? clientUpload.state : serverAnalysis?.state ?? clientUpload?.state ?? "no-evidence";
  const analysisProgress = clientTransferActive && clientUpload ? clientUpload.progress : serverAnalysis?.progress ?? clientUpload?.progress ?? 0;
  const analysisStep = clientTransferActive && clientUpload ? clientUpload.step : serverAnalysis?.step ?? clientUpload?.step ?? "waiting_for_evidence";
  const analysisError = serverAnalysis?.error ?? clientUpload?.error ?? workspaceError;
  const analysisBusy = ["accepted", "uploading", "finalizing", "queued", "running"].includes(analysisState);
  const reportEligible = analysisState === "completed" && Boolean(workspace?.reportEligible ?? record?.reportEligible);
  const reportBlockedReason = workspace?.reportBlockedReason ?? record?.reportBlockedReason ?? "Report generation becomes available after analysis completes.";

  const refreshWorkspaceStatus = useCallback(async () => {
    if (!routeRef || statusInFlightRef.current) return;
    statusInFlightRef.current = true;
    try {
      const payload = await apiGet<CaseWorkspaceStatusRecord>(`/workspaces/${routeRef}/status`);
      setWorkspace((current) => current ? {
        ...current,
        analysisStatus: payload.analysisStatus,
        reportEligible: payload.reportEligible,
        reportBlockedReason: payload.reportBlockedReason,
        workspace: {
          ...current.workspace,
          case: {
            ...current.workspace.case,
            status: payload.caseStatus,
            reportStatus: payload.reportStatus,
            analysisStatus: payload.analysisStatus,
            reportEligible: payload.reportEligible,
            reportBlockedReason: payload.reportBlockedReason,
            updatedAt: payload.updatedAt,
          },
        },
      } : current);
      setRecord((current) => current ? {
        ...current,
        status: payload.caseStatus,
        reportStatus: payload.reportStatus,
        analysisStatus: payload.analysisStatus,
        reportEligible: payload.reportEligible,
        reportBlockedReason: payload.reportBlockedReason,
        updatedAt: payload.updatedAt,
      } : current);
      setActiveUpload((current) => {
        if (!current || current.routeRef !== routeRef || ["uploading", "finalizing"].includes(current.state)) return current;
        return {
          ...current,
          state: payload.analysisStatus.state,
          progress: payload.analysisStatus.progress,
          step: payload.analysisStatus.step,
          steps: payload.analysisStatus.steps,
          error: payload.analysisStatus.error,
        };
      });
    } finally {
      statusInFlightRef.current = false;
    }
  }, [routeRef, setActiveUpload]);

  useEffect(() => {
    if (!routeRef || !analysisBusy || clientTransferActive) return undefined;
    void refreshWorkspaceStatus().catch(() => undefined);
    const timer = window.setInterval(() => void refreshWorkspaceStatus().catch(() => undefined), 2000);
    return () => window.clearInterval(timer);
  }, [analysisBusy, clientTransferActive, refreshWorkspaceStatus, routeRef]);

  useEffect(() => {
    if (!routeRef || clientUpload?.state !== "completed") return;
    const refreshKey = `${clientUpload.jobId || clientUpload.uploadSessionId || routeRef}:completed`;
    if (finalRefreshRef.current === refreshKey) return;
    finalRefreshRef.current = refreshKey;
    refreshWorkspace(true)
      .then(() => {
        setActiveUpload((current) => current?.routeRef === routeRef ? null : current);
      })
      .catch(() => {
        finalRefreshRef.current = "";
      });
  }, [clientUpload?.jobId, clientUpload?.state, clientUpload?.uploadSessionId, refreshWorkspace, routeRef, setActiveUpload]);

  const availableTabs = useMemo(
    () => workspace?.workspace.availableTabs ?? { overview: true, suspiciousActivity: true, trafficEvidence: true, timeline: true, reports: true, custody: true },
    [workspace?.workspace.availableTabs],
  );
  const displayedTabs = useMemo(
    () => analysisBusy
      ? { overview: true, suspiciousActivity: true, trafficEvidence: true, timeline: true, reports: true, custody: true }
      : availableTabs,
    [analysisBusy, availableTabs],
  );
  const dataMessages = workspace?.workspace.dataMessages ?? {};
  const tabVisible = useCallback((value: string) => {
    if (value === "activity") return displayedTabs.suspiciousActivity;
    if (value === "evidence") return displayedTabs.trafficEvidence;
    if (value === "timeline") return displayedTabs.timeline;
    if (value === "reports") return displayedTabs.reports;
    if (value === "custody") return displayedTabs.custody;
    return true;
  }, [displayedTabs]);

  useEffect(() => {
    if (!tabVisible(activeTab)) setActiveTab("overview");
  }, [activeTab, tabVisible]);

  async function generateCaseReport() {
    if (!record) return;
    if (!reportEligible) {
      toast.error(reportBlockedReason);
      return;
    }
    const response = await fetch(`${API_BASE}/reports/${record.id}/generate-pdf`, { method: "POST", headers: netraHeaders({ "Content-Type": "application/json" }), body: JSON.stringify({ language: "English", format: "pdf" }) });
    const payload = await response.json();
    if (!response.ok) {
      toast.error(payload.error ?? "PDF report generation failed");
      return;
    }
    await downloadApiFile(payload.downloadUrl, payload.filename ?? `${record.id}-report.pdf`);
    await refreshWorkspace().catch(() => undefined);
    toast.success(`PDF report downloaded: ${payload.filename}`);
  }

  async function addFlag() {
    if (!record || !CASE_FLAG_OPTIONS.includes(flagInput as (typeof CASE_FLAG_OPTIONS)[number])) return;
    const response = await fetch(`${API_BASE}/cases/${record.id}/flags`, { method: "POST", headers: netraHeaders({ "Content-Type": "application/json" }), body: JSON.stringify({ flags: [flagInput.trim()] }) });
    const payload = await response.json();
    if (!response.ok) {
      toast.error(payload.error ?? "Flag could not be added");
      return;
    }
    setRecord({ ...record, flags: payload.flags });
    setWorkspace((current) => current ? { ...current, workspace: { ...current.workspace, case: { ...current.workspace.case, flags: payload.flags } } } : current);
    setFlagInput("");
  }

  async function linkCase() {
    if (!record || !linkTarget.trim()) return;
    const response = await fetch(`${API_BASE}/cases/${record.id}/links`, { method: "POST", headers: netraHeaders({ "Content-Type": "application/json" }), body: JSON.stringify({ targetCaseId: linkTarget.trim(), relationType: linkRelation }) });
    const payload = await response.json();
    if (!response.ok) {
      toast.error(payload.error ?? "Related case could not be linked");
      return;
    }
    setRecord({ ...record, linkedCases: [...(record.linkedCases ?? []), payload] });
    setWorkspace((current) => current ? { ...current, workspace: { ...current.workspace, case: { ...current.workspace.case, linkedCases: [...(current.workspace.case.linkedCases ?? []), payload] } } } : current);
    setLinkTarget("");
    toast.success("Related case linked.");
  }

  if (!record) {
    return <PageFrame title={t("caseDetail")} description={t("caseQueueDesc")}><div className="surface rounded-[1.5rem] p-6 text-sm text-muted">{workspaceLoading ? "Loading the secure case workspace…" : workspaceError || "The case workspace is not available."}</div></PageFrame>;
  }
  const highRiskAlerts = alerts.filter((alert) => ["critical", "high"].includes(alert.severity));
  const chartEmptyText = dataMessages.chart || "No data found in this evidence file.";
  return (
    <PageFrame title={`${t("caseDetail")} - ${record.id}`} description={record.title}>
      <div className="surface rounded-[1.5rem] p-5">
        <div className="flex flex-wrap items-start justify-between gap-4">
          <div>
            <div className="flex flex-wrap gap-2">
              <Badge>{record.status}</Badge>
              <SeverityBadge severity={(summary?.riskLevel ?? record.riskLevel ?? "low") as Severity} />
              {(record.flags ?? []).map((flag) => <Badge key={flag} variant="secondary">{flag}</Badge>)}
            </div>
            <h2 className="mt-3 text-2xl font-black text-strong">{record.id}</h2>
            <p className="mt-1 max-w-3xl text-sm leading-6 text-muted">{record.title}</p>
          </div>
          <div className="flex flex-wrap gap-2">
            <Button onClick={generateCaseReport} disabled={!reportEligible} title={reportBlockedReason}><FileText className="size-4" />Generate report</Button>
            <Button asChild variant="secondary"><Link to={appViewRoute("cases")}>Back to cases</Link></Button>
          </div>
        </div>
        <div className="mt-5 grid gap-3 sm:grid-cols-2 lg:grid-cols-3 2xl:grid-cols-6">
          <MetricTile label="Risk" value={(summary?.riskLevel ?? record.riskLevel ?? "low").toUpperCase()} detail={summary?.topAttackClass ?? record.topAttackClass ?? "Normal Baseline"} />
          <MetricTile label="Packets" value={formatNumber(summary?.packets ?? record.packetCount ?? 0)} />
          <MetricTile label="Sessions" value={formatNumber(summary?.sessions ?? record.sessionCount ?? 0)} />
          <MetricTile label="Alerts" value={formatNumber(alerts.length || record.alertCount || 0)} detail={`${highRiskAlerts.length} high risk`} />
          <MetricTile label="Anomalies" value={formatNumber(anomalies.length)} detail="ML-assisted findings" />
          <MetricTile label="Reports" value={reports.length} detail={record.reportStatus} />
        </div>
      </div>
      <div className="surface rounded-[1.5rem] p-5" aria-live="polite">
        <div className="flex flex-wrap items-start justify-between gap-3">
          <div><div className="text-xs font-bold uppercase tracking-[0.12em] text-muted">Analysis status</div><h2 className="mt-2 text-xl font-black text-strong">{analysisStateLabel(analysisState)}</h2><p className="mt-1 text-sm text-muted">{analysisStep.replaceAll("_", " ")}{clientUpload?.filename ? ` · ${clientUpload.filename}` : ""}</p></div>
          <Badge>{analysisProgress}%</Badge>
        </div>
        <Progress className="mt-4" value={analysisProgress} />
        {clientUpload?.state === "uploading" && <p className="mt-3 text-xs text-muted">{formatBytes(clientUpload.bytesUploaded)} of {formatBytes(clientUpload.sizeBytes)} · {clientUpload.speedBytesPerSecond > 0 ? `${formatBytes(clientUpload.speedBytesPerSecond)}/s` : "measuring speed"}</p>}
        {!clientUpload && analysisState === "uploading" && <Alert>Upload interrupted in this browser. Return to Start Investigation and reselect the same file to resume the verified upload session.</Alert>}
        {analysisError && ["failed", "canceled", "expired"].includes(analysisState) && <Alert>{analysisError}</Alert>}
        {["failed", "canceled", "expired"].includes(analysisState) && <Button className="mt-3" variant="secondary" onClick={() => navigate(appViewRoute("upload"))}>Retry evidence intake</Button>}
        {!reportEligible && <p className="mt-3 text-xs text-muted">{reportBlockedReason}</p>}
      </div>
      {analysisBusy && <Alert>Analysis is still running. Case metadata is available now; evidence, findings, and report actions will unlock as processing completes.</Alert>}
      <Tabs value={activeTab} onValueChange={setActiveTab} className="flex flex-col gap-4">
        <TabsList className="max-w-full overflow-x-auto">
          <TabsTrigger value="overview">Overview</TabsTrigger>
          {displayedTabs.suspiciousActivity && <TabsTrigger value="activity">Suspicious activity</TabsTrigger>}
          {displayedTabs.trafficEvidence && <TabsTrigger value="evidence">Traffic evidence</TabsTrigger>}
          {displayedTabs.timeline && <TabsTrigger value="timeline">Timeline</TabsTrigger>}
          {displayedTabs.reports && <TabsTrigger value="reports">Reports</TabsTrigger>}
          {displayedTabs.custody && <TabsTrigger value="custody">Custody</TabsTrigger>}
        </TabsList>
        {analysisBusy && activeTab !== "overview" && <Alert>Analysis in progress. This section will refresh automatically when its case data becomes available.</Alert>}
        <TabsContent value="overview">
          <div className="grid gap-4 lg:grid-cols-[0.9fr_1.1fr]">
            <div className="surface rounded-[1.5rem] p-5">
              <h2 className="text-xl font-black text-strong">{t("caseSummary")}</h2>
              <div className="mt-4 grid gap-2">
                <MetadataRow label={t("caseNumber")} value={record.id} />
                <MetadataRow label={t("investigator")} value={record.investigator || "-"} />
                <MetadataRow label={t("department")} value={record.department || "-"} />
                <MetadataRow label={t("sourceLocation")} value={record.sourceLocation || "-"} />
                <MetadataRow label="Priority" value={record.priority || "Standard"} />
                <MetadataRow label="Evidence" value={record.evidenceFilename || clientUpload?.filename || "Waiting for evidence"} />
                <MetadataRow label="Remarks" value={record.remarks || "-"} />
                <MetadataRow label="Opened" value={record.openedAt ? new Date(record.openedAt).toLocaleString() : record.createdAt} />
                <MetadataRow label="Latest update" value={record.updatedAt ? new Date(record.updatedAt).toLocaleString() : record.createdAt} />
                <MetadataRow label="Closed" value={record.closedAt ? new Date(record.closedAt).toLocaleString() : "Open"} />
              </div>
              <div className="mt-5 grid gap-3">
                <div className="flex gap-2">
                  <SelectField label="Approved case flag" value={flagInput || "Select flag"} values={["Select flag", ...CASE_FLAG_OPTIONS]} onChange={(value) => setFlagInput(value === "Select flag" ? "" : value)} />
                  <Button type="button" onClick={addFlag}>Add</Button>
                </div>
                <div className="flex flex-wrap gap-2">{(record.flags ?? []).map((flag) => <Badge key={flag} variant="secondary">{flag}</Badge>)}</div>
              </div>
            </div>
            <div className="grid gap-4 md:grid-cols-2">
              <ChartPanel title="Alert severity">{charts?.severity?.length ? <MiniBarList rows={charts.severity} /> : <p className="text-sm text-muted">{chartEmptyText}</p>}</ChartPanel>
              <ChartPanel title="Attack classes">{charts?.attackClasses?.length ? <MiniBarList rows={charts.attackClasses} /> : <p className="text-sm text-muted">{chartEmptyText}</p>}</ChartPanel>
              <ChartPanel title="Protocols">{charts?.protocols?.length ? <MiniBarList rows={charts.protocols} /> : <p className="text-sm text-muted">{chartEmptyText}</p>}</ChartPanel>
              <ChartPanel title="Top sources">{charts?.topSources?.length ? <MiniBarList rows={charts.topSources} /> : <p className="text-sm text-muted">{chartEmptyText}</p>}</ChartPanel>
              <ChartPanel title="Top destinations">{charts?.topDestinations?.length ? <MiniBarList rows={charts.topDestinations} /> : <p className="text-sm text-muted">{chartEmptyText}</p>}</ChartPanel>
              <ChartPanel title="Activity timeline">{charts?.timeline?.length ? <ResponsiveContainer width="100%" height={150}><AreaChart data={charts.timeline}><CartesianGrid stroke="var(--border)" strokeDasharray="3 3" vertical={false} /><XAxis dataKey="time" fontSize={11} stroke="var(--muted)" /><YAxis fontSize={11} stroke="var(--muted)" /><ChartTooltip /><Area dataKey="alerts" type="monotone" stroke="var(--accent)" fill="var(--accent-soft)" /></AreaChart></ResponsiveContainer> : <p className="text-sm text-muted">{dataMessages.timeline || chartEmptyText}</p>}</ChartPanel>
            </div>
          </div>
          {charts?.dataQuality && <div className="mt-4 rounded-xl border border-[var(--border)] bg-[var(--surface-muted)] px-4 py-3 text-xs font-semibold uppercase tracking-[0.08em] text-muted">Data quality: {charts.dataQuality}</div>}
          <div className="surface mt-4 rounded-[1.5rem] p-5">
            <h2 className="text-xl font-black text-strong">Related cases</h2>
            <div className="mt-4 grid gap-3 md:grid-cols-[1fr_220px_auto]">
              <Input value={linkTarget} onChange={(event) => setLinkTarget(event.target.value)} placeholder="Case number to link" />
              <Select value={linkRelation} onValueChange={setLinkRelation}>
                <SelectTrigger><SelectValue /></SelectTrigger>
                <SelectContent>{["manual_link", "similar_traffic", "same_source_ip", "same_target", "same_suspect", "same_incident"].map((item) => <SelectItem key={item} value={item}>{item}</SelectItem>)}</SelectContent>
              </Select>
              <Button onClick={linkCase}>Link case</Button>
            </div>
            <div className="mt-4 grid gap-2">{(record.linkedCases ?? []).map((link) => <div key={link.id} className="rounded-xl border border-[var(--border)] bg-[var(--surface-muted)] p-3 text-sm"><b>{link.caseId}</b> · {link.relationType}<div className="text-muted">{link.caseTitle}</div></div>)}</div>
          </div>
        </TabsContent>
        {displayedTabs.suspiciousActivity && <TabsContent value="activity">
          <AlertTable alerts={alerts} />
          <div className="mt-4"><AnomalyReviewPanel anomalies={anomalies} timeline={charts?.timeline ?? []} /></div>
        </TabsContent>}
        {displayedTabs.trafficEvidence && <TabsContent value="evidence">
          <div className="mb-4 rounded-xl border border-[var(--border)] bg-[var(--surface-muted)] px-4 py-3 text-sm text-muted">
            Showing the stored case snapshot preview. Use the advanced packet explorer only when you need deeper pagination.
          </div>
          <Tabs defaultValue="packets" className="flex flex-col gap-4">
            <TabsList className="w-fit flex-wrap"><TabsTrigger value="packets">Packets</TabsTrigger><TabsTrigger value="sessions">Sessions</TabsTrigger><TabsTrigger value="protocols">Protocols</TabsTrigger><TabsTrigger value="payloads">Payloads</TabsTrigger><TabsTrigger value="map">Communication map</TabsTrigger></TabsList>
            <TabsContent value="packets"><PacketEvidenceTable packets={packets} /></TabsContent>
            <TabsContent value="sessions"><SessionEvidenceTable sessions={sessions} /></TabsContent>
            <TabsContent value="protocols"><ProtocolEvidenceTable protocols={decodedProtocols} /></TabsContent>
            <TabsContent value="payloads"><PayloadEvidenceTable findings={payloadFindings} /></TabsContent>
            <TabsContent value="map"><FlowEvidenceTable flows={networkFlows} /></TabsContent>
          </Tabs>
        </TabsContent>}
        {displayedTabs.timeline && <TabsContent value="timeline">
          <div className="surface rounded-[1.5rem] p-5">
            <h2 className="text-xl font-black text-strong">{t("caseHistory")}</h2>
            <TimelineList record={record} />
            <div className="mt-5">
              <Dialog>
                <DialogTrigger asChild><Button>{t("addNote")}</Button></DialogTrigger>
                <DialogContent aria-describedby={undefined}>
                  <DialogTitle>{t("addNote")}</DialogTitle>
                  <div className="mt-4 flex flex-col gap-4">
                    <Textarea value={note} onChange={(event) => setNote(event.target.value)} />
                    <Button onClick={() => { if (note.trim()) { addCaseNote(record.id, note.trim()); setNote(""); } }}>{t("saveNote")}</Button>
                  </div>
                </DialogContent>
              </Dialog>
            </div>
          </div>
        </TabsContent>}
        {displayedTabs.reports && <TabsContent value="reports">
          <div className="surface rounded-[1.5rem] p-5">
            <div className="flex flex-wrap items-center justify-between gap-3"><h2 className="text-xl font-black text-strong">Case reports</h2><Button onClick={generateCaseReport} disabled={!reportEligible} title={reportBlockedReason}>Generate PDF report</Button></div>
            <div className="mt-4 overflow-x-auto">
              <table className="w-full min-w-[760px] text-left text-sm">
                <thead className="border-b border-[var(--border)] text-xs uppercase text-muted"><tr><th className="py-3">Report</th><th>Generated</th><th>Language</th><th>Status</th><th>Action</th></tr></thead>
                <tbody>{reports.map((report) => <tr key={report.id} className="border-b border-[var(--border)]"><td className="py-3 font-bold text-strong">{report.filename}</td><td>{new Date(report.generatedAt).toLocaleString()}</td><td>{report.language}</td><td><Badge>{report.status}</Badge></td><td><Button size="sm" variant="secondary" onClick={() => downloadApiFile(report.downloadUrl, report.filename)}>Download</Button></td></tr>)}</tbody>
              </table>
              {!reports.length && <div className="py-8 text-center text-sm text-muted">No reports generated for this case yet.</div>}
            </div>
          </div>
        </TabsContent>}
        {displayedTabs.custody && <TabsContent value="custody">
          <div className="grid gap-5 lg:grid-cols-3">
            <CustodyMetric label="Ledger" value={ledger.verification?.verified ? "Verified" : "Pending"} />
            <CustodyMetric label="Events" value={ledger.verification?.eventCount ?? 0} />
            <CustodyMetric label="Latest hash" value={ledger.verification?.latestHash ?? "-"} mono compact />
          </div>
          <div className="mt-6">
            <CustodyLedgerTable rows={ledger.results ?? []} />
          </div>
        </TabsContent>}
      </Tabs>
    </PageFrame>
  );
}
