import { AnimatePresence, motion } from "framer-motion";
import { API_BASE } from "../ConsoleCore";
import { apiErrorMessage, findingStatusPath } from "../../../lib/analysisApi";
import { Badge, Button, Input, Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "../../../components/ui/primitives";
import { caseWorkspaceRoute } from "../ConsoleCore";
import { cn } from "../../../lib/utils";
import { Download, History, Languages } from "lucide-react";
import { downloadApiFile } from "../ConsoleCore";
import { Link, useLocation, useParams } from "react-router-dom";
import { netraHeaders } from "../ConsoleCore";
import { toast } from "sonner";
import { type AlertRecord, type AttackClass, type CaseRecord, type DetectionRuleMatch, type IntegrationRecord, type Language, type Severity } from "../../../lib/types";
import { type ReactNode, useEffect, useRef } from "react";
import { useNetra } from "../ConsoleCore";

export function ReportPage() {
  const { t, language, setLanguage, caseRecords, alertRecords, anomalies, complianceRecords, decodedProtocols, detectionMatches, evidence, intakeForm, packets, payloadFindings, sessions, summary, zeek } = useNetra();
  const { routeRef = "" } = useParams();
  const record = caseRecords.find((caseRecord) => caseRecord.routeRef === routeRef);
  const recommendedActions = Array.from(new Set(alertRecords.map((alert) => alert.recommendedAction).filter(Boolean))).slice(0, 3);
  if (!record) {
    return <PageFrame title={t("reportTitle")} description={t("reportDesc")}><div className="surface rounded-[1.5rem] p-6 text-sm text-muted">Upload a PCAP to generate a real report.</div></PageFrame>;
  }
  async function exportPdfReport() {
    if (!record) return;
    if (!record.reportEligible) {
      toast.error(record.reportBlockedReason ?? "Report generation becomes available after analysis completes.");
      return;
    }
    const response = await fetch(`${API_BASE}/reports/${record.id}/generate`, { method: "POST", headers: netraHeaders({ "Content-Type": "application/json" }), body: JSON.stringify({ language, format: "pdf" }) });
    const payload = await response.json();
    if (!response.ok) {
      toast.error(payload.error ?? "PDF report generation failed");
      return;
    }
    await downloadApiFile(payload.downloadUrl, payload.filename ?? `${record.id}-report.pdf`);
    toast.success(`PDF report downloaded: ${payload.filename}`);
  }
  return (
    <PageFrame title={t("reportTitle")} description={`${record.id} - ${record.createdAt}`}>
      <div className="no-print glass-panel flex flex-wrap items-center gap-3 rounded-[1.5rem] p-3">
        <Select value={language} onValueChange={(value) => setLanguage(value as Language)}>
          <SelectTrigger><Languages className="size-4" /><SelectValue /></SelectTrigger>
          <SelectContent><SelectItem value="English">English</SelectItem><SelectItem value="Hindi">Hindi</SelectItem><SelectItem value="Gujarati">Gujarati</SelectItem></SelectContent>
        </Select>
        <Button variant="secondary" onClick={exportPdfReport} disabled={!record.reportEligible} title={record.reportBlockedReason}><Download className="size-4" />Download PDF report</Button>
        <Button asChild variant="secondary"><Link to={caseWorkspaceRoute(record.routeRef)}>{t("backToCase")}</Link></Button>
      </div>
      <div className="print-surface report-print surface-solid mx-auto flex max-w-5xl flex-col gap-6 rounded-[1.5rem] p-6">
        <div className="border-b border-[var(--border)] pb-5">
          <Badge>{t("hashVerification")}</Badge>
          <h2 className="mt-3 text-3xl font-black text-strong">{t("reportTitle")}</h2>
          <p className="mt-1 text-sm text-muted">{record.id} - {intakeForm.department}</p>
        </div>
        <ReportSection title={t("caseSummary")}><p className="leading-7 text-muted">Netra reviewed real PCAP evidence and classified the top behavior as {summary.topAttackClass} with {summary.riskLevel} risk. The report links packet/session evidence, Zeek logs, anomaly explanations, and chain-of-custody metadata.</p></ReportSection>
        <div className="grid gap-4 md:grid-cols-2">
          <ReportSection title={t("evidenceMetadata")}>
            <MetadataRow label={t("filename")} value={evidence?.filename ?? "No PCAP uploaded"} />
            <MetadataRow label="SHA-256" value={evidence?.sha256 ?? "-"} />
            <MetadataRow label={t("investigator")} value={intakeForm.investigator} />
            <MetadataRow label={t("evidenceType")} value={intakeForm.evidenceType} />
          </ReportSection>
          <ReportSection title={t("attackClassification")}>
            <div className="flex flex-wrap gap-2">{(summary.detectedAttackClasses?.length ? summary.detectedAttackClasses : [summary.topAttackClass]).map((item) => <AttackBadge key={item} attackClass={item as AttackClass} />)}</div>
          </ReportSection>
        </div>
        <ReportSection title={t("alertSummary")}><AlertTable alerts={alertRecords.slice(0, 5)} compact /></ReportSection>
        <ReportSection title="Zeek Log Summary"><p className="text-sm leading-7 text-muted">Status: {zeek?.status ?? "not-run"} | Logs: {(zeek?.logs ?? []).join(", ") || "none"} | Connections: {zeek?.summary?.connections ?? 0} | SSH: {zeek?.summary?.sshSessions ?? 0} | DNS: {zeek?.summary?.dnsQueries ?? 0}</p></ReportSection>
        <div className="grid gap-4 md:grid-cols-2">
          <ReportSection title="Packet Capture Summary"><p className="text-sm leading-7 text-muted">{packets.length} representative packets and {sessions.length} sessions are linked to this case.</p></ReportSection>
          <ReportSection title="Protocol Decoding Summary"><p className="text-sm leading-7 text-muted">{decodedProtocols.length} protocols represented with DNS, HTTP, TLS metadata, SMTP, FTP, ICMP, TCP, and UDP readiness.</p></ReportSection>
          <ReportSection title="Payload Inspection Summary"><p className="text-sm leading-7 text-muted">{payloadFindings.length} payload findings were generated from the uploaded capture.</p></ReportSection>
          <ReportSection title="Session Reconstruction Summary"><p className="text-sm leading-7 text-muted">{sessions.length} reconstructed sessions connect packet timelines with alerts and case evidence.</p></ReportSection>
          <ReportSection title="Signature Detection Summary"><p className="text-sm leading-7 text-muted">{detectionMatches.length} signature matches were generated from the uploaded capture.</p></ReportSection>
          <ReportSection title="AI Anomaly Summary"><p className="text-sm leading-7 text-muted">{anomalies.length} anomaly records compare baseline traffic against observed suspicious behaviour.</p></ReportSection>
          <ReportSection title="Tool Status"><div className="flex flex-wrap gap-2">{Object.entries(summary.toolStatus ?? {}).map(([name, ok]) => <Badge key={name}>{name}: {ok ? "ready" : "missing"}</Badge>)}</div></ReportSection>
          <ReportSection title="Compliance Notes"><div className="grid gap-2">{complianceRecords.length ? complianceRecords.slice(0, 4).map((item) => <p key={item.item} className="text-sm text-muted">{item.item}: {item.status}</p>) : <p className="text-sm text-muted">Compliance rows will appear after real custody and audit activity.</p>}</div></ReportSection>
        </div>
        <ReportSection title={t("timeline")}><TimelineList record={record} /></ReportSection>
        <ReportSection title={t("investigatorNotes")}><div className="grid gap-3">{record.notes.map((note) => <p key={note} className="rounded-xl bg-[var(--surface-muted)] p-3 text-sm">{note}</p>)}</div></ReportSection>
        <ReportSection title={t("nextSteps")}><ol className="list-decimal space-y-2 pl-5 text-sm leading-6 text-muted">{(recommendedActions.length ? recommendedActions : ["Review the linked packet and session evidence before closing the case."]).map((action) => <li key={action}>{action}</li>)}</ol></ReportSection>
      </div>
    </PageFrame>
  );
}

export function MetricTile({ label, value, detail }: { label: string; value: string | number; detail?: string }) {
  return (
    <div className="surface min-w-0 rounded-[1.25rem] p-4">
      <div className="text-xs font-bold uppercase tracking-[0.12em] text-muted">{label}</div>
      <div className="mt-2 min-w-0 break-words text-2xl font-black leading-tight text-strong">{value}</div>
      {detail && <p className="mt-2 text-xs leading-5 text-muted">{detail}</p>}
    </div>
  );
}

export function CustodyMetric({ label, value, mono = false, compact = false }: { label: string; value: string | number; mono?: boolean; compact?: boolean }) {
  return (
    <div className="surface min-w-0 rounded-[1.25rem] p-5">
      <div className="text-xs font-bold uppercase tracking-[0.14em] text-muted">{label}</div>
      <div
        className={cn(
          "mt-3 min-h-[2.5rem] text-2xl font-black leading-tight text-strong",
          mono && "font-mono",
          compact ? "break-all text-base leading-7 md:text-lg" : "truncate",
        )}
        title={String(value)}
      >
        {value}
      </div>
    </div>
  );
}

export function CodeBlock({ title, value }: { title: string; value: string }) {
  return (
    <div className="mt-4 rounded-xl border border-[var(--border)] bg-[rgba(0,0,0,0.18)] p-4">
      <div className="mb-2 text-xs font-bold uppercase tracking-[0.14em] text-muted">{title}</div>
      <pre className="whitespace-pre-wrap break-words font-mono text-xs leading-6 text-strong">{value}</pre>
    </div>
  );
}

export function DetectionTable({ category }: { category?: string }) {
  const { activeCaseId, caseRecords, detectionMatches, reloadAnalysis } = useNetra();
  const rows = category ? detectionMatches.filter((item) => item.category === category || item.ruleName.includes(category)) : detectionMatches;
  const activeCase = caseRecords.find((record) => record.id === activeCaseId);
  const scope = activeCase?.routeRef && activeCase.analysisStatus.jobId
    ? { routeRef: activeCase.routeRef, jobId: activeCase.analysisStatus.jobId }
    : null;
  async function updateStatus(item: DetectionRuleMatch, status: "reviewing" | "confirmed" | "dismissed") {
    if (!scope) {
      toast.error("Analysis is not ready for finding review.");
      return;
    }
    const response = await fetch(`${API_BASE}${findingStatusPath(scope, "detections", item.id)}`, { method: "PATCH", headers: netraHeaders({ "Content-Type": "application/json" }), body: JSON.stringify({ status }) });
    const payload = await response.json();
    if (!response.ok) {
      toast.error(apiErrorMessage(payload, "Status update failed"));
      return;
    }
    toast.success(`Finding marked ${status}`);
    await reloadAnalysis();
  }
  return (
    <div className="surface-solid overflow-hidden rounded-[1.5rem]">
      <div className="overflow-x-auto p-4">
        <table className="w-full min-w-[780px] text-left text-sm">
              <thead className="border-b border-[var(--border)] text-xs uppercase text-muted"><tr><th className="py-3">Rule ID</th><th>Rule name</th><th>Class</th><th>Matched entity</th><th>Evidence</th><th>Confidence</th><th>Status</th></tr></thead>
          <tbody>{rows.map((item) => <tr key={item.id} className="border-b border-[var(--border)] align-top"><td className="py-3 font-mono text-xs">{item.ruleId ?? item.id}</td><td className="min-w-60 font-bold text-strong">{item.ruleName}<p className="mt-1 text-xs font-normal leading-5 text-muted">{item.explanation}</p><p className="mt-1 text-xs font-normal leading-5 text-muted">{item.recommendedAction}</p></td><td><Badge>{item.attackClass ?? item.category}</Badge></td><td>{item.matchedEntity}</td><td className="max-w-52 break-words text-xs">{[...(item.evidencePacketIds ?? []), ...(item.evidenceSessionIds ?? [])].slice(0, 4).join(", ") || "-"}</td><td>{item.confidence}%</td><td><div className="flex flex-col gap-2"><Badge variant="secondary">{item.status}</Badge><div className="flex flex-wrap gap-1"><Button size="sm" variant="secondary" disabled={!scope} onClick={() => updateStatus(item, "reviewing")}>Review</Button><Button size="sm" disabled={!scope} onClick={() => updateStatus(item, "confirmed")}>Confirm</Button><Button size="sm" variant="secondary" disabled={!scope} onClick={() => updateStatus(item, "dismissed")}>Dismiss</Button></div>{!scope ? <span className="text-xs text-muted">Analysis is not ready.</span> : null}</div></td></tr>)}</tbody>
        </table>
      </div>
    </div>
  );
}

export function ExportHistoryTable() {
  const { exportRecords } = useNetra();
  const rows = exportRecords;
  return (
    <div className="surface-solid overflow-hidden rounded-[1.5rem]">
      <div className="overflow-x-auto p-4">
        <table className="w-full min-w-[820px] text-left text-sm">
          <thead className="border-b border-[var(--border)] text-xs uppercase text-muted"><tr><th className="py-3">Export ID</th><th>Type</th><th>Case</th><th>Requested by</th><th>Timestamp</th><th>Hash</th><th>Status</th></tr></thead>
          <tbody>{rows.length ? rows.map((item) => <tr key={item.id} className="border-b border-[var(--border)]"><td className="py-3 font-bold text-strong">{item.id}</td><td>{item.type}</td><td>{item.caseId}</td><td>{item.requestedBy}</td><td>{item.timestamp}</td><td className="font-mono text-xs">{item.hash}</td><td><Badge>{item.status}</Badge></td></tr>) : <tr><td className="py-5 text-muted" colSpan={7}>No exports yet. Generate a report, JSON evidence bundle, or alert CSV from a real case.</td></tr>}</tbody>
        </table>
      </div>
    </div>
  );
}

export function IntegrationTable({ rows = [] }: { rows?: IntegrationRecord[] }) {
  return (
    <div className="surface-solid overflow-hidden rounded-[1.5rem]">
      <div className="overflow-x-auto p-4">
        <table className="w-full min-w-[760px] text-left text-sm">
          <thead className="border-b border-[var(--border)] text-xs uppercase text-muted"><tr><th className="py-3">System</th><th>Status</th><th>Last sync</th><th>Linked cases</th><th>API mode</th></tr></thead>
          <tbody>{rows.length ? rows.map((item) => <tr key={item.system} className="border-b border-[var(--border)]"><td className="py-3 font-bold text-strong">{item.system}</td><td><Badge>{item.status}</Badge></td><td>{item.lastSync}</td><td>{item.linkedCases}</td><td>{item.apiMode}</td></tr>) : <tr><td className="py-5 text-muted" colSpan={5}>No integrations configured.</td></tr>}</tbody>
        </table>
      </div>
    </div>
  );
}

export function DeliveryTable({ rows }: { rows: { id: string; timestamp: string; caseId: string; type: string; result: string; response: string }[] }) {
  return (
    <div className="surface-solid overflow-hidden rounded-[1.5rem]">
      <div className="p-5 pb-0"><h3 className="text-lg font-black text-strong">Delivery history</h3></div>
      <div className="overflow-x-auto p-4">
        <table className="w-full min-w-[760px] text-left text-sm">
          <thead className="border-b border-[var(--border)] text-xs uppercase text-muted"><tr><th className="py-3">Time</th><th>Case</th><th>Type</th><th>Result</th><th>Response</th></tr></thead>
          <tbody>{(rows.length ? rows : [{ id: "empty", timestamp: "-", caseId: "-", type: "-", result: "No deliveries yet", response: "Run Test or Send Alerts" }]).map((item) => <tr key={item.id} className="border-b border-[var(--border)]"><td className="py-3">{item.timestamp}</td><td>{item.caseId}</td><td>{item.type}</td><td><Badge>{item.result}</Badge></td><td>{item.response}</td></tr>)}</tbody>
        </table>
      </div>
    </div>
  );
}

export function CustodyLedgerTable({ rows }: { rows: { id: string; timestamp: string; actor: string; action: string; previousHash: string; eventHash: string }[] }) {
  return (
    <div className="surface-solid overflow-hidden rounded-[1.5rem]">
      <div className="p-6 pb-2"><h3 className="text-lg font-black text-strong">Chain of custody</h3></div>
      <div className="overflow-x-auto px-6 pb-6">
        <table className="w-full min-w-[860px] table-fixed text-left text-sm">
          <thead className="border-b border-[var(--border)] text-xs uppercase text-muted"><tr><th className="py-3">Time</th><th>Actor</th><th>Action</th><th>Previous hash</th><th>Event hash</th></tr></thead>
          <tbody>{(rows.length ? rows : []).map((item) => <tr key={item.id} className="border-b border-[var(--border)]"><td className="py-3 pr-4 text-xs text-muted">{new Date(item.timestamp).toLocaleString()}</td><td className="pr-4">{item.actor}</td><td className="pr-4">{item.action}</td><td className="truncate pr-4 font-mono text-xs" title={item.previousHash || "root"}>{item.previousHash || "root"}</td><td className="truncate font-mono text-xs" title={item.eventHash}>{item.eventHash}</td></tr>)}</tbody>
        </table>
        {!rows.length && <div className="py-8 text-center text-sm text-muted">No custody events found for this case yet.</div>}
      </div>
    </div>
  );
}

export function AccessLogTable() {
  const { accessLogRecords } = useNetra();
  const rows = accessLogRecords;
  return (
    <div className="surface-solid overflow-hidden rounded-[1.5rem]">
      <div className="overflow-x-auto p-4">
        <table className="w-full min-w-[760px] text-left text-sm">
          <thead className="border-b border-[var(--border)] text-xs uppercase text-muted"><tr><th className="py-3">Timestamp</th><th>User</th><th>Role</th><th>Action</th><th>Case</th><th>Result</th></tr></thead>
          <tbody>{rows.length ? rows.map((item) => <tr key={`${item.timestamp}-${item.action}-${item.caseId}`} className="border-b border-[var(--border)]"><td className="py-3">{item.timestamp}</td><td className="font-bold text-strong">{item.user}</td><td><Badge>{item.role}</Badge></td><td>{item.action}</td><td>{item.caseId}</td><td><Badge variant="secondary">{item.result}</Badge></td></tr>) : <tr><td className="py-5 text-muted" colSpan={6}>No access log entries yet.</td></tr>}</tbody>
        </table>
      </div>
    </div>
  );
}

export function PageFrame({ title, description, children }: { title: string; description: string; children: ReactNode }) {
  const location = useLocation();
  const headingRef = useRef<HTMLHeadingElement>(null);

  useEffect(() => {
    document.title = `${title} | Netra`;
    headingRef.current?.focus({ preventScroll: true });
  }, [location.pathname, title]);

  return (
    <motion.main id="main-content" initial={{ opacity: 0, y: 12 }} animate={{ opacity: 1, y: 0 }} className="min-w-0 max-w-full overflow-x-hidden flex flex-col gap-5">
      <div>
        <h1 ref={headingRef} tabIndex={-1} className="text-3xl font-black tracking-normal text-strong">{title}</h1>
        <p className="mt-1 max-w-3xl text-sm leading-6 text-muted">{description}</p>
      </div>
      {children}
    </motion.main>
  );
}

export function Field({ label, value, onChange, disabled }: { label: string; value: string; onChange: (value: string) => void; disabled?: boolean }) {
  return <label className="flex flex-col gap-2"><span className="text-sm font-semibold text-strong">{label}</span><Input value={value} disabled={disabled} onChange={(event) => onChange(event.target.value)} /></label>;
}

export function SelectField({
  label,
  value,
  values,
  onChange,
  helper,
  tone = "normal",
}: {
  label: string;
  value: string;
  values: string[];
  onChange: (value: string) => void;
  helper?: string;
  tone?: "normal" | "danger" | "success";
}) {
  return (
    <label
      className={cn(
        "flex flex-col gap-2 rounded-xl transition-colors",
        tone === "danger" && "border border-[#7f2f23] bg-[#2b1410] p-3",
        tone === "success" && "border border-[#2f6b4f] bg-[#102017] p-3",
      )}
    >
      <span className="text-sm font-semibold text-strong">{label}</span>
      <Select value={value} onValueChange={onChange}>
        <SelectTrigger><SelectValue /></SelectTrigger>
        <SelectContent>{values.map((item) => <SelectItem key={item} value={item}>{item}</SelectItem>)}</SelectContent>
      </Select>
      {helper && <span className={cn("text-xs leading-5", tone === "danger" ? "text-[#ffd0c4]" : "text-muted")}>{helper}</span>}
    </label>
  );
}

export function EvidenceCard() {
  const { t, evidence, intakeForm } = useNetra();
  return (
    <motion.aside initial={{ opacity: 0, y: 22 }} animate={{ opacity: 1, y: 0 }} className="min-w-0">
      <div className="surface-solid min-w-0 rounded-[1.5rem] p-5">
        <h3 className="text-lg font-black text-strong">{t("evidenceMetadata")}</h3>
        <div className="mt-4">
          <MetadataRow label={t("caseNumber")} value={intakeForm.caseNumber} />
          <MetadataRow label={t("investigator")} value={intakeForm.investigator} />
          <MetadataRow label={t("department")} value={intakeForm.department} />
          <MetadataRow label={t("filename")} value={evidence?.filename ?? "No PCAP uploaded"} />
          <MetadataRow label="SHA-256" value={evidence?.sha256 ?? "-"} />
        </div>
      </div>
    </motion.aside>
  );
}

export function TimelineList({ record }: { record: CaseRecord }) {
  return (
    <div className="mt-5 flex flex-col gap-4">
      {record.history.map((item) => (
        <div key={item.id} className="grid grid-cols-[2rem_1fr] gap-3">
          <span className="mt-1 flex size-8 items-center justify-center rounded-full bg-[var(--accent-soft)] text-accent"><History className="size-4" /></span>
          <div><div className="text-sm font-bold text-strong">{item.action}</div><div className="text-xs text-muted">{item.timestamp} - {item.actor}</div><p className="mt-1 text-sm text-muted">{item.details}</p></div>
        </div>
      ))}
    </div>
  );
}

export function ChartPanel({ title, children }: { title: string; children: ReactNode }) {
  return <section aria-label={`${title} chart`} className="min-w-0 rounded-[1.25rem] border border-[var(--border)] bg-[var(--surface-muted)] p-4"><h3 className="mb-3 text-sm font-bold text-strong">{title}</h3>{children}<p className="sr-only">A visual summary of {title}. Equivalent values are available in the associated case tables.</p></section>;
}

export function MiniBarList({ rows }: { rows: { name: string; value: number }[] }) {
  const max = Math.max(1, ...rows.map((row) => row.value));
  return (
    <div className="grid gap-3">
      {rows.slice(0, 8).map((row) => (
        <div key={row.name}>
          <div className="mb-1 flex items-center justify-between gap-3 text-xs">
            <span className="truncate text-muted">{row.name}</span>
            <span className="font-bold text-strong">{row.value}</span>
          </div>
          <div className="h-2 overflow-hidden rounded-full bg-[var(--surface)]">
            <div className="h-full rounded-full bg-[var(--accent)]" style={{ width: `${Math.max(8, (row.value / max) * 100)}%` }} />
          </div>
        </div>
      ))}
    </div>
  );
}

export function AlertTable({ alerts: rows, liveId, compact = false }: { alerts: AlertRecord[]; liveId?: string; compact?: boolean }) {
  const { t } = useNetra();
  return (
    <div className={cn("min-w-0 overflow-hidden rounded-[1.25rem] border border-[var(--border)]", !compact && "surface-solid")}>
      {!compact && <div className="p-5 pb-0"><h3 className="text-lg font-black text-strong">{t("alertQueue")}</h3><p className="text-sm text-muted">{t("alertQueueBody")}</p></div>}
      <div className="overflow-x-auto p-5">
        <table className={cn("w-full text-left text-sm", compact && "min-w-[760px]")}>
          <caption className="sr-only">Analysis alerts with severity, classification, endpoints, confidence, and review status</caption>
          <thead className="border-b border-[var(--border)] text-xs uppercase text-muted"><tr><th scope="col" className="py-3 pr-4">{t("severity")}</th><th scope="col" className="pr-4">{t("class")}</th><th scope="col" className="pr-4">{t("type")}</th><th scope="col" className="pr-4">{t("source")}</th><th scope="col" className="pr-4">{t("destination")}</th><th scope="col" className="pr-4">{t("protocol")}</th><th scope="col" className="pr-4">{t("confidence")}</th><th scope="col">{t("status")}</th></tr></thead>
          <tbody>
            <AnimatePresence>{rows.map((alert) => (
              <motion.tr key={alert.id} initial={{ opacity: 0 }} animate={{ opacity: 1 }} className={cn("border-b border-[var(--border)] hover:bg-[var(--surface-muted)]", liveId === alert.id && "orange-pulse bg-[var(--accent-soft)]")}>
                <td className="py-3 pr-4 align-top"><SeverityBadge severity={alert.severity} /></td><td className="pr-4 align-top"><AttackBadge attackClass={alert.attackClass} /></td><td className="min-w-48 max-w-64 pr-4 align-top font-medium text-strong">{alert.type}</td><td className="pr-4 align-top font-mono text-xs break-words">{alert.sourceIp}</td><td className="max-w-36 break-words pr-4 align-top font-mono text-xs">{alert.destination}</td><td className="pr-4 align-top">{alert.protocol}</td><td className="pr-4 align-top">{alert.confidence}%</td><td className="align-top"><Badge variant="secondary">{alert.status}</Badge></td>
              </motion.tr>
            ))}</AnimatePresence>
          </tbody>
        </table>
        {!rows.length && <div className="py-8 text-center text-sm text-muted">No suspicious activity found in this evidence file.</div>}
      </div>
    </div>
  );
}

export function SeverityBadge({ severity }: { severity: Severity }) {
  return <Badge variant={severity === "critical" ? "destructive" : "secondary"}>{severity}</Badge>;
}

export function AttackBadge({ attackClass }: { attackClass: AttackClass }) {
  return <Badge>{attackClass}</Badge>;
}

export function MetadataRow({ label, value }: { label: string; value: string }) {
  return <div className="grid grid-cols-[minmax(7rem,0.45fr)_minmax(0,1fr)] gap-4 border-b border-[var(--border)] py-2 text-sm last:border-b-0"><span className="text-muted">{label}</span><span className="min-w-0 break-all text-right font-semibold text-strong">{value}</span></div>;
}

export function NormalizationMetric({ label, value, compact = false }: { label: string; value: string; compact?: boolean }) {
  return (
    <div className="min-w-0 rounded-xl border border-[var(--border)] bg-[var(--surface)] px-3 py-3">
      <div className="text-[11px] font-semibold uppercase tracking-[0.08em] text-muted">{label}</div>
      <div className={cn("mt-1 text-sm font-black leading-5 text-strong", compact ? "break-words" : "truncate")} title={value}>{value}</div>
    </div>
  );
}

export function ReportSection({ title, children }: { title: string; children: ReactNode }) {
  return <motion.section initial={{ opacity: 0, y: 10 }} animate={{ opacity: 1, y: 0 }} className="rounded-[1.25rem] border border-[var(--border)] p-4"><h3 className="mb-3 text-base font-bold text-strong">{title}</h3>{children}</motion.section>;
}

export function nodeStyle(risk = 0) {
  const color = risk >= 90 ? "#ef4444" : risk >= 75 ? "#f97316" : risk >= 50 ? "#f59e0b" : "var(--accent)";
  return { border: `2px solid ${color}`, borderRadius: 12, color: "var(--text-strong)", background: "#15120f", boxShadow: "0 14px 36px rgba(13, 13, 13, 0.22)", fontWeight: 700, whiteSpace: "pre-line" as const, padding: 12, width: 180 };
}

export function edgeStyle(width: number, risk = 0) {
  const color = risk >= 90 ? "#ef4444" : risk >= 75 ? "#f97316" : "var(--accent)";
  return { stroke: color, strokeWidth: width };
}
