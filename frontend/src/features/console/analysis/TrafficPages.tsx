import { Alert, Badge, Button, Input, Sheet, SheetContent, SheetTitle, Tabs, TabsContent, TabsList, TabsTrigger } from "../../../components/ui/primitives";
import { AlertTriangle, Database, FileText, Upload, UploadCloud } from "lucide-react";
import { appViewRoute } from "../ConsoleCore";
import { Area, AreaChart, CartesianGrid, Tooltip as ChartTooltip, ResponsiveContainer, XAxis, YAxis } from "recharts";
import { AttackBadge } from "../reports/ReportPages";
import { CaseContextSelector } from "../evidence/EvidenceShared";
import { ChartPanel } from "../reports/ReportPages";
import { CodeBlock } from "../reports/ReportPages";
import { DetectionTable } from "../reports/ReportPages";
import { formatNumber } from "../../../lib/utils";
import { Link } from "react-router-dom";
import { MetadataRow } from "../reports/ReportPages";
import { MetricTile } from "../reports/ReportPages";
import { PageFrame } from "../reports/ReportPages";
import { SelectField } from "../reports/ReportPages";
import { SeverityBadge } from "../reports/ReportPages";
import { toast } from "sonner";
import { type AttackClass, type PacketRecord, type PayloadFinding, type SessionRecord } from "../../../lib/types";
import { useMemo, useState } from "react";
import { useNetra } from "../ConsoleCore";

export function DashboardPage() {
  const { t, alertRecords, anomalies, caseRecords, decodedProtocols, evidence, networkFlows, packets, sessions, summary, zeek, activeCaseId, setActiveCaseId } = useNetra();
  const currentCase = caseRecords.find((record) => record.id === activeCaseId) ?? caseRecords[0];
  const highRiskAlerts = alertRecords.filter((alert) => ["critical", "high"].includes(alert.severity));
  const topAlert = highRiskAlerts[0] ?? alertRecords[0] ?? null;
  const suspiciousFlows = networkFlows.filter((flow) => flow.suspicious || (flow.risk ?? 0) >= 60);
  const evidenceVerified = evidence?.status === "verified" || Boolean(evidence?.manifestHash);
  const findingText = topAlert?.explanation
    ?? (alertRecords.length
      ? "Netra found suspicious network behavior and linked it to packet, session, and protocol evidence."
      : "No high-risk behavior has been found in the selected evidence so far.");
  const nextStep = topAlert
    ? "Review the suspicious activity details, then generate the evidence report when the finding is ready for case review."
    : "Open the traffic evidence tabs to inspect the capture, or generate a baseline report if this is a normal sample.";
  if (caseRecords.length === 0) {
    return (
      <PageFrame title={t("dashboardTitle")} description={t("dashboardDesc")}>
        <div className="surface mx-auto flex max-w-2xl flex-col items-center gap-4 rounded-[1.5rem] p-8 text-center">
          <UploadCloud size={34} aria-hidden="true" />
          <div>
            <h2 className="text-xl font-black text-strong">No PCAP evidence uploaded yet</h2>
            <p className="mt-2 text-sm leading-6 text-muted">Upload a real PCAP or PCAPNG file to create the first investigation case and populate this dashboard.</p>
          </div>
          <Button asChild><Link to={appViewRoute("upload")}><Upload size={16} />Upload PCAP</Link></Button>
        </div>
      </PageFrame>
    );
  }
  return (
    <PageFrame title={t("dashboardTitle")} description={t("dashboardDesc")}>
      <div className="surface rounded-[1.5rem] p-5">
        <div className="flex flex-wrap items-start justify-between gap-4">
          <div>
            <div className="text-xs font-bold uppercase tracking-[0.14em] text-muted">Selected case</div>
            <h2 className="mt-2 text-2xl font-black text-strong">{currentCase?.id ?? "No case selected"}</h2>
            <p className="mt-1 text-sm leading-6 text-muted">{currentCase?.title ?? "Choose a case to see investigation results."}</p>
          </div>
          <CaseContextSelector value={activeCaseId ?? caseRecords[0]?.id ?? ""} onChange={setActiveCaseId} />
        </div>
        <div className="mt-5 grid gap-4 md:grid-cols-5">
          <MetricTile label="Risk" value={summary.riskLevel.toUpperCase()} detail={summary.topAttackClass} />
          <MetricTile label="Packets" value={formatNumber(summary.indexedPackets ?? packets.length)} detail={(summary.searchCompleteness === "truncated-search-index" && summary.observedPackets) ? `${formatNumber(summary.observedPackets)} observed; metadata capped` : "Packet metadata indexed"} />
          <MetricTile label="Sessions" value={sessions.length} detail="Reconstructed conversations" />
          <MetricTile label="Alerts" value={alertRecords.length} detail={`${highRiskAlerts.length} high risk`} />
          <MetricTile label="Evidence hash" value={evidenceVerified ? "Verified" : "Pending"} detail={evidence?.sha256 ? `${evidence.sha256.slice(0, 16)}...` : "No hash available"} />
        </div>
        <div className="mt-5 grid gap-4 lg:grid-cols-[1fr_0.9fr]">
          <div className="surface-solid rounded-[1.5rem] p-5">
            <div className="flex flex-wrap gap-2">
              <SeverityBadge severity={topAlert?.severity ?? summary.riskLevel} />
              <AttackBadge attackClass={(topAlert?.attackClass ?? summary.topAttackClass) as AttackClass} />
            </div>
            <h2 className="mt-4 text-xl font-black text-strong">What Netra found</h2>
            <p className="mt-2 text-sm leading-7 text-muted">{findingText}</p>
            {topAlert?.observedSignals?.length ? (
              <div className="mt-4 flex flex-wrap gap-2">
                {topAlert.observedSignals.slice(0, 3).map((signal) => <Badge key={signal} variant="secondary">{signal}</Badge>)}
              </div>
            ) : null}
          </div>
          <div className="surface-solid rounded-[1.5rem] p-5">
            <h2 className="text-xl font-black text-strong">Recommended next step</h2>
            <p className="mt-2 text-sm leading-7 text-muted">{topAlert?.recommendedAction ?? nextStep}</p>
            <div className="mt-5 flex flex-wrap gap-2">
              <Button asChild><Link to={appViewRoute("activity")}><AlertTriangle className="size-4" />Review activity</Link></Button>
              <Button asChild variant="secondary"><Link to={appViewRoute("evidence")}><Database className="size-4" />Inspect evidence</Link></Button>
              <Button asChild variant="secondary"><Link to={appViewRoute("reports")}><FileText className="size-4" />Prepare report</Link></Button>
            </div>
          </div>
        </div>
      </div>
      <div className="grid gap-4 lg:grid-cols-3">
        <div className="surface rounded-[1.5rem] p-5">
          <h2 className="text-lg font-black text-strong">Investigation counts</h2>
          <div className="mt-4 grid gap-3 text-sm">
            <MetadataRow label="Protocols decoded" value={`${decodedProtocols.length}`} />
            <MetadataRow label="Anomaly explanations" value={`${anomalies.length}`} />
            <MetadataRow label="Suspicious flows" value={`${suspiciousFlows.length}`} />
          </div>
        </div>
        <div className="surface rounded-[1.5rem] p-5">
          <h2 className="text-lg font-black text-strong">Evidence integrity</h2>
          <div className="mt-4 grid gap-3 text-sm">
            <MetadataRow label="File" value={evidence?.filename ?? "No file"} />
            <MetadataRow label="Manifest" value={evidence?.manifestHash ? "Available" : "Pending"} />
            <MetadataRow label="Encryption key" value={evidence?.keyId ?? "Pending"} />
          </div>
        </div>
        <div className="surface rounded-[1.5rem] p-5">
          <h2 className="text-lg font-black text-strong">Analysis tools</h2>
          <div className="mt-4 flex flex-wrap gap-2">
            {Object.entries(summary.toolStatus ?? {}).map(([name, ok]) => <Badge key={name} variant={ok ? "secondary" : "destructive"}>{name}: {ok ? "ready" : "missing"}</Badge>)}
            <Badge>Zeek {zeek?.status ?? "not-run"}</Badge>
          </div>
        </div>
      </div>
    </PageFrame>
  );
}

export function PacketExplorerPage() {
  const { t, packets } = useNetra();
  const [selectedPacket, setSelectedPacket] = useState<PacketRecord | null>(null);
  const [query, setQuery] = useState("");
  const [sourceIp, setSourceIp] = useState("");
  const [destinationIp, setDestinationIp] = useState("");
  const [port, setPort] = useState("");
  const [sessionId, setSessionId] = useState("");
  const [protocol, setProtocol] = useState("all");
  const [severity, setSeverity] = useState("all");
  const filteredPackets = useMemo(() => {
    const text = query.trim().toLowerCase();
    return packets.filter((packet) => {
      const haystack = [
        packet.id,
        packet.timestamp,
        packet.sourceIp,
        packet.destinationIp,
        packet.protocol,
        packet.sessionId,
        packet.decodedSummary,
      ].join(" ").toLowerCase();
      return (
        (!text || haystack.includes(text)) &&
        (!sourceIp || packet.sourceIp.includes(sourceIp.trim())) &&
        (!destinationIp || packet.destinationIp.toLowerCase().includes(destinationIp.trim().toLowerCase())) &&
        (!port || String(packet.sourcePort).includes(port.trim()) || String(packet.destinationPort).includes(port.trim())) &&
        (!sessionId || packet.sessionId.toLowerCase().includes(sessionId.trim().toLowerCase())) &&
        (protocol === "all" || packet.protocol === protocol) &&
        (severity === "all" || packet.severity === severity)
      );
    });
  }, [destinationIp, packets, port, protocol, query, sessionId, severity, sourceIp]);

  return (
    <PageFrame title={t("packetExplorer")} description={t("packetExplorerDesc")}>
      <div className="surface rounded-[1.5rem] p-4">
        <div className="grid gap-3 md:grid-cols-4 xl:grid-cols-7">
          <Input value={query} onChange={(event) => setQuery(event.target.value)} placeholder={t("searchPlaceholder")} />
          <Input value={sourceIp} onChange={(event) => setSourceIp(event.target.value)} placeholder={t("sourceIp")} />
          <Input value={destinationIp} onChange={(event) => setDestinationIp(event.target.value)} placeholder={t("destinationIp")} />
          <Input value={port} onChange={(event) => setPort(event.target.value)} placeholder={t("port")} />
          <Input value={sessionId} onChange={(event) => setSessionId(event.target.value)} placeholder="Session ID" />
          <SelectField label={t("protocol")} value={protocol} values={["all", "DNS", "TLS", "TCP", "HTTP", "ICMP"]} onChange={setProtocol} />
          <SelectField label={t("severity")} value={severity} values={["all", "critical", "high", "medium", "low"]} onChange={setSeverity} />
        </div>
      </div>
      <div className="surface-solid overflow-hidden rounded-[1.5rem]">
        <div className="overflow-x-auto p-4">
          <table className="w-full min-w-[1080px] text-left text-sm">
            <thead className="border-b border-[var(--border)] text-xs uppercase text-muted"><tr><th className="py-3">Packet ID</th><th>Timestamp</th><th>Source</th><th>Destination</th><th>Ports</th><th>{t("protocol")}</th><th>Size</th><th>Flags</th><th>Session</th><th>Risk</th></tr></thead>
            <tbody>{filteredPackets.map((packet) => (
              <tr key={packet.id} onClick={() => setSelectedPacket(packet)} className="cursor-pointer border-b border-[var(--border)] hover:bg-[var(--surface-muted)]">
                <td className="py-3 font-bold text-strong">{packet.id}</td><td className="font-mono text-xs">{packet.timestamp}</td><td className="font-mono text-xs">{packet.sourceIp}</td><td className="font-mono text-xs">{packet.destinationIp}</td><td>{packet.sourcePort} → {packet.destinationPort}</td><td><Badge>{packet.protocol}</Badge></td><td>{packet.size} B</td><td>{packet.flags}</td><td>{packet.sessionId}</td><td className="font-bold text-strong">{packet.riskScore}</td>
              </tr>
            ))}</tbody>
          </table>
          {filteredPackets.length === 0 && <div className="py-8 text-center text-sm text-muted">No packets match the current filters.</div>}
        </div>
      </div>
      <Sheet open={!!selectedPacket} onOpenChange={(open) => !open && setSelectedPacket(null)}>
        <SheetContent aria-describedby={undefined}>
          <SheetTitle>{selectedPacket?.id}</SheetTitle>
          {selectedPacket && <div className="mt-6 grid gap-4">
            <Badge>{selectedPacket.protocol}</Badge>
            <MetadataRow label={t("metadata")} value={`${selectedPacket.sourceIp}:${selectedPacket.sourcePort} → ${selectedPacket.destinationIp}:${selectedPacket.destinationPort}`} />
            <MetadataRow label={t("decodedFields")} value={selectedPacket.decodedSummary} />
            <MetadataRow label={t("relatedAlert")} value={selectedPacket.relatedAlertId ?? "none"} />
            <MetadataRow label={t("relatedSession")} value={selectedPacket.sessionId} />
            <CodeBlock title={t("hexPreview")} value={selectedPacket.hexPreview} />
            <CodeBlock title={t("asciiPreview")} value={selectedPacket.asciiPreview} />
            <Button onClick={() => toast.success(t("nodeToast"))}>{t("addToCase")}</Button>
          </div>}
        </SheetContent>
      </Sheet>
    </PageFrame>
  );
}

export function ProtocolDecoderPage() {
  const { t, decodedProtocols, zeek } = useNetra();
  return (
    <PageFrame title={t("protocolDecoder")} description={t("decoderDesc")}>
      <Alert>Encrypted content is not decrypted; metadata patterns are analyzed.</Alert>
      <div className="surface rounded-[1.5rem] p-4">
        <div className="flex flex-wrap items-center gap-3">
          <Badge>Zeek: {zeek?.status ?? "not-run"}</Badge>
          {(zeek?.logs ?? []).map((log) => <Badge key={log} variant="secondary">{log}</Badge>)}
        </div>
        <div className="mt-4 grid gap-3 md:grid-cols-4">
          {Object.entries(zeek?.summary ?? {}).map(([key, value]) => <MetricTile key={key} label={key} value={value ?? 0} />)}
        </div>
      </div>
      <div className="grid gap-4 md:grid-cols-3 xl:grid-cols-6">
        {decodedProtocols.map((record) => <MetricTile key={record.protocol} label={record.protocol} value={`${record.suspiciousCount} suspicious`} detail={`${record.packetCount.toLocaleString()} packets`} />)}
      </div>
      <div className="surface-solid overflow-hidden rounded-[1.5rem]">
        <div className="overflow-x-auto p-4">
          <table className="w-full min-w-[820px] text-left text-sm">
            <thead className="border-b border-[var(--border)] text-xs uppercase text-muted"><tr><th className="py-3">Protocol</th><th>Packets</th><th>Sessions</th><th>Suspicious</th><th>Status</th><th>Top destination</th><th>Decoder detail</th></tr></thead>
            <tbody>{decodedProtocols.map((record) => <tr key={record.protocol} className="border-b border-[var(--border)]"><td className="py-3 font-bold text-strong">{record.protocol}</td><td>{record.packetCount.toLocaleString()}</td><td>{record.sessionCount}</td><td>{record.suspiciousCount}</td><td><Badge>{record.status}</Badge></td><td>{record.topDestination}</td><td>{record.detail}</td></tr>)}</tbody>
          </table>
        </div>
      </div>
      <Tabs defaultValue="DNS">
        <TabsList className="flex-wrap">{["DNS", "HTTP", "TLS", "SSH", "SMTP", "FTP"].map((item) => <TabsTrigger key={item} value={item}>{item}</TabsTrigger>)}</TabsList>
        {["DNS", "HTTP", "TLS", "SSH", "SMTP", "FTP"].map((item) => <TabsContent key={item} value={item}><CodeBlock title={`${item} decoded preview`} value={decodedProtocols.find((record) => record.protocol.includes(item))?.detail ?? `${item} decoder preview ready for backend data.`} /></TabsContent>)}
      </Tabs>
    </PageFrame>
  );
}

export function PayloadInspectionPage() {
  const { t, payloadFindings } = useNetra();
  const [selectedFinding, setSelectedFinding] = useState<PayloadFinding | null>(null);
  const activeFinding = selectedFinding ?? payloadFindings[0] ?? null;
  return (
    <PageFrame title={t("payloadInspection")} description={t("payloadDesc")}>
      <div className="grid gap-5 xl:grid-cols-[1fr_0.8fr]">
        <div className="surface-solid overflow-hidden rounded-[1.5rem]">
          <div className="overflow-x-auto p-4">
            <table className="w-full min-w-[860px] text-left text-sm">
              <thead className="border-b border-[var(--border)] text-xs uppercase text-muted"><tr><th className="py-3">Finding</th><th>Packet</th><th>Session</th><th>{t("protocol")}</th><th>Type</th><th>Entropy</th><th>Hidden</th><th>Obfuscated</th><th>Risk</th></tr></thead>
              <tbody>{payloadFindings.map((finding) => <tr key={finding.id} onClick={() => setSelectedFinding(finding)} className="cursor-pointer border-b border-[var(--border)] hover:bg-[var(--surface-muted)]"><td className="py-3 font-bold text-strong">{finding.id}</td><td>{finding.packetId}</td><td>{finding.sessionId}</td><td><Badge>{finding.protocol}</Badge></td><td>{finding.payloadType}</td><td>{finding.entropyScore}</td><td>{finding.hiddenData ? "yes" : "no"}</td><td>{finding.obfuscated ? "yes" : "no"}</td><td><SeverityBadge severity={finding.risk} /></td></tr>)}</tbody>
            </table>
            {payloadFindings.length === 0 && <div className="py-8 text-center text-sm text-muted">Upload a PCAP to generate payload findings.</div>}
          </div>
        </div>
        <div className="surface rounded-[1.5rem] p-5">
          {activeFinding ? (
            <>
              <h2 className="text-xl font-black text-strong">{activeFinding.id}</h2>
              <p className="mt-1 text-sm text-muted">{activeFinding.matchedPattern}</p>
              {activeFinding.description && <p className="mt-3 text-sm leading-6 text-strong">{activeFinding.description}</p>}
              {activeFinding.limitations && <p className="mt-2 text-xs leading-5 text-muted">{activeFinding.limitations}</p>}
              <CodeBlock title={t("textPreview")} value={activeFinding.textPreview} />
              <CodeBlock title={t("hexPreview")} value={activeFinding.hexPreview} />
              <div className="mt-4 flex flex-wrap gap-2">{activeFinding.extractedStrings.map((item) => <Badge key={item}>{item}</Badge>)}</div>
            </>
          ) : <p className="text-sm text-muted">No findings yet.</p>}
        </div>
      </div>
    </PageFrame>
  );
}

export function SessionsPage() {
  const { t, sessions } = useNetra();
  const [selectedSession, setSelectedSession] = useState<SessionRecord | null>(null);
  return (
    <PageFrame title={t("sessions")} description={t("sessionsDesc")}>
      <div className="surface-solid overflow-hidden rounded-[1.5rem]">
        <div className="overflow-x-auto p-4">
          <table className="w-full min-w-[980px] text-left text-sm">
            <thead className="border-b border-[var(--border)] text-xs uppercase text-muted"><tr><th className="py-3">Session</th><th>Source</th><th>Destination</th><th>{t("protocol")}</th><th>Start</th><th>End</th><th>Duration</th><th>Bytes sent</th><th>Bytes received</th><th>Packets</th><th>Risk</th></tr></thead>
            <tbody>{sessions.map((session) => <tr key={session.id} onClick={() => setSelectedSession(session)} className="cursor-pointer border-b border-[var(--border)] hover:bg-[var(--surface-muted)]"><td className="py-3 font-bold text-strong">{session.id}</td><td>{session.source}</td><td>{session.destination}</td><td><Badge>{session.protocol}</Badge></td><td>{session.startTime}</td><td>{session.endTime}</td><td>{session.duration}</td><td>{formatNumber(session.bytesSent)}</td><td>{formatNumber(session.bytesReceived)}</td><td>{session.packetCount}</td><td>{session.riskScore}</td></tr>)}</tbody>
          </table>
        </div>
      </div>
      <Sheet open={!!selectedSession} onOpenChange={(open) => !open && setSelectedSession(null)}>
        <SheetContent aria-describedby={undefined}>
          <SheetTitle>{selectedSession?.id}</SheetTitle>
          {selectedSession && <div className="mt-6 grid gap-4">
            <MetadataRow label={t("requestResponseFlow")} value={`${selectedSession.source} → ${selectedSession.destination}`} />
            <MetadataRow label={t("packetTimeline")} value={`${selectedSession.startTime} - ${selectedSession.endTime}`} />
            <MetadataRow label={t("relatedAlert")} value={selectedSession.relatedAlertIds.join(", ")} />
            <CodeBlock title="Reconstruction" value={`Client request burst → server response → suspicious repeated interval. ${selectedSession.packetCount} packets reconstructed for investigator review.`} />
            <Button onClick={() => toast.success(t("nodeToast"))}>{t("addToCase")}</Button>
          </div>}
        </SheetContent>
      </Sheet>
    </PageFrame>
  );
}

export function ThreatDetectionPage() {
  const { t } = useNetra();
  const classes = ["Signature Rules", "Credential Brute Force", "IoT Botnet / Scanning", "Malware C2 / Beaconing", "Service Exploitation", "Remote Command Execution", "SMB / NetBIOS Lateral Movement"];
  return (
    <PageFrame title={t("threatDetection")} description={t("detectionDesc")}>
      <Tabs defaultValue="rules">
        <TabsList className="flex-wrap">{classes.map((item) => <TabsTrigger key={item} value={item === "Signature Rules" ? "rules" : item}>{item}</TabsTrigger>)}</TabsList>
        <TabsContent value="rules"><DetectionTable /></TabsContent>
        {classes.slice(1).map((item) => <TabsContent key={item} value={item}><DetectionTable category={item} /></TabsContent>)}
      </Tabs>
    </PageFrame>
  );
}

export function AiAnomalyPage() {
  const { t, anomalies, trafficTimelineData } = useNetra();
  return (
    <PageFrame title="AI-assisted Anomaly Scoring" description="Explainable anomaly detection with observed values, baseline comparisons, and investigator actions.">
      <div className="grid gap-4 md:grid-cols-4">
        {anomalies.map((item) => <MetricTile key={item.id} label={item.behaviour} value={item.deviation} detail={`${item.confidence}% confidence`} />)}
      </div>
      <div className="grid gap-4 lg:grid-cols-[1fr_0.8fr]">
        <div className="surface-solid overflow-hidden rounded-[1.5rem]">
          <div className="overflow-x-auto p-4">
            <table className="w-full min-w-[840px] text-left text-sm">
              <thead className="border-b border-[var(--border)] text-xs uppercase text-muted"><tr><th className="py-3">Entity</th><th>Behaviour</th><th>Observed vs baseline</th><th>Features</th><th>Confidence</th><th>Hypothesis / Action</th></tr></thead>
              <tbody>{anomalies.map((item) => <tr key={item.id} className="border-b border-[var(--border)] align-top"><td className="py-3 font-mono text-xs">{item.entity}</td><td>{item.behaviour}<div className="mt-1 font-bold text-strong">{item.deviation}</div></td><td><div>{item.observed}</div><div className="text-xs text-muted">{item.baseline}</div></td><td className="max-w-48 text-xs">{item.topFeatures?.join(", ") ?? "-"}</td><td>{item.confidence}%</td><td className="max-w-72"><Badge>{item.hypothesis}</Badge><p className="mt-2 text-xs leading-5 text-muted">{item.recommendedAction}</p></td></tr>)}</tbody>
            </table>
          </div>
        </div>
        <ChartPanel title={t("baselineComparison")}>
          <ResponsiveContainer width="100%" height={280}><AreaChart data={trafficTimelineData}><CartesianGrid stroke="var(--border)" strokeDasharray="3 3" vertical={false} /><XAxis dataKey="time" fontSize={11} stroke="var(--muted)" /><YAxis fontSize={11} stroke="var(--muted)" /><ChartTooltip /><Area dataKey="mb" type="monotone" stroke="var(--accent)" fill="var(--accent-soft)" /></AreaChart></ResponsiveContainer>
        </ChartPanel>
      </div>
    </PageFrame>
  );
}
