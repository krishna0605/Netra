import { Alert, Badge, Button, Input, Progress, Select, SelectContent, SelectItem, SelectTrigger, SelectValue, Tabs, TabsContent, TabsList, TabsTrigger } from "../../../components/ui/primitives";
import { AlertTriangle, Database, FileText, Upload } from "lucide-react";
import { analysisStateLabel } from "../evidence/EvidenceShared";
import { AnomalyReviewPanel } from "../reports/EvidenceReportPages";
import { apiWorkspace } from "../ConsoleCore";
import { appViewRoute } from "../ConsoleCore";
import { CaseContextSelector } from "../evidence/EvidenceShared";
import { DetectionTable } from "../reports/ReportPages";
import { FlowEvidenceTable } from "../reports/EvidenceReportPages";
import { formatBytes, formatNumber } from "../../../lib/utils";
import { graphEdgesToFlows } from "../ConsoleCore";
import { Link } from "react-router-dom";
import { MetadataRow } from "../reports/ReportPages";
import { MetricTile } from "../reports/ReportPages";
import { PacketEvidenceTable } from "../reports/EvidenceReportPages";
import { PageFrame } from "../reports/ReportPages";
import { PayloadEvidenceTable } from "../reports/EvidenceReportPages";
import { ProtocolEvidenceTable } from "../reports/EvidenceReportPages";
import { SessionEvidenceTable } from "../reports/EvidenceReportPages";
import { SeverityBadge } from "../reports/ReportPages";
import { type AlertRecord, type AnomalyRecord, type DecodedProtocolRecord, type DetectionRuleMatch, type NetworkFlow, type PacketRecord, type PayloadFinding, type SessionRecord, type Severity, type ZeekEvidence } from "../../../lib/types";
import { useEffect, useMemo, useState } from "react";
import { useNetra } from "../ConsoleCore";

export function SuspiciousActivityPage() {
  const { t, activeCaseId, caseRecords, setActiveCaseId } = useNetra();
  const [alertRecords, setAlertRecords] = useState<AlertRecord[]>([]);
  const [anomalies, setAnomalies] = useState<AnomalyRecord[]>([]);
  const [detectionMatches, setDetectionMatches] = useState<DetectionRuleMatch[]>([]);
  const [networkFlows, setNetworkFlows] = useState<NetworkFlow[]>([]);
  const [aiExplanation, setAiExplanation] = useState<{ mode: string; modelVersion: string; fallbackUsed: boolean; limitations: string[] } | null>(null);
  const [loading, setLoading] = useState(false);
  const [loadError, setLoadError] = useState("");
  const currentCase = caseRecords.find((record) => record.id === activeCaseId);
  const currentRouteRef = currentCase?.routeRef;
  useEffect(() => {
    if (!currentRouteRef) {
      setLoading(false);
      return;
    }
    let cancelled = false;
    setAlertRecords([]);
    setAnomalies([]);
    setDetectionMatches([]);
    setNetworkFlows([]);
    setAiExplanation(null);
    setLoadError("");
    setLoading(true);
    apiWorkspace(currentRouteRef)
      .then((payload) => {
        if (cancelled) return;
        const suspicious = payload.workspace.suspiciousActivity;
        setAlertRecords(suspicious.alerts ?? []);
        setAnomalies(suspicious.anomalies ?? []);
        setDetectionMatches(suspicious.detectionMatches ?? []);
        setNetworkFlows(graphEdgesToFlows(payload.workspace.trafficEvidence.communicationMap ?? {}));
        setAiExplanation(suspicious.mlExplanation ?? null);
        setLoading(false);
      })
      .catch((error) => {
        if (cancelled) return;
        setLoadError(error instanceof Error ? error.message : "Suspicious activity could not be loaded.");
        setLoading(false);
      });
    return () => {
      cancelled = true;
    };
  }, [currentRouteRef]);
  const highRiskAlerts = alertRecords.filter((alert) => ["critical", "high"].includes(alert.severity));
  const suspiciousFlows = networkFlows.filter((flow) => flow.suspicious || (flow.risk ?? 0) >= 60).slice(0, 8);
  const reviewItems = [
    ...(highRiskAlerts.length ? highRiskAlerts : alertRecords).slice(0, 6).map((alert) => ({
      id: `alert-${alert.id}`,
      kind: "Alert",
      title: alert.type || alert.attackClass,
      severity: alert.severity,
      badge: alert.attackClass,
      confidence: alert.confidence,
      explanation: alert.explanation || "Netra found suspicious traffic behavior linked to packet or session evidence.",
      evidence: [...(alert.evidencePacketIds ?? []), ...(alert.evidenceSessionIds ?? [])].slice(0, 6),
      recommendation: alert.recommendedAction || "Review linked packets and sessions before adding this finding to the report.",
      meta: [
        ["Source", alert.sourceIp || "-"],
        ["Destination", alert.destination || "-"],
        ["Protocol", alert.protocol || "-"],
      ],
    })),
    ...anomalies.slice(0, 4).map((item) => ({
      id: `anomaly-${item.id}`,
      kind: "Anomaly",
      title: item.behaviour,
      severity: item.confidence >= 85 ? "high" as Severity : item.confidence >= 65 ? "medium" as Severity : "low" as Severity,
      badge: "AI-assisted anomaly",
      confidence: item.confidence,
      explanation: `${item.observed} compared with ${item.baseline}. ${item.hypothesis}`,
      evidence: item.topFeatures ?? [],
      recommendation: item.recommendedAction || "Compare this pattern with case context and related packet evidence.",
      meta: [
        ["Entity", item.entity],
        ["Deviation", item.deviation],
        ["Observed", item.observed],
      ],
    })),
    ...suspiciousFlows.slice(0, 4).map((flow) => ({
      id: `flow-${flow.id}`,
      kind: "Flow",
      title: `${flow.source} to ${flow.target}`,
      severity: (flow.risk ?? 0) >= 80 ? "high" as Severity : (flow.risk ?? 0) >= 60 ? "medium" as Severity : "low" as Severity,
      badge: flow.attackClass,
      confidence: flow.risk ?? 0,
      explanation: `Suspicious communication path over ${flow.protocol} with ${formatNumber(flow.packets)} packets and ${formatBytes(flow.bytes)} transferred.`,
      evidence: flow.alertIds,
      recommendation: "Open Traffic Evidence to inspect the linked packets, sessions, and communication path.",
      meta: [
        ["Source", flow.source],
        ["Destination", flow.target],
        ["Protocol", flow.protocol],
      ],
    })),
  ];
  if (!activeCaseId) {
    return <PageFrame title={t("suspiciousActivity")} description={t("suspiciousActivityDesc")}><div className="surface rounded-[1.5rem] p-6"><CaseContextSelector value="" onChange={setActiveCaseId} /><p className="mt-4 text-sm text-muted">Select a case to load its alerts, anomalies, and suspicious communication paths.</p></div></PageFrame>;
  }
  if (loading) {
    return <PageFrame title={t("suspiciousActivity")} description={t("suspiciousActivityDesc")}><div className="surface rounded-[1.5rem] p-6"><CaseContextSelector value={activeCaseId} onChange={setActiveCaseId} /><div className="mt-5"><Progress value={currentCase?.analysisStatus?.progress ?? 15} /><p className="mt-3 text-sm text-muted">Loading suspicious activity for {activeCaseId}…</p></div></div></PageFrame>;
  }
  if (!alertRecords.length && !anomalies.length && !detectionMatches.length) {
    return (
      <PageFrame title={t("suspiciousActivity")} description={t("suspiciousActivityDesc")}>
        <div className="surface rounded-[1.5rem] p-5"><CaseContextSelector value={activeCaseId} onChange={setActiveCaseId} /></div>
        <div className="surface mx-auto flex max-w-2xl flex-col items-center gap-4 rounded-[1.5rem] p-8 text-center">
          <AlertTriangle size={34} aria-hidden="true" />
          <div>
            <h2 className="text-xl font-black text-strong">No suspicious activity yet</h2>
            <p className="mt-2 text-sm leading-6 text-muted">{currentCase?.analysisStatus?.state === "completed" ? "Analysis completed without suspicious findings for this case." : `${analysisStateLabel(currentCase?.analysisStatus?.state)}. Findings will appear here as analysis progresses.`}</p>
          </div>
          <Button asChild><Link to={appViewRoute("upload")}><Upload size={16} />Start investigation</Link></Button>
        </div>
      </PageFrame>
    );
  }
  return (
    <PageFrame title={t("suspiciousActivity")} description={t("suspiciousActivityDesc")}>
      <div className="surface flex flex-wrap items-end justify-between gap-4 rounded-[1.5rem] p-5"><CaseContextSelector value={activeCaseId} onChange={setActiveCaseId} /><Badge>{analysisStateLabel(currentCase?.analysisStatus?.state)}</Badge></div>
      {loadError && <Alert>{loadError}</Alert>}
      <div className="grid gap-4 md:grid-cols-4">
        <MetricTile label="Review queue" value={reviewItems.length} detail="Alerts, anomalies, and risky flows" />
        <MetricTile label="High risk" value={highRiskAlerts.length} detail="Critical or high severity findings" />
        <MetricTile label="Rule matches" value={detectionMatches.length} detail="Signature and behavior detections" />
        <MetricTile label="Case" value={activeCaseId ?? "none"} detail="Current investigation" />
      </div>
      {aiExplanation && (
        <div className="surface rounded-[1.5rem] p-5">
          <div className="flex flex-wrap items-start justify-between gap-3">
            <div>
              <h2 className="text-xl font-black text-strong">AI anomaly explanation</h2>
              <p className="mt-2 text-sm leading-6 text-muted">Netra uses ML-assisted scoring with explainable fallback. It highlights unusual network behavior; it does not prove compromise by itself.</p>
            </div>
            <Badge>{aiExplanation.fallbackUsed ? "Fallback scoring" : aiExplanation.modelVersion}</Badge>
          </div>
          <div className="mt-3 flex flex-wrap gap-2">
            <Badge variant="secondary">{aiExplanation.mode}</Badge>
            {aiExplanation.limitations.slice(0, 2).map((item) => <Badge key={item} variant="warning">{item}</Badge>)}
          </div>
        </div>
      )}
      <Tabs defaultValue="summary" className="flex flex-col gap-4">
        <TabsList className="w-fit flex-wrap">
          <TabsTrigger value="summary">Simple review</TabsTrigger>
          <TabsTrigger value="rules">Detection details</TabsTrigger>
          <TabsTrigger value="patterns">Suspicious patterns</TabsTrigger>
          <TabsTrigger value="flows">Communication map</TabsTrigger>
        </TabsList>
        <TabsContent value="summary">
          <div className="grid gap-4">
            {reviewItems.map((item) => (
              <div key={item.id} className="surface rounded-[1.5rem] p-5">
                <div className="flex flex-wrap items-start justify-between gap-3">
                  <div>
                    <div className="flex flex-wrap gap-2"><Badge variant="secondary">{item.kind}</Badge><SeverityBadge severity={item.severity} /><Badge>{item.badge}</Badge></div>
                    <h2 className="mt-3 text-xl font-black text-strong">{item.title}</h2>
                    <p className="mt-2 max-w-3xl text-sm leading-6 text-muted">{item.explanation}</p>
                  </div>
                  <Badge>{item.confidence}% confidence</Badge>
                </div>
                <div className="mt-4 grid gap-3 md:grid-cols-3">
                  {item.meta.map(([label, value]) => <MetadataRow key={`${item.id}-${label}`} label={label} value={value} />)}
                </div>
                <div className="mt-4 grid gap-3 md:grid-cols-2">
                  <div className="rounded-xl border border-[var(--border)] bg-[var(--surface-muted)] p-4">
                    <div className="text-sm font-bold text-strong">Evidence</div>
                    <p className="mt-2 text-sm leading-6 text-muted">{item.evidence.join(", ") || "Packet and session evidence will appear after analysis finalizes."}</p>
                  </div>
                  <div className="rounded-xl border border-[var(--border)] bg-[var(--surface-muted)] p-4">
                    <div className="text-sm font-bold text-strong">Recommended action</div>
                    <p className="mt-2 text-sm leading-6 text-muted">{item.recommendation}</p>
                  </div>
                </div>
                <div className="mt-4 flex flex-wrap gap-2">
                  <Button asChild size="sm" variant="secondary"><Link to={appViewRoute("evidence")}><Database className="size-4" />Open evidence</Link></Button>
                  <Button asChild size="sm" variant="secondary"><Link to={appViewRoute("reports")}><FileText className="size-4" />Prepare report</Link></Button>
                </div>
              </div>
            ))}
          </div>
        </TabsContent>
        <TabsContent value="rules"><DetectionTable /></TabsContent>
        <TabsContent value="patterns"><AnomalyReviewPanel /></TabsContent>
        <TabsContent value="flows">
          <div className="surface-solid overflow-hidden rounded-[1.5rem]">
            <div className="overflow-x-auto p-4">
              <table className="w-full min-w-[760px] text-left text-sm">
                <thead className="border-b border-[var(--border)] text-xs uppercase text-muted"><tr><th className="py-3">Source</th><th>Destination</th><th>Protocol</th><th>Packets</th><th>Risk</th><th>Finding</th></tr></thead>
                <tbody>{suspiciousFlows.map((flow) => <tr key={flow.id} className="border-b border-[var(--border)]"><td className="py-3 font-mono text-xs">{flow.source}</td><td className="font-mono text-xs">{flow.target}</td><td><Badge>{flow.protocol}</Badge></td><td>{formatNumber(flow.packets)}</td><td>{flow.risk ?? 0}</td><td>{flow.attackClass}</td></tr>)}</tbody>
              </table>
              {!suspiciousFlows.length && <div className="py-8 text-center text-sm text-muted">No suspicious communication paths found yet.</div>}
            </div>
          </div>
          <div className="mt-4"><Button asChild variant="secondary"><Link to={appViewRoute("graph")}>Open full communication map</Link></Button></div>
        </TabsContent>
      </Tabs>
    </PageFrame>
  );
}

export function TrafficEvidencePage() {
  const { t, activeCaseId, caseRecords, setActiveCaseId } = useNetra();
  const [packets, setPackets] = useState<PacketRecord[]>([]);
  const [sessions, setSessions] = useState<SessionRecord[]>([]);
  const [decodedProtocols, setDecodedProtocols] = useState<DecodedProtocolRecord[]>([]);
  const [payloadFindings, setPayloadFindings] = useState<PayloadFinding[]>([]);
  const [networkFlows, setNetworkFlows] = useState<NetworkFlow[]>([]);
  const [zeek, setZeek] = useState<ZeekEvidence | null>(null);
  const [query, setQuery] = useState("");
  const [protocol, setProtocol] = useState("all");
  const [port, setPort] = useState("");
  const [severity, setSeverity] = useState("all");
  const [loading, setLoading] = useState(false);
  const [loadError, setLoadError] = useState("");
  const currentCase = caseRecords.find((record) => record.id === activeCaseId);
  const currentRouteRef = currentCase?.routeRef;
  useEffect(() => {
    if (!currentRouteRef) {
      setLoading(false);
      return;
    }
    let cancelled = false;
    setPackets([]);
    setSessions([]);
    setDecodedProtocols([]);
    setPayloadFindings([]);
    setNetworkFlows([]);
    setZeek(null);
    setLoadError("");
    setLoading(true);
    apiWorkspace(currentRouteRef)
      .then((payload) => {
        if (cancelled) return;
        const traffic = payload.workspace.trafficEvidence;
        setPackets(traffic.packetsPreview ?? []);
        setSessions(traffic.sessionsPreview ?? []);
        setDecodedProtocols(traffic.protocols ?? []);
        setPayloadFindings(traffic.payloadClues ?? []);
        setNetworkFlows(graphEdgesToFlows(traffic.communicationMap ?? {}));
        setZeek(payload.workspace.summary.zeek ?? null);
        setLoading(false);
      })
      .catch((error) => {
        if (cancelled) return;
        setLoadError(error instanceof Error ? error.message : "Traffic evidence could not be loaded.");
        setLoading(false);
      });
    return () => {
      cancelled = true;
    };
  }, [currentRouteRef]);
  const filteredPackets = useMemo(() => {
    const text = query.trim().toLowerCase();
    const portText = port.trim();
    return packets.filter((packet) => {
      const haystack = [packet.sourceIp, packet.destinationIp, packet.protocol, packet.sessionId, packet.decodedSummary, packet.relatedAlertId ?? ""].join(" ").toLowerCase();
      return (
        (!text || haystack.includes(text)) &&
        (protocol === "all" || packet.protocol.toLowerCase() === protocol.toLowerCase()) &&
        (!portText || String(packet.sourcePort).includes(portText) || String(packet.destinationPort).includes(portText)) &&
        (severity === "all" || packet.severity === severity)
      );
    });
  }, [packets, port, protocol, query, severity]);
  const filteredSessions = useMemo(() => {
    const text = query.trim().toLowerCase();
    const portText = port.trim();
    return sessions.filter((session) => {
      const haystack = [session.id, session.source, session.destination, session.protocol, ...(session.relatedAlertIds ?? [])].join(" ").toLowerCase();
      return (
        (!text || haystack.includes(text)) &&
        (protocol === "all" || session.protocol.toLowerCase() === protocol.toLowerCase()) &&
        (!portText || session.source.includes(portText) || session.destination.includes(portText)) &&
        (severity === "all" || session.riskScore >= (severity === "critical" ? 90 : severity === "high" ? 70 : severity === "medium" ? 40 : 0))
      );
    });
  }, [port, protocol, query, sessions, severity]);
  const filteredProtocols = decodedProtocols.filter((record) => protocol === "all" || record.protocol.toLowerCase().includes(protocol.toLowerCase()));
  const filteredPayloads = payloadFindings.filter((finding) => {
    const text = query.trim().toLowerCase();
    return (!text || [finding.id, finding.packetId, finding.sessionId, finding.protocol, finding.payloadType, finding.matchedPattern].join(" ").toLowerCase().includes(text)) && (protocol === "all" || finding.protocol.toLowerCase() === protocol.toLowerCase()) && (severity === "all" || finding.risk === severity);
  });
  const filteredFlows = networkFlows.filter((flow) => {
    const text = query.trim().toLowerCase();
    const portText = port.trim();
    return (
      (!text || [flow.source, flow.target, flow.protocol, flow.attackClass, ...flow.alertIds].join(" ").toLowerCase().includes(text)) &&
      (protocol === "all" || flow.protocol.toLowerCase() === protocol.toLowerCase()) &&
      (!portText || flow.source.includes(portText) || flow.target.includes(portText)) &&
      (severity === "all" || (flow.risk ?? 0) >= (severity === "critical" ? 90 : severity === "high" ? 70 : severity === "medium" ? 40 : 0))
    );
  });
  if (!activeCaseId) {
    return <PageFrame title={t("trafficEvidence")} description={t("trafficEvidenceDesc")}><div className="surface rounded-[1.5rem] p-6"><CaseContextSelector value="" onChange={setActiveCaseId} /><p className="mt-4 text-sm text-muted">Select a case to load its packets, sessions, protocols, payload clues, and communication map.</p></div></PageFrame>;
  }
  if (loading) {
    return <PageFrame title={t("trafficEvidence")} description={t("trafficEvidenceDesc")}><div className="surface rounded-[1.5rem] p-6"><CaseContextSelector value={activeCaseId} onChange={setActiveCaseId} /><div className="mt-5"><Progress value={currentCase?.analysisStatus?.progress ?? 15} /><p className="mt-3 text-sm text-muted">Loading traffic evidence for {activeCaseId}…</p></div></div></PageFrame>;
  }
  if (!packets.length && !sessions.length && !decodedProtocols.length && !payloadFindings.length) {
    return (
      <PageFrame title={t("trafficEvidence")} description={t("trafficEvidenceDesc")}>
        <div className="surface rounded-[1.5rem] p-5"><CaseContextSelector value={activeCaseId} onChange={setActiveCaseId} /></div>
        <div className="surface mx-auto flex max-w-2xl flex-col items-center gap-4 rounded-[1.5rem] p-8 text-center">
          <Database size={34} aria-hidden="true" />
          <div>
            <h2 className="text-xl font-black text-strong">No traffic evidence yet</h2>
            <p className="mt-2 text-sm leading-6 text-muted">{currentCase?.analysisStatus?.state === "completed" ? "Analysis completed without packet, session, protocol, or payload records for this case." : `${analysisStateLabel(currentCase?.analysisStatus?.state)}. Traffic records will appear after analysis produces them.`}</p>
          </div>
          <Button asChild><Link to={appViewRoute("upload")}><Upload size={16} />Add network evidence</Link></Button>
        </div>
      </PageFrame>
    );
  }
  return (
    <PageFrame title={t("trafficEvidence")} description={t("trafficEvidenceDesc")}>
      <div className="surface flex flex-wrap items-end justify-between gap-4 rounded-[1.5rem] p-5"><CaseContextSelector value={activeCaseId} onChange={setActiveCaseId} /><Badge>{analysisStateLabel(currentCase?.analysisStatus?.state)}</Badge></div>
      {loadError && <Alert>{loadError}</Alert>}
      <div className="grid gap-4 md:grid-cols-4">
        <MetricTile label="Packets" value={formatNumber(packets.length)} detail="Representative packet metadata" />
        <MetricTile label="Sessions" value={sessions.length} detail="Reconstructed conversations" />
        <MetricTile label="Protocols" value={decodedProtocols.length} detail={`Zeek ${zeek?.status ?? "not-run"}`} />
        <MetricTile label="Payload clues" value={payloadFindings.length} detail="Hidden-data and obfuscation indicators" />
      </div>
      <div className="surface rounded-[1.5rem] p-4">
        <div className="grid gap-3 md:grid-cols-4">
          <Input value={query} onChange={(event) => setQuery(event.target.value)} placeholder="Search IP, session, alert, protocol" />
          <Select value={protocol} onValueChange={setProtocol}>
            <SelectTrigger><SelectValue placeholder="Protocol" /></SelectTrigger>
            <SelectContent>{["all", "TCP", "UDP", "DNS", "HTTP", "TLS", "SSH", "FTP", "SMTP", "ICMP"].map((item) => <SelectItem key={item} value={item}>{item}</SelectItem>)}</SelectContent>
          </Select>
          <Input value={port} onChange={(event) => setPort(event.target.value)} placeholder="Port" />
          <Select value={severity} onValueChange={setSeverity}>
            <SelectTrigger><SelectValue placeholder="Severity" /></SelectTrigger>
            <SelectContent>{["all", "critical", "high", "medium", "low"].map((item) => <SelectItem key={item} value={item}>{item}</SelectItem>)}</SelectContent>
          </Select>
        </div>
        <p className="mt-3 text-xs leading-5 text-muted">These filters narrow the officer evidence view only. Use advanced drilldowns for raw packet inspection.</p>
      </div>
      <Tabs defaultValue="packets" className="flex flex-col gap-4">
        <TabsList className="w-fit flex-wrap">
          <TabsTrigger value="packets">Packets</TabsTrigger>
          <TabsTrigger value="sessions">Sessions</TabsTrigger>
          <TabsTrigger value="protocols">Protocols</TabsTrigger>
          <TabsTrigger value="payloads">Payload clues</TabsTrigger>
          <TabsTrigger value="map">Communication map</TabsTrigger>
        </TabsList>
        <TabsContent value="packets"><PacketEvidenceTable packets={filteredPackets.slice(0, 120)} /></TabsContent>
        <TabsContent value="sessions"><SessionEvidenceTable sessions={filteredSessions.slice(0, 120)} /></TabsContent>
        <TabsContent value="protocols"><ProtocolEvidenceTable protocols={filteredProtocols} zeek={zeek} /></TabsContent>
        <TabsContent value="payloads"><PayloadEvidenceTable findings={filteredPayloads} /></TabsContent>
        <TabsContent value="map"><FlowEvidenceTable flows={filteredFlows.slice(0, 120)} /></TabsContent>
      </Tabs>
    </PageFrame>
  );
}
