import { API_BASE } from "./ConsoleCore";
import { apiGet } from "./ConsoleCore";
import { BACKGROUND_ANALYSIS_REFRESH_MS } from "./ConsoleCore";
import { capabilityAvailable, type CapabilityMap } from "../../lib/capabilities";
import { createDefaultIntakeForm } from "./ConsoleCore";
import { DEFAULT_DEPLOYMENT_ACCESS } from "./ConsoleCore";
import { loadAnalysisData } from "./ConsoleCore";
import { NetraContext } from "./ConsoleCore";
import { netraHeaders } from "./ConsoleCore";
import { runBoundedEventStream } from "../../lib/eventStream";
import { SUPABASE_AUTH_ENABLED } from "../../lib/supabase";
import { toast } from "sonner";
import { translations } from "./ConsoleMessages";
import { type AccessLogRecord, type AlertRecord, type AnomalyRecord, type CaseRecord, type DashboardSummary, type DecodedProtocolRecord, type DetectionRuleMatch, type EvidenceFile, type EvidenceIntakeForm, type ExportRecord, type Language, type NetworkFlow, type PacketRecord, type PayloadFinding, type SessionRecord, type ZeekEvidence } from "../../lib/types";
import { type ActiveUploadWorkflow } from "./ConsoleCore";
import { type ComplianceRecord } from "./ConsoleCore";
import { type DeploymentAccess } from "./ConsoleCore";
import { type DeploymentModuleAccess } from "./ConsoleCore";
import { type DeploymentModuleKey } from "./ConsoleCore";
import { type ReactNode, useCallback, useEffect, useMemo, useRef, useState } from "react";
import { useAuth } from "../auth/AuthContext";

export function NetraProvider({ children }: { children: ReactNode }) {
  const { session, signOut: authSignOut } = useAuth();
  const [alertRecords, setAlertRecords] = useState<AlertRecord[]>([]);
  const [anomaliesState, setAnomaliesState] = useState<AnomalyRecord[]>([]);
  const [caseRecords, setCaseRecords] = useState<CaseRecord[]>([]);
  const [accessLogRecordsState, setAccessLogRecordsState] = useState<AccessLogRecord[]>([]);
  const [complianceRecordsState, setComplianceRecordsState] = useState<ComplianceRecord[]>([]);
  const [decodedProtocolsState, setDecodedProtocolsState] = useState<DecodedProtocolRecord[]>([]);
  const [detectionMatchesState, setDetectionMatchesState] = useState<DetectionRuleMatch[]>([]);
  const [evidenceState, setEvidenceState] = useState<EvidenceFile | null>(null);
  const [exportRecordsState, setExportRecordsState] = useState<ExportRecord[]>([]);
  const [intakeForm, setIntakeForm] = useState<EvidenceIntakeForm>(() => createDefaultIntakeForm());
  const [networkFlowsState, setNetworkFlowsState] = useState<NetworkFlow[]>([]);
  const [packetsState, setPacketsState] = useState<PacketRecord[]>([]);
  const [payloadFindingsState, setPayloadFindingsState] = useState<PayloadFinding[]>([]);
  const [protocolChartDataState, setProtocolChartDataState] = useState<{ name: string; value: number }[]>([]);
  const [sessionsState, setSessionsState] = useState<SessionRecord[]>([]);
  const [summaryState, setSummaryState] = useState<DashboardSummary>({
    packets: 0,
    sessions: 0,
    protocolsDecoded: 0,
    payloadFindings: 0,
    alerts: 0,
    anomalies: 0,
    topAttackClass: "Normal Baseline",
    riskLevel: "low",
    toolStatus: {},
  });
  const [trafficTimelineDataState, setTrafficTimelineDataState] = useState<{ time: string; mb: number; alerts: number }[]>([]);
  const [zeekState, setZeekState] = useState<ZeekEvidence | null>(null);
  const [activeCaseId, setActiveCaseIdState] = useState<string | null>(() => window.localStorage.getItem("netra-active-case"));
  const [activeUpload, setActiveUpload] = useState<ActiveUploadWorkflow | null>(null);
  const [deploymentAccess, setDeploymentAccess] = useState<DeploymentAccess>(DEFAULT_DEPLOYMENT_ACCESS);
  const [eventStreamAvailable, setEventStreamAvailable] = useState(
    () => document.visibilityState === "visible" && window.navigator.onLine,
  );
  const refreshTimerRef = useRef<number | null>(null);
  const [language, setLanguage] = useState<Language>(() => {
    const stored = window.localStorage.getItem("netra-language");
    return stored === "Hindi" || stored === "Gujarati" || stored === "English" ? stored : "English";
  });

  useEffect(() => {
    window.localStorage.setItem("netra-language", language);
  }, [language]);

  useEffect(() => {
    const updateAvailability = () => setEventStreamAvailable(document.visibilityState === "visible" && window.navigator.onLine);
    document.addEventListener("visibilitychange", updateAvailability);
    window.addEventListener("online", updateAvailability);
    window.addEventListener("offline", updateAvailability);
    return () => {
      document.removeEventListener("visibilitychange", updateAvailability);
      window.removeEventListener("online", updateAvailability);
      window.removeEventListener("offline", updateAvailability);
    };
  }, []);

  const refreshDeploymentAccess = useCallback(async () => {
    const payload = await apiGet<{
      user: string;
      department: string;
      role: string;
      capabilities: CapabilityMap;
      deployment: { profile: string; hostCaptureEnabled: boolean; replayEnabled: boolean; sensorCaptureEnabled: boolean; modules: Record<DeploymentModuleKey, DeploymentModuleAccess> };
    }>("/auth/me");
    setDeploymentAccess({
      verified: true,
      user: payload.user,
      department: payload.department,
      role: payload.role,
      profile: payload.deployment.profile,
      hostCaptureEnabled: payload.deployment.hostCaptureEnabled,
      replayEnabled: payload.deployment.replayEnabled,
      sensorCaptureEnabled: payload.deployment.sensorCaptureEnabled,
      capabilities: payload.capabilities ?? {},
      modules: payload.deployment.modules,
    });
  }, []);

  const setActiveCaseId = useCallback((caseId: string | null) => {
    setActiveCaseIdState(caseId);
    if (caseId) window.localStorage.setItem("netra-active-case", caseId);
    else window.localStorage.removeItem("netra-active-case");
  }, []);

  const reloadAnalysis = useCallback(async (caseIdOverride?: string | null) => {
    const requestedCaseId = caseIdOverride === undefined ? activeCaseId : caseIdOverride;
    const data = await loadAnalysisData(requestedCaseId);
    setAccessLogRecordsState(data.accessLogs);
    setComplianceRecordsState(data.complianceRecords);
    setAlertRecords(data.alerts);
    setAnomaliesState(data.anomalies);
    setCaseRecords(data.cases);
    setDecodedProtocolsState(data.decodedProtocols);
    setDetectionMatchesState(data.detectionMatches);
    setEvidenceState(data.evidence);
    setExportRecordsState(data.exports);
    setNetworkFlowsState(data.networkFlows);
    setPacketsState(data.packets);
    setPayloadFindingsState(data.payloadFindings);
    setProtocolChartDataState(data.protocolChartData);
    setSessionsState(data.sessions);
    setSummaryState(data.summary);
    setTrafficTimelineDataState(data.trafficTimelineData);
    setZeekState(data.zeek);
    if (data.selectedCaseId && data.selectedCaseId !== activeCaseId) {
      setActiveCaseId(data.selectedCaseId);
    }
  }, [activeCaseId, setActiveCaseId]);

  const scheduleRefresh = useCallback(() => {
    if (refreshTimerRef.current) window.clearTimeout(refreshTimerRef.current);
    refreshTimerRef.current = window.setTimeout(() => {
      reloadAnalysis().catch(() => undefined);
    }, 1500);
  }, [reloadAnalysis]);
  const activeCaseRouteRef = useMemo(
    () => caseRecords.find((record) => record.id === activeCaseId)?.routeRef ?? "",
    [activeCaseId, caseRecords],
  );

  useEffect(() => {
    const isProtectedAppRoute = window.location.pathname.startsWith("/app/") && window.location.pathname !== "/app/login";
    if (SUPABASE_AUTH_ENABLED && (!isProtectedAppRoute || !session?.access_token)) return;
    refreshDeploymentAccess().catch(() => setDeploymentAccess(DEFAULT_DEPLOYMENT_ACCESS));
    reloadAnalysis().catch(() => undefined);
  }, [refreshDeploymentAccess, reloadAnalysis, session?.access_token]);

  useEffect(() => {
    if (!session?.access_token) return undefined;
    const pollTimer = window.setInterval(() => {
      const isProtectedAppRoute = window.location.pathname.startsWith("/app/") && window.location.pathname !== "/app/login";
      if (document.visibilityState === "visible" && isProtectedAppRoute) scheduleRefresh();
    }, BACKGROUND_ANALYSIS_REFRESH_MS);
    return () => {
      window.clearInterval(pollTimer);
    };
  }, [scheduleRefresh, session?.access_token]);

  useEffect(() => {
    const isProtectedAppRoute = window.location.pathname.startsWith("/app/") && window.location.pathname !== "/app/login";
    if (
      !activeCaseRouteRef
      || !deploymentAccess.verified
      || !capabilityAvailable(deploymentAccess.capabilities, "sse")
      || !isProtectedAppRoute
      || !eventStreamAvailable
      || !session?.access_token
    ) return undefined;
    const controller = new AbortController();
    void runBoundedEventStream({
      url: `${API_BASE}/events/stream?caseRef=${encodeURIComponent(activeCaseRouteRef)}`,
      getAccessToken: () => session?.access_token ?? "",
      signal: controller.signal,
      onInvalidate: scheduleRefresh,
      onUnauthorized: () => {
        setDeploymentAccess(DEFAULT_DEPLOYMENT_ACCESS);
        void authSignOut();
      },
    });
    return () => {
      controller.abort();
    };
  }, [activeCaseRouteRef, authSignOut, deploymentAccess.capabilities, deploymentAccess.verified, eventStreamAvailable, scheduleRefresh, session?.access_token]);

  const addCaseNote = useCallback(
    (caseId: string, note: string) => {
      fetch(`${API_BASE}/cases/${caseId}/notes`, { method: "POST", headers: netraHeaders({ "Content-Type": "application/json" }), body: JSON.stringify({ note }) })
        .then(async (response) => {
          if (!response.ok) {
            const payload = await response.json().catch(() => ({}));
            toast.error(payload.error ?? "Could not save note");
          }
        })
        .catch(() => toast.error("Could not save note"));
      setCaseRecords((current) =>
        current.map((record) =>
          record.id === caseId
            ? {
                ...record,
                notes: [note, ...record.notes],
                history: [
                  {
                    id: `hist-note-${Date.now()}`,
                    timestamp: "Now",
                    actor: intakeForm.investigator,
                    action: translations[language].noteAction,
                    details: note,
                  },
                  ...record.history,
                ],
              }
            : record,
        ),
      );
      toast.success(translations[language].saveNote);
    },
    [intakeForm.investigator, language],
  );

  const value = useMemo(
    () => ({
      alertRecords,
      accessLogRecords: accessLogRecordsState,
      anomalies: anomaliesState,
      activeCaseId,
      caseRecords,
      decodedProtocols: decodedProtocolsState,
      detectionMatches: detectionMatchesState,
      evidence: evidenceState,
      exportRecords: exportRecordsState,
      intakeForm,
      language,
      networkFlows: networkFlowsState,
      packets: packetsState,
      payloadFindings: payloadFindingsState,
      protocolChartData: protocolChartDataState,
      reloadAnalysis,
      sessions: sessionsState,
      summary: summaryState,
      trafficTimelineData: trafficTimelineDataState,
      zeek: zeekState,
      complianceRecords: complianceRecordsState,
      deploymentAccess,
      t: (key: string) => translations[language][key] ?? key,
      setLanguage,
      setIntakeForm,
      setActiveCaseId,
      addCaseNote,
      activeUpload,
      setActiveUpload,
    }),
    [accessLogRecordsState, activeCaseId, activeUpload, addCaseNote, alertRecords, anomaliesState, caseRecords, complianceRecordsState, decodedProtocolsState, deploymentAccess, detectionMatchesState, evidenceState, exportRecordsState, intakeForm, language, networkFlowsState, packetsState, payloadFindingsState, protocolChartDataState, reloadAnalysis, sessionsState, summaryState, trafficTimelineDataState, setActiveCaseId, zeekState],
  );

  return <NetraContext.Provider value={value}>{children}</NetraContext.Provider>;
}
