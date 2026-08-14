import { createContext, type Dispatch, type SetStateAction, useContext } from "react";
import { ensureCurrentAccessToken, getCurrentAccessToken, SUPABASE_AUTH_ENABLED } from "../../lib/supabase";
import { type AccessLogRecord, type AlertRecord, type AnalysisStatus, type AnomalyRecord, type AttackClass, type CaseRecord, type CaseWorkspaceRecord, type DashboardSummary, type DecodedProtocolRecord, type DetectionRuleMatch, type EvidenceFile, type EvidenceIntakeForm, type ExportRecord, type Language, type NetworkFlow, type PacketRecord, type PayloadFinding, type SessionRecord, type ZeekEvidence } from "../../lib/types";
import { type CapabilityMap } from "../../lib/capabilities";

export type Dict = Record<string, string>;

export type ComplianceRecord = { item: string; status: string; detail: string };

export const VIEW_REFS = {
  upload: "7b9914d4-53ef-482f-9f85-9cc5cf17bf69",
  overview: "7cab94c3-622f-46b0-b3e4-7e8ea6df0831",
  activity: "1310f49a-114e-4c91-ae05-587c23f65dc9",
  evidence: "1b438ac1-72e9-4413-a28d-cc87ea35ab54",
  reports: "dca32a39-8348-4f14-b62a-fdba9987e234",
  packets: "fd194142-3050-41dc-938c-1250cc494ca4",
  sessions: "7655d88f-d7b9-40cb-86fa-53b7b6129229",
  decoder: "d8caac3c-b968-4421-9009-658a6073ced6",
  payloads: "301d2ced-af42-4548-b874-7c366d72dc69",
  detection: "67c443d2-77c3-44d5-a600-cd5a75f2b78f",
  aiAnomaly: "6bb1857c-2064-484e-9762-624ca850d238",
  graph: "0ec62c3f-47b7-4638-a452-a25a688d41f3",
  cases: "14e61a2b-40b2-4c73-bd5c-d75b832322ad",
  exports: "53f8cbfa-e55f-4406-b83b-d19f8d491455",
  lab: "e7e7d465-e28f-474d-959a-e12136db52aa",
  compliance: "d5bb3600-c3bb-4279-bd02-cb8025d10fc9",
  settings: "4c1bed57-4a3b-4c98-a7ee-778b5500eb91",
  technicalStatus: "9f26eb92-724c-4c78-98d4-672f111c7a96",
  sensors: "b65a8685-7123-4133-8b1d-b23c85bd568c",
  schedules: "ad7da1a0-e32c-43db-af37-ed6ec02ba7ac",
  integrations: "9d11e611-5ad8-4e39-8aa0-1ba5ca622bbe",
  retention: "dd7f47ca-7efc-41ca-9972-e0132292208b",
} as const;

export type ViewName = keyof typeof VIEW_REFS;

export const appViewRoute = (view: ViewName) => `/app/v/${VIEW_REFS[view]}`;

export const caseWorkspaceRoute = (routeRef: string) => `/app/w/${routeRef}`;

export type ActiveUploadWorkflow = {
  caseId: string;
  routeRef: string;
  filename: string;
  sizeBytes: number;
  uploadSessionId?: string;
  jobId?: string;
  state: AnalysisStatus["state"];
  progress: number;
  bytesUploaded: number;
  speedBytesPerSecond: number;
  step: string;
  steps: { name: string; status: string }[];
  error?: string;
};

export type AppState = {
  alertRecords: AlertRecord[];
  anomalies: AnomalyRecord[];
  caseRecords: CaseRecord[];
  decodedProtocols: DecodedProtocolRecord[];
  detectionMatches: DetectionRuleMatch[];
  evidence: EvidenceFile | null;
  intakeForm: EvidenceIntakeForm;
  language: Language;
  networkFlows: NetworkFlow[];
  packets: PacketRecord[];
  payloadFindings: PayloadFinding[];
  protocolChartData: { name: string; value: number }[];
  reloadAnalysis: (caseIdOverride?: string | null) => Promise<void>;
  sessions: SessionRecord[];
  summary: DashboardSummary;
  trafficTimelineData: { time: string; mb: number; alerts: number }[];
  zeek: ZeekEvidence | null;
  t: (key: string) => string;
  setLanguage: (language: Language) => void;
  setIntakeForm: (form: EvidenceIntakeForm) => void;
  addCaseNote: (caseId: string, note: string) => void;
  activeCaseId: string | null;
  setActiveCaseId: (caseId: string | null) => void;
  accessLogRecords: AccessLogRecord[];
  complianceRecords: ComplianceRecord[];
  exportRecords: ExportRecord[];
  deploymentAccess: DeploymentAccess;
  activeUpload: ActiveUploadWorkflow | null;
  setActiveUpload: Dispatch<SetStateAction<ActiveUploadWorkflow | null>>;
};

export type DeploymentModuleKey = "lab" | "sensors" | "schedules" | "integrations" | "retention" | "system";

export type DeploymentModuleAccess = { enabled: boolean; visible: boolean; reason: string };

export type DeploymentAccess = {
  verified: boolean;
  user: string;
  department: string;
  role: string;
  profile: string;
  hostCaptureEnabled: boolean;
  replayEnabled: boolean;
  sensorCaptureEnabled: boolean;
  capabilities: CapabilityMap;
  modules: Record<DeploymentModuleKey, DeploymentModuleAccess>;
};

export const DEFAULT_DEPLOYMENT_ACCESS: DeploymentAccess = {
  verified: false,
  user: "",
  department: "",
  role: "Viewer",
  profile: import.meta.env.VITE_DEPLOYMENT_PROFILE ?? "local",
  hostCaptureEnabled: false,
  replayEnabled: false,
  sensorCaptureEnabled: false,
  capabilities: {},
  modules: {
    lab: { enabled: false, visible: false, reason: "Lab access has not been verified." },
    sensors: { enabled: false, visible: false, reason: "Sensor access has not been verified." },
    schedules: { enabled: false, visible: false, reason: "Scheduling access has not been verified." },
    integrations: { enabled: false, visible: false, reason: "Integration access has not been verified." },
    retention: { enabled: false, visible: false, reason: "Retention access has not been verified." },
    system: { enabled: false, visible: false, reason: "Administrator access has not been verified." },
  },
};

export const NetraContext = createContext<AppState | null>(null);

export const API_BASE = import.meta.env.VITE_API_BASE_URL ?? "/api";

export const DEPLOYMENT_PROFILE = import.meta.env.VITE_DEPLOYMENT_PROFILE ?? "local";

export const HACKATHON_CORE = DEPLOYMENT_PROFILE === "hackathon-core";

export const BPF_FILTER_ENABLED = import.meta.env.VITE_BPF_FILTER_ENABLED === "1";

export const DIRECT_UPLOAD_ENABLED = import.meta.env.VITE_DIRECT_UPLOAD_ENABLED === "1";

export const MAX_UPLOAD_MB = Math.max(1, Number(import.meta.env.VITE_MAX_UPLOAD_MB ?? (HACKATHON_CORE ? 25 : 500)) || 25);

export const ACTIVE_UPLOAD_JOB_KEY = "netra-active-upload-job";

export const EVIDENCE_TYPE_OPTIONS: EvidenceIntakeForm["evidenceType"][] = ["Auto-detect", "PCAP", "Firewall Logs", "DNS Logs", "TLS Metadata", "Mixed Evidence"];

export const CASE_FLAG_OPTIONS = ["urgent", "ransomware", "insider-threat", "exfiltration", "related-case", "needs-review", "synthetic", "release-gate"] as const;

export const NORMALIZATION_PREVIEW_BYTES = 64 * 1024;

export const EVIDENCE_EXTENSIONS: Record<EvidenceIntakeForm["evidenceType"], string[]> = {
  "Auto-detect": [".pcap", ".pcapng", ".log", ".txt", ".csv", ".json", ".ndjson", ".zip"],
  PCAP: [".pcap", ".pcapng"],
  "Firewall Logs": [".log", ".txt", ".csv", ".json", ".ndjson"],
  "DNS Logs": [".log", ".txt", ".csv", ".json", ".ndjson"],
  "TLS Metadata": [".log", ".txt", ".csv", ".json", ".ndjson"],
  "Mixed Evidence": [".zip", ".json", ".csv"],
};

export type EvidenceNormalizationPreview = {
  code?: string;
  selectedType: string;
  detectedType: string;
  normalizedType: string;
  recommendedType: string;
  validForSelectedType: boolean;
  valid: boolean;
  extensionAllowed?: boolean;
  allowedExtensions?: string[];
  confidence: number;
  parser: string;
  reason: string;
  message: string;
  signals: string[];
  features?: { extension?: string; magicType?: string; lineFormat?: string | null; sampleSignals?: string[] };
};

export type UploadStage = "idle" | "uploading" | "processing" | "queued" | "complete" | "failed";

export type UploadTransferState = {
  bytesUploaded: number;
  speedBytesPerSecond: number;
  etaSeconds: number | null;
  paused: boolean;
  retryAttempt: number;
  message: string;
};

export type EvidenceUploadPayload = Partial<EvidenceNormalizationPreview> & {
  error?: string;
  reason?: string;
  caseId?: string;
  routeRef?: string;
  status?: string;
  sha256?: string;
  encrypted_sha256?: string;
  keyId?: string;
  jobId?: string;
  job?: { steps?: { name: string; status: string }[] };
  detectedAttackClasses?: string[];
  riskLevel?: string;
  analysis?: {
    packets?: number;
    sessions?: number;
    protocolsDecoded?: number;
    payloadFindings?: number;
    alerts?: number;
  };
};

export type UploadResult = {
  topClass?: string;
  risk?: string;
  hash?: string;
  encryptedHash?: string;
  keyId?: string;
  jobId?: string;
  filename?: string;
  packets?: number;
  sessions?: number;
  protocolsDecoded?: number;
  payloadFindings?: number;
  alerts?: number;
  steps?: { name: string; status: string }[];
};

export function formatEta(seconds: number | null) {
  if (seconds === null || !Number.isFinite(seconds)) return "calculating ETA";
  const whole = Math.max(0, Math.round(seconds));
  if (whole < 60) return `${whole}s remaining`;
  const minutes = Math.floor(whole / 60);
  const remainder = whole % 60;
  return `${minutes}m ${remainder}s remaining`;
}

export function uploadFormWithProgress<T>(path: string, form: FormData, onProgress: (percent: number) => void, onUploaded: () => void) {
  return new Promise<{ ok: boolean; status: number; payload: T }>((resolve, reject) => {
    const request = new XMLHttpRequest();
    request.open("POST", `${API_BASE}${path}`);
    new Headers(netraHeaders()).forEach((value, name) => request.setRequestHeader(name, value));
    request.timeout = 240_000;
    request.upload.onprogress = (event) => {
      if (event.lengthComputable && event.total > 0) onProgress(Math.min(100, Math.round((event.loaded / event.total) * 100)));
    };
    request.upload.onload = () => {
      onProgress(100);
      onUploaded();
    };
    request.onload = () => {
      try {
        resolve({ ok: request.status >= 200 && request.status < 300, status: request.status, payload: JSON.parse(request.responseText) as T });
      } catch {
        reject(new Error(`Upload returned an unreadable response (${request.status || "network error"}).`));
      }
    };
    request.onerror = () => reject(new Error("Upload failed before the server responded."));
    request.ontimeout = () => reject(new Error("Upload timed out while the server was processing the evidence."));
    request.send(form);
  });
}

export function createDefaultIntakeForm(): EvidenceIntakeForm {
  const now = new Date();
  const suffix = now.toISOString().replace(/\D/g, "").slice(2, 12);
  return {
    caseNumber: `CYB-GJ-${suffix}`,
    investigator: "",
    department: "",
    evidenceType: "Auto-detect",
    sourceLocation: "",
    priority: "",
    remarks: "",
    flags: [],
    linkedCaseIds: [],
    sourceIp: "",
    destinationIp: "",
    protocol: "",
    port: "",
    durationSeconds: "",
    packetLimit: "5000",
    bpfFilter: "",
  };
}

export function allowedExtensionsForType(type: EvidenceIntakeForm["evidenceType"]) {
  return EVIDENCE_EXTENSIONS[type] ?? EVIDENCE_EXTENSIONS["Auto-detect"];
}

export function acceptForEvidenceType(type: EvidenceIntakeForm["evidenceType"]) {
  return allowedExtensionsForType(type).join(",");
}

export function evidenceTypeHelper(type: EvidenceIntakeForm["evidenceType"]) {
  return `Allowed for ${type}: ${allowedExtensionsForType(type).join(", ")}`;
}

export function fileExtension(file: File) {
  return file.name.includes(".") ? `.${file.name.split(".").pop()?.toLowerCase()}` : "";
}

export function fileExtensionAllowed(file: File, type: EvidenceIntakeForm["evidenceType"]) {
  return allowedExtensionsForType(type).includes(fileExtension(file));
}

export function localNormalizationPreview(file: File, selectedType: EvidenceIntakeForm["evidenceType"]): EvidenceNormalizationPreview {
  const extension = fileExtension(file);
  const allowedExtensions = allowedExtensionsForType(selectedType);
  const extensionAllowed = allowedExtensions.includes(extension);
  if (!extensionAllowed) {
    return {
      code: "unsupported_evidence_extension",
      selectedType,
      detectedType: "Unknown",
      normalizedType: "Unknown",
      recommendedType: selectedType,
      validForSelectedType: false,
      valid: false,
      extensionAllowed: false,
      allowedExtensions,
      confidence: 0,
      parser: "none",
      reason: `Unsupported file type ${extension || "(none)"}. ${evidenceTypeHelper(selectedType)}.`,
      message: "Choose another file or change the evidence type.",
      signals: extension ? [`unsupported-extension:${extension}`] : ["unsupported-extension:(none)"],
      features: { extension, sampleSignals: extension ? [`unsupported-extension:${extension}`] : ["unsupported-extension:(none)"] },
    };
  }
  const detectedType = extension === ".pcap" || extension === ".pcapng" ? "PCAP" : extension === ".zip" ? "Mixed Evidence" : extension === ".json" || extension === ".csv" || extension === ".log" || extension === ".txt" || extension === ".ndjson" ? "Unknown" : "Unknown";
  const normalizedType = detectedType === "Unknown" && selectedType !== "Auto-detect" ? selectedType : detectedType;
  const valid = selectedType === "Auto-detect" ? detectedType !== "Unknown" : detectedType !== "Unknown" && selectedType === detectedType;
  return {
    selectedType,
    detectedType,
    normalizedType,
    recommendedType: normalizedType,
    validForSelectedType: valid,
    valid,
    extensionAllowed: true,
    allowedExtensions,
    confidence: detectedType === "PCAP" ? 70 : 20,
    parser: detectedType === "PCAP" ? "pcap" : "unknown",
    reason: detectedType === "PCAP" ? "Local extension preview suggests PCAP. Backend will verify magic bytes before analysis." : "Backend normalization will inspect this file before analysis.",
    message: detectedType === "PCAP" ? "Local extension preview suggests PCAP. Backend will verify magic bytes before analysis." : "Backend normalization will inspect this file before analysis.",
    signals: extension ? [`extension:${extension}`] : [],
    features: { extension, sampleSignals: extension ? [`extension:${extension}`] : [] },
  };
}

export async function apiGet<T>(path: string): Promise<T> {
  if (SUPABASE_AUTH_ENABLED && !getCurrentAccessToken()) {
    const token = await ensureCurrentAccessToken();
    if (!token) throw new Error(`API ${path} requires an authenticated session`);
  }
  const response = await fetch(`${API_BASE}${path}`, { headers: netraHeaders() });
  if (!response.ok) throw new Error(`API ${path} failed with ${response.status}`);
  return response.json() as Promise<T>;
}

export const WORKSPACE_CACHE_TTL_MS = 15_000;

export const BACKGROUND_ANALYSIS_REFRESH_MS = 5 * 60_000;

export const TECHNICAL_STATUS_REFRESH_MS = 60_000;

export const workspaceResponseCache = new Map<string, { expiresAt: number; request: Promise<CaseWorkspaceRecord> }>();

export let workspaceCacheAuthToken = "";

export function apiWorkspace(routeRef: string, force = false): Promise<CaseWorkspaceRecord> {
  const authToken = getCurrentAccessToken() ?? "";
  if (workspaceCacheAuthToken !== authToken) {
    workspaceResponseCache.clear();
    workspaceCacheAuthToken = authToken;
  }
  if (force) workspaceResponseCache.delete(routeRef);
  const cached = workspaceResponseCache.get(routeRef);
  if (cached && cached.expiresAt > Date.now()) return cached.request;
  const request = apiGet<CaseWorkspaceRecord>(`/workspaces/${routeRef}`).catch((error) => {
    workspaceResponseCache.delete(routeRef);
    throw error;
  });
  workspaceResponseCache.set(routeRef, { expiresAt: Date.now() + WORKSPACE_CACHE_TTL_MS, request });
  return request;
}

export function netraHeaders(extra?: HeadersInit): HeadersInit {
  const token = getCurrentAccessToken();
  const contextId = window.sessionStorage.getItem("netra-console-context-id") ?? "";
  return {
    ...(extra ?? {}),
    ...(token ? { Authorization: `Bearer ${token}` } : {}),
    ...(contextId ? { "X-Netra-Context-ID": contextId } : {}),
  };
}

export async function downloadApiFile(path: string, fallbackFilename: string) {
  const normalizedPath = path.startsWith(`${API_BASE}/`)
    ? path.slice(API_BASE.length)
    : path.startsWith("/api/")
      ? path.slice(4)
      : path;
  const response = await fetch(`${API_BASE}${normalizedPath.startsWith("/") ? normalizedPath : `/${normalizedPath}`}`, { headers: netraHeaders() });
  if (!response.ok) {
    const payload = await response.json().catch(() => ({}));
    throw new Error(payload.error ?? `Download failed with ${response.status}`);
  }
  const blob = await response.blob();
  const disposition = response.headers.get("Content-Disposition") ?? "";
  const match = disposition.match(/filename="?([^"]+)"?/i);
  const filename = match?.[1] || fallbackFilename;
  const url = window.URL.createObjectURL(blob);
  const anchor = document.createElement("a");
  anchor.href = url;
  anchor.download = filename;
  document.body.appendChild(anchor);
  anchor.click();
  anchor.remove();
  window.URL.revokeObjectURL(url);
}

export function graphEdgesToFlows(graphResponse: { edges?: { source: string; target: string; protocol: string; packets: number; bytes?: number; risk?: number; attackClass?: AttackClass; alertIds?: string[] }[] }): NetworkFlow[] {
  return (graphResponse.edges ?? []).map((edge, index) => ({
    id: `flow-${index + 1}`,
    source: edge.source,
    target: edge.target,
    protocol: edge.protocol,
    bytes: edge.bytes ?? 0,
    packets: edge.packets,
    suspicious: Boolean(edge.alertIds?.length),
    attackClass: edge.attackClass ?? ("Normal Baseline" as AttackClass),
    alertIds: edge.alertIds ?? [],
    risk: edge.risk ?? 0,
  }));
}

export async function loadAnalysisData(activeCaseId: string | null) {
  const casesResponse = await apiGet<{ results: CaseRecord[] }>("/cases?limit=100");
  const selectedCaseId = (activeCaseId && casesResponse.results.some((record) => record.id === activeCaseId) ? activeCaseId : casesResponse.results[0]?.id) ?? null;
  const selectedCase = casesResponse.results.find((record) => record.id === selectedCaseId);
  const workspaceResponse = selectedCase?.routeRef ? await apiWorkspace(selectedCase.routeRef) : null;
  const workspace = workspaceResponse?.workspace;
  const summaryResponse = workspace?.summary ?? {
    packets: 0,
    sessions: 0,
    protocolsDecoded: 0,
    payloadFindings: 0,
    alerts: 0,
    anomalies: 0,
    topAttackClass: "Normal Baseline" as AttackClass,
    riskLevel: "low" as const,
    toolStatus: {},
  };
  return {
    cases: casesResponse.results,
    selectedCaseId,
    evidence: workspace?.evidence ?? null,
    summary: summaryResponse,
    zeek: summaryResponse.zeek ?? null,
    packets: workspace?.trafficEvidence.packetsPreview ?? [] as PacketRecord[],
    sessions: workspace?.trafficEvidence.sessionsPreview ?? [] as SessionRecord[],
    alerts: workspace?.suspiciousActivity.alerts ?? [] as AlertRecord[],
    decodedProtocols: workspace?.trafficEvidence.protocols ?? [] as DecodedProtocolRecord[],
    payloadFindings: workspace?.trafficEvidence.payloadClues ?? [] as PayloadFinding[],
    detectionMatches: [] as DetectionRuleMatch[],
    anomalies: workspace?.suspiciousActivity.anomalies ?? [] as AnomalyRecord[],
    trafficTimelineData: (workspace?.charts.timeline ?? []).map((row) => ({ time: row.time, mb: row.mb ?? 0, alerts: row.alerts ?? 0 })),
    protocolChartData: workspace?.charts.protocols ?? [] as { name: string; value: number }[],
    exports: [] as ExportRecord[],
    accessLogs: [] as AccessLogRecord[],
    complianceRecords: [] as ComplianceRecord[],
    networkFlows: workspace ? graphEdgesToFlows(workspace.trafficEvidence.communicationMap) : [] as NetworkFlow[],
  };
}

export function useNetra() {
  const value = useContext(NetraContext);
  if (!value) throw new Error("useNetra must be used inside NetraProvider");
  return value;
}
