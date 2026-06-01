export type Severity = "low" | "medium" | "high" | "critical";

export type Language = "English" | "Hindi" | "Gujarati";

export type AttackClass =
  | "Normal Baseline"
  | "Credential Brute Force"
  | "IoT Botnet / Scanning"
  | "Malware C2 / Beaconing"
  | "ICMP Tunnel"
  | "Data Exfiltration"
  | "Port Scan / Reconnaissance"
  | "Service Exploitation"
  | "Web Service Exploitation"
  | "Remote Command Execution"
  | "SMB / NetBIOS Lateral Movement"
  | "Suspicious SMTP Transfer"
  | "Malware / APT Behavior"
  | "Unknown Exploit / High Anomaly"
  | "Java RMI Exploitation"
  | "Ruby DRb Exploitation"
  | "IRC Service Backdoor"
  | "Replay / Repeated Traffic Pattern"
  | "Unknown High-risk Anomaly"
  | "Exfiltration"
  | "Beaconing"
  | "DNS Tunnel"
  | "Malware C2"
  | "Port Scan";

export type ToolStatus = {
  scapy?: boolean;
  tshark?: boolean;
  zeek?: boolean;
};

export type ZeekSummary = {
  connections?: number;
  dnsQueries?: number;
  httpRequests?: number;
  tlsSessions?: number;
  sshSessions?: number;
  notices?: number;
  weirdEvents?: number;
};

export type ZeekEvidence = {
  status: string;
  logDir?: string;
  logs: string[];
  summary: ZeekSummary;
  topServices?: { service: string; count: number }[];
  topDnsQueries?: { value: string; count: number }[];
  topExternalHosts?: { host: string; count: number }[];
  error?: string;
};

export type DashboardSummary = {
  packets: number;
  sessions: number;
  protocolsDecoded: number;
  payloadFindings: number;
  alerts: number;
  anomalies?: number;
  topAttackClass: AttackClass;
  detectedAttackClasses?: AttackClass[];
  riskLevel: "low" | "medium" | "high" | "critical";
  toolStatus: ToolStatus;
  zeek?: ZeekEvidence;
};

export type EvidenceFile = {
  id: string;
  filename: string;
  size: string;
  sha256: string;
  plaintextSha256?: string;
  encryptedSha256?: string;
  manifestHash?: string;
  keyId?: string;
  uploadedAt: string;
  capturedAt: string;
  investigator: string;
  status: "verified" | "processing" | "failed";
};

export type EvidenceIntakeForm = {
  caseNumber: string;
  investigator: string;
  department: string;
  evidenceType: "PCAP" | "Firewall Logs" | "DNS Logs" | "TLS Metadata" | "Mixed Evidence";
  sourceLocation: string;
  priority: "Standard" | "Urgent" | "Critical";
  remarks: string;
  sourceIp: string;
  destinationIp: string;
  protocol: string;
  port: string;
  durationSeconds: string;
  packetLimit: string;
  bpfFilter: string;
};

export type AlertRecord = {
  id: string;
  severity: Severity;
  attackClass: AttackClass;
  type: string;
  sourceIp: string;
  destination: string;
  protocol: string;
  timestamp: string;
  confidence: number;
  status: "new" | "reviewing" | "confirmed" | "dismissed";
  ruleId?: string;
  evidencePacketIds?: string[];
  evidenceSessionIds?: string[];
  explanation?: string;
  recommendedAction?: string;
  detectorType?: string;
  observedSignals?: string[];
  confidenceFactors?: { signal: string; weight: number }[];
  limitations?: string;
};

export type NetworkFlow = {
  id: string;
  source: string;
  target: string;
  protocol: string;
  bytes: number;
  packets: number;
  suspicious: boolean;
  attackClass: AttackClass;
  alertIds: string[];
  risk?: number;
};

export type CaseRecord = {
  id: string;
  title: string;
  investigator: string;
  status: "open" | "reviewing" | "report-ready";
  evidenceFileId: string;
  alertIds: string[];
  notes: string[];
  history: CaseHistoryEvent[];
  createdAt: string;
  reportStatus: "draft" | "ready";
};

export type CaseHistoryEvent = {
  id: string;
  timestamp: string;
  actor: string;
  action: string;
  details: string;
};

export type TimelineEvent = {
  time: string;
  label: string;
  severity: Severity;
};

export type PacketRecord = {
  id: string;
  timestamp: string;
  sourceIp: string;
  destinationIp: string;
  sourcePort: number;
  destinationPort: number;
  protocol: string;
  size: number;
  flags: string;
  sessionId: string;
  riskScore: number;
  severity: Severity;
  hexPreview: string;
  asciiPreview: string;
  decodedSummary: string;
  relatedAlertId?: string;
};

export type DecodedProtocolRecord = {
  protocol: string;
  packetCount: number;
  sessionCount: number;
  suspiciousCount: number;
  status: "decoded" | "metadata-only" | "partial";
  topDestination: string;
  detail: string;
};

export type PayloadFinding = {
  id: string;
  packetId: string;
  sessionId: string;
  protocol: string;
  payloadType: string;
  entropyScore: number;
  hiddenData: boolean;
  obfuscated: boolean;
  matchedPattern: string;
  risk: Severity;
  textPreview: string;
  hexPreview: string;
  extractedStrings: string[];
};

export type SessionRecord = {
  id: string;
  source: string;
  destination: string;
  protocol: string;
  startTime: string;
  endTime: string;
  duration: string;
  bytesSent: number;
  bytesReceived: number;
  packetCount: number;
  riskScore: number;
  relatedAlertIds: string[];
};

export type DetectionRuleMatch = {
  id: string;
  ruleId?: string;
  ruleName: string;
  category: string;
  attackClass?: AttackClass;
  matchedEntity: string;
  confidence: number;
  status: "new" | "reviewing" | "confirmed";
  evidencePacketIds?: string[];
  evidenceSessionIds?: string[];
  explanation?: string;
  recommendedAction?: string;
};

export type AnomalyRecord = {
  id: string;
  entity: string;
  behaviour: string;
  baseline: string;
  observed: string;
  deviation: string;
  confidence: number;
  hypothesis: string;
  topFeatures?: string[];
  recommendedAction?: string;
};

export type ExportRecord = {
  id: string;
  type: string;
  caseId: string;
  requestedBy: string;
  timestamp: string;
  hash: string;
  status: string;
};

export type IntegrationRecord = {
  id?: string | number;
  system: string;
  status: string;
  lastSync: string;
  linkedCases: number;
  apiMode: string;
};

export type SensorRecord = {
  id: string;
  name: string;
  hostname: string;
  platform: string;
  agentVersion: string;
  captureEngine: string;
  captureEngineVersion?: string;
  status: "online" | "stale" | "offline" | "warning" | "capturing" | "disabled";
  lastHeartbeatAt?: string;
  heartbeatAgeSeconds?: number;
  interfaces: { index: string; name: string; label: string }[];
  groupId?: number | null;
  groupName?: string;
  location?: string;
  tags?: string[];
  notes?: string;
  enabled?: boolean;
  currentCaptureJob?: string;
  totalChunksUploaded?: number;
  totalBytesUploaded?: number;
};

export type SensorGroupRecord = { id: number; name: string; description: string; color: string; sensorCount: number };

export type CaptureScheduleRecord = {
  id: number;
  name: string;
  sensorId: string;
  sensorName: string;
  enabled: boolean;
  scheduleType: "one-time" | "daily" | "weekly";
  startAt: string;
  timezone: string;
  durationSeconds: number;
  packetLimit: number;
  chunkIntervalSeconds: number;
  interfaceName: string;
  bpfFilter: string;
  caseIdPrefix: string;
  lastRunAt?: string;
  nextRunAt?: string;
  lastJobId?: string;
};

export type CapacityRecord = {
  status: string;
  kafka: { lag: number; warningThreshold: number; criticalThreshold: number };
  storage: { usedBytes: number; freeBytes: number; totalBytes: number; usedPercent: number };
  search: { indexedDocuments: number; failedBulkRequests: number };
  sensors: { total: number; online: number; capturing: number; offline: number };
};

export type CaptureJobRecord = {
  jobId: string;
  caseId: string;
  status: string;
  mode: "stored_pcap" | "replay" | "live_capture" | "log_import";
  source: string;
  packetsReceived: number;
  chunksReceived: number;
  progress: number;
  startedAt?: string;
  completedAt?: string;
  finalEvidenceId?: string;
};

export type OperationalEventRecord = {
  id: number;
  eventType: string;
  caseId: string;
  captureJobId?: string;
  payload: Record<string, unknown>;
  createdAt: string;
};

export type AccessLogRecord = {
  timestamp: string;
  user: string;
  role: "Admin" | "Investigator" | "Analyst" | "Viewer" | "LAN Operator";
  action: string;
  caseId: string;
  result: "allowed" | "review" | "denied";
};

export type ComplianceChecklistItem = {
  item: string;
  status: string;
  detail: string;
};
