import "@xyflow/react/dist/style.css";
import { Background, Controls, MiniMap, ReactFlow, type Edge, type Node, type NodeMouseHandler } from "@xyflow/react";
import {
  Activity,
  AlertTriangle,
  Database,
  Download,
  FileSearch,
  FileText,
  Fingerprint,
  History,
  Languages,
  Menu,
  PanelLeftClose,
  PanelLeftOpen,
  Search,
  Settings as SettingsIcon,
  Upload,
  UploadCloud,
  type LucideIcon,
} from "lucide-react";
import { AnimatePresence, motion } from "framer-motion";
import { createContext, useCallback, useContext, useEffect, useMemo, useRef, useState, type FormEvent, type ReactNode } from "react";
import { BrowserRouter as Router, Link, Navigate, NavLink, Route, Routes, useLocation, useNavigate, useParams } from "react-router-dom";
import {
  Area,
  AreaChart,
  CartesianGrid,
  ResponsiveContainer,
  Tooltip as ChartTooltip,
  XAxis,
  YAxis,
} from "recharts";
import { toast, Toaster } from "sonner";
import {
  Alert,
  Badge,
  Button,
  Dialog,
  DialogContent,
  DialogTitle,
  DialogTrigger,
  Input,
  Progress,
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
  Sheet,
  SheetContent,
  SheetTitle,
  Switch,
  Tabs,
  TabsContent,
  TabsList,
  TabsTrigger,
  Textarea,
  TooltipProvider,
} from "./components/ui/primitives";
import type {
  AlertRecord,
  AccessLogRecord,
  AnomalyRecord,
  AttackClass,
  CaseChartsRecord,
  CaseRecord,
  CaseWorkspaceRecord,
  DashboardSummary,
  DecodedProtocolRecord,
  DetectionRuleMatch,
  EvidenceFile,
  EvidenceIntakeForm,
  ExportRecord,
  IntegrationRecord,
  Language,
  NetworkFlow,
  PacketRecord,
  PayloadFinding,
  SessionRecord,
  Severity,
  SensorRecord,
  CaptureJobRecord,
  CaptureScheduleRecord,
  CapacityRecord,
  ReportRecord,
  SensorGroupRecord,
  ZeekEvidence,
} from "./lib/types";
import { ensureCurrentAccessToken, getCurrentAccessToken, refreshStoredSupabaseSession, setCurrentAccessToken, supabase, SUPABASE_AUTH_ENABLED, SUPABASE_REALTIME_ENABLED } from "./lib/supabase";
import { beginResumableUpload, type DirectUploadSession, type ResumableUploadHandle } from "./lib/resumableUpload";
import { cn, formatBytes, formatNumber } from "./lib/utils";
import {
  PublicAboutPage,
  PublicContactPage,
  PublicHomePage,
  PublicNotFoundPage,
  PublicPrivacyPage,
  PublicTermsPage,
  PublicUpdatesPage,
} from "./public/PublicSite";

type Dict = Record<string, string>;
type ComplianceRecord = { item: string; status: string; detail: string };

const en: Dict = {
  viewDemo: "Open Investigation Console",
  startInvestigation: "Open Evidence Intake",
  exploreWorkflow: "Explore Workflow",
  workflow: "Workflow",
  capabilities: "Capabilities",
  demo: "Demo",
  reports: "Reports",
  capture: "Capture",
  analysis: "Analysis",
  investigation: "Investigation",
  governance: "Governance",
  mainWorkflow: "Workflow",
  advancedTools: "Advanced",
  caseOverview: "Case Overview",
  suspiciousActivity: "Suspicious Activity",
  trafficEvidence: "Traffic Evidence",
  evidenceReport: "Evidence Report",
  systemTools: "Technical Status",
  caseOverviewDesc: "A plain-language summary of the active investigation, risk, alerts, traffic volume, and next steps.",
  suspiciousActivityDesc: "All confirmed and AI-assisted suspicious findings in one investigator-friendly review queue.",
  trafficEvidenceDesc: "Packets, sessions, decoded protocols, and payload clues grouped as evidence tabs.",
  evidenceReportDesc: "Generate legal-ready reports, exports, custody records, and evidence integrity summaries.",
  packetExplorer: "Packet Explorer",
  sessions: "Sessions",
  protocolDecoder: "Protocol Decoder",
  payloadInspection: "Payload Inspection",
  threatDetection: "Threat Detection",
  aiAnomaly: "AI Anomaly",
  exportCenter: "Export Center",
  integrations: "Integrations",
  compliance: "Compliance",
  evidenceIntake: "Evidence Intake",
  dashboard: "Dashboard",
  networkGraph: "Network Graph",
  cases: "Cases",
  generateReport: "Generate Report",
  logImport: "Log Import",
  captureConfig: "Capture Configuration",
  preAnalysisFilters: "Pre-analysis Filters",
  sourceIp: "Source IP",
  destinationIp: "Destination IP",
  port: "Port",
  timeRange: "Time range",
  packetsParsed: "Packets parsed",
  sessionsReconstructed: "Sessions reconstructed",
  protocolsDecoded: "Protocols decoded",
  payloadFindings: "Payload findings",
  linkedEvidence: "Linked evidence",
  alertsGenerated: "Alerts generated",
  openDetails: "Open details",
  packetExplorerDesc: "Inspect packet-level metadata, decoded fields, and related evidence links.",
  decoderDesc: "Review protocol decoding coverage for DNS, HTTP, TLS, FTP, SMTP, ICMP, TCP, and UDP.",
  payloadDesc: "Inspect visible payload patterns, entropy, hidden-data indicators, and obfuscation signals.",
  sessionsDesc: "Reconstruct request/response activity and connect sessions to alerts and evidence.",
  detectionDesc: "Review signature rules and known attack pattern matches.",
  anomalyDesc: "Compare baseline behaviour against observed suspicious traffic.",
  exportDesc: "Prepare forensic exports for reports, evidence bundles, logs, and filtered PCAPs.",
  integrationsDesc: "Configure real local SIEM, webhook, and investigation-tool delivery records.",
  complianceDesc: "Review evidence integrity, custody history, and access logs.",
  metadata: "Metadata",
  decodedFields: "Decoded fields",
  hexPreview: "Hex preview",
  asciiPreview: "ASCII preview",
  relatedAlert: "Related alert",
  relatedSession: "Related session",
  textPreview: "Text preview",
  extractedStrings: "Extracted strings",
  requestResponseFlow: "Request / response flow",
  packetTimeline: "Packet timeline",
  baselineComparison: "Baseline comparison",
  requirementCoverage: "Requirement Coverage",
  requirementCoverageBody: "Frontend surfaces now cover capture, DPI, threat detection, AI anomaly analysis, forensics, integration, and compliance workflows.",
  evidenceToast: "Evidence processed successfully",
  nodeToast: "Node evidence added to case",
  noteAction: "Investigator note added",
  collapseSidebar: "Collapse sidebar",
  openNavigation: "Open navigation",
  filename: "Filename",
  landingHeadline: "Network evidence, ready for investigation.",
  landingSubhead: "AI-assisted network forensics for cybercrime teams.",
  landingBody:
    "Netra turns packet captures into timelines, encrypted metadata intelligence, attack classifications, case history, and multilingual forensic reports.",
  heroPoint1Title: "Evidence-first",
  heroPoint1Body: "Preserve filename, SHA-256 hash, investigator, and custody details from the first screen.",
  heroPoint2Title: "Metadata-aware",
  heroPoint2Body: "Review SNI, JA3, certificates, timing patterns, and reputation without decrypting traffic.",
  heroPoint3Title: "Report-ready",
  heroPoint3Body: "Move from alert to case history to police-facing report in one guided flow.",
  proofIntegrity: "Evidence integrity",
  proofIntegrityBody: "Every analysis view keeps evidence hash, timestamp, and case context close to the investigator.",
  proofEncrypted: "Encrypted metadata",
  proofEncryptedBody: "Netra does not break encryption; it studies traffic behavior and metadata patterns.",
  proofReports: "Multilingual reporting",
  proofReportsBody: "English, Hindi, and Gujarati reporting modes support regional police workflows.",
  workflowTitle: "Investigation Workflow",
  workflowDescription: "Six operational steps, designed like a case desk rather than a generic dashboard.",
  workflowRegisterTitle: "Register evidence",
  workflowRegisterBody: "Capture case details, investigator, source, priority, and evidence type.",
  workflowAnalyzeTitle: "Analyze traffic",
  workflowAnalyzeBody: "Simulate hash verification, flow extraction, and TLS metadata review.",
  workflowClassifyTitle: "Classify threats",
  workflowClassifyBody: "Label DNS Tunnel, Exfiltration, Beaconing, Malware C2, and Port Scan behavior.",
  workflowMapTitle: "Map attack path",
  workflowMapBody: "Connect suspicious workstation, DNS tunnel, encrypted session, and destination.",
  workflowCaseTitle: "Build case history",
  workflowCaseBody: "Track notes, review activity, linked alerts, and custody timeline.",
  workflowReportTitle: "Generate report",
  workflowReportBody: "Preview a police-ready multilingual forensic report.",
  storyTitle: "Investigation Story",
  storyDescription: "A single cybercrime scenario shown through the artifacts investigators actually use.",
  story1Title: "Workstation flagged",
  story1Body: "An internal machine begins sending unusual DNS queries and periodic encrypted traffic.",
  story1Signal: "Periodic outbound activity",
  story1Finding: "DNS length anomaly",
  story1Outcome: "Endpoint review opened",
  story2Title: "DNS tunnel identified",
  story2Body: "Long query bursts, repeated timing, and suspicious destinations trigger classification.",
  story2Signal: "Long query bursts",
  story2Finding: "DNS Tunnel classification",
  story2Outcome: "Domain evidence linked",
  story3Title: "TLS metadata reviewed",
  story3Body: "SNI, JA3, certificate issuer, timing, and reputation are reviewed without decryption.",
  story3Signal: "SNI and JA3 metadata",
  story3Finding: "Encrypted risk pattern",
  story3Outcome: "No decryption required",
  story4Title: "Case history built",
  story4Body: "Notes, custody actions, linked alerts, and timeline entries become part of the case.",
  story4Signal: "Reviewed alert chain",
  story4Finding: "Custody timeline complete",
  story4Outcome: "Case file strengthened",
  story5Title: "Report generated",
  story5Body: "A structured report summarizes evidence, classification, metadata, and next steps.",
  story5Signal: "Verified case packet",
  story5Finding: "Police-ready summary",
  story5Outcome: "Report ready for review",
  capTitle: "Capabilities",
  capDescription: "Real-PCAP investigation capabilities for repeatable local forensic analysis.",
  capLive: "PCAP-driven alerting",
  capLiveBody: "Uploaded packet captures feed parsing, protocol evidence, detections, anomalies, and investigation views.",
  capEncrypted: "Encrypted metadata without decryption",
  capEncryptedBody: "Metadata patterns provide useful evidence while respecting encrypted content.",
  capClassify: "Attack classification",
  capClassifyBody: "Alerts are grouped into practical investigation classes.",
  capHistory: "Case history",
  capHistoryBody: "Every action can be presented as part of the investigation record.",
  capReports: "Multilingual forensic reports",
  capReportsBody: "Report sections adapt to English, Hindi, and Gujarati.",
  marqueePcap: "PCAP",
  marqueeDns: "DNS",
  marqueeTls: "TLS Metadata",
  marqueeJa3: "JA3",
  marqueeSni: "SNI",
  marqueeReport: "Case Report",
  marqueeCustody: "Chain of Custody",
  previewConsole: "Netra Console",
  previewPackets: "Packets",
  previewAlerts: "Alerts",
  previewHash: "Hash",
  previewVerified: "Verified",
  footerSentence: "Netra converts packet evidence into cybercrime investigation workflows.",
  footerNav: "Navigation",
  footerDemo: "Operational flow",
  footerNote: "Built for a cybersecurity public-safety hackathon.",
  sidebarSubtitle: "AI Network Forensics",
  dockerReady: "Docker ready",
  dockerBody: "Full stack is reading real PCAP analysis from the Django API.",
  searchPlaceholder: "Search alerts, IPs, hashes",
  uploadTitle: "Start Investigation",
  uploadDesc: "Upload network evidence and Netra will analyze packets, sessions, protocols, suspicious activity, and report-ready findings automatically.",
  caseNumber: "Case number",
  investigator: "Investigator",
  department: "Department",
  evidenceType: "Evidence type",
  sourceLocation: "Source location",
  priority: "Priority",
  remarks: "Remarks",
  useSample: "Use Sample PCAP",
  processing: "Processing checklist",
  processingBody: "Attach real packet evidence and watch each analysis stage complete.",
  stepHash: "Hash calculation",
  stepRegister: "Case registration",
  stepFlow: "Flow extraction",
  stepTls: "TLS metadata analysis",
  stepClassify: "Attack classification",
  stepDashboard: "Dashboard preparation",
  evidenceMetadata: "Evidence Metadata",
  dashboardTitle: "Investigation Dashboard",
  dashboardDesc: "A calmer workspace for uploaded-PCAP alerts, encrypted metadata, and classifications.",
  overview: "Overview",
  alerts: "Alerts",
  encryptedTraffic: "Encrypted Traffic",
  classifications: "Classifications",
  packets: "Packets",
  flows: "Flows",
  critical: "Critical",
  hosts: "Hosts",
  case: "Case",
  protocolDistribution: "Protocol Distribution",
  trafficTimeline: "Traffic Timeline",
  alertVolume: "Alert Volume",
  alertQueue: "Alert Queue",
  alertQueueBody: "Suspicious activity with class, source, destination, and confidence.",
  severity: "Severity",
  class: "Class",
  type: "Type",
  source: "Source",
  destination: "Destination",
  protocol: "Protocol",
  confidence: "Confidence",
  status: "Status",
  encryptedTitle: "Encrypted Traffic Intelligence",
  encryptedBody: "TLS packet metadata from the uploaded capture without decrypting protected content.",
  issuer: "Issuer",
  reputation: "Reputation",
  timing: "Timing",
  risk: "Risk",
  nextActions: "Next actions",
  actionDomain: "Review suspicious destinations and linked sessions",
  actionIsolate: "Escalate endpoint isolation when evidence supports it",
  actionMetadata: "Attach encrypted metadata table",
  actionReport: "Generate multilingual report",
  graphTitle: "Network Attack Graph",
  graphDesc: "A case-scoped attack path generated from uploaded packet sessions and alerts.",
  nodeDetail: "Node Investigation Detail",
  highConfidence: "High confidence path",
  riskScore: "Risk score",
  relatedAlerts: "Related alerts",
  bytesTransferred: "Bytes transferred",
  metadataRisk: "Encrypted metadata risk",
  addToCase: "Add to Case",
  caseQueue: "Cybercrime Case Queue",
  caseQueueDesc: "Click any case to review its history, then open the dedicated case page.",
  caseHistory: "Case history",
  viewFullCase: "View full case",
  caseDetail: "Case Detail",
  addNote: "Add note",
  saveNote: "Save note",
  caseSummary: "Case Summary",
  created: "Created",
  report: "Report",
  investigatorNotes: "Investigator Notes",
  reportTitle: "Forensic Network Investigation Report",
  hashVerification: "Hash Verification",
  alertSummary: "Alert Summary",
  encryptedMetadata: "Encrypted Traffic Metadata",
  attackClassification: "Attack Classification",
  timeline: "Timeline",
  nextSteps: "Recommended Next Steps",
  print: "Print",
  backToCase: "Back to case",
};

const hi: Dict = {
  ...en,
  viewDemo: "जांच कंसोल खोलें",
  startInvestigation: "जांच शुरू करें",
  exploreWorkflow: "वर्कफ़्लो देखें",
  workflow: "वर्कफ़्लो",
  capabilities: "क्षमताएं",
  demo: "डेमो",
  reports: "रिपोर्ट",
  capture: "कैप्चर",
  analysis: "विश्लेषण",
  investigation: "जांच",
  governance: "गवर्नेंस",
  packetExplorer: "Packet Explorer",
  sessions: "Sessions",
  protocolDecoder: "Protocol Decoder",
  payloadInspection: "Payload Inspection",
  threatDetection: "Threat Detection",
  aiAnomaly: "AI Anomaly",
  exportCenter: "Export Center",
  integrations: "Integrations",
  compliance: "Compliance",
  evidenceIntake: "साक्ष्य इनटेक",
  dashboard: "डैशबोर्ड",
  networkGraph: "नेटवर्क ग्राफ",
  cases: "केस",
  generateReport: "रिपोर्ट बनाएं",
  logImport: "Log Import",
  linkedEvidence: "लिंक किए गए साक्ष्य",
  captureConfig: "Capture Configuration",
  preAnalysisFilters: "Pre-analysis Filters",
  sourceIp: "Source IP",
  destinationIp: "Destination IP",
  port: "Port",
  timeRange: "Time range",
  packetsParsed: "Packets parsed",
  sessionsReconstructed: "Sessions reconstructed",
  protocolsDecoded: "Protocols decoded",
  payloadFindings: "Payload findings",
  alertsGenerated: "Alerts generated",
  packetExplorerDesc: "Packet-level metadata, decoded fields और related evidence links inspect करें।",
  decoderDesc: "DNS, HTTP, TLS, FTP, SMTP, ICMP, TCP और UDP decoding coverage review करें।",
  payloadDesc: "Visible payload patterns, entropy, hidden-data indicators और obfuscation signals inspect करें।",
  sessionsDesc: "Request/response activity reconstruct करें और sessions को alerts से जोड़ें।",
  detectionDesc: "Signature rules और known attack pattern matches review करें।",
  anomalyDesc: "Baseline behaviour को observed suspicious traffic से compare करें।",
  exportDesc: "Reports, evidence bundles, logs और filtered PCAP exports prepare करें।",
  integrationsDesc: "Cyber Crime Branch और investigation-tool integration readiness देखें।",
  complianceDesc: "Evidence integrity, custody history और access logs review करें।",
  evidenceToast: "साक्ष्य सफलतापूर्वक processed हुआ",
  nodeToast: "Node evidence case में जोड़ा गया",
  noteAction: "जांच अधिकारी note added",
  collapseSidebar: "Sidebar collapse करें",
  openNavigation: "Navigation खोलें",
  filename: "फाइल का नाम",
  landingHeadline: "नेटवर्क साक्ष्य, जांच के लिए तैयार।",
  landingSubhead: "साइबर अपराध टीमों के लिए AI-सहायित नेटवर्क फॉरेंसिक।",
  landingBody: "Netra packet capture को timeline, metadata intelligence, case history और multilingual forensic report में बदलता है।",
  heroPoint1Title: "साक्ष्य पहले",
  heroPoint1Body: "Filename, SHA-256 hash, investigator और custody details शुरुआत से सुरक्षित रहें।",
  heroPoint2Title: "Metadata-aware",
  heroPoint2Body: "SNI, JA3, certificates, timing और reputation को decryption के बिना देखें।",
  heroPoint3Title: "Report-ready",
  heroPoint3Body: "Alert से case history और police-facing report तक guided flow।",
  proofIntegrity: "साक्ष्य अखंडता",
  proofIntegrityBody: "हर analysis view में evidence hash, timestamp और case context दिखता है।",
  proofEncrypted: "Encrypted metadata",
  proofEncryptedBody: "Netra encryption नहीं तोड़ता; traffic behavior और metadata patterns पढ़ता है।",
  proofReports: "बहुभाषी रिपोर्टिंग",
  proofReportsBody: "English, Hindi और Gujarati modes regional police workflows को support करते हैं।",
  workflowTitle: "जांच वर्कफ़्लो",
  workflowDescription: "छह operational steps, generic dashboard नहीं बल्कि case desk जैसा अनुभव।",
  workflowRegisterTitle: "साक्ष्य दर्ज करें",
  workflowRegisterBody: "Case details, investigator, source, priority और evidence type capture करें।",
  workflowAnalyzeTitle: "Traffic analyze करें",
  workflowAnalyzeBody: "Hash verification, flow extraction और TLS metadata review simulate करें।",
  workflowClassifyTitle: "Threat classify करें",
  workflowClassifyBody: "DNS Tunnel, Exfiltration, Beaconing, Malware C2 और Port Scan labels लगाएं।",
  workflowMapTitle: "Attack path map करें",
  workflowMapBody: "Suspicious workstation, DNS tunnel, encrypted session और destination connect करें।",
  workflowCaseTitle: "Case history बनाएं",
  workflowCaseBody: "Notes, review activity, linked alerts और custody timeline track करें।",
  workflowReportTitle: "Report बनाएं",
  workflowReportBody: "Police-ready multilingual forensic report preview करें।",
  storyTitle: "जांच कहानी",
  storyDescription: "एक cybercrime scenario, उन artifacts के साथ जिनकी investigator को जरूरत होती है।",
  story1Title: "वर्कस्टेशन फ्लैग हुआ",
  story1Body: "एक internal machine असामान्य DNS queries और periodic encrypted traffic भेजना शुरू करती है।",
  story1Signal: "Periodic outbound activity",
  story1Finding: "DNS length anomaly",
  story1Outcome: "Endpoint review opened",
  story2Title: "DNS tunnel पहचाना गया",
  story2Body: "लंबे query bursts, repeated timing और suspicious destinations classification trigger करते हैं।",
  story2Signal: "Long query bursts",
  story2Finding: "DNS Tunnel classification",
  story2Outcome: "Domain evidence linked",
  story3Title: "TLS metadata review हुआ",
  story3Body: "SNI, JA3, certificate issuer, timing और reputation को decryption के बिना review किया गया।",
  story3Signal: "SNI और JA3 metadata",
  story3Finding: "Encrypted risk pattern",
  story3Outcome: "Decryption की जरूरत नहीं",
  story4Title: "Case history बनी",
  story4Body: "Notes, custody actions, linked alerts और timeline entries case का हिस्सा बनते हैं।",
  story4Signal: "Reviewed alert chain",
  story4Finding: "Custody timeline complete",
  story4Outcome: "Case file strengthened",
  story5Title: "Report generated",
  story5Body: "Structured report evidence, classification, metadata और next steps summarize करता है।",
  story5Signal: "Verified case packet",
  story5Finding: "Police-ready summary",
  story5Outcome: "Report ready for review",
  capTitle: "क्षमताएं",
  capDescription: "Repeatable local forensic analysis के लिए real-PCAP investigation capabilities।",
  capLive: "PCAP-driven alerting",
  capLiveBody: "Uploaded packet captures parsing, protocol evidence, detections, anomalies और investigation views को feed करते हैं।",
  capEncrypted: "Decryption के बिना encrypted metadata",
  capEncryptedBody: "Metadata patterns encrypted content का सम्मान करते हुए useful evidence देते हैं।",
  capClassify: "Attack classification",
  capClassifyBody: "Alerts को practical investigation classes में group किया जाता है।",
  capHistory: "Case history",
  capHistoryBody: "हर action investigation record के हिस्से के रूप में दिखाया जा सकता है।",
  capReports: "बहुभाषी forensic reports",
  capReportsBody: "Report sections English, Hindi और Gujarati के अनुसार बदलते हैं।",
  previewConsole: "Netra Console",
  previewPackets: "Packets",
  previewAlerts: "Alerts",
  previewHash: "Hash",
  previewVerified: "Verified",
  footerSentence: "Netra packet evidence को cybercrime investigation workflow में बदलता है।",
  footerNav: "नेविगेशन",
  footerDemo: "ऑपरेशनल flow",
  footerNote: "Cybersecurity public-safety hackathon के लिए बनाया गया।",
  sidebarSubtitle: "AI Network Forensics",
  dockerReady: "Docker ready",
  dockerBody: "Full stack Django API से real PCAP analysis पढ़ रहा है।",
  searchPlaceholder: "Alerts, IPs, hashes खोजें",
  uploadTitle: "जांच शुरू करें",
  uploadDesc: "Network evidence upload करें और Netra packets, sessions, protocols, suspicious activity और report-ready findings automatically analyze करेगा।",
  caseNumber: "केस नंबर",
  investigator: "जांच अधिकारी",
  department: "विभाग",
  evidenceType: "साक्ष्य प्रकार",
  sourceLocation: "स्रोत स्थान",
  priority: "प्राथमिकता",
  remarks: "टिप्पणी",
  useSample: "Sample PCAP उपयोग करें",
  processing: "प्रोसेसिंग चेकलिस्ट",
  processingBody: "Real packet evidence attach करें और हर analysis stage को complete होते देखें।",
  stepHash: "Hash calculation",
  stepRegister: "Case registration",
  stepFlow: "Flow extraction",
  stepTls: "TLS metadata analysis",
  stepClassify: "Attack classification",
  stepDashboard: "Dashboard preparation",
  dashboardTitle: "जांच डैशबोर्ड",
  dashboardDesc: "Uploaded-PCAP alerts, encrypted metadata और classifications के लिए शांत workspace.",
  overview: "सारांश",
  alerts: "अलर्ट",
  encryptedTraffic: "Encrypted Traffic",
  classifications: "Classifications",
  packets: "Packets",
  flows: "Flows",
  critical: "Critical",
  hosts: "Hosts",
  case: "Case",
  protocolDistribution: "Protocol Distribution",
  trafficTimeline: "Traffic Timeline",
  alertVolume: "Alert Volume",
  alertQueue: "Alert Queue",
  alertQueueBody: "Class, source, destination और confidence के साथ suspicious activity.",
  severity: "Severity",
  class: "Class",
  type: "Type",
  source: "Source",
  destination: "Destination",
  protocol: "Protocol",
  confidence: "Confidence",
  status: "Status",
  encryptedTitle: "Encrypted Traffic Intelligence",
  encryptedBody: "Decryption के बिना SNI, JA3, certificates, timing और reputation.",
  issuer: "Issuer",
  reputation: "Reputation",
  timing: "Timing",
  risk: "Risk",
  nextActions: "Next actions",
  actionDomain: "DNS tunnel domain ownership confirm करें",
  actionIsolate: "Endpoint isolation request करें",
  actionMetadata: "Encrypted metadata table attach करें",
  actionReport: "Multilingual report generate करें",
  graphTitle: "Network Attack Graph",
  graphDesc: "Source, DNS tunnel, encrypted beaconing और case linkage दिखाने वाला warm-accent attack path.",
  nodeDetail: "Node Investigation Detail",
  highConfidence: "High confidence path",
  riskScore: "Risk score",
  relatedAlerts: "Related alerts",
  bytesTransferred: "Bytes transferred",
  metadataRisk: "Encrypted metadata risk",
  addToCase: "Case में जोड़ें",
  caseQueue: "साइबर अपराध केस कतार",
  caseQueueDesc: "History review करने के लिए किसी भी case पर click करें, फिर dedicated case page खोलें।",
  caseHistory: "केस इतिहास",
  viewFullCase: "पूरा केस देखें",
  caseDetail: "केस विवरण",
  addNote: "नोट जोड़ें",
  saveNote: "नोट सेव करें",
  created: "Created",
  report: "Report",
  reportTitle: "फॉरेंसिक नेटवर्क जांच रिपोर्ट",
  caseSummary: "केस सारांश",
  evidenceMetadata: "साक्ष्य मेटाडेटा",
  hashVerification: "Hash Verification",
  alertSummary: "अलर्ट सारांश",
  encryptedMetadata: "Encrypted Traffic Metadata",
  attackClassification: "Attack Classification",
  timeline: "टाइमलाइन",
  investigatorNotes: "जांच नोट्स",
  nextSteps: "अनुशंसित अगले कदम",
  print: "प्रिंट",
  backToCase: "केस पर वापस",
};

const gu: Dict = {
  ...en,
  viewDemo: "તપાસ કન્સોલ ખોલો",
  startInvestigation: "તપાસ શરૂ કરો",
  exploreWorkflow: "વર્કફ્લો જુઓ",
  workflow: "વર્કફ્લો",
  capabilities: "ક્ષમતાઓ",
  demo: "ડેમો",
  reports: "રિપોર્ટ",
  capture: "કૅપ્ચર",
  analysis: "વિશ્લેષણ",
  investigation: "તપાસ",
  governance: "ગવર્નન્સ",
  packetExplorer: "Packet Explorer",
  sessions: "Sessions",
  protocolDecoder: "Protocol Decoder",
  payloadInspection: "Payload Inspection",
  threatDetection: "Threat Detection",
  aiAnomaly: "AI Anomaly",
  exportCenter: "Export Center",
  integrations: "Integrations",
  compliance: "Compliance",
  evidenceIntake: "પુરાવા ઇનટેક",
  dashboard: "ડેશબોર્ડ",
  networkGraph: "નેટવર્ક ગ્રાફ",
  cases: "કેસ",
  generateReport: "રિપોર્ટ બનાવો",
  logImport: "Log Import",
  captureConfig: "Capture Configuration",
  preAnalysisFilters: "Pre-analysis Filters",
  sourceIp: "Source IP",
  destinationIp: "Destination IP",
  port: "Port",
  timeRange: "Time range",
  packetsParsed: "Packets parsed",
  sessionsReconstructed: "Sessions reconstructed",
  protocolsDecoded: "Protocols decoded",
  payloadFindings: "Payload findings",
  linkedEvidence: "લિંક કરેલા પુરાવા",
  alertsGenerated: "Alerts generated",
  packetExplorerDesc: "Packet-level metadata, decoded fields અને related evidence links inspect કરો.",
  decoderDesc: "DNS, HTTP, TLS, FTP, SMTP, ICMP, TCP અને UDP decoding coverage review કરો.",
  payloadDesc: "Visible payload patterns, entropy, hidden-data indicators અને obfuscation signals inspect કરો.",
  sessionsDesc: "Request/response activity reconstruct કરો અને sessions ને alerts સાથે જોડો.",
  detectionDesc: "Signature rules અને known attack pattern matches review કરો.",
  anomalyDesc: "Baseline behaviour ને observed suspicious traffic સાથે compare કરો.",
  exportDesc: "Reports, evidence bundles, logs અને filtered PCAP exports prepare કરો.",
  integrationsDesc: "Cyber Crime Branch અને investigation-tool integration readiness જુઓ.",
  complianceDesc: "Evidence integrity, custody history અને access logs review કરો.",
  evidenceToast: "પુરાવો સફળતાપૂર્વક processed થયો",
  nodeToast: "Node evidence case માં ઉમેરાયું",
  noteAction: "તપાસ અધિકારી note added",
  collapseSidebar: "Sidebar collapse કરો",
  openNavigation: "Navigation ખોલો",
  filename: "ફાઇલનું નામ",
  landingHeadline: "નેટવર્ક પુરાવા, તપાસ માટે તૈયાર.",
  landingSubhead: "સાઇબર ક્રાઇમ ટીમો માટે AI-assisted network forensics.",
  landingBody: "Netra packet capture ને timeline, metadata intelligence, case history અને multilingual forensic report માં ફેરવે છે.",
  heroPoint1Title: "પુરાવા પહેલા",
  heroPoint1Body: "Filename, SHA-256 hash, investigator અને custody details પ્રથમ screen થી જાળવો.",
  heroPoint2Title: "Metadata-aware",
  heroPoint2Body: "SNI, JA3, certificates, timing અને reputation ને decryption વિના જુઓ.",
  heroPoint3Title: "Report-ready",
  heroPoint3Body: "Alert થી case history અને police-facing report સુધી guided flow.",
  proofIntegrity: "પુરાવા અખંડિતતા",
  proofIntegrityBody: "દરેક analysis view માં evidence hash, timestamp અને case context દેખાય છે.",
  proofEncrypted: "Encrypted metadata",
  proofEncryptedBody: "Netra encryption તોડતું નથી; traffic behavior અને metadata patterns વાંચે છે.",
  proofReports: "બહુભાષી રિપોર્ટિંગ",
  proofReportsBody: "English, Hindi અને Gujarati modes regional police workflows ને support કરે છે.",
  workflowTitle: "તપાસ વર્કફ્લો",
  workflowDescription: "છ operational steps, generic dashboard નહીં પણ case desk જેવો અનુભવ.",
  workflowRegisterTitle: "પુરાવા નોંધો",
  workflowRegisterBody: "Case details, investigator, source, priority અને evidence type capture કરો.",
  workflowAnalyzeTitle: "Traffic analyze કરો",
  workflowAnalyzeBody: "Hash verification, flow extraction અને TLS metadata review simulate કરો.",
  workflowClassifyTitle: "Threat classify કરો",
  workflowClassifyBody: "DNS Tunnel, Exfiltration, Beaconing, Malware C2 અને Port Scan labels આપો.",
  workflowMapTitle: "Attack path map કરો",
  workflowMapBody: "Suspicious workstation, DNS tunnel, encrypted session અને destination connect કરો.",
  workflowCaseTitle: "Case history બનાવો",
  workflowCaseBody: "Notes, review activity, linked alerts અને custody timeline track કરો.",
  workflowReportTitle: "Report બનાવો",
  workflowReportBody: "Police-ready multilingual forensic report preview કરો.",
  storyTitle: "તપાસ વાર્તા",
  storyDescription: "એક cybercrime scenario, investigator ને લાગતા artifacts સાથે.",
  story1Title: "વર્કસ્ટેશન flag થયું",
  story1Body: "એક internal machine અસામાન્ય DNS queries અને periodic encrypted traffic મોકલવાનું શરૂ કરે છે.",
  story1Signal: "Periodic outbound activity",
  story1Finding: "DNS length anomaly",
  story1Outcome: "Endpoint review opened",
  story2Title: "DNS tunnel ઓળખાયું",
  story2Body: "Long query bursts, repeated timing અને suspicious destinations classification trigger કરે છે.",
  story2Signal: "Long query bursts",
  story2Finding: "DNS Tunnel classification",
  story2Outcome: "Domain evidence linked",
  story3Title: "TLS metadata review થયું",
  story3Body: "SNI, JA3, certificate issuer, timing અને reputation ને decryption વિના review કરવામાં આવ્યું.",
  story3Signal: "SNI અને JA3 metadata",
  story3Finding: "Encrypted risk pattern",
  story3Outcome: "Decryption જરૂરી નથી",
  story4Title: "Case history બની",
  story4Body: "Notes, custody actions, linked alerts અને timeline entries case નો ભાગ બને છે.",
  story4Signal: "Reviewed alert chain",
  story4Finding: "Custody timeline complete",
  story4Outcome: "Case file strengthened",
  story5Title: "Report generated",
  story5Body: "Structured report evidence, classification, metadata અને next steps summarize કરે છે.",
  story5Signal: "Verified case packet",
  story5Finding: "Police-ready summary",
  story5Outcome: "Report ready for review",
  capTitle: "ક્ષમતાઓ",
  capDescription: "Repeatable local forensic analysis માટે real-PCAP investigation capabilities.",
  capLive: "PCAP-driven alerting",
  capLiveBody: "Uploaded packet captures parsing, protocol evidence, detections, anomalies અને investigation views ને feed કરે છે.",
  capEncrypted: "Decryption વિના encrypted metadata",
  capEncryptedBody: "Metadata patterns encrypted content નું સન્માન રાખીને useful evidence આપે છે.",
  capClassify: "Attack classification",
  capClassifyBody: "Alerts ને practical investigation classes માં group કરવામાં આવે છે.",
  capHistory: "Case history",
  capHistoryBody: "દરેક action investigation record ના ભાગ રૂપે બતાવી શકાય છે.",
  capReports: "બહુભાષી forensic reports",
  capReportsBody: "Report sections English, Hindi અને Gujarati મુજબ બદલાય છે.",
  previewConsole: "Netra Console",
  previewPackets: "Packets",
  previewAlerts: "Alerts",
  previewHash: "Hash",
  previewVerified: "Verified",
  footerSentence: "Netra packet evidence ને cybercrime investigation workflow માં ફેરવે છે.",
  footerNav: "નેવિગેશન",
  footerDemo: "ઓપરેશનલ flow",
  footerNote: "Cybersecurity public-safety hackathon માટે બનાવેલ.",
  sidebarSubtitle: "AI Network Forensics",
  dockerReady: "Docker ready",
  dockerBody: "Full stack Django API માંથી real PCAP analysis વાંચે છે.",
  searchPlaceholder: "Alerts, IPs, hashes શોધો",
  uploadTitle: "તપાસ શરૂ કરો",
  uploadDesc: "Network evidence upload કરો અને Netra packets, sessions, protocols, suspicious activity અને report-ready findings automatically analyze કરશે.",
  caseNumber: "કેસ નંબર",
  investigator: "તપાસ અધિકારી",
  department: "વિભાગ",
  evidenceType: "પુરાવા પ્રકાર",
  sourceLocation: "સ્રોત સ્થળ",
  priority: "પ્રાથમિકતા",
  remarks: "નોંધ",
  useSample: "Sample PCAP વાપરો",
  processing: "પ્રોસેસિંગ ચેકલિસ્ટ",
  processingBody: "Real packet evidence attach કરો અને દરેક analysis stage complete થતું જુઓ.",
  stepHash: "Hash calculation",
  stepRegister: "Case registration",
  stepFlow: "Flow extraction",
  stepTls: "TLS metadata analysis",
  stepClassify: "Attack classification",
  stepDashboard: "Dashboard preparation",
  dashboardTitle: "તપાસ ડેશબોર્ડ",
  dashboardDesc: "Uploaded-PCAP alerts, encrypted metadata અને classifications માટે શાંત workspace.",
  overview: "સારાંશ",
  alerts: "અલર્ટ",
  encryptedTraffic: "Encrypted Traffic",
  classifications: "Classifications",
  packets: "Packets",
  flows: "Flows",
  critical: "Critical",
  hosts: "Hosts",
  case: "Case",
  protocolDistribution: "Protocol Distribution",
  trafficTimeline: "Traffic Timeline",
  alertVolume: "Alert Volume",
  alertQueue: "Alert Queue",
  alertQueueBody: "Class, source, destination અને confidence સાથે suspicious activity.",
  severity: "Severity",
  class: "Class",
  type: "Type",
  source: "Source",
  destination: "Destination",
  protocol: "Protocol",
  confidence: "Confidence",
  status: "Status",
  encryptedTitle: "Encrypted Traffic Intelligence",
  encryptedBody: "Decryption વિના SNI, JA3, certificates, timing અને reputation.",
  issuer: "Issuer",
  reputation: "Reputation",
  timing: "Timing",
  risk: "Risk",
  nextActions: "Next actions",
  actionDomain: "DNS tunnel domain ownership confirm કરો",
  actionIsolate: "Endpoint isolation request કરો",
  actionMetadata: "Encrypted metadata table attach કરો",
  actionReport: "Multilingual report generate કરો",
  graphTitle: "Network Attack Graph",
  graphDesc: "Source, DNS tunnel, encrypted beaconing અને case linkage બતાવતો warm-accent attack path.",
  nodeDetail: "Node Investigation Detail",
  highConfidence: "High confidence path",
  riskScore: "Risk score",
  relatedAlerts: "Related alerts",
  bytesTransferred: "Bytes transferred",
  metadataRisk: "Encrypted metadata risk",
  addToCase: "Case માં ઉમેરો",
  caseQueue: "સાઇબર ક્રાઇમ કેસ કતાર",
  caseQueueDesc: "History review કરવા કોઈપણ case પર click કરો, પછી dedicated case page ખોલો.",
  caseHistory: "કેસ ઇતિહાસ",
  viewFullCase: "પૂરો કેસ જુઓ",
  caseDetail: "કેસ વિગત",
  addNote: "નોંધ ઉમેરો",
  saveNote: "નોંધ સેવ કરો",
  created: "Created",
  report: "Report",
  reportTitle: "ફોરેન્સિક નેટવર્ક તપાસ રિપોર્ટ",
  caseSummary: "કેસ સારાંશ",
  evidenceMetadata: "પુરાવા મેટાડેટા",
  hashVerification: "Hash Verification",
  alertSummary: "અલર્ટ સારાંશ",
  encryptedMetadata: "Encrypted Traffic Metadata",
  attackClassification: "Attack Classification",
  timeline: "ટાઇમલાઇન",
  investigatorNotes: "તપાસ નોંધો",
  nextSteps: "ભલામણ કરેલા આગળના પગલા",
  print: "પ્રિન્ટ",
  backToCase: "કેસ પર પાછા",
};

const translations: Record<Language, Dict> = { English: en, Hindi: hi, Gujarati: gu };

type AppState = {
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
};

type DeploymentModuleKey = "lab" | "sensors" | "schedules" | "integrations" | "retention" | "system";
type DeploymentModuleAccess = { enabled: boolean; visible: boolean; reason: string };
type DeploymentAccess = {
  verified: boolean;
  user: string;
  department: string;
  role: string;
  profile: string;
  hostCaptureEnabled: boolean;
  replayEnabled: boolean;
  sensorCaptureEnabled: boolean;
  modules: Record<DeploymentModuleKey, DeploymentModuleAccess>;
};

const DEFAULT_DEPLOYMENT_ACCESS: DeploymentAccess = {
  verified: false,
  user: "",
  department: "",
  role: "Viewer",
  profile: import.meta.env.VITE_DEPLOYMENT_PROFILE ?? "local",
  hostCaptureEnabled: false,
  replayEnabled: false,
  sensorCaptureEnabled: false,
  modules: {
    lab: { enabled: false, visible: false, reason: "Lab access has not been verified." },
    sensors: { enabled: false, visible: false, reason: "Sensor access has not been verified." },
    schedules: { enabled: false, visible: false, reason: "Scheduling access has not been verified." },
    integrations: { enabled: false, visible: false, reason: "Integration access has not been verified." },
    retention: { enabled: false, visible: false, reason: "Retention access has not been verified." },
    system: { enabled: false, visible: false, reason: "Administrator access has not been verified." },
  },
};

const NetraContext = createContext<AppState | null>(null);

const API_BASE = import.meta.env.VITE_API_BASE_URL ?? "/api";
const DEPLOYMENT_PROFILE = import.meta.env.VITE_DEPLOYMENT_PROFILE ?? "local";
const HACKATHON_CORE = DEPLOYMENT_PROFILE === "hackathon-core";
const BPF_FILTER_ENABLED = import.meta.env.VITE_BPF_FILTER_ENABLED === "1";
const DIRECT_UPLOAD_ENABLED = import.meta.env.VITE_DIRECT_UPLOAD_ENABLED === "1";
const MAX_UPLOAD_MB = Math.max(1, Number(import.meta.env.VITE_MAX_UPLOAD_MB ?? (HACKATHON_CORE ? 25 : 500)) || 25);
const ACTIVE_UPLOAD_JOB_KEY = "netra-active-upload-job";
const EVIDENCE_TYPE_OPTIONS: EvidenceIntakeForm["evidenceType"][] = ["Auto-detect", "PCAP", "Firewall Logs", "DNS Logs", "TLS Metadata", "Mixed Evidence"];
const CASE_FLAG_OPTIONS = ["urgent", "ransomware", "insider-threat", "exfiltration", "related-case", "needs-review", "synthetic", "release-gate"] as const;
const NORMALIZATION_PREVIEW_BYTES = 64 * 1024;
const EVIDENCE_EXTENSIONS: Record<EvidenceIntakeForm["evidenceType"], string[]> = {
  "Auto-detect": [".pcap", ".pcapng", ".log", ".txt", ".csv", ".json", ".ndjson", ".zip"],
  PCAP: [".pcap", ".pcapng"],
  "Firewall Logs": [".log", ".txt", ".csv", ".json", ".ndjson"],
  "DNS Logs": [".log", ".txt", ".csv", ".json", ".ndjson"],
  "TLS Metadata": [".log", ".txt", ".csv", ".json", ".ndjson"],
  "Mixed Evidence": [".zip", ".json", ".csv"],
};

type EvidenceNormalizationPreview = {
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

type UploadStage = "idle" | "uploading" | "processing" | "queued" | "complete" | "failed";
type UploadTransferState = {
  bytesUploaded: number;
  speedBytesPerSecond: number;
  etaSeconds: number | null;
  paused: boolean;
  retryAttempt: number;
  message: string;
};
type EvidenceUploadPayload = Partial<EvidenceNormalizationPreview> & {
  error?: string;
  reason?: string;
  caseId?: string;
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

type UploadResult = {
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

function formatEta(seconds: number | null) {
  if (seconds === null || !Number.isFinite(seconds)) return "calculating ETA";
  const whole = Math.max(0, Math.round(seconds));
  if (whole < 60) return `${whole}s remaining`;
  const minutes = Math.floor(whole / 60);
  const remainder = whole % 60;
  return `${minutes}m ${remainder}s remaining`;
}

function uploadFormWithProgress<T>(path: string, form: FormData, onProgress: (percent: number) => void, onUploaded: () => void) {
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

function createDefaultIntakeForm(): EvidenceIntakeForm {
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

function allowedExtensionsForType(type: EvidenceIntakeForm["evidenceType"]) {
  return EVIDENCE_EXTENSIONS[type] ?? EVIDENCE_EXTENSIONS["Auto-detect"];
}

function acceptForEvidenceType(type: EvidenceIntakeForm["evidenceType"]) {
  return allowedExtensionsForType(type).join(",");
}

function evidenceTypeHelper(type: EvidenceIntakeForm["evidenceType"]) {
  return `Allowed for ${type}: ${allowedExtensionsForType(type).join(", ")}`;
}

function fileExtension(file: File) {
  return file.name.includes(".") ? `.${file.name.split(".").pop()?.toLowerCase()}` : "";
}

function fileExtensionAllowed(file: File, type: EvidenceIntakeForm["evidenceType"]) {
  return allowedExtensionsForType(type).includes(fileExtension(file));
}

function localNormalizationPreview(file: File, selectedType: EvidenceIntakeForm["evidenceType"]): EvidenceNormalizationPreview {
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

async function apiGet<T>(path: string): Promise<T> {
  if (SUPABASE_AUTH_ENABLED && !getCurrentAccessToken()) {
    const token = await ensureCurrentAccessToken();
    if (!token) throw new Error(`API ${path} requires an authenticated session`);
  }
  const response = await fetch(`${API_BASE}${path}`, { headers: netraHeaders() });
  if (!response.ok) throw new Error(`API ${path} failed with ${response.status}`);
  return response.json() as Promise<T>;
}

function netraHeaders(extra?: HeadersInit): HeadersInit {
  const token = getCurrentAccessToken();
  return {
    ...(extra ?? {}),
    ...(token ? { Authorization: `Bearer ${token}` } : {}),
  };
}

async function downloadApiFile(path: string, fallbackFilename: string) {
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

function graphEdgesToFlows(graphResponse: { edges?: { source: string; target: string; protocol: string; packets: number; bytes?: number; risk?: number; attackClass?: AttackClass; alertIds?: string[] }[] }): NetworkFlow[] {
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

async function loadAnalysisData(activeCaseId: string | null) {
  const casesResponse = await apiGet<{ results: CaseRecord[] }>("/cases?limit=100");
  const selectedCaseId = (activeCaseId && casesResponse.results.some((record) => record.id === activeCaseId) ? activeCaseId : casesResponse.results[0]?.id) ?? null;
  const workspaceResponse = selectedCaseId ? await apiGet<CaseWorkspaceRecord>(`/cases/${selectedCaseId}/workspace`) : null;
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

function useNetra() {
  const value = useContext(NetraContext);
  if (!value) throw new Error("useNetra must be used inside NetraProvider");
  return value;
}

function NetraProvider({ children }: { children: ReactNode }) {
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
  const [deploymentAccess, setDeploymentAccess] = useState<DeploymentAccess>(DEFAULT_DEPLOYMENT_ACCESS);
  const refreshTimerRef = useRef<number | null>(null);
  const [language, setLanguage] = useState<Language>(() => {
    const stored = window.localStorage.getItem("netra-language");
    return stored === "Hindi" || stored === "Gujarati" || stored === "English" ? stored : "English";
  });

  useEffect(() => {
    window.localStorage.setItem("netra-language", language);
  }, [language]);

  const refreshDeploymentAccess = useCallback(async () => {
    const payload = await apiGet<{
      user: string;
      department: string;
      role: string;
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

  useEffect(() => {
    const isProtectedAppRoute = window.location.pathname.startsWith("/app/") && window.location.pathname !== "/app/login";
    if (SUPABASE_AUTH_ENABLED && (!isProtectedAppRoute || !getCurrentAccessToken())) return;
    refreshDeploymentAccess().catch(() => setDeploymentAccess(DEFAULT_DEPLOYMENT_ACCESS));
    reloadAnalysis().catch(() => undefined);
  }, [refreshDeploymentAccess, reloadAnalysis]);

  useEffect(() => {
    if (!SUPABASE_AUTH_ENABLED || !supabase) return undefined;
    const client = supabase;
    refreshStoredSupabaseSession().catch(() => undefined);
    const {
      data: { subscription },
    } = client.auth.onAuthStateChange((_event, session) => {
      if (session?.access_token) {
        setCurrentAccessToken(session.access_token);
        refreshDeploymentAccess().catch(() => setDeploymentAccess(DEFAULT_DEPLOYMENT_ACCESS));
        reloadAnalysis().catch(() => undefined);
      } else {
        setCurrentAccessToken();
        setDeploymentAccess(DEFAULT_DEPLOYMENT_ACCESS);
      }
    });
    if (!SUPABASE_REALTIME_ENABLED) {
      const pollTimer = window.setInterval(scheduleRefresh, 5000);
      return () => {
        window.clearInterval(pollTimer);
        subscription.unsubscribe();
      };
    }
    const channel = client
      .channel("netra-operational-refresh")
      .on("postgres_changes", { event: "*", schema: "public", table: "forensics_operationalevent" }, scheduleRefresh)
      .on("postgres_changes", { event: "*", schema: "public", table: "forensics_processingjob" }, scheduleRefresh)
      .on("postgres_changes", { event: "*", schema: "public", table: "forensics_alert" }, scheduleRefresh)
      .on("postgres_changes", { event: "*", schema: "public", table: "forensics_capturejob" }, scheduleRefresh)
      .subscribe();
    return () => {
      subscription.unsubscribe();
      client.removeChannel(channel);
    };
  }, [refreshDeploymentAccess, reloadAnalysis, scheduleRefresh]);

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
    }),
    [accessLogRecordsState, activeCaseId, addCaseNote, alertRecords, anomaliesState, caseRecords, complianceRecordsState, decodedProtocolsState, deploymentAccess, detectionMatchesState, evidenceState, exportRecordsState, intakeForm, language, networkFlowsState, packetsState, payloadFindingsState, protocolChartDataState, reloadAnalysis, sessionsState, summaryState, trafficTimelineDataState, setActiveCaseId, zeekState],
  );

  return <NetraContext.Provider value={value}>{children}</NetraContext.Provider>;
}

function App() {
  return (
    <TooltipProvider>
      <NetraProvider>
        <div className="app-theme">
          <Router>
            <Toaster position="top-right" />
            <Routes>
              <Route path="/" element={<PublicHomePage languageControl={<LanguageControl />} />} />
              <Route path="/about" element={<PublicAboutPage languageControl={<LanguageControl />} />} />
              <Route path="/updates" element={<PublicUpdatesPage languageControl={<LanguageControl />} />} />
              <Route path="/changelog" element={<Navigate to="/updates" replace />} />
              <Route path="/contact" element={<PublicContactPage languageControl={<LanguageControl />} />} />
              <Route path="/privacy" element={<PublicPrivacyPage languageControl={<LanguageControl />} />} />
              <Route path="/terms" element={<PublicTermsPage languageControl={<LanguageControl />} />} />
              <Route path="/demo" element={<Navigate to="/login" replace state={{ from: "/app/upload" }} />} />
              <Route path="/login" element={<LoginPage />} />
              <Route path="/app/login" element={<Navigate to="/login" replace />} />
              <Route path="/app/*" element={<RequireAuth><AppShell /></RequireAuth>} />
              <Route path="*" element={<PublicNotFoundPage languageControl={<LanguageControl />} />} />
            </Routes>
          </Router>
        </div>
      </NetraProvider>
    </TooltipProvider>
  );
}

function RequireAuth({ children }: { children: ReactNode }) {
  const location = useLocation();
  const [status, setStatus] = useState<"checking" | "signed-in" | "signed-out">("checking");

  useEffect(() => {
    if (!SUPABASE_AUTH_ENABLED || !supabase) {
      setStatus("signed-out");
      return undefined;
    }
    let mounted = true;
    refreshStoredSupabaseSession()
      .then((session) => {
        if (!mounted) return;
        setStatus(session?.access_token ? "signed-in" : "signed-out");
      })
      .catch(() => {
        if (mounted) setStatus("signed-out");
      });
    const {
      data: { subscription },
    } = supabase.auth.onAuthStateChange((_event, session) => {
      if (session?.access_token) {
        setCurrentAccessToken(session.access_token);
        setStatus("signed-in");
      } else {
        setCurrentAccessToken();
        setStatus("signed-out");
      }
    });
    return () => {
      mounted = false;
      subscription.unsubscribe();
    };
  }, []);

  if (status === "checking") {
    return (
      <main className="auth-shell flex min-h-screen items-center justify-center px-4">
        <section className="auth-panel w-full max-w-md border border-[var(--border)] bg-[var(--panel)] p-6 shadow-sm">
          <p className="text-sm font-semibold text-accent">Netra Secure Access</p>
          <h1 className="mt-2 text-2xl font-bold text-strong">Checking session</h1>
          <p className="mt-2 text-sm leading-6 text-muted">Verifying your secure session before opening the investigation console.</p>
        </section>
      </main>
    );
  }

  if (status === "signed-out") {
    return <Navigate to="/login" replace state={{ from: location.pathname }} />;
  }

  return <>{children}</>;
}

function LoginPage() {
  const navigate = useNavigate();
  const location = useLocation();
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [loading, setLoading] = useState(false);
  const [checkingSession, setCheckingSession] = useState(true);
  const [hasSession, setHasSession] = useState(false);
  const from = typeof location.state === "object" && location.state && "from" in location.state ? String(location.state.from) : "/app/upload";

  useEffect(() => {
    if (!SUPABASE_AUTH_ENABLED || !supabase) {
      setCheckingSession(false);
      return undefined;
    }
    let mounted = true;
    refreshStoredSupabaseSession().then((session) => {
      if (!mounted) return;
      setHasSession(Boolean(session?.access_token));
      setCheckingSession(false);
    }).catch(() => {
      if (!mounted) return;
      setHasSession(false);
      setCheckingSession(false);
    });
    return () => {
      mounted = false;
    };
  }, []);

  async function signIn(event?: FormEvent<HTMLFormElement>) {
    event?.preventDefault();
    if (!supabase) {
      toast.error("Supabase Auth is not configured for this build.");
      return;
    }
    setLoading(true);
    const { data, error } = await supabase.auth.signInWithPassword({ email, password });
    setLoading(false);
    if (error) {
      toast.error(error.message);
      return;
    }
    setCurrentAccessToken(data.session?.access_token);
    toast.success("Secure session verified");
    navigate(from, { replace: true });
  }

  async function signOut() {
    if (supabase) await supabase.auth.signOut();
    setCurrentAccessToken();
    setHasSession(false);
    toast.success("Signed out");
  }

  return (
    <main className="auth-shell flex min-h-screen items-center justify-center px-4">
      <section className="auth-panel w-full max-w-md border border-[var(--border)] bg-[var(--panel)] p-6 shadow-sm">
        <div className="mb-6">
          <Link to="/" className="font-mono text-xs font-semibold uppercase tracking-[0.14em] text-accent">NETRA / Secure access</Link>
          <h1 className="mt-6 text-4xl font-normal text-strong">Enter the investigation console.</h1>
          <p className="mt-2 text-sm text-muted">Authorized officers only. Accounts and roles are provisioned by a Netra administrator.</p>
        </div>
        {!SUPABASE_AUTH_ENABLED && <Alert>Set VITE_SUPABASE_URL and VITE_SUPABASE_ANON_KEY, then rebuild the frontend.</Alert>}
        {checkingSession && <Alert>Checking whether this browser already has an active Netra session.</Alert>}
        {hasSession && (
          <div className="mt-4 grid gap-3">
            <Alert>You are already signed in on this browser. Continue to the investigation console or sign out to use another officer account.</Alert>
            <Button type="button" onClick={() => navigate(from, { replace: true })}>Continue to investigation console</Button>
            <Button type="button" variant="secondary" onClick={signOut}>Sign out</Button>
          </div>
        )}
        {!hasSession && <form className="mt-4 grid gap-3" onSubmit={signIn}>
          <label className="grid gap-1 text-sm font-semibold text-strong">
            Email
            <Input value={email} onChange={(event) => setEmail(event.target.value)} placeholder="officer@example.com" type="email" autoComplete="email" />
          </label>
          <label className="grid gap-1 text-sm font-semibold text-strong">
            Password
            <Input value={password} onChange={(event) => setPassword(event.target.value)} placeholder="Password" type="password" autoComplete="current-password" />
          </label>
          <Button type="submit" disabled={loading || !email || !password}>
            {loading ? "Signing in..." : "Sign in"}
          </Button>
        </form>}
      </section>
    </main>
  );
}

function LanguageControl() {
  const { language, setLanguage } = useNetra();
  return (
    <Select value={language} onValueChange={(value) => setLanguage(value as Language)}>
      <SelectTrigger className="min-w-28">
        <Languages className="size-4" />
        <SelectValue />
      </SelectTrigger>
      <SelectContent>
        <SelectItem value="English">English</SelectItem>
        <SelectItem value="Hindi">Hindi</SelectItem>
        <SelectItem value="Gujarati">Gujarati</SelectItem>
      </SelectContent>
    </Select>
  );
}

function ModuleRoute({ module, children }: { module: DeploymentModuleKey; children: ReactNode }) {
  const { deploymentAccess } = useNetra();
  const access = deploymentAccess.modules[module];
  if (!deploymentAccess.verified) {
    return <PageFrame title="Checking access" description="Verifying your role and the active deployment profile."><div /></PageFrame>;
  }
  if (!access.visible) return <Navigate to="/app/upload" replace />;
  if (!access.enabled) {
    return (
      <PageFrame title="Not configured" description={access.reason}>
        <Alert>{module === "lab" ? "Use normal evidence upload for this deployment. Native capture must run through an enrolled external sensor and replay requires an isolated lab environment." : "This operation is intentionally unavailable in the active deployment profile. No action was simulated or queued."}</Alert>
        <div className="surface rounded-[1.5rem] p-5">
          <MetadataRow label="Deployment profile" value={deploymentAccess.profile} />
          <MetadataRow label="Module" value={module} />
          <MetadataRow label="Status" value="Disabled" />
        </div>
      </PageFrame>
    );
  }
  return <>{children}</>;
}

function AppShell() {
  const [sidebarCollapsed, setSidebarCollapsed] = useState(false);
  return (
    <div className="min-h-screen bg-[var(--charcoal-deep)]">
      <div className="flex">
        <motion.aside
          animate={{ width: sidebarCollapsed ? 80 : 288 }}
          className="no-print fixed inset-y-0 left-0 hidden border-r border-[var(--border)] bg-[var(--bg)] p-4 lg:flex lg:flex-col"
        >
          <SidebarContent collapsed={sidebarCollapsed} onToggle={() => setSidebarCollapsed((value) => !value)} />
        </motion.aside>
        <div className={cn("min-w-0 flex-1 transition-[padding] duration-300", sidebarCollapsed ? "lg:pl-20" : "lg:pl-72")}>
          <TopBar />
          <div className="app-main-canvas p-4 sm:p-6">
            <Routes>
              <Route index element={<Navigate to="upload" replace />} />
              <Route path="upload" element={<UploadPage />} />
              <Route path="overview" element={<DashboardPage />} />
              <Route path="activity" element={<SuspiciousActivityPage />} />
              <Route path="evidence" element={<TrafficEvidencePage />} />
              <Route path="report" element={<Navigate to="/app/reports" replace />} />
              <Route path="packets" element={<PacketExplorerPage />} />
              <Route path="sessions" element={<SessionsPage />} />
              <Route path="dashboard" element={<DashboardPage />} />
              <Route path="decoder" element={<ProtocolDecoderPage />} />
              <Route path="payloads" element={<PayloadInspectionPage />} />
              <Route path="detection" element={<ThreatDetectionPage />} />
              <Route path="ai-anomaly" element={<AiAnomalyPage />} />
              <Route path="graph" element={<GraphPage />} />
              <Route path="cases" element={<CasesPage />} />
              <Route path="cases/:caseId" element={<CaseDetailPage />} />
              <Route path="reports" element={<EvidenceReportPage />} />
              <Route path="reports/:caseId" element={<ReportPage />} />
              <Route path="exports" element={<ExportCenterPage />} />
              <Route path="lab" element={<ModuleRoute module="lab"><LabToolsPage /></ModuleRoute>} />
              <Route path="compliance" element={<CompliancePage />} />
              <Route path="settings" element={<ModuleRoute module="system"><SettingsPage /></ModuleRoute>} />
              <Route path="settings/technical-status" element={<ModuleRoute module="system"><SystemPage /></ModuleRoute>} />
              <Route path="settings/sensors" element={<ModuleRoute module="sensors"><SensorsPage /></ModuleRoute>} />
              <Route path="settings/schedules" element={<ModuleRoute module="schedules"><SchedulesPage /></ModuleRoute>} />
              <Route path="settings/integrations" element={<ModuleRoute module="integrations"><IntegrationsPage /></ModuleRoute>} />
              <Route path="settings/retention" element={<ModuleRoute module="retention"><RetentionPage /></ModuleRoute>} />
              <Route path="system" element={<Navigate to="/app/settings/technical-status" replace />} />
              <Route path="sensors" element={<Navigate to="/app/settings/sensors" replace />} />
              <Route path="schedules" element={<Navigate to="/app/settings/schedules" replace />} />
              <Route path="integrations" element={<Navigate to="/app/settings/integrations" replace />} />
              <Route path="retention" element={<Navigate to="/app/settings/retention" replace />} />
            </Routes>
          </div>
        </div>
      </div>
    </div>
  );
}

function SidebarContent({ collapsed = false, onToggle }: { collapsed?: boolean; onToggle?: () => void }) {
  const { t, deploymentAccess } = useNetra();
  const navItem = (icon: LucideIcon, label: string, href: string): [LucideIcon, string, string] => [icon, label, href];
  const navGroups: { label: string; items: [LucideIcon, string, string][] }[] = [
    {
      label: t("mainWorkflow"),
      items: [
        navItem(Upload, "Start Investigation", "/app/upload"),
        navItem(FileSearch, t("cases"), "/app/cases"),
        navItem(FileText, t("evidenceReport"), "/app/reports"),
        navItem(AlertTriangle, t("suspiciousActivity"), "/app/activity"),
        navItem(Database, t("trafficEvidence"), "/app/evidence"),
      ],
    },
    ...(deploymentAccess.modules.lab.visible ? [{
      label: "Lab Tools",
      items: [navItem(Activity, "Capture and Replay", "/app/lab")],
    }] : []),
    ...(deploymentAccess.modules.system.visible ? [{
      label: "Settings",
      items: [navItem(SettingsIcon, "Settings", "/app/settings")],
    }] : []),
  ];
  return (
    <>
      <div className={cn("mb-8 flex items-center", collapsed ? "flex-col gap-3" : "justify-between gap-2")}>
        <Link className={cn("flex min-w-0 items-center gap-3", collapsed && "justify-center")} to="/">
          <span className="flex size-10 shrink-0 items-center justify-center">
            <img className="size-full object-contain" src="/brand/netra-logo-mark.svg" alt="" aria-hidden="true" />
          </span>
          {!collapsed && (
            <motion.div initial={{ opacity: 0 }} animate={{ opacity: 1 }}>
              <div className="font-bold text-strong">Netra</div>
              <div className="text-xs text-muted">{t("sidebarSubtitle")}</div>
            </motion.div>
          )}
        </Link>
        {onToggle && (
          <Button variant="ghost" size="icon" onClick={onToggle} aria-label={t("collapseSidebar")}>
            {collapsed ? <PanelLeftOpen className="size-4" /> : <PanelLeftClose className="size-4" />}
          </Button>
        )}
      </div>
      <nav className="flex flex-col gap-4 overflow-y-auto pr-1">
        {navGroups.map((group) => (
          <div key={group.label} className="grid gap-1">
            {!collapsed && <div className="px-3 pb-1 text-[0.68rem] font-bold uppercase tracking-[0.16em] text-muted">{group.label}</div>}
            {group.items.map(([Icon, label, href]) => (
              <NavLink
                key={href}
                to={href}
                className={({ isActive }) =>
                  cn(
                    "group relative flex items-center gap-3 rounded-xl px-3 py-2.5 text-sm font-semibold text-muted transition hover:bg-[var(--surface-muted)] hover:text-strong",
                    collapsed && "justify-center px-0",
                    isActive && "bg-[var(--surface-muted)] text-strong",
                  )
                }
              >
                {({ isActive }) => (
                  <>
                    <span className={cn("absolute left-0 h-6 w-0.5 rounded-full bg-[var(--accent)] opacity-0 transition", isActive && "opacity-100")} />
                    <Icon className="size-4 shrink-0" />
                    {!collapsed && <span>{label}</span>}
                  </>
                )}
              </NavLink>
            ))}
          </div>
        ))}
      </nav>
    </>
  );
}

function TopBar() {
  const { t } = useNetra();
  const [mobileOpen, setMobileOpen] = useState(false);
  return (
    <header className="technical-topbar no-print sticky top-0 z-20 flex items-center justify-between gap-3 border-b border-[var(--border)] px-4 py-3 backdrop-blur-xl sm:px-6">
      <div className="flex min-w-0 items-center gap-3">
        <Sheet open={mobileOpen} onOpenChange={setMobileOpen}>
          <Button variant="ghost" size="icon" className="lg:hidden" onClick={() => setMobileOpen(true)} aria-label={t("openNavigation")}>
            <Menu className="size-5" />
          </Button>
          <SheetContent aria-describedby={undefined} className="left-0 right-auto w-72 border-l-0 border-r bg-[var(--bg)]">
            <SheetTitle className="sr-only">Mobile navigation</SheetTitle>
            <SidebarContent />
          </SheetContent>
        </Sheet>
        <div className="hidden min-w-72 items-center gap-2 rounded-full border border-[var(--border)] bg-[var(--surface-muted)] px-4 py-2 text-sm text-muted md:flex">
          <Search className="size-4" />
          {t("searchPlaceholder")}
        </div>
      </div>
      <div className="flex items-center gap-3">
        <LanguageControl />
        <Button asChild>
          <Link to="/app/reports">{t("generateReport")}</Link>
        </Button>
      </div>
    </header>
  );
}

function UploadPage() {
  const { t, alertRecords, decodedProtocols, deploymentAccess, evidence, intakeForm, packets, payloadFindings, reloadAnalysis, sessions, setActiveCaseId, setIntakeForm, summary } = useNetra();
  const navigate = useNavigate();
  const [draft, setDraft] = useState<EvidenceIntakeForm>(intakeForm);
  const [selectedFile, setSelectedFile] = useState<File | null>(null);
  const [processing, setProcessing] = useState(false);
  const [uploadStage, setUploadStage] = useState<UploadStage>("idle");
  const [uploadProgress, setUploadProgress] = useState(0);
  const [uploadTransfer, setUploadTransfer] = useState<UploadTransferState>({
    bytesUploaded: 0,
    speedBytesPerSecond: 0,
    etaSeconds: null,
    paused: false,
    retryAttempt: 0,
    message: "",
  });
  const fileInputRef = useRef<HTMLInputElement | null>(null);
  const resumableUploadRef = useRef<ResumableUploadHandle | null>(null);
  const transferSampleRef = useRef({ bytes: 0, timestamp: 0, speed: 0 });
  const [uploadResult, setUploadResult] = useState<UploadResult | null>(null);
  const [normalization, setNormalization] = useState<EvidenceNormalizationPreview | null>(null);
  const [uploadIdempotencyKey, setUploadIdempotencyKey] = useState(() => window.crypto.randomUUID());
  const activeJobPollRef = useRef<string | null>(null);
  const selectedFileExtensionAllowed = selectedFile ? fileExtensionAllowed(selectedFile, draft.evidenceType) : true;
  const selectedFileTooLarge = Boolean(selectedFile && selectedFile.size > MAX_UPLOAD_MB * 1024 * 1024);

  useEffect(() => {
    if (!deploymentAccess.verified) return;
    setDraft((current) => ({
      ...current,
      investigator: deploymentAccess.user,
      department: deploymentAccess.department,
    }));
  }, [deploymentAccess.department, deploymentAccess.user, deploymentAccess.verified]);
  const effectiveExtensionAllowed = normalization ? normalization.extensionAllowed !== false : selectedFileExtensionAllowed;
  const normalizationCode = normalization?.code ?? "";
  const normalizationBlocked = Boolean(
    selectedFile && (
      selectedFileTooLarge ||
      !effectiveExtensionAllowed ||
      normalization?.extensionAllowed === false ||
      normalization?.validForSelectedType === false
    )
  );
  const normalizationTone: "normal" | "danger" | "success" = selectedFile && normalizationBlocked ? "danger" : selectedFile && normalization?.validForSelectedType ? "success" : "normal";
  const bpfAvailableForEvidence = BPF_FILTER_ENABLED && (
    draft.evidenceType === "PCAP" ||
    (draft.evidenceType === "Auto-detect" && (!normalization || normalization.normalizedType === "PCAP"))
  );
  const normalizationLabel =
    !selectedFile ? "" :
    !normalization ? "Checking" :
    normalizationCode === "upload_too_large" ? "File too large" :
    normalizationCode === "unsupported_evidence_extension" || normalization.extensionAllowed === false ? "Unsupported file type" :
    normalization.validForSelectedType ? "Verified" :
    "Mismatch";
  const uploadStageLabel: Record<UploadStage, string> = {
    idle: "Ready",
    uploading: "Uploading evidence",
    processing: "Upload complete — validating, hashing, encrypting, and analyzing",
    queued: "Encrypted and queued for analysis",
    complete: "Evidence analysis complete",
    failed: "Evidence processing failed",
  };

  function update<K extends keyof EvidenceIntakeForm>(key: K, value: EvidenceIntakeForm[K]) {
    setDraft((current) => ({ ...current, [key]: value }));
  }

  function selectEvidenceFile(file: File | null) {
    setSelectedFile(file);
    setNormalization(null);
    setUploadResult(null);
    setUploadStage("idle");
    setUploadProgress(0);
    setUploadTransfer({ bytesUploaded: 0, speedBytesPerSecond: 0, etaSeconds: null, paused: false, retryAttempt: 0, message: "" });
    resumableUploadRef.current = null;
    transferSampleRef.current = { bytes: 0, timestamp: 0, speed: 0 };
    setUploadIdempotencyKey(window.crypto.randomUUID());
  }

  useEffect(() => {
    if (!selectedFile) {
      setNormalization(null);
      return;
    }
    if (selectedFileTooLarge) {
      const reason = `This deployment accepts files up to ${MAX_UPLOAD_MB} MiB. The selected file is ${formatBytes(selectedFile.size)}.`;
      setNormalization({
        code: "upload_too_large",
        selectedType: draft.evidenceType,
        detectedType: "Not checked",
        normalizedType: "Unknown",
        recommendedType: draft.evidenceType,
        validForSelectedType: false,
        valid: false,
        confidence: 0,
        parser: "none",
        reason,
        message: reason,
        signals: ["client-size-limit"],
      });
      return;
    }
    let cancelled = false;
    const form = new FormData();
    const previewFile = selectedFile.size > NORMALIZATION_PREVIEW_BYTES
      ? new File([selectedFile.slice(0, NORMALIZATION_PREVIEW_BYTES)], selectedFile.name, { type: selectedFile.type, lastModified: selectedFile.lastModified })
      : selectedFile;
    form.append("file", previewFile);
    form.append("evidenceType", draft.evidenceType);
    fetch(`${API_BASE}/evidence/normalize-preview`, { method: "POST", headers: netraHeaders(), body: form })
      .then(async (response) => {
        const payload = await response.json();
        if (!response.ok) throw new Error(payload.error ?? "Evidence normalization preview failed");
        if (!cancelled) setNormalization(payload);
      })
      .catch(() => {
        if (!cancelled) setNormalization(localNormalizationPreview(selectedFile, draft.evidenceType));
      });
    return () => {
      cancelled = true;
    };
  }, [selectedFile, selectedFileTooLarge, draft.evidenceType]);

  async function startResumableProcessing(file: File) {
    const accessToken = await ensureCurrentAccessToken();
    if (!accessToken) throw new Error("Your sign-in session expired. Sign in again before uploading evidence.");
    const createResponse = await fetch(`${API_BASE}/evidence/upload-sessions`, {
      method: "POST",
      headers: netraHeaders({ "Content-Type": "application/json", "Idempotency-Key": uploadIdempotencyKey }),
      body: JSON.stringify({
        caseId: draft.caseNumber,
        filename: file.name,
        sizeBytes: file.size,
        contentType: file.type || "application/octet-stream",
        lastModified: String(file.lastModified),
        evidenceType: draft.evidenceType,
        sourceLocation: draft.sourceLocation,
        priority: draft.priority,
        remarks: draft.remarks,
        flags: draft.flags ?? [],
        sourceIp: draft.sourceIp,
        destinationIp: draft.destinationIp,
        protocol: draft.protocol,
        port: draft.port,
        durationSeconds: draft.durationSeconds,
        packetLimit: draft.packetLimit,
        bpfFilter: draft.bpfFilter,
      }),
    });
    const created = await createResponse.json() as DirectUploadSession & { error?: string };
    if (!createResponse.ok) throw new Error(created.error ?? "A resumable upload session could not be created.");

    transferSampleRef.current = { bytes: 0, timestamp: performance.now(), speed: 0 };
    const handle = beginResumableUpload(file, created, accessToken, {
      onProgress: ({ bytesUploaded, bytesTotal, percentage }) => {
        const now = performance.now();
        const previous = transferSampleRef.current;
        const elapsedSeconds = Math.max(0.001, (now - previous.timestamp) / 1000);
        let speed = previous.speed;
        if (bytesUploaded >= previous.bytes && elapsedSeconds >= 0.2) {
          const instantSpeed = (bytesUploaded - previous.bytes) / elapsedSeconds;
          speed = previous.speed > 0 ? previous.speed * 0.7 + instantSpeed * 0.3 : instantSpeed;
          transferSampleRef.current = { bytes: bytesUploaded, timestamp: now, speed };
        }
        setUploadProgress(Math.min(100, Math.round(percentage)));
        setUploadTransfer((current) => ({
          ...current,
          bytesUploaded,
          speedBytesPerSecond: speed,
          etaSeconds: speed > 0 ? Math.max(0, (bytesTotal - bytesUploaded) / speed) : null,
          paused: false,
          message: current.retryAttempt > 0 ? "Connection restored; upload is continuing." : "Resumable upload active.",
        }));
      },
      onRetry: (attempt) => {
        setUploadTransfer((current) => ({
          ...current,
          retryAttempt: attempt,
          message: `Network interruption detected. Automatic retry ${attempt} is scheduled.`,
        }));
      },
      onResumed: () => {
        setUploadTransfer((current) => ({ ...current, message: "A previous partial upload was found and resumed." }));
      },
    });
    resumableUploadRef.current = handle;
    await handle.completion;
    resumableUploadRef.current = null;
    setUploadProgress(100);
    setUploadStage("processing");
    setUploadTransfer((current) => ({ ...current, bytesUploaded: file.size, etaSeconds: 0, message: "Upload complete. Server validation is running." }));

    const finalizeResponse = await fetch(`${API_BASE}/evidence/upload-sessions/${created.id}/finalize`, {
      method: "POST",
      headers: netraHeaders({ "Content-Type": "application/json" }),
      body: "{}",
    });
    const finalized = await finalizeResponse.json() as DirectUploadSession & { error?: string };
    if (!finalizeResponse.ok) throw new Error(finalized.error ?? "The uploaded evidence could not be finalized.");
    if (!finalized.jobId) throw new Error("The upload was verified, but durable analysis has not been queued yet.");

    setActiveCaseId(finalized.caseId);
    setUploadStage("queued");
    setUploadResult({ jobId: finalized.jobId, filename: file.name });
    window.localStorage.setItem(ACTIVE_UPLOAD_JOB_KEY, JSON.stringify({ jobId: finalized.jobId, caseId: finalized.caseId }));
    toast.success("Resumable evidence upload verified and queued for analysis.");
    void followUploadJob(finalized.jobId, finalized.caseId);
  }

  async function toggleResumablePause() {
    const handle = resumableUploadRef.current;
    if (!handle) return;
    if (handle.isPaused()) {
      handle.resume();
      setUploadTransfer((current) => ({ ...current, paused: false, message: "Upload resumed." }));
      return;
    }
    await handle.pause();
    setUploadTransfer((current) => ({ ...current, paused: true, message: "Upload paused. Resume when the connection is ready." }));
  }

  async function startProcessing() {
    if (!selectedFile) {
      toast.error("Choose an evidence file first.");
      return;
    }
    if (selectedFileTooLarge) {
      toast.error(`Choose a file no larger than ${MAX_UPLOAD_MB} MiB for this deployment.`);
      return;
    }
    if (normalizationBlocked) {
      toast.error(normalization?.reason ?? "Fix the evidence type or choose a supported file before analysis.");
      return;
    }
    setIntakeForm(draft);
    setProcessing(true);
    setUploadStage("uploading");
    setUploadProgress(0);
    const form = new FormData();
    form.append("caseId", draft.caseNumber);
    form.append("file", selectedFile);
    form.append("evidenceType", draft.evidenceType);
    form.append("sourceLocation", draft.sourceLocation);
    form.append("priority", draft.priority);
    form.append("remarks", draft.remarks);
    form.append("sourceIp", draft.sourceIp);
    form.append("destinationIp", draft.destinationIp);
    form.append("protocol", draft.protocol);
    form.append("port", draft.port);
    form.append("durationSeconds", draft.durationSeconds);
    form.append("packetLimit", draft.packetLimit);
    form.append("bpfFilter", draft.bpfFilter);
    form.append("flags", JSON.stringify(draft.flags ?? []));
    form.append("idempotencyKey", uploadIdempotencyKey);
    try {
      if (DIRECT_UPLOAD_ENABLED) {
        await startResumableProcessing(selectedFile);
        return;
      }
      const response = await uploadFormWithProgress<EvidenceUploadPayload>(
        "/evidence/upload",
        form,
        setUploadProgress,
        () => setUploadStage("processing"),
      );
      const payload = response.payload;
      if (!response.ok) {
        if (payload.code === "unsupported_evidence_extension" || payload.code === "evidence_type_mismatch" || payload.code === "evidence_type_unrecognized" || payload.code === "invalid_pcap") {
          setNormalization(payload as EvidenceNormalizationPreview);
        }
        setUploadStage("failed");
        throw new Error(payload.reason ?? payload.error ?? "Upload failed");
      }
      setActiveCaseId(payload.caseId ?? null);
      if (payload.status === "queued") {
        setUploadStage("queued");
        setUploadResult({ hash: payload.sha256, encryptedHash: payload.encrypted_sha256, keyId: payload.keyId, jobId: payload.jobId, steps: payload.job?.steps });
        toast.success("Evidence encrypted and queued for async worker analysis.");
        if (payload.jobId) {
          window.localStorage.setItem(ACTIVE_UPLOAD_JOB_KEY, JSON.stringify({ jobId: payload.jobId, caseId: payload.caseId }));
          void followUploadJob(payload.jobId, payload.caseId);
        }
        return;
      }
      await reloadAnalysis(payload.caseId ?? null);
      setUploadStage("complete");
      setUploadResult({
        topClass: payload.detectedAttackClasses?.[0],
        risk: payload.riskLevel,
        hash: payload.sha256,
        encryptedHash: payload.encrypted_sha256,
        keyId: payload.keyId,
        jobId: payload.jobId,
        filename: selectedFile.name,
        packets: payload.analysis?.packets,
        sessions: payload.analysis?.sessions,
        protocolsDecoded: payload.analysis?.protocolsDecoded,
        payloadFindings: payload.analysis?.payloadFindings,
        alerts: payload.analysis?.alerts,
        steps: payload.job?.steps,
      });
      toast.success(t("evidenceToast"));
    } catch (error) {
      setUploadStage("failed");
      toast.error(error instanceof Error ? error.message : "Evidence analysis failed");
    } finally {
      setProcessing(false);
    }
  }

  const followUploadJob = useCallback(async (jobId: string, caseId?: string) => {
    if (activeJobPollRef.current === jobId) return;
    activeJobPollRef.current = jobId;
    try {
      for (let attempt = 0; attempt < 120; attempt += 1) {
        const job = await apiGet<{ status: string; progress?: number; error?: string; steps?: { name: string; status: string }[] }>(`/jobs/${jobId}/status`).catch(() => null);
        if (job) {
          setUploadProgress(Math.max(0, Math.min(100, job.progress ?? 0)));
          setUploadResult((current) => ({ ...(current ?? {}), jobId, steps: job.steps }));
          if (job.status === "completed") {
            window.localStorage.removeItem(ACTIVE_UPLOAD_JOB_KEY);
            setUploadStage("complete");
            await reloadAnalysis(caseId);
            toast.success("Async evidence analysis completed.");
            return;
          }
          if (job.status === "failed" || job.status === "canceled") {
            window.localStorage.removeItem(ACTIVE_UPLOAD_JOB_KEY);
            setUploadStage("failed");
            toast.error(job.error || `Async evidence analysis ${job.status}.`);
            return;
          }
          setUploadStage("queued");
        }
        await new Promise((resolve) => window.setTimeout(resolve, 2000));
      }
      toast.error("Async analysis is still queued. Check System Monitor for worker health.");
    } finally {
      if (activeJobPollRef.current === jobId) activeJobPollRef.current = null;
    }
  }, [reloadAnalysis]);

  useEffect(() => {
    const raw = window.localStorage.getItem(ACTIVE_UPLOAD_JOB_KEY);
    if (!raw) return;
    try {
      const active = JSON.parse(raw) as { jobId?: string; caseId?: string };
      if (!active.jobId) return;
      setUploadStage("queued");
      setUploadResult((current) => ({ ...(current ?? {}), jobId: active.jobId }));
      if (active.caseId) setActiveCaseId(active.caseId);
      void followUploadJob(active.jobId, active.caseId);
    } catch {
      window.localStorage.removeItem(ACTIVE_UPLOAD_JOB_KEY);
    }
  }, [followUploadJob, setActiveCaseId]);

  return (
    <PageFrame title={t("uploadTitle")} description={t("uploadDesc")}>
      <div className="grid gap-5 xl:grid-cols-[1.05fr_0.95fr]">
        <div className="surface rounded-[1.5rem] p-6">
          <div className="flex flex-wrap items-start justify-between gap-4">
            <div>
              <Badge>Primary action</Badge>
              <h2 className="mt-3 text-2xl font-black text-strong">Upload PCAP Evidence</h2>
              <p className="mt-2 max-w-2xl text-sm leading-6 text-muted">Choose a real PCAP or PCAPNG file. Netra will validate, hash, encrypt, analyze, and prepare the investigation automatically.</p>
            </div>
            <UploadCloud className="size-9 text-accent" aria-hidden="true" />
          </div>
          <input ref={fileInputRef} className="hidden" type="file" accept={acceptForEvidenceType(draft.evidenceType)} onChange={(event) => selectEvidenceFile(event.target.files?.[0] ?? null)} />
          <div className="mt-6 rounded-[1.25rem] border border-dashed border-[var(--border-strong)] bg-[var(--surface-muted)] p-5">
            <div className="grid gap-4 md:grid-cols-[1fr_auto] md:items-center">
              <div>
                <div className="text-sm font-bold text-strong">{selectedFile?.name ?? "No file selected"}</div>
                <div className="mt-1 text-xs text-muted">{selectedFile ? `${formatBytes(selectedFile.size)} | ${fileExtension(selectedFile) || "no extension"} | ${MAX_UPLOAD_MB} MiB deployment limit` : `${evidenceTypeHelper(draft.evidenceType)}. Maximum ${MAX_UPLOAD_MB} MiB.`}</div>
              </div>
              <Button type="button" variant="secondary" onClick={() => fileInputRef.current?.click()}>
                <Upload className="size-4" />
                Choose file
              </Button>
            </div>
            {selectedFile && !effectiveExtensionAllowed && (
              <div className="mt-4 rounded-xl border border-[#7f2f23] bg-[#2b1410] px-4 py-3 text-sm text-[#ffd0c4]">
                Unsupported file type {fileExtension(selectedFile) || "(none)"}. {evidenceTypeHelper(draft.evidenceType)}.
              </div>
            )}
            {selectedFileTooLarge && (
              <div className="mt-4 rounded-xl border border-[#7f2f23] bg-[#2b1410] px-4 py-3 text-sm text-[#ffd0c4]">
                The selected file is {formatBytes(selectedFile?.size ?? 0)}. This deployment is verified for files up to {MAX_UPLOAD_MB} MiB.
              </div>
            )}
            <div className="mt-5 flex flex-wrap items-center gap-3">
              <Button onClick={startProcessing} disabled={processing || !selectedFile || normalizationBlocked || selectedFileTooLarge}>
                {processing ? uploadStageLabel[uploadStage] : "Analyze Evidence"}
              </Button>
              {selectedFile && <Badge variant={normalizationBlocked ? "destructive" : "secondary"}>{normalizationBlocked ? normalizationLabel : "Ready to analyze"}</Badge>}
            </div>
          </div>
          {uploadStage !== "idle" && (
            <div className={cn("mt-5 rounded-[1.25rem] border p-4", uploadStage === "failed" ? "border-[#7f2f23] bg-[#2b1410]" : "border-[var(--border)] bg-[var(--surface-muted)]")} aria-live="polite">
              <div className="flex flex-wrap items-center justify-between gap-3">
                <div>
                  <h3 className="text-sm font-black text-strong">{uploadStageLabel[uploadStage]}</h3>
                  <p className="mt-1 text-xs leading-5 text-muted">
                    {uploadStage === "uploading" && DIRECT_UPLOAD_ENABLED
                      ? `${formatBytes(uploadTransfer.bytesUploaded)} of ${formatBytes(selectedFile?.size ?? 0)} · ${uploadTransfer.speedBytesPerSecond > 0 ? `${formatBytes(uploadTransfer.speedBytesPerSecond)}/s` : "measuring speed"} · ${formatEta(uploadTransfer.etaSeconds)}`
                      : uploadStage === "uploading" ? `${uploadProgress}% of file bytes sent to Netra.` : uploadStage === "processing" ? "The browser upload is finished. Server-side evidence checks and analysis are still running." : uploadStage === "queued" ? "The worker status below will update automatically." : uploadStage === "complete" ? "Hashes, case records, findings, and report data are ready." : "Review the error message, correct the file or metadata, and retry."}
                  </p>
                  {DIRECT_UPLOAD_ENABLED && uploadTransfer.message && <p className="mt-1 text-xs leading-5 text-muted">{uploadTransfer.message}</p>}
                </div>
                <div className="flex items-center gap-2">
                  {DIRECT_UPLOAD_ENABLED && uploadStage === "uploading" && resumableUploadRef.current && (
                    <Button type="button" variant="secondary" onClick={() => void toggleResumablePause()}>
                      {uploadTransfer.paused ? "Resume" : "Pause"}
                    </Button>
                  )}
                  <Badge variant={uploadStage === "failed" ? "destructive" : "secondary"}>{uploadStage === "uploading" ? `${uploadProgress}%` : uploadStage}</Badge>
                </div>
              </div>
              <Progress className="mt-4" value={uploadProgress} aria-label="Evidence upload byte progress" />
            </div>
          )}
          {selectedFile && (
            <div
              className={cn(
                "mt-5 rounded-[1.25rem] border p-4 transition-colors",
                normalizationTone === "danger" && "border-[#7f2f23] bg-[#2b1410]",
                normalizationTone === "success" && "border-[#2f6b4f] bg-[#102017]",
                normalizationTone === "normal" && "border-[var(--border)] bg-[var(--surface-muted)]",
              )}
            >
              <div className="flex flex-wrap items-start justify-between gap-3">
                <div>
                  <h3 className="text-sm font-black text-strong">Evidence Normalization</h3>
                  <p className="mt-1 text-xs leading-5 text-muted">Netra checks whether the selected evidence type matches the file before storage and ML analysis.</p>
                </div>
                <Badge variant={normalizationTone === "danger" ? "destructive" : "secondary"}>{normalizationLabel}</Badge>
              </div>
              <div className="mt-4 grid gap-3 sm:grid-cols-2 xl:grid-cols-4">
                <NormalizationMetric label="Selected type" value={normalization?.selectedType ?? draft.evidenceType} />
                <NormalizationMetric label="Detected type" value={normalization?.detectedType ?? "Checking"} />
                <NormalizationMetric label="Allowed extensions" value={(normalization?.allowedExtensions?.length ? normalization.allowedExtensions : allowedExtensionsForType(draft.evidenceType)).join(", ")} compact />
                <NormalizationMetric label="Parser / confidence" value={normalization ? `${normalization.parser} | ${normalization.confidence}%` : "-"} />
              </div>
              <p className="mt-3 text-sm leading-6 text-muted">{normalization?.reason ?? "Reading file signature and sample metadata..."}</p>
              {normalization && !normalization.validForSelectedType && normalization.detectedType !== "Unknown" && (
                <Button className="mt-3" type="button" variant="secondary" onClick={() => update("evidenceType", normalization.recommendedType as EvidenceIntakeForm["evidenceType"])}>
                  Use detected type: {normalization.recommendedType}
                </Button>
              )}
            </div>
          )}
          <div className="mt-5 grid gap-3 sm:grid-cols-2 lg:grid-cols-5">
            {[[t("packetsParsed"), formatNumber(uploadResult?.packets ?? packets.length)], [t("sessionsReconstructed"), uploadResult?.sessions ?? sessions.length], [t("protocolsDecoded"), uploadResult?.protocolsDecoded ?? decodedProtocols.length], [t("payloadFindings"), uploadResult?.payloadFindings ?? payloadFindings.length], [t("alertsGenerated"), uploadResult?.alerts ?? alertRecords.length]].map(([label, value]) => (
              <div key={label} className="rounded-xl border border-[var(--border)] bg-[var(--surface-muted)] p-3">
                <div className="text-xs uppercase text-muted">{label}</div>
                <div className="mt-1 text-xl font-black text-strong">{value}</div>
              </div>
            ))}
          </div>
        </div>
        <div className="surface rounded-[1.5rem] p-5">
          <h2 className="text-xl font-black text-strong">Case Details</h2>
          <p className="mt-1 text-sm text-muted">Investigator and department come from your authenticated server profile; evidence details remain editable for this investigation.</p>
          <div className="mt-5 grid gap-4 md:grid-cols-2">
            <Field label={t("caseNumber")} value={draft.caseNumber} onChange={(value) => update("caseNumber", value)} disabled />
            <Field label={t("investigator")} value={draft.investigator || "Loading authenticated profile..."} onChange={() => undefined} disabled />
            <Field label={t("department")} value={draft.department || "Loading authenticated profile..."} onChange={() => undefined} disabled />
            <Field label={t("sourceLocation")} value={draft.sourceLocation} onChange={(value) => update("sourceLocation", value)} />
            <SelectField label={t("priority")} value={draft.priority || "Select priority"} values={["Select priority", "Standard", "Urgent", "Critical"]} onChange={(value) => update("priority", value === "Select priority" ? "" : value as EvidenceIntakeForm["priority"])} />
            <SelectField label={t("evidenceType")} value={draft.evidenceType} values={EVIDENCE_TYPE_OPTIONS} onChange={(value) => update("evidenceType", value as EvidenceIntakeForm["evidenceType"])} helper={evidenceTypeHelper(draft.evidenceType)} tone={normalizationTone} />
            <label className="flex flex-col gap-2 md:col-span-2">
              <span className="text-sm font-semibold text-strong">{t("remarks")}</span>
              <Textarea value={draft.remarks} onChange={(event) => update("remarks", event.target.value)} placeholder="Optional notes for the report" />
            </label>
            <div className="md:col-span-2">
              <div className="text-sm font-semibold text-strong">Case flags</div>
              <p className="mt-1 text-xs leading-5 text-muted">Optional tags to help connect related investigations later.</p>
              <div className="mt-3 flex flex-wrap gap-2">
                {CASE_FLAG_OPTIONS.map((flag) => {
                  const active = (draft.flags ?? []).includes(flag);
                  return (
                    <Button
                      key={flag}
                      type="button"
                      size="sm"
                      variant={active ? "default" : "secondary"}
                      onClick={() => update("flags", active ? (draft.flags ?? []).filter((item) => item !== flag) : [...(draft.flags ?? []), flag])}
                    >
                      {flag}
                    </Button>
                  );
                })}
              </div>
            </div>
          </div>
        </div>
      </div>

      <details className="surface rounded-[1.5rem] p-5">
        <summary className="cursor-pointer text-lg font-black text-strong">Advanced Options</summary>
        <p className="mt-2 text-sm leading-6 text-muted">Optional filters for investigators who already know which source, destination, protocol, or port matters. Leave these blank for normal analysis.</p>
        <div className="mt-5 grid gap-4 lg:grid-cols-2">
          <div>
            <h3 className="font-bold text-strong">Analysis filters</h3>
            <div className="mt-3 grid gap-3 md:grid-cols-2">
              <Field label={t("sourceIp")} value={draft.sourceIp} onChange={(value) => update("sourceIp", value)} />
              <Field label={t("destinationIp")} value={draft.destinationIp} onChange={(value) => update("destinationIp", value)} />
              <SelectField label={t("protocol")} value={draft.protocol || "all"} values={["all", "DNS", "TLS", "HTTP", "SSH", "FTP", "SMTP", "SMB", "TCP", "UDP", "ICMP"]} onChange={(value) => update("protocol", value === "all" ? "" : value)} />
              <Field label={t("port")} value={draft.port} onChange={(value) => update("port", value)} />
            </div>
          </div>
          <div>
            <h3 className="font-bold text-strong">Capture bounds</h3>
            <div className="mt-3 grid gap-3 md:grid-cols-2">
              <Field label="Duration limit (seconds)" value={draft.durationSeconds} onChange={(value) => update("durationSeconds", value)} />
              <Field label="Packet limit" value={draft.packetLimit} onChange={(value) => update("packetLimit", value)} />
              <div className="md:col-span-2">
                <Field label="Expert BPF capture filter" value={draft.bpfFilter} onChange={(value) => update("bpfFilter", value)} disabled={!bpfAvailableForEvidence} />
                <p className="mt-2 text-xs text-muted">
                  {!BPF_FILTER_ENABLED
                    ? "Offline BPF filtering is unavailable in this deployment. Use the source, destination, protocol, port, duration, and packet-limit filters above."
                    : bpfAvailableForEvidence
                      ? "Applied by tcpdump to the complete PCAP before packet parsing. Most investigations should leave this blank."
                      : "BPF is available only for PCAP or PCAPNG evidence; the other analysis filters still apply to structured evidence."}
                </p>
              </div>
            </div>
          </div>
        </div>
      </details>

      {(uploadResult || evidence) && (
        <div className="surface rounded-[1.5rem] p-5 text-sm">
          <div className="font-bold text-strong">Latest immutable evidence</div>
          <div className="mt-3 grid gap-2 md:grid-cols-3">
            <MetadataRow label="Top class" value={uploadResult?.topClass ?? summary.topAttackClass} />
            <MetadataRow label="Risk" value={uploadResult?.risk ?? summary.riskLevel} />
            <MetadataRow label="Job" value={uploadResult?.jobId ?? "latest completed"} />
            <MetadataRow label="SHA-256" value={uploadResult?.hash ?? evidence?.sha256 ?? "-"} />
            <MetadataRow label="Encrypted SHA-256" value={uploadResult?.encryptedHash ?? evidence?.encryptedSha256 ?? "-"} />
            <MetadataRow label="Key ID" value={uploadResult?.keyId ?? evidence?.keyId ?? "dev-key-001"} />
          </div>
          <div className="mt-4 flex flex-wrap gap-2">
            {uploadResult?.steps?.map((step) => (
              <Badge key={step.name} variant={step.status === "completed" ? "secondary" : "warning"}>{step.name}: {step.status}</Badge>
            ))}
          </div>
          {uploadStage === "complete" && <Button className="mt-4" onClick={() => navigate("/app/overview")}>Open case overview</Button>}
        </div>
      )}
      <EvidenceCard />
    </PageFrame>
  );
}

function DashboardPage() {
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
          <Button asChild><Link to="/app/upload"><Upload size={16} />Upload PCAP</Link></Button>
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
          <Select value={activeCaseId ?? caseRecords[0]?.id ?? ""} onValueChange={(value) => setActiveCaseId(value)}>
            <SelectTrigger className="max-w-xs"><SelectValue placeholder="Select case" /></SelectTrigger>
            <SelectContent>{caseRecords.map((record) => <SelectItem key={record.id} value={record.id}>{record.id}</SelectItem>)}</SelectContent>
          </Select>
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
              <Button asChild><Link to="/app/activity"><AlertTriangle className="size-4" />Review activity</Link></Button>
              <Button asChild variant="secondary"><Link to="/app/evidence"><Database className="size-4" />Inspect evidence</Link></Button>
              <Button asChild variant="secondary"><Link to="/app/report"><FileText className="size-4" />Prepare report</Link></Button>
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

function PacketExplorerPage() {
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

function ProtocolDecoderPage() {
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

function PayloadInspectionPage() {
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

function SessionsPage() {
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

function ThreatDetectionPage() {
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

function AiAnomalyPage() {
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

function SuspiciousActivityPage() {
  const { t, activeCaseId, alertRecords: contextAlerts, anomalies: contextAnomalies, detectionMatches: contextDetectionMatches, networkFlows: contextFlows } = useNetra();
  const [alertRecords, setAlertRecords] = useState<AlertRecord[]>(contextAlerts);
  const [anomalies, setAnomalies] = useState<AnomalyRecord[]>(contextAnomalies);
  const [detectionMatches, setDetectionMatches] = useState<DetectionRuleMatch[]>(contextDetectionMatches);
  const [networkFlows, setNetworkFlows] = useState<NetworkFlow[]>(contextFlows);
  const [aiExplanation, setAiExplanation] = useState<{ mode: string; modelVersion: string; fallbackUsed: boolean; limitations: string[] } | null>(null);
  useEffect(() => {
    if (!activeCaseId) return;
    let cancelled = false;
    Promise.all([
      apiGet<{ results: AlertRecord[] }>(`/alerts?caseId=${encodeURIComponent(activeCaseId)}&limit=100`),
      apiGet<{ results: AnomalyRecord[] }>(`/anomalies?caseId=${encodeURIComponent(activeCaseId)}&limit=100`),
      apiGet<{ results: DetectionRuleMatch[] }>(`/detection/matches?caseId=${encodeURIComponent(activeCaseId)}&limit=100`),
      apiGet<{ edges?: { source: string; target: string; protocol: string; packets: number; bytes?: number; risk?: number; attackClass?: AttackClass; alertIds?: string[] }[] }>(`/graph?caseId=${encodeURIComponent(activeCaseId)}`),
      apiGet<{ mode: string; modelVersion: string; fallbackUsed: boolean; limitations: string[] }>(`/cases/${activeCaseId}/anomaly-explanation`),
    ]).then(([alertsPayload, anomalyPayload, detectionPayload, graphPayload, explanationPayload]) => {
      if (cancelled) return;
      setAlertRecords(alertsPayload.results);
      setAnomalies(anomalyPayload.results);
      setDetectionMatches(detectionPayload.results);
      setNetworkFlows(graphEdgesToFlows(graphPayload));
      setAiExplanation(explanationPayload);
    }).catch(() => undefined);
    return () => {
      cancelled = true;
    };
  }, [activeCaseId]);
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
  if (!alertRecords.length && !anomalies.length && !detectionMatches.length) {
    return (
      <PageFrame title={t("suspiciousActivity")} description={t("suspiciousActivityDesc")}>
        <div className="surface mx-auto flex max-w-2xl flex-col items-center gap-4 rounded-[1.5rem] p-8 text-center">
          <AlertTriangle size={34} aria-hidden="true" />
          <div>
            <h2 className="text-xl font-black text-strong">No suspicious activity yet</h2>
            <p className="mt-2 text-sm leading-6 text-muted">Upload a PCAP, replay evidence, or start a bounded sensor capture. Netra will automatically explain suspicious traffic here.</p>
          </div>
          <Button asChild><Link to="/app/upload"><Upload size={16} />Start investigation</Link></Button>
        </div>
      </PageFrame>
    );
  }
  return (
    <PageFrame title={t("suspiciousActivity")} description={t("suspiciousActivityDesc")}>
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
                  <Button asChild size="sm" variant="secondary"><Link to="/app/evidence"><Database className="size-4" />Open evidence</Link></Button>
                  <Button asChild size="sm" variant="secondary"><Link to="/app/report"><FileText className="size-4" />Prepare report</Link></Button>
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
          <div className="mt-4"><Button asChild variant="secondary"><Link to="/app/graph">Open full communication map</Link></Button></div>
        </TabsContent>
      </Tabs>
    </PageFrame>
  );
}

function TrafficEvidencePage() {
  const { t, activeCaseId } = useNetra();
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
  useEffect(() => {
    if (!activeCaseId) return;
    let cancelled = false;
    Promise.all([
      apiGet<{ results: PacketRecord[] }>(`/packets?caseId=${encodeURIComponent(activeCaseId)}&limit=120`),
      apiGet<{ results: SessionRecord[] }>(`/sessions?caseId=${encodeURIComponent(activeCaseId)}&limit=120`),
      apiGet<{ results: DecodedProtocolRecord[]; zeek?: ZeekEvidence }>(`/decoder/summary?caseId=${encodeURIComponent(activeCaseId)}`),
      apiGet<{ results: PayloadFinding[] }>(`/payloads?caseId=${encodeURIComponent(activeCaseId)}&limit=120`),
      apiGet<{ edges?: { source: string; target: string; protocol: string; packets: number; bytes?: number; risk?: number; attackClass?: AttackClass; alertIds?: string[] }[] }>(`/graph?caseId=${encodeURIComponent(activeCaseId)}`),
    ]).then(([packetPayload, sessionPayload, protocolPayload, payloadPayload, graphPayload]) => {
      if (cancelled) return;
      setPackets(packetPayload.results);
      setSessions(sessionPayload.results);
      setDecodedProtocols(protocolPayload.results);
      setZeek(protocolPayload.zeek ?? null);
      setPayloadFindings(payloadPayload.results);
      setNetworkFlows(graphEdgesToFlows(graphPayload));
    }).catch(() => undefined);
    return () => {
      cancelled = true;
    };
  }, [activeCaseId]);
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
  if (!packets.length && !sessions.length && !decodedProtocols.length && !payloadFindings.length) {
    return (
      <PageFrame title={t("trafficEvidence")} description={t("trafficEvidenceDesc")}>
        <div className="surface mx-auto flex max-w-2xl flex-col items-center gap-4 rounded-[1.5rem] p-8 text-center">
          <Database size={34} aria-hidden="true" />
          <div>
            <h2 className="text-xl font-black text-strong">No traffic evidence yet</h2>
            <p className="mt-2 text-sm leading-6 text-muted">Upload or capture network traffic first. Packets, sessions, protocols, and payload clues will be grouped here automatically.</p>
          </div>
          <Button asChild><Link to="/app/upload"><Upload size={16} />Add network evidence</Link></Button>
        </div>
      </PageFrame>
    );
  }
  return (
    <PageFrame title={t("trafficEvidence")} description={t("trafficEvidenceDesc")}>
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

function EvidenceReportPage() {
  const { t, activeCaseId, caseRecords, language, reloadAnalysis, summary, setActiveCaseId } = useNetra();
  const [selectedCaseId, setSelectedCaseId] = useState(activeCaseId ?? caseRecords[0]?.id ?? "");
  const [reports, setReports] = useState<ReportRecord[]>([]);
  const [exports, setExports] = useState<ExportRecord[]>([]);
  const [legalReview, setLegalReview] = useState<{ status: string; items: { name: string; status: string; detail: string }[] } | null>(null);
  const [busyAction, setBusyAction] = useState<string | null>(null);
  const currentCase = caseRecords.find((record) => record.id === selectedCaseId) ?? caseRecords[0];

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
          <Button asChild><Link to="/app/upload"><Upload size={16} />Start investigation</Link></Button>
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
          <label className="min-w-[18rem] max-w-xl flex-1">
            <span className="mb-2 block text-xs font-bold uppercase tracking-[0.12em] text-muted">Selected case</span>
            <Select value={currentCase.id} onValueChange={selectCase}>
            <SelectTrigger><SelectValue /></SelectTrigger>
            <SelectContent>{caseRecords.map((record) => <SelectItem key={record.id} value={record.id}>{record.id}</SelectItem>)}</SelectContent>
            </Select>
          </label>
        </div>
        <div className="mt-5 grid gap-4 md:grid-cols-4">
          <MetricTile label="Case" value={currentCase.id} detail={currentCase.status} />
          <MetricTile label="Risk" value={(currentCase.riskLevel ?? summary.riskLevel).toUpperCase()} detail={currentCase.topAttackClass ?? summary.topAttackClass} />
          <MetricTile label="Reports" value={reports.length} detail="Generated PDF/HTML artifacts" />
          <MetricTile label="Exports" value={exports.length} detail="JSON, CSV, and CEF bundles" />
        </div>
        <div className="mt-5 flex flex-wrap gap-3">
          <Button className="whitespace-nowrap" onClick={exportPdfReport} disabled={busyAction !== null}><FileText className="size-4" />{busyAction === "report" ? "Generating..." : "Generate and download PDF"}</Button>
          <Button className="whitespace-nowrap" variant="secondary" onClick={() => createExport("Evidence JSON")} disabled={busyAction !== null}><Download className="size-4" />Export JSON bundle</Button>
          <Button className="whitespace-nowrap" variant="secondary" onClick={() => createExport("Alert CSV")} disabled={busyAction !== null}><Download className="size-4" />Export alert CSV</Button>
          <Button className="whitespace-nowrap" variant="secondary" onClick={verifyEvidence} disabled={busyAction !== null || !currentCase.evidenceFileId}><Fingerprint className="size-4" />Verify evidence hash</Button>
        </div>
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

function AnomalyReviewPanel({ anomalies: scopedAnomalies, timeline }: { anomalies?: AnomalyRecord[]; timeline?: { time: string; mb?: number; alerts?: number; packets?: number; anomalies?: number; value?: number }[] }) {
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

function PacketEvidenceTable({ packets }: { packets: PacketRecord[] }) {
  return (
    <div className="surface-solid overflow-hidden rounded-[1.5rem]">
      <div className="overflow-x-auto p-4">
        <table className="w-full min-w-[920px] text-left text-sm">
          <thead className="border-b border-[var(--border)] text-xs uppercase text-muted"><tr><th className="py-3">Packet</th><th>Time</th><th>Source</th><th>Destination</th><th>Protocol</th><th>Session</th><th>Risk</th></tr></thead>
          <tbody>{packets.map((packet) => <tr key={packet.id} className="border-b border-[var(--border)]"><td className="py-3 font-bold text-strong">{packet.id}</td><td className="font-mono text-xs">{packet.timestamp}</td><td className="font-mono text-xs">{packet.sourceIp}:{packet.sourcePort}</td><td className="font-mono text-xs">{packet.destinationIp}:{packet.destinationPort}</td><td><Badge>{packet.protocol}</Badge></td><td>{packet.sessionId}</td><td>{packet.riskScore}</td></tr>)}</tbody>
        </table>
        {!packets.length && <div className="py-8 text-center text-sm text-muted">No packet rows found in this evidence file.</div>}
      </div>
      <div className="border-t border-[var(--border)] p-4"><Button asChild variant="secondary" size="sm"><Link to="/app/packets">Open advanced packet explorer</Link></Button></div>
    </div>
  );
}

function SessionEvidenceTable({ sessions }: { sessions: SessionRecord[] }) {
  return (
    <div className="surface-solid overflow-hidden rounded-[1.5rem]">
      <div className="overflow-x-auto p-4">
        <table className="w-full min-w-[880px] text-left text-sm">
          <thead className="border-b border-[var(--border)] text-xs uppercase text-muted"><tr><th className="py-3">Session</th><th>Source</th><th>Destination</th><th>Protocol</th><th>Duration</th><th>Packets</th><th>Risk</th></tr></thead>
          <tbody>{sessions.map((session) => <tr key={session.id} className="border-b border-[var(--border)]"><td className="py-3 font-bold text-strong">{session.id}</td><td>{session.source}</td><td>{session.destination}</td><td><Badge>{session.protocol}</Badge></td><td>{session.duration}</td><td>{session.packetCount}</td><td>{session.riskScore}</td></tr>)}</tbody>
        </table>
        {!sessions.length && <div className="py-8 text-center text-sm text-muted">No sessions were reconstructed from this evidence file.</div>}
      </div>
      <div className="border-t border-[var(--border)] p-4"><Button asChild variant="secondary" size="sm"><Link to="/app/sessions">Open session drilldown</Link></Button></div>
    </div>
  );
}

function ProtocolEvidenceTable({ protocols, zeek }: { protocols: DecodedProtocolRecord[]; zeek?: ZeekEvidence | null }) {
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
        <div className="border-t border-[var(--border)] p-4"><Button asChild variant="secondary" size="sm"><Link to="/app/decoder">Open protocol decoder</Link></Button></div>
      </div>
    </div>
  );
}

function PayloadEvidenceTable({ findings }: { findings: PayloadFinding[] }) {
  return (
    <div className="surface-solid overflow-hidden rounded-[1.5rem]">
      <div className="overflow-x-auto p-4">
        <table className="w-full min-w-[860px] text-left text-sm">
          <thead className="border-b border-[var(--border)] text-xs uppercase text-muted"><tr><th className="py-3">Finding</th><th>Packet</th><th>Session</th><th>Protocol</th><th>Type</th><th>Hidden</th><th>Risk</th><th>Pattern</th></tr></thead>
          <tbody>{findings.map((finding) => <tr key={finding.id} className="border-b border-[var(--border)]"><td className="py-3 font-bold text-strong">{finding.id}</td><td>{finding.packetId}</td><td>{finding.sessionId}</td><td><Badge>{finding.protocol}</Badge></td><td>{finding.payloadType}</td><td>{finding.hiddenData ? "yes" : "no"}</td><td><SeverityBadge severity={finding.risk} /></td><td>{finding.description ?? finding.matchedPattern}</td></tr>)}</tbody>
        </table>
        {!findings.length && <div className="py-8 text-center text-sm text-muted">No payload clues found in this evidence file.</div>}
      </div>
      <div className="border-t border-[var(--border)] p-4"><Button asChild variant="secondary" size="sm"><Link to="/app/payloads">Open payload drilldown</Link></Button></div>
    </div>
  );
}

function FlowEvidenceTable({ flows }: { flows: NetworkFlow[] }) {
  return (
    <div className="surface-solid overflow-hidden rounded-[1.5rem]">
      <div className="overflow-x-auto p-4">
        <table className="w-full min-w-[860px] text-left text-sm">
          <thead className="border-b border-[var(--border)] text-xs uppercase text-muted"><tr><th className="py-3">Source</th><th>Destination</th><th>Protocol</th><th>Packets</th><th>Bytes</th><th>Risk</th><th>Finding</th></tr></thead>
          <tbody>{flows.map((flow) => <tr key={flow.id} className="border-b border-[var(--border)]"><td className="py-3 font-mono text-xs">{flow.source}</td><td className="font-mono text-xs">{flow.target}</td><td><Badge>{flow.protocol}</Badge></td><td>{formatNumber(flow.packets)}</td><td>{formatBytes(flow.bytes)}</td><td>{flow.risk ?? 0}</td><td>{flow.attackClass}</td></tr>)}</tbody>
        </table>
        {!flows.length && <div className="py-8 text-center text-sm text-muted">No communication paths found in this evidence file.</div>}
      </div>
      <div className="border-t border-[var(--border)] p-4"><Button asChild variant="secondary" size="sm"><Link to="/app/graph">Open full communication map</Link></Button></div>
    </div>
  );
}

function ExportCenterPage() {
  const { t, activeCaseId, reloadAnalysis } = useNetra();
  const options = ["Evidence JSON", "Alert CSV"];
  async function createExport(type: string) {
    const response = await fetch(`${API_BASE}/exports`, { method: "POST", headers: netraHeaders({ "Content-Type": "application/json" }), body: JSON.stringify({ type, caseId: activeCaseId }) });
    const payload = await response.json();
    if (!response.ok) {
      toast.error(payload.error ?? "Export failed");
      return;
    }
    toast.success(`${type} export ready: ${payload.filename}`);
    await reloadAnalysis().catch(() => undefined);
  }
  return (
    <PageFrame title={t("exportCenter")} description={t("exportDesc")}>
      <div className="grid gap-3 md:grid-cols-3">
        {options.map((item) => <Button key={item} onClick={() => createExport(item)}>{item}</Button>)}
      </div>
      <ExportHistoryTable />
    </PageFrame>
  );
}

function SettingsPage() {
  const { deploymentAccess } = useNetra();
  const sections: { module: DeploymentModuleKey; title: string; description: string; href: string; icon: LucideIcon }[] = [
    { module: "system", title: "Technical Status", description: "Deployment health, workers, storage, database, ML artifact, and operational diagnostics.", href: "/app/settings/technical-status", icon: Activity },
    { module: "sensors", title: "Sensors", description: "Enrollment, heartbeats, interfaces, groups, and bounded native-capture controls.", href: "/app/settings/sensors", icon: Database },
    { module: "schedules", title: "Schedules", description: "One-time and recurring capture windows for enrolled external sensors.", href: "/app/settings/schedules", icon: History },
    { module: "integrations", title: "Integrations", description: "Administrator-managed SIEM and signed webhook destinations and delivery history.", href: "/app/settings/integrations", icon: FileText },
    { module: "retention", title: "Retention", description: "Retention policy, cleanup previews, legal holds, and approved storage cleanup.", href: "/app/settings/retention", icon: Fingerprint },
  ];
  return (
    <PageFrame title="Settings" description="Administrator configuration and technical operations are grouped here so the investigation workflow stays focused.">
      <div className="surface rounded-[1.5rem] p-5">
        <div className="flex flex-wrap items-start justify-between gap-3">
          <div>
            <h2 className="text-xl font-black text-strong">Deployment and access</h2>
            <p className="mt-1 text-sm text-muted">Capabilities are authorized by the backend for the signed-in administrator.</p>
          </div>
          <Badge>{deploymentAccess.profile}</Badge>
        </div>
        <div className="mt-4 grid gap-3 md:grid-cols-3">
          <MetadataRow label="Administrator" value={deploymentAccess.user || "Signed-in administrator"} />
          <MetadataRow label="Department" value={deploymentAccess.department || "-"} />
          <MetadataRow label="Role" value={deploymentAccess.role} />
        </div>
      </div>
      <div className="grid gap-4 md:grid-cols-2 xl:grid-cols-3">
        {sections.map((section) => {
          const access = deploymentAccess.modules[section.module];
          const Icon = section.icon;
          return (
            <section key={section.module} className="surface flex min-h-56 flex-col rounded-[1.5rem] p-5">
              <div className="flex items-start justify-between gap-3">
                <span className="flex size-11 items-center justify-center rounded-2xl bg-[var(--accent-soft)] text-[var(--accent)]"><Icon className="size-5" /></span>
                <Badge variant={access.enabled ? "secondary" : "warning"}>{access.enabled ? "enabled" : "not configured"}</Badge>
              </div>
              <h2 className="mt-5 text-xl font-black text-strong">{section.title}</h2>
              <p className="mt-2 text-sm leading-6 text-muted">{section.description}</p>
              <p className="mt-3 text-xs leading-5 text-muted">{access.reason}</p>
              <Button asChild className="mt-auto w-fit" variant={access.enabled ? "default" : "secondary"}>
                <Link to={section.href}>{access.enabled ? `Open ${section.title}` : "View requirements"}</Link>
              </Button>
            </section>
          );
        })}
      </div>
    </PageFrame>
  );
}

function LabToolsPage() {
  const { activeCaseId, deploymentAccess, intakeForm, reloadAnalysis, setActiveCaseId } = useNetra();
  const [sensors, setSensors] = useState<SensorRecord[]>([]);
  const [sensorId, setSensorId] = useState("");
  const [interfaceName, setInterfaceName] = useState("");
  const [replayFile, setReplayFile] = useState<File | null>(null);
  const [durationSeconds, setDurationSeconds] = useState(intakeForm.durationSeconds || "60");
  const [packetLimit, setPacketLimit] = useState(intakeForm.packetLimit || "10000");
  const [bpfFilter, setBpfFilter] = useState(intakeForm.bpfFilter || "");
  const [captureJob, setCaptureJob] = useState<CaptureJobRecord | null>(null);
  const [labError, setLabError] = useState("");
  const selectedSensor = sensors.find((sensor) => sensor.id === sensorId);
  const terminal = captureJob ? ["completed", "failed", "stopped"].includes(captureJob.status) : true;

  const loadSensors = useCallback(async () => {
    try {
      const payload = await apiGet<{ results: SensorRecord[] }>("/sensors");
      setSensors(payload.results);
      const online = payload.results.find((sensor) => sensor.status === "online");
      if (online) {
        setSensorId((current) => current || online.id);
        setInterfaceName((current) => current || online.interfaces[0]?.name || "");
      }
      setLabError("");
    } catch (error) {
      setSensors([]);
      setLabError(error instanceof Error ? error.message : "Sensor inventory could not be loaded.");
    }
  }, []);

  useEffect(() => {
    if (deploymentAccess.sensorCaptureEnabled) void loadSensors();
    else {
      setSensors([]);
      setLabError("");
    }
  }, [deploymentAccess.sensorCaptureEnabled, loadSensors]);

  useEffect(() => {
    if (!captureJob || terminal) return undefined;
    let mounted = true;
    const refresh = async () => {
      const family = captureJob.mode === "replay" ? "replay" : "live";
      try {
        const current = await apiGet<CaptureJobRecord>(`/capture/${family}/${captureJob.jobId}/status`);
        if (!mounted) return;
        setCaptureJob(current);
        setLabError("");
        if (current.status === "completed") {
          await reloadAnalysis(current.caseId);
          toast.success("Lab job finalized into encrypted evidence.");
        }
      } catch (error) {
        if (mounted) setLabError(error instanceof Error ? error.message : "Lab job status could not be refreshed.");
      }
    };
    void refresh();
    const timer = window.setInterval(() => void refresh(), 5000);
    return () => {
      mounted = false;
      window.clearInterval(timer);
    };
  }, [captureJob?.jobId, captureJob?.mode, terminal, reloadAnalysis]);

  async function startReplay() {
    if (!replayFile) {
      setLabError("Choose a PCAP or PCAPNG file before starting replay.");
      return;
    }
    const form = new FormData();
    form.append("file", replayFile);
    form.append("caseId", activeCaseId || intakeForm.caseNumber);
    form.append("speed", "5x");
    form.append("chunkIntervalSeconds", "5");
    form.append("packetLimit", packetLimit || "10000");
    const response = await fetch(`${API_BASE}/capture/replay/start`, { method: "POST", headers: netraHeaders(), body: form });
    const payload = await response.json().catch(() => ({})) as CaptureJobRecord & { error?: string };
    if (!response.ok) {
      setLabError(payload.error || "Replay could not start.");
      return;
    }
    setCaptureJob(payload);
    setActiveCaseId(payload.caseId);
    setLabError("");
    toast.success("PCAP replay started in the lab pipeline.");
  }

  async function startSensorCapture() {
    if (!selectedSensor || selectedSensor.status !== "online" || !interfaceName) {
      setLabError("An online enrolled sensor and a reported capture interface are required.");
      return;
    }
    const response = await fetch(`${API_BASE}/capture/live/start`, {
      method: "POST",
      headers: netraHeaders({ "Content-Type": "application/json" }),
      body: JSON.stringify({
        caseId: activeCaseId || intakeForm.caseNumber,
        sensorId: selectedSensor.id,
        interfaceName,
        durationSeconds: Number(durationSeconds || 60),
        packetLimit: Number(packetLimit || 10000),
        chunkIntervalSeconds: 5,
        bpfFilter,
      }),
    });
    const payload = await response.json().catch(() => ({})) as CaptureJobRecord & { error?: string };
    if (!response.ok) {
      setLabError(payload.error || "Sensor capture could not be queued.");
      return;
    }
    setCaptureJob(payload);
    setActiveCaseId(payload.caseId);
    setLabError("");
    toast.success("Bounded capture command queued for the external sensor.");
  }

  async function stopLabJob() {
    if (!captureJob) return;
    const family = captureJob.mode === "replay" ? "replay" : "live";
    const response = await fetch(`${API_BASE}/capture/${family}/${captureJob.jobId}/stop`, { method: "POST", headers: netraHeaders() });
    const payload = await response.json().catch(() => ({})) as CaptureJobRecord & { error?: string };
    if (!response.ok) {
      setLabError(payload.error || "Lab job could not be stopped.");
      return;
    }
    setCaptureJob(payload);
  }

  return (
    <PageFrame title="Capture and Replay" description="Replay a bounded PCAP through the evidence pipeline or connect an authorized external sensor for native capture.">
      <Alert>
        Uploaded-PCAP replay is {deploymentAccess.replayEnabled ? "enabled" : "disabled"}. Railway host capture remains {deploymentAccess.hostCaptureEnabled ? "enabled by configuration" : "disabled"}; native packets require an enrolled sensor on an authorized Windows or Linux host.
      </Alert>
      {labError && <Alert>{labError}</Alert>}
      <div className="grid gap-5 lg:grid-cols-2">
        <div className="surface order-2 rounded-[1.5rem] p-5 lg:order-1">
          <div className="flex items-start justify-between gap-3">
            <div><h2 className="text-xl font-black text-strong">Native sensor capture</h2><p className="mt-1 text-sm leading-6 text-muted">Requires the sensor agent, dumpcap or tcpdump, capture permission, the Railway API URL, and the configured sensor key.</p></div>
            <Badge variant={selectedSensor?.status === "online" ? "secondary" : "warning"}>{deploymentAccess.sensorCaptureEnabled ? selectedSensor?.status ?? "not connected" : "not configured"}</Badge>
          </div>
          {!deploymentAccess.sensorCaptureEnabled && <p className="mt-4 rounded-2xl border border-[var(--border)] bg-[var(--surface-muted)] p-4 text-sm leading-6 text-muted">Native capture is intentionally off in Railway. Enroll an external sensor and enable the sensor-capture setting before using this section.</p>}
          <fieldset className="mt-4 grid gap-3 md:grid-cols-2" disabled={!deploymentAccess.sensorCaptureEnabled}>
            <SelectField label="Sensor" value={sensorId || "none"} values={sensors.length ? sensors.map((sensor) => sensor.id) : ["none"]} onChange={(value) => {
              const nextId = value === "none" ? "" : value;
              setSensorId(nextId);
              setInterfaceName(sensors.find((sensor) => sensor.id === nextId)?.interfaces[0]?.name || "");
            }} />
            <SelectField label="Interface" value={interfaceName || "none"} values={selectedSensor?.interfaces.length ? selectedSensor.interfaces.map((item) => item.name) : ["none"]} onChange={(value) => setInterfaceName(value === "none" ? "" : value)} />
            <Field label="Duration (seconds)" value={durationSeconds} onChange={setDurationSeconds} />
            <Field label="Packet limit" value={packetLimit} onChange={setPacketLimit} />
            <div className="md:col-span-2"><Field label="BPF filter" value={bpfFilter} onChange={setBpfFilter} disabled={!BPF_FILTER_ENABLED} /></div>
          </fieldset>
          <div className="mt-4 flex flex-wrap gap-2">
            <Button onClick={startSensorCapture} disabled={!deploymentAccess.sensorCaptureEnabled || !selectedSensor || selectedSensor.status !== "online" || !interfaceName}>Queue bounded capture</Button>
            <Button variant="secondary" onClick={loadSensors} disabled={!deploymentAccess.sensorCaptureEnabled}>Refresh sensors</Button>
            {!deploymentAccess.sensorCaptureEnabled && <Button asChild variant="secondary"><Link to="/app/settings/sensors">View sensor requirements</Link></Button>}
          </div>
        </div>
        <div className="surface order-1 rounded-[1.5rem] p-5 lg:order-2">
          <div className="flex items-start justify-between gap-3"><h2 className="text-xl font-black text-strong">PCAP replay</h2><Badge variant="secondary">enabled</Badge></div>
          <p className="mt-1 text-sm leading-6 text-muted">Replay is a validation tool, not live network capture. It processes a supplied PCAP through the isolated replay path and reports real server status.</p>
          <div className="mt-4 grid gap-3">
            <Input type="file" accept=".pcap,.pcapng,application/vnd.tcpdump.pcap" onChange={(event) => setReplayFile(event.target.files?.[0] ?? null)} />
            <Button className="w-fit" onClick={startReplay} disabled={!deploymentAccess.replayEnabled || !replayFile}>Start PCAP replay</Button>
          </div>
        </div>
      </div>
      {captureJob && (
        <div className="surface rounded-[1.5rem] p-5">
          <div className="flex flex-wrap items-start justify-between gap-3">
            <div><h2 className="text-xl font-black text-strong">Current lab job</h2><p className="mt-1 text-sm text-muted">{captureJob.jobId} · {captureJob.mode} · {captureJob.status}</p></div>
            {!terminal && <Button variant="secondary" onClick={stopLabJob}>Stop job</Button>}
          </div>
          <div className="mt-5 grid gap-3 md:grid-cols-4">
            <MetricTile label="Packets" value={formatNumber(captureJob.packetsReceived)} detail="Server-reported" />
            <MetricTile label="Chunks" value={captureJob.chunksReceived} detail="Persisted chunks" />
            <MetricTile label="Progress" value={`${captureJob.progress}%`} detail="Reload-safe status" />
            <MetricTile label="Evidence" value={captureJob.finalEvidenceId || "not finalized"} detail={captureJob.status} />
          </div>
          <Progress className="mt-5" value={captureJob.progress} />
        </div>
      )}
    </PageFrame>
  );
}

function SensorsPage() {
  const [sensors, setSensors] = useState<SensorRecord[]>([]);
  const [groups, setGroups] = useState<SensorGroupRecord[]>([]);
  const [groupName, setGroupName] = useState("");
  const load = useCallback(() => {
    apiGet<{ results: SensorRecord[] }>("/sensors").then((payload) => setSensors(payload.results)).catch(() => setSensors([]));
    apiGet<{ results: SensorGroupRecord[] }>("/sensor-groups").then((payload) => setGroups(payload.results)).catch(() => setGroups([]));
  }, []);
  useEffect(() => { load(); }, [load]);
  async function createGroup() {
    const response = await fetch(`${API_BASE}/sensor-groups`, { method: "POST", headers: netraHeaders({ "Content-Type": "application/json" }), body: JSON.stringify({ name: groupName }) });
    if (!response.ok) toast.error("Sensor group could not be created.");
    else { setGroupName(""); load(); }
  }
  async function toggle(sensor: SensorRecord) {
    await fetch(`${API_BASE}/sensors/${sensor.id}/${sensor.enabled === false ? "enable" : "disable"}`, { method: "POST", headers: netraHeaders() });
    load();
  }
  return (
    <PageFrame title="Sensor Fleet" description="Coordinate bounded Windows and Linux capture sensors across the trusted LAN.">
      <div className="grid gap-4 md:grid-cols-4">
        <MetricTile label="Sensors" value={`${sensors.length}`} detail="Registered fleet members" />
        <MetricTile label="Online" value={`${sensors.filter((row) => row.status === "online").length}`} detail="Heartbeat within 30 seconds" />
        <MetricTile label="Capturing" value={`${sensors.filter((row) => row.status === "capturing").length}`} detail="Active bounded jobs" />
        <MetricTile label="Groups" value={`${groups.length}`} detail="Operational locations" />
      </div>
      <div className="surface rounded-[1.5rem] p-5">
        <h2 className="text-xl font-black text-strong">Create sensor group</h2>
        <div className="mt-4 flex max-w-xl gap-3"><Input value={groupName} onChange={(event) => setGroupName(event.target.value)} placeholder="Office LAN" /><Button onClick={createGroup} disabled={!groupName.trim()}>Create</Button></div>
      </div>
      <div className="surface-solid overflow-hidden rounded-[1.5rem]">
        <div className="overflow-x-auto p-4">
          <table className="w-full min-w-[920px] text-left text-sm">
            <thead className="border-b border-[var(--border)] text-xs uppercase text-muted"><tr><th className="py-3">Sensor</th><th>Group</th><th>Location</th><th>Status</th><th>Heartbeat</th><th>Uploaded</th><th>Action</th></tr></thead>
            <tbody>{(sensors.length ? sensors : [{ id: "none", name: "No sensors registered", hostname: "-", platform: "-", agentVersion: "-", captureEngine: "-", status: "offline", interfaces: [] } as SensorRecord]).map((sensor) => <tr key={sensor.id} className="border-b border-[var(--border)]"><td className="py-3"><div className="font-bold text-strong">{sensor.name}</div><div className="text-xs text-muted">{sensor.hostname}</div></td><td>{sensor.groupName || "-"}</td><td>{sensor.location || "-"}</td><td><Badge>{sensor.status}</Badge></td><td>{sensor.lastHeartbeatAt ?? "-"}</td><td>{formatNumber(sensor.totalBytesUploaded ?? 0)} B</td><td>{sensor.id !== "none" && <Button size="sm" variant="secondary" onClick={() => toggle(sensor)}>{sensor.enabled === false ? "Enable" : "Disable"}</Button>}</td></tr>)}</tbody>
          </table>
        </div>
      </div>
    </PageFrame>
  );
}

function SchedulesPage() {
  const [schedules, setSchedules] = useState<CaptureScheduleRecord[]>([]);
  const [sensors, setSensors] = useState<SensorRecord[]>([]);
  const [name, setName] = useState("Office bounded capture");
  const [sensorId, setSensorId] = useState("");
  const [startAt, setStartAt] = useState(new Date(Date.now() + 10 * 60 * 1000).toISOString().slice(0, 16));
  const load = useCallback(() => {
    apiGet<{ results: CaptureScheduleRecord[] }>("/capture-schedules").then((payload) => setSchedules(payload.results)).catch(() => setSchedules([]));
    apiGet<{ results: SensorRecord[] }>("/sensors").then((payload) => { setSensors(payload.results); setSensorId((current) => current || payload.results[0]?.id || ""); }).catch(() => setSensors([]));
  }, []);
  useEffect(() => { load(); }, [load]);
  async function createSchedule() {
    const sensor = sensors.find((row) => row.id === sensorId);
    const response = await fetch(`${API_BASE}/capture-schedules`, { method: "POST", headers: netraHeaders({ "Content-Type": "application/json" }), body: JSON.stringify({ name, sensorId, scheduleType: "one-time", startAt: new Date(startAt).toISOString(), durationSeconds: 60, packetLimit: 10000, chunkIntervalSeconds: 5, interfaceName: sensor?.interfaces[0]?.name || "", bpfFilter: "", caseIdPrefix: "CYB-GJ-SCHEDULED" }) });
    const payload = await response.json();
    if (!response.ok) toast.error(payload.error ?? "Schedule could not be created.");
    else { toast.success("Bounded capture schedule saved."); load(); }
  }
  return (
    <PageFrame title="Capture Schedules" description="Queue predictable one-time, daily, or weekly bounded capture windows.">
      <div className="surface rounded-[1.5rem] p-5">
        <div className="grid gap-3 md:grid-cols-3">
          <Field label="Schedule name" value={name} onChange={setName} />
          <SelectField label="Sensor" value={sensorId || "none"} values={sensors.length ? sensors.map((row) => row.id) : ["none"]} onChange={(value) => setSensorId(value === "none" ? "" : value)} />
          <Field label="Start time" value={startAt} onChange={setStartAt} />
        </div>
        <Button className="mt-4" onClick={createSchedule} disabled={!sensorId}>Create one-time schedule</Button>
      </div>
      <div className="surface-solid overflow-hidden rounded-[1.5rem]">
        <div className="overflow-x-auto p-4"><table className="w-full min-w-[820px] text-left text-sm"><thead className="border-b border-[var(--border)] text-xs uppercase text-muted"><tr><th className="py-3">Name</th><th>Sensor</th><th>Type</th><th>Next run</th><th>Bounds</th><th>Status</th></tr></thead><tbody>{schedules.map((row) => <tr key={row.id} className="border-b border-[var(--border)]"><td className="py-3 font-bold text-strong">{row.name}</td><td>{row.sensorName}</td><td>{row.scheduleType}</td><td>{row.nextRunAt ?? "-"}</td><td>{row.durationSeconds}s / {formatNumber(row.packetLimit)} packets</td><td><Badge>{row.enabled ? "enabled" : "disabled"}</Badge></td></tr>)}</tbody></table></div>
      </div>
    </PageFrame>
  );
}

function RetentionPage() {
  const [policy, setPolicy] = useState<{ highVolumeSearchDays: number; evidenceDays: number; captureChunkDays: number } | null>(null);
  const [preview, setPreview] = useState<{ candidates?: { resourceType: string; resourceId: string; caseId: string; status: string }[]; bytesReclaimed?: number } | null>(null);
  useEffect(() => { apiGet<typeof policy>("/retention/policy").then(setPolicy).catch(() => undefined); }, []);
  async function run(path: "preview" | "execute") {
    const response = await fetch(`${API_BASE}/retention/${path}`, { method: "POST", headers: netraHeaders() });
    const payload = await response.json();
    if (!response.ok) toast.error("Retention operation failed.");
    else { setPreview(payload); toast.success(path === "preview" ? "Cleanup preview ready." : "Safe chunk cleanup completed."); }
  }
  return (
    <PageFrame title="Retention & Storage" description="Preview cleanup, preserve immutable evidence, and keep legal holds visible.">
      <div className="grid gap-4 md:grid-cols-3">
        <MetricTile label="Search metadata" value={`${policy?.highVolumeSearchDays ?? 30} days`} detail="Elasticsearch lifecycle window" />
        <MetricTile label="Capture chunks" value={`${policy?.captureChunkDays ?? 7} days`} detail="Removed only after final evidence exists" />
        <MetricTile label="Immutable evidence" value={`${policy?.evidenceDays ?? 90} days`} detail="Explicit approval required before purge" />
      </div>
      <div className="surface rounded-[1.5rem] p-5">
        <div className="flex flex-wrap gap-3"><Button onClick={() => run("preview")}>Preview cleanup</Button><Button variant="secondary" onClick={() => run("execute")}>Run safe cleanup</Button></div>
        <div className="mt-5 grid gap-2">{preview?.candidates?.map((row) => <div key={`${row.resourceType}-${row.resourceId}`} className="rounded-xl border border-[var(--border)] p-3 text-sm"><span className="font-bold text-strong">{row.resourceType}</span> {row.resourceId} <Badge>{row.status}</Badge></div>) ?? <p className="text-sm text-muted">Generate a preview to inspect retention candidates.</p>}</div>
      </div>
    </PageFrame>
  );
}

function SystemPage() {
  const { deploymentAccess } = useNetra();
  const [health, setHealth] = useState<{ status: string; checks: Record<string, { status: string; latencyMs?: number; detail?: string; rbac?: string; devRoleHeaders?: boolean; serviceRoleBackendOnly?: boolean; serviceRoleConfigured?: boolean; adminProfiles?: number }>; database?: { mode: string; host: string; port: string; name: string; tables: number }; access?: { mode: string; label: string; authentication: string; authorization?: string; publicInternet: string; actor?: string; role?: string }; incidentReadiness?: { status: string; summary: Record<string, number>; checks: { name: string; status: string; detail: string }[]; recommendedActions: string[] } } | null>(null);
  const [statusMatrix, setStatusMatrix] = useState<{ results: { area: string; targetStatus: string; detail: string; validation: string[] }[]; summary: { total: number; validated: number; gated: number } } | null>(null);
  const [mlStatus, setMlStatus] = useState<{ status: string; modelAvailable: boolean; experimental?: boolean; trustedArtifact?: boolean; version?: string; modelType?: string; trainingRows?: number; metrics?: Record<string, unknown>; detail?: string } | null>(null);
  const [database, setDatabase] = useState<{ mode: string; host: string; port: string; name: string; user: string; tables: number; forensicsTables: string[]; access?: { mode: string; label: string; authentication: string; publicInternet: string } } | null>(null);
  const [metrics, setMetrics] = useState<Record<string, number>>({});
  const [deadLetters, setDeadLetters] = useState<{ id: string; workerName: string; caseId: string; error: string; status: string }[]>([]);
  const [workerStatus, setWorkerStatus] = useState<{ processingMode?: string; queueProvider?: string; workerMode?: string; results: { name: string; status: string; lastSeen?: string; currentJobId?: string; replicaCount?: number }[] }>({ results: [] });
  const [sensors, setSensors] = useState<SensorRecord[]>([]);
  const [capacity, setCapacity] = useState<CapacityRecord | null>(null);
  useEffect(() => {
    function refresh() {
      apiGet<{ status: string; checks: Record<string, { status: string; latencyMs?: number; detail?: string; rbac?: string; devRoleHeaders?: boolean; serviceRoleBackendOnly?: boolean; serviceRoleConfigured?: boolean; adminProfiles?: number }>; database?: { mode: string; host: string; port: string; name: string; tables: number }; access?: { mode: string; label: string; authentication: string; authorization?: string; publicInternet: string; actor?: string; role?: string } }>("/system/health/deep").then(setHealth).catch(() => undefined);
      apiGet<{ mode: string; host: string; port: string; name: string; user: string; tables: number; forensicsTables: string[]; access?: { mode: string; label: string; authentication: string; publicInternet: string } }>("/system/database").then(setDatabase).catch(() => undefined);
      apiGet<{ results: { area: string; targetStatus: string; detail: string; validation: string[] }[]; summary: { total: number; validated: number; gated: number } }>("/system/status-matrix").then(setStatusMatrix).catch(() => undefined);
      apiGet<{ status: string; modelAvailable: boolean; experimental?: boolean; trustedArtifact?: boolean; version?: string; modelType?: string; trainingRows?: number; metrics?: Record<string, unknown>; detail?: string }>("/ml/model-status").then(setMlStatus).catch(() => undefined);
      apiGet<Record<string, number>>("/system/metrics").then(setMetrics).catch(() => undefined);
      apiGet<{ results: typeof deadLetters }>("/system/dead-letter").then((payload) => setDeadLetters(payload.results)).catch(() => undefined);
      apiGet<{ processingMode?: string; queueProvider?: string; workerMode?: string; results: { name: string; status: string; lastSeen?: string; currentJobId?: string; replicaCount?: number }[] }>("/system/workers").then(setWorkerStatus).catch(() => undefined);
      apiGet<{ results: SensorRecord[] }>("/system/sensors").then((payload) => setSensors(payload.results)).catch(() => undefined);
      apiGet<CapacityRecord>("/system/capacity").then(setCapacity).catch(() => undefined);
    }
    refresh();
    const interval = window.setInterval(refresh, 10000);
    return () => window.clearInterval(interval);
  }, []);
  return (
    <PageFrame title="Technical Status" description="Operator diagnostics for Supabase, packet-analysis tools, workers, storage, and sensors. Officers do not need this page for normal investigations.">
      <div className="surface rounded-[1.5rem] p-5">
        <div className="flex flex-wrap items-start justify-between gap-3">
          <div><h2 className="text-xl font-black text-strong">Deployment profile</h2><p className="mt-1 text-sm text-muted">Authoritative module gates returned by the backend for the signed-in administrator.</p></div>
          <Badge>{deploymentAccess.profile}</Badge>
        </div>
        <div className="mt-4 grid gap-3 md:grid-cols-2 xl:grid-cols-3">
          {Object.entries(deploymentAccess.modules).map(([name, module]) => (
            <div key={name} className="rounded-2xl border border-[var(--border)] bg-[var(--surface-muted)] p-4">
              <div className="flex items-center justify-between gap-2"><h3 className="font-bold capitalize text-strong">{name}</h3><Badge variant={module.enabled ? "secondary" : "warning"}>{module.enabled ? "enabled" : "not configured"}</Badge></div>
              <p className="mt-2 text-xs leading-5 text-muted">{module.reason}</p>
            </div>
          ))}
        </div>
      </div>
      <div className="grid gap-4 md:grid-cols-3 xl:grid-cols-6">
        {Object.entries(health?.checks ?? {}).map(([key, value]) => <MetricTile key={key} label={key} value={value.status} detail={value.detail ?? (value.latencyMs !== undefined ? `${value.latencyMs} ms` : "Live deep-health probe")} />)}
      </div>
      <div className="surface rounded-[1.5rem] p-5">
        <h2 className="text-xl font-black text-strong">Incident readiness</h2>
        <div className="mt-4 grid gap-3 md:grid-cols-5">
          <MetadataRow label="Status" value={health?.incidentReadiness?.status ?? "-"} />
          <MetadataRow label="Failed jobs" value={`${health?.incidentReadiness?.summary?.failedJobs ?? 0}`} />
          <MetadataRow label="Dead letters" value={`${health?.incidentReadiness?.summary?.unresolvedDeadLetters ?? 0}`} />
          <MetadataRow label="Denied access" value={`${health?.incidentReadiness?.summary?.deniedAccessLast24h ?? 0}`} />
          <MetadataRow label="Ops events" value={`${health?.incidentReadiness?.summary?.operationalEventsLast24h ?? 0}`} />
        </div>
        <div className="mt-4 flex flex-wrap gap-2">
          {(health?.incidentReadiness?.checks ?? []).slice(0, 8).map((item) => <Badge key={item.name} variant={item.status === "attention" ? "destructive" : "secondary"}>{item.name}: {item.status}</Badge>)}
        </div>
        <p className="mt-3 text-sm text-muted">{health?.incidentReadiness?.recommendedActions?.[0] ?? "Operational readiness will appear after health checks load."}</p>
      </div>
      <div className="surface rounded-[1.5rem] p-5">
        <div className="flex flex-wrap items-start justify-between gap-3">
          <div>
            <h2 className="text-xl font-black text-strong">Feature status matrix</h2>
            <p className="mt-1 text-sm text-muted">Generated from validation-backed status rules, not manual labels.</p>
          </div>
          <Badge variant={statusMatrix?.summary?.gated ? "destructive" : "secondary"}>{statusMatrix?.summary?.validated ?? 0}/{statusMatrix?.summary?.total ?? 0} validated</Badge>
        </div>
        <div className="mt-4 grid gap-3 md:grid-cols-2 xl:grid-cols-3">
          {(statusMatrix?.results ?? []).map((row) => (
            <div key={row.area} className="rounded-2xl border border-[var(--border)] bg-[var(--surface-muted)] p-4">
              <div className="flex items-center justify-between gap-2">
                <h3 className="text-sm font-black text-strong">{row.area}</h3>
                <Badge variant={row.targetStatus.includes("Gated") || row.targetStatus.includes("fallback") ? "destructive" : "secondary"}>{row.targetStatus}</Badge>
              </div>
              <p className="mt-2 text-xs leading-5 text-muted">{row.detail}</p>
            </div>
          ))}
        </div>
      </div>
      <div className="surface rounded-[1.5rem] p-5">
        <div className="flex flex-wrap items-center justify-between gap-2"><h2 className="text-xl font-black text-strong">ML anomaly model</h2><Badge variant="warning">Experimental</Badge></div>
        <div className="mt-4 grid gap-2 md:grid-cols-4">
          <MetadataRow label="Mode" value={mlStatus?.status ?? "-"} />
          <MetadataRow label="Model" value={mlStatus?.modelAvailable ? "experimental / available" : "fallback scoring"} />
          <MetadataRow label="Version" value={mlStatus?.version ?? "-"} />
          <MetadataRow label="Training rows" value={`${mlStatus?.trainingRows ?? 0}`} />
        </div>
        <p className="mt-3 text-sm text-muted">{mlStatus?.detail ?? (mlStatus?.modelAvailable ? "Experimental model is available for triage only; reports retain explainable feature context." : "Explainable fallback scoring is active.")}</p>
        <p className="mt-2 text-xs leading-5 text-muted">Model output assists investigator review and must not be presented as a standalone forensic or legal conclusion. Trusted artifact: {mlStatus?.trustedArtifact ? "verified" : "not verified"}.</p>
      </div>
      <div className="surface rounded-[1.5rem] p-5">
        <h2 className="text-xl font-black text-strong">Database</h2>
        <div className="mt-4 grid gap-2 md:grid-cols-4">
          <MetadataRow label="Mode" value={database?.mode ?? health?.database?.mode ?? "-"} />
          <MetadataRow label="Host" value={`${database?.host ?? health?.database?.host ?? "-"}:${database?.port ?? health?.database?.port ?? ""}`} />
          <MetadataRow label="Database" value={database?.name ?? health?.database?.name ?? "-"} />
          <MetadataRow label="Tables" value={`${database?.tables ?? health?.database?.tables ?? 0}`} />
        </div>
        <p className="mt-3 text-sm text-muted">Use pgAdmin or psql against native Windows PostgreSQL when running `npm run netra:start:local-db`.</p>
      </div>
      <div className="surface rounded-[1.5rem] p-5">
        <h2 className="text-xl font-black text-strong">Application Access</h2>
        <div className="mt-4 grid gap-2 md:grid-cols-4">
          <MetadataRow label="Access mode" value={health?.access?.label ?? database?.access?.label ?? "Supabase Auth"} />
          <MetadataRow label="Authentication" value={health?.access?.authentication ?? database?.access?.authentication ?? "Enabled"} />
          <MetadataRow label="Authorization" value={health?.access?.authorization ?? health?.checks?.security?.rbac ?? "role-based"} />
          <MetadataRow label="Public internet" value={health?.access?.publicInternet ?? database?.access?.publicInternet ?? "Not configured"} />
          <MetadataRow label="Dev role headers" value={health?.checks?.security?.devRoleHeaders ? "enabled" : "disabled"} />
          <MetadataRow label="Service key" value={health?.checks?.security?.serviceRoleBackendOnly ? "backend-only" : "check config"} />
          <MetadataRow label="Admin profiles" value={`${health?.checks?.security?.adminProfiles ?? 0}`} />
          <MetadataRow label="Audit actor" value={health?.access?.actor ?? "Signed-in officer"} />
        </div>
        <p className="mt-3 text-sm text-muted">Netra requires a Supabase session before investigation actions can run. Keep service-role keys on the backend only.</p>
      </div>
      <div className="grid gap-4 md:grid-cols-3 xl:grid-cols-6">
        {Object.entries(metrics).map(([key, value]) => <MetricTile key={key} label={key} value={formatNumber(value)} detail="Current platform metric" />)}
      </div>
      <div className="surface rounded-[1.5rem] p-5">
        <h2 className="text-xl font-black text-strong">Fleet capacity</h2>
        <div className="mt-4 grid gap-3 md:grid-cols-4">
          <MetadataRow label="Capacity" value={capacity?.status ?? "-"} />
          <MetadataRow label="Disk usage" value={`${capacity?.storage.usedPercent ?? 0}%`} />
          <MetadataRow label="Kafka lag" value={`${capacity?.kafka.lag ?? 0}`} />
          <MetadataRow label="Active captures" value={`${capacity?.sensors.capturing ?? 0}`} />
        </div>
      </div>
      <div className="surface-solid overflow-hidden rounded-[1.5rem]">
        <div className="p-5 pb-0"><h3 className="text-lg font-black text-strong">Native sensors</h3></div>
        <div className="overflow-x-auto p-4">
          <table className="w-full min-w-[760px] text-left text-sm">
            <thead className="border-b border-[var(--border)] text-xs uppercase text-muted"><tr><th className="py-3">Sensor</th><th>Host</th><th>Platform</th><th>Engine</th><th>Status</th><th>Heartbeat</th></tr></thead>
            <tbody>{(sensors.length ? sensors : [{ id: "none", name: "No sensor registered", hostname: "-", platform: "-", agentVersion: "-", captureEngine: "-", status: "offline", interfaces: [] } as SensorRecord]).map((item) => <tr key={item.id} className="border-b border-[var(--border)]"><td className="py-3 font-bold text-strong">{item.name}</td><td>{item.hostname}</td><td>{item.platform}</td><td>{item.captureEngine}</td><td><Badge>{item.status}</Badge></td><td>{item.lastHeartbeatAt ?? "-"}</td></tr>)}</tbody>
          </table>
        </div>
      </div>
      <div className="surface-solid overflow-hidden rounded-[1.5rem]">
        <div className="p-5 pb-0">
          <h3 className="text-lg font-black text-strong">Worker heartbeats</h3>
          <p className="mt-1 text-sm text-muted">Mode: {workerStatus.workerMode ?? "disabled"} | Queue: {workerStatus.queueProvider ?? "supabase-pgmq"} | Processing: {workerStatus.processingMode ?? "hybrid"}</p>
        </div>
        <div className="overflow-x-auto p-4">
          <table className="w-full min-w-[760px] text-left text-sm">
            <thead className="border-b border-[var(--border)] text-xs uppercase text-muted"><tr><th className="py-3">Worker</th><th>Status</th><th>Replicas</th><th>Current job</th><th>Last heartbeat</th></tr></thead>
            <tbody>{workerStatus.results.map((item) => <tr key={item.name} className="border-b border-[var(--border)]"><td className="py-3 font-bold text-strong">{item.name}</td><td><Badge>{item.status}</Badge></td><td>{item.replicaCount ?? 0}</td><td>{item.currentJobId || "-"}</td><td>{item.lastSeen ?? "-"}</td></tr>)}</tbody>
          </table>
        </div>
      </div>
      <div className="surface-solid overflow-hidden rounded-[1.5rem]">
        <div className="p-5 pb-0"><h3 className="text-lg font-black text-strong">Dead-letter queue</h3></div>
        <div className="overflow-x-auto p-4">
          <table className="w-full min-w-[760px] text-left text-sm">
            <thead className="border-b border-[var(--border)] text-xs uppercase text-muted"><tr><th className="py-3">Event</th><th>Worker</th><th>Case</th><th>Error</th><th>Status</th></tr></thead>
            <tbody>{(deadLetters.length ? deadLetters : [{ id: "none", workerName: "-", caseId: "-", error: "No failed worker events", status: "clear" }]).map((item) => <tr key={item.id} className="border-b border-[var(--border)]"><td className="py-3 font-mono text-xs">{item.id}</td><td>{item.workerName}</td><td>{item.caseId}</td><td>{item.error}</td><td><Badge>{item.status}</Badge></td></tr>)}</tbody>
          </table>
        </div>
      </div>
    </PageFrame>
  );
}

function IntegrationsPage() {
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

function CompliancePage() {
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

function GraphPage() {
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

function CasesPage() {
  const { t, caseRecords, reloadAnalysis, setActiveCaseId } = useNetra();
  const [query, setQuery] = useState("");
  const [status, setStatus] = useState("all");
  const navigate = useNavigate();
  const filteredCases = caseRecords.filter((record) => {
    const text = query.trim().toLowerCase();
    return (!text || [record.id, record.title, record.investigator, record.sourceLocation ?? "", record.topAttackClass ?? ""].join(" ").toLowerCase().includes(text)) && (status === "all" || record.status === status);
  });
  async function generateCaseReport(caseId: string) {
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
    setActiveCaseId(caseId);
    navigate(`/app/cases/${caseId}`);
  }
  return (
    <PageFrame title={t("cases")} description={t("caseQueueDesc")}>
      <div className="surface rounded-[1.5rem] p-5">
        <div className="flex flex-wrap items-start justify-between gap-4">
          <div>
            <h2 className="text-xl font-black text-strong">Case registry</h2>
            <p className="mt-2 max-w-3xl text-sm leading-6 text-muted">Only real officer-facing investigations are shown here. Validator and system-test cases are hidden from this list.</p>
          </div>
          <Button asChild><Link to="/app/upload"><Upload className="size-4" />New investigation</Link></Button>
        </div>
        <div className="mt-5 grid gap-3 md:grid-cols-3">
          <Input value={query} onChange={(event) => setQuery(event.target.value)} placeholder="Search case, investigator, IP, finding" />
          <Select value={status} onValueChange={setStatus}>
            <SelectTrigger><SelectValue /></SelectTrigger>
            <SelectContent>{["all", "open", "reviewing", "report-ready"].map((item) => <SelectItem key={item} value={item}>{item}</SelectItem>)}</SelectContent>
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

function CaseRegistryCard({ record, onOpen, onGenerate, onDownloadLatest }: { record: CaseRecord; onOpen: () => void; onGenerate: () => void; onDownloadLatest: () => void }) {
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
          <Button size="sm" variant="secondary" onClick={onGenerate}>Generate report</Button>
          {record.latestReportDownloadUrl && <Button size="sm" variant="secondary" onClick={onDownloadLatest}>Latest PDF</Button>}
        </div>
      </div>
      {record.flags?.length ? <div className="mt-4 flex flex-wrap gap-2 border-t border-[var(--border)] pt-4">{record.flags.slice(0, 6).map((flag) => <Badge key={flag} variant="secondary">{flag}</Badge>)}</div> : null}
    </article>
  );
}

function CaseStat({ label, value }: { label: string; value: string | number }) {
  return (
    <div className="min-w-0 rounded-xl border border-[var(--border)] bg-[var(--surface-muted)] p-3">
      <div className="text-[11px] font-bold uppercase tracking-[0.1em] text-muted">{label}</div>
      <div className="mt-1 truncate text-sm font-bold text-strong" title={String(value)}>{value}</div>
    </div>
  );
}

function CaseDetailPage() {
  const { t, caseRecords, addCaseNote, setActiveCaseId } = useNetra();
  const { caseId = caseRecords[0]?.id ?? "" } = useParams();
  const [workspace, setWorkspace] = useState<CaseWorkspaceRecord | null>(null);
  const [record, setRecord] = useState<CaseRecord | null>(caseRecords.find((caseRecord) => caseRecord.id === caseId) ?? null);
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

  const refreshWorkspace = useCallback(async () => {
    if (!caseId) return;
    const payload = await apiGet<CaseWorkspaceRecord>(`/cases/${caseId}/workspace`);
    applyWorkspace(payload);
  }, [applyWorkspace, caseId]);

  useEffect(() => {
    if (!caseId) return;
    setActiveCaseId(caseId);
    let cancelled = false;
    apiGet<CaseWorkspaceRecord>(`/cases/${caseId}/workspace`)
      .then((payload) => {
        if (!cancelled) applyWorkspace(payload);
      })
      .catch(() => undefined);
    return () => {
      cancelled = true;
    };
  }, [applyWorkspace, caseId, setActiveCaseId]);

  const availableTabs = useMemo(
    () => workspace?.workspace.availableTabs ?? { overview: true, suspiciousActivity: true, trafficEvidence: true, timeline: true, reports: true, custody: true },
    [workspace?.workspace.availableTabs],
  );
  const dataMessages = workspace?.workspace.dataMessages ?? {};
  const tabVisible = useCallback((value: string) => {
    if (value === "activity") return availableTabs.suspiciousActivity;
    if (value === "evidence") return availableTabs.trafficEvidence;
    if (value === "timeline") return availableTabs.timeline;
    if (value === "reports") return availableTabs.reports;
    if (value === "custody") return availableTabs.custody;
    return true;
  }, [availableTabs]);

  useEffect(() => {
    if (!tabVisible(activeTab)) setActiveTab("overview");
  }, [activeTab, tabVisible]);

  async function generateCaseReport() {
    if (!record) return;
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
    return <PageFrame title={t("caseDetail")} description={t("caseQueueDesc")}><div className="surface rounded-[1.5rem] p-6 text-sm text-muted">Upload a PCAP to create a real case record.</div></PageFrame>;
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
            <Button onClick={generateCaseReport}><FileText className="size-4" />Generate report</Button>
            <Button asChild variant="secondary"><Link to="/app/cases">Back to cases</Link></Button>
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
      <Tabs value={activeTab} onValueChange={setActiveTab} className="flex flex-col gap-4">
        <TabsList className="max-w-full overflow-x-auto">
          <TabsTrigger value="overview">Overview</TabsTrigger>
          {availableTabs.suspiciousActivity && <TabsTrigger value="activity">Suspicious activity</TabsTrigger>}
          {availableTabs.trafficEvidence && <TabsTrigger value="evidence">Traffic evidence</TabsTrigger>}
          {availableTabs.timeline && <TabsTrigger value="timeline">Timeline</TabsTrigger>}
          {availableTabs.reports && <TabsTrigger value="reports">Reports</TabsTrigger>}
          {availableTabs.custody && <TabsTrigger value="custody">Custody</TabsTrigger>}
        </TabsList>
        <TabsContent value="overview">
          <div className="grid gap-4 lg:grid-cols-[0.9fr_1.1fr]">
            <div className="surface rounded-[1.5rem] p-5">
              <h2 className="text-xl font-black text-strong">{t("caseSummary")}</h2>
              <div className="mt-4 grid gap-2">
                <MetadataRow label={t("caseNumber")} value={record.id} />
                <MetadataRow label={t("investigator")} value={record.investigator || "-"} />
                <MetadataRow label={t("department")} value={record.department || "-"} />
                <MetadataRow label={t("sourceLocation")} value={record.sourceLocation || "-"} />
                <MetadataRow label="Opened" value={record.openedAt ? new Date(record.openedAt).toLocaleString() : record.createdAt} />
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
        {availableTabs.suspiciousActivity && <TabsContent value="activity">
          <AlertTable alerts={alerts} />
          <div className="mt-4"><AnomalyReviewPanel anomalies={anomalies} timeline={charts?.timeline ?? []} /></div>
        </TabsContent>}
        {availableTabs.trafficEvidence && <TabsContent value="evidence">
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
        {availableTabs.timeline && <TabsContent value="timeline">
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
        {availableTabs.reports && <TabsContent value="reports">
          <div className="surface rounded-[1.5rem] p-5">
            <div className="flex flex-wrap items-center justify-between gap-3"><h2 className="text-xl font-black text-strong">Case reports</h2><Button onClick={generateCaseReport}>Generate PDF report</Button></div>
            <div className="mt-4 overflow-x-auto">
              <table className="w-full min-w-[760px] text-left text-sm">
                <thead className="border-b border-[var(--border)] text-xs uppercase text-muted"><tr><th className="py-3">Report</th><th>Generated</th><th>Language</th><th>Status</th><th>Action</th></tr></thead>
                <tbody>{reports.map((report) => <tr key={report.id} className="border-b border-[var(--border)]"><td className="py-3 font-bold text-strong">{report.filename}</td><td>{new Date(report.generatedAt).toLocaleString()}</td><td>{report.language}</td><td><Badge>{report.status}</Badge></td><td><Button size="sm" variant="secondary" onClick={() => downloadApiFile(report.downloadUrl, report.filename)}>Download</Button></td></tr>)}</tbody>
              </table>
              {!reports.length && <div className="py-8 text-center text-sm text-muted">No reports generated for this case yet.</div>}
            </div>
          </div>
        </TabsContent>}
        {availableTabs.custody && <TabsContent value="custody">
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

function ReportPage() {
  const { t, language, setLanguage, caseRecords, alertRecords, anomalies, complianceRecords, decodedProtocols, detectionMatches, evidence, intakeForm, packets, payloadFindings, sessions, summary, zeek } = useNetra();
  const { caseId = "new" } = useParams();
  const record = caseRecords.find((caseRecord) => caseRecord.id === caseId) ?? caseRecords[0];
  const recommendedActions = Array.from(new Set(alertRecords.map((alert) => alert.recommendedAction).filter(Boolean))).slice(0, 3);
  if (!record) {
    return <PageFrame title={t("reportTitle")} description={t("reportDesc")}><div className="surface rounded-[1.5rem] p-6 text-sm text-muted">Upload a PCAP to generate a real report.</div></PageFrame>;
  }
  async function exportPdfReport() {
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
        <Button variant="secondary" onClick={exportPdfReport}><Download className="size-4" />Download PDF report</Button>
        <Button asChild variant="secondary"><Link to={`/app/cases/${record.id}`}>{t("backToCase")}</Link></Button>
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

function MetricTile({ label, value, detail }: { label: string; value: string | number; detail?: string }) {
  return (
    <div className="surface min-w-0 rounded-[1.25rem] p-4">
      <div className="text-xs font-bold uppercase tracking-[0.12em] text-muted">{label}</div>
      <div className="mt-2 min-w-0 break-words text-2xl font-black leading-tight text-strong">{value}</div>
      {detail && <p className="mt-2 text-xs leading-5 text-muted">{detail}</p>}
    </div>
  );
}

function CustodyMetric({ label, value, mono = false, compact = false }: { label: string; value: string | number; mono?: boolean; compact?: boolean }) {
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

function CodeBlock({ title, value }: { title: string; value: string }) {
  return (
    <div className="mt-4 rounded-xl border border-[var(--border)] bg-[rgba(0,0,0,0.18)] p-4">
      <div className="mb-2 text-xs font-bold uppercase tracking-[0.14em] text-muted">{title}</div>
      <pre className="whitespace-pre-wrap break-words font-mono text-xs leading-6 text-strong">{value}</pre>
    </div>
  );
}

function DetectionTable({ category }: { category?: string }) {
  const { activeCaseId, detectionMatches, reloadAnalysis } = useNetra();
  const rows = category ? detectionMatches.filter((item) => item.category === category || item.ruleName.includes(category)) : detectionMatches;
  async function updateStatus(item: DetectionRuleMatch, status: "reviewing" | "confirmed" | "dismissed") {
    const response = await fetch(`${API_BASE}/detection/matches/${item.id}/status`, { method: "PATCH", headers: netraHeaders({ "Content-Type": "application/json" }), body: JSON.stringify({ status, caseId: activeCaseId }) });
    const payload = await response.json();
    if (!response.ok) {
      toast.error(payload.error ?? "Status update failed");
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
          <tbody>{rows.map((item) => <tr key={item.id} className="border-b border-[var(--border)] align-top"><td className="py-3 font-mono text-xs">{item.ruleId ?? item.id}</td><td className="min-w-60 font-bold text-strong">{item.ruleName}<p className="mt-1 text-xs font-normal leading-5 text-muted">{item.explanation}</p><p className="mt-1 text-xs font-normal leading-5 text-muted">{item.recommendedAction}</p></td><td><Badge>{item.attackClass ?? item.category}</Badge></td><td>{item.matchedEntity}</td><td className="max-w-52 break-words text-xs">{[...(item.evidencePacketIds ?? []), ...(item.evidenceSessionIds ?? [])].slice(0, 4).join(", ") || "-"}</td><td>{item.confidence}%</td><td><div className="flex flex-col gap-2"><Badge variant="secondary">{item.status}</Badge><div className="flex flex-wrap gap-1"><Button size="sm" variant="secondary" onClick={() => updateStatus(item, "reviewing")}>Review</Button><Button size="sm" onClick={() => updateStatus(item, "confirmed")}>Confirm</Button><Button size="sm" variant="secondary" onClick={() => updateStatus(item, "dismissed")}>Dismiss</Button></div></div></td></tr>)}</tbody>
        </table>
      </div>
    </div>
  );
}

function ExportHistoryTable() {
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

function IntegrationTable({ rows = [] }: { rows?: IntegrationRecord[] }) {
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

function DeliveryTable({ rows }: { rows: { id: string; timestamp: string; caseId: string; type: string; result: string; response: string }[] }) {
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

function CustodyLedgerTable({ rows }: { rows: { id: string; timestamp: string; actor: string; action: string; previousHash: string; eventHash: string }[] }) {
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

function AccessLogTable() {
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

function PageFrame({ title, description, children }: { title: string; description: string; children: ReactNode }) {
  return (
    <motion.main initial={{ opacity: 0, y: 12 }} animate={{ opacity: 1, y: 0 }} className="min-w-0 max-w-full overflow-x-hidden flex flex-col gap-5">
      <div>
        <h1 className="text-3xl font-black tracking-normal text-strong">{title}</h1>
        <p className="mt-1 max-w-3xl text-sm leading-6 text-muted">{description}</p>
      </div>
      {children}
    </motion.main>
  );
}

function Field({ label, value, onChange, disabled }: { label: string; value: string; onChange: (value: string) => void; disabled?: boolean }) {
  return <label className="flex flex-col gap-2"><span className="text-sm font-semibold text-strong">{label}</span><Input value={value} disabled={disabled} onChange={(event) => onChange(event.target.value)} /></label>;
}

function SelectField({
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

function EvidenceCard() {
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

function TimelineList({ record }: { record: CaseRecord }) {
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

function ChartPanel({ title, children }: { title: string; children: ReactNode }) {
  return <div className="min-w-0 rounded-[1.25rem] border border-[var(--border)] bg-[var(--surface-muted)] p-4"><h3 className="mb-3 text-sm font-bold text-strong">{title}</h3>{children}</div>;
}

function MiniBarList({ rows }: { rows: { name: string; value: number }[] }) {
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

function AlertTable({ alerts: rows, liveId, compact = false }: { alerts: AlertRecord[]; liveId?: string; compact?: boolean }) {
  const { t } = useNetra();
  return (
    <div className={cn("min-w-0 overflow-hidden rounded-[1.25rem] border border-[var(--border)]", !compact && "surface-solid")}>
      {!compact && <div className="p-5 pb-0"><h3 className="text-lg font-black text-strong">{t("alertQueue")}</h3><p className="text-sm text-muted">{t("alertQueueBody")}</p></div>}
      <div className="overflow-x-auto p-5">
        <table className={cn("w-full text-left text-sm", compact && "min-w-[760px]")}>
          <thead className="border-b border-[var(--border)] text-xs uppercase text-muted"><tr><th className="py-3 pr-4">{t("severity")}</th><th className="pr-4">{t("class")}</th><th className="pr-4">{t("type")}</th><th className="pr-4">{t("source")}</th><th className="pr-4">{t("destination")}</th><th className="pr-4">{t("protocol")}</th><th className="pr-4">{t("confidence")}</th><th>{t("status")}</th></tr></thead>
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

function SeverityBadge({ severity }: { severity: Severity }) {
  return <Badge variant={severity === "critical" ? "destructive" : "secondary"}>{severity}</Badge>;
}

function AttackBadge({ attackClass }: { attackClass: AttackClass }) {
  return <Badge>{attackClass}</Badge>;
}

function MetadataRow({ label, value }: { label: string; value: string }) {
  return <div className="grid grid-cols-[minmax(7rem,0.45fr)_minmax(0,1fr)] gap-4 border-b border-[var(--border)] py-2 text-sm last:border-b-0"><span className="text-muted">{label}</span><span className="min-w-0 break-all text-right font-semibold text-strong">{value}</span></div>;
}

function NormalizationMetric({ label, value, compact = false }: { label: string; value: string; compact?: boolean }) {
  return (
    <div className="min-w-0 rounded-xl border border-[var(--border)] bg-[var(--surface)] px-3 py-3">
      <div className="text-[11px] font-semibold uppercase tracking-[0.08em] text-muted">{label}</div>
      <div className={cn("mt-1 text-sm font-black leading-5 text-strong", compact ? "break-words" : "truncate")} title={value}>{value}</div>
    </div>
  );
}

function ReportSection({ title, children }: { title: string; children: ReactNode }) {
  return <motion.section initial={{ opacity: 0, y: 10 }} animate={{ opacity: 1, y: 0 }} className="rounded-[1.25rem] border border-[var(--border)] p-4"><h3 className="mb-3 text-base font-bold text-strong">{title}</h3>{children}</motion.section>;
}

function nodeStyle(risk = 0) {
  const color = risk >= 90 ? "#ef4444" : risk >= 75 ? "#f97316" : risk >= 50 ? "#f59e0b" : "var(--accent)";
  return { border: `2px solid ${color}`, borderRadius: 12, color: "var(--text-strong)", background: "#15120f", boxShadow: "0 14px 36px rgba(13, 13, 13, 0.22)", fontWeight: 700, whiteSpace: "pre-line" as const, padding: 12, width: 180 };
}

function edgeStyle(width: number, risk = 0) {
  const color = risk >= 90 ? "#ef4444" : risk >= 75 ? "#f97316" : "var(--accent)";
  return { stroke: color, strokeWidth: width };
}

export default App;
