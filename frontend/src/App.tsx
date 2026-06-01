import "@xyflow/react/dist/style.css";
import { Background, Controls, MiniMap, ReactFlow, type Edge, type Node, type NodeMouseHandler } from "@xyflow/react";
import {
  Activity,
  AlertTriangle,
  Bell,
  CheckCircle2,
  ClipboardCheck,
  Database,
  Download,
  Eye,
  FileSearch,
  FileText,
  Fingerprint,
  History,
  Languages,
  Menu,
  Network,
  PanelLeftClose,
  PanelLeftOpen,
  Printer,
  Radio,
  Search,
  Shield,
  Upload,
  UploadCloud,
} from "lucide-react";
import { AnimatePresence, motion } from "framer-motion";
import { createContext, useCallback, useContext, useEffect, useMemo, useState, type ReactNode } from "react";
import { BrowserRouter as Router, Link, Navigate, NavLink, Route, Routes, useParams } from "react-router-dom";
import {
  Area,
  AreaChart,
  Bar,
  BarChart,
  CartesianGrid,
  Cell,
  Pie,
  PieChart,
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
  Separator,
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
  CaseRecord,
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
  OperationalEventRecord,
  SensorGroupRecord,
  ZeekEvidence,
} from "./lib/types";
import { cn, formatNumber } from "./lib/utils";

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
  uploadTitle: "Evidence Intake",
  uploadDesc: "Register case details, upload a PCAP or PCAPNG, and run real packet analysis.",
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
  uploadTitle: "साक्ष्य इनटेक",
  uploadDesc: "Case details दर्ज करें, PCAP या PCAPNG upload करें, और real packet analysis चलाएं।",
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
  uploadTitle: "પુરાવા ઇનટેક",
  uploadDesc: "Case details દાખલ કરો, PCAP અથવા PCAPNG upload કરો, અને real packet analysis ચલાવો.",
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

const workflowIcons = [Upload, Database, AlertTriangle, Network, FileSearch, FileText] as const;
const workflowKeys = [
  ["workflowRegisterTitle", "workflowRegisterBody"],
  ["workflowAnalyzeTitle", "workflowAnalyzeBody"],
  ["workflowClassifyTitle", "workflowClassifyBody"],
  ["workflowMapTitle", "workflowMapBody"],
  ["workflowCaseTitle", "workflowCaseBody"],
  ["workflowReportTitle", "workflowReportBody"],
] as const;
const storyKeys = [
  ["story1Title", "story1Body"],
  ["story2Title", "story2Body"],
  ["story3Title", "story3Body"],
  ["story4Title", "story4Body"],
  ["story5Title", "story5Body"],
] as const;
const capabilityKeys = [
  ["capLive", "capLiveBody"],
  ["capEncrypted", "capEncryptedBody"],
  ["capClassify", "capClassifyBody"],
  ["capHistory", "capHistoryBody"],
  ["capReports", "capReportsBody"],
] as const;
const marqueeKeys = ["marqueePcap", "marqueeDns", "marqueeTls", "marqueeJa3", "marqueeSni", "marqueeReport", "marqueeCustody"] as const;

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
  reloadAnalysis: () => Promise<void>;
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
};

const NetraContext = createContext<AppState | null>(null);

const API_BASE = import.meta.env.VITE_API_BASE_URL ?? "/api";

function createDefaultIntakeForm(): EvidenceIntakeForm {
  const now = new Date();
  const suffix = now.toISOString().replace(/\D/g, "").slice(2, 12);
  return {
    caseNumber: `CYB-GJ-${suffix}`,
    investigator: "Local Investigator",
    department: "Gujarat Cyber Crime Cell",
    evidenceType: "PCAP",
    sourceLocation: "",
    priority: "Standard",
    remarks: "",
    sourceIp: "",
    destinationIp: "",
    protocol: "",
    port: "",
    durationSeconds: "",
    packetLimit: "5000",
    bpfFilter: "",
  };
}

async function apiGet<T>(path: string): Promise<T> {
  const response = await fetch(`${API_BASE}${path}`, { headers: netraHeaders() });
  if (!response.ok) throw new Error(`API ${path} failed with ${response.status}`);
  return response.json() as Promise<T>;
}

function netraHeaders(extra?: HeadersInit): HeadersInit {
  return extra ?? {};
}

function scoped(path: string, caseId: string | null) {
  if (!caseId) return path;
  const joiner = path.includes("?") ? "&" : "?";
  return `${path}${joiner}caseId=${encodeURIComponent(caseId)}`;
}

async function loadAnalysisData(activeCaseId: string | null) {
  const [summaryResponse, casesResponse, packetsResponse, sessionsResponse, alertsResponse, decoderResponse, payloadResponse, detectionResponse, anomaliesResponse, timelineResponse, protocolResponse, graphResponse, exportsResponse, accessResponse, complianceResponse] = await Promise.all([
    apiGet<DashboardSummary & { evidence: EvidenceFile | null }>(scoped("/dashboard/summary", activeCaseId)),
    apiGet<{ results: CaseRecord[] }>("/cases"),
    apiGet<{ results: PacketRecord[] }>(scoped("/packets", activeCaseId)),
    apiGet<{ results: SessionRecord[] }>(scoped("/sessions", activeCaseId)),
    apiGet<{ results: AlertRecord[] }>(scoped("/alerts", activeCaseId)),
    apiGet<{ results: DecodedProtocolRecord[]; zeek?: ZeekEvidence }>(scoped("/decoder/summary", activeCaseId)),
    apiGet<{ results: PayloadFinding[] }>(scoped("/payloads", activeCaseId)),
    apiGet<{ results: DetectionRuleMatch[] }>(scoped("/detection/matches", activeCaseId)),
    apiGet<{ results: AnomalyRecord[] }>(scoped("/anomalies", activeCaseId)),
    apiGet<{ results: { time: string; mb: number; alerts: number }[] }>(scoped("/dashboard/traffic-timeline", activeCaseId)),
    apiGet<{ results: { name: string; value: number }[] }>(scoped("/dashboard/protocol-distribution", activeCaseId)),
    apiGet<{ nodes: { id: string; label: string; risk: number }[]; edges: { source: string; target: string; protocol: string; packets: number; bytes?: number; risk?: number; attackClass?: AttackClass; sessionId: string; alertIds?: string[] }[] }>(scoped("/graph", activeCaseId)),
    apiGet<{ results: ExportRecord[] }>("/exports"),
    apiGet<{ results: AccessLogRecord[] }>("/audit/access-logs"),
    apiGet<{ results: ComplianceRecord[] }>("/compliance/checklist"),
  ]);
  return {
    cases: casesResponse.results,
    evidence: summaryResponse.evidence,
    summary: summaryResponse,
    zeek: decoderResponse.zeek ?? summaryResponse.zeek ?? null,
    packets: packetsResponse.results,
    sessions: sessionsResponse.results,
    alerts: alertsResponse.results,
    decodedProtocols: decoderResponse.results,
    payloadFindings: payloadResponse.results,
    detectionMatches: detectionResponse.results,
    anomalies: anomaliesResponse.results,
    trafficTimelineData: timelineResponse.results,
    protocolChartData: protocolResponse.results,
    exports: exportsResponse.results,
    accessLogs: accessResponse.results,
    complianceRecords: complianceResponse.results,
    networkFlows: graphResponse.edges.map((edge, index) => ({
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
    })),
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
  const [language, setLanguage] = useState<Language>(() => {
    const stored = window.localStorage.getItem("netra-language");
    return stored === "Hindi" || stored === "Gujarati" || stored === "English" ? stored : "English";
  });

  useEffect(() => {
    window.localStorage.setItem("netra-language", language);
  }, [language]);

  const setActiveCaseId = useCallback((caseId: string | null) => {
    setActiveCaseIdState(caseId);
    if (caseId) window.localStorage.setItem("netra-active-case", caseId);
    else window.localStorage.removeItem("netra-active-case");
  }, []);

  const reloadAnalysis = useCallback(async () => {
    const data = await loadAnalysisData(activeCaseId);
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
    if (!activeCaseId && data.cases[0]) {
      setActiveCaseId(data.cases[0].id);
    }
    if (data.cases[0]) {
      setIntakeForm((current) => ({ ...current, caseNumber: data.cases[0].id, investigator: data.cases[0].investigator }));
    }
  }, [activeCaseId, setActiveCaseId]);

  useEffect(() => {
    reloadAnalysis().catch(() => undefined);
  }, [reloadAnalysis]);

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
      t: (key: string) => translations[language][key] ?? key,
      setLanguage,
      setIntakeForm,
      setActiveCaseId,
      addCaseNote,
    }),
    [accessLogRecordsState, activeCaseId, addCaseNote, alertRecords, anomaliesState, caseRecords, complianceRecordsState, decodedProtocolsState, detectionMatchesState, evidenceState, exportRecordsState, intakeForm, language, networkFlowsState, packetsState, payloadFindingsState, protocolChartDataState, reloadAnalysis, sessionsState, summaryState, trafficTimelineDataState, setActiveCaseId, zeekState],
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
              <Route path="/" element={<LandingPage />} />
              <Route path="/demo" element={<Navigate to="/app/upload" replace />} />
              <Route path="/app/*" element={<AppShell />} />
            </Routes>
          </Router>
        </div>
      </NetraProvider>
    </TooltipProvider>
  );
}

function LandingPage() {
  const { t } = useNetra();
  return (
    <main className="min-h-screen overflow-hidden">
      <LandingHeader />
      <section className="px-4 pb-20 pt-16 sm:px-6 lg:pb-28 lg:pt-24">
        <div className="mx-auto grid max-w-7xl gap-12 lg:grid-cols-[0.9fr_1.1fr]">
          <div className="flex flex-col gap-8">
            <div className="grid gap-3 md:grid-cols-3 lg:grid-cols-1">
              {[
                ["01", "heroPoint1Title", "heroPoint1Body"],
                ["02", "heroPoint2Title", "heroPoint2Body"],
                ["03", "heroPoint3Title", "heroPoint3Body"],
              ].map(([number, titleKey, bodyKey], index) => (
                <motion.div
                  key={number}
                  initial={{ opacity: 0, y: 18 }}
                  animate={{ opacity: 1, y: 0 }}
                  transition={{ delay: index * 0.08 }}
                  className="grid grid-cols-[3rem_1fr] gap-4 border-b border-[var(--border)] pb-4"
                >
                  <span className="text-sm font-bold text-accent">{number}</span>
                  <div>
                    <h3 className="font-semibold text-strong">{t(titleKey)}</h3>
                    <p className="mt-1 text-sm leading-6 text-muted">{t(bodyKey)}</p>
                  </div>
                </motion.div>
              ))}
            </div>
            <motion.div initial={{ opacity: 0, y: 22 }} animate={{ opacity: 1, y: 0 }} transition={{ delay: 0.18 }} className="flex flex-col gap-6">
              <h1 className="max-w-4xl text-5xl font-black leading-[1.03] tracking-normal text-strong sm:text-7xl lg:text-8xl">
                {t("landingHeadline")}
              </h1>
              <p className="max-w-2xl text-2xl font-semibold text-[var(--text)]">{t("landingSubhead")}</p>
              <p className="max-w-2xl text-base leading-7 text-muted">{t("landingBody")}</p>
              <div className="flex flex-col gap-3 sm:flex-row">
                <Button asChild size="lg">
                  <Link to="/app/upload">
                    <Eye data-icon="inline-start" />
                    {t("viewDemo")}
                  </Link>
                </Button>
                <Button asChild variant="secondary" size="lg">
                  <a href="#workflow">{t("exploreWorkflow")}</a>
                </Button>
              </div>
            </motion.div>
          </div>
          <motion.div initial={{ opacity: 0, y: 26 }} animate={{ opacity: 1, y: 0 }} transition={{ delay: 0.16 }} className="lg:pt-8">
            <PremiumPreview />
          </motion.div>
        </div>
      </section>
      <EvidenceMarquee />
      <ProofSection />
      <RequirementCoverageSection />
      <WorkflowSection />
      <StorySection />
      <CapabilitiesSection />
      <LandingFooter />
    </main>
  );
}

function RequirementCoverageSection() {
  const { t } = useNetra();
  const items = [
    ["Capture", "PCAP upload, real tshark parsing, filtering"],
    ["DPI", "Protocol decoder and payload inspection"],
    ["Detection", "Signatures, tunnels, malware C2, exfiltration"],
    ["AI", "Baseline deviation and unknown attack indicators"],
    ["Forensics", "Sessions, case evidence, exports, reports"],
    ["Compliance", "Evidence integrity, access logs, custody controls"],
  ];
  return (
    <section className="mx-auto max-w-7xl px-4 py-20 sm:px-6">
      <SectionHeading title={t("requirementCoverage")} description={t("requirementCoverageBody")} />
      <div className="grid gap-4 md:grid-cols-3">
        {items.map(([title, body]) => (
          <div key={title} className="rounded-[1.25rem] border border-[var(--border)] bg-[var(--surface-muted)] p-5">
            <div className="text-sm font-bold uppercase tracking-[0.16em] text-accent">{title}</div>
            <p className="mt-3 text-sm leading-6 text-muted">{body}</p>
          </div>
        ))}
      </div>
    </section>
  );
}

function LandingHeader() {
  const { t } = useNetra();
  return (
    <header className="sticky top-0 z-30 border-b border-[var(--border)] bg-[rgba(13,13,13,0.82)] backdrop-blur-xl">
      <div className="mx-auto flex max-w-7xl items-center justify-between gap-4 px-4 py-4 sm:px-6">
        <Link className="flex items-center gap-3 font-bold text-strong" to="/">
          <span className="flex size-10 items-center justify-center rounded-full border border-[var(--border)] bg-[var(--surface-muted)]">
            <Shield className="size-5 text-accent" />
          </span>
          Netra
        </Link>
        <nav className="hidden items-center gap-7 text-sm font-semibold text-muted md:flex">
          <a href="#workflow">{t("workflow")}</a>
          <a href="#capabilities">{t("capabilities")}</a>
          <Link to="/app/upload">{t("evidenceIntake")}</Link>
          <Link to="/app/cases">{t("reports")}</Link>
        </nav>
        <div className="flex items-center gap-2">
          <LanguageControl />
          <Button asChild>
            <Link to="/app/upload">{t("viewDemo")}</Link>
          </Button>
        </div>
      </div>
    </header>
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

function PremiumPreview() {
  const { t, alertRecords, evidence, packets, trafficTimelineData } = useNetra();
  const previewTimeline = trafficTimelineData.length ? trafficTimelineData : [{ time: "Ready", mb: 0, alerts: 0 }];
  const topAlert = alertRecords[0];
  return (
    <motion.div animate={{ y: [0, -8, 0] }} transition={{ duration: 6, repeat: Infinity, ease: "easeInOut" }} className="glass-panel overflow-hidden rounded-[2rem]">
      <div className="flex items-center justify-between border-b border-[var(--border)] p-5">
        <div className="flex items-center gap-2 font-semibold text-strong">
          <Shield className="size-5 text-accent" />
          {t("previewConsole")}
        </div>
        <Badge>{evidence ? "PCAP analyzed" : "Awaiting PCAP"}</Badge>
      </div>
      <div className="grid gap-5 p-5">
        <div className="grid grid-cols-3 gap-3">
          {[
            [t("previewPackets"), formatNumber(packets.length)],
            [t("previewAlerts"), String(alertRecords.length).padStart(2, "0")],
            [t("previewHash"), evidence?.sha256 ? t("previewVerified") : "Pending"],
          ].map(([label, value]) => (
            <div key={label} className="rounded-2xl border border-[var(--border)] bg-[var(--surface-muted)] p-4">
              <div className="text-xs text-muted">{label}</div>
              <div className="mt-1 text-2xl font-black text-strong">{value}</div>
            </div>
          ))}
        </div>
        <ResponsiveContainer width="100%" height={210}>
          <AreaChart data={previewTimeline}>
            <defs>
              <linearGradient id="previewOrange" x1="0" x2="0" y1="0" y2="1">
                <stop offset="5%" stopColor="var(--accent)" stopOpacity={0.42} />
                <stop offset="95%" stopColor="var(--accent)" stopOpacity={0.02} />
              </linearGradient>
            </defs>
            <XAxis dataKey="time" fontSize={11} tickLine={false} axisLine={false} stroke="var(--muted)" />
            <YAxis hide />
            <Area type="monotone" dataKey="mb" stroke="var(--accent)" fill="url(#previewOrange)" strokeWidth={2} />
          </AreaChart>
        </ResponsiveContainer>
        <div className="rounded-2xl border border-[var(--accent-line)] bg-[var(--accent-soft)] p-4">
          <div className="flex items-center gap-2 text-sm font-bold text-strong">
            <Bell className="size-4 text-accent" />
            {topAlert?.type ?? "Upload a PCAP to begin"}
          </div>
          <p className="mt-2 text-xs text-muted">{topAlert?.explanation ?? "Netra creates packet, protocol, alert, and anomaly rows only after real evidence is uploaded."}</p>
        </div>
      </div>
    </motion.div>
  );
}

function EvidenceMarquee() {
  const { t } = useNetra();
  const items = [...marqueeKeys, ...marqueeKeys];
  return (
    <section className="border-y border-[var(--border)] py-6">
      <div className="overflow-hidden">
        <div className="marquee-track gap-4">
          {items.map((key, index) => (
            <span key={`${key}-${index}`} className="rounded-full border border-[var(--border)] px-6 py-3 text-sm font-bold uppercase tracking-[0.16em] text-muted">
              {t(key)}
            </span>
          ))}
        </div>
      </div>
    </section>
  );
}

function ProofSection() {
  const { t } = useNetra();
  const rows = [
    [Fingerprint, "proofIntegrity", "proofIntegrityBody"],
    [Shield, "proofEncrypted", "proofEncryptedBody"],
    [Languages, "proofReports", "proofReportsBody"],
  ] as const;
  return (
    <section className="mx-auto grid max-w-7xl gap-5 px-4 py-24 sm:px-6 lg:grid-cols-3">
      {rows.map(([Icon, titleKey, bodyKey], index) => (
        <motion.div key={titleKey} initial={{ opacity: 0.35, y: 16 }} whileInView={{ opacity: 1, y: 0 }} viewport={{ once: true }} transition={{ delay: index * 0.06 }}>
          <div className="surface h-full rounded-[1.5rem] p-6 transition hover:-translate-y-1 hover:border-[var(--accent-line)]">
            <Icon className="mb-8 size-7 text-accent" />
            <h3 className="text-2xl font-black text-strong">{t(titleKey)}</h3>
            <p className="mt-3 text-sm leading-7 text-muted">{t(bodyKey)}</p>
          </div>
        </motion.div>
      ))}
    </section>
  );
}

function WorkflowSection() {
  const { t } = useNetra();
  return (
    <section id="workflow" className="mx-auto max-w-7xl px-4 py-24 sm:px-6">
      <SectionHeading title={t("workflowTitle")} description={t("workflowDescription")} />
      <div className="divide-y divide-[var(--border)] border-y border-[var(--border)]">
        {workflowKeys.map(([titleKey, bodyKey], index) => {
          const Icon = workflowIcons[index];
          return (
            <motion.div
              key={titleKey}
              initial={{ opacity: 0.35, y: 18 }}
              whileInView={{ opacity: 1, y: 0 }}
              viewport={{ once: true }}
              whileHover={{ x: 4 }}
              className="group grid gap-5 py-8 md:grid-cols-[6rem_1fr] md:items-center"
            >
              <div className="text-4xl font-black text-accent">0{index + 1}</div>
              <div>
                <div className="mb-3 flex items-center gap-3">
                  <Icon className="size-5 text-accent" />
                  <h3 className="text-3xl font-black text-strong">{t(titleKey)}</h3>
                </div>
                <p className="max-w-2xl text-sm leading-7 text-muted">{t(bodyKey)}</p>
                <div className="mt-5 h-px w-24 bg-[var(--accent)] transition-all duration-500 group-hover:w-56" />
              </div>
            </motion.div>
          );
        })}
      </div>
    </section>
  );
}

function StorySection() {
  const { t } = useNetra();
  return (
    <section className="mx-auto max-w-7xl px-4 py-24 sm:px-6">
      <SectionHeading title={t("storyTitle")} description={t("storyDescription")} />
      <div className="surface rounded-[1.75rem] p-4 sm:p-5">
        <div className="grid gap-4 md:grid-cols-2 xl:grid-cols-5">
          {storyKeys.map(([titleKey, bodyKey], index) => (
            <motion.article
              key={titleKey}
              initial={{ opacity: 0.78, y: 14 }}
              whileInView={{ opacity: 1, y: 0 }}
              viewport={{ once: true }}
              transition={{ delay: index * 0.04 }}
              whileHover={{ y: -4 }}
              className="min-h-64 rounded-[1.25rem] border border-[var(--border)] bg-[var(--surface-muted)] p-5 transition hover:border-[var(--accent-line)] hover:bg-[var(--accent-soft)]"
            >
              <Badge>0{index + 1}</Badge>
              <h3 className="mt-5 text-2xl font-black leading-tight text-strong">{t(titleKey)}</h3>
              <p className="mt-4 text-sm leading-7 text-muted">{t(bodyKey)}</p>
            </motion.article>
          ))}
        </div>
      </div>
    </section>
  );
}

function CapabilitiesSection() {
  const { t } = useNetra();
  return (
    <section id="capabilities" className="mx-auto max-w-7xl px-4 py-24 sm:px-6">
      <SectionHeading title={t("capTitle")} description={t("capDescription")} />
      <div className="divide-y divide-[var(--border)] border-y border-[var(--border)]">
        {capabilityKeys.map(([titleKey, bodyKey], index) => (
          <motion.div key={titleKey} whileHover={{ x: 4 }} className="group grid gap-4 py-7 md:grid-cols-[4rem_1fr] md:items-center">
            <span className="text-sm font-bold text-accent">0{index + 1}</span>
            <div>
              <h3 className="text-2xl font-black text-strong">{t(titleKey)}</h3>
              <p className="mt-2 max-w-2xl text-sm leading-7 text-muted">{t(bodyKey)}</p>
              <div className="mt-4 h-px w-16 bg-[var(--accent)] opacity-60 transition-all duration-500 group-hover:w-40" />
            </div>
          </motion.div>
        ))}
      </div>
    </section>
  );
}

function LandingFooter() {
  const { t } = useNetra();
  return (
    <footer className="border-t border-[var(--border)] px-4 py-14 sm:px-6">
      <div className="mx-auto grid max-w-7xl gap-10 md:grid-cols-[1.4fr_0.8fr_0.8fr]">
        <div>
          <div className="flex items-center gap-3 text-2xl font-black text-strong">
            <Shield className="size-6 text-accent" />
            Netra
          </div>
          <p className="mt-4 max-w-md text-sm leading-7 text-muted">{t("footerSentence")}</p>
          <p className="mt-8 text-xs text-muted">Netra ©2026</p>
        </div>
        <div>
          <h4 className="font-bold text-strong">{t("footerNav")}</h4>
          <div className="mt-4 grid gap-3 text-sm text-muted">
            <a href="#workflow">{t("workflow")}</a>
            <a href="#capabilities">{t("capabilities")}</a>
            <Link to="/app/cases">{t("cases")}</Link>
          </div>
        </div>
        <div>
          <h4 className="font-bold text-strong">{t("footerDemo")}</h4>
          <div className="mt-4 grid gap-3 text-sm text-muted">
            <Link to="/app/upload">{t("startInvestigation")}</Link>
            <Link to="/app/dashboard">{t("dashboard")}</Link>
            <Link to="/app/cases">{t("reports")}</Link>
          </div>
          <p className="mt-6 text-xs leading-6 text-muted">{t("footerNote")}</p>
        </div>
      </div>
    </footer>
  );
}

function AppShell() {
  const [sidebarCollapsed, setSidebarCollapsed] = useState(false);
  return (
    <div className="min-h-screen">
      <div className="flex">
        <motion.aside
          animate={{ width: sidebarCollapsed ? 80 : 288 }}
          className="no-print fixed inset-y-0 left-0 hidden border-r border-[var(--border)] bg-[var(--bg)] p-4 lg:flex lg:flex-col"
        >
          <SidebarContent collapsed={sidebarCollapsed} onToggle={() => setSidebarCollapsed((value) => !value)} />
        </motion.aside>
        <div className={cn("min-w-0 flex-1 transition-[padding] duration-300", sidebarCollapsed ? "lg:pl-20" : "lg:pl-72")}>
          <TopBar />
          <div className="p-4 sm:p-6">
            <Routes>
              <Route path="upload" element={<UploadPage />} />
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
              <Route path="reports/:caseId" element={<ReportPage />} />
              <Route path="exports" element={<ExportCenterPage />} />
              <Route path="integrations" element={<IntegrationsPage />} />
              <Route path="compliance" element={<CompliancePage />} />
              <Route path="system" element={<SystemPage />} />
              <Route path="sensors" element={<SensorsPage />} />
              <Route path="schedules" element={<SchedulesPage />} />
              <Route path="retention" element={<RetentionPage />} />
            </Routes>
          </div>
        </div>
      </div>
    </div>
  );
}

function SidebarContent({ collapsed = false, onToggle }: { collapsed?: boolean; onToggle?: () => void }) {
  const { activeCaseId, t } = useNetra();
  const navGroups = [
    { label: t("capture"), items: [[Upload, t("evidenceIntake"), "/app/upload"], [Database, t("packetExplorer"), "/app/packets"], [History, t("sessions"), "/app/sessions"]] },
    { label: t("analysis"), items: [[Activity, t("dashboard"), "/app/dashboard"], [Fingerprint, t("protocolDecoder"), "/app/decoder"], [Eye, t("payloadInspection"), "/app/payloads"], [AlertTriangle, t("threatDetection"), "/app/detection"], [Radio, t("aiAnomaly"), "/app/ai-anomaly"], [Network, t("networkGraph"), "/app/graph"]] },
    { label: t("investigation"), items: [[FileSearch, t("cases"), "/app/cases"], [FileText, t("reports"), `/app/reports/${activeCaseId ?? "new"}`], [Download, t("exportCenter"), "/app/exports"]] },
    { label: t("governance"), items: [[Radio, "Sensor Fleet", "/app/sensors"], [History, "Schedules", "/app/schedules"], [Database, "Retention", "/app/retention"], [Database, t("integrations"), "/app/integrations"], [ClipboardCheck, t("compliance"), "/app/compliance"], [Activity, "System", "/app/system"]] },
  ] as const;
  return (
    <>
      <div className="mb-8 flex items-center justify-between gap-2">
        <Link className="flex min-w-0 items-center gap-3" to="/">
          <span className="flex size-10 shrink-0 items-center justify-center rounded-full border border-[var(--border)] bg-[var(--surface-muted)]">
            <Shield className="size-5 text-accent" />
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
      {!collapsed && (
        <div className="mt-auto rounded-2xl border border-[var(--border)] bg-[var(--surface-muted)] p-4">
          <div className="mb-2 flex items-center gap-2 text-sm font-semibold text-strong">
            <Database className="size-4 text-accent" />
            {t("dockerReady")}
          </div>
          <p className="text-xs leading-5 text-muted">{t("dockerBody")}</p>
        </div>
      )}
    </>
  );
}

function TopBar() {
  const { t, activeCaseId } = useNetra();
  const [mobileOpen, setMobileOpen] = useState(false);
  return (
    <header className="no-print sticky top-0 z-20 flex items-center justify-between gap-3 border-b border-[var(--border)] bg-[rgba(13,13,13,0.82)] px-4 py-3 backdrop-blur-xl sm:px-6">
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
          <Link to={`/app/reports/${activeCaseId ?? "new"}`}>{t("generateReport")}</Link>
        </Button>
      </div>
    </header>
  );
}

function UploadPage() {
  const { t, alertRecords, decodedProtocols, evidence, intakeForm, packets, payloadFindings, reloadAnalysis, sessions, setActiveCaseId, setIntakeForm, summary } = useNetra();
  const [draft, setDraft] = useState<EvidenceIntakeForm>(intakeForm);
  const [selectedFile, setSelectedFile] = useState<File | null>(null);
  const [replayFile, setReplayFile] = useState<File | null>(null);
  const [processing, setProcessing] = useState(false);
  const [sensors, setSensors] = useState<SensorRecord[]>([]);
  const [sensorId, setSensorId] = useState("");
  const [interfaceName, setInterfaceName] = useState("");
  const [captureJob, setCaptureJob] = useState<CaptureJobRecord | null>(null);
  const [events, setEvents] = useState<OperationalEventRecord[]>([]);
  const [uploadResult, setUploadResult] = useState<{ topClass?: string; risk?: string; hash?: string; encryptedHash?: string; keyId?: string; jobId?: string; steps?: { name: string; status: string }[] } | null>(null);
  const selectedSensor = sensors.find((sensor) => sensor.id === sensorId);

  useEffect(() => {
    apiGet<{ results: SensorRecord[] }>("/sensors")
      .then((payload) => {
        setSensors(payload.results);
        const online = payload.results.find((sensor) => sensor.status === "online");
        if (online) {
          setSensorId((current) => current || online.id);
          setInterfaceName((current) => current || online.interfaces[0]?.name || "");
        }
      })
      .catch(() => setSensors([]));
  }, []);

  useEffect(() => {
    if (!captureJob || ["completed", "failed", "stopped"].includes(captureJob.status)) return;
    const source = new EventSource(`${API_BASE}/events/stream?captureJobId=${encodeURIComponent(captureJob.jobId)}`);
    let pollFailures = 0;
    const refreshStatus = async () => {
      try {
        const path = captureJob.mode === "replay" ? `/capture/replay/${captureJob.jobId}/status` : `/capture/live/${captureJob.jobId}/status`;
        const current = await apiGet<CaptureJobRecord>(path);
        setCaptureJob(current);
        pollFailures = 0;
        if (current.status === "completed") {
          await reloadAnalysis();
          toast.success("Capture finalized into immutable encrypted evidence.");
        }
      } catch {
        pollFailures += 1;
      }
    };
    const handleOperationalEvent = (message: MessageEvent) => {
      const event = JSON.parse(message.data) as OperationalEventRecord;
      setEvents((current) => [event, ...current].slice(0, 24));
      void refreshStatus();
    };
    const eventTypes = [
      "sensor.connected",
      "sensor.heartbeat",
      "capture.started",
      "capture.chunk_received",
      "capture.chunk_parsed",
      "capture.progress",
      "analysis.started",
      "analysis.completed",
      "capture.completed",
      "capture.failed",
      "worker.warning",
    ];
    source.onmessage = handleOperationalEvent;
    eventTypes.forEach((eventType) => source.addEventListener(eventType, handleOperationalEvent as EventListener));
    source.onerror = () => {
      pollFailures += 1;
      if (pollFailures > 2) source.close();
    };
    const poll = window.setInterval(() => void refreshStatus(), 5000);
    return () => {
      eventTypes.forEach((eventType) => source.removeEventListener(eventType, handleOperationalEvent as EventListener));
      source.close();
      window.clearInterval(poll);
    };
  }, [captureJob?.jobId, captureJob?.mode, captureJob?.status, reloadAnalysis]);

  function update<K extends keyof EvidenceIntakeForm>(key: K, value: EvidenceIntakeForm[K]) {
    setDraft((current) => ({ ...current, [key]: value }));
  }
  async function startProcessing() {
    if (!selectedFile) {
      toast.error("Choose a PCAP file first.");
      return;
    }
    setIntakeForm(draft);
    setProcessing(true);
    const form = new FormData();
    form.append("caseId", draft.caseNumber);
    form.append("file", selectedFile);
    form.append("investigator", draft.investigator);
    form.append("department", draft.department);
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
    try {
      const response = await fetch(`${API_BASE}/evidence/upload`, { method: "POST", headers: netraHeaders(), body: form });
      const payload = await response.json();
      if (!response.ok) throw new Error(payload.error ?? "Upload failed");
      setActiveCaseId(payload.caseId);
      if (payload.status === "queued") {
        setUploadResult({ hash: payload.sha256, encryptedHash: payload.encrypted_sha256, keyId: "dev-key-001", jobId: payload.jobId, steps: payload.job?.steps });
        toast.success("Evidence encrypted and queued for async worker analysis.");
        void followUploadJob(payload.jobId);
        return;
      }
      await reloadAnalysis();
      setUploadResult({ topClass: payload.detectedAttackClasses?.[0], risk: payload.riskLevel, hash: payload.sha256, encryptedHash: payload.encrypted_sha256, keyId: "dev-key-001", jobId: payload.jobId, steps: payload.job?.steps });
      toast.success(t("evidenceToast"));
    } catch (error) {
      toast.error(error instanceof Error ? error.message : "PCAP analysis failed");
    } finally {
      setProcessing(false);
    }
  }

  async function followUploadJob(jobId: string) {
    for (let attempt = 0; attempt < 120; attempt += 1) {
      await new Promise((resolve) => window.setTimeout(resolve, 2000));
      const job = await apiGet<{ status: string; steps?: { name: string; status: string }[] }>(`/jobs/${jobId}/status`).catch(() => null);
      if (!job) continue;
      setUploadResult((current) => ({ ...(current ?? {}), jobId, steps: job.steps }));
      if (job.status === "completed") {
        await reloadAnalysis();
        toast.success("Async evidence analysis completed.");
        return;
      }
      if (job.status === "failed") {
        toast.error("Async evidence analysis failed. Recovery fallback is available in the job record.");
        return;
      }
    }
    toast.error("Async analysis is still queued. Check System Monitor for worker health.");
  }

  async function startReplay() {
    if (!replayFile) {
      toast.error("Choose a PCAP file to replay.");
      return;
    }
    const form = new FormData();
    form.append("file", replayFile);
    form.append("caseId", draft.caseNumber);
    form.append("speed", "5x");
    form.append("chunkIntervalSeconds", "5");
    form.append("packetLimit", draft.packetLimit || "10000");
    const response = await fetch(`${API_BASE}/capture/replay/start`, { method: "POST", headers: netraHeaders(), body: form });
    const payload = await response.json();
    if (!response.ok) {
      toast.error(payload.error ?? "Replay could not start");
      return;
    }
    setCaptureJob(payload);
    setActiveCaseId(payload.caseId);
    toast.success("Replay feed started.");
  }

  async function startCapture() {
    if (!sensorId || !interfaceName) {
      toast.error("Start the native sensor and select one of its interfaces.");
      return;
    }
    const response = await fetch(`${API_BASE}/capture/live/start`, {
      method: "POST",
      headers: netraHeaders({ "Content-Type": "application/json" }),
      body: JSON.stringify({
        caseId: draft.caseNumber,
        sensorId,
        interfaceName,
        durationSeconds: Number(draft.durationSeconds || 60),
        packetLimit: Number(draft.packetLimit || 10000),
        chunkIntervalSeconds: 5,
        bpfFilter: draft.bpfFilter,
        sourceIp: draft.sourceIp,
        destinationIp: draft.destinationIp,
        protocol: draft.protocol,
        port: draft.port,
      }),
    });
    const payload = await response.json();
    if (!response.ok) {
      toast.error(payload.error ?? "Live capture could not start");
      return;
    }
    setCaptureJob(payload);
    setActiveCaseId(payload.caseId);
    toast.success("Bounded sensor capture queued.");
  }

  async function stopActiveCapture() {
    if (!captureJob) return;
    const family = captureJob.mode === "replay" ? "replay" : "live";
    const response = await fetch(`${API_BASE}/capture/${family}/${captureJob.jobId}/stop`, { method: "POST", headers: netraHeaders() });
    const payload = await response.json();
    if (!response.ok) toast.error(payload.error ?? "Capture could not be stopped");
    else setCaptureJob(payload);
  }

  return (
    <PageFrame title={t("uploadTitle")} description={t("uploadDesc")}>
      <div className="surface rounded-[1.5rem] p-5">
        <Alert>Choose a concrete evidence action. Netra creates investigation rows only from an uploaded file, a replayed feed, or bounded traffic captured by a connected sensor.</Alert>
        <div className="mt-5 grid gap-4 lg:grid-cols-2">
          <div>
            <h3 className="font-bold text-strong">Capture bounds</h3>
            <div className="mt-3 grid gap-3 md:grid-cols-2">
              <Field label="Duration limit (seconds)" value={draft.durationSeconds} onChange={(value) => update("durationSeconds", value)} />
              <Field label="Packet limit" value={draft.packetLimit} onChange={(value) => update("packetLimit", value)} />
              <Field label="BPF capture filter" value={draft.bpfFilter} onChange={(value) => update("bpfFilter", value)} />
            </div>
          </div>
          <div>
            <h3 className="font-bold text-strong">{t("preAnalysisFilters")}</h3>
            <div className="mt-3 grid gap-3 md:grid-cols-2">
              <Field label={t("sourceIp")} value={draft.sourceIp} onChange={(value) => update("sourceIp", value)} />
              <Field label={t("destinationIp")} value={draft.destinationIp} onChange={(value) => update("destinationIp", value)} />
              <SelectField label={t("protocol")} value={draft.protocol || "all"} values={["all", "DNS", "TLS", "HTTP", "SSH", "FTP", "SMTP", "SMB", "TCP", "UDP", "ICMP"]} onChange={(value) => update("protocol", value === "all" ? "" : value)} />
              <Field label={t("port")} value={draft.port} onChange={(value) => update("port", value)} />
            </div>
          </div>
        </div>
        <div className="mt-5 grid gap-3 sm:grid-cols-2 lg:grid-cols-5">
          {[[t("packetsParsed"), formatNumber(packets.length)], [t("sessionsReconstructed"), sessions.length], [t("protocolsDecoded"), decodedProtocols.length], [t("payloadFindings"), payloadFindings.length], [t("alertsGenerated"), alertRecords.length]].map(([label, value]) => (
            <div key={label} className="rounded-xl border border-[var(--border)] bg-[var(--surface-muted)] p-3">
              <div className="text-xs uppercase text-muted">{label}</div>
              <div className="mt-1 text-xl font-black text-strong">{value}</div>
            </div>
          ))}
        </div>
      </div>
      <div className="grid gap-5 xl:grid-cols-[0.8fr_1.2fr]">
        <div className="surface rounded-[1.5rem] p-5">
          <h2 className="text-xl font-black text-strong">{t("stepRegister")}</h2>
          <div className="mt-5 grid gap-4 md:grid-cols-2">
            <Field label={t("caseNumber")} value={draft.caseNumber} onChange={(value) => update("caseNumber", value)} disabled />
            <Field label={t("investigator")} value={draft.investigator} onChange={(value) => update("investigator", value)} />
            <Field label={t("department")} value={draft.department} onChange={(value) => update("department", value)} />
            <Field label={t("sourceLocation")} value={draft.sourceLocation} onChange={(value) => update("sourceLocation", value)} />
            <SelectField label={t("evidenceType")} value={draft.evidenceType} values={["PCAP", "Firewall Logs", "DNS Logs", "TLS Metadata", "Mixed Evidence"]} onChange={(value) => update("evidenceType", value as EvidenceIntakeForm["evidenceType"])} />
            <SelectField label={t("priority")} value={draft.priority} values={["Standard", "Urgent", "Critical"]} onChange={(value) => update("priority", value as EvidenceIntakeForm["priority"])} />
            <label className="flex flex-col gap-2 md:col-span-2">
              <span className="text-sm font-semibold text-strong">{t("remarks")}</span>
              <Textarea value={draft.remarks} onChange={(event) => update("remarks", event.target.value)} />
            </label>
          </div>
        </div>
        <div className="grid gap-5">
          <div className="surface-solid rounded-[1.5rem] p-5">
            <h2 className="text-xl font-black text-strong">Import existing PCAP</h2>
            <p className="mt-1 text-sm text-muted">Validate, hash, encrypt, parse, classify, and index one historical evidence file.</p>
            <div className="mt-5 flex flex-col gap-3 rounded-[1.25rem] border border-dashed border-[var(--border-strong)] bg-[var(--surface-muted)] p-5">
              <Input type="file" accept=".pcap,.pcapng,application/vnd.tcpdump.pcap" onChange={(event) => setSelectedFile(event.target.files?.[0] ?? null)} />
              <div className="font-bold text-strong">{selectedFile?.name ?? "Choose a real PCAP or PCAPNG file"}</div>
              <Button className="w-fit" onClick={startProcessing} disabled={processing || !selectedFile}>{processing ? "Analyzing..." : "Upload and analyze"}</Button>
            </div>
          </div>
          <div className="surface-solid rounded-[1.5rem] p-5">
            <h2 className="text-xl font-black text-strong">Capture from sensor</h2>
            <p className="mt-1 text-sm text-muted">Run a bounded native `dumpcap` capture from a sensor interface. Start the local sensor agent first.</p>
            <div className="mt-4 grid gap-3 md:grid-cols-2">
              <SelectField label="Sensor" value={sensorId || "none"} values={sensors.length ? sensors.map((sensor) => sensor.id) : ["none"]} onChange={(value) => {
                setSensorId(value === "none" ? "" : value);
                const sensor = sensors.find((item) => item.id === value);
                setInterfaceName(sensor?.interfaces[0]?.name ?? "");
              }} />
              <SelectField label="Interface" value={interfaceName || "none"} values={selectedSensor?.interfaces.length ? selectedSensor.interfaces.map((item) => item.name) : ["none"]} onChange={(value) => setInterfaceName(value === "none" ? "" : value)} />
            </div>
            <div className="mt-4 flex flex-wrap items-center gap-3">
              <Button onClick={startCapture} disabled={!sensorId || !interfaceName}>Start bounded capture</Button>
              <Badge variant={selectedSensor?.status === "online" ? "secondary" : "warning"}>{selectedSensor ? `${selectedSensor.name}: ${selectedSensor.status}` : "No sensor connected"}</Badge>
            </div>
          </div>
          <div className="surface-solid rounded-[1.5rem] p-5">
            <h2 className="text-xl font-black text-strong">Replay PCAP feed</h2>
            <p className="mt-1 text-sm text-muted">Stream an explicitly selected PCAP through the same chunk ingestion and finalization path used by native sensors.</p>
            <div className="mt-4 flex flex-col gap-3">
              <Input type="file" accept=".pcap,.pcapng,application/vnd.tcpdump.pcap" onChange={(event) => setReplayFile(event.target.files?.[0] ?? null)} />
              <Button className="w-fit" onClick={startReplay} disabled={!replayFile}>Start replay feed</Button>
            </div>
          </div>
        </div>
      </div>
      {captureJob && (
        <div className="surface rounded-[1.5rem] p-5">
          <div className="flex flex-wrap items-center justify-between gap-3">
            <div>
              <h2 className="text-xl font-black text-strong">Live evidence feed</h2>
              <p className="mt-1 text-sm text-muted">{captureJob.source} | {captureJob.status} | {captureJob.jobId}</p>
            </div>
            {!["completed", "failed", "stopped"].includes(captureJob.status) && <Button variant="secondary" onClick={stopActiveCapture}>Stop capture</Button>}
          </div>
          <div className="mt-5 grid gap-3 md:grid-cols-4">
            <MetricTile label="Packets" value={formatNumber(captureJob.packetsReceived)} detail="Received from real chunks" />
            <MetricTile label="Chunks" value={captureJob.chunksReceived} detail="Encrypted at rest" />
            <MetricTile label="Progress" value={`${captureJob.progress}%`} detail="Server-reported capture progress" />
            <MetricTile label="Status" value={captureJob.status} detail={captureJob.finalEvidenceId ? `Evidence ${captureJob.finalEvidenceId}` : "Awaiting finalization"} />
          </div>
          <Progress className="mt-5" value={captureJob.progress} />
          <div className="mt-5 overflow-x-auto">
            <table className="w-full min-w-[760px] text-left text-sm">
              <thead className="border-b border-[var(--border)] text-xs uppercase text-muted"><tr><th className="py-3">Time</th><th>Event</th><th>Details</th></tr></thead>
              <tbody>
                {(events.length ? events : [{ id: 0, eventType: "capture.awaiting_events", createdAt: "-", caseId: "", payload: { detail: "Waiting for persisted SSE events" } }]).map((event) => (
                  <tr key={`${event.id}-${event.eventType}`} className="border-b border-[var(--border)]">
                    <td className="py-3">{event.createdAt}</td><td>{event.eventType}</td><td className="font-mono text-xs">{JSON.stringify(event.payload)}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>
      )}
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
        </div>
      )}
      <EvidenceCard />
    </PageFrame>
  );
}

function DashboardPage() {
  const { t, alertRecords, caseRecords, decodedProtocols, packets, protocolChartData, sessions, trafficTimelineData, intakeForm, summary, zeek, activeCaseId, setActiveCaseId } = useNetra();
  const [severity, setSeverity] = useState("all");
  const [attackClass, setAttackClass] = useState("all");
  const filteredAlerts = alertRecords.filter((alert) => (severity === "all" || alert.severity === severity) && (attackClass === "all" || alert.attackClass === attackClass));
  const timeline = trafficTimelineData;
  const classificationData = Object.entries(alertRecords.reduce<Record<string, number>>((acc, alert) => {
    acc[alert.attackClass] = (acc[alert.attackClass] ?? 0) + 1;
    return acc;
  }, {})).map(([name, value]) => ({ name, value }));
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
      <div className="surface rounded-[1.5rem] p-4">
        <div className="flex flex-wrap items-center gap-3">
          <Select value={activeCaseId ?? caseRecords[0]?.id ?? ""} onValueChange={(value) => setActiveCaseId(value)}>
            <SelectTrigger className="max-w-xs"><SelectValue placeholder="Select case" /></SelectTrigger>
            <SelectContent>{caseRecords.map((record) => <SelectItem key={record.id} value={record.id}>{record.id}</SelectItem>)}</SelectContent>
          </Select>
          <Input className="max-w-xs" placeholder={t("searchPlaceholder")} />
          <Select value={severity} onValueChange={setSeverity}>
            <SelectTrigger><SelectValue /></SelectTrigger>
            <SelectContent>{["all", "critical", "high", "medium", "low"].map((item) => <SelectItem key={item} value={item}>{item}</SelectItem>)}</SelectContent>
          </Select>
          <Select value={attackClass} onValueChange={setAttackClass}>
            <SelectTrigger><SelectValue /></SelectTrigger>
            <SelectContent>{["all", "Credential Brute Force", "IoT Botnet / Scanning", "Malware C2 / Beaconing", "DNS Tunnel", "Data Exfiltration", "Service Exploitation", "Remote Command Execution", "SMB / NetBIOS Lateral Movement"].map((item) => <SelectItem key={item} value={item}>{item}</SelectItem>)}</SelectContent>
          </Select>
        </div>
        <div className="mt-5 grid gap-4 md:grid-cols-5">
          {[[t("packets"), formatNumber(packets.length)], [t("sessions"), sessions.length], [t("protocolsDecoded"), decodedProtocols.length], [t("alerts"), alertRecords.length], ["Top class", summary.topAttackClass], ["Risk", summary.riskLevel.toUpperCase()], [t("case"), intakeForm.caseNumber]].map(([label, value]) => (
            <div key={label} className="border-l border-[var(--border)] pl-4 first:border-l-0">
              <div className="text-xs font-semibold uppercase text-muted">{label}</div>
              <div className="mt-1 text-2xl font-black text-strong">{value}</div>
            </div>
          ))}
        </div>
        <div className="mt-5 grid gap-3 md:grid-cols-[1fr_0.8fr]">
          <div className="rounded-xl border border-[var(--border)] bg-[var(--surface-muted)] p-4">
            <div className="text-xs font-bold uppercase text-muted">Top alert</div>
            <div className="mt-2 text-lg font-black text-strong">{alertRecords[0]?.attackClass ?? "No high-risk alert"}</div>
            <p className="mt-1 text-sm leading-6 text-muted">{alertRecords[0]?.explanation ?? "Current capture is behaving like a low-risk baseline."}</p>
          </div>
          <div className="rounded-xl border border-[var(--border)] bg-[var(--surface-muted)] p-4">
            <div className="text-xs font-bold uppercase text-muted">Tool status</div>
            <div className="mt-3 flex flex-wrap gap-2">
              {Object.entries(summary.toolStatus ?? {}).map(([name, ok]) => <Badge key={name} variant={ok ? "secondary" : "destructive"}>{name}: {ok ? "ready" : "missing"}</Badge>)}
              <Badge>Zeek {zeek?.status ?? "not-run"}</Badge>
            </div>
          </div>
        </div>
        <div className="mt-5 flex flex-wrap gap-2">
          {[[t("packetExplorer"), "/app/packets"], [t("sessions"), "/app/sessions"], [t("protocolDecoder"), "/app/decoder"], [t("aiAnomaly"), "/app/ai-anomaly"]].map(([label, href]) => (
            <Button key={href} asChild variant="secondary" size="sm"><Link to={href}>{label}</Link></Button>
          ))}
        </div>
      </div>
      <div className="surface rounded-[1.5rem] p-4">
        <Tabs defaultValue="overview" className="flex flex-col gap-4">
          <TabsList className="w-fit flex-wrap">
            <TabsTrigger value="overview">{t("overview")}</TabsTrigger>
            <TabsTrigger value="alerts">{t("alerts")}</TabsTrigger>
            <TabsTrigger value="encrypted">{t("encryptedTraffic")}</TabsTrigger>
            <TabsTrigger value="classes">{t("classifications")}</TabsTrigger>
          </TabsList>
          <TabsContent value="overview">
            <div className="grid gap-4 lg:grid-cols-3">
              <ChartPanel title={t("protocolDistribution")}>
                <ResponsiveContainer width="100%" height={250}>
                  <PieChart>
                    <Pie data={protocolChartData} dataKey="value" nameKey="name" innerRadius={58} outerRadius={86}>
                      {["var(--accent)", "var(--text-strong)", "var(--muted)", "var(--border-strong)"].map((color) => <Cell key={color} fill={color} />)}
                    </Pie>
                    <ChartTooltip />
                  </PieChart>
                </ResponsiveContainer>
              </ChartPanel>
              <ChartPanel title={t("trafficTimeline")}>
                <ResponsiveContainer width="100%" height={250}>
                  <AreaChart data={timeline}>
                    <CartesianGrid stroke="var(--border)" strokeDasharray="3 3" vertical={false} />
                    <XAxis dataKey="time" fontSize={11} stroke="var(--muted)" />
                    <YAxis fontSize={11} stroke="var(--muted)" />
                    <ChartTooltip />
                    <Area dataKey="mb" type="monotone" stroke="var(--accent)" fill="var(--accent-soft)" />
                  </AreaChart>
                </ResponsiveContainer>
              </ChartPanel>
              <ChartPanel title={t("alertVolume")}>
                <ResponsiveContainer width="100%" height={250}>
                  <BarChart data={classificationData}>
                    <CartesianGrid stroke="var(--border)" strokeDasharray="3 3" vertical={false} />
                    <XAxis dataKey="name" fontSize={11} stroke="var(--muted)" />
                    <YAxis allowDecimals={false} fontSize={11} stroke="var(--muted)" />
                    <ChartTooltip />
                    <Bar dataKey="value" fill="var(--accent)" radius={[6, 6, 0, 0]} />
                  </BarChart>
                </ResponsiveContainer>
              </ChartPanel>
            </div>
          </TabsContent>
          <TabsContent value="alerts"><AlertTable alerts={filteredAlerts} /></TabsContent>
          <TabsContent value="encrypted"><EncryptedTrafficTable /></TabsContent>
          <TabsContent value="classes"><ClassificationPanel data={classificationData} /></TabsContent>
        </Tabs>
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
  }, [destinationIp, port, protocol, query, sessionId, severity, sourceIp]);

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
  const [health, setHealth] = useState<{ status: string; checks: Record<string, { status: string; latencyMs?: number; detail?: string }>; database?: { mode: string; host: string; port: string; name: string; tables: number }; access?: { mode: string; label: string; authentication: string; publicInternet: string; actor?: string; role?: string } } | null>(null);
  const [database, setDatabase] = useState<{ mode: string; host: string; port: string; name: string; user: string; tables: number; forensicsTables: string[]; access?: { mode: string; label: string; authentication: string; publicInternet: string } } | null>(null);
  const [metrics, setMetrics] = useState<Record<string, number>>({});
  const [deadLetters, setDeadLetters] = useState<{ id: string; workerName: string; caseId: string; error: string; status: string }[]>([]);
  const [workers, setWorkers] = useState<{ name: string; status: string; lastSeen?: string; currentJobId?: string; replicaCount?: number }[]>([]);
  const [sensors, setSensors] = useState<SensorRecord[]>([]);
  const [capacity, setCapacity] = useState<CapacityRecord | null>(null);
  useEffect(() => {
    function refresh() {
      apiGet<{ status: string; checks: Record<string, { status: string; latencyMs?: number; detail?: string }>; database?: { mode: string; host: string; port: string; name: string; tables: number }; access?: { mode: string; label: string; authentication: string; publicInternet: string; actor?: string; role?: string } }>("/system/health/deep").then(setHealth).catch(() => undefined);
      apiGet<{ mode: string; host: string; port: string; name: string; user: string; tables: number; forensicsTables: string[]; access?: { mode: string; label: string; authentication: string; publicInternet: string } }>("/system/database").then(setDatabase).catch(() => undefined);
      apiGet<Record<string, number>>("/system/metrics").then(setMetrics).catch(() => undefined);
      apiGet<{ results: typeof deadLetters }>("/system/dead-letter").then((payload) => setDeadLetters(payload.results)).catch(() => undefined);
      apiGet<{ results: typeof workers }>("/system/workers").then((payload) => setWorkers(payload.results)).catch(() => undefined);
      apiGet<{ results: SensorRecord[] }>("/system/sensors").then((payload) => setSensors(payload.results)).catch(() => undefined);
      apiGet<CapacityRecord>("/system/capacity").then(setCapacity).catch(() => undefined);
    }
    refresh();
    const interval = window.setInterval(refresh, 10000);
    return () => window.clearInterval(interval);
  }, []);
  return (
    <PageFrame title="System Monitor" description="Verified service probes, native sensors, worker heartbeats, storage, and dead-letter visibility.">
      <div className="grid gap-4 md:grid-cols-3 xl:grid-cols-6">
        {Object.entries(health?.checks ?? {}).map(([key, value]) => <MetricTile key={key} label={key} value={value.status} detail={value.detail ?? (value.latencyMs !== undefined ? `${value.latencyMs} ms` : "Live deep-health probe")} />)}
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
        <h2 className="text-xl font-black text-strong">LAN Access</h2>
        <div className="mt-4 grid gap-2 md:grid-cols-4">
          <MetadataRow label="Access mode" value={health?.access?.label ?? database?.access?.label ?? "Trusted LAN"} />
          <MetadataRow label="Authentication" value={health?.access?.authentication ?? database?.access?.authentication ?? "Disabled"} />
          <MetadataRow label="Public internet" value={health?.access?.publicInternet ?? database?.access?.publicInternet ?? "Not supported"} />
          <MetadataRow label="Audit actor" value={health?.access?.actor ?? "Local Investigator"} />
        </div>
        <p className="mt-3 text-sm text-muted">Anyone who can reach the private LAN URL can operate Netra. Keep port 8080 limited to trusted private networks.</p>
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
        <div className="p-5 pb-0"><h3 className="text-lg font-black text-strong">Worker heartbeats</h3></div>
        <div className="overflow-x-auto p-4">
          <table className="w-full min-w-[760px] text-left text-sm">
            <thead className="border-b border-[var(--border)] text-xs uppercase text-muted"><tr><th className="py-3">Worker</th><th>Status</th><th>Replicas</th><th>Current job</th><th>Last heartbeat</th></tr></thead>
            <tbody>{workers.map((item) => <tr key={item.name} className="border-b border-[var(--border)]"><td className="py-3 font-bold text-strong">{item.name}</td><td><Badge>{item.status}</Badge></td><td>{item.replicaCount ?? 0}</td><td>{item.currentJobId || "-"}</td><td>{item.lastSeen ?? "-"}</td></tr>)}</tbody>
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
  const { t, caseRecords, activeCaseId, setActiveCaseId } = useNetra();
  const [selectedCaseId, setSelectedCaseId] = useState(activeCaseId ?? caseRecords[0]?.id ?? "");
  const selectedCase = caseRecords.find((record) => record.id === selectedCaseId) ?? caseRecords[0];
  if (!selectedCase) {
    return <PageFrame title={t("cases")} description={t("caseQueueDesc")}><div className="surface rounded-[1.5rem] p-6 text-sm text-muted">Upload a PCAP to create a real case record.</div></PageFrame>;
  }
  return (
    <PageFrame title={t("cases")} description={t("caseQueueDesc")}>
      <div className="grid min-w-0 gap-5 xl:grid-cols-[minmax(0,0.95fr)_minmax(0,1.05fr)]">
        <div className="surface min-w-0 rounded-[1.5rem] p-5">
          <h2 className="text-xl font-black text-strong">{t("caseQueue")}</h2>
          <div className="mt-4 overflow-x-auto">
            <table className="w-full text-left text-sm">
              <thead className="border-b border-[var(--border)] text-xs uppercase text-muted">
                <tr><th className="py-3">{t("case")}</th><th>{t("status")}</th><th>{t("investigator")}</th><th>{t("report")}</th></tr>
              </thead>
              <tbody>
                {caseRecords.map((record) => (
                  <tr key={record.id} onClick={() => { setSelectedCaseId(record.id); setActiveCaseId(record.id); }} className={cn("cursor-pointer border-b border-[var(--border)] hover:bg-[var(--surface-muted)]", record.id === selectedCaseId && "bg-[var(--accent-soft)]")}>
                    <td className="py-3"><div className="font-semibold text-strong">{record.id}</div><div className="text-xs text-muted">{record.title}</div></td>
                    <td><Badge>{record.status}</Badge></td>
                    <td>{record.investigator}</td>
                    <td>{record.reportStatus}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>
        <CaseHistoryPanel record={selectedCase} />
      </div>
    </PageFrame>
  );
}

function CaseDetailPage() {
  const { t, caseRecords, alertRecords, addCaseNote, decodedProtocols, exportRecords, packets, payloadFindings, sessions } = useNetra();
  const { caseId = caseRecords[0]?.id ?? "" } = useParams();
  const record = caseRecords.find((caseRecord) => caseRecord.id === caseId) ?? caseRecords[0];
  const [note, setNote] = useState("");
  if (!record) {
    return <PageFrame title={t("caseDetail")} description={t("caseQueueDesc")}><div className="surface rounded-[1.5rem] p-6 text-sm text-muted">Upload a PCAP to create a real case record.</div></PageFrame>;
  }
  const linkedAlerts = alertRecords.filter((alert) => record.alertIds.includes(alert.id));
  return (
    <PageFrame title={`${t("caseDetail")} - ${record.id}`} description={record.title}>
      <div className="grid min-w-0 gap-5 xl:grid-cols-[minmax(0,420px)_minmax(0,1fr)]">
        <div className="min-w-0 flex flex-col gap-5">
          <div className="surface min-w-0 rounded-[1.5rem] p-5">
            <h2 className="text-xl font-black text-strong">{t("caseSummary")}</h2>
            <div className="mt-4 flex flex-col gap-1">
              <MetadataRow label={t("caseNumber")} value={record.id} />
              <MetadataRow label={t("investigator")} value={record.investigator} />
              <MetadataRow label={t("created")} value={record.createdAt} />
              <MetadataRow label={t("report")} value={record.reportStatus} />
            </div>
          </div>
          <EvidenceCard />
        </div>
        <div className="surface min-w-0 rounded-[1.5rem] p-5">
          <div className="flex flex-wrap items-center justify-between gap-3">
            <h2 className="text-xl font-black text-strong">{t("caseHistory")}</h2>
            <div className="flex flex-wrap gap-2">
              <Button asChild variant="secondary"><Link to={`/app/reports/${record.id}`}>{t("generateReport")}</Link></Button>
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
          <TimelineList record={record} />
          <Separator className="my-5" />
          <h3 className="mb-3 font-bold text-strong">{t("alerts")}</h3>
          <AlertTable alerts={linkedAlerts} compact />
          <Separator className="my-5" />
          <h3 className="mb-3 font-bold text-strong">{t("linkedEvidence")}</h3>
          <div className="grid gap-4 md:grid-cols-2 xl:grid-cols-3">
            <LinkedEvidencePanel title={t("packetExplorer")} items={packets.slice(0, 3).map((packet) => `${packet.id} · ${packet.protocol} · ${packet.riskScore}`)} />
            <LinkedEvidencePanel title={t("sessions")} items={sessions.slice(0, 3).map((session) => `${session.id} · ${session.protocol} · ${session.duration}`)} />
            <LinkedEvidencePanel title={t("payloadFindings")} items={payloadFindings.map((finding) => `${finding.id} · ${finding.matchedPattern}`)} />
            <LinkedEvidencePanel title={t("protocolDecoder")} items={decodedProtocols.slice(0, 3).map((record) => `${record.protocol} · ${record.status}`)} />
            <LinkedEvidencePanel title={t("exportCenter")} items={exportRecords.map((item) => `${item.id} · ${item.type} · ${item.status}`)} />
          </div>
          <Separator className="my-5" />
          <h3 className="mb-3 font-bold text-strong">{t("investigatorNotes")}</h3>
          <div className="grid gap-3">{record.notes.map((caseNote) => <div key={caseNote} className="rounded-xl bg-[var(--surface-muted)] p-3 text-sm">{caseNote}</div>)}</div>
        </div>
      </div>
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
  async function generateHtmlReport() {
    const response = await fetch(`${API_BASE}/reports/${record.id}/generate`, { method: "POST", headers: netraHeaders({ "Content-Type": "application/json" }), body: JSON.stringify({ language }) });
    const payload = await response.json();
    if (!response.ok) {
      toast.error(payload.error ?? "Report generation failed");
      return;
    }
    toast.success(`Report generated: ${payload.filename}`);
  }
  return (
    <PageFrame title={t("reportTitle")} description={`${record.id} - ${record.createdAt}`}>
      <div className="no-print glass-panel flex flex-wrap items-center gap-3 rounded-[1.5rem] p-3">
        <Select value={language} onValueChange={(value) => setLanguage(value as Language)}>
          <SelectTrigger><Languages className="size-4" /><SelectValue /></SelectTrigger>
          <SelectContent><SelectItem value="English">English</SelectItem><SelectItem value="Hindi">Hindi</SelectItem><SelectItem value="Gujarati">Gujarati</SelectItem></SelectContent>
        </Select>
        <Button variant="secondary" onClick={() => window.print()}><Printer className="size-4" />{t("print")}</Button>
        <Button variant="secondary" onClick={generateHtmlReport}><Download className="size-4" />Generate HTML Report</Button>
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
    <div className="surface rounded-[1.25rem] p-4">
      <div className="text-xs font-bold uppercase tracking-[0.12em] text-muted">{label}</div>
      <div className="mt-2 text-2xl font-black text-strong">{value}</div>
      {detail && <p className="mt-2 text-xs leading-5 text-muted">{detail}</p>}
    </div>
  );
}

function LinkedEvidencePanel({ title, items }: { title: string; items: string[] }) {
  return (
    <div className="rounded-[1.25rem] border border-[var(--border)] bg-[var(--surface-muted)] p-4">
      <h3 className="font-bold text-strong">{title}</h3>
      <div className="mt-3 grid gap-2">
        {items.map((item) => <div key={item} className="break-words rounded-lg bg-[var(--surface-muted)] p-2 text-xs text-muted">{item}</div>)}
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
      <div className="p-5 pb-0"><h3 className="text-lg font-black text-strong">Chain of custody</h3></div>
      <div className="overflow-x-auto p-4">
        <table className="w-full min-w-[900px] text-left text-sm">
          <thead className="border-b border-[var(--border)] text-xs uppercase text-muted"><tr><th className="py-3">Time</th><th>Actor</th><th>Action</th><th>Previous hash</th><th>Event hash</th></tr></thead>
          <tbody>{(rows.length ? rows : []).map((item) => <tr key={item.id} className="border-b border-[var(--border)]"><td className="py-3">{item.timestamp}</td><td>{item.actor}</td><td>{item.action}</td><td className="max-w-44 truncate font-mono text-xs">{item.previousHash || "root"}</td><td className="max-w-52 truncate font-mono text-xs">{item.eventHash}</td></tr>)}</tbody>
        </table>
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

function SectionHeading({ title, description }: { title: string; description: string }) {
  return (
    <div className="mb-10 max-w-4xl">
      <h2 className="text-4xl font-black tracking-normal text-strong md:text-5xl">{title}</h2>
      <p className="mt-3 max-w-2xl text-sm leading-7 text-muted">{description}</p>
    </div>
  );
}

function Field({ label, value, onChange, disabled }: { label: string; value: string; onChange: (value: string) => void; disabled?: boolean }) {
  return <label className="flex flex-col gap-2"><span className="text-sm font-semibold text-strong">{label}</span><Input value={value} disabled={disabled} onChange={(event) => onChange(event.target.value)} /></label>;
}

function SelectField({ label, value, values, onChange }: { label: string; value: string; values: string[]; onChange: (value: string) => void }) {
  return (
    <label className="flex flex-col gap-2">
      <span className="text-sm font-semibold text-strong">{label}</span>
      <Select value={value} onValueChange={onChange}>
        <SelectTrigger><SelectValue /></SelectTrigger>
        <SelectContent>{values.map((item) => <SelectItem key={item} value={item}>{item}</SelectItem>)}</SelectContent>
      </Select>
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

function CaseHistoryPanel({ record }: { record: CaseRecord }) {
  const { t } = useNetra();
  return (
    <div className="surface min-w-0 rounded-[1.5rem] p-5">
      <div className="flex items-start justify-between gap-3">
        <div><h2 className="text-xl font-black text-strong">{record.title}</h2><p className="mt-1 text-sm text-muted">{record.id}</p></div>
        <Button asChild><Link to={`/app/cases/${record.id}`}>{t("viewFullCase")}</Link></Button>
      </div>
      <h3 className="mt-6 text-sm font-bold uppercase text-muted">{t("caseHistory")}</h3>
      <TimelineList record={record} />
      <Separator className="my-5" />
      <h3 className="mb-3 font-bold text-strong">{t("investigatorNotes")}</h3>
      <div className="grid gap-3">{record.notes.slice(0, 2).map((note) => <div key={note} className="rounded-xl bg-[var(--surface-muted)] p-3 text-sm">{note}</div>)}</div>
    </div>
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
  return <div className="rounded-[1.25rem] border border-[var(--border)] bg-[var(--surface-muted)] p-4"><h3 className="mb-3 text-sm font-bold text-strong">{title}</h3>{children}</div>;
}

function ClassificationPanel({ data }: { data: { name: string; value: number }[] }) {
  const { t } = useNetra();
  return (
    <div className="grid gap-4 lg:grid-cols-[1fr_0.8fr]">
      <ChartPanel title={t("attackClassification")}>
        <ResponsiveContainer width="100%" height={270}>
          <BarChart data={data}><CartesianGrid stroke="var(--border)" strokeDasharray="3 3" vertical={false} /><XAxis dataKey="name" fontSize={11} stroke="var(--muted)" /><YAxis allowDecimals={false} fontSize={11} stroke="var(--muted)" /><ChartTooltip /><Bar dataKey="value" fill="var(--accent)" radius={[6, 6, 0, 0]} /></BarChart>
        </ResponsiveContainer>
      </ChartPanel>
      <div className="rounded-[1.25rem] border border-[var(--border)] bg-[var(--surface-muted)] p-5">
        <h3 className="font-bold text-strong">{t("nextActions")}</h3>
        <div className="mt-4 grid gap-3">{["actionDomain", "actionIsolate", "actionMetadata", "actionReport"].map((item) => <div key={item} className="flex items-center gap-2 text-sm"><CheckCircle2 className="size-4 text-accent" />{t(item)}</div>)}</div>
      </div>
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
      </div>
    </div>
  );
}

function EncryptedTrafficTable({ compact = false }: { compact?: boolean }) {
  const { t, packets } = useNetra();
  const tlsPackets = packets.filter((packet) => packet.protocol === "TLS");
  const rows = compact ? tlsPackets.slice(0, 4) : tlsPackets.slice(0, 100);
  return (
    <div className={cn("overflow-hidden rounded-[1.25rem] border border-[var(--border)]", !compact && "surface-solid")}>
      {!compact && <div className="p-5 pb-0"><h3 className="text-lg font-black text-strong">{t("encryptedTitle")}</h3><p className="text-sm text-muted">{t("encryptedBody")}</p></div>}
      <div className="overflow-x-auto p-5">
        <table className="w-full text-left text-sm">
          <thead className="border-b border-[var(--border)] text-xs uppercase text-muted"><tr><th className="py-3">{t("source")}</th><th>{t("destination")}</th><th>Session</th><th>Metadata preview</th><th>{t("risk")}</th></tr></thead>
          <tbody>{rows.map((packet) => (
            <tr key={packet.id} className="border-b border-[var(--border)] hover:bg-[var(--surface-muted)]"><td className="py-3 font-mono text-xs">{packet.sourceIp}:{packet.sourcePort || "-"}</td><td className="font-mono text-xs">{packet.destinationIp}:{packet.destinationPort || "-"}</td><td className="font-mono text-xs">{packet.sessionId || "-"}</td><td className="max-w-80 truncate font-mono text-xs">{packet.asciiPreview || "TLS metadata only; encrypted payload not decrypted."}</td><td className="font-bold text-strong">{packet.riskScore}</td></tr>
          ))}
          {rows.length === 0 && <tr><td className="py-6 text-center text-muted" colSpan={5}>No TLS packet metadata found. Upload a PCAP containing TLS traffic to populate this view.</td></tr>}</tbody>
        </table>
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
