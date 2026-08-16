import { Activity, AlertTriangle, ArrowLeftRight, Database, FileSearch, FileText, FolderSearch, KeyRound, Languages, LogOut, type LucideIcon, Menu, PanelLeftClose, PanelLeftOpen, Search, Settings as SettingsIcon, ShieldCheck, Upload } from "lucide-react";
import { Alert, Button, Select, SelectContent, SelectItem, SelectTrigger, SelectValue, Sheet, SheetContent, SheetTitle, TooltipProvider } from "../../components/ui/primitives";
import { InlineTransition, PageTransition } from "../../components/PageTransition";
import { appViewRoute } from "./ConsoleCore";
import { AuthProvider } from "../auth/AuthProvider";
import { caseWorkspaceRoute } from "./ConsoleCore";
import { cn } from "../../lib/utils";
import { Link, MemoryRouter as Router, Navigate, NavLink, Route, Routes, useLocation, useNavigate, useParams } from "react-router-dom";
import { MetadataRow } from "./reports/ReportPages";
import { MfaPage } from "../auth/MfaPage";
import { motion, MotionConfig } from "framer-motion";
import { NetraProvider } from "./ConsoleProvider";
import { PageFrame } from "./reports/ReportPages";
import { PublicHomePage } from "../../public/PublicSite";
import { RouteErrorBoundary } from "../../components/RouteErrorBoundary";
import { toast, Toaster } from "sonner";
import { type DeploymentModuleKey } from "./ConsoleCore";
import { lazy, Suspense, type ReactNode, useCallback, useEffect, useRef, useState } from "react";
import { type Language } from "../../lib/types";
import { useAuth } from "../auth/AuthContext";
import { AuthLayout } from "../auth/AuthLayout";
import { useNetra } from "./ConsoleCore";
import { VIEW_REFS } from "./ConsoleCore";
import { clearLastConsoleWorkspace, getLastConsoleWorkspace, rememberConsoleWorkspace, switchConsoleWorkspace } from "../../lib/consoleContext";

const loadEvidencePages = () => import("./evidence/EvidencePages");
const loadAdministrationWorkspace = () => import("../administration/EmbeddedApp");
const UploadPage = lazy(() => loadEvidencePages().then((module) => ({ default: module.UploadPage })));
const TrafficPages = {
  Dashboard: lazy(() => import("./analysis/TrafficPages").then((module) => ({ default: module.DashboardPage }))),
  Packets: lazy(() => import("./analysis/TrafficPages").then((module) => ({ default: module.PacketExplorerPage }))),
  Protocols: lazy(() => import("./analysis/TrafficPages").then((module) => ({ default: module.ProtocolDecoderPage }))),
  Payloads: lazy(() => import("./analysis/TrafficPages").then((module) => ({ default: module.PayloadInspectionPage }))),
  Sessions: lazy(() => import("./analysis/TrafficPages").then((module) => ({ default: module.SessionsPage }))),
  Detection: lazy(() => import("./analysis/TrafficPages").then((module) => ({ default: module.ThreatDetectionPage }))),
  Anomaly: lazy(() => import("./analysis/TrafficPages").then((module) => ({ default: module.AiAnomalyPage }))),
};
const SuspiciousActivityPage = lazy(() => import("./analysis/FindingPages").then((module) => ({ default: module.SuspiciousActivityPage })));
const TrafficEvidencePage = lazy(() => import("./analysis/FindingPages").then((module) => ({ default: module.TrafficEvidencePage })));
const EvidenceReportPage = lazy(() => import("./reports/EvidenceReportPages").then((module) => ({ default: module.EvidenceReportPage })));
const ReportPage = lazy(() => import("./reports/ReportPages").then((module) => ({ default: module.ReportPage })));
const CasesPage = lazy(() => import("./cases/CasePages").then((module) => ({ default: module.CasesPage })));
const CaseDetailPage = lazy(() => import("./cases/CasePages").then((module) => ({ default: module.CaseDetailPage })));
const IntegrationsPage = lazy(() => import("./integrations/IntegrationPages").then((module) => ({ default: module.IntegrationsPage })));
const CompliancePage = lazy(() => import("./integrations/IntegrationPages").then((module) => ({ default: module.CompliancePage })));
const GraphPage = lazy(() => import("./integrations/IntegrationPages").then((module) => ({ default: module.GraphPage })));
const ExportCenterPage = lazy(() => import("./operations/OperationsPages").then((module) => ({ default: module.ExportCenterPage })));
const SettingsPage = lazy(() => import("./operations/OperationsPages").then((module) => ({ default: module.SettingsPage })));
const LabToolsPage = lazy(() => import("./operations/OperationsPages").then((module) => ({ default: module.LabToolsPage })));
const SensorsPage = lazy(() => import("./operations/OperationsPages").then((module) => ({ default: module.SensorsPage })));
const SchedulesPage = lazy(() => import("./operations/OperationsPages").then((module) => ({ default: module.SchedulesPage })));
const RetentionPage = lazy(() => import("./operations/OperationsPages").then((module) => ({ default: module.RetentionPage })));
const SystemPage = lazy(() => import("./operations/OperationsPages").then((module) => ({ default: module.SystemPage })));
const AdministrationWorkspace = lazy(loadAdministrationWorkspace);

export function App() {
  return (
    <AuthProvider>
      <MotionConfig reducedMotion="user">
        <TooltipProvider>
          <NetraProvider>
            <div className="app-theme">
              <Router initialEntries={["/"]}>
            <Toaster position="top-right" />
            <Suspense fallback={<RouteLoadingScreen />}>
            <Routes>
              <Route path="/" element={<RootEntry />} />
              <Route path="/app/*" element={<RequireAuth><AppShell /></RequireAuth>} />
              <Route path="/administration/*" element={<RequireAuth><AdministrationEntry /></RequireAuth>} />
              <Route path="*" element={<Navigate to="/" replace />} />
            </Routes>
            </Suspense>
              </Router>
            </div>
          </NetraProvider>
        </TooltipProvider>
      </MotionConfig>
    </AuthProvider>
  );
}

function AdministrationEntry() {
  const navigate = useNavigate();
  const { state, signOut } = useAuth();
  if (!("profile" in state) || !("session" in state) || !state.profile.workspaces?.administration?.available) {
    return <Navigate to="/" replace />;
  }
  return (
    <AdministrationWorkspace
      profile={{
        userId: state.session.user.id,
        email: state.session.user.email ?? "",
        displayName: state.profile.user,
        role: state.profile.role,
        organizationName: state.profile.organization.name,
        isOwner: false,
        isAdministrative: true,
      }}
      onExit={() => {
        clearLastConsoleWorkspace();
        navigate("/", { replace: true });
      }}
      onSignOut={signOut}
    />
  );
}

function LeaveForLogin({ path }: { path: string }) {
  useEffect(() => {
    window.location.replace(path);
  }, [path]);
  return <RouteLoadingScreen />;
}

function RootEntry() {
  const { state } = useAuth();

  if (state.status === "initializing" || state.status === "resolving_profile") return <RouteLoadingScreen />;
  if (state.status === "signed_out" || state.status === "profile_denied") {
    return <PublicHomePage languageControl={<LanguageControl />} />;
  }
  if (state.status === "recovery") return <LeaveForLogin path="/login/recovery?required=1" />;
  if (state.status === "mfa_enrollment_required" || state.status === "mfa_challenge_required") {
    return <LeaveForLogin path="/login/mfa" />;
  }
  if (!("session" in state) || !("profile" in state)) return <RouteLoadingScreen />;
  return <WorkspaceEntry state={state} />;
}

function WorkspaceEntry({ state }: { state: Extract<ReturnType<typeof useAuth>["state"], { session: unknown; profile: unknown }> }) {
  const navigate = useNavigate();
  const [opening, setOpening] = useState<"investigation" | "administration" | null>(null);
  const [error, setError] = useState("");
  const restored = useRef(false);

  const administration = state.profile.workspaces?.administration?.available === true;
  const open = useCallback(async (workspace: "investigation" | "administration") => {
    setOpening(workspace);
    setError("");
    try {
      await Promise.all([
        switchConsoleWorkspace(state.session.access_token, workspace),
        workspace === "administration" ? loadAdministrationWorkspace() : loadEvidencePages(),
      ]);
      rememberConsoleWorkspace(workspace);
      navigate(workspace === "administration" ? "/administration" : appViewRoute("upload"), { replace: true });
    } catch {
      if (workspace === "administration") {
        try {
          await Promise.all([
            switchConsoleWorkspace(state.session.access_token, "investigation"),
            loadEvidencePages(),
          ]);
          rememberConsoleWorkspace("investigation");
          toast.warning("Administration is not available for this account. Investigation was opened instead.");
          navigate(appViewRoute("upload"), { replace: true });
          return;
        } catch {
          // The shared context may have expired; surface the sign-in guidance below.
        }
      }
      setError("Netra could not open that workspace. Your access may have changed; sign in again.");
    } finally {
      setOpening(null);
    }
  }, [navigate, state.session.access_token]);

  useEffect(() => {
    if (restored.current) return;
    restored.current = true;
    const previous = getLastConsoleWorkspace();
    if (!administration || previous === "investigation" || previous === "administration") {
      const target = previous === "administration" && administration ? "administration" : "investigation";
      void open(target);
    }
  }, [administration, open]);

  if (!administration) {
    if (error) return <AuthLayout title="Investigation is unavailable" subtitle={error}><Button className="mt-5 w-full" onClick={() => void open("investigation")}>Try again</Button></AuthLayout>;
    return <PageTransition label="Loading Investigation" />;
  }
  return (
    <AuthLayout title="Choose a workspace" subtitle="You have access to more than one." width="wide">
        <div className="mb-5 flex items-center gap-3 border border-[var(--border)] bg-[var(--surface-solid)] px-4 py-3">
          <span className="grid size-9 shrink-0 place-items-center border border-[var(--accent-line)] bg-[var(--accent-soft)] text-[var(--accent)]"><ShieldCheck className="size-4" aria-hidden="true" /></span>
          <div className="min-w-0 flex-1">
            <p className="truncate text-[13.5px] font-medium text-[var(--text-strong)]">{state.profile.user}</p>
            <p className="truncate font-mono text-[11.5px] text-[var(--muted)]">{state.session.user.email ?? "Verified officer"} · {state.profile.organization.name}</p>
          </div>
          <span className="border border-[var(--accent-line)] bg-[var(--accent-soft)] px-2 py-1 font-mono text-[10px] uppercase tracking-[0.08em] text-[var(--accent-contrast)]">Verified</span>
        </div>
        {error ? <Alert>{error}</Alert> : null}
        <div className="grid gap-3 sm:grid-cols-2">
          <WorkspaceChoice icon={FolderSearch} name="Investigation Console" description="Cases, evidence, analysis and reports. Your day-to-day work." busy={opening !== null} opening={opening === "investigation"} onSelect={() => void open("investigation")} />
          <WorkspaceChoice icon={KeyRound} name="Administration" description="User accounts, roles, permissions and the access record." elevated busy={opening !== null} opening={opening === "administration"} onSelect={() => void open("administration")} />
        </div>
    </AuthLayout>
  );
}

function WorkspaceChoice({ icon: Icon, name, description, elevated = false, busy, opening, onSelect }: {
  icon: LucideIcon;
  name: string;
  description: string;
  elevated?: boolean;
  busy: boolean;
  opening: boolean;
  onSelect: () => void;
}) {
  return (
    <button
      type="button"
      disabled={busy}
      onClick={onSelect}
      className={cn(
        "group flex min-h-56 flex-col gap-3 border px-5 py-5 text-left transition-colors disabled:cursor-wait disabled:opacity-60",
        elevated ? "border-[var(--accent-line)] bg-[var(--accent-soft)] hover:border-[var(--accent)]" : "border-[var(--border-strong)] bg-[var(--surface-solid)] hover:border-[var(--muted)]",
      )}
    >
      <span className={cn("grid size-10 place-items-center border", elevated ? "border-[var(--accent-line)] bg-[var(--accent-soft)] text-[var(--accent)]" : "border-[var(--border-strong)] text-[var(--muted)]")}>
        <Icon className="size-5" strokeWidth={1.75} aria-hidden="true" />
      </span>
      <span className="text-[16px] font-semibold text-[var(--text-strong)]">{name}</span>
      <span className="text-[13px] leading-relaxed text-[var(--muted)]">{description}</span>
      {elevated ? <span className="border border-[var(--accent-line)] px-2 py-1 font-mono text-[10px] uppercase tracking-[0.08em] text-[var(--accent-contrast)]">Elevated privileges</span> : null}
      <span className={cn("mt-auto flex w-full items-center justify-center gap-2 px-3 py-2 text-center font-mono text-[12px] font-semibold uppercase", elevated ? "bg-[var(--accent)] text-[var(--charcoal-deep)]" : "border border-[var(--border-strong)] text-[var(--text)] group-hover:border-[var(--accent-line)] group-hover:text-[var(--accent)]")}>
        {opening ? <span className="size-3 animate-spin rounded-full border border-current border-t-transparent motion-reduce:animate-none" aria-hidden="true" /> : null}
        {opening ? "Opening…" : "Open"}
      </span>
    </button>
  );
}

export function RequireAuth({ children }: { children: ReactNode }) {
  const { state } = useAuth();

  if (state.status === "initializing" || state.status === "resolving_profile") {
    return <PageTransition label="Checking secure access" />;
  }

  if (state.status === "signed_out" || state.status === "profile_denied") {
    return <LeaveForLogin path="/login" />;
  }
  if (state.status === "mfa_enrollment_required" || state.status === "mfa_challenge_required") {
    return <LeaveForLogin path="/login/mfa" />;
  }
  if (state.status === "recovery") return <LeaveForLogin path="/login/recovery?required=1" />;

  return <>{children}</>;
}

function RouteLoadingScreen() {
  return <PageTransition label="Loading your workspace" />;
}

function RouteLoadingPanel() {
  return <main id="main-content"><InlineTransition label="Loading view" /></main>;
}

export function LanguageControl() {
  const { language, setLanguage } = useNetra();
  return (
    <Select value={language} onValueChange={(value) => setLanguage(value as Language)}>
      <SelectTrigger aria-label="Language" className="min-h-11 w-11 min-w-11 px-0 sm:w-auto sm:min-w-28 sm:px-3">
        <Languages className="size-4" />
        <span className="hidden sm:inline"><SelectValue /></span>
      </SelectTrigger>
      <SelectContent>
        <SelectItem value="English">English</SelectItem>
        <SelectItem value="Hindi">Hindi</SelectItem>
        <SelectItem value="Gujarati">Gujarati</SelectItem>
      </SelectContent>
    </Select>
  );
}

export function ModuleRoute({ module, children }: { module: DeploymentModuleKey; children: ReactNode }) {
  const { deploymentAccess } = useNetra();
  const access = deploymentAccess.modules[module];
  if (!deploymentAccess.verified) {
    return <Navigate to={appViewRoute("upload")} replace />;
  }
  if (!access.visible) return <Navigate to={appViewRoute("upload")} replace />;
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

export function OpaqueViewRoute() {
  const { viewRef = "" } = useParams();
  if (viewRef === VIEW_REFS.upload) return <UploadPage />;
  if (viewRef === VIEW_REFS.overview) return <TrafficPages.Dashboard />;
  if (viewRef === VIEW_REFS.activity) return <SuspiciousActivityPage />;
  if (viewRef === VIEW_REFS.evidence) return <TrafficEvidencePage />;
  if (viewRef === VIEW_REFS.reports) return <EvidenceReportPage />;
  if (viewRef === VIEW_REFS.packets) return <TrafficPages.Packets />;
  if (viewRef === VIEW_REFS.sessions) return <TrafficPages.Sessions />;
  if (viewRef === VIEW_REFS.decoder) return <TrafficPages.Protocols />;
  if (viewRef === VIEW_REFS.payloads) return <TrafficPages.Payloads />;
  if (viewRef === VIEW_REFS.detection) return <TrafficPages.Detection />;
  if (viewRef === VIEW_REFS.aiAnomaly) return <TrafficPages.Anomaly />;
  if (viewRef === VIEW_REFS.graph) return <GraphPage />;
  if (viewRef === VIEW_REFS.cases) return <CasesPage />;
  if (viewRef === VIEW_REFS.exports) return <ExportCenterPage />;
  if (viewRef === VIEW_REFS.lab) return <ModuleRoute module="lab"><LabToolsPage /></ModuleRoute>;
  if (viewRef === VIEW_REFS.compliance) return <CompliancePage />;
  if (viewRef === VIEW_REFS.settings) return <ModuleRoute module="system"><SettingsPage /></ModuleRoute>;
  if (viewRef === VIEW_REFS.technicalStatus) return <ModuleRoute module="system"><SystemPage /></ModuleRoute>;
  if (viewRef === VIEW_REFS.sensors) return <ModuleRoute module="sensors"><SensorsPage /></ModuleRoute>;
  if (viewRef === VIEW_REFS.schedules) return <ModuleRoute module="schedules"><SchedulesPage /></ModuleRoute>;
  if (viewRef === VIEW_REFS.integrations) return <ModuleRoute module="integrations"><IntegrationsPage /></ModuleRoute>;
  if (viewRef === VIEW_REFS.retention) return <ModuleRoute module="retention"><RetentionPage /></ModuleRoute>;
  return <Navigate to={appViewRoute("upload")} replace />;
}

export function LegacyCaseRedirect() {
  const { caseId = "" } = useParams();
  const { caseRecords } = useNetra();
  const record = caseRecords.find((item) => item.id === caseId);
  if (record?.routeRef) return <Navigate to={caseWorkspaceRoute(record.routeRef)} replace />;
  return <PageFrame title="Opening case" description="Resolving the secure case workspace."><div className="surface rounded-[1.5rem] p-6 text-sm text-muted">Checking case access…</div></PageFrame>;
}

export function AppShell() {
  const [sidebarCollapsed, setSidebarCollapsed] = useState(false);
  const location = useLocation();
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
            <RouteErrorBoundary resetKey={location.pathname}>
            <Suspense fallback={<RouteLoadingPanel />}>
            <Routes>
              <Route index element={<Navigate to={appViewRoute("upload")} replace />} />
              <Route path="v/:viewRef" element={<OpaqueViewRoute />} />
              <Route path="w/:routeRef" element={<CaseDetailPage />} />
              <Route path="d/:routeRef" element={<ReportPage />} />
              <Route path="cases/:caseId" element={<LegacyCaseRedirect />} />
              <Route path="reports/:caseId" element={<Navigate to={appViewRoute("reports")} replace />} />
              <Route path="upload" element={<Navigate to={appViewRoute("upload")} replace />} />
              <Route path="overview" element={<Navigate to={appViewRoute("overview")} replace />} />
              <Route path="dashboard" element={<Navigate to={appViewRoute("overview")} replace />} />
              <Route path="activity" element={<Navigate to={appViewRoute("activity")} replace />} />
              <Route path="evidence" element={<Navigate to={appViewRoute("evidence")} replace />} />
              <Route path="report" element={<Navigate to={appViewRoute("reports")} replace />} />
              <Route path="reports" element={<Navigate to={appViewRoute("reports")} replace />} />
              <Route path="packets" element={<Navigate to={appViewRoute("packets")} replace />} />
              <Route path="sessions" element={<Navigate to={appViewRoute("sessions")} replace />} />
              <Route path="decoder" element={<Navigate to={appViewRoute("decoder")} replace />} />
              <Route path="payloads" element={<Navigate to={appViewRoute("payloads")} replace />} />
              <Route path="detection" element={<Navigate to={appViewRoute("detection")} replace />} />
              <Route path="ai-anomaly" element={<Navigate to={appViewRoute("aiAnomaly")} replace />} />
              <Route path="graph" element={<Navigate to={appViewRoute("graph")} replace />} />
              <Route path="cases" element={<Navigate to={appViewRoute("cases")} replace />} />
              <Route path="exports" element={<Navigate to={appViewRoute("exports")} replace />} />
              <Route path="lab" element={<Navigate to={appViewRoute("lab")} replace />} />
              <Route path="compliance" element={<Navigate to={appViewRoute("compliance")} replace />} />
              <Route path="settings" element={<Navigate to={appViewRoute("settings")} replace />} />
              <Route path="settings/technical-status" element={<Navigate to={appViewRoute("technicalStatus")} replace />} />
              <Route path="settings/security" element={<MfaPage allowAdditional />} />
              <Route path="settings/sensors" element={<Navigate to={appViewRoute("sensors")} replace />} />
              <Route path="settings/schedules" element={<Navigate to={appViewRoute("schedules")} replace />} />
              <Route path="settings/integrations" element={<Navigate to={appViewRoute("integrations")} replace />} />
              <Route path="settings/retention" element={<Navigate to={appViewRoute("retention")} replace />} />
              <Route path="system" element={<Navigate to={appViewRoute("technicalStatus")} replace />} />
              <Route path="sensors" element={<Navigate to={appViewRoute("sensors")} replace />} />
              <Route path="schedules" element={<Navigate to={appViewRoute("schedules")} replace />} />
              <Route path="integrations" element={<Navigate to={appViewRoute("integrations")} replace />} />
              <Route path="retention" element={<Navigate to={appViewRoute("retention")} replace />} />
            </Routes>
            </Suspense>
            </RouteErrorBoundary>
          </div>
        </div>
      </div>
    </div>
  );
}

export function SidebarContent({ collapsed = false, onToggle }: { collapsed?: boolean; onToggle?: () => void }) {
  const { t, deploymentAccess } = useNetra();
  const navItem = (icon: LucideIcon, label: string, href: string): [LucideIcon, string, string] => [icon, label, href];
  const navGroups: { label: string; items: [LucideIcon, string, string][] }[] = [
    {
      label: t("mainWorkflow"),
      items: [
        navItem(Upload, "Start Investigation", appViewRoute("upload")),
        navItem(FileSearch, t("cases"), appViewRoute("cases")),
        navItem(FileText, t("evidenceReport"), appViewRoute("reports")),
        navItem(AlertTriangle, t("suspiciousActivity"), appViewRoute("activity")),
        navItem(Database, t("trafficEvidence"), appViewRoute("evidence")),
      ],
    },
    ...(deploymentAccess.modules.lab.visible ? [{
      label: "Lab Tools",
      items: [navItem(Activity, "Capture and Replay", appViewRoute("lab"))],
    }] : []),
    ...(deploymentAccess.modules.system.visible ? [{
      label: "Settings",
      items: [navItem(SettingsIcon, "Settings", appViewRoute("settings"))],
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

export function TopBar() {
  const { t, activeCaseId, caseRecords } = useNetra();
  const { state, signOut } = useAuth();
  const navigate = useNavigate();
  const activeCase = caseRecords.find((record) => record.id === activeCaseId);
  const canSwitchWorkspace = "profile" in state && state.profile.workspaces?.administration?.available === true;
  const [mobileOpen, setMobileOpen] = useState(false);
  return (
    <header className="technical-topbar no-print sticky top-0 z-20 flex items-center justify-between gap-3 border-b border-[var(--border)] px-4 py-3 backdrop-blur-xl sm:px-6">
      <div className="flex min-w-0 items-center gap-3">
        <Sheet open={mobileOpen} onOpenChange={setMobileOpen}>
          <Button variant="ghost" size="icon" className="min-h-11 min-w-11 lg:hidden" onClick={() => setMobileOpen(true)} aria-label={t("openNavigation")}>
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
      <div className="flex items-center gap-1 sm:gap-3">
        <LanguageControl />
        {canSwitchWorkspace ? (
          <Button variant="outline" className="min-h-11 min-w-11 px-0 xl:px-4" onClick={() => {
            clearLastConsoleWorkspace();
            navigate("/", { replace: true });
          }} aria-label="Switch workspace">
            <ArrowLeftRight className="size-4" aria-hidden="true" />
            <span className="hidden xl:inline">Switch workspace</span>
          </Button>
        ) : null}
        <Button variant="ghost" size="icon" className="min-h-11 min-w-11" onClick={() => void signOut()} aria-label="Sign out">
          <LogOut className="size-4" aria-hidden="true" />
        </Button>
        <Button className="min-h-11 min-w-11 px-0 sm:px-4" onClick={() => navigate(appViewRoute("reports"))} disabled={!activeCase?.reportEligible} title={activeCase?.reportBlockedReason ?? "Select a completed case first."} aria-label={t("generateReport")}>
          <FileText className="size-4 sm:hidden" aria-hidden="true" />
          <span className="hidden sm:inline">{t("generateReport")}</span>
        </Button>
      </div>
    </header>
  );
}

export default App;
