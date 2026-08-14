import { Activity, Database, FileText, Fingerprint, History, type LucideIcon } from "lucide-react";
import { Alert, Badge, Button, Input, Progress } from "../../../components/ui/primitives";
import { API_BASE } from "../ConsoleCore";
import { apiGet } from "../ConsoleCore";
import { appViewRoute } from "../ConsoleCore";
import { BPF_FILTER_ENABLED } from "../ConsoleCore";
import { ExportHistoryTable } from "../reports/ReportPages";
import { Field } from "../reports/ReportPages";
import { formatNumber } from "../../../lib/utils";
import { Link } from "react-router-dom";
import { MetadataRow } from "../reports/ReportPages";
import { MetricTile } from "../reports/ReportPages";
import { netraHeaders } from "../ConsoleCore";
import { PageFrame } from "../reports/ReportPages";
import { SelectField } from "../reports/ReportPages";
import { TECHNICAL_STATUS_REFRESH_MS } from "../ConsoleCore";
import { toast } from "sonner";
import { type CapacityRecord, type CaptureJobRecord, type CaptureScheduleRecord, type SensorGroupRecord, type SensorRecord } from "../../../lib/types";
import { type DeploymentModuleKey } from "../ConsoleCore";
import { useCallback, useEffect, useState } from "react";
import { useNetra } from "../ConsoleCore";

export function ExportCenterPage() {
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

export function SettingsPage() {
  const { deploymentAccess } = useNetra();
  const sections: { module: DeploymentModuleKey; title: string; description: string; href: string; icon: LucideIcon }[] = [
    { module: "system", title: "Technical Status", description: "Deployment health, workers, storage, database, ML artifact, and operational diagnostics.", href: appViewRoute("technicalStatus"), icon: Activity },
    { module: "system", title: "User Administration", description: "AAL2-protected invitations, roles, account activation, MFA state, and Administrator transfer.", href: "/administration", icon: Fingerprint },
    { module: "system", title: "Account Security", description: "Enroll an additional authenticator and review the current MFA policy.", href: "/app/settings/security", icon: Fingerprint },
    { module: "sensors", title: "Sensors", description: "Enrollment, heartbeats, interfaces, groups, and bounded native-capture controls.", href: appViewRoute("sensors"), icon: Database },
    { module: "schedules", title: "Schedules", description: "One-time and recurring capture windows for enrolled external sensors.", href: appViewRoute("schedules"), icon: History },
    { module: "integrations", title: "Integrations", description: "Administrator-managed SIEM and signed webhook destinations and delivery history.", href: appViewRoute("integrations"), icon: FileText },
    { module: "retention", title: "Retention", description: "Retention policy, cleanup previews, legal holds, and approved storage cleanup.", href: appViewRoute("retention"), icon: Fingerprint },
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

export function LabToolsPage() {
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
  const captureJobId = captureJob?.jobId;
  const captureJobMode = captureJob?.mode;

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
    if (!captureJobId || !captureJobMode || terminal) return undefined;
    let mounted = true;
    const refresh = async () => {
      const family = captureJobMode === "replay" ? "replay" : "live";
      try {
        const current = await apiGet<CaptureJobRecord>(`/capture/${family}/${captureJobId}/status`);
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
  }, [captureJobId, captureJobMode, terminal, reloadAnalysis]);

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
            {!deploymentAccess.sensorCaptureEnabled && <Button asChild variant="secondary"><Link to={appViewRoute("sensors")}>View sensor requirements</Link></Button>}
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

export function SensorsPage() {
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

export function SchedulesPage() {
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

export function RetentionPage() {
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

export function SystemPage() {
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
    const interval = window.setInterval(() => {
      if (document.visibilityState === "visible") refresh();
    }, TECHNICAL_STATUS_REFRESH_MS);
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
