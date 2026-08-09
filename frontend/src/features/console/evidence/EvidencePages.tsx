import {
  acceptForEvidenceType, ACTIVE_UPLOAD_JOB_KEY, allowedExtensionsForType, API_BASE, apiGet,
  appViewRoute, BPF_FILTER_ENABLED, CASE_FLAG_OPTIONS, caseWorkspaceRoute, DIRECT_UPLOAD_ENABLED,
  EVIDENCE_TYPE_OPTIONS, evidenceTypeHelper, fileExtension, fileExtensionAllowed, formatEta,
  localNormalizationPreview, MAX_UPLOAD_MB, netraHeaders, NORMALIZATION_PREVIEW_BYTES,
  uploadFormWithProgress, useNetra,
  type EvidenceNormalizationPreview, type EvidenceUploadPayload, type UploadResult,
  type UploadStage, type UploadTransferState,
} from "../ConsoleCore";
import { Badge, Button, Progress, Textarea } from "../../../components/ui/primitives";
import { beginResumableUpload, type DirectUploadSession, type ResumableUploadHandle } from "../../../lib/resumableUpload";
import { cn, formatBytes, formatNumber } from "../../../lib/utils";
import { ensureCurrentAccessToken } from "../../../lib/supabase";
import { EvidenceCard, Field, MetadataRow, NormalizationMetric, PageFrame, SelectField } from "../reports/ReportPages";
import { toast } from "sonner";
import { type CaseRecord, type EvidenceIntakeForm } from "../../../lib/types";
import { Upload, UploadCloud } from "lucide-react";
import { useCallback, useEffect, useRef, useState } from "react";
import { useNavigate } from "react-router-dom";
export function UploadPage() {
  const { t, alertRecords, decodedProtocols, deploymentAccess, evidence, intakeForm, packets, payloadFindings, reloadAnalysis, sessions, setActiveCaseId, setActiveUpload, setIntakeForm, summary } = useNetra();
  const navigate = useNavigate();
  const [draft, setDraft] = useState<EvidenceIntakeForm>(intakeForm); const [selectedFile, setSelectedFile] = useState<File | null>(null);
  const [processing, setProcessing] = useState(false); const [uploadStage, setUploadStage] = useState<UploadStage>("idle");
  const [uploadProgress, setUploadProgress] = useState(0);
  const [uploadTransfer, setUploadTransfer] = useState<UploadTransferState>({ bytesUploaded: 0, speedBytesPerSecond: 0, etaSeconds: null, paused: false, retryAttempt: 0, message: "" });
  const fileInputRef = useRef<HTMLInputElement | null>(null); const resumableUploadRef = useRef<ResumableUploadHandle | null>(null);
  const transferSampleRef = useRef({ bytes: 0, timestamp: 0, speed: 0 }); const [uploadResult, setUploadResult] = useState<UploadResult | null>(null);
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
  const uploadStageLabel: Record<UploadStage, string> = { idle: "Ready", uploading: "Uploading evidence", processing: "Upload complete — validating, hashing, encrypting, and analyzing", queued: "Encrypted and queued for analysis", complete: "Evidence analysis complete", failed: "Evidence processing failed" };
  function update<K extends keyof EvidenceIntakeForm>(key: K, value: EvidenceIntakeForm[K]) {
    setDraft((current) => ({ ...current, [key]: value }));
  }
  async function ensureCaseForAnalysis(file: File): Promise<CaseRecord> {
    const response = await fetch(`${API_BASE}/cases`, {
      method: "POST",
      headers: netraHeaders({ "Content-Type": "application/json" }),
      body: JSON.stringify({
        caseNumber: draft.caseNumber,
        title: `Evidence intake: ${file.name}`,
        priority: draft.priority,
        sourceLocation: draft.sourceLocation,
        remarks: draft.remarks,
        flags: draft.flags ?? [],
        origin: "officer_upload",
      }),
    });
    if (response.status === 409) return apiGet<CaseRecord>(`/cases/${encodeURIComponent(draft.caseNumber)}`);
    const payload = await response.json() as CaseRecord & { error?: string };
    if (!response.ok) throw new Error(payload.error ?? "The investigation case could not be created.");
    return payload;
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
    setActiveUpload((current) => current?.caseId === created.caseId ? { ...current, routeRef: created.routeRef, uploadSessionId: created.id, state: "uploading", step: "uploading" } : current);
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
        setActiveUpload((current) => current?.caseId === created.caseId ? { ...current, state: "uploading", progress: Math.min(100, Math.round(percentage)), bytesUploaded, speedBytesPerSecond: speed, step: "uploading" } : current);
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
    setActiveUpload((current) => current?.caseId === created.caseId ? { ...current, state: "finalizing", progress: 100, bytesUploaded: file.size, step: "validating_and_encrypting" } : current);
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
    setActiveUpload((current) => current?.caseId === finalized.caseId ? { ...current, routeRef: finalized.routeRef, uploadSessionId: finalized.id, jobId: finalized.jobId, state: "queued", progress: 5, step: "queued" } : current);
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
      const caseRecord = await ensureCaseForAnalysis(selectedFile);
      setActiveCaseId(caseRecord.id);
      setActiveUpload({
        caseId: caseRecord.id,
        routeRef: caseRecord.routeRef,
        filename: selectedFile.name,
        sizeBytes: selectedFile.size,
        state: "accepted",
        progress: 0,
        bytesUploaded: 0,
        speedBytesPerSecond: 0,
        step: "case_created",
        steps: [],
      });
      navigate(caseWorkspaceRoute(caseRecord.routeRef));
      void reloadAnalysis(caseRecord.id).catch(() => undefined);
      if (DIRECT_UPLOAD_ENABLED) {
        await startResumableProcessing(selectedFile);
        return;
      }
      const response = await uploadFormWithProgress<EvidenceUploadPayload>(
        "/evidence/upload",
        form,
        (percent) => {
          setUploadProgress(percent);
          setActiveUpload((current) => current ? { ...current, state: "uploading", progress: percent, bytesUploaded: Math.round(selectedFile.size * percent / 100), step: "uploading" } : current);
        },
        () => {
          setUploadStage("processing");
          setActiveUpload((current) => current ? { ...current, state: "finalizing", progress: 100, bytesUploaded: selectedFile.size, step: "validating_and_encrypting" } : current);
        },
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
          setActiveUpload((current) => current ? { ...current, routeRef: payload.routeRef ?? current.routeRef, jobId: payload.jobId, state: "queued", progress: 5, step: "queued", steps: payload.job?.steps ?? [] } : current);
          window.localStorage.setItem(ACTIVE_UPLOAD_JOB_KEY, JSON.stringify({ jobId: payload.jobId, caseId: payload.caseId }));
          void followUploadJob(payload.jobId, payload.caseId);
        }
        return;
      }
      await reloadAnalysis(payload.caseId ?? null);
      setUploadStage("complete");
      setActiveUpload((current) => current ? { ...current, routeRef: payload.routeRef ?? current.routeRef, jobId: payload.jobId, state: "completed", progress: 100, step: "completed", steps: payload.job?.steps ?? [] } : current);
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
      setActiveUpload((current) => current ? { ...current, state: "failed", step: "failed", error: error instanceof Error ? error.message : "Evidence analysis failed" } : current);
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
        const job = await apiGet<{ status: string; progress?: number; step?: string; error?: string; steps?: { name: string; status: string }[] }>(`/jobs/${jobId}/status`).catch(() => null);
        if (job) {
          setUploadProgress(Math.max(0, Math.min(100, job.progress ?? 0)));
          setUploadResult((current) => ({ ...(current ?? {}), jobId, steps: job.steps }));
          setActiveUpload((current) => current && (!caseId || current.caseId === caseId) ? {
            ...current,
            jobId,
            state: job.status === "running" ? "running" : job.status === "completed" ? "completed" : job.status === "failed" ? "failed" : job.status === "canceled" ? "canceled" : "queued",
            progress: Math.max(0, Math.min(100, job.progress ?? 0)),
            step: job.step ?? job.status,
            steps: job.steps ?? [],
            error: job.error,
          } : current);
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
  }, [reloadAnalysis, setActiveUpload]);
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
          {uploadStage === "complete" && <Button className="mt-4" onClick={() => navigate(appViewRoute("overview"))}>Open case overview</Button>}
        </div>
      )}
      <EvidenceCard />
    </PageFrame>
  );
}
