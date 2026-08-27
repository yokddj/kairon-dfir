import { useEffect, useMemo, useRef, useState } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { useNavigate } from "react-router-dom";

import { api, type Evidence, type EvidenceIntent, type EvidencePlatform, type EvidenceUploadSessionCreateResponse, type EvidenceUploadSessionRead, type EvtxProfile, type IngestMode, type MemoryUploadStatus, type PreflightReport, type ResumableUploadSessionRead } from "../api/client";
import { useNotifications } from "../context/NotificationsContext";
import { MemoryEvidencePreparationCard } from "./memory/MemoryEvidencePreparationCard";
import { MemoryInitialAnalysisAction } from "./memory/MemoryInitialAnalysisAction";
import { DEFAULT_CHUNK_SIZE, runResumableUpload } from "../features/memory/runResumableUpload";
import { memoryEvidenceRoute } from "../lib/canonicalRoutes";
import { hashBlob } from "../lib/sha256";

type IntakeType = "disk_image" | "memory_dump" | "artifact_collection" | "folder" | "server_path";
type WizardStep = 0 | 1 | 2 | 3 | 4 | 5 | 6;
type ProcessingMode = "recommended" | "custom" | "skip";
type AcquisitionSource = "files" | "server_path";
type HostChoice = "auto" | "__create__" | "__unassigned__" | string;
type InspectionState = "idle" | "uploading" | "finalizing_upload" | "preflight_running" | "complete" | "failed";
type ForcedRoute = "disk_image" | "memory_dump" | "collection" | "archive" | "unknown";
type BatchPreflightItem = { file: File; session: EvidenceUploadSessionRead; preflight: PreflightReport };
type BatchPreflightResponse = { batch: true; items: BatchPreflightItem[]; health: EvidenceUploadSessionCreateResponse["health"] };

const CREATE_HOST_CHOICE = "__create__";
const UNASSIGNED_HOST_CHOICE = "__unassigned__";
const TERMINAL_UPLOAD_STATUSES = new Set(["cancelled", "completed", "completed_with_errors", "completed_with_warnings", "expired", "finished", "indexed", "processing", "promoted"]);
const ACTIONABLE_UPLOAD_STATUSES = new Set(["created", "interrupted", "paused", "preflight_running", "staged", "uploading"]);

type Props = {
  open: boolean;
  caseId: string;
  resumeSessionId?: string;
  resumeCandidate?: ResumableUploadSessionRead | null;
  expectedKind?: ForcedRoute | null;
  onClose: () => void;
};

const OVERRIDE_OPTIONS: Array<{ value: ForcedRoute; label: string }> = [
  { value: "disk_image", label: "Disk" },
  { value: "memory_dump", label: "Memory" },
  { value: "collection", label: "Collection" },
  { value: "archive", label: "Archive" },
  { value: "unknown", label: "Unknown" },
];

// Mirrors the server-side gate exactly (app.services.memory.upload_sessions
// _allowed_archive_extension) -- kept in sync deliberately rather than
// derived from the API response, since this only decides which upload
// call to make, not authoritative eligibility (the server re-validates
// unconditionally at session creation).
const SUPPORTED_ARCHIVE_SUFFIX_GROUPS: string[][] = [[".zip"], [".7z"], [".tar", ".gz"], [".tar"], [".gz"], [".xz"]];

function isSupportedArchiveFilename(filename: string): boolean {
  const parts = filename.toLowerCase().split(".");
  if (parts.length < 2) return false;
  const suffixes = parts.slice(1).map((part) => `.${part}`);
  return SUPPORTED_ARCHIVE_SUFFIX_GROUPS.some((group) => suffixes.length >= group.length && group.every((suffix, index) => suffixes[suffixes.length - group.length + index] === suffix));
}

function bytes(value: number | null | undefined): string {
  if (value === null || value === undefined) return "unknown";
  let num = value;
  for (const unit of ["B", "KB", "MB", "GB", "TB"]) {
    if (num < 1024 || unit === "TB") return unit === "B" ? `${Math.round(num)} B` : `${num.toFixed(1)} ${unit}`;
    num /= 1024;
  }
  return `${num.toFixed(1)} TB`;
}

function durationBucketLabel(bucket: string | null): string | null {
  switch (bucket) {
    case "fast":
      return "Fast (under 2 minutes)";
    case "medium":
      return "Medium (10–20 minutes)";
    case "long":
      return "Long (1–2 hours)";
    case "very_long":
      return "Very long (several hours)";
    default:
      return null;
  }
}

function normalizePreflightReport(report: PreflightReport): PreflightReport {
  const maybeReport = report as PreflightReport & { evidence_options?: PreflightReport["evidence_options"] };
  return {
    ...report,
    evidence_options: maybeReport.evidence_options ?? [],
    classification: { ...report.classification, volume_diagnostics: report.classification.volume_diagnostics ?? [] },
  };
}

function normalizeHostLabel(value: string | null | undefined): string {
  return String(value ?? "").trim().replace(/\.+$/, "").toLowerCase();
}

function inspectionStateLabel(state: InspectionState, options: { isServerPath: boolean }): string {
  switch (state) {
    case "uploading":
      return "Analysing evidence...";
    case "finalizing_upload":
      return "Analysing evidence...";
    case "preflight_running":
      return options.isServerPath ? "Analysing server path..." : "Analysing evidence...";
    case "complete":
      return "Inspection complete";
    case "failed":
      return "Inspection failed";
    default:
      return "Ready for inspection";
  }
}

// Maps the backend's current_stage checkpoints (see
// evidence_upload_session._report_stage / evidence_preflight.run_preflight's
// on_stage callback) to analyst-facing labels. Falls back to the old
// generic label when a session predates this field or hasn't reported a
// stage yet -- never invents a stage the server didn't report.
function finalizeStageLabel(stage: string): string {
  switch (stage) {
    case "verifying_integrity":
      return "Verifying evidence integrity";
    case "classifying":
      return "Classifying evidence";
    case "inspecting_evidence":
      return "Inspecting evidence";
    case "preparing_evidence":
      return "Preparing evidence";
    case "preflight_complete":
      return "Ready for ingestion";
    case "preflight_failed":
      // Should not normally render: once the operation/session is failed,
      // the wizard shows the dedicated error branch instead of this stage
      // list (see inspectionState === "failed" below). Kept honest rather
      // than falling through to the generic label, in case a future caller
      // ever renders finalizeStageHistory outside that branch.
      return "Finalize failed";
    default:
      return "Finalizing upload on the server";
  }
}

function inspectionErrorMessage(error: unknown): string {
  if (error instanceof Error) return error.message;
  return "Kairon could not inspect this evidence.";
}

function evidenceKindLabel(category: string | null | undefined): string {
  switch (category) {
    case "disk_image":
      return "Disk";
    case "memory_dump":
      return "Memory";
    case "auxiliary":
      return "Auxiliary";
    case "collection":
      return "Collection";
    case "archive":
      return "Archive";
    case "mixed":
      return "Mixed";
    default:
      return "Unknown";
  }
}

function confidenceTierLabel(confidence: string | null | undefined, hasConflicts: boolean): { label: string; tone: "mint" | "amber" | "danger" } {
  if (hasConflicts) return { label: "Ambiguous", tone: "amber" };
  const normalized = String(confidence || "").toLowerCase();
  if (["high", "filesystem", "ewf_signature", "signature"].includes(normalized)) return { label: "Confirmed", tone: "mint" };
  if (["medium", "extension"].includes(normalized)) return { label: "Likely", tone: "amber" };
  if (["low", "unknown", "ambiguous"].includes(normalized)) return { label: normalized === "unknown" ? "Unknown" : "Ambiguous", tone: "danger" };
  return { label: confidence ? "Likely" : "Unknown", tone: confidence ? "amber" : "danger" };
}

function hasConflictingSignals(report: PreflightReport): boolean {
  const text = [report.classification.reason, ...report.classification.warnings.map((warning) => warning.message), ...report.diagnostics.map((diagnostic) => `${diagnostic.problem} ${diagnostic.reason}`)].join(" ").toLowerCase();
  return text.includes("conflict") || text.includes("ambiguous") || text.includes("only a raw") || text.includes("low confidence");
}

function needsManualOverride(report: PreflightReport): boolean {
  const confidence = String(report.classification.confidence || "").toLowerCase();
  return report.classification.category === "unknown" || confidence === "low" || confidence === "extension" || hasConflictingSignals(report);
}

function routeForCategory(category: string): ForcedRoute | null {
  if (category === "disk_image" || category === "memory_dump" || category === "archive" || category === "unknown") return category;
  if (category === "collection") return "collection";
  return null;
}

function isUnfinishedUploadForCurrentCase(candidate: ResumableUploadSessionRead, caseId: string): boolean {
  if (candidate.case_id !== caseId) return false;
  if (candidate.promoted_evidence_id) return false;
  const status = candidate.status.toLowerCase();
  if (status.startsWith("completed") || TERMINAL_UPLOAD_STATUSES.has(status)) return false;
  if (status === "failed") return candidate.resumable;
  if (ACTIONABLE_UPLOAD_STATUSES.has(status)) return true;
  return candidate.resumable && candidate.progress_percent !== 100;
}

async function sha256Hex(blob: Blob): Promise<string | undefined> {
  // Pure JS (see lib/sha256.ts), not SubtleCrypto: crypto.subtle.digest is
  // restricted to secure contexts (HTTPS/localhost) and is silently
  // undefined the moment this is served over plain HTTP -- which is the
  // actual deployed reality here. A hashing failure degrades to "no hash"
  // (best-effort) rather than aborting the caller, matching how the
  // server already treats a missing/absent client-declared chunk hash.
  try {
    return await hashBlob(blob);
  } catch {
    return undefined;
  }
}

function evidenceSessionUploadStatus(session: EvidenceUploadSessionRead, file: File, chunkSize: number): MemoryUploadStatus {
  const bytesReceived = Math.max(0, Math.min(file.size, session.bytes_received || 0));
  const totalChunks = Math.max(1, Math.ceil(file.size / chunkSize));
  const firstMissingChunk = bytesReceived >= file.size ? totalChunks : Math.floor(bytesReceived / chunkSize);
  const missingChunks = bytesReceived >= file.size ? [] : Array.from({ length: totalChunks - firstMissingChunk }, (_, index) => firstMissingChunk + index);
  const status: MemoryUploadStatus["status"] = session.status === "created" ? "created" : session.status === "expired" ? "expired" : session.status === "cancelled" ? "cancelled" : session.status === "failed" ? "failed" : "uploading";
  return {
    upload_id: session.id,
    case_id: session.case_id,
    evidence_id: null,
    status,
    bytes_received: bytesReceived,
    expected_bytes: file.size,
    chunk_size_bytes: chunkSize,
    total_chunks: totalChunks,
    received_chunks: Array.from({ length: firstMissingChunk }, (_, index) => index),
    missing_chunks: missingChunks,
    filename: session.original_filename,
    updated_at: session.updated_at,
    failure_code: null,
    failure_message: session.failure_message,
    message: session.failure_message || "Evidence upload in progress.",
    retryable: true,
  };
}

function hostMatchesName(host: { canonical_name?: string; display_name?: string; aliases?: string[]; all_names?: string[] }, name: string | null | undefined): boolean {
  const normalized = normalizeHostLabel(name);
  if (!normalized) return false;
  return [host.canonical_name, host.display_name, ...(host.aliases ?? []), ...(host.all_names ?? [])].some((candidate) => normalizeHostLabel(candidate) === normalized);
}

export default function EvidenceIngestionWizard({ open, caseId, resumeSessionId, resumeCandidate: resumeCandidateProp, expectedKind, onClose }: Props) {
  const navigate = useNavigate();
  const queryClient = useQueryClient();
  const { notify } = useNotifications();

  const [step, setStep] = useState<WizardStep>(4);
  const [intakeType, setIntakeType] = useState<IntakeType | null>("artifact_collection");
  const [platform, setPlatform] = useState<EvidencePlatform>("auto");
  const [hostChoice, setHostChoice] = useState<HostChoice>("auto");
  const [newHostName, setNewHostName] = useState("");
  const [hostSearch, setHostSearch] = useState("");
  const [files, setFiles] = useState<File[]>([]);
  const [folderUploadSelected, setFolderUploadSelected] = useState(false);
  const [acquisitionSource, setAcquisitionSource] = useState<AcquisitionSource>("files");
  const [serverPath, setServerPath] = useState("");
  const [session, setSession] = useState<EvidenceUploadSessionRead | null>(null);
  const [preflight, setPreflight] = useState<PreflightReport | null>(null);
  // Step 6 only: the just-registered memory evidence, shown in a
  // read-only Memory Preparation screen before the wizard hands off to
  // memoryEvidenceRoute (see handleContinueFromPreparation below).
  const [preparationEvidence, setPreparationEvidence] = useState<Evidence | null>(null);
  const [batchItems, setBatchItems] = useState<BatchPreflightItem[]>([]);
  const [manualOverrideAccepted, setManualOverrideAccepted] = useState(false);
  const [forcedRoutes, setForcedRoutes] = useState<Record<string, ForcedRoute>>({});
  const [wrongRouteAccepted, setWrongRouteAccepted] = useState<Record<string, boolean>>({});
  const [memoryAuthorizationAcknowledged, setMemoryAuthorizationAcknowledged] = useState(false);
  const [advancedOpen, setAdvancedOpen] = useState(false);
  const [selectionAdvancedOpen, setSelectionAdvancedOpen] = useState(false);
  const [processingMode, setProcessingMode] = useState<ProcessingMode>("recommended");
  // Default on: leaving the wizard after only the first profile left the image
  // mostly unexamined, with nothing saying a second manual step was needed.
  // Opting out stays available because the full battery is several minutes of
  // Volatility per image and some operators want to choose what runs.
  const [runFullMemoryAnalysis, setRunFullMemoryAnalysis] = useState(true);
  const [labels, setLabels] = useState("");
  const [notes, setNotes] = useState("");
  // Wizard Advanced Options (WIZARD_ADVANCED_OPTIONS_ENABLED). Defaults
  // match exactly what the backend already assumes when these are omitted
  // (evidence_intent="raw", ingest_mode=full_forensic) -- see
  // promote_upload_session/evidence_archive_workflow.py.
  const [evidenceIntent, setEvidenceIntent] = useState<EvidenceIntent>("raw");
  const [ingestMode, setIngestMode] = useState<IngestMode>("full_forensic");
  const [evtxProfile, setEvtxProfile] = useState<EvtxProfile>("full");
  const [hashProgress, setHashProgress] = useState<number | null>(null);
  const [clientSha256, setClientSha256] = useState<string | null>(null);
  const [inspectionState, setInspectionState] = useState<InspectionState>("idle");
  const [inspectionError, setInspectionError] = useState<string | null>(null);
  const [uploadProgress, setUploadProgress] = useState<number | null>(null);
  const [inspectionStartedAt, setInspectionStartedAt] = useState<number | null>(null);
  const [nowMs, setNowMs] = useState(Date.now());
  // Real, server-reported finalize checkpoints only (see current_stage on
  // EvidenceUploadSessionRead) -- appended in the order they're observed
  // while polling an in-flight finalize call, never guessed or timed
  // client-side. Stages the backend skips for a given evidence type (e.g.
  // memory dumps skip "inspecting_evidence") simply never appear here.
  const [finalizeStageHistory, setFinalizeStageHistory] = useState<string[]>([]);
  const promotedRef = useRef(false);
  const promotedEvidenceRef = useRef<Evidence | null>(null);
  // Holds the current finalize-stage poller's stop function (see
  // startFinalizeStagePolling) so it can be stopped from outside the
  // finalize call itself -- on unmount, or when the wizard is closed/reset
  // mid-finalize (cancellation). Success/failure of the finalize call
  // itself already stops it via its own try/finally.
  const stopFinalizePollingRef = useRef<(() => void) | null>(null);
  const explicitInspectRef = useRef(false);
  const [resumeTarget, setResumeTarget] = useState<ResumableUploadSessionRead | null>(null);
  const [resumeFile, setResumeFile] = useState<File | null>(null);
  const [resumeFileError, setResumeFileError] = useState<string | null>(null);
  const [resumeVerifying, setResumeVerifying] = useState(false);

  const requiresPathInput = acquisitionSource === "server_path";
  const requiresFolderInput = folderUploadSelected;
  const activePreflightReports = batchItems.length ? batchItems.map((item) => item.preflight) : preflight ? [preflight] : [];

  const caseHostsQuery = useQuery({ queryKey: ["case-hosts", caseId], queryFn: () => api.getCaseHosts(caseId), enabled: open && Boolean(caseId), staleTime: 15_000 });
  const caseHosts = caseHostsQuery.data?.hosts ?? [];

  // Same query keys MemoryEvidencePreparationCard / MemoryInitialAnalysisAction
  // already fetch (see their own module docstrings) -- reused here, not
  // refetched separately, only to decide whether the step 6 Continue
  // button should still be the primary action or a secondary escape
  // hatch. Never a second source of readiness/run truth.
  const stepSixPreparationQuery = useQuery({
    queryKey: ["memory-evidence-preparation", caseId, preparationEvidence?.id ?? ""],
    queryFn: () => api.getMemoryEvidencePreparation(caseId, preparationEvidence!.id),
    enabled: Boolean(caseId && preparationEvidence?.id),
    refetchOnWindowFocus: false,
  });
  const readyForInitialAnalysis = Boolean(
    stepSixPreparationQuery.data?.readiness === "ready" && stepSixPreparationQuery.data?.can_start_analysis,
  );

  const healthQuery = useQuery({
    queryKey: ["ingestion-readiness", caseId],
    queryFn: () => api.getIngestionReadiness(caseId),
    enabled: open && Boolean(caseId),
    staleTime: 10_000,
  });
  const unifiedMemoryDumpEnabled = Boolean(healthQuery.data?.unified_upload_evidence_memory_dump);
  const useUnifiedMemoryDump = intakeType === "memory_dump" && unifiedMemoryDumpEnabled;
  // disk_image reuses the exact same chunk-index transport, resume/discovery,
  // and Activity Center projection as memory_dump (see runUnifiedEvidenceTransfer
  // / uploadUnifiedEvidence below) -- only single-file images qualify, since
  // multi-segment EWF (.E01/.E02...) stays on the legacy multipart flow that
  // already supports it (see files.length === 1 gate at the call site).
  const unifiedDiskImageEnabled = Boolean(healthQuery.data?.unified_upload_evidence_disk_image);
  const useUnifiedDiskImage = intakeType === "disk_image" && unifiedDiskImageEnabled;
  // Single-file archives use the unified transport when selected directly;
  // structural preflight remains the source of truth for evidence kind.
  const unifiedArchiveEnabled = Boolean(healthQuery.data?.unified_upload_evidence_archive);
  const useUnifiedArchive = intakeType === "artifact_collection" && unifiedArchiveEnabled && files.length === 1 && isSupportedArchiveFilename(files[0].name);
  // Advanced Options (evidence_intent/ingest_mode/evtx_profile) are hidden
  // unless the analyst explicitly expands Advanced import options.
  const wizardAdvancedOptionsEnabled = Boolean(healthQuery.data?.wizard_advanced_options_enabled);
  const showAdvancedOptions = wizardAdvancedOptionsEnabled && selectionAdvancedOpen;
  const showEvtxProfileOption = showAdvancedOptions && files.length === 1 && (files[0].name.toLowerCase().endsWith(".evtx") || isSupportedArchiveFilename(files[0].name));
  // Discovery: lists sessions the analyst can still resume/cancel/open for
  // this case, reconciled server-side against their backing MemoryUpload.
  // Used both for the "Interrupted or active uploads" panel below and to
  // resolve a resumeSessionId (deep link / Activity Center) into a full
  // candidate without a second bespoke fetch.
  const resumableSessionsQuery = useQuery({
    queryKey: ["resumable-evidence-uploads", caseId],
    queryFn: () => api.listResumableEvidenceUploads(caseId),
    enabled: open && Boolean(caseId),
    staleTime: 5_000,
    refetchInterval: open ? 15_000 : false,
  });
  const resumableSessions = resumableSessionsQuery.data?.sessions ?? [];
  // Only show uploads that still need investigator action. Explicit
  // resumeSessionId deep links still resolve against the full server list below;
  // this filter scopes only the general Add Evidence discovery panel.
  const interruptedOrActiveSessions = resumableSessions.filter((candidate) => isUnfinishedUploadForCurrentCase(candidate, caseId));

  useEffect(() => {
    if (resumeCandidateProp) {
      setResumeTarget(resumeCandidateProp);
      return;
    }
    if (resumeSessionId) {
      const match = resumableSessions.find((candidate) => candidate.id === resumeSessionId);
      if (match) setResumeTarget(match);
    }
  }, [resumeCandidateProp, resumeSessionId, resumableSessions]);

  useEffect(() => {
    setClientSha256(null);
    setHashProgress(null);
  }, [files, requiresPathInput]);

  useEffect(() => {
    return () => {
      stopFinalizePollingRef.current?.();
    };
  }, []);

  function reset() {
    setStep(4);
    setIntakeType("artifact_collection");
    setPlatform("auto");
    setHostChoice("auto");
    setNewHostName("");
    setHostSearch("");
    setFiles([]);
    setFolderUploadSelected(false);
    setAcquisitionSource("files");
    setServerPath("");
    setSession(null);
    setPreflight(null);
    setBatchItems([]);
    setManualOverrideAccepted(false);
    setForcedRoutes({});
    setWrongRouteAccepted({});
    setMemoryAuthorizationAcknowledged(false);
    setAdvancedOpen(false);
    setSelectionAdvancedOpen(false);
    setProcessingMode("recommended");
    setLabels("");
    setNotes("");
    setHashProgress(null);
    setClientSha256(null);
    stopFinalizePollingRef.current?.();
    stopFinalizePollingRef.current = null;
    setFinalizeStageHistory([]);
    setInspectionState("idle");
    setInspectionError(null);
    setUploadProgress(null);
    setInspectionStartedAt(null);
    setNowMs(Date.now());
    promotedRef.current = false;
    promotedEvidenceRef.current = null;
    explicitInspectRef.current = false;
    setResumeTarget(null);
    setResumeFile(null);
    setResumeFileError(null);
    setResumeVerifying(false);
    setPreparationEvidence(null);
  }

  function handleClose() {
    reset();
    onClose();
  }

  function handleContinueFromPreparation() {
    const evidence = preparationEvidence;
    if (!evidence) return;
    handleClose();
    navigate(memoryEvidenceRoute(caseId, evidence.id));
  }

  function selectEvidenceFiles(selectedFiles: File[], options: { folderUpload?: boolean } = {}) {
    setAcquisitionSource("files");
    setFolderUploadSelected(Boolean(options.folderUpload));
    setFiles(selectedFiles);
    setSession(null);
    setPreflight(null);
    setBatchItems([]);
    setForcedRoutes({});
    setWrongRouteAccepted({});
    setManualOverrideAccepted(false);
    setInspectionState(selectedFiles.length ? "uploading" : "idle");
    setInspectionError(null);
    setUploadProgress(selectedFiles.length ? 0 : null);
  }

  // Finalize (POST .../evidence-uploads/{id}/finalize) is a single
  // synchronous call that can legitimately run for minutes on large disk
  // images/archives (hashing + preflight inspection scale with file size --
  // see the nginx 1800s timeout and the finalize instrumentation this was
  // diagnosed from). It is not made asynchronous and no new endpoint is
  // introduced here: this only polls the existing session GET concurrently
  // while that POST is still in flight, purely to surface the real
  // current_stage checkpoints the backend already commits along the way.
  // A transient poll failure never affects the outstanding finalize call --
  // it just means one fewer progress update.
  function startFinalizeStagePolling(targetCaseId: string, sessionId: string): () => void {
    let stopped = false;
    let timeoutId: number | undefined;
    const poll = async () => {
      if (stopped) return;
      try {
        const response = await api.getEvidenceUploadSession(targetCaseId, sessionId);
        // Re-check after the await: stopPolling() may have run while this
        // request was in flight (finalize resolved/rejected, or the wizard
        // closed/unmounted) -- a response landing after that point must
        // never be applied, or a stale stage could render as active right
        // after the operation has already failed or succeeded.
        if (stopped) return;
        const stage = response.session.current_stage;
        if (stage) {
          setFinalizeStageHistory((previous) => (previous[previous.length - 1] === stage ? previous : [...previous, stage]));
        }
      } catch {
        // best-effort only; the outstanding finalize POST is unaffected
      }
      if (!stopped) timeoutId = window.setTimeout(poll, 1500);
    };
    timeoutId = window.setTimeout(poll, 1500);
    return () => {
      stopped = true;
      if (timeoutId !== undefined) window.clearTimeout(timeoutId);
    };
  }

  async function uploadSingleFileResumable(file: File, onProgress: (progress: { loaded: number; total: number; lengthComputable: boolean }) => void) {
    if (!api.createResumableEvidenceUploadSession || !api.appendResumableEvidenceUpload || !api.finalizeResumableEvidenceUploadSession) {
      return api.createEvidenceUploadSession(caseId, { file }, { declaredPlatform: platform, onProgress });
    }
    const existing = session && ["created", "uploading", "interrupted"].includes(session.status) ? session : null;
    if (existing && (existing.original_filename !== file.name || existing.expected_size_bytes !== file.size)) {
      throw new Error(`Select the original file (${existing.original_filename}, ${bytes(existing.expected_size_bytes)}) to resume this upload.`);
    }
    const activeSession = existing ?? (await api.createResumableEvidenceUploadSession(caseId, {
      filename: file.name,
      expected_size_bytes: file.size,
      declared_platform: platform,
    })).session;
    setSession(activeSession);
    const chunkSize = DEFAULT_CHUNK_SIZE;
    const controller = new AbortController();
    let latestSession = activeSession;
    let finalizedResponse: EvidenceUploadSessionCreateResponse | null = null;
    const result = await runResumableUpload({
      uploadId: activeSession.id,
      file,
      chunkSize,
      getStatus: async () => {
        const response = await api.getEvidenceUploadSession(caseId, activeSession.id);
        latestSession = response.session;
        setSession(response.session);
        return evidenceSessionUploadStatus(response.session, file, chunkSize);
      },
      uploadChunk: async (_uploadId, chunkIndex, blob, signal, uploadProgress) => {
        const offset = chunkIndex * chunkSize;
        const response = await api.appendResumableEvidenceUpload(caseId, activeSession.id, blob, offset, {
          signal,
          onProgress: uploadProgress ? (progress) => uploadProgress({ loaded: progress.loaded, total: progress.total }) : undefined,
        });
        latestSession = response.session;
        setSession(response.session);
        return evidenceSessionUploadStatus(response.session, file, chunkSize);
      },
      finalize: async () => {
        setInspectionState("finalizing_upload");
        setFinalizeStageHistory([]);
        const stopPolling = startFinalizeStagePolling(caseId, activeSession.id);
        stopFinalizePollingRef.current = stopPolling;
        try {
          finalizedResponse = await api.finalizeResumableEvidenceUploadSession(caseId, activeSession.id);
        } finally {
          stopPolling();
          if (stopFinalizePollingRef.current === stopPolling) stopFinalizePollingRef.current = null;
        }
        latestSession = finalizedResponse.session;
        setSession(finalizedResponse.session);
        return evidenceSessionUploadStatus(finalizedResponse.session, file, chunkSize);
      },
      signal: controller.signal,
      onProgress: (progress) => onProgress({ loaded: progress.loaded, total: progress.total, lengthComputable: true }),
    });
    if (result.type === "completed") {
      return finalizedResponse ?? api.finalizeResumableEvidenceUploadSession(caseId, activeSession.id);
    }
    if (result.type === "terminal" && finalizedResponse) return finalizedResponse;
    if (result.type === "aborted") throw new Error("Upload aborted");
    if (result.type === "stalled") throw new Error("Upload paused because the server did not acknowledge the last chunk. Resume the upload to continue.");
    throw new Error(result.type === "failed" ? result.message : latestSession.failure_message || "Upload failed.");
  }

  // Feature-flagged per category (UNIFIED_UPLOAD_EVIDENCE_MEMORY_DUMP,
  // UNIFIED_UPLOAD_EVIDENCE_DISK_IMAGE): routes the actual byte transfer
  // through the same chunk-index protocol, concurrency, and finalize
  // lifecycle Memory Overview uses (see runResumableUpload and
  // app.services.evidence_unified_upload on the backend), instead of the
  // legacy sequential PUT .../bytes?offset=N endpoint. Host and
  // authorization are collected up front (step 3, before this runs) so
  // finalize can register the Evidence immediately once the transfer
  // completes -- there is no separate "Start Processing" step for this path.
  // Shared by both a fresh unified upload and a resumed one, and by every
  // unified category: the transfer itself, finalize, and post-finalize
  // evidence lookup are identical regardless of category, since
  // runResumableUpload() re-derives the missing-chunk set from the server's
  // authoritative status on every call -- a "resume" is just calling this
  // against a memory_upload_id that already has some chunks landed, nothing
  // else differs.
  async function runUnifiedEvidenceTransfer(
    sessionId: string,
    unified: { memory_upload_id: string; chunk_size_bytes: number; default_concurrency: number; max_concurrency: number },
    file: File,
    onProgress: (progress: { loaded: number; total: number; lengthComputable: boolean }) => void,
  ): Promise<{ evidence: Evidence }> {
    const { memory_upload_id, chunk_size_bytes, default_concurrency, max_concurrency } = unified;
    const controller = new AbortController();
    const result = await runResumableUpload({
      uploadId: memory_upload_id,
      file,
      chunkSize: chunk_size_bytes || DEFAULT_CHUNK_SIZE,
      getStatus: (uploadId) => api.getMemoryUploadStatus(caseId, uploadId),
      uploadChunk: async (uploadId, chunkIndex, blob, signal, uploadProgress) => {
        const chunkSha256 = await sha256Hex(blob);
        return api.uploadMemoryUploadChunk(caseId, uploadId, chunkIndex, blob, { chunkSha256, signal, onProgress: uploadProgress });
      },
      finalize: (uploadId) => {
        setInspectionState("finalizing_upload");
        return api.finalizeMemoryUpload(caseId, uploadId);
      },
      signal: controller.signal,
      onProgress: (progress) => onProgress({ loaded: progress.loaded, total: progress.total, lengthComputable: true }),
      concurrency: default_concurrency,
      maxConcurrency: max_concurrency,
    });
    if (result.type === "aborted") throw new Error("Upload aborted");
    if (result.type === "stalled") throw new Error("Upload paused because the server did not acknowledge the last chunk. Resume the upload to continue.");
    if (result.type === "failed") throw new Error(result.message);

    setInspectionState("preflight_running");
    const finalStatus = await api.getEvidenceUploadSession(caseId, sessionId);
    setSession(finalStatus.session);
    if (!finalStatus.session.promoted_evidence_id) {
      throw new Error(finalStatus.session.failure_message || "Upload finished but Kairon did not register the memory evidence. Check Activity Center for details.");
    }
    const evidence = await api.getEvidence(finalStatus.session.promoted_evidence_id);
    promotedRef.current = true;
    promotedEvidenceRef.current = evidence;
    setInspectionState("complete");
    return { evidence };
  }

  async function uploadUnifiedEvidence(file: File, onProgress: (progress: { loaded: number; total: number; lengthComputable: boolean }) => void): Promise<{ evidence: Evidence }> {
    const hostAssignment = await resolveHostAssignment();
    const declaredPlatform = platform === "auto" ? undefined : platform;
    // "archive" has no dedicated intake card (see useUnifiedArchive) -- the
    // Wizard's own intakeType stays "artifact_collection", but the server's
    // UNIFIED_UPLOAD_KINDS registry key (and workflow) is "archive".
    const unifiedKind = useUnifiedArchive ? "archive" : intakeType ?? undefined;
    const created = await api.createResumableEvidenceUploadSession(caseId, {
      filename: file.name,
      expected_size_bytes: file.size,
      declared_platform: declaredPlatform,
      client_sha256: clientSha256 ?? undefined,
      intake_category: unifiedKind,
      host_id: hostAssignment.host_id,
      provided_host: hostAssignment.provided_host,
      memory_authorization_acknowledged: memoryAuthorizationAcknowledged,
      notes: notes.trim() || undefined,
      // Only consulted by the archive workflow handler (the only unified
      // kind whose registration already calls upload_evidence()); harmless
      // no-op metadata for memory_dump/disk_image. Defaults match today's
      // behavior exactly when Advanced Options isn't shown for this kind.
      evidence_intent: evidenceIntent,
      ingest_mode: ingestMode,
      evtx_profile: evtxProfile,
    });
    if (!created.unified) {
      throw new Error("Kairon could not start a unified upload session for this file.");
    }
    setSession(created.session);
    setInspectionState("uploading");
    return runUnifiedEvidenceTransfer(created.session.id, created.unified, file, onProgress);
  }

  async function verifyResumeFile(candidate: ResumableUploadSessionRead, file: File): Promise<string | null> {
    if (candidate.expected_size_bytes !== null && file.size !== candidate.expected_size_bytes) {
      return `Selected file is ${bytes(file.size)}, but this upload expected ${bytes(candidate.expected_size_bytes)}. Select the original file (${candidate.original_filename}).`;
    }
    const unified = candidate.unified;
    if (unified && unified.verification_chunk_index !== null && unified.verification_chunk_sha256 && unified.verification_chunk_size) {
      const start = unified.verification_chunk_index * unified.chunk_size_bytes;
      const slice = file.slice(start, start + unified.verification_chunk_size);
      const digest = await sha256Hex(slice);
      // sha256Hex returns undefined when crypto.subtle is unavailable, not
      // just on a genuine hashing failure -- notably, browsers only expose
      // SubtleCrypto in a secure context (HTTPS or localhost), so it is
      // routinely undefined when Kairon is served over plain HTTP. Treat
      // that as "verification skipped", not "mismatch": the size check
      // above still applies, and server-side per-chunk hash verification
      // (on the actual chunk re-upload) remains the mandatory backstop
      // that catches a genuinely wrong file.
      if (digest !== undefined && digest !== unified.verification_chunk_sha256) {
        return "This file's content does not match the bytes Kairon already received for this upload. Select the original file, not a different or re-exported copy.";
      }
    }
    return null;
  }

  const createSessionMutation = useMutation({
    mutationFn: async () => {
      setInspectionError(null);
      setInspectionStartedAt(Date.now());
      setNowMs(Date.now());

      if (resumeTarget && resumeFile) {
        const target = resumeTarget;
        const file = resumeFile;
        setUploadProgress(target.expected_size_bytes ? Math.min(1, target.bytes_received / target.expected_size_bytes) : 0);
        const onResumeProgress = (progress: { loaded: number; total: number; lengthComputable: boolean }) => {
          if (!progress.lengthComputable || progress.total <= 0) return;
          const fraction = Math.min(1, progress.loaded / progress.total);
          setUploadProgress(fraction);
          if (fraction >= 1) setInspectionState("finalizing_upload");
        };
        setInspectionState("uploading");
        if (target.backend === "unified" && target.unified) {
          return runUnifiedEvidenceTransfer(target.id, target.unified, file, onResumeProgress);
        }
        const fetched = await api.getEvidenceUploadSession(caseId, target.id);
        if (fetched.session.original_filename !== file.name || fetched.session.expected_size_bytes !== file.size) {
          throw new Error(`Select the original file (${fetched.session.original_filename}, ${bytes(fetched.session.expected_size_bytes)}) to resume this upload.`);
        }
        setSession(fetched.session);
        return uploadSingleFileResumable(file, onResumeProgress);
      }

      setUploadProgress(requiresPathInput ? null : 0);
      if (intakeType === "server_path") {
        setInspectionState("preflight_running");
        return api.createEvidenceUploadSession(caseId, { serverPath: serverPath.trim() }, { declaredPlatform: platform });
      }
      setInspectionState("uploading");
      const onProgress = (progress: { loaded: number; total: number; lengthComputable: boolean }) => {
        if (!progress.lengthComputable || progress.total <= 0) return;
        const fraction = Math.min(1, progress.loaded / progress.total);
        setUploadProgress(fraction);
        if (fraction >= 1) setInspectionState("finalizing_upload");
      };
      if ((useUnifiedMemoryDump || useUnifiedDiskImage || useUnifiedArchive) && !requiresFolderInput && files.length === 1) {
        return uploadUnifiedEvidence(files[0], onProgress);
      }
      if (!requiresFolderInput && files.length > 1) {
        const items: BatchPreflightItem[] = [];
        for (let index = 0; index < files.length; index += 1) {
          const file = files[index];
          const response = await api.createEvidenceUploadSession(caseId, { file }, {
            declaredPlatform: platform,
            onProgress: (progress) => {
              if (!progress.lengthComputable || progress.total <= 0) return;
              const fileFraction = Math.min(1, progress.loaded / progress.total);
              setUploadProgress(Math.min(1, (index + fileFraction) / files.length));
            },
          });
          items.push({ file, session: response.session, preflight: normalizePreflightReport(response.preflight) });
        }
        return { batch: true, items, health: healthQuery.data ?? null } satisfies BatchPreflightResponse;
      }
      if (!requiresFolderInput && files.length === 1) {
        return uploadSingleFileResumable(files[0], onProgress);
      }
      if (requiresFolderInput || files.length > 1) {
        return api.createEvidenceUploadSession(caseId, { files, folderUpload: requiresFolderInput }, { declaredPlatform: platform, onProgress });
      }
      return api.createEvidenceUploadSession(caseId, { file: files[0] }, { declaredPlatform: platform, clientSha256: clientSha256 ?? undefined, onProgress });
    },
    onSuccess: async (response) => {
      if ("batch" in response) {
        setBatchItems(response.items);
        setSession(response.items[0]?.session ?? null);
        setPreflight(response.items[0]?.preflight ?? null);
        setUploadProgress(1);
        setInspectionState("complete");
        setInspectionError(null);
        setStep(explicitInspectRef.current ? 5 : 4);
        explicitInspectRef.current = false;
        return;
      }
      if ("evidence" in response) {
        const { evidence } = response;
        setUploadProgress(1);
        setInspectionState("complete");
        setInspectionError(null);
        void queryClient.invalidateQueries({ queryKey: ["case-processing", caseId] });
        void queryClient.invalidateQueries({ queryKey: ["evidences", caseId] });
        void queryClient.invalidateQueries({ queryKey: ["resumable-evidence-uploads", caseId] });
        if (evidence.evidence_type === "memory_dump") {
          notify({ title: "Memory evidence registered", description: `${evidence.original_filename} was uploaded and registered.`, tone: "success" });
          setPreparationEvidence(evidence);
          setStep(6);
          return;
        }
        // Non-memory unified categories (currently disk_image) still need
        // the same processing-pipeline kickoff the legacy staged flow
        // triggers from "Start Processing" (see the memory_dump-only
        // skip in startMutation below) -- there is no separate
        // confirmation step here to click that button from, so fire it
        // with the same "recommended" default automatically. Registration
        // already succeeded at this point regardless of whether this
        // best-effort kickoff does.
        notify({ title: "Evidence registered", description: `${evidence.original_filename} was uploaded and registered.`, tone: "success" });
        try {
          const plan = await api.runEvidenceIndexingPlan(evidence.id, { profile: "recommended" });
          if (plan.queued_jobs.length > 0) {
            notify({ title: "Indexing started", description: `${plan.queued_jobs.length} indexing step(s) were queued for ${evidence.original_filename}.`, tone: "success" });
          }
        } catch {
          notify({ title: "Automatic indexing did not start", description: `${evidence.original_filename} was registered, but indexing could not be started automatically. Start it from the evidence page.`, tone: "error" });
        }
        handleClose();
        navigate(`/evidences/${evidence.id}`);
        return;
      }
      const preflightReport = normalizePreflightReport(response.preflight);
      setBatchItems([]);
      setSession(response.session);
      setPreflight(preflightReport);
      setUploadProgress(response.session.is_server_path ? null : 1);
      setInspectionState("complete");
      setInspectionError(null);
      setStep(explicitInspectRef.current ? 5 : 4);
      explicitInspectRef.current = false;
    },
    onError: (error) => {
      const message = inspectionErrorMessage(error);
      setInspectionState("failed");
      setInspectionError(message);
      notify({ title: "Preflight inspection failed", description: message, tone: "error" });
    },
  });

  useEffect(() => {
    if (!createSessionMutation.isPending) return;
    const interval = window.setInterval(() => setNowMs(Date.now()), 1000);
    return () => window.clearInterval(interval);
  }, [createSessionMutation.isPending]);

  useEffect(() => {
    if (!open || step !== 4 || resumeTarget || requiresPathInput) return;
    if (!files.length || session || preflight || batchItems.length) return;
    if (inspectionState !== "uploading" || createSessionMutation.isPending) return;
    const timer = window.setTimeout(() => {
      setInspectionStartedAt(Date.now());
      explicitInspectRef.current = false;
      createSessionMutation.mutate();
    }, 1000);
    return () => window.clearTimeout(timer);
  }, [batchItems.length, createSessionMutation, files.length, inspectionState, open, preflight, requiresPathInput, resumeTarget, session, step]);

  // Reacts to a resolved resume target (from the panel, Activity Center's
  // Resume action via resumeSessionId, or a resumeCandidate prop) -- the
  // single entry point for "browser closed/reloaded mid-upload" discovery,
  // replacing the old resumeSessionId-only, unified-unaware restore path.
  useEffect(() => {
    const target = resumeTarget;
    if (!target) return;
    setResumeFile(null);
    setResumeFileError(null);
    setIntakeType((target.category as IntakeType | null) ?? "artifact_collection");
    setUploadProgress(target.expected_size_bytes ? Math.min(1, target.bytes_received / target.expected_size_bytes) : null);
    setInspectionStartedAt(target.created_at ? Date.parse(target.created_at) : null);

    if (target.status === "promoted" && target.promoted_evidence_id) {
      handleClose();
      navigate(target.category === "memory_dump" ? memoryEvidenceRoute(caseId, target.promoted_evidence_id) : `/evidences/${target.promoted_evidence_id}`);
      return;
    }
    if (target.status === "staged") {
      api.getEvidenceUploadSession(caseId, target.id).then((response) => {
        setSession(response.session);
        setPlatform((response.session.declared_platform as EvidencePlatform | null) ?? "auto");
      });
      setStep(5);
      setInspectionState("preflight_running");
      api.rerunEvidenceUploadPreflight(caseId, target.id, null)
        .then((report) => {
          setPreflight(normalizePreflightReport(report));
          setInspectionState("complete");
          setInspectionError(null);
        })
        .catch((error) => {
          setInspectionState("failed");
          setInspectionError(inspectionErrorMessage(error));
        });
      return;
    }
    // created / uploading / interrupted / retryable failed: needs the
    // analyst to reselect the original file before any bytes move again --
    // browsers cannot silently reopen a local File after a reload.
    setStep(4);
    setInspectionState("idle");
    setInspectionError(null);
  }, [caseId, resumeTarget]);

  // Friendly, sequential 1-based display numbers for real partitions only
  // (pytsk3's own partition_index has gaps -- unallocated-space/partition-
  // table entries are counted too -- and a logical volume's synthetic
  // partition_index is not a partition at all; see
  // app.services.evidence_preflight's PreflightVolumeDiagnostic.kind).
  const partitionDisplayNumbers = useMemo(() => {
    const numbers = new Map<number, number>();
    let next = 1;
    for (const volume of preflight?.classification.volume_diagnostics ?? []) {
      if (volume.kind !== "logical_volume") {
        numbers.set(volume.volume_id, next);
        next += 1;
      }
    }
    return numbers;
  }, [preflight?.classification.volume_diagnostics]);

  const detectedHostname = preflight?.classification.hostname?.trim() || "";
  const detectedHostMatches = useMemo(() => caseHosts.filter((host) => hostMatchesName(host, detectedHostname)), [caseHosts, detectedHostname]);
  const filteredCaseHosts = useMemo(() => {
    const query = normalizeHostLabel(hostSearch);
    if (!query) return caseHosts;
    return caseHosts.filter((host) => [host.display_name, host.canonical_name, ...(host.aliases ?? []), ...(host.all_names ?? [])].some((candidate) => normalizeHostLabel(candidate).includes(query)));
  }, [caseHosts, hostSearch]);

  useEffect(() => {
    if (!preflight || intakeType === "memory_dump") return;
    if (detectedHostname) {
      setHostChoice("auto");
      return;
    }
    setHostChoice((current) => current === "auto" ? CREATE_HOST_CHOICE : current);
  }, [detectedHostname, intakeType, preflight]);

  async function resolveHostAssignment(report: PreflightReport | undefined = preflight ?? undefined): Promise<{ host_id?: string; provided_host?: string }> {
    const reportHostname = report?.classification.hostname?.trim() || "";
    const reportHostMatches = caseHosts.filter((host) => hostMatchesName(host, reportHostname));
    if (hostChoice === UNASSIGNED_HOST_CHOICE) return {};
    if (hostChoice === "auto") {
      if (!reportHostname) return {};
      if (reportHostMatches.length === 1) return { host_id: reportHostMatches[0].id };
      if (reportHostMatches.length > 1) throw new Error("Multiple hosts match the detected hostname. Select the correct host before indexing.");
      return { provided_host: reportHostname };
    }
    if (hostChoice === CREATE_HOST_CHOICE) {
      const name = newHostName.trim();
      if (!name) return {};
      const result = await api.createCaseHost(caseId, { host_name: name, reason: "Created during evidence ingestion wizard" });
      await queryClient.invalidateQueries({ queryKey: ["case-hosts", caseId] });
      return { host_id: result.host.id };
    }
    return { host_id: hostChoice };
  }

  const cancelResumableMutation = useMutation({
    mutationFn: (sessionId: string) => api.cancelEvidenceUploadSession(caseId, sessionId),
    onSuccess: (_result, sessionId) => {
      void queryClient.invalidateQueries({ queryKey: ["resumable-evidence-uploads", caseId] });
      if (resumeTarget?.id === sessionId) {
        setResumeTarget(null);
        setResumeFile(null);
        setResumeFileError(null);
      }
      notify({ title: "Upload cancelled", description: "The interrupted upload was cancelled and its staged bytes were cleaned up.", tone: "success" });
    },
    onError: (error) => {
      notify({ title: "Could not cancel upload", description: error instanceof Error ? error.message : "The upload could not be cancelled.", tone: "error" });
    },
  });

  const startMutation = useMutation({
    mutationFn: async (): Promise<{ evidence: Evidence; queuedJobs: number | null }> => {
      if (batchItems.length) {
        let lastEvidence: Evidence | null = null;
        let queuedTotal = 0;
        for (const item of batchItems) {
          if (item.preflight.classification.category === "auxiliary") continue;
          const hostAssignment = await resolveHostAssignment(item.preflight);
          const declaredPlatform = platform === "auto" ? undefined : platform;
          const evidence = await api.promoteEvidenceUploadSession(caseId, item.session.id, {
            provided_platform: declaredPlatform,
            host_id: hostAssignment.host_id,
            provided_host: hostAssignment.provided_host,
            memory_authorization_acknowledged: item.preflight.classification.category === "memory_dump" ? memoryAuthorizationAcknowledged : undefined,
            labels: labels.split(",").map((label) => label.trim()).filter(Boolean),
            notes: notes.trim() || undefined,
            forced_evidence_kind: forcedRoutes[item.preflight.token] ?? undefined,
            evidence_intent: evidenceIntent,
            ingest_mode: ingestMode,
            evtx_profile: evtxProfile,
          });
          lastEvidence = evidence;
          if (evidence.evidence_type !== "memory_dump" && processingMode !== "skip") {
            const result = await api.runEvidenceIndexingPlan(evidence.id, { profile: processingMode === "custom" ? "fast" : "recommended" });
            queuedTotal += result.queued_jobs.length;
          }
        }
        if (!lastEvidence) throw new Error("No ingestable evidence was selected. Auxiliary files are support files and are not processed as evidence.");
        return { evidence: lastEvidence, queuedJobs: processingMode === "skip" ? null : queuedTotal };
      }
      if (!session) throw new Error("No upload session is active");
      let evidence = promotedEvidenceRef.current;
      if (!evidence) {
        const hostAssignment = await resolveHostAssignment(preflight ?? undefined);
        const declaredPlatform = platform === "auto" ? undefined : platform;
        evidence = await api.promoteEvidenceUploadSession(caseId, session.id, {
          provided_platform: declaredPlatform,
          host_id: hostAssignment.host_id,
          provided_host: hostAssignment.provided_host,
          memory_authorization_acknowledged: preflight?.classification.category === "memory_dump" ? memoryAuthorizationAcknowledged : undefined,
          labels: labels.split(",").map((label) => label.trim()).filter(Boolean),
          notes: notes.trim() || undefined,
          forced_evidence_kind: preflight ? forcedRoutes[preflight.token] ?? undefined : undefined,
          // Only meaningful for promote_upload_session's bare-else
          // (single-file legacy-compat) branch -- harmlessly ignored by
          // folder/server_path/disk_image/memory_dump. Defaults match
          // today's behavior exactly when Advanced Options isn't shown.
          evidence_intent: evidenceIntent,
          ingest_mode: ingestMode,
          evtx_profile: evtxProfile,
        });
        promotedRef.current = true;
        promotedEvidenceRef.current = evidence;
      }

      if (evidence.evidence_type === "memory_dump" || processingMode === "skip") {
        return { evidence, queuedJobs: null };
      }

      const result = await api.runEvidenceIndexingPlan(evidence.id, {
        profile: processingMode === "custom" ? "fast" : "recommended",
      });
      return { evidence, queuedJobs: result.queued_jobs.length };
    },
    onSuccess: ({ evidence, queuedJobs }) => {
      promotedRef.current = true;
      notify({
        title: queuedJobs === null ? "Evidence saved" : "Indexing started",
        description: queuedJobs === null
          ? `${evidence.original_filename} was added to the case.`
          : queuedJobs > 0
            ? `${queuedJobs} indexing step(s) were queued for ${evidence.original_filename}.`
            : `${evidence.original_filename} is already indexed for the selected profile.`,
        tone: "success",
      });
      void queryClient.invalidateQueries({ queryKey: ["case-processing", caseId] });
      void queryClient.invalidateQueries({ queryKey: ["evidences", caseId] });
      void queryClient.invalidateQueries({ queryKey: ["evidence-indexing-plan", evidence.id] });
      if (evidence.evidence_type === "memory_dump") {
        setPreparationEvidence(evidence);
        setStep(6);
        return;
      }
      handleClose();
      navigate(`/cases/${caseId}?tab=processing&evidence_id=${evidence.id}`);
    },
    onError: (error) => {
      notify({ title: "Could not start processing", description: error instanceof Error ? error.message : "The evidence could not be queued for processing.", tone: "error" });
    },
  });

  const blocked = activePreflightReports.some((report) => report.status === "blocked" && !manualOverrideAccepted && !needsManualOverride(report));
  const hasMemoryEvidence = activePreflightReports.some((report) => report.classification.category === "memory_dump") || intakeType === "memory_dump";

  const canAdvanceStep4 = useMemo(() => {
    if (requiresPathInput) return serverPath.trim().length > 0;
    return files.length > 0;
  }, [requiresPathInput, serverPath, files]);

  const hashPending = files.length === 1 && !requiresPathInput && hashProgress !== null && hashProgress < 1;
  const inspectionElapsedSeconds = inspectionStartedAt ? Math.max(0, Math.floor((nowMs - inspectionStartedAt) / 1000)) : 0;
  const inspectionLabel = inspectionStateLabel(inspectionState, { isServerPath: requiresPathInput });

  const hostAssignmentRequired = hasMemoryEvidence || processingMode !== "skip";
  // Whether hostAssignmentPanel renders visibly (outside Advanced) or stays
  // tucked away, for any evidence type. Deliberately independent of
  // hostChoice/processingMode -- both are controls the analyst can change
  // *while the panel itself is open*, and if either flipped this value, the
  // panel would move between two different parents mid-interaction. React
  // would then unmount/remount it, discarding focus and any in-progress
  // selection. Based only on facts already known from classification/case
  // data before the analyst touches anything: memory always shows it;
  // anything else shows it only when detection didn't already resolve a
  // single, unambiguous host.
  const hostRequirementVisible = hasMemoryEvidence || !detectedHostname || detectedHostMatches.length > 1;
  const hostAssignmentBlockingReason = useMemo(() => {
    if (!hostAssignmentRequired) return null;
    if (hostChoice === UNASSIGNED_HOST_CHOICE) return "Choose an existing host or create a new host before indexing.";
    if (hostChoice === CREATE_HOST_CHOICE) return newHostName.trim() ? null : "Enter a hostname before indexing.";
    if (hostChoice === "auto") {
      if (!detectedHostname) return "No reliable hostname was detected. Choose an existing host or create a new one before indexing.";
      if (detectedHostMatches.length > 1) return "Multiple hosts match the detected hostname. Select the correct host before indexing.";
      return null;
    }
    return hostChoice ? null : "Choose a host before indexing.";
  }, [detectedHostMatches.length, detectedHostname, hostAssignmentRequired, hostChoice, newHostName]);
  const overrideBlocking = activePreflightReports.some((report) => needsManualOverride(report) && !forcedRoutes[report.token]);
  const wrongRouteBlocking = activePreflightReports.some((report) => {
    const forced = forcedRoutes[report.token];
    const detected = routeForCategory(report.classification.category);
    return forced && detected && forced !== detected && [forced, detected].includes("disk_image") && [forced, detected].includes("memory_dump") && !wrongRouteAccepted[report.token];
  });
  const canStartProcessing = !startMutation.isPending && !(hasMemoryEvidence && !memoryAuthorizationAcknowledged) && hostAssignmentBlockingReason === null && !overrideBlocking && !wrongRouteBlocking;
  const selectedHostName = hostChoice !== "auto" && hostChoice !== CREATE_HOST_CHOICE && hostChoice !== UNASSIGNED_HOST_CHOICE
    ? caseHosts.find((h) => h.id === hostChoice)?.display_name || "Selected host"
    : null;
  const assignedHostLabel = hostChoice === CREATE_HOST_CHOICE
    ? newHostName.trim() || null
    : hostChoice === "auto"
      ? detectedHostMatches.length === 1 ? detectedHostMatches[0].display_name : detectedHostname
      : selectedHostName;
  // Single source of truth for "does this evidence need a host, right now,
  // that it doesn't have" -- drives the "Host required" banner, the status
  // pill, the Ready-to-process gate and the disabled-button explanation,
  // for every evidence type (not just memory). Resolves live as soon as a
  // valid host is chosen. hostAssignmentPanel's own placement (visible vs.
  // tucked in Advanced) intentionally uses the more stable
  // hostAssignmentRequired instead -- it must not flip mid-interaction
  // (e.g. the instant a host is picked), or React unmounts/remounts the
  // panel out from under the very selection the analyst is making.
  const hostRequirementBlocking = hostAssignmentBlockingReason !== null;
  const readyToProcess = !preflight?.diagnostics.length && !hostRequirementBlocking;

  const hostAssignmentPanel = (
    <div className="rounded-2xl border border-line bg-abyss/60 p-3" data-testid="host-assignment-panel">
      <p className="text-xs uppercase tracking-[0.16em] text-muted">Assign to host</p>
      <div className="mt-3 grid gap-3">
        {detectedHostname ? (
          <label className={`rounded-2xl border p-3 text-sm ${hostChoice === "auto" ? "border-accent bg-accent/10 text-ink" : "border-line bg-abyss/70 text-muted"}`}>
            <input type="radio" name="final-host-choice" className="mr-2" checked={hostChoice === "auto"} onChange={() => setHostChoice("auto")} disabled={detectedHostMatches.length > 1} />
            {detectedHostMatches.length === 1 ? `Auto assign to ${detectedHostMatches[0].display_name}` : `Create host from detected hostname (${detectedHostname})`}
          </label>
        ) : null}
        <label className={`rounded-2xl border p-3 text-sm ${hostChoice !== "auto" && hostChoice !== CREATE_HOST_CHOICE && hostChoice !== UNASSIGNED_HOST_CHOICE ? "border-accent bg-accent/10 text-ink" : "border-line bg-abyss/70 text-muted"}`}>
          <input type="radio" name="final-host-choice" className="mr-2" checked={hostChoice !== "auto" && hostChoice !== CREATE_HOST_CHOICE && hostChoice !== UNASSIGNED_HOST_CHOICE} onChange={() => setHostChoice(filteredCaseHosts[0]?.id ?? caseHosts[0]?.id ?? "auto")} disabled={!caseHosts.length} />
          Existing host
          {hostChoice !== "auto" && hostChoice !== CREATE_HOST_CHOICE && hostChoice !== UNASSIGNED_HOST_CHOICE ? (
            <>
              <input value={hostSearch} onChange={(event) => setHostSearch(event.target.value)} placeholder="Search hosts" className="mt-3 w-full rounded-2xl border border-line bg-abyss/80 px-4 py-2 text-sm text-ink" />
              <select
                aria-label="Existing host"
                value={hostChoice}
                onChange={(event) => setHostChoice(event.target.value)}
                className="mt-2 w-full rounded-2xl border border-line bg-abyss/80 px-4 py-3 text-sm text-ink"
              >
                {filteredCaseHosts.map((host) => <option key={host.id} value={host.id}>{host.display_name}</option>)}
              </select>
            </>
          ) : null}
        </label>
        <label className={`rounded-2xl border p-3 text-sm ${hostChoice === CREATE_HOST_CHOICE ? "border-accent bg-accent/10 text-ink" : "border-line bg-abyss/70 text-muted"}`}>
          <input type="radio" name="final-host-choice" className="mr-2" checked={hostChoice === CREATE_HOST_CHOICE} onChange={() => setHostChoice(CREATE_HOST_CHOICE)} />
          New host
          {hostChoice === CREATE_HOST_CHOICE ? (
            <input
              aria-label="New host name"
              value={newHostName}
              onChange={(event) => setNewHostName(event.target.value)}
              placeholder={detectedHostname || "DESKTOP-7FQ2A1"}
              className="mt-3 w-full rounded-2xl border border-line bg-abyss/80 px-4 py-3 text-sm text-ink"
            />
          ) : null}
        </label>
        {processingMode === "skip" && !hasMemoryEvidence ? (
          <label className={`rounded-2xl border p-3 text-sm ${hostChoice === UNASSIGNED_HOST_CHOICE ? "border-accent bg-accent/10 text-ink" : "border-line bg-abyss/70 text-muted"}`}>
            <input type="radio" name="final-host-choice" className="mr-2" checked={hostChoice === UNASSIGNED_HOST_CHOICE} onChange={() => setHostChoice(UNASSIGNED_HOST_CHOICE)} />
            Keep unassigned
          </label>
        ) : null}
      </div>
      {hostAssignmentBlockingReason ? <p className="mt-3 text-sm text-amber" data-testid="host-assignment-guidance">{hostAssignmentBlockingReason}</p> : null}
    </div>
  );

  const healthStatus = healthQuery.isLoading
    ? { label: "Checking systems", tone: "text-muted", dot: "bg-muted" }
    : healthQuery.data?.critical_ready === false
      ? { label: "Critical dependency down", tone: "text-danger", dot: "bg-danger" }
      : healthQuery.data?.ready === false
        ? { label: "Partial systems ready", tone: "text-amber", dot: "bg-amber" }
        : { label: "All systems ready", tone: "text-mint", dot: "bg-mint" };

  if (!open) return null;

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/70 p-4" role="dialog" aria-modal="true" aria-label="Add Evidence">
      <div className="w-full max-w-3xl max-h-[90vh] overflow-y-auto rounded-[28px] border border-line bg-panel p-6 shadow-panel">
        <div className="flex items-center justify-between gap-3">
          <div>
            <p className="font-mono text-xs uppercase tracking-[0.24em] text-accent">{step === 5 ? "Confirm evidence" : step === 6 ? "Memory Preparation" : "Add Evidence"}</p>
            <p className={`mt-1 inline-flex items-center gap-2 text-xs ${healthStatus.tone}`} data-testid="ingestion-health-chip"><span className={`h-2 w-2 rounded-full ${healthStatus.dot}`} />{healthStatus.label}</p>
          </div>
          <button type="button" onClick={handleClose} className="rounded-xl border border-line px-3 py-2 text-xs text-muted">Close</button>
        </div>

        {healthQuery.data?.critical_ready === false ? (
          <section className="mt-5 rounded-2xl border border-danger/40 bg-danger/10 p-4" data-testid="health-check">
            <h2 className="text-xl font-semibold text-danger">Critical dependency unavailable</h2>
            <p className="mt-1 text-sm text-muted">Storage and database must be reachable before evidence intake can continue.</p>
            <div className="mt-4 space-y-2">
              {healthQuery.data.checks.map((check) => (
                <p key={check.label} className={`text-sm ${check.ok ? "text-mint" : "text-danger"}`}>{check.ok ? "✔" : "⚠"} {check.label}: {check.detail}</p>
              ))}
            </div>
            <button type="button" onClick={() => healthQuery.refetch()} className="mt-4 rounded-2xl border border-line bg-abyss/80 px-4 py-2 text-sm text-muted">Recheck</button>
          </section>
        ) : null}

        {step === 4 && resumeTarget ? (
          <section className="mt-5" data-testid="resume-upload-step">
            <h2 className="text-xl font-semibold text-ink">Resume upload</h2>
            <p className="mt-1 text-sm text-muted">
              Browsers can't silently reopen a local file after a reload. Select <strong className="text-ink">{resumeTarget.original_filename}</strong> again
              ({bytes(resumeTarget.expected_size_bytes)}, {resumeTarget.progress_percent !== null ? `${resumeTarget.progress_percent.toFixed(0)}% already uploaded` : "in progress"}) to continue &mdash;
              Kairon verifies it's the same file before resuming.
            </p>
            <label className="mt-4 flex flex-col gap-2 rounded-2xl border border-dashed border-line bg-abyss/60 p-6 text-sm text-muted">
              <span>Select the original file</span>
              <input
                type="file"
                data-testid="resume-file-input"
                onChange={async (event) => {
                  const file = event.target.files?.[0];
                  setResumeFile(null);
                  setResumeFileError(null);
                  if (!file) return;
                  setResumeVerifying(true);
                  try {
                    const error = await verifyResumeFile(resumeTarget, file);
                    if (error) {
                      setResumeFileError(error);
                    } else {
                      setResumeFile(file);
                    }
                  } finally {
                    setResumeVerifying(false);
                  }
                }}
              />
              {resumeVerifying ? <span className="text-xs text-muted" data-testid="resume-verifying">Verifying selected file matches this upload session...</span> : null}
              {resumeFileError ? <span className="text-xs text-danger" data-testid="resume-file-error">{resumeFileError}</span> : null}
              {resumeFile && !resumeFileError && !resumeVerifying ? <span className="text-xs text-mint" data-testid="resume-file-verified">Verified &mdash; ready to resume.</span> : null}
            </label>
            {(createSessionMutation.isPending || inspectionState === "failed") ? (
              <div className={`mt-5 rounded-2xl border p-4 text-sm ${inspectionState === "failed" ? "border-danger/40 bg-danger/10" : "border-line bg-abyss/60"}`} data-testid="inspection-progress-panel">
                <p className={`font-semibold ${inspectionState === "failed" ? "text-danger" : "text-ink"}`}>{inspectionLabel}</p>
                {inspectionState === "failed" && inspectionError ? <p className="mt-3 text-sm text-danger">{inspectionError}</p> : (
                  <div className="mt-4 space-y-2">
                    <div className={`rounded-xl border px-3 py-2 ${uploadProgress === 1 ? "border-mint/30 bg-mint/10 text-mint" : "border-accent/30 bg-accent/10 text-accent"}`}>
                      Resuming upload{uploadProgress !== null ? ` ${Math.round(uploadProgress * 100)}%` : ""}
                      {uploadProgress !== null ? <div className="mt-2 h-1.5 rounded-full bg-abyss"><div className="h-1.5 rounded-full bg-accent transition-all" style={{ width: `${Math.max(5, Math.round(uploadProgress * 100))}%` }} /></div> : null}
                    </div>
                  </div>
                )}
              </div>
            ) : null}
            <div className="mt-5 flex justify-between">
              <button
                type="button"
                onClick={() => { setResumeTarget(null); setResumeFile(null); setResumeFileError(null); setStep(4); }}
                className="rounded-2xl border border-line bg-abyss/80 px-4 py-2 text-sm text-muted"
              >
                Start a different upload
              </button>
              <button
                type="button"
                disabled={!resumeFile || resumeVerifying || createSessionMutation.isPending}
                onClick={() => createSessionMutation.mutate()}
                className="rounded-2xl bg-accent px-4 py-2 text-sm font-semibold text-abyss disabled:opacity-50"
                data-testid="resume-upload-button"
              >
                {createSessionMutation.isPending ? inspectionLabel : "Resume Upload"}
              </button>
            </div>
          </section>
        ) : null}

        {step === 4 && !resumeTarget && healthQuery.data?.critical_ready !== false ? (
          <section className="mt-5">
            {interruptedOrActiveSessions.length ? (
              <div className="mb-6 rounded-3xl border border-amber-400/30 bg-amber-400/5 p-4" data-testid="resumable-uploads-panel">
                <p className="font-mono text-xs uppercase tracking-[0.16em] text-amber-300">Interrupted uploads</p>
                <div className="mt-3 space-y-2">
                  {interruptedOrActiveSessions.map((candidate) => (
                    <div key={candidate.id} className="flex flex-wrap items-center justify-between gap-3 rounded-2xl border border-line bg-abyss/60 p-3" data-testid="resumable-upload-row">
                      <div className="min-w-0">
                        <p className="truncate text-sm font-semibold text-ink">{candidate.original_filename}</p>
                        <p className="mt-0.5 text-xs text-muted">
                          {candidate.category ?? "evidence"} &middot; {candidate.status}
                          {candidate.progress_percent !== null ? ` · ${candidate.progress_percent.toFixed(0)}%` : ""}
                        </p>
                      </div>
                      <div className="flex shrink-0 gap-2">
                        {candidate.resumable || candidate.status === "staged" ? (
                          <button type="button" onClick={() => setResumeTarget(candidate)} className="rounded-xl bg-accent px-3 py-1.5 text-xs font-semibold text-abyss" data-testid="resume-upload-select">Resume</button>
                        ) : null}
                        {candidate.cancellable ? (
                          <button type="button" disabled={cancelResumableMutation.isPending} onClick={() => cancelResumableMutation.mutate(candidate.id)} className="rounded-xl border border-line px-3 py-1.5 text-xs text-muted">Cancel</button>
                        ) : null}
                      </div>
                    </div>
                  ))}
                </div>
              </div>
            ) : null}
            <h2 className="text-xl font-semibold text-ink">Select Evidence</h2>
            <p className="mt-1 text-sm text-muted">Select one or more files. Kairon will inspect each item and decide the evidence kind before processing.</p>
            <div
              className="mt-4 rounded-3xl border border-dashed border-line bg-abyss/60 p-8 text-center text-sm text-muted"
              onDragOver={(event) => event.preventDefault()}
              onDrop={(event) => {
                event.preventDefault();
                selectEvidenceFiles(Array.from(event.dataTransfer.files ?? []));
              }}
              data-testid="evidence-dropzone"
            >
              <p className="text-base font-semibold text-ink">Drop evidence here</p>
              <p className="mt-2">or choose an input method. Kairon will detect the evidence kind after selection.</p>
              <div className="mt-5 flex flex-wrap justify-center gap-3">
                <label className="cursor-pointer rounded-2xl bg-accent px-4 py-2 text-sm font-semibold text-abyss">
                  Select Files
                  <input
                    type="file"
                    multiple
                    className="sr-only"
                    onChange={(event) => {
                      selectEvidenceFiles(Array.from(event.target.files ?? []));
                    }}
                  />
                </label>
                <label className="cursor-pointer rounded-2xl border border-line bg-panel/70 px-4 py-2 text-sm font-semibold text-ink">
                  Select Folder
                  <input
                    type="file"
                    multiple
                    className="sr-only"
                    {...({ webkitdirectory: "true", directory: "true" } as Record<string, string>)}
                    onChange={(event) => {
                      selectEvidenceFiles(Array.from(event.target.files ?? []), { folderUpload: true });
                    }}
                  />
                </label>
              </div>
              {files.length ? <p className="mt-4 text-xs text-ink">{files.length === 1 ? files[0].name : `${files.length} files selected for detection`}</p> : null}
              {files.length === 1 && !requiresPathInput ? (
                hashProgress === null ? null : hashProgress < 1 ? (
                  <p className="mt-2 text-xs text-muted" data-testid="sha256-progress">Calculating SHA-256... {Math.round(hashProgress * 100)}%</p>
                ) : (
                  <p className="mt-2 text-xs text-mint" data-testid="sha256-ready">SHA-256: {clientSha256}</p>
                )
              ) : null}
            </div>
            <details className="mt-4 rounded-2xl border border-line bg-abyss/50 p-4" open={selectionAdvancedOpen} onToggle={(event) => setSelectionAdvancedOpen((event.target as HTMLDetailsElement).open)}>
              <summary className="cursor-pointer text-xs uppercase tracking-[0.16em] text-muted">Advanced import options</summary>
              <div className="mt-4 space-y-4">
                <label className="flex items-start gap-2 rounded-2xl border border-line bg-abyss/60 p-3 text-sm text-muted">
                  <input
                    type="checkbox"
                    className="mt-1"
                    checked={requiresPathInput}
                    onChange={(event) => {
                      if (event.target.checked) {
                        setAcquisitionSource("server_path");
                        setFolderUploadSelected(false);
                        setFiles([]);
                        setSession(null);
                        setPreflight(null);
                        setBatchItems([]);
                        setInspectionState("idle");
                        setInspectionError(null);
                        setUploadProgress(null);
                      } else {
                        setAcquisitionSource("files");
                      }
                    }}
                  />
                  <span>
                    Import from existing server path
                    <span className="mt-1 block text-xs text-muted">Use only when evidence is already mounted or staged on the server.</span>
                  </span>
                </label>
                {requiresPathInput ? (
                  <label className="block text-sm text-muted">
                    Server path
                    <input value={serverPath} onChange={(event) => setServerPath(event.target.value)} placeholder="/mnt/evidence/case-001/evidence.img" className="mt-2 w-full rounded-2xl border border-line bg-abyss/80 px-4 py-3 text-sm text-ink" />
                  </label>
                ) : null}
              </div>
            </details>
            {showAdvancedOptions ? (
              <div className="mt-4 space-y-4 rounded-2xl border border-line bg-abyss/50 p-4" data-testid="wizard-advanced-options">
                <p className="font-mono text-xs uppercase tracking-[0.16em] text-muted">Advanced options</p>
                <div>
                  <p className="text-xs text-muted">Evidence type</p>
                  <div className="mt-2 grid gap-2 sm:grid-cols-2">
                    <label className={`rounded-2xl border p-3 text-sm ${evidenceIntent === "raw" ? "border-accent bg-accent/10 text-ink" : "border-line bg-abyss/60 text-muted"}`}>
                      <input type="radio" name="evidence-intent" className="mr-2" checked={evidenceIntent === "raw"} onChange={() => setEvidenceIntent("raw")} data-testid="evidence-intent-raw" />
                      Raw
                      <span className="mt-1 block text-xs text-muted">Source evidence requiring parsing/normalization.</span>
                    </label>
                    <label className={`rounded-2xl border p-3 text-sm ${evidenceIntent === "parsed" ? "border-accent bg-accent/10 text-ink" : "border-line bg-abyss/60 text-muted"}`}>
                      <input type="radio" name="evidence-intent" className="mr-2" checked={evidenceIntent === "parsed"} onChange={() => setEvidenceIntent("parsed")} data-testid="evidence-intent-parsed" />
                      Parsed
                      <span className="mt-1 block text-xs text-muted">Already-processed or tool-generated artifacts.</span>
                    </label>
                  </div>
                </div>
                <div>
                  <p className="text-xs text-muted">Processing depth</p>
                  <div className="mt-2 grid gap-2 sm:grid-cols-2">
                    <label className={`rounded-2xl border p-3 text-sm ${ingestMode === "full_forensic" ? "border-accent bg-accent/10 text-ink" : "border-line bg-abyss/60 text-muted"}`}>
                      <input type="radio" name="ingest-mode" className="mr-2" checked={ingestMode === "full_forensic"} onChange={() => setIngestMode("full_forensic")} data-testid="ingest-mode-full-forensic" />
                      Full forensic <span className="text-muted">(recommended)</span>
                      <span className="mt-1 block text-xs text-muted">Complete processing and detections.</span>
                    </label>
                    <label className={`rounded-2xl border p-3 text-sm ${ingestMode === "usable_search" ? "border-accent bg-accent/10 text-ink" : "border-line bg-abyss/60 text-muted"}`}>
                      <input type="radio" name="ingest-mode" className="mr-2" checked={ingestMode === "usable_search"} onChange={() => setIngestMode("usable_search")} data-testid="ingest-mode-usable-search" />
                      Usable search
                      <span className="mt-1 block text-xs text-muted">Faster, lighter processing with reduced forensic depth &mdash; rules and detections are skipped, not just deferred.</span>
                    </label>
                  </div>
                </div>
                {showEvtxProfileOption ? (
                  <div>
                    <p className="text-xs text-muted">EVTX profile</p>
                    <div className="mt-2 grid gap-2 sm:grid-cols-2">
                      <label className={`rounded-2xl border p-3 text-sm ${evtxProfile === "fast_high_value" ? "border-accent bg-accent/10 text-ink" : "border-line bg-abyss/60 text-muted"}`}>
                        <input type="radio" name="evtx-profile" className="mr-2" checked={evtxProfile === "fast_high_value"} onChange={() => setEvtxProfile("fast_high_value")} data-testid="evtx-profile-fast" />
                        Fast (high-value channels)
                      </label>
                      <label className={`rounded-2xl border p-3 text-sm ${evtxProfile === "full" ? "border-accent bg-accent/10 text-ink" : "border-line bg-abyss/60 text-muted"}`}>
                        <input type="radio" name="evtx-profile" className="mr-2" checked={evtxProfile === "full"} onChange={() => setEvtxProfile("full")} data-testid="evtx-profile-full" />
                        Full
                      </label>
                    </div>
                  </div>
                ) : null}
              </div>
            ) : null}
            {(createSessionMutation.isPending || inspectionState === "failed") ? (
              <div className={`mt-5 rounded-2xl border p-4 text-sm ${inspectionState === "failed" ? "border-danger/40 bg-danger/10" : "border-line bg-abyss/60"}`} data-testid="inspection-progress-panel">
                <p className={`font-semibold ${inspectionState === "failed" ? "text-danger" : "text-ink"}`}>{inspectionLabel}</p>
                {inspectionStartedAt ? <p className="mt-1 text-xs text-muted">Elapsed: {inspectionElapsedSeconds}s</p> : null}
                {inspectionState === "failed" && inspectionError ? (
                  <>
                    <p className="mt-3 text-sm text-danger">{inspectionError}</p>
                    <div className="mt-4 flex flex-wrap gap-2">
                      <button type="button" onClick={() => createSessionMutation.mutate()} className="rounded-2xl bg-accent px-4 py-2 text-xs font-semibold text-abyss">Retry inspection</button>
                      <button type="button" onClick={() => { setInspectionState("idle"); setInspectionError(null); }} className="rounded-2xl border border-line bg-abyss/80 px-4 py-2 text-xs text-muted">Change evidence</button>
                    </div>
                  </>
                ) : (
                  <div className="mt-4 space-y-2">
                    {!requiresPathInput ? (
                      <div className={`rounded-xl border px-3 py-2 ${uploadProgress === 1 ? "border-mint/30 bg-mint/10 text-mint" : inspectionState === "uploading" || inspectionState === "finalizing_upload" ? "border-accent/30 bg-accent/10 text-accent" : "border-line text-muted"}`}>
                        {uploadProgress === 1 ? "Done:" : inspectionState === "uploading" || inspectionState === "finalizing_upload" ? "Active:" : "Queued:"} Uploading evidence{uploadProgress !== null ? ` ${Math.round(uploadProgress * 100)}%` : ""}
                        {uploadProgress !== null ? <div className="mt-2 h-1.5 rounded-full bg-abyss"><div className="h-1.5 rounded-full bg-accent transition-all" style={{ width: `${Math.max(5, Math.round(uploadProgress * 100))}%` }} /></div> : null}
                      </div>
                    ) : null}
                    {!requiresPathInput && finalizeStageHistory.length === 0 ? (
                      <p className={`rounded-xl border px-3 py-2 ${inspectionState === "finalizing_upload" ? "border-accent/30 bg-accent/10 text-accent" : uploadProgress === 1 ? "border-mint/30 bg-mint/10 text-mint" : "border-line text-muted"}`}>
                        {inspectionState === "finalizing_upload" ? "Active:" : uploadProgress === 1 ? "Done:" : "Queued:"} Finalizing upload on the server
                      </p>
                    ) : null}
                    {!requiresPathInput
                      ? finalizeStageHistory.map((stage, index) => {
                          const isLast = index === finalizeStageHistory.length - 1;
                          const active = isLast && inspectionState === "finalizing_upload";
                          return (
                            <p key={stage} data-testid="finalize-stage-row" className={`rounded-xl border px-3 py-2 ${active ? "border-accent/30 bg-accent/10 text-accent" : "border-mint/30 bg-mint/10 text-mint"}`}>
                              {active ? "Active:" : "Done:"} {finalizeStageLabel(stage)}
                            </p>
                          );
                        })
                      : null}
                    <p className={`rounded-xl border px-3 py-2 ${inspectionState === "preflight_running" ? "border-accent/30 bg-accent/10 text-accent" : "border-line text-muted"}`}>
                      {inspectionState === "preflight_running" ? "Active:" : "Queued:"} Scanning contents, detecting platform, discovering hosts, and estimating processing
                    </p>
                    <p className="text-xs text-muted">Kairon is staging the evidence, then running a read-only preflight. Large archives or disk images can take longer while metadata and candidate artifacts are inspected.</p>
                  </div>
                )}
              </div>
            ) : null}
            {activePreflightReports.length ? (
              <div className="mt-5 space-y-3" data-testid="selected-evidence-list">
                <p className="text-sm font-semibold text-ink">{activePreflightReports.length} {activePreflightReports.length === 1 ? "item" : "items"}</p>
                {activePreflightReports.map((report) => {
                  const tier = confidenceTierLabel(report.classification.confidence, hasConflictingSignals(report));
                  const toneClass = tier.tone === "mint" ? "border-mint/30 bg-mint/10 text-mint" : tier.tone === "amber" ? "border-amber/30 bg-amber/10 text-amber" : "border-danger/30 bg-danger/10 text-danger";
                  return (
                    <div key={report.token} className="rounded-2xl border border-line bg-abyss/60 p-4" data-testid="selected-evidence-row">
                      <div className="flex flex-wrap items-start justify-between gap-3">
                        <div>
                          <p className="font-semibold text-ink">{report.original_filename}</p>
                          <p className="mt-1 text-xs text-muted">{bytes(report.resource_check.file_size_bytes)}</p>
                        </div>
                        <span className={`rounded-full border px-3 py-1 text-xs font-semibold ${toneClass}`}>{tier.label} — {evidenceKindLabel(report.classification.category)}</span>
                      </div>
                      <p className="mt-3 text-sm text-muted">{report.classification.reason || "Kairon inspected this item and produced a classification."}</p>
                    </div>
                  );
                })}
              </div>
            ) : null}
            <div className="mt-5 flex justify-between">
              <button type="button" onClick={handleClose} className="rounded-2xl border border-line bg-abyss/80 px-4 py-2 text-sm text-muted">Cancel</button>
              <button
                type="button"
                disabled={createSessionMutation.isPending || hashPending || (!activePreflightReports.length && !canAdvanceStep4)}
                onClick={() => {
                  if (activePreflightReports.length) {
                    setStep(5);
                  } else {
                    explicitInspectRef.current = true;
                    createSessionMutation.mutate();
                  }
                }}
                className="rounded-2xl bg-accent px-4 py-2 text-sm font-semibold text-abyss disabled:opacity-50"
              >
                {createSessionMutation.isPending ? inspectionLabel : hashPending ? "Calculating SHA-256..." : activePreflightReports.length ? "Continue →" : "Inspect evidence"}
              </button>
            </div>
          </section>
        ) : null}

        {step === 5 && preflight ? (
          <section className="mt-5" data-testid="preflight-report">
            <h2 className="text-xl font-semibold text-ink">Confirm evidence</h2>
            <p className="mt-1 text-sm text-muted">Review what Kairon found, confirm where it belongs, then start processing.</p>

            {session?.client_sha256_mismatch ? (
              <p className="mt-3 rounded-2xl border border-amber/40 bg-amber/10 p-3 text-xs text-amber" data-testid="hash-mismatch-warning">
                The SHA-256 computed in your browser does not match what Kairon staged on the server. The file may have changed during upload &mdash; consider re-selecting it before continuing.
              </p>
            ) : null}

            <div className="mt-4 space-y-3" data-testid="detection-results-list">
              {activePreflightReports.map((report) => {
                const needsOverride = needsManualOverride(report);
                const detectedRoute = routeForCategory(report.classification.category);
                const forcedRoute = forcedRoutes[report.token];
                const selectedRoute = forcedRoute ?? detectedRoute;
                const wrongRoute = forcedRoute && detectedRoute && forcedRoute !== detectedRoute && [forcedRoute, detectedRoute].includes("disk_image") && [forcedRoute, detectedRoute].includes("memory_dump");
                const expectedMismatch = expectedKind && detectedRoute && expectedKind !== detectedRoute;
                const decisiveSignals = [report.classification.reason, ...report.classification.warnings.map((warning) => warning.message)].filter(Boolean);
                const conflictingSignals = hasConflictingSignals(report) ? report.diagnostics.map((diag) => diag.reason).filter(Boolean) : [];
                return (
                  <div key={report.token} className="rounded-2xl border border-line bg-abyss/60 p-4" data-testid="detection-result-row">
                    <div className="flex flex-wrap items-start justify-between gap-3">
                      <div>
                        <p className="font-semibold text-ink">{report.original_filename}</p>
                        <p className="mt-1 text-xs text-muted">{report.classification.container ?? report.classification.format_key ?? "Unknown container"}</p>
                      </div>
                      {(() => {
                        const tier = confidenceTierLabel(report.classification.confidence, hasConflictingSignals(report));
                        const toneClass = tier.tone === "mint" ? "border-mint/30 bg-mint/10 text-mint" : tier.tone === "amber" ? "border-amber/30 bg-amber/10 text-amber" : "border-danger/30 bg-danger/10 text-danger";
                        return <div className={`rounded-full border px-3 py-1 text-xs font-semibold ${toneClass}`}>{tier.label}</div>;
                      })()}
                    </div>
                    <div className="mt-3 grid gap-2 text-sm text-muted sm:grid-cols-2">
                      <p>Detected kind: <span className="text-ink">{evidenceKindLabel(report.classification.category)}</span></p>
                      <p>Detected platform: <span className="text-ink">{report.classification.platform === "unknown" ? report.classification.contained_object ?? "Unknown" : report.classification.platform}</span></p>
                      <p>Assign to host: <span className="text-ink">{assignedHostLabel || "Needs confirmation"}</span></p>
                      <p>Status: <span className={hostRequirementBlocking ? "text-amber" : report.status === "ready" ? "text-mint" : report.status === "warning" ? "text-amber" : "text-danger"}>{hostRequirementBlocking ? "action required" : report.status}</span></p>
                    </div>
                    {expectedMismatch ? (
                      <div className="mt-3 rounded-xl border border-amber/30 bg-amber/10 p-3 text-xs text-amber" data-testid="expected-kind-warning">
                        <p className="font-semibold">Expected {evidenceKindLabel(expectedKind)}, detected {evidenceKindLabel(detectedRoute)}.</p>
                        <p className="mt-1">Kairon will use the detected route unless you expand Advanced options and choose a manual override.</p>
                      </div>
                    ) : null}
                    {decisiveSignals.length ? (
                      <div className="mt-3">
                        <p className="text-xs text-muted">Decisive signals</p>
                        <div className="mt-1 flex flex-wrap gap-1.5">
                          {decisiveSignals.slice(0, 4).map((signal) => <span key={signal} className="rounded-full border border-mint/30 bg-mint/10 px-2 py-0.5 text-xs text-mint">{signal}</span>)}
                        </div>
                      </div>
                    ) : null}
                    {conflictingSignals.length ? (
                      <div className="mt-3">
                        <p className="text-xs text-muted">Conflicting signals</p>
                        <div className="mt-1 flex flex-wrap gap-1.5">
                          {conflictingSignals.slice(0, 3).map((signal) => <span key={signal} className="rounded-full border border-amber/30 bg-amber/10 px-2 py-0.5 text-xs text-amber">{signal}</span>)}
                        </div>
                      </div>
                    ) : null}
                    {needsOverride || advancedOpen ? (
                      <div className="mt-3 rounded-xl border border-amber/30 bg-amber/10 p-3" data-testid="manual-override-panel">
                        <label className="text-xs text-amber">
                          Manual override
                          <select
                            value={forcedRoute ?? ""}
                            onChange={(event) => setForcedRoutes((current) => ({ ...current, [report.token]: event.target.value as ForcedRoute }))}
                            className="mt-1 w-full rounded-xl border border-line bg-abyss/90 px-3 py-2 text-sm text-ink"
                          >
                            <option value="">Choose forced route...</option>
                            {OVERRIDE_OPTIONS.map((option) => <option key={option.value} value={option.value}>{option.label}</option>)}
                          </select>
                        </label>
                        {forcedRoute ? <p className="mt-2 text-xs text-amber">You are forcing the processing pipeline. Use this only when you have external evidence that Kairon's detection is incomplete.</p> : null}
                        {wrongRoute ? (
                          <div className="mt-3 rounded-xl border border-danger/30 bg-danger/10 p-3 text-xs text-danger" data-testid="wrong-route-warning">
                            <p className="font-semibold">Forced route conflicts with strong structural detection.</p>
                            <p className="mt-1">Kairon detected {evidenceKindLabel(report.classification.category)} but you selected {evidenceKindLabel(forcedRoute)}. Processing through the wrong pipeline may fail or produce misleading results.</p>
                            <label className="mt-2 flex items-center gap-2 text-ink">
                              <input type="checkbox" checked={Boolean(wrongRouteAccepted[report.token])} onChange={(event) => setWrongRouteAccepted((current) => ({ ...current, [report.token]: event.target.checked }))} />
                              Process anyway
                            </label>
                          </div>
                        ) : null}
                      </div>
                    ) : null}
                  </div>
                );
              })}
            </div>

            <div className="mt-4 rounded-2xl border border-line bg-abyss/60 p-4">
              <p className="font-mono text-[11px] uppercase tracking-[0.16em] text-accent">Evidence Classification</p>
              <p className="mt-2 text-sm text-ink">{[...preflight.classification.chain, preflight.classification.platform !== "unknown" ? preflight.classification.platform : null].filter(Boolean).join(" → ")}</p>
              <div className="mt-3 grid gap-2 text-sm text-muted sm:grid-cols-2">
                <p>Evidence type: <span className="text-ink">{preflight.classification.category}</span></p>
                {preflight.classification.container ? <p>Container: <span className="text-ink">{preflight.classification.container}</span></p> : null}
                {preflight.classification.contained_object ? <p>Contained object: <span className="text-ink">{preflight.classification.contained_object}</span></p> : null}
                {preflight.classification.hostname ? <p>Hostname: <span className="text-ink">{preflight.classification.hostname}</span></p> : null}
                {preflight.classification.distro ? <p>Distribution: <span className="text-ink">{preflight.classification.distro}{preflight.classification.version ? ` (${preflight.classification.version})` : ""}</span></p> : null}
                {/* "Volumes" and "Partitions" are the same count today (Kairon
                    discovers physical partitions only -- see Partition
                    Discovery below); showing both labels for one number was
                    confusing, so only the more precise term is shown. Logical
                    volumes are counted separately -- they are not partitions. */}
                {preflight.classification.partitions !== null ? <p>Partitions: <span className="text-ink">{preflight.classification.partitions}</span></p> : null}
                {preflight.classification.logical_volumes !== null ? <p>Logical volumes: <span className="text-ink">{preflight.classification.logical_volumes}</span></p> : null}
                {preflight.classification.filesystems.length ? <p>Filesystems: <span className="text-ink">{preflight.classification.filesystems.join(", ")}</span></p> : null}
                {preflight.classification.installations !== null ? <p>Installations: <span className="text-ink">{preflight.classification.installations}</span></p> : null}
                <p>Confidence: <span className="text-ink">{preflight.classification.confidence}</span></p>
              </div>
              {preflight.classification.expected_parsers.length ? (
                <div className="mt-3">
                  <p className="text-xs text-muted">Expected artifact families</p>
                  <div className="mt-1 flex flex-wrap gap-1.5">
                    {preflight.classification.expected_parsers.map((parser) => (
                      <span key={parser} className="rounded-full border border-mint/30 bg-mint/10 px-2 py-0.5 text-xs text-mint">&#10003; {parser}</span>
                    ))}
                  </div>
                </div>
              ) : null}
              {preflight.classification.warnings.length ? (
                <div className="mt-3 space-y-1">
                  {preflight.classification.warnings.map((warning) => (
                    <p key={warning.message} className={`text-xs ${warning.severity === "recommendation" ? "text-amber" : "text-muted"}`}>
                      {warning.severity === "recommendation" ? "Recommendation" : "Information"}: {warning.message}
                    </p>
                  ))}
                </div>
              ) : null}
            </div>

            {preflight.classification.volume_diagnostics.length ? (
              <div className="mt-4 rounded-2xl border border-line bg-abyss/60 p-4" data-testid="volume-diagnostics">
                <p className="font-mono text-[11px] uppercase tracking-[0.16em] text-accent">Partition Discovery</p>
                <p className="mt-1 text-xs text-muted">Per-partition detection results -- explains which partitions contributed to the classification above, and why any that didn't could not be read. When a partition is an LVM container, any logical volumes Kairon discovered and processed inside it are listed beneath it.</p>
                <div className="mt-3 space-y-2">
                  {preflight.classification.volume_diagnostics.map((volume) => {
                    const isLogicalVolume = volume.kind === "logical_volume";
                    const containerNumber = volume.container_volume_id !== null ? partitionDisplayNumbers.get(volume.container_volume_id) : undefined;
                    const label = isLogicalVolume ? `Logical Volume${volume.name ? ` — ${volume.name}` : ""}` : `Partition ${partitionDisplayNumbers.get(volume.volume_id) ?? "?"}`;
                    return (
                      <div
                        key={volume.volume_id}
                        className={`rounded-xl border px-3 py-2 text-sm ${volume.ok ? "border-mint/30 bg-mint/10" : "border-amber/30 bg-amber/10"} ${isLogicalVolume ? "ml-4 border-l-2 border-l-line" : ""}`}
                        data-testid="volume-diagnostic-row"
                      >
                        <p className={`font-semibold ${volume.ok ? "text-mint" : "text-amber"}`}>
                          {volume.ok ? "✓" : "⚠"} {label}
                          {isLogicalVolume && containerNumber !== undefined ? ` (inside Partition ${containerNumber})` : ""}
                          {volume.size_bytes !== null ? ` · ${bytes(volume.size_bytes)}` : ""}
                          {volume.filesystem ? ` · ${volume.filesystem}` : ""}
                        </p>
                        <p className="mt-1 text-xs text-muted">{volume.explanation}</p>
                        {volume.detected_signature ? (
                          <p className="mt-1 text-xs text-muted">Container format: <span className="text-ink">{volume.detected_signature}</span></p>
                        ) : null}
                      </div>
                    );
                  })}
                </div>
              </div>
            ) : null}

            <div className="mt-4 rounded-2xl border border-line bg-abyss/60 p-4">
              <p className="font-mono text-[11px] uppercase tracking-[0.16em] text-accent">Processing Pipeline Preview</p>
              <p className="mt-2 text-sm text-ink">{preflight.pipeline_preview.join(" → ")}</p>
            </div>

            <div className="mt-4 rounded-2xl border border-line bg-abyss/60 p-4">
              <p className="font-mono text-[11px] uppercase tracking-[0.16em] text-accent">Preflight Resource Check</p>
              <div className="mt-3 grid gap-2 text-sm text-muted sm:grid-cols-2">
                <p>File size: <span className="text-ink">{bytes(preflight.resource_check.file_size_bytes)}</span></p>
                {preflight.resource_check.estimated_extracted_bytes !== null ? <p>Estimated disk usage: <span className="text-ink">{bytes(preflight.resource_check.estimated_final_size_bytes)}</span></p> : null}
                {preflight.resource_check.estimated_temp_storage_bytes !== null ? <p>Estimated temporary storage: <span className="text-ink">{bytes(preflight.resource_check.estimated_temp_storage_bytes)}</span></p> : null}
                <p>Available storage: <span className="text-ink">{bytes(preflight.resource_check.available_disk_space_bytes)}</span></p>
                <p>Estimated duration: <span className="text-ink">{durationBucketLabel(preflight.resource_check.estimated_duration_bucket) ?? "unknown"}</span></p>
                {preflight.resource_check.estimated_artifact_count !== null ? <p>Estimated artifact count: <span className="text-ink">{preflight.resource_check.estimated_artifact_count}</span></p> : null}
                <p>Upload limit: <span className="text-ink">{bytes(preflight.resource_check.configured_upload_limit_bytes)}</span></p>
              </div>
            </div>

            <div className="mt-4 space-y-2">
              {preflight.status_checks.map((check) => (
                <p key={check.label} className={`text-sm ${check.ok ? "text-mint" : "text-danger"}`}>
                  {check.ok ? "✔" : "⚠"} {check.label}: {check.detail}
                </p>
              ))}
            </div>

            {hostRequirementBlocking ? (
              <div className="mt-4 rounded-2xl border border-amber/40 bg-amber/10 p-4" data-testid="host-required-message">
                <p className="font-semibold text-amber">Host required</p>
                <p className="mt-1 text-sm text-ink">This evidence must be associated with a host before processing.</p>
                <p className="mt-1 text-sm text-muted">{hostAssignmentBlockingReason}</p>
              </div>
            ) : null}

            {hostRequirementVisible ? <div className="mt-4">{hostAssignmentPanel}</div> : null}

            {preflight.diagnostics.length ? (
              <div className="mt-4 space-y-3">
                {preflight.diagnostics.map((diag) => (
                  <div key={diag.problem} className={`rounded-2xl border p-4 text-sm ${diag.severity === "recommendation" ? "border-amber/30 bg-amber/10" : "border-danger/30 bg-danger/10"}`}>
                    <p className={`font-semibold ${diag.severity === "recommendation" ? "text-amber" : "text-danger"}`}>
                      {diag.severity === "recommendation" ? "Recommendation" : "Blocking"}: {diag.problem}
                    </p>
                    <p className="mt-1 text-muted">{diag.reason}</p>
                    {diag.configuration_key ? (
                      <div className="mt-2 rounded-xl border border-line bg-abyss/60 p-3 text-xs text-muted">
                        <p>Current value: <span className="text-ink">{diag.current_configuration?.limit ?? diag.current_configuration?.available ?? diag.current_configuration?.depth ?? "unknown"}</span></p>
                        <p>Required value: <span className="text-ink">{diag.required_configuration?.limit ?? diag.required_configuration?.available ?? diag.required_configuration?.depth ?? "unknown"}</span></p>
                        <p>Configuration key: <span className="text-ink">{diag.configuration_key}</span></p>
                        {diag.configuration_file ? <p>Configuration file: <span className="text-ink">{diag.configuration_file}</span></p> : null}
                      </div>
                    ) : null}
                    {diag.how_to_fix.length ? (
                      <ol className="mt-2 list-decimal space-y-1 pl-5 text-xs text-muted">
                        {diag.how_to_fix.map((step) => <li key={step}>{step}</li>)}
                      </ol>
                    ) : null}
                    {diag.problem === "Low confidence classification" ? (
                      <label className="mt-3 flex items-center gap-2 text-xs text-ink">
                        <input type="checkbox" checked={manualOverrideAccepted} onChange={(event) => setManualOverrideAccepted(event.target.checked)} />
                        Continue with a manual override
                      </label>
                    ) : null}
                  </div>
                ))}
              </div>
            ) : readyToProcess ? (
              <p className="mt-4 text-sm font-semibold text-mint">Ready to process</p>
            ) : null}

            {hasMemoryEvidence ? (
              <label className="mt-4 flex items-start gap-2 rounded-2xl border border-amber/40 bg-amber/10 p-4 text-sm text-ink">
                <input type="checkbox" className="mt-1" checked={memoryAuthorizationAcknowledged} onChange={(event) => setMemoryAuthorizationAcknowledged(event.target.checked)} />
                I am authorized to handle this RAM evidence and understand it may contain highly sensitive data.
              </label>
            ) : null}

            <details className="mt-4 rounded-2xl border border-line bg-abyss/50 p-4" open={advancedOpen} onToggle={(event) => setAdvancedOpen((event.target as HTMLDetailsElement).open)}>
              <summary className="cursor-pointer text-xs uppercase tracking-[0.16em] text-muted">Advanced — evidence options</summary>
              <div className="mt-3 grid gap-3">
                {!hostRequirementVisible ? hostAssignmentPanel : null}
                {!hasMemoryEvidence ? (
                  <div className="rounded-2xl border border-line bg-abyss/60 p-3">
                    <p className="text-xs uppercase tracking-[0.16em] text-muted">Processing profile</p>
                    <div className="mt-3 grid gap-2 md:grid-cols-3">
                      <label className={`rounded-2xl border p-3 text-sm ${processingMode === "recommended" ? "border-accent bg-accent/10 text-ink" : "border-line bg-abyss/70 text-muted"}`}><input type="radio" name="processing-mode" className="mr-2" checked={processingMode === "recommended"} onChange={() => setProcessingMode("recommended")} />Standard</label>
                      <label className={`rounded-2xl border p-3 text-sm ${processingMode === "custom" ? "border-accent bg-accent/10 text-ink" : "border-line bg-abyss/70 text-muted"}`}><input type="radio" name="processing-mode" className="mr-2" checked={processingMode === "custom"} onChange={() => setProcessingMode("custom")} />Custom</label>
                      <label className={`rounded-2xl border p-3 text-sm ${processingMode === "skip" ? "border-accent bg-accent/10 text-ink" : "border-line bg-abyss/70 text-muted"}`}><input type="radio" name="processing-mode" className="mr-2" checked={processingMode === "skip"} onChange={() => setProcessingMode("skip")} />Save only</label>
                    </div>
                  </div>
                ) : null}
                <label className="text-xs text-muted">Labels<input value={labels} onChange={(event) => setLabels(event.target.value)} placeholder="comma, separated, labels" className="mt-1 w-full rounded-2xl border border-line bg-abyss/80 px-4 py-2 text-sm text-ink" /></label>
                <label className="text-xs text-muted">Evidence notes<textarea value={notes} onChange={(event) => setNotes(event.target.value)} className="mt-1 h-20 w-full rounded-2xl border border-line bg-abyss/80 px-4 py-2 text-sm text-ink" /></label>
              </div>
            </details>

            {startMutation.error instanceof Error ? <p className="mt-3 text-sm text-danger">{startMutation.error.message}</p> : null}
            {hostRequirementBlocking ? (
              <p className="mt-3 text-sm text-amber" data-testid="start-processing-host-reason">
                Select a host before starting processing.
              </p>
            ) : null}
            <div className="mt-5 flex justify-between">
              <button type="button" onClick={() => setStep(4)} className="rounded-2xl border border-line bg-abyss/80 px-4 py-2 text-sm text-muted">Back</button>
              <button
                type="button"
                disabled={blocked || !canStartProcessing}
                onClick={() => startMutation.mutate()}
                className="rounded-2xl bg-accent px-4 py-2 text-sm font-semibold text-abyss disabled:opacity-50"
              >
                {startMutation.isPending ? "Starting..." : processingMode === "skip" && !hasMemoryEvidence ? "Save Evidence" : "Start Processing"}
              </button>
            </div>
          </section>
        ) : null}

        {step === 6 && preparationEvidence ? (
          <section className="mt-5" data-testid="memory-evidence-preparation-step">
            <h2 className="text-xl font-semibold text-ink">Evidence registered</h2>
            <p className="mt-1 text-sm text-muted">
              {preparationEvidence.original_filename} was registered as memory evidence. Kairon's current preparation
              status for this evidence is shown below.
            </p>

            <MemoryEvidencePreparationCard caseId={caseId} evidenceId={preparationEvidence.id} />

            {/* Phase 3A golden path: once Memory Preparation is ready, this
                is the primary action -- Continue below drops to a secondary
                escape hatch (still functional, never removed) rather than
                letting the wizard hand off to MemoryEvidencePage without
                ever having offered to start the initial analysis. */}
            <label className="mt-5 flex items-start gap-2 text-xs text-muted" data-testid="memory-full-analysis-toggle">
              <input
                type="checkbox"
                checked={runFullMemoryAnalysis}
                onChange={(event) => setRunFullMemoryAnalysis(event.target.checked)}
                className="mt-0.5"
              />
              <span>
                <span className="font-semibold text-ink">Run the full memory analysis</span>
                <br />
                Runs every applicable profile (processes, network, suspicious regions, handles, modules, drivers).
                Uncheck to run the initial process analysis only and choose the rest yourself later.
              </span>
            </label>

            <MemoryInitialAnalysisAction
              caseId={caseId}
              evidenceId={preparationEvidence.id}
              onBeforeNavigateToResults={handleClose}
              runFullAnalysis={runFullMemoryAnalysis}
            />

            <div className="mt-5 flex justify-end">
              <button
                type="button"
                onClick={handleContinueFromPreparation}
                className={
                  readyForInitialAnalysis
                    ? "rounded-2xl border border-line bg-abyss/70 px-4 py-2 text-sm text-muted"
                    : "rounded-2xl bg-accent px-4 py-2 text-sm font-semibold text-abyss"
                }
                data-testid="memory-preparation-continue-button"
              >
                Continue
              </button>
            </div>
          </section>
        ) : null}

      </div>
    </div>
  );
}
