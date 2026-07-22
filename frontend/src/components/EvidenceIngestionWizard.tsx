import { useEffect, useMemo, useRef, useState } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { useNavigate } from "react-router-dom";

import { api, type Evidence, type EvidencePlatform, type EvidenceUploadSessionCreateResponse, type EvidenceUploadSessionRead, type MemoryUploadStatus, type PreflightReport, type ResumableUploadSessionRead } from "../api/client";
import { useNotifications } from "../context/NotificationsContext";
import { DEFAULT_CHUNK_SIZE, runResumableUpload } from "../features/memory/runResumableUpload";
import { platformUploadOptions } from "../lib/platformRegistry";

type IntakeType = "disk_image" | "memory_dump" | "artifact_collection" | "folder" | "server_path";
type WizardStep = 0 | 1 | 2 | 3 | 4 | 5 | 6;
type ProcessingMode = "recommended" | "custom" | "skip";
type HostChoice = "auto" | "__create__" | "__unassigned__" | string;
type InspectionState = "idle" | "uploading" | "finalizing_upload" | "preflight_running" | "complete" | "failed";

const TOTAL_STEPS = 7;
const CREATE_HOST_CHOICE = "__create__";
const UNASSIGNED_HOST_CHOICE = "__unassigned__";

type Props = {
  open: boolean;
  caseId: string;
  resumeSessionId?: string;
  resumeCandidate?: ResumableUploadSessionRead | null;
  onClose: () => void;
};

const INTAKE_CARDS: { id: IntakeType; icon: string; title: string; examples: string }[] = [
  { id: "disk_image", icon: "\u{1F5B4}", title: "Disk Image", examples: "RAW, DD, IMG, E01, Ex01, QCOW2, VMDK..." },
  { id: "memory_dump", icon: "\u{1F4BE}", title: "Memory Dump", examples: "WinPmem, Lime, RAW memory..." },
  { id: "artifact_collection", icon: "\u{1F4E6}", title: "Artifact Collection", examples: "KAPE, Velociraptor, manual ZIP" },
  { id: "folder", icon: "\u{1F4C1}", title: "Folder", examples: "Directory containing artifacts" },
  { id: "server_path", icon: "\u{2601}", title: "Existing Server Path", examples: "Already stored locally" },
];

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
  return { ...report, evidence_options: maybeReport.evidence_options ?? [] };
}

function normalizeHostLabel(value: string | null | undefined): string {
  return String(value ?? "").trim().replace(/\.+$/, "").toLowerCase();
}

function inspectionStateLabel(state: InspectionState, options: { isServerPath: boolean }): string {
  switch (state) {
    case "uploading":
      return "Uploading evidence to staging storage";
    case "finalizing_upload":
      return "Finalizing staged upload";
    case "preflight_running":
      return options.isServerPath ? "Inspecting server path" : "Inspecting staged evidence";
    case "complete":
      return "Inspection complete";
    case "failed":
      return "Inspection failed";
    default:
      return "Ready for inspection";
  }
}

function inspectionErrorMessage(error: unknown): string {
  if (error instanceof Error) return error.message;
  return "Kairon could not inspect this evidence.";
}

async function sha256Hex(blob: Blob): Promise<string | undefined> {
  try {
    if (typeof globalThis.crypto?.subtle?.digest !== "function") return undefined;
    const digest = await globalThis.crypto.subtle.digest("SHA-256", await blob.arrayBuffer());
    return Array.from(new Uint8Array(digest), (value) => value.toString(16).padStart(2, "0")).join("");
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

export default function EvidenceIngestionWizard({ open, caseId, resumeSessionId, resumeCandidate: resumeCandidateProp, onClose }: Props) {
  const navigate = useNavigate();
  const queryClient = useQueryClient();
  const { notify } = useNotifications();

  const [step, setStep] = useState<WizardStep>(0);
  const [intakeType, setIntakeType] = useState<IntakeType | null>(null);
  const [platform, setPlatform] = useState<EvidencePlatform>("auto");
  const [hostChoice, setHostChoice] = useState<HostChoice>("auto");
  const [newHostName, setNewHostName] = useState("");
  const [hostSearch, setHostSearch] = useState("");
  const [files, setFiles] = useState<File[]>([]);
  const [serverPath, setServerPath] = useState("");
  const [session, setSession] = useState<EvidenceUploadSessionRead | null>(null);
  const [preflight, setPreflight] = useState<PreflightReport | null>(null);
  const [manualOverrideAccepted, setManualOverrideAccepted] = useState(false);
  const [memoryAuthorizationAcknowledged, setMemoryAuthorizationAcknowledged] = useState(false);
  const [advancedOpen, setAdvancedOpen] = useState(false);
  const [processingMode, setProcessingMode] = useState<ProcessingMode>("recommended");
  const [labels, setLabels] = useState("");
  const [notes, setNotes] = useState("");
  const [hashProgress, setHashProgress] = useState<number | null>(null);
  const [clientSha256, setClientSha256] = useState<string | null>(null);
  const [inspectionState, setInspectionState] = useState<InspectionState>("idle");
  const [inspectionError, setInspectionError] = useState<string | null>(null);
  const [uploadProgress, setUploadProgress] = useState<number | null>(null);
  const [inspectionStartedAt, setInspectionStartedAt] = useState<number | null>(null);
  const [nowMs, setNowMs] = useState(Date.now());
  const promotedRef = useRef(false);
  const promotedEvidenceRef = useRef<Evidence | null>(null);
  const [resumeTarget, setResumeTarget] = useState<ResumableUploadSessionRead | null>(null);
  const [resumeFile, setResumeFile] = useState<File | null>(null);
  const [resumeFileError, setResumeFileError] = useState<string | null>(null);
  const [resumeVerifying, setResumeVerifying] = useState(false);

  const requiresPathInput = intakeType === "server_path";
  const requiresFolderInput = intakeType === "folder";

  const caseHostsQuery = useQuery({ queryKey: ["case-hosts", caseId], queryFn: () => api.getCaseHosts(caseId), enabled: open && Boolean(caseId), staleTime: 15_000 });
  const caseHosts = caseHostsQuery.data?.hosts ?? [];

  const healthQuery = useQuery({
    queryKey: ["ingestion-readiness", caseId],
    queryFn: () => api.getIngestionReadiness(caseId),
    enabled: open && Boolean(caseId),
    staleTime: 10_000,
  });
  const unifiedMemoryDumpEnabled = Boolean(healthQuery.data?.unified_upload_evidence_memory_dump);
  const useUnifiedMemoryDump = intakeType === "memory_dump" && unifiedMemoryDumpEnabled;
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

  function reset() {
    setStep(0);
    setIntakeType(null);
    setPlatform("auto");
    setHostChoice("auto");
    setNewHostName("");
    setHostSearch("");
    setFiles([]);
    setServerPath("");
    setSession(null);
    setPreflight(null);
    setManualOverrideAccepted(false);
    setMemoryAuthorizationAcknowledged(false);
    setAdvancedOpen(false);
    setProcessingMode("recommended");
    setLabels("");
    setNotes("");
    setHashProgress(null);
    setClientSha256(null);
    setInspectionState("idle");
    setInspectionError(null);
    setUploadProgress(null);
    setInspectionStartedAt(null);
    setNowMs(Date.now());
    promotedRef.current = false;
    promotedEvidenceRef.current = null;
    setResumeTarget(null);
    setResumeFile(null);
    setResumeFileError(null);
    setResumeVerifying(false);
  }

  function handleClose() {
    reset();
    onClose();
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
        finalizedResponse = await api.finalizeResumableEvidenceUploadSession(caseId, activeSession.id);
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

  // Feature-flagged (UNIFIED_UPLOAD_EVIDENCE_MEMORY_DUMP): routes the actual
  // byte transfer through the same chunk-index protocol, concurrency, and
  // finalize lifecycle Memory Overview uses (see runResumableUpload and
  // app.services.evidence_unified_memory on the backend), instead of the
  // legacy sequential PUT .../bytes?offset=N endpoint. Host and
  // authorization are collected up front (step 3, before this runs) so
  // finalize can register the Evidence immediately once the transfer
  // completes -- there is no separate "Start Processing" step for this path.
  // Shared by both a fresh unified upload and a resumed one: the transfer
  // itself, finalize, and post-finalize evidence lookup are identical
  // either way, since runResumableUpload() re-derives the missing-chunk set
  // from the server's authoritative status on every call -- a "resume" is
  // just calling this against a memory_upload_id that already has some
  // chunks landed, nothing else differs.
  async function runUnifiedMemoryDumpTransfer(
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

  async function uploadUnifiedMemoryDump(file: File, onProgress: (progress: { loaded: number; total: number; lengthComputable: boolean }) => void): Promise<{ evidence: Evidence }> {
    const hostAssignment = await resolveHostAssignment();
    const declaredPlatform = platform === "auto" ? undefined : platform;
    const created = await api.createResumableEvidenceUploadSession(caseId, {
      filename: file.name,
      expected_size_bytes: file.size,
      declared_platform: declaredPlatform,
      client_sha256: clientSha256 ?? undefined,
      intake_category: "memory_dump",
      host_id: hostAssignment.host_id,
      provided_host: hostAssignment.provided_host,
      memory_authorization_acknowledged: memoryAuthorizationAcknowledged,
      notes: notes.trim() || undefined,
    });
    if (!created.unified) {
      throw new Error("Kairon could not start a unified memory upload session for this file.");
    }
    setSession(created.session);
    setInspectionState("uploading");
    return runUnifiedMemoryDumpTransfer(created.session.id, created.unified, file, onProgress);
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
      if (digest !== unified.verification_chunk_sha256) {
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
          return runUnifiedMemoryDumpTransfer(target.id, target.unified, file, onResumeProgress);
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
      if (useUnifiedMemoryDump && !requiresFolderInput && files.length === 1) {
        return uploadUnifiedMemoryDump(files[0], onProgress);
      }
      if (!requiresFolderInput && files.length === 1) {
        return uploadSingleFileResumable(files[0], onProgress);
      }
      if (requiresFolderInput || files.length > 1) {
        return api.createEvidenceUploadSession(caseId, { files, folderUpload: requiresFolderInput }, { declaredPlatform: platform, onProgress });
      }
      return api.createEvidenceUploadSession(caseId, { file: files[0] }, { declaredPlatform: platform, clientSha256: clientSha256 ?? undefined, onProgress });
    },
    onSuccess: (response) => {
      if ("evidence" in response) {
        const { evidence } = response;
        setUploadProgress(1);
        setInspectionState("complete");
        setInspectionError(null);
        notify({ title: "Memory evidence registered", description: `${evidence.original_filename} was uploaded and registered.`, tone: "success" });
        void queryClient.invalidateQueries({ queryKey: ["case-processing", caseId] });
        void queryClient.invalidateQueries({ queryKey: ["evidences", caseId] });
        void queryClient.invalidateQueries({ queryKey: ["resumable-evidence-uploads", caseId] });
        handleClose();
        navigate(`/cases/${caseId}/memory/${evidence.id}`);
        return;
      }
      const preflightReport = normalizePreflightReport(response.preflight);
      setSession(response.session);
      setPreflight(preflightReport);
      setUploadProgress(response.session.is_server_path ? null : 1);
      setInspectionState("complete");
      setInspectionError(null);
      setStep(5);
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
      navigate(target.category === "memory_dump" ? `/cases/${caseId}/memory/${target.promoted_evidence_id}` : `/evidences/${target.promoted_evidence_id}`);
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

  async function resolveHostAssignment(): Promise<{ host_id?: string; provided_host?: string }> {
    if (hostChoice === UNASSIGNED_HOST_CHOICE) return {};
    if (hostChoice === "auto") {
      if (!detectedHostname) return {};
      if (detectedHostMatches.length === 1) return { host_id: detectedHostMatches[0].id };
      if (detectedHostMatches.length > 1) throw new Error("Multiple hosts match the detected hostname. Select the correct host before indexing.");
      return { provided_host: detectedHostname };
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
      if (!session) throw new Error("No upload session is active");
      let evidence = promotedEvidenceRef.current;
      if (!evidence) {
        const hostAssignment = await resolveHostAssignment();
        const declaredPlatform = platform === "auto" ? undefined : platform;
        evidence = await api.promoteEvidenceUploadSession(caseId, session.id, {
          provided_platform: declaredPlatform,
          host_id: hostAssignment.host_id,
          provided_host: hostAssignment.provided_host,
          memory_authorization_acknowledged: intakeType === "memory_dump" ? memoryAuthorizationAcknowledged : undefined,
          labels: labels.split(",").map((label) => label.trim()).filter(Boolean),
          notes: notes.trim() || undefined,
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
      handleClose();
      if (evidence.evidence_type === "memory_dump") {
        navigate(`/cases/${caseId}/memory/${evidence.id}`);
        return;
      }
      navigate(`/cases/${caseId}?tab=processing&evidence_id=${evidence.id}`);
    },
    onError: (error) => {
      notify({ title: "Could not start processing", description: error instanceof Error ? error.message : "The evidence could not be queued for processing.", tone: "error" });
    },
  });

  const blocked = preflight?.status === "blocked" && !manualOverrideAccepted;
  const memoryRequiresExplicitHost = intakeType === "memory_dump";
  const hostStepBlockingReason = useMemo(() => {
    if (!memoryRequiresExplicitHost) return null;
    if (hostChoice === CREATE_HOST_CHOICE) {
      if (!newHostName.trim()) return "Enter a source host name for this memory evidence.";
    } else if (hostChoice === "auto") {
      return "Memory evidence requires an explicit source host, matching the legacy memory uploader.";
    }
    if (useUnifiedMemoryDump && !memoryAuthorizationAcknowledged) {
      return "Confirm you are authorized to handle this RAM evidence before continuing.";
    }
    return null;
  }, [hostChoice, memoryAuthorizationAcknowledged, memoryRequiresExplicitHost, newHostName, useUnifiedMemoryDump]);
  const canContinueHostStep = hostStepBlockingReason === null;

  const canAdvanceStep4 = useMemo(() => {
    if (requiresPathInput) return serverPath.trim().length > 0;
    return files.length > 0;
  }, [requiresPathInput, serverPath, files]);

  const hashPending = files.length === 1 && !requiresPathInput && hashProgress !== null && hashProgress < 1;
  const inspectionElapsedSeconds = inspectionStartedAt ? Math.max(0, Math.floor((nowMs - inspectionStartedAt) / 1000)) : 0;
  const inspectionLabel = inspectionStateLabel(inspectionState, { isServerPath: requiresPathInput });

  const hostAssignmentRequired = intakeType === "memory_dump" || processingMode !== "skip";
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
  const canStartProcessing = !startMutation.isPending && !(intakeType === "memory_dump" && !memoryAuthorizationAcknowledged) && hostAssignmentBlockingReason === null;
  const selectedHostName = hostChoice !== "auto" && hostChoice !== CREATE_HOST_CHOICE && hostChoice !== UNASSIGNED_HOST_CHOICE
    ? caseHosts.find((h) => h.id === hostChoice)?.display_name || "Selected host"
    : null;

  if (!open) return null;

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/70 p-4" role="dialog" aria-modal="true" aria-label="Add Evidence">
      <div className="w-full max-w-3xl max-h-[90vh] overflow-y-auto rounded-[28px] border border-line bg-panel p-6 shadow-panel">
        <div className="flex items-center justify-between">
          <p className="font-mono text-xs uppercase tracking-[0.24em] text-accent">Add Evidence &middot; Step {step + 1} of {TOTAL_STEPS}</p>
          <button type="button" onClick={handleClose} className="rounded-xl border border-line px-3 py-2 text-xs text-muted">Cancel</button>
        </div>

        {step === 0 ? (
          <section className="mt-5" data-testid="health-check">
            <h2 className="text-xl font-semibold text-ink">Server Health Check</h2>
            <p className="mt-1 text-sm text-muted">Kairon checks its core dependencies before you start adding evidence.</p>
            {healthQuery.isLoading ? (
              <p className="mt-4 text-sm text-muted">Checking system health...</p>
            ) : healthQuery.data ? (
              <>
                <div className="mt-4 space-y-2">
                  {healthQuery.data.checks.map((check) => (
                    <p key={check.label} className={`text-sm ${check.ok ? "text-mint" : "text-danger"}`}>
                      {check.ok ? "✔" : "⚠"} {check.label}: {check.detail}
                    </p>
                  ))}
                </div>
                <div className="mt-4 grid gap-2 text-sm text-muted sm:grid-cols-2">
                  <p>Available disk space: <span className="text-ink">{bytes(healthQuery.data.available_disk_space_bytes)}</span></p>
                  <p>Configured upload limit: <span className="text-ink">{bytes(healthQuery.data.configured_upload_limit_bytes)}</span></p>
                  <p>Configured extraction limit: <span className="text-ink">{bytes(healthQuery.data.configured_extraction_limit_bytes)}</span></p>
                </div>
                {!healthQuery.data.critical_ready ? (
                  <p className="mt-4 text-sm font-semibold text-danger">Processing cannot begin: Storage and Database must both be reachable.</p>
                ) : !healthQuery.data.ready ? (
                  <p className="mt-4 text-sm text-amber">Some non-critical dependencies (search or workers) are unavailable. You can continue, but processing may be delayed until they recover.</p>
                ) : (
                  <p className="mt-4 text-sm font-semibold text-mint">All systems ready</p>
                )}
              </>
            ) : (
              <p className="mt-4 text-sm text-danger">Kairon could not reach its own health check endpoint.</p>
            )}
            <div className="mt-5 flex justify-between">
              <button type="button" onClick={() => healthQuery.refetch()} className="rounded-2xl border border-line bg-abyss/80 px-4 py-2 text-sm text-muted">Recheck</button>
              <button
                type="button"
                disabled={!healthQuery.data?.critical_ready}
                onClick={() => setStep(1)}
                className="rounded-2xl bg-accent px-4 py-2 text-sm font-semibold text-abyss disabled:opacity-50"
              >
                Continue
              </button>
            </div>
          </section>
        ) : null}

        {step === 1 ? (
          <section className="mt-5">
            {resumableSessions.length ? (
              <div className="mb-6 rounded-3xl border border-amber-400/30 bg-amber-400/5 p-4" data-testid="resumable-uploads-panel">
                <p className="font-mono text-xs uppercase tracking-[0.16em] text-amber-300">Interrupted or active uploads</p>
                <div className="mt-3 space-y-2">
                  {resumableSessions.map((candidate) => (
                    <div key={candidate.id} className="flex flex-wrap items-center justify-between gap-3 rounded-2xl border border-line bg-abyss/60 p-3" data-testid="resumable-upload-row">
                      <div className="min-w-0">
                        <p className="truncate text-sm font-semibold text-ink">{candidate.original_filename}</p>
                        <p className="mt-0.5 text-xs text-muted">
                          {candidate.category ?? "evidence"} &middot; {candidate.status}
                          {candidate.progress_percent !== null ? ` · ${candidate.progress_percent.toFixed(0)}%` : ""}
                        </p>
                      </div>
                      <div className="flex shrink-0 gap-2">
                        {candidate.status === "promoted" && candidate.promoted_evidence_id ? (
                          <button type="button" onClick={() => { handleClose(); navigate(candidate.category === "memory_dump" ? `/cases/${caseId}/memory/${candidate.promoted_evidence_id}` : `/evidences/${candidate.promoted_evidence_id}`); }} className="rounded-xl bg-accent px-3 py-1.5 text-xs font-semibold text-abyss">Open evidence</button>
                        ) : candidate.resumable || candidate.status === "staged" ? (
                          <button type="button" onClick={() => setResumeTarget(candidate)} className="rounded-xl bg-accent px-3 py-1.5 text-xs font-semibold text-abyss" data-testid="resume-upload-select">Resume</button>
                        ) : null}
                        {candidate.cancellable ? (
                          <button
                            type="button"
                            disabled={cancelResumableMutation.isPending}
                            onClick={() => cancelResumableMutation.mutate(candidate.id)}
                            className="rounded-xl border border-line px-3 py-1.5 text-xs text-muted"
                          >
                            Cancel
                          </button>
                        ) : null}
                      </div>
                    </div>
                  ))}
                </div>
              </div>
            ) : null}
            <h2 className="text-xl font-semibold text-ink">What are you adding?</h2>
            <div className="mt-4 grid gap-3 sm:grid-cols-2">
              {INTAKE_CARDS.map((card) => (
                <button
                  key={card.id}
                  type="button"
                  onClick={() => { setIntakeType(card.id); setStep(2); }}
                  className="rounded-2xl border border-line bg-abyss/60 p-4 text-left transition hover:border-accent/50"
                >
                  <p className="text-2xl">{card.icon}</p>
                  <p className="mt-2 font-semibold text-ink">{card.title}</p>
                  <p className="mt-1 text-xs text-muted">{card.examples}</p>
                </button>
              ))}
            </div>
          </section>
        ) : null}

        {step === 2 ? (
          <section className="mt-5">
            <h2 className="text-xl font-semibold text-ink">Platform</h2>
            <p className="mt-1 text-sm text-muted">Auto Detect is recommended &mdash; Kairon classifies the platform from the evidence itself during the next step.</p>
            <div className="mt-4 grid gap-3">
              {platformUploadOptions().map((option) => (
                <button
                  key={option.id}
                  type="button"
                  disabled={option.disabled}
                  onClick={() => setPlatform(option.id as EvidencePlatform)}
                  className={`rounded-2xl border p-4 text-left transition disabled:cursor-not-allowed disabled:opacity-50 ${platform === option.id ? "border-accent bg-accent/10" : "border-line bg-abyss/60 hover:border-accent/40"}`}
                >
                  <p className="font-semibold text-ink">{option.label}{option.id === "auto" ? " (Recommended)" : ""}</p>
                  <p className="mt-1 text-xs text-muted">{option.description}</p>
                </button>
              ))}
            </div>
            <div className="mt-5 flex justify-between">
              <button type="button" onClick={() => setStep(1)} className="rounded-2xl border border-line bg-abyss/80 px-4 py-2 text-sm text-muted">Back</button>
              <button type="button" onClick={() => setStep(3)} className="rounded-2xl bg-accent px-4 py-2 text-sm font-semibold text-abyss">Continue</button>
            </div>
          </section>
        ) : null}

        {step === 3 ? (
          <section className="mt-5">
            <h2 className="text-xl font-semibold text-ink">Host</h2>
            <p className="mt-1 text-sm text-muted">
              {memoryRequiresExplicitHost
                ? "Memory evidence follows the legacy uploader contract and requires an explicit source host."
                : "Auto Assign lets Kairon match or create a host once the evidence is inspected."}
            </p>
            <div className="mt-4 grid gap-3">
              {!memoryRequiresExplicitHost ? (
                <label className={`rounded-2xl border p-4 ${hostChoice === "auto" ? "border-accent bg-accent/10" : "border-line bg-abyss/60"}`}>
                  <input type="radio" name="host-choice" className="mr-2" checked={hostChoice === "auto"} onChange={() => setHostChoice("auto")} />
                  Auto Assign
                </label>
              ) : null}
              <label className={`rounded-2xl border p-4 ${hostChoice !== "auto" && hostChoice !== CREATE_HOST_CHOICE && hostChoice !== UNASSIGNED_HOST_CHOICE ? "border-accent bg-accent/10" : "border-line bg-abyss/60"}`}>
                <input type="radio" name="host-choice" className="mr-2" checked={hostChoice !== "auto" && hostChoice !== CREATE_HOST_CHOICE && hostChoice !== UNASSIGNED_HOST_CHOICE} onChange={() => setHostChoice(caseHosts[0]?.id ?? "auto")} disabled={!caseHosts.length} />
                Assign existing host
                {hostChoice !== "auto" && hostChoice !== CREATE_HOST_CHOICE && hostChoice !== UNASSIGNED_HOST_CHOICE ? (
                  <select value={hostChoice} onChange={(event) => setHostChoice(event.target.value)} className="mt-3 w-full rounded-2xl border border-line bg-abyss/80 px-4 py-3 text-sm text-ink">
                    {caseHosts.map((host) => <option key={host.id} value={host.id}>{host.display_name}</option>)}
                  </select>
                ) : null}
              </label>
              <label className={`rounded-2xl border p-4 ${hostChoice === CREATE_HOST_CHOICE ? "border-accent bg-accent/10" : "border-line bg-abyss/60"}`}>
                <input type="radio" name="host-choice" className="mr-2" checked={hostChoice === CREATE_HOST_CHOICE} onChange={() => setHostChoice(CREATE_HOST_CHOICE)} />
                Create new host
                {hostChoice === CREATE_HOST_CHOICE ? (
                  <input value={newHostName} onChange={(event) => setNewHostName(event.target.value)} placeholder="WS-01" className="mt-3 w-full rounded-2xl border border-line bg-abyss/80 px-4 py-3 text-sm text-ink" />
                ) : null}
              </label>
            </div>
            {memoryRequiresExplicitHost ? (
              <p className="mt-3 rounded-2xl border border-amber-400/30 bg-amber-400/10 px-4 py-3 text-sm text-amber-100" data-testid="memory-host-required-message">
                Memory uploads require a source host before registration. Select an existing host or create one before continuing.
              </p>
            ) : null}
            {useUnifiedMemoryDump ? (
              <div className="mt-4 space-y-3 rounded-2xl border border-line bg-abyss/60 p-4">
                <label className="flex items-start gap-2 text-sm text-ink">
                  <input type="checkbox" className="mt-1" checked={memoryAuthorizationAcknowledged} onChange={(event) => setMemoryAuthorizationAcknowledged(event.target.checked)} data-testid="unified-memory-authorization-checkbox" />
                  I am authorized to handle this RAM evidence and understand it may contain highly sensitive data.
                </label>
                <label className="block text-xs text-muted">
                  Evidence notes (optional)
                  <textarea value={notes} onChange={(event) => setNotes(event.target.value)} className="mt-1 h-16 w-full rounded-2xl border border-line bg-abyss/80 px-4 py-2 text-sm text-ink" />
                </label>
              </div>
            ) : null}
            <div className="mt-5 flex justify-between">
              <button type="button" onClick={() => setStep(2)} className="rounded-2xl border border-line bg-abyss/80 px-4 py-2 text-sm text-muted">Back</button>
              <button type="button" onClick={() => setStep(4)} disabled={!canContinueHostStep} title={hostStepBlockingReason ?? undefined} className="rounded-2xl bg-accent px-4 py-2 text-sm font-semibold text-abyss disabled:opacity-50">Continue</button>
            </div>
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
                onClick={() => { setResumeTarget(null); setResumeFile(null); setResumeFileError(null); setStep(1); }}
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

        {step === 4 && !resumeTarget ? (
          <section className="mt-5">
            <h2 className="text-xl font-semibold text-ink">Choose evidence</h2>
            {requiresPathInput ? (
              <label className="mt-4 block text-sm text-muted">
                Server path
                <input value={serverPath} onChange={(event) => setServerPath(event.target.value)} placeholder="/mnt/evidence/case-001/disk.E01" className="mt-2 w-full rounded-2xl border border-line bg-abyss/80 px-4 py-3 text-sm text-ink" />
              </label>
            ) : (
              <label className="mt-4 flex flex-col gap-2 rounded-2xl border border-dashed border-line bg-abyss/60 p-6 text-sm text-muted">
                <span>{requiresFolderInput ? "Select a folder" : "Select a file"}</span>
                <input
                  type="file"
                  multiple={requiresFolderInput || intakeType === "disk_image"}
                  {...(requiresFolderInput ? { webkitdirectory: "true", directory: "true" } : {})}
                  onChange={(event) => setFiles(Array.from(event.target.files ?? []))}
                />
                {files.length ? <span className="text-xs text-ink">{files.length === 1 ? files[0].name : `${files.length} files selected`}</span> : null}
                {files.length === 1 && !requiresPathInput ? (
                  hashProgress === null ? null : hashProgress < 1 ? (
                    <span className="text-xs text-muted" data-testid="sha256-progress">Calculating SHA-256... {Math.round(hashProgress * 100)}%</span>
                  ) : (
                    <span className="text-xs text-mint" data-testid="sha256-ready">SHA-256: {clientSha256}</span>
                  )
                ) : null}
              </label>
            )}
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
                    {!requiresPathInput ? (
                      <p className={`rounded-xl border px-3 py-2 ${inspectionState === "finalizing_upload" ? "border-accent/30 bg-accent/10 text-accent" : uploadProgress === 1 ? "border-mint/30 bg-mint/10 text-mint" : "border-line text-muted"}`}>
                        {inspectionState === "finalizing_upload" ? "Active:" : uploadProgress === 1 ? "Done:" : "Queued:"} Finalizing upload on the server
                      </p>
                    ) : null}
                    <p className={`rounded-xl border px-3 py-2 ${inspectionState === "preflight_running" ? "border-accent/30 bg-accent/10 text-accent" : "border-line text-muted"}`}>
                      {inspectionState === "preflight_running" ? "Active:" : "Queued:"} Scanning contents, detecting platform, discovering hosts, and estimating processing
                    </p>
                    <p className="text-xs text-muted">Kairon is staging the evidence, then running a read-only preflight. Large archives or disk images can take longer while metadata and candidate artifacts are inspected.</p>
                  </div>
                )}
              </div>
            ) : null}
            <div className="mt-5 flex justify-between">
              <button type="button" onClick={() => setStep(3)} className="rounded-2xl border border-line bg-abyss/80 px-4 py-2 text-sm text-muted">Back</button>
              <button
                type="button"
                disabled={!canAdvanceStep4 || createSessionMutation.isPending || hashPending}
                onClick={() => createSessionMutation.mutate()}
                className="rounded-2xl bg-accent px-4 py-2 text-sm font-semibold text-abyss disabled:opacity-50"
              >
                {createSessionMutation.isPending ? inspectionLabel : hashPending ? "Calculating SHA-256..." : "Inspect evidence"}
              </button>
            </div>
          </section>
        ) : null}

        {step === 5 && preflight ? (
          <section className="mt-5" data-testid="preflight-report">
            <h2 className="text-xl font-semibold text-ink">Preflight Inspection</h2>

            {session?.client_sha256_mismatch ? (
              <p className="mt-3 rounded-2xl border border-amber/40 bg-amber/10 p-3 text-xs text-amber" data-testid="hash-mismatch-warning">
                The SHA-256 computed in your browser does not match what Kairon staged on the server. The file may have changed during upload &mdash; consider re-selecting it before continuing.
              </p>
            ) : null}

            <div className="mt-4 rounded-2xl border border-line bg-abyss/60 p-4">
              <p className="font-mono text-[11px] uppercase tracking-[0.16em] text-accent">Evidence Classification</p>
              <p className="mt-2 text-sm text-ink">{[...preflight.classification.chain, preflight.classification.platform !== "unknown" ? preflight.classification.platform : null].filter(Boolean).join(" → ")}</p>
              <div className="mt-3 grid gap-2 text-sm text-muted sm:grid-cols-2">
                <p>Evidence type: <span className="text-ink">{preflight.classification.category}</span></p>
                {preflight.classification.container ? <p>Container: <span className="text-ink">{preflight.classification.container}</span></p> : null}
                {preflight.classification.contained_object ? <p>Contained object: <span className="text-ink">{preflight.classification.contained_object}</span></p> : null}
                {preflight.classification.hostname ? <p>Hostname: <span className="text-ink">{preflight.classification.hostname}</span></p> : null}
                {preflight.classification.distro ? <p>Distribution: <span className="text-ink">{preflight.classification.distro}{preflight.classification.version ? ` (${preflight.classification.version})` : ""}</span></p> : null}
                {preflight.classification.volumes !== null ? <p>Volumes: <span className="text-ink">{preflight.classification.volumes}</span></p> : null}
                {preflight.classification.partitions !== null ? <p>Partitions: <span className="text-ink">{preflight.classification.partitions}</span></p> : null}
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
            ) : (
              <p className="mt-4 text-sm font-semibold text-mint">Ready to process</p>
            )}

            <details className="mt-4 rounded-2xl border border-line bg-abyss/50 p-4" open={advancedOpen} onToggle={(event) => setAdvancedOpen((event.target as HTMLDetailsElement).open)}>
              <summary className="cursor-pointer text-xs uppercase tracking-[0.16em] text-muted">Advanced options</summary>
              <div className="mt-3 grid gap-3">
                <label className="text-xs text-muted">Labels<input value={labels} onChange={(event) => setLabels(event.target.value)} placeholder="comma, separated, labels" className="mt-1 w-full rounded-2xl border border-line bg-abyss/80 px-4 py-2 text-sm text-ink" /></label>
                <label className="text-xs text-muted">Evidence notes<textarea value={notes} onChange={(event) => setNotes(event.target.value)} className="mt-1 h-20 w-full rounded-2xl border border-line bg-abyss/80 px-4 py-2 text-sm text-ink" /></label>
              </div>
            </details>

            <div className="mt-5 flex justify-between">
              <button type="button" onClick={() => setStep(4)} className="rounded-2xl border border-line bg-abyss/80 px-4 py-2 text-sm text-muted">Back</button>
              <button
                type="button"
                disabled={blocked}
                onClick={() => setStep(6)}
                className="rounded-2xl bg-accent px-4 py-2 text-sm font-semibold text-abyss disabled:opacity-50"
              >
                Continue
              </button>
            </div>
          </section>
        ) : null}

        {step === 6 && preflight ? (
          <section className="mt-5">
            <h2 className="text-xl font-semibold text-ink">Confirmation</h2>
            <div className="mt-4 rounded-2xl border border-line bg-abyss/60 p-4 text-sm text-muted">
              <p>Evidence: <span className="text-ink">{preflight.original_filename}</span></p>
              <p className="mt-1">Platform: <span className="text-ink">{platform === "auto" ? `Auto Detect (${preflight.classification.platform})` : platform}</span></p>
              <p className="mt-1">Pipeline: <span className="text-ink">{preflight.pipeline_preview.join(" → ")}</span></p>
              <p className="mt-1">Estimated duration: <span className="text-ink">{durationBucketLabel(preflight.resource_check.estimated_duration_bucket) ?? "unknown"}</span></p>
            </div>
            <div className="mt-4 rounded-2xl border border-line bg-abyss/60 p-4" data-testid="host-assignment-panel">
              <h3 className="text-sm font-semibold text-ink">Host Assignment</h3>
              {detectedHostname ? (
                <div className="mt-3 rounded-2xl border border-mint/30 bg-mint/10 p-3 text-sm text-mint" data-testid="detected-hostname">
                  <p className="font-semibold">&#10003; Detected hostname</p>
                  <p className="mt-1 text-ink">{detectedHostname}</p>
                </div>
              ) : (
                <p className="mt-3 rounded-2xl border border-amber/30 bg-amber/10 p-3 text-sm text-amber" data-testid="missing-hostname">
                  No reliable hostname was detected. Choose an existing host or create a new one before indexing.
                </p>
              )}
              {detectedHostname && detectedHostMatches.length === 0 ? (
                <p className="mt-3 text-sm text-muted">No existing host matches this hostname. Kairon can create it during evidence registration.</p>
              ) : null}
              {detectedHostname && detectedHostMatches.length > 1 ? (
                <p className="mt-3 rounded-2xl border border-amber/30 bg-amber/10 p-3 text-sm text-amber" data-testid="multiple-host-matches">
                  Multiple hosts match this hostname. Select the correct host before indexing.
                </p>
              ) : null}
              <div className="mt-4 grid gap-3">
                {detectedHostname ? (
                  <label className={`rounded-2xl border p-3 text-sm ${hostChoice === "auto" ? "border-accent bg-accent/10 text-ink" : "border-line bg-abyss/70 text-muted"}`}>
                    <input type="radio" name="final-host-choice" className="mr-2" checked={hostChoice === "auto"} onChange={() => setHostChoice("auto")} disabled={detectedHostMatches.length > 1} />
                    {detectedHostMatches.length === 1 ? `Auto assign to ${detectedHostMatches[0].display_name}` : "Create host from detected hostname"}
                  </label>
                ) : null}
                <label className={`rounded-2xl border p-3 text-sm ${hostChoice !== "auto" && hostChoice !== CREATE_HOST_CHOICE && hostChoice !== UNASSIGNED_HOST_CHOICE ? "border-accent bg-accent/10 text-ink" : "border-line bg-abyss/70 text-muted"}`}>
                  <input type="radio" name="final-host-choice" className="mr-2" checked={hostChoice !== "auto" && hostChoice !== CREATE_HOST_CHOICE && hostChoice !== UNASSIGNED_HOST_CHOICE} onChange={() => setHostChoice(filteredCaseHosts[0]?.id ?? caseHosts[0]?.id ?? "auto")} disabled={!caseHosts.length} />
                  Assign to existing host
                  {hostChoice !== "auto" && hostChoice !== CREATE_HOST_CHOICE && hostChoice !== UNASSIGNED_HOST_CHOICE ? (
                    <>
                      <input value={hostSearch} onChange={(event) => setHostSearch(event.target.value)} placeholder="Search hosts" className="mt-3 w-full rounded-2xl border border-line bg-abyss/80 px-4 py-2 text-sm text-ink" />
                      <select value={hostChoice} onChange={(event) => setHostChoice(event.target.value)} className="mt-2 w-full rounded-2xl border border-line bg-abyss/80 px-4 py-3 text-sm text-ink">
                        {filteredCaseHosts.map((host) => <option key={host.id} value={host.id}>{host.display_name}</option>)}
                      </select>
                    </>
                  ) : null}
                </label>
                <label className={`rounded-2xl border p-3 text-sm ${hostChoice === CREATE_HOST_CHOICE ? "border-accent bg-accent/10 text-ink" : "border-line bg-abyss/70 text-muted"}`}>
                  <input type="radio" name="final-host-choice" className="mr-2" checked={hostChoice === CREATE_HOST_CHOICE} onChange={() => setHostChoice(CREATE_HOST_CHOICE)} />
                  Create new host
                  {hostChoice === CREATE_HOST_CHOICE ? (
                    <input value={newHostName} onChange={(event) => setNewHostName(event.target.value)} placeholder={detectedHostname || "WS-01"} className="mt-3 w-full rounded-2xl border border-line bg-abyss/80 px-4 py-3 text-sm text-ink" />
                  ) : null}
                </label>
                {processingMode === "skip" && intakeType !== "memory_dump" ? (
                  <label className={`rounded-2xl border p-3 text-sm ${hostChoice === UNASSIGNED_HOST_CHOICE ? "border-accent bg-accent/10 text-ink" : "border-line bg-abyss/70 text-muted"}`}>
                    <input type="radio" name="final-host-choice" className="mr-2" checked={hostChoice === UNASSIGNED_HOST_CHOICE} onChange={() => setHostChoice(UNASSIGNED_HOST_CHOICE)} />
                    Keep unassigned
                    <span className="mt-1 block text-xs text-muted">Host assignment can be completed later because indexing will not start now.</span>
                  </label>
                ) : null}
              </div>
              <p className="mt-3 text-sm text-muted">
                Assignment: <span className="text-ink">{hostChoice === "auto" ? detectedHostMatches.length === 1 ? detectedHostMatches[0].display_name : detectedHostname ? detectedHostname : "Needs host" : hostChoice === CREATE_HOST_CHOICE ? newHostName || "New host" : hostChoice === UNASSIGNED_HOST_CHOICE ? "Keep unassigned" : selectedHostName}</span>
              </p>
              {hostAssignmentBlockingReason ? <p className="mt-3 text-sm text-amber" data-testid="host-assignment-guidance">{hostAssignmentBlockingReason}</p> : null}
            </div>
            {intakeType !== "memory_dump" ? (
              <div className="mt-4 rounded-2xl border border-line bg-abyss/60 p-4">
                <h3 className="text-sm font-semibold text-ink">Processing</h3>
                <div className="mt-3 grid gap-3 md:grid-cols-3">
                  <label className={`rounded-2xl border p-3 text-sm ${processingMode === "recommended" ? "border-accent bg-accent/10 text-ink" : "border-line bg-abyss/70 text-muted"}`}>
                    <input type="radio" name="processing-mode" className="mr-2" checked={processingMode === "recommended"} onChange={() => setProcessingMode("recommended")} />
                    Recommended indexing
                    <span className="mt-1 block text-xs text-muted">Queue the default parsers for this evidence type.</span>
                  </label>
                  <label className={`rounded-2xl border p-3 text-sm ${processingMode === "custom" ? "border-accent bg-accent/10 text-ink" : "border-line bg-abyss/70 text-muted"}`}>
                    <input type="radio" name="processing-mode" className="mr-2" checked={processingMode === "custom"} onChange={() => setProcessingMode("custom")} />
                    Custom indexing
                    <span className="mt-1 block text-xs text-muted">Use the faster supported custom profile.</span>
                  </label>
                  <label className={`rounded-2xl border p-3 text-sm ${processingMode === "skip" ? "border-accent bg-accent/10 text-ink" : "border-line bg-abyss/70 text-muted"}`}>
                    <input type="radio" name="processing-mode" className="mr-2" checked={processingMode === "skip"} onChange={() => setProcessingMode("skip")} />
                    Save without indexing
                    <span className="mt-1 block text-xs text-muted">Add evidence now and start indexing later.</span>
                  </label>
                </div>
              </div>
            ) : null}
            {intakeType === "memory_dump" ? (
              <label className="mt-4 flex items-start gap-2 rounded-2xl border border-amber/40 bg-amber/10 p-4 text-sm text-ink">
                <input type="checkbox" className="mt-1" checked={memoryAuthorizationAcknowledged} onChange={(event) => setMemoryAuthorizationAcknowledged(event.target.checked)} />
                I am authorized to handle this RAM evidence and understand it may contain highly sensitive data.
              </label>
            ) : null}
            {startMutation.error instanceof Error ? <p className="mt-3 text-sm text-danger">{startMutation.error.message}</p> : null}
            <div className="mt-5 flex justify-between">
              <button type="button" onClick={() => setStep(5)} className="rounded-2xl border border-line bg-abyss/80 px-4 py-2 text-sm text-muted">Back</button>
              <button
                type="button"
                disabled={!canStartProcessing}
                onClick={() => startMutation.mutate()}
                className="rounded-2xl bg-accent px-4 py-2 text-sm font-semibold text-abyss disabled:opacity-50"
              >
                {startMutation.isPending ? "Starting..." : processingMode === "skip" && intakeType !== "memory_dump" ? "Save Evidence" : "Start Processing"}
              </button>
            </div>
          </section>
        ) : null}
      </div>
    </div>
  );
}
