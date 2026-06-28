import { useEffect, useMemo, useRef, useState } from "react";
import { useQuery } from "@tanstack/react-query";
import { Link, useNavigate, useParams } from "react-router-dom";

import {
  api,
  type Evidence,
  type MemoryUploadReadiness,
  type MemoryUploadStatus,
} from "../api/client";
import { useActiveCase } from "../context/ActiveCaseContext";

const MEMORY_EXTENSIONS = [".raw", ".mem", ".dmp", ".dump", ".bin", ".img", ".vmem", ".lime", ".aff4"];

type UploadStage = "idle" | "validating" | "created" | "uploading" | "verifying" | "finalizing" | "completed" | "failed";

type DuplicateMemoryUpload = {
  existingEvidenceId: string;
  existingFilename: string | null;
  message: string;
};

type StoredUploadSession = {
  uploadId: string;
  filename: string;
  expectedBytes: number;
  providedHost: string;
};

type ActiveSessionConflict = {
  existingUploadId: string;
  filename: string;
  expectedBytes: number;
  receivedBytes: number;
  receivedChunkCount: number;
  totalChunks: number;
  status: string;
  resumable: boolean;
  expiresAt: string;
  cancellable: boolean;
};

function formatBytes(value: number) {
  if (!Number.isFinite(value) || value <= 0) return "0 B";
  const units = ["B", "KiB", "MiB", "GiB", "TiB"];
  let size = value;
  let unitIndex = 0;
  while (size >= 1024 && unitIndex < units.length - 1) {
    size /= 1024;
    unitIndex += 1;
  }
  return `${size >= 100 || unitIndex === 0 ? size.toFixed(0) : size.toFixed(1)} ${units[unitIndex]}`;
}

function formatSeconds(value: number | null) {
  if (value === null || !Number.isFinite(value) || value < 0) return "Calculating";
  if (value < 60) return `${value}s`;
  const minutes = Math.floor(value / 60);
  const seconds = value % 60;
  return `${minutes}m ${seconds}s`;
}

function fileExtension(file: File | null) {
  if (!file?.name.includes(".")) return "";
  return `.${file.name.split(".").pop() || ""}`.toLowerCase();
}

function storageKey(caseId: string) {
  return `kairon-memory-upload:${caseId}`;
}

function readStoredUpload(caseId: string): StoredUploadSession | null {
  const raw = localStorage.getItem(storageKey(caseId));
  if (!raw) return null;
  try {
    const parsed = JSON.parse(raw) as StoredUploadSession;
    if (!parsed?.uploadId) return null;
    return parsed;
  } catch {
    return { uploadId: raw, filename: "", expectedBytes: 0, providedHost: "" };
  }
}

function writeStoredUpload(caseId: string, value: StoredUploadSession | null) {
  if (!value) {
    localStorage.removeItem(storageKey(caseId));
    return;
  }
  localStorage.setItem(storageKey(caseId), JSON.stringify(value));
}

async function sha256Hex(blob: Blob): Promise<string | undefined> {
  if (typeof globalThis.crypto?.subtle?.digest !== "function") return undefined;
  const digest = await globalThis.crypto.subtle.digest("SHA-256", await blob.arrayBuffer());
  return Array.from(new Uint8Array(digest), (value) => value.toString(16).padStart(2, "0")).join("");
}

function readinessLabel(readiness?: MemoryUploadReadiness) {
  if (!readiness) return "Checking";
  if (!readiness.upload_enabled) return "Upload disabled";
  if (!readiness.can_accept_selected_size) return "Storage check needed";
  if (!readiness.backend_ready) return "Upload now, analyze later";
  return "Ready";
}

export default function MemoryUploadPage() {
  const { caseId = "" } = useParams();
  const { setActiveCaseId } = useActiveCase();
  const navigate = useNavigate();
  const inputRef = useRef<HTMLInputElement | null>(null);
  const retryRegistrationInFlight = useRef(false);
  const bypassUploadBlocking = useRef(false);
  const storedUpload = readStoredUpload(caseId);

  const [file, setFile] = useState<File | null>(null);
  const [providedHost, setProvidedHost] = useState(storedUpload?.providedHost || "");
  const [acknowledged, setAcknowledged] = useState(false);
  const [stage, setStage] = useState<UploadStage>("idle");
  const [status, setStatus] = useState("");
  const [progress, setProgress] = useState({ loaded: 0, total: 0 });
  const [speedBytesPerSecond, setSpeedBytesPerSecond] = useState(0);
  const [uploadedEvidence, setUploadedEvidence] = useState<Evidence | null>(null);
  const [duplicateUpload, setDuplicateUpload] = useState<DuplicateMemoryUpload | null>(null);
  const [acceptedReadiness, setAcceptedReadiness] = useState<MemoryUploadReadiness | null>(null);
  const [activeUploadId, setActiveUploadId] = useState<string | null>(storedUpload?.uploadId || null);
  const [finalizationStartedAt, setFinalizationStartedAt] = useState<number | null>(null);
  const [elapsedSeconds, setElapsedSeconds] = useState(0);
  const [activeSessionConflict, setActiveSessionConflict] = useState<ActiveSessionConflict | null>(null);
  const [restartPhase, setRestartPhase] = useState<"idle" | "confirming" | "executing">("idle");

  const readinessQuery = useQuery({
    queryKey: ["memory-upload-readiness", caseId, file?.size || 0],
    queryFn: () => api.getMemoryUploadReadiness(caseId, file?.size || undefined),
    enabled: Boolean(caseId),
    refetchOnWindowFocus: false,
  });

  const activeUploadQuery = useQuery({
    queryKey: ["memory-active-upload", caseId],
    queryFn: () => api.getActiveMemoryUpload(caseId),
    enabled: Boolean(caseId),
    refetchInterval: 5000,
    retry: false,
  });

  const statusQuery = useQuery({
    queryKey: ["memory-upload-status", caseId, activeUploadId],
    queryFn: () => api.getMemoryUploadStatus(caseId, activeUploadId || ""),
    enabled: Boolean(caseId && activeUploadId),
    refetchInterval: (query) => {
      const current = query.state.data as MemoryUploadStatus | undefined;
      return current && ["completed", "failed", "cancelled", "expired", "inconsistent"].includes(current.status)
        ? false
        : 2000;
    },
    retry: false,
  });

  const readiness = readinessQuery.data;
  const extension = fileExtension(file);
  const extensionAllowed = MEMORY_EXTENSIONS.includes(extension);
  const fileWithinLimit = !file || !readiness || file.size <= readiness.max_upload_bytes;
  const resumeSessionMatchesFile = Boolean(
    storedUpload?.uploadId
      && file
      && (!storedUpload.filename || storedUpload.filename === file.name)
      && (!storedUpload.expectedBytes || storedUpload.expectedBytes === file.size),
  );
  const uploadBlockingReason = useMemo(() => {
    if (activeSessionConflict) return "An upload session already exists for this memory image. Choose Resume, Cancel and restart, or Select another file.";
    if (stage !== "idle") return "An upload action is already in progress or requires recovery.";
    if (activeUploadId && !file) return "A resumable upload session exists. Re-select the same file to continue from the missing chunks.";
    if (!file) return "No file selected.";
    if (file.size <= 0) return "The selected file is empty or its browser file handle is no longer valid. Select the file again.";
    if (!extensionAllowed) return "This file extension is not supported for memory image upload.";
    if (storedUpload?.uploadId && !resumeSessionMatchesFile) {
      const expected = storedUpload.filename ? `${storedUpload.filename} — ${formatBytes(storedUpload.expectedBytes)}` : `${formatBytes(storedUpload.expectedBytes)}`;
      return `This file does not match the resumable upload session. Expected: ${expected}`;
    }
    if (!providedHost.trim()) return "Source host is required.";
    if (!acknowledged) return "Authorization acknowledgement is required.";
    if (readinessQuery.isLoading || readinessQuery.isFetching) return "Memory upload readiness is still being checked.";
    if (readinessQuery.error || !readiness) return "Backend upload readiness is unavailable.";
    if (!readiness.upload_enabled) return "Memory image upload is disabled by server configuration.";
    if (!fileWithinLimit) return "The selected file exceeds the configured maximum memory upload size.";
    if (!readiness.can_accept_selected_size) return readiness.message || "Storage capacity check rejected the selected file.";
    return null;
  }, [acknowledged, activeSessionConflict, activeUploadId, extensionAllowed, file, fileWithinLimit, providedHost, readiness, readinessQuery.error, readinessQuery.isFetching, readinessQuery.isLoading, resumeSessionMatchesFile, stage, storedUpload?.uploadId]);
  const canUpload = uploadBlockingReason === null;
  const percent = progress.total > 0 ? Math.min(100, Math.round((progress.loaded / progress.total) * 100)) : 0;
  const etaSeconds = speedBytesPerSecond > 0 ? Math.max(0, Math.round((progress.total - progress.loaded) / speedBytesPerSecond)) : null;
  const isBrowserTransferActive = ["uploading", "verifying", "finalizing"].includes(stage) && Boolean(file) && resumeSessionMatchesFile;
  const needsFileReselection = Boolean(activeUploadId && storedUpload?.uploadId && !file);

  useEffect(() => {
    if (caseId) setActiveCaseId(caseId);
  }, [caseId, setActiveCaseId]);

  useEffect(() => {
    if (!["created", "uploading", "verifying", "finalizing"].includes(stage)) return;
    const handler = (event: BeforeUnloadEvent) => {
      event.preventDefault();
      event.returnValue = "";
    };
    window.addEventListener("beforeunload", handler);
    return () => window.removeEventListener("beforeunload", handler);
  }, [stage]);

  useEffect(() => {
    if (statusQuery.error && activeUploadId) {
      writeStoredUpload(caseId, null);
      setActiveUploadId(null);
    }
  }, [statusQuery.error, activeUploadId, caseId]);

  useEffect(() => {
    if (!finalizationStartedAt || !["verifying", "finalizing"].includes(stage)) return;
    const timer = window.setInterval(() => {
      setElapsedSeconds(Math.floor((Date.now() - finalizationStartedAt) / 1000));
    }, 1000);
    return () => window.clearInterval(timer);
  }, [finalizationStartedAt, stage]);

  useEffect(() => {
    const uploadStatus = statusQuery.data;
    if (!uploadStatus) return;
    setProgress({ loaded: uploadStatus.bytes_received, total: uploadStatus.expected_bytes });
    setStatus(uploadStatus.message);
    if (["created", "uploading", "verifying", "finalizing", "validating"].includes(uploadStatus.status)) {
      const isStalledWithoutFile = uploadStatus.status === "uploading" && storedUpload?.uploadId && !file;
      const isMismatchedFile = uploadStatus.status === "uploading" && storedUpload?.uploadId && file && !resumeSessionMatchesFile;
      if (isStalledWithoutFile || isMismatchedFile) {
        // Resumable session exists but browser has no matching file — keep idle
        // so the file picker remains enabled for reselection.
      } else {
        setStage(uploadStatus.status as UploadStage);
      }
      if (["verifying", "finalizing"].includes(uploadStatus.status) && !finalizationStartedAt) {
        setFinalizationStartedAt(Date.now());
      }
      return;
    }
    if (uploadStatus.status === "completed" && uploadStatus.evidence_id) {
      setStage("completed");
      writeStoredUpload(caseId, null);
      setActiveUploadId(null);
      void api.getEvidence(uploadStatus.evidence_id).then((evidence) => setUploadedEvidence(evidence));
      return;
    }
    if (["failed", "cancelled", "expired", "inconsistent"].includes(uploadStatus.status)) {
      setStage("failed");
    }
  }, [caseId, file, finalizationStartedAt, resumeSessionMatchesFile, statusQuery.data, storedUpload]);

  const summary = useMemo(() => {
    if (!file) return "Select an authorized Windows memory image to begin.";
    if (file.size <= 0) return "The selected file is empty or its browser file handle is no longer valid. Select the file again.";
    if (!extensionAllowed) return "This file extension is not supported for memory image upload.";
    if (!fileWithinLimit) return "This file exceeds the configured maximum memory upload size.";
    if (readiness && !readiness.can_accept_selected_size) return readiness.message;
    if (storedUpload?.uploadId && resumeSessionMatchesFile) return "A resumable upload session already exists for this file. Kairon will continue only the missing chunks.";
    return "The selected file can be uploaded as isolated memory_dump evidence.";
  }, [extensionAllowed, file, fileWithinLimit, readiness, resumeSessionMatchesFile, storedUpload?.uploadId]);

  function handleActiveSessionConflict(error: unknown): boolean {
    const conflictError = error as { errorCode?: string | null; detail?: unknown };
    if (conflictError?.errorCode !== "MEMORY_UPLOAD_ACTIVE_SESSION_EXISTS") return false;
    const detail = (conflictError.detail && typeof conflictError.detail === "object")
      ? conflictError.detail as Record<string, unknown>
      : {};
    setActiveSessionConflict({
      existingUploadId: String(detail.existing_upload_id || ""),
      filename: String(detail.filename || ""),
      expectedBytes: Number(detail.expected_bytes || 0),
      receivedBytes: Number(detail.received_bytes || 0),
      receivedChunkCount: Number(detail.received_chunk_count || 0),
      totalChunks: Number(detail.total_chunks || 0),
      status: String(detail.status || "uploading"),
      resumable: Boolean(detail.resumable),
      expiresAt: String(detail.expires_at || ""),
      cancellable: Boolean(detail.cancellable),
    });
    setStage("idle");
    setStatus("");
    setSpeedBytesPerSecond(0);
    return true;
  }

  function handleDuplicateError(error: unknown): boolean {
    const duplicateError = error as { errorCode?: string | null; detail?: unknown; message?: string };
    if (duplicateError?.errorCode !== "MEMORY_EVIDENCE_DUPLICATE") return false;
    const detail = (duplicateError.detail && typeof duplicateError.detail === "object")
      ? duplicateError.detail as { existing_evidence_id?: string; existing_filename?: string | null; message?: string }
      : {};
    const existingEvidenceId = String(detail.existing_evidence_id || "").trim();
    if (!existingEvidenceId) return false;
    writeStoredUpload(caseId, null);
    setActiveUploadId(null);
    setStage("idle");
    setStatus("");
    setDuplicateUpload({
      existingEvidenceId,
      existingFilename: detail.existing_filename ?? null,
      message: detail.message || duplicateError.message || "This memory image is already registered in this case.",
    });
    return true;
  }

  async function continueChunkedUpload(uploadStatus: MemoryUploadStatus, selectedFile: File) {
    const chunkSize = uploadStatus.chunk_size_bytes || readiness?.recommended_chunk_size_bytes || 64 * 1024 * 1024;
    const totalChunks = uploadStatus.total_chunks || Math.ceil(selectedFile.size / chunkSize);
    const missingChunks = uploadStatus.missing_chunks && uploadStatus.missing_chunks.length > 0
      ? uploadStatus.missing_chunks
      : Array.from({ length: totalChunks }, (_, index) => index);
    let uploadedBaseline = uploadStatus.bytes_received || 0;
    let completedThisAttempt = 0;
    const startedAt = Date.now();

    for (const chunkIndex of missingChunks) {
      const start = chunkIndex * chunkSize;
      const end = Math.min(selectedFile.size, start + chunkSize);
      const blob = selectedFile.slice(start, end);
      const chunkSha256 = await sha256Hex(blob);
      setStage("uploading");
      setStatus(`Uploading chunk ${chunkIndex + 1} of ${totalChunks}`);
      await api.uploadMemoryUploadChunk(caseId, uploadStatus.upload_id, chunkIndex, blob, {
        chunkSha256,
        onProgress: ({ loaded }) => {
          const totalLoaded = uploadedBaseline + completedThisAttempt + loaded;
          setProgress({ loaded: totalLoaded, total: selectedFile.size });
          const elapsed = Math.max(1, (Date.now() - startedAt) / 1000);
          setSpeedBytesPerSecond(totalLoaded / elapsed);
        },
      });
      completedThisAttempt += blob.size;
    }

    setStage("verifying");
    setStatus("Upload transferred; verifying and finalizing");
    setFinalizationStartedAt(Date.now());
    setSpeedBytesPerSecond(0);
    const finalized = await api.finalizeMemoryUpload(caseId, uploadStatus.upload_id);
    if (finalized.evidence_id) {
      const evidence = await api.getEvidence(finalized.evidence_id);
      setUploadedEvidence(evidence);
      writeStoredUpload(caseId, null);
      setActiveUploadId(null);
      setProgress({ loaded: selectedFile.size, total: selectedFile.size });
      setStage("completed");
      setStatus("Memory image uploaded and registered.");
      return;
    }
    setStatus(finalized.message);
  }

  async function upload() {
    setStage("validating");
    setStatus("Validating upload…");
    setUploadedEvidence(null);
    setDuplicateUpload(null);
    try {
      if (!bypassUploadBlocking.current && (uploadBlockingReason || !file)) {
        throw new Error(uploadBlockingReason || "No file selected.");
      }
      setProgress({ loaded: 0, total: file.size });
      const currentReadiness = await api.getMemoryUploadReadiness(caseId, file.size);
      if (!currentReadiness.upload_enabled || !currentReadiness.can_accept_selected_size) {
        throw new Error(currentReadiness.message || "Memory upload readiness could not be confirmed.");
      }
      setAcceptedReadiness(currentReadiness);
      const uploadStatus = activeUploadId
        ? await api.getMemoryUploadStatus(caseId, activeUploadId)
        : await api.createMemoryUploadSession(caseId, {
            filename: file.name,
            expected_size_bytes: file.size,
            provided_host: providedHost.trim(),
            authorization_acknowledged: true,
          });
      writeStoredUpload(caseId, {
        uploadId: uploadStatus.upload_id,
        filename: file.name,
        expectedBytes: file.size,
        providedHost: providedHost.trim(),
      });
      setActiveUploadId(uploadStatus.upload_id);
      await continueChunkedUpload(uploadStatus, file);
    } catch (error) {
      if (handleActiveSessionConflict(error)) return;
      if (handleDuplicateError(error)) return;
      setSpeedBytesPerSecond(0);
      setStage("failed");
      setStatus(error instanceof Error ? error.message : "Memory image upload failed.");
    }
  }

  async function retryUpload() {
    setStage("validating");
    setStatus("Refreshing memory upload readiness");
    setProgress({ loaded: 0, total: file?.size || 0 });
    setAcceptedReadiness(null);
    await readinessQuery.refetch();
    setStage("idle");
    setStatus("");
  }

  async function reconcileUpload() {
    if (!activeUploadId) return;
    const result = await api.reconcileMemoryUpload(caseId, activeUploadId);
    setStatus(result.message);
    await statusQuery.refetch();
  }

  async function retryRegistration() {
    if (!activeUploadId) return;
    if (retryRegistrationInFlight.current) return;
    retryRegistrationInFlight.current = true;
    setStatus("Retrying evidence registration...");
    try {
      const result = await api.retryMemoryUploadRegistration(caseId, activeUploadId);
      setStatus(result.message);
      if (result.status === "completed" && result.evidence_id) {
        writeStoredUpload(caseId, null);
        setActiveUploadId(null);
        navigate(`/cases/${caseId}/memory/${result.evidence_id}`);
        return;
      }
      await statusQuery.refetch();
    } catch (error) {
      if (handleDuplicateError(error)) return;
      setStatus(error instanceof Error ? error.message : "Evidence registration retry failed");
    } finally {
      retryRegistrationInFlight.current = false;
    }
  }

  async function prepareReupload() {
    writeStoredUpload(caseId, null);
    setActiveUploadId(null);
    setStage("idle");
    setStatus("");
    setProgress({ loaded: 0, total: file?.size || 0 });
    await readinessQuery.refetch();
  }

  function dismissActiveSessionConflict() {
    setActiveSessionConflict(null);
    setRestartPhase("idle");
  }

  async function resumeExistingSession() {
    if (!activeSessionConflict || !file) return;
    if (file.name !== activeSessionConflict.filename || file.size !== activeSessionConflict.expectedBytes) {
      setStatus("The selected file does not match the existing upload session.");
      setActiveSessionConflict(null);
      return;
    }
    const uploadId = activeSessionConflict.existingUploadId;
    writeStoredUpload(caseId, {
      uploadId,
      filename: file.name,
      expectedBytes: file.size,
      providedHost: providedHost.trim(),
    });
    setActiveUploadId(uploadId);
    setActiveSessionConflict(null);
    setStage("idle");
    setTimeout(() => { void upload(); }, 0);
  }

  async function executeCancelAndRestart() {
    if (!activeSessionConflict || !file) return;
    setRestartPhase("executing");
    try {
      await api.cancelMemoryUpload(
        caseId,
        activeSessionConflict.existingUploadId,
        "Operator requested restart",
      );
      writeStoredUpload(caseId, null);
      setActiveUploadId(null);
      setActiveSessionConflict(null);
      setRestartPhase("idle");
      setStage("idle");
      bypassUploadBlocking.current = true;
      void upload().finally(() => { bypassUploadBlocking.current = false; });
    } catch (error) {
      setRestartPhase("idle");
      setStatus(error instanceof Error ? error.message : "Failed to cancel the existing upload session.");
    }
  }

  if (!caseId) {
    return <div className="rounded-[28px] border border-line bg-panel/70 p-8 text-sm text-muted shadow-panel">Select a case first.</div>;
  }

  const serverActive = activeUploadQuery.data;

  return (
    <div className="space-y-6">
      <section className="rounded-[28px] border border-line bg-panel/70 p-6 shadow-panel">
        <p className="font-mono text-xs uppercase tracking-[0.24em] text-accent">Memory Analysis</p>
        <div className="mt-2 flex flex-wrap items-start justify-between gap-4">
          <div>
            <h2 className="text-3xl font-semibold">Add memory image</h2>
            <p className="mt-2 max-w-3xl text-sm text-muted">Upload authorized RAM evidence into isolated memory storage. It will not enter global disk Search, Timeline, Artifact Views or detections.</p>
          </div>
          <Link to={`/cases/${caseId}/memory`} className="rounded-xl border border-line bg-abyss/70 px-3 py-2 text-xs text-muted">Back to Memory Analysis</Link>
        </div>
      </section>

      {serverActive && serverActive.is_active ? (
        <section data-testid="memory-active-upload-panel" className="rounded-[28px] border border-warning/30 bg-warning/10 p-5 text-sm">
          <div className="flex flex-wrap items-start justify-between gap-3">
            <div>
              <h3 className="text-lg font-semibold text-ink">{serverActive.stale ? "Interrupted memory upload" : "Active memory upload"}</h3>
              <p className="mt-1 text-sm text-muted">File: <span className="font-mono">{serverActive.filename || serverActive.upload_id}</span></p>
              <p className="mt-1 text-sm text-muted">State: <span className="font-mono">{serverActive.status}</span></p>
              {serverActive.stage ? <p className="mt-1 text-sm text-muted">Registration stage: <span data-testid="memory-upload-registration-stage" className="font-mono">{serverActive.stage}</span></p> : null}
              {serverActive.canonical_preserved ? <p className="mt-1 text-sm text-mint" data-testid="memory-upload-canonical-preserved">Canonical file is preserved on the server.</p> : null}
              {serverActive.failure_code === "evidence_registration_failed" && serverActive.canonical_preserved ? (
                <div className="mt-3 rounded-2xl border border-warning/30 bg-warning/10 p-3 text-sm text-warning">
                  <p>The memory image reached Kairon and is preserved on the server, but evidence registration did not complete. No bytes need to be re-uploaded.</p>
                  <p className="mt-1 text-xs" data-testid="memory-upload-technical-details">Technical details: code={serverActive.last_registration_error_code || "evidence_registration_failed"}, class={serverActive.last_registration_error_class || "RuntimeError"}</p>
                  <button
                    type="button"
                    data-testid="memory-upload-retry-registration"
                    onClick={() => void retryRegistration()}
                    className="mt-3 rounded-xl border border-mint/30 bg-mint/10 px-3 py-2 text-xs font-semibold text-mint"
                  >
                    Retry evidence registration
                  </button>
                </div>
              ) : null}
              <p className="mt-1 text-sm text-muted">Progress: {formatBytes(serverActive.bytes_received)} / {formatBytes(serverActive.expected_bytes)}{serverActive.expected_bytes > 0 ? ` (${Math.round((serverActive.bytes_received / serverActive.expected_bytes) * 100)}%)` : ""}</p>
              <p className="mt-1 text-sm text-muted">Last activity: {serverActive.last_heartbeat ? new Date(serverActive.last_heartbeat).toLocaleString() : "unknown"}{serverActive.stale ? " (stale)" : ""}</p>
              {serverActive.stale ? <p className="mt-1 text-sm text-warning">No activity for a long time. Re-select the same file to resume the missing chunks or cancel the session.</p> : null}
            </div>
            <div className="flex flex-wrap gap-2">
              <button type="button" data-testid="memory-active-check-status" onClick={() => { void activeUploadQuery.refetch(); void statusQuery.refetch(); }} className="rounded-xl border border-line bg-abyss/70 px-3 py-2 text-xs text-muted">Check status</button>
              {serverActive.cancellable ? (
                <button
                  type="button"
                  data-testid="memory-active-cancel"
                  onClick={() => {
                    const reason = window.prompt("Cancel and discard incomplete upload?", "Operator requested cancel");
                    if (!reason) return;
                    api.cancelMemoryUpload(caseId, serverActive.upload_id, reason)
                      .then(() => {
                        writeStoredUpload(caseId, null);
                        setActiveUploadId(null);
                        void activeUploadQuery.refetch();
                      })
                      .catch((error) => setStatus(error instanceof Error ? error.message : "Cancel failed"));
                  }}
                  className="rounded-xl border border-rose-400/40 bg-rose-500/10 px-3 py-2 text-xs text-rose-100"
                >
                  Cancel and discard
                </button>
              ) : null}
              {serverActive.evidence_id ? <Link to={`/cases/${caseId}/memory/${serverActive.evidence_id}`} className="rounded-xl bg-accent px-3 py-2 text-xs font-semibold text-abyss">Open evidence</Link> : null}
            </div>
          </div>
        </section>
      ) : null}

      <section className="grid gap-3 md:grid-cols-4">
        <div className="rounded-2xl border border-line bg-panel/60 p-4"><p className="text-xs uppercase tracking-[0.16em] text-muted">Upload</p><p className="mt-1 text-lg font-semibold">{readiness?.upload_enabled ? "Enabled" : "Disabled"}</p></div>
        <div className="rounded-2xl border border-line bg-panel/60 p-4"><p className="text-xs uppercase tracking-[0.16em] text-muted">Analysis</p><p className="mt-1 text-lg font-semibold">{readiness?.analysis_enabled ? "Enabled" : "Disabled"}</p></div>
        <div className="rounded-2xl border border-line bg-panel/60 p-4"><p className="text-xs uppercase tracking-[0.16em] text-muted">Memory worker</p><p className="mt-1 text-lg font-semibold">{readiness?.dedicated_worker_online ? "Online" : "Offline"}</p></div>
        <div className="rounded-2xl border border-line bg-panel/60 p-4"><p className="text-xs uppercase tracking-[0.16em] text-muted">Status</p><p className="mt-1 text-lg font-semibold">{readinessLabel(readiness)}</p></div>
      </section>

      <section className="rounded-[28px] border border-line bg-panel/60 p-5">
        <h3 className="text-lg font-semibold">Upload readiness</h3>
        {readinessQuery.isLoading ? <p className="mt-3 text-sm text-muted">Checking upload capacity...</p> : null}
        {readinessQuery.error instanceof Error ? <p className="mt-3 text-sm text-rose-200">{readinessQuery.error.message}</p> : null}
        {readiness ? (
          <div className="mt-4 grid gap-3 md:grid-cols-4 text-sm">
            <div className="rounded-2xl border border-line bg-abyss/60 p-4"><p className="text-xs uppercase tracking-[0.14em] text-muted">Maximum</p><p className="mt-1 text-ink">{readiness.max_upload_display}</p></div>
            <div className="rounded-2xl border border-line bg-abyss/60 p-4"><p className="text-xs uppercase tracking-[0.14em] text-muted">Chunk size</p><p className="mt-1 text-ink">{formatBytes(readiness.recommended_chunk_size_bytes)}</p></div>
            <div className="rounded-2xl border border-line bg-abyss/60 p-4"><p className="text-xs uppercase tracking-[0.14em] text-muted">Case quota remaining</p><p className="mt-1 text-ink">{formatBytes(readiness.case_quota_remaining_bytes)}</p></div>
            <div className="rounded-2xl border border-line bg-abyss/60 p-4"><p className="text-xs uppercase tracking-[0.14em] text-muted">Required additional capacity</p><p className="mt-1 text-ink">{formatBytes(readiness.required_capacity_bytes)}</p></div>
          </div>
        ) : null}
        {readiness ? <p className="mt-4 rounded-2xl border border-line bg-abyss/60 p-4 text-sm text-muted">{readiness.message}</p> : null}
      </section>

      <section className="rounded-[28px] border border-warning/30 bg-warning/10 p-5 text-sm text-warning">
        <h3 className="text-lg font-semibold text-ink">Privacy and authorization</h3>
        <p className="mt-2">Memory images may contain credentials, personal data, encryption material, browser data, access tokens, and other sensitive information. Upload only evidence that you own or are explicitly authorized to analyze.</p>
        <label className="mt-4 flex gap-3 text-sm"><input type="checkbox" checked={acknowledged} onChange={(event) => setAcknowledged(event.target.checked)} /><span>I confirm that I own this memory image or am explicitly authorized to upload and analyze it.</span></label>
      </section>

      <section className="rounded-[28px] border border-line bg-panel/60 p-5">
        <h3 className="text-lg font-semibold">Memory image file</h3>
        <div className="mt-4 grid gap-4 md:grid-cols-[1fr_220px]">
          <label className="block"><span className="text-sm text-muted">Source host</span><input value={providedHost} onChange={(event) => setProvidedHost(event.target.value)} placeholder="HOSTA or hosta.example.local" className="mt-2 w-full rounded-2xl border border-line bg-abyss/80 px-4 py-3 text-sm outline-none" /></label>
          <button type="button" onClick={() => inputRef.current?.click()} disabled={isBrowserTransferActive} className="self-end rounded-2xl border border-line bg-white/5 px-4 py-3 text-sm text-muted disabled:opacity-60">{needsFileReselection ? `Reselect ${storedUpload?.filename || "file"}` : "Select RAM image"}</button>
        </div>
        <input ref={inputRef} data-testid="memory-image-file-input" aria-label="Memory image file" type="file" accept={MEMORY_EXTENSIONS.join(",") + ",application/octet-stream"} className="hidden" onChange={(event) => {
          const next = event.target.files?.[0] || null;
          setFile(next);
          setUploadedEvidence(null);
          setDuplicateUpload(null);
          setAcceptedReadiness(null);
          setStage("idle");
          setStatus(next ? `Selected ${next.name}` : "");
          setProgress({ loaded: 0, total: next?.size || 0 });
        }} />
        {file ? <div className="mt-4 rounded-2xl border border-line bg-abyss/60 p-4 text-sm"><p className="truncate font-medium text-ink" title={file.name}>{file.name}</p><p className="mt-1 text-muted">Extension: {extension || "none"} · Size: {formatBytes(file.size)} · Detected type: {extensionAllowed ? "Memory image" : "Unsupported"}</p><p className={`mt-2 ${extensionAllowed && fileWithinLimit && readiness?.can_accept_selected_size ? "text-mint" : "text-warning"}`}>{summary}</p></div> : null}
      </section>

      <section className="rounded-[28px] border border-line bg-panel/60 p-5">
        <div className="flex flex-wrap items-center justify-between gap-3"><div><h3 className="text-lg font-semibold">Upload</h3><p className="mt-1 text-sm text-muted">Stages: session creation, bounded chunk transfer, verification, finalization, completed, failed.</p></div><button type="button" onClick={() => { if (needsFileReselection) { inputRef.current?.click(); } else { void upload(); } }} disabled={!canUpload && !needsFileReselection} className="rounded-2xl bg-accent px-4 py-3 text-sm font-semibold text-abyss disabled:opacity-50">{needsFileReselection ? "Select file to resume" : stage === "validating" ? "Validating upload…" : activeUploadId ? "Resume upload" : "Upload memory image"}</button></div>
        {uploadBlockingReason && stage === "idle" ? <p className="mt-3 rounded-xl border border-warning/30 bg-warning/10 px-3 py-2 text-sm text-warning" role="status">{uploadBlockingReason}</p> : null}
        {status && stage === "idle" ? <p className="mt-3 rounded-xl border border-rose-400/40 bg-rose-500/10 px-3 py-2 text-sm text-rose-100" role="status">{status}</p> : null}
        {acceptedReadiness ? <p className="mt-3 text-xs text-muted">Resumable upload enabled · Chunk size: {formatBytes(acceptedReadiness.recommended_chunk_size_bytes)} · Finalization: {acceptedReadiness.finalization_strategy === "staged_copy" ? "staged copy" : "atomic move"}</p> : null}
        {activeSessionConflict ? (
          <div className="mt-4 rounded-2xl border border-warning/30 bg-warning/10 p-4 text-sm" data-testid="memory-active-session-conflict">
            <p className="font-semibold text-ink">Existing upload found</p>
            <p className="mt-1 font-mono text-muted">{activeSessionConflict.filename}</p>
            <p className="mt-1 text-muted">
              {formatBytes(activeSessionConflict.receivedBytes)} of {formatBytes(activeSessionConflict.expectedBytes)} uploaded
              {activeSessionConflict.totalChunks > 0 ? ` (${activeSessionConflict.receivedChunkCount} of ${activeSessionConflict.totalChunks} chunks)` : ""}
            </p>
            {activeSessionConflict.expiresAt ? (
              <p className="mt-1 text-xs text-muted">Session valid until {new Date(activeSessionConflict.expiresAt).toLocaleString()}</p>
            ) : null}
            <div className="mt-4 flex flex-wrap gap-2">
              <button
                type="button"
                data-testid="memory-conflict-resume"
                onClick={() => void resumeExistingSession()}
                disabled={restartPhase !== "idle"}
                className="rounded-xl bg-accent px-3 py-2 text-xs font-semibold text-abyss disabled:opacity-50"
              >
                Resume existing upload
              </button>
              {activeSessionConflict.cancellable ? (
                restartPhase === "confirming" ? (
                  <div className="flex flex-wrap items-center gap-2">
                    <span className="text-xs text-warning">Restart upload? This will discard {formatBytes(activeSessionConflict.receivedBytes)} already uploaded.</span>
                    <button
                      type="button"
                      data-testid="memory-conflict-confirm-restart"
                      onClick={() => void executeCancelAndRestart()}
                      disabled={restartPhase === "executing"}
                      className="rounded-xl border border-rose-400/40 bg-rose-500/10 px-3 py-2 text-xs text-rose-100 disabled:opacity-50"
                    >
                      {restartPhase === "executing" ? "Restarting…" : "Cancel and restart"}
                    </button>
                    <button
                      type="button"
                      data-testid="memory-conflict-keep-existing"
                      onClick={() => setRestartPhase("idle")}
                      disabled={restartPhase === "executing"}
                      className="rounded-xl border border-line bg-abyss/70 px-3 py-2 text-xs text-muted disabled:opacity-50"
                    >
                      Keep existing upload
                    </button>
                  </div>
                ) : (
                  <button
                    type="button"
                    data-testid="memory-conflict-cancel-restart"
                    onClick={() => setRestartPhase("confirming")}
                    disabled={restartPhase !== "idle"}
                    className="rounded-xl border border-rose-400/40 bg-rose-500/10 px-3 py-2 text-xs text-rose-100 disabled:opacity-50"
                  >
                    Cancel and start over
                  </button>
                )
              ) : null}
              <button
                type="button"
                data-testid="memory-conflict-select-another"
                onClick={() => {
                  dismissActiveSessionConflict();
                  inputRef.current?.click();
                }}
                disabled={restartPhase !== "idle"}
                className="rounded-xl border border-line bg-abyss/70 px-3 py-2 text-xs text-muted disabled:opacity-50"
              >
                Select another file
              </button>
            </div>
          </div>
        ) : null}
        {stage !== "idle" ? <div className="mt-4"><div className="flex justify-between text-xs text-muted"><span>{stage}</span><span>{formatBytes(progress.loaded)} / {formatBytes(progress.total)} · {percent}% transferred</span></div><div className="mt-2 h-3 overflow-hidden rounded-full bg-abyss"><div className={`h-full transition-all ${stage === "failed" ? "bg-rose-500" : stage === "completed" ? "bg-mint" : "bg-accent"}`} style={{ width: `${percent}%` }} /></div><p className={`mt-3 text-sm ${stage === "failed" ? "text-rose-200" : "text-muted"}`}>{status}</p>{stage === "uploading" ? <p className="mt-2 text-xs text-muted">Speed: {speedBytesPerSecond > 0 ? `${formatBytes(speedBytesPerSecond)}/s` : "Calculating"} · ETA: {formatSeconds(etaSeconds)}</p> : null}{stage === "verifying" || stage === "finalizing" ? <><p className="mt-2 text-xs text-muted" role="status">Server finalization is active · {elapsedSeconds}s elapsed.</p>{elapsedSeconds >= 30 ? <p className="mt-2 text-xs text-warning">The file has been transferred. Kairon is still finalizing the evidence.</p> : null}</> : null}</div> : null}
        {activeUploadId && stage !== "completed" ? <div className="mt-4 flex flex-wrap gap-2"><button type="button" onClick={() => void statusQuery.refetch()} className="rounded-xl border border-line bg-abyss/70 px-3 py-2 text-xs text-muted">Check status</button>{statusQuery.data?.retryable ? <button type="button" onClick={() => void reconcileUpload()} className="rounded-xl border border-line bg-abyss/70 px-3 py-2 text-xs text-muted">Retry finalization</button> : null}{statusQuery.data?.failure_code === "upload_bytes_lost" ? <button type="button" onClick={() => void prepareReupload()} className="rounded-xl border border-line bg-abyss/70 px-3 py-2 text-xs text-muted">Prepare new upload</button> : null}{statusQuery.data?.status === "failed" && file && activeUploadId ? <button type="button" onClick={() => void upload()} className="rounded-xl border border-line bg-abyss/70 px-3 py-2 text-xs text-muted">Resume missing chunks</button> : null}</div> : null}
        {stage === "failed" && !activeUploadId ? <div className="mt-4 flex flex-wrap gap-2"><button type="button" onClick={() => void retryUpload()} className="rounded-xl border border-line bg-abyss/70 px-3 py-2 text-xs text-muted">Retry upload</button><button type="button" onClick={() => inputRef.current?.click()} className="rounded-xl border border-line bg-abyss/70 px-3 py-2 text-xs text-muted">Select another file</button></div> : null}
        {duplicateUpload ? <div className="mt-4 rounded-2xl border border-warning/30 bg-warning/10 p-4 text-sm" data-testid="memory-upload-duplicate-warning"><p className="font-semibold text-ink">This memory image is already registered in this case.</p><p className="mt-1 text-muted">{duplicateUpload.message}</p>{duplicateUpload.existingFilename ? <p className="mt-1 text-muted">Existing evidence: {duplicateUpload.existingFilename}</p> : null}<div className="mt-4 flex flex-wrap gap-2"><button type="button" onClick={() => navigate(`/cases/${caseId}/memory/${duplicateUpload.existingEvidenceId}`)} className="rounded-xl bg-accent px-3 py-2 text-xs font-semibold text-abyss">Open existing evidence</button><button type="button" onClick={() => setDuplicateUpload(null)} className="rounded-xl border border-line bg-abyss/70 px-3 py-2 text-xs text-muted">Cancel</button></div></div> : null}
        {uploadedEvidence ? <div className="mt-4 rounded-2xl border border-mint/30 bg-mint/10 p-4 text-sm"><p className="font-semibold text-ink">Upload completed</p><p className="mt-1 text-muted">Evidence ID: {uploadedEvidence.id}</p><p className="mt-1 text-muted">Type: Memory image · Size: {formatBytes(uploadedEvidence.size_bytes)}</p><div className="mt-4 flex flex-wrap gap-2"><button type="button" onClick={() => navigate(`/cases/${caseId}/memory/${uploadedEvidence.id}`)} className="rounded-xl bg-accent px-3 py-2 text-xs font-semibold text-abyss">Open Memory Analysis</button><button type="button" onClick={() => { setFile(null); setUploadedEvidence(null); setStage("idle"); setStatus(""); setProgress({ loaded: 0, total: 0 }); setSpeedBytesPerSecond(0); }} className="rounded-xl border border-line bg-abyss/70 px-3 py-2 text-xs text-muted">Upload another memory image</button></div></div> : null}
        {needsFileReselection ? (
          <div className="mt-4 rounded-2xl border border-warning/30 bg-warning/10 p-4 text-sm">
            <p className="font-semibold text-ink">Upload paused</p>
            <p className="mt-1 text-muted">
              Kairon has safely stored {formatBytes(progress.loaded)} of {formatBytes(storedUpload?.expectedBytes || progress.total)}.
              {storedUpload?.filename ? ` Reselect the same ${storedUpload.filename} file to continue from chunk ${(statusQuery.data?.received_chunk_count || 0) + 1} of ${statusQuery.data?.total_chunks || "?"}.` : " Reselect the file to continue."}
            </p>
          </div>
        ) : null}
      </section>
    </div>
  );
}
