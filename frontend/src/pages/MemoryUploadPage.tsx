import { useEffect, useMemo, useRef, useState } from "react";
import { useQuery } from "@tanstack/react-query";
import { Link, useNavigate, useParams } from "react-router-dom";
import { api, type Evidence, type MemoryUploadReadiness, type MemoryUploadStatus } from "../api/client";
import { useActiveCase } from "../context/ActiveCaseContext";

const MEMORY_EXTENSIONS = [".raw", ".mem", ".vmem", ".dmp", ".lime"];

type UploadStage = "idle" | "validating" | "uploading" | "verifying" | "finalizing" | "completed" | "failed";

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

function fileExtension(file: File | null) {
  if (!file?.name.includes(".")) return "";
  return `.${file.name.split(".").pop() || ""}`.toLowerCase();
}

function isMemoryImage(file: File | null) {
  return MEMORY_EXTENSIONS.includes(fileExtension(file));
}

function createUploadId() {
  if (typeof globalThis.crypto?.randomUUID === "function") return globalThis.crypto.randomUUID();
  if (typeof globalThis.crypto?.getRandomValues !== "function") {
    throw new Error("This browser cannot generate a secure upload identifier. Reload in a current browser and try again.");
  }
  const bytes = globalThis.crypto.getRandomValues(new Uint8Array(16));
  bytes[6] = (bytes[6] & 0x0f) | 0x40;
  bytes[8] = (bytes[8] & 0x3f) | 0x80;
  const hex = Array.from(bytes, (value) => value.toString(16).padStart(2, "0")).join("");
  return `${hex.slice(0, 8)}-${hex.slice(8, 12)}-${hex.slice(12, 16)}-${hex.slice(16, 20)}-${hex.slice(20)}`;
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
  const [file, setFile] = useState<File | null>(null);
  const [providedHost, setProvidedHost] = useState("");
  const [acknowledged, setAcknowledged] = useState(false);
  const [stage, setStage] = useState<UploadStage>("idle");
  const [status, setStatus] = useState("");
  const [progress, setProgress] = useState({ loaded: 0, total: 0 });
  const [uploadedEvidence, setUploadedEvidence] = useState<Evidence | null>(null);
  const [acceptedReadiness, setAcceptedReadiness] = useState<MemoryUploadReadiness | null>(null);
  const [activeUploadId, setActiveUploadId] = useState<string | null>(() => localStorage.getItem(`kairon-memory-upload:${caseId}`));
  const [finalizationStartedAt, setFinalizationStartedAt] = useState<number | null>(null);
  const [elapsedSeconds, setElapsedSeconds] = useState(0);

  useEffect(() => {
    if (caseId) setActiveCaseId(caseId);
  }, [caseId, setActiveCaseId]);

  useEffect(() => {
    if (stage !== "uploading" && stage !== "verifying" && stage !== "finalizing") return;
    const handler = (event: BeforeUnloadEvent) => {
      event.preventDefault();
      event.returnValue = "";
    };
    window.addEventListener("beforeunload", handler);
    return () => window.removeEventListener("beforeunload", handler);
  }, [stage]);

  const readinessQuery = useQuery({
    queryKey: ["memory-upload-readiness", caseId, file?.size || 0],
    queryFn: () => api.getMemoryUploadReadiness(caseId, file?.size || undefined),
    enabled: Boolean(caseId),
    refetchOnWindowFocus: false,
  });

  const statusQuery = useQuery({
    queryKey: ["memory-upload-status", caseId, activeUploadId],
    queryFn: () => api.getMemoryUploadStatus(caseId, activeUploadId || ""),
    enabled: Boolean(caseId && activeUploadId),
    refetchInterval: (query) => {
      const current = query.state.data as MemoryUploadStatus | undefined;
      return current && ["completed", "failed", "inconsistent"].includes(current.status) ? false : 2000;
    },
    retry: 2,
  });

  useEffect(() => {
    if (!finalizationStartedAt || !["uploading", "verifying", "finalizing"].includes(stage)) return;
    const timer = window.setInterval(() => setElapsedSeconds(Math.floor((Date.now() - finalizationStartedAt) / 1000)), 1000);
    return () => window.clearInterval(timer);
  }, [finalizationStartedAt, stage]);

  useEffect(() => {
    const uploadStatus = statusQuery.data;
    if (!uploadStatus) return;
    setProgress({ loaded: uploadStatus.bytes_received, total: uploadStatus.expected_bytes });
    if (["validating", "uploading", "verifying", "finalizing"].includes(uploadStatus.status)) {
      setStage(uploadStatus.status === "validating" ? "validating" : uploadStatus.status === "uploading" ? "verifying" : uploadStatus.status === "inconsistent" ? "failed" : uploadStatus.status);
      setStatus(uploadStatus.message);
      if (!finalizationStartedAt) setFinalizationStartedAt(Date.now());
      return;
    }
    if (uploadStatus.status === "completed" && uploadStatus.evidence_id) {
      setStage("completed");
      setStatus(uploadStatus.message);
      localStorage.removeItem(`kairon-memory-upload:${caseId}`);
      void api.getEvidence(uploadStatus.evidence_id).then((evidence) => {
        setUploadedEvidence(evidence);
        setActiveUploadId(null);
      });
      return;
    }
    setStage("failed");
    setStatus(uploadStatus.message);
  }, [caseId, finalizationStartedAt, statusQuery.data]);

  const readiness = readinessQuery.data;
  const extension = fileExtension(file);
  const extensionAllowed = isMemoryImage(file);
  const fileWithinLimit = !file || !readiness || file.size <= readiness.max_upload_bytes;
  const uploadBlockingReason = useMemo(() => {
    if (activeUploadId) return "A memory upload lifecycle is already active. Check its status before starting another upload.";
    if (stage !== "idle") return "An upload action is already in progress or requires recovery.";
    if (!file) return "No file selected.";
    if (file.size <= 0) return "The selected file is empty or its browser file handle is no longer valid. Select the file again.";
    if (!extensionAllowed) return "This file extension is not supported for memory image upload.";
    if (!providedHost.trim()) return "Source host is required.";
    if (!acknowledged) return "Authorization acknowledgement is required.";
    if (readinessQuery.isLoading || readinessQuery.isFetching) return "Memory upload readiness is still being checked.";
    if (readinessQuery.error || !readiness) return "Backend upload readiness is unavailable.";
    if (!readiness.upload_enabled) return "Memory image upload is disabled by server configuration.";
    if (!fileWithinLimit) return "The selected file exceeds the configured maximum memory upload size.";
    if (!readiness.can_accept_selected_size) return readiness.message || "Storage capacity check rejected the selected file.";
    return null;
  }, [acknowledged, activeUploadId, extensionAllowed, file, fileWithinLimit, providedHost, readiness, readinessQuery.error, readinessQuery.isFetching, readinessQuery.isLoading, stage]);
  const canUpload = uploadBlockingReason === null;
  const percent = progress.total > 0 ? Math.min(100, Math.round((progress.loaded / progress.total) * 100)) : 0;

  const summary = useMemo(() => {
    if (!file) return "Select an authorized Windows memory image to begin.";
    if (file.size <= 0) return "The selected file is empty or its browser file handle is no longer valid. Select the file again.";
    if (!extensionAllowed) return "This file extension is not supported for memory image upload.";
    if (!fileWithinLimit) return "This file exceeds the configured maximum memory upload size.";
    if (readiness && !readiness.can_accept_selected_size) return readiness.message;
    return "The selected file can be uploaded as isolated memory_dump evidence.";
  }, [extensionAllowed, file, fileWithinLimit, readiness]);

  async function upload() {
    setStage("validating");
    setStatus("Validating upload…");
    setUploadedEvidence(null);
    let uploadTransferred = false;
    let uploadId: string | null = null;
    try {
      if (uploadBlockingReason || !file) {
        throw new Error(uploadBlockingReason || "No file selected.");
      }
      setProgress({ loaded: 0, total: file.size });
      uploadId = createUploadId();
      const currentReadiness = await api.getMemoryUploadReadiness(caseId, file.size);
      if (!currentReadiness?.upload_enabled || !currentReadiness.can_accept_selected_size || file.size > currentReadiness.max_upload_bytes) {
        throw new Error(currentReadiness?.message || "Memory upload readiness could not be confirmed.");
      }
      setAcceptedReadiness(currentReadiness);
      setActiveUploadId(uploadId);
      localStorage.setItem(`kairon-memory-upload:${caseId}`, uploadId);
      setStage("uploading");
      setStatus("Uploading memory image");
      const evidence = await api.uploadEvidence(caseId, file, {
        evidenceIntent: "raw",
        packaging: "single_file",
        providedHost: providedHost.trim(),
        memoryAuthorizationAcknowledged: true,
        memoryUploadId: uploadId,
        onProgress: ({ loaded, total }) => {
          setProgress({ loaded, total: total || file.size });
          if (loaded >= (total || file.size)) {
            uploadTransferred = true;
            setStage("verifying");
            setStatus("Upload transferred; verifying and finalizing");
            setFinalizationStartedAt(Date.now());
          }
        },
      });
      setStage("finalizing");
      setStatus("Finalizing memory evidence registration");
      if (!evidence.id || evidence.evidence_type !== "memory_dump" || evidence.size_bytes !== file.size || !/^[0-9a-f]{64}$/i.test(evidence.sha256 || "")) {
        throw new Error("The server response did not confirm a finalized memory_dump evidence.");
      }
      setUploadedEvidence(evidence);
      localStorage.removeItem(`kairon-memory-upload:${caseId}`);
      setActiveUploadId(null);
      setProgress({ loaded: file.size, total: file.size });
      setStage("completed");
      setStatus("Memory image uploaded and registered.");
    } catch (error) {
      const reason = error instanceof Error ? error.message : "Memory image upload failed.";
      if (uploadTransferred) {
        try {
          const durable = uploadId ? await api.getMemoryUploadStatus(caseId, uploadId) : null;
          if (!durable) throw new Error("Durable upload status is not available.");
          if (["validating", "uploading", "verifying", "finalizing"].includes(durable.status)) {
            setStage("verifying");
            setStatus(durable.message);
            return;
          }
          setStage("failed");
          setStatus(durable.message);
          return;
        } catch {
          setStage("verifying");
          setStatus("The file was transferred. Kairon is checking its durable finalization state.");
          return;
        }
      }
      setActiveUploadId(null);
      localStorage.removeItem(`kairon-memory-upload:${caseId}`);
      setStage("failed");
      setStatus(reason);
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

  async function prepareReupload() {
    localStorage.removeItem(`kairon-memory-upload:${caseId}`);
    setActiveUploadId(null);
    setStage("idle");
    setStatus("");
    setProgress({ loaded: 0, total: file?.size || 0 });
    await readinessQuery.refetch();
  }

  if (!caseId) {
    return <div className="rounded-[28px] border border-line bg-panel/70 p-8 text-sm text-muted shadow-panel">Select a case first.</div>;
  }

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
          <div className="mt-4 grid gap-3 md:grid-cols-3 text-sm">
            <div className="rounded-2xl border border-line bg-abyss/60 p-4"><p className="text-xs uppercase tracking-[0.14em] text-muted">Maximum</p><p className="mt-1 text-ink">{readiness.max_upload_display}</p></div>
            <div className="rounded-2xl border border-line bg-abyss/60 p-4"><p className="text-xs uppercase tracking-[0.14em] text-muted">Recommended current maximum</p><p className="mt-1 text-ink">{formatBytes(readiness.recommended_max_upload_bytes)}</p></div>
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
          <button type="button" onClick={() => inputRef.current?.click()} disabled={stage === "uploading" || stage === "verifying" || stage === "finalizing"} className="self-end rounded-2xl border border-line bg-white/5 px-4 py-3 text-sm text-muted disabled:opacity-60">Select RAM image</button>
        </div>
        <input ref={inputRef} aria-label="Memory image file" type="file" accept={MEMORY_EXTENSIONS.join(",")} className="hidden" onChange={(event) => { const next = event.target.files?.[0] || null; setFile(next); setUploadedEvidence(null); setAcceptedReadiness(null); setStage("idle"); setStatus(next ? `Selected ${next.name}` : ""); }} />
        {file ? <div className="mt-4 rounded-2xl border border-line bg-abyss/60 p-4 text-sm"><p className="truncate font-medium text-ink" title={file.name}>{file.name}</p><p className="mt-1 text-muted">Extension: {extension || "none"} · Size: {formatBytes(file.size)} · Detected type: {extensionAllowed ? "Memory image" : "Unsupported"}</p><p className={`mt-2 ${extensionAllowed && fileWithinLimit && readiness?.can_accept_selected_size ? "text-mint" : "text-warning"}`}>{summary}</p></div> : null}
      </section>

      <section className="rounded-[28px] border border-line bg-panel/60 p-5">
        <div className="flex flex-wrap items-center justify-between gap-3"><div><h3 className="text-lg font-semibold">Upload</h3><p className="mt-1 text-sm text-muted">Stages: validating, uploading, verifying, finalizing, completed, failed.</p></div><button type="button" onClick={() => void upload()} disabled={!canUpload} className="rounded-2xl bg-accent px-4 py-3 text-sm font-semibold text-abyss disabled:opacity-50">{stage === "validating" ? "Validating upload…" : "Upload memory image"}</button></div>
        {uploadBlockingReason && stage === "idle" ? <p className="mt-3 rounded-xl border border-warning/30 bg-warning/10 px-3 py-2 text-sm text-warning" role="status">{uploadBlockingReason}</p> : null}
        {acceptedReadiness ? <p className="mt-3 text-xs text-muted">Accepted capacity check · Finalization: {acceptedReadiness.finalization_strategy === "staged_copy" ? "staged copy" : "atomic move"}</p> : null}
        {stage !== "idle" ? <div className="mt-4"><div className="flex justify-between text-xs text-muted"><span>{stage}</span><span>{formatBytes(progress.loaded)} / {formatBytes(progress.total)} · {percent}% transferred</span></div><div className="mt-2 h-3 overflow-hidden rounded-full bg-abyss"><div className={`h-full transition-all ${stage === "failed" ? "bg-rose-500" : stage === "completed" ? "bg-mint" : "bg-accent"}`} style={{ width: `${percent}%` }} /></div><p className={`mt-3 text-sm ${stage === "failed" ? "text-rose-200" : "text-muted"}`}>{status}</p>{stage === "verifying" || stage === "finalizing" ? <><p className="mt-2 text-xs text-muted" role="status">Server finalization is active · {elapsedSeconds}s elapsed.</p>{elapsedSeconds >= 30 ? <p className="mt-2 text-xs text-warning">The file has been transferred. Kairon is still finalizing the evidence.</p> : null}</> : null}</div> : null}
        {activeUploadId && stage !== "completed" ? <div className="mt-4 flex flex-wrap gap-2"><button type="button" onClick={() => void statusQuery.refetch()} className="rounded-xl border border-line bg-abyss/70 px-3 py-2 text-xs text-muted">Check status</button>{statusQuery.data?.retryable ? <button type="button" onClick={() => void reconcileUpload()} className="rounded-xl border border-line bg-abyss/70 px-3 py-2 text-xs text-muted">Retry finalization</button> : null}{statusQuery.data?.failure_code === "upload_bytes_lost" ? <button type="button" onClick={() => void prepareReupload()} className="rounded-xl border border-line bg-abyss/70 px-3 py-2 text-xs text-muted">Prepare new upload</button> : null}</div> : null}
        {stage === "failed" && !activeUploadId ? <div className="mt-4 flex flex-wrap gap-2"><button type="button" onClick={() => void retryUpload()} className="rounded-xl border border-line bg-abyss/70 px-3 py-2 text-xs text-muted">Retry upload</button><button type="button" onClick={() => inputRef.current?.click()} className="rounded-xl border border-line bg-abyss/70 px-3 py-2 text-xs text-muted">Select another file</button></div> : null}
        {uploadedEvidence ? <div className="mt-4 rounded-2xl border border-mint/30 bg-mint/10 p-4 text-sm"><p className="font-semibold text-ink">Upload completed</p><p className="mt-1 text-muted">Evidence ID: {uploadedEvidence.id}</p><p className="mt-1 text-muted">Type: Memory image · Size: {formatBytes(uploadedEvidence.size_bytes)}</p><div className="mt-4 flex flex-wrap gap-2"><button type="button" onClick={() => navigate(`/cases/${caseId}/memory?evidence_id=${uploadedEvidence.id}`)} className="rounded-xl bg-accent px-3 py-2 text-xs font-semibold text-abyss">Open Memory Analysis</button><button type="button" onClick={() => { setFile(null); setUploadedEvidence(null); setStage("idle"); setStatus(""); setProgress({ loaded: 0, total: 0 }); }} className="rounded-xl border border-line bg-abyss/70 px-3 py-2 text-xs text-muted">Upload another memory image</button></div></div> : null}
      </section>
    </div>
  );
}
