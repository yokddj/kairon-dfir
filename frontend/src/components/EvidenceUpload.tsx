import { useRef, useState } from "react";
import { useQuery } from "@tanstack/react-query";
import { useNavigate } from "react-router-dom";
import { CheckCircle2, LoaderCircle, UploadCloud } from "lucide-react";
import { api, type Evidence, type EvidenceIntent, type EvidencePackaging, type EvtxProfile, type IngestMode, type VelociraptorDiscoverResponse } from "../api/client";

type Props = {
  caseId: string;
  onUploaded?: () => void;
};

type UploadFlowPhase = "idle" | "preparing" | "uploading" | "analyzing" | "selection_pending" | "processing" | "completed" | "failed";
type EvidenceKind = "raw_evidence" | "parsed_evidence" | "server_path";
type UploadFormat =
  | "raw_single_file"
  | "raw_archive"
  | "raw_folder"
  | "parsed_single_file"
  | "parsed_archive"
  | "parsed_folder"
  | "server_path";
type FileIntent =
  | "raw_single_file"
  | "raw_archive"
  | "parsed_single_file"
  | "parsed_archive";

type DetectionPreview = {
  title: string;
  detail: string;
  tone: "info" | "warning";
};

function isExperimentalFolderUploadEnabled() {
  return String(import.meta.env.VITE_ENABLE_EXPERIMENTAL_FOLDER_UPLOAD ?? "").toLowerCase() === "true";
}

function getExperimentalFolderMaxFiles() {
  return Number(import.meta.env.VITE_EXPERIMENTAL_FOLDER_UPLOAD_MAX_FILES ?? 1500);
}

function getExperimentalFolderMaxTotalBytes() {
  return Number(import.meta.env.VITE_EXPERIMENTAL_FOLDER_UPLOAD_MAX_TOTAL_BYTES ?? 1073741824);
}

const KIND_OPTIONS: Array<{ id: EvidenceKind; title: string; description: string }> = [
  {
    id: "raw_evidence",
    title: "RAW evidence",
    description:
      "Original or near-original forensic evidence that still needs parsing. This can be an acquisition archive, extracted endpoint folder, EVTX files, registry hives, browser databases, email files, disk contents, or raw logs.",
  },
  {
    id: "parsed_evidence",
    title: "Parsed evidence",
    description: "Already structured evidence such as CSV, JSONL, parser exports, timelines, or artifact-specific outputs.",
  },
  {
    id: "server_path",
    title: "Server-mounted path",
    description: "Evidence already available on the server, NAS, or Docker-mounted volume. Recommended for large folders.",
  },
];

const FORMAT_OPTIONS: Record<EvidenceKind, Array<{ id: UploadFormat; title: string; description: string }>> = {
  raw_evidence: [
    {
      id: "raw_single_file",
      title: "Single file",
      description: "One RAW evidence file such as EVTX, EML, registry hive/export, browser database, log or similar artifact.",
    },
    {
      id: "raw_archive",
      title: "Compressed archive ZIP/TAR/7z",
      description: "A compressed archive containing RAW evidence. The backend may automatically detect known collection layouts, but you do not need to choose a specific tool format.",
    },
    {
      id: "raw_folder",
      title: "Folder/directory",
      description: "RAW folders from the browser are disabled by default because they are unreliable for large forensic evidence.",
    },
  ],
  parsed_evidence: [
    {
      id: "parsed_single_file",
      title: "Single file",
      description: "One structured or exported evidence file such as CSV, JSONL, parser output or timeline export.",
    },
    {
      id: "parsed_archive",
      title: "Compressed archive ZIP/TAR/7z",
      description: "A compressed archive containing parsed or structured evidence exports.",
    },
    {
      id: "parsed_folder",
      title: "Folder/directory",
      description: "Parsed folders from the browser are disabled by default because they are unreliable for large forensic evidence.",
    },
  ],
  server_path: [{ id: "server_path", title: "File or directory path", description: "A file, archive or directory already mounted or shared into the backend/worker." }],
};

function formatBytes(value: number) {
  if (!Number.isFinite(value) || value <= 0) return "0 B";
  const units = ["B", "KB", "MB", "GB", "TB"];
  let size = value;
  let unitIndex = 0;
  while (size >= 1024 && unitIndex < units.length - 1) {
    size /= 1024;
    unitIndex += 1;
  }
  return `${size >= 100 || unitIndex === 0 ? size.toFixed(0) : size.toFixed(1)} ${units[unitIndex]}`;
}

function normalizeFilePath(value: string) {
  return value.replaceAll("\\", "/").trim();
}

function isRawDiscoveryEvidence(evidence: Evidence) {
  const phase = typeof evidence.metadata_json?.current_phase === "string" ? evidence.metadata_json.current_phase : "";
  const candidates = ((evidence.metadata_json?.velociraptor_discovery as { candidates?: unknown[] } | undefined)?.candidates ?? []).length;
  const collectionKind = typeof evidence.metadata_json?.collection_kind === "string" ? evidence.metadata_json.collection_kind : "";
  const sourceType = typeof evidence.metadata_json?.source_type === "string" ? evidence.metadata_json.source_type : "";
  const rawLike = evidence.evidence_type === "velociraptor_zip" || collectionKind === "raw_evidence_collection" || sourceType === "raw_collection";
  return rawLike && phase === "waiting_selection" && candidates > 0;
}

function isEvtxFile(file: File) {
  return file.name.toLowerCase().endsWith(".evtx");
}

function isArchiveFile(file: File) {
  return /\.(zip|7z|tar|tgz|gz|bz2|xz|txz|tbz2|rar)$/i.test(file.name);
}

function isMemoryImageFile(file: File) {
  return /\.(raw|mem|vmem|dmp|lime|aff4)$/i.test(file.name);
}

function isParsedStructuredFile(file: File) {
  return /\.(csv|json|jsonl)$/i.test(file.name);
}

function buildDetectionPreview(file: File, intent: FileIntent): DetectionPreview {
  if (isMemoryImageFile(file)) {
    return {
      title: "Detected: Memory image",
      detail: "This will be uploaded as isolated memory_dump evidence and will not enter normal disk ingest.",
      tone: "warning",
    };
  }
  if (isEvtxFile(file)) {
    return {
      title: "Detected: Windows Event Log (.evtx)",
      detail: "Will be processed as RAW evidence.",
      tone: "info",
    };
  }
  if (isArchiveFile(file)) {
    return {
      title: "Detected: Compressed archive",
      detail:
        intent === "parsed_archive"
          ? "Will be processed as Parsed evidence archive."
          : "The platform will inspect the archive and process supported artifacts.",
      tone: "info",
    };
  }
  if (isParsedStructuredFile(file)) {
    return {
      title: file.name.toLowerCase().endsWith(".jsonl") ? "Detected: JSONL structured evidence" : "Detected: Structured evidence file",
      detail:
        intent === "raw_single_file"
          ? "This file looks like parsed evidence. You can still continue as RAW."
          : "Will be processed as Parsed evidence.",
      tone: intent === "raw_single_file" ? "warning" : "info",
    };
  }
  return {
    title: "Unknown file type",
    detail: "You can still upload it as RAW evidence, but parsing may be limited.",
    tone: "warning",
  };
}

async function snapshotSelectedFile(file: File): Promise<File> {
  const relativePath = normalizeFilePath((file as File & { webkitRelativePath?: string }).webkitRelativePath || "");
  const snapshot = new File([await file.arrayBuffer()], file.name, {
    type: file.type,
    lastModified: file.lastModified,
  });
  if (relativePath) {
    Object.defineProperty(snapshot, "webkitRelativePath", {
      configurable: true,
      enumerable: false,
      value: relativePath,
      writable: false,
    });
  }
  return snapshot as File & { webkitRelativePath?: string };
}

export default function EvidenceUpload({ caseId, onUploaded }: Props) {
  const navigate = useNavigate();
  const capabilitiesQuery = useQuery({ queryKey: ["storage-capabilities"], queryFn: () => api.getStorageCapabilities(), staleTime: 60_000, refetchOnWindowFocus: false });
  const systemStatusQuery = useQuery({ queryKey: ["system-status"], queryFn: () => api.getSystemStatus(), staleTime: 60_000, refetchOnWindowFocus: false });
  const experimentalFolderUploadEnabled = isExperimentalFolderUploadEnabled();
  const experimentalFolderMaxFiles = getExperimentalFolderMaxFiles();
  const experimentalFolderMaxTotalBytes = getExperimentalFolderMaxTotalBytes();

  const [selectedKind, setSelectedKind] = useState<EvidenceKind>("raw_evidence");
  const [selectedFormat, setSelectedFormat] = useState<UploadFormat>("raw_archive");
  const [uploading, setUploading] = useState(false);
  const [phase, setPhase] = useState<UploadFlowPhase>("idle");
  const [status, setStatus] = useState("Choose an evidence type and a format to start.");
  const [currentItem, setCurrentItem] = useState("");
  const [uploadBytes, setUploadBytes] = useState<{ loaded: number; total: number }>({ loaded: 0, total: 0 });
  const [serverPath, setServerPath] = useState("");
  const [serverName, setServerName] = useState("");
  const [copyToStorage, setCopyToStorage] = useState(false);
  const [ingestMode, setIngestMode] = useState<IngestMode>("usable_search");
  const [evtxProfile, setEvtxProfile] = useState<EvtxProfile>("full");
  const [showEvtxAdvanced, setShowEvtxAdvanced] = useState(false);
  const [showAdvancedProcessing, setShowAdvancedProcessing] = useState(false);
  const [showAdvancedUploadOptions, setShowAdvancedUploadOptions] = useState(false);
  const [providedHost, setProvidedHost] = useState("");
  const [pathValidation, setPathValidation] = useState<Awaited<ReturnType<typeof api.validateEvidencePath>> | null>(null);
  const [pathValidationError, setPathValidationError] = useState("");
  const [fileIntent, setFileIntent] = useState<FileIntent | null>(null);
  const [fileAccept, setFileAccept] = useState("");
  const [detectionPreview, setDetectionPreview] = useState<DetectionPreview | null>(null);
  const [pendingFile, setPendingFile] = useState<File | null>(null);
  const [latestEvidenceId, setLatestEvidenceId] = useState("");

  const fileInputRef = useRef<HTMLInputElement | null>(null);
  const folderInputRef = useRef<HTMLInputElement | null>(null);

  const capabilities = capabilitiesQuery.data;
  const uploadLimit = capabilities?.max_upload_size ?? 0;
  const allowedRoots = capabilities?.allowed_roots ?? [];
  const hostPathImportEnabled = Boolean(capabilities?.allow_host_path_import);
  const hostRequired = !providedHost.trim();
  const registerDisabled = uploading || !pathValidation?.valid || !hostPathImportEnabled || hostRequired;
  const effectiveEvtxProfile: EvtxProfile = ingestMode === "full_forensic" ? "full" : evtxProfile;
  const evtxecmdBackend = systemStatusQuery.data?.evtx_parser_backends?.evtxecmd;
  const evtxecmdAvailable = Boolean(evtxecmdBackend?.available);
  const evtxBackendLabel = evtxecmdAvailable ? `EvtxECmd CSV${evtxecmdBackend?.version ? ` ${evtxecmdBackend.version}` : ""}` : "Python EVTX fallback";
  const evtxSelectorCopy = evtxecmdAvailable
    ? "EvtxECmd is available, so Full EVTX Indexing is recommended for usable_search and provides full EVTX coverage. Fast EVTX Search remains a Beta/Triage mode with partial coverage."
    : "Python EVTX parser fallback may be slow on large evidence. Full EVTX keeps complete coverage; Fast EVTX Search is available as a Beta/Triage alternative with partial coverage.";
  const fullEvtxBadge = evtxecmdAvailable ? "Recommended with EvtxECmd" : "Full coverage / slow fallback";
  const fullEvtxHelp = evtxecmdAvailable
    ? "Indexes every selected EVTX file with the preferred EvtxECmd CSV backend and Python fallback."
    : "Indexes every selected EVTX file with the Python fallback. This can be slow on large Security.evtx files.";

  function selectedEvidenceIntent(): EvidenceIntent {
    if (selectedKind === "raw_evidence") return "raw";
    if (selectedKind === "parsed_evidence") return "parsed";
    if (selectedKind === "server_path") return "mounted";
    return "auto";
  }

  function selectedPackaging(): EvidencePackaging {
    if (selectedFormat === "raw_archive" || selectedFormat === "parsed_archive") return "archive";
    if (selectedFormat === "raw_folder" || selectedFormat === "parsed_folder") return "directory";
    if (selectedFormat === "server_path") return "mounted_path";
    return "single_file";
  }

  function buildProgressHandler(totalBytes: number) {
    return ({ loaded, total, lengthComputable }: { loaded: number; total: number; lengthComputable: boolean }) => {
      setUploadBytes({
        loaded: Math.min(loaded, totalBytes || loaded),
        total: lengthComputable && total > 0 ? totalBytes : totalBytes,
      });
    };
  }

  function resetPickers() {
    if (fileInputRef.current) fileInputRef.current.value = "";
    if (folderInputRef.current) folderInputRef.current.value = "";
  }

  function openFilePicker(intent: FileIntent, accept: string) {
    if (uploading) return;
    setFileIntent(intent);
    setFileAccept(accept);
    fileInputRef.current?.click();
  }

  function openPrimaryFilePicker() {
    if (uploading) return;
    setFileIntent(null);
    setFileAccept(".zip,.7z,.rar,.tar,.gz,.bz2,.xz,.tgz,.tbz2,.txz,.evtx,.raw,.mem,.vmem,.dmp,.lime,.aff4,.pf,.lnk,.reg,.dat,.db,.sqlite,.csv,.json,.jsonl,.log,.txt,.eml,.mbox,.pst,.ost,.xml");
    fileInputRef.current?.click();
  }

  async function uploadRawArchiveWithAutoDetection(file: File, onProgress: (progress: { loaded: number; total: number; lengthComputable: boolean }) => void) {
    try {
      return await api.discoverVelociraptorZip(caseId, file, {
        onProgress,
        ingestMode,
        providedHost: providedHost.trim() || undefined,
        evtxProfile: effectiveEvtxProfile,
      });
    } catch {
      return null;
    }
  }

  async function handleUploadFile(file: File, intent: FileIntent) {
    setDetectionPreview(buildDetectionPreview(file, intent));
    setUploading(true);
    setCurrentItem(file.name);
    setUploadBytes({ loaded: 0, total: file.size });
    setPhase("uploading");
    setStatus(
      isMemoryImageFile(file)
        ? `Uploading memory image: ${file.name}`
        : intent === "raw_archive"
        ? `Uploading RAW evidence archive: ${file.name}`
        : intent === "parsed_archive"
          ? `Uploading parsed evidence archive: ${file.name}`
          : `Uploading evidence file: ${file.name}`,
    );
    try {
      let discoveryEvidenceId: string | null = null;
      if (intent === "raw_archive") {
        const result: VelociraptorDiscoverResponse | null = await uploadRawArchiveWithAutoDetection(file, buildProgressHandler(file.size));
        if (result) {
          if (result.fallback_supported) {
            setPhase("processing");
            setStatus("This archive was processed as generic evidence.");
          } else {
            setPhase("selection_pending");
            setStatus("RAW archive recognized. Opening artifact selection.");
            discoveryEvidenceId = result.evidence.id;
          }
        } else {
          const evidence = await api.uploadEvidence(caseId, file, {
            onProgress: buildProgressHandler(file.size),
            evidenceIntent: "raw",
            packaging: "archive",
            ingestMode,
            providedHost: providedHost.trim() || undefined,
            evtxProfile: effectiveEvtxProfile,
          });
          if (isRawDiscoveryEvidence(evidence)) {
            setPhase("selection_pending");
            setStatus("RAW evidence recognized. Opening artifact selection.");
            discoveryEvidenceId = evidence.id;
          } else {
            setLatestEvidenceId(evidence.id);
            setPhase("processing");
            setStatus("This archive was processed as generic evidence.");
          }
        }
      } else {
        const evidence = await api.uploadEvidence(caseId, file, {
          onProgress: buildProgressHandler(file.size),
          evidenceIntent: intent === "parsed_single_file" || intent === "parsed_archive" ? "parsed" : "raw",
          packaging: intent === "parsed_archive" ? "archive" : "single_file",
          ingestMode,
          providedHost: providedHost.trim() || undefined,
          evtxProfile: effectiveEvtxProfile,
        });
        if (isRawDiscoveryEvidence(evidence)) {
          setPhase("selection_pending");
          setStatus("RAW evidence recognized. Opening artifact selection.");
          discoveryEvidenceId = evidence.id;
        } else {
          setLatestEvidenceId(evidence.id);
          setPhase(evidence.evidence_type === "memory_dump" ? "completed" : "processing");
          setStatus(
            evidence.evidence_type === "memory_dump"
              ? "Memory image uploaded and finalized. Open Memory Analysis to run authorized metadata or process analysis."
              : isEvtxFile(file)
              ? "Detected: Windows Event Log (.evtx). Ingest started."
              : intent === "parsed_single_file" || intent === "parsed_archive"
                ? "Parsed evidence accepted. Ingest started."
                : "RAW evidence accepted. Ingest started.",
          );
        }
      }
      setUploadBytes({ loaded: file.size, total: file.size });
      onUploaded?.();
      if (discoveryEvidenceId) {
        setLatestEvidenceId(discoveryEvidenceId);
        navigate(`/evidences/${discoveryEvidenceId}`);
      }
    } catch (error) {
      setPhase("failed");
      setStatus(error instanceof Error ? error.message : "The backend could not be reached.");
    } finally {
      resetPickers();
      setUploading(false);
    }
  }

  async function handleExperimentalFolderUpload(files: FileList | null) {
    if (!files?.length || uploading) return;
    if (!providedHost.trim()) {
      setStatus("Enter the host name before indexing evidence.");
      resetPickers();
      return;
    }
    const selectedFiles = await Promise.all(Array.from(files).map((file) => snapshotSelectedFile(file)));
    const totalBytes = selectedFiles.reduce((sum, file) => sum + file.size, 0);
    const folderName = normalizeFilePath((selectedFiles[0] as File & { webkitRelativePath?: string }).webkitRelativePath || selectedFiles[0].name).split("/")[0] || "folder";
    if (selectedFiles.length > experimentalFolderMaxFiles) {
      setPhase("failed");
      setStatus(
        `Browser folder upload is experimental and limited to ${experimentalFolderMaxFiles} files. Compress the folder into ZIP/TAR/7z or use Register server-mounted path.`,
      );
      resetPickers();
      return;
    }
    if (totalBytes > experimentalFolderMaxTotalBytes) {
      setPhase("failed");
      setStatus(
        `Browser folder upload is experimental and limited to ${formatBytes(experimentalFolderMaxTotalBytes)}. Compress the folder into ZIP/TAR/7z or use Register server-mounted path.`,
      );
      resetPickers();
      return;
    }

    setUploading(true);
    setCurrentItem(folderName);
    setUploadBytes({ loaded: 0, total: totalBytes });
    setPhase("uploading");
    setStatus(`Experimental browser folder upload: ${folderName}`);
    try {
      const evidence = await api.uploadEvidenceFolder(caseId, selectedFiles, {
        onProgress: buildProgressHandler(totalBytes),
        evidenceIntent: selectedKind === "parsed_evidence" ? "parsed" : "raw",
        ingestMode,
        providedHost: providedHost.trim() || undefined,
        evtxProfile: effectiveEvtxProfile,
      });
      if (isRawDiscoveryEvidence(evidence)) {
        setPhase("selection_pending");
        setStatus("RAW evidence folder recognized. Opening artifact selection.");
        navigate(`/evidences/${evidence.id}`);
      } else {
        setPhase("processing");
        setStatus("Experimental folder upload accepted. Ingest started.");
      }
      setUploadBytes({ loaded: totalBytes, total: totalBytes });
      onUploaded?.();
    } catch (error) {
      setPhase("failed");
      setStatus(error instanceof Error ? error.message : "Folder upload failed. Compress the folder or use a server-mounted path.");
    } finally {
      resetPickers();
      setUploading(false);
    }
  }

  async function onFileInputChange(files: FileList | null) {
    if (!files?.length) return;
    const file = await snapshotSelectedFile(files[0]);
    const inferredIntent: FileIntent = fileIntent ?? (isArchiveFile(file) ? "raw_archive" : "raw_single_file");
    setSelectedKind(inferredIntent.startsWith("parsed") ? "parsed_evidence" : "raw_evidence");
    setSelectedFormat(inferredIntent === "raw_archive" ? "raw_archive" : inferredIntent === "parsed_archive" ? "parsed_archive" : inferredIntent === "parsed_single_file" ? "parsed_single_file" : "raw_single_file");
    setFileIntent(inferredIntent);
    setPendingFile(file);
    setDetectionPreview(buildDetectionPreview(file, inferredIntent));
    setStatus(`Ready to index: ${file.name}`);
    resetPickers();
  }

  async function startIndexing() {
    if (!providedHost.trim()) {
      setStatus("Host name is required before indexing evidence.");
      return;
    }
    if (selectedKind === "server_path") {
      if (!pathValidation?.valid) {
        const validatedPath = await validateServerPath();
        if (!validatedPath?.valid) {
          setStatus("Validate the server-mounted path before indexing.");
          return;
        }
      }
      await registerServerPath(true);
      return;
    }
    if (!pendingFile) {
      setStatus("Add an evidence file before indexing.");
      return;
    }
    await handleUploadFile(pendingFile, fileIntent ?? (isArchiveFile(pendingFile) ? "raw_archive" : "raw_single_file"));
  }

  async function validateServerPath() {
    setPathValidationError("");
    setPathValidation(null);
    try {
      const result = await api.validateEvidencePath({
        path: serverPath,
        copy_to_storage: copyToStorage,
        evidence_intent: selectedEvidenceIntent(),
        packaging: selectedPackaging(),
      });
      setPathValidation(result);
      if (!result.valid) {
        setPathValidationError(result.message || result.error || "Invalid path");
      }
      return result;
    } catch (error) {
      setPathValidationError(error instanceof Error ? error.message : "The backend could not be reached.");
      return null;
    }
  }

  async function registerServerPath(startIngest: boolean) {
    if (!providedHost.trim()) {
      setStatus("Enter the host name before indexing evidence.");
      return;
    }
    setUploading(true);
    setPhase("processing");
    setStatus("Registering server-mounted path");
    try {
      const evidence = await api.registerEvidencePath(caseId, {
        path: serverPath,
        name: serverName || undefined,
        copy_to_storage: copyToStorage,
        start_ingest: startIngest,
        storage_mode: "mounted_path",
        evidence_intent: selectedEvidenceIntent(),
        packaging: selectedPackaging(),
        ingest_mode: ingestMode,
        provided_host: providedHost.trim() || undefined,
        evtx_profile: effectiveEvtxProfile,
      });
      onUploaded?.();
      setLatestEvidenceId(evidence.id);
      setPhase("completed");
      setStatus(startIngest ? "Server-mounted path registered and ingest started." : "Server-mounted path registered.");
      navigate(`/evidences/${evidence.id}`);
    } catch (error) {
      setPhase("failed");
      setStatus(error instanceof Error ? error.message : "Server-mounted path registration failed.");
    } finally {
      setUploading(false);
    }
  }

  const currentFormatOption = FORMAT_OPTIONS[selectedKind].find((option) => option.id === selectedFormat);
  const progressPct = uploadBytes.total > 0 ? Math.round((uploadBytes.loaded / uploadBytes.total) * 100) : phase === "completed" ? 100 : 0;
  const statusTone = phase === "failed" ? "text-danger" : phase === "completed" ? "text-mint" : "text-accent";
  const showStatusPanel = phase !== "idle" || uploading || status !== "Choose an evidence type and a format to start.";

  function showFolderWarning(kind: "raw" | "parsed") {
    return (
      <div className="space-y-4 rounded-3xl border border-warning/40 bg-warning/10 p-5">
        <p className="font-mono text-[11px] uppercase tracking-[0.16em] text-warning">Recommended method</p>
        <p className="text-sm text-warning">Browser folder upload is not recommended for forensic evidence.</p>
        <p className="text-sm text-muted">Browser folder upload is not recommended for forensic evidence with many files. Compress the folder into ZIP/TAR/7z or use a server-mounted path.</p>
        <div className="flex flex-wrap gap-3">
          <button
            type="button"
            onClick={() => {
              setSelectedKind(kind === "raw" ? "raw_evidence" : "parsed_evidence");
              setSelectedFormat(kind === "raw" ? "raw_archive" : "parsed_archive");
            }}
            className="rounded-2xl bg-accent px-4 py-3 text-sm font-semibold text-abyss"
          >
            Upload compressed archive
          </button>
          <button
            type="button"
            onClick={() => {
              setSelectedKind("server_path");
              setSelectedFormat("server_path");
            }}
            className="rounded-2xl border border-line bg-panel/80 px-4 py-3 text-sm text-ink"
          >
            Register server-mounted path
          </button>
        </div>
        <div className="rounded-2xl border border-line bg-panel/70 p-4 text-xs text-muted">
          <p className="font-semibold text-ink">How to create an archive</p>
          <p className="mt-2">macOS / Linux: `zip -r evidence.zip /path/to/folder`</p>
          <p className="mt-1">Windows PowerShell: `Compress-Archive -Path C:\Evidence\* -DestinationPath C:\Evidence.zip`</p>
        </div>
        {experimentalFolderUploadEnabled ? (
          <div className="rounded-2xl border border-danger/30 bg-danger/10 p-4 text-sm text-danger">
            <p className="font-semibold">Experimental browser folder upload</p>
            <p className="mt-2">This path is unreliable for many files. Limit: {experimentalFolderMaxFiles} files and {formatBytes(experimentalFolderMaxTotalBytes)} total.</p>
            <button type="button" disabled={uploading || hostRequired} onClick={() => folderInputRef.current?.click()} className="mt-4 rounded-2xl border border-danger/40 bg-danger/10 px-4 py-3 text-sm font-semibold text-danger disabled:opacity-60">
              Try experimental folder upload
            </button>
          </div>
        ) : null}
      </div>
    );
  }

  function renderRecommendedMethod() {
    if (selectedFormat === "raw_archive") {
      return (
        <div className="rounded-3xl border border-line bg-panel/70 p-5">
          <p className="font-mono text-[11px] uppercase tracking-[0.16em] text-accent">Recommended method</p>
          <p className="mt-3 text-sm text-muted">Upload a RAW evidence archive. The backend may automatically detect known collection layouts and, if it does not, it will fall back to generic archive ingest.</p>
          <button type="button" disabled={uploading || hostRequired} onClick={() => openFilePicker("raw_archive", ".zip,.7z,.rar,.tar,.gz,.bz2,.xz,.tgz,.tbz2,.txz")} className="mt-4 rounded-2xl bg-accent px-4 py-3 text-sm font-semibold text-abyss disabled:opacity-60">
            Upload RAW evidence archive
          </button>
        </div>
      );
    }
    if (selectedFormat === "parsed_archive") {
      return (
        <div className="rounded-3xl border border-line bg-panel/70 p-5">
          <p className="font-mono text-[11px] uppercase tracking-[0.16em] text-accent">Recommended method</p>
          <p className="mt-3 text-sm text-muted">Upload a parsed evidence archive and process it as structured evidence.</p>
          <button type="button" disabled={uploading || hostRequired} onClick={() => openFilePicker("parsed_archive", ".zip,.7z,.rar,.tar,.gz,.bz2,.xz,.tgz,.tbz2,.txz")} className="mt-4 rounded-2xl bg-accent px-4 py-3 text-sm font-semibold text-abyss disabled:opacity-60">
            Upload parsed evidence archive
          </button>
        </div>
      );
    }
    if (selectedFormat === "parsed_single_file") {
      return (
        <div className="rounded-3xl border border-line bg-panel/70 p-5">
          <p className="font-mono text-[11px] uppercase tracking-[0.16em] text-accent">Recommended method</p>
          <p className="mt-3 text-sm text-muted">Upload a parsed evidence file such as CSV, JSONL, timeline export or parser output.</p>
          <button type="button" disabled={uploading || hostRequired} onClick={() => openFilePicker("parsed_single_file", ".csv,.json,.jsonl,.txt,.log,.xml")} className="mt-4 rounded-2xl bg-accent px-4 py-3 text-sm font-semibold text-abyss disabled:opacity-60">
            Upload parsed evidence file
          </button>
        </div>
      );
    }
    if (selectedFormat === "raw_single_file") {
      return (
        <div className="rounded-3xl border border-line bg-panel/70 p-5">
          <p className="font-mono text-[11px] uppercase tracking-[0.16em] text-accent">Recommended method</p>
          <p className="mt-3 text-sm text-muted">Upload a RAW evidence file such as EVTX, EML, registry hive/export, database, log or similar artifact.</p>
          <button type="button" disabled={uploading || hostRequired} onClick={() => openFilePicker("raw_single_file", ".evtx,.pf,.lnk,.reg,.dat,.db,.sqlite,.csv,.json,.jsonl,.log,.txt,.eml,.mbox,.pst,.ost,.xml")} className="mt-4 rounded-2xl bg-accent px-4 py-3 text-sm font-semibold text-abyss disabled:opacity-60">
            Upload RAW evidence file
          </button>
        </div>
      );
    }
    if (selectedFormat === "raw_folder") {
      return showFolderWarning("raw");
    }
    if (selectedFormat === "parsed_folder") {
      return showFolderWarning("parsed");
    }
    return (
      <div className="rounded-3xl border border-line bg-panel/70 p-5">
        <p className="font-mono text-[11px] uppercase tracking-[0.16em] text-accent">Recommended method</p>
        <p className="mt-3 text-sm text-muted">Register the path that is already available on the server. This is the recommended flow for large folders, NAS shares and Docker-mounted evidence.</p>
      </div>
    );
  }

  function renderEvtxProfileSelector() {
    return (
      <div className="mt-4 rounded-2xl border border-line bg-abyss/60 p-4">
        <div className="flex flex-wrap items-start justify-between gap-3">
          <div>
            <p className="font-mono text-[11px] uppercase tracking-[0.16em] text-accent">EVTX handling</p>
            <p className="mt-2 text-sm text-muted">
              {evtxecmdAvailable
                ? "If EVTX files are discovered, they will be parsed with EvtxECmd CSV using Full EVTX coverage by default."
                : evtxSelectorCopy}
            </p>
            <p className="mt-1 text-xs text-muted">EVTX parser: <span className="font-semibold text-ink">{evtxBackendLabel}</span></p>
          </div>
          <span className={`rounded-full border px-3 py-1 font-mono text-[11px] uppercase tracking-[0.16em] ${evtxecmdAvailable ? "border-amber/30 bg-amber/10 text-amber" : "border-accent/30 bg-accent/10 text-accent"}`}>
            {evtxecmdAvailable ? "Full coverage default" : "Fallback warning"}
          </span>
        </div>
        {evtxecmdAvailable ? (
          <button type="button" onClick={() => setShowEvtxAdvanced((current) => !current)} className="mt-3 rounded-full border border-line px-3 py-1.5 text-xs text-muted">
            {showEvtxAdvanced ? "Hide Advanced/Beta EVTX options" : "Advanced/Beta EVTX options"}
          </button>
        ) : null}
        {evtxecmdAvailable && !showEvtxAdvanced ? null : (
        <div className="mt-4 grid gap-3 xl:grid-cols-2">
          <button
            type="button"
            onClick={() => setEvtxProfile("fast_high_value")}
            className={`rounded-2xl border px-4 py-3 text-left ${evtxProfile === "fast_high_value" ? "border-accent bg-accent/10 text-ink" : "border-line bg-panel/40 text-muted"}`}
          >
            <div className="flex flex-wrap items-center justify-between gap-2">
              <p className="text-sm font-semibold">Fast EVTX Search</p>
              <span className="font-mono text-[11px] uppercase tracking-[0.16em] text-accent">Beta / Triage</span>
            </div>
            <p className="mt-2 text-xs">Indexes high-value logs with safety limits. This is not full EVTX coverage; large logs may be partially indexed for later continuation.</p>
          </button>
          <button
            type="button"
            onClick={() => setEvtxProfile("full")}
            className={`rounded-2xl border px-4 py-3 text-left ${evtxProfile === "full" ? "border-amber bg-amber/10 text-ink" : "border-line bg-panel/40 text-muted"}`}
          >
            <div className="flex flex-wrap items-center justify-between gap-2">
              <p className="text-sm font-semibold">Full EVTX Indexing</p>
              <span className="font-mono text-[11px] uppercase tracking-[0.16em] text-amber">{fullEvtxBadge}</span>
            </div>
            <p className="mt-2 text-xs">{fullEvtxHelp}</p>
          </button>
        </div>
        )}
        {!evtxecmdAvailable && evtxProfile === "full" ? <p className="mt-3 text-xs text-amber">Python EVTX parser fallback may take a long time on evidence with many EVTX files.</p> : null}
      </div>
    );
  }

  function renderServerPathSection() {
    if (selectedKind !== "server_path") return null;
    return (
      <div className="rounded-3xl border border-line bg-panel/70 p-6 shadow-panel">
        <div className="space-y-3">
          <p className="text-sm text-muted">
            Register a file, archive or directory path already present on the server.
          </p>
          <div className="rounded-2xl border border-warning/30 bg-warning/10 p-4 text-sm text-warning">
            This must be a path visible to the backend and worker, not a path from your analyst workstation.
            <div className="mt-2 text-xs">Debe ser una ruta visible para backend y worker, no una ruta local del equipo desde el que abres el navegador.</div>
          </div>
          {!hostPathImportEnabled ? (
            <div className="rounded-2xl border border-danger/30 bg-danger/10 p-4 text-sm text-danger">
              <p>Mounted path import is disabled. The backend and worker cannot access analyst PC paths directly.</p>
              <p className="mt-2">Enable it in System / Performance → Evidence storage, then configure allowed roots visible to the server.</p>
              <button type="button" onClick={() => navigate("/system/performance?tab=evidence-storage")} className="mt-3 rounded-2xl border border-danger/40 bg-danger/10 px-4 py-2 text-xs font-semibold text-danger">
                Open System / Performance
              </button>
            </div>
          ) : null}
        </div>
        <div className="mt-4 grid gap-4 xl:grid-cols-2">
          <label className="block">
            <span className="mb-2 block font-mono text-[11px] uppercase tracking-[0.16em] text-muted">Server-mounted path</span>
            <input value={serverPath} onChange={(event) => setServerPath(event.target.value)} placeholder="/mnt/evidence/case001 or /mnt/evidence/case001/archive.7z" className="w-full rounded-2xl border border-line bg-abyss/80 px-4 py-3 text-sm" />
          </label>
          <label className="block">
            <span className="mb-2 block font-mono text-[11px] uppercase tracking-[0.16em] text-muted">Name (optional)</span>
            <input value={serverName} onChange={(event) => setServerName(event.target.value)} placeholder="CASE001 mounted evidence" className="w-full rounded-2xl border border-line bg-abyss/80 px-4 py-3 text-sm" />
          </label>
        </div>
        <label className="mt-4 flex items-center gap-3 text-sm text-muted">
          <input type="checkbox" checked={copyToStorage} onChange={(event) => setCopyToStorage(event.target.checked)} />
          Copy to internal storage before ingest
        </label>
        <p className="mt-2 text-xs text-muted">If you keep this unchecked, deleting the evidence record will not delete the external source path.</p>
        <div className="mt-4 rounded-2xl border border-line bg-abyss/60 p-4 text-sm text-muted">
          <p className="font-mono text-[11px] uppercase tracking-[0.16em] text-muted">Allowed evidence roots</p>
          <p className="mt-2">{allowedRoots.length ? allowedRoots.join(", ") : "Host path import disabled or not configured."}</p>
        </div>
        <div className="mt-4 flex flex-wrap gap-3">
          <button type="button" disabled={!serverPath.trim() || uploading || !hostPathImportEnabled} onClick={() => void validateServerPath()} className="rounded-2xl border border-line bg-white/5 px-4 py-3 text-sm text-muted disabled:opacity-60">
            Validate path
          </button>
          <button type="button" disabled={registerDisabled} onClick={() => void registerServerPath(false)} className="rounded-2xl border border-line bg-white/5 px-4 py-3 text-sm text-muted disabled:opacity-60">
            Register path
          </button>
          <button type="button" disabled={registerDisabled} onClick={() => void registerServerPath(true)} className="rounded-2xl bg-accent px-4 py-3 text-sm font-semibold text-abyss disabled:opacity-60">
            Register path and ingest
          </button>
        </div>
        {pathValidationError ? <div className="mt-4 rounded-2xl border border-danger/30 bg-danger/10 p-3 text-sm text-danger">{pathValidationError}</div> : null}
        {pathValidation ? (
          <div className="mt-4 rounded-2xl border border-line bg-abyss/60 p-4 text-sm text-muted">
            {pathValidation.message ? <p className={`mb-3 ${pathValidation.valid ? "text-mint" : "text-warning"}`}>{pathValidation.message}</p> : null}
            <div className="grid gap-3 md:grid-cols-2">
              <p>exists: <span className="text-white">{String(pathValidation.exists)}</span></p>
              <p>readable: <span className="text-white">{String(pathValidation.readable)}</span></p>
              <p>within allowed root: <span className="text-white">{String(pathValidation.within_allowed_root)}</span></p>
              <p>path style: <span className="text-white">{pathValidation.path_style || "-"}</span></p>
              <p>looks like client path: <span className="text-white">{String(pathValidation.looks_like_client_path ?? false)}</span></p>
              <p>suggested action: <span className="text-white">{pathValidation.suggested_action || "-"}</span></p>
              <p>type: <span className="text-white">{pathValidation.is_directory ? "directory" : pathValidation.is_file ? "file" : "unknown"}</span></p>
              <p>resolved: <span className="text-white">{pathValidation.resolved_path || "-"}</span></p>
              <p>estimated size: <span className="text-white">{pathValidation.size_bytes ? formatBytes(pathValidation.size_bytes) : "-"}</span></p>
              <p>file count: <span className="text-white">{pathValidation.file_count ?? "-"}</span></p>
            </div>
          </div>
        ) : null}
      </div>
    );
  }

  return (
    <div className="space-y-6">
      <div className="rounded-3xl border border-line bg-panel/70 p-6">
        <div className="flex items-start gap-4">
          <div className="rounded-2xl border border-accent/30 bg-accent/10 p-3 text-accent">
            <UploadCloud />
          </div>
          <div>
            <p className="font-mono text-[11px] uppercase tracking-[0.16em] text-accent">Evidence & Ingest</p>
            <p className="mt-2 text-sm text-muted">Guided upload flow for RAW evidence, parsed evidence and server-mounted evidence. Technology-specific detection is automatic. Browser folder upload is intentionally not the primary path for forensic evidence.</p>
          </div>
        </div>
      </div>

      <div className="sticky top-4 z-10 rounded-3xl border border-accent/30 bg-panel/95 p-6 shadow-panel backdrop-blur">
        <div className="grid gap-4 xl:grid-cols-[minmax(0,1.2fr)_minmax(0,1fr)]">
          <div>
            <p className="font-mono text-[11px] uppercase tracking-[0.16em] text-accent">Core indexing</p>
            <h3 className="mt-2 text-lg font-semibold text-ink">Index evidence</h3>
            <p className="mt-2 text-sm text-muted">Recommended: parses supported artifacts and makes them searchable. Rules, reports and enrichment stay on-demand after indexing.</p>
          </div>
          <div className="rounded-2xl border border-line bg-abyss/60 p-4 text-sm text-muted">
            <p className="font-mono text-[11px] uppercase tracking-[0.16em] text-accent">Default processing</p>
            <p className="mt-2 text-base font-semibold text-ink">{ingestMode === "usable_search" ? "Core indexing" : "Advanced forensic processing"}</p>
            <p className="mt-1 text-xs text-muted">
              {ingestMode === "usable_search"
                ? "Search-first ingest. Heavy modules do not run automatically."
                : "Deeper processing selected intentionally. This can take significantly longer."}
            </p>
            {providedHost.trim() ? <p className="mt-3 text-xs text-slate-300">Evidence host: {providedHost.trim()}</p> : null}
          </div>
        </div>
        <div className="mt-4 rounded-3xl border border-line bg-panel/40 p-5">
          <div className="flex flex-wrap items-center justify-between gap-3">
            <div>
              <p className="text-sm font-semibold text-ink">Primary flow: Index evidence</p>
              <p className="mt-2 text-sm text-muted">Internally this uses the core searchable ingest path. Full forensic processing remains available under Advanced.</p>
            </div>
            <span className="rounded-full border border-accent/30 bg-accent/10 px-3 py-1 font-mono text-[11px] uppercase tracking-[0.16em] text-accent">Recommended</span>
          </div>
          <button
            type="button"
            onClick={() => setShowAdvancedProcessing((current) => !current)}
            className="mt-4 rounded-full border border-line px-3 py-1.5 text-xs text-muted"
          >
            {showAdvancedProcessing ? "Hide Advanced processing" : "Advanced processing"}
          </button>
          {showAdvancedProcessing ? (
            <div className="mt-4 rounded-2xl border border-amber/30 bg-amber/10 p-4">
              <div className="flex flex-wrap items-center justify-between gap-3">
                <div>
                  <p className="text-sm font-semibold text-ink">Run advanced forensic processing</p>
                  <p className="mt-2 text-sm text-muted">Enables deeper parser tiers and inline detections. Use only when you explicitly need that behavior.</p>
                </div>
                <button
                  type="button"
                  onClick={() => {
                    const nextMode = ingestMode === "full_forensic" ? "usable_search" : "full_forensic";
                    setIngestMode(nextMode);
                    if (nextMode === "full_forensic") setEvtxProfile("full");
                  }}
                  className={`rounded-2xl border px-4 py-2 text-sm font-semibold ${ingestMode === "full_forensic" ? "border-amber bg-amber/20 text-amber" : "border-line bg-panel/50 text-muted"}`}
                >
                  {ingestMode === "full_forensic" ? "Advanced selected" : "Select Advanced"}
                </button>
              </div>
            </div>
          ) : null}
        </div>
        {showAdvancedUploadOptions && selectedKind === "raw_evidence" ? renderEvtxProfileSelector() : null}
        <div className="mt-4 grid gap-4 xl:grid-cols-2">
          <label className="block">
            <span className="mb-2 block font-mono text-[11px] uppercase tracking-[0.16em] text-muted">Host name required</span>
            <input required value={providedHost} onChange={(event) => setProvidedHost(event.target.value)} placeholder="HOSTA or hosta.examplecorp.local" className="w-full rounded-2xl border border-line bg-abyss/80 px-4 py-3 text-sm" />
            <span className="mt-2 block text-xs text-muted">Name of the computer this evidence belongs to. This becomes the canonical host for filters unless a reliable artifact conflict is recorded.</span>
          </label>
          <div className="rounded-2xl border border-line bg-abyss/60 p-4 text-sm text-muted">
            <p className="font-mono text-[11px] uppercase tracking-[0.16em] text-accent">Before you launch</p>
            <ul className="mt-3 space-y-1 text-xs text-muted">
              <li>Processing: {ingestMode === "usable_search" ? "Core indexing (default)" : "Advanced forensic processing"}</li>
                {selectedKind === "raw_evidence" ? <li>EVTX: Full EVTX Indexing if EVTX is discovered</li> : null}
              <li>Packaging: {selectedPackaging().replaceAll("_", " ")}</li>
              <li>Intent: {selectedEvidenceIntent()}</li>
            </ul>
          </div>
        </div>
      </div>

      <div data-testid="upload-wizard-simple-flow" className="grid gap-4 xl:grid-cols-4">
        <div className="rounded-3xl border border-line bg-panel/70 p-5">
          <p className="font-mono text-[11px] uppercase tracking-[0.16em] text-accent">Step 1</p>
          <h3 className="mt-2 text-lg font-semibold text-ink">Select case</h3>
          <p className="mt-2 text-sm text-muted">This evidence will be added to the current case.</p>
          <p className="mt-3 rounded-2xl border border-line bg-abyss/60 px-4 py-3 text-sm text-ink">Case: {caseId}</p>
        </div>
        <div className="rounded-3xl border border-line bg-panel/70 p-5">
          <p className="font-mono text-[11px] uppercase tracking-[0.16em] text-accent">Step 2</p>
          <h3 className="mt-2 text-lg font-semibold text-ink">Identify host</h3>
          <p className="mt-2 text-sm text-muted">Which computer does this evidence come from?</p>
          <p className={`mt-3 text-xs ${providedHost.trim() ? "text-mint" : "text-warning"}`}>{providedHost.trim() ? `Host: ${providedHost.trim()}` : "Host name is required."}</p>
        </div>
        <div className="rounded-3xl border border-line bg-panel/70 p-5">
          <p className="font-mono text-[11px] uppercase tracking-[0.16em] text-accent">Step 3</p>
          <h3 className="mt-2 text-lg font-semibold text-ink">Add evidence</h3>
          <p className="mt-2 text-sm text-muted">Drop in an archive or evidence file. The app detects supported artifacts automatically.</p>
          {pendingFile ? (
            <div className="mt-3 rounded-2xl border border-line bg-abyss/60 p-3 text-sm">
              <p className="truncate text-ink" title={pendingFile.name}>{pendingFile.name}</p>
              <p className="mt-1 text-xs text-muted">{formatBytes(pendingFile.size)} · {detectionPreview?.title ?? "Ready to index"}</p>
              {isMemoryImageFile(pendingFile) ? (
                <div className="mt-3 rounded-xl border border-warning/30 bg-warning/10 p-3 text-xs text-warning">
                  <p className="font-semibold">Memory image</p>
                  <p className="mt-1">Memory images may contain credentials, personal data, encryption material, browser data, and other sensitive information. Upload only evidence that you own or are explicitly authorized to analyze.</p>
                  <p className="mt-1 text-muted">It will be stored as memory_dump evidence, bypass normal disk ingest, and processing occurs later in Memory Analysis.</p>
                  {uploadLimit > 0 ? <p className="mt-1 text-muted">Configured upload limit: {formatBytes(uploadLimit)}</p> : null}
                </div>
              ) : null}
            </div>
          ) : null}
          <button type="button" onClick={openPrimaryFilePicker} disabled={uploading} className="mt-4 rounded-2xl border border-line bg-white/5 px-4 py-3 text-sm text-muted disabled:opacity-60">
            {pendingFile ? "Change evidence file" : "Add evidence file"}
          </button>
        </div>
        <div className="rounded-3xl border border-accent/30 bg-accent/8 p-5">
          <p className="font-mono text-[11px] uppercase tracking-[0.16em] text-accent">Step 4</p>
          <h3 className="mt-2 text-lg font-semibold text-ink">Review and index</h3>
          <p className="mt-2 text-sm text-muted">The app will extract and index searchable artifacts. You can run rules and reports later.</p>
          <ul className="mt-3 space-y-1 text-xs text-muted">
            <li>Processing: Core indexing</li>
            <li>EVTX: Full coverage with EvtxECmd if event logs are found</li>
            <li>Rules/reports: on-demand after indexing</li>
          </ul>
          <button type="button" onClick={() => void startIndexing()} disabled={uploading || !providedHost.trim() || (!pendingFile && selectedKind !== "server_path")} className="mt-4 w-full rounded-2xl bg-accent px-4 py-3 text-sm font-semibold text-abyss disabled:opacity-60">
            {uploading ? "Indexing..." : "Index evidence"}
          </button>
        </div>
      </div>

      <details className="rounded-3xl border border-line bg-panel/60 p-5" open={showAdvancedUploadOptions} onToggle={(event) => setShowAdvancedUploadOptions(event.currentTarget.open)}>
        <summary className="cursor-pointer font-mono text-[11px] uppercase tracking-[0.16em] text-muted">Advanced options</summary>
        <p className="mt-3 text-sm text-muted">Use these only when you need to override automatic detection, register a server path, or choose parsed evidence handling manually.</p>
      </details>

      {showAdvancedUploadOptions ? (
      <div className="grid gap-4 xl:grid-cols-3">
        <div className="rounded-3xl border border-line bg-panel/70 p-5 xl:col-span-3">
          <p className="font-mono text-[11px] uppercase tracking-[0.16em] text-accent">Step 1</p>
          <h3 className="mt-2 text-lg font-semibold text-ink">What are you adding?</h3>
          <div className="mt-4 grid gap-4 xl:grid-cols-3">
            {KIND_OPTIONS.map((option) => (
              <button
                key={option.id}
                type="button"
                onClick={() => {
                  setSelectedKind(option.id);
                  setSelectedFormat(FORMAT_OPTIONS[option.id][0].id);
                  setDetectionPreview(null);
                }}
                className={`rounded-3xl border p-5 text-left transition ${selectedKind === option.id ? "border-accent bg-accent/10" : "border-line bg-panel/50 hover:border-accent/40"}`}
              >
                <p className="text-sm font-semibold text-ink">{option.title}</p>
                <p className="mt-2 text-sm text-muted">{option.description}</p>
              </button>
            ))}
          </div>
        </div>

        <div className="rounded-3xl border border-line bg-panel/70 p-5 xl:col-span-3">
          <p className="font-mono text-[11px] uppercase tracking-[0.16em] text-accent">Step 2</p>
          <h3 className="mt-2 text-lg font-semibold text-ink">Format</h3>
          <div className="mt-4 grid gap-4 xl:grid-cols-3">
            {FORMAT_OPTIONS[selectedKind].map((option) => (
              <button
                key={option.id}
                type="button"
                onClick={() => {
                  setSelectedFormat(option.id);
                  setDetectionPreview(null);
                }}
                className={`rounded-3xl border p-5 text-left transition ${selectedFormat === option.id ? "border-accent bg-accent/10" : "border-line bg-panel/50 hover:border-accent/40"}`}
              >
                <p className="text-sm font-semibold text-ink">{option.title}</p>
                <p className="mt-2 text-sm text-muted">{option.description}</p>
              </button>
            ))}
          </div>
        </div>

        <div className="rounded-3xl border border-line bg-panel/70 p-5 xl:col-span-3">
          <p className="font-mono text-[11px] uppercase tracking-[0.16em] text-accent">Step 3</p>
          <h3 className="mt-2 text-lg font-semibold text-ink">Launch summary</h3>
          <p className="mt-2 text-sm text-muted">This evidence will be indexed first so Search is available quickly. Advanced processing remains opt-in.</p>
          <div className="mt-4 grid gap-4 xl:grid-cols-[minmax(0,1.2fr)_minmax(0,1fr)]">
            <div className="rounded-3xl border border-line bg-panel/40 p-5">
              <div className="flex flex-wrap items-center justify-between gap-3">
                <p className="text-sm font-semibold text-ink">Processing: {ingestMode === "usable_search" ? "Core indexing" : "Advanced forensic processing"}</p>
                <span className={`rounded-full border px-3 py-1 font-mono text-[11px] uppercase tracking-[0.16em] ${ingestMode === "usable_search" ? "border-accent/30 bg-accent/10 text-accent" : "border-amber/30 bg-amber/10 text-amber"}`}>
                  {ingestMode === "usable_search" ? "Default" : "Advanced"}
                </span>
              </div>
              <ul className="mt-3 space-y-1 text-xs text-muted">
                <li>Packaging: {selectedPackaging().replaceAll("_", " ")}</li>
                <li>Intent: {selectedEvidenceIntent()}</li>
                <li>Host: {providedHost.trim() || "Required before indexing"}</li>
                {selectedKind === "raw_evidence" ? <li>EVTX: Full EVTX Indexing if EVTX is discovered</li> : null}
              </ul>
              {ingestMode === "usable_search" ? (
                <p className="mt-3 text-sm text-muted">Parses supported artifacts and makes them searchable. Rules, reports and enrichment can run later.</p>
              ) : (
                <p className="mt-3 text-sm text-amber">Full Forensic mode can take significantly longer. Use it only when you explicitly need deeper processing.</p>
              )}
            </div>
            <div className="rounded-3xl border border-line bg-panel/40 p-5">
              <p className="font-mono text-[11px] uppercase tracking-[0.16em] text-accent">Launch checklist</p>
              <ul className="mt-3 space-y-1 text-xs text-muted">
                <li>Core indexing is sent to the backend unless Advanced processing is selected.</li>
                <li>RAW archive autodetection keeps the chosen mode.</li>
                <li>Rules, reports and enrichment remain manual in Usable Search.</li>
              </ul>
            </div>
          </div>
        </div>

        <div className="rounded-3xl border border-line bg-panel/70 p-5 xl:col-span-3">
          <p className="font-mono text-[11px] uppercase tracking-[0.16em] text-accent">Step 4</p>
          <h3 className="mt-2 text-lg font-semibold text-ink">Recommended method</h3>
          {currentFormatOption ? <p className="mt-2 text-sm text-muted">{currentFormatOption.description}</p> : null}
          <div className="mt-4">{renderRecommendedMethod()}</div>
          {detectionPreview ? (
            <div className={`mt-4 rounded-2xl border p-4 text-sm ${detectionPreview.tone === "warning" ? "border-warning/40 bg-warning/10" : "border-accent/30 bg-accent/10"}`}>
              <p className={`font-semibold ${detectionPreview.tone === "warning" ? "text-warning" : "text-accent"}`}>{detectionPreview.title}</p>
              <p className="mt-2 text-muted">{detectionPreview.detail}</p>
            </div>
          ) : null}
        </div>
      </div>
      ) : null}

      {renderServerPathSection()}

      {showStatusPanel ? (
        <div className="rounded-3xl border border-line bg-panel/70 p-5">
          <div className="flex items-center gap-3">
            {phase === "completed" ? <CheckCircle2 className="h-4 w-4 text-mint" /> : <LoaderCircle className={`h-4 w-4 ${statusTone} ${uploading || phase === "preparing" || phase === "uploading" || phase === "analyzing" || phase === "processing" || phase === "selection_pending" ? "animate-spin" : ""}`} />}
            <div>
              <p className={`text-sm font-medium ${statusTone}`}>{status}</p>
              {currentItem ? <p className="text-xs text-muted">{currentItem}</p> : null}
            </div>
          </div>
          {latestEvidenceId ? (
            <div className="mt-4 flex flex-wrap gap-3">
              <button type="button" onClick={() => navigate(`/cases/${caseId}/search?evidence_id=${latestEvidenceId}&tab=results`)} className="rounded-2xl bg-accent px-4 py-3 text-sm font-semibold text-abyss">
                Search evidence
              </button>
              <button type="button" onClick={() => navigate(`/evidences/${latestEvidenceId}`)} className="rounded-2xl border border-line bg-white/5 px-4 py-3 text-sm text-muted">
                View indexing progress
              </button>
              <button type="button" onClick={() => navigate(`/cases/${caseId}/memory`)} className="rounded-2xl border border-line bg-white/5 px-4 py-3 text-sm text-muted">
                Open Memory Analysis
              </button>
              <button type="button" onClick={() => navigate(`/cases/${caseId}/rules?evidence_id=${latestEvidenceId}`)} className="rounded-2xl border border-line bg-white/5 px-4 py-3 text-sm text-muted">
                Run rules
              </button>
              <button type="button" onClick={() => navigate(`/cases/${caseId}/reports?evidence_id=${latestEvidenceId}`)} className="rounded-2xl border border-line bg-white/5 px-4 py-3 text-sm text-muted">
                Generate report
              </button>
            </div>
          ) : null}
          {uploadBytes.total > 0 ? (
            <div className="mt-4">
              <div className="h-2 rounded-full bg-abyss/80">
                <div className="h-2 rounded-full bg-accent transition-all" style={{ width: `${Math.max(progressPct, uploading ? 12 : 0)}%` }} />
              </div>
              <p className="mt-2 text-xs text-muted">
                {formatBytes(uploadBytes.loaded)} / {formatBytes(uploadBytes.total)} uploaded
              </p>
            </div>
          ) : null}
        </div>
      ) : null}

      <div className="rounded-3xl border border-line bg-panel/50 p-4 text-xs text-muted">
        Browser folder upload is not recommended for forensic evidence. For many files, use ZIP/TAR/7z or server-mounted path.
      </div>

      <input ref={fileInputRef} type="file" accept={fileAccept} className="hidden" disabled={uploading} onChange={(event) => void onFileInputChange(event.target.files)} />
      {experimentalFolderUploadEnabled ? (
        <input
          ref={folderInputRef}
          type="file"
          data-testid="experimental-folder-input"
          className="hidden"
          disabled={uploading}
          {...({ webkitdirectory: "", directory: "" } as Record<string, string>)}
          onChange={(event) => void handleExperimentalFolderUpload(event.target.files)}
        />
      ) : null}
    </div>
  );
}
