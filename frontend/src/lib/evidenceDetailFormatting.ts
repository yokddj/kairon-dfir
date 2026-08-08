import type { EvidenceRun, ProblematicArtifact } from "../api/client";

export type ArtifactFilters = {
  status: string;
  artifactType: string;
  parser: string;
  sourcePath: string;
};

export type LinuxInventoryArtifact = { key?: string; label?: string; family?: string; status?: string; paths?: string[]; reason?: string };
export type LinuxInventory = {
  distribution?: string | null;
  hostname?: string | null;
  kernel?: string | null;
  detected_artifacts?: LinuxInventoryArtifact[];
  not_detected?: LinuxInventoryArtifact[];
  unsupported?: LinuxInventoryArtifact[];
  warnings?: string[];
  coverage?: { detected?: number; total_detected?: number; supported?: number; unsupported?: number; coverage_percent?: number };
};

export function asLinuxInventory(value: unknown): LinuxInventory | null {
  if (!value || typeof value !== "object") return null;
  return value as LinuxInventory;
}

// Evidence type ("velociraptor_zip", "kape_archive", ...) is a persisted,
// API-facing identifier (EvidenceType enum, backend/app/models/evidence.py)
// -- do not rename the values themselves. This only controls what analysts
// see. velociraptor_zip is a raw evidence collection identified by which
// collection tool produced it; the public label should describe what it is,
// not which tool made it.
const EVIDENCE_TYPE_LABEL_OVERRIDES: Record<string, string> = {
  velociraptor_zip: "Evidence collection",
};

export function evidenceTypeLabel(value: string | null | undefined): string {
  const key = String(value ?? "").trim();
  if (!key) return "-";
  if (EVIDENCE_TYPE_LABEL_OVERRIDES[key]) return EVIDENCE_TYPE_LABEL_OVERRIDES[key];
  return key
    .split(/[_\s]+/)
    .filter(Boolean)
    .map((token) => token.charAt(0).toUpperCase() + token.slice(1))
    .join(" ");
}

export function matchesArtifactFilter(artifact: { status: string; artifact_type: string; parser: string; source_path: string }, filters: ArtifactFilters) {
  return (
    (!filters.status || artifact.status === filters.status) &&
    (!filters.artifactType || artifact.artifact_type === filters.artifactType) &&
    (!filters.parser || artifact.parser === filters.parser) &&
    (!filters.sourcePath || artifact.source_path.toLowerCase().includes(filters.sourcePath.toLowerCase()))
  );
}

export function formatDuration(value: unknown) {
  if (typeof value !== "number" || !Number.isFinite(value) || value < 0) return "-";
  if (value < 60) return `${Math.round(value)}s`;
  const minutes = Math.floor(value / 60);
  const seconds = Math.round(value % 60);
  if (minutes < 60) return `${minutes}m ${seconds}s`;
  const hours = Math.floor(minutes / 60);
  const remMinutes = minutes % 60;
  return `${hours}h ${remMinutes}m`;
}

export function formatDateTime(value: string | null | undefined) {
  if (!value) return "-";
  const timestamp = Date.parse(value);
  if (Number.isNaN(timestamp)) return value;
  return new Date(timestamp).toLocaleString();
}

export function formatBytes(value: unknown) {
  const bytes = typeof value === "number" && Number.isFinite(value) ? value : 0;
  if (bytes <= 0) return "-";
  const units = ["bytes", "KB", "MB", "GB", "TB"];
  let size = bytes;
  let index = 0;
  while (size >= 1024 && index < units.length - 1) {
    size /= 1024;
    index += 1;
  }
  return `${size >= 10 || index === 0 ? Math.round(size).toLocaleString() : size.toFixed(1)} ${units[index]}`;
}

export function formatHeartbeatAge(heartbeatAt: string | null) {
  if (!heartbeatAt) return "-";
  const timestamp = Date.parse(heartbeatAt);
  if (Number.isNaN(timestamp)) return heartbeatAt;
  const elapsedSeconds = Math.max(0, Math.round((Date.now() - timestamp) / 1000));
  return formatDuration(elapsedSeconds);
}

export function extractTimeoutSeconds(message: string | null | undefined) {
  const value = String(message || "");
  const rqMatch = value.match(/maximum timeout value \((\d+) seconds\)/i);
  if (rqMatch?.[1]) return Number.parseInt(rqMatch[1], 10);
  const directMatch = value.match(/timed out after (\d+)s/i);
  if (directMatch?.[1]) return Number.parseInt(directMatch[1], 10);
  return null;
}

export function buildRunTimeoutSummary(run: EvidenceRun | null, problematicCount: number) {
  if (!run) return null;
  const timeoutSeconds = extractTimeoutSeconds(run.last_error);
  if (!timeoutSeconds) return null;
  const completed = run.artifacts_done ?? 0;
  const total = run.artifacts_total ?? completed;
  const problematic = problematicCount || Math.max(total - completed, run.artifacts_failed ?? 0, 0);
  return `Run timed out after ${timeoutSeconds}s. ${completed}/${total} artifacts completed. ${problematic} artifact was marked problematic and can be retried.`;
}

export function formatEvtxBackend(value: string) {
  if (value === "evtxecmd_csv") return "EvtxECmd CSV";
  if (value === "evtxecmd_json") return "EvtxECmd JSON";
  if (value === "evtx_raw_python") return "Python EVTX fallback";
  return value || "-";
}

export function formatPlatform(value: string | null | undefined) {
  const normalized = String(value || "").trim().toLowerCase();
  if (!normalized) return "-";
  if (normalized === "auto") return "Auto-detect";
  if (normalized === "macos") return "macOS";
  return normalized.replaceAll("_", " ").replace(/^./, (char) => char.toUpperCase());
}

export function parseActiveBenchmarkConflict(message: string | null | undefined) {
  const raw = String(message || "").trim();
  if (!raw) return null;
  try {
    const parsed = JSON.parse(raw) as { error?: string; active_run_id?: string; active_benchmark_id?: string; message?: string };
    if (parsed.error !== "active_ingest_exists") return null;
    return parsed;
  } catch {
    return null;
  }
}

export function formatProblematicStatusLabel(status: string | null | undefined) {
  const value = String(status || "").trim();
  if (!value) return "unknown";
  return value.replaceAll("_", " ");
}

export function problematicStatusTone(status: string | null | undefined) {
  switch (String(status || "").trim().toLowerCase()) {
    case "skipped_empty":
    case "completed_no_records":
    case "unsupported_no_records":
      return "border-mint/25 bg-mint/10 text-mint";
    case "recovered":
    case "recovered_with_warning":
      return "border-emerald-400/30 bg-emerald-400/10 text-emerald-200";
    case "accepted_warning":
    case "parsed_with_warning":
    case "health_check_only_valid":
    case "source_missing_but_indexed":
      return "border-amber/30 bg-amber/10 text-amber";
    case "partially_parsed":
    case "partial_data_loss":
      return "border-orange-400/30 bg-orange-400/10 text-orange-200";
    default:
      return "border-danger/30 bg-danger/10 text-danger";
  }
}

export function problematicRecoveryText(artifact: ProblematicArtifact) {
  const effectiveStatus = String(artifact.effective_status || artifact.status || "").trim().toLowerCase();
  if (effectiveStatus === "recovered_with_warning" || effectiveStatus === "recovered") {
    const recoveredCount = artifact.recovered_records ?? artifact.effective_records_indexed ?? artifact.records_indexed;
    return `Recovered ${recoveredCount} events with deep safe mode.`;
  }
  if (effectiveStatus === "source_missing_but_indexed") {
    return "The original or staged file is no longer available for health check, but indexed events are searchable.";
  }
  if (["skipped_empty", "completed_no_records", "unsupported_no_records"].includes(effectiveStatus)) {
    return "No records produced. Empty or unsupported EVTX channels are not investigation blockers.";
  }
  if (effectiveStatus === "parsed_with_warning" || effectiveStatus === "accepted_warning" || effectiveStatus === "health_check_only_valid") {
    return "All read records were indexed.";
  }
  return "No records indexed. Data loss expected.";
}

export function problematicImpact(artifact: ProblematicArtifact): { group: "critical" | "warning" | "skipped" | "tooling_missing" | "informational"; label: string; action: string } {
  const text = `${artifact.status || ""} ${artifact.effective_status || ""} ${artifact.name || ""} ${artifact.health_summary || ""} ${artifact.loss_summary || ""}`.toLowerCase();
  if (text.includes("host_identity_skipped_for_parallel_bulk")) {
    return { group: "informational", label: "Informational", action: "No action needed. Host alias-aware Search still applies at query time." };
  }
  if (text.includes("tooling_missing") || text.includes("requires windows") || text.includes("srum")) {
    return { group: "tooling_missing", label: "Unsupported/tooling missing", action: "Requires optional parser tooling or a Windows worker." };
  }
  if (text.includes("skipped_empty") || text.includes("completed_no_records") || text.includes("unsupported_no_records") || text.includes("no records produced")) {
    return { group: "informational", label: "Empty/no records", action: "No retry needed. The parser completed but the log produced no parseable records." };
  }
  if ((artifact.effective_records_indexed ?? artifact.records_indexed ?? 0) > 0 && !(artifact.current_data_loss_expected ?? artifact.data_loss_expected)) {
    return { group: "warning", label: "Warning", action: "Searchable data exists. Review details only if this artifact matters." };
  }
  if (artifact.current_data_loss_expected ?? artifact.data_loss_expected) {
    return { group: "critical", label: "Critical error", action: "Retry parser or inspect source if this artifact is required." };
  }
  return { group: "skipped", label: "Skipped/empty", action: "Usually no action unless the artifact was expected." };
}

export function indexingStepTone(status: string | null | undefined) {
  const value = String(status || "").toLowerCase();
  if (["completed", "derived"].includes(value)) return "border-mint/25 bg-mint/10 text-mint";
  if (["queued", "running", "processing", "ready", "advanced_available"].includes(value)) return "border-accent/30 bg-accent/10 text-accent";
  if (value.includes("tooling") || value.includes("unsupported")) return "border-amber/30 bg-amber/10 text-amber";
  if (value.includes("failed")) return "border-danger/30 bg-danger/10 text-danger";
  return "border-line bg-abyss/60 text-muted";
}

export function formatIndexingStatus(status: string | null | undefined) {
  return String(status || "unknown").replaceAll("_", " ");
}

export type EvidenceIndexingState = "not_started" | "action_required" | "planning_or_waiting" | "indexing" | "stale" | "completed" | "completed_with_warnings" | "completed_with_errors" | "failed";

export function formatEvidenceStatusForDisplay(status: string | null | undefined) {
  const value = String(status || "unknown").replaceAll("_", " ");
  if (value === "completed with warnings") return "ready with warnings";
  if (value === "completed") return "ready";
  return value;
}

// Backend identifiers for the disk-image ingest stages (see
// app.workers.tasks.DISK_IMAGE_PROGRESS_ACTIONS and
// app.disk_images.service's progress_cb current_action values) --
// current_phase is set to one of these directly during disk-image
// materialization, since the total file count isn't known ahead of a
// pytsk3 directory walk and no single generic phase label can honestly
// describe every stage of it. This is the single canonical place these
// identifiers are translated to analyst-facing text -- keep it here
// rather than duplicating a second mapping anywhere else.
const DISK_IMAGE_PHASE_LABELS: Record<string, string> = {
  detecting_format: "Detecting image format",
  hashing: "Hashing evidence",
  inspecting_image: "Inspecting disk image",
  discovering_volumes: "Discovering volumes",
  materializing_disk_image_files: "Extracting filesystem contents",
};

export function formatIndexingPhaseForDisplay(phase: string | null | undefined) {
  const value = String(phase || "").trim();
  if (value in DISK_IMAGE_PHASE_LABELS) return DISK_IMAGE_PHASE_LABELS[value];
  switch (value) {
    case "selection_pending":
    case "waiting_selection":
      return "Preparing indexing plan";
    case "pending":
      return "Indexing job queued";
    case "extracting_selected":
      return "Extracting selected artifacts";
    case "processing":
      return "Indexing in progress";
    case "completed":
      return "Evidence ready for investigation";
    case "completed_with_errors":
      return "Indexing completed with errors";
    case "failed":
      return "Indexing failed";
    default:
      return value ? value.replaceAll("_", " ") : "Unknown";
  }
}

export function isRawDiscoveryEvidenceLike(evidence: { evidence_type?: string; metadata_json?: Record<string, unknown> } | null | undefined, discoveryCandidatesCount: number) {
  if (!evidence || !discoveryCandidatesCount) return false;
  const metadata = evidence.metadata_json ?? {};
  const collectionKind = typeof metadata.collection_kind === "string" ? metadata.collection_kind : "";
  const sourceType = typeof metadata.source_type === "string" ? metadata.source_type : "";
  return evidence.evidence_type === "velociraptor_zip" || collectionKind === "raw_evidence_collection" || sourceType === "raw_collection";
}

export function normalizeEvidenceHostName(value: string | null | undefined) {
  const normalized = String(value || "").trim().toLowerCase();
  return normalized.endsWith(".local") ? normalized.slice(0, -6) : normalized;
}

export function assignedHostMatchesDetected(host: { id: string; canonical_name: string; display_name: string; aliases?: string[]; all_names?: string[] } | null, detected: string | null | undefined) {
  const target = normalizeEvidenceHostName(detected);
  if (!host || !target) return false;
  return [host.id, host.canonical_name, host.display_name, ...(host.aliases || []), ...(host.all_names || [])].some((name) => normalizeEvidenceHostName(name) === target);
}
