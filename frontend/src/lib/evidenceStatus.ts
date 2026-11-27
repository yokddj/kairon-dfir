import type { Evidence, EvidenceIndexingPlan, EvidenceRun, ProblematicArtifact } from "../api/client";
import { problematicImpact } from "./evidenceDetailFormatting";

/**
 * Pure state derivation for the evidence page. Every number shown there comes
 * from here, so the rules for "what is running", "what failed" and "what is
 * only a note" live in one place and are unit-tested.
 */

const ACTIVE_RUN_STATUSES = new Set(["queued", "running", "pending", "processing"]);
const EMPTY_STATUSES = new Set(["skipped_empty", "completed_no_records", "unsupported_no_records"]);
// A worker that has not reported for this long while the evidence is still
// "processing" is dead, not slow. Matches the backend watchdog's default.
export const HEARTBEAT_STALE_MS = 10 * 60 * 1000;

/** Backend timestamps without a zone are UTC; Date.parse would read them as local time. */
export function parseUtc(value: string | null | undefined): number {
  if (!value) return Number.NaN;
  const hasZone = /(?:Z|[+-]\d{2}:?\d{2})$/i.test(value);
  return Date.parse(hasZone ? value : `${value}Z`);
}

export type EvidenceState = "processing" | "stalled" | "needs_selection" | "not_indexed" | "failed" | "ready";

export type ProcessingStep = "prepare" | "parse" | "index" | "finish";
export const PROCESSING_STEPS: Array<{ id: ProcessingStep; label: string }> = [
  { id: "prepare", label: "Prepare" },
  { id: "parse", label: "Parse" },
  { id: "index", label: "Index" },
  { id: "finish", label: "Finish" },
];

const PARSE_PHASES = new Set(["parsing", "materializing_and_parsing", "extracting_selected", "processing", "running", "retry_running"]);
const INDEX_PHASES = new Set(["indexing", "indexing_events", "indexing_zip"]);
const FINISH_PHASES = new Set(["counting_events", "matching_events", "loading_rules", "post_processing", "finalizing", "detections"]);

/** Maps a backend phase identifier onto one of the four steps an analyst sees. */
export function processingStepForPhase(phase: string | null | undefined): ProcessingStep {
  const value = String(phase || "").trim().toLowerCase();
  if (PARSE_PHASES.has(value)) return "parse";
  if (INDEX_PHASES.has(value)) return "index";
  if (FINISH_PHASES.has(value)) return "finish";
  return "prepare";
}

export function isActiveRun(run: EvidenceRun | null | undefined) {
  return Boolean(run && ACTIVE_RUN_STATUSES.has(String(run.status || "").toLowerCase()));
}

export type ProblemBuckets = {
  /** Artifacts that lost data or can be retried: the only ones that need attention. */
  failures: ProblematicArtifact[];
  /** Indexed, but the parser reported something worth knowing. */
  warnings: ProblematicArtifact[];
  /** Files that parsed fine and simply held no records. A note, not a warning. */
  emptyCount: number;
};

export function bucketProblems(items: ProblematicArtifact[]): ProblemBuckets {
  const failures: ProblematicArtifact[] = [];
  const warnings: ProblematicArtifact[] = [];
  let emptyCount = 0;
  for (const artifact of items) {
    const status = String(artifact.effective_status ?? artifact.status ?? "").toLowerCase();
    if (EMPTY_STATUSES.has(status)) {
      emptyCount += 1;
      continue;
    }
    const dataLoss = Boolean(artifact.current_data_loss_expected ?? artifact.data_loss_expected);
    if (dataLoss || artifact.retryable || problematicImpact(artifact).group === "critical") {
      failures.push(artifact);
    } else if (problematicImpact(artifact).group !== "informational") {
      warnings.push(artifact);
    }
  }
  return { failures, warnings, emptyCount };
}

export type EvidenceView = {
  state: EvidenceState;
  /** The run that is moving right now (ingest or retry), when there is one. */
  activeRun: EvidenceRun | null;
  heartbeatAt: string | null;
};

/**
 * One state per evidence, with a single meaning each. "Processing" requires
 * that something is actually queued or running; a stale "processing" flag with
 * no live worker is "stalled", and a raw collection waiting for a choice is
 * "needs_selection".
 */
export function deriveEvidenceView({
  evidence,
  runs,
  plan,
  indexedDocs,
  nowMs,
}: {
  evidence: Evidence | undefined;
  runs: EvidenceRun[];
  plan: EvidenceIndexingPlan | undefined;
  indexedDocs: number;
  nowMs: number;
}): EvidenceView {
  const metadata = evidence?.metadata_json ?? {};
  const ingestStatus = String(evidence?.ingest_status ?? "").toLowerCase();
  const ingestActive = ingestStatus === "pending" || ingestStatus === "processing";
  const phase = String(metadata.current_phase ?? "").toLowerCase();
  const candidates = (metadata.velociraptor_discovery as { candidates?: unknown[] } | undefined)?.candidates;
  const hasCandidates = Array.isArray(candidates) && candidates.length > 0;
  const waitingForSelection = (phase === "selection_pending" || phase === "waiting_selection") && hasCandidates && !metadata.current_ingest_run_id;

  const planActive = Boolean(plan?.active);
  // A run row can stay "running" after its worker died; it only counts while
  // the evidence or the indexing plan also says work is in flight (a retry of
  // single artifacts runs on a completed evidence, so it counts on its own).
  const activeRun =
    runs.slice(0, 3).find((run) => isActiveRun(run) && (ingestActive || planActive || run.run_type === "artifact_retry")) ?? null;
  const heartbeatAt =
    activeRun?.tail_last_progress_at || activeRun?.heartbeat_at || (typeof metadata.heartbeat_at === "string" ? metadata.heartbeat_at : null);

  if (activeRun || planActive || (ingestActive && !waitingForSelection && plan?.state !== "planned_not_started")) {
    const heartbeatMs = parseUtc(heartbeatAt);
    const stale = Number.isFinite(heartbeatMs) && nowMs - heartbeatMs > HEARTBEAT_STALE_MS;
    return { state: stale ? "stalled" : "processing", activeRun, heartbeatAt };
  }
  if (waitingForSelection) return { state: "needs_selection", activeRun: null, heartbeatAt };
  if (indexedDocs > 0 || evidence?.investigation_ready) return { state: "ready", activeRun: null, heartbeatAt };
  if (ingestStatus === "failed" || ingestStatus === "completed_with_errors") return { state: "failed", activeRun: null, heartbeatAt };
  if (ingestStatus === "completed") return { state: "ready", activeRun: null, heartbeatAt };
  return { state: "not_indexed", activeRun: null, heartbeatAt };
}

export type LiveProgress = {
  title: string;
  step: ProcessingStep;
  /** null when the total is unknown: show an indeterminate bar, never a made-up number. */
  percent: number | null;
  artifactsDone: number | null;
  artifactsTotal: number | null;
  recordsIndexed: number | null;
  currentItem: string | null;
  elapsedSeconds: number | null;
};

/**
 * Progress numbers for the run that is running now. Values left over from an
 * earlier run (its elapsed time, its artifact totals) are never shown: when the
 * current run has not reported a value yet, the value is null.
 */
export function liveProgress(evidence: Evidence | undefined, run: EvidenceRun | null, nowMs: number): LiveProgress {
  const metadata = evidence?.metadata_json ?? {};
  const isRetry = run?.run_type === "artifact_retry";
  const metadataRunId = String(metadata.current_ingest_run_id ?? "");
  // Evidence metadata describes the current run only when it says so.
  const metadataIsCurrent = !run || !metadataRunId || metadataRunId === run.run_id;
  const num = (value: unknown) => (typeof value === "number" && Number.isFinite(value) ? value : null);

  const phase = String(run?.phase || (metadataIsCurrent ? metadata.current_phase : "") || run?.status || "");
  const total = num(run?.artifacts_total) ?? (metadataIsCurrent ? num(metadata.artifacts_total) : null);
  const done = num(run?.artifacts_done) ?? (metadataIsCurrent ? num(metadata.artifacts_done) : null);
  const indeterminate = metadataIsCurrent && metadata.progress_indeterminate === true;
  let percent = indeterminate ? null : num(run?.progress) ?? (metadataIsCurrent ? num(metadata.progress_pct) : null);
  if (percent === null && !indeterminate && total && total > 0 && done !== null) percent = Math.min(99, Math.round((done / total) * 100));
  if (percent !== null) percent = Math.max(0, Math.min(100, Math.round(percent)));

  const startedAt = parseUtc(run?.started_at);
  const elapsedSeconds = Number.isFinite(startedAt) ? Math.max(0, Math.round((nowMs - startedAt) / 1000)) : num(run?.elapsed_seconds);
  const queued = String(run?.status || "").toLowerCase() === "queued";
  const currentItem = run?.current_artifact || (metadataIsCurrent && typeof metadata.current_artifact === "string" ? metadata.current_artifact : null);

  return {
    title: isRetry ? "Retrying failed artifacts" : queued ? "Queued" : "Processing",
    step: isRetry ? "parse" : processingStepForPhase(phase),
    percent: queued ? null : percent,
    artifactsDone: done,
    artifactsTotal: total && total > 0 ? total : null,
    recordsIndexed: num(run?.records_indexed) ?? num(run?.events_indexed),
    currentItem: currentItem || null,
    elapsedSeconds: queued ? null : elapsedSeconds,
  };
}

export const STATE_LABEL: Record<EvidenceState, string> = {
  processing: "Processing",
  stalled: "Stalled",
  needs_selection: "Choose what to index",
  not_indexed: "Not indexed",
  failed: "Failed",
  ready: "Ready",
};

export const STATE_TONE: Record<EvidenceState, string> = {
  processing: "border-accent/30 bg-accent/10 text-accent",
  stalled: "border-warning/40 bg-warning/10 text-warning",
  needs_selection: "border-accent/30 bg-accent/10 text-accent",
  not_indexed: "border-line bg-abyss/60 text-muted",
  failed: "border-danger/30 bg-danger/10 text-danger",
  ready: "border-mint/30 bg-mint/10 text-mint",
};
