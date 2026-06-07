import { useEffect, useMemo, useRef, useState } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { Link, useNavigate, useParams } from "react-router-dom";
import { api, type CaseReport, type EvidenceBenchmark, type EvidenceIndexingPlan, type EvidenceIndexingStep, type EvidenceRun, type EvtxHealthCheckResult, type EvtxProfile, type IngestPlanCandidate, type OnDemandModule, type ProblematicArtifact, type RuleRun, type VelociraptorCandidate } from "../api/client";
import DebugExportDialog from "../components/DebugExportDialog";
import { useNotifications } from "../context/NotificationsContext";

type ArtifactFilters = {
  status: string;
  artifactType: string;
  parser: string;
  sourcePath: string;
};

function matchesArtifactFilter(artifact: { status: string; artifact_type: string; parser: string; source_path: string }, filters: ArtifactFilters) {
  return (
    (!filters.status || artifact.status === filters.status) &&
    (!filters.artifactType || artifact.artifact_type === filters.artifactType) &&
    (!filters.parser || artifact.parser === filters.parser) &&
    (!filters.sourcePath || artifact.source_path.toLowerCase().includes(filters.sourcePath.toLowerCase()))
  );
}

function formatDuration(value: unknown) {
  if (typeof value !== "number" || !Number.isFinite(value) || value < 0) return "-";
  if (value < 60) return `${Math.round(value)}s`;
  const minutes = Math.floor(value / 60);
  const seconds = Math.round(value % 60);
  if (minutes < 60) return `${minutes}m ${seconds}s`;
  const hours = Math.floor(minutes / 60);
  const remMinutes = minutes % 60;
  return `${hours}h ${remMinutes}m`;
}

function formatDateTime(value: string | null | undefined) {
  if (!value) return "-";
  const timestamp = Date.parse(value);
  if (Number.isNaN(timestamp)) return value;
  return new Date(timestamp).toLocaleString();
}

function formatHeartbeatAge(heartbeatAt: string | null) {
  if (!heartbeatAt) return "-";
  const timestamp = Date.parse(heartbeatAt);
  if (Number.isNaN(timestamp)) return heartbeatAt;
  const elapsedSeconds = Math.max(0, Math.round((Date.now() - timestamp) / 1000));
  return formatDuration(elapsedSeconds);
}

function extractTimeoutSeconds(message: string | null | undefined) {
  const value = String(message || "");
  const rqMatch = value.match(/maximum timeout value \((\d+) seconds\)/i);
  if (rqMatch?.[1]) return Number.parseInt(rqMatch[1], 10);
  const directMatch = value.match(/timed out after (\d+)s/i);
  if (directMatch?.[1]) return Number.parseInt(directMatch[1], 10);
  return null;
}

function buildRunTimeoutSummary(run: EvidenceRun | null, problematicCount: number) {
  if (!run) return null;
  const timeoutSeconds = extractTimeoutSeconds(run.last_error);
  if (!timeoutSeconds) return null;
  const completed = run.artifacts_done ?? 0;
  const total = run.artifacts_total ?? completed;
  const problematic = problematicCount || Math.max(total - completed, run.artifacts_failed ?? 0, 0);
  return `Run timed out after ${timeoutSeconds}s. ${completed}/${total} artifacts completed. ${problematic} artifact was marked problematic and can be retried.`;
}

function formatEvtxBackend(value: string) {
  if (value === "evtxecmd_csv") return "EvtxECmd CSV";
  if (value === "evtxecmd_json") return "EvtxECmd JSON";
  if (value === "evtx_raw_python") return "Python EVTX fallback";
  return value || "-";
}

function parseActiveBenchmarkConflict(message: string | null | undefined) {
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

function formatProblematicStatusLabel(status: string | null | undefined) {
  const value = String(status || "").trim();
  if (!value) return "unknown";
  return value.replaceAll("_", " ");
}

function problematicStatusTone(status: string | null | undefined) {
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

function problematicRecoveryText(artifact: ProblematicArtifact) {
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

function problematicImpact(artifact: ProblematicArtifact): { group: "critical" | "warning" | "skipped" | "tooling_missing" | "informational"; label: string; action: string } {
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

function indexingStepTone(status: string | null | undefined) {
  const value = String(status || "").toLowerCase();
  if (["completed", "derived"].includes(value)) return "border-mint/25 bg-mint/10 text-mint";
  if (["queued", "running", "processing", "ready", "advanced_available"].includes(value)) return "border-accent/30 bg-accent/10 text-accent";
  if (value.includes("tooling") || value.includes("unsupported")) return "border-amber/30 bg-amber/10 text-amber";
  if (value.includes("failed")) return "border-danger/30 bg-danger/10 text-danger";
  return "border-line bg-abyss/60 text-muted";
}

function formatIndexingStatus(status: string | null | undefined) {
  return String(status || "unknown").replaceAll("_", " ");
}

type EvidenceIndexingState = "not_started" | "action_required" | "planning_or_waiting" | "indexing" | "stale" | "completed" | "completed_with_warnings" | "completed_with_errors" | "failed";

function formatEvidenceStatusForDisplay(status: string | null | undefined) {
  const value = String(status || "unknown").replaceAll("_", " ");
  if (value === "completed with warnings") return "ready with warnings";
  if (value === "completed") return "ready";
  return value;
}

function formatIndexingPhaseForDisplay(phase: string | null | undefined) {
  const value = String(phase || "").trim();
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

function isRawDiscoveryEvidenceLike(evidence: { evidence_type?: string; metadata_json?: Record<string, unknown> } | null | undefined, discoveryCandidatesCount: number) {
  if (!evidence || !discoveryCandidatesCount) return false;
  const metadata = evidence.metadata_json ?? {};
  const collectionKind = typeof metadata.collection_kind === "string" ? metadata.collection_kind : "";
  const sourceType = typeof metadata.source_type === "string" ? metadata.source_type : "";
  return evidence.evidence_type === "velociraptor_zip" || collectionKind === "raw_evidence_collection" || sourceType === "raw_collection";
}

export default function EvidenceDetail() {
  const { evidenceId = "" } = useParams();
  const navigate = useNavigate();
  const queryClient = useQueryClient();
  const { notify } = useNotifications();
  const [nowMs, setNowMs] = useState(() => Date.now());
  const parseSelectionRef = useRef<HTMLDetailsElement | null>(null);
  const selectedArtifactTypesRef = useRef<HTMLDivElement | null>(null);
  const [filters, setFilters] = useState<ArtifactFilters>({ status: "", artifactType: "", parser: "", sourcePath: "" });
  const [selectedCandidateIds, setSelectedCandidateIds] = useState<string[]>([]);
  const [parseEvtxProfile, setParseEvtxProfile] = useState<EvtxProfile>("full");
  const [expandedCategories, setExpandedCategories] = useState<Record<string, boolean>>({});
  const [debugExportOpen, setDebugExportOpen] = useState(false);
  const [reprocessDialogOpen, setReprocessDialogOpen] = useState(false);
  const [reprocessMode, setReprocessMode] = useState<"previous_selection" | "choose_again" | "full_rediscovery" | "manual_selection">("previous_selection");
  const [reprocessIngestMode, setReprocessIngestMode] = useState<"usable_search" | "full_forensic">("usable_search");
  const [reprocessEvtxProfile, setReprocessEvtxProfile] = useState<EvtxProfile>("full");
  const [reprocessProvidedHost, setReprocessProvidedHost] = useState("");
  const [reprocessSelectionIds, setReprocessSelectionIds] = useState<string[]>([]);
  const [rediscoveryConfirmText, setRediscoveryConfirmText] = useState("");
  const [selectedProblematicArtifactIds, setSelectedProblematicArtifactIds] = useState<string[]>([]);
  const [problematicRetryMode, setProblematicRetryMode] = useState("higher_timeout");
  const [latestStartedRunId, setLatestStartedRunId] = useState<string | null>(null);
  const [rulesEngineSelection, setRulesEngineSelection] = useState<"sigma" | "yara" | "all">("sigma");
  const [indexingProfile, setIndexingProfile] = useState<"recommended" | "fast" | "advanced_custom">("recommended");
  const [benchmarkAutopilot, setBenchmarkAutopilot] = useState(true);
  const [benchmarkMaxAttempts, setBenchmarkMaxAttempts] = useState(2);
  const [benchmarkMaxWallTimeSeconds, setBenchmarkMaxWallTimeSeconds] = useState(7200);
  const [benchmarkNoProgressTimeoutSeconds, setBenchmarkNoProgressTimeoutSeconds] = useState(600);
  const [benchmarkHeartbeatTimeoutSeconds, setBenchmarkHeartbeatTimeoutSeconds] = useState(300);
  const [advancedProcessingDetailsOpen, setAdvancedProcessingDetailsOpen] = useState(false);
  const [deleteDialogOpen, setDeleteDialogOpen] = useState(false);
  const [deleteConfirmText, setDeleteConfirmText] = useState("");
  const evidenceQuery = useQuery({
    queryKey: ["evidence", evidenceId],
    queryFn: () => api.getEvidence(evidenceId),
    enabled: Boolean(evidenceId),
    refetchInterval: (query) => {
      const status = query.state.data?.ingest_status;
      return status === "pending" || status === "processing" ? 3000 : false;
    },
    refetchIntervalInBackground: true,
  });
  const manifestQuery = useQuery({
    queryKey: ["evidence-manifest", evidenceId],
    queryFn: () => api.getEvidenceManifest(evidenceId),
    enabled: Boolean(evidenceId),
    refetchInterval: () => (evidenceQuery.data?.ingest_status === "pending" || evidenceQuery.data?.ingest_status === "processing" ? 3000 : false),
  });
  const onDemandModulesQuery = useQuery({
    queryKey: ["evidence-on-demand-modules", evidenceId],
    queryFn: () => api.getEvidenceOnDemandModules(evidenceId),
    enabled: Boolean(evidenceId),
  });
  const searchSummaryQuery = useQuery({
    queryKey: ["evidence-search-summary", evidenceId],
    queryFn: () => api.getEvidenceSearchSummary(evidenceId),
    enabled: Boolean(evidenceId),
    staleTime: 15_000,
  });
  const mftDiagnosticQuery = useQuery({
    queryKey: ["evidence-mft-diagnostic", evidenceId],
    queryFn: () => api.getEvidenceMftDiagnostic(evidenceId),
    enabled: Boolean(evidenceId),
    staleTime: 30_000,
  });
  const indexingPlanQuery = useQuery({
    queryKey: ["evidence-indexing-plan", evidenceId, indexingProfile],
    queryFn: () => api.getEvidenceIndexingPlan(evidenceId, indexingProfile),
    enabled: Boolean(evidenceId),
    refetchInterval: () => (evidenceQuery.data?.ingest_status === "pending" || evidenceQuery.data?.ingest_status === "processing" ? 3000 : false),
  });
  const runIndexingPlanMutation = useMutation({
    mutationFn: () => api.runEvidenceIndexingPlan(evidenceId, { profile: indexingProfile }),
    onSuccess: async (result) => {
      notify({
        title: "Indexing plan queued",
        description: result.queued_jobs.length
          ? `${result.queued_jobs.length} step(s) were queued for ${result.profile} indexing.`
          : "The selected indexing plan is already satisfied; no parser jobs were queued.",
        tone: "success",
      });
      await queryClient.invalidateQueries({ queryKey: ["evidence-indexing-plan", evidenceId] });
      await queryClient.invalidateQueries({ queryKey: ["evidence", evidenceId] });
      await queryClient.invalidateQueries({ queryKey: ["evidence-runs", evidenceId] });
      await queryClient.invalidateQueries({ queryKey: ["evidence-search-summary", evidenceId] });
    },
    onError: (error) => {
      notify({ title: "Indexing plan blocked", description: error instanceof Error ? error.message : "The indexing profile could not be started.", tone: "warning" });
    },
  });
  const cancelIndexingMutation = useMutation({
    mutationFn: () => api.cancelEvidenceIndexing(evidenceId, { reason: "Cancelled from Evidence Detail to recover a waiting selection or stale indexing state." }),
    onSuccess: async () => {
      notify({ title: "Indexing cancelled", description: "The active indexing state was cleared. Recommended indexing can be started again.", tone: "success" });
      await queryClient.invalidateQueries({ queryKey: ["evidence-indexing-plan", evidenceId] });
      await queryClient.invalidateQueries({ queryKey: ["evidence", evidenceId] });
      await queryClient.invalidateQueries({ queryKey: ["evidence-runs", evidenceId] });
      await queryClient.invalidateQueries({ queryKey: ["evidence-search-summary", evidenceId] });
    },
    onError: (error) => {
      notify({ title: "Cancel indexing failed", description: error instanceof Error ? error.message : "The indexing state could not be cancelled.", tone: "error" });
    },
  });
  const indexMftSummaryMutation = useMutation({
    mutationFn: () => api.indexEvidenceMftSummary(evidenceId),
    onSuccess: (result) => {
      notify({ title: "MFT summary queued", description: `MFTECmd summary indexing run ${result.run_id.slice(0, 8)} was queued.`, tone: "success" });
      void queryClient.invalidateQueries({ queryKey: ["evidence", evidenceId] });
      void queryClient.invalidateQueries({ queryKey: ["evidence-search-summary", evidenceId] });
      void queryClient.invalidateQueries({ queryKey: ["evidence-mft-diagnostic", evidenceId] });
    },
    onError: (error) => {
      notify({ title: "MFT summary failed", description: error instanceof Error ? error.message : "The MFT summary job could not be queued.", tone: "error" });
    },
  });
  const indexMftFullMutation = useMutation({
    mutationFn: () => api.indexEvidenceMftFull(evidenceId, { force: true }),
    onSuccess: (result) => {
      notify({ title: "Full MFT queued", description: `MFTECmd full indexing run ${result.run_id.slice(0, 8)} was queued.`, tone: "success" });
      void queryClient.invalidateQueries({ queryKey: ["evidence", evidenceId] });
      void queryClient.invalidateQueries({ queryKey: ["evidence-search-summary", evidenceId] });
      void queryClient.invalidateQueries({ queryKey: ["evidence-mft-diagnostic", evidenceId] });
    },
    onError: (error) => {
      notify({ title: "Full MFT failed", description: error instanceof Error ? error.message : "The full MFT job could not be queued.", tone: "error" });
    },
  });
  const indexRecmdUserActivityMutation = useMutation({
    mutationFn: () => api.indexEvidenceRecmdUserActivity(evidenceId, { force: true }),
    onSuccess: (result) => {
      notify({ title: "User activity queued", description: `RECmd user activity run ${result.run_id.slice(0, 8)} was queued.`, tone: "success" });
      void queryClient.invalidateQueries({ queryKey: ["evidence", evidenceId] });
      void queryClient.invalidateQueries({ queryKey: ["evidence-search-summary", evidenceId] });
    },
    onError: (error) => {
      notify({ title: "User activity failed", description: error instanceof Error ? error.message : "The RECmd user activity job could not be queued.", tone: "error" });
    },
  });
  const indexDefenderEvtxMutation = useMutation({
    mutationFn: () => api.indexEvidenceDefenderEvtx(evidenceId, { force: true }),
    onSuccess: (result) => {
      notify({ title: "Defender indexing queued", description: `Defender EVTX run ${result.run_id.slice(0, 8)} was queued.`, tone: "success" });
      void queryClient.invalidateQueries({ queryKey: ["evidence", evidenceId] });
      void queryClient.invalidateQueries({ queryKey: ["evidence-search-summary", evidenceId] });
    },
    onError: (error) => {
      notify({ title: "Defender indexing failed", description: error instanceof Error ? error.message : "The Defender EVTX job could not be queued.", tone: "error" });
    },
  });
  const indexSrumMutation = useMutation({
    mutationFn: () => api.indexEvidenceSrum(evidenceId, { force: true }),
    onSuccess: (result) => {
      notify({ title: "SRUM indexing queued", description: `SrumECmd run ${result.run_id.slice(0, 8)} was queued.`, tone: "success" });
      void queryClient.invalidateQueries({ queryKey: ["evidence", evidenceId] });
      void queryClient.invalidateQueries({ queryKey: ["evidence-search-summary", evidenceId] });
    },
    onError: (error) => {
      notify({ title: "SRUM indexing failed", description: error instanceof Error ? error.message : "The SRUM job could not be queued.", tone: "error" });
    },
  });
  const problematicArtifactsQuery = useQuery({
    queryKey: ["evidence-problematic-artifacts", evidenceId],
    queryFn: () => api.getProblematicArtifacts(evidenceId),
    enabled: Boolean(evidenceId),
    refetchInterval: () => (evidenceQuery.data?.ingest_status === "pending" || evidenceQuery.data?.ingest_status === "processing" ? 5000 : false),
  });
  const problematicRetryCandidatesQuery = useQuery({
    queryKey: ["evidence-problematic-retry-candidates", evidenceId],
    queryFn: () => api.getProblematicRetryCandidates(evidenceId),
    enabled: Boolean(evidenceId),
    refetchInterval: () => (evidenceQuery.data?.ingest_status === "pending" || evidenceQuery.data?.ingest_status === "processing" ? 5000 : false),
  });
  const longTailArtifactsQuery = useQuery({
    queryKey: ["evidence-long-tail-artifacts", evidenceId],
    queryFn: () => api.getLongTailArtifacts(evidenceId),
    enabled: Boolean(evidenceId),
    refetchInterval: () => (evidenceQuery.data?.ingest_status === "pending" || evidenceQuery.data?.ingest_status === "processing" ? 5000 : false),
  });
  const evidenceRunsQuery = useQuery({
    queryKey: ["evidence-runs", evidenceId],
    queryFn: () => api.getEvidenceRuns(evidenceId),
    enabled: Boolean(evidenceId),
    refetchInterval: () => (evidenceQuery.data?.ingest_status === "pending" || evidenceQuery.data?.ingest_status === "processing" ? 3000 : false),
  });
  const evidenceRuleRunsQuery = useQuery({
    queryKey: ["evidence-rule-runs", evidenceId],
    queryFn: () => api.listEvidenceRuleRuns(evidenceId),
    enabled: Boolean(evidenceId),
    refetchInterval: (query) => {
      const latest = (query.state.data ?? [])[0];
      return latest?.status === "queued" || latest?.status === "running" ? 3000 : false;
    },
  });
  const evidenceReportsQuery = useQuery({
    queryKey: ["evidence-reports", evidenceId],
    queryFn: () => api.listEvidenceReports(evidenceId),
    enabled: Boolean(evidenceId),
    refetchInterval: (query) => {
      const latest = (query.state.data ?? [])[0];
      return latest?.status === "queued" || latest?.status === "running" ? 3000 : false;
    },
  });
  const evidenceBenchmarksQuery = useQuery({
    queryKey: ["evidence-benchmarks", evidenceId],
    queryFn: () => api.getEvidenceBenchmarks(evidenceId),
    enabled: Boolean(evidenceId),
    refetchInterval: () => (evidenceQuery.data?.ingest_status === "pending" || evidenceQuery.data?.ingest_status === "processing" ? 5000 : false),
  });
  const reprocessPreviewQuery = useQuery({
    queryKey: ["evidence-reprocess-preview", evidenceId, reprocessMode],
    queryFn: () => api.previewReprocessEvidence(evidenceId, { mode: reprocessMode }),
    enabled: Boolean(evidenceId) && reprocessDialogOpen,
    retry: false,
  });
  const reprocessMutation = useMutation({
    mutationFn: async (payload: { mode: "previous_selection" | "choose_again" | "full_rediscovery" | "manual_selection"; selectedCandidateIds?: string[]; explicitConfirm?: boolean }) => {
      return api.reprocessEvidence(evidenceId, {
        mode: payload.mode,
        selected_candidate_ids: payload.selectedCandidateIds,
        parser_options: {},
        preserve_analyst_state: true,
        explicit_confirm: payload.explicitConfirm,
        ingest_mode: reprocessIngestMode,
        provided_host: reprocessProvidedHost.trim() || undefined,
        evtx_profile: reprocessIngestMode === "full_forensic" ? "full" : reprocessEvtxProfile,
      });
    },
    onMutate: (payload) => {
      const descriptions: Record<string, string> = {
        previous_selection: "Reprocessing the same artifacts and parsers that were used in the previous ingest plan.",
        choose_again: "Refreshing discovery candidates so you can review the previous selection and change it before reprocessing.",
        full_rediscovery: "Running a full rediscovery. This may parse a different set of artifacts than the previous ingest.",
        manual_selection: "Reprocessing only the artifacts and parsers selected manually in this preview.",
      };
      const description = descriptions[payload.mode] ?? "Reprocessing evidence with the selected ingest plan.";
      notify({ title: "Reprocess requested", description, tone: "info" });
    },
    onSuccess: (result) => {
      void queryClient.invalidateQueries({ queryKey: ["evidence", evidenceId] });
      void queryClient.invalidateQueries({ queryKey: ["evidence-manifest", evidenceId] });
      void queryClient.invalidateQueries({ queryKey: ["evidence-runs", evidenceId] });
      setLatestStartedRunId(result.run_id);
      notify({
        title: "Reprocessing started",
        description: `Run ${result.run_id} has been queued. Progress will refresh automatically on this page.`,
        tone: "success",
      });
      setReprocessDialogOpen(false);
    },
    onError: (error) => {
      notify({ title: "Reprocess failed", description: error instanceof Error ? error.message : "The evidence could not be reprocessed.", tone: "error" });
    },
  });
  const benchmarkMutation = useMutation({
    mutationFn: async (payload: { profile: "safe" | "performance" | "max"; label: string }) =>
      api.runEvidenceBenchmark(evidenceId, {
        mode: "reprocess_previous_selection",
        profile: payload.profile,
        label: payload.label,
        max_duration_seconds: 3600,
        skip_detections: true,
        skip_rules: true,
        autopilot: benchmarkAutopilot,
        max_attempts: benchmarkMaxAttempts,
        max_wall_time_seconds: benchmarkMaxWallTimeSeconds,
        no_progress_timeout_seconds: benchmarkNoProgressTimeoutSeconds,
        heartbeat_timeout_seconds: benchmarkHeartbeatTimeoutSeconds,
      }),
    onSuccess: async (result) => {
      setLatestStartedRunId(result.run_id);
      notify({ title: "Benchmark queued", description: `Benchmark ${result.benchmark_id} started with profile ${result.profile}.`, tone: "success" });
      await queryClient.invalidateQueries({ queryKey: ["evidence-benchmarks", evidenceId] });
      await queryClient.invalidateQueries({ queryKey: ["evidence-runs", evidenceId] });
      await queryClient.invalidateQueries({ queryKey: ["evidence", evidenceId] });
    },
    onError: (error) => {
      const conflict = parseActiveBenchmarkConflict(error instanceof Error ? error.message : "");
      if (conflict) {
        notify({
          title: "Benchmark already running",
          description: `A benchmark or ingest is already running for this evidence. Active run: ${conflict.active_run_id ?? "-"}. Active benchmark: ${conflict.active_benchmark_id ?? "-"}.`,
          tone: "warning",
        });
        return;
      }
      notify({ title: "Benchmark failed", description: error instanceof Error ? error.message : "The benchmark could not be queued.", tone: "error" });
    },
  });
  const onDemandRulesMutation = useMutation({
    mutationFn: async () =>
      api.runRulesForEvidence(evidenceId, {
        mode: "on_demand",
        scope: "evidence",
        rule_types: rulesEngineSelection === "all" ? ["sigma", "yara"] : [rulesEngineSelection],
      }),
    onSuccess: async (result) => {
      notify({
        title: "Rules run queued",
        description: result.message || `Rule run ${result.run_id} has been queued for this evidence.`,
        tone: "success",
      });
      await queryClient.invalidateQueries({ queryKey: ["evidence-rule-runs", evidenceId] });
    },
    onError: (error) => {
      notify({ title: "Rules run failed", description: error instanceof Error ? error.message : "The rules run could not be started.", tone: "error" });
    },
  });
  const generateReportMutation = useMutation({
    mutationFn: async () =>
      api.generateEvidenceReport(evidenceId, {
        scope: "evidence",
        report_type: "summary",
        format: "markdown",
        mode: "on_demand",
        include_detections: true,
        include_problematic_artifacts: true,
        include_search_summary: true,
        include_parser_contract: true,
      }),
    onSuccess: async (result) => {
      notify({
        title: "Report generated",
        description: `Report ${result.id} was generated from indexed evidence data.`,
        tone: "success",
      });
      await queryClient.invalidateQueries({ queryKey: ["evidence-reports", evidenceId] });
    },
    onError: (error) => {
      notify({ title: "Report generation failed", description: error instanceof Error ? error.message : "The report could not be generated.", tone: "error" });
    },
  });
  const benchmarkCompareMutation = useMutation({
    mutationFn: async (benchmarkIds: string[]) => api.compareEvidenceBenchmarks(evidenceId, { benchmark_ids: benchmarkIds }),
    onError: (error) => {
      notify({ title: "Benchmark compare failed", description: error instanceof Error ? error.message : "The benchmarks could not be compared.", tone: "error" });
    },
  });
  const deleteMutation = useMutation({
    mutationFn: () => api.deleteEvidence(evidenceId),
    onMutate: () => {
      notify({ title: "Deleting evidence", description: "The evidence is being removed from the case.", tone: "warning" });
    },
    onSuccess: async () => {
      const caseId = evidenceQuery.data?.case_id;
      notify({ title: "Evidence deleted", description: "The evidence was removed successfully.", tone: "success" });
      if (caseId) {
        await queryClient.invalidateQueries({ queryKey: ["evidences", caseId] });
        navigate(`/cases/${caseId}`);
      } else {
        navigate("/cases");
      }
    },
    onError: (error) => {
      notify({ title: "Delete failed", description: error instanceof Error ? error.message : "The evidence could not be deleted.", tone: "error" });
    },
  });
  const parseVelociraptorMutation = useMutation({
    mutationFn: (payload: { selected_candidate_ids?: string[]; parse_all?: boolean }) =>
      api.parseVelociraptorSelection({
        evidence_id: evidenceId,
        selected_candidate_ids: payload.selected_candidate_ids,
        parse_all: payload.parse_all,
        ingest_mode: (data?.metadata_json?.ingest_mode as "usable_search" | "full_forensic" | undefined) ?? "usable_search",
        provided_host: data?.provided_host ?? undefined,
        evtx_profile: ((data?.metadata_json?.ingest_mode as "usable_search" | "full_forensic" | undefined) ?? "usable_search") === "full_forensic" ? "full" : parseEvtxProfile,
      }),
    onMutate: (payload) => {
      notify({
        title: "Parsing queued",
        description: payload.parse_all ? "All supported raw collection artifacts have been queued for parsing." : "Selected raw collection artifacts have been queued for parsing.",
        tone: "info",
      });
    },
    onSuccess: () => {
      void queryClient.invalidateQueries({ queryKey: ["evidence", evidenceId] });
      void queryClient.invalidateQueries({ queryKey: ["evidence-manifest", evidenceId] });
      notify({ title: "Parsing started", description: "The worker has started extracting and parsing the selected artifacts.", tone: "success" });
    },
    onError: (error) => {
      notify({ title: "Parsing failed", description: error instanceof Error ? error.message : "The selected artifacts could not be queued for parsing.", tone: "error" });
    },
  });
  const retryProblematicArtifactsMutation = useMutation({
    mutationFn: async (payload: { artifactIds?: string[]; singleArtifactId?: string; mode: string }) => {
      if (payload.singleArtifactId) {
        return api.retryProblematicArtifact(evidenceId, payload.singleArtifactId, {
          mode: payload.mode,
          preserve_existing_events: true,
          replace_existing_events_for_artifact: false,
        });
      }
      return api.retryProblematicArtifacts(evidenceId, {
        artifact_ids: payload.artifactIds,
        mode: payload.mode,
        preserve_existing_events: true,
        replace_existing_events_for_artifact: false,
      });
    },
    onSuccess: () => {
      notify({ title: "Artifact retry queued", description: "Selected problematic artifacts were queued for retry without reprocessing the full evidence.", tone: "success" });
      void queryClient.invalidateQueries({ queryKey: ["evidence", evidenceId] });
      void queryClient.invalidateQueries({ queryKey: ["evidence-search-summary", evidenceId] });
      void queryClient.invalidateQueries({ queryKey: ["evidence-manifest", evidenceId] });
      void queryClient.invalidateQueries({ queryKey: ["evidence-problematic-artifacts", evidenceId] });
      void queryClient.invalidateQueries({ queryKey: ["evidence-problematic-retry-candidates", evidenceId] });
      void queryClient.invalidateQueries({ queryKey: ["evidence-runs", evidenceId] });
      setSelectedProblematicArtifactIds([]);
    },
    onError: (error) => {
      notify({ title: "Artifact retry failed", description: error instanceof Error ? error.message : "The selected artifacts could not be retried.", tone: "error" });
    },
  });
  const evtxHealthCheckMutation = useMutation({
    mutationFn: async (payload: { artifactId: string }) => api.checkEvtxHealth(evidenceId, payload.artifactId),
    onSuccess: async () => {
      notify({ title: "EVTX health check completed", description: "The problematic artifact report has been refreshed with the latest diagnosis.", tone: "success" });
      await queryClient.invalidateQueries({ queryKey: ["evidence-problematic-artifacts", evidenceId] });
    },
    onError: (error) => {
      notify({ title: "EVTX health check failed", description: error instanceof Error ? error.message : "The EVTX health check could not be completed.", tone: "error" });
    },
  });
  const acceptProblematicWarningMutation = useMutation({
    mutationFn: async (payload: { artifactId: string }) => api.acceptProblematicArtifactWarning(evidenceId, payload.artifactId),
    onSuccess: async () => {
      notify({ title: "Warning accepted", description: "The artifact warning was marked as acknowledged without changing the indexed events.", tone: "success" });
      await queryClient.invalidateQueries({ queryKey: ["evidence-problematic-artifacts", evidenceId] });
    },
    onError: (error) => {
      notify({ title: "Accept warning failed", description: error instanceof Error ? error.message : "The warning could not be acknowledged.", tone: "error" });
    },
  });
  const deferLongTailMutation = useMutation({
    mutationFn: async (payload: { artifactIds?: string[]; artifactId?: string }) => {
      if (payload.artifactId) {
        return api.deferLongTailArtifact(evidenceId, payload.artifactId, {});
      }
      return api.deferLongTailArtifacts(evidenceId, { artifact_ids: payload.artifactIds ?? [] });
    },
    onSuccess: async () => {
      notify({ title: "Long-tail defer requested", description: "The selected long-tail artifacts were marked for defer review.", tone: "success" });
      await queryClient.invalidateQueries({ queryKey: ["evidence-long-tail-artifacts", evidenceId] });
      await queryClient.invalidateQueries({ queryKey: ["evidence", evidenceId] });
    },
    onError: (error) => {
      notify({ title: "Long-tail defer failed", description: error instanceof Error ? error.message : "The long-tail artifacts could not be marked for defer.", tone: "error" });
    },
  });

  const data = evidenceQuery.data;
  const manifest = manifestQuery.data;
  const evidenceRuns = evidenceRunsQuery.data ?? [];
  const indexingPlan: EvidenceIndexingPlan | undefined = indexingPlanQuery.data;
  const benchmarks = evidenceBenchmarksQuery.data ?? [];
  const latestRun = evidenceRuns[0] ?? null;
  const latestBenchmark = benchmarks[0] ?? null;
  const activeBenchmark = benchmarks.find((item) => item.status === "queued" || item.status === "running") ?? null;
  const completedBenchmarks = benchmarks.filter((item) => item.status === "completed" || item.status === "completed_with_errors" || item.status === "failed");
  const compareableBenchmarks = completedBenchmarks.slice(0, 2);
  const benchmarkComparison = benchmarkCompareMutation.data as { speedup_duration?: number; speedup_records_per_sec?: number; profile_recommendation?: string; reason?: string } | undefined;
  const metadata = data?.metadata_json ?? {};
  const artifactProgressDone = typeof metadata.artifacts_done === "number" ? (metadata.artifacts_done as number) : typeof metadata.artifacts_processed === "number" ? (metadata.artifacts_processed as number) : 0;
  const artifactProgressTotal = typeof metadata.artifacts_total === "number" ? (metadata.artifacts_total as number) : 0;
  const progressPct =
    typeof metadata.progress_pct === "number"
      ? (metadata.progress_pct as number)
      : data?.ingest_status === "completed"
        ? 100
        : artifactProgressTotal > 0
          ? Math.min(99, Math.round((artifactProgressDone / artifactProgressTotal) * 100))
          : 0;
  const currentPhase =
    typeof metadata.current_phase === "string"
      ? (metadata.current_phase as string)
      : typeof metadata.phase === "string"
        ? (metadata.phase as string)
        : typeof (metadata.parallel_ingest as { bottleneck?: unknown } | undefined)?.bottleneck === "string"
          ? String((metadata.parallel_ingest as { bottleneck?: unknown }).bottleneck)
          : data?.ingest_status ?? "unknown";
  const rawDiscoveryCandidatesForState = ((metadata.velociraptor_discovery as { candidates?: unknown[] } | undefined)?.candidates ?? []);
  const rawDiscoveryCandidateCountForState = Array.isArray(rawDiscoveryCandidatesForState) ? rawDiscoveryCandidatesForState.length : 0;
  const waitingSelectionPhase = currentPhase === "selection_pending" || currentPhase === "waiting_selection";
  const isActive = data?.ingest_status === "pending" || data?.ingest_status === "processing";
  const metadataRunId = String(metadata.current_ingest_run_id ?? metadata.latest_ingest_run_id ?? "").trim();
  const latestRunId = String(latestRun?.run_id ?? "").trim();
  const planRunId = String(indexingPlan?.active_job?.run_id ?? "").trim();
  const latestRunIsActive = ["queued", "running", "pending", "processing"].includes(String(latestRun?.status || "").toLowerCase());
  const activeRun =
    isActive && latestRun && latestRunIsActive && (!metadataRunId || latestRunId === metadataRunId) && (!planRunId || latestRunId === planRunId)
      ? latestRun
      : null;
  const plannedNotStarted = indexingPlan?.state === "planned_not_started";
  const activeIndexingJob = Boolean(indexingPlan?.active || activeRun || (isActive && !plannedNotStarted && !(waitingSelectionPhase && rawDiscoveryCandidateCountForState > 0 && !metadata.current_ingest_run_id)));
  const waitingSelectionNeedsAction = isActive && !activeIndexingJob && waitingSelectionPhase && rawDiscoveryCandidateCountForState > 0;
  const staleIndexingState = isActive && !activeIndexingJob && !waitingSelectionNeedsAction && !plannedNotStarted;
  const activeIndexingPhase = String(indexingPlan?.active_job?.step || indexingPlan?.active_job?.status || activeRun?.status || currentPhase || "");
  const liveRunProgressPct = typeof activeRun?.progress === "number" ? activeRun.progress : progressPct;
  const liveRunPhase = activeIndexingPhase || activeRun?.phase || currentPhase;
  const liveRunArtifactsDone = typeof activeRun?.artifacts_done === "number" ? activeRun.artifacts_done : artifactProgressDone;
  const liveRunArtifactsTotal = typeof activeRun?.artifacts_total === "number" ? activeRun.artifacts_total : artifactProgressTotal;
  const liveRunIndexedDocs =
    typeof activeRun?.events_indexed === "number"
      ? activeRun.events_indexed
      : typeof activeRun?.records_indexed === "number"
        ? activeRun.records_indexed
        : Number(metadata.events_indexed ?? manifest?.stats?.indexed_events ?? 0);
  const liveRunHeartbeatAt = activeRun?.tail_last_progress_at || activeRun?.heartbeat_at || (typeof metadata.heartbeat_at === "string" ? (metadata.heartbeat_at as string) : null);
  const liveRunCurrentArtifact = activeRun?.current_artifact || (typeof metadata.current_artifact === "string" ? (metadata.current_artifact as string) : null);
  const activeRecommendedIndexing = activeIndexingJob && (indexingPlan?.profile === "recommended" || indexingProfile === "recommended");
  const displayStatus = String(data?.display_status ?? metadata.display_status ?? data?.ingest_status ?? "unknown");
  const investigationReady = Boolean(data?.investigation_ready ?? metadata.investigation_ready ?? false);
  const hasSearchableDocs = Number(searchSummaryQuery.data?.total_indexed_docs ?? metadata.events_indexed ?? manifest?.stats?.indexed_events ?? 0) > 0;
  const indexingState: EvidenceIndexingState = waitingSelectionNeedsAction
    ? "action_required"
    : staleIndexingState
      ? "stale"
      : activeIndexingJob
        ? ["pending", "queued", "selection_pending", "waiting_selection", "planning", "preparing"].some((item) => activeIndexingPhase.toLowerCase().includes(item))
          ? "planning_or_waiting"
          : "indexing"
        : displayStatus === "completed_with_warnings"
          ? "completed_with_warnings"
          : data?.ingest_status === "completed_with_errors"
            ? hasSearchableDocs || investigationReady
              ? "completed_with_errors"
              : "failed"
            : data?.ingest_status === "failed"
              ? "failed"
              : investigationReady || hasSearchableDocs || data?.ingest_status === "completed"
                ? "completed"
                : "not_started";
  const indexingStateTitle =
    indexingState === "not_started"
      ? plannedNotStarted
        ? "Ready to index"
        : "Index evidence for investigation"
      : indexingState === "action_required"
        ? "Action required: select what to index"
        : indexingState === "stale"
          ? "Indexing appears stuck"
      : indexingState === "planning_or_waiting"
        ? activeIndexingPhase.toLowerCase().includes("queued") || activeRun
          ? "Indexing job queued"
          : "Preparing indexing plan"
        : indexingState === "indexing"
          ? activeRecommendedIndexing
            ? "Recommended indexing is running"
            : "Indexing in progress"
          : indexingState === "completed"
            ? "Evidence ready for investigation"
            : indexingState === "completed_with_warnings"
              ? "Evidence ready with warnings"
              : indexingState === "completed_with_errors"
                ? "Indexing completed with errors"
                : "Indexing failed";
  const indexingStateSubcopy = indexingState === "action_required"
    ? "Discovery found supported artifacts, but indexing has not started yet. Continue with recommended indexing or choose categories manually."
    : indexingState === "stale"
      ? "The evidence is marked active but no worker run is visible. Cancel the stale state, then retry recommended indexing."
      : activeIndexingJob
    ? "An indexing job is already running for this evidence. Wait for it to finish or open Jobs & Activity."
    : indexingState === "not_started"
      ? plannedNotStarted
        ? "Recommended indexing plan is ready. Start indexing to parse and centralize the supported artifacts for investigation."
        : "Recommended indexing prepares event logs, filesystem, user activity, Defender, downloaded-file evidence and core artifacts. Rules and reports are run later."
      : indexingState === "completed" || indexingState === "completed_with_warnings"
        ? "Search, timeline, artifact views, rules and reports are available as post-indexing actions."
        : indexingState === "completed_with_errors"
          ? "Searchable data may already be available. Review real parser failures before retrying only the affected artifacts."
          : "Review the failure details and retry indexing only after checking the reported cause.";
  const primaryIndexingDisabled = runIndexingPlanMutation.isPending || activeIndexingJob || indexingProfile === "advanced_custom" || !indexingPlan?.can_run;
  const conflictingIndexingActionsDisabled = activeIndexingJob;
  const evidenceLifecycleStatus = String(data?.ingest_status ?? "").toLowerCase();
  const evidenceCanShowInvestigationActions = !["uploaded", "pending", "processing"].includes(evidenceLifecycleStatus);
  const evidenceReadyForActions =
    evidenceCanShowInvestigationActions && !activeIndexingJob && (investigationReady || hasSearchableDocs || indexingState === "completed" || indexingState === "completed_with_warnings" || indexingState === "completed_with_errors");
  const benchmarkLaunchDisabled = benchmarkMutation.isPending || activeIndexingJob || Boolean(activeBenchmark);
  const benchmarkToolsEnabled = import.meta.env.VITE_DFIR_ENABLE_BENCHMARK_TOOLS === "true";
  const latestWatchdogAction = latestBenchmark?.watchdog_actions?.length ? latestBenchmark.watchdog_actions[latestBenchmark.watchdog_actions.length - 1] : null;
  const latestBenchmarkAttempts = Array.isArray(latestBenchmark?.attempts) ? latestBenchmark?.attempts ?? [] : [];
  const onDemandModules = onDemandModulesQuery.data?.modules ?? {};
  const rulesModule = onDemandModules.rules;
  const reportsModule = onDemandModules.reports;
  const coreSearchHref = data?.case_id ? `/cases/${data.case_id}/search?evidence_id=${encodeURIComponent(evidenceId)}&tab=results` : "#";
  const timelineHref = data?.case_id ? `/cases/${data.case_id}/search?evidence_id=${encodeURIComponent(evidenceId)}&view=timeline&sort=@timestamp&order=asc` : "#";
  const artifactViewsHref = data?.case_id ? `/cases/${data.case_id}/artifacts?evidence_id=${encodeURIComponent(evidenceId)}` : "#";
  const detectionsHref = data?.case_id ? `/cases/${data.case_id}/detections?evidence_id=${encodeURIComponent(evidenceId)}` : "#";
  const reportsHref = data?.case_id ? `/cases/${data.case_id}/reports?evidence_id=${encodeURIComponent(evidenceId)}` : "#";
  const problematicHref = "#problematic-artifacts";
  const coreActions = [
    { id: "search", label: "Search this evidence", href: coreSearchHref, description: "Search all indexed data scoped to this evidence." },
    { id: "timeline", label: "Timeline view", href: timelineHref, description: "Open Search as a timeline with the same evidence scope." },
    { id: "artifacts", label: "Artifact Views", href: artifactViewsHref, description: "Open specialized artifact views without leaving the Search workspace model." },
    { id: "detections", label: "Detections", href: detectionsHref, description: "Review rule matches after you run rules on demand." },
    { id: "reports", label: "Reports", href: reportsHref, description: "Generate or open on-demand case reports." },
    { id: "problematic", label: "Problematic artifacts", href: problematicHref, description: "Review deferred, failed or retryable artifacts for this evidence." },
    { id: "indexed", label: "View indexed artifacts", href: "#artifact-manifest", description: "Inspect manifest, parsed artifacts and raw-preserved items." },
  ];
  const orderedModuleIds = ["rules", "reports", "host_enrichment", "deep_retry", "benchmark", "advanced_exports"];
  const onDemandEntries = orderedModuleIds
    .map((moduleId) => onDemandModules[moduleId] as OnDemandModule | undefined)
    .filter((entry): entry is OnDemandModule => Boolean(entry))
    .filter((entry) => entry.id !== "benchmark" || benchmarkToolsEnabled);
  const stableOnDemandEntries = onDemandEntries.filter((entry) => entry.module_category === "on_demand_stable");
  const advancedEntries = onDemandEntries.filter((entry) => entry.module_category !== "on_demand_stable");
  const evidenceRuleRuns = evidenceRuleRunsQuery.data ?? [];
  const evidenceReports = evidenceReportsQuery.data ?? [];
  const latestEvidenceRuleRun: RuleRun | null = evidenceRuleRuns[0] ?? null;
  const activeEvidenceRuleRun = evidenceRuleRuns.find((item) => item.status === "queued" || item.status === "running") ?? null;
  const latestEvidenceReport: CaseReport | null = evidenceReports[0] ?? null;
  const activeEvidenceReport = evidenceReports.find((item) => item.status === "queued" || item.status === "running") ?? null;
  const ruleRunDetectionsHref =
    data?.case_id && latestEvidenceRuleRun
      ? `/cases/${data.case_id}/detections?evidence_id=${encodeURIComponent(evidenceId)}&rule_run_id=${encodeURIComponent(latestEvidenceRuleRun.id)}`
      : "#";
  const rulesWorkspaceHref = rulesModule?.case_route || "#";
  const reportsWorkspaceHref = reportsModule?.case_route || "#";
  const rulesLaunchDisabled =
    rulesModule?.status === "disabled" ||
    onDemandRulesMutation.isPending ||
    activeIndexingJob ||
    Boolean(activeEvidenceRuleRun) ||
    !data?.case_id;
  const reportLaunchDisabled =
    reportsModule?.status === "disabled" ||
    generateReportMutation.isPending ||
    activeIndexingJob ||
    Boolean(activeEvidenceReport) ||
    !data?.case_id;

  const filteredArtifacts = useMemo(
    () => (manifest?.artifacts ?? []).filter((artifact) => matchesArtifactFilter(artifact, filters)),
    [filters, manifest?.artifacts],
  );
  const indexedArtifactTypeCounts = useMemo(() => {
    if (searchSummaryQuery.data?.artifact_type_counts && Object.keys(searchSummaryQuery.data.artifact_type_counts).length) {
      return Object.entries(searchSummaryQuery.data.artifact_type_counts).sort((left, right) => right[1] - left[1]).slice(0, 6);
    }
    const counts = new Map<string, number>();
    for (const artifact of manifest?.artifacts ?? []) {
      if (artifact.status !== "completed") continue;
      const key = artifact.artifact_type || "unknown";
      counts.set(key, (counts.get(key) ?? 0) + 1);
    }
    return Array.from(counts.entries()).sort((left, right) => right[1] - left[1]).slice(0, 6);
  }, [manifest?.artifacts, searchSummaryQuery.data?.artifact_type_counts]);
  const indexedParserCounts = useMemo(
    () => Object.entries(searchSummaryQuery.data?.parser_counts ?? {}).sort((left, right) => right[1] - left[1]).slice(0, 6),
    [searchSummaryQuery.data?.parser_counts],
  );
  const processedArtifacts = filteredArtifacts.filter((artifact) => artifact.status === "completed");
  const preservedRawArtifacts = filteredArtifacts.filter((artifact) => artifact.status === "detected_not_parsed");
  const otherArtifacts = filteredArtifacts.filter((artifact) => !["completed", "detected_not_parsed"].includes(artifact.status));
  const artifactTypes = [...new Set((manifest?.artifacts ?? []).map((artifact) => artifact.artifact_type))];
  const parsers = [...new Set((manifest?.artifacts ?? []).map((artifact) => artifact.parser))];
  const statuses = [...new Set((manifest?.artifacts ?? []).map((artifact) => artifact.status))];
  const discovery = (data?.metadata_json?.velociraptor_discovery as { candidates?: VelociraptorCandidate[]; collection_root?: string; hostname?: string; total_files_scanned?: number } | undefined) ?? null;
  const discoveryCandidates = discovery?.candidates ?? [];
  const evtxDeferredCount = typeof data?.metadata_json?.evtx_deferred_count === "number" ? (data.metadata_json.evtx_deferred_count as number) : 0;
  const evtxPartialCount = typeof data?.metadata_json?.evtx_partial_count === "number" ? (data.metadata_json.evtx_partial_count as number) : 0;
  const evtxCoverageStatus = typeof data?.metadata_json?.evtx_coverage_status === "string" ? (data.metadata_json.evtx_coverage_status as string) : "";
  const evtxProfile = typeof data?.metadata_json?.evtx_profile === "string" ? (data.metadata_json.evtx_profile as string) : "";
  const evtxParserBackend = typeof data?.metadata_json?.evtx_parser_backend === "string" ? (data.metadata_json.evtx_parser_backend as string) : "";
  const evtxParserBackendVersion = typeof data?.metadata_json?.evtx_parser_backend_version === "string" ? (data.metadata_json.evtx_parser_backend_version as string) : "";
  const evtxParserBackendFallback = data?.metadata_json?.evtx_parser_backend_fallback === true;
  const evtxecmdAvailable = evtxParserBackend === "evtxecmd_csv";
  const evtxSelectedFiles = Array.isArray(data?.metadata_json?.evtx_selected_files) ? (data.metadata_json.evtx_selected_files as unknown[]) : [];
  const evtxCoverageIsFull = evtxCoverageStatus === "full" && evtxDeferredCount === 0 && evtxPartialCount === 0;
  const indexedDocumentsTotal = Number(searchSummaryQuery.data?.total_indexed_docs ?? data?.metadata_json?.events_indexed ?? manifest?.stats?.indexed_events ?? 0);
  const mftDiagnostic = mftDiagnosticQuery.data ?? searchSummaryQuery.data?.mft_diagnostic ?? null;
  const userActivityCounts = (data?.metadata_json?.registry_user_activity_counts as Record<string, number> | undefined) ?? {};
  const userActivityTotal = Number(data?.metadata_json?.registry_user_activity_records_indexed ?? Object.values(userActivityCounts).reduce((sum, value) => sum + Number(value || 0), 0));
  const userActivityStatus = String(data?.metadata_json?.registry_user_activity_status ?? "not_indexed");
  const defenderDocs = Number(data?.metadata_json?.defender_evtx_docs_indexed ?? searchSummaryQuery.data?.artifact_type_counts?.defender ?? 0);
  const defenderStatus = String(data?.metadata_json?.defender_evtx_status ?? "not_indexed");
  const defenderNoData = data?.metadata_json?.defender_evtx_no_data === true;
  const srumDocs = Number(data?.metadata_json?.srum_records_indexed ?? searchSummaryQuery.data?.artifact_type_counts?.srum ?? 0);
  const srumStatus = String(data?.metadata_json?.srum_status ?? "not_indexed");
  const srumNoData = data?.metadata_json?.srum_no_data === true;
  const srumToolingMissing = data?.metadata_json?.srum_tooling_missing === true;
  const srumTables = (data?.metadata_json?.srum_tables_detected as Record<string, number> | undefined) ?? {};
  const artifactTypeCount = Object.keys(searchSummaryQuery.data?.artifact_type_counts ?? {}).length || indexedArtifactTypeCounts.length;
  const problemsCount = Number(problematicArtifactsQuery.data?.summary?.problematic_count ?? data?.metadata_json?.evtx_deferred_count ?? 0) + evtxPartialCount;
  const displayCounts = activeIndexingJob
    ? {
        source: "active_run" as const,
        isFinal: false,
        progressPct: liveRunProgressPct,
        phase: liveRunPhase,
        indexedDocs: liveRunIndexedDocs,
        artifactsDone: liveRunArtifactsDone,
        artifactsTotal: liveRunArtifactsTotal,
        heartbeatAt: liveRunHeartbeatAt,
        currentArtifact: liveRunCurrentArtifact,
      }
    : {
        source: "persisted_summary" as const,
        isFinal: true,
        progressPct,
        phase: currentPhase,
        indexedDocs: indexedDocumentsTotal,
        artifactsDone: artifactProgressDone,
        artifactsTotal: artifactProgressTotal,
        heartbeatAt: typeof data?.metadata_json?.heartbeat_at === "string" ? (data.metadata_json.heartbeat_at as string) : null,
        currentArtifact: typeof data?.metadata_json?.current_artifact === "string" ? (data.metadata_json.current_artifact as string) : null,
      };
  const completedAt = data?.processed_at ?? (typeof data?.metadata_json?.completed_at === "string" ? (data.metadata_json.completed_at as string) : null);
  const productModeLabel = String(data?.metadata_json?.ingest_mode ?? "usable_search") === "full_forensic" ? "Advanced processing" : "Core indexing";
  const evtxCoverageLabel = evtxCoverageIsFull
    ? `Full EVTX coverage · ${formatEvtxBackend(evtxParserBackend)}${evtxParserBackendVersion ? ` ${evtxParserBackendVersion}` : ""}`
    : evtxDeferredCount || evtxPartialCount
      ? `Partial/Triage EVTX · ${evtxDeferredCount} deferred · ${evtxPartialCount} partial`
      : evtxParserBackend
        ? `EVTX parser · ${formatEvtxBackend(evtxParserBackend)}${evtxParserBackendVersion ? ` ${evtxParserBackendVersion}` : ""}`
        : "EVTX coverage not reported";
  const selectionPending = !activeIndexingJob && (currentPhase === "selection_pending" || currentPhase === "waiting_selection") && Boolean(discoveryCandidates.length);
  const startedAt = typeof data?.metadata_json?.started_at === "string" ? (data.metadata_json.started_at as string) : null;
  const elapsedSeconds = typeof data?.metadata_json?.elapsed_seconds === "number" ? (data.metadata_json.elapsed_seconds as number) : null;
  const startedAtTimestamp = startedAt ? Date.parse(startedAt) : Number.NaN;
  const liveElapsedSeconds = isActive && Number.isFinite(startedAtTimestamp) ? Math.max(0, Math.round((nowMs - startedAtTimestamp) / 1000)) : null;
  const displayedElapsedSeconds = liveElapsedSeconds ?? elapsedSeconds;
  const etaSeconds = typeof data?.metadata_json?.estimated_remaining_seconds === "number" ? (data.metadata_json.estimated_remaining_seconds as number) : null;
  const currentItem = typeof data?.metadata_json?.current_item === "string" ? (data.metadata_json.current_item as string) : null;
  const currentAction = typeof data?.metadata_json?.current_action === "string" ? (data.metadata_json.current_action as string) : null;
  const currentSelectedPath = typeof data?.metadata_json?.current_selected_path === "string" ? (data.metadata_json.current_selected_path as string) : null;
  const currentArtifactPath = typeof data?.metadata_json?.current_artifact_path === "string" ? (data.metadata_json.current_artifact_path as string) : null;
  const currentArtifactLabel = typeof data?.metadata_json?.current_artifact_progress_label === "string" ? (data.metadata_json.current_artifact_progress_label as string) : null;
  const currentArtifactSource = typeof data?.metadata_json?.current_artifact_source === "string" ? (data.metadata_json.current_artifact_source as string) : null;
  const currentArtifactRecordsRead = typeof data?.metadata_json?.current_artifact_records_read === "number" ? (data.metadata_json.current_artifact_records_read as number) : null;
  const currentArtifactRecordsIndexed = typeof data?.metadata_json?.current_artifact_records_indexed === "number" ? (data.metadata_json.current_artifact_records_indexed as number) : null;
  const artifactsDone = artifactProgressDone;
  const artifactsFailed = typeof data?.metadata_json?.artifacts_failed === "number" ? (data.metadata_json.artifacts_failed as number) : 0;
  const parallelIngest = (data?.metadata_json?.parallel_ingest as {
    enabled?: boolean;
    effective_parallelism?: number;
    desired_parallelism?: number;
    running_artifacts?: Array<{ artifact?: string; artifact_type?: string; parser?: string; source_path?: string; records_read?: number; records_indexed?: number; elapsed_seconds?: number }>;
    running_artifact_types?: string[];
    queued_artifacts?: number;
    bottleneck?: string;
    limitation_reason?: string | null;
    artifacts_parallelized_by_type?: Record<string, number>;
    artifacts_sequential_by_type?: Record<string, number>;
  } | undefined) ?? null;
  const modeEffectivePlan = (data?.metadata_json?.mode_effective_plan as {
    ingest_mode?: string;
    automatic_tasks?: string[];
    automatic_task_categories?: string[];
    skipped_features?: string[];
    enabled_artifact_categories?: string[];
    disabled_artifact_categories?: string[];
    expensive_features_disabled?: string[];
  } | undefined) ?? null;
  const tailArtifactsRunning = typeof data?.metadata_json?.tail_artifacts_running === "number" ? (data.metadata_json.tail_artifacts_running as number) : (parallelIngest?.running_artifacts?.length ?? 0);
  const tailArtifactsQueued = typeof data?.metadata_json?.tail_artifacts_queued === "number" ? (data.metadata_json.tail_artifacts_queued as number) : (parallelIngest?.queued_artifacts ?? 0);
  const tailArtifactsTotal = typeof data?.metadata_json?.tail_artifacts_total === "number" ? (data.metadata_json.tail_artifacts_total as number) : tailArtifactsRunning + tailArtifactsQueued;
  const tailRecordsRead = typeof data?.metadata_json?.tail_records_read === "number" ? (data.metadata_json.tail_records_read as number) : null;
  const tailRecordsIndexed = typeof data?.metadata_json?.tail_records_indexed === "number" ? (data.metadata_json.tail_records_indexed as number) : null;
  const tailLastProgressAt = typeof data?.metadata_json?.tail_last_progress_at === "string" ? (data.metadata_json.tail_last_progress_at as string) : null;
  const tailCurrentArtifacts = Array.isArray(data?.metadata_json?.tail_current_artifacts)
    ? (data.metadata_json.tail_current_artifacts as Array<Record<string, unknown>>)
    : ((parallelIngest?.running_artifacts as Array<Record<string, unknown>> | undefined) ?? []);
  const longTailArtifacts = longTailArtifactsQuery.data?.items ?? [];
  const longTailSummary = longTailArtifactsQuery.data?.summary;
  const hasLongTail =
    isActive &&
    ((longTailSummary?.tail_artifacts_total ?? tailArtifactsTotal) > 0) &&
    ((longTailSummary?.running_count ?? tailArtifactsRunning) > 0 || (longTailSummary?.queued_count ?? tailArtifactsQueued) > 0);
  const effectiveCurrentArtifactPath = currentArtifactSource === "parallel_running_artifacts" && tailArtifactsRunning > 1 ? null : currentArtifactPath;
  const effectiveCurrentArtifactLabel =
    currentArtifactSource === "parallel_running_artifacts" && tailArtifactsRunning > 1
      ? `${tailArtifactsRunning} artifacts active${tailRecordsRead !== null && tailRecordsIndexed !== null ? ` · ${tailRecordsRead} records read / ${tailRecordsIndexed} indexed` : ""}`
      : currentArtifactLabel;
  const currentDisplayArtifact = String(displayCounts.currentArtifact ?? effectiveCurrentArtifactPath ?? currentSelectedPath ?? currentItem ?? "");
  const heartbeatAt = typeof data?.metadata_json?.heartbeat_at === "string" ? (data.metadata_json.heartbeat_at as string) : null;
  const ingestModeLabel = String(data?.metadata_json?.ingest_mode ?? onDemandModulesQuery.data?.core_flow.recommended_ingest_mode ?? "usable_search").replaceAll("_", " ");
  const lastProgressAgeLabel = tailLastProgressAt ? formatHeartbeatAge(tailLastProgressAt) : displayCounts.heartbeatAt ? formatHeartbeatAge(displayCounts.heartbeatAt) : heartbeatAt ? formatHeartbeatAge(heartbeatAt) : "-";
  const lastProgressAgeSeconds = (() => {
    const value = tailLastProgressAt || heartbeatAt;
    if (!value) return null;
    const timestamp = Date.parse(value);
    if (Number.isNaN(timestamp)) return null;
    return Math.max(0, Math.round((Date.now() - timestamp) / 1000));
  })();
  const recentActivityState =
    !isActive
      ? "Terminal"
      : lastProgressAgeSeconds !== null && lastProgressAgeSeconds <= 90
        ? "Still progressing"
        : heartbeatAt
          ? "Possible stall"
          : "Waiting for worker progress";
  const progressStatusLabel = isActive
    ? tailLastProgressAt && formatHeartbeatAge(tailLastProgressAt) !== "-"
      ? `Still progressing · last material progress ${formatHeartbeatAge(tailLastProgressAt)} ago`
      : heartbeatAt
        ? `No recent progress detected · heartbeat ${formatHeartbeatAge(heartbeatAt)} ago`
        : "Waiting for worker progress"
    : "Terminal";
  const recentActivityDetail =
    !isActive
      ? "This run is already in a terminal state."
      : tailLastProgressAt && tailRecordsIndexed !== null
        ? `Slow but active · ${tailRecordsIndexed} indexed in the current tail view · last material progress ${formatHeartbeatAge(tailLastProgressAt)} ago`
        : heartbeatAt
          ? `No recent material delta detected · worker heartbeat ${formatHeartbeatAge(heartbeatAt)} ago`
          : "Waiting for worker progress";
  const hasStructuredProgressMetadata =
    currentArtifactPath !== null ||
    currentArtifactLabel !== null ||
    currentArtifactRecordsRead !== null ||
    currentArtifactRecordsIndexed !== null ||
    typeof data?.metadata_json?.artifacts_total === "number";
  const showMissingProgressWarning = isActive && Boolean(heartbeatAt) && !hasStructuredProgressMetadata;
  const discoveryFilesScanned = typeof data?.metadata_json?.discovery_files_scanned === "number" ? (data.metadata_json.discovery_files_scanned as number) : null;
  const discoveryTotalFiles = typeof data?.metadata_json?.discovery_total_files === "number" ? (data.metadata_json.discovery_total_files as number) : null;
  const discoveryCandidatesDetected = typeof data?.metadata_json?.discovery_candidates_detected === "number" ? (data.metadata_json.discovery_candidates_detected as number) : null;
  const totalZipEntries = typeof data?.metadata_json?.total_zip_entries === "number" ? (data.metadata_json.total_zip_entries as number) : null;
  const ignoredEntries = typeof data?.metadata_json?.ignored_entries === "number" ? (data.metadata_json.ignored_entries as number) : null;
  const candidateFiles = typeof data?.metadata_json?.candidate_files === "number" ? (data.metadata_json.candidate_files as number) : null;
  const selectedFilesTotal = typeof data?.metadata_json?.selected_files_total === "number" ? (data.metadata_json.selected_files_total as number) : null;
  const selectedFilesExtracted = typeof data?.metadata_json?.selected_files_extracted === "number" ? (data.metadata_json.selected_files_extracted as number) : null;
  const selectedFilesProcessed = typeof data?.metadata_json?.selected_files_processed === "number" ? (data.metadata_json.selected_files_processed as number) : selectedFilesExtracted;
  const filesMaterialized = typeof data?.metadata_json?.files_materialized === "number" ? (data.metadata_json.files_materialized as number) : null;
  const filesSkippedExisting = typeof data?.metadata_json?.files_skipped_existing === "number" ? (data.metadata_json.files_skipped_existing as number) : null;
  const extractionRateFiles = typeof data?.metadata_json?.extraction_rate_files_per_sec === "number" ? (data.metadata_json.extraction_rate_files_per_sec as number) : null;
  const extractionRateMb = typeof data?.metadata_json?.extraction_rate_mb_per_sec === "number" ? (data.metadata_json.extraction_rate_mb_per_sec as number) : null;
  const extractingElapsedSeconds = typeof data?.metadata_json?.extracting_selected_elapsed_seconds === "number" ? (data.metadata_json.extracting_selected_elapsed_seconds as number) : null;
  const extractionErrors = typeof data?.metadata_json?.extraction_errors === "number" ? (data.metadata_json.extraction_errors as number) : null;
  const selectedArtifactTypes = Array.isArray(data?.metadata_json?.selected_artifact_types) ? (data?.metadata_json?.selected_artifact_types as string[]) : [];
  const notSelectedCandidatesCountByCategory = (data?.metadata_json?.not_selected_candidates_count_by_category as Record<string, number> | undefined) ?? {};
  const showExtractingSelected = currentPhase === "extracting_selected";
  const showExtractionStallWarning =
    showExtractingSelected &&
    isActive &&
    Boolean(heartbeatAt) &&
    selectedFilesTotal !== null &&
    selectedFilesProcessed !== null &&
    selectedFilesProcessed <= 0 &&
    (extractingElapsedSeconds ?? displayedElapsedSeconds ?? 0) >= 30;
  const retryModeDescriptions: Record<string, string> = {
    default: "Use the current limits. Good for transient failures.",
    higher_timeout: "Increase record, artifact and bulk timeouts for slow EVTX files.",
    no_detections: "Parse and index events but skip detection creation during the retry.",
    safe_mode: "Use higher timeout, no detections and smaller batches for difficult EVTX files.",
    deep_safe_mode: "Use long EVTX timeouts, no detections, small batches and a hard per-artifact limit for deep recovery attempts.",
    parse_only: "Read records without indexing them, useful to isolate parser vs indexing issues.",
  };

  useEffect(() => {
    if (!reprocessDialogOpen) return;
    function handleKeyDown(event: KeyboardEvent) {
      if (event.key === "Escape") {
        setReprocessDialogOpen(false);
      }
    }
    window.addEventListener("keydown", handleKeyDown);
    const body = document.body;
    const previousOverflow = body.style.overflow;
    const previousOverscroll = body.style.overscrollBehavior;
    body.style.overflow = "hidden";
    body.style.overscrollBehavior = "contain";
    return () => {
      window.removeEventListener("keydown", handleKeyDown);
      body.style.overflow = previousOverflow;
      body.style.overscrollBehavior = previousOverscroll;
    };
  }, [reprocessDialogOpen]);
  const categoryRows = Object.entries(
    discoveryCandidates.reduce<Record<string, { total: number; supported: number; partial: number; notImplemented: number; warnings: number }>>((accumulator, candidate) => {
      const bucket = accumulator[candidate.category] ?? { total: 0, supported: 0, partial: 0, notImplemented: 0, warnings: 0 };
      bucket.total += 1;
      if (candidate.supported) bucket.supported += 1;
      if (candidate.supported && candidate.parser_status === "partial") bucket.partial += 1;
      if (!candidate.supported) bucket.notImplemented += 1;
      bucket.warnings += candidate.warnings.length;
      accumulator[candidate.category] = bucket;
      return accumulator;
    }, {}),
  );
  const candidatesByCategory = useMemo(
    () =>
      Object.entries(
        discoveryCandidates.reduce<Record<string, VelociraptorCandidate[]>>((accumulator, candidate) => {
          const key = candidate.category || "other";
          accumulator[key] = accumulator[key] ?? [];
          accumulator[key].push(candidate);
          return accumulator;
        }, {}),
      ).sort((left, right) => {
        const leftSupported = left[1].filter((candidate) => candidate.supported).length;
        const rightSupported = right[1].filter((candidate) => candidate.supported).length;
        if (leftSupported !== rightSupported) return rightSupported - leftSupported;
        return left[0].localeCompare(right[0]);
      }),
    [discoveryCandidates],
  );
  const supportsGranularReprocess = isRawDiscoveryEvidenceLike(data, discoveryCandidates.length);
  const problematicArtifacts = problematicArtifactsQuery.data?.items ?? [];
  const problemImpactCounts = problematicArtifacts.reduce<Record<string, number>>((accumulator, artifact) => {
    const impact = problematicImpact(artifact);
    accumulator[impact.group] = (accumulator[impact.group] ?? 0) + 1;
    return accumulator;
  }, {});
  const problematicSummary = problematicArtifactsQuery.data?.summary;
  const retryCandidates = problematicRetryCandidatesQuery.data?.retry_candidates ?? problematicArtifacts.filter((artifact) => artifact.retryable && (artifact.current_data_loss_expected ?? artifact.data_loss_expected));
  const retryCandidateIds = problematicRetryCandidatesQuery.data?.artifact_ids ?? retryCandidates.map((artifact) => artifact.artifact_id).filter((artifactId): artifactId is string => Boolean(artifactId));
  const retryAffectedFamilies = Object.keys(problematicRetryCandidatesQuery.data?.affected_families ?? {}).length
    ? Object.keys(problematicRetryCandidatesQuery.data?.affected_families ?? {})
    : Array.from(new Set(retryCandidates.map((artifact) => artifact.artifact_type || artifact.parser || "unknown")));
  const retryCandidateExamples = retryCandidates.slice(0, 4).map((artifact) => artifact.name);
  const warningProblems = problematicArtifacts.filter((artifact) => {
    const effectiveStatus = String(artifact.effective_status ?? artifact.status ?? "").toLowerCase();
    const recordsRead = artifact.effective_records_read ?? artifact.records_read;
    const recordsIndexed = artifact.effective_records_indexed ?? artifact.records_indexed;
    return !artifact.retryable && !((artifact.current_data_loss_expected ?? artifact.data_loss_expected) === true) && recordsRead > 0 && recordsRead === recordsIndexed && ["parsed_with_warning", "accepted_warning", "health_check_only_valid", "source_missing_but_indexed"].includes(effectiveStatus);
  });
  const informationalProblems = problematicArtifacts.filter((artifact) => {
    const effectiveStatus = String(artifact.effective_status ?? artifact.status ?? "").toLowerCase();
    return ["skipped_empty", "completed_no_records", "unsupported_no_records"].includes(effectiveStatus);
  });
  const timeoutRunSummary = buildRunTimeoutSummary(latestRun, problematicSummary?.problematic_count ?? 0);
  const metadataCoherence = (data?.metadata_json?.ingest_performance as { metadata_coherence?: { delta?: number } } | undefined)?.metadata_coherence;
  const indexedEventsCoherent = typeof metadataCoherence?.delta === "number" && metadataCoherence.delta === 0;
  const ingestPlan = (data?.metadata_json?.ingest_plan as Record<string, unknown> | undefined) ?? null;
  const lastSuccessfulIngestPlan = (data?.metadata_json?.last_successful_ingest_plan as Record<string, unknown> | undefined) ?? ingestPlan;
  const reprocessPreview = reprocessPreviewQuery.data;
  const previewSelectedByArtifactType = useMemo(() => {
    if (!reprocessPreview) return {} as Record<string, number>;
    if (reprocessPreview.summary.selected_by_artifact_type) return reprocessPreview.summary.selected_by_artifact_type;
    return reprocessPreview.selected_candidates.reduce<Record<string, number>>((accumulator, candidate) => {
      const key = candidate.artifact_type || "unknown";
      accumulator[key] = (accumulator[key] ?? 0) + 1;
      return accumulator;
    }, {});
  }, [reprocessPreview]);
  const previewSelectedByParser = useMemo(() => {
    if (!reprocessPreview) return {} as Record<string, number>;
    if (reprocessPreview.summary.selected_by_parser) return reprocessPreview.summary.selected_by_parser;
    return reprocessPreview.selected_candidates.reduce<Record<string, number>>((accumulator, candidate) => {
      const key = candidate.parser || "unknown";
      accumulator[key] = (accumulator[key] ?? 0) + 1;
      return accumulator;
    }, {});
  }, [reprocessPreview]);
  const reprocessHasEvtx = Boolean(previewSelectedByArtifactType.windows_event || previewSelectedByParser.evtx_raw);
  const selectedSupportedCandidateCount = selectedCandidateIds.filter((candidateId) => discoveryCandidates.some((candidate) => candidate.id === candidateId && candidate.supported)).length;
  const supportedCategoryOptions = useMemo(
    () =>
      candidatesByCategory
        .map(([category, candidates]) => ({
          category,
          label: formatCategoryLabel(category),
          supportedIds: candidates.filter((candidate) => candidate.supported).map((candidate) => candidate.id),
          parseableCount: candidates.filter((candidate) => candidate.supported && candidate.parser_status !== "partial").length,
          partialCount: candidates.filter((candidate) => candidate.supported && candidate.parser_status === "partial").length,
        }))
        .filter((entry) => entry.supportedIds.length > 0),
    [candidatesByCategory],
  );
  const storageMode = data?.storage_mode ?? "uploaded";
  const storagePath = data?.stored_path ?? "-";
  const originalPath = data?.original_path ?? "-";
  const hasPowerShellCategory = supportedCategoryOptions.some((option) => option.category === "powershell");
  const hasEvtxCategory = supportedCategoryOptions.some((option) => option.category === "evtx");
  const selectedCategoryNames = supportedCategoryOptions
    .filter((option) => option.supportedIds.some((id) => selectedCandidateIds.includes(id)))
    .map((option) => option.label);
  const manualSelectionActive = selectedCandidateIds.length > 0;
  const enabledArtifactCategories = modeEffectivePlan?.enabled_artifact_categories ?? [];
  const activeRunCategoryNames = useMemo(() => {
    const parserCategoryMap: Record<string, string> = {
      evtx_raw: "evtx",
      evtxecmd_csv: "evtx",
      sysmon_evtx: "evtx",
      powershell_evtx: "evtx",
      scheduled_task_xml: "scheduled_task",
      windows_service_registry: "service",
      shimcache_raw: "shimcache",
      prefetch_raw: "prefetch",
      lnk_raw: "lnk",
      jumplist_raw: "jumplist",
      mft_raw: "mft",
      ntfs_raw: "mft",
      defender_evtx: "defender",
      recmd_user_activity: "user_activity",
      motw: "motw",
      startup_persistence: "startup_persistence",
    };
    const categoryAliases: Record<string, string> = {
      windows_event: "evtx",
      services: "service",
      scheduled_tasks: "scheduled_task",
      startup: "startup_persistence",
      startup_folder: "startup_persistence",
      autoruns: "startup_persistence",
    };
    const preferredOrder = ["evtx", "scheduled_task", "service", "shimcache", "prefetch", "lnk", "jumplist", "mft", "defender", "user_activity", "motw", "startup_persistence"];
    const values: string[] = [];
    const pushValue = (value: unknown) => {
      const raw = String(value ?? "").trim();
      if (!raw) return;
      const normalized = raw.toLowerCase().replaceAll("-", "_").replaceAll(" ", "_");
      values.push(categoryAliases[normalized] ?? parserCategoryMap[normalized] ?? normalized);
    };
    const metadataCategories = metadata.velociraptor_selected_categories;
    if (Array.isArray(metadataCategories)) metadataCategories.forEach(pushValue);
    const selectedByParser = ingestPlan?.selected_by_parser;
    if (selectedByParser && typeof selectedByParser === "object" && !Array.isArray(selectedByParser)) Object.keys(selectedByParser).forEach(pushValue);
    const selectedByArtifactType = ingestPlan?.selected_by_artifact_type;
    if (selectedByArtifactType && typeof selectedByArtifactType === "object" && !Array.isArray(selectedByArtifactType)) Object.keys(selectedByArtifactType).forEach(pushValue);
    enabledArtifactCategories.forEach(pushValue);
    const unique = Array.from(new Set(values));
    return unique.sort((left, right) => {
      const leftIndex = preferredOrder.indexOf(left);
      const rightIndex = preferredOrder.indexOf(right);
      if (leftIndex === -1 && rightIndex === -1) return left.localeCompare(right);
      if (leftIndex === -1) return 1;
      if (rightIndex === -1) return -1;
      return leftIndex - rightIndex;
    });
  }, [enabledArtifactCategories, ingestPlan, metadata.velociraptor_selected_categories]);
  const selectedIndexingLocked = activeIndexingJob;
  const selectedIndexingAvailable = supportsGranularReprocess && supportedCategoryOptions.length > 0;
  const skippedFeatures = modeEffectivePlan?.skipped_features ?? [];
  const currentBottleneck = parallelIngest?.running_artifact_types?.includes("windows_event")
    ? "EVTX parsing/indexing"
    : parallelIngest?.bottleneck
      ? String(parallelIngest.bottleneck).replaceAll("_", " ")
      : null;
  const effectivePlanSummary = ingestModeLabel === "full forensic"
    ? "Advanced processing enabled"
    : `Usable Search — ${skippedFeatures.length ? `${skippedFeatures.join(", ").replaceAll("_", " ")} skipped` : "search-first plan active"}`;

  useEffect(() => {
    if (!isActive) return;
    const timer = window.setInterval(() => setNowMs(Date.now()), 1000);
    return () => window.clearInterval(timer);
  }, [isActive]);

  useEffect(() => {
    if (!reprocessDialogOpen || !reprocessPreview) return;
    setReprocessSelectionIds((current) => {
      if (reprocessMode !== "manual_selection" && current.length) {
        return current;
      }
      const next = reprocessPreview.selected_candidates.map((candidate) => candidate.candidate_id);
      return next;
    });
  }, [reprocessDialogOpen, reprocessPreview, reprocessMode]);

  function toggleCandidate(candidateId: string) {
    setSelectedCandidateIds((current) => (current.includes(candidateId) ? current.filter((item) => item !== candidateId) : [...current, candidateId]));
  }

  function selectAllSupported() {
    setSelectedCandidateIds(discoveryCandidates.filter((candidate) => candidate.supported).map((candidate) => candidate.id));
  }

  function selectEventLogsOnly() {
    setSelectedCandidateIds(discoveryCandidates.filter((candidate) => (candidate.category === "evtx" || candidate.category === "windows_event") && candidate.supported).map((candidate) => candidate.id));
  }

  function selectCategories(categories: string[]) {
    const categorySet = new Set(categories);
    setSelectedCandidateIds(discoveryCandidates.filter((candidate) => categorySet.has(candidate.category) && candidate.supported).map((candidate) => candidate.id));
  }

  function selectExecutionArtifacts() {
    selectCategories(["evtx", "windows_event", "prefetch", "shimcache", "amcache", "lnk", "jumplist"]);
  }

  function selectPersistenceArtifacts() {
    selectCategories(["scheduled_task", "service", "registry_autoruns", "autoruns", "startup", "startup_folder", "wmi", "defender"]);
  }

  function scrollToParseSelection() {
    if (typeof selectedArtifactTypesRef.current?.scrollIntoView === "function") {
      selectedArtifactTypesRef.current.scrollIntoView({ behavior: "smooth", block: "start" });
    }
  }

  function selectCategory(category: string) {
    setSelectedCandidateIds(discoveryCandidates.filter((candidate) => candidate.category === category && candidate.supported).map((candidate) => candidate.id));
  }

  function toggleCategorySelection(category: string) {
    const categoryIds = new Set(discoveryCandidates.filter((candidate) => candidate.category === category && candidate.supported).map((candidate) => candidate.id));
    if (!categoryIds.size) return;
    setSelectedCandidateIds((current) => {
      const allSelected = Array.from(categoryIds).every((id) => current.includes(id));
      if (allSelected) {
        return current.filter((id) => !categoryIds.has(id));
      }
      return Array.from(new Set([...current, ...categoryIds]));
    });
  }

  function clearSelection() {
    setSelectedCandidateIds([]);
  }

  function indexSelectedArtifactTypes() {
    if (!selectedCandidateIds.length || selectedIndexingLocked) return;
    parseVelociraptorMutation.mutate({ selected_candidate_ids: selectedCandidateIds });
  }

  function toggleCategoryExpanded(category: string) {
    setExpandedCategories((current) => ({ ...current, [category]: !current[category] }));
  }

  function openReprocessDialog() {
    if (supportsGranularReprocess) {
      setReprocessMode("previous_selection");
    } else {
      setReprocessMode("previous_selection");
    }
    setReprocessIngestMode("usable_search");
    setReprocessProvidedHost(String(data?.provided_host ?? "").trim());
    setReprocessSelectionIds([]);
    setRediscoveryConfirmText("");
    setReprocessDialogOpen(true);
  }

  function confirmReprocess() {
    if (reprocessMode === "manual_selection" || reprocessMode === "choose_again") {
      if (!reprocessSelectionIds.length) {
        notify({ title: "Select artifacts first", description: "Choose at least one candidate before starting this reprocess.", tone: "warning" });
        return;
      }
    }
    if (reprocessMode === "full_rediscovery" && rediscoveryConfirmText.trim() !== "REDISCOVER") {
      notify({ title: "Confirmation required", description: "Type REDISCOVER before starting a full rediscovery.", tone: "warning" });
      return;
    }
    reprocessMutation.mutate({
      mode: reprocessMode,
      selectedCandidateIds: reprocessMode === "manual_selection" || reprocessMode === "choose_again" ? reprocessSelectionIds : undefined,
      explicitConfirm: reprocessMode === "full_rediscovery",
    });
  }

  function toggleReprocessCandidate(candidateId: string) {
    setReprocessSelectionIds((current) => (current.includes(candidateId) ? current.filter((item) => item !== candidateId) : [...current, candidateId]));
  }

  function toggleProblematicArtifact(artifactId: string) {
    setSelectedProblematicArtifactIds((current) => (current.includes(artifactId) ? current.filter((item) => item !== artifactId) : [...current, artifactId]));
  }

  function problematicSearchHref(artifact: ProblematicArtifact) {
    const query = `evidence_id:${evidenceId} artifact.type:${artifact.artifact_type || "evtx_raw"} source_file:"${artifact.source_path}"`;
    return data?.case_id ? `/cases/${data.case_id}/search?q=${encodeURIComponent(query)}` : "#";
  }

  function renderHealthCheckSummary(healthCheck: Record<string, unknown> | EvtxHealthCheckResult | null | undefined) {
    if (!healthCheck) return null;
    const diagnosis = typeof healthCheck.diagnosis === "string" ? healthCheck.diagnosis : "unknown_error";
    const recordsSeen = typeof healthCheck.records_seen === "number" ? healthCheck.records_seen : 0;
    const timedOut = healthCheck.timed_out === true;
    const likelyCorrupt = healthCheck.likely_corrupt === true;
    return (
      <div className="mt-2 rounded-2xl border border-line bg-panel/50 px-3 py-2 text-xs text-muted">
        <p className="font-mono text-[11px] uppercase tracking-[0.14em] text-ink">Latest health check</p>
        <p className="mt-1">Diagnosis: {diagnosis}</p>
        <p>Records seen: {recordsSeen}</p>
        {timedOut ? <p>Record iteration timed out during health check.</p> : null}
        {likelyCorrupt ? <p>The file likely looks corrupt or truncated.</p> : null}
      </div>
    );
  }

  async function handleRefresh() {
    notify({ title: "Refreshing evidence", description: "Fetching the latest ingest and manifest state.", tone: "info", durationMs: 2200 });
    await Promise.all([
      queryClient.invalidateQueries({ queryKey: ["evidence", evidenceId] }),
      queryClient.invalidateQueries({ queryKey: ["evidence-manifest", evidenceId] }),
    ]);
  }

  async function handleDownloadReport(reportId: string, format?: "json" | "markdown" | "html") {
    const { blob, filename } = await api.downloadReport(reportId, format);
    const url = URL.createObjectURL(blob);
    const anchor = document.createElement("a");
    anchor.href = url;
    anchor.download = filename;
    document.body.append(anchor);
    anchor.click();
    anchor.remove();
    URL.revokeObjectURL(url);
  }

function formatCategoryLabel(category: string) {
  return category.replaceAll("_", " ");
}

function formatRuleRunStatus(status: string | null | undefined) {
  const value = String(status || "").trim();
  if (!value) return "unknown";
  return value.replaceAll("_", " ");
}

function formatReportStatus(status: string | null | undefined) {
  return formatRuleRunStatus(status);
}

  function candidatePrimaryPath(candidate: VelociraptorCandidate) {
    return candidate.original_path || candidate.original_i_path || candidate.original_r_path || candidate.normalized_windows_path || "-";
  }

  function getNoParseableMessage(category: string, candidates: VelociraptorCandidate[]) {
    if (category === "evtx") {
      const anyNative = candidates.some((candidate) => candidate.parser_status === "parsed_native");
      if (anyNative) return "EVTX raw artifacts can be parsed natively.";
      if (candidates.length > 0) {
        return "EVTX raw files detected, but native EVTX parsing is not enabled. Upload EvtxECmd/Hayabusa/Chainsaw output or enable the native EVTX parser.";
      }
    }
    if (category === "lnk") {
      const anyNative = candidates.some((candidate) => candidate.parser_status === "parsed_native");
      if (anyNative) return "LNK raw artifacts can be parsed natively.";
    }
    if (category === "bits") {
      return "No directly parseable BITS artifacts found. Raw qmgr parsing is not implemented yet; BITS EVTX artifacts are handled by the EVTX parser.";
    }
    if (category === "network") {
      const onlyEvtxHandled = candidates.length > 0 && candidates.every((candidate) => candidate.parser_status === "handled_by_evtx_parser");
      if (onlyEvtxHandled) {
        return "No directly parseable network artifacts found. WLAN/Network EVTX artifacts are handled by the EVTX parser.";
      }
    }
    if (category === "network_activity") {
      const hasRawSrum = candidates.some((candidate) => candidate.artifact_type === "srum_database" || candidate.artifact_type === "srum_raw");
      const hasCheckpoint = candidates.some((candidate) => candidate.artifact_type === "srum_checkpoint");
      if (hasRawSrum || hasCheckpoint) {
        return "SRUM databases were detected. Use the scoped SRUM action to parse SRUDB.dat with SrumECmd without re-indexing EVTX or MFT.";
      }
    }
    return `No parseable ${formatCategoryLabel(category)} artifacts found`;
  }

  function candidateStatusLabel(candidate: VelociraptorCandidate) {
    if (!candidate.supported) return candidate.parser_status;
    if (candidate.parser_status === "partial") return "partial";
    if (candidate.parser_status) return candidate.parser_status;
    return "parseable";
  }

  const noRecordStatuses = new Set(["skipped_empty", "completed_no_records", "unsupported_no_records"]);
  const isNoRecordProblem = (artifact: ProblematicArtifact) => noRecordStatuses.has(String(artifact.effective_status ?? artifact.status ?? "").toLowerCase());
  const isFullyIndexedWarning = (artifact: ProblematicArtifact) => {
    const effectiveStatus = String(artifact.effective_status ?? artifact.status ?? "").toLowerCase();
    const recordsRead = artifact.effective_records_read ?? artifact.records_read ?? 0;
    const recordsIndexed = artifact.effective_records_indexed ?? artifact.records_indexed ?? 0;
    return recordsRead > 0 && recordsRead === recordsIndexed && ["parsed_with_warning", "accepted_warning", "health_check_only_valid", "source_missing_but_indexed"].includes(effectiveStatus);
  };
  const realFailureArtifacts = problematicArtifacts.filter((artifact) => {
    if (isNoRecordProblem(artifact) || isFullyIndexedWarning(artifact)) return false;
    return Boolean((artifact.current_data_loss_expected ?? artifact.data_loss_expected) || artifact.retryable || problematicImpact(artifact).group === "critical");
  });
  const realFailureCount = realFailureArtifacts.length;
  const skippedEmptyCount = informationalProblems.length || Number(problematicSummary?.skipped_empty ?? 0);
  const warningCount = warningProblems.length + Math.max(0, Number(problematicSummary?.indexed_with_warning ?? 0) - warningProblems.length);
  const minimalStatusLabel =
    activeIndexingJob
      ? "Processing"
      : realFailureCount > 0
        ? "Completed with errors"
        : indexingState === "completed_with_warnings" || warningCount > 0 || skippedEmptyCount > 0
          ? "Ready with warnings"
          : evidenceReadyForActions
            ? "Ready"
            : plannedNotStarted || waitingSelectionNeedsAction || indexingState === "not_started"
              ? "Not indexed"
              : formatEvidenceStatusForDisplay(displayStatus);
  const latestRetryRun = evidenceRuns.find((run) => run.run_type === "artifact_retry") ?? null;
  const retryRunData = (latestRetryRun ?? {}) as EvidenceRun & {
    artifact_ids?: string[];
    retry_of_artifact_ids?: string[];
    recovered_count?: number;
    still_failed_count?: number;
    skipped_count?: number;
    final_message?: string;
  };
  const retryRunItems = Array.isArray(latestRetryRun?.items) ? latestRetryRun.items : [];
  const retryArtifactsTotal = Number(
    retryRunData.artifacts_total ??
      retryRunData.retry_of_artifact_ids?.length ??
      retryRunData.artifact_ids?.length ??
      retryRunItems.length ??
      0,
  );
  const retryArtifactsDone = Number(retryRunData.artifacts_done ?? (["completed", "completed_with_errors", "failed"].includes(String(latestRetryRun?.status ?? "")) ? retryArtifactsTotal : 0));
  const retryProgressPct = retryArtifactsTotal > 0 ? Math.round((retryArtifactsDone / retryArtifactsTotal) * 100) : Number(latestRetryRun?.progress ?? 0);
  const retryActive = latestRetryRun ? ["queued", "running", "pending", "processing"].includes(String(latestRetryRun.status).toLowerCase()) : false;
  const latestRetryRecoveredCount = Number(retryRunData.recovered_count ?? 0);
  const latestRetryStillFailedCount = Number(retryRunData.still_failed_count ?? latestRetryRun?.artifacts_failed ?? 0);
  const latestRetrySkippedCount = Number(retryRunData.skipped_count ?? 0);
  const finalProcessingStatus = realFailureCount > 0 ? "Completed with parser errors" : minimalStatusLabel === "Ready with warnings" ? "Ready with warnings" : "Ready for investigation";
  const terminalProcessingResult = !activeIndexingJob && !retryActive;
  const terminalArtifactsDone = realFailureCount === 0 && displayCounts.artifactsTotal > 0 ? displayCounts.artifactsTotal : displayCounts.artifactsDone;
  const progressTitle = retryActive ? "Retrying failed artifacts" : activeIndexingJob ? "Processing" : "Processing result";
  const progressPercent = retryActive ? retryProgressPct : activeIndexingJob ? displayCounts.progressPct : realFailureCount === 0 ? 100 : displayCounts.progressPct;
  const progressArtifactsDone = retryActive ? retryArtifactsDone : terminalProcessingResult ? terminalArtifactsDone : displayCounts.artifactsDone;
  const progressArtifactsTotal = retryActive ? retryArtifactsTotal : displayCounts.artifactsTotal;
  const progressRecordsRead = retryActive ? Number(latestRetryRun?.records_read ?? 0) : activeIndexingJob ? Number(activeRun?.records_read ?? currentArtifactRecordsRead ?? tailRecordsRead ?? data?.metadata_json?.records_read ?? 0) : Number(latestRetryRun?.records_read ?? 0);
  const progressRecordsIndexed = retryActive ? Number(latestRetryRun?.records_indexed ?? latestRetryRun?.events_indexed ?? 0) : activeIndexingJob ? Number(activeRun?.records_indexed ?? currentArtifactRecordsIndexed ?? tailRecordsIndexed ?? displayCounts.indexedDocs ?? 0) : Number(latestRetryRun?.records_indexed ?? latestRetryRun?.events_indexed ?? 0);
  const progressCurrentArtifact = retryActive ? latestRetryRun?.current_artifact : currentDisplayArtifact;
  const minimalCategoryOptions = [
    { id: "evtx", label: "Event logs" },
    { id: "powershell", label: "PowerShell" },
    { id: "prefetch", label: "Prefetch" },
    { id: "shimcache", label: "Shimcache" },
    { id: "service", label: "Services" },
    { id: "scheduled_task", label: "Scheduled Tasks" },
    { id: "browser", label: "Browser" },
    { id: "defender", label: "Defender" },
    { id: "lnk", label: "LNK" },
    { id: "jumplist", label: "Jump Lists" },
    { id: "recycle_bin", label: "Recycle Bin" },
    { id: "usb", label: "USB" },
    { id: "amcache", label: "Amcache" },
  ].map((option) => {
    const supported = supportedCategoryOptions.find((entry) => entry.category === option.id);
    const selectedCount = supported?.supportedIds.filter((id) => selectedCandidateIds.includes(id)).length ?? 0;
    return { ...option, supported, selectedCount, disabled: !supported || selectedIndexingLocked };
  });
  const commandHistoryHref = data?.case_id ? `/cases/${data.case_id}/command-history?evidence_id=${encodeURIComponent(evidenceId)}` : "#";
  const findingsHref = data?.case_id ? `/cases/${data.case_id}/findings?evidence_id=${encodeURIComponent(evidenceId)}` : "#";
  const deleteConfirmationValid = deleteConfirmText.trim() === "DELETE";
  const minimalProcessingView = true;
  if (minimalProcessingView) {
    return (
      <div className="min-w-0 space-y-5">
        <section className="rounded-[28px] border border-line bg-panel/75 p-6 shadow-panel">
          <div className="flex flex-col gap-5 xl:flex-row xl:items-start xl:justify-between">
            <div className="min-w-0">
              <p className="font-mono text-xs uppercase tracking-[0.24em] text-accent">Evidence</p>
              <h2 className="mt-2 break-words text-3xl font-semibold">{data?.original_filename}</h2>
              <div className="mt-3 flex flex-wrap items-center gap-2 text-sm text-muted">
                <span className={`rounded-full border px-3 py-1 font-mono text-[11px] uppercase tracking-[0.16em] ${minimalStatusLabel === "Ready" ? "border-mint/30 bg-mint/10 text-mint" : minimalStatusLabel === "Completed with errors" ? "border-danger/30 bg-danger/10 text-danger" : minimalStatusLabel === "Ready with warnings" ? "border-amber/30 bg-amber/10 text-amber" : "border-accent/30 bg-accent/10 text-accent"}`}>{minimalStatusLabel}</span>
                <span>Host: <span className="text-ink">{data?.provided_host || data?.detected_host || "-"}</span></span>
              </div>
            </div>
            <div className="flex flex-wrap gap-2">
              <button type="button" onClick={() => void handleRefresh()} disabled={evidenceQuery.isFetching || manifestQuery.isFetching} className="rounded-2xl border border-line bg-abyss/80 px-4 py-2 text-sm text-muted disabled:opacity-50">
                {evidenceQuery.isFetching || manifestQuery.isFetching ? "Refreshing..." : "Refresh"}
              </button>
              <button type="button" onClick={() => reprocessMutation.mutate({ mode: "previous_selection" })} disabled={activeIndexingJob || reprocessMutation.isPending || !lastSuccessfulIngestPlan} className="rounded-2xl border border-line bg-abyss/80 px-4 py-2 text-sm text-muted disabled:opacity-50">
                {reprocessMutation.isPending ? "Queueing..." : "Re-index evidence"}
              </button>
              <button type="button" onClick={() => setDeleteDialogOpen(true)} className="rounded-2xl border border-danger/40 bg-danger/10 px-4 py-2 text-sm text-danger">
                Delete evidence
              </button>
              {data?.case_id ? <Link to={`/cases/${data.case_id}`} className="rounded-2xl border border-line bg-abyss/80 px-4 py-2 text-sm text-muted">Back to case</Link> : null}
            </div>
          </div>

          {(activeIndexingJob || retryActive) ? (
            <div className="mt-5 rounded-3xl border border-accent/30 bg-accent/10 p-5">
              <div className="flex flex-col gap-4 md:flex-row md:items-center md:justify-between">
                <div>
                  <p className="font-mono text-[11px] uppercase tracking-[0.18em] text-accent">{progressTitle}</p>
                  <h3 className="mt-1 text-2xl font-semibold text-ink">{progressPercent}%</h3>
                  <p className="mt-1 text-sm text-muted">{retryActive ? "Retrying failed artifacts" : formatIndexingPhaseForDisplay(displayCounts.phase)}</p>
                </div>
                <div className="h-3 min-w-[220px] flex-1 overflow-hidden rounded-full bg-abyss/80">
                  <div className="h-full rounded-full bg-accent transition-all duration-500" style={{ width: `${Math.max(0, Math.min(100, progressPercent))}%` }} />
                </div>
              </div>
            </div>
          ) : null}

          <div className="mt-5 grid gap-3 md:grid-cols-2 xl:grid-cols-6">
            <div className="rounded-2xl border border-line bg-abyss/70 px-4 py-3"><p className="font-mono text-[11px] uppercase tracking-[0.16em] text-muted">Indexed documents</p><p className="mt-1 text-lg font-semibold text-ink">{indexedDocumentsTotal.toLocaleString()}</p></div>
            <div className="rounded-2xl border border-line bg-abyss/70 px-4 py-3"><p className="font-mono text-[11px] uppercase tracking-[0.16em] text-muted">Artifact types</p><p className="mt-1 text-lg font-semibold text-ink">{artifactTypeCount}</p></div>
            <div className="rounded-2xl border border-line bg-abyss/70 px-4 py-3"><p className="font-mono text-[11px] uppercase tracking-[0.16em] text-muted">Real failures</p><p className={`mt-1 text-lg font-semibold ${realFailureCount ? "text-danger" : "text-mint"}`}>{realFailureCount}</p></div>
            <div className="rounded-2xl border border-line bg-abyss/70 px-4 py-3"><p className="font-mono text-[11px] uppercase tracking-[0.16em] text-muted">Warnings</p><p className="mt-1 text-lg font-semibold text-amber">{warningCount}</p></div>
            <div className="rounded-2xl border border-line bg-abyss/70 px-4 py-3"><p className="font-mono text-[11px] uppercase tracking-[0.16em] text-muted">Skipped empty</p><p className="mt-1 text-lg font-semibold text-muted">{skippedEmptyCount}</p></div>
            <div className="rounded-2xl border border-line bg-abyss/70 px-4 py-3"><p className="font-mono text-[11px] uppercase tracking-[0.16em] text-muted">Completed</p><p className="mt-1 text-sm font-semibold text-ink">{formatDateTime(completedAt)}</p></div>
          </div>
        </section>

        <section className="rounded-[28px] border border-line bg-panel/70 p-6 shadow-panel">
          <p className="font-mono text-xs uppercase tracking-[0.24em] text-accent">Choose what to parse</p>
          <div className="mt-4 grid gap-4 xl:grid-cols-[minmax(0,0.8fr)_minmax(0,1.2fr)]">
            <div className="rounded-3xl border border-accent/30 bg-accent/10 p-5">
              <h3 className="text-lg font-semibold text-ink">Recommended indexing</h3>
              <p className="mt-1 text-sm text-muted">Parse all supported artifact types. Recommended for most investigations.</p>
              <button type="button" onClick={() => runIndexingPlanMutation.mutate()} disabled={primaryIndexingDisabled} className="mt-4 rounded-2xl bg-accent px-5 py-3 text-sm font-semibold text-abyss disabled:cursor-not-allowed disabled:opacity-60">
                {runIndexingPlanMutation.isPending ? "Queueing..." : evidenceReadyForActions ? "Run recommended indexing again" : "Start recommended indexing"}
              </button>
            </div>
            <div className="rounded-3xl border border-line bg-abyss/60 p-5">
              <div className="flex flex-col gap-2 md:flex-row md:items-start md:justify-between">
                <div>
                  <h3 className="text-lg font-semibold text-ink">Selected artifact types</h3>
                  <p className="mt-1 text-sm text-muted">Choose focused families when you do not want to parse everything.</p>
                </div>
                <button type="button" onClick={indexSelectedArtifactTypes} disabled={!selectedCandidateIds.length || selectedIndexingLocked || parseVelociraptorMutation.isPending} className="rounded-2xl border border-accent/40 bg-accent/10 px-4 py-2 text-sm font-semibold text-accent disabled:opacity-50">
                  {parseVelociraptorMutation.isPending ? "Queueing..." : "Start selected parsing"}
                </button>
              </div>
              <div className="mt-4 grid gap-2 md:grid-cols-2 xl:grid-cols-3">
                {minimalCategoryOptions.map((option) => (
                  <label key={option.id} className={`flex min-h-[70px] items-start gap-3 rounded-2xl border px-3 py-3 ${option.selectedCount ? "border-accent/40 bg-accent/10" : "border-line bg-panel/40"} ${option.disabled ? "opacity-50" : "cursor-pointer"}`}>
                    <input type="checkbox" className="mt-1" disabled={option.disabled} checked={Boolean(option.supported && option.selectedCount === option.supported.supportedIds.length)} onChange={() => toggleCategorySelection(option.id)} />
                    <span>
                      <span className="block text-sm font-semibold text-ink">{option.label}</span>
                      <span className="mt-1 block text-xs text-muted">{option.supported ? `${option.supported.supportedIds.length} candidates` : "Not detected"}</span>
                    </span>
                  </label>
                ))}
              </div>
              <details className="mt-4 rounded-2xl border border-line bg-panel/40 p-3">
                <summary className="cursor-pointer text-sm font-semibold text-muted">Advanced custom</summary>
                <div className="mt-3 flex flex-wrap gap-2">
                  <button type="button" onClick={selectAllSupported} disabled={!selectedIndexingAvailable || selectedIndexingLocked} className="rounded-xl border border-line bg-abyss/70 px-3 py-2 text-xs text-muted disabled:opacity-50">Select all supported</button>
                  <button type="button" onClick={clearSelection} disabled={!selectedIndexingAvailable || selectedIndexingLocked} className="rounded-xl border border-line bg-abyss/70 px-3 py-2 text-xs text-muted disabled:opacity-50">Clear selection</button>
                  <button type="button" onClick={selectExecutionArtifacts} disabled={selectedIndexingLocked} className="rounded-xl border border-line bg-abyss/70 px-3 py-2 text-xs text-muted disabled:opacity-50">Execution artifacts</button>
                  <button type="button" onClick={selectPersistenceArtifacts} disabled={selectedIndexingLocked} className="rounded-xl border border-line bg-abyss/70 px-3 py-2 text-xs text-muted disabled:opacity-50">Persistence artifacts</button>
                </div>
              </details>
            </div>
          </div>
        </section>

        <section id="indexing-progress" data-testid="evidence-progress-primary" className="rounded-[28px] border border-line bg-panel/70 p-6 shadow-panel">
          <div className="flex flex-col gap-4 xl:flex-row xl:items-start xl:justify-between">
            <div>
              <p className="font-mono text-xs uppercase tracking-[0.24em] text-accent">{terminalProcessingResult ? "Processing result" : "Processing progress"}</p>
              <h3 className="mt-2 text-2xl font-semibold text-ink">{progressTitle}</h3>
              {terminalProcessingResult ? (
                <p className="mt-1 text-sm text-muted">
                  {finalProcessingStatus}
                  {latestRetryRun && latestRetryRecoveredCount > 0 ? ` · ${latestRetryRecoveredCount} failed artifact${latestRetryRecoveredCount === 1 ? " was" : "s were"} recovered by retry.` : ""}
                  {realFailureCount === 0 && retryCandidateIds.length === 0 ? " No retryable failures remain." : ""}
                </p>
              ) : (
                <>
                  <p className="mt-1 text-sm text-muted">Current step: {retryActive ? String(latestRetryRun?.status ?? "retry") : formatIndexingPhaseForDisplay(displayCounts.phase)}</p>
                  {progressCurrentArtifact ? <p className="mt-1 max-w-3xl truncate text-sm text-muted" title={progressCurrentArtifact}>Current artifact: {progressCurrentArtifact}</p> : null}
                </>
              )}
            </div>
            {!terminalProcessingResult ? (
              <div className="rounded-3xl border border-accent/30 bg-accent/10 px-6 py-4 text-right">
                <p className="font-mono text-[11px] uppercase tracking-[0.16em] text-accent">Progress</p>
                <p className="mt-1 text-4xl font-semibold text-ink">{progressPercent}%</p>
              </div>
            ) : null}
          </div>
          <div className="mt-5 grid gap-3 md:grid-cols-3 xl:grid-cols-7">
            <div className="rounded-2xl border border-line bg-abyss/60 px-3 py-2"><p className="font-mono text-[11px] uppercase tracking-[0.16em] text-muted">Artifacts</p><p className="mt-1 text-sm text-ink">{progressArtifactsDone} / {progressArtifactsTotal}</p></div>
            {!terminalProcessingResult || latestRetryRun ? <div className="rounded-2xl border border-line bg-abyss/60 px-3 py-2"><p className="font-mono text-[11px] uppercase tracking-[0.16em] text-muted">{retryActive || terminalProcessingResult ? "Retry records read" : "Records read"}</p><p className="mt-1 text-sm text-ink">{progressRecordsRead.toLocaleString()}</p></div> : null}
            {!terminalProcessingResult || latestRetryRun ? <div className="rounded-2xl border border-line bg-abyss/60 px-3 py-2"><p className="font-mono text-[11px] uppercase tracking-[0.16em] text-muted">{retryActive || terminalProcessingResult ? "Retry records indexed" : "Records indexed"}</p><p className="mt-1 text-sm text-ink">{progressRecordsIndexed.toLocaleString()}</p></div> : null}
            <div className="rounded-2xl border border-line bg-abyss/60 px-3 py-2"><p className="font-mono text-[11px] uppercase tracking-[0.16em] text-muted">Indexed docs</p><p className="mt-1 text-sm text-ink">{displayCounts.indexedDocs.toLocaleString()}</p></div>
            <div className="rounded-2xl border border-line bg-abyss/60 px-3 py-2"><p className="font-mono text-[11px] uppercase tracking-[0.16em] text-muted">Elapsed</p><p className="mt-1 text-sm text-ink">{formatDuration(retryActive ? latestRetryRun?.elapsed_seconds : displayedElapsedSeconds)}</p></div>
            {!terminalProcessingResult ? <div className="rounded-2xl border border-line bg-abyss/60 px-3 py-2"><p className="font-mono text-[11px] uppercase tracking-[0.16em] text-muted">Heartbeat</p><p className="mt-1 text-sm text-ink">{retryActive ? formatHeartbeatAge(latestRetryRun?.heartbeat_at ?? null) : lastProgressAgeLabel}</p></div> : null}
            <div className="rounded-2xl border border-line bg-abyss/60 px-3 py-2"><p className="font-mono text-[11px] uppercase tracking-[0.16em] text-muted">{terminalProcessingResult ? "Last run" : "Run ID"}</p><p className="mt-1 truncate text-sm text-ink" title={retryActive ? latestRetryRun?.run_id : latestRun?.run_id}>{retryActive ? latestRetryRun?.run_id ?? "-" : latestRetryRun?.run_id ?? latestRun?.run_id ?? "-"}</p></div>
            {terminalProcessingResult ? <div className="rounded-2xl border border-line bg-abyss/60 px-3 py-2"><p className="font-mono text-[11px] uppercase tracking-[0.16em] text-muted">Recovered by retry</p><p className="mt-1 text-sm text-mint">{latestRetryRecoveredCount}</p></div> : null}
          </div>
          {latestRetryRun ? (
            <div className="mt-4 rounded-2xl border border-line bg-abyss/60 px-4 py-3 text-sm text-muted">
              <p className="font-semibold text-ink">{retryActive ? "Retry in progress" : latestRetryRecoveredCount > 0 && latestRetryStillFailedCount === 0 ? "Retry completed successfully" : "Latest retry outcome"}</p>
              <p className="mt-1">
                Recovered {latestRetryRecoveredCount} · Still failing {latestRetryStillFailedCount} · Skipped {latestRetrySkippedCount}
              </p>
              {retryRunData.final_message ? <p className="mt-1 text-muted">{retryRunData.final_message}</p> : latestRetryRecoveredCount === 0 && latestRetryStillFailedCount === 0 ? <p className="mt-1 text-muted">No retryable failures remain.</p> : null}
            </div>
          ) : null}
        </section>

        <section id="problematic-artifacts" className="rounded-[28px] border border-line bg-panel/70 p-6 shadow-panel">
          <div className="flex flex-col gap-3 xl:flex-row xl:items-start xl:justify-between">
            <div>
              <p className="font-mono text-xs uppercase tracking-[0.24em] text-accent">Real failures / retry</p>
              <h3 className="mt-2 text-2xl font-semibold text-ink">{realFailureCount ? `${realFailureCount} parser failure${realFailureCount === 1 ? "" : "s"} need attention` : "No real parser failures"}</h3>
              {skippedEmptyCount ? <p className="mt-1 text-sm text-muted">{skippedEmptyCount} empty/no-record logs skipped. These are informational and hidden from the main failures list.</p> : null}
            </div>
            {retryCandidateIds.length ? (
              <button type="button" onClick={() => retryProblematicArtifactsMutation.mutate({ artifactIds: retryCandidateIds, mode: "higher_timeout" })} disabled={activeIndexingJob || retryProblematicArtifactsMutation.isPending} className="rounded-2xl bg-accent px-5 py-3 text-sm font-semibold text-abyss disabled:opacity-50">
                {retryProblematicArtifactsMutation.isPending ? `Retrying ${retryCandidateIds.length} failed artifacts` : "Retry failed artifacts"}
              </button>
            ) : null}
          </div>
          {realFailureArtifacts.length ? (
            <div className="mt-5 overflow-x-auto rounded-3xl border border-line">
              <table className="min-w-full divide-y divide-line text-sm">
                <thead className="bg-abyss/70">
                  <tr className="text-left text-xs uppercase tracking-[0.16em] text-muted">
                    <th className="px-3 py-3">Artifact</th>
                    <th className="px-3 py-3">Type</th>
                    <th className="px-3 py-3">Reason</th>
                    <th className="px-3 py-3">Data loss</th>
                    <th className="px-3 py-3">Retryable</th>
                    <th className="px-3 py-3">Last attempt</th>
                    <th className="px-3 py-3">Actions</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-line">
                  {realFailureArtifacts.map((artifact, index) => (
                    <tr key={`${artifact.artifact_id ?? `${artifact.source_path}:${artifact.parser}`}:${index}`} className="bg-panel/40">
                      <td className="px-3 py-3 align-top"><p className="font-semibold text-ink">{artifact.name}</p><p className="mt-1 max-w-[420px] break-all text-xs text-muted">{artifact.source_path}</p></td>
                      <td className="px-3 py-3 align-top text-muted">{artifact.artifact_type || artifact.parser || "-"}</td>
                      <td className="px-3 py-3 align-top text-muted">{artifact.error_message || artifact.health_summary || formatProblematicStatusLabel(artifact.effective_status ?? artifact.status)}</td>
                      <td className="px-3 py-3 align-top text-muted">{artifact.current_data_loss_expected ?? artifact.data_loss_expected ? "Yes" : "No"}</td>
                      <td className="px-3 py-3 align-top text-muted">{artifact.retryable ? "Yes" : "No"}</td>
                      <td className="px-3 py-3 align-top text-muted">{artifact.latest_retry?.finished_at ? formatDateTime(String(artifact.latest_retry.finished_at)) : artifact.latest_retry?.status ? String(artifact.latest_retry.status) : "-"}</td>
                      <td className="px-3 py-3 align-top">
                        <div className="flex flex-wrap gap-2">
                          {artifact.retryable && artifact.artifact_id ? <button type="button" onClick={() => retryProblematicArtifactsMutation.mutate({ singleArtifactId: artifact.artifact_id!, mode: "higher_timeout" })} disabled={activeIndexingJob || retryProblematicArtifactsMutation.isPending} className="rounded-full border border-accent/40 bg-accent/10 px-3 py-1 text-xs text-accent disabled:opacity-50">Retry</button> : null}
                          <details className="rounded-full border border-line bg-abyss/80 px-3 py-1 text-xs text-muted">
                            <summary className="cursor-pointer">View logs/details</summary>
                            <pre className="mt-3 max-w-xl whitespace-pre-wrap rounded-2xl border border-line bg-panel/80 p-3 text-left text-[11px] text-muted">{JSON.stringify({ status: artifact.status, effective_status: artifact.effective_status, error_type: artifact.error_type, error_message: artifact.error_message, health_summary: artifact.health_summary, retry_history: artifact.retry_history }, null, 2)}</pre>
                          </details>
                        </div>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          ) : (
            <p className="mt-4 rounded-2xl border border-mint/25 bg-mint/10 px-4 py-3 text-sm text-mint">No real parser failures.</p>
          )}
          <details className="mt-4 rounded-2xl border border-line bg-abyss/60 p-4">
            <summary className="cursor-pointer text-sm font-semibold text-muted">Warnings and informational skipped items</summary>
            <div className="mt-3 grid gap-3 md:grid-cols-2">
              <div className="rounded-2xl border border-amber/30 bg-amber/10 p-3"><p className="font-semibold text-amber">Warnings</p><p className="mt-1 text-sm text-muted">{warningCount} warnings, including fully indexed artifacts with non-critical parser warnings.</p></div>
              <div className="rounded-2xl border border-mint/25 bg-mint/10 p-3"><p className="font-semibold text-mint">Informational skipped</p><p className="mt-1 text-sm text-muted">{skippedEmptyCount} empty/no-record artifacts skipped.</p></div>
            </div>
          </details>
        </section>

        {evidenceReadyForActions ? (
          <section className="rounded-[28px] border border-line bg-panel/70 p-6 shadow-panel">
            <p className="font-mono text-xs uppercase tracking-[0.24em] text-accent">Investigation actions</p>
            <div className="mt-4 flex flex-wrap gap-3">
              <Link to={coreSearchHref} className="rounded-2xl border border-line bg-abyss/70 px-4 py-3 text-sm font-semibold text-ink">Search</Link>
              <Link to={commandHistoryHref} className="rounded-2xl border border-line bg-abyss/70 px-4 py-3 text-sm font-semibold text-ink">Command History</Link>
              <Link to={artifactViewsHref} className="rounded-2xl border border-line bg-abyss/70 px-4 py-3 text-sm font-semibold text-ink">Artifact Views</Link>
              <Link to={timelineHref} className="rounded-2xl border border-line bg-abyss/70 px-4 py-3 text-sm font-semibold text-ink">Timeline</Link>
              <Link to={findingsHref} className="rounded-2xl border border-line bg-abyss/70 px-4 py-3 text-sm font-semibold text-ink">Findings</Link>
              <Link to={reportsHref} className="rounded-2xl border border-line bg-abyss/70 px-4 py-3 text-sm font-semibold text-ink">Report</Link>
            </div>
          </section>
        ) : null}

        <details className="rounded-[28px] border border-line bg-panel/50 p-5">
          <summary className="cursor-pointer font-mono text-xs uppercase tracking-[0.18em] text-muted">Advanced diagnostics</summary>
          <div className="mt-4 grid gap-4 xl:grid-cols-2">
            <div className="rounded-2xl border border-line bg-abyss/60 p-4">
              <p className="font-semibold text-ink">Ingest & reprocess runs</p>
              <div className="mt-3 space-y-2">
                {evidenceRuns.slice(0, 6).map((run) => (
                  <div key={run.run_id} className="rounded-xl border border-line bg-panel/40 px-3 py-2 text-xs text-muted">
                    <p className="font-semibold text-ink">{run.run_type} · {run.status}</p>
                    <p>Artifacts {run.artifacts_done ?? 0}/{run.artifacts_total ?? 0} · records {run.records_read ?? 0}/{run.records_indexed ?? run.events_indexed ?? 0}</p>
                    {run.current_artifact ? <p className="truncate" title={run.current_artifact}>{run.current_artifact}</p> : null}
                  </div>
                ))}
              </div>
            </div>
            <div className="rounded-2xl border border-line bg-abyss/60 p-4">
              <p className="font-semibold text-ink">Raw discovery inventory</p>
              <p className="mt-1 text-sm text-muted">Hidden from the main flow. Discovery found {discoveryCandidates.length} candidates across {supportedCategoryOptions.length} supported categories.</p>
              <div className="mt-3 max-h-80 overflow-auto rounded-xl border border-line bg-panel/40 p-3 text-xs text-muted">
                {supportedCategoryOptions.map((option) => <p key={option.category}>{option.label}: {option.supportedIds.length} supported</p>)}
              </div>
            </div>
          </div>
        </details>

        {deleteDialogOpen ? (
          <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/70 p-4">
            <div className="w-full max-w-xl rounded-[28px] border border-danger/40 bg-panel p-6 shadow-panel">
              <p className="font-mono text-xs uppercase tracking-[0.24em] text-danger">Delete evidence</p>
              <h3 className="mt-2 text-2xl font-semibold text-ink">{data?.original_filename}</h3>
              <p className="mt-3 text-sm text-muted">
                This removes the evidence record, parsed artifacts and indexed documents for this evidence. Original uploaded archive removal depends on storage policy.
              </p>
              <div className="mt-4 grid gap-2 text-sm text-muted">
                <p>Host: <span className="text-ink">{data?.provided_host || data?.detected_host || "-"}</span></p>
                <p>Indexed docs: <span className="text-ink">{indexedDocumentsTotal.toLocaleString()}</span></p>
              </div>
              <label className="mt-5 block text-sm text-muted">
                Type DELETE to confirm.
                <input value={deleteConfirmText} onChange={(event) => setDeleteConfirmText(event.target.value)} className="mt-2 w-full rounded-2xl border border-line bg-abyss px-4 py-3 font-mono text-sm text-ink outline-none focus:border-danger" />
              </label>
              <div className="mt-5 flex flex-wrap justify-end gap-2">
                <button type="button" onClick={() => { setDeleteDialogOpen(false); setDeleteConfirmText(""); }} className="rounded-2xl border border-line bg-abyss/80 px-4 py-2 text-sm text-muted">Cancel</button>
                <button type="button" onClick={() => deleteMutation.mutate()} disabled={!deleteConfirmationValid || deleteMutation.isPending} className="rounded-2xl bg-danger px-4 py-2 text-sm font-semibold text-white disabled:opacity-50">
                  {deleteMutation.isPending ? "Deleting..." : "Delete evidence"}
                </button>
              </div>
            </div>
          </div>
        ) : null}
      </div>
    );
  }

  return (
    <div className="min-w-0 space-y-6">
      <section className="rounded-[28px] border border-line bg-panel/70 p-6 shadow-panel">
        <div className="flex flex-col gap-5 xl:flex-row xl:items-start xl:justify-between">
          <div className="min-w-0">
            <p className="font-mono text-xs uppercase tracking-[0.24em] text-accent">Evidence summary</p>
            <h2 className="mt-2 break-words text-3xl font-semibold">{data?.original_filename}</h2>
            <div className="mt-4 flex flex-wrap items-center gap-3">
              <span className={`rounded-full border px-3 py-1 font-mono text-[11px] uppercase tracking-[0.16em] ${indexingState === "completed" ? "border-mint/30 bg-mint/10 text-mint" : indexingState === "completed_with_warnings" || indexingState === "completed_with_errors" ? "border-amber/30 bg-amber/10 text-amber" : indexingState === "failed" ? "border-danger/30 bg-danger/10 text-danger" : "border-accent/30 bg-accent/10 text-accent"}`}>{formatEvidenceStatusForDisplay(displayStatus)}</span>
              <span className="rounded-full border border-line bg-abyss/60 px-3 py-1 font-mono text-[11px] uppercase tracking-[0.16em] text-muted">{productModeLabel}</span>
              <span className="font-mono text-xs text-muted">{activeIndexingJob ? "Auto-refresh every 3s" : "Stable state"}</span>
            </div>
          </div>
          <div className="flex flex-wrap gap-2">
            <button onClick={() => void handleRefresh()} disabled={evidenceQuery.isFetching || manifestQuery.isFetching} className="rounded-full border border-line bg-abyss/80 px-3 py-1 font-mono text-[11px] uppercase tracking-[0.16em] text-muted disabled:opacity-50">
              {evidenceQuery.isFetching || manifestQuery.isFetching ? "Refreshing..." : "Refresh"}
            </button>
            <button onClick={openReprocessDialog} disabled={reprocessMutation.isPending} className="rounded-full border border-line bg-abyss/80 px-3 py-1 font-mono text-[11px] uppercase tracking-[0.16em] text-muted disabled:opacity-50">
              {reprocessMutation.isPending ? "Re-indexing..." : "Re-index evidence"}
            </button>
            {data?.case_id ? <Link to={`/cases/${data.case_id}`} className="rounded-full border border-line bg-abyss/80 px-3 py-1 font-mono text-[11px] uppercase tracking-[0.16em] text-muted">Back to case</Link> : null}
          </div>
        </div>

        <div className="mt-5 grid gap-3 md:grid-cols-2 xl:grid-cols-6">
          <div className="rounded-2xl border border-line bg-abyss/70 px-4 py-3">
            <p className="font-mono text-[11px] uppercase tracking-[0.16em] text-muted">Host</p>
            <p className="mt-1 truncate text-sm font-semibold text-ink" title={data?.provided_host || data?.detected_host || "-"}>{data?.provided_host || data?.detected_host || "-"}</p>
          </div>
          <div className="rounded-2xl border border-line bg-abyss/70 px-4 py-3">
            <p className="font-mono text-[11px] uppercase tracking-[0.16em] text-muted">{activeIndexingJob ? "Status" : "Completed"}</p>
            <p className="mt-1 text-sm font-semibold text-ink">{activeIndexingJob ? "Indexing" : formatDateTime(completedAt)}</p>
          </div>
          <div className="rounded-2xl border border-line bg-abyss/70 px-4 py-3">
            <p className="font-mono text-[11px] uppercase tracking-[0.16em] text-muted">{activeIndexingJob ? "Indexed this run" : "Indexed documents"}</p>
            <p className="mt-1 text-lg font-semibold text-ink">{displayCounts.indexedDocs.toLocaleString()}</p>
          </div>
          <div className="rounded-2xl border border-line bg-abyss/70 px-4 py-3">
            <p className="font-mono text-[11px] uppercase tracking-[0.16em] text-muted">{activeIndexingJob ? "Artifacts" : "Artifact types"}</p>
            <p className="mt-1 text-lg font-semibold text-ink">{activeIndexingJob ? `${displayCounts.artifactsDone} / ${displayCounts.artifactsTotal}` : artifactTypeCount}</p>
          </div>
          <div className="rounded-2xl border border-line bg-abyss/70 px-4 py-3">
            <p className="font-mono text-[11px] uppercase tracking-[0.16em] text-muted">{activeIndexingJob ? "Problems" : "Problems/deferred"}</p>
            <p className={`mt-1 ${activeIndexingJob ? "text-sm" : "text-lg"} font-semibold ${activeIndexingJob || problemsCount ? "text-amber" : "text-mint"}`}>
              {activeIndexingJob ? "Pending review" : problemsCount}
            </p>
          </div>
          <div className="rounded-2xl border border-line bg-abyss/70 px-4 py-3">
            <p className="font-mono text-[11px] uppercase tracking-[0.16em] text-muted">EVTX</p>
            <p className={`mt-1 text-sm font-semibold ${evtxCoverageIsFull ? "text-mint" : evtxDeferredCount || evtxPartialCount ? "text-amber" : "text-ink"}`}>{evtxCoverageLabel}</p>
          </div>
        </div>

        <div className="mt-5 rounded-3xl border border-accent/30 bg-accent/10 p-4" data-testid="indexing-profile-card">
          <div className="flex flex-col gap-4 xl:flex-row xl:items-start xl:justify-between">
            <div className="min-w-0">
              <p className="font-mono text-[11px] uppercase tracking-[0.18em] text-accent">Investigation indexing</p>
              <h3 className="mt-1 text-xl font-semibold text-ink">{indexingStateTitle}</h3>
              <p className="mt-1 max-w-4xl text-sm text-muted">
                {indexingStateSubcopy}
              </p>
              {activeIndexingJob ? (
                <>
                  {activeRecommendedIndexing ? <p className="mt-2 text-sm font-semibold text-amber">Recommended indexing is running</p> : null}
                  {activeRunCategoryNames.length ? (
                    <p className="mt-1 text-sm text-muted">Categories in this run: <span className="font-semibold text-ink">{activeRunCategoryNames.join(", ")}</span></p>
                  ) : null}
                  <p className="mt-2 text-sm text-amber">Active step: {formatIndexingPhaseForDisplay(displayCounts.phase)}</p>
                </>
              ) : waitingSelectionNeedsAction ? (
                <p className="mt-2 text-sm text-amber">{rawDiscoveryCandidateCountForState} discovered artifacts · {indexingPlan?.supported_candidate_count ?? 0} supported for recommended indexing</p>
              ) : staleIndexingState ? (
                <p className="mt-2 text-sm text-amber">No active worker run is visible for this evidence state.</p>
              ) : plannedNotStarted ? (
                <p className="mt-2 text-sm text-amber">Indexing plan prepared · {indexingPlan?.supported_candidate_count ?? 0} supported artifacts detected</p>
              ) : null}
              {!evidenceReadyForActions ? <div className="mt-3 flex flex-wrap gap-2" role="group" aria-label="Indexing profiles">
                {(["recommended", "fast", "advanced_custom"] as const).map((profile) => (
                  <button
                    key={profile}
                    type="button"
                    onClick={() => setIndexingProfile(profile)}
                    disabled={conflictingIndexingActionsDisabled}
                    className={`rounded-full border px-3 py-1 text-xs font-semibold ${indexingProfile === profile ? "border-accent bg-accent text-abyss" : "border-line bg-abyss/70 text-muted"}`}
                  >
                    {profile === "recommended" ? "Recommended" : profile === "fast" ? "Fast indexing" : "Advanced custom"}
                  </button>
                ))}
              </div> : null}
            </div>
            <div className="flex flex-wrap gap-2">
              {activeIndexingJob ? (
                <>
                  <a href="#indexing-progress" className="rounded-2xl bg-accent px-4 py-2 text-sm font-semibold text-abyss">View progress</a>
                  <a href="#jobs-activity" className="rounded-2xl border border-line bg-panel/60 px-4 py-2 text-sm text-muted">Open Jobs & Activity</a>
                </>
              ) : waitingSelectionNeedsAction ? (
                <>
                  <button
                    type="button"
                    onClick={() => runIndexingPlanMutation.mutate()}
                    disabled={primaryIndexingDisabled}
                    className="rounded-2xl bg-accent px-5 py-3 text-sm font-semibold text-abyss disabled:cursor-not-allowed disabled:opacity-60"
                  >
                    {runIndexingPlanMutation.isPending ? "Queueing plan..." : "Continue with recommended indexing"}
                  </button>
                  <button type="button" onClick={scrollToParseSelection} className="rounded-2xl border border-line bg-panel/60 px-4 py-2 text-sm text-muted">
                    Choose categories
                  </button>
                  <button type="button" onClick={() => cancelIndexingMutation.mutate()} disabled={cancelIndexingMutation.isPending} className="rounded-2xl border border-danger/40 bg-danger/10 px-4 py-2 text-sm text-danger disabled:opacity-60">
                    {cancelIndexingMutation.isPending ? "Cancelling..." : "Cancel indexing"}
                  </button>
                </>
              ) : staleIndexingState ? (
                <>
                  <button type="button" onClick={() => cancelIndexingMutation.mutate()} disabled={cancelIndexingMutation.isPending} className="rounded-2xl bg-accent px-5 py-3 text-sm font-semibold text-abyss disabled:opacity-60">
                    {cancelIndexingMutation.isPending ? "Clearing..." : "Mark stale and retry"}
                  </button>
                  <a href="#jobs-activity" className="rounded-2xl border border-line bg-panel/60 px-4 py-2 text-sm text-muted">Open logs</a>
                </>
              ) : evidenceReadyForActions ? (
                <>
                  <Link to={coreSearchHref} className="rounded-2xl bg-accent px-4 py-2 text-sm font-semibold text-abyss">Search this evidence</Link>
                  <Link to={artifactViewsHref} className="rounded-2xl border border-line bg-panel/60 px-4 py-2 text-sm text-muted">View artifacts</Link>
                </>
              ) : (
                <>
                  <button
                    type="button"
                    onClick={() => runIndexingPlanMutation.mutate()}
                    disabled={primaryIndexingDisabled}
                    className="rounded-2xl bg-accent px-5 py-3 text-sm font-semibold text-abyss disabled:cursor-not-allowed disabled:opacity-60"
                  >
                    {runIndexingPlanMutation.isPending ? "Queueing plan..." : plannedNotStarted ? "Start recommended indexing" : "Index evidence for investigation"}
                  </button>
                  <button type="button" onClick={scrollToParseSelection} disabled={conflictingIndexingActionsDisabled} className="rounded-2xl border border-line bg-panel/60 px-4 py-2 text-sm text-muted disabled:opacity-60">
                    Index selected types
                  </button>
                </>
              )}
            </div>
          </div>

          {indexingPlanQuery.isLoading ? (
            <p className="mt-4 text-sm text-muted">Loading indexing plan...</p>
          ) : indexingPlan ? (
            <div className="mt-4 grid gap-4 xl:grid-cols-[minmax(0,1fr)_minmax(280px,0.45fr)]">
              <div className="rounded-2xl border border-line bg-panel/60 p-4">
                <div className="flex items-center justify-between gap-3">
                  <div>
                    <p className="text-sm font-semibold text-ink">{indexingPlan.label}</p>
                    <p className="mt-1 text-xs text-muted">{indexingPlan.subcopy}</p>
                  </div>
                  {indexingPlan.active ? (
                    <span className="rounded-full border border-amber/30 bg-amber/10 px-3 py-1 text-xs text-amber">
                      Active: {formatIndexingStatus(indexingPlan.active_job?.step || indexingPlan.active_job?.status)}
                    </span>
                  ) : null}
                </div>
                <div className="mt-3 grid gap-2 md:grid-cols-2">
                  {indexingPlan.steps.map((step: EvidenceIndexingStep) => (
                    <div key={step.id} className="rounded-2xl border border-line bg-abyss/60 px-3 py-2">
                      <div className="flex items-start justify-between gap-2">
                        <p className="text-sm font-semibold text-ink">{step.name}</p>
                        <span className={`shrink-0 rounded-full border px-2 py-0.5 text-[11px] ${indexingStepTone(step.status)}`}>{formatIndexingStatus(step.status)}</span>
                      </div>
                      <p className="mt-1 text-xs text-muted">{step.reason}</p>
                    </div>
                  ))}
                </div>
              </div>
              <div className="rounded-2xl border border-line bg-panel/60 p-4">
                <p className="text-sm font-semibold text-ink">Excluded from indexing</p>
                <div className="mt-3 space-y-2">
                  {indexingPlan.excluded.map((item) => (
                    <div key={`${item.name}-${item.reason}`} className="rounded-2xl border border-line bg-abyss/60 px-3 py-2">
                      <p className="text-sm font-semibold text-ink">{item.name}</p>
                      <p className="mt-1 text-xs text-muted">{item.reason}</p>
                    </div>
                  ))}
                </div>
                <p className="mt-3 text-xs text-muted">Individual rebuilds, SRUM retries, rules and diagnostics remain available under advanced actions.</p>
              </div>
            </div>
          ) : (
            <p className="mt-4 text-sm text-muted">Indexing plan is unavailable for this evidence.</p>
          )}
        </div>

        <div ref={selectedArtifactTypesRef} className="mt-5 rounded-3xl border border-line bg-panel/60 p-5" data-testid="selected-artifact-types-section">
          <div className="flex flex-col gap-4 xl:flex-row xl:items-start xl:justify-between">
            <div className="min-w-0">
              <p className="font-mono text-[11px] uppercase tracking-[0.18em] text-accent">Selected artifact types</p>
              <h3 className="mt-1 text-xl font-semibold text-ink">Index selected artifact types</h3>
              <p className="mt-1 max-w-4xl text-sm text-muted">
                Use this when you only want to parse specific artifact families, such as EVTX, Scheduled Tasks, Services or Shimcache.
              </p>
              {selectedIndexingLocked ? (
                <div className="mt-3 rounded-2xl border border-amber/30 bg-amber/10 px-4 py-3 text-sm text-amber">
                  <p>{activeRecommendedIndexing ? "Manual selected indexing is locked while recommended indexing is running." : "Manual selected indexing is locked while another indexing job is running."}</p>
                  {!manualSelectionActive ? <p className="mt-1 text-muted">No manual selection is active.</p> : null}
                </div>
              ) : !selectedIndexingAvailable ? (
                <p className="mt-3 rounded-2xl border border-line bg-abyss/60 px-4 py-3 text-sm text-muted">
                  No supported raw discovery artifact types are available for selected indexing.
                </p>
              ) : null}
            </div>
            <div className="flex flex-wrap gap-2">
              <button type="button" onClick={selectAllSupported} disabled={!selectedIndexingAvailable || selectedIndexingLocked} className="rounded-2xl border border-line bg-panel/50 px-4 py-2 text-sm text-muted disabled:opacity-60">
                Select all supported
              </button>
              <button type="button" onClick={clearSelection} disabled={!selectedIndexingAvailable || selectedIndexingLocked} className="rounded-2xl border border-line bg-panel/50 px-4 py-2 text-sm text-muted disabled:opacity-60">
                Clear selection
              </button>
            </div>
          </div>

          {selectedIndexingAvailable ? (
            <>
              <div className="mt-4 flex flex-wrap gap-2">
                {hasEvtxCategory ? (
                  <button type="button" onClick={selectEventLogsOnly} disabled={selectedIndexingLocked} className="rounded-2xl border border-line bg-abyss/70 px-4 py-2 text-sm text-muted disabled:opacity-60">
                    Event logs only
                  </button>
                ) : null}
                <button type="button" onClick={selectExecutionArtifacts} disabled={selectedIndexingLocked} className="rounded-2xl border border-line bg-abyss/70 px-4 py-2 text-sm text-muted disabled:opacity-60">
                  Execution artifacts
                </button>
                <button type="button" onClick={selectPersistenceArtifacts} disabled={selectedIndexingLocked} className="rounded-2xl border border-line bg-abyss/70 px-4 py-2 text-sm text-muted disabled:opacity-60">
                  Persistence artifacts
                </button>
              </div>

              <div className="mt-4 grid gap-3 md:grid-cols-2 xl:grid-cols-4">
                {supportedCategoryOptions.map((option) => {
                  const selectedCount = option.supportedIds.filter((id) => selectedCandidateIds.includes(id)).length;
                  const fullySelected = selectedCount === option.supportedIds.length;
                  return (
                    <label key={option.category} className={`flex min-h-[96px] cursor-pointer items-start gap-3 rounded-2xl border px-4 py-3 transition ${fullySelected ? "border-accent/40 bg-accent/10" : "border-line bg-abyss/60 hover:border-accent/20"} ${selectedIndexingLocked ? "cursor-not-allowed opacity-60" : ""}`}>
                      <input
                        type="checkbox"
                        className="mt-1"
                        checked={fullySelected}
                        disabled={selectedIndexingLocked}
                        onChange={() => toggleCategorySelection(option.category)}
                      />
                      <div className="min-w-0">
                        <p className="text-sm font-semibold text-ink">{option.label}</p>
                        <p className="mt-1 text-xs text-muted">
                          {option.parseableCount} parseable
                          {option.partialCount ? ` · ${option.partialCount} partial` : ""}
                          {` · ${option.supportedIds.length} selectable`}
                        </p>
                      </div>
                    </label>
                  );
                })}
              </div>

              {manualSelectionActive ? (
                <div className="mt-4 rounded-2xl border border-line bg-abyss/70 px-4 py-3 text-sm text-muted">
                  <p>
                    Selected preview: <span className="font-semibold text-ink">{selectedCandidateIds.length}</span> candidates
                  </p>
                  {selectedCategoryNames.length ? <p className="mt-1">Selected categories: <span className="font-semibold text-ink">{selectedCategoryNames.join(", ")}</span></p> : null}
                </div>
              ) : selectedIndexingLocked ? null : (
                <div className="mt-4 rounded-2xl border border-line bg-abyss/70 px-4 py-3 text-sm text-muted">
                  No manual selection is active.
                </div>
              )}

              {hasPowerShellCategory ? (
                <div className="mt-3 rounded-2xl border border-cyan-400/25 bg-cyan-400/10 px-4 py-3 text-sm text-cyan-100">
                  PowerShell selection covers PSReadLine, transcripts, script files and PowerShell exports. PowerShell events stored inside EVTX files are only scanned when you also select EVTX.
                </div>
              ) : null}
              {hasEvtxCategory && !evtxecmdAvailable ? (
                <div className="mt-3 rounded-2xl border border-line bg-abyss/60 p-4 text-sm text-muted">
                  <p className="font-semibold text-ink">EVTX indexing profile</p>
                  <p className="mt-1">Full EVTX indexing is unavailable because EvtxECmd is not available. Limited EVTX triage mode is partial and should only be used as a fallback.</p>
                  <div className="mt-3 flex flex-wrap gap-2">
                    <button type="button" onClick={() => setParseEvtxProfile("fast_high_value")} disabled={selectedIndexingLocked} className={`rounded-2xl border px-4 py-2 text-sm ${parseEvtxProfile === "fast_high_value" ? "border-accent bg-accent/10 text-ink" : "border-line bg-panel/40 text-muted"}`}>
                      Fast EVTX Search
                    </button>
                    <button type="button" onClick={() => setParseEvtxProfile("full")} disabled={selectedIndexingLocked} className={`rounded-2xl border px-4 py-2 text-sm ${parseEvtxProfile === "full" ? "border-amber bg-amber/10 text-ink" : "border-line bg-panel/40 text-muted"}`}>
                      Full EVTX Indexing
                    </button>
                  </div>
                </div>
              ) : null}

              <div className="mt-4 flex justify-end">
                <button
                  type="button"
                  onClick={indexSelectedArtifactTypes}
                  disabled={!selectedCandidateIds.length || selectedIndexingLocked || parseVelociraptorMutation.isPending}
                  className="rounded-2xl bg-accent px-5 py-3 text-sm font-semibold text-abyss disabled:cursor-not-allowed disabled:opacity-60"
                >
                  {parseVelociraptorMutation.isPending ? "Queueing selected types..." : "Index selected types"}
                </button>
              </div>
              {parseVelociraptorMutation.error instanceof Error ? <p className="mt-3 text-sm text-danger">{parseVelociraptorMutation.error.message}</p> : null}
            </>
          ) : null}
        </div>

        <details className="mt-5 rounded-3xl border border-line bg-panel/50 p-4">
          <summary className="cursor-pointer font-mono text-[11px] uppercase tracking-[0.16em] text-muted">Advanced recovery & diagnostics</summary>
          <p className="mt-2 text-sm text-muted">Use these scoped actions for rebuilds, parser diagnostics or explicit artifact-level control. They are intentionally outside the recommended indexing flow.</p>

        {mftDiagnostic ? (
          mftDiagnostic.mft_present_in_evidence ? (
            <div className={`mt-5 rounded-3xl border p-4 ${mftDiagnostic.mft_indexed_docs > 0 ? "border-mint/25 bg-mint/10" : "border-amber/30 bg-amber/10"}`}>
              <div className="flex flex-col gap-3 lg:flex-row lg:items-start lg:justify-between">
                <div>
                  <p className="font-mono text-[11px] uppercase tracking-[0.16em] text-accent">MFT / Filesystem</p>
                  <p className="mt-1 text-sm font-semibold text-ink">
                    {mftDiagnostic.mft_indexed_docs > 0 ? `MFT indexed · ${mftDiagnostic.mft_indexed_docs.toLocaleString()} docs` : "MFT detected but not indexed"}
                  </p>
                  <p className="mt-1 text-sm text-muted">
                    {mftDiagnostic.mft_indexed_docs > 0
                      ? `Filesystem metadata is searchable and available in Artifact Views. Coverage: ${mftDiagnostic.mft_coverage_status || "summary"}. Backend: ${mftDiagnostic.mft_parser_backend || "mftecmd_csv"}.`
                      : `Reason: ${mftDiagnostic.mft_skipped_reason || "detected_not_indexed"}. ${mftDiagnostic.recommended_action}`}
                  </p>
                  {mftDiagnostic.mft_indexed_docs > 0 ? (
                    <p className="mt-2 text-xs text-muted">
                      Records indexed: {(mftDiagnostic.mft_records_indexed ?? mftDiagnostic.mft_indexed_docs).toLocaleString()}
                      {mftDiagnostic.mft_records_total ? ` / ${mftDiagnostic.mft_records_total.toLocaleString()}` : ""}.
                      {mftDiagnostic.mft_full_status ? ` Full MFT: ${mftDiagnostic.mft_full_status}${mftDiagnostic.mft_full_records_indexed ? ` · ${mftDiagnostic.mft_full_records_indexed.toLocaleString()} records` : ""}.` : ""}
                    </p>
                  ) : null}
                  {mftDiagnostic.detected_candidates?.[0]?.source_path ? (
                    <p className="mt-2 break-all font-mono text-xs text-muted">{mftDiagnostic.detected_candidates[0].source_path}</p>
                  ) : null}
                </div>
                <div className="flex flex-wrap gap-2">
                  {mftDiagnostic.mft_indexed_docs > 0 ? (
                    <>
                      <Link to={data?.case_id ? `/cases/${data.case_id}/artifacts?evidence_id=${encodeURIComponent(evidenceId)}&artifact_type=mft` : "#"} className="rounded-2xl border border-line bg-abyss/70 px-4 py-2 text-sm text-ink">
                        Open MFT / Filesystem view
                      </Link>
                      <button
                        type="button"
                        disabled={conflictingIndexingActionsDisabled || indexMftFullMutation.isPending || mftDiagnostic.mft_full_status === "running" || mftDiagnostic.mft_full_status === "queued"}
                        onClick={() => {
                          const existing = mftDiagnostic.mft_full_records_indexed ?? 0;
                          const message = existing > 0
                            ? `Rebuild full MFT for this evidence? This replaces existing MFT docs only and may add about ${(mftDiagnostic.mft_records_total || existing).toLocaleString()} filesystem records.`
                            : `Index full MFT for this evidence? This may add about ${(mftDiagnostic.mft_records_total || 0).toLocaleString()} filesystem records.`;
                          if (window.confirm(message)) indexMftFullMutation.mutate();
                        }}
                        className="rounded-2xl border border-warning/40 bg-warning/10 px-4 py-2 text-sm text-warning disabled:opacity-60"
                      >
                        {indexMftFullMutation.isPending || mftDiagnostic.mft_full_status === "queued" ? "Queueing full MFT..." : mftDiagnostic.mft_full_status === "running" ? "Full MFT indexing..." : mftDiagnostic.mft_full_records_indexed ? "Rebuild full MFT" : "Index full MFT"}
                      </button>
                    </>
                  ) : (
                    <>
                      <button type="button" disabled={conflictingIndexingActionsDisabled || indexMftSummaryMutation.isPending} onClick={() => indexMftSummaryMutation.mutate()} className="rounded-2xl border border-accent/40 bg-accent/10 px-4 py-2 text-sm text-accent disabled:opacity-60">
                        {indexMftSummaryMutation.isPending ? "Queueing..." : "Index MFT summary"}
                      </button>
                      <button
                        type="button"
                        disabled={conflictingIndexingActionsDisabled || indexMftFullMutation.isPending || mftDiagnostic.mft_full_status === "running" || mftDiagnostic.mft_full_status === "queued"}
                        onClick={() => {
                          if (window.confirm("Index full MFT? This advanced action can add hundreds of thousands of filesystem records.")) indexMftFullMutation.mutate();
                        }}
                        className="rounded-2xl border border-warning/40 bg-warning/10 px-4 py-2 text-sm text-warning disabled:opacity-60"
                      >
                        Index full MFT
                      </button>
                    </>
                  )}
                  <a href="#artifact-manifest" className="rounded-2xl border border-line bg-abyss/70 px-4 py-2 text-sm text-muted">
                    View raw artifact
                  </a>
                </div>
              </div>
            </div>
          ) : (
            <details className="mt-5 rounded-3xl border border-line bg-panel/50 p-4">
              <summary className="cursor-pointer font-mono text-[11px] uppercase tracking-[0.16em] text-muted">Advanced filesystem diagnostics</summary>
              <p className="mt-3 text-sm text-muted">No MFT artifact detected in this evidence.</p>
            </details>
          )
        ) : null}

        <div className={`mt-5 rounded-3xl border p-4 ${userActivityTotal > 0 ? "border-mint/25 bg-mint/10" : "border-line bg-panel/50"}`}>
          <div className="flex flex-col gap-3 lg:flex-row lg:items-start lg:justify-between">
            <div>
              <p className="font-mono text-[11px] uppercase tracking-[0.16em] text-accent">User Activity</p>
              <p className="mt-1 text-sm font-semibold text-ink">
                {userActivityTotal > 0 ? `RECmd user activity indexed · ${userActivityTotal.toLocaleString()} docs` : userActivityStatus === "queued" || userActivityStatus === "running" ? "RECmd user activity indexing queued" : "User activity artifacts not indexed"}
              </p>
              <p className="mt-1 text-sm text-muted">
                Extract Shellbags, UserAssist, RecentDocs, RunMRU and OpenSaveMRU from NTUSER.DAT / UsrClass.dat. This is scoped and does not re-index EVTX or MFT.
              </p>
              {userActivityTotal > 0 ? (
                <p className="mt-2 text-xs text-muted">
                  Shellbags {(userActivityCounts.shellbag ?? 0).toLocaleString()} · UserAssist {(userActivityCounts.userassist ?? 0).toLocaleString()} · RecentDocs {(userActivityCounts.recentdocs ?? 0).toLocaleString()} · RunMRU {(userActivityCounts.runmru ?? 0).toLocaleString()} · OpenSaveMRU {(userActivityCounts.opensavemru ?? 0).toLocaleString()}
                </p>
              ) : null}
            </div>
            <div className="flex flex-wrap gap-2">
              {userActivityTotal > 0 && data?.case_id ? (
                <Link to={`/cases/${data.case_id}/artifacts?evidence_id=${encodeURIComponent(evidenceId)}&artifact_type=shellbag`} className="rounded-2xl border border-line bg-abyss/70 px-4 py-2 text-sm text-ink">
                  Open User Activity
                </Link>
              ) : null}
              <button
                type="button"
                disabled={conflictingIndexingActionsDisabled || indexRecmdUserActivityMutation.isPending || userActivityStatus === "queued" || userActivityStatus === "running"}
                onClick={() => {
                  const message = userActivityTotal > 0 ? "Rebuild RECmd user activity artifacts for this evidence? Existing RECmd user activity docs for this evidence will be replaced." : "Index RECmd user activity artifacts for this evidence?";
                  if (window.confirm(message)) indexRecmdUserActivityMutation.mutate();
                }}
                className="rounded-2xl border border-accent/40 bg-accent/10 px-4 py-2 text-sm text-accent disabled:opacity-60"
              >
                {indexRecmdUserActivityMutation.isPending || userActivityStatus === "queued" ? "Queueing..." : userActivityStatus === "running" ? "Indexing..." : userActivityTotal > 0 ? "Rebuild user activity" : "Index user activity"}
              </button>
            </div>
          </div>
        </div>

        <div className={`mt-5 rounded-3xl border p-4 ${defenderDocs > 0 ? "border-mint/25 bg-mint/10" : defenderNoData ? "border-line bg-panel/50" : "border-line bg-panel/50"}`}>
          <div className="flex flex-col gap-3 lg:flex-row lg:items-start lg:justify-between">
            <div>
              <p className="font-mono text-[11px] uppercase tracking-[0.16em] text-accent">Microsoft Defender</p>
              <p className="mt-1 text-sm font-semibold text-ink">
                {defenderDocs > 0
                  ? `Defender events indexed · ${defenderDocs.toLocaleString()} docs`
                  : defenderStatus === "queued" || defenderStatus === "running"
                    ? "Defender EVTX indexing queued"
                    : defenderNoData
                      ? "Defender log present, no relevant detection events found"
                      : "Defender artifact view not indexed"}
              </p>
              <p className="mt-1 text-sm text-muted">
                Extract Defender detections, remediation, action failures and configuration changes from Windows Defender Operational EVTX.
              </p>
            </div>
            <div className="flex flex-wrap gap-2">
              {defenderDocs > 0 && data?.case_id ? (
                <Link to={`/cases/${data.case_id}/artifacts?evidence_id=${encodeURIComponent(evidenceId)}&artifact_type=defender`} className="rounded-2xl border border-line bg-abyss/70 px-4 py-2 text-sm text-ink">
                  Open Defender view
                </Link>
              ) : null}
              <button
                type="button"
                disabled={conflictingIndexingActionsDisabled || indexDefenderEvtxMutation.isPending || defenderStatus === "queued" || defenderStatus === "running"}
                onClick={() => {
                  const message = defenderDocs > 0 ? "Rebuild Defender EVTX artifact docs for this evidence? Existing Defender docs for this evidence will be replaced." : "Index Defender EVTX artifact docs for this evidence?";
                  if (window.confirm(message)) indexDefenderEvtxMutation.mutate();
                }}
                className="rounded-2xl border border-accent/40 bg-accent/10 px-4 py-2 text-sm text-accent disabled:opacity-60"
              >
                {indexDefenderEvtxMutation.isPending || defenderStatus === "queued" ? "Queueing..." : defenderStatus === "running" ? "Indexing..." : defenderDocs > 0 ? "Rebuild Defender" : "Index Defender"}
              </button>
            </div>
          </div>
        </div>

        <div className={`mt-5 rounded-3xl border p-4 ${srumDocs > 0 ? "border-mint/25 bg-mint/10" : srumToolingMissing ? "border-amber/30 bg-amber/10" : "border-line bg-panel/50"}`}>
          <div className="flex flex-col gap-3 lg:flex-row lg:items-start lg:justify-between">
            <div>
              <p className="font-mono text-[11px] uppercase tracking-[0.16em] text-accent">SRUM</p>
              <p className="mt-1 text-sm font-semibold text-ink">
                {srumDocs > 0
                  ? `SRUM indexed · ${srumDocs.toLocaleString()} docs`
                  : srumStatus === "queued" || srumStatus === "running"
                    ? "SRUM indexing queued"
                    : srumToolingMissing
                      ? "Requires Windows parser worker"
                      : srumNoData
                        ? "SRUM database present, no records indexed"
                        : "SRUM not indexed"}
              </p>
              <p className="mt-1 text-sm text-muted">
                Extract application and network usage from SRUDB.dat with SrumECmd. This scoped action does not re-index EVTX, MFT or rules.
              </p>
              {srumDocs > 0 ? (
                <p className="mt-2 text-xs text-muted">
                  Tables: {Object.entries(srumTables).slice(0, 4).map(([name, count]) => `${name} ${Number(count).toLocaleString()}`).join(" · ") || "indexed"}.
                </p>
              ) : null}
              {srumToolingMissing ? (
                <p className="mt-2 text-xs text-amber">
                  SRUM source detected, but this parser requires a Windows-capable worker because the Linux runtime lacks Windows ESE libraries. Evidence status is not affected.
                </p>
              ) : null}
            </div>
            <div className="flex flex-wrap gap-2">
              {srumDocs > 0 && data?.case_id ? (
                <Link to={`/cases/${data.case_id}/artifacts?evidence_id=${encodeURIComponent(evidenceId)}&artifact_type=srum`} className="rounded-2xl border border-line bg-abyss/70 px-4 py-2 text-sm text-ink">
                  Open SRUM view
                </Link>
              ) : null}
              <button
                type="button"
                disabled={conflictingIndexingActionsDisabled || indexSrumMutation.isPending || srumStatus === "queued" || srumStatus === "running"}
                onClick={() => {
                  const message = srumDocs > 0 ? "Rebuild SRUM artifact docs for this evidence? Existing SRUM docs for this evidence will be replaced." : "Index SRUM artifact docs for this evidence?";
                  if (window.confirm(message)) indexSrumMutation.mutate();
                }}
                className="rounded-2xl border border-accent/40 bg-accent/10 px-4 py-2 text-sm text-accent disabled:opacity-60"
              >
                {indexSrumMutation.isPending || srumStatus === "queued"
                  ? "Queueing..."
                  : srumStatus === "running"
                    ? "Indexing..."
                    : srumToolingMissing
                      ? "Retry when worker available"
                      : srumDocs > 0
                        ? "Rebuild SRUM"
                        : "Index SRUM"}
              </button>
            </div>
          </div>
        </div>
        </details>

        {evidenceReadyForActions ? (
          <div className="mt-5 flex flex-wrap gap-3">
            {coreActions.slice(0, 4).map((action) => (
              <Link key={action.id} to={action.href} className="rounded-2xl border border-line bg-abyss/70 px-4 py-3 text-sm text-muted transition hover:border-accent hover:text-ink">
                <span className="font-medium text-ink">{action.label}</span>
                <span className="ml-2 text-xs text-muted">{action.description}</span>
              </Link>
            ))}
            <button type="button" onClick={() => onDemandRulesMutation.mutate()} disabled={rulesLaunchDisabled} className="rounded-2xl border border-line bg-abyss/70 px-4 py-3 text-sm font-medium text-ink disabled:opacity-60">
              {onDemandRulesMutation.isPending ? "Launching rules..." : activeEvidenceRuleRun ? "Rules running" : "Run rules"}
            </button>
            <button type="button" onClick={() => generateReportMutation.mutate()} disabled={reportLaunchDisabled} className="rounded-2xl border border-line bg-abyss/70 px-4 py-3 text-sm font-medium text-ink disabled:opacity-60">
              {generateReportMutation.isPending ? "Generating report..." : activeEvidenceReport ? "Report running" : "Generate report"}
            </button>
            <Link to={data?.case_id ? `/cases/${data.case_id}/evidence` : "#"} className="rounded-2xl border border-line bg-abyss/70 px-4 py-3 text-sm font-medium text-ink">
              Add more evidence
            </Link>
          </div>
        ) : null}

        <div className="mt-5 grid gap-4 xl:grid-cols-[minmax(0,1.2fr)_minmax(0,0.8fr)]">
          <div className="rounded-3xl border border-line bg-panel/60 p-4">
            <p className="font-mono text-[11px] uppercase tracking-[0.16em] text-accent">Indexed data</p>
            {indexedArtifactTypeCounts.length ? (
              <div className="mt-3 flex flex-wrap gap-2">
                {indexedArtifactTypeCounts.map(([artifactType, count]) => (
                  <Link
                    key={artifactType}
                    to={data?.case_id ? `/cases/${data.case_id}/search?evidence_id=${encodeURIComponent(evidenceId)}&artifact_type=${encodeURIComponent(artifactType)}&tab=results` : "#"}
                    className="rounded-full border border-line bg-abyss/70 px-3 py-1 text-xs text-muted transition hover:border-accent hover:text-ink"
                  >
                    {artifactType} · {count}
                  </Link>
                ))}
              </div>
            ) : (
              <p className="mt-2 text-sm text-muted">No indexed artifact counts are available yet.</p>
            )}
            {indexedParserCounts.length ? (
              <div className="mt-3 flex flex-wrap gap-2">
                {indexedParserCounts.map(([parserName, count]) => (
                  <Link
                    key={parserName}
                    to={data?.case_id ? `/cases/${data.case_id}/search?evidence_id=${encodeURIComponent(evidenceId)}&parser=${encodeURIComponent(parserName)}&tab=results` : "#"}
                    className="rounded-full border border-line bg-abyss/70 px-3 py-1 text-xs text-muted transition hover:border-accent hover:text-ink"
                  >
                    {parserName} · {count}
                  </Link>
                ))}
              </div>
            ) : null}
          </div>
          <div className="rounded-3xl border border-line bg-panel/60 p-4">
            <p className="font-mono text-[11px] uppercase tracking-[0.16em] text-accent">Problems</p>
            {problemsCount ? (
              <p className="mt-2 text-sm text-amber">{problemsCount} item(s) need review. Deferred and problematic artifacts are preserved for explicit follow-up.</p>
            ) : (
              <p className="mt-2 text-sm text-mint">No deferred artifacts reported.</p>
            )}
          </div>
        </div>

        <div className="mt-5 rounded-3xl border border-line bg-panel/50 p-4 text-sm text-muted">
          {selectionPending
            ? "Raw discovery inventory is available below. Use Index selected artifact types for scoped parsing."
            : activeIndexingJob
              ? "Raw discovery inventory remains readable while indexing is running; selected indexing is locked until the job finishes."
              : "Raw discovery inventory is preserved for candidate counts, support status and parser availability."}
        </div>
        {selectionPending ? (
          <details className="mt-3 rounded-3xl border border-line bg-panel/50 p-4">
            <summary className="cursor-pointer font-mono text-[11px] uppercase tracking-[0.16em] text-accent">Raw discovery inventory</summary>
            <div className="grid gap-4 xl:grid-cols-[minmax(0,1fr)_auto] xl:items-center">
              <div>
                <p className="mt-4 font-mono text-[11px] uppercase tracking-[0.16em] text-accent">Raw discovery inventory</p>
                <p className="mt-1 text-sm font-semibold text-ink">Supported artifacts detected</p>
                <p className="mt-1 text-sm text-muted">
                  Read-only inventory of discovered candidates, support status and parser availability. Use Index selected artifact types above for scoped parsing.
                </p>
                <div className="mt-3 grid gap-2 text-sm text-muted md:grid-cols-2 xl:grid-cols-4">
                  <div className="rounded-2xl border border-line bg-panel/40 px-3 py-2">
                    <p className="font-mono text-[10px] uppercase tracking-[0.14em] text-muted">Case</p>
                    <p className="mt-1 truncate text-ink" title={data?.case_id ?? "-"}>{data?.case_id ?? "-"}</p>
                  </div>
                  <div className="rounded-2xl border border-line bg-panel/40 px-3 py-2">
                    <p className="font-mono text-[10px] uppercase tracking-[0.14em] text-muted">Host</p>
                    <p className="mt-1 truncate text-ink" title={data?.provided_host || data?.detected_host || "-"}>{data?.provided_host || data?.detected_host || "-"}</p>
                  </div>
                  <div className="rounded-2xl border border-line bg-panel/40 px-3 py-2">
                    <p className="font-mono text-[10px] uppercase tracking-[0.14em] text-muted">Supported data</p>
                    <p className="mt-1 text-ink">{supportedCategoryOptions.length} categories · {discoveryCandidates.length} candidates</p>
                  </div>
                  <div className="rounded-2xl border border-line bg-panel/40 px-3 py-2">
                    <p className="font-mono text-[10px] uppercase tracking-[0.14em] text-muted">Event logs</p>
                    <p className="mt-1 text-ink">{hasEvtxCategory ? evtxecmdAvailable ? "Full coverage with EvtxECmd" : "EVTX fallback available" : "None detected"}</p>
                  </div>
                </div>
                <div className="mt-3 rounded-2xl border border-line bg-panel/40 px-4 py-3 text-sm text-muted">
                  <p className="font-semibold text-ink">Inventory only</p>
                  <p className="mt-1">Discovered candidates are preserved for traceability. Scoped parsing controls live in Index selected artifact types.</p>
                </div>
              </div>
              <div className="flex flex-wrap gap-2">
                <button onClick={scrollToParseSelection} disabled={conflictingIndexingActionsDisabled} className="rounded-2xl border border-line bg-panel/50 px-4 py-2 text-sm text-muted disabled:opacity-60">
                  Index selected types
                </button>
              </div>
            </div>
          </details>
        ) : null}
        {!selectionPending && selectedArtifactTypes.length ? (
          <div className="mt-3 rounded-3xl border border-line bg-panel/60 p-4 text-sm text-muted">
            Parsed artifacts in this run are limited to the selected categories: <span className="font-semibold text-ink">{selectedArtifactTypes.join(", ")}</span>. Detected candidates can still include other categories that were not selected for extraction.
          </div>
        ) : null}
        {evtxDeferredCount > 0 || evtxPartialCount > 0 ? (
          <div className="mt-3 rounded-3xl border border-amber/30 bg-amber/10 p-4 text-sm text-amber">
            <div className="flex flex-col gap-3 md:flex-row md:items-center md:justify-between">
              <div>
                <p className="font-mono text-[11px] uppercase tracking-[0.16em]">EVTX Fast Search profile</p>
                <p className="mt-1 font-semibold">
                  {evtxSelectedFiles.length ? `${evtxSelectedFiles.length} EVTX indexed or selected · ` : ""}
                  {evtxDeferredCount} deferred · {evtxPartialCount} partial
                </p>
                <p className="mt-1 text-xs text-muted">
                  Fast profile: partial EVTX coverage. Large logs may be partially indexed; nothing is deleted.
                </p>
                {evtxCoverageStatus ? <p className="mt-1 text-xs text-muted">Coverage status: {evtxCoverageStatus}</p> : null}
                {evtxParserBackend ? <p className="mt-1 text-xs text-muted">EVTX parser: {formatEvtxBackend(evtxParserBackend)}{evtxParserBackendVersion ? ` ${evtxParserBackendVersion}` : ""}</p> : null}
              </div>
              <button disabled className="rounded-2xl border border-amber/30 bg-abyss/40 px-4 py-2 text-sm text-amber opacity-70">
                Continue EVTX indexing · Advanced/Beta
              </button>
            </div>
          </div>
        ) : evtxProfile || evtxParserBackend || evtxCoverageStatus ? (
          <div className="mt-3 rounded-3xl border border-line bg-panel/60 p-4 text-sm text-muted">
            <div className="flex flex-col gap-2 md:flex-row md:items-center md:justify-between">
              <div>
                <p>
                  EVTX coverage: <span className="font-semibold text-ink">{evtxProfile === "fast_high_value" ? "Partial triage" : "Full coverage"}</span>
                </p>
                {evtxParserBackend ? <p className="mt-1 text-xs">EVTX parser: <span className="font-semibold text-ink">{formatEvtxBackend(evtxParserBackend)}{evtxParserBackendVersion ? ` ${evtxParserBackendVersion}` : ""}</span></p> : null}
                {evtxParserBackendFallback ? <p className="mt-1 text-xs text-amber">Python EVTX parser fallback may be slow on large evidence.</p> : null}
              </div>
              {evtxCoverageIsFull ? (
                <span className="rounded-full border border-emerald-400/30 bg-emerald-400/10 px-3 py-1 font-mono text-[11px] uppercase tracking-[0.16em] text-emerald-200">Full EVTX coverage</span>
              ) : evtxCoverageStatus ? (
                <span className="rounded-full border border-line bg-abyss/50 px-3 py-1 font-mono text-[11px] uppercase tracking-[0.16em] text-muted">{evtxCoverageStatus}</span>
              ) : null}
            </div>
          </div>
        ) : null}

        <div id="indexing-progress" data-testid="evidence-progress-primary" className="mt-5 rounded-3xl border border-accent/30 bg-panel/70 p-4 shadow-panel">
          <div className="flex flex-wrap items-start justify-between gap-4">
            <div>
              <p className="font-mono text-[11px] uppercase tracking-[0.16em] text-accent">Indexing progress</p>
              <h3 className="mt-1 text-lg font-semibold text-ink">{activeIndexingJob ? indexingStateTitle : formatIndexingPhaseForDisplay(displayCounts.phase)}</h3>
              <p className="mt-1 text-xs text-muted">Current step: {formatIndexingPhaseForDisplay(displayCounts.phase)}</p>
              <p className="mt-1 text-sm text-muted">{progressStatusLabel}</p>
              {currentDisplayArtifact ? <p className="mt-1 max-w-[760px] truncate text-xs text-muted" title={currentDisplayArtifact}>Current artifact: {currentDisplayArtifact}</p> : null}
              {effectiveCurrentArtifactLabel ? <p className="mt-1 text-xs text-muted">Current artifact progress: {effectiveCurrentArtifactLabel}</p> : null}
              {showExtractingSelected ? <p className="mt-1 text-xs text-muted">Preparing selected artifacts before parser workers start.</p> : null}
              {currentSelectedPath ? <p className="mt-1 max-w-[760px] truncate text-xs text-muted" title={currentSelectedPath}>Current selected file: {currentSelectedPath}</p> : null}
              {currentAction ? <p className="mt-1 text-xs text-muted">Current action: {currentAction}</p> : null}
              {currentBottleneck ? <p className="mt-1 text-xs text-muted">Current bottleneck: {currentBottleneck}</p> : null}
              {showMissingProgressWarning ? (
                <p className="mt-2 rounded-xl border border-amber-500/40 bg-amber-500/10 px-3 py-2 text-xs text-amber-100">
                  Worker heartbeat is alive but progress metadata is missing. The job may still be running, but the backend is not reporting artifact progress correctly yet.
                </p>
              ) : null}
              {showExtractionStallWarning ? (
                <p className="mt-2 rounded-xl border border-amber-500/40 bg-amber-500/10 px-3 py-2 text-xs text-amber-100">
                  No extraction progress detected yet. The worker is still preparing selected artifacts before parsing can start.
                </p>
              ) : null}
            </div>
            <div className="min-w-[180px] rounded-2xl border border-line bg-abyss/70 px-4 py-3 text-right">
              <p className="font-mono text-[11px] uppercase tracking-[0.16em] text-muted">Progress</p>
              <p className="mt-1 text-3xl font-semibold text-ink">{displayCounts.progressPct}%</p>
            </div>
          </div>
          <div className="mt-4 grid gap-3 md:grid-cols-3 xl:grid-cols-5">
            <div className="rounded-2xl border border-line bg-abyss/60 px-3 py-2"><p className="font-mono text-[11px] uppercase tracking-[0.16em] text-muted">Status</p><p className="mt-1 text-sm text-ink">{indexingStateTitle}</p></div>
            <div className="rounded-2xl border border-line bg-abyss/60 px-3 py-2"><p className="font-mono text-[11px] uppercase tracking-[0.16em] text-muted">Artifacts</p><p className="mt-1 text-sm text-ink">{displayCounts.artifactsDone} / {displayCounts.artifactsTotal}</p></div>
            <div className="rounded-2xl border border-line bg-abyss/60 px-3 py-2"><p className="font-mono text-[11px] uppercase tracking-[0.16em] text-muted">Indexed docs</p><p className="mt-1 text-sm text-ink">{displayCounts.indexedDocs.toLocaleString()}</p></div>
            <div className="rounded-2xl border border-line bg-abyss/60 px-3 py-2"><p className="font-mono text-[11px] uppercase tracking-[0.16em] text-muted">Last progress</p><p className="mt-1 text-sm text-ink">{lastProgressAgeLabel}</p></div>
            <div className="rounded-2xl border border-line bg-abyss/60 px-3 py-2"><p className="font-mono text-[11px] uppercase tracking-[0.16em] text-muted">Mode</p><p className="mt-1 text-sm text-ink">{productModeLabel}</p></div>
          </div>
        </div>

        <details className="mt-5 rounded-3xl border border-line bg-abyss/60 p-4 text-sm text-muted">
          <summary className="cursor-pointer font-mono text-[11px] uppercase tracking-[0.16em] text-accent">Advanced details</summary>
          <div className="mt-4 space-y-3">
        <div className="rounded-3xl border border-line bg-abyss/70 p-4">
          {activeIndexingJob ? (
            <p className="rounded-2xl border border-accent/20 bg-accent/10 px-3 py-2 text-xs text-muted">
              Live counters are shown once in Indexing progress above. Advanced details below are diagnostics only while the run is active.
            </p>
          ) : null}
          <div className="mt-3 flex flex-wrap items-start justify-between gap-4">
            <div>
              <p className="font-mono text-[11px] uppercase tracking-[0.16em] text-accent">{activeIndexingJob ? "Processing diagnostics" : "Progress summary"}</p>
              <p className="mt-1 text-sm text-ink">
                {ingestModeLabel === "full forensic" ? "Advanced processing" : "Core indexing"} · {currentPhase}
              </p>
              <p className="mt-1 text-xs text-muted">{progressStatusLabel}</p>
              <p className="mt-1 text-xs text-slate-300">{effectivePlanSummary}</p>
              {data?.metadata_json?.current_artifact ? <p className="mt-1 text-xs text-muted">Current artifact: {String(data.metadata_json.current_artifact)}</p> : null}
              {hasLongTail ? <p className="mt-1 text-xs text-muted">Tail running {tailArtifactsRunning} · queued {tailArtifactsQueued}</p> : null}
              {currentBottleneck ? <p className="mt-1 text-xs text-muted">Current bottleneck: {currentBottleneck}</p> : null}
              {ingestModeLabel === "full forensic" ? <p className="mt-2 text-xs text-amber">Advanced processing can take significantly longer.</p> : null}
            </div>
            {!activeIndexingJob ? <div className="min-w-[180px] rounded-2xl border border-line bg-panel/50 px-4 py-3 text-right">
              <p className="font-mono text-[11px] uppercase tracking-[0.16em] text-muted">Progress</p>
              <p className="mt-1 text-2xl font-semibold text-ink">{progressPct}%</p>
            </div> : null}
          </div>
          {!activeIndexingJob ? <div className="mt-4 grid gap-3 md:grid-cols-3 xl:grid-cols-6">
            <div className="rounded-2xl border border-line bg-panel/50 px-3 py-2"><p className="font-mono text-[11px] uppercase tracking-[0.16em] text-muted">Mode</p><p className="mt-1 text-sm text-ink">{ingestModeLabel}</p></div>
            <div className="rounded-2xl border border-line bg-panel/50 px-3 py-2"><p className="font-mono text-[11px] uppercase tracking-[0.16em] text-muted">Artifacts</p><p className="mt-1 text-sm text-ink">{artifactsDone} / {String(data?.metadata_json?.artifacts_total ?? 0)}</p></div>
            <div className="rounded-2xl border border-line bg-panel/50 px-3 py-2"><p className="font-mono text-[11px] uppercase tracking-[0.16em] text-muted">Failed</p><p className="mt-1 text-sm text-ink">{artifactsFailed}</p></div>
            <div className="rounded-2xl border border-line bg-panel/50 px-3 py-2"><p className="font-mono text-[11px] uppercase tracking-[0.16em] text-muted">Indexed docs</p><p className="mt-1 text-sm text-ink">{String(data?.metadata_json?.events_indexed ?? manifest?.stats?.indexed_events ?? 0)}</p></div>
            <div className="rounded-2xl border border-line bg-panel/50 px-3 py-2"><p className="font-mono text-[11px] uppercase tracking-[0.16em] text-muted">Last progress</p><p className="mt-1 text-sm text-ink">{lastProgressAgeLabel}</p></div>
            <div className="rounded-2xl border border-line bg-panel/50 px-3 py-2"><p className="font-mono text-[11px] uppercase tracking-[0.16em] text-muted">Current artifact</p><p className="mt-1 truncate text-sm text-ink" title={String(data?.metadata_json?.current_artifact ?? effectiveCurrentArtifactPath ?? "-")}>{String(data?.metadata_json?.current_artifact ?? effectiveCurrentArtifactPath ?? "-")}</p></div>
          </div> : null}
          <div className="mt-3 grid gap-3 md:grid-cols-2 xl:grid-cols-4">
            <div className="rounded-2xl border border-line bg-panel/40 px-4 py-3 text-sm text-muted">
              <p className="font-mono text-[11px] uppercase tracking-[0.16em] text-accent">Activity</p>
              <p className="mt-1 font-semibold text-ink">{recentActivityState}</p>
              <p className="mt-1 text-xs text-muted">{recentActivityDetail}</p>
            </div>
            <div className="rounded-2xl border border-line bg-panel/40 px-4 py-3 text-sm text-muted">
              <p className="font-mono text-[11px] uppercase tracking-[0.16em] text-accent">Extractor</p>
              <p className="mt-1 font-semibold text-ink">{String(data?.metadata_json?.extractor_used ?? "-").replaceAll("_", " ")}</p>
              <p className="mt-1 text-xs text-muted">Phase timings are tracked in metadata while the run is active.</p>
            </div>
            <div className="rounded-2xl border border-line bg-panel/40 px-4 py-3 text-sm text-muted">
              <p className="font-mono text-[11px] uppercase tracking-[0.16em] text-accent">Effective plan</p>
              <p className="mt-1 font-semibold text-ink">{modeEffectivePlan?.ingest_mode ? String(modeEffectivePlan.ingest_mode).replaceAll("_", " ") : ingestModeLabel}</p>
              <p className="mt-1 text-xs text-muted">{skippedFeatures.length ? `Skipped: ${skippedFeatures.join(", ").replaceAll("_", " ")}` : "No heavy features skipped in this mode."}</p>
            </div>
            <div className="rounded-2xl border border-line bg-panel/40 px-4 py-3 text-sm text-muted">
              <p className="font-mono text-[11px] uppercase tracking-[0.16em] text-accent">Artifact scope</p>
              <p className="mt-1 font-semibold text-ink">{enabledArtifactCategories.length || selectedArtifactTypes.length || 0} categories</p>
              <p className="mt-1 text-xs text-muted">
                {(enabledArtifactCategories.length ? enabledArtifactCategories : selectedArtifactTypes).slice(0, 4).join(", ") || "Not scoped by category"}
              </p>
            </div>
          </div>
        </div>

        <div className="mt-3 grid gap-4 xl:grid-cols-[minmax(0,1.2fr)_minmax(0,1fr)]">
          <div className="rounded-3xl border border-line bg-panel/60 p-4">
            <div className="flex flex-wrap items-center justify-between gap-3">
              <div>
                <p className="font-mono text-[11px] uppercase tracking-[0.16em] text-accent">Core flow</p>
                <p className="mt-1 text-sm text-muted">Evidence → Usable Search ingest → Search/Timeline. Index data first, then decide which advanced modules to run.</p>
              </div>
              <span className="rounded-full border border-accent/30 bg-accent/10 px-3 py-1 font-mono text-[11px] uppercase tracking-[0.16em] text-accent">
                {String(onDemandModulesQuery.data?.core_flow.recommended_ingest_mode ?? (data?.metadata_json?.ingest_mode ?? "usable_search")).replaceAll("_", " ")}
              </span>
            </div>
            <div className="mt-4 grid gap-3 md:grid-cols-2">
              {coreActions.map((action) => (
                <Link key={action.id} to={action.href} className="rounded-2xl border border-line bg-abyss/70 px-4 py-3 text-sm text-muted transition hover:border-accent hover:text-ink">
                  <p className="font-medium text-ink">{action.label}</p>
                  <p className="mt-1 text-xs text-muted">{action.description}</p>
                </Link>
              ))}
            </div>
            <div className="mt-4 grid gap-3 md:grid-cols-3">
              <div className="rounded-2xl border border-line bg-abyss/50 px-4 py-3 text-sm text-muted">
                <p className="font-mono text-[11px] uppercase tracking-[0.16em] text-muted">{activeIndexingJob ? "Indexed documents" : "Indexed documents"}</p>
                <p className={`${activeIndexingJob ? "text-sm" : "text-lg"} mt-1 font-semibold text-ink`}>{activeIndexingJob ? "See live progress" : (searchSummaryQuery.data?.total_indexed_docs ?? 0)}</p>
              </div>
              <div className="rounded-2xl border border-line bg-abyss/50 px-4 py-3 text-sm text-muted">
                <p className="font-mono text-[11px] uppercase tracking-[0.16em] text-muted">Latest ingest</p>
                <p className="mt-1 text-lg font-semibold text-ink">{data?.ingest_status ?? "-"}</p>
              </div>
              <div className="rounded-2xl border border-line bg-abyss/50 px-4 py-3 text-sm text-muted">
                <p className="font-mono text-[11px] uppercase tracking-[0.16em] text-muted">Artifact types ready</p>
                <p className="mt-1 text-lg font-semibold text-ink">{Object.keys(searchSummaryQuery.data?.artifact_type_counts ?? {}).length || indexedArtifactTypeCounts.length}</p>
              </div>
            </div>
            <div className="mt-4 grid gap-3 md:grid-cols-2">
              <div className="rounded-2xl border border-line bg-abyss/50 px-4 py-3 text-sm text-muted">
                <p className="font-mono text-[11px] uppercase tracking-[0.16em] text-muted">Host provided by user</p>
                <p className="mt-1 text-lg font-semibold text-ink">{data?.provided_host ?? "-"}</p>
              </div>
              <div className="rounded-2xl border border-line bg-abyss/50 px-4 py-3 text-sm text-muted">
                <p className="font-mono text-[11px] uppercase tracking-[0.16em] text-muted">Host detected</p>
                <p className="mt-1 text-lg font-semibold text-ink">{data?.detected_host ?? "-"}</p>
              </div>
            </div>
            {indexedArtifactTypeCounts.length ? (
              <div className="mt-4">
                <p className="font-mono text-[11px] uppercase tracking-[0.16em] text-muted">Search by artifact type</p>
                <div className="mt-2 flex flex-wrap gap-2">
                  {indexedArtifactTypeCounts.map(([artifactType, count]) => (
                    <Link
                      key={artifactType}
                      to={data?.case_id ? `/cases/${data.case_id}/search?evidence_id=${encodeURIComponent(evidenceId)}&artifact_type=${encodeURIComponent(artifactType)}&tab=results` : "#"}
                      className="rounded-full border border-line bg-abyss/70 px-3 py-1 text-xs text-muted transition hover:border-accent hover:text-ink"
                    >
                      {artifactType} · {count}
                    </Link>
                  ))}
                </div>
              </div>
            ) : null}
            {indexedParserCounts.length ? (
              <div className="mt-4">
                <p className="font-mono text-[11px] uppercase tracking-[0.16em] text-muted">Search by parser backend</p>
                <div className="mt-2 flex flex-wrap gap-2">
                  {indexedParserCounts.map(([parserName, count]) => (
                    <Link
                      key={parserName}
                      to={data?.case_id ? `/cases/${data.case_id}/search?evidence_id=${encodeURIComponent(evidenceId)}&parser=${encodeURIComponent(parserName)}&tab=results` : "#"}
                      className="rounded-full border border-line bg-abyss/70 px-3 py-1 text-xs text-muted transition hover:border-accent hover:text-ink"
                    >
                      {parserName} · {count}
                    </Link>
                  ))}
                </div>
              </div>
            ) : null}
          </div>

          <div className="rounded-3xl border border-line bg-panel/60 p-4">
            <p className="font-mono text-[11px] uppercase tracking-[0.16em] text-accent">On-demand modules</p>
            <p className="mt-1 text-sm text-muted">Stable follow-up actions run only when you launch them manually after data is already indexed.</p>
            <div className="mt-4 space-y-3">
              {stableOnDemandEntries.map((entry) => {
                if (entry.id === "rules") {
                  return (
                    <div key={entry.id} className="rounded-2xl border border-line bg-abyss/70 px-4 py-3 text-sm">
                      <div className="flex flex-wrap items-center justify-between gap-2">
                        <p className="font-medium text-ink">{entry.label}</p>
                        <span className="rounded-full border border-line px-2 py-0.5 font-mono text-[10px] uppercase tracking-[0.14em] text-muted">{entry.badge ?? entry.status}</span>
                      </div>
                      <p className="mt-1 text-xs text-muted">{entry.description}</p>
                      {entry.warning ? <p className="mt-2 text-xs text-accent">{entry.warning}</p> : null}
                      {entry.disabled_reason ? <p className="mt-2 text-xs text-amber">{entry.disabled_reason}</p> : null}
                      <div className="mt-3 flex flex-wrap items-center gap-2">
                        <label className="text-xs text-muted" htmlFor="rules-engine-selection">
                          Engine
                        </label>
                        <select
                          id="rules-engine-selection"
                          value={rulesEngineSelection}
                          onChange={(event) => setRulesEngineSelection(event.target.value as "sigma" | "yara" | "all")}
                          disabled={rulesLaunchDisabled}
                          className="rounded-full border border-line bg-panel px-3 py-1 text-xs text-ink disabled:opacity-60"
                        >
                          <option value="sigma">Sigma</option>
                          <option value="yara">YARA</option>
                          <option value="all">All</option>
                        </select>
                        <button
                          type="button"
                          onClick={() => onDemandRulesMutation.mutate()}
                          disabled={rulesLaunchDisabled}
                          className="rounded-full border border-line bg-panel px-3 py-1 font-mono text-[11px] uppercase tracking-[0.14em] text-ink disabled:opacity-60"
                        >
                          {onDemandRulesMutation.isPending ? "Launching..." : activeEvidenceRuleRun ? "Run in progress" : "Run now"}
                        </button>
                        {rulesWorkspaceHref !== "#" ? (
                          <Link to={rulesWorkspaceHref} className="rounded-full border border-line bg-transparent px-3 py-1 font-mono text-[11px] uppercase tracking-[0.14em] text-muted transition hover:border-accent hover:text-ink">
                            Open rules workspace
                          </Link>
                        ) : null}
                      </div>
                      {latestEvidenceRuleRun ? (
                        <div className="mt-3 rounded-2xl border border-line bg-panel/60 px-3 py-3 text-xs text-muted">
                          <div className="flex flex-wrap items-center justify-between gap-2">
                            <p className="font-mono uppercase tracking-[0.14em] text-muted">Latest rules run</p>
                            <span className="rounded-full border border-line px-2 py-0.5 font-mono uppercase tracking-[0.14em] text-muted">
                              {formatRuleRunStatus(latestEvidenceRuleRun.status)}
                            </span>
                          </div>
                          <div className="mt-2 grid gap-2 md:grid-cols-2">
                            <p>Run ID: <span className="text-ink">{latestEvidenceRuleRun.id}</span></p>
                            <p>Detections created: <span className="text-ink">{latestEvidenceRuleRun.created_detections ?? 0}</span></p>
                            <p>Rules processed: <span className="text-ink">{latestEvidenceRuleRun.processed_rules ?? 0}/{latestEvidenceRuleRun.total_rules ?? 0}</span></p>
                            <p>Events scanned: <span className="text-ink">{latestEvidenceRuleRun.scanned_events ?? 0}</span></p>
                          </div>
                          {latestEvidenceRuleRun.current_phase ? <p className="mt-2">Phase: <span className="text-ink">{latestEvidenceRuleRun.current_phase}</span></p> : null}
                          {latestEvidenceRuleRun.last_error ? <p className="mt-2 text-amber">{latestEvidenceRuleRun.last_error}</p> : null}
                          <div className="mt-3 flex flex-wrap items-center gap-2">
                            {ruleRunDetectionsHref !== "#" ? (
                              <Link to={ruleRunDetectionsHref} className="rounded-full border border-line bg-transparent px-3 py-1 font-mono text-[11px] uppercase tracking-[0.14em] text-muted transition hover:border-accent hover:text-ink">
                                View detections
                              </Link>
                            ) : null}
                            {latestEvidenceRuleRun.can_retry && rulesWorkspaceHref !== "#" ? (
                              <Link to={rulesWorkspaceHref} className="rounded-full border border-line bg-transparent px-3 py-1 font-mono text-[11px] uppercase tracking-[0.14em] text-muted transition hover:border-accent hover:text-ink">
                                Open previous runs
                              </Link>
                            ) : null}
                          </div>
                        </div>
                      ) : (
                        <p className="mt-3 text-xs text-muted">No on-demand rules runs yet. Rules execute against already indexed data and do not reprocess the evidence.</p>
                      )}
                    </div>
                  );
                }
                if (entry.id === "reports") {
                  return (
                    <div key={entry.id} className="rounded-2xl border border-line bg-abyss/70 px-4 py-3 text-sm">
                      <div className="flex flex-wrap items-center justify-between gap-2">
                        <p className="font-medium text-ink">{entry.label}</p>
                        <span className="rounded-full border border-line px-2 py-0.5 font-mono text-[10px] uppercase tracking-[0.14em] text-muted">{entry.badge ?? entry.status}</span>
                      </div>
                      <p className="mt-1 text-xs text-muted">Generates a summary from already indexed data. This does not reprocess evidence.</p>
                      {entry.warning ? <p className="mt-2 text-xs text-accent">{entry.warning}</p> : null}
                      {entry.disabled_reason ? <p className="mt-2 text-xs text-amber">{entry.disabled_reason}</p> : null}
                      <div className="mt-3 flex flex-wrap items-center gap-2">
                        <button
                          type="button"
                          onClick={() => generateReportMutation.mutate()}
                          disabled={reportLaunchDisabled}
                          className="rounded-full border border-line bg-panel px-3 py-1 font-mono text-[11px] uppercase tracking-[0.14em] text-ink disabled:opacity-60"
                        >
                          {generateReportMutation.isPending ? "Generating..." : activeEvidenceReport ? "Report in progress" : "Generate summary"}
                        </button>
                        {latestEvidenceReport ? (
                          <>
                            <button
                              type="button"
                              onClick={() => void handleDownloadReport(latestEvidenceReport.id, (latestEvidenceReport.format as "json" | "markdown" | "html" | undefined) ?? "markdown")}
                              className="rounded-full border border-line bg-transparent px-3 py-1 font-mono text-[11px] uppercase tracking-[0.14em] text-muted transition hover:border-accent hover:text-ink"
                            >
                              Download
                            </button>
                            <button
                              type="button"
                              onClick={() => void handleDownloadReport(latestEvidenceReport.id, "json")}
                              className="rounded-full border border-line bg-transparent px-3 py-1 font-mono text-[11px] uppercase tracking-[0.14em] text-muted transition hover:border-accent hover:text-ink"
                            >
                              Download JSON
                            </button>
                          </>
                        ) : null}
                        {reportsWorkspaceHref !== "#" ? (
                          <Link to={reportsWorkspaceHref} className="rounded-full border border-line bg-transparent px-3 py-1 font-mono text-[11px] uppercase tracking-[0.14em] text-muted transition hover:border-accent hover:text-ink">
                            Open reports workspace
                          </Link>
                        ) : null}
                      </div>
                      {latestEvidenceReport ? (
                        <div className="mt-3 rounded-2xl border border-line bg-panel/60 px-3 py-3 text-xs text-muted">
                          <div className="flex flex-wrap items-center justify-between gap-2">
                            <p className="font-mono uppercase tracking-[0.14em] text-muted">Latest report</p>
                            <span className="rounded-full border border-line px-2 py-0.5 font-mono uppercase tracking-[0.14em] text-muted">
                              {formatReportStatus(latestEvidenceReport.status)}
                            </span>
                          </div>
                          <div className="mt-2 grid gap-2 md:grid-cols-2">
                            <p>Report ID: <span className="text-ink">{latestEvidenceReport.id}</span></p>
                            <p>Format: <span className="text-ink">{latestEvidenceReport.format ?? "markdown"}</span></p>
                            <p>Type: <span className="text-ink">{latestEvidenceReport.report_type ?? "summary"}</span></p>
                            <p>Size: <span className="text-ink">{latestEvidenceReport.size_bytes ?? 0} bytes</span></p>
                          </div>
                          {Array.isArray(latestEvidenceReport.metadata_json?.warnings) && latestEvidenceReport.metadata_json?.warnings.length ? (
                            <p className="mt-2 text-amber">{String((latestEvidenceReport.metadata_json?.warnings as unknown[]).join(" | "))}</p>
                          ) : null}
                        </div>
                      ) : (
                        <p className="mt-3 text-xs text-muted">No on-demand reports yet. Reports summarize indexed data and remain separate from the ingest path.</p>
                      )}
                    </div>
                  );
                }
              })}
            </div>
            <div className="mt-6 rounded-2xl border border-amber/20 bg-amber/5 p-4">
              <div className="flex flex-wrap items-center justify-between gap-2">
                <div>
                  <p className="font-mono text-[11px] uppercase tracking-[0.16em] text-amber">Advanced / Beta</p>
                  <p className="mt-1 text-sm text-muted">Potentially slower, noisier or debugging-oriented paths. These do not run automatically from usable_search.</p>
                </div>
                <span className="rounded-full border border-amber/30 bg-amber/10 px-3 py-1 font-mono text-[11px] uppercase tracking-[0.16em] text-amber">Use only when needed</span>
              </div>
              <div className="mt-4 space-y-3">
                {advancedEntries.map((entry) => {
                  const href = entry.case_route || entry.evidence_route || "#";
                  const actionable = entry.status !== "disabled" && href !== "#";
                  const content = (
                    <>
                      <div className="flex flex-wrap items-center justify-between gap-2">
                        <p className="font-medium text-ink">{entry.label}</p>
                        <span className="rounded-full border border-line px-2 py-0.5 font-mono text-[10px] uppercase tracking-[0.14em] text-muted">{entry.badge ?? entry.status}</span>
                      </div>
                      <p className="mt-1 text-xs text-muted">{entry.description}</p>
                      {entry.warning ? <p className="mt-2 text-xs text-amber">{entry.warning}</p> : null}
                      {entry.disabled_reason ? <p className="mt-2 text-xs text-amber">{entry.disabled_reason}</p> : null}
                    </>
                  );
                  return actionable ? (
                    <Link key={entry.id} to={href} className="block rounded-2xl border border-line bg-abyss/70 px-4 py-3 text-sm transition hover:border-amber hover:text-ink">
                      {content}
                    </Link>
                  ) : (
                    <div key={entry.id} className="rounded-2xl border border-line bg-abyss/40 px-4 py-3 text-sm opacity-80">
                      {content}
                    </div>
                  );
                })}
              </div>
            </div>
          </div>
        </div>

        <div className="mt-3 rounded-3xl border border-line bg-panel/60 p-4 text-sm text-muted">
          <div className="grid gap-3 md:grid-cols-2 xl:grid-cols-4">
            <div>
              <p className="font-mono text-[11px] uppercase tracking-[0.16em] text-muted">Storage mode</p>
              <p className="mt-1 text-ink">{storageMode}</p>
            </div>
            <div>
              <p className="font-mono text-[11px] uppercase tracking-[0.16em] text-muted">External</p>
              <p className="mt-1 text-ink">{String(data?.is_external ?? false)}</p>
            </div>
            <div>
              <p className="font-mono text-[11px] uppercase tracking-[0.16em] text-muted">Copy to storage</p>
              <p className="mt-1 text-ink">{String(data?.copy_to_storage ?? true)}</p>
            </div>
            <div>
              <p className="font-mono text-[11px] uppercase tracking-[0.16em] text-muted">File count</p>
              <p className="mt-1 text-ink">{data?.file_count ?? "-"}</p>
            </div>
          </div>
          <div className="mt-3 grid gap-3 xl:grid-cols-2">
            <div>
              <p className="font-mono text-[11px] uppercase tracking-[0.16em] text-muted">Original path</p>
              <p className="mt-1 break-all text-ink">{originalPath}</p>
            </div>
            <div>
              <p className="font-mono text-[11px] uppercase tracking-[0.16em] text-muted">Storage path</p>
              <p className="mt-1 break-all text-ink">{storagePath}</p>
            </div>
          </div>
        </div>

        <div className="mt-3 rounded-3xl border border-line bg-panel/60 p-4 text-sm text-muted">
          <div className="flex flex-wrap items-center justify-between gap-3">
            <div>
              <p className="font-mono text-[11px] uppercase tracking-[0.16em] text-accent">Ingest plan</p>
              <p className="mt-1 text-sm text-muted">
                {lastSuccessfulIngestPlan
                  ? "Reprocess reuses this stored parser selection by default."
                  : "No ingest plan is stored for this evidence yet."}
              </p>
            </div>
            {lastSuccessfulIngestPlan ? (
              <span className="rounded-full border border-line px-3 py-1 font-mono text-[11px] uppercase tracking-[0.16em] text-muted">
                {String(lastSuccessfulIngestPlan.discovery_mode ?? "previous_selection")}
              </span>
            ) : null}
          </div>
          {lastSuccessfulIngestPlan ? (
            <div className="mt-3 grid gap-3 md:grid-cols-2 xl:grid-cols-4">
              <div className="rounded-2xl border border-line bg-abyss/60 px-3 py-2">
                <p className="font-mono text-[11px] uppercase tracking-[0.16em] text-muted">Last successful selected</p>
                <p className="mt-1 text-sm text-ink">{Array.isArray(lastSuccessfulIngestPlan.selected_candidates) ? lastSuccessfulIngestPlan.selected_candidates.length : 0}</p>
              </div>
              <div className="rounded-2xl border border-line bg-abyss/60 px-3 py-2">
                <p className="font-mono text-[11px] uppercase tracking-[0.16em] text-muted">Disabled candidates</p>
                <p className="mt-1 text-sm text-ink">{Array.isArray(lastSuccessfulIngestPlan.disabled_candidates) ? lastSuccessfulIngestPlan.disabled_candidates.length : 0}</p>
              </div>
              <div className="rounded-2xl border border-line bg-abyss/60 px-3 py-2">
                <p className="font-mono text-[11px] uppercase tracking-[0.16em] text-muted">Last run summary</p>
                <p className="mt-1 text-sm text-ink">{String((lastSuccessfulIngestPlan.last_reprocess_summary as { parsed_candidates?: number } | undefined)?.parsed_candidates ?? "-")} parsed</p>
              </div>
              <div className="rounded-2xl border border-line bg-abyss/60 px-3 py-2">
                <p className="font-mono text-[11px] uppercase tracking-[0.16em] text-muted">Updated</p>
                <p className="mt-1 text-sm text-ink">{typeof lastSuccessfulIngestPlan.updated_at === "string" ? lastSuccessfulIngestPlan.updated_at : "-"}</p>
              </div>
            </div>
          ) : null}
        </div>

        <div className="mt-5 rounded-3xl border border-line bg-abyss/70 p-4">
          {!activeIndexingJob ? (
            <>
          <div className="mb-3 flex items-center justify-between gap-4">
            <div>
              <p className="font-mono text-[11px] uppercase tracking-[0.18em] text-accent">Progress</p>
              <p className="mt-1 text-sm text-muted">Current phase: {currentPhase}</p>
              {showExtractingSelected ? <p className="mt-1 text-xs text-muted">Preparing selected artifacts before parser workers start.</p> : null}
              {currentItem ? <p className="mt-1 max-w-[720px] truncate text-xs text-muted" title={currentItem}>Current item: {currentItem}</p> : null}
              {currentSelectedPath ? <p className="mt-1 max-w-[720px] truncate text-xs text-muted" title={currentSelectedPath}>Current selected file: {currentSelectedPath}</p> : null}
              {currentAction ? <p className="mt-1 text-xs text-muted">Current action: {currentAction}</p> : null}
              {effectiveCurrentArtifactPath ? <p className="mt-1 max-w-[720px] truncate text-xs text-muted" title={effectiveCurrentArtifactPath}>Current artifact: {effectiveCurrentArtifactPath}</p> : null}
              {effectiveCurrentArtifactLabel ? <p className="mt-1 text-xs text-muted">Current artifact progress: {effectiveCurrentArtifactLabel}</p> : null}
              {parallelIngest ? (
                <p className="mt-1 text-xs text-muted">
                  Parallel artifact ingest {parallelIngest.enabled ? "enabled" : "disabled"} · effective parallelism {parallelIngest.effective_parallelism ?? 1}
                  {parallelIngest.limitation_reason ? ` · ${parallelIngest.limitation_reason}` : ""}
                </p>
              ) : null}
              {showMissingProgressWarning ? (
                <p className="mt-2 rounded-xl border border-amber-500/40 bg-amber-500/10 px-3 py-2 text-xs text-amber-100">
                  Worker heartbeat is alive but progress metadata is missing. The job may still be running, but the backend is not reporting artifact progress correctly yet.
                </p>
              ) : null}
              {showExtractionStallWarning ? (
                <p className="mt-2 rounded-xl border border-amber-500/40 bg-amber-500/10 px-3 py-2 text-xs text-amber-100">
                  No extraction progress detected yet. The worker is still preparing selected artifacts before parsing can start.
                </p>
              ) : null}
            </div>
            <p className="font-mono text-lg text-ink">{progressPct}%</p>
          </div>
          <div className="h-3 overflow-hidden rounded-full bg-panel">
            <div className="h-full rounded-full bg-accent transition-all duration-500" style={{ width: `${progressPct}%` }} />
          </div>
          <div className="mt-3 grid gap-3 md:grid-cols-3 xl:grid-cols-8">
            <div className="rounded-2xl border border-line bg-panel/50 px-3 py-2"><p className="font-mono text-[11px] uppercase tracking-[0.16em] text-muted">Artifacts</p><p className="mt-1 text-sm text-ink">{String(artifactsDone)} / {String(data?.metadata_json?.artifacts_total ?? 0)}</p></div>
            <div className="rounded-2xl border border-line bg-panel/50 px-3 py-2"><p className="font-mono text-[11px] uppercase tracking-[0.16em] text-muted">Indexed events</p><p className="mt-1 text-sm text-ink">{String(data?.metadata_json?.events_indexed ?? manifest?.stats?.indexed_events ?? 0)}</p></div>
            <div className="rounded-2xl border border-line bg-panel/50 px-3 py-2"><p className="font-mono text-[11px] uppercase tracking-[0.16em] text-muted">Records/sec</p><p className="mt-1 text-sm text-ink">{String(data?.metadata_json?.records_per_second ?? "-")}</p></div>
            <div className="rounded-2xl border border-line bg-panel/50 px-3 py-2"><p className="font-mono text-[11px] uppercase tracking-[0.16em] text-muted">Current artifact records</p><p className="mt-1 text-sm text-ink">{currentArtifactRecordsRead ?? "-"}</p></div>
            <div className="rounded-2xl border border-line bg-panel/50 px-3 py-2"><p className="font-mono text-[11px] uppercase tracking-[0.16em] text-muted">Current indexed</p><p className="mt-1 text-sm text-ink">{currentArtifactRecordsIndexed ?? "-"}</p></div>
            <div className="rounded-2xl border border-line bg-panel/50 px-3 py-2"><p className="font-mono text-[11px] uppercase tracking-[0.16em] text-muted">Elapsed</p><p className="mt-1 text-sm text-ink">{formatDuration(displayedElapsedSeconds)}</p></div>
            <div className="rounded-2xl border border-line bg-panel/50 px-3 py-2"><p className="font-mono text-[11px] uppercase tracking-[0.16em] text-muted">Heartbeat age</p><p className="mt-1 text-sm text-ink">{formatHeartbeatAge(heartbeatAt)}</p></div>
            <div className="rounded-2xl border border-line bg-panel/50 px-3 py-2"><p className="font-mono text-[11px] uppercase tracking-[0.16em] text-muted">Artifacts failed</p><p className="mt-1 text-sm text-ink">{artifactsFailed}</p></div>
            <div className="rounded-2xl border border-line bg-panel/50 px-3 py-2"><p className="font-mono text-[11px] uppercase tracking-[0.16em] text-muted">Raw not parsed</p><p className="mt-1 text-sm text-ink">{String(data?.metadata_json?.raw_artifacts_not_parsed ?? manifest?.stats?.raw_artifacts_not_parsed ?? 0)}</p></div>
            <div className="rounded-2xl border border-line bg-panel/50 px-3 py-2"><p className="font-mono text-[11px] uppercase tracking-[0.16em] text-muted">Detected host</p><p className="mt-1 text-sm text-ink">{data?.detected_host ?? "-"}</p></div>
            {parallelIngest ? <div className="rounded-2xl border border-line bg-panel/50 px-3 py-2"><p className="font-mono text-[11px] uppercase tracking-[0.16em] text-muted">Effective parallelism</p><p className="mt-1 text-sm text-ink">{parallelIngest.effective_parallelism ?? 1} / {parallelIngest.desired_parallelism ?? parallelIngest.effective_parallelism ?? 1}</p></div> : null}
            {parallelIngest ? <div className="rounded-2xl border border-line bg-panel/50 px-3 py-2"><p className="font-mono text-[11px] uppercase tracking-[0.16em] text-muted">Running artifact types</p><p className="mt-1 text-sm text-ink">{(parallelIngest.running_artifact_types ?? []).filter(Boolean).join(", ") || "-"}</p></div> : null}
            {parallelIngest ? <div className="rounded-2xl border border-line bg-panel/50 px-3 py-2"><p className="font-mono text-[11px] uppercase tracking-[0.16em] text-muted">Queued parallel</p><p className="mt-1 text-sm text-ink">{parallelIngest.queued_artifacts ?? 0}</p></div> : null}
            {parallelIngest ? <div className="rounded-2xl border border-line bg-panel/50 px-3 py-2"><p className="font-mono text-[11px] uppercase tracking-[0.16em] text-muted">Bottleneck</p><p className="mt-1 text-sm text-ink">{parallelIngest.bottleneck ?? "-"}</p></div> : null}
            {showExtractingSelected ? <div className="rounded-2xl border border-line bg-panel/50 px-3 py-2"><p className="font-mono text-[11px] uppercase tracking-[0.16em] text-muted">Selected files</p><p className="mt-1 text-sm text-ink">{selectedFilesProcessed ?? "-"} / {selectedFilesTotal ?? "-"}</p></div> : null}
            {showExtractingSelected ? <div className="rounded-2xl border border-line bg-panel/50 px-3 py-2"><p className="font-mono text-[11px] uppercase tracking-[0.16em] text-muted">Extraction rate</p><p className="mt-1 text-sm text-ink">{extractionRateFiles !== null ? `${extractionRateFiles} files/s` : "-"}</p></div> : null}
            {showExtractingSelected ? <div className="rounded-2xl border border-line bg-panel/50 px-3 py-2"><p className="font-mono text-[11px] uppercase tracking-[0.16em] text-muted">Transfer rate</p><p className="mt-1 text-sm text-ink">{extractionRateMb !== null ? `${extractionRateMb} MB/s` : "-"}</p></div> : null}
            {showExtractingSelected ? <div className="rounded-2xl border border-line bg-panel/50 px-3 py-2"><p className="font-mono text-[11px] uppercase tracking-[0.16em] text-muted">Staging reuse</p><p className="mt-1 text-sm text-ink">{filesSkippedExisting ?? 0} reused / {filesMaterialized ?? 0} ready</p></div> : null}
            {showExtractingSelected ? <div className="rounded-2xl border border-line bg-panel/50 px-3 py-2"><p className="font-mono text-[11px] uppercase tracking-[0.16em] text-muted">Extraction errors</p><p className="mt-1 text-sm text-ink">{extractionErrors ?? 0}</p></div> : null}
          </div>
            </>
          ) : (
            <div className="rounded-2xl border border-line bg-panel/30 px-3 py-3 text-sm text-muted">
              <p className="font-mono text-[11px] uppercase tracking-[0.16em] text-accent">Worker diagnostics</p>
              <p className="mt-1">Detailed scheduler, long-tail and extraction diagnostics are shown here without repeating the live progress summary.</p>
              {parallelIngest ? (
                <p className="mt-1">
                  Effective parallelism {parallelIngest.effective_parallelism ?? 1} / {parallelIngest.desired_parallelism ?? parallelIngest.effective_parallelism ?? 1}
                  {typeof parallelIngest.queued_artifacts === "number" ? ` · Queued parallel ${parallelIngest.queued_artifacts}` : ""}
                  {parallelIngest.bottleneck ? ` · Bottleneck ${parallelIngest.bottleneck}` : ""}
                </p>
              ) : null}
              {showExtractingSelected ? (
                <p className="mt-1">
                  Selected files {selectedFilesProcessed ?? "-"} / {selectedFilesTotal ?? "-"}
                  {extractionRateFiles !== null ? ` · ${extractionRateFiles} files/s` : ""}
                  {extractionRateMb !== null ? ` · ${extractionRateMb} MB/s` : ""}
                  {filesSkippedExisting !== null || filesMaterialized !== null ? ` · ${filesSkippedExisting ?? 0} reused / ${filesMaterialized ?? 0} ready` : ""}
                </p>
              ) : null}
            </div>
          )}
          {parallelIngest ? (
            <div className="mt-3 rounded-2xl border border-line bg-panel/30 px-3 py-3 text-sm text-muted">
              <p className="font-mono text-[11px] uppercase tracking-[0.16em] text-accent">Artifact Scheduler</p>
              <p className="mt-1">Parallel-safe queue: {Object.entries(parallelIngest.artifacts_parallelized_by_type ?? {}).map(([key, value]) => `${key} (${value})`).join(", ") || "None"}</p>
              <p className="mt-1">Sequential safety fallback: {Object.entries(parallelIngest.artifacts_sequential_by_type ?? {}).map(([key, value]) => `${key} (${value})`).join(", ") || "None"}</p>
            </div>
          ) : null}
          {hasLongTail ? (
            <div className="mt-3 rounded-2xl border border-line bg-panel/30 px-3 py-3 text-sm text-muted">
              <p className="font-mono text-[11px] uppercase tracking-[0.16em] text-accent">Long-tail artifacts still processing</p>
              <p className="mt-1">
                Running {longTailSummary?.running_count ?? tailArtifactsRunning} · queued {longTailSummary?.queued_count ?? tailArtifactsQueued} · remaining {longTailSummary?.tail_artifacts_total ?? tailArtifactsTotal}
                {tailLastProgressAt ? ` · last progress ${formatHeartbeatAge(tailLastProgressAt)} ago` : ""}
              </p>
              {(tailRecordsRead !== null || tailRecordsIndexed !== null) ? (
                <p className="mt-1">Tail progress: {tailRecordsRead ?? 0} records read / {tailRecordsIndexed ?? 0} indexed</p>
              ) : null}
              {longTailSummary ? (
                <p className="mt-1">
                  High-value {longTailSummary.high_value_count} · partial indexed {longTailSummary.partial_indexed_count} · stalled {longTailSummary.stalled_count}
                </p>
              ) : null}
              <div className="mt-3 space-y-2">
                {(longTailArtifacts.length ? longTailArtifacts : tailCurrentArtifacts).slice(0, 6).map((artifact, index) => (
                  <div key={`${String((artifact as Record<string, unknown>).artifact_id ?? (artifact as Record<string, unknown>).artifact ?? "artifact")}-${index}`} className="rounded-2xl border border-line bg-abyss/60 px-3 py-2">
                    <div className="flex flex-wrap items-center justify-between gap-2">
                      <p className="break-all text-ink">{String((artifact as Record<string, unknown>).source_path ?? (artifact as Record<string, unknown>).artifact ?? "-")}</p>
                      <div className="flex flex-wrap gap-2 text-[11px] uppercase tracking-[0.14em]">
                        <span className="rounded-full border border-line px-2 py-0.5 text-muted">{String((artifact as Record<string, unknown>).long_tail_state ?? "active_progressing").replaceAll("_", " ")}</span>
                        {String((artifact as Record<string, unknown>).importance ?? "") === "high" ? <span className="rounded-full border border-amber-400/40 px-2 py-0.5 text-amber-200">High value</span> : null}
                      </div>
                    </div>
                    <p className="mt-1 text-xs text-muted">
                      {String((artifact as Record<string, unknown>).parser ?? (artifact as Record<string, unknown>).artifact_type ?? "unknown")} · {Number((artifact as Record<string, unknown>).records_read ?? 0)} read / {Number((artifact as Record<string, unknown>).records_indexed ?? 0)} indexed
                      {typeof (artifact as Record<string, unknown>).elapsed_seconds === "number" ? ` · ${Number((artifact as Record<string, unknown>).elapsed_seconds).toFixed(0)}s elapsed` : ""}
                      {typeof (artifact as Record<string, unknown>).no_progress_seconds === "number" ? ` · ${Number((artifact as Record<string, unknown>).no_progress_seconds).toFixed(0)}s since progress` : ""}
                    </p>
                    {Boolean((artifact as Record<string, unknown>).partial_coverage_warning) ? <p className="mt-1 text-xs text-amber-200">Partial coverage warning: indexed events are preserved but the artifact has not completed yet.</p> : null}
                    {Boolean((artifact as Record<string, unknown>).defer_recommended) ? <p className="mt-1 text-xs text-amber-200">Defer is recommended if you want to finish the main ingest and retry this artifact later in deep safe mode.</p> : null}
                    {Boolean((artifact as Record<string, unknown>).artifact_id) ? (
                      <div className="mt-2">
                        <button
                          type="button"
                          onClick={() => deferLongTailMutation.mutate({ artifactId: String((artifact as Record<string, unknown>).artifact_id) })}
                          disabled={deferLongTailMutation.isPending}
                          className="rounded-xl border border-line px-3 py-1 text-xs text-ink transition hover:border-accent hover:text-accent disabled:cursor-not-allowed disabled:opacity-60"
                        >
                          Defer and finish later
                        </button>
                      </div>
                    ) : null}
                  </div>
                ))}
              </div>
            </div>
          ) : null}
          {(isActive || selectionPending) && (etaSeconds !== null || discoveryFilesScanned !== null || discoveryCandidatesDetected !== null || totalZipEntries !== null || selectedFilesTotal !== null) ? (
            <div className="mt-3 grid gap-3 md:grid-cols-3 xl:grid-cols-6">
              <div className="rounded-2xl border border-line bg-panel/50 px-3 py-2">
                <p className="font-mono text-[11px] uppercase tracking-[0.16em] text-muted">ETA</p>
                <p className="mt-1 text-sm text-ink">{formatDuration(etaSeconds)}</p>
              </div>
              <div className="rounded-2xl border border-line bg-panel/50 px-3 py-2">
                <p className="font-mono text-[11px] uppercase tracking-[0.16em] text-muted">Total ZIP entries</p>
                <p className="mt-1 text-sm text-ink">{totalZipEntries ?? "-"}</p>
              </div>
              <div className="rounded-2xl border border-line bg-panel/50 px-3 py-2">
                <p className="font-mono text-[11px] uppercase tracking-[0.16em] text-muted">Ignored entries</p>
                <p className="mt-1 text-sm text-ink">{ignoredEntries ?? "-"}</p>
              </div>
              <div className="rounded-2xl border border-line bg-panel/50 px-3 py-2">
                <p className="font-mono text-[11px] uppercase tracking-[0.16em] text-muted">Files scanned</p>
                <p className="mt-1 text-sm text-ink">
                  {discoveryFilesScanned !== null ? `${discoveryFilesScanned}` : "-"}
                  {discoveryTotalFiles !== null ? ` / ${discoveryTotalFiles}` : ""}
                </p>
              </div>
              <div className="rounded-2xl border border-line bg-panel/50 px-3 py-2">
                <p className="font-mono text-[11px] uppercase tracking-[0.16em] text-muted">Candidates detected</p>
                <p className="mt-1 text-sm text-ink">{discoveryCandidatesDetected ?? "-"}</p>
              </div>
              <div className="rounded-2xl border border-line bg-panel/50 px-3 py-2">
                <p className="font-mono text-[11px] uppercase tracking-[0.16em] text-muted">Selected files to extract</p>
                <p className="mt-1 text-sm text-ink">{selectedFilesTotal ?? candidateFiles ?? "-"}</p>
              </div>
              <div className="rounded-2xl border border-line bg-panel/50 px-3 py-2">
                <p className="font-mono text-[11px] uppercase tracking-[0.16em] text-muted">Extracted selected files</p>
                <p className="mt-1 text-sm text-ink">{selectedFilesExtracted ?? "-"}</p>
              </div>
            </div>
          ) : null}
        </div>
          </div>
        </details>
      </section>

      <section id="jobs-activity" className="rounded-3xl border border-line bg-panel/70 p-5 shadow-panel">
        <div className="flex flex-wrap items-center justify-between gap-3">
          <div>
            <p className="font-mono text-xs uppercase tracking-[0.18em] text-accent">Ingest &amp; Reprocess Runs</p>
            <p className="mt-1 text-sm text-muted">Track ingest, reprocess and artifact retry execution with status, phase, heartbeat and recent errors.</p>
          </div>
          {latestStartedRunId ? <p className="rounded-full border border-accent/30 bg-accent/10 px-3 py-1 font-mono text-[11px] uppercase tracking-[0.16em] text-accent">Latest requested run {latestStartedRunId}</p> : null}
        </div>
        {latestRun ? (
          <div className="mt-4 rounded-2xl border border-line bg-abyss/70 p-4">
            <div className="flex flex-wrap items-center justify-between gap-3">
              <div>
                <p className="font-mono text-[11px] uppercase tracking-[0.16em] text-muted">{latestRun.run_type} · {latestRun.mode ?? "default"}</p>
                <p className="mt-1 text-sm font-semibold text-ink">{latestRun.run_id}</p>
              </div>
              <span className={`rounded-full border px-3 py-1 font-mono text-[11px] uppercase tracking-[0.16em] ${latestRun.status === "completed" ? "border-mint/30 bg-mint/10 text-mint" : latestRun.status === "completed_with_errors" ? "border-amber/30 bg-amber/10 text-amber" : latestRun.status === "failed" ? "border-danger/30 bg-danger/10 text-danger" : "border-accent/30 bg-accent/10 text-accent"}`}>{latestRun.status}</span>
            </div>
            <div className="mt-4 grid gap-3 md:grid-cols-4">
              <div className="rounded-2xl border border-line bg-panel/40 px-3 py-2"><p className="font-mono text-[11px] uppercase tracking-[0.16em] text-muted">Phase</p><p className="mt-1 text-sm text-ink">{latestRun.phase ?? "-"}</p></div>
              <div className="rounded-2xl border border-line bg-panel/40 px-3 py-2"><p className="font-mono text-[11px] uppercase tracking-[0.16em] text-muted">Progress</p><p className="mt-1 text-sm text-ink">{typeof latestRun.progress === "number" ? `${latestRun.progress}%` : "-"}</p></div>
              <div className="rounded-2xl border border-line bg-panel/40 px-3 py-2"><p className="font-mono text-[11px] uppercase tracking-[0.16em] text-muted">Heartbeat</p><p className="mt-1 text-sm text-ink">{formatHeartbeatAge(latestRun.heartbeat_at ?? null)}</p></div>
              <div className="rounded-2xl border border-line bg-panel/40 px-3 py-2"><p className="font-mono text-[11px] uppercase tracking-[0.16em] text-muted">Elapsed</p><p className="mt-1 text-sm text-ink">{formatDuration(latestRun.elapsed_seconds ?? null)}</p></div>
            </div>
            <div className="mt-3 grid gap-3 md:grid-cols-3">
              <div className="rounded-2xl border border-line bg-panel/40 px-3 py-2"><p className="font-mono text-[11px] uppercase tracking-[0.16em] text-muted">Current artifact</p><p className="mt-1 break-all text-sm text-ink">{latestRun.current_artifact ?? "-"}</p></div>
              <div className="rounded-2xl border border-line bg-panel/40 px-3 py-2"><p className="font-mono text-[11px] uppercase tracking-[0.16em] text-muted">Records</p><p className="mt-1 text-sm text-ink">{latestRun.records_read ?? 0} read / {latestRun.records_indexed ?? 0} indexed</p></div>
              <div className="rounded-2xl border border-line bg-panel/40 px-3 py-2"><p className="font-mono text-[11px] uppercase tracking-[0.16em] text-muted">Artifacts</p><p className="mt-1 text-sm text-ink">{latestRun.artifacts_done ?? 0} / {latestRun.artifacts_total ?? 0} done · {latestRun.artifacts_failed ?? 0} failed</p></div>
            </div>
            {timeoutRunSummary ? <p className="mt-3 rounded-2xl border border-amber/30 bg-amber/10 p-3 text-sm text-amber">{timeoutRunSummary}</p> : latestRun.last_error ? <p className="mt-3 rounded-2xl border border-danger/30 bg-danger/10 p-3 text-sm text-danger">{latestRun.last_error}</p> : null}
            {timeoutRunSummary && indexedEventsCoherent ? <p className="mt-3 text-sm text-mint">Indexed events are coherent with OpenSearch.</p> : null}
            {latestRun.status === "completed_with_errors" ? <p className="mt-3 text-sm text-amber">This run completed with errors. Review Problematic artifacts for retryable failures.</p> : null}
          </div>
        ) : (
          <div className="mt-4 rounded-2xl border border-line bg-abyss/70 p-4 text-sm text-muted">No ingest or reprocess runs recorded yet.</div>
        )}
        {evidenceRuns.length > 1 ? (
          <div className="mt-4 overflow-x-auto rounded-3xl border border-line">
            <table className="min-w-full divide-y divide-line text-sm">
              <thead className="bg-abyss/70">
                <tr className="text-left text-xs uppercase tracking-[0.16em] text-muted">
                  <th className="px-3 py-3">Run</th>
                  <th className="px-3 py-3">Type</th>
                  <th className="px-3 py-3">Status</th>
                  <th className="px-3 py-3">Phase</th>
                  <th className="px-3 py-3">Artifacts</th>
                  <th className="px-3 py-3">Records</th>
                  <th className="px-3 py-3">Elapsed</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-line">
                {evidenceRuns.map((run) => (
                  <tr key={run.run_id} className="bg-panel/40">
                    <td className="px-3 py-3 font-mono text-xs text-ink">{run.run_id}</td>
                    <td className="px-3 py-3 text-muted">{run.run_type} {run.mode ? `· ${run.mode}` : ""}</td>
                    <td className="px-3 py-3 text-muted">{run.status}</td>
                    <td className="px-3 py-3 text-muted">{run.phase ?? "-"}</td>
                    <td className="px-3 py-3 text-muted">{run.artifacts_done ?? 0} / {run.artifacts_total ?? 0}</td>
                    <td className="px-3 py-3 text-muted">{run.records_read ?? 0} / {run.records_indexed ?? 0}</td>
                    <td className="px-3 py-3 text-muted">{formatDuration(run.elapsed_seconds ?? null)}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        ) : null}
      </section>

      {benchmarkToolsEnabled ? (
      <details className="rounded-3xl border border-line bg-panel/70 p-5 shadow-panel">
        <summary className="cursor-pointer font-mono text-xs uppercase tracking-[0.18em] text-accent">Benchmark &amp; tuning · Developer/Performance</summary>
        <div className="mt-4 flex flex-wrap items-center justify-between gap-3">
          <div>
            <p className="font-mono text-xs uppercase tracking-[0.18em] text-accent">Benchmark &amp; Tuning · Advanced/Beta</p>
            <p className="mt-1 text-sm text-muted">Advanced module for test or demo evidence. This is not part of the recommended ingest path.</p>
            <p className="mt-2 text-xs text-amber">Benchmark reprocesses evidence and may reconcile indexed events. Use test/demo evidence if you do not want to alter investigation state.</p>
            <p className="mt-1 text-xs text-muted">Rules and detections are skipped by default for benchmark runs to reduce analyst-facing side effects.</p>
            <label className="mt-3 flex items-center gap-2 text-xs text-muted">
              <input type="checkbox" checked={benchmarkAutopilot} onChange={(event) => setBenchmarkAutopilot(event.target.checked)} />
              <span>Run with autopilot</span>
            </label>
            <div className="mt-2 grid gap-2 md:grid-cols-4">
              <label className="text-xs text-muted">
                <span className="block font-mono uppercase tracking-[0.14em] text-[10px]">Max attempts</span>
                <input type="number" min={1} max={5} value={benchmarkMaxAttempts} onChange={(event) => setBenchmarkMaxAttempts(Number(event.target.value) || 1)} className="mt-1 w-full rounded-xl border border-line bg-abyss/70 px-2 py-1 text-sm text-ink" />
              </label>
              <label className="text-xs text-muted">
                <span className="block font-mono uppercase tracking-[0.14em] text-[10px]">Max wall time</span>
                <input type="number" min={300} step={60} value={benchmarkMaxWallTimeSeconds} onChange={(event) => setBenchmarkMaxWallTimeSeconds(Number(event.target.value) || 300)} className="mt-1 w-full rounded-xl border border-line bg-abyss/70 px-2 py-1 text-sm text-ink" />
              </label>
              <label className="text-xs text-muted">
                <span className="block font-mono uppercase tracking-[0.14em] text-[10px]">No progress timeout</span>
                <input type="number" min={60} step={30} value={benchmarkNoProgressTimeoutSeconds} onChange={(event) => setBenchmarkNoProgressTimeoutSeconds(Number(event.target.value) || 60)} className="mt-1 w-full rounded-xl border border-line bg-abyss/70 px-2 py-1 text-sm text-ink" />
              </label>
              <label className="text-xs text-muted">
                <span className="block font-mono uppercase tracking-[0.14em] text-[10px]">Heartbeat timeout</span>
                <input type="number" min={60} step={30} value={benchmarkHeartbeatTimeoutSeconds} onChange={(event) => setBenchmarkHeartbeatTimeoutSeconds(Number(event.target.value) || 60)} className="mt-1 w-full rounded-xl border border-line bg-abyss/70 px-2 py-1 text-sm text-ink" />
              </label>
            </div>
          </div>
          <div className="flex flex-wrap items-center gap-2">
            <button
              onClick={() => benchmarkMutation.mutate({ profile: "safe", label: "baseline-safe" })}
              disabled={benchmarkLaunchDisabled}
              className="rounded-full border border-line bg-abyss/80 px-3 py-1 font-mono text-[11px] uppercase tracking-[0.16em] text-muted disabled:opacity-50"
            >
              Run safe baseline
            </button>
            <button
              onClick={() => benchmarkMutation.mutate({ profile: "performance", label: "benchmark-performance" })}
              disabled={benchmarkLaunchDisabled}
              className="rounded-full border border-line bg-abyss/80 px-3 py-1 font-mono text-[11px] uppercase tracking-[0.16em] text-muted disabled:opacity-50"
            >
              Run performance benchmark
            </button>
            <button
              onClick={() => benchmarkMutation.mutate({ profile: "max", label: "benchmark-max" })}
              disabled={benchmarkLaunchDisabled}
              className="rounded-full border border-line bg-abyss/80 px-3 py-1 font-mono text-[11px] uppercase tracking-[0.16em] text-muted disabled:opacity-50"
            >
              Run max benchmark
            </button>
            <button
              onClick={() => benchmarkCompareMutation.mutate(compareableBenchmarks.map((item) => item.benchmark_id))}
              disabled={compareableBenchmarks.length < 2 || benchmarkCompareMutation.isPending}
              className="rounded-full border border-line bg-abyss/80 px-3 py-1 font-mono text-[11px] uppercase tracking-[0.16em] text-muted disabled:opacity-50"
            >
              Compare benchmarks
            </button>
          </div>
        </div>
        {latestBenchmark ? (
          <div className="mt-4 rounded-2xl border border-line bg-abyss/70 p-4">
            <div className="flex flex-wrap items-center justify-between gap-3">
              <div>
                <p className="font-mono text-[11px] uppercase tracking-[0.16em] text-muted">{latestBenchmark.profile} · {latestBenchmark.mode}</p>
                <p className="mt-1 text-sm font-semibold text-ink">{latestBenchmark.label ?? latestBenchmark.benchmark_id}</p>
              </div>
              <span className={`rounded-full border px-3 py-1 font-mono text-[11px] uppercase tracking-[0.16em] ${latestBenchmark.status === "completed" ? "border-mint/30 bg-mint/10 text-mint" : latestBenchmark.status === "completed_with_errors" ? "border-amber/30 bg-amber/10 text-amber" : latestBenchmark.status === "failed" ? "border-danger/30 bg-danger/10 text-danger" : "border-accent/30 bg-accent/10 text-accent"}`}>{latestBenchmark.status}</span>
            </div>
            <div className="mt-4 grid gap-3 md:grid-cols-4">
              <div className="rounded-2xl border border-line bg-panel/40 px-3 py-2"><p className="font-mono text-[11px] uppercase tracking-[0.16em] text-muted">Duration</p><p className="mt-1 text-sm text-ink">{formatDuration(latestBenchmark.total_duration_seconds ?? null)}</p></div>
              <div className="rounded-2xl border border-line bg-panel/40 px-3 py-2"><p className="font-mono text-[11px] uppercase tracking-[0.16em] text-muted">Records/sec</p><p className="mt-1 text-sm text-ink">{latestBenchmark.records_per_sec ?? 0}</p></div>
              <div className="rounded-2xl border border-line bg-panel/40 px-3 py-2"><p className="font-mono text-[11px] uppercase tracking-[0.16em] text-muted">Artifacts/sec</p><p className="mt-1 text-sm text-ink">{latestBenchmark.artifacts_per_sec ?? 0}</p></div>
              <div className="rounded-2xl border border-line bg-panel/40 px-3 py-2"><p className="font-mono text-[11px] uppercase tracking-[0.16em] text-muted">Effective parallelism</p><p className="mt-1 text-sm text-ink">{latestBenchmark.effective_parallelism ?? "-"}</p></div>
            </div>
            <div className="mt-3 grid gap-3 md:grid-cols-3">
              <div className="rounded-2xl border border-line bg-panel/40 px-3 py-2"><p className="font-mono text-[11px] uppercase tracking-[0.16em] text-muted">Phase</p><p className="mt-1 text-sm text-ink">{latestBenchmark.phase ?? "-"}</p></div>
              <div className="rounded-2xl border border-line bg-panel/40 px-3 py-2"><p className="font-mono text-[11px] uppercase tracking-[0.16em] text-muted">Current action</p><p className="mt-1 text-sm text-ink">{latestBenchmark.current_action ?? "-"}</p></div>
              <div className="rounded-2xl border border-line bg-panel/40 px-3 py-2"><p className="font-mono text-[11px] uppercase tracking-[0.16em] text-muted">Last progress</p><p className="mt-1 text-sm text-ink">{latestBenchmark.last_progress_at ? `${formatHeartbeatAge(latestBenchmark.last_progress_at)} ago` : "-"}</p></div>
            </div>
            <div className="mt-3 grid gap-3 md:grid-cols-4">
              <div className="rounded-2xl border border-line bg-panel/40 px-3 py-2"><p className="font-mono text-[11px] uppercase tracking-[0.16em] text-muted">Watchdog</p><p className="mt-1 text-sm text-ink">{latestBenchmark.watchdog_status ?? (latestBenchmark.autopilot_enabled ? "healthy" : "disabled")}</p></div>
              <div className="rounded-2xl border border-line bg-panel/40 px-3 py-2"><p className="font-mono text-[11px] uppercase tracking-[0.16em] text-muted">Attempt</p><p className="mt-1 text-sm text-ink">{latestBenchmark.current_attempt ?? 1}/{Math.max(latestBenchmarkAttempts.length, latestBenchmark.current_attempt ?? 1, 1)}</p></div>
              <div className="rounded-2xl border border-line bg-panel/40 px-3 py-2"><p className="font-mono text-[11px] uppercase tracking-[0.16em] text-muted">Last watchdog check</p><p className="mt-1 text-sm text-ink">{latestBenchmark.last_watchdog_check_at ? `${formatHeartbeatAge(latestBenchmark.last_watchdog_check_at)} ago` : "-"}</p></div>
              <div className="rounded-2xl border border-line bg-panel/40 px-3 py-2"><p className="font-mono text-[11px] uppercase tracking-[0.16em] text-muted">Last action</p><p className="mt-1 text-sm text-ink">{typeof latestWatchdogAction?.action === "string" ? latestWatchdogAction.action : "-"}</p></div>
            </div>
            {latestBenchmark.current_phase_stalled ? (
              <div className="mt-3 rounded-2xl border border-amber/30 bg-amber/10 p-3 text-sm text-amber">
                <p className="font-medium text-amber">Benchmark appears stalled in {latestBenchmark.phase ?? latestBenchmark.current_action ?? "the current phase"}.</p>
                <p className="mt-1">{latestBenchmark.stalled_phase_warning ?? "No progress has been observed recently."}</p>
              </div>
            ) : null}
            {latestBenchmark.watchdog_status === "orphaned_reconciled" ? (
              <div className="mt-3 rounded-2xl border border-amber/30 bg-amber/10 p-3 text-sm text-amber">
                <p className="font-medium text-amber">The benchmark run became orphaned and was automatically reconciled.</p>
                <p className="mt-1">{latestBenchmark.final_recommendation ?? "Autopilot completed a safe reconciliation of the stalled run."}</p>
              </div>
            ) : null}
            {latestBenchmark.watchdog_status === "retrying" ? (
              <div className="mt-3 rounded-2xl border border-accent/30 bg-accent/10 p-3 text-sm text-accent">
                Retrying benchmark attempt {latestBenchmark.current_attempt ?? 1}/{Math.max(latestBenchmarkAttempts.length, latestBenchmark.current_attempt ?? 1, 1)}.
              </div>
            ) : null}
            <div className="mt-3 grid gap-3 md:grid-cols-3">
              <div className="rounded-2xl border border-line bg-panel/40 px-3 py-2"><p className="font-mono text-[11px] uppercase tracking-[0.16em] text-muted">First event indexed</p><p className="mt-1 text-sm text-ink">{formatDuration(latestBenchmark.time_to_first_event_indexed ?? null)}</p></div>
              <div className="rounded-2xl border border-line bg-panel/40 px-3 py-2"><p className="font-mono text-[11px] uppercase tracking-[0.16em] text-muted">Problematic</p><p className="mt-1 text-sm text-ink">{latestBenchmark.problematic_count ?? 0}</p></div>
              <div className="rounded-2xl border border-line bg-panel/40 px-3 py-2"><p className="font-mono text-[11px] uppercase tracking-[0.16em] text-muted">Metadata delta</p><p className="mt-1 text-sm text-ink">{latestBenchmark.metadata_opensearch_delta ?? 0}</p></div>
            </div>
            <div className="mt-3 rounded-2xl border border-line bg-panel/40 p-3 text-sm text-muted">
              <p className="font-mono text-[11px] uppercase tracking-[0.16em] text-accent">Bottleneck</p>
              <p className="mt-1 text-ink">{latestBenchmark.bottleneck_report?.bottleneck ?? "unknown"} {latestBenchmark.bottleneck_report?.confidence ? `· ${latestBenchmark.bottleneck_report.confidence}` : ""}</p>
              {latestBenchmark.bottleneck_report?.reasons?.length ? <p className="mt-1">{latestBenchmark.bottleneck_report.reasons[0]}</p> : null}
              {latestBenchmark.bottleneck_report?.recommendations?.length ? <p className="mt-1 text-amber">{latestBenchmark.bottleneck_report.recommendations[0]}</p> : null}
            </div>
            {latestBenchmark.final_recommendation ? <p className="mt-3 text-sm text-mint">{latestBenchmark.final_recommendation}</p> : null}
            {benchmarkComparison ? <p className="mt-3 text-sm text-mint">Recommendation: {benchmarkComparison.profile_recommendation ?? "-"} · {benchmarkComparison.reason ?? ""}</p> : null}
            {activeBenchmark ? <p className="mt-3 text-sm text-amber">A benchmark or ingest is already running for this evidence. Active run: {activeBenchmark.run_id ?? latestRun?.run_id ?? "-"}.</p> : null}
            <div className="mt-4 overflow-x-auto">
              <table className="min-w-full divide-y divide-line text-sm">
                <thead>
                  <tr className="text-left text-[11px] uppercase tracking-[0.16em] text-muted">
                    <th className="px-3 py-2">Label</th>
                    <th className="px-3 py-2">Profile</th>
                    <th className="px-3 py-2">Status</th>
                    <th className="px-3 py-2">Duration</th>
                    <th className="px-3 py-2">Records/sec</th>
                    <th className="px-3 py-2">Artifacts/sec</th>
                    <th className="px-3 py-2">Parallelism</th>
                    <th className="px-3 py-2">Bottleneck</th>
                    <th className="px-3 py-2">Watchdog</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-line/80">
                  {benchmarks.slice(0, 6).map((benchmark) => (
                    <tr key={benchmark.benchmark_id}>
                      <td className="px-3 py-2 text-ink">{benchmark.label ?? benchmark.benchmark_id}</td>
                      <td className="px-3 py-2 text-muted">{benchmark.profile}</td>
                      <td className="px-3 py-2 text-muted">{benchmark.status}</td>
                      <td className="px-3 py-2 text-muted">{formatDuration(benchmark.total_duration_seconds ?? null)}</td>
                      <td className="px-3 py-2 text-muted">{benchmark.records_per_sec ?? 0}</td>
                      <td className="px-3 py-2 text-muted">{benchmark.artifacts_per_sec ?? 0}</td>
                      <td className="px-3 py-2 text-muted">{benchmark.effective_parallelism ?? "-"}</td>
                      <td className="px-3 py-2 text-muted">{benchmark.bottleneck_report?.bottleneck ?? "-"}</td>
                      <td className="px-3 py-2 text-muted">{benchmark.watchdog_status ?? "-"}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </div>
        ) : (
          <div className="mt-4 rounded-2xl border border-line bg-abyss/70 p-4 text-sm text-muted">No benchmarks recorded yet.</div>
        )}
      </details>
      ) : null}

      {retryCandidateIds.length > 0 ? (
        <section className="rounded-3xl border border-danger/30 bg-danger/10 p-5 shadow-panel">
          <div className="flex flex-wrap items-start justify-between gap-4">
            <div className="max-w-3xl">
              <p className="font-mono text-xs uppercase tracking-[0.18em] text-danger">Retryable parser failures</p>
              <h3 className="mt-1 text-lg font-semibold text-ink">{retryCandidateIds.length} retryable failures</h3>
              <p className="mt-2 text-sm text-muted">
                Some selected artifacts could not be indexed. You can retry only these failed artifacts without reprocessing the whole evidence.
              </p>
              <div className="mt-3 flex flex-wrap gap-2 text-xs">
                <span className="rounded-full border border-danger/30 bg-abyss/80 px-3 py-1 text-danger">{problematicSummary?.data_loss_expected_count ?? retryCandidateIds.length} data loss expected</span>
                {retryAffectedFamilies.map((family) => (
                  <span key={family} className="rounded-full border border-line bg-abyss/80 px-3 py-1 text-muted">{family === "windows_event" ? "EVTX" : family}</span>
                ))}
              </div>
              {retryCandidateExamples.length ? (
                <div className="mt-3 text-sm text-muted">
                  <span className="font-semibold text-ink">Affected artifacts:</span> {retryCandidateExamples.join(", ")}
                </div>
              ) : null}
              <p className="mt-2 text-xs text-muted">Extended timeout will be used for timeout-related failures.</p>
            </div>
            <div className="flex flex-wrap gap-2">
              <button
                onClick={() => retryProblematicArtifactsMutation.mutate({ artifactIds: retryCandidateIds, mode: "higher_timeout" })}
                disabled={activeIndexingJob || retryProblematicArtifactsMutation.isPending}
                className="rounded-full border border-danger/40 bg-danger/20 px-4 py-2 font-mono text-[11px] uppercase tracking-[0.16em] text-danger disabled:opacity-50"
              >
                {retryProblematicArtifactsMutation.isPending ? `Retrying ${retryCandidateIds.length} failed artifacts` : "Retry failed artifacts"}
              </button>
              <a href="#problematic-artifacts" className="rounded-full border border-line bg-abyss/80 px-4 py-2 font-mono text-[11px] uppercase tracking-[0.16em] text-muted">
                View details
              </a>
            </div>
          </div>
        </section>
      ) : null}

      {problematicSummary && problematicSummary.problematic_count > 0 ? (
        <section id="problematic-artifacts" className="rounded-3xl border border-line bg-panel/70 p-5 shadow-panel">
          <div className="flex flex-wrap items-center justify-between gap-3">
            <div>
              <p className="font-mono text-xs uppercase tracking-[0.18em] text-accent">Problematic artifacts</p>
              <p className="mt-1 text-sm text-muted">
                These artifacts had issues during ingest. Historical failures stay visible, but the current status below reflects health checks, retries and recovered indexed data.
              </p>
              {(problematicSummary.skipped_empty ?? 0) > 0 ? (
                <p className="mt-2 text-sm text-muted">
                  Some Windows event log files do not contain parseable records. These are informational and do not block investigation.
                </p>
              ) : null}
              <p className="mt-2 text-sm text-ink">
                {problematicSummary.problematic_count} artifacts had issues during ingest. {problematicSummary.indexed_with_warning + problematicSummary.recovered_count + problematicSummary.source_missing_but_indexed} have indexed records available; {problematicSummary.recovered_count} recovered by retry; {problematicSummary.unresolved_count} still unresolved.
              </p>
            </div>
            <div className="flex flex-wrap items-center gap-2">
              <select
                aria-label="Problematic retry mode"
                value={problematicRetryMode}
                onChange={(event) => setProblematicRetryMode(event.target.value)}
                className="rounded-full border border-line bg-abyss/80 px-3 py-2 text-xs text-ink"
              >
                <option value="higher_timeout">Retry: higher timeout</option>
                <option value="no_detections">Retry: no detections</option>
                <option value="deep_safe_mode">Retry: deep safe mode</option>
                <option value="parse_only">Retry: parse only</option>
                <option value="safe_mode">Retry: safe mode</option>
                <option value="default">Retry: default</option>
              </select>
              <span className="text-xs text-muted">{retryModeDescriptions[problematicRetryMode] ?? ""}</span>
              <button
                onClick={() => retryProblematicArtifactsMutation.mutate({ artifactIds: selectedProblematicArtifactIds, mode: problematicRetryMode })}
                disabled={activeIndexingJob || !selectedProblematicArtifactIds.length || retryProblematicArtifactsMutation.isPending}
                className="rounded-full border border-line bg-abyss/80 px-3 py-1 font-mono text-[11px] uppercase tracking-[0.16em] text-muted disabled:opacity-50"
              >
                Retry selected
              </button>
            </div>
          </div>
          <div className="mt-4 grid gap-3 md:grid-cols-6">
            <div className="rounded-2xl border border-line bg-panel/50 px-3 py-2"><p className="font-mono text-[11px] uppercase tracking-[0.16em] text-muted">Critical errors</p><p className="mt-1 text-sm text-danger">{problemImpactCounts.critical ?? 0}</p></div>
            <div className="rounded-2xl border border-line bg-panel/50 px-3 py-2"><p className="font-mono text-[11px] uppercase tracking-[0.16em] text-muted">Warnings</p><p className="mt-1 text-sm text-amber">{problemImpactCounts.warning ?? 0}</p></div>
            <div className="rounded-2xl border border-line bg-panel/50 px-3 py-2"><p className="font-mono text-[11px] uppercase tracking-[0.16em] text-muted">Skipped/empty</p><p className="mt-1 text-sm text-muted">{problemImpactCounts.skipped ?? 0}</p></div>
            <div className="rounded-2xl border border-line bg-panel/50 px-3 py-2"><p className="font-mono text-[11px] uppercase tracking-[0.16em] text-muted">Tooling missing</p><p className="mt-1 text-sm text-amber">{problemImpactCounts.tooling_missing ?? 0}</p></div>
            <div className="rounded-2xl border border-line bg-panel/50 px-3 py-2"><p className="font-mono text-[11px] uppercase tracking-[0.16em] text-muted">Informational</p><p className="mt-1 text-sm text-mint">{problemImpactCounts.informational ?? 0}</p></div>
            <div className="rounded-2xl border border-line bg-panel/50 px-3 py-2"><p className="font-mono text-[11px] uppercase tracking-[0.16em] text-muted">Problematic</p><p className="mt-1 text-sm text-ink">{problematicSummary.problematic_count}</p></div>
            <div className="rounded-2xl border border-line bg-panel/50 px-3 py-2"><p className="font-mono text-[11px] uppercase tracking-[0.16em] text-muted">Indexed with warning</p><p className="mt-1 text-sm text-amber">{problematicSummary.indexed_with_warning}</p></div>
            <div className="rounded-2xl border border-line bg-panel/50 px-3 py-2"><p className="font-mono text-[11px] uppercase tracking-[0.16em] text-muted">Recovered</p><p className="mt-1 text-sm text-emerald-200">{problematicSummary.recovered_count}</p></div>
            <div className="rounded-2xl border border-line bg-panel/50 px-3 py-2"><p className="font-mono text-[11px] uppercase tracking-[0.16em] text-muted">Unresolved</p><p className="mt-1 text-sm text-danger">{problematicSummary.unresolved_count}</p></div>
            <div className="rounded-2xl border border-line bg-panel/50 px-3 py-2"><p className="font-mono text-[11px] uppercase tracking-[0.16em] text-muted">Data loss expected</p><p className="mt-1 text-sm text-orange-300">{problematicSummary.data_loss_expected_count}</p></div>
            <div className="rounded-2xl border border-line bg-panel/50 px-3 py-2"><p className="font-mono text-[11px] uppercase tracking-[0.16em] text-muted">Source missing, indexed</p><p className="mt-1 text-sm text-amber">{problematicSummary.source_missing_but_indexed}</p></div>
            <div className="rounded-2xl border border-line bg-panel/50 px-3 py-2"><p className="font-mono text-[11px] uppercase tracking-[0.16em] text-muted">Retryable</p><p className="mt-1 text-sm text-ink">{problematicSummary.retryable}</p></div>
            <div className="rounded-2xl border border-line bg-panel/50 px-3 py-2"><p className="font-mono text-[11px] uppercase tracking-[0.16em] text-muted">No records</p><p className="mt-1 text-sm text-mint">{problematicSummary.skipped_empty ?? 0}</p></div>
          </div>
          <div className="mt-4 grid gap-4 lg:grid-cols-3">
            <div className="rounded-2xl border border-danger/30 bg-danger/10 p-4">
              <div className="flex items-center justify-between gap-3">
                <p className="font-mono text-[11px] uppercase tracking-[0.16em] text-danger">Requires attention</p>
                <span className="rounded-full border border-danger/30 px-2 py-1 text-xs text-danger">{retryCandidateIds.length}</span>
              </div>
              <p className="mt-2 text-sm text-muted">Real parser failures with retry available and expected data loss.</p>
              <p className="mt-2 text-xs text-muted">Retryability: yes · Data loss: yes</p>
              {retryCandidateExamples.length ? <p className="mt-2 text-xs text-ink">Examples: {retryCandidateExamples.join(", ")}</p> : null}
            </div>
            <div className="rounded-2xl border border-amber/30 bg-amber/10 p-4">
              <div className="flex items-center justify-between gap-3">
                <p className="font-mono text-[11px] uppercase tracking-[0.16em] text-amber">Warnings</p>
                <span className="rounded-full border border-amber/30 px-2 py-1 text-xs text-amber">{warningProblems.length}</span>
              </div>
              <p className="mt-2 text-sm text-muted">Artifacts completed with warning or fully indexed despite timeout/stall.</p>
              <p className="mt-2 text-xs text-muted">Retryability: no · Data loss: no</p>
              {warningProblems[0] ? <p className="mt-2 text-xs text-ink">Example: {warningProblems[0].name}</p> : null}
            </div>
            <div className="rounded-2xl border border-mint/25 bg-mint/10 p-4">
              <div className="flex items-center justify-between gap-3">
                <p className="font-mono text-[11px] uppercase tracking-[0.16em] text-mint">Informational / skipped</p>
                <span className="rounded-full border border-mint/25 px-2 py-1 text-xs text-mint">{informationalProblems.length}</span>
              </div>
              <p className="mt-2 text-sm text-muted">Empty/no-record logs and optional unsupported artifacts that do not block investigation.</p>
              <p className="mt-2 text-xs text-muted">Retryability: no · Data loss: no</p>
              {informationalProblems[0] ? <p className="mt-2 text-xs text-ink">Example: {informationalProblems[0].name}</p> : null}
            </div>
          </div>
          <div className="mt-4 overflow-x-auto rounded-3xl border border-line">
            <table className="min-w-full divide-y divide-line text-sm">
              <thead className="bg-abyss/70">
                <tr className="text-left text-xs uppercase tracking-[0.16em] text-muted">
                  <th className="px-3 py-3">Select</th>
                  <th className="px-3 py-3">Artifact</th>
                  <th className="px-3 py-3">Original status</th>
                  <th className="px-3 py-3">Current status</th>
                  <th className="px-3 py-3">Read / Indexed</th>
                  <th className="px-3 py-3">Data loss</th>
                  <th className="px-3 py-3">Recovery</th>
                  <th className="px-3 py-3">Actions</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-line">
                {problematicArtifacts.map((artifact) => (
                  <tr key={`${artifact.source_path}:${artifact.parser}`} className="bg-panel/40">
                    <td className="px-3 py-3 align-top">
                      {artifact.retryable && artifact.artifact_id ? <input type="checkbox" checked={selectedProblematicArtifactIds.includes(artifact.artifact_id)} onChange={() => toggleProblematicArtifact(artifact.artifact_id!)} aria-label={`Select problematic artifact ${artifact.name}`} /> : null}
                    </td>
                    <td className="px-3 py-3 align-top">
                      <p className="font-semibold text-ink">{artifact.name}</p>
                      <p className="mt-1 max-w-[440px] break-all text-xs text-muted">{artifact.source_path}</p>
                    </td>
                    <td className="px-3 py-3 align-top">
                      <span className={`rounded-full border px-2 py-1 font-mono text-[11px] uppercase tracking-[0.14em] ${problematicStatusTone(artifact.original_status ?? artifact.status)}`}>
                        {formatProblematicStatusLabel(artifact.original_status ?? artifact.status)}
                      </span>
                    </td>
                    <td className="px-3 py-3 align-top text-muted">
                      <span className={`rounded-full border px-2 py-1 font-mono text-[11px] uppercase tracking-[0.14em] ${problematicStatusTone(artifact.effective_status ?? artifact.status)}`}>
                        {artifact.effective_status === "parsed_with_warning" ? "Indexed with warning" : artifact.effective_status === "recovered_with_warning" ? "Recovered by retry" : artifact.effective_status === "source_missing_but_indexed" ? "Source missing, indexed data available" : artifact.effective_status === "skipped_empty" || artifact.effective_status === "completed_no_records" || artifact.effective_status === "unsupported_no_records" ? "No records produced" : artifact.effective_status === "unresolved_timeout" || artifact.effective_status === "unresolved_failed" || artifact.effective_status === "health_check_failed" ? "Still unresolved" : formatProblematicStatusLabel(artifact.effective_status ?? artifact.status)}
                      </span>
                      {artifact.health_summary ? <p className="mt-2 text-xs">{artifact.health_summary}</p> : null}
                    </td>
                    <td className="px-3 py-3 align-top text-muted">{artifact.effective_records_read ?? artifact.records_read} / {artifact.effective_records_indexed ?? artifact.records_indexed}</td>
                    <td className="px-3 py-3 align-top text-muted">
                      <p>{artifact.current_data_loss_expected ?? artifact.data_loss_expected ? "Expected data loss" : "No expected data loss"}</p>
                      {artifact.loss_summary ? <p className="mt-1 text-xs">{artifact.loss_summary}</p> : null}
                    </td>
                    <td className="px-3 py-3 align-top text-xs text-muted">
                      <p>{problematicRecoveryText(artifact)}</p>
                      <p className="mt-2 text-ink">{problematicImpact(artifact).label}: {problematicImpact(artifact).action}</p>
                      {artifact.accepted_warning ? <p className="mt-2 text-emerald-300">Warning accepted by analyst.</p> : null}
                      {renderHealthCheckSummary(artifact.health_check)}
                    </td>
                    <td className="px-3 py-3 align-top">
                      <div className="flex flex-wrap gap-2">
                        {(artifact.effective_records_indexed ?? artifact.records_indexed) > 0 ? (
                          <Link to={problematicSearchHref(artifact)} className="rounded-full border border-line bg-abyss/80 px-3 py-1 font-mono text-[11px] uppercase tracking-[0.16em] text-muted">
                            Search indexed events
                          </Link>
                        ) : null}
                        {artifact.retryable && artifact.artifact_id ? (
                          <button
                            onClick={() => evtxHealthCheckMutation.mutate({ artifactId: artifact.artifact_id! })}
                            disabled={activeIndexingJob || evtxHealthCheckMutation.isPending}
                            className="rounded-full border border-line bg-abyss/80 px-3 py-1 font-mono text-[11px] uppercase tracking-[0.16em] text-muted disabled:opacity-50"
                          >
                            Check EVTX health
                          </button>
                        ) : null}
                        {(artifact.effective_status === "unresolved_timeout" || artifact.effective_status === "unresolved_failed" || artifact.effective_status === "health_check_only_valid" || artifact.effective_status === "health_check_failed") && artifact.artifact_id ? (
                          <button
                            onClick={() => retryProblematicArtifactsMutation.mutate({ singleArtifactId: artifact.artifact_id!, mode: "deep_safe_mode" })}
                            disabled={activeIndexingJob || retryProblematicArtifactsMutation.isPending}
                            className="rounded-full border border-amber/30 bg-amber/10 px-3 py-1 font-mono text-[11px] uppercase tracking-[0.16em] text-amber disabled:opacity-50"
                          >
                            Retry deep safe mode
                          </button>
                        ) : null}
                        {!artifact.accepted_warning && !(artifact.current_data_loss_expected ?? artifact.data_loss_expected) && artifact.artifact_id ? (
                          <button
                            onClick={() => acceptProblematicWarningMutation.mutate({ artifactId: artifact.artifact_id! })}
                            disabled={activeIndexingJob || acceptProblematicWarningMutation.isPending}
                            className="rounded-full border border-line bg-abyss/80 px-3 py-1 font-mono text-[11px] uppercase tracking-[0.16em] text-muted disabled:opacity-50"
                          >
                            Accept warning
                          </button>
                        ) : null}
                        {artifact.retryable && artifact.artifact_id ? (
                          <button
                            onClick={() => retryProblematicArtifactsMutation.mutate({ singleArtifactId: artifact.artifact_id!, mode: problematicRetryMode })}
                            disabled={activeIndexingJob || retryProblematicArtifactsMutation.isPending}
                            className="rounded-full border border-line bg-abyss/80 px-3 py-1 font-mono text-[11px] uppercase tracking-[0.16em] text-muted disabled:opacity-50"
                          >
                            Retry artifact
                          </button>
                        ) : null}
                      </div>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </section>
      ) : null}

      {selectionPending ? (
        <details
          id="parse-selection"
          ref={parseSelectionRef}
          open={advancedProcessingDetailsOpen}
          onToggle={(event) => setAdvancedProcessingDetailsOpen(event.currentTarget.open)}
          className="rounded-3xl border border-line bg-panel/70 p-5 shadow-panel"
        >
          <summary className="cursor-pointer font-mono text-xs uppercase tracking-[0.18em] text-accent">Raw discovery candidate details</summary>
          <div className="mt-4 rounded-3xl border border-line bg-abyss/80 p-5">
            <div className="flex flex-col gap-2">
              <p className="font-mono text-xs uppercase tracking-[0.18em] text-accent">Candidate inventory</p>
              <p className="text-lg font-semibold text-ink">Discovered artifact candidates</p>
              <p className="text-sm text-muted">
                Category-level indexing controls are available in Index selected artifact types. This detail view is for inspecting individual raw candidates and parser status.
              </p>
            </div>
          </div>

          <div className="flex flex-col gap-2">
            <p className="font-mono text-xs uppercase tracking-[0.18em] text-accent">Detected evidences</p>
            <p className="text-sm text-muted">
              Collection root: {discovery?.collection_root ?? "-"} · Files scanned: {String(discovery?.total_files_scanned ?? 0)} · Host: {discovery?.hostname ?? "-"}
            </p>
          </div>
          <div className="mt-4 grid gap-3 md:grid-cols-2 xl:grid-cols-4">
            {categoryRows.map(([category, counts]) => (
              <div key={category} className="rounded-2xl border border-line bg-abyss/70 px-4 py-3">
                <p className="font-mono text-[11px] uppercase tracking-[0.16em] text-muted">{category}</p>
                <p className="mt-2 text-sm text-ink">total {counts.total}</p>
                <p className="text-xs text-muted">supported {counts.supported} · partial {counts.partial} · not implemented {counts.notImplemented} · warnings {counts.warnings}</p>
              </div>
            ))}
          </div>
          {candidatesByCategory.map(([category, candidates]) => {
            const supportedCount = candidates.filter((candidate) => candidate.supported).length;
            const categoryLabel = formatCategoryLabel(category);
            const parseableCount = candidates.filter((candidate) => candidate.supported && candidate.parser_status !== "partial").length;
            const partialCount = candidates.filter((candidate) => candidate.supported && candidate.parser_status === "partial").length;
            const notImplementedCount = candidates.filter((candidate) => !candidate.supported).length;
            const isExpanded = Boolean(expandedCategories[category]);
            return (
              <div key={category} className="mt-5 rounded-2xl border border-line bg-abyss/70 p-4">
                <div className="flex flex-wrap items-center justify-between gap-3">
                  <div>
                    <p className="font-mono text-xs uppercase tracking-[0.18em] text-accent">{categoryLabel}</p>
                    <p className="mt-1 text-xs text-muted">
                      total {candidates.length} · parseable {parseableCount} · partial {partialCount} · not implemented {notImplementedCount}
                    </p>
                  </div>
                  <div className="flex flex-wrap gap-2">
                    {supportedCount ? (
                      <button onClick={() => selectCategory(category)} className="rounded-2xl border border-line bg-panel/40 px-3 py-2 text-xs text-muted">
                        {`Select ${categoryLabel}`}
                      </button>
                    ) : null}
                    <button onClick={() => toggleCategoryExpanded(category)} className="rounded-2xl border border-line bg-panel/40 px-3 py-2 text-xs text-muted">
                      {isExpanded ? "Hide details" : "Show details"}
                    </button>
                  </div>
                </div>
                {!supportedCount ? (
                  <div className="mt-3 rounded-2xl border border-amber/30 bg-amber/10 px-4 py-3 text-sm text-amber">
                    {getNoParseableMessage(category, candidates)}
                  </div>
                ) : null}
                {category === "jumplist" && supportedCount ? (
                  <div className="mt-3 rounded-2xl border border-mint/20 bg-mint/10 px-4 py-3 text-sm text-mint">
                    Raw automaticDestinations files can be parsed directly. CustomDestinations support is partial.
                  </div>
                ) : null}
                {!isExpanded ? (
                  <div className="mt-3 rounded-2xl border border-line/60 bg-panel/30 px-4 py-3 text-sm text-muted">
                    {supportedCount
                      ? `This category is collapsed to reduce noise. Expand it to review the ${candidates.length} detected artifacts and choose them one by one if needed.`
                      : `This category is collapsed. Expand it if you want to inspect the ${candidates.length} detected artifacts and their warnings.`}
                  </div>
                ) : null}
                {isExpanded ? (
                  <div className="mt-3 space-y-3">
                  {candidates.map((candidate) => (
                    <div key={candidate.id} className="rounded-2xl border border-line/70 bg-panel/40 p-3">
                      <div className="flex flex-wrap items-start justify-between gap-3">
                        <div className="min-w-0 flex-1">
                          <div className="flex items-center gap-3">
                            <input type="checkbox" checked={selectedCandidateIds.includes(candidate.id)} disabled={!candidate.supported} onChange={() => toggleCandidate(candidate.id)} />
                            <div className="min-w-0">
                              <p className="truncate text-sm font-semibold text-ink">{candidate.display_name}</p>
                              <p className="mt-1 font-mono text-[11px] text-muted">
                                {candidate.artifact_type} · {candidate.parser_status}
                                {candidate.parser ? ` · ${candidate.parser}` : ""}
                                {candidate.user ? ` · user ${candidate.user}` : ""}
                                {candidate.profile ? ` · profile ${candidate.profile}` : ""}
                                {candidate.task_path ? ` · ${candidate.task_path}` : ""}
                                {candidate.sid ? ` · ${candidate.sid}` : ""}
                              </p>
                            </div>
                          </div>
                        </div>
                        <span className={`rounded-full border px-3 py-1 font-mono text-[11px] uppercase tracking-[0.16em] ${candidate.supported && candidate.parser_status !== "partial" ? "border-mint/30 bg-mint/10 text-mint" : candidate.supported ? "border-cyan-400/30 bg-cyan-400/10 text-cyan-200" : "border-amber/30 bg-amber/10 text-amber"}`}>
                          {candidateStatusLabel(candidate)}
                        </span>
                      </div>
                      <p className="mt-2 break-all text-xs text-muted">{candidatePrimaryPath(candidate)}</p>
                      {candidate.original_r_path && candidate.original_r_path !== candidatePrimaryPath(candidate) ? <p className="mt-1 break-all text-xs text-muted">Content: {candidate.original_r_path}</p> : null}
                      <div className="mt-2 flex flex-wrap gap-3 text-xs text-muted">
                        <span>size {candidate.size ?? "-"}</span>
                        <span>{candidate.normalized_windows_path || candidate.normalized_windows_i_path || "-"}</span>
                      </div>
                      {candidate.reason ? <p className="mt-2 text-sm text-amber">{candidate.reason}</p> : null}
                      {candidate.warnings.length ? (
                        <div className="mt-2 space-y-1">
                          {candidate.warnings.map((warning) => (
                            <p key={warning} className="text-xs text-amber/90">{warning}</p>
                          ))}
                        </div>
                      ) : null}
                    </div>
                  ))}
                  </div>
                ) : null}
              </div>
            );
          })}
          {parseVelociraptorMutation.error instanceof Error ? <p className="mt-3 text-sm text-danger">{parseVelociraptorMutation.error.message}</p> : null}
        </details>
      ) : null}

      <details className="rounded-3xl border border-line bg-panel/70 p-5 shadow-panel">
        <summary className="cursor-pointer font-mono text-xs uppercase tracking-[0.18em] text-accent">Raw discovery inventory</summary>
      <section className="mt-4 grid min-w-0 gap-6 xl:grid-cols-[minmax(0,1fr)_minmax(0,1fr)]">
        <div className="space-y-6">
          <div id="artifact-manifest" className="rounded-3xl border border-line bg-panel/70 p-5 shadow-panel">
            <p className="font-mono text-xs uppercase tracking-[0.18em] text-accent">Manifest summary</p>
            <div className="mt-4 grid gap-3 md:grid-cols-2">
              <div className="rounded-2xl border border-line bg-abyss/80 p-4 text-sm text-muted">Processed result artifacts: {manifest?.stats?.results_artifacts_parsed ?? 0} / {manifest?.stats?.results_artifacts_detected ?? 0}</div>
              <div className="rounded-2xl border border-line bg-abyss/80 p-4 text-sm text-muted">Preserved raw artifacts: {manifest?.stats?.raw_artifacts_not_parsed ?? 0}</div>
              <div className="rounded-2xl border border-line bg-abyss/80 p-4 text-sm text-muted">Indexed events: {manifest?.stats?.indexed_events ?? 0}</div>
              <div className="rounded-2xl border border-line bg-abyss/80 p-4 text-sm text-muted">Failed artifacts: {manifest?.stats?.failed_artifacts ?? 0}</div>
            </div>
            {Object.keys(notSelectedCandidatesCountByCategory).length ? (
              <div className="mt-3 rounded-2xl border border-line bg-abyss/80 p-4 text-sm text-muted">
                Detected but not selected: {Object.entries(notSelectedCandidatesCountByCategory).map(([category, count]) => `${category} ${count}`).join(" · ")}
              </div>
            ) : null}
          </div>
          <div className="rounded-3xl border border-line bg-panel/70 p-5 shadow-panel">
            <p className="font-mono text-xs uppercase tracking-[0.18em] text-accent">Original files</p>
            <div className="mt-4 max-h-[420px] overflow-auto rounded-2xl border border-line bg-abyss/80 p-4 font-mono text-xs text-muted">
              {(manifest?.files ?? []).length ? (
                manifest?.files.map((item) => (
                  <div key={item.path} className="mb-2 rounded-xl border border-line/50 p-3">
                    <p>{item.path}</p>
                    <p className="mt-1 text-[11px] text-muted">{item.size} bytes · {item.extension || "no ext"} · {item.ignored ? `ignored (${item.reason})` : "included"}</p>
                  </div>
                ))
              ) : (
                <p>No file tree available yet.</p>
              )}
            </div>
          </div>
        </div>

        <div className="space-y-6">
          <div className="rounded-3xl border border-line bg-panel/70 p-5 shadow-panel">
            <div className="flex flex-wrap items-end gap-3">
              <div className="min-w-[150px] flex-1">
                <p className="mb-2 font-mono text-[11px] uppercase tracking-[0.16em] text-muted">Status</p>
                <select value={filters.status} onChange={(event) => setFilters((current) => ({ ...current, status: event.target.value }))} className="w-full rounded-2xl border border-line bg-abyss/80 px-3 py-2 text-sm">
                  <option value="">All</option>
                  {statuses.map((status) => <option key={status} value={status}>{status}</option>)}
                </select>
              </div>
              <div className="min-w-[150px] flex-1">
                <p className="mb-2 font-mono text-[11px] uppercase tracking-[0.16em] text-muted">Artifact type</p>
                <select value={filters.artifactType} onChange={(event) => setFilters((current) => ({ ...current, artifactType: event.target.value }))} className="w-full rounded-2xl border border-line bg-abyss/80 px-3 py-2 text-sm">
                  <option value="">All</option>
                  {artifactTypes.map((artifactType) => <option key={artifactType} value={artifactType}>{artifactType}</option>)}
                </select>
              </div>
              <div className="min-w-[150px] flex-1">
                <p className="mb-2 font-mono text-[11px] uppercase tracking-[0.16em] text-muted">Parser</p>
                <select value={filters.parser} onChange={(event) => setFilters((current) => ({ ...current, parser: event.target.value }))} className="w-full rounded-2xl border border-line bg-abyss/80 px-3 py-2 text-sm">
                  <option value="">All</option>
                  {parsers.map((parser) => <option key={parser} value={parser}>{parser}</option>)}
                </select>
              </div>
              <div className="min-w-[220px] flex-[2]">
                <p className="mb-2 font-mono text-[11px] uppercase tracking-[0.16em] text-muted">Source path</p>
                <input value={filters.sourcePath} onChange={(event) => setFilters((current) => ({ ...current, sourcePath: event.target.value }))} className="w-full rounded-2xl border border-line bg-abyss/80 px-3 py-2 text-sm" placeholder="uploads/... or results/..." />
              </div>
            </div>
          </div>

          {([
            ["Processed artifacts", processedArtifacts],
            ["Preserved raw artifacts", preservedRawArtifacts],
            ["Unsupported or not parsed yet", otherArtifacts],
          ] as Array<[string, typeof filteredArtifacts]>).map(([title, artifacts]) => (
            <div key={title} className="rounded-3xl border border-line bg-panel/70 p-5 shadow-panel">
              <p className="font-mono text-xs uppercase tracking-[0.18em] text-accent">{title}</p>
              <div className="mt-4 max-h-[300px] space-y-3 overflow-auto">
                {(artifacts as typeof filteredArtifacts).length ? (
                  (artifacts as typeof filteredArtifacts).map((artifact) => (
                    <div key={`${artifact.source_path}-${artifact.name}`} className="rounded-2xl border border-line bg-abyss/80 p-4">
                      <div className="flex items-center justify-between gap-3">
                        <p className="text-sm font-semibold">{artifact.name}</p>
                        <span className="rounded-full border border-line px-3 py-1 font-mono text-[11px] uppercase tracking-[0.16em] text-accent">{artifact.status}</span>
                      </div>
                      <p className="mt-2 font-mono text-xs text-muted">{artifact.source_path}</p>
                      <p className="mt-2 text-xs text-muted">{artifact.parser} · {artifact.artifact_type} · {artifact.record_count} records</p>
                      {artifact.reason ? <p className="mt-2 text-xs text-amber">{artifact.reason}</p> : null}
                      {artifact.planned_parser ? <p className="mt-2 text-xs text-muted">Planned parser: {artifact.planned_parser}</p> : null}
                    </div>
                  ))
                ) : (
                  <p className="text-sm text-muted">No artifacts in this group for the current filters.</p>
                )}
              </div>
            </div>
          ))}

          <div className="rounded-3xl border border-line bg-panel/70 p-5 shadow-panel">
            <p className="font-mono text-xs uppercase tracking-[0.18em] text-accent">Errors</p>
            <div className="mt-4 max-h-[240px] overflow-auto rounded-2xl border border-line bg-abyss/80 p-4 text-xs text-muted">
              {(manifest?.errors ?? []).length ? <pre className="whitespace-pre-wrap break-words">{JSON.stringify(manifest?.errors ?? [], null, 2)}</pre> : <p>No errors recorded.</p>}
            </div>
          </div>
        </div>
      </section>
      </details>
      {data?.case_id ? (
        <DebugExportDialog
          open={debugExportOpen}
          onClose={() => setDebugExportOpen(false)}
          caseId={data.case_id}
          title="Export evidence debug pack"
          defaultRequest={{
            scope: "evidence",
            evidence_id: evidenceId,
            include_raw_samples: false,
            include_raw_xml: false,
            include_source_paths: true,
            include_full_raw: false,
            max_events_per_type: 25,
            max_field_length: 2000,
            redact_secrets: true,
            ui_context: {
              page: "EvidenceDetail",
              selected_case: data.case_id,
              selected_evidence: evidenceId,
              filters,
              current_phase: currentPhase,
            },
          }}
        />
      ) : null}
      {reprocessDialogOpen ? (
        <div data-testid="reprocess-modal-overlay" className="fixed inset-0 z-50 flex overflow-hidden bg-abyss/80 px-4 py-6 backdrop-blur-sm">
          <div className="flex min-h-full items-start justify-center">
            <div className="flex max-h-[calc(100vh-3rem)] w-full max-w-4xl flex-col overflow-hidden overscroll-contain rounded-[28px] border border-line bg-panel/95 p-6 shadow-panel">
            <div className="flex items-start justify-between gap-4">
              <div>
                <p className="font-mono text-xs uppercase tracking-[0.24em] text-accent">Re-index evidence</p>
                <h3 className="mt-2 text-2xl font-semibold text-ink">{data?.original_filename}</h3>
                <p className="mt-2 max-w-3xl text-sm text-muted">
                  {supportsGranularReprocess
                    ? "Recommended: run core indexing again using the previous supported artifact selection. Advanced controls are available if you need to change the selection."
                    : "This evidence does not expose raw discovery candidates. Re-indexing will reuse the generic core ingest plan for the full evidence."}
                </p>
              </div>
              <button onClick={() => setReprocessDialogOpen(false)} className="rounded-full border border-line px-3 py-1 text-sm text-muted">Close</button>
            </div>

            <div data-testid="reprocess-modal-content" className="mt-5 min-h-0 flex-1 overflow-y-auto overscroll-contain pr-1">
              {supportsGranularReprocess ? (
                <>
                  <div className="grid gap-3 md:grid-cols-2 xl:grid-cols-3">
                  <button
                    type="button"
                    onClick={() => setReprocessMode("previous_selection")}
                    className={`rounded-2xl border px-4 py-4 text-left ${reprocessMode === "previous_selection" ? "border-accent bg-accent/10 text-ink" : "border-line bg-abyss/70 text-muted"}`}
                  >
                    <p className="font-mono text-[11px] uppercase tracking-[0.16em]">Re-index evidence</p>
                    <p className="mt-2 text-sm">Recommended. Use core indexing with the same supported artifacts that were used last time.</p>
                  </button>
                  <details className="rounded-2xl border border-line bg-abyss/70 px-4 py-4 text-muted md:col-span-2 xl:col-span-2">
                    <summary className="cursor-pointer font-mono text-[11px] uppercase tracking-[0.16em] text-accent">Advanced re-index options</summary>
                    <div className="mt-4 grid gap-3 md:grid-cols-2">
                  <button
                    type="button"
                    onClick={() => setReprocessMode("choose_again")}
                    className={`rounded-2xl border px-4 py-4 text-left ${reprocessMode === "choose_again" ? "border-accent bg-accent/10 text-ink" : "border-line bg-abyss/70 text-muted"}`}
                  >
                    <p className="font-mono text-[11px] uppercase tracking-[0.16em]">Choose artifacts again</p>
                    <p className="mt-2 text-sm">Review detected candidates again, with the previous successful selection preselected.</p>
                  </button>
                  <button
                    type="button"
                    onClick={() => setReprocessMode("manual_selection")}
                    className={`rounded-2xl border px-4 py-4 text-left ${reprocessMode === "manual_selection" ? "border-accent bg-accent/10 text-ink" : "border-line bg-abyss/70 text-muted"}`}
                  >
                    <p className="font-mono text-[11px] uppercase tracking-[0.16em]">Edit selection manually</p>
                    <p className="mt-2 text-sm">Choose exactly which artifact candidates and parsers to run in this reprocess.</p>
                  </button>
                    </div>
                  </details>
                  </div>

                  <details className="mt-4 rounded-2xl border border-line bg-abyss/60 p-4 text-sm text-muted">
                    <summary className="cursor-pointer font-mono text-[11px] uppercase tracking-[0.16em] text-accent">Start from scratch</summary>
                    <p className="mt-3">Full rediscovery ignores the last successful plan and can produce a different selection. Use it only when you really want to rebuild the candidate set from zero.</p>
                    <button
                      type="button"
                      onClick={() => setReprocessMode("full_rediscovery")}
                      className={`mt-3 rounded-2xl border px-4 py-3 text-left ${reprocessMode === "full_rediscovery" ? "border-accent bg-accent/10 text-ink" : "border-line bg-panel/40 text-muted"}`}
                    >
                      <p className="font-mono text-[11px] uppercase tracking-[0.16em]">Start from scratch / Full rediscovery</p>
                      <p className="mt-2 text-sm">Requires explicit confirmation and will not silently replace the last successful parser selection.</p>
                    </button>
                  </details>

                  <div className="mt-4 rounded-2xl border border-line bg-abyss/60 p-4 text-sm text-muted">
                    <p className="font-mono text-[11px] uppercase tracking-[0.16em] text-accent">Processing</p>
                    <p className="mt-2 text-sm text-muted">
                      Default: re-index evidence with core indexing. Rules, reports and enrichment stay manual.
                    </p>
                    <details className="mt-4 rounded-2xl border border-amber/30 bg-amber/10 p-4">
                      <summary className="cursor-pointer font-mono text-[11px] uppercase tracking-[0.16em] text-amber">Experimental processing</summary>
                      <div className="mt-3 flex flex-wrap items-center justify-between gap-3">
                        <p className="text-sm text-muted">Enables deeper parser tiers and inline detections. Use only when needed.</p>
                        <button
                          type="button"
                          onClick={() => {
                            const nextMode = reprocessIngestMode === "full_forensic" ? "usable_search" : "full_forensic";
                            setReprocessIngestMode(nextMode);
                            if (nextMode === "full_forensic") setReprocessEvtxProfile("full");
                          }}
                          className={`rounded-2xl border px-4 py-2 text-sm font-semibold ${reprocessIngestMode === "full_forensic" ? "border-amber bg-amber/20 text-amber" : "border-line bg-panel/40 text-muted"}`}
                        >
                          {reprocessIngestMode === "full_forensic" ? "Advanced selected" : "Select Advanced"}
                        </button>
                      </div>
                    </details>
                    <label className="mt-4 block">
                      <span className="mb-2 block font-mono text-[11px] uppercase tracking-[0.16em] text-muted">Hostname / host label (optional)</span>
                      <input value={reprocessProvidedHost} onChange={(event) => setReprocessProvidedHost(event.target.value)} placeholder="HOSTA / TEST-WIN10-01" className="w-full rounded-2xl border border-line bg-panel/40 px-3 py-2 text-sm text-ink" />
                      <span className="mt-2 block text-xs text-muted">Used as preferred host metadata only when the evidence does not already provide a clearer forensic host.</span>
                    </label>
                  </div>

                  <div className="mt-4 rounded-2xl border border-line bg-abyss/60 p-4 text-sm text-muted">
                    <p className="font-mono text-[11px] uppercase tracking-[0.16em] text-accent">Selected ingest mode</p>
                    <p className="mt-3 text-sm text-muted">
                      {reprocessIngestMode === "usable_search"
                        ? "Core indexing will be launched. Rules, reports and enrichment stay manual."
                        : "Experimental advanced processing will be launched. This can take significantly longer."}
                    </p>
                  </div>

                  {reprocessHasEvtx && !evtxecmdAvailable ? (
                    <div className="mt-4 rounded-2xl border border-line bg-abyss/60 p-4 text-sm text-muted">
                      <p className="font-mono text-[11px] uppercase tracking-[0.16em] text-accent">EVTX indexing profile</p>
                      <p className="mt-2">
                        EvtxECmd is not available for this evidence. Limited EVTX triage mode is partial; use it only as a fallback.
                      </p>
                      {evtxParserBackend ? <p className="mt-1 text-xs text-muted">Current EVTX parser: <span className="font-semibold text-ink">{formatEvtxBackend(evtxParserBackend)}{evtxParserBackendVersion ? ` ${evtxParserBackendVersion}` : ""}</span></p> : null}
                      <div className="mt-3 grid gap-3 md:grid-cols-2">
                        <button
                          type="button"
                          onClick={() => setReprocessEvtxProfile("fast_high_value")}
                          className={`rounded-2xl border px-4 py-3 text-left ${reprocessEvtxProfile === "fast_high_value" ? "border-accent bg-accent/10 text-ink" : "border-line bg-panel/40 text-muted"}`}
                        >
                          <div className="flex flex-wrap items-center justify-between gap-2">
                            <span className="text-sm font-semibold">Fast EVTX Search</span>
                            <span className="font-mono text-[11px] uppercase tracking-[0.16em] text-accent">Beta / Triage</span>
                          </div>
                          <p className="mt-2 text-xs">Bounded fast-profile coverage for large EVTX files. This is not full EVTX coverage.</p>
                        </button>
                        <button
                          type="button"
                          onClick={() => setReprocessEvtxProfile("full")}
                          className={`rounded-2xl border px-4 py-3 text-left ${reprocessEvtxProfile === "full" ? "border-amber bg-amber/10 text-ink" : "border-line bg-panel/40 text-muted"}`}
                        >
                          <div className="flex flex-wrap items-center justify-between gap-2">
                            <span className="text-sm font-semibold">Full EVTX Indexing</span>
                            <span className="font-mono text-[11px] uppercase tracking-[0.16em] text-amber">{evtxParserBackend === "evtxecmd_csv" ? "Recommended with EvtxECmd" : "Full coverage"}</span>
                          </div>
                        </button>
                      </div>
                      {reprocessEvtxProfile === "full" ? <p className="mt-3 text-xs text-amber">This can take a long time on evidence with many EVTX files.</p> : null}
                    </div>
                  ) : reprocessHasEvtx ? (
                    <div className="mt-4 rounded-2xl border border-mint/20 bg-mint/10 p-4 text-sm text-mint">
                      Event logs will be fully indexed with EvtxECmd automatically during re-indexing.
                    </div>
                  ) : null}

                  {reprocessMode === "full_rediscovery" ? (
                    <div className="mt-4 rounded-2xl border border-amber/30 bg-amber/10 p-4 text-sm text-amber">
                      Full rediscovery may parse a different set of artifacts than the previous ingest. Type <span className="font-mono">REDISCOVER</span> to confirm.
                      <input
                        value={rediscoveryConfirmText}
                        onChange={(event) => setRediscoveryConfirmText(event.target.value)}
                        placeholder="Type REDISCOVER"
                        className="mt-3 block w-full rounded-2xl border border-amber/40 bg-abyss/70 px-3 py-2 text-sm text-ink"
                      />
                    </div>
                  ) : null}

                  {reprocessPreviewQuery.isLoading ? (
                    <div className="mt-5 rounded-2xl border border-line bg-abyss/60 p-4 text-sm text-muted">Previewing reprocess plan...</div>
                  ) : reprocessPreview ? (
                    <div className="mt-5 space-y-4">
                      <div className="grid gap-3 md:grid-cols-3 xl:grid-cols-6">
                        <div className="rounded-2xl border border-line bg-abyss/60 p-3"><p className="font-mono text-[11px] uppercase tracking-[0.16em] text-muted">Previously selected</p><p className="mt-1 text-sm text-ink">{reprocessPreview.summary.previous_selected}</p></div>
                        <div className="rounded-2xl border border-line bg-abyss/60 p-3"><p className="font-mono text-[11px] uppercase tracking-[0.16em] text-muted">Available again</p><p className="mt-1 text-sm text-ink">{reprocessPreview.summary.available_again}</p></div>
                        <div className="rounded-2xl border border-line bg-abyss/60 p-3"><p className="font-mono text-[11px] uppercase tracking-[0.16em] text-muted">Missing</p><p className="mt-1 text-sm text-ink">{reprocessPreview.summary.missing}</p></div>
                        <div className="rounded-2xl border border-line bg-abyss/60 p-3"><p className="font-mono text-[11px] uppercase tracking-[0.16em] text-muted">Changed</p><p className="mt-1 text-sm text-ink">{reprocessPreview.summary.changed}</p></div>
                        <div className="rounded-2xl border border-line bg-abyss/60 p-3"><p className="font-mono text-[11px] uppercase tracking-[0.16em] text-muted">New candidates</p><p className="mt-1 text-sm text-ink">{reprocessPreview.summary.new_candidates}</p></div>
                        <div className="rounded-2xl border border-line bg-abyss/60 p-3"><p className="font-mono text-[11px] uppercase tracking-[0.16em] text-muted">Unsupported</p><p className="mt-1 text-sm text-ink">{reprocessPreview.summary.unsupported}</p></div>
                      </div>

                      {!reprocessPreview.previous_plan_available ? (
                        <div className="rounded-2xl border border-amber/30 bg-amber/10 p-4 text-sm text-amber">
                          No previous ingest plan is stored for this evidence. Use Choose artifacts again to build a selection or start discovery from scratch.
                        </div>
                      ) : null}

                      {reprocessPreview.warnings.length ? (
                        <div className="rounded-2xl border border-amber/30 bg-amber/10 p-4 text-sm text-amber">
                          {reprocessPreview.warnings.join(" ")}
                        </div>
                      ) : null}

                      <div className="rounded-2xl border border-line bg-abyss/60 p-4 text-sm text-muted">
                        <p className="font-mono text-[11px] uppercase tracking-[0.16em] text-accent">What will be reprocessed</p>
                        <p className="mt-2">
                          {reprocessMode === "previous_selection"
                            ? "This mode reuses the same parser selection that was used previously. New candidates are not selected automatically."
                            : reprocessMode === "choose_again"
                              ? "This mode shows current discovery candidates with the previous successful selection preselected so you can review and change it."
                              : reprocessMode === "manual_selection"
                                ? "This mode lets you choose the exact candidates and parsers before reprocessing."
                                : "This mode rebuilds the candidate list from scratch using the current discovery logic."}
                        </p>
                      </div>

                      <div className="grid gap-3 xl:grid-cols-2">
                        <div className="rounded-2xl border border-line bg-abyss/60 p-4 text-sm text-muted">
                          <p className="font-mono text-[11px] uppercase tracking-[0.16em] text-accent">Selected by artifact type</p>
                          <div className="mt-3 space-y-2">
                            {Object.entries(previewSelectedByArtifactType).length ? (
                              Object.entries(previewSelectedByArtifactType).map(([artifactType, count]) => (
                                <div key={artifactType} className="flex items-center justify-between gap-3 rounded-2xl border border-line/70 bg-panel/30 px-3 py-2">
                                  <span className="truncate text-ink">{artifactType}</span>
                                  <span className="font-mono text-xs text-muted">{count}</span>
                                </div>
                              ))
                            ) : (
                              <p>No typed candidates are available for this preview.</p>
                            )}
                          </div>
                        </div>
                        <div className="rounded-2xl border border-line bg-abyss/60 p-4 text-sm text-muted">
                          <p className="font-mono text-[11px] uppercase tracking-[0.16em] text-accent">Selected by parser</p>
                          <div className="mt-3 space-y-2">
                            {Object.entries(previewSelectedByParser).length ? (
                              Object.entries(previewSelectedByParser).map(([parserName, count]) => (
                                <div key={parserName} className="flex items-center justify-between gap-3 rounded-2xl border border-line/70 bg-panel/30 px-3 py-2">
                                  <span className="truncate text-ink">{parserName}</span>
                                  <span className="font-mono text-xs text-muted">{count}</span>
                                </div>
                              ))
                            ) : (
                              <p>No parser-level selection details are available for this preview.</p>
                            )}
                          </div>
                        </div>
                      </div>

                      <div className="max-h-[320px] space-y-3 overflow-y-auto overscroll-contain rounded-2xl border border-line bg-abyss/60 p-3">
                        {(reprocessPreview.selected_candidates as IngestPlanCandidate[]).map((candidate) => (
                          <div key={`${candidate.candidate_id}-${candidate.status}`} className="rounded-2xl border border-line bg-panel/40 p-3 text-sm text-muted">
                            <p className="truncate font-medium text-ink">{candidate.display_name || candidate.relative_path || candidate.source_path}</p>
                            <p className="mt-1 break-all text-xs">{candidate.source_path}</p>
                            <p className="mt-1 text-xs text-muted">{candidate.artifact_type} · {candidate.parser} · {candidate.status}</p>
                          </div>
                        ))}
                      </div>

                      {reprocessMode === "manual_selection" || reprocessMode === "choose_again" ? (
                        <div className="max-h-[320px] space-y-3 overflow-y-auto overscroll-contain rounded-2xl border border-line bg-abyss/60 p-3">
                          {([...(reprocessPreview.selected_candidates || []), ...(reprocessPreview.new_candidates || [])] as IngestPlanCandidate[]).map((candidate) => (
                            <label key={`${candidate.candidate_id}-${candidate.status}`} className="flex items-start gap-3 rounded-2xl border border-line bg-panel/40 p-3 text-sm text-muted">
                              <input
                                type="checkbox"
                                checked={reprocessSelectionIds.includes(candidate.candidate_id)}
                                onChange={() => toggleReprocessCandidate(candidate.candidate_id)}
                                className="mt-1"
                              />
                              <div className="min-w-0">
                                <p className="truncate font-medium text-ink">{candidate.display_name || candidate.relative_path || candidate.source_path}</p>
                                <p className="mt-1 break-all text-xs">{candidate.source_path}</p>
                                <p className="mt-1 text-xs text-muted">{candidate.artifact_type} · {candidate.parser} · {candidate.status}</p>
                              </div>
                            </label>
                          ))}
                        </div>
                      ) : null}
                    </div>
                  ) : null}
                </>
              ) : (
                <div className="rounded-2xl border border-amber/30 bg-amber/10 p-4 text-sm text-amber">
                  This evidence does not have raw discovery candidates. It will reuse the generic core indexing plan and index the evidence again.
                </div>
              )}
            </div>

            <div className="sticky bottom-0 z-10 mt-6 flex justify-end gap-3 border-t border-line bg-panel/95 pt-4 backdrop-blur">
              <button onClick={() => setReprocessDialogOpen(false)} className="rounded-2xl border border-line px-4 py-2 text-sm text-muted">Cancel</button>
              <button onClick={confirmReprocess} disabled={reprocessMutation.isPending} className="rounded-2xl bg-accent px-4 py-2 text-sm font-semibold text-abyss disabled:opacity-50">
                {reprocessMutation.isPending ? "Re-indexing..." : "Start re-indexing"}
              </button>
            </div>
          </div>
        </div>
        </div>
      ) : null}
    </div>
  );
}
