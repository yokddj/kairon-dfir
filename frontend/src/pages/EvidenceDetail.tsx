import { useEffect, useMemo, useRef, useState } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { Link, useNavigate, useParams } from "react-router-dom";
import { api, type CaseReport, type EvidenceBenchmark, type EvidenceIndexingPlan, type EvidenceIndexingStep, type EvidencePlatformProfile, type EvidenceRun, type EvtxHealthCheckResult, type EvtxProfile, type IngestPlanCandidate, type OnDemandModule, type ProblematicArtifact, type RuleRun, type VelociraptorCandidate } from "../api/client";
import DebugExportDialog from "../components/DebugExportDialog";
import HostAssignmentPanel from "../components/HostAssignmentPanel";
import InvestigationContext from "../components/InvestigationContext";
import { Disclosure } from "../components/common/Disclosure";
import { useNotifications } from "../context/NotificationsContext";
import { useHostAssignment } from "../hooks/useHostAssignment";
import { useHostContext } from "../hooks/useHostContext";
import { linuxCommandHistoryRoute, memoryEvidenceRoute } from "../lib/canonicalRoutes";
import {
  asLinuxInventory,
  buildRunTimeoutSummary,
  formatBytes,
  formatDateTime,
  formatDuration,
  formatEvidenceStatusForDisplay,
  formatEvtxBackend,
  formatHeartbeatAge,
  formatIndexingPhaseForDisplay,
  formatIndexingStatus,
  formatPlatform,
  formatProblematicStatusLabel,
  indexingStepTone,
  isRawDiscoveryEvidenceLike,
  matchesArtifactFilter,
  normalizeEvidenceHostName,
  parseActiveBenchmarkConflict,
  problematicImpact,
  problematicRecoveryText,
  problematicStatusTone,
  type ArtifactFilters,
  type EvidenceIndexingState,
  type LinuxInventory,
} from "../lib/evidenceDetailFormatting";

export default function EvidenceDetail() {
  const { evidenceId = "" } = useParams();
  const navigate = useNavigate();
  const queryClient = useQueryClient();
  const { notify } = useNotifications();
  const { activeHost, activeHostId, hasHostFilter, hostMatchesName, clearHostFilter } = useHostContext();
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
  const integrityQuery = useQuery({
    queryKey: ["evidence-integrity", evidenceQuery.data?.case_id, evidenceId],
    queryFn: () => api.getEvidenceIntegrity(evidenceQuery.data!.case_id, evidenceId),
    enabled: Boolean(evidenceId && evidenceQuery.data?.case_id),
  });
  const custodyEventsQuery = useQuery({
    queryKey: ["evidence-custody-events", evidenceQuery.data?.case_id, evidenceId],
    queryFn: () => api.getEvidenceCustodyEvents(evidenceQuery.data!.case_id, evidenceId),
    enabled: Boolean(evidenceId && evidenceQuery.data?.case_id),
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
  const registryDiagnosticQuery = useQuery({
    queryKey: ["evidence-registry-diagnostic", evidenceId],
    queryFn: () => api.getEvidenceRegistryDiagnostic(evidenceId),
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
  const pauseIndexingMutation = useMutation({
    mutationFn: () => api.pauseEvidenceIndexing(evidenceId, { reason: "Paused by analyst from Evidence Detail." }),
    onSuccess: async () => {
      notify({ title: "Indexing paused", description: "The running job was stopped. Use \"Re-index evidence\" to resume from where it left off.", tone: "success" });
      await queryClient.invalidateQueries({ queryKey: ["evidence-indexing-plan", evidenceId] });
      await queryClient.invalidateQueries({ queryKey: ["evidence", evidenceId] });
      await queryClient.invalidateQueries({ queryKey: ["evidence-runs", evidenceId] });
      await queryClient.invalidateQueries({ queryKey: ["evidence-search-summary", evidenceId] });
    },
    onError: (error) => {
      notify({ title: "Pause failed", description: error instanceof Error ? error.message : "The indexing job could not be paused.", tone: "error" });
    },
  });
  const verifyIntegrityMutation = useMutation({
    mutationFn: () => api.verifyEvidenceIntegrity(evidenceQuery.data!.case_id, evidenceId),
    onSuccess: async (result) => {
      const status = result.integrity_status === "verified" ? "SHA-256 verified." : result.integrity_status === "mismatch" ? "Hash mismatch detected." : result.integrity_status === "missing_file" ? "Stored file missing." : "Integrity check completed.";
      notify({ title: "Integrity checked", description: status, tone: result.integrity_status === "verified" ? "success" : "warning" });
      await queryClient.invalidateQueries({ queryKey: ["evidence", evidenceId] });
      await queryClient.invalidateQueries({ queryKey: ["evidence-integrity", evidenceQuery.data?.case_id, evidenceId] });
      await queryClient.invalidateQueries({ queryKey: ["evidence-custody-events", evidenceQuery.data?.case_id, evidenceId] });
      await queryClient.invalidateQueries({ queryKey: ["evidence-manifest", evidenceId] });
    },
    onError: (error) => {
      notify({ title: "Integrity check failed", description: error instanceof Error ? error.message : "The integrity check could not be completed.", tone: "error" });
    },
  });
  const exportManifestMutation = useMutation({
    mutationFn: () => api.exportEvidenceManifest(evidenceQuery.data!.case_id, evidenceId),
    onSuccess: async (manifest) => {
      const blob = new Blob([JSON.stringify(manifest, null, 2)], { type: "application/json" });
      const url = URL.createObjectURL(blob);
      const anchor = document.createElement("a");
      anchor.href = url;
      anchor.download = `kairon-evidence-manifest-${evidenceId}.json`;
      anchor.click();
      URL.revokeObjectURL(url);
      notify({ title: "Manifest exported", description: "Evidence integrity manifest downloaded as JSON.", tone: "success" });
      await queryClient.invalidateQueries({ queryKey: ["evidence-custody-events", evidenceQuery.data?.case_id, evidenceId] });
      await queryClient.invalidateQueries({ queryKey: ["evidence-manifest", evidenceId] });
    },
    onError: (error) => {
      notify({ title: "Manifest export failed", description: error instanceof Error ? error.message : "The manifest could not be exported.", tone: "error" });
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
      void queryClient.invalidateQueries({ queryKey: ["evidence-registry-diagnostic", evidenceId] });
    },
    onError: (error) => {
      notify({ title: "User activity failed", description: error instanceof Error ? error.message : "The RECmd user activity job could not be queued.", tone: "error" });
    },
  });
  const indexRegistryPersistenceSummaryMutation = useMutation({
    mutationFn: () => api.indexEvidenceRegistryPersistenceSummary(evidenceId, { force: true }),
    onSuccess: (result) => {
      notify({ title: "Registry persistence queued", description: `Registry persistence summary run ${result.run_id.slice(0, 8)} was queued.`, tone: "success" });
      void queryClient.invalidateQueries({ queryKey: ["evidence", evidenceId] });
      void queryClient.invalidateQueries({ queryKey: ["evidence-search-summary", evidenceId] });
      void queryClient.invalidateQueries({ queryKey: ["evidence-registry-diagnostic", evidenceId] });
    },
    onError: (error) => {
      notify({ title: "Registry persistence failed", description: error instanceof Error ? error.message : "The registry persistence summary job could not be queued.", tone: "error" });
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
  const evidenceHostLabel = data?.provided_host || data?.detected_host || "";
  const evidenceMatchesActiveHost = !hasHostFilter || (activeHostId && data?.host_id === activeHostId) || hostMatchesName(evidenceHostLabel);
  const platformMismatch = Boolean(data?.provided_platform && data.provided_platform !== "auto" && data.detected_platform && data.detected_platform !== "unknown" && data.provided_platform !== data.detected_platform);
  const isMemoryEvidence = String(data?.evidence_type || "").toLowerCase().includes("memory");

  const hostAssignment = useHostAssignment({
    caseId: data?.case_id,
    evidenceId,
    currentHostId: data?.host_id,
    detectedHost: data?.detected_host,
    ready: Boolean(data),
  });
  const { caseHosts, assignedHost, assignmentMismatch } = hostAssignment;

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
  const linuxInventory = asLinuxInventory(metadata.linux_inventory);
  const linuxCoverage = linuxInventory?.coverage ?? null;
  const linuxDetectedArtifacts = linuxInventory?.detected_artifacts ?? [];
  const linuxUnsupportedArtifacts = linuxInventory?.unsupported ?? [];
  const linuxWarnings = linuxInventory?.warnings ?? [];
  const diskImage = data?.disk_image ?? null;
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
  // Matches the backend watchdog's own no_progress_timeout_seconds default (job_watchdog.py):
  // a worker that stops sending heartbeats for 10+ minutes while ingest_status is still
  // active/processing is a dead work-horse, not "just slow". activeIndexingJob/indexingState
  // treat any active ingest_status as "active" regardless of heartbeat freshness, so this is
  // computed independently to reliably surface the recovery action.
  const heartbeatStaleThresholdMs = 10 * 60 * 1000;
  const heartbeatAgeMs = liveRunHeartbeatAt ? Date.now() - new Date(liveRunHeartbeatAt).getTime() : null;
  const heartbeatStale = isActive && heartbeatAgeMs !== null && heartbeatAgeMs > heartbeatStaleThresholdMs;
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
  const processingHref = data?.case_id ? `/cases/${data.case_id}?tab=processing` : "#";
  const memoryHref = data?.case_id ? memoryEvidenceRoute(data.case_id, evidenceId) : "#";
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
  const integrity = integrityQuery.data;
  const custodyEvents = custodyEventsQuery.data ?? manifest?.events ?? [];
  const integrityStatus = String(integrity?.integrity_status ?? data?.integrity_status ?? manifest?.integrity_status ?? "unknown");
  const integrityCheckedAt = integrity?.integrity_checked_at ?? data?.integrity_checked_at ?? manifest?.integrity_checked_at ?? null;
  const evidenceSha256 = integrity?.sha256 ?? data?.sha256 ?? manifest?.sha256 ?? null;
  const evidenceSizeBytes = integrity?.size_bytes ?? data?.size_bytes ?? manifest?.size_bytes ?? null;
  const uploadedAt = data?.uploaded_at ?? manifest?.uploaded_at ?? data?.created_at ?? null;
  const uploadedBy = manifest?.uploaded_by ?? data?.uploaded_by_user_id ?? null;
  const integrityStatusLabel = integrityStatus === "unknown" ? "Integrity not checked yet." : integrityStatus === "verified" ? "SHA-256 verified." : integrityStatus === "mismatch" ? "Hash mismatch detected." : integrityStatus === "missing_file" ? "Stored file missing." : "Integrity check error.";
  const integrityTone = integrityStatus === "verified" ? "border-mint/30 bg-mint/10 text-mint" : integrityStatus === "mismatch" || integrityStatus === "missing_file" || integrityStatus === "error" ? "border-danger/30 bg-danger/10 text-danger" : "border-amber/30 bg-amber/10 text-amber";
  const mftDiagnostic = mftDiagnosticQuery.data ?? searchSummaryQuery.data?.mft_diagnostic ?? null;
  const mftStatus = mftDiagnostic?.mft_status;
  const mftVisibleInParseMode = Boolean(mftDiagnostic?.mft_present_in_evidence || mftStatus?.available || mftStatus?.status === "tooling_missing" || mftStatus?.status === "indexed" || mftStatus?.status === "indexing" || mftStatus?.status === "failed");
  const mftIndexedDocs = Number(mftStatus?.indexed_docs ?? mftDiagnostic?.mft_indexed_docs ?? 0);
  const mftIsIndexing = mftStatus?.status === "indexing" || mftDiagnostic?.mft_summary_status === "queued" || mftDiagnostic?.mft_summary_status === "running" || mftDiagnostic?.mft_full_status === "queued" || mftDiagnostic?.mft_full_status === "running";
  const mftToolAvailable = Boolean(mftStatus?.tool_available ?? mftDiagnostic?.mft_backend_available);
  const registryDiagnostic = registryDiagnosticQuery.data ?? searchSummaryQuery.data?.registry_diagnostic ?? null;
  const registryVisibleInParseMode = Boolean(registryDiagnostic?.hives_present || registryDiagnostic?.registry_events_present || registryDiagnostic?.derived_persistence_indexed);
  const registrySummaryStatus = registryDiagnostic?.registry_status?.persistence_summary_status ?? registryDiagnostic?.persistence_summary_status ?? "not_indexed";
  const registryPersistenceDocs = Number(registryDiagnostic?.registry_status?.persistence_summary_docs ?? registryDiagnostic?.registry_persistence_docs ?? 0);
  const registryModificationCoverage = registryDiagnostic?.registry_modification_coverage;
  const registryEventDocs = Number(registryModificationCoverage?.registry_event_docs_indexed ?? registryDiagnostic?.registry_event_docs ?? 0);
  const registryCommandEvidenceCount = Number(registryModificationCoverage?.registry_command_evidence_count ?? registryDiagnostic?.registry_command_evidence_count ?? 0);
  const registryModificationStatus = registryModificationCoverage?.status ?? (registryEventDocs ? "indexed" : registryDiagnostic?.registry_events_present ? "available_from_event_logs" : "not_present");
  const registryIsIndexing = registryDiagnostic?.status === "indexing" || registrySummaryStatus === "queued" || registrySummaryStatus === "running" || registrySummaryStatus === "indexing" || registryDiagnostic?.user_activity_status === "queued" || registryDiagnostic?.user_activity_status === "running";
  const registryHiveList = registryDiagnostic?.registry_status?.hives?.length ? registryDiagnostic.registry_status.hives : registryDiagnostic?.detected_hives ?? [];
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
  // Set by app.workers.tasks.extraction_progress specifically during
  // disk-image materialization, where the total file count genuinely
  // isn't known until a pytsk3 directory walk completes -- a percentage
  // computed from an unknown denominator would be a floor value, not a
  // real measurement, so it is not shown as one (see the progress/phase
  // timing sprint this addresses). Not set (falsy) for every other
  // ingest path, which continues to show its own real, moving percentage
  // exactly as before.
  const progressIndeterminate = data?.metadata_json?.progress_indeterminate === true;
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
  const platformProfile: EvidencePlatformProfile = data?.platform_profile ?? {
    platform: (data?.effective_platform ?? "unknown") as string,
    platforms: [],
    capabilities: {
      supportsTimeline: false,
      supportsSearch: false,
      supportsProcesses: false,
      supportsNetwork: false,
      supportsPersistence: false,
      supportsRegistry: false,
      supportsJournal: false,
      supportsMemory: false,
      supportsPackages: false,
      supportsServices: false,
      supportsUsers: false,
      supportsFilesystem: false,
      supportsBrowser: false,
      supportsCloud: false,
      supportsEmail: false,
    },
    groups: [],
    quick_selects: [],
    categories: [],
    artifacts: [],
    available_categories: [],
  };
  const categoryLabelLookup = useMemo(
    () =>
      platformProfile.categories.reduce<Record<string, string>>((accumulator, category) => {
        accumulator[category.id] = category.label;
        return accumulator;
      }, {}),
    [platformProfile.categories],
  );
  const supportedCategoryOptions = useMemo(
    () =>
      candidatesByCategory
        .map(([category, candidates]) => ({
          category,
          label: categoryLabelLookup[category] ?? formatCategoryLabel(category),
          supportedIds: candidates.filter((candidate) => candidate.supported).map((candidate) => candidate.id),
          parseableCount: candidates.filter((candidate) => candidate.supported && candidate.parser_status !== "partial").length,
          partialCount: candidates.filter((candidate) => candidate.supported && candidate.parser_status === "partial").length,
        }))
        .filter((entry) => entry.supportedIds.length > 0),
    [candidatesByCategory, categoryLabelLookup],
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
  const selectedIndexingLocked = activeIndexingJob;
  const platformCategoryOptions = useMemo(() => {
    const seen = new Set<string>();
    return platformProfile.categories
      .filter((option) => {
        if (seen.has(option.id)) return false;
        seen.add(option.id);
        return true;
      })
      .map((option) => {
        const supported = supportedCategoryOptions.find((entry) => entry.category === option.id);
        const selectedCount = supported?.supportedIds.filter((id) => selectedCandidateIds.includes(id)).length ?? 0;
        return { ...option, supported, selectedCount, disabled: !supported || selectedIndexingLocked };
      });
  }, [platformProfile.categories, supportedCategoryOptions, selectedCandidateIds, selectedIndexingLocked]);
  const platformQuickSelects = useMemo(
    () =>
      (platformProfile.quick_selects ?? [])
        .map((quickSelect) => ({
          ...quickSelect,
          category_ids: quickSelect.category_ids.filter((categoryId) => supportedCategoryOptions.some((option) => option.category === categoryId)),
        }))
        .filter((quickSelect) => quickSelect.category_ids.length > 0),
    [platformProfile.quick_selects, supportedCategoryOptions],
  );
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

  function selectCategories(categories: string[]) {
    const categorySet = new Set(categories);
    setSelectedCandidateIds(discoveryCandidates.filter((candidate) => categorySet.has(candidate.category) && candidate.supported).map((candidate) => candidate.id));
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
  type SupportedCategoryOption = (typeof supportedCategoryOptions)[number];
  type MinimalCategoryOption = {
    id: string;
    label: string;
    group_id: string;
    group_label: string;
    platform: string;
    supported?: SupportedCategoryOption;
    selectedCount: number;
    disabled: boolean;
  };
  const minimalCategoryOptions: MinimalCategoryOption[] = platformCategoryOptions.length
    ? platformCategoryOptions
    : supportedCategoryOptions.map((option) => {
        const selectedCount = option.supportedIds.filter((id) => selectedCandidateIds.includes(id)).length;
        return { id: option.category, label: option.label, supported: option, disabled: selectedIndexingLocked, selectedCount, group_id: "discovered", group_label: "Discovered", platform: String(platformProfile.platform || "unknown") };
      });
  const minimalCategoryGroups = useMemo(() => {
    const groups = new Map<string, { id: string; label: string; items: MinimalCategoryOption[] }>();
    minimalCategoryOptions.forEach((option) => {
      const key = String(option.group_id || option.group_label || "discovered");
      const existing = groups.get(key) ?? { id: key, label: String(option.group_label || "Discovered"), items: [] };
      existing.items.push(option);
      groups.set(key, existing);
    });
    return Array.from(groups.values());
  }, [minimalCategoryOptions]);
  const supportedCategoryGroups = useMemo(() => {
    const lookup = new Map(supportedCategoryOptions.map((option) => [option.category, option]));
    const groups = platformProfile.groups
      .map((group) => ({
        id: group.id,
        label: group.label,
        items: group.categories.map((category) => lookup.get(category.id)).filter((option): option is (typeof supportedCategoryOptions)[number] => Boolean(option)),
      }))
      .filter((group) => group.items.length > 0);
    const groupedIds = new Set(groups.flatMap((group) => group.items.map((item) => item.category)));
    const remaining = supportedCategoryOptions.filter((option) => !groupedIds.has(option.category));
    if (remaining.length) groups.push({ id: "detected", label: "Detected", items: remaining });
    return groups;
  }, [platformProfile.groups, supportedCategoryOptions]);
  const commandHistoryHref = data?.case_id ? linuxCommandHistoryRoute(data.case_id, new URLSearchParams({ evidence_id: evidenceId })) : "#";
  const findingsHref = data?.case_id ? `/cases/${data.case_id}/findings?evidence_id=${encodeURIComponent(evidenceId)}` : "#";
  const addFindingHref = data?.case_id ? `/cases/${data.case_id}/findings?create=1&evidence_id=${encodeURIComponent(evidenceId)}&title=${encodeURIComponent("Evidence note")}&source_view=evidence${data.host_id ? `&host_id=${encodeURIComponent(data.host_id)}` : ""}` : "#";
  const deleteConfirmationValid = deleteConfirmText.trim() === "DELETE";
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
            {activeIndexingJob ? (
              <button type="button" onClick={() => pauseIndexingMutation.mutate()} disabled={pauseIndexingMutation.isPending} className="rounded-2xl border border-warning/40 bg-warning/10 px-4 py-2 text-sm font-semibold text-warning disabled:opacity-50">
                {pauseIndexingMutation.isPending ? "Pausing..." : "Pause indexing"}
              </button>
            ) : null}
            <button type="button" onClick={() => setDeleteDialogOpen(true)} className="rounded-2xl border border-danger/40 bg-danger/10 px-4 py-2 text-sm text-danger">
              Delete evidence
            </button>
            {data?.case_id ? <Link to={addFindingHref} className="rounded-2xl border border-accent/40 bg-accent/10 px-4 py-2 text-sm text-accent">Add finding</Link> : null}
            {data?.case_id ? <Link to={`/cases/${data.case_id}`} className="rounded-2xl border border-line bg-abyss/80 px-4 py-2 text-sm text-muted">Back to case</Link> : null}
          </div>
        </div>

        {(activeIndexingJob || retryActive) ? (
          <div className="mt-5 rounded-3xl border border-accent/30 bg-accent/10 p-5">
            <div className="flex flex-col gap-4 md:flex-row md:items-center md:justify-between">
              <div>
                <p className="font-mono text-[11px] uppercase tracking-[0.18em] text-accent">{progressTitle}</p>
                <h3 className="mt-1 text-2xl font-semibold text-ink">{progressIndeterminate ? "Active" : `${progressPercent}%`}</h3>
                <p className="mt-1 text-sm text-muted">{retryActive ? "Retrying failed artifacts" : formatIndexingPhaseForDisplay(displayCounts.phase)}</p>
                {progressIndeterminate ? (
                  <p className="mt-1 text-xs text-muted">Progress can't be shown as a percentage yet -- the file count is unknown until the walk finishes. {liveRunHeartbeatAt ? `Last activity: ${formatDateTime(liveRunHeartbeatAt)}.` : ""}</p>
                ) : null}
              </div>
              <div className="h-3 min-w-[220px] flex-1 overflow-hidden rounded-full bg-abyss/80">
                {progressIndeterminate ? (
                  <div className="h-full w-full animate-pulse rounded-full bg-accent/50" data-testid="evidence-progress-indeterminate-bar" />
                ) : (
                  <div className="h-full rounded-full bg-accent transition-all duration-500" style={{ width: `${Math.max(0, Math.min(100, progressPercent))}%` }} />
                )}
              </div>
            </div>
          </div>
        ) : null}

        {heartbeatStale ? (
          <div className="mt-5 rounded-3xl border border-warning/40 bg-warning/10 p-5" data-testid="evidence-heartbeat-stale-banner">
            <div className="flex flex-col gap-3 md:flex-row md:items-center md:justify-between">
              <div>
                <p className="font-mono text-[11px] uppercase tracking-[0.18em] text-warning">Indexing appears stuck</p>
                <p className="mt-1 text-sm text-ink">No worker activity since {formatDateTime(liveRunHeartbeatAt)}. Cancel the stale state, then retry indexing.</p>
              </div>
              <button
                type="button"
                onClick={() => cancelIndexingMutation.mutate()}
                disabled={cancelIndexingMutation.isPending}
                className="rounded-2xl border border-warning/50 bg-warning/20 px-4 py-2 text-sm font-semibold text-warning disabled:opacity-60"
              >
                {cancelIndexingMutation.isPending ? "Cancelling..." : "Cancel stuck indexing"}
              </button>
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
        <HostAssignmentPanel
          hostId={data?.host_id}
          detectedHost={data?.detected_host}
          providedHost={data?.provided_host}
          assignmentMismatch={assignmentMismatch}
          isMemoryEvidence={isMemoryEvidence}
          assignedHostDisplayName={assignedHost?.display_name}
          caseHosts={caseHosts}
          hostAssignmentMode={hostAssignment.mode}
          onHostAssignmentModeChange={hostAssignment.setMode}
          hostAssignmentId={hostAssignment.selectedHostId}
          onHostAssignmentIdChange={hostAssignment.setSelectedHostId}
          hostAssignmentName={hostAssignment.newHostName}
          onHostAssignmentNameChange={hostAssignment.setNewHostName}
          onSubmit={hostAssignment.submit}
          isSubmitting={hostAssignment.isSubmitting}
        />
        <div className="mt-5 rounded-3xl border border-line bg-abyss/60 p-4" data-testid="evidence-integrity-panel">
          <div className="flex flex-col gap-4 xl:flex-row xl:items-start xl:justify-between">
            <div className="min-w-0">
              <div className="flex flex-wrap items-center gap-3">
                <p className="font-mono text-[11px] uppercase tracking-[0.18em] text-accent">Evidence Integrity</p>
                <span className={`rounded-full border px-3 py-1 text-xs font-semibold ${integrityTone}`}>{integrityStatus.replaceAll("_", " ")}</span>
              </div>
              <p className="mt-2 text-sm text-muted">{integrityStatusLabel}</p>
            </div>
            <div className="flex shrink-0 flex-wrap gap-2">
              <button type="button" onClick={() => verifyIntegrityMutation.mutate()} disabled={!data?.case_id || verifyIntegrityMutation.isPending} className="rounded-2xl bg-accent px-4 py-2 text-sm font-semibold text-abyss disabled:opacity-60">{verifyIntegrityMutation.isPending ? "Verifying..." : "Verify integrity"}</button>
              <button type="button" onClick={() => exportManifestMutation.mutate()} disabled={!data?.case_id || exportManifestMutation.isPending} className="rounded-2xl border border-line bg-panel/60 px-4 py-2 text-sm text-muted disabled:opacity-60">{exportManifestMutation.isPending ? "Exporting..." : "Export manifest"}</button>
            </div>
          </div>
          <div className="mt-4">
            <Disclosure label="Technical details" testId="evidence-integrity-technical-details">
              <div className="grid gap-3 md:grid-cols-2 xl:grid-cols-4">
                <div className="rounded-2xl border border-line bg-panel/60 px-3 py-2"><p className="font-mono text-[10px] uppercase tracking-[0.16em] text-muted">SHA-256</p><p className="mt-1 break-all font-mono text-xs text-ink">{evidenceSha256 || "No hash recorded yet"}</p></div>
                <div className="rounded-2xl border border-line bg-panel/60 px-3 py-2"><p className="font-mono text-[10px] uppercase tracking-[0.16em] text-muted">Size</p><p className="mt-1 text-sm font-semibold text-ink">{formatBytes(evidenceSizeBytes)}</p></div>
                <div className="rounded-2xl border border-line bg-panel/60 px-3 py-2"><p className="font-mono text-[10px] uppercase tracking-[0.16em] text-muted">Uploaded by</p><p className="mt-1 truncate text-sm font-semibold text-ink">{uploadedBy || "-"}</p></div>
                <div className="rounded-2xl border border-line bg-panel/60 px-3 py-2"><p className="font-mono text-[10px] uppercase tracking-[0.16em] text-muted">Last integrity check</p><p className="mt-1 text-sm font-semibold text-ink">{formatDateTime(integrityCheckedAt)}</p></div>
              </div>
              <div className="mt-4 border-t border-line pt-4">
                <p className="font-mono text-[11px] uppercase tracking-[0.18em] text-muted">Chain of Custody / Activity</p>
                {custodyEvents.length ? <ol className="mt-3 space-y-2">{custodyEvents.slice(-8).reverse().map((event) => <li key={event.id} className="rounded-2xl border border-line bg-panel/60 px-3 py-2"><div className="flex flex-wrap items-center justify-between gap-2"><span className="font-mono text-[11px] uppercase tracking-[0.14em] text-accent">{event.event_type.replaceAll("_", " ")}</span><span className="text-xs text-muted">{formatDateTime(event.timestamp)}</span></div><p className="mt-1 text-sm text-ink">{event.summary}</p>{event.actor_user_id ? <p className="mt-1 text-xs text-muted">Actor: {event.actor_user_id}</p> : null}</li>)}</ol> : <p className="mt-3 rounded-2xl border border-line bg-panel/60 px-3 py-2 text-sm text-muted">No chain-of-custody events recorded yet.</p>}
              </div>
            </Disclosure>
          </div>
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
            <div className="mt-4 space-y-4">
              {minimalCategoryGroups.map((group) => (
                <div key={group.id}>
                  <p className="font-mono text-[11px] uppercase tracking-[0.16em] text-muted">{group.label}</p>
                  <div className="mt-2 grid gap-2 md:grid-cols-2 xl:grid-cols-3">
                    {group.items.map((option) => (
                      <label key={option.id} className={`flex min-h-[70px] items-start gap-3 rounded-2xl border px-3 py-3 ${option.selectedCount ? "border-accent/40 bg-accent/10" : "border-line bg-panel/40"} ${option.disabled ? "opacity-50" : "cursor-pointer"}`}>
                        <input type="checkbox" className="mt-1" disabled={option.disabled} checked={Boolean(option.supported && option.selectedCount === option.supported.supportedIds.length)} onChange={() => toggleCategorySelection(option.id)} />
                        <span>
                          <span className="block text-sm font-semibold text-ink">{option.label}</span>
                          <span className="mt-1 block text-xs text-muted">{option.supported ? `${option.supported.supportedIds.length} candidates` : "Not detected"}</span>
                        </span>
                      </label>
                    ))}
                  </div>
                </div>
              ))}
            </div>
            {mftVisibleInParseMode ? (
              <div className={`mt-4 rounded-3xl border p-4 ${mftIndexedDocs > 0 ? "border-mint/25 bg-mint/10" : mftStatus?.status === "tooling_missing" ? "border-warning/40 bg-warning/10" : "border-accent/30 bg-accent/10"}`}>
                <div className="flex flex-col gap-3 lg:flex-row lg:items-start lg:justify-between">
                  <div className="min-w-0">
                    <p className="font-mono text-[11px] uppercase tracking-[0.16em] text-accent">NTFS / MFT</p>
                    <h4 className="mt-1 text-base font-semibold text-ink">
                      {mftIndexedDocs > 0 ? `MFT indexed · ${mftIndexedDocs.toLocaleString()} docs` : mftIsIndexing ? "MFT indexing in progress" : mftStatus?.status === "tooling_missing" ? "MFT detected · tooling missing" : "MFT detected · available on demand"}
                    </h4>
                    <div className="mt-2 flex flex-wrap gap-2 text-xs text-muted">
                      {mftStatus?.raw_mft_found || mftDiagnostic?.mft_present_in_evidence ? <span className="rounded-full border border-line bg-abyss/60 px-2 py-1">$MFT detected{mftStatus?.raw_mft_size_bytes ? ` · ${formatBytes(mftStatus.raw_mft_size_bytes)}` : ""}</span> : null}
                      {mftStatus?.usn_found ? <span className="rounded-full border border-line bg-abyss/60 px-2 py-1">$UsnJrnl detected{mftStatus.usn_size_bytes ? ` · ${formatBytes(mftStatus.usn_size_bytes)}` : ""}</span> : null}
                      <span className="rounded-full border border-line bg-abyss/60 px-2 py-1">MFTECmd {mftToolAvailable ? "available" : "missing"}</span>
                      {mftStatus?.mftecmd_output_found ? <span className="rounded-full border border-line bg-abyss/60 px-2 py-1">MFTECmd output detected</span> : null}
                    </div>
                    <p className="mt-2 text-sm text-muted">
                      {mftIndexedDocs > 0
                        ? "Filesystem metadata is searchable and available in Artifact Views."
                        : mftToolAvailable
                        ? "Full MFT indexing can produce many records and may take longer. Use summary for quick triage or full indexing when file-level timeline/search is needed."
                        : "MFTECmd is required before raw MFT can be indexed."}
                    </p>
                  </div>
                  <div className="flex shrink-0 flex-wrap gap-2">
                    {mftIndexedDocs > 0 && data?.case_id ? (
                      <>
                        <Link to={`/search?q=${encodeURIComponent("$MFT")}&evidence_id=${encodeURIComponent(evidenceId)}`} className="rounded-2xl border border-line bg-abyss/70 px-4 py-2 text-sm text-ink">Search MFT</Link>
                        <Link to={`/cases/${data.case_id}/artifacts?evidence_id=${encodeURIComponent(evidenceId)}&artifact_type=mft`} className="rounded-2xl border border-line bg-abyss/70 px-4 py-2 text-sm text-ink">Open MFT artifacts</Link>
                      </>
                    ) : null}
                    {mftToolAvailable ? (
                      <>
                        <button type="button" disabled={conflictingIndexingActionsDisabled || mftIsIndexing || indexMftSummaryMutation.isPending} onClick={() => indexMftSummaryMutation.mutate()} className="rounded-2xl border border-accent/40 bg-accent/10 px-4 py-2 text-sm font-semibold text-accent disabled:opacity-60">
                          {indexMftSummaryMutation.isPending || mftDiagnostic?.mft_summary_status === "queued" ? "Queueing summary..." : mftDiagnostic?.mft_summary_status === "running" ? "Indexing summary..." : mftIndexedDocs > 0 ? "Re-index MFT summary" : "Index MFT summary"}
                        </button>
                        <button
                          type="button"
                          disabled={conflictingIndexingActionsDisabled || mftIsIndexing || indexMftFullMutation.isPending}
                          onClick={() => {
                            const message = mftIndexedDocs > 0
                              ? "Re-index full MFT for this evidence? This replaces existing MFT docs scoped to this evidence only."
                              : "Index full MFT for this evidence? This can add many filesystem records and may take longer than summary indexing.";
                            if (window.confirm(message)) indexMftFullMutation.mutate();
                          }}
                          className="rounded-2xl border border-warning/40 bg-warning/10 px-4 py-2 text-sm font-semibold text-warning disabled:opacity-60"
                        >
                          {indexMftFullMutation.isPending || mftDiagnostic?.mft_full_status === "queued" ? "Queueing full MFT..." : mftDiagnostic?.mft_full_status === "running" ? "Indexing full MFT..." : mftIndexedDocs > 0 ? "Re-index full MFT" : "Index full MFT"}
                        </button>
                      </>
                    ) : null}
                  </div>
                </div>
              </div>
            ) : null}
            {registryVisibleInParseMode ? (
              <div className={`mt-4 rounded-3xl border p-4 ${registryPersistenceDocs || registryDiagnostic?.registry_docs || registryDiagnostic?.user_activity_docs ? "border-mint/25 bg-mint/10" : registryDiagnostic?.status === "tooling_missing" ? "border-warning/40 bg-warning/10" : "border-accent/30 bg-accent/10"}`}>
                <div className="flex flex-col gap-3 lg:flex-row lg:items-start lg:justify-between">
                  <div className="min-w-0">
                    <p className="font-mono text-[11px] uppercase tracking-[0.16em] text-accent">Registry</p>
                    <h4 className="mt-1 text-base font-semibold text-ink">
                      {registryPersistenceDocs
                        ? "Registry persistence summary indexed"
                        : registryIsIndexing
                        ? "Registry indexing in progress"
                        : registryDiagnostic?.status === "tooling_missing"
                        ? "Registry hives detected · tooling missing"
                        : "Registry hives detected · persistence summary available"}
                    </h4>
                    <div className="mt-2 flex flex-wrap gap-2 text-xs text-muted">
                      <span className="rounded-full border border-line bg-abyss/60 px-2 py-1">{registryDiagnostic?.hive_count ?? 0} hives</span>
                      {registryHiveList.slice(0, 6).map((hive, index) => (
                        <span key={`${hive.name ?? hive.hive ?? index}`} className="rounded-full border border-line bg-abyss/60 px-2 py-1">{hive.name ?? hive.hive}{hive.size_bytes || hive.size ? ` · ${formatBytes(Number(hive.size_bytes ?? hive.size))}` : ""}</span>
                      ))}
                      <span className="rounded-full border border-line bg-abyss/60 px-2 py-1">Persistence summary: {registryPersistenceDocs ? `${registryPersistenceDocs.toLocaleString()} docs` : registrySummaryStatus.replaceAll("_", " ")}</span>
                      <span className="rounded-full border border-line bg-abyss/60 px-2 py-1">Modification events: {registryEventDocs ? `${registryEventDocs.toLocaleString()} observed` : registryModificationStatus.replaceAll("_", " ")}</span>
                      <span className="rounded-full border border-line bg-abyss/60 px-2 py-1">Registry commands: {registryCommandEvidenceCount.toLocaleString()}</span>
                      <span className="rounded-full border border-line bg-abyss/60 px-2 py-1">Full hive: {registryDiagnostic?.registry_status?.full_hive_status?.replaceAll("_", " ") ?? "available on demand"}</span>
                      {registryDiagnostic?.sysmon_registry_events ? <span className="rounded-full border border-line bg-abyss/60 px-2 py-1">Sysmon registry events: {registryDiagnostic.sysmon_registry_events.toLocaleString()}</span> : null}
                      {registryDiagnostic?.security_4657_events ? <span className="rounded-full border border-line bg-abyss/60 px-2 py-1">Security 4657: {registryDiagnostic.security_4657_events.toLocaleString()}</span> : null}
                    </div>
                    <p className="mt-2 text-sm text-muted">
                      {registryPersistenceDocs
                        ? "Common autorun, service, Winlogon, IFEO, Defender and RDP registry persistence/configuration keys are indexed with LastWrite semantics."
                        : registryDiagnostic?.tool_available
                        ? "Extracts common persistence and configuration keys from registry hives without indexing the full registry. LastWrite is shown as key LastWrite, not a value modification event."
                        : "The python-registry backend is required before registry hives can be parsed on demand."}
                    </p>
                    <p className="mt-2 text-xs text-muted">
                      {registryEventDocs
                        ? "Registry modification events are observed telemetry from Sysmon/Security logs."
                        : "Registry modification events were not present in the collected event logs. Registry persistence LastWrite remains separate from observed modifications."}
                    </p>
                    {registryDiagnostic?.coverage_gaps?.length ? <p className="mt-2 text-xs text-muted">Coverage: {registryDiagnostic.coverage_gaps.join(", ")}</p> : null}
                  </div>
                  <div className="flex shrink-0 flex-wrap gap-2">
                    {registryPersistenceDocs ? (
                      <Link to={data?.case_id ? `/cases/${data.case_id}/artifacts?evidence_id=${encodeURIComponent(evidenceId)}&artifact_type=registry_persistence` : "#"} className="rounded-2xl border border-line bg-abyss/70 px-4 py-2 text-sm text-ink">
                        Open Registry Persistence
                      </Link>
                    ) : null}
                    {registryEventDocs ? (
                      <Link to={data?.case_id ? `/cases/${data.case_id}/artifacts?evidence_id=${encodeURIComponent(evidenceId)}&artifact_type=registry_event` : "#"} className="rounded-2xl border border-line bg-abyss/70 px-4 py-2 text-sm text-ink">
                        Open Registry Events
                      </Link>
                    ) : null}
                    {registryCommandEvidenceCount ? (
                      <Link to={data?.case_id ? `/cases/${data.case_id}/artifacts?evidence_id=${encodeURIComponent(evidenceId)}&artifact_type=registry_command` : "#"} className="rounded-2xl border border-line bg-abyss/70 px-4 py-2 text-sm text-ink">
                        Open Registry Commands
                      </Link>
                    ) : null}
                    {registryDiagnostic?.tool_available ? (
                      <button
                        type="button"
                        disabled={conflictingIndexingActionsDisabled || registryIsIndexing || indexRegistryPersistenceSummaryMutation.isPending}
                        onClick={() => {
                          const message = registryPersistenceDocs
                            ? "Rebuild registry persistence summary? This replaces existing registry_persistence docs scoped to this evidence only."
                            : "Index registry persistence summary? This is scoped to common persistence/configuration keys and does not index full hives.";
                          if (window.confirm(message)) indexRegistryPersistenceSummaryMutation.mutate();
                        }}
                        className="rounded-2xl border border-accent/40 bg-accent/10 px-4 py-2 text-sm font-semibold text-accent disabled:opacity-60"
                      >
                        {indexRegistryPersistenceSummaryMutation.isPending || registrySummaryStatus === "queued" ? "Queueing summary..." : registrySummaryStatus === "running" || registrySummaryStatus === "indexing" ? "Indexing summary..." : registryPersistenceDocs ? "Re-index persistence summary" : "Index registry persistence summary"}
                      </button>
                    ) : null}
                    {registryDiagnostic?.tool_available ? (
                      <button
                        type="button"
                        disabled={conflictingIndexingActionsDisabled || registryIsIndexing || indexRecmdUserActivityMutation.isPending}
                        onClick={() => {
                          const message = registryDiagnostic?.user_activity_docs
                            ? "Rebuild registry user activity with RECmd? This replaces existing user activity docs scoped to this evidence."
                            : "Index registry user activity with RECmd? This is scoped to selected user activity registry artifacts, not full hive expansion.";
                          if (window.confirm(message)) indexRecmdUserActivityMutation.mutate();
                        }}
                        className="rounded-2xl border border-accent/40 bg-accent/10 px-4 py-2 text-sm font-semibold text-accent disabled:opacity-60"
                      >
                        {indexRecmdUserActivityMutation.isPending || registryDiagnostic?.user_activity_status === "queued" ? "Queueing registry..." : registryDiagnostic?.user_activity_status === "running" ? "Indexing registry..." : registryDiagnostic?.user_activity_docs ? "Rebuild registry user activity" : "Index registry user activity"}
                      </button>
                    ) : null}
                  </div>
                </div>
              </div>
            ) : null}
            <details className="mt-4 rounded-2xl border border-line bg-panel/40 p-3">
              <summary className="cursor-pointer text-sm font-semibold text-muted">Advanced custom</summary>
              <div className="mt-3 flex flex-wrap gap-2">
                <button type="button" onClick={selectAllSupported} disabled={!selectedIndexingAvailable || selectedIndexingLocked} className="rounded-xl border border-line bg-abyss/70 px-3 py-2 text-xs text-muted disabled:opacity-50">Select all supported</button>
                <button type="button" onClick={clearSelection} disabled={!selectedIndexingAvailable || selectedIndexingLocked} className="rounded-xl border border-line bg-abyss/70 px-3 py-2 text-xs text-muted disabled:opacity-50">Clear selection</button>
                {platformQuickSelects.map((quickSelect) => (
                  <button key={quickSelect.id} type="button" onClick={() => selectCategories(quickSelect.category_ids)} disabled={selectedIndexingLocked} className="rounded-xl border border-line bg-abyss/70 px-3 py-2 text-xs text-muted disabled:opacity-50">{quickSelect.label}</button>
                ))}
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
                {progressIndeterminate ? (
                  <p className="mt-1 text-sm text-muted">Progress can't be shown as a percentage yet -- the file count is unknown until the walk finishes. {liveRunHeartbeatAt ? `Last activity: ${formatDateTime(liveRunHeartbeatAt)}.` : ""}</p>
                ) : null}
              </>
            )}
          </div>
          {!terminalProcessingResult ? (
            <div className="rounded-3xl border border-accent/30 bg-accent/10 px-6 py-4 text-right">
              <p className="font-mono text-[11px] uppercase tracking-[0.16em] text-accent">Progress</p>
              <p className="mt-1 text-4xl font-semibold text-ink">{progressIndeterminate ? "Active" : `${progressPercent}%`}</p>
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
