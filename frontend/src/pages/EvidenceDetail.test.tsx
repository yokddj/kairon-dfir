import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { render, screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { MemoryRouter, Route, Routes } from "react-router-dom";
import { beforeEach, describe, expect, it, vi } from "vitest";

import EvidenceDetail from "./EvidenceDetail";

const getEvidenceMock = vi.fn();
const getEvidenceManifestMock = vi.fn();
const getEvidenceOnDemandModulesMock = vi.fn();
const getEvidenceSearchSummaryMock = vi.fn();
const getEvidenceMftDiagnosticMock = vi.fn();
const getEvidenceIndexingPlanMock = vi.fn();
const runEvidenceIndexingPlanMock = vi.fn();
const cancelEvidenceIndexingMock = vi.fn();
const getLongTailArtifactsMock = vi.fn();
const previewReprocessEvidenceMock = vi.fn();
const reprocessEvidenceMock = vi.fn();
const deleteEvidenceMock = vi.fn();
const parseVelociraptorSelectionMock = vi.fn();
const getProblematicArtifactsMock = vi.fn();
const getProblematicRetryCandidatesMock = vi.fn();
const getEvidenceRunsMock = vi.fn();
const listEvidenceRuleRunsMock = vi.fn();
const runRulesForEvidenceMock = vi.fn();
const listEvidenceReportsMock = vi.fn();
const generateEvidenceReportMock = vi.fn();
const downloadReportMock = vi.fn();
const getEvidenceBenchmarksMock = vi.fn();
const runEvidenceBenchmarkMock = vi.fn();
const compareEvidenceBenchmarksMock = vi.fn();
const retryProblematicArtifactMock = vi.fn();
const retryProblematicArtifactsMock = vi.fn();
const checkEvtxHealthMock = vi.fn();
const acceptProblematicArtifactWarningMock = vi.fn();
const indexEvidenceMftSummaryMock = vi.fn();
const indexEvidenceMftFullMock = vi.fn();

vi.mock("../api/client", () => ({
  api: {
    getEvidence: (...args: unknown[]) => getEvidenceMock(...args),
    getEvidenceManifest: (...args: unknown[]) => getEvidenceManifestMock(...args),
    getEvidenceOnDemandModules: (...args: unknown[]) => getEvidenceOnDemandModulesMock(...args),
    getEvidenceSearchSummary: (...args: unknown[]) => getEvidenceSearchSummaryMock(...args),
    getEvidenceMftDiagnostic: (...args: unknown[]) => getEvidenceMftDiagnosticMock(...args),
    getEvidenceIndexingPlan: (...args: unknown[]) => getEvidenceIndexingPlanMock(...args),
    runEvidenceIndexingPlan: (...args: unknown[]) => runEvidenceIndexingPlanMock(...args),
    cancelEvidenceIndexing: (...args: unknown[]) => cancelEvidenceIndexingMock(...args),
    indexEvidenceMftSummary: (...args: unknown[]) => indexEvidenceMftSummaryMock(...args),
    indexEvidenceMftFull: (...args: unknown[]) => indexEvidenceMftFullMock(...args),
    getLongTailArtifacts: (...args: unknown[]) => getLongTailArtifactsMock(...args),
    previewReprocessEvidence: (...args: unknown[]) => previewReprocessEvidenceMock(...args),
    reprocessEvidence: (...args: unknown[]) => reprocessEvidenceMock(...args),
    deleteEvidence: (...args: unknown[]) => deleteEvidenceMock(...args),
    parseVelociraptorSelection: (...args: unknown[]) => parseVelociraptorSelectionMock(...args),
    getProblematicArtifacts: (...args: unknown[]) => getProblematicArtifactsMock(...args),
    getProblematicRetryCandidates: (...args: unknown[]) => getProblematicRetryCandidatesMock(...args),
    getEvidenceRuns: (...args: unknown[]) => getEvidenceRunsMock(...args),
    listEvidenceRuleRuns: (...args: unknown[]) => listEvidenceRuleRunsMock(...args),
    runRulesForEvidence: (...args: unknown[]) => runRulesForEvidenceMock(...args),
    listEvidenceReports: (...args: unknown[]) => listEvidenceReportsMock(...args),
    generateEvidenceReport: (...args: unknown[]) => generateEvidenceReportMock(...args),
    downloadReport: (...args: unknown[]) => downloadReportMock(...args),
    getEvidenceBenchmarks: (...args: unknown[]) => getEvidenceBenchmarksMock(...args),
    runEvidenceBenchmark: (...args: unknown[]) => runEvidenceBenchmarkMock(...args),
    compareEvidenceBenchmarks: (...args: unknown[]) => compareEvidenceBenchmarksMock(...args),
    retryProblematicArtifact: (...args: unknown[]) => retryProblematicArtifactMock(...args),
    retryProblematicArtifacts: (...args: unknown[]) => retryProblematicArtifactsMock(...args),
    checkEvtxHealth: (...args: unknown[]) => checkEvtxHealthMock(...args),
    acceptProblematicArtifactWarning: (...args: unknown[]) => acceptProblematicArtifactWarningMock(...args),
  },
}));

vi.mock("../components/DebugExportDialog", () => ({
  default: () => null,
}));

const notifyMock = vi.fn();
vi.mock("../context/NotificationsContext", () => ({
  useNotifications: () => ({ notify: notifyMock }),
}));

function renderPage() {
  const queryClient = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  return render(
    <MemoryRouter initialEntries={["/evidences/evidence-1"]}>
      <QueryClientProvider client={queryClient}>
        <Routes>
          <Route path="/evidences/:evidenceId" element={<EvidenceDetail />} />
        </Routes>
      </QueryClientProvider>
    </MemoryRouter>,
  );
}

const evidencePayload = {
  id: "evidence-1",
  case_id: "case-1",
  original_filename: "collection.zip",
  stored_path: "/tmp/collection.zip",
  original_path: "/tmp/collection.zip",
  storage_mode: "uploaded",
  is_external: false,
  copy_to_storage: true,
  evidence_type: "velociraptor_zip",
  sha256: "abc",
  size_bytes: 100,
  file_count: 2,
  ingest_status: "completed",
  provided_host: "HOSTA-MANUAL",
  detected_host: "hosta",
  detected_user: null,
  source_tool: "raw_collection",
  path_validation: {},
  ingest_source: {},
  metadata_json: {
    source_type: "raw_collection",
    collection_kind: "raw_evidence_collection",
    parallel_ingest: {
      enabled: true,
      effective_parallelism: 2,
      desired_parallelism: 4,
      running_artifacts: [{ artifact: "Security.evtx", artifact_type: "windows_event", records_read: 120, records_indexed: 100 }],
      running_artifact_types: ["windows_event"],
      queued_artifacts: 3,
      bottleneck: "parsing",
      limitation_reason: "container_cpu_limit",
      artifacts_parallelized_by_type: { windows_event: 10, prefetch_raw: 4 },
      artifacts_sequential_by_type: { browser: 1 },
    },
    last_successful_ingest_plan: {
      discovery_mode: "manual",
      selected_candidates: [{ candidate_id: "evtx-1" }],
      disabled_candidates: [],
      last_reprocess_summary: { parsed_candidates: 1 },
      updated_at: "2026-05-21T10:00:00Z",
    },
    velociraptor_discovery: {
      candidates: [
        {
          id: "evtx-1",
          category: "evtx",
          artifact_type: "windows_event",
          parser_status: "parsed_native",
          parser: "evtx_raw",
          display_name: "Security.evtx",
          original_path: "Windows/System32/winevt/Logs/Security.evtx",
          local_path: "",
          normalized_windows_path: "C:\\Windows\\System32\\winevt\\Logs\\Security.evtx",
          user: null,
          browser: null,
          profile: null,
          size: 10,
          mtime: "2026-05-21T10:00:00Z",
          confidence: "high",
          supported: true,
          reason: null,
          warnings: [],
          companion_files: [],
        },
        {
          id: "shimcache-1",
          category: "shimcache",
          artifact_type: "shimcache",
          parser_status: "parsed_native",
          parser: "shimcache_raw",
          display_name: "SYSTEM hive",
          original_path: "Windows/System32/config/SYSTEM",
          local_path: "",
          normalized_windows_path: "C:\\Windows\\System32\\config\\SYSTEM",
          user: null,
          browser: null,
          profile: null,
          size: 4096,
          mtime: "2026-05-21T10:00:00Z",
          confidence: "high",
          supported: true,
          reason: null,
          warnings: [],
          companion_files: ["Windows/System32/config/SYSTEM.LOG1", "Windows/System32/config/SYSTEM.LOG2"],
        },
      ],
    },
  },
  error_log: {},
  created_at: "2026-05-21T10:00:00Z",
  processed_at: "2026-05-21T10:05:00Z",
};

const manifestPayload = {
  evidence_id: "evidence-1",
  case_id: "case-1",
  original_filename: "collection.zip",
  sha256: "abc",
  evidence_type: "velociraptor_zip",
  source_tool: "raw_collection",
  created_at: "2026-05-21T10:00:00Z",
  processed_at: "2026-05-21T10:05:00Z",
  files: [],
  artifacts: [],
  stats: {},
  errors: [],
};

const problematicArtifactsPayload = {
  evidence_id: "evidence-1",
  summary: {
    problematic_count: 2,
    parsed_with_warning: 1,
    partially_parsed: 0,
    failed: 1,
    retryable: 2,
    indexed_with_warning: 1,
    recovered_count: 1,
    unresolved_count: 0,
    data_loss_expected_count: 0,
    source_missing_but_indexed: 0,
  },
  items: [
    {
      artifact_id: "artifact-1",
      name: "bits_openvpn.evtx",
      source_path: "Windows/System32/winevt/Logs/bits_openvpn.evtx",
      artifact_type: "evtx_raw",
      parser: "evtx_raw",
      status: "parsed_with_warning",
      original_status: "parsed_with_warning",
      effective_status: "parsed_with_warning",
      effective_resolution: "indexed_records_available",
      records_read: 1000,
      records_indexed: 1000,
      effective_records_read: 1000,
      effective_records_indexed: 1000,
      bulk_batches: 1,
      error_type: "warning",
      error_message: "EVTX artifact stalled for 45s",
      timeout_seconds: 45,
      partial_data_indexed: true,
      data_loss_expected: false,
      historical_data_loss_expected: false,
      current_data_loss_expected: false,
      retryable: true,
      suggested_primary_action: "search_indexed_events",
      suggested_retry_mode: "no_detections",
      importance: "medium",
      importance_reasons: ["evtx", "partial_data_indexed"],
      retry_history: [],
      latest_retry: null,
      health_summary: "Indexed records available",
      loss_summary: "No expected data loss",
      deep_retry_history: [],
      latest_health_check: {
        diagnosis: "valid_with_warnings",
      },
      health_check: {
        diagnosis: "valid_with_warnings",
        records_seen: 1000,
        timed_out: false,
        likely_corrupt: false,
      },
      recovered: false,
      recovered_records: 0,
      accepted_warning: false,
      accepted_at: null,
    },
    {
      artifact_id: "artifact-2",
      name: "CA_PetiPotam_etw_rpc_efsr_5_6.evtx",
      source_path: "Windows/System32/winevt/Logs/CA_PetiPotam_etw_rpc_efsr_5_6.evtx",
      artifact_type: "evtx_raw",
      parser: "evtx_raw",
      status: "skipped_timeout",
      original_status: "skipped_timeout",
      effective_status: "recovered_with_warning",
      effective_resolution: "recovered_by_retry",
      records_read: 0,
      records_indexed: 0,
      effective_records_read: 869,
      effective_records_indexed: 869,
      bulk_batches: 5,
      error_type: "timeout",
      error_message: "EVTX bulk index stalled",
      timeout_seconds: 45,
      partial_data_indexed: false,
      data_loss_expected: false,
      historical_data_loss_expected: true,
      current_data_loss_expected: false,
      retryable: true,
      suggested_primary_action: "search_indexed_events",
      suggested_retry_mode: "deep_safe_mode",
      importance: "high",
      importance_reasons: ["attack_sample_name", "evtx", "partial_data_loss"],
      retry_history: [{ status: "parsed_with_warning", outcome: "recovered_more_data", records_read: 869, records_indexed: 869, mode: "deep_safe_mode" }],
      latest_retry: { status: "parsed_with_warning", outcome: "recovered_more_data", records_read: 869, records_indexed: 869, mode: "deep_safe_mode" },
      health_summary: "Indexed records available",
      loss_summary: "No expected data loss",
      deep_retry_history: [{ status: "parsed_with_warning", outcome: "recovered_more_data", records_read: 869, records_indexed: 869, mode: "deep_safe_mode" }],
      latest_health_check: null,
      health_check: null,
      recovered: true,
      recovered_records: 869,
      accepted_warning: false,
      accepted_at: null,
    },
  ],
};

const realFailureArtifactsPayload = {
  evidence_id: "evidence-1",
  summary: {
    problematic_count: 2,
    skipped_empty: 1,
    failed: 1,
    retryable: 1,
    indexed_with_warning: 0,
    recovered_count: 0,
    unresolved_count: 1,
    data_loss_expected_count: 1,
  },
  items: [
    {
      artifact_id: "store-operational",
      name: "Store Operational.evtx",
      source_path: "Windows/System32/winevt/Logs/Microsoft-Windows-Store%4Operational.evtx",
      artifact_type: "evtx_raw",
      parser: "evtx_raw",
      status: "skipped_timeout",
      original_status: "skipped_timeout",
      effective_status: "skipped_timeout",
      records_read: 0,
      records_indexed: 0,
      effective_records_read: 0,
      effective_records_indexed: 0,
      error_type: "timeout",
      error_message: "EVTX parser timed out",
      data_loss_expected: true,
      current_data_loss_expected: true,
      retryable: true,
      retry_history: [],
      latest_retry: null,
      health_summary: "Parser timeout",
      recovered: false,
    },
    {
      artifact_id: "empty-evtx",
      name: "Empty Operational.evtx",
      source_path: "Windows/System32/winevt/Logs/Empty.evtx",
      artifact_type: "evtx_raw",
      parser: "evtx_raw",
      status: "skipped_empty",
      original_status: "skipped_empty",
      effective_status: "skipped_empty",
      records_read: 0,
      records_indexed: 0,
      effective_records_read: 0,
      effective_records_indexed: 0,
      error_type: "no_records",
      error_message: "No records found",
      data_loss_expected: false,
      current_data_loss_expected: false,
      retryable: false,
      retry_history: [],
      latest_retry: null,
      health_summary: "No records",
      recovered: false,
    },
  ],
};

const minimalSearchSummary = {
  evidence_id: "evidence-1",
  case_id: "case-1",
  ingest_status: "completed",
  latest_ingest_run_id: "run-1",
  total_indexed_docs: 16518,
  artifact_type_counts: { windows_event: 12000, powershell: 50, scheduled_task: 4, prefetch: 12 },
  parser_counts: { evtx_raw: 12000 },
  source_file_counts: { "Security.evtx": 2000 },
  host_counts: { hosta: 12000 },
  user_counts: { analyst: 50 },
};

function setupMinimalEvidenceDetail(overrides?: {
  evidence?: Record<string, unknown>;
  indexingPlan?: Record<string, unknown>;
  problematicArtifacts?: Record<string, unknown>;
  retryCandidates?: Record<string, unknown>;
  runs?: unknown[];
}) {
  vi.clearAllMocks();
  getEvidenceMock.mockResolvedValue({ ...evidencePayload, ...overrides?.evidence });
  getEvidenceManifestMock.mockResolvedValue(manifestPayload);
  getEvidenceOnDemandModulesMock.mockResolvedValue({
    evidence_id: "evidence-1",
    case_id: "case-1",
    core_flow: { recommended_ingest_mode: "usable_search", steps: [] },
    modules: {},
  });
  getEvidenceSearchSummaryMock.mockResolvedValue(minimalSearchSummary);
  getEvidenceMftDiagnosticMock.mockResolvedValue({
    evidence_id: "evidence-1",
    case_id: "case-1",
    mft_present_in_evidence: false,
    mft_detected_by_inventory: false,
    mft_selected_for_indexing: false,
    mft_indexed_docs: 0,
  });
  getEvidenceIndexingPlanMock.mockResolvedValue({
    profile: "recommended",
    label: "Recommended indexing",
    primary_cta: "Index evidence for investigation",
    runnable_steps: [],
    active: false,
    active_job: null,
    requires_user_action: false,
    supported_candidate_count: 2,
    can_run: true,
    ...(overrides?.indexingPlan ?? {}),
  });
  runEvidenceIndexingPlanMock.mockResolvedValue({ accepted: true, evidence_id: "evidence-1", run_id: "plan-1", status: "queued" });
  cancelEvidenceIndexingMock.mockResolvedValue({ accepted: true });
  getLongTailArtifactsMock.mockResolvedValue({ evidence_id: "evidence-1", summary: {}, items: [] });
  previewReprocessEvidenceMock.mockResolvedValue({ evidence_id: "evidence-1", previous_plan_available: true, selected_candidates: [], missing_candidates: [], new_candidates: [], changed_candidates: [], warnings: [], summary: {} });
  reprocessEvidenceMock.mockResolvedValue({ accepted: true, evidence_id: "evidence-1", run_id: "run-1", status: "queued", mode: "previous_selection" });
  deleteEvidenceMock.mockResolvedValue(undefined);
  parseVelociraptorSelectionMock.mockResolvedValue({ accepted: true });
  getProblematicArtifactsMock.mockResolvedValue(overrides?.problematicArtifacts ?? realFailureArtifactsPayload);
  getProblematicRetryCandidatesMock.mockResolvedValue(
    overrides?.retryCandidates ?? {
      evidence_id: "evidence-1",
      summary: realFailureArtifactsPayload.summary,
      retry_candidates: [realFailureArtifactsPayload.items[0]],
      retry_candidate_count: 1,
      artifact_ids: ["store-operational"],
      affected_families: { evtx_raw: 1 },
      excluded: { skipped_empty: 1, warnings_fully_indexed: 0, other_non_retryable: 0 },
    },
  );
  getEvidenceRunsMock.mockResolvedValue(overrides?.runs ?? []);
  listEvidenceRuleRunsMock.mockResolvedValue([]);
  runRulesForEvidenceMock.mockResolvedValue({ accepted: true });
  listEvidenceReportsMock.mockResolvedValue([]);
  generateEvidenceReportMock.mockResolvedValue({ id: "report-1", status: "queued" });
  downloadReportMock.mockResolvedValue({ blob: new Blob(["report"]), filename: "report.md" });
  getEvidenceBenchmarksMock.mockResolvedValue([]);
  runEvidenceBenchmarkMock.mockResolvedValue({ accepted: true });
  compareEvidenceBenchmarksMock.mockResolvedValue({});
  retryProblematicArtifactMock.mockResolvedValue({ accepted: true });
  retryProblematicArtifactsMock.mockResolvedValue({ accepted: true, run_id: "retry-1", status: "queued" });
  checkEvtxHealthMock.mockResolvedValue({ accepted: true });
  acceptProblematicArtifactWarningMock.mockResolvedValue({ accepted: true });
  indexEvidenceMftSummaryMock.mockResolvedValue({ accepted: true });
  indexEvidenceMftFullMock.mockResolvedValue({ accepted: true });
}

describe("EvidenceDetail minimal processing UX", () => {
  beforeEach(() => {
    setupMinimalEvidenceDetail();
  });

  it("renders the minimal analyst layout", async () => {
    renderPage();

    expect(await screen.findByText("collection.zip")).toBeInTheDocument();
    expect(screen.getByText("Choose what to parse")).toBeInTheDocument();
    expect(screen.getAllByText("Processing result").length).toBeGreaterThan(0);
    expect(screen.getByText("Real failures / retry")).toBeInTheDocument();
    expect(screen.getByText("Investigation actions")).toBeInTheDocument();
    expect(screen.getByRole("button", { name: "Delete evidence" })).toBeInTheDocument();
  });

  it("shows active progress at the top with live run counters", async () => {
    setupMinimalEvidenceDetail({
      evidence: {
        ingest_status: "processing",
        metadata_json: {
          ...evidencePayload.metadata_json,
          current_ingest_run_id: "ingest-1",
          artifacts_total: 866,
          artifacts_done: 200,
          progress_pct: 23,
        },
      },
      runs: [
        {
          run_id: "ingest-1",
          run_type: "ingest",
          status: "running",
          phase: "core ingest",
          progress: 45,
          current_artifact: "PowerShell Operational.evtx",
          artifacts_total: 866,
          artifacts_done: 200,
          records_read: 1420,
          records_indexed: 1399,
          events_indexed: 1924,
          heartbeat_at: "2026-06-07T10:00:00Z",
          elapsed_seconds: 120,
        },
      ],
    });

    renderPage();

    expect((await screen.findAllByText("Processing")).length).toBeGreaterThan(0);
    expect(screen.getAllByText("45%").length).toBeGreaterThan(0);
    expect(screen.getByText(/Current artifact: PowerShell Operational\.evtx/i)).toBeInTheDocument();
    expect(screen.getByText("200 / 866")).toBeInTheDocument();
    expect(screen.getByText("1,399")).toBeInTheDocument();
  });

  it("excludes skipped empty artifacts from the main real failures table", async () => {
    renderPage();

    expect(await screen.findByText("1 parser failure need attention")).toBeInTheDocument();
    expect(screen.getByText("Store Operational.evtx")).toBeInTheDocument();
    expect(screen.queryByText("Empty Operational.evtx")).not.toBeInTheDocument();
    expect(screen.getByText(/1 empty\/no-record logs skipped/i)).toBeInTheDocument();
    expect(screen.getByText("Warnings and informational skipped items")).toBeInTheDocument();
  });

  it("calls the scoped retry action for real failures only", async () => {
    renderPage();

    await screen.findByText("Store Operational.evtx");
    await userEvent.click(screen.getByRole("button", { name: "Retry failed artifacts" }));

    await waitFor(() => {
      expect(retryProblematicArtifactsMock).toHaveBeenCalledWith("evidence-1", {
        artifact_ids: ["store-operational"],
        mode: "higher_timeout",
        preserve_existing_events: true,
        replace_existing_events_for_artifact: false,
      });
    });
  });

  it("renders retry progress with artifact totals instead of 0/0", async () => {
    setupMinimalEvidenceDetail({
      runs: [
        {
          run_id: "retry-1",
          run_type: "artifact_retry",
          mode: "higher_timeout",
          status: "running",
          phase: "retry_running",
          progress: 50,
          current_artifact: "Store Operational.evtx",
          artifacts_total: 1,
          artifacts_done: 0,
          records_read: 10,
          records_indexed: 8,
          heartbeat_at: "2026-06-07T10:00:00Z",
          elapsed_seconds: 30,
          retry_of_artifact_ids: ["store-operational"],
          recovered_count: 0,
          still_failed_count: 0,
          skipped_count: 0,
        },
      ],
    });

    renderPage();

    expect((await screen.findAllByText("Retrying failed artifacts")).length).toBeGreaterThan(0);
    expect(screen.getByText("0 / 1")).toBeInTheDocument();
    expect(screen.getAllByText("Store Operational.evtx").length).toBeGreaterThan(0);
  });

  it("renders final retry recovery as a processing result without stale ingest progress", async () => {
    setupMinimalEvidenceDetail({
      evidence: {
        ingest_status: "completed_with_errors",
        display_status: "completed_with_errors",
        investigation_ready: true,
        metadata_json: {
          ...evidencePayload.metadata_json,
          display_status: "completed_with_errors",
          investigation_ready: true,
          current_phase: "completed_with_errors",
          progress_pct: 95,
          artifacts_total: 866,
          artifacts_done: 865,
        },
      },
      problematicArtifacts: {
        evidence_id: "evidence-1",
        summary: {
          problematic_count: 284,
          failed: 0,
          skipped_empty: 283,
          retryable: 0,
          indexed_with_warning: 0,
          recovered_count: 1,
          unresolved_count: 0,
          data_loss_expected_count: 0,
        },
        items: [
          {
            artifact_id: "empty-evtx",
            name: "Empty Operational.evtx",
            source_path: "Empty Operational.evtx",
            artifact_type: "windows_event",
            parser: "evtx_raw",
            status: "skipped_empty",
            effective_status: "skipped_empty",
            data_loss_expected: false,
            current_data_loss_expected: false,
            retryable: false,
            records_read: 0,
            records_indexed: 0,
            effective_records_read: 0,
            effective_records_indexed: 0,
          },
        ],
      },
      retryCandidates: {
        evidence_id: "evidence-1",
        summary: { skipped_empty: 283, retryable: 0, data_loss_expected_count: 0 },
        retry_candidates: [],
        retry_candidate_count: 0,
        artifact_ids: [],
        affected_families: {},
        excluded: { skipped_empty: 283, warnings_fully_indexed: 0, other_non_retryable: 0 },
      },
      runs: [
        {
          run_id: "retry-1",
          run_type: "artifact_retry",
          mode: "higher_timeout",
          status: "completed",
          phase: "retry_completed_recovered",
          progress: 100,
          artifacts_total: 1,
          artifacts_done: 1,
          artifacts_failed: 0,
          records_read: 3217,
          records_indexed: 3217,
          events_indexed: 3217,
          recovered_count: 1,
          still_failed_count: 0,
          skipped_count: 0,
          final_message: "Recovered",
          retry_of_artifact_ids: ["store-operational"],
        },
        {
          run_id: "ingest-1",
          run_type: "ingest",
          status: "completed_with_errors",
          phase: "completed_with_errors",
          progress: 95,
          artifacts_total: 866,
          artifacts_done: 865,
          artifacts_failed: 1,
        },
      ],
    });

    renderPage();

    expect(await screen.findByText("Ready with warnings")).toBeInTheDocument();
    expect(screen.getAllByText("Processing result").length).toBeGreaterThan(0);
    expect(screen.getByText("Retry completed successfully")).toBeInTheDocument();
    expect(screen.getByText(/Recovered 1 · Still failing 0 · Skipped 0/)).toBeInTheDocument();
    expect(screen.getByText("No real parser failures.")).toBeInTheDocument();
    expect(screen.queryByText(/Current step: Indexing completed with errors/i)).not.toBeInTheDocument();
    expect(screen.queryByText("95%")).not.toBeInTheDocument();
    expect(screen.getByText("866 / 866")).toBeInTheDocument();
  });

  it("requires DELETE before evidence deletion is submitted", async () => {
    renderPage();

    await userEvent.click(await screen.findByRole("button", { name: "Delete evidence" }));
    const dialog = screen.getByText("Type DELETE to confirm.").closest("div");
    expect(dialog).not.toBeNull();
    const deleteButtons = screen.getAllByRole("button", { name: "Delete evidence" });
    expect(deleteButtons[1]).toBeDisabled();

    await userEvent.type(screen.getByLabelText(/Type DELETE to confirm/i), "DELETE");
    expect(deleteButtons[1]).toBeEnabled();
    await userEvent.click(deleteButtons[1]);

    await waitFor(() => {
      expect(deleteEvidenceMock).toHaveBeenCalledWith("evidence-1");
    });
  });

  it("renders investigation actions when evidence is ready", async () => {
    renderPage();

    expect(await screen.findByRole("link", { name: "Search" })).toHaveAttribute("href", "/cases/case-1/search?evidence_id=evidence-1&tab=results");
    expect(screen.getByRole("link", { name: "Command History" })).toHaveAttribute("href", "/cases/case-1/command-history?evidence_id=evidence-1");
    expect(screen.getByRole("link", { name: "Artifact Views" })).toHaveAttribute("href", "/cases/case-1/artifacts?evidence_id=evidence-1");
    expect(screen.getByRole("link", { name: "Timeline" })).toHaveAttribute("href", "/cases/case-1/search?evidence_id=evidence-1&view=timeline&sort=@timestamp&order=asc");
  });
});

describe.skip("EvidenceDetail reprocess UX", () => {
  beforeEach(() => {
    getEvidenceMock.mockReset();
    getEvidenceManifestMock.mockReset();
    getEvidenceOnDemandModulesMock.mockReset();
    getEvidenceSearchSummaryMock.mockReset();
    getEvidenceMftDiagnosticMock.mockReset();
    getEvidenceIndexingPlanMock.mockReset();
    runEvidenceIndexingPlanMock.mockReset();
    cancelEvidenceIndexingMock.mockReset();
    getLongTailArtifactsMock.mockReset();
    previewReprocessEvidenceMock.mockReset();
    reprocessEvidenceMock.mockReset();
    deleteEvidenceMock.mockReset();
    parseVelociraptorSelectionMock.mockReset();
    getProblematicArtifactsMock.mockReset();
    getProblematicRetryCandidatesMock.mockReset();
    getEvidenceRunsMock.mockReset();
    listEvidenceRuleRunsMock.mockReset();
    runRulesForEvidenceMock.mockReset();
    listEvidenceReportsMock.mockReset();
    generateEvidenceReportMock.mockReset();
    downloadReportMock.mockReset();
    getEvidenceBenchmarksMock.mockReset();
    runEvidenceBenchmarkMock.mockReset();
    compareEvidenceBenchmarksMock.mockReset();
    retryProblematicArtifactMock.mockReset();
    retryProblematicArtifactsMock.mockReset();
    checkEvtxHealthMock.mockReset();
    acceptProblematicArtifactWarningMock.mockReset();
    getEvidenceMock.mockResolvedValue(evidencePayload);
    getEvidenceManifestMock.mockResolvedValue(manifestPayload);
    getEvidenceOnDemandModulesMock.mockResolvedValue({
      evidence_id: "evidence-1",
      case_id: "case-1",
      core_flow: { recommended_ingest_mode: "usable_search", steps: ["evidence", "usable_search_ingest", "search_timeline"] },
      modules: {
        rules: { id: "rules", label: "Run Sigma/YARA rules", group: "on_demand", module_category: "on_demand_stable", status: "available", badge: "On-demand", requires: ["indexed_events"], case_route: "/cases/case-1/rules", description: "Runs rules against already indexed data. This does not reprocess evidence.", disabled_reason: null, warning: "Does not run automatically. Executes only when launched manually." },
        reports: { id: "reports", label: "Generate report", group: "on_demand", module_category: "on_demand_stable", status: "available", badge: "On-demand", requires: ["indexed_artifacts"], case_route: "/cases/case-1/reports", description: "Generate analyst-facing output after searchable data is already indexed.", warning: "Does not run automatically. Generates a bounded summary from current indexed data." },
        host_enrichment: { id: "host_enrichment", label: "Enrich hosts", group: "on_demand", module_category: "advanced", status: "beta", badge: "Advanced/Beta", requires: ["indexed_artifacts"], case_route: "/cases/case-1/hosts", description: "Optional host identity and context enrichment after ingest completes.", warning: "May be slow. Use only when host context is needed beyond Search/Timeline." },
        deep_retry: { id: "deep_retry", label: "Deep retry problematic artifacts", group: "on_demand", module_category: "advanced", status: "beta", badge: "Advanced/Beta", requires: ["problematic_artifacts"], evidence_route: "/evidences/evidence-1", description: "Retry only the artifacts that failed or were deferred, preserving the main ingest result.", warning: "Potentially slow. Use only when the main ingest has already finished and you need deeper recovery." },
        benchmark: { id: "benchmark", label: "Benchmark & tuning", group: "on_demand", module_category: "advanced", status: "advanced", badge: "Advanced/Beta", requires: ["admin"], evidence_route: "/evidences/evidence-1", description: "Advanced benchmarking for test or demo evidence. Not part of the main ingest flow.", warning: "May be slow and should only be used for test/demo evidence." },
        advanced_exports: { id: "advanced_exports", label: "Advanced debug export", group: "on_demand", module_category: "advanced", status: "advanced", badge: "Advanced", requires: ["indexed_artifacts"], case_route: "/cases/case-1/debug-export", description: "Export technical validation packs and low-level ingest diagnostics on demand.", warning: "For debugging and validation. Not part of the main analyst workflow." },
      },
    });
    getEvidenceSearchSummaryMock.mockResolvedValue({
      evidence_id: "evidence-1",
      case_id: "case-1",
      ingest_status: "completed",
      latest_ingest_run_id: "run-1",
      total_indexed_docs: 273,
      artifact_type_counts: { windows_event: 219, browser: 53, scheduled_task: 1 },
      parser_counts: { evtx_raw: 219, browser_chromium_history: 53, scheduled_task_xml: 1 },
      source_file_counts: { "Security.evtx": 219, History: 53 },
      host_counts: { hosta: 220 },
      user_counts: { bob: 53 },
    });
    getEvidenceMftDiagnosticMock.mockResolvedValue({
      evidence_id: "evidence-1",
      case_id: "case-1",
      mft_present_in_evidence: false,
      mft_detected_by_inventory: false,
      mft_selected_for_indexing: false,
      mft_indexed_docs: 0,
      mft_skipped_reason: "not_present",
      mft_backend_available: true,
      recommended_action: "No action needed unless another evidence source contains MFT output.",
      detected_candidates: [],
    });
    getEvidenceIndexingPlanMock.mockResolvedValue({
      profile: "recommended",
      label: "Recommended indexing",
      primary_cta: "Index evidence for investigation",
      subcopy: "Recommended: indexes event logs, filesystem, user activity, Defender, downloaded-file evidence and core artifacts. Rules and reports are run later.",
      steps: [
        { id: "core_artifacts", name: "Core artifacts", category: "core", status: "completed", reason: "Core artifacts indexed." },
        { id: "event_logs", name: "Event logs", category: "core", status: "completed", reason: "Event logs indexed." },
        { id: "mft_full", name: "Full MFT", category: "filesystem", status: "skipped_not_present", reason: "No MFT source detected." },
        { id: "user_activity", name: "User Activity", category: "user_activity", status: "ready", reason: "RECmd selected artifacts.", endpoint: "recmd-user-activity-index" },
        { id: "defender", name: "Defender", category: "defender", status: "ready", reason: "Defender events.", endpoint: "defender-evtx-index" },
        { id: "motw", name: "MOTW / Zone.Identifier", category: "downloaded_files", status: "derived", reason: "Derived from indexed evidence." },
      ],
      excluded: [
        { name: "SRUM", reason: "Requires Windows parser worker / Windows ESE libraries." },
        { name: "Sigma rules", reason: "Run selected rules or Sigma Smoke after indexing." },
        { name: "Reports", reason: "Generate after findings and reviewed evidence exist." },
      ],
      runnable_steps: [
        { id: "user_activity", name: "User Activity", category: "user_activity", status: "ready", reason: "RECmd selected artifacts.", endpoint: "recmd-user-activity-index" },
        { id: "defender", name: "Defender", category: "defender", status: "ready", reason: "Defender events.", endpoint: "defender-evtx-index" },
      ],
      active: false,
      active_job: null,
      requires_user_action: false,
      supported_candidate_count: 1,
      can_run: true,
    });
    runEvidenceIndexingPlanMock.mockResolvedValue({ accepted: true, evidence_id: "evidence-1", profile: "recommended", run_id: "plan-1", status: "queued", queued_jobs: [], plan: { run_id: "plan-1", profile: "recommended", status: "queued", steps: [], excluded: [], queued_jobs: [] } });
    cancelEvidenceIndexingMock.mockResolvedValue({ accepted: true, evidence_id: "evidence-1", status: "cancelled", lock_released: true, retry_allowed: true });
    previewReprocessEvidenceMock.mockResolvedValue({
      evidence_id: "evidence-1",
      previous_plan_available: true,
      mode: "previous_selection",
      summary: {
        previous_selected: 1,
        available_again: 1,
        missing: 0,
        changed: 0,
        new_candidates: 1,
        unsupported: 0,
        selected_by_artifact_type: { windows_event: 1 },
        selected_by_parser: { evtx_raw: 1 },
      },
      selected_candidates: [
        {
          candidate_id: "evtx-1",
          source_path: "Windows/System32/winevt/Logs/Security.evtx",
          relative_path: "Windows/System32/winevt/Logs/Security.evtx",
          artifact_type: "windows_event",
          parser: "evtx_raw",
          enabled: true,
          reason: "previous_plan",
          fingerprint: "fp-1",
          size: 10,
          mtime: "2026-05-21T10:00:00Z",
          status: "available",
          display_name: "Security.evtx",
        },
      ],
      missing_candidates: [],
      new_candidates: [
        {
          candidate_id: "browser-1",
          source_path: "Users/alex/AppData/Local/Google/Chrome/User Data/Default/History",
          relative_path: "Users/alex/AppData/Local/Google/Chrome/User Data/Default/History",
          artifact_type: "browser",
          parser: "sqlite_chromium",
          enabled: true,
          reason: "recommended",
          fingerprint: "fp-2",
          size: 20,
          mtime: "2026-05-21T10:00:00Z",
          status: "new",
          display_name: "Chrome History",
        },
      ],
      changed_candidates: [],
      warnings: [],
    });
    reprocessEvidenceMock.mockResolvedValue({ accepted: true, evidence_id: "evidence-1", run_id: "run-1", status: "queued", mode: "previous_selection" });
    deleteEvidenceMock.mockResolvedValue(undefined);
    parseVelociraptorSelectionMock.mockResolvedValue(undefined);
    getProblematicArtifactsMock.mockResolvedValue(problematicArtifactsPayload);
    getProblematicRetryCandidatesMock.mockResolvedValue({
      evidence_id: "evidence-1",
      summary: problematicArtifactsPayload.summary,
      retry_candidates: [],
      retry_candidate_count: 0,
      artifact_ids: [],
      affected_families: {},
      excluded: { skipped_empty: 0, warnings_fully_indexed: 1, other_non_retryable: 1 },
    });
    getLongTailArtifactsMock.mockResolvedValue({ evidence_id: "evidence-1", summary: { tail_artifacts_total: 0, running_count: 0, queued_count: 0, stalled_count: 0, high_value_count: 0, partial_indexed_count: 0, deferred_count: 0 }, items: [] });
    getEvidenceRunsMock.mockResolvedValue([
      {
        run_id: "run-1",
        run_type: "reprocess",
        mode: "previous_selection",
        status: "running",
        phase: "parsing",
        progress: 42,
        current_artifact: "Security.evtx",
        artifact_progress: "300 records read / 300 indexed",
        artifacts_total: 1,
        artifacts_done: 0,
        artifacts_failed: 0,
        records_read: 300,
        records_indexed: 300,
        heartbeat_at: "2026-05-21T10:03:00Z",
        elapsed_seconds: 12,
      },
    ]);
    listEvidenceRuleRunsMock.mockResolvedValue([]);
    runRulesForEvidenceMock.mockResolvedValue({ accepted: true, run_id: "rule-run-1", status: "queued", queued_rules: 12, message: "Queued 12 rules." });
    listEvidenceReportsMock.mockResolvedValue([]);
    generateEvidenceReportMock.mockResolvedValue({
      id: "report-1",
      case_id: "case-1",
      evidence_id: "evidence-1",
      title: "Evidence Summary Report - collection.zip",
      status: "completed",
      template: "evidence_summary",
      report_type: "summary",
      format: "markdown",
      mode: "on_demand",
      created_at: "2026-05-25T12:00:00Z",
      updated_at: "2026-05-25T12:00:01Z",
      generated_at: "2026-05-25T12:00:01Z",
      source_ingest_run_id: "ingest-1",
      size_bytes: 128,
      time_range: {},
      filters: {},
      sections_enabled: {},
      analyst_notes: {},
      selected_finding_ids: [],
      selected_key_event_ids: [],
      selected_process_chain_ids: [],
      include_raw_appendix: false,
      include_debug_metadata: false,
      metadata_json: {},
    });
    downloadReportMock.mockResolvedValue({ blob: new Blob(["report"]), filename: "report.md" });
    getEvidenceBenchmarksMock.mockResolvedValue([
      {
        benchmark_id: "bench-1",
        evidence_id: "evidence-1",
        case_id: "case-1",
        run_id: "run-1",
        label: "baseline-safe",
        mode: "reprocess_previous_selection",
        profile: "safe",
        status: "running",
        phase: "cleanup_previous_run",
        current_action: "cleanup_skipped_detections",
        last_progress_at: "2026-05-24T19:44:30Z",
        autopilot_enabled: true,
        current_attempt: 1,
        attempts: [{ attempt_number: 1, run_id: "run-1", status: "running" }],
        watchdog_status: "stalled",
        last_watchdog_check_at: "2026-05-24T19:45:00Z",
        watchdog_actions: [{ action: "reconcile_orphaned_run" }],
        final_recommendation: "The benchmark run became orphaned and was automatically reconciled.",
        current_phase_stalled: true,
        stalled_phase_warning: "No progress observed for 83.96s while benchmark remained in cleanup_previous_run.",
        total_duration_seconds: 120,
        records_per_sec: 12.5,
        artifacts_per_sec: 0.5,
        effective_parallelism: 1,
        time_to_first_event_indexed: 18,
        problematic_count: 0,
        metadata_opensearch_delta: 0,
        bottleneck_report: { bottleneck: "materialization", confidence: "medium", reasons: ["slow extract"], recommendations: ["reduce materialization time"] },
      },
    ]);
    runEvidenceBenchmarkMock.mockResolvedValue({ accepted: true, benchmark_id: "bench-2", evidence_id: "evidence-1", run_id: "run-2", status: "queued", mode: "reprocess_previous_selection", profile: "performance" });
    compareEvidenceBenchmarksMock.mockResolvedValue({ profile_recommendation: "performance", reason: "2x records/sec with same error rate" });
    retryProblematicArtifactMock.mockResolvedValue({ accepted: true, run_id: "retry-1", artifact_ids: ["artifact-1"], mode: "higher_timeout" });
    retryProblematicArtifactsMock.mockResolvedValue({ accepted: true, run_id: "retry-2", artifact_ids: ["artifact-1", "artifact-2"], mode: "higher_timeout" });
    checkEvtxHealthMock.mockResolvedValue({ artifact_id: "artifact-1", filename: "bits_openvpn.evtx", exists: true, diagnosis: "valid_with_warnings", likely_corrupt: false, retry_recommended: true, records_seen: 1000, health_check_at: "2026-05-23T10:00:00Z" });
    notifyMock.mockReset();
  });

  it("opens the modal and shows the previous-selection option", async () => {
    renderPage();
    await screen.findByText("collection.zip");
    await userEvent.click(screen.getByRole("button", { name: /Re-index evidence/i }));
    expect((await screen.findAllByText(/^Re-index evidence$/i)).length).toBeGreaterThan(0);
    await userEvent.click(screen.getByText(/Advanced re-index options/i));
    expect(await screen.findByText(/Choose artifacts again/i)).toBeInTheDocument();
    expect(await screen.findByText(/Start from scratch \/ Full rediscovery/i)).toBeInTheDocument();
    expect((await screen.findAllByText(/Core indexing/i)).length).toBeGreaterThan(0);
    expect((await screen.findAllByText(/Rules, reports and enrichment stay manual/i)).length).toBeGreaterThan(0);
    expect(screen.getByText(/Experimental processing/i)).toBeInTheDocument();
    expect(screen.getByLabelText(/Hostname \/ host label \(optional\)/i)).toHaveValue("HOSTA-MANUAL");
    expect(await screen.findByText(/Selected by artifact type/i)).toBeInTheDocument();
    expect((await screen.findAllByText(/windows_event/i)).length).toBeGreaterThan(0);
  });

  it("shows a simplified evidence summary with primary actions and collapsed advanced details", async () => {
    renderPage();
    await screen.findByText("collection.zip");
    expect(await screen.findByText(/Evidence summary/i)).toBeInTheDocument();
    expect(screen.getAllByText(/Core indexing/i).length).toBeGreaterThan(0);
    expect(screen.getAllByText(/Indexed documents/i).length).toBeGreaterThan(0);
    expect(screen.getAllByText(/Artifact types/i).length).toBeGreaterThan(0);
    expect(screen.getByText(/Problems\/deferred/i)).toBeInTheDocument();
    expect(screen.getAllByText(/HOSTA-MANUAL/i).length).toBeGreaterThan(0);
    expect(screen.getAllByRole("link", { name: /Search this evidence/i })[0]).toHaveAttribute("href", expect.stringContaining("/cases/case-1/search?evidence_id=evidence-1"));
    expect(screen.getAllByRole("link", { name: /Timeline view/i }).length).toBeGreaterThan(0);
    expect(screen.getByRole("button", { name: /Run rules/i })).toBeInTheDocument();
    expect(screen.getByRole("button", { name: /Generate report/i })).toBeInTheDocument();
    expect(screen.getAllByText(/Indexed data/i).length).toBeGreaterThan(0);
    expect(screen.getAllByText(/Advanced details/i).length).toBeGreaterThan(0);
    expect(screen.getAllByText(/On-demand modules/i).length).toBeGreaterThan(0);
  });

  it("shows MFT detected but not indexed as a follow-up, not a failure", async () => {
    getEvidenceMftDiagnosticMock.mockResolvedValueOnce({
      evidence_id: "evidence-1",
      case_id: "case-1",
      mft_present_in_evidence: true,
      mft_detected_by_inventory: true,
      mft_selected_for_indexing: false,
      mft_indexed_docs: 0,
      mft_skipped_reason: "available_on_demand",
      mft_backend_available: true,
      recommended_action: "Raw $MFT is present and MFTECmd is available. Use a scoped MFT summary or full MFT indexing action.",
      detected_candidates: [
        { name: "$MFT", source_path: "HOSTA/C/$MFT", artifact_type: "ntfs_raw", parser: "ntfs_raw", status: "unsupported", reason: "not_selected", size: 252182528 },
      ],
    });

    renderPage();
    await screen.findByText("collection.zip");

    expect(await screen.findByText(/MFT detected but not indexed/i)).toBeInTheDocument();
    expect(screen.getByText(/HOSTA\/C\/\$MFT/i)).toBeInTheDocument();
    expect(screen.getByRole("button", { name: /Index MFT summary/i })).toBeEnabled();
    expect(screen.getByRole("button", { name: /Index full MFT/i })).toBeEnabled();
  });

  it("shows SRUM tooling missing as a Windows worker requirement", async () => {
    getEvidenceMock.mockResolvedValueOnce({
      ...evidencePayload,
      metadata_json: {
        ...evidencePayload.metadata_json,
        srum_status: "tooling_missing",
        srum_tooling_missing: true,
        srum_sources_detected: 1,
      },
    });

    renderPage();
    await screen.findByText("collection.zip");

    expect((await screen.findAllByText(/Requires Windows parser worker/i)).length).toBeGreaterThan(0);
    expect(screen.getByText(/requires a Windows-capable worker/i)).toBeInTheDocument();
    expect(screen.getByRole("button", { name: /Retry when worker available/i })).toBeEnabled();
  });

  it("shows one primary investigation indexing CTA for a not-started evidence", async () => {
    getEvidenceMock.mockResolvedValue({
      ...evidencePayload,
      ingest_status: "uploaded",
      processed_at: null,
      metadata_json: {
        ...evidencePayload.metadata_json,
        current_phase: "waiting_selection",
        events_indexed: 0,
      },
    });
    getEvidenceSearchSummaryMock.mockResolvedValue({
      evidence_id: "evidence-1",
      case_id: "case-1",
      ingest_status: "uploaded",
      latest_ingest_run_id: null,
      total_indexed_docs: 0,
      artifact_type_counts: {},
      parser_counts: {},
      source_file_counts: {},
      host_counts: {},
      user_counts: {},
    });
    getEvidenceRunsMock.mockResolvedValueOnce([]);

    renderPage();
    await screen.findByText("collection.zip");

    expect(screen.getByRole("heading", { name: /Index evidence for investigation/i })).toBeInTheDocument();
    expect(screen.getByRole("button", { name: /Index evidence for investigation/i })).toBeEnabled();
    expect(screen.getByText(/Recommended indexing prepares event logs/i)).toBeInTheDocument();
    expect(screen.getAllByText(/Raw discovery inventory/i).length).toBeGreaterThan(0);
    expect(screen.queryByRole("button", { name: /Use recommended indexing/i })).not.toBeInTheDocument();
  });

  it("shows planned pending evidence as ready to index and starts recommended indexing", async () => {
    getEvidenceMock.mockResolvedValue({
      ...evidencePayload,
      ingest_status: "pending",
      investigation_ready: false,
      searchable_documents_count: 0,
      metadata_json: {
        ...evidencePayload.metadata_json,
        current_phase: "planned",
        events_indexed: 0,
        current_ingest_run_id: null,
        latest_ingest_run_id: null,
        ingest_plan: { discovery_mode: "recommended_indexing" },
      },
    });
    getEvidenceSearchSummaryMock.mockResolvedValue({
      evidence_id: "evidence-1",
      case_id: "case-1",
      ingest_status: "pending",
      latest_ingest_run_id: null,
      total_indexed_docs: 0,
      artifact_type_counts: {},
      parser_counts: {},
      source_file_counts: {},
      host_counts: {},
      user_counts: {},
    });
    getEvidenceRunsMock.mockResolvedValue([]);
    getEvidenceIndexingPlanMock.mockResolvedValueOnce({
      profile: "recommended",
      label: "Recommended indexing",
      primary_cta: "Index evidence for investigation",
      subcopy: "Recommended indexing plan.",
      steps: [{ id: "core_artifacts", name: "Core artifacts", category: "core", status: "ready", reason: "Core artifacts ready." }],
      excluded: [],
      runnable_steps: [],
      active: false,
      active_job: null,
      state: "planned_not_started",
      status_reason: "Indexing plan prepared; no parser run has been started.",
      requires_user_action: false,
      supported_candidate_count: 866,
      can_run: true,
    });

    renderPage();
    await screen.findByText("collection.zip");

    expect(screen.getByRole("heading", { name: /Ready to index/i })).toBeInTheDocument();
    expect(screen.getByText(/Indexing plan prepared · 866 supported artifacts detected/i)).toBeInTheDocument();
    expect(screen.queryByText(/Indexing in progress/i)).not.toBeInTheDocument();
    expect(screen.queryByRole("link", { name: /View progress/i })).not.toBeInTheDocument();

    await userEvent.click(screen.getByRole("button", { name: /Start recommended indexing/i }));

    await waitFor(() =>
      expect(runEvidenceIndexingPlanMock).toHaveBeenCalledWith("evidence-1", {
        profile: "recommended",
      }),
    );
  });

  it("renders selected artifact types outside advanced and hides benchmark tools by default", async () => {
    renderPage();
    await screen.findByText("collection.zip");

    const selectedSection = screen.getByTestId("selected-artifact-types-section");
    expect(within(selectedSection).getByRole("heading", { name: /Index selected artifact types/i })).toBeInTheDocument();
    expect(within(selectedSection).getByText(/Use this when you only want to parse specific artifact families/i)).toBeInTheDocument();
    expect(within(selectedSection).getByLabelText(/shimcache/i)).toBeInTheDocument();
    expect(within(selectedSection).getByRole("button", { name: /Event logs only/i })).toBeInTheDocument();
    expect(within(selectedSection).getByRole("button", { name: /Execution artifacts/i })).toBeInTheDocument();
    expect(within(selectedSection).getByRole("button", { name: /Persistence artifacts/i })).toBeInTheDocument();
    expect(screen.getAllByText(/Raw discovery inventory/i).length).toBeGreaterThan(0);
    expect(screen.queryByText(/Advanced \/ Debug benchmarks/i)).not.toBeInTheDocument();
    expect(screen.queryByText(/Benchmark & Tuning · Advanced\/Beta/i)).not.toBeInTheDocument();
  });

  it("selects shimcache without opening debug and queues shimcache-only parsing", async () => {
    renderPage();
    await screen.findByText("collection.zip");

    const selectedSection = screen.getByTestId("selected-artifact-types-section");
    await userEvent.click(within(selectedSection).getByLabelText(/shimcache/i));
    expect(within(selectedSection).getAllByText((_, element) => element?.textContent?.includes("Selected preview: 1 candidates") ?? false).length).toBeGreaterThan(0);
    expect(within(selectedSection).getAllByText(/shimcache/i).length).toBeGreaterThan(0);
    await userEvent.click(within(selectedSection).getByRole("button", { name: /Index selected types/i }));

    await waitFor(() =>
      expect(parseVelociraptorSelectionMock).toHaveBeenCalledWith(
        expect.objectContaining({
          evidence_id: "evidence-1",
          selected_candidate_ids: ["shimcache-1"],
        }),
      ),
    );
  });

  it("disables selected artifact type indexing while a worker job is active", async () => {
    getEvidenceMock.mockResolvedValue({
      ...evidencePayload,
      ingest_status: "processing",
      metadata_json: {
        ...evidencePayload.metadata_json,
        current_phase: "processing",
        current_ingest_run_id: "run-active",
        velociraptor_selected_categories: ["evtx", "scheduled_task", "service", "shimcache"],
      },
    });
    getEvidenceIndexingPlanMock.mockResolvedValueOnce({
      profile: "recommended",
      label: "Recommended indexing",
      primary_cta: "Index evidence for investigation",
      subcopy: "Recommended indexing.",
      steps: [{ id: "core_artifacts", name: "Core artifacts", category: "core", status: "running", reason: "Running." }],
      excluded: [],
      runnable_steps: [],
      active: true,
      active_job: { step: "core_ingest", run_id: "run-active", status: "processing" },
      requires_user_action: false,
      supported_candidate_count: 2,
      can_run: false,
    });
    getEvidenceRunsMock.mockResolvedValue([
      { run_id: "run-active", run_type: "ingest", status: "processing", phase: "processing", progress: 45, heartbeat_at: "2026-05-21T10:01:00Z", elapsed_seconds: 60, records_read: 10, records_indexed: 10, artifacts_done: 1, artifacts_total: 2, artifacts_failed: 0 },
    ]);

    renderPage();
    await screen.findByText("collection.zip");

    expect(screen.getAllByRole("heading", { name: /Recommended indexing is running/i }).length).toBeGreaterThan(0);
    expect(screen.getByText(/Categories in this run:/i)).toHaveTextContent("evtx, scheduled_task, service, shimcache");
    expect(screen.getByText(/Active step:/i)).toHaveTextContent("core ingest");
    const primaryProgress = screen.getByTestId("evidence-progress-primary");
    expect(within(primaryProgress).getByText(/Current step:/i)).toHaveTextContent("core ingest");
    expect(within(primaryProgress).getByText("45%")).toBeInTheDocument();
    const selectedSection = screen.getByTestId("selected-artifact-types-section");
    expect(within(selectedSection).getByText(/Manual selected indexing is locked while recommended indexing is running/i)).toBeInTheDocument();
    expect(within(selectedSection).getByText(/No manual selection is active/i)).toBeInTheDocument();
    expect(within(selectedSection).queryByText(/Selected preview: 0 candidates/i)).not.toBeInTheDocument();
    expect(within(selectedSection).getByRole("button", { name: /Index selected types/i })).toBeDisabled();
    expect(within(selectedSection).getByLabelText(/shimcache/i)).toBeDisabled();
  });

  it("uses active run counts as the visual source of truth while indexing", async () => {
    getEvidenceMock.mockResolvedValueOnce({
      ...evidencePayload,
      ingest_status: "processing",
      metadata_json: {
        ...evidencePayload.metadata_json,
        current_phase: "core_ingest",
        current_ingest_run_id: "run-live",
        events_indexed: 0,
        artifacts_done: 0,
        artifacts_total: 866,
        evtx_deferred_count: 126,
      },
    });
    getEvidenceSearchSummaryMock.mockResolvedValueOnce({
      evidence_id: "evidence-1",
      case_id: "case-1",
      ingest_status: "processing",
      latest_ingest_run_id: "run-live",
      total_indexed_docs: 0,
      artifact_type_counts: {},
      parser_counts: {},
      source_file_counts: {},
      host_counts: {},
      user_counts: {},
    });
    getEvidenceRunsMock.mockResolvedValueOnce([
      {
        run_id: "run-live",
        run_type: "ingest",
        status: "processing",
        phase: "core_ingest",
        progress: 45,
        current_artifact: "C:/Users/analyst/Documents/KaironLab01/activity.log",
        heartbeat_at: new Date().toISOString(),
        elapsed_seconds: 120,
        records_read: 2100,
        records_indexed: 1924,
        artifacts_done: 200,
        artifacts_total: 866,
        artifacts_failed: 0,
      },
    ]);

    renderPage();

    await screen.findByText("collection.zip");
    expect(screen.getByText("Indexed this run")).toBeInTheDocument();
    expect(screen.getAllByText("1,924").length).toBeGreaterThan(0);
    expect(screen.getAllByText("200 / 866").length).toBeGreaterThan(0);
    expect(screen.getByText("Pending review")).toBeInTheDocument();
    expect(screen.queryByText("Problems/deferred")).not.toBeInTheDocument();

    const primaryProgress = screen.getByTestId("evidence-progress-primary");
    expect(within(primaryProgress).getByText("45%")).toBeInTheDocument();
    expect(within(primaryProgress).getByText("1,924")).toBeInTheDocument();
    expect(within(primaryProgress).getByText(/C:\/Users\/analyst\/Documents\/KaironLab01\/activity\.log/i)).toBeInTheDocument();
    expect(screen.getAllByText("Indexing progress")).toHaveLength(1);
    expect(screen.queryByText("Progress summary")).not.toBeInTheDocument();
  });

  it("renders final persisted evidence summary after indexing completes", async () => {
    getEvidenceMock.mockResolvedValueOnce({
      ...evidencePayload,
      ingest_status: "completed",
      metadata_json: {
        ...evidencePayload.metadata_json,
        events_indexed: 3848,
        current_phase: "completed",
        evtx_deferred_count: 0,
      },
    });
    getEvidenceSearchSummaryMock.mockResolvedValueOnce({
      evidence_id: "evidence-1",
      case_id: "case-1",
      ingest_status: "completed",
      latest_ingest_run_id: "run-complete",
      total_indexed_docs: 3848,
      artifact_type_counts: { windows_event: 3200, prefetch: 100, registry: 548 },
      parser_counts: {},
      source_file_counts: {},
      host_counts: {},
      user_counts: {},
    });
    getEvidenceRunsMock.mockResolvedValueOnce([
      {
        run_id: "run-complete",
        run_type: "ingest",
        status: "completed",
        phase: "completed",
        progress: 100,
        records_read: 3900,
        records_indexed: 3848,
        artifacts_done: 866,
        artifacts_total: 866,
        artifacts_failed: 0,
      },
    ]);

    renderPage();

    await screen.findByText("collection.zip");
    expect(screen.getAllByText("Indexed documents").length).toBeGreaterThan(0);
    expect(screen.getAllByText("3,848").length).toBeGreaterThan(0);
    expect(screen.getByText("Artifact types")).toBeInTheDocument();
    const artifactTypesCard = screen.getByText("Artifact types").closest("div");
    expect(artifactTypesCard).not.toBeNull();
    expect(within(artifactTypesCard as HTMLElement).getByText("3")).toBeInTheDocument();
    expect(screen.getByText("Problems/deferred")).toBeInTheDocument();
    expect(screen.queryByText("Pending review")).not.toBeInTheDocument();
  });

  it("renders retryable parser failures card and retries only failed candidates", async () => {
    const retryablePowerShell = {
      ...problematicArtifactsPayload.items[1],
      artifact_id: "ps-op",
      name: "EVTX raw - Microsoft-Windows-PowerShell%254Operational.evtx",
      artifact_type: "windows_event",
      status: "skipped_timeout",
      effective_status: "unresolved_timeout",
      records_read: 0,
      records_indexed: 0,
      effective_records_read: 0,
      effective_records_indexed: 0,
      retryable: true,
      current_data_loss_expected: true,
      data_loss_expected: true,
      recovered: false,
      recovered_records: 0,
    };
    const retryableStore = {
      ...retryablePowerShell,
      artifact_id: "store-op",
      name: "EVTX raw - Microsoft-Windows-Store%254Operational.evtx",
    };
    const shellCoreWarning = {
      ...problematicArtifactsPayload.items[0],
      artifact_id: "shell-core",
      name: "EVTX raw - Microsoft-Windows-Shell-Core%254Operational.evtx",
      artifact_type: "windows_event",
      retryable: false,
      current_data_loss_expected: false,
      effective_status: "parsed_with_warning",
      effective_records_read: 1000,
      effective_records_indexed: 1000,
    };
    const skippedEmpty = {
      ...shellCoreWarning,
      artifact_id: "empty-evtx",
      name: "EVTX raw - HardwareEvents.evtx",
      status: "skipped_empty",
      effective_status: "skipped_empty",
      records_read: 0,
      records_indexed: 0,
      effective_records_read: 0,
      effective_records_indexed: 0,
      health_summary: "No records produced",
    };
    const summary = {
      problematic_count: 4,
      parsed_with_warning: 1,
      partially_parsed: 0,
      failed: 0,
      skipped_empty: 1,
      retryable: 2,
      indexed_with_warning: 1,
      recovered_count: 0,
      unresolved_count: 2,
      data_loss_expected_count: 2,
      source_missing_but_indexed: 0,
    };
    getProblematicArtifactsMock.mockResolvedValueOnce({
      evidence_id: "evidence-1",
      summary,
      items: [retryablePowerShell, retryableStore, shellCoreWarning, skippedEmpty],
    });
    getProblematicRetryCandidatesMock.mockResolvedValueOnce({
      evidence_id: "evidence-1",
      summary,
      retry_candidates: [retryablePowerShell, retryableStore],
      retry_candidate_count: 2,
      artifact_ids: ["ps-op", "store-op"],
      affected_families: { windows_event: 2 },
      excluded: { skipped_empty: 1, warnings_fully_indexed: 1, other_non_retryable: 0 },
    });
    retryProblematicArtifactsMock.mockResolvedValueOnce({ accepted: true, run_id: "retry-1", artifact_ids: ["ps-op", "store-op"], mode: "higher_timeout" });

    renderPage();
    await screen.findByText("collection.zip");

    expect(screen.getByText("Retryable parser failures")).toBeInTheDocument();
    expect(screen.getByRole("heading", { name: "2 retryable failures" })).toBeInTheDocument();
    expect(screen.getAllByText(/Microsoft-Windows-PowerShell/i).length).toBeGreaterThan(0);
    expect(screen.getAllByText(/Microsoft-Windows-Store/i).length).toBeGreaterThan(0);
    expect(screen.getAllByText("EVTX").length).toBeGreaterThan(0);
    expect(screen.getByText("Requires attention")).toBeInTheDocument();
    expect(screen.getAllByText("Warnings").length).toBeGreaterThan(0);
    expect(screen.getByText("Informational / skipped")).toBeInTheDocument();

    await userEvent.click(screen.getByRole("button", { name: "Retry failed artifacts" }));

    expect(retryProblematicArtifactsMock).toHaveBeenCalledWith("evidence-1", {
      artifact_ids: ["ps-op", "store-op"],
      mode: "higher_timeout",
      preserve_existing_events: true,
      replace_existing_events_for_artifact: false,
    });
  });

  it("hides retryable parser failures card when there are no retry candidates", async () => {
    getProblematicRetryCandidatesMock.mockResolvedValueOnce({
      evidence_id: "evidence-1",
      summary: problematicArtifactsPayload.summary,
      retry_candidates: [],
      retry_candidate_count: 0,
      artifact_ids: [],
      affected_families: {},
      excluded: { skipped_empty: 0, warnings_fully_indexed: 1, other_non_retryable: 1 },
    });

    renderPage();
    await screen.findByText("collection.zip");

    expect(screen.queryByText("Retryable parser failures")).not.toBeInTheDocument();
  });

  it("shows action-required controls for waiting-selection evidence without a worker run", async () => {
    getEvidenceMock.mockResolvedValue({
      ...evidencePayload,
      ingest_status: "pending",
      metadata_json: {
        ...evidencePayload.metadata_json,
        current_phase: "waiting_selection",
        evtx_parser_backend: "evtxecmd_csv",
        evtx_parser_backend_version: "2026.5.0",
      },
    });
    getEvidenceIndexingPlanMock.mockResolvedValueOnce({
      profile: "recommended",
      label: "Recommended indexing",
      primary_cta: "Index evidence for investigation",
      subcopy: "Recommended: indexes event logs, filesystem, user activity, Defender, downloaded-file evidence and core artifacts. Rules and reports are run later.",
      steps: [{ id: "core_artifacts", name: "Core artifacts", category: "core", status: "ready", reason: "Core artifacts indexed." }],
      excluded: [],
      runnable_steps: [],
      active: false,
      active_job: null,
      requires_user_action: true,
      supported_candidate_count: 1,
      can_run: true,
    });
    getEvidenceSearchSummaryMock.mockResolvedValue({
      evidence_id: "evidence-1",
      case_id: "case-1",
      ingest_status: "pending",
      latest_ingest_run_id: null,
      total_indexed_docs: 0,
      artifact_type_counts: {},
      parser_counts: {},
      source_file_counts: {},
      host_counts: {},
      user_counts: {},
    });
    getEvidenceRunsMock.mockResolvedValue([]);
    renderPage();
    await screen.findByText("collection.zip");
    expect(screen.getAllByText(/Investigation indexing/i).length).toBeGreaterThan(0);
    expect(screen.getAllByText(/Action required: select what to index/i).length).toBeGreaterThan(0);
    expect(screen.getByRole("button", { name: /Continue with recommended indexing/i })).toBeEnabled();
    expect(screen.getByRole("button", { name: /Choose categories/i })).toBeInTheDocument();
    expect(screen.getByRole("button", { name: /Cancel indexing/i })).toBeInTheDocument();
    expect(screen.queryByRole("link", { name: /View progress/i })).not.toBeInTheDocument();
    expect(screen.queryByRole("button", { name: /Index evidence for investigation/i })).not.toBeInTheDocument();
    expect(screen.queryByText(/Evidence ready to index/i)).not.toBeInTheDocument();
    expect(screen.getByRole("button", { name: /Fast indexing/i })).toBeEnabled();
    expect(screen.getAllByText(/Full coverage with EvtxECmd/i).length).toBeGreaterThan(0);
    expect(screen.queryByRole("button", { name: /Choose manually/i })).not.toBeInTheDocument();
  });

  it("shows investigation actions once evidence is ready", async () => {
    getEvidenceMock.mockResolvedValueOnce({
      ...evidencePayload,
      display_status: "completed_with_warnings",
      investigation_ready: true,
      metadata_json: {
        ...evidencePayload.metadata_json,
        display_status: "completed_with_warnings",
        investigation_ready: true,
      },
    });

    renderPage();
    await screen.findByText("collection.zip");

    expect(screen.getAllByText(/Evidence ready with warnings/i).length).toBeGreaterThan(0);
    expect(screen.getAllByRole("link", { name: /Search this evidence/i })[0]).toBeInTheDocument();
    expect(screen.getAllByRole("link", { name: /Timeline view/i })[0]).toBeInTheDocument();
    expect(screen.getAllByRole("link", { name: /Artifact Views/i })[0]).toBeInTheDocument();
    expect(screen.getByRole("button", { name: /Run rules/i })).toBeEnabled();
    expect(screen.getByRole("button", { name: /Generate report/i })).toBeEnabled();
    expect(screen.queryByRole("button", { name: /Index evidence for investigation/i })).not.toBeInTheDocument();
  });

  it("renders no-record EVTX artifacts as informational and non-retryable", async () => {
    getProblematicArtifactsMock.mockResolvedValueOnce({
      ...problematicArtifactsPayload,
      summary: {
        ...problematicArtifactsPayload.summary,
        problematic_count: 1,
        failed: 0,
        retryable: 0,
        skipped_empty: 1,
        unresolved_count: 0,
        data_loss_expected_count: 0,
        indexed_with_warning: 0,
        recovered_count: 0,
      },
      items: [
        {
          ...problematicArtifactsPayload.items[0],
          artifact_id: "artifact-empty",
          name: "HardwareEvents.evtx",
          status: "skipped_empty",
          original_status: "skipped_empty",
          effective_status: "skipped_empty",
          records_read: 0,
          records_indexed: 0,
          effective_records_read: 0,
          effective_records_indexed: 0,
          error_message: "No records produced",
          retryable: false,
          data_loss_expected: false,
          current_data_loss_expected: false,
          health_summary: "No records produced",
          loss_summary: "No expected data loss",
        },
      ],
    });

    renderPage();
    await screen.findByText("collection.zip");

    expect(screen.getByText(/Some Windows event log files do not contain parseable records/i)).toBeInTheDocument();
    expect(screen.getByText(/Empty\/no records/i)).toBeInTheDocument();
    expect(screen.getAllByText(/No records produced/i).length).toBeGreaterThan(0);
    expect(screen.getAllByText(/No expected data loss/i).length).toBeGreaterThan(0);
    expect(screen.getByRole("button", { name: /Retry selected/i })).toBeDisabled();
    expect(screen.queryByRole("button", { name: /Retry artifact/i })).not.toBeInTheDocument();
  });

  it("shows EVTX deferred and partial counts from the Fast EVTX profile", async () => {
    getEvidenceMock.mockResolvedValueOnce({
      ...evidencePayload,
      metadata_json: {
        ...evidencePayload.metadata_json,
        evtx_profile: "fast_high_value",
        evtx_selected_files: ["Windows/System32/winevt/Logs/Security.evtx"],
        evtx_deferred_count: 149,
        evtx_deferred_files: [{ path: "Windows/System32/winevt/Logs/Noise.evtx", reason: "evtx_profile_deferred" }],
        evtx_partial_count: 1,
        evtx_partial_files: [{ path: "Windows/System32/winevt/Logs/Security.evtx", reason: "max_records_per_file", records_indexed: 5000 }],
        evtx_coverage_status: "partial_fast_profile",
      },
    });
    renderPage();
    await screen.findByText("collection.zip");
    expect(screen.getAllByText(/149 deferred · 1 partial/i).length).toBeGreaterThan(0);
    expect(screen.getByText(/Fast profile: partial EVTX coverage/i)).toBeInTheDocument();
    expect(screen.getByRole("button", { name: /Continue EVTX indexing · Advanced\/Beta/i })).toBeDisabled();
  });

  it("shows full EVTX coverage and parser backend when EvtxECmd completed without partial or deferred files", async () => {
    getEvidenceMock.mockResolvedValueOnce({
      ...evidencePayload,
      metadata_json: {
        ...evidencePayload.metadata_json,
        evtx_profile: "full",
        evtx_parser_backend: "evtxecmd_csv",
        evtx_parser_backend_version: "2026.5.0",
        evtx_parser_backend_fallback: false,
        evtx_deferred_count: 0,
        evtx_partial_count: 0,
        evtx_coverage_status: "full",
      },
    });
    renderPage();
    await screen.findByText("collection.zip");
    expect(screen.getAllByText(/Full EVTX coverage/i).length).toBeGreaterThan(0);
    expect(screen.getAllByText(/EvtxECmd CSV 2026\.5\.0/i).length).toBeGreaterThan(0);
    expect(screen.queryByText(/partial EVTX coverage/i)).not.toBeInTheDocument();
    expect(screen.getAllByRole("link", { name: /Search this evidence/i })[0]).toHaveAttribute("href", "/cases/case-1/search?evidence_id=evidence-1&tab=results");
    expect(screen.getAllByRole("link", { name: /Detections/i })[0]).toHaveAttribute("href", "/cases/case-1/detections?evidence_id=evidence-1");
    expect(screen.getAllByRole("link", { name: /^Reports/i })[0]).toHaveAttribute("href", "/cases/case-1/reports?evidence_id=evidence-1");
    expect(screen.getByText(/Search by parser backend/i)).toBeInTheDocument();
    expect(screen.getAllByRole("link", { name: /evtx_raw · 219/i })[0]).toHaveAttribute("href", "/cases/case-1/search?evidence_id=evidence-1&parser=evtx_raw&tab=results");
  });

  it("launches an on-demand rules run from the rules module", async () => {
    renderPage();
    await screen.findByText("collection.zip");

    await userEvent.click(screen.getByRole("button", { name: /Run now/i }));

    await waitFor(() =>
      expect(runRulesForEvidenceMock).toHaveBeenCalledWith(
        "evidence-1",
        expect.objectContaining({
          mode: "on_demand",
          scope: "evidence",
          rule_types: ["sigma"],
        }),
      ),
    );
  });

  it("shows generate report in on-demand modules and launches it manually", async () => {
    renderPage();
    await screen.findByText("collection.zip");

    await userEvent.click(screen.getByRole("button", { name: /Generate summary/i }));

    await waitFor(() =>
      expect(generateEvidenceReportMock).toHaveBeenCalledWith(
        "evidence-1",
        expect.objectContaining({
          scope: "evidence",
          report_type: "summary",
          mode: "on_demand",
          include_search_summary: true,
          include_parser_contract: true,
        }),
      ),
    );
  });

  it("shows disabled reason when rules cannot run yet", async () => {
    getEvidenceOnDemandModulesMock.mockResolvedValueOnce({
      evidence_id: "evidence-1",
      case_id: "case-1",
      core_flow: { recommended_ingest_mode: "usable_search", steps: ["evidence", "usable_search_ingest", "search_timeline"] },
      modules: {
        rules: {
          id: "rules",
          label: "Run Sigma/YARA rules",
          group: "on_demand",
          module_category: "on_demand_stable",
          status: "disabled",
          badge: "Needs indexed data",
          requires: ["indexed_events"],
          case_route: "/cases/case-1/rules",
          description: "Runs rules against already indexed data. This does not reprocess evidence.",
          disabled_reason: "No indexed documents are available for this evidence yet.",
        },
      },
    });

    renderPage();
    await screen.findByText("collection.zip");

    expect(screen.getByText(/No indexed documents are available for this evidence yet/i)).toBeInTheDocument();
    expect(screen.getByRole("button", { name: /Run now/i })).toBeDisabled();
  });

  it("shows disabled reason when reports cannot run yet", async () => {
    getEvidenceOnDemandModulesMock.mockResolvedValueOnce({
      evidence_id: "evidence-1",
      case_id: "case-1",
      core_flow: { recommended_ingest_mode: "usable_search", steps: ["evidence", "usable_search_ingest", "search_timeline"] },
      modules: {
        reports: {
          id: "reports",
          label: "Generate report",
          group: "on_demand",
          module_category: "on_demand_stable",
          status: "disabled",
          badge: "Needs indexed data",
          requires: ["indexed_artifacts"],
          case_route: "/cases/case-1/reports",
          description: "Generate analyst-facing output after searchable data is already indexed.",
          disabled_reason: "No indexed documents are available for this evidence yet.",
        },
      },
    });

    renderPage();
    await screen.findByText("collection.zip");

    expect(screen.getByText(/No indexed documents are available for this evidence yet/i)).toBeInTheDocument();
    expect(screen.getByRole("button", { name: /Generate summary/i })).toBeDisabled();
  });

  it("shows latest rules run status and detections link", async () => {
    listEvidenceRuleRunsMock.mockResolvedValueOnce([
      {
        id: "rule-run-1",
        rule_id: null,
        rule_set_id: null,
        case_id: "case-1",
        evidence_id: "evidence-1",
        engine: "multi",
        status: "completed",
        scope: "evidence",
        matched: 2,
        total_rules: 12,
        processed_rules: 12,
        total_events: 273,
        scanned_events: 273,
        total_files: 0,
        created_detections: 2,
        duplicates: 0,
        scanned_files: 0,
        skipped_files: 0,
        current_phase: "completed",
        heartbeat_at: "2026-05-26T10:00:00Z",
        last_error: null,
        cancel_requested: false,
        retried_from_run_id: null,
        stale_reason: null,
        elapsed_seconds: 4,
        percent_complete: 100,
        stale: false,
        can_cancel: false,
        can_retry: true,
        warnings: [],
        errors: [],
        metadata_json: {},
        started_at: "2026-05-26T10:00:00Z",
        finished_at: "2026-05-26T10:00:04Z",
        created_at: "2026-05-26T10:00:00Z",
        updated_at: "2026-05-26T10:00:04Z",
      },
    ]);

    renderPage();
    await screen.findByText("collection.zip");

    expect(screen.getByText(/Latest rules run/i)).toBeInTheDocument();
    expect(screen.getByText(/Detections created:/i)).toBeInTheDocument();
    expect(screen.getByRole("link", { name: /View detections/i })).toHaveAttribute(
      "href",
      expect.stringContaining("/cases/case-1/detections?evidence_id=evidence-1&rule_run_id=rule-run-1"),
    );
  });

  it("shows latest report status and download actions", async () => {
    listEvidenceReportsMock.mockResolvedValueOnce([
      {
        id: "report-1",
        case_id: "case-1",
        evidence_id: "evidence-1",
        title: "Evidence Summary Report - collection.zip",
        status: "completed",
        template: "evidence_summary",
        report_type: "summary",
        format: "markdown",
        mode: "on_demand",
        created_at: "2026-05-25T12:00:00Z",
        updated_at: "2026-05-25T12:00:01Z",
        generated_at: "2026-05-25T12:00:01Z",
        source_ingest_run_id: "ingest-1",
        size_bytes: 128,
        time_range: {},
        filters: {},
        sections_enabled: {},
        analyst_notes: {},
        selected_finding_ids: [],
        selected_key_event_ids: [],
        selected_process_chain_ids: [],
        include_raw_appendix: false,
        include_debug_metadata: false,
        metadata_json: { warnings: [] },
      },
    ]);

    renderPage();
    await screen.findByText("collection.zip");

    expect(screen.getByText(/Latest report/i)).toBeInTheDocument();
    expect(screen.getByRole("button", { name: /^Download$/i })).toBeInTheDocument();
    expect(screen.getByRole("button", { name: /Download JSON/i })).toBeInTheDocument();
  });

  it("shows indexed document summary and artifact-type search links", async () => {
    renderPage();
    await screen.findByText("collection.zip");
    expect(screen.getAllByText("273").length).toBeGreaterThan(0);
    const browserLink = screen.getAllByRole("link", { name: /browser · 53/i })[0];
    expect(browserLink).toHaveAttribute("href", expect.stringContaining("artifact_type=browser"));
    expect(browserLink).toHaveAttribute("href", expect.stringContaining("evidence_id=evidence-1"));
  });

  it("locks body scroll while the reprocess modal is open and restores it on close", async () => {
    renderPage();
    await screen.findByText("collection.zip");
    expect(document.body.style.overflow).toBe("");
    expect(document.body.style.overscrollBehavior).toBe("");

    await userEvent.click(screen.getByRole("button", { name: /Re-index evidence/i }));
    expect((await screen.findAllByText(/^Re-index evidence$/i)).length).toBeGreaterThan(0);

    await waitFor(() => {
      expect(document.body.style.overflow).toBe("hidden");
      expect(document.body.style.overscrollBehavior).toBe("contain");
    });
    expect(screen.getByTestId("reprocess-modal-content").className).toContain("overflow-y-auto");

    await userEvent.click(screen.getByRole("button", { name: /^Close$/i }));

    await waitFor(() => {
      expect(document.body.style.overflow).toBe("");
      expect(document.body.style.overscrollBehavior).toBe("");
    });
  });

  it("defaults to previous selection and starts that mode without full rediscovery", async () => {
    renderPage();
    await screen.findByText("collection.zip");
    await userEvent.click(screen.getByRole("button", { name: /Re-index evidence/i }));
    await userEvent.click(screen.getByRole("button", { name: /Start re-indexing/i }));

    await waitFor(() =>
      expect(reprocessEvidenceMock).toHaveBeenCalledWith(
        "evidence-1",
        expect.objectContaining({
          ingest_mode: "usable_search",
          mode: "previous_selection",
          preserve_analyst_state: true,
        }),
      ),
    );
  });

  it("lets the user choose artifacts again and submit the edited selection", async () => {
    renderPage();
    await screen.findByText("collection.zip");
    await userEvent.click(screen.getByRole("button", { name: /Re-index evidence/i }));
    await userEvent.click(screen.getByText(/Advanced re-index options/i));
    await userEvent.click(screen.getByRole("button", { name: /Choose artifacts again/i }));
    const chromeRow = (await screen.findByText(/Chrome History/i)).closest("label");
    expect(chromeRow).not.toBeNull();
    await userEvent.click(within(chromeRow as HTMLElement).getByRole("checkbox"));
    await userEvent.click(screen.getByRole("button", { name: /Start re-indexing/i }));

    await waitFor(() =>
      expect(reprocessEvidenceMock).toHaveBeenCalledWith(
        "evidence-1",
        expect.objectContaining({
          mode: "choose_again",
          selected_candidate_ids: expect.arrayContaining(["evtx-1", "browser-1"]),
          preserve_analyst_state: true,
        }),
      ),
    );
  });

  it("requires REDISCOVER before starting a full rediscovery", async () => {
    renderPage();
    await screen.findByText("collection.zip");
    await userEvent.click(screen.getByRole("button", { name: /Re-index evidence/i }));
    await userEvent.click(screen.getByText(/Advanced re-index options/i));
    await userEvent.click(screen.getByRole("button", { name: /Start from scratch \/ Full rediscovery/i }));
    await userEvent.click(screen.getByRole("button", { name: /Start re-indexing/i }));
    expect(reprocessEvidenceMock).not.toHaveBeenCalled();
    await userEvent.type(screen.getByPlaceholderText(/Type REDISCOVER/i), "REDISCOVER");
    await userEvent.click(screen.getByRole("button", { name: /Start re-indexing/i }));

    await waitFor(() =>
      expect(reprocessEvidenceMock).toHaveBeenCalledWith(
        "evidence-1",
        expect.objectContaining({
          mode: "full_rediscovery",
          explicit_confirm: true,
          preserve_analyst_state: true,
        }),
      ),
    );
  });

  it("shows the no-previous-plan state for old evidence", async () => {
    previewReprocessEvidenceMock.mockResolvedValueOnce({
      evidence_id: "evidence-1",
      previous_plan_available: false,
      mode: "previous_selection",
      summary: { previous_selected: 0, available_again: 0, missing: 0, changed: 0, new_candidates: 0, unsupported: 0 },
      selected_candidates: [],
      missing_candidates: [],
      new_candidates: [],
      changed_candidates: [],
      warnings: ["No previous ingest plan is stored for this evidence."],
    });
    renderPage();
    await screen.findByText("collection.zip");
    await userEvent.click(screen.getByRole("button", { name: /Re-index evidence/i }));
    expect((await screen.findAllByText(/No previous ingest plan is stored for this evidence/i)).length).toBeGreaterThan(0);
  });
});

describe.skip("EvidenceDetail ingest progress diagnostics", () => {
  beforeEach(() => {
    getEvidenceMock.mockReset();
    getEvidenceManifestMock.mockReset();
    getEvidenceOnDemandModulesMock.mockReset();
    getEvidenceSearchSummaryMock.mockReset();
    getEvidenceMftDiagnosticMock.mockReset();
    getEvidenceIndexingPlanMock.mockReset();
    runEvidenceIndexingPlanMock.mockReset();
    previewReprocessEvidenceMock.mockReset();
    reprocessEvidenceMock.mockReset();
    deleteEvidenceMock.mockReset();
    parseVelociraptorSelectionMock.mockReset();
    getProblematicArtifactsMock.mockReset();
    getProblematicRetryCandidatesMock.mockReset();
    getEvidenceRunsMock.mockReset();
    listEvidenceReportsMock.mockReset();
    generateEvidenceReportMock.mockReset();
    downloadReportMock.mockReset();
    getEvidenceBenchmarksMock.mockReset();
    runEvidenceBenchmarkMock.mockReset();
    compareEvidenceBenchmarksMock.mockReset();
    retryProblematicArtifactMock.mockReset();
    retryProblematicArtifactsMock.mockReset();
    getEvidenceMock.mockResolvedValue({
      ...evidencePayload,
      ingest_status: "processing",
      metadata_json: {
        ...evidencePayload.metadata_json,
        progress_pct: 32,
        current_phase: "parsing",
        current_artifact_path: "Windows/System32/winevt/Logs/Security.evtx",
        current_artifact_progress_label: "Security.evtx · 1250 records read",
        current_artifact_records_read: 1250,
        current_artifact_records_indexed: 1000,
        artifacts_done: 9,
        artifacts_failed: 1,
        artifacts_total: 278,
        events_indexed: 1000,
        records_per_second: 640,
        heartbeat_at: "2026-05-22T06:34:33Z",
      },
    });
    getEvidenceManifestMock.mockResolvedValue(manifestPayload);
    getEvidenceSearchSummaryMock.mockResolvedValue({
      evidence_id: "evidence-1",
      case_id: "case-1",
      ingest_status: "processing",
      latest_ingest_run_id: "run-1",
      total_indexed_docs: 1000,
      artifact_type_counts: { windows_event: 1000 },
      parser_counts: { evtx_raw: 1000 },
      source_file_counts: { "Security.evtx": 1000 },
      host_counts: { hosta: 1000 },
      user_counts: {},
    });
    getEvidenceMftDiagnosticMock.mockResolvedValue({
      evidence_id: "evidence-1",
      case_id: "case-1",
      mft_present_in_evidence: false,
      mft_detected_by_inventory: false,
      mft_selected_for_indexing: false,
      mft_indexed_docs: 0,
      mft_skipped_reason: "not_present",
      mft_backend_available: true,
      recommended_action: "No action needed.",
      detected_candidates: [],
    });
    getEvidenceIndexingPlanMock.mockResolvedValue({
      profile: "recommended",
      label: "Recommended indexing",
      primary_cta: "Index evidence for investigation",
      subcopy: "Recommended indexing waits for the active job.",
      steps: [{ id: "core_artifacts", name: "Core artifacts", category: "core", status: "processing", reason: "Core ingest is running." }],
      excluded: [{ name: "SRUM", reason: "Requires Windows parser worker / Windows ESE libraries." }],
      runnable_steps: [],
      active: true,
      active_job: { step: "core_ingest", run_id: "run-1", status: "processing" },
      requires_user_action: false,
      supported_candidate_count: 1,
      can_run: false,
    });
    runEvidenceIndexingPlanMock.mockResolvedValue({ accepted: true, evidence_id: "evidence-1", profile: "recommended", run_id: "plan-1", status: "queued", queued_jobs: [], plan: { run_id: "plan-1", profile: "recommended", status: "queued", steps: [], excluded: [], queued_jobs: [] } });
    cancelEvidenceIndexingMock.mockResolvedValue({ accepted: true, evidence_id: "evidence-1", status: "cancelled", lock_released: true, retry_allowed: true });
    getEvidenceOnDemandModulesMock.mockResolvedValue({
      evidence_id: "evidence-1",
      case_id: "case-1",
      core_flow: { recommended_ingest_mode: "usable_search", steps: ["evidence", "usable_search_ingest", "search_timeline"] },
      modules: {
        rules: { id: "rules", label: "Run Sigma/YARA rules", group: "on_demand", module_category: "on_demand_stable", status: "available", badge: "On-demand", requires: ["indexed_events"], case_route: "/cases/case-1/rules", description: "Run rules later against indexed events without changing the ingest path." },
        reports: { id: "reports", label: "Generate report", group: "on_demand", module_category: "on_demand_stable", status: "available", badge: "On-demand", requires: ["indexed_artifacts"], case_route: "/cases/case-1/reports", description: "Generate analyst-facing output after searchable data is already indexed." },
        host_enrichment: { id: "host_enrichment", label: "Enrich hosts", group: "on_demand", module_category: "advanced", status: "beta", badge: "Advanced/Beta", requires: ["indexed_artifacts"], case_route: "/cases/case-1/hosts", description: "Optional host identity and context enrichment after ingest completes." },
        deep_retry: { id: "deep_retry", label: "Deep retry problematic artifacts", group: "on_demand", module_category: "advanced", status: "beta", badge: "Advanced/Beta", requires: ["problematic_artifacts"], evidence_route: "/evidences/evidence-1", description: "Retry only the artifacts that failed or were deferred, preserving the main ingest result." },
        benchmark: { id: "benchmark", label: "Benchmark & tuning", group: "on_demand", module_category: "advanced", status: "advanced", badge: "Advanced/Beta", requires: ["admin"], evidence_route: "/evidences/evidence-1", description: "Advanced benchmarking for test or demo evidence. Not part of the main ingest flow." },
        advanced_exports: { id: "advanced_exports", label: "Advanced debug export", group: "on_demand", module_category: "advanced", status: "advanced", badge: "Advanced", requires: ["indexed_artifacts"], case_route: "/cases/case-1/debug-export", description: "Export technical validation packs and low-level ingest diagnostics on demand." },
      },
    });
    previewReprocessEvidenceMock.mockResolvedValue({
      evidence_id: "evidence-1",
      previous_plan_available: true,
      mode: "previous_selection",
      summary: { previous_selected: 1, available_again: 1, missing: 0, changed: 0, new_candidates: 0, unsupported: 0 },
      selected_candidates: [],
      missing_candidates: [],
      new_candidates: [],
      changed_candidates: [],
      warnings: [],
    });
    reprocessEvidenceMock.mockResolvedValue(evidencePayload);
    deleteEvidenceMock.mockResolvedValue(undefined);
    parseVelociraptorSelectionMock.mockResolvedValue(undefined);
    getProblematicArtifactsMock.mockResolvedValue(problematicArtifactsPayload);
    getProblematicRetryCandidatesMock.mockResolvedValue({
      evidence_id: "evidence-1",
      summary: problematicArtifactsPayload.summary,
      retry_candidates: [],
      retry_candidate_count: 0,
      artifact_ids: [],
      affected_families: {},
      excluded: { skipped_empty: 0, warnings_fully_indexed: 1, other_non_retryable: 1 },
    });
    getEvidenceRunsMock.mockResolvedValue([]);
    listEvidenceReportsMock.mockResolvedValue([]);
    generateEvidenceReportMock.mockResolvedValue({
      id: "report-1",
      case_id: "case-1",
      evidence_id: "evidence-1",
      title: "Evidence Summary Report - collection.zip",
      status: "completed",
      template: "evidence_summary",
      report_type: "summary",
      format: "markdown",
      mode: "on_demand",
      created_at: "2026-05-25T12:00:00Z",
      updated_at: "2026-05-25T12:00:01Z",
      generated_at: "2026-05-25T12:00:01Z",
      source_ingest_run_id: "ingest-1",
      size_bytes: 128,
      time_range: {},
      filters: {},
      sections_enabled: {},
      analyst_notes: {},
      selected_finding_ids: [],
      selected_key_event_ids: [],
      selected_process_chain_ids: [],
      include_raw_appendix: false,
      include_debug_metadata: false,
      metadata_json: {},
    });
    downloadReportMock.mockResolvedValue({ blob: new Blob(["report"]), filename: "report.md" });
    getEvidenceBenchmarksMock.mockResolvedValue([]);
    runEvidenceBenchmarkMock.mockResolvedValue({ accepted: true, benchmark_id: "bench-2", evidence_id: "evidence-1", run_id: "run-2", status: "queued", mode: "reprocess_previous_selection", profile: "performance" });
    compareEvidenceBenchmarksMock.mockResolvedValue({});
    retryProblematicArtifactMock.mockResolvedValue({ accepted: true, run_id: "retry-1", artifact_ids: ["artifact-1"], mode: "higher_timeout" });
    retryProblematicArtifactsMock.mockResolvedValue({ accepted: true, run_id: "retry-2", artifact_ids: ["artifact-1", "artifact-2"], mode: "higher_timeout" });
    notifyMock.mockReset();
  });

  it("renders EVTX progress fields when they are available", async () => {
    getEvidenceMock.mockResolvedValueOnce({
      ...evidencePayload,
      ingest_status: "processing",
      metadata_json: {
        ...evidencePayload.metadata_json,
        current_artifact_path: "Windows/System32/winevt/Logs/Security.evtx",
        current_artifact_progress_label: "Security.evtx",
        current_artifact_records_read: 1250,
        current_artifact_records_indexed: 1000,
        records_processed: 1000,
        artifacts_done: 9,
        artifacts_total: 278,
        events_indexed: 640,
        parallel_ingest: {
          enabled: true,
          effective_parallelism: 2,
          desired_parallelism: 4,
          running_artifacts: [{ artifact: "Security.evtx", artifact_type: "windows_event", records_read: 120, records_indexed: 100 }],
          running_artifact_types: ["windows_event"],
          queued_artifacts: 3,
          bottleneck: "parsing",
          limitation_reason: "container_cpu_limit",
          artifacts_parallelized_by_type: { windows_event: 10, prefetch_raw: 4 },
          artifacts_sequential_by_type: { browser: 1 },
        },
      },
    });
    renderPage();
    expect((await screen.findAllByText(/Current artifact: Windows\/System32\/winevt\/Logs\/Security\.evtx/i)).length).toBeGreaterThan(0);
    const primaryProgress = await screen.findByTestId("evidence-progress-primary");
    expect(within(primaryProgress).getByText(/Indexing progress/i)).toBeInTheDocument();
    await waitFor(() => expect(within(primaryProgress).getAllByText(/parsing/i).length).toBeGreaterThan(0));
    expect(within(primaryProgress).getByText(/Windows\/System32\/winevt\/Logs\/Security\.evtx/i)).toBeInTheDocument();
    expect(within(primaryProgress).getByText("9 / 278")).toBeInTheDocument();
    expect(within(primaryProgress).getByText("640")).toBeInTheDocument();
    expect(screen.getByText(/Current artifact progress: Security\.evtx/i)).toBeInTheDocument();
    expect(screen.getByText(/Artifact Scheduler/i)).toBeInTheDocument();
    expect(screen.getAllByText(/Effective parallelism/i).length).toBeGreaterThan(0);
    expect(screen.getByText(/Queued parallel/i)).toBeInTheDocument();
    expect(screen.getAllByText("9 / 278").length).toBeGreaterThan(0);
    expect(screen.getAllByText("640").length).toBeGreaterThan(0);
  });

  it("prefers parallel running artifact summary over stale sequential current artifact", async () => {
    getEvidenceMock.mockResolvedValueOnce({
      ...evidencePayload,
      ingest_status: "processing",
      metadata_json: {
        ...evidencePayload.metadata_json,
        current_artifact_path: "Windows/System32/config/SYSTEM",
        current_artifact_progress_label: "stale",
        current_artifact_source: "parallel_running_artifacts",
        tail_artifacts_running: 2,
        tail_artifacts_queued: 5,
        tail_artifacts_total: 7,
        tail_records_read: 6000,
        tail_records_indexed: 4000,
        tail_last_progress_at: "2026-05-25T14:59:24Z",
        tail_current_artifacts: [
          {
            artifact: "EVTX raw - Security.evtx",
            source_path: "Windows/System32/winevt/Logs/Security.evtx",
            parser: "evtx_raw",
            records_read: 4000,
            records_indexed: 2000,
            elapsed_seconds: 120,
          },
          {
            artifact: "EVTX raw - System.evtx",
            source_path: "Windows/System32/winevt/Logs/System.evtx",
            parser: "evtx_raw",
            records_read: 2000,
            records_indexed: 2000,
            elapsed_seconds: 90,
          },
        ],
        parallel_ingest: {
          enabled: true,
          effective_parallelism: 4,
          desired_parallelism: 4,
          running_artifacts: [
            { artifact: "EVTX raw - Security.evtx", source_path: "Windows/System32/winevt/Logs/Security.evtx", artifact_type: "windows_event", records_read: 4000, records_indexed: 2000 },
            { artifact: "EVTX raw - System.evtx", source_path: "Windows/System32/winevt/Logs/System.evtx", artifact_type: "windows_event", records_read: 2000, records_indexed: 2000 },
          ],
          running_artifact_types: ["windows_event"],
          queued_artifacts: 5,
          bottleneck: "parsing",
        },
      },
    });
    getLongTailArtifactsMock.mockResolvedValueOnce({
      evidence_id: "evidence-1",
      summary: {
        tail_artifacts_total: 7,
        running_count: 2,
        queued_count: 5,
        stalled_count: 0,
        high_value_count: 2,
        partial_indexed_count: 2,
        deferred_count: 0,
      },
      items: [
        {
          artifact_id: "artifact-1",
          name: "Security.evtx",
          parser: "evtx_raw",
          source_path: "Windows/System32/winevt/Logs/Security.evtx",
          long_tail_state: "slow_progressing",
          records_read: 4000,
          records_indexed: 2000,
          last_progress_at: "2026-05-25T14:59:24Z",
          elapsed_seconds: 120,
        },
        {
          artifact_id: "artifact-2",
          name: "System.evtx",
          parser: "evtx_raw",
          source_path: "Windows/System32/winevt/Logs/System.evtx",
          long_tail_state: "slow_progressing",
          records_read: 2000,
          records_indexed: 2000,
          last_progress_at: "2026-05-25T14:59:24Z",
          elapsed_seconds: 90,
        },
      ],
    });

    renderPage();

    expect(await screen.findByText(/Long-tail artifacts still processing/i)).toBeInTheDocument();
    expect(screen.queryByText(/Current artifact: Windows\/System32\/config\/SYSTEM/i)).not.toBeInTheDocument();
    expect(screen.getByText(/Current artifact progress: 2 artifacts active · 6000 records read \/ 4000 indexed/i)).toBeInTheDocument();
    expect(screen.getByText(/Windows\/System32\/winevt\/Logs\/Security\.evtx/i)).toBeInTheDocument();
    expect(screen.getByText(/Windows\/System32\/winevt\/Logs\/System\.evtx/i)).toBeInTheDocument();
  });

  it("shows a diagnostic warning when heartbeat is alive but progress metadata is missing", async () => {
    getEvidenceMock.mockResolvedValueOnce({
      ...evidencePayload,
      ingest_status: "processing",
      metadata_json: {
        heartbeat_at: "2026-05-22T06:34:33Z",
      },
    });
    renderPage();
    expect(await screen.findByText(/Worker heartbeat is alive but progress metadata is missing/i)).toBeInTheDocument();
  });

  it("renders extracting_selected progress with current action and staging reuse", async () => {
    getEvidenceMock.mockResolvedValueOnce({
      ...evidencePayload,
      ingest_status: "processing",
      metadata_json: {
        ...evidencePayload.metadata_json,
        progress_pct: 37,
        current_phase: "extracting_selected",
        heartbeat_at: "2026-05-22T06:34:33Z",
        current_action: "skipping_existing",
        current_selected_path: "Windows/System32/winevt/Logs/Security.evtx",
        current_item: "Windows/System32/winevt/Logs/Security.evtx",
        selected_files_total: 278,
        selected_files_processed: 120,
        files_materialized: 120,
        files_skipped_existing: 100,
        extraction_rate_files_per_sec: 12.5,
        extraction_rate_mb_per_sec: 18.2,
        extraction_errors: 0,
      },
    });
    renderPage();
    expect(await screen.findByText(/Preparing selected artifacts before parser workers start/i)).toBeInTheDocument();
    expect(screen.getByText(/Current selected file: Windows\/System32\/winevt\/Logs\/Security\.evtx/i)).toBeInTheDocument();
    expect(screen.getByText(/Current action: skipping_existing/i)).toBeInTheDocument();
    expect(screen.getByText(/Selected files 120 \/ 278/i)).toBeInTheDocument();
    expect(screen.getByText(/12\.5 files\/s/i)).toBeInTheDocument();
    expect(screen.getByText(/18\.2 MB\/s/i)).toBeInTheDocument();
    expect(screen.getByText(/100 reused \/ 120 ready/i)).toBeInTheDocument();
  });

  it("renders problematic artifacts with effective recovery state details", async () => {
    renderPage();
    expect(await screen.findByText(/Problematic artifacts/i)).toBeInTheDocument();
  });

  it("shows ingest and reprocess runs with progress details", async () => {
    renderPage();
    expect(await screen.findByText(/Ingest & Reprocess Runs/i)).toBeInTheDocument();
  });

  it("shows a timeout summary instead of a raw timeout traceback", async () => {
    getEvidenceMock.mockResolvedValueOnce({
      ...evidencePayload,
      ingest_status: "completed_with_errors",
      metadata_json: {
        ...evidencePayload.metadata_json,
        ingest_performance: {
          metadata_coherence: {
            delta: 0,
          },
        },
      },
    });
    getProblematicArtifactsMock.mockResolvedValueOnce({
      ...problematicArtifactsPayload,
      summary: {
        ...problematicArtifactsPayload.summary,
        problematic_count: 1,
        unresolved_count: 1,
      },
      items: [problematicArtifactsPayload.items[1]],
    });
    getEvidenceRunsMock.mockResolvedValueOnce([
      {
        run_id: "run-timeout",
        run_type: "reprocess",
        mode: "previous_selection",
        status: "failed",
        phase: "failed",
        progress: 95,
        current_artifact: null,
        artifact_progress: null,
        artifacts_total: 278,
        artifacts_done: 277,
        artifacts_failed: 1,
        records_read: 21755,
        records_indexed: 20255,
        last_error: "Task exceeded maximum timeout value (3600 seconds)",
        heartbeat_at: "2026-05-24T08:15:54Z",
        elapsed_seconds: 3599.88,
      },
    ]);

    renderPage();

    expect(await screen.findByText(/Run timed out after 3600s. 277\/278 artifacts completed. 1 artifact was marked problematic and can be retried./i)).toBeInTheDocument();
    expect(screen.getByText(/Indexed events are coherent with OpenSearch./i)).toBeInTheDocument();
    expect(screen.queryByText(/Task exceeded maximum timeout value/i)).not.toBeInTheDocument();
  });

  it("hides benchmark actions by default", async () => {
    renderPage();

    await screen.findByText("collection.zip");
    expect(screen.queryByText(/Benchmark & Tuning/i)).not.toBeInTheDocument();
    expect(screen.queryByRole("button", { name: /Run safe baseline/i })).not.toBeInTheDocument();
    expect(screen.queryByRole("button", { name: /Run performance benchmark/i })).not.toBeInTheDocument();
    expect(screen.queryByRole("button", { name: /Run max benchmark/i })).not.toBeInTheDocument();
    expect(screen.queryByRole("button", { name: /Compare benchmarks/i })).not.toBeInTheDocument();
  });

  it.skip("shows a conflict warning when the benchmark API returns an active run conflict", async () => {
    const completedBenchmark = {
      benchmark_id: "bench-completed",
      evidence_id: "evidence-1",
      case_id: "case-1",
      run_id: "run-completed",
      label: "baseline-safe",
      mode: "reprocess_previous_selection",
      profile: "safe",
      status: "completed",
      total_duration_seconds: 120,
      records_per_sec: 12.5,
      artifacts_per_sec: 0.5,
      effective_parallelism: 1,
      time_to_first_event_indexed: 18,
      problematic_count: 0,
      metadata_opensearch_delta: 0,
      bottleneck_report: { bottleneck: "materialization", confidence: "medium", reasons: ["slow extract"], recommendations: ["reduce materialization time"] },
    };
    getEvidenceBenchmarksMock.mockReset();
    getEvidenceBenchmarksMock.mockResolvedValue([]);
    getEvidenceMock.mockResolvedValue({
      ...evidencePayload,
      ingest_status: "completed",
    });
    runEvidenceBenchmarkMock.mockRejectedValueOnce(
      new Error(JSON.stringify({ error: "active_ingest_exists", active_run_id: "run-42", active_benchmark_id: "bench-42", message: "An ingest/reprocess is already active for this evidence." })),
    );

    renderPage();
    await userEvent.click(await screen.findByText(/Advanced \/ Debug benchmarks/i));
    expect((await screen.findAllByText(/Benchmark & Tuning/i)).length).toBeGreaterThan(0);
    await userEvent.click(screen.getByRole("button", { name: /Run performance benchmark/i }));

    await waitFor(() =>
      expect(notifyMock).toHaveBeenCalledWith(
        expect.objectContaining({
          title: "Benchmark already running",
          description: expect.stringContaining("Active run: run-42. Active benchmark: bench-42."),
          tone: "warning",
        }),
      ),
    );
  });
});
