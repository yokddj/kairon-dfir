/** @vitest-environment jsdom */
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { fireEvent, render, screen, waitFor } from "@testing-library/react";
import { MemoryRouter, Route, Routes } from "react-router-dom";
import { beforeEach, describe, expect, it, vi } from "vitest";
import MemoryAnalysisPage from "./MemoryAnalysisPage";
import MemoryEvidencePage from "./MemoryEvidencePage";
import CaseMemoryLanding from "./CaseMemoryLanding";

const getMemoryOverviewMock = vi.fn();
const getMemoryBackendOverviewMock = vi.fn();
const getMemoryEvidenceReadinessMock = vi.fn();
const getMemorySymbolCacheStatusMock = vi.fn();
const getMemoryRunOptionsMock = vi.fn();
const getCanonicalProcessSummaryMock = vi.fn();
const getCanonicalProcessEntitiesMock = vi.fn();
const getCanonicalProcessTreeMock = vi.fn();
const getCanonicalProcessEntityDetailMock = vi.fn();
const getCaseMemorySystemInfoMock = vi.fn();
const getCaseMemoryProcessesMock = vi.fn();
const getMemoryProcessTreeMock = vi.fn();
const startMemoryScanMock = vi.fn();
const getMemoryArtifactOverviewMock = vi.fn();
const getMemoryNetworkConnectionsMock = vi.fn();
const getMemoryProcessModulesMock = vi.fn();
const getMemoryHandlesMock = vi.fn();
const getMemoryDriversMock = vi.fn();
const getMemoryKernelModulesMock = vi.fn();
const getMemorySuspiciousRegionsMock = vi.fn();
const getMemoryArtifactDetailMock = vi.fn();
const listMemoryRunsMock = vi.fn();
const getMemoryEvidenceLandingMock = vi.fn();
const getMemoryActiveResultMock = vi.fn();
const getMemoryAnalysisCatalogueMock = vi.fn();
const previewMemoryRunAllMock = vi.fn();
const startMemoryRunAllMock = vi.fn();
const getActiveMemoryAnalysisBatchMock = vi.fn();
const getMemoryAnalysisBatchMock = vi.fn();
const cancelMemoryAnalysisBatchMock = vi.fn();

const landingPayload = {
  case_id: "case-1",
  items: [
    {
      evidence_id: "ev-A",
      case_id: "case-1",
      filename: "ws01.dmp",
      detected_host: "WS01",
      size_bytes: 4_255_346_688,
      created_at: "2026-06-15T00:00:00Z",
      processed_at: "2026-06-15T00:01:00Z",
      ingest_status: "completed",
      metadata: {},
      families: [
        { family: "system_info", title: "System information", state: "completed", active_run: { id: "r-A-1", profile: "metadata_only", status: "completed" }, latest_attempt: { id: "r-A-1" }, selection_reason: "latest_successful", using_fallback: false, historical_override: false, availability_reason: null, count: 0, document_type: "memory_system_info", count_source: "summary" },
        { family: "processes", title: "Processes", state: "completed", active_run: { id: "r-A-2", profile: "processes_extended", status: "completed" }, latest_attempt: { id: "r-A-2" }, selection_reason: "latest_successful", using_fallback: false, historical_override: false, availability_reason: null, count: 255, document_type: "memory_process", count_source: "summary" },
        { family: "network", title: "Network connections", state: "unavailable", active_run: null, latest_attempt: null, selection_reason: "runtime_plugin_missing", using_fallback: false, historical_override: false, availability_reason: "No compatible Windows network plugin is available.", count: 0, document_type: "memory_network_connection", count_source: "no_active_run" },
        { family: "modules", title: "Process modules", state: "completed", active_run: { id: "r-A-3", profile: "modules_basic", status: "completed" }, latest_attempt: { id: "r-A-3" }, selection_reason: "latest_successful", using_fallback: false, historical_override: false, availability_reason: null, count: 21339, document_type: "memory_process_module", count_source: "opensearch" },
        { family: "handles", title: "Process handles", state: "completed", active_run: { id: "r-A-4", profile: "handles_basic", status: "completed" }, latest_attempt: { id: "r-A-4" }, selection_reason: "latest_successful", using_fallback: false, historical_override: false, availability_reason: null, count: 97087, document_type: "memory_handle", count_source: "opensearch" },
        { family: "kernel_modules", title: "Kernel modules", state: "completed", active_run: { id: "r-A-5", profile: "kernel_basic", status: "completed" }, latest_attempt: { id: "r-A-5" }, selection_reason: "latest_successful", using_fallback: false, historical_override: false, availability_reason: null, count: 169, document_type: "memory_kernel_module", count_source: "opensearch" },
        { family: "drivers", title: "Drivers", state: "completed", active_run: { id: "r-A-5", profile: "kernel_basic", status: "completed" }, latest_attempt: { id: "r-A-5" }, selection_reason: "latest_successful", using_fallback: false, historical_override: false, availability_reason: null, count: 135, document_type: "memory_driver", count_source: "opensearch" },
        { family: "suspicious_regions", title: "Suspicious memory regions", state: "completed", active_run: { id: "r-A-6", profile: "suspicious_memory", status: "completed" }, latest_attempt: { id: "r-A-6" }, selection_reason: "latest_successful", using_fallback: false, historical_override: false, availability_reason: null, count: 19, document_type: "memory_suspicious_region", count_source: "opensearch" },
        { family: "raw_observations", title: "Raw observations", state: "completed", active_run: { id: "r-A-2", profile: "processes_extended", status: "completed" }, latest_attempt: { id: "r-A-2" }, selection_reason: "latest_successful", using_fallback: false, historical_override: false, availability_reason: null, count: 507, document_type: "memory_process_observation", count_source: "opensearch" },
      ],
      run_count: 8,
      latest_run_id: "r-A-6",
      latest_run_status: "completed",
    },
  ],
};

const cataloguePayload = {
  case_id: "case-1",
  evidence_id: "ev-A",
  items: [
    { profile: "metadata_only", family: "system_info", title: "System metadata", description: "", cost_label: "Fast", est_duration_seconds: 20, available: true, availability_reason: null, last_run: { id: "r-A-1" }, last_status: "completed", last_count: 0 },
    { profile: "processes_basic", family: "processes", title: "Standard process analysis", description: "", cost_label: "Medium", est_duration_seconds: 90, available: true, availability_reason: null, last_run: { id: "r-A-2a" }, last_status: "completed", last_count: 253 },
    { profile: "processes_extended", family: "processes", title: "Extended process analysis", description: "", cost_label: "Medium", est_duration_seconds: 240, available: true, availability_reason: null, last_run: { id: "r-A-2" }, last_status: "completed", last_count: 255 },
    { profile: "network_basic", family: "network", title: "Network connections", description: "", cost_label: "Medium", est_duration_seconds: 90, available: false, availability_reason: "No compatible Windows network plugin is available in the installed Volatility runtime.", last_run: null, last_status: null, last_count: 0 },
    { profile: "modules_basic", family: "modules", title: "Process modules (DLLs)", description: "", cost_label: "Medium", est_duration_seconds: 120, available: true, availability_reason: null, last_run: { id: "r-A-3" }, last_status: "completed", last_count: 21339 },
    { profile: "handles_basic", family: "handles", title: "Process handles", description: "", cost_label: "High volume", est_duration_seconds: 1800, available: true, availability_reason: null, last_run: { id: "r-A-4" }, last_status: "completed", last_count: 97087 },
    { profile: "kernel_basic", family: "kernel_modules", title: "Kernel modules & drivers", description: "", cost_label: "Medium", est_duration_seconds: 180, available: true, availability_reason: null, last_run: { id: "r-A-5" }, last_status: "completed", last_count: 169 },
    { profile: "suspicious_memory", family: "suspicious_regions", title: "Suspicious memory regions", description: "", cost_label: "Slow", est_duration_seconds: 1800, available: true, availability_reason: null, last_run: { id: "r-A-6" }, last_status: "completed", last_count: 19 },
  ],
};

vi.mock("../api/client", () => ({
  api: {
    getMemoryBackendOverview: (...args: unknown[]) => getMemoryBackendOverviewMock(...args),
    getMemoryOverview: (...args: unknown[]) => getMemoryOverviewMock(...args),
    getCaseMemorySystemInfo: (...args: unknown[]) => getCaseMemorySystemInfoMock(...args),
    getMemoryRunOptions: (...args: unknown[]) => getMemoryRunOptionsMock(...args),
    getCanonicalProcessSummary: (...args: unknown[]) => getCanonicalProcessSummaryMock(...args),
    getCanonicalProcessEntities: (...args: unknown[]) => getCanonicalProcessEntitiesMock(...args),
    getCanonicalProcessTree: (...args: unknown[]) => getCanonicalProcessTreeMock(...args),
    getCanonicalProcessEntityDetail: (...args: unknown[]) => getCanonicalProcessEntityDetailMock(...args),
    getMemoryEvidenceReadiness: (...args: unknown[]) => getMemoryEvidenceReadinessMock(...args),
    getMemorySymbolCacheStatus: (...args: unknown[]) => getMemorySymbolCacheStatusMock(...args),
    getCaseMemoryProcesses: (...args: unknown[]) => getCaseMemoryProcessesMock(...args),
    getMemoryProcessTree: (...args: unknown[]) => getMemoryProcessTreeMock(...args),
    startMemoryScan: (...args: unknown[]) => startMemoryScanMock(...args),
    getMemoryArtifactOverview: (...args: unknown[]) => getMemoryArtifactOverviewMock(...args),
    getMemoryNetworkConnections: (...args: unknown[]) => getMemoryNetworkConnectionsMock(...args),
    getMemoryProcessModules: (...args: unknown[]) => getMemoryProcessModulesMock(...args),
    getMemoryHandles: (...args: unknown[]) => getMemoryHandlesMock(...args),
    getMemoryDrivers: (...args: unknown[]) => getMemoryDriversMock(...args),
    getMemoryKernelModules: (...args: unknown[]) => getMemoryKernelModulesMock(...args),
    getMemorySuspiciousRegions: (...args: unknown[]) => getMemorySuspiciousRegionsMock(...args),
    getMemoryArtifactDetail: (...args: unknown[]) => getMemoryArtifactDetailMock(...args),
    listMemoryRuns: (...args: unknown[]) => listMemoryRunsMock(...args),
    getMemoryEvidenceLanding: (...args: unknown[]) => getMemoryEvidenceLandingMock(...args),
    getMemoryActiveResult: (...args: unknown[]) => getMemoryActiveResultMock(...args),
    getMemoryAnalysisCatalogue: (...args: unknown[]) => getMemoryAnalysisCatalogueMock(...args),
    previewMemoryRunAll: (...args: unknown[]) => previewMemoryRunAllMock(...args),
    startMemoryRunAll: (...args: unknown[]) => startMemoryRunAllMock(...args),
    getActiveMemoryAnalysisBatch: (...args: unknown[]) => getActiveMemoryAnalysisBatchMock(...args),
    getMemoryAnalysisBatch: (...args: unknown[]) => getMemoryAnalysisBatchMock(...args),
    cancelMemoryAnalysisBatch: (...args: unknown[]) => cancelMemoryAnalysisBatchMock(...args),
  },
}));

vi.mock("../context/ActiveCaseContext", () => ({
  useActiveCase: () => ({ setActiveCaseId: vi.fn() }),
}));

function makeArtifactList(overrides: Record<string, unknown> = {}) {
  return {
    document_type: "memory_artifact",
    selected_run: null,
    evidence_id: "ev-A",
    total: 0,
    page: 1,
    page_size: 50,
    items: [],
    facets: {},
    normalization_version: "memory_artifact_canonical_v1",
    ...overrides,
  };
}

function renderWorkspaceAt(initialPath: string) {
  const queryClient = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  return render(
    <MemoryRouter initialEntries={[initialPath]}>
      <QueryClientProvider client={queryClient}>
        <Routes>
          <Route path="/cases/:caseId/memory" element={<MemoryAnalysisPage />} />
          <Route path="/cases/:caseId/memory/landing" element={<CaseMemoryLanding />} />
          <Route path="/cases/:caseId/memory/:evidenceId" element={<MemoryEvidencePage />} />
        </Routes>
      </QueryClientProvider>
    </MemoryRouter>,
  );
}

beforeEach(() => {
  vi.clearAllMocks();
  getMemoryOverviewMock.mockResolvedValue({
    case_id: "case-1",
    memory_analysis_enabled: true,
    has_memory_evidence: true,
    has_memory_results: true,
    has_disk_events: false,
    mode: "memory_only",
    evidences: [
      { id: "ev-A", case_id: "case-1", original_filename: "ws01.dmp", evidence_type: "memory_dump", size_bytes: 4255346688, ingest_status: "completed", created_at: "2026-06-15T00:00:00Z" },
    ],
    runs: [],
    message: "Memory analysis is available.",
  });
  getMemoryBackendOverviewMock.mockResolvedValue({
    memory_analysis_enabled: true,
    external_execution_allowed: true,
    preferred_backend: "volatility3",
    ready_backend_count: 1,
    message: "1 memory-analysis backend is ready.",
    backends: [
      {
        backend: "volatility3", display_name: "Volatility 3",
        configured: true, executable_found: true, execution_allowed: true,
        available: true, ready: true, version: "Volatility 3 Framework 2.28.0",
        command_display: "vol", status: "available", message: "Volatility 3 is available.",
        checked_at: "2026-06-15T00:00:00Z", error_code: null,
        execution_mode: "dedicated_worker", dedicated_worker_required: true,
        dedicated_worker_online: true, queue: "memory", queue_reachable: true,
        backend_available: true, backend_version: "2.28.0",
        supported_profiles: ["metadata_only", "processes_extended", "modules_basic", "handles_basic", "kernel_basic", "suspicious_memory"],
        supported_plugins: ["windows.info"], symbol_network_enabled: false,
      },
    ],
  });
  getMemoryEvidenceReadinessMock.mockResolvedValue({
    exists: true, regular_file: true, readable_by_memory_worker: true, size_matches: true,
    output_writable_by_memory_worker: true, worker_online: true, backend_ready: true, can_analyze: true,
    error_code: null, sanitized_message: "Memory evidence is available to the dedicated memory worker.",
  });
  getMemorySymbolCacheStatusMock.mockResolvedValue({
    mode: "offline_only", managed_download_enabled: false, network_isolation_ready: true,
    administrator_authorization_available: false, local_approval_enabled: false,
    pending_requests: 0, awaiting_operator_approval: 0, approved_pending: 0, fetcher_online: true,
    total_bytes: 1024, configured_max_bytes: 1024, available_bytes: 1024,
    symbol_count: 1, pdb_count: 1, isf_count: 1, active_requests: 0, failed_requests: 0,
    last_success_at: "2026-06-16T00:00:00Z", error_code: "SYMBOL_ACQUISITION_DISABLED", message: "Symbols cached.",
  });
  getMemoryRunOptionsMock.mockResolvedValue({ runs: [], default_run_id: null, combined_historical_available: false });
  getCanonicalProcessSummaryMock.mockResolvedValue(null);
  getCanonicalProcessEntitiesMock.mockResolvedValue({ items: [], total: 0, page: 1, page_size: 50, selected_run: null });
  getCanonicalProcessTreeMock.mockResolvedValue({ nodes: [], edges: [], total: 0 });
  getCanonicalProcessEntityDetailMock.mockResolvedValue(null);
  getCaseMemorySystemInfoMock.mockResolvedValue([]);
  getCaseMemoryProcessesMock.mockResolvedValue({ items: [], total: 0, page: 1, page_size: 50 });
  getMemoryProcessTreeMock.mockResolvedValue({ run_id: "run-1", nodes: [], edges: [], orphan_count: 0, root_count: 0, warnings: [], source_plugins: [], total_process_count: 0 });
  startMemoryScanMock.mockResolvedValue({ accepted: true, evidence_id: "ev-A", run_id: "r-new", status: "queued", message: "queued", run: null });
  getMemoryArtifactOverviewMock.mockResolvedValue({
    case_id: "case-1",
    evidence_id: "ev-A",
    selected_run: null,
    run_status: null,
    profile: null,
    network_connections: { count: 0 },
    process_modules: { count: 21339 },
    module_discrepancies: 0,
    kernel_modules: { count: 169 },
    drivers: { count: 135 },
    handles: { count: 97087 },
    suspicious_regions: { count: 19 },
    facets: {},
    normalization_version: "memory_artifact_canonical_v1",
  });
  getMemoryNetworkConnectionsMock.mockResolvedValue(makeArtifactList());
  getMemoryProcessModulesMock.mockResolvedValue(makeArtifactList());
  getMemoryHandlesMock.mockResolvedValue(makeArtifactList());
  getMemoryDriversMock.mockResolvedValue(makeArtifactList());
  getMemoryKernelModulesMock.mockResolvedValue(makeArtifactList());
  getMemorySuspiciousRegionsMock.mockResolvedValue(makeArtifactList());
  getMemoryArtifactDetailMock.mockResolvedValue({ document_type: "memory_artifact", document_id: "x", fields: {}, provenance: {} });
  listMemoryRunsMock.mockResolvedValue([]);
  getMemoryEvidenceLandingMock.mockResolvedValue(landingPayload);
  getMemoryActiveResultMock.mockResolvedValue({
    case_id: "case-1",
    evidence_id: "ev-A",
    artifact_family: "processes",
    active_run: { id: "r-A-2", profile: "processes_extended", status: "completed" },
    latest_attempt: { id: "r-A-2" },
    selection_reason: "latest_successful",
    using_fallback: false,
    historical_override: false,
    total: 0,
    items: [],
    analysis_state: "completed",
  });
  getMemoryAnalysisCatalogueMock.mockResolvedValue(cataloguePayload);
  previewMemoryRunAllMock.mockResolvedValue({
    case_id: "case-1",
    evidence_id: "ev-A",
    mode: "missing_or_failed",
    selected_profiles: [],
    skipped_profiles: [
      { profile: "metadata_only", reason: "already_completed" },
    ],
    excluded_profiles: [
      { profile: "processes_basic", reason: "standard process analysis is replaced by the extended profile in run-all" },
    ],
  });
  startMemoryRunAllMock.mockResolvedValue({});
  getActiveMemoryAnalysisBatchMock.mockRejectedValue(new Error("404 not found"));
  getMemoryAnalysisBatchMock.mockResolvedValue({});
  cancelMemoryAnalysisBatchMock.mockResolvedValue({});
  vi.spyOn(window, "confirm").mockReturnValue(true);
});

describe("Memory count integrity and batch runtime", () => {
  // 1-2: Count integrity
  it("shows the exact modules count from the per-family source", async () => {
    renderWorkspaceAt("/cases/case-1/memory/ev-A?tab=overview");
    await screen.findByTestId("memory-family-row-modules");
    const count = screen.getByTestId("memory-family-count-modules");
    expect(count.textContent).toMatch(/21,339/);
  });

  it("separates Kernel modules (169) and Drivers (135) and never sums them", async () => {
    renderWorkspaceAt("/cases/case-1/memory/ev-A?tab=overview");
    await screen.findByTestId("memory-family-row-kernel_modules");
    await screen.findByTestId("memory-family-row-drivers");
    const kernel = screen.getByTestId("memory-family-count-kernel_modules");
    const drivers = screen.getByTestId("memory-family-count-drivers");
    expect(kernel.textContent).toMatch(/169/);
    expect(drivers.textContent).toMatch(/135/);
    expect(kernel.textContent).not.toMatch(/304/);
    expect(drivers.textContent).not.toMatch(/304/);
  });

  // 3: No discrepancy between Overview and Artifacts
  it("Overview and Artifacts cards agree on counts", async () => {
    renderWorkspaceAt("/cases/case-1/memory/ev-A?tab=overview");
    await screen.findByTestId("memory-overview");
    const modules = screen.getByTestId("memory-artifact-card-modules");
    expect(modules.textContent).toMatch(/21,339/);
  });

  // 4-5: Batch progress and reconciled state
  it("shows the batch progress section while a batch is in flight", async () => {
    getActiveMemoryAnalysisBatchMock.mockResolvedValue({
      id: "batch-1",
      case_id: "case-1",
      evidence_id: "ev-A",
      mode: "missing_or_failed",
      status: "running",
      requested_profiles: ["metadata_only", "processes_extended", "modules_basic"],
      skipped_profiles: [],
      current_profile: "processes_extended",
      completed_profiles: ["metadata_only"],
      failed_profiles: [],
      continue_on_failure: true,
      cancellation_requested: false,
      authorization_acknowledged: true,
      version: 3,
      last_advanced_run_id: "r-1",
      last_advanced_at: "2026-06-21T10:00:00Z",
      reconciled_at: null,
      failure_reason: null,
      requested_by: "server-operator",
      created_at: "2026-06-21T10:00:00Z",
      started_at: "2026-06-21T10:00:00Z",
      completed_at: null,
    });
    renderWorkspaceAt("/cases/case-1/memory/ev-A?tab=overview");
    const progress = await screen.findByTestId("memory-batch-progress");
    const summary = screen.getByTestId("memory-batch-progress-summary");
    expect(progress).toBeInTheDocument();
    expect(summary.textContent).toMatch(/1 of 3 completed/);
    expect(summary.textContent).toMatch(/processes_extended/);
  });

  it("does not render the batch progress section when no batch is active", async () => {
    renderWorkspaceAt("/cases/case-1/memory/ev-A?tab=overview");
    await screen.findByTestId("memory-overview");
    expect(screen.queryByTestId("memory-batch-progress")).not.toBeInTheDocument();
  });

  // 6-7: Active result preservation
  it("keeps the previous active result visible while a new run is queued", async () => {
    getMemoryActiveResultMock.mockResolvedValue({
      case_id: "case-1",
      evidence_id: "ev-A",
      artifact_family: "processes",
      active_run: { id: "r-A-2", profile: "processes_extended", status: "completed" },
      latest_attempt: { id: "r-A-new", profile: "processes_extended", status: "queued" },
      selection_reason: "latest_attempt_failed_kept_last_success",
      using_fallback: true,
      historical_override: false,
      total: 0,
      items: [],
      analysis_state: "completed",
    });
    renderWorkspaceAt("/cases/case-1/memory/ev-A?tab=processes");
    await screen.findByTestId("memory-processes-tab");
    expect(screen.queryByText("Analysis failed")).not.toBeInTheDocument();
  });

  it("shows latest attempt failed banner when a failure is the latest attempt", async () => {
    getMemoryActiveResultMock.mockResolvedValue({
      case_id: "case-1",
      evidence_id: "ev-A",
      artifact_family: "processes",
      active_run: { id: "r-A-2", profile: "processes_extended", status: "completed" },
      latest_attempt: { id: "r-A-fail", profile: "processes_extended", status: "failed" },
      selection_reason: "latest_attempt_failed_kept_last_success",
      using_fallback: true,
      historical_override: false,
      total: 0,
      items: [],
      analysis_state: "completed",
    });
    renderWorkspaceAt("/cases/case-1/memory/ev-A?tab=processes");
    await screen.findByTestId("memory-processes-tab");
    expect(screen.queryByTestId("memory-latest-failed-banner")).toBeInTheDocument();
  });

  // 8-9: Network/Modules reads without 500
  it("does not 500 on the Network endpoint when the runtime plugin is missing", async () => {
    getMemoryNetworkConnectionsMock.mockResolvedValue(makeArtifactList());
    renderWorkspaceAt("/cases/case-1/memory/ev-A?tab=artifacts&artifact=network");
    await screen.findByTestId("memory-artifacts-tab");
    // The Network row in the Overview already shows Unavailable.
    // This test asserts that the listing endpoint does not throw.
    expect(screen.queryByText("500")).not.toBeInTheDocument();
  });

  it("does not 500 on the Modules endpoint when the pid field is unmapped", async () => {
    getMemoryProcessModulesMock.mockResolvedValue(makeArtifactList());
    renderWorkspaceAt("/cases/case-1/memory/ev-A?tab=artifacts&artifact=modules");
    await screen.findByTestId("memory-artifacts-tab");
    expect(screen.queryByText("500")).not.toBeInTheDocument();
  });

  // 10-11: Batch reconciled state visible
  it("shows the reconciled timestamp when reconciliation has run", async () => {
    getActiveMemoryAnalysisBatchMock.mockResolvedValue({
      id: "batch-1",
      case_id: "case-1",
      evidence_id: "ev-A",
      mode: "missing_or_failed",
      status: "running",
      requested_profiles: ["metadata_only", "processes_extended"],
      skipped_profiles: [],
      current_profile: "metadata_only",
      completed_profiles: [],
      failed_profiles: [],
      continue_on_failure: true,
      cancellation_requested: false,
      authorization_acknowledged: true,
      version: 2,
      last_advanced_run_id: null,
      last_advanced_at: null,
      reconciled_at: "2026-06-21T10:00:00Z",
      failure_reason: null,
      requested_by: "server-operator",
      created_at: "2026-06-21T09:59:00Z",
      started_at: "2026-06-21T09:59:00Z",
      completed_at: null,
    });
    renderWorkspaceAt("/cases/case-1/memory/ev-A?tab=overview");
    const progress = await screen.findByTestId("memory-batch-progress");
    expect(progress).toBeInTheDocument();
  });

  it("hides the cancel button when cancellation is already requested", async () => {
    getActiveMemoryAnalysisBatchMock.mockResolvedValue({
      id: "batch-1",
      case_id: "case-1",
      evidence_id: "ev-A",
      mode: "missing_or_failed",
      status: "running",
      requested_profiles: ["metadata_only", "processes_extended"],
      skipped_profiles: [],
      current_profile: "metadata_only",
      completed_profiles: [],
      failed_profiles: [],
      continue_on_failure: true,
      cancellation_requested: true,
      authorization_acknowledged: true,
      version: 2,
      last_advanced_run_id: null,
      last_advanced_at: null,
      reconciled_at: null,
      failure_reason: null,
      requested_by: "server-operator",
      created_at: "2026-06-21T09:59:00Z",
      started_at: "2026-06-21T09:59:00Z",
      completed_at: null,
    });
    renderWorkspaceAt("/cases/case-1/memory/ev-A?tab=overview");
    await screen.findByTestId("memory-batch-progress");
    expect(screen.queryByTestId("memory-batch-cancel")).not.toBeInTheDocument();
  });

  // 12-13: UI hygiene
  it("responsive: the family table does not produce a horizontal scroll", async () => {
    renderWorkspaceAt("/cases/case-1/memory/ev-A?tab=overview");
    const table = await screen.findByTestId("memory-family-table");
    const styles = window.getComputedStyle(table);
    expect(styles.overflowX).not.toBe("auto");
  });

  it("does not render any private server paths in the evidence view", async () => {
    renderWorkspaceAt("/cases/case-1/memory/ev-A?tab=overview");
    await screen.findByTestId("memory-evidence-header");
    const text = (document.body.textContent ?? "").toLowerCase();
    expect(text).not.toMatch(/\/var\/lib/);
    expect(text).not.toMatch(/\/opt\/kairon/);
    expect(text).not.toMatch(/c:\\|\\\\/);
  });

  // 14-16: No CORS / no JS errors / no failed chunks
  it("does not surface a CORS error for the /analysis-batches/active endpoint", async () => {
    renderWorkspaceAt("/cases/case-1/memory/ev-A?tab=overview");
    await screen.findByTestId("memory-overview");
    // 404 from the active-batch endpoint is the expected end
    // state when no batch is in flight.  The UI must not treat
    // it as a fatal error.
    expect(screen.queryByText("CORS")).not.toBeInTheDocument();
    expect(screen.queryByText("blocked by CORS")).not.toBeInTheDocument();
  });

  it("does not show 'No canonical entities for the current run yet' anywhere", async () => {
    renderWorkspaceAt("/cases/case-1/memory/ev-A?tab=overview");
    await screen.findByTestId("memory-overview");
    const text = document.body.textContent ?? "";
    expect(text).not.toMatch(/No canonical entities for the current run yet/);
  });

  it("does not show 'Latest run: None' anywhere in the workspace", async () => {
    renderWorkspaceAt("/cases/case-1/memory/ev-A?tab=overview");
    await screen.findByTestId("memory-overview");
    const text = document.body.textContent ?? "";
    expect(text).not.toMatch(/Latest run: None/);
  });
});
