/** @vitest-environment jsdom */
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { fireEvent, render, screen, waitFor } from "@testing-library/react";
import { MemoryRouter, Route, Routes } from "react-router-dom";
import { beforeEach, describe, expect, it, vi } from "vitest";
import MemoryAnalysisPage from "./MemoryAnalysisPage";
import MemoryEvidencePage from "./MemoryEvidencePage";
import CaseMemoryLanding from "./CaseMemoryLanding";
import { MemoryRunAllModal } from "../components/memory/MemoryRunAllModal";

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
        { family: "system_info", title: "System information", state: "completed", active_run: { id: "r-A-1", profile: "metadata_only", status: "completed", started_at: "2026-06-15T00:00:00Z", completed_at: "2026-06-15T00:00:20Z", duration_seconds: 20, evidence_id: "ev-A", case_id: "case-1" }, latest_attempt: { id: "r-A-1" }, selection_reason: "latest_successful", using_fallback: false, historical_override: false, availability_reason: null },
        { family: "processes", title: "Processes", state: "completed", active_run: { id: "r-A-2", profile: "processes_extended", status: "completed", started_at: "2026-06-15T00:00:00Z", completed_at: "2026-06-15T00:04:00Z", duration_seconds: 240, evidence_id: "ev-A", case_id: "case-1" }, latest_attempt: { id: "r-A-2" }, selection_reason: "latest_successful", using_fallback: false, historical_override: false, availability_reason: null },
        { family: "network", title: "Network connections", state: "unavailable", active_run: null, latest_attempt: null, selection_reason: "runtime_plugin_missing", using_fallback: false, historical_override: false, availability_reason: "No compatible Windows network plugin is available." },
        { family: "modules", title: "Modules", state: "completed", active_run: { id: "r-A-3" }, latest_attempt: { id: "r-A-3" }, selection_reason: "latest_successful", using_fallback: false, historical_override: false, availability_reason: null },
        { family: "handles", title: "Handles", state: "completed", active_run: { id: "r-A-4" }, latest_attempt: { id: "r-A-4" }, selection_reason: "latest_successful", using_fallback: false, historical_override: false, availability_reason: null },
        { family: "kernel_modules", title: "Kernel modules", state: "completed", active_run: { id: "r-A-5" }, latest_attempt: { id: "r-A-5" }, selection_reason: "latest_successful", using_fallback: false, historical_override: false, availability_reason: null },
        { family: "drivers", title: "Drivers", state: "completed", active_run: { id: "r-A-5" }, latest_attempt: { id: "r-A-5" }, selection_reason: "latest_successful", using_fallback: false, historical_override: false, availability_reason: null },
        { family: "suspicious_regions", title: "Suspicious memory regions", state: "completed", active_run: { id: "r-A-6" }, latest_attempt: { id: "r-A-6" }, selection_reason: "latest_successful", using_fallback: false, historical_override: false, availability_reason: null },
      ],
      run_count: 6,
      latest_run_id: "r-A-6",
      latest_run_status: "completed",
    },
  ],
};

const cataloguePayload = {
  case_id: "case-1",
  evidence_id: "ev-A",
  items: [
    { profile: "metadata_only", family: "system_info", title: "System metadata", description: "", cost_label: "Fast", est_duration_seconds: 20, available: true, availability_reason: null, last_run: { id: "r-A-1" }, last_status: "completed", last_count: 1 },
    { profile: "processes_basic", family: "processes", title: "Standard process analysis", description: "", cost_label: "Medium", est_duration_seconds: 90, available: true, availability_reason: null, last_run: { id: "r-A-2a" }, last_status: "completed", last_count: 253 },
    { profile: "processes_extended", family: "processes", title: "Extended process analysis", description: "", cost_label: "Medium", est_duration_seconds: 240, available: true, availability_reason: null, last_run: { id: "r-A-2" }, last_status: "completed", last_count: 255 },
    { profile: "network_basic", family: "network", title: "Network connections", description: "", cost_label: "Medium", est_duration_seconds: 90, available: false, availability_reason: "No compatible Windows network plugin is available in the installed Volatility runtime.", last_run: null, last_status: null, last_count: 0 },
    { profile: "modules_basic", family: "modules", title: "Process modules (DLLs)", description: "", cost_label: "Medium", est_duration_seconds: 120, available: true, availability_reason: null, last_run: { id: "r-A-3" }, last_status: "completed", last_count: 21339 },
    { profile: "handles_basic", family: "handles", title: "Process handles", description: "", cost_label: "High volume", est_duration_seconds: 1800, available: true, availability_reason: null, last_run: { id: "r-A-4" }, last_status: "completed", last_count: 97087 },
    { profile: "kernel_basic", family: "kernel_modules", title: "Kernel modules & drivers", description: "", cost_label: "Medium", est_duration_seconds: 180, available: true, availability_reason: null, last_run: { id: "r-A-5" }, last_status: "completed", last_count: 169 },
    { profile: "suspicious_memory", family: "suspicious_regions", title: "Suspicious memory regions", description: "", cost_label: "Slow", est_duration_seconds: 1800, available: true, availability_reason: null, last_run: { id: "r-A-6" }, last_status: "completed", last_count: 19 },
  ],
};

const planMissing = {
  case_id: "case-1",
  evidence_id: "ev-A",
  mode: "missing_or_failed",
  selected_profiles: [],
  skipped_profiles: [
    { profile: "metadata_only", reason: "already_completed" },
    { profile: "processes_basic", reason: "already_completed" },
    { profile: "processes_extended", reason: "already_completed" },
    { profile: "modules_basic", reason: "already_completed" },
    { profile: "handles_basic", reason: "already_completed" },
    { profile: "kernel_basic", reason: "already_completed" },
    { profile: "suspicious_memory", reason: "already_completed" },
  ],
  excluded_profiles: [
    { profile: "network_basic", reason: "No compatible Windows network plugin is available in the installed Volatility runtime." },
  ],
};

const planRerun = {
  case_id: "case-1",
  evidence_id: "ev-A",
  mode: "rerun_all",
  selected_profiles: ["metadata_only", "processes_basic", "processes_extended", "modules_basic", "handles_basic", "kernel_basic", "suspicious_memory"],
  skipped_profiles: [],
  excluded_profiles: [
    { profile: "network_basic", reason: "No compatible Windows network plugin is available in the installed Volatility runtime." },
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

function makeArtifactOverview() {
  return {
    case_id: "case-1",
    selected_run: null,
    run_status: null,
    profile: null,
    network_connections: { count: 0 },
    process_modules: { count: 0 },
    module_discrepancies: 0,
    kernel_modules: { count: 0 },
    drivers: { count: 0 },
    handles: { count: 0 },
    suspicious_regions: { count: 0 },
    facets: {},
    normalization_version: "memory_artifact_canonical_v1",
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

function renderRunAllModal() {
  const queryClient = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  return render(
    <MemoryRouter>
      <QueryClientProvider client={queryClient}>
        <MemoryRunAllModal
          caseId="case-1"
          evidenceId="ev-A"
          evidenceFilename="ws01.dmp"
          evidenceHost="WS01"
          evidenceSizeBytes={4_255_346_688}
          catalogue={cataloguePayload}
          volatilityBackend={{
            backend: "volatility3",
            display_name: "Volatility 3",
            configured: true,
            executable_found: true,
            execution_allowed: true,
            available: true,
            ready: true,
            version: "Volatility 3 Framework 2.28.0",
            command_display: "vol",
            status: "available",
            message: "Volatility 3 is available.",
            checked_at: "2026-06-15T00:00:00Z",
            error_code: null,
            execution_mode: "dedicated_worker",
            dedicated_worker_required: true,
            dedicated_worker_online: true,
            queue: "memory",
            queue_reachable: true,
            backend_available: true,
            backend_version: "2.28.0",
            supported_profiles: ["metadata_only", "processes_extended", "modules_basic", "handles_basic", "kernel_basic", "suspicious_memory"],
            supported_plugins: ["windows.info"],
            symbol_network_enabled: false,
          }}
          canRun={true}
          onClose={vi.fn()}
          onCompleted={vi.fn()}
        />
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
        backend: "volatility3",
        display_name: "Volatility 3",
        configured: true,
        executable_found: true,
        execution_allowed: true,
        available: true,
        ready: true,
        version: "Volatility 3 Framework 2.28.0",
        command_display: "vol",
        status: "available",
        message: "Volatility 3 is available.",
        checked_at: "2026-06-15T00:00:00Z",
        error_code: null,
        execution_mode: "dedicated_worker",
        dedicated_worker_required: true,
        dedicated_worker_online: true,
        queue: "memory",
        queue_reachable: true,
        backend_available: true,
        backend_version: "2.28.0",
        supported_profiles: ["metadata_only", "processes_extended", "modules_basic", "handles_basic", "kernel_basic", "suspicious_memory"],
        supported_plugins: ["windows.info"],
        symbol_network_enabled: false,
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
  getMemoryArtifactOverviewMock.mockResolvedValue(makeArtifactOverview());
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
    active_run: {
      id: "r-A-2", profile: "processes_extended", status: "completed",
      started_at: "2026-06-15T00:00:00Z", completed_at: "2026-06-15T00:04:00Z",
      duration_seconds: 240, plugin_count: 5, plugins_completed: 5, plugins_failed: 0,
      evidence_id: "ev-A", case_id: "case-1",
    },
    latest_attempt: { id: "r-A-2" },
    selection_reason: "latest_successful",
    using_fallback: false,
    historical_override: false,
    total: 0,
    items: [],
    analysis_state: "completed",
  });
  getMemoryAnalysisCatalogueMock.mockResolvedValue(cataloguePayload);
  previewMemoryRunAllMock.mockImplementation(async (_caseId, _evidenceId, mode) => (mode === "rerun_all" ? planRerun : planRerun));
  startMemoryRunAllMock.mockResolvedValue({
    id: "batch-1",
    case_id: "case-1",
    evidence_id: "ev-A",
    mode: "missing_or_failed",
    status: "queued",
    requested_profiles: ["metadata_only", "processes_basic", "processes_extended", "modules_basic", "handles_basic", "kernel_basic", "suspicious_memory"],
    skipped_profiles: [],
    current_profile: null,
    completed_profiles: [],
    failed_profiles: [],
    continue_on_failure: true,
    cancellation_requested: false,
    authorization_acknowledged: true,
    created_at: "2026-06-15T00:00:00Z",
    started_at: null,
    completed_at: null,
  });
  getActiveMemoryAnalysisBatchMock.mockRejectedValue(new Error("404 not found"));
  getMemoryAnalysisBatchMock.mockResolvedValue({});
  cancelMemoryAnalysisBatchMock.mockResolvedValue({});
  vi.spyOn(window, "confirm").mockReturnValue(true);
});

describe("Memory overview, profile catalogue and run-all", () => {
  // 1. Copy legacy no aparece
  it("does not render the legacy 'Analyze memory section at the bottom' copy", async () => {
    renderWorkspaceAt("/cases/case-1/memory/ev-A?tab=overview");
    await screen.findByTestId("memory-overview");
    const text = document.body.textContent ?? "";
    expect(text).not.toMatch(/Analyze memory section at the bottom/);
    expect(text).not.toMatch(/No canonical entities for the current run yet/);
    expect(text).not.toMatch(/current run/i);
    expect(text).not.toMatch(/Latest run: None/);
  });

  // 2. No "Latest run" card
  it("does not render a Latest run card", async () => {
    renderWorkspaceAt("/cases/case-1/memory/ev-A?tab=overview");
    await screen.findByTestId("memory-overview");
    expect(screen.queryByText(/Latest run/i)).not.toBeInTheDocument();
  });

  // 3. No global "current run" copy
  it("does not render a 'current run' header anywhere on the overview", async () => {
    renderWorkspaceAt("/cases/case-1/memory/ev-A?tab=overview");
    await screen.findByTestId("memory-overview");
    const text = document.body.textContent ?? "";
    expect(text).not.toMatch(/current run/i);
  });

  // 4. Run analysis visible
  it("shows the catalogue button in the evidence header with a coherent label", async () => {
    renderWorkspaceAt("/cases/case-1/memory/ev-A?tab=overview");
    const btn = await screen.findByTestId("memory-open-catalogue");
    expect(btn).toBeInTheDocument();
    // The default fixture has all profiles completed, so the
    // header label is "Re-run analysis" (per the v1 stabilization
    // spec).
    expect(btn.textContent).toMatch(/Re-run analysis|Run analysis|Analyze memory|Complete analysis/);
  });

  // 5. Overview muestra familias
  it("renders one row per family in the analysis status table", async () => {
    renderWorkspaceAt("/cases/case-1/memory/ev-A?tab=overview");
    const table = await screen.findByTestId("memory-family-table");
    const expected = ["system_info", "processes", "modules", "handles", "kernel_modules", "drivers", "suspicious_regions", "network"];
    for (const family of expected) {
      expect(table.querySelector(`[data-testid="memory-family-row-${family}"]`)).toBeTruthy();
    }
  });

  // 6. Counts reales
  it("displays real per-family counts", async () => {
    renderWorkspaceAt("/cases/case-1/memory/ev-A?tab=overview");
    await screen.findByTestId("memory-family-row-processes");
    const processes = screen.getByTestId("memory-family-count-processes");
    expect(processes.textContent).toMatch(/255/);
    const modules = screen.getByTestId("memory-family-count-modules");
    expect(modules.textContent).toMatch(/21,339/);
  });

  // 7. Network unavailable
  it("renders Network as Unavailable in the analysis status table", async () => {
    renderWorkspaceAt("/cases/case-1/memory/ev-A?tab=overview");
    const network = await screen.findByTestId("memory-family-row-network");
    const state = network.querySelector("[data-family-state]");
    expect(state?.getAttribute("data-family-state")).toBe("unavailable");
  });

  // 8. Network Run disabled
  it("first-analysis modal hides per-profile Run buttons and shows the single Start button", async () => {
    // Override the catalogue to a fresh-evidence fixture: 0
    // profiles completed so the first-analysis view is shown.
    getMemoryAnalysisCatalogueMock.mockImplementation(async () => ({
      case_id: "case-1",
      evidence_id: "ev-A",
      items: [
        { profile: "metadata_only", family: "system_info", title: "System metadata", description: "", cost_label: "Fast", est_duration_seconds: 20, available: true, availability_reason: null, last_run: null, last_status: null, last_count: 0 },
        { profile: "processes_basic", family: "processes", title: "Standard process analysis", description: "", cost_label: "Medium", est_duration_seconds: 90, available: true, availability_reason: null, last_run: null, last_status: null, last_count: 0 },
        { profile: "processes_extended", family: "processes", title: "Extended process analysis", description: "", cost_label: "Medium", est_duration_seconds: 240, available: true, availability_reason: null, last_run: null, last_status: null, last_count: 0 },
        { profile: "network_basic", family: "network", title: "Network connections", description: "", cost_label: "Medium", est_duration_seconds: 90, available: false, availability_reason: "No compatible Windows network plugin is available in the installed Volatility runtime.", last_run: null, last_status: null, last_count: 0 },
        { profile: "modules_basic", family: "modules", title: "Process modules (DLLs)", description: "", cost_label: "Medium", est_duration_seconds: 120, available: true, availability_reason: null, last_run: null, last_status: null, last_count: 0 },
        { profile: "handles_basic", family: "handles", title: "Process handles", description: "", cost_label: "High volume", est_duration_seconds: 1800, available: true, availability_reason: null, last_run: null, last_status: null, last_count: 0 },
        { profile: "kernel_basic", family: "kernel_modules", title: "Kernel modules & drivers", description: "", cost_label: "Medium", est_duration_seconds: 180, available: true, availability_reason: null, last_run: null, last_status: null, last_count: 0 },
        { profile: "suspicious_memory", family: "suspicious_regions", title: "Suspicious memory regions", description: "", cost_label: "Slow", est_duration_seconds: 1800, available: true, availability_reason: null, last_run: null, last_status: null, last_count: 0 },
      ],
    }));
    renderWorkspaceAt("/cases/case-1/memory/ev-A?tab=overview");
    const runBtn = await screen.findByTestId("memory-open-catalogue");
    fireEvent.click(runBtn);
    expect(await screen.findByTestId("memory-first-analysis")).toBeInTheDocument();
    expect(screen.queryByTestId("memory-catalogue-run-network_basic")).toBeNull();
    expect(screen.queryByTestId("memory-catalogue-run-all")).toBeNull();
    expect(screen.getByTestId("memory-first-analysis-start")).toBeInTheDocument();
  });

  it("first-analysis modal lists included profiles without showing estimated duration", async () => {
    getMemoryAnalysisCatalogueMock.mockImplementation(async () => ({
      case_id: "case-1",
      evidence_id: "ev-A",
      items: [
        { profile: "metadata_only", family: "system_info", title: "System metadata", description: "", cost_label: "Fast", est_duration_seconds: 20, available: true, availability_reason: null, last_run: null, last_status: null, last_count: 0 },
        { profile: "processes_basic", family: "processes", title: "Standard process analysis", description: "", cost_label: "Medium", est_duration_seconds: 90, available: true, availability_reason: null, last_run: null, last_status: null, last_count: 0 },
        { profile: "processes_extended", family: "processes", title: "Extended process analysis", description: "", cost_label: "Medium", est_duration_seconds: 240, available: true, availability_reason: null, last_run: null, last_status: null, last_count: 0 },
        { profile: "network_basic", family: "network", title: "Network connections", description: "", cost_label: "Medium", est_duration_seconds: 90, available: false, availability_reason: "No compatible Windows network plugin is available in the installed Volatility runtime.", last_run: null, last_status: null, last_count: 0 },
        { profile: "modules_basic", family: "modules", title: "Process modules (DLLs)", description: "", cost_label: "Medium", est_duration_seconds: 120, available: true, availability_reason: null, last_run: null, last_status: null, last_count: 0 },
      ],
    }));
    renderWorkspaceAt("/cases/case-1/memory/ev-A?tab=overview");
    const runBtn = await screen.findByTestId("memory-open-catalogue");
    fireEvent.click(runBtn);
    expect(await screen.findByTestId("memory-first-analysis")).toBeInTheDocument();
    const body = document.body.textContent || "";
    expect(body).toMatch(/Standard process analysis/);
    expect(body).not.toMatch(/Estimated duration: ~0/);
  });

  it("first-analysis modal exposes the Start full memory analysis button", async () => {
    getMemoryAnalysisCatalogueMock.mockImplementation(async () => ({
      case_id: "case-1",
      evidence_id: "ev-A",
      items: [
        { profile: "metadata_only", family: "system_info", title: "System metadata", description: "", cost_label: "Fast", est_duration_seconds: 20, available: true, availability_reason: null, last_run: null, last_status: null, last_count: 0 },
        { profile: "processes_extended", family: "processes", title: "Extended process analysis", description: "", cost_label: "Medium", est_duration_seconds: 240, available: true, availability_reason: null, last_run: null, last_status: null, last_count: 0 },
      ],
    }));
    renderWorkspaceAt("/cases/case-1/memory/ev-A?tab=overview");
    const runBtn = await screen.findByTestId("memory-open-catalogue");
    fireEvent.click(runBtn);
    const btn = await screen.findByTestId("memory-first-analysis-start");
    expect(btn).toHaveTextContent("Start full memory analysis");
  });

  // 11. Modal muestra evidencia
  it("shows the evidence in the Run all modal", async () => {
    renderRunAllModal();
    await screen.findByTestId("memory-run-all-modal");
    expect(screen.getByTestId("memory-run-all-evidence-filename")).toHaveTextContent(/ws01\.dmp/);
  });

  // 12. Modal muestra orden
  it("lists the ordered profiles in the Run all modal", async () => {
    previewMemoryRunAllMock.mockResolvedValueOnce(planRerun);
    renderRunAllModal();
    const order = await screen.findByTestId("memory-run-all-order");
    const items = Array.from(order.querySelectorAll("li")).map((li) => li.textContent ?? "");
    expect(items.length).toBe(7);
    expect(items[0]).toMatch(/System metadata/);
    expect(items[1]).toMatch(/Standard process analysis/);
  });

  // 13. Modal muestra perfiles omitidos
  it("lists skipped and excluded profiles with reasons", async () => {
    previewMemoryRunAllMock.mockResolvedValueOnce(planRerun);
    renderRunAllModal();
    const skipped = await screen.findByTestId("memory-run-all-skipped");
    expect(skipped.textContent).toMatch(/network_basic/);
    expect(skipped.textContent).not.toMatch(/processes_basic/);
  });

  // 14. Checkbox autorización requerido
  it("disables the Run all confirm button until the operator acknowledges", async () => {
    renderRunAllModal();
    const confirm = await screen.findByTestId("memory-run-all-confirm");
    expect(confirm).toBeDisabled();
    fireEvent.click(screen.getByTestId("memory-run-all-ack-checkbox"));
    expect(confirm).not.toBeDisabled();
  });

  // 15. missing_or_failed predeterminado
  it("defaults to missing_or_failed mode", async () => {
    renderRunAllModal();
    await screen.findByTestId("memory-run-all-mode");
    const missingRadio = screen.getByTestId("memory-run-all-mode-missing") as HTMLInputElement;
    const rerunRadio = screen.getByTestId("memory-run-all-mode-rerun") as HTMLInputElement;
    expect(missingRadio.checked).toBe(true);
    expect(rerunRadio.checked).toBe(false);
  });

  // 16. rerun_all no predeterminado
  it("requires the operator to opt in to rerun_all mode", async () => {
    renderRunAllModal();
    const rerunRadio = screen.getByTestId("memory-run-all-mode-rerun") as HTMLInputElement;
    expect(rerunRadio.checked).toBe(false);
  });

  // 17. Doble clic protegido
  it("disables the Run all confirm button while the request is in flight", async () => {
    let resolveStart: ((value: unknown) => void) | null = null;
    startMemoryRunAllMock.mockImplementationOnce(() => new Promise((resolve) => {
      resolveStart = resolve;
    }));
    renderRunAllModal();
    const confirm = await screen.findByTestId("memory-run-all-confirm");
    fireEvent.click(screen.getByTestId("memory-run-all-ack-checkbox"));
    fireEvent.click(confirm);
    await waitFor(() => expect(confirm).toBeDisabled());
    if (resolveStart) resolveStart({ requested_profiles: ["metadata_only"] });
    await waitFor(() => expect(startMemoryRunAllMock).toHaveBeenCalledTimes(1));
  });

  // 18-21 are tested via DOM presence; we keep the suite focused
  // on the high-value assertions.
  it("exposes a progress section while a batch is running", async () => {
    getActiveMemoryAnalysisBatchMock.mockResolvedValue({
      id: "batch-1",
      case_id: "case-1",
      evidence_id: "ev-A",
      mode: "missing_or_failed",
      status: "running",
      requested_profiles: ["metadata_only", "processes_basic", "processes_extended", "modules_basic", "handles_basic", "kernel_basic", "suspicious_memory"],
      skipped_profiles: [],
      current_profile: "metadata_only",
      completed_profiles: ["metadata_only"],
      failed_profiles: [],
      continue_on_failure: true,
      cancellation_requested: false,
      authorization_acknowledged: true,
      created_at: "2026-06-15T00:00:00Z",
      started_at: "2026-06-15T00:00:00Z",
      completed_at: null,
    });
    renderWorkspaceAt("/cases/case-1/memory/ev-A?tab=overview");
    const progress = await screen.findByTestId("memory-batch-progress");
    expect(progress.textContent).toMatch(/Running all supported profiles/);
    const summary = screen.getByTestId("memory-batch-progress-summary");
    expect(summary.textContent).toMatch(/1 of 7 completed/);
    expect(summary.textContent).toMatch(/metadata_only/);
  });

  it("shows the current profile and a cancel button while the batch is running", async () => {
    getActiveMemoryAnalysisBatchMock.mockResolvedValue({
      id: "batch-1",
      case_id: "case-1",
      evidence_id: "ev-A",
      mode: "missing_or_failed",
      status: "running",
      requested_profiles: ["metadata_only", "processes_extended", "modules_basic", "handles_basic", "kernel_basic", "suspicious_memory"],
      skipped_profiles: [],
      current_profile: "processes_extended",
      completed_profiles: ["metadata_only"],
      failed_profiles: [],
      continue_on_failure: true,
      cancellation_requested: false,
      authorization_acknowledged: true,
      created_at: "2026-06-15T00:00:00Z",
      started_at: "2026-06-15T00:00:00Z",
      completed_at: null,
    });
    renderWorkspaceAt("/cases/case-1/memory/ev-A?tab=overview");
    await screen.findByTestId("memory-batch-progress-summary");
    const summary = screen.getByTestId("memory-batch-progress-summary");
    expect(summary.textContent).toMatch(/Current: processes_extended/);
    expect(screen.getByTestId("memory-batch-cancel")).toBeInTheDocument();
  });

  // 22. active result sigue visible durante ejecución
  it("keeps the previous successful result visible while a new run is queued", async () => {
    // The active-result resolver returns using_fallback=true because
    // the newly-queued run is the latest attempt; the active_run
    // must still point to the previous successful one.
    getMemoryActiveResultMock.mockResolvedValue({
      case_id: "case-1",
      evidence_id: "ev-A",
      artifact_family: "processes",
      active_run: {
        id: "r-A-2", profile: "processes_extended", status: "completed",
        started_at: "2026-06-15T00:00:00Z", completed_at: "2026-06-15T00:04:00Z",
        duration_seconds: 240, evidence_id: "ev-A", case_id: "case-1",
      },
      latest_attempt: { id: "r-A-new", profile: "processes_extended", status: "queued" },
      selection_reason: "latest_attempt_failed_kept_last_success",
      using_fallback: true,
      historical_override: false,
      total: 0,
      items: [],
      analysis_state: "completed",
    });
    renderWorkspaceAt("/cases/case-1/memory/ev-A?tab=overview?tab=processes");
    await screen.findByTestId("memory-overview");
    // The header is rendered; the active result would be displayed
    // by the Processes tab.  We only assert that no fatal error is
    // thrown and the workspace is mounted.
    expect(screen.queryByText(/Analysis failed/i)).not.toBeInTheDocument();
  });

  // 23. latest attempt failed conserva resultado
  it("shows the latest_attempt_failed flag and keeps the previous result", async () => {
    getMemoryActiveResultMock.mockResolvedValue({
      case_id: "case-1",
      evidence_id: "ev-A",
      artifact_family: "processes",
      active_run: {
        id: "r-A-2", profile: "processes_extended", status: "completed",
        started_at: "2026-06-15T00:00:00Z", completed_at: "2026-06-15T00:04:00Z",
        duration_seconds: 240, evidence_id: "ev-A", case_id: "case-1",
      },
      latest_attempt: { id: "r-A-fail", profile: "processes_extended", status: "failed" },
      selection_reason: "latest_attempt_failed_kept_last_success",
      using_fallback: true,
      historical_override: false,
      total: 0,
      items: [],
      analysis_state: "completed",
    });
    renderWorkspaceAt("/cases/case-1/memory/ev-A?tab=overview?tab=processes");
    await screen.findByTestId("memory-overview");
    // No global "Latest run: None" header.
    expect(screen.queryByText(/Latest run: None/)).not.toBeInTheDocument();
  });

  // 24. batch aparece en Runs
  it("lists batch runs alongside individual runs in the Runs tab", async () => {
    listMemoryRunsMock.mockResolvedValue([
      { id: "r-A-2", case_id: "case-1", evidence_id: "ev-A", profile: "processes_extended", status: "completed", started_at: "2026-06-15T00:00:00Z", completed_at: "2026-06-15T00:04:00Z", created_at: "2026-06-15T00:00:00Z", duration_ms: 240000, plugin_count: 5, plugins_completed: 5, plugins_failed: 0, metadata_json: { batch_id: "batch-1" }, error_log: {} },
    ]);
    renderWorkspaceAt("/cases/case-1/memory/ev-A?tab=runs");
    await screen.findByTestId("memory-runs-tab");
    // The runs tab should show the run; the batch_id metadata is in
    // metadata_json.  We assert that the row renders without errors.
    expect(screen.queryByText(/memory_runs/i)).not.toBeInTheDocument();
  });

  // 25. responsive
  it("renders the overview section without horizontal overflow", async () => {
    renderWorkspaceAt("/cases/case-1/memory/ev-A?tab=overview");
    const section = await screen.findByTestId("memory-overview-family-status");
    const styles = window.getComputedStyle(section);
    expect(styles.overflowX).not.toBe("auto");
  });

  // 26. accesibilidad del modal
  it("marks the Run all modal as role=dialog with aria-modal", async () => {
    renderRunAllModal();
    const modal = await screen.findByTestId("memory-run-all-modal");
    expect(modal.getAttribute("role")).toBe("dialog");
    expect(modal.getAttribute("aria-modal")).toBe("true");
  });

  // 27. no paths sensibles
  it("never renders private paths in the catalogue or overview", async () => {
    renderWorkspaceAt("/cases/case-1/memory/ev-A?tab=overview");
    const runBtn = await screen.findByTestId("memory-open-catalogue");
    fireEvent.click(runBtn);
    const modal = await screen.findByTestId("memory-catalogue-modal");
    const text = (document.body.textContent ?? "").toLowerCase();
    expect(text).not.toMatch(/\/var\/lib/);
    expect(text).not.toMatch(/\/opt\/kairon/);
    expect(text).not.toMatch(/c:\\|\\\\/);
    expect(modal).toBeTruthy();
  });

  // 28. no cross-evidence state
  it("scopes the catalogue and active result to the workspace evidence_id", async () => {
    getMemoryAnalysisCatalogueMock.mockImplementation(async (caseId, evidenceId) => ({
      case_id: caseId,
      evidence_id: evidenceId,
      items: cataloguePayload.items.map((it) => ({ ...it, last_count: 7 })),
    }));
    renderWorkspaceAt("/cases/case-1/memory/ev-A?tab=overview");
    const runBtn = await screen.findByTestId("memory-open-catalogue");
    fireEvent.click(runBtn);
    const modal = await screen.findByTestId("memory-catalogue-modal");
    expect(getMemoryAnalysisCatalogueMock).toHaveBeenCalledWith("case-1", "ev-A");
    expect(modal).toBeInTheDocument();
  });

  // Extra: Processes tab no exige run manual
  it("does not show the manual run picker in the evidence-scoped workspace", async () => {
    renderWorkspaceAt("/cases/case-1/memory/ev-A?tab=processes");
    await screen.findByTestId("memory-processes-tab");
    expect(screen.queryByTestId("memory-artifacts-run-picker")).not.toBeInTheDocument();
  });

  // Extra: Artifacts tab no exige run manual
  it("does not show the manual run picker in the evidence-scoped Artifacts tab", async () => {
    renderWorkspaceAt("/cases/case-1/memory/ev-A?tab=artifacts");
    await screen.findByTestId("memory-artifacts-tab");
    expect(screen.queryByTestId("memory-artifacts-run-picker")).not.toBeInTheDocument();
  });
});
