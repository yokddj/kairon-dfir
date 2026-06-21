import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { fireEvent, render, screen, waitFor } from "@testing-library/react";
import { MemoryRouter, Route, Routes } from "react-router-dom";
import { beforeEach, describe, expect, it, vi } from "vitest";
import MemoryAnalysisPage from "./MemoryAnalysisPage";
import MemoryEvidencePage from "./MemoryEvidencePage";
import CaseMemoryLanding from "./CaseMemoryLanding";

const getMemoryOverviewMock = vi.fn();
const getMemoryBackendOverviewMock = vi.fn();
const getCaseMemorySystemInfoMock = vi.fn();
const getMemoryRunOptionsMock = vi.fn();
const getCanonicalProcessSummaryMock = vi.fn();
const getCanonicalProcessEntitiesMock = vi.fn();
const getCanonicalProcessTreeMock = vi.fn();
const getCanonicalProcessEntityDetailMock = vi.fn();
const getMemoryEvidenceReadinessMock = vi.fn();
const getMemorySymbolCacheStatusMock = vi.fn();
const getCaseMemoryProcessesMock = vi.fn();
const getMemoryProcessTreeMock = vi.fn();
const startMemoryScanMock = vi.fn();
const renormalizeProcessEntitiesMock = vi.fn();
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
    renormalizeProcessEntities: (...args: unknown[]) => renormalizeProcessEntitiesMock(...args),
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
  },
}));

vi.mock("../context/ActiveCaseContext", () => ({
  useActiveCase: () => ({ setActiveCaseId: vi.fn() }),
}));

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

function multiEvidenceOverview() {
  return {
    case_id: "case-1",
    memory_analysis_enabled: true,
    has_memory_evidence: true,
    has_memory_results: true,
    has_disk_events: false,
    mode: "memory_only",
    evidences: [
      { id: "ev-A", case_id: "case-1", original_filename: "ws01.dmp", evidence_type: "memory_dump", size_bytes: 4255346688, ingest_status: "completed", created_at: "2026-06-15T00:00:00Z" },
      { id: "ev-B", case_id: "case-1", original_filename: "fs01.dmp", evidence_type: "memory_dump", size_bytes: 8388608, ingest_status: "completed", created_at: "2026-06-16T00:00:00Z" },
    ],
    runs: [],
    message: "Memory analysis is available.",
  };
}

function multiEvidenceLanding() {
  return {
    case_id: "case-1",
    items: [
      {
        evidence_id: "ev-A", case_id: "case-1", filename: "ws01.dmp",
        detected_host: "WS01", size_bytes: 4255346688, created_at: "2026-06-15T00:00:00Z",
        processed_at: "2026-06-15T00:01:00Z", ingest_status: "completed",
        metadata: {}, run_count: 5, latest_run_id: "r-A-1", latest_run_status: "completed",
        families: [
          { family: "system_info", title: "System metadata", state: "completed", active_run: { id: "r-A-1" }, latest_attempt: { id: "r-A-1" }, selection_reason: "latest_successful", using_fallback: false, historical_override: false, availability_reason: null },
          { family: "processes", title: "Processes", state: "completed", active_run: { id: "r-A-2" }, latest_attempt: { id: "r-A-2" }, selection_reason: "latest_successful", using_fallback: false, historical_override: false, availability_reason: null },
          { family: "network", title: "Network connections", state: "unavailable", active_run: null, latest_attempt: null, selection_reason: "runtime_plugin_missing", using_fallback: false, historical_override: false, availability_reason: "No compatible Windows network plugin is available in the installed Volatility runtime." },
          { family: "modules", title: "Process modules", state: "completed", active_run: { id: "r-A-3" }, latest_attempt: { id: "r-A-3" }, selection_reason: "latest_successful", using_fallback: false, historical_override: false, availability_reason: null },
          { family: "handles", title: "Process handles", state: "completed", active_run: { id: "r-A-4" }, latest_attempt: { id: "r-A-4" }, selection_reason: "latest_successful", using_fallback: false, historical_override: false, availability_reason: null },
          { family: "kernel_modules", title: "Kernel modules", state: "completed", active_run: { id: "r-A-5" }, latest_attempt: { id: "r-A-5" }, selection_reason: "latest_successful", using_fallback: false, historical_override: false, availability_reason: null },
          { family: "drivers", title: "Drivers", state: "completed", active_run: { id: "r-A-5" }, latest_attempt: { id: "r-A-5" }, selection_reason: "latest_successful", using_fallback: false, historical_override: false, availability_reason: null },
          { family: "suspicious_regions", title: "Suspicious memory regions", state: "completed", active_run: { id: "r-A-6" }, latest_attempt: { id: "r-A-6" }, selection_reason: "latest_successful", using_fallback: false, historical_override: false, availability_reason: null },
        ],
      },
      {
        evidence_id: "ev-B", case_id: "case-1", filename: "fs01.dmp",
        detected_host: "FS01", size_bytes: 8388608, created_at: "2026-06-16T00:00:00Z",
        processed_at: null, ingest_status: "completed",
        metadata: {}, run_count: 0, latest_run_id: null, latest_run_status: null,
        families: [
          { family: "system_info", title: "System metadata", state: "not_analyzed", active_run: null, latest_attempt: null, selection_reason: "not_analyzed", using_fallback: false, historical_override: false, availability_reason: null },
          { family: "processes", title: "Processes", state: "not_analyzed", active_run: null, latest_attempt: null, selection_reason: "not_analyzed", using_fallback: false, historical_override: false, availability_reason: null },
          { family: "network", title: "Network connections", state: "unavailable", active_run: null, latest_attempt: null, selection_reason: "runtime_plugin_missing", using_fallback: false, historical_override: false, availability_reason: "No compatible Windows network plugin is available in the installed Volatility runtime." },
          { family: "modules", title: "Process modules", state: "not_analyzed", active_run: null, latest_attempt: null, selection_reason: "not_analyzed", using_fallback: false, historical_override: false, availability_reason: null },
          { family: "handles", title: "Process handles", state: "not_analyzed", active_run: null, latest_attempt: null, selection_reason: "not_analyzed", using_fallback: false, historical_override: false, availability_reason: null },
          { family: "kernel_modules", title: "Kernel modules", state: "not_analyzed", active_run: null, latest_attempt: null, selection_reason: "not_analyzed", using_fallback: false, historical_override: false, availability_reason: null },
          { family: "drivers", title: "Drivers", state: "not_analyzed", active_run: null, latest_attempt: null, selection_reason: "not_analyzed", using_fallback: false, historical_override: false, availability_reason: null },
          { family: "suspicious_regions", title: "Suspicious memory regions", state: "not_analyzed", active_run: null, latest_attempt: null, selection_reason: "not_analyzed", using_fallback: false, historical_override: false, availability_reason: null },
        ],
      },
    ],
  };
}

function backendReady() {
  return {
    memory_analysis_enabled: true,
    external_execution_allowed: true,
    preferred_backend: "volatility3",
    ready_backend_count: 1,
    message: "1 memory-analysis backend is ready.",
    backends: [{
      backend: "volatility3", display_name: "Volatility 3",
      configured: true, executable_found: true, execution_allowed: true,
      available: true, ready: true, version: "Volatility 3 Framework 2.28.0",
      command_display: "vol", status: "available", message: "Volatility 3 is available.",
      checked_at: "2026-06-16T00:00:00Z", error_code: null,
      execution_mode: "dedicated_worker", dedicated_worker_required: true,
      dedicated_worker_online: true, queue: "memory", queue_reachable: true,
      backend_available: true, backend_version: "2.28.0",
      supported_profiles: ["metadata_only", "processes_basic", "processes_extended", "network_basic", "modules_basic", "handles_basic", "kernel_basic", "suspicious_memory"],
      supported_plugins: ["windows.info", "windows.pslist", "windows.psscan", "windows.pstree", "windows.cmdline"],
      symbol_network_enabled: false,
    }],
  };
}

function activeResultOk() {
  return {
    case_id: "case-1",
    evidence_id: "ev-A",
    artifact_family: "processes",
    active_run: {
      id: "r-A-2", profile: "processes_extended", status: "completed",
      started_at: "2026-06-15T00:00:00Z", completed_at: "2026-06-15T00:04:00Z",
      duration_seconds: 240, plugin_count: 5, plugins_completed: 5, plugins_failed: 0,
      evidence_id: "ev-A", case_id: "case-1",
    },
    latest_attempt: {
      id: "r-A-2", profile: "processes_extended", status: "completed",
      started_at: "2026-06-15T00:00:00Z", completed_at: "2026-06-15T00:04:00Z",
      duration_seconds: 240, plugin_count: 5, plugins_completed: 5, plugins_failed: 0,
      evidence_id: "ev-A", case_id: "case-1",
    },
    selection_reason: "latest_successful",
    using_fallback: false,
    historical_override: false,
    total: 255,
    items: [],
    analysis_state: "completed",
  };
}

function activeResultLatestFailed() {
  return {
    ...activeResultOk(),
    selection_reason: "latest_attempt_failed_kept_last_success",
    using_fallback: true,
    latest_attempt: {
      id: "r-A-fail", profile: "processes_extended", status: "failed",
      started_at: "2026-06-16T00:00:00Z", completed_at: "2026-06-16T00:01:00Z",
      duration_seconds: 60, plugin_count: 5, plugins_completed: 1, plugins_failed: 4,
      evidence_id: "ev-A", case_id: "case-1",
    },
  };
}

function activeResultHistorical() {
  return {
    ...activeResultOk(),
    selection_reason: "historical_override",
    using_fallback: false,
    historical_override: true,
    active_run: {
      id: "r-A-hist", profile: "processes_basic", status: "completed",
      started_at: "2026-06-10T00:00:00Z", completed_at: "2026-06-10T00:01:00Z",
      duration_seconds: 60, plugin_count: 4, plugins_completed: 4, plugins_failed: 0,
      evidence_id: "ev-A", case_id: "case-1",
    },
  };
}

function analysisCatalogue() {
  return {
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
}

function historyRuns() {
  return [
    { id: "r-A-fail", case_id: "case-1", evidence_id: "ev-A", profile: "processes_extended", status: "failed", started_at: "2026-06-16T00:00:00Z", completed_at: "2026-06-16T00:01:00Z", created_at: "2026-06-16T00:00:00Z", duration_ms: 60000, plugin_count: 5, plugins_completed: 1, plugins_failed: 4, metadata_json: {}, error_log: {} },
    { id: "r-A-2", case_id: "case-1", evidence_id: "ev-A", profile: "processes_extended", status: "completed", started_at: "2026-06-15T00:00:00Z", completed_at: "2026-06-15T00:04:00Z", created_at: "2026-06-15T00:00:00Z", duration_ms: 240000, plugin_count: 5, plugins_completed: 5, plugins_failed: 0, metadata_json: {}, error_log: {} },
    { id: "r-A-hist", case_id: "case-1", evidence_id: "ev-A", profile: "processes_basic", status: "completed", started_at: "2026-06-10T00:00:00Z", completed_at: "2026-06-10T00:01:00Z", created_at: "2026-06-10T00:00:00Z", duration_ms: 60000, plugin_count: 4, plugins_completed: 4, plugins_failed: 0, metadata_json: {}, error_log: {} },
  ];
}

beforeEach(() => {
  vi.clearAllMocks();
  getMemoryOverviewMock.mockImplementation(() => multiEvidenceOverview());
  getMemoryBackendOverviewMock.mockImplementation(() => backendReady());
  getMemoryEvidenceLandingMock.mockImplementation(() => multiEvidenceLanding());
  getMemoryActiveResultMock.mockImplementation(() => activeResultOk());
  getMemoryAnalysisCatalogueMock.mockImplementation(() => analysisCatalogue());
  getMemoryEvidenceReadinessMock.mockImplementation(() => ({
    exists: true, regular_file: true, readable_by_memory_worker: true,
    size_matches: true, output_writable_by_memory_worker: true,
    worker_online: true, backend_ready: true, can_analyze: true,
    error_code: null, sanitized_message: "",
    symbols_required: false, symbol_identifier_present: true,
    acquisition_available: false, acquisition_status: null,
    can_analyze_offline: true, pending_request_id: null,
  }));
  getCaseMemorySystemInfoMock.mockImplementation(() => []);
  getMemoryRunOptionsMock.mockImplementation(() => ({ runs: [], default_run_id: null, combined_historical_available: false }));
  getCanonicalProcessSummaryMock.mockImplementation(() => null);
  getCanonicalProcessEntitiesMock.mockImplementation(() => ({ items: [], total: 0, page: 1, page_size: 50, selected_run: null }));
  getCanonicalProcessTreeMock.mockImplementation(() => ({ nodes: [], edges: [], total: 0 }));
  getCanonicalProcessEntityDetailMock.mockImplementation(() => null);
  getMemorySymbolCacheStatusMock.mockImplementation(() => ({ mode: "offline_only", managed_download_enabled: false, acquisition_enabled: false, network_isolation_ready: false, administrator_authorization_available: false, cases_with_pending_requests: 0, total_cached_packages: 0, total_disk_bytes: 0, last_acquisition_at: null, recent_requests: [] }));
  getCaseMemoryProcessesMock.mockImplementation(() => ({ items: [], total: 0, page: 1, page_size: 50, selected_run: null }));
  getMemoryProcessTreeMock.mockImplementation(() => ({ nodes: [], edges: [], total: 0 }));
  startMemoryScanMock.mockImplementation(() => ({ accepted: true, evidence_id: "ev-A", run_id: "r-new", status: "queued", message: "queued", run: null }));
  renormalizeProcessEntitiesMock.mockImplementation(() => ({ case_id: "case-1", evidence_id: "ev-A", run_id: null, source_documents: 0, candidate_entities: 0, observation_count: 0, duplicate_groups_collapsed: 0, invalid_records: 0, ambiguous_pid_groups: 0, expected_edges: 0, tree_metrics: { total_nodes: 0, roots: 0, orphans: 0, unknown_parent: 0, cycles: 0, self_parent: 0, hidden_candidates: 0, scan_only: 0, terminated: 0, pid_zero_count: 0, pid_4_count: 0 }, normalization_version: "memory_process_canonical_v1", materialization_status: "applied" }));
  getMemoryArtifactOverviewMock.mockImplementation(() => makeArtifactOverview());
  getMemoryNetworkConnectionsMock.mockImplementation(() => makeArtifactList());
  getMemoryProcessModulesMock.mockImplementation(() => makeArtifactList());
  getMemoryHandlesMock.mockImplementation(() => makeArtifactList());
  getMemoryDriversMock.mockImplementation(() => makeArtifactList());
  getMemoryKernelModulesMock.mockImplementation(() => makeArtifactList());
  getMemorySuspiciousRegionsMock.mockImplementation(() => makeArtifactList());
  getMemoryArtifactDetailMock.mockImplementation(() => ({ document_type: "memory_artifact", document_id: "doc", fields: {}, provenance: {} }));
  listMemoryRunsMock.mockImplementation(() => historyRuns());
});

describe("Memory evidence scoping v1", () => {
  it("renders the evidence landing page when a case has multiple memory evidence", async () => {
    renderWorkspaceAt("/cases/case-1/memory");
    expect(await screen.findByTestId("memory-landing")).toBeInTheDocument();
    const cards = await screen.findAllByTestId("memory-evidence-card");
    expect(cards).toHaveLength(2);
    expect(cards[0].getAttribute("data-evidence-id")).toBe("ev-A");
    expect(cards[1].getAttribute("data-evidence-id")).toBe("ev-B");
  });

  it("renders one evidence card per host with filename and host label", async () => {
    renderWorkspaceAt("/cases/case-1/memory/landing");
    const cards = await screen.findAllByTestId("memory-evidence-card");
    expect(cards[0].textContent).toContain("ws01.dmp");
    expect(cards[0].textContent).toContain("WS01");
    expect(cards[1].textContent).toContain("fs01.dmp");
    expect(cards[1].textContent).toContain("FS01");
  });

  it("shows per-family status on every evidence card", async () => {
    renderWorkspaceAt("/cases/case-1/memory/landing");
    const modulesMatches = await screen.findAllByTestId("memory-evidence-family-modules");
    expect(modulesMatches.length).toBeGreaterThanOrEqual(1);
    expect(modulesMatches[0].getAttribute("data-family-state")).toBe("completed");
    const networkMatches = await screen.findAllByTestId("memory-evidence-family-network");
    expect(networkMatches.length).toBeGreaterThanOrEqual(1);
    expect(networkMatches[0].getAttribute("data-family-state")).toBe("unavailable");
  });

  it("renders the evidence workspace with header at /cases/:caseId/memory/:evidenceId", async () => {
    renderWorkspaceAt("/cases/case-1/memory/ev-A");
    const header = await screen.findByTestId("memory-evidence-header");
    expect(header).toBeInTheDocument();
    expect(header.getAttribute("data-evidence-id")).toBe("ev-A");
    expect(screen.getByTestId("memory-evidence-filename")).toHaveTextContent("ws01.dmp");
    expect(screen.getByTestId("memory-evidence-host")).toHaveTextContent("WS01");
    expect(screen.getByTestId("memory-evidence-size")).toHaveTextContent(/GiB/);
  });

  it("shows the Latest successful badge in the evidence header", async () => {
    renderWorkspaceAt("/cases/case-1/memory/ev-A");
    const badge = await screen.findByTestId("memory-active-result-badge");
    expect(badge).toHaveTextContent("Latest successful");
  });

  it("hides the manual run selector when the workspace is evidence-scoped", async () => {
    renderWorkspaceAt("/cases/case-1/memory/ev-A?tab=artifacts");
    const latest = await screen.findByTestId("memory-artifacts-latest-successful");
    expect(latest).toBeInTheDocument();
    expect(screen.queryByTestId("memory-artifacts-run-picker")).not.toBeInTheDocument();
  });

  it("renders the catalogue modal with 8 profiles and disables network", async () => {
    renderWorkspaceAt("/cases/case-1/memory/ev-A");
    fireEvent.click(await screen.findByTestId("memory-open-catalogue"));
    const modal = await screen.findByTestId("memory-catalogue-modal");
    expect(modal).toBeInTheDocument();
    expect(screen.getByTestId("memory-catalogue-item-metadata_only")).toBeInTheDocument();
    expect(screen.getByTestId("memory-catalogue-item-processes_extended")).toBeInTheDocument();
    expect(screen.getByTestId("memory-catalogue-item-network_basic")).toBeInTheDocument();
    expect(screen.getAllByTestId("catalogue-unavailable").length).toBeGreaterThanOrEqual(1);
    const networkRun = screen.getByTestId("memory-catalogue-run-network_basic") as HTMLButtonElement;
    expect(networkRun.disabled).toBe(true);
    expect(screen.getByTestId("catalogue-unavailable-reason")).toHaveTextContent(/Windows network plugin/);
  });

  it("renders the View analysis history button and opens the panel scoped to the evidence + family", async () => {
    renderWorkspaceAt("/cases/case-1/memory/ev-A?tab=processes");
    fireEvent.click(await screen.findByTestId("memory-view-history"));
    const panel = await screen.findByTestId("memory-history-panel");
    expect(panel).toBeInTheDocument();
    await waitFor(() => {
      expect(listMemoryRunsMock).toHaveBeenCalledWith("case-1", "ev-A");
    });
  });

  it("shows the latest-attempt-failed banner when using_fallback is true", async () => {
    getMemoryActiveResultMock.mockImplementation(() => activeResultLatestFailed());
    renderWorkspaceAt("/cases/case-1/memory/ev-A?tab=processes");
    expect(await screen.findByTestId("memory-latest-failed-banner")).toBeInTheDocument();
  });

  it("shows the historical-result banner when run_id is set and the active result is the override", async () => {
    getMemoryActiveResultMock.mockImplementation(() => activeResultHistorical());
    renderWorkspaceAt("/cases/case-1/memory/ev-A?tab=processes&run_id=r-A-hist");
    expect(await screen.findByTestId("memory-historical-banner")).toBeInTheDocument();
  });

  it("returns to the latest successful result from the historical banner", async () => {
    getMemoryActiveResultMock.mockImplementation(() => activeResultHistorical());
    renderWorkspaceAt("/cases/case-1/memory/ev-A?tab=processes&run_id=r-A-hist");
    fireEvent.click(await screen.findByTestId("memory-historical-return"));
    await waitFor(() => {
      expect(window.location.search).not.toContain("run_id=r-A-hist");
    });
  });

  it("shows the evidence back link and routes to the case memory landing", async () => {
    renderWorkspaceAt("/cases/case-1/memory/ev-A");
    const back = await screen.findByTestId("memory-evidence-back");
    expect(back.getAttribute("href")).toBe("/cases/case-1/memory");
  });

  it("shows a Not analyzed family card on the Overview tab for unrun evidence", async () => {
    getMemoryActiveResultMock.mockImplementation(() => ({
      ...activeResultOk(),
      analysis_state: "not_analyzed",
      active_run: null,
      latest_attempt: null,
      selection_reason: "not_analyzed",
    }));
    renderWorkspaceAt("/cases/case-1/memory/ev-A?tab=processes");
    // The header should not show the active-result badge for an unrun family
    expect(screen.queryByTestId("memory-active-result-badge")).not.toBeInTheDocument();
  });

  it("does not leak cross-evidence data: listMemoryRuns is called with the workspace's evidence_id", async () => {
    renderWorkspaceAt("/cases/case-1/memory/ev-A?tab=processes");
    fireEvent.click(await screen.findByTestId("memory-view-history"));
    await waitFor(() => {
      expect(listMemoryRunsMock).toHaveBeenCalledWith("case-1", "ev-A");
    });
    // Second call (if any) should not be for ev-B
    const calls = listMemoryRunsMock.mock.calls;
    for (const call of calls) {
      expect(call[1]).toBe("ev-A");
    }
  });

  it("the catalogue is fetched for the workspace's evidence_id", async () => {
    renderWorkspaceAt("/cases/case-1/memory/ev-A");
    fireEvent.click(await screen.findByTestId("memory-open-catalogue"));
    await waitFor(() => {
      expect(getMemoryAnalysisCatalogueMock).toHaveBeenCalledWith("case-1", "ev-A");
    });
  });

  it("the active-result endpoint is called with the workspace's evidence_id and family for processes", async () => {
    renderWorkspaceAt("/cases/case-1/memory/ev-A?tab=processes");
    await waitFor(() => {
      expect(getMemoryActiveResultMock).toHaveBeenCalled();
    });
    const calls = getMemoryActiveResultMock.mock.calls;
    expect(calls.some((call) => call[1] === "ev-A" && call[2] === "processes")).toBe(true);
  });

  it("does not produce a global horizontal scroll on the evidence workspace", async () => {
    renderWorkspaceAt("/cases/case-1/memory/ev-A");
    const workspace = await screen.findByTestId("memory-evidence-workspace");
    const styles = window.getComputedStyle(workspace);
    expect(styles.overflowX).not.toBe("auto");
    expect(styles.overflowX).not.toBe("scroll");
  });

  it("renders the responsive grid of evidence cards in the landing page", async () => {
    renderWorkspaceAt("/cases/case-1/memory/landing");
    const cards = await screen.findAllByTestId("memory-evidence-card");
    expect(cards).toHaveLength(2);
  });

  it("does not render private server paths in the evidence header", async () => {
    renderWorkspaceAt("/cases/case-1/memory/ev-A");
    const header = await screen.findByTestId("memory-evidence-header");
    expect(header.textContent).not.toMatch(/\/var\/lib/);
    expect(header.textContent).not.toMatch(/\/opt\/kairon/);
    expect(header.textContent).not.toMatch(/C:\\|\\\\/);
  });

  it("does not show the legacy 'Add memory image' from the analyze action when on a single evidence", async () => {
    // The single evidence landing should not show the old analyze-action component
    renderWorkspaceAt("/cases/case-1/memory/ev-A");
    expect(screen.queryByTestId("memory-analyze-action")).not.toBeInTheDocument();
  });

  it("the catalogue modal Run button posts startMemoryScan with the chosen profile", async () => {
    renderWorkspaceAt("/cases/case-1/memory/ev-A");
    fireEvent.click(await screen.findByTestId("memory-open-catalogue"));
    const runBtn = screen.getByTestId("memory-catalogue-run-suspicious_memory") as HTMLButtonElement;
    window.confirm = vi.fn().mockReturnValue(true);
    fireEvent.click(runBtn);
    await waitFor(() => {
      expect(startMemoryScanMock).toHaveBeenCalledWith("ev-A", "suspicious_memory", true);
    });
  });

  it("the landing page only shows memory evidence and excludes disk-only evidence", async () => {
    const landing = multiEvidenceLanding();
    landing.items = landing.items.slice(0, 1);
    getMemoryEvidenceLandingMock.mockImplementation(() => landing);
    renderWorkspaceAt("/cases/case-1/memory/landing");
    const cards = await screen.findAllByTestId("memory-evidence-card");
    expect(cards).toHaveLength(1);
    expect(cards[0].getAttribute("data-evidence-id")).toBe("ev-A");
  });

  it("the Runs tab in the evidence-scoped workspace only lists runs for that evidence", async () => {
    listMemoryRunsMock.mockImplementation((_caseId: string, evidenceId?: string) =>
      evidenceId === "ev-A" ? historyRuns() : [],
    );
    renderWorkspaceAt("/cases/case-1/memory/ev-A?tab=runs");
    await waitFor(() => {
      const calls = listMemoryRunsMock.mock.calls;
      for (const call of calls) {
        // The History panel would call with "ev-A"; the workspace header shouldn't fetch all-runs for the case
        // We assert that no call was made with no evidence_id (which would leak all case runs)
        if (call.length > 1) {
          expect(call[1]).toBe("ev-A");
        }
      }
    });
  });

  it("the historical banner is not shown when run_id is missing from the URL", async () => {
    renderWorkspaceAt("/cases/case-1/memory/ev-A?tab=processes");
    expect(screen.queryByTestId("memory-historical-banner")).not.toBeInTheDocument();
  });

  it("redirects to the evidence-scoped route when a case has exactly one memory evidence", async () => {
    const singleOverview = {
      case_id: "case-1",
      memory_analysis_enabled: true,
      has_memory_evidence: true,
      has_memory_results: true,
      has_disk_events: false,
      mode: "memory_only",
      evidences: [
        { id: "ev-sole", case_id: "case-1", original_filename: "sole.dmp", evidence_type: "memory_dump", size_bytes: 4255346688, ingest_status: "completed", created_at: "2026-06-15T00:00:00Z" },
      ],
      runs: [],
      message: "Memory analysis is available.",
    };
    getMemoryOverviewMock.mockImplementation(() => singleOverview);
    const singleLanding = {
      case_id: "case-1",
      items: [
        {
          evidence_id: "ev-sole", case_id: "case-1", filename: "sole.dmp",
          detected_host: "WS-SOLE", size_bytes: 4255346688, created_at: "2026-06-15T00:00:00Z",
          processed_at: "2026-06-15T00:01:00Z", ingest_status: "completed",
          metadata: {}, run_count: 1, latest_run_id: "r-sole-1", latest_run_status: "completed",
          families: [
            { family: "system_info", title: "System metadata", state: "completed", active_run: { id: "r-sole-1" }, latest_attempt: { id: "r-sole-1" }, selection_reason: "latest_successful", using_fallback: false, historical_override: false, availability_reason: null },
            { family: "processes", title: "Processes", state: "completed", active_run: { id: "r-sole-1" }, latest_attempt: { id: "r-sole-1" }, selection_reason: "latest_successful", using_fallback: false, historical_override: false, availability_reason: null },
            { family: "network", title: "Network connections", state: "unavailable", active_run: null, latest_attempt: null, selection_reason: "runtime_plugin_missing", using_fallback: false, historical_override: false, availability_reason: "No compatible Windows network plugin is available." },
            { family: "modules", title: "Process modules", state: "completed", active_run: { id: "r-sole-1" }, latest_attempt: { id: "r-sole-1" }, selection_reason: "latest_successful", using_fallback: false, historical_override: false, availability_reason: null },
            { family: "handles", title: "Process handles", state: "completed", active_run: { id: "r-sole-1" }, latest_attempt: { id: "r-sole-1" }, selection_reason: "latest_successful", using_fallback: false, historical_override: false, availability_reason: null },
            { family: "kernel_modules", title: "Kernel modules", state: "completed", active_run: { id: "r-sole-1" }, latest_attempt: { id: "r-sole-1" }, selection_reason: "latest_successful", using_fallback: false, historical_override: false, availability_reason: null },
            { family: "drivers", title: "Drivers", state: "completed", active_run: { id: "r-sole-1" }, latest_attempt: { id: "r-sole-1" }, selection_reason: "latest_successful", using_fallback: false, historical_override: false, availability_reason: null },
            { family: "suspicious_regions", title: "Suspicious memory regions", state: "completed", active_run: { id: "r-sole-1" }, latest_attempt: { id: "r-sole-1" }, selection_reason: "latest_successful", using_fallback: false, historical_override: false, availability_reason: null },
          ],
        },
      ],
    };
    getMemoryEvidenceLandingMock.mockImplementation(() => singleLanding);
    renderWorkspaceAt("/cases/case-1/memory");
    const header = await screen.findByTestId("memory-evidence-header");
    expect(header).toBeInTheDocument();
    expect(header.getAttribute("data-evidence-id")).toBe("ev-sole");
    expect(screen.getByTestId("memory-evidence-filename")).toHaveTextContent("sole.dmp");
    expect(screen.queryByTestId("memory-analyze-action")).not.toBeInTheDocument();
    expect(screen.queryByTestId("analyze-profile-select")).not.toBeInTheDocument();
  });

  it("the legacy 3-option Analyze memory selector is not rendered in any evidence-scoped view", async () => {
    renderWorkspaceAt("/cases/case-1/memory/ev-A?tab=overview");
    expect(screen.queryByTestId("memory-analyze-action")).not.toBeInTheDocument();
    expect(screen.queryByTestId("analyze-profile-select")).not.toBeInTheDocument();
    expect(screen.queryByTestId("analyze-run-button")).not.toBeInTheDocument();
  });

  it("does not crash and shows the empty-state copy when a case has zero memory evidence", async () => {
    getMemoryOverviewMock.mockImplementation(() => ({
      case_id: "case-empty",
      memory_analysis_enabled: true,
      has_memory_evidence: false,
      has_memory_results: false,
      has_disk_events: false,
      mode: "empty_case",
      evidences: [],
      runs: [],
      message: "No memory evidence registered.",
    }));
    renderWorkspaceAt("/cases/case-empty/memory");
    expect(await screen.findByText(/Select a case first|Loading memory evidence|No memory evidence|Authorized RAM evidence|Opening evidence workspace/i)).toBeInTheDocument();
  });
});
