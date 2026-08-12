import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { fireEvent, render, screen, waitFor } from "@testing-library/react";
import { MemoryRouter, Route, Routes, useLocation } from "react-router-dom";
import { beforeEach, describe, expect, it, vi } from "vitest";
import MemoryEvidencePage from "./MemoryEvidencePage";

// Exposes the router's current pathname+search as a testid so tests can
// assert on location.pathname the same way a real click-through in the
// browser would be verified, instead of only inferring it indirectly from
// which subview happened to render.
function LocationProbe() {
  const location = useLocation();
  return <span data-testid="current-location">{location.pathname + location.search}</span>;
}

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
const listMemoryRunsMock = vi.fn();
const getMemoryEvidenceLandingMock = vi.fn();
const getMemoryActiveResultMock = vi.fn();
const getMemoryAnalysisCatalogueMock = vi.fn();

vi.mock("../api/client", () => ({
  api: {
    getMemoryBackendOverview: (...args: unknown[]) => getMemoryBackendOverviewMock(...args),
    getMemoryOverview: (...args: unknown[]) => getMemoryOverviewMock(...args),
    getCaseMemorySystemInfo: (...args: unknown[]) => getCaseMemorySystemInfoMock(...args),
    getEvidenceMemorySystemInfo: (...args: unknown[]) => getCaseMemorySystemInfoMock(...args),
    getMemoryRunOptions: (...args: unknown[]) => getMemoryRunOptionsMock(...args),
    getEvidenceMemoryRunOptions: (...args: unknown[]) => getMemoryRunOptionsMock(...args),
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
    listMemoryRuns: (...args: unknown[]) => listMemoryRunsMock(...args),
    getMemoryEvidenceLanding: (...args: unknown[]) => getMemoryEvidenceLandingMock(...args),
    getMemoryActiveResult: (...args: unknown[]) => getMemoryActiveResultMock(...args),
    getMemoryAnalysisCatalogue: (...args: unknown[]) => getMemoryAnalysisCatalogueMock(...args),
  },
}));

vi.mock("../context/ActiveCaseContext", () => ({
  useActiveCase: () => ({
    setActiveCaseId: vi.fn(),
  }),
}));

function renderPage(initialPath = "/cases/case-1/memory/ev-memory") {
  const queryClient = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  return render(
    <MemoryRouter initialEntries={[initialPath]}>
      <QueryClientProvider client={queryClient}>
        <LocationProbe />
        <Routes>
          <Route path="/cases/:caseId/memory/:evidenceId/:memoryTab" element={<MemoryEvidencePage />} />
          <Route path="/cases/:caseId/memory/:evidenceId" element={<MemoryEvidencePage />} />
          {/* Real tab clicks navigate to the canonical /m/ route
              (memoryEvidenceRoute / memoryViewPath), not this file's legacy
              /memory/ initialPath strings -- both have to be registered here
              so clicking a tab (which pushes a canonical URL) actually
              resolves inside this test's own router, the same way it does
              in the real App.tsx route table. */}
          <Route path="/cases/:caseId/m/:evidenceId/:memoryTab" element={<MemoryEvidencePage />} />
          <Route path="/cases/:caseId/m/:evidenceId" element={<MemoryEvidencePage />} />
        </Routes>
      </QueryClientProvider>
    </MemoryRouter>,
  );
}

function overview(overrides = {}) {
  return {
    case_id: "case-1",
    memory_analysis_enabled: true,
    has_memory_evidence: true,
    has_memory_results: true,
    has_disk_events: false,
    mode: "memory_only",
    evidences: [
      {
        id: "ev-memory",
        case_id: "case-1",
        original_filename: "memory.mem",
        evidence_type: "memory_dump",
        size_bytes: 2048,
        ingest_status: "completed",
        created_at: "2026-06-16T00:00:00Z",
      },
    ],
    runs: [
      {
        id: "run-basic",
        case_id: "case-1",
        evidence_id: "ev-memory",
        backend: "volatility3",
        profile: "processes_basic",
        status: "completed",
        requested_plugin_count: 4,
        plugin_count: 4,
        plugins_completed: 4,
        plugins_failed: 0,
        plugins_skipped: 0,
        started_at: "2026-06-16T00:00:00Z",
        completed_at: "2026-06-16T00:01:00Z",
        duration_ms: 60000,
        output_dir: null,
        metadata_json: {},
        error_log: {},
        backend_version: "Volatility 3 Framework 2.28.0",
        worker_task_id: null,
        cancellation_requested: false,
        created_at: "2026-06-16T00:00:00Z",
      },
    ],
    message: "Memory analysis is available.",
    ...overrides,
  };
}

function backendOverview(overrides = {}) {
  return {
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
        checked_at: "2026-06-16T00:00:00Z",
        error_code: null,
        execution_mode: "dedicated_worker",
        dedicated_worker_required: true,
        dedicated_worker_online: true,
        queue: "memory",
        queue_reachable: true,
        backend_available: true,
        backend_version: "2.28.0",
        supported_profiles: ["metadata_only", "processes_basic", "processes_extended"],
        supported_plugins: ["windows.info", "windows.pslist", "windows.psscan", "windows.pstree", "windows.cmdline"],
        symbol_network_enabled: false,
      },
    ],
    ...overrides,
  };
}

function runOptions() {
  return {
    runs: [
      {
        run_id: "run-basic",
        profile: "processes_basic",
        status: "completed",
        created_at: "2026-06-16T00:00:00Z",
        completed_at: "2026-06-16T00:01:00Z",
        plugin_count: 4,
        plugins_completed: 4,
        plugins_failed: 0,
        selected: true,
      },
      {
        run_id: "run-extended",
        profile: "processes_extended",
        status: "completed",
        created_at: "2026-06-16T00:30:00Z",
        completed_at: "2026-06-16T00:32:00Z",
        plugin_count: 5,
        plugins_completed: 5,
        plugins_failed: 0,
        selected: false,
      },
    ],
    default_run_id: "run-basic",
    combined_historical_available: true,
  };
}

function summary() {
  return {
    case_id: "case-1",
    evidence_id: "ev-memory",
    run_id: "run-basic",
    source_documents: 100,
    candidate_entities: 50,
    observation_count: 100,
    duplicate_groups_collapsed: 50,
    invalid_records: 0,
    ambiguous_pid_groups: 1,
    expected_edges: 40,
    tree_metrics: {
      total_nodes: 50,
      roots: 1,
      orphans: 5,
      unknown_parent: 0,
      cycles: 0,
      self_parent: 0,
      hidden_candidates: 2,
      scan_only: 2,
      terminated: 5,
      pid_zero_count: 1,
      pid_4_count: 1,
    },
    normalization_version: "memory_process_canonical_v1",
    materialization_status: "applied",
  };
}

function systemInfo() {
  return [
    {
      case_id: "case-1",
      evidence_id: "ev-memory",
      memory_run_id: "run-basic",
      memory_plugin_run_id: "plugin-basic-info",
      source_layer: "memory",
      memory_artifact_type: "memory_system_info",
      backend: "volatility3",
      plugin: "windows.info",
      host: { name: "WS01" },
      os: {
        family: "windows",
        kernel_base: "0xf8000000",
        kernel_version: "10.0.19041",
        machine_type: "x64",
        nt_major_version: 10,
        nt_minor_version: 0,
      },
      memory: {
        layer_name: "primary",
        dtb: "0x1abcd000",
        kernel_symbols: "ntkrnlmp.pdb",
        system_time: "2024-03-22T10:00:00+00:00",
      },
      parsed_at: "2026-06-16T00:01:00Z",
      raw: { backend_version: "2.28.0" },
    },
    {
      case_id: "case-1",
      evidence_id: "ev-memory",
      memory_run_id: "run-extended",
      memory_plugin_run_id: "plugin-ext-info",
      source_layer: "memory",
      memory_artifact_type: "memory_system_info",
      backend: "volatility3",
      plugin: "windows.info",
      host: { name: "WS01" },
      os: { family: "windows", kernel_base: "0xf8000000", machine_type: "x64" },
      memory: {},
      parsed_at: "2026-06-16T00:32:00Z",
      raw: {},
    },
  ];
}

describe("MemoryAnalysisPage workspace", () => {
  beforeEach(() => {
    vi.clearAllMocks();
    getMemoryOverviewMock.mockResolvedValue(overview());
    getMemoryBackendOverviewMock.mockResolvedValue(backendOverview());
    getCaseMemorySystemInfoMock.mockResolvedValue(systemInfo());
    getMemoryRunOptionsMock.mockResolvedValue(runOptions());
    getCanonicalProcessSummaryMock.mockResolvedValue(summary());
    getCanonicalProcessEntitiesMock.mockResolvedValue({ items: [], total: 0, page: 1, page_size: 50, selected_run: "run-basic", normalization_version: "memory_process_canonical_v1", total_observations: 0, facets: {} });
    getCanonicalProcessTreeMock.mockResolvedValue({
      run_id: "run-basic",
      nodes: [
        {
          process_entity_id: "ent-system",
          pid: 4,
          ppid: 0,
          name: "System",
          command_line: null,
          sources: ["windows.pslist"],
          visibility: { listed: true },
          findings: [],
          child_count: 1,
          confidence: "high",
          tree: { is_root: true },
          truncated: false,
          omitted_children: 0,
          children: [
            {
              process_entity_id: "ent-smss",
              pid: 444,
              ppid: 4,
              name: "smss.exe",
              command_line: null,
              sources: ["windows.pslist"],
              visibility: { listed: true },
              findings: [],
              child_count: 0,
              confidence: "high",
              tree: {},
              truncated: false,
              omitted_children: 0,
              children: [],
            },
          ],
        },
      ],
      edges: [],
      metrics: { total_nodes: 2, roots: 1, orphans: 0, unknown_parent: 0, cycles: 0, self_parent: 0, hidden_candidates: 0, scan_only: 0, terminated: 0, pid_zero_count: 0, pid_4_count: 1, visible_nodes: 2, search_results: [] },
      total_entities: 2,
      omitted_count: 0,
      truncation_reason: null,
      search_results: [],
    });
    getCanonicalProcessEntityDetailMock.mockResolvedValue(null);
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
      last_success_at: "2026-06-16T00:00:00Z", error_code: "SYMBOL_ACQUISITION_DISABLED",
      message: "Symbols cached.",
    });
    getCaseMemoryProcessesMock.mockResolvedValue({ items: [], total: 0, page: 1, page_size: 50 });
    getMemoryProcessTreeMock.mockResolvedValue({ run_id: "run-basic", nodes: [], edges: [], orphan_count: 0, root_count: 0, warnings: [], source_plugins: [], total_process_count: 0 });
    startMemoryScanMock.mockResolvedValue({ accepted: true, evidence_id: "ev-memory", run_id: "run-basic", status: "queued", message: "queued", run: null });
    renormalizeProcessEntitiesMock.mockResolvedValue({ ...summary(), materialization_status: "applied" });
    listMemoryRunsMock.mockResolvedValue([
      { id: "run-basic", case_id: "case-1", evidence_id: "ev-memory", backend: "volatility3", profile: "processes_basic", status: "completed", requested_plugin_count: 4, plugin_count: 4, plugins_completed: 4, plugins_failed: 0, plugins_skipped: 0, started_at: "2026-06-16T00:00:00Z", completed_at: "2026-06-16T00:00:30Z", duration_ms: 30000, output_dir: null, metadata_json: {}, error_log: {}, backend_version: "2.28.0", worker_task_id: null, cancellation_requested: false, created_at: "2026-06-16T00:00:00Z" },
    ]);
    getMemoryEvidenceLandingMock.mockResolvedValue({
      case_id: "case-1",
      items: [
        {
          evidence_id: "ev-memory",
          case_id: "case-1",
          filename: "memory.mem",
          detected_host: "WS01",
          size_bytes: 2048,
          created_at: "2026-06-16T00:00:00Z",
          processed_at: "2026-06-16T00:01:00Z",
          ingest_status: "completed",
          metadata: {},
          families: [
            { family: "system_info", title: "System metadata", state: "completed", active_run: { id: "run-basic" }, latest_attempt: { id: "run-basic" }, selection_reason: "latest_successful", using_fallback: false, historical_override: false, availability_reason: null },
            { family: "processes", title: "Processes", state: "completed", active_run: { id: "run-basic" }, latest_attempt: { id: "run-basic" }, selection_reason: "latest_successful", using_fallback: false, historical_override: false, availability_reason: null },
            { family: "network", title: "Network connections", state: "unavailable", active_run: null, latest_attempt: null, selection_reason: "runtime_plugin_missing", using_fallback: false, historical_override: false, availability_reason: "No compatible Windows network plugin is available." },
            { family: "modules", title: "Process modules", state: "completed", active_run: { id: "run-basic" }, latest_attempt: { id: "run-basic" }, selection_reason: "latest_successful", using_fallback: false, historical_override: false, availability_reason: null },
            { family: "handles", title: "Process handles", state: "completed", active_run: { id: "run-basic" }, latest_attempt: { id: "run-basic" }, selection_reason: "latest_successful", using_fallback: false, historical_override: false, availability_reason: null },
            { family: "kernel_modules", title: "Kernel modules", state: "completed", active_run: { id: "run-basic" }, latest_attempt: { id: "run-basic" }, selection_reason: "latest_successful", using_fallback: false, historical_override: false, availability_reason: null },
            { family: "drivers", title: "Drivers", state: "completed", active_run: { id: "run-basic" }, latest_attempt: { id: "run-basic" }, selection_reason: "latest_successful", using_fallback: false, historical_override: false, availability_reason: null },
            { family: "suspicious_regions", title: "Suspicious memory regions", state: "completed", active_run: { id: "run-basic" }, latest_attempt: { id: "run-basic" }, selection_reason: "latest_successful", using_fallback: false, historical_override: false, availability_reason: null },
          ],
          run_count: 1,
          latest_run_id: "run-basic",
          latest_run_status: "completed",
        },
      ],
    });
    getMemoryActiveResultMock.mockResolvedValue({
      case_id: "case-1",
      evidence_id: "ev-memory",
      artifact_family: "processes",
      active_run: {
        id: "run-basic",
        profile: "processes_basic",
        status: "completed",
        started_at: "2026-06-16T00:00:00Z",
        completed_at: "2026-06-16T00:01:00Z",
        duration_seconds: 60,
        plugin_count: 4,
        plugins_completed: 4,
        plugins_failed: 0,
        evidence_id: "ev-memory",
        case_id: "case-1",
      },
      latest_attempt: {
        id: "run-basic",
        profile: "processes_basic",
        status: "completed",
        started_at: "2026-06-16T00:00:00Z",
        completed_at: "2026-06-16T00:01:00Z",
        duration_seconds: 60,
        plugin_count: 4,
        plugins_completed: 4,
        plugins_failed: 0,
        evidence_id: "ev-memory",
        case_id: "case-1",
      },
      selection_reason: "latest_successful",
      using_fallback: false,
      historical_override: false,
      total: 0,
      items: [],
      analysis_state: "completed",
    });
    getMemoryAnalysisCatalogueMock.mockResolvedValue({
      case_id: "case-1",
      evidence_id: "ev-memory",
      items: [
        { profile: "metadata_only", family: "system_info", title: "System metadata", description: "", cost_label: "Fast", est_duration_seconds: 20, available: true, availability_reason: null, last_run: { id: "run-basic" }, last_status: "completed", last_count: 1 },
        { profile: "processes_basic", family: "processes", title: "Standard process analysis", description: "", cost_label: "Medium", est_duration_seconds: 90, available: true, availability_reason: null, last_run: { id: "run-basic" }, last_status: "completed", last_count: 50 },
        { profile: "processes_extended", family: "processes", title: "Extended process analysis", description: "", cost_label: "Medium", est_duration_seconds: 240, available: true, availability_reason: null, last_run: { id: "run-basic" }, last_status: "completed", last_count: 50 },
        { profile: "network_basic", family: "network", title: "Network connections", description: "", cost_label: "Medium", est_duration_seconds: 90, available: false, availability_reason: "No compatible Windows network plugin is available.", last_run: null, last_status: null, last_count: 0 },
        { profile: "modules_basic", family: "modules", title: "Process modules (DLLs)", description: "", cost_label: "Medium", est_duration_seconds: 120, available: true, availability_reason: null, last_run: { id: "run-basic" }, last_status: "completed", last_count: 21339 },
        { profile: "handles_basic", family: "handles", title: "Process handles", description: "", cost_label: "High volume", est_duration_seconds: 1800, available: true, availability_reason: null, last_run: { id: "run-basic" }, last_status: "completed", last_count: 97087 },
        { profile: "kernel_basic", family: "kernel_modules", title: "Kernel modules & drivers", description: "", cost_label: "Medium", est_duration_seconds: 180, available: true, availability_reason: null, last_run: { id: "run-basic" }, last_status: "completed", last_count: 169 },
        { profile: "suspicious_memory", family: "suspicious_regions", title: "Suspicious memory regions", description: "", cost_label: "Slow", est_duration_seconds: 1800, available: true, availability_reason: null, last_run: { id: "run-basic" }, last_status: "completed", last_count: 19 },
      ],
    });
    vi.spyOn(window, "confirm").mockReturnValue(true);
  });

  // 1. Overview renders summary (new evidence-scoped overview).
  it("renders the overview summary by default", async () => {
    renderPage();
    expect(await screen.findByTestId("memory-overview")).toBeInTheDocument();
    // The new overview shows the per-family status table, not the
    // legacy "Latest run" card.
    expect(screen.getByTestId("memory-family-table")).toBeInTheDocument();
    expect(screen.getByTestId("memory-overview-status")).toBeInTheDocument();
  });

  // 2. Processes tab shows the canonical table
  it("renders the Processes tab with the canonical table", async () => {
    renderPage();
    fireEvent.click(await screen.findByTestId("memory-tab-processes"));
    expect(await screen.findByTestId("memory-processes-tab")).toBeInTheDocument();
    await waitFor(() => {
      expect(getCanonicalProcessEntitiesMock).toHaveBeenCalled();
    });
  });

  // 3. Graph tab shows graph
  it("renders the Graph tab with the interactive graph", async () => {
    renderPage();
    fireEvent.click(await screen.findByTestId("memory-tab-graph"));
    expect(await screen.findByTestId("memory-graph-tab")).toBeInTheDocument();
    await waitFor(() => {
      expect(screen.getByTestId("memory-process-canvas")).toBeInTheDocument();
    }, { timeout: 5000 });
    expect(screen.getByTestId("metrics-strip")).toBeInTheDocument();
  });

  // 4. System tab shows only latest successful by default
  it("renders the System tab with the latest successful windows.info", async () => {
    renderPage();
    fireEvent.click(await screen.findByTestId("memory-tab-system"));
    expect(await screen.findByTestId("memory-system-tab")).toBeInTheDocument();
    const primary = await screen.findByTestId("system-info-card-primary");
    expect(primary).toHaveTextContent("WS01");
  });

  // 5. Runs tab contains history
  it("renders the Runs tab with the full history", async () => {
    renderPage();
    fireEvent.click(await screen.findByTestId("memory-tab-runs"));
    expect(await screen.findByTestId("memory-runs-tab")).toBeInTheDocument();
    await waitFor(() => {
      expect(screen.getByTestId("runs-table")).toBeInTheDocument();
    });
    expect(screen.getByTestId("run-row-run-basic")).toBeInTheDocument();
  });

  it("opens a direct evidence-scoped Runs URL without rendering the selector", async () => {
    renderPage("/cases/case-1/memory/ev-memory/runs");
    expect(await screen.findByTestId("memory-runs-tab")).toBeInTheDocument();
    expect(screen.queryByTestId("memory-landing")).not.toBeInTheDocument();
    await waitFor(() => {
      expect(listMemoryRunsMock).toHaveBeenCalledWith("case-1", "ev-memory");
    });
  });

  it("marks Runs (and only Runs) as the active tab on a direct URL load, which also covers reload", async () => {
    renderPage("/cases/case-1/memory/ev-memory/runs");
    await screen.findByTestId("memory-runs-tab");
    // A direct load at the Runs URL is exactly what a hard reload replays
    // (SPA state is rebuilt from the URL, not from in-memory React state) --
    // this doubles as the "reload keeps Runs active" check from the spec.
    expect(screen.getByTestId("memory-tab-runs")).toHaveAttribute("aria-selected", "true");
    expect(screen.getByTestId("memory-tab-overview")).toHaveAttribute("aria-selected", "false");
    expect(screen.getByTestId("memory-tab-processes")).toHaveAttribute("aria-selected", "false");
  });

  it("never widens the Runs query to case-wide when loaded for a specific evidence", async () => {
    renderPage("/cases/case-1/memory/ev-memory/runs");
    await screen.findByTestId("run-row-run-basic");
    // caseId + evidenceId together, every time -- never a case-wide
    // (evidenceId-less) fetch for an evidence-scoped Runs URL.
    for (const call of listMemoryRunsMock.mock.calls) {
      expect(call).toEqual(["case-1", "ev-memory"]);
    }
    expect(listMemoryRunsMock).toHaveBeenCalledWith("case-1", "ev-memory");
  });

  it("shows failed and skipped plugin counts as distinct, uncollapsed values", async () => {
    // MemoryEvidencePage's own evidenceRunsQuery and MemoryWorkspace's
    // runsQuery both call api.listMemoryRuns(caseId, evidenceId) -- a
    // "once" override would only satisfy whichever of the two fires
    // first, so the persistent form is required to cover both callers.
    listMemoryRunsMock.mockResolvedValue([
      {
        id: "run-mixed", case_id: "case-1", evidence_id: "ev-memory", backend: "volatility3", profile: "processes_extended",
        status: "completed_with_errors", requested_plugin_count: 6, plugin_count: 6, plugins_completed: 3, plugins_failed: 2,
        plugins_skipped: 1, started_at: "2026-06-16T00:00:00Z", completed_at: "2026-06-16T00:01:00Z", duration_ms: 60000,
        output_dir: null, metadata_json: {}, error_log: {}, backend_version: "2.28.0", worker_task_id: null,
        cancellation_requested: false, created_at: "2026-06-16T00:00:00Z",
      },
    ]);
    renderPage("/cases/case-1/memory/ev-memory/runs");
    await screen.findByTestId("run-row-run-mixed");
    expect(screen.getByTestId("run-row-run-mixed-failed")).toHaveTextContent("2");
    expect(screen.getByTestId("run-row-run-mixed-skipped")).toHaveTextContent("1");
  });

  it("shows an empty state when the evidence has no runs", async () => {
    listMemoryRunsMock.mockResolvedValue([]);
    renderPage("/cases/case-1/memory/ev-memory/runs");
    await screen.findByTestId("memory-runs-tab");
    expect(await screen.findByText("No runs match the current filters.")).toBeInTheDocument();
  });

  it("shows an error state when the runs query fails, instead of a silent empty table", async () => {
    listMemoryRunsMock.mockRejectedValue(new Error("Failed to load memory runs"));
    renderPage("/cases/case-1/memory/ev-memory/runs");
    expect(await screen.findByTestId("memory-runs-tab-error")).toHaveTextContent("Failed to load memory runs");
    expect(screen.queryByTestId("memory-runs-tab")).not.toBeInTheDocument();
  });

  // 6. Raw tab contains legacy views
  it("renders the Raw tab with legacy plugin observations", async () => {
    renderPage();
    fireEvent.click(await screen.findByTestId("memory-tab-raw"));
    expect(await screen.findByTestId("memory-raw-tab")).toBeInTheDocument();
    expect(screen.getByTestId("raw-plugin-filter")).toBeInTheDocument();
  });

  // 7. Legacy table is not in Overview
  it("does not show the legacy 'Analyze memory' instruction footer in Overview", async () => {
    renderPage();
    await screen.findByTestId("memory-overview");
    const text = document.body.textContent ?? "";
    expect(text).not.toMatch(/Analyze memory section at the bottom/i);
  });

  // 8. Legacy tree is not in Overview
  it("does not show the legacy process tree in Overview", async () => {
    renderPage();
    await screen.findByTestId("memory-overview");
    expect(screen.queryByText("No memory process tree is available.")).not.toBeInTheDocument();
  });

  // 9. Tab navigation preserves run
  it("preserves the run selection when switching tabs", async () => {
    renderPage();
    fireEvent.click(await screen.findByTestId("memory-tab-runs"));
    expect(await screen.findByTestId("memory-runs-tab")).toBeInTheDocument();
    fireEvent.click(screen.getByTestId("memory-tab-processes"));
    expect(await screen.findByTestId("memory-processes-tab")).toBeInTheDocument();
  });

  // 10. Tab navigation preserves filters (processName stays in URL or shared state)
  it("preserves shared state across tabs", async () => {
    renderPage();
    fireEvent.click(await screen.findByTestId("memory-tab-processes"));
    expect(await screen.findByTestId("memory-processes-tab")).toBeInTheDocument();
    fireEvent.click(screen.getByTestId("memory-tab-raw"));
    expect(await screen.findByTestId("memory-raw-tab")).toBeInTheDocument();
  });

  // 11. Processes tab navigation works in evidence-scoped view
  it("navigates to the Processes tab via the family link", async () => {
    renderPage();
    await screen.findByTestId("memory-family-link-processes");
    fireEvent.click(screen.getByTestId("memory-family-link-processes"));
    expect(await screen.findByTestId("memory-processes-tab")).toBeInTheDocument();
  });

  // 12. Graph detail panel appears on the right in desktop
  it("renders a single shared metrics strip in the Graph tab", async () => {
    renderPage();
    fireEvent.click(await screen.findByTestId("memory-tab-graph"));
    expect(await screen.findByTestId("metrics-strip")).toBeInTheDocument();
  });

  // 13. Renamed graph metrics
  it("renames graph metrics in the Graph tab header", async () => {
    renderPage();
    fireEvent.click(await screen.findByTestId("memory-tab-graph"));
    expect(await screen.findByTestId("metrics-strip-visible")).toBeInTheDocument();
    expect(screen.getByTestId("metrics-strip-orphans")).toBeInTheDocument();
  });

  // 14. Case roots vs current-view roots differentiated
  it("differentiates case roots and current-view roots in the Graph tab", async () => {
    renderPage();
    fireEvent.click(await screen.findByTestId("memory-tab-graph"));
    await screen.findByTestId("metrics-strip-case-roots");
    expect(screen.getByTestId("metrics-strip-case-roots")).toBeInTheDocument();
    expect(screen.getByTestId("metrics-strip-view-roots")).toBeInTheDocument();
  });

  // 15. Backend status row is rendered (no collapsed detail row any more)
  it("renders the memory engine status row in the Overview", async () => {
    renderPage();
    await screen.findByTestId("memory-overview-status");
    expect(screen.getByTestId("overview-backend-volatility")).toBeInTheDocument();
    expect(screen.getByTestId("overview-backend-worker")).toBeInTheDocument();
    expect(screen.getByTestId("overview-backend-symbols")).toBeInTheDocument();
  });

  // 16. Legacy Analyze memory selector is NOT rendered in evidence-scoped view
  it("does not render the legacy Analyze memory selector in the evidence-scoped workspace", async () => {
    renderPage();
    await screen.findByTestId("memory-evidence-header");
    expect(screen.queryByTestId("memory-analyze-action")).not.toBeInTheDocument();
    expect(screen.queryByTestId("analyze-profile-select")).not.toBeInTheDocument();
    expect(screen.queryByTestId("analyze-run-button")).not.toBeInTheDocument();
  });

  // 17. Run analysis is exposed via the catalogue modal in the evidence header
  it("exposes the catalogue button in the evidence header with a coherent label", async () => {
    renderPage();
    const catalogueButton = await screen.findByTestId("memory-open-catalogue");
    expect(catalogueButton).toBeInTheDocument();
    // The test fixture has all profiles completed, so the label
    // is "Re-run analysis" (per the v1 stabilization spec).
    expect(catalogueButton.textContent).toMatch(/Re-run analysis|Run analysis|Analyze memory|Complete analysis/);
  });

  // 18. No sensitive paths rendered
  it("does not render private server paths anywhere", async () => {
    renderPage();
    await screen.findByTestId("memory-overview");
    expect(screen.queryByText(/\/opt\/private/)).not.toBeInTheDocument();
    expect(screen.queryByText(/C:\\private/)).not.toBeInTheDocument();
  });

  // 19. Keyboard tab navigation
  it("marks tab buttons with role=tab and aria-selected", async () => {
    renderPage();
    const overview = await screen.findByTestId("memory-tab-overview");
    expect(overview.getAttribute("role")).toBe("tab");
    expect(overview.getAttribute("aria-selected")).toBe("true");
    const processes = screen.getByTestId("memory-tab-processes");
    expect(processes.getAttribute("aria-selected")).toBe("false");
  });

  // 20. Existing MemoryCanonicalView behavior preserved
  it("keeps the canonical MemoryCanonicalView mounted inside the Processes tab", async () => {
    renderPage();
    fireEvent.click(await screen.findByTestId("memory-tab-processes"));
    await waitFor(() => {
      expect(getCanonicalProcessEntitiesMock).toHaveBeenCalled();
    });
  });

  // 21. Full-coverage navigation matrix -- every Memory tab, exercised the
  // same way an analyst does (click the tab button), against the real
  // MemoryEvidencePage/MemoryWorkspace tree. This is what would have caught
  // the missing Runs route (and would catch a future one) if it had covered
  // every tab instead of a handful.
  const ALL_TABS: Array<{ key: string; segment: string; tabTestId: string; panelTestId: string }> = [
    { key: "overview", segment: "overview", tabTestId: "memory-tab-overview", panelTestId: "memory-tabpanel-overview" },
    { key: "processes", segment: "processes", tabTestId: "memory-tab-processes", panelTestId: "memory-tabpanel-processes" },
    { key: "graph", segment: "process-graph", tabTestId: "memory-tab-graph", panelTestId: "memory-tabpanel-graph" },
    { key: "network", segment: "network", tabTestId: "memory-tab-network", panelTestId: "memory-tabpanel-network" },
    { key: "modules", segment: "modules", tabTestId: "memory-tab-modules", panelTestId: "memory-tabpanel-modules" },
    { key: "handles", segment: "handles", tabTestId: "memory-tab-handles", panelTestId: "memory-tabpanel-handles" },
    { key: "suspicious", segment: "suspicious", tabTestId: "memory-tab-suspicious", panelTestId: "memory-tabpanel-suspicious" },
    { key: "vads", segment: "vads", tabTestId: "memory-tab-vads", panelTestId: "memory-tabpanel-vads" },
    { key: "system", segment: "system", tabTestId: "memory-tab-system", panelTestId: "memory-tabpanel-system" },
    { key: "runs", segment: "runs", tabTestId: "memory-tab-runs", panelTestId: "memory-tabpanel-runs" },
    { key: "raw", segment: "raw", tabTestId: "memory-tab-raw", panelTestId: "memory-tabpanel-raw" },
  ];

  it.each(ALL_TABS)("clicking $key navigates to the evidence-scoped URL, activates the tab, and renders its subview", async ({ segment, tabTestId, panelTestId }) => {
    renderPage();
    await screen.findByTestId("memory-overview");
    fireEvent.click(screen.getByTestId(tabTestId));

    await waitFor(() => {
      expect(screen.getByTestId("current-location")).toHaveTextContent(`/cases/case-1/m/ev-memory/${segment}`);
    });
    expect(screen.getByTestId(tabTestId)).toHaveAttribute("aria-selected", "true");
    expect(await screen.findByTestId(panelTestId)).toBeInTheDocument();
    // Never falls back to the case-wide/global memory landing.
    expect(screen.queryByTestId("memory-landing")).not.toBeInTheDocument();
  });

  it.each(ALL_TABS)("a direct URL load of $key (reload-equivalent) keeps that tab active and renders its subview", async ({ segment, tabTestId, panelTestId }) => {
    // The canonical /m/ URL, not the legacy /memory/ form -- a real reload
    // re-requests whatever URL is already in the address bar (which is
    // always canonical once the analyst has navigated there), it never
    // reintroduces the legacy prefix.
    renderPage(`/cases/case-1/m/ev-memory/${segment}`);
    expect(await screen.findByTestId(panelTestId)).toBeInTheDocument();
    expect(screen.getByTestId(tabTestId)).toHaveAttribute("aria-selected", "true");
    expect(screen.getByTestId("current-location")).toHaveTextContent(`/cases/case-1/m/ev-memory/${segment}`);
  });

  // 21b. Regression: reproduces the exact reported runtime bug --
  // /cases/:caseId/m/:evidenceId/processes?tab=overview rendered Overview,
  // not Processes, because App.tsx's per-tab routes never captured
  // :memoryTab at all, so the tab computation always fell through to the
  // stale ?tab= query param. The path segment must be authoritative for
  // every tab, with an inherited/stale ?tab= present.
  it("the exact reported URL /processes?tab=overview renders Processes, not Overview (path wins over stale ?tab=)", async () => {
    renderPage("/cases/case-1/m/ev-memory/processes?tab=overview");
    expect(await screen.findByTestId("memory-tabpanel-processes")).toBeInTheDocument();
    expect(screen.getByTestId("memory-tab-processes")).toHaveAttribute("aria-selected", "true");
    expect(screen.getByTestId("memory-tab-overview")).toHaveAttribute("aria-selected", "false");
    expect(screen.queryByTestId("memory-tabpanel-overview")).not.toBeInTheDocument();
  });

  it.each(ALL_TABS)("$key wins over an inherited/stale ?tab=overview query param on the same URL", async ({ segment, tabTestId, panelTestId }) => {
    renderPage(`/cases/case-1/m/ev-memory/${segment}?tab=overview`);
    expect(await screen.findByTestId(panelTestId)).toBeInTheDocument();
    expect(screen.getByTestId(tabTestId)).toHaveAttribute("aria-selected", "true");
    if (segment !== "overview") {
      expect(screen.getByTestId("memory-tab-overview")).toHaveAttribute("aria-selected", "false");
    }
  });

  it("switching from a stale ?tab=overview URL to Graph, Network, or Runs via click still works", async () => {
    renderPage("/cases/case-1/m/ev-memory/processes?tab=overview");
    await screen.findByTestId("memory-tabpanel-processes");

    fireEvent.click(screen.getByTestId("memory-tab-graph"));
    expect(await screen.findByTestId("memory-tabpanel-graph")).toBeInTheDocument();

    fireEvent.click(screen.getByTestId("memory-tab-network"));
    expect(await screen.findByTestId("memory-tabpanel-network")).toBeInTheDocument();

    fireEvent.click(screen.getByTestId("memory-tab-runs"));
    expect(await screen.findByTestId("memory-tabpanel-runs")).toBeInTheDocument();
  });

  it("an unrelated query param alongside a stale ?tab= is preserved while the path still wins", async () => {
    renderPage("/cases/case-1/m/ev-memory/processes?tab=overview&process_entity_id=ent-42");
    expect(await screen.findByTestId("memory-tabpanel-processes")).toBeInTheDocument();
    expect(screen.getByTestId("memory-tab-processes")).toHaveAttribute("aria-selected", "true");
    expect(screen.getByTestId("current-location")).toHaveTextContent("process_entity_id=ent-42");
  });

  // 22. Two memory evidences in the same case must never mix data --
  // switching between them by URL must only ever query the evidenceId in
  // the path, not a "last selected" or case-wide default.
  it("scopes each tab to the evidence in the path when a case has two RAM evidences with different data", async () => {
    getMemoryEvidenceLandingMock.mockResolvedValue({
      case_id: "case-1",
      items: [
        {
          evidence_id: "ev-memory", case_id: "case-1", filename: "memory-a.mem", detected_host: "WS01", size_bytes: 2048,
          created_at: "2026-06-16T00:00:00Z", processed_at: "2026-06-16T00:01:00Z", ingest_status: "completed", metadata: {},
          families: [{ family: "processes", title: "Processes", state: "completed", active_run: { id: "run-a" }, latest_attempt: { id: "run-a" }, selection_reason: "latest_successful", using_fallback: false, historical_override: false, availability_reason: null }],
          run_count: 1, latest_run_id: "run-a", latest_run_status: "completed",
        },
        {
          evidence_id: "ev-memory-2", case_id: "case-1", filename: "memory-b.mem", detected_host: "WS02", size_bytes: 4096,
          created_at: "2026-06-17T00:00:00Z", processed_at: "2026-06-17T00:01:00Z", ingest_status: "completed", metadata: {},
          families: [{ family: "processes", title: "Processes", state: "not_analyzed", active_run: null, latest_attempt: null, selection_reason: "not_analyzed", using_fallback: false, historical_override: false, availability_reason: null }],
          run_count: 0, latest_run_id: null, latest_run_status: null,
        },
      ],
    });
    listMemoryRunsMock.mockImplementation((_caseId: string, evidenceId?: string) =>
      Promise.resolve(evidenceId === "ev-memory"
        ? [{ id: "run-a", case_id: "case-1", evidence_id: "ev-memory", backend: "volatility3", profile: "processes_basic", status: "completed", requested_plugin_count: 4, plugin_count: 4, plugins_completed: 4, plugins_failed: 0, plugins_skipped: 0, started_at: "2026-06-16T00:00:00Z", completed_at: "2026-06-16T00:00:30Z", duration_ms: 30000, output_dir: null, metadata_json: {}, error_log: {}, backend_version: "2.28.0", worker_task_id: null, cancellation_requested: false, created_at: "2026-06-16T00:00:00Z" }]
        : []),
    );

    const first = renderPage("/cases/case-1/memory/ev-memory/runs");
    await screen.findByTestId("run-row-run-a");
    expect(listMemoryRunsMock).toHaveBeenCalledWith("case-1", "ev-memory");
    expect(listMemoryRunsMock).not.toHaveBeenCalledWith("case-1", "ev-memory-2");
    // Unmount before switching evidence -- render() doesn't auto-unmount a
    // previous tree within the same test, and leaving evidence A's DOM
    // mounted would make the isolation assertions below meaningless (they'd
    // find A's row because it's still there, not because B leaked into it).
    first.unmount();

    listMemoryRunsMock.mockClear();
    renderPage("/cases/case-1/memory/ev-memory-2/runs");
    await screen.findByTestId("memory-runs-tab");
    expect(screen.queryByTestId("run-row-run-a")).not.toBeInTheDocument();
    expect(listMemoryRunsMock).toHaveBeenCalledWith("case-1", "ev-memory-2");
    expect(listMemoryRunsMock).not.toHaveBeenCalledWith("case-1", "ev-memory");
  });

  // 23. The exact reported inconsistency: "Analysis status" (the family
  // table) reports processes as analyzed_with_results, but the Processes
  // summary card below it independently re-derived "is this family
  // analyzed" with a narrower condition that didn't recognize that state,
  // so it showed "Processes have not been analyzed" underneath a table row
  // that said otherwise. Both now go through the same isFamilyAnalyzed()
  // predicate the investigation checklist already used correctly.
  it("does not show 'Processes have not been analyzed' when the family state is analyzed_with_results", async () => {
    getMemoryEvidenceLandingMock.mockResolvedValue({
      case_id: "case-1",
      items: [
        {
          evidence_id: "ev-memory", case_id: "case-1", filename: "memory.mem", detected_host: "WS01", size_bytes: 2048,
          created_at: "2026-06-16T00:00:00Z", processed_at: "2026-06-16T00:01:00Z", ingest_status: "completed", metadata: {},
          families: [
            { family: "processes", title: "Processes", state: "analyzed_with_results", count: 42, active_run: { id: "run-basic", profile: "processes_basic", completed_at: "2026-06-16T00:01:00Z" }, latest_attempt: { id: "run-basic" }, selection_reason: "latest_successful", using_fallback: false, historical_override: false, availability_reason: null },
          ],
          run_count: 1, latest_run_id: "run-basic", latest_run_status: "completed",
        },
      ],
    });
    renderPage();
    await screen.findByTestId("memory-overview");
    expect(await screen.findByTestId("memory-family-state-processes")).toHaveTextContent("Completed");
    expect(screen.queryByTestId("overview-processes-empty")).not.toBeInTheDocument();
    expect(screen.getByTestId("overview-processes-processes")).toHaveTextContent("42");
  });

  it("shows a real 'not analyzed' state (not a false empty result) when the family genuinely has no run", async () => {
    getMemoryEvidenceLandingMock.mockResolvedValue({
      case_id: "case-1",
      items: [
        {
          evidence_id: "ev-memory", case_id: "case-1", filename: "memory.mem", detected_host: "WS01", size_bytes: 2048,
          created_at: "2026-06-16T00:00:00Z", processed_at: "2026-06-16T00:01:00Z", ingest_status: "completed", metadata: {},
          families: [
            { family: "processes", title: "Processes", state: "not_analyzed", active_run: null, latest_attempt: null, selection_reason: "not_analyzed", using_fallback: false, historical_override: false, availability_reason: null },
          ],
          run_count: 0, latest_run_id: null, latest_run_status: null,
        },
      ],
    });
    renderPage();
    await screen.findByTestId("memory-overview");
    expect(await screen.findByTestId("overview-processes-empty")).toHaveTextContent("Processes have not been analyzed for this evidence.");
  });

  it("shows a genuine zero-results state (analyzed_empty) distinctly from not_analyzed", async () => {
    getMemoryEvidenceLandingMock.mockResolvedValue({
      case_id: "case-1",
      items: [
        {
          evidence_id: "ev-memory", case_id: "case-1", filename: "memory.mem", detected_host: "WS01", size_bytes: 2048,
          created_at: "2026-06-16T00:00:00Z", processed_at: "2026-06-16T00:01:00Z", ingest_status: "completed", metadata: {},
          families: [
            { family: "processes", title: "Processes", state: "analyzed_empty", count: 0, active_run: { id: "run-basic", profile: "processes_basic", completed_at: "2026-06-16T00:01:00Z" }, latest_attempt: { id: "run-basic" }, selection_reason: "latest_successful", using_fallback: false, historical_override: false, availability_reason: null },
          ],
          run_count: 1, latest_run_id: "run-basic", latest_run_status: "completed",
        },
      ],
    });
    renderPage();
    await screen.findByTestId("memory-overview");
    // Genuinely analyzed with zero results -- not the "not analyzed yet" copy.
    expect(screen.queryByTestId("overview-processes-empty")).not.toBeInTheDocument();
    expect(screen.getByTestId("overview-processes-processes")).toHaveTextContent("0");
    expect(await screen.findByTestId("memory-family-zero-processes")).toBeInTheDocument();
  });
});
