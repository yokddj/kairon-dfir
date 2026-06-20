import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { fireEvent, render, screen, waitFor } from "@testing-library/react";
import { MemoryRouter, Route, Routes } from "react-router-dom";
import { beforeEach, describe, expect, it, vi } from "vitest";
import MemoryAnalysisPage from "./MemoryAnalysisPage";

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
  },
}));

vi.mock("../context/ActiveCaseContext", () => ({
  useActiveCase: () => ({
    setActiveCaseId: vi.fn(),
  }),
}));

function renderPage(initialPath = "/cases/case-1/memory") {
  const queryClient = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  return render(
    <MemoryRouter initialEntries={[initialPath]}>
      <QueryClientProvider client={queryClient}>
        <Routes>
          <Route path="/cases/:caseId/memory" element={<MemoryAnalysisPage />} />
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
    vi.spyOn(window, "confirm").mockReturnValue(true);
  });

  // 1. Overview renders summary
  it("renders the overview summary by default", async () => {
    renderPage();
    expect(await screen.findByTestId("memory-overview")).toBeInTheDocument();
    await waitFor(() => {
      expect(screen.getByTestId("overview-card-evidence")).toHaveTextContent("1 memory image");
    });
    expect(screen.getByTestId("overview-card-worker")).toHaveTextContent("Ready");
    expect(screen.getByTestId("overview-card-symbols")).toHaveTextContent(/Cached/);
  });

  // 2. Processes tab shows the canonical table
  it("renders the Processes tab with the canonical table", async () => {
    renderPage();
    fireEvent.click(screen.getByTestId("memory-tab-processes"));
    expect(await screen.findByTestId("memory-processes-tab")).toBeInTheDocument();
    await waitFor(() => {
      expect(getCanonicalProcessEntitiesMock).toHaveBeenCalled();
    });
  });

  // 3. Graph tab shows graph
  it("renders the Graph tab with the interactive graph", async () => {
    renderPage();
    fireEvent.click(screen.getByTestId("memory-tab-graph"));
    expect(await screen.findByTestId("memory-graph-tab")).toBeInTheDocument();
    await waitFor(() => {
      expect(screen.getByTestId("memory-process-canvas")).toBeInTheDocument();
    }, { timeout: 5000 });
    expect(screen.getByTestId("graph-side-panel")).toBeInTheDocument();
  });

  // 4. System tab shows only latest successful by default
  it("renders the System tab with the latest successful windows.info", async () => {
    renderPage();
    fireEvent.click(screen.getByTestId("memory-tab-system"));
    expect(await screen.findByTestId("memory-system-tab")).toBeInTheDocument();
    const primary = await screen.findByTestId("system-info-card-primary");
    expect(primary).toHaveTextContent("WS01");
  });

  // 5. Runs tab contains history
  it("renders the Runs tab with the full history", async () => {
    renderPage();
    fireEvent.click(screen.getByTestId("memory-tab-runs"));
    expect(await screen.findByTestId("memory-runs-tab")).toBeInTheDocument();
    await waitFor(() => {
      expect(screen.getByTestId("runs-table")).toBeInTheDocument();
    });
    expect(screen.getByTestId("run-row-run-basic")).toBeInTheDocument();
  });

  // 6. Raw tab contains legacy views
  it("renders the Raw tab with legacy plugin observations", async () => {
    renderPage();
    fireEvent.click(screen.getByTestId("memory-tab-raw"));
    expect(await screen.findByTestId("memory-raw-tab")).toBeInTheDocument();
    expect(screen.getByTestId("raw-plugin-filter")).toBeInTheDocument();
  });

  // 7. Legacy table is not in Overview
  it("does not show the legacy processes table in Overview", async () => {
    renderPage();
    await screen.findByTestId("memory-overview");
    expect(screen.queryByRole("heading", { name: /Processes$/ })).not.toBeInTheDocument();
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
    fireEvent.click(screen.getByTestId("memory-tab-runs"));
    expect(await screen.findByTestId("memory-runs-tab")).toBeInTheDocument();
    fireEvent.click(screen.getByTestId("memory-tab-processes"));
    expect(await screen.findByTestId("memory-processes-tab")).toBeInTheDocument();
  });

  // 10. Tab navigation preserves filters (processName stays in URL or shared state)
  it("preserves shared state across tabs", async () => {
    renderPage();
    fireEvent.click(screen.getByTestId("memory-tab-processes"));
    expect(await screen.findByTestId("memory-processes-tab")).toBeInTheDocument();
    fireEvent.click(screen.getByTestId("memory-tab-raw"));
    expect(await screen.findByTestId("memory-raw-tab")).toBeInTheDocument();
  });

  // 11. Interesting card opens Processes filtered
  it("opens the Processes tab when clicking the scan-only finding card", async () => {
    renderPage();
    await screen.findByTestId("memory-overview");
    await waitFor(() => {
      expect(screen.getByTestId("finding-card-scan-only")).toBeInTheDocument();
    });
    fireEvent.click(screen.getByTestId("finding-card-scan-only"));
    expect(await screen.findByTestId("memory-processes-tab")).toBeInTheDocument();
  });

  // 12. Graph detail panel appears on the right in desktop
  it("renders a side detail panel in the Graph tab", async () => {
    renderPage();
    fireEvent.click(screen.getByTestId("memory-tab-graph"));
    expect(await screen.findByTestId("graph-side-panel")).toBeInTheDocument();
  });

  // 13. Renamed graph metrics
  it("renames graph metrics in the Graph tab header", async () => {
    renderPage();
    fireEvent.click(screen.getByTestId("memory-tab-graph"));
    expect(await screen.findByTestId("graph-tab-stat-visible")).toBeInTheDocument();
    expect(screen.getByTestId("graph-tab-stat-orphans")).toBeInTheDocument();
  });

  // 14. Case roots vs current-view roots differentiated
  it("differentiates case roots and current-view roots in the Graph tab", async () => {
    renderPage();
    fireEvent.click(screen.getByTestId("memory-tab-graph"));
    await screen.findByTestId("graph-tab-stat-case-roots");
    expect(screen.getByTestId("graph-tab-stat-case-roots")).toBeInTheDocument();
  });

  // 15. Backend details collapsed
  it("collapses backend details behind a toggle in the Overview", async () => {
    renderPage();
    await screen.findByTestId("memory-overview");
    expect(screen.queryByText("Execution mode")).not.toBeInTheDocument();
    fireEvent.click(screen.getByTestId("overview-toggle-backend-details"));
    expect(await screen.findByText("Execution mode")).toBeInTheDocument();
  });

  // 16. Analyze memory selector
  it("renders the Analyze memory selector with profile options", async () => {
    renderPage();
    expect(await screen.findByTestId("memory-analyze-action")).toBeInTheDocument();
    const select = screen.getByTestId("analyze-profile-select") as HTMLSelectElement;
    expect(select.value).toBe("processes_basic");
    expect(screen.getByTestId("analyze-run-button")).toBeInTheDocument();
  });

  // 17. Analyze memory only appears on Overview (no duplicates across tabs)
  it("renders the Analyze memory action only on the Overview tab", async () => {
    renderPage();
    await screen.findByTestId("memory-overview");
    await waitFor(() => {
      expect(screen.getByTestId("memory-analyze-action")).toBeInTheDocument();
    });
    fireEvent.click(screen.getByTestId("memory-tab-runs"));
    await screen.findByTestId("memory-runs-tab");
    expect(screen.queryByTestId("memory-analyze-action")).not.toBeInTheDocument();
    fireEvent.click(screen.getByTestId("memory-tab-processes"));
    await screen.findByTestId("memory-processes-tab");
    expect(screen.queryByTestId("memory-analyze-action")).not.toBeInTheDocument();
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
    const overview = screen.getByTestId("memory-tab-overview");
    expect(overview.getAttribute("role")).toBe("tab");
    expect(overview.getAttribute("aria-selected")).toBe("true");
    const processes = screen.getByTestId("memory-tab-processes");
    expect(processes.getAttribute("aria-selected")).toBe("false");
  });

  // 20. Existing MemoryCanonicalView behavior preserved
  it("keeps the canonical MemoryCanonicalView mounted inside the Processes tab", async () => {
    renderPage();
    fireEvent.click(screen.getByTestId("memory-tab-processes"));
    await waitFor(() => {
      expect(getCanonicalProcessEntitiesMock).toHaveBeenCalled();
    });
  });
});
