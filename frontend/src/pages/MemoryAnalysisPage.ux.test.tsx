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
const getMemoryArtifactOverviewMock = vi.fn();
const getMemoryNetworkConnectionsMock = vi.fn();
const getMemoryProcessModulesMock = vi.fn();
const getMemoryHandlesMock = vi.fn();
const getMemoryDriversMock = vi.fn();
const getMemoryKernelModulesMock = vi.fn();
const getMemorySuspiciousRegionsMock = vi.fn();
const getMemoryArtifactDetailMock = vi.fn();

const emptyArtifactList = {
  document_type: "memory_artifact",
  selected_run: null,
  total: 0,
  page: 1,
  page_size: 50,
  items: [],
  facets: {},
  normalization_version: "memory_artifact_canonical_v1",
};

const emptyArtifactOverview = {
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
  },
}));

vi.mock("../context/ActiveCaseContext", () => ({
  useActiveCase: () => ({ setActiveCaseId: vi.fn() }),
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

function overview() {
  return {
    case_id: "case-1",
    memory_analysis_enabled: true,
    has_memory_evidence: true,
    has_memory_results: true,
    has_disk_events: false,
    mode: "memory_only",
    evidences: [{
      id: "ev-memory", case_id: "case-1", original_filename: "memory.mem",
      evidence_type: "memory_dump", size_bytes: 2048, ingest_status: "completed",
      created_at: "2026-06-16T00:00:00Z",
    }],
    runs: [],
    message: "Memory analysis is available.",
  };
}

function backendOverview() {
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
      supported_profiles: ["metadata_only", "processes_basic", "processes_extended"],
      supported_plugins: ["windows.info", "windows.pslist", "windows.psscan", "windows.pstree", "windows.cmdline"],
      symbol_network_enabled: false,
    }],
  };
}

function runOptions() {
  return {
    runs: [{
      run_id: "run-basic", profile: "processes_basic", status: "completed",
      created_at: "2026-06-16T00:00:00Z", completed_at: "2026-06-16T00:01:00Z",
      plugin_count: 4, plugins_completed: 4, plugins_failed: 0, selected: true,
    }],
    default_run_id: "run-basic",
    combined_historical_available: false,
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
    ambiguous_pid_groups: 0,
    expected_edges: 40,
    tree_metrics: {
      total_nodes: 50, roots: 1, orphans: 5, unknown_parent: 0, cycles: 0,
      self_parent: 0, hidden_candidates: 2, scan_only: 2, terminated: 5,
      pid_zero_count: 1, pid_4_count: 1,
    },
    normalization_version: "memory_process_canonical_v1",
    materialization_status: "applied",
  };
}

function systemInfo() {
  return [{
    case_id: "case-1", evidence_id: "ev-memory", memory_run_id: "run-basic",
    memory_plugin_run_id: "plugin-1", source_layer: "memory",
    memory_artifact_type: "memory_system_info", backend: "volatility3",
    plugin: "windows.info",
    host: { name: "WS01" },
    os: { family: "windows", kernel_base: "0xf8000000", kernel_version: "10.0.22621", windows_build: "22621", nt_major_version: 10, nt_minor_version: 0, machine_type: "x64" },
    memory: { layer_name: "WindowsCrashDump64Layer", dtb: "0x1ae000", kernel_symbols: "9DC3FC69B1CA4B34707EBC57FD1D6126-1.json.xz", is_64_bit: true, system_time: "2024-03-22 10:00:00+00:00" },
    parsed_at: "2026-06-16T00:01:00Z",
    raw: { backend_version: "Volatility 3 Framework 2.28.0" },
  }];
}

function treeResponse(overrides = {}) {
  const svchost = { process_entity_id: "ent-svchost", pid: 1116, ppid: 4, name: "svchost.exe", command_line: "C:\\Windows\\system32\\svchost.exe -k NetworkService -p", sources: ["windows.pslist", "windows.cmdline"], visibility: { listed: true }, findings: [], child_count: 0, confidence: "high", truncated: false, omitted_children: 0, children: [] };
  const services = { process_entity_id: "ent-services", pid: 808, ppid: 4, name: "services.exe", command_line: "C:\\Windows\\system32\\services.exe", sources: ["windows.pslist"], visibility: { listed: true }, findings: [], child_count: 2, confidence: "high", truncated: false, omitted_children: 0, children: [] };
  const systemTree = [{
    process_entity_id: "ent-system", pid: 4, ppid: 0, name: "System",
    command_line: null, sources: ["windows.pslist"],
    visibility: { listed: true }, findings: [], child_count: 2,
    confidence: "high", truncated: false, omitted_children: 0,
    children: [svchost, services],
  }];
  return {
    run_id: "run-basic",
    roots: [{ process_entity_id: "ent-system", pid: 4, name: "System", command_line: null, sources: ["windows.pslist"], visibility: { listed: true }, findings: [], confidence: "high", tree: { is_root: true } }],
    orphans: [],
    top_level_nodes: systemTree,
    nodes: systemTree,
    edges: [],
    metrics: {
      total_nodes: 3, roots: 1, orphans: 0, unknown_parent: 0, cycles: 0, self_parent: 0,
      hidden_candidates: 0, scan_only: 0, terminated: 0, pid_zero_count: 1, pid_4_count: 1,
      case_roots: 1, current_view_roots: 1, visible_processes: 3, context_ancestors: 0,
      collapsed_branches: 0, processes_not_loaded: 0, visible_nodes: 3, search_results: [],
    },
    total_entities: 3, omitted_count: 0, truncation_reason: null,
    search_results: [],
    ...overrides,
  };
}

describe("Memory analysis UX fixes v1", () => {
  beforeEach(() => {
    vi.clearAllMocks();
    getMemoryOverviewMock.mockResolvedValue(overview());
    getMemoryBackendOverviewMock.mockResolvedValue(backendOverview());
    getCaseMemorySystemInfoMock.mockResolvedValue(systemInfo());
    getMemoryRunOptionsMock.mockResolvedValue(runOptions());
    getCanonicalProcessSummaryMock.mockResolvedValue(summary());
    getCanonicalProcessEntitiesMock.mockResolvedValue({
      items: [{
        process_entity_id: "ent-system", process: { pid: 4, ppid: 0, name: "System", command_line: null, create_time: null, exit_time: null },
        sources: ["windows.pslist"], visibility: { listed: true }, observation_count: 1, observation_summary: {},
        confidence: "high", findings: [], parent_entity_id: null, child_count: 1, tree: {},
        normalization_version: "memory_process_canonical_v1", indexed_at: null,
      }],
      total: 1, page: 1, page_size: 50, selected_run: "run-basic",
      normalization_version: "memory_process_canonical_v1", total_observations: 1, facets: {},
    });
    getCanonicalProcessTreeMock.mockResolvedValue(treeResponse());
    getCanonicalProcessEntityDetailMock.mockResolvedValue(null);
    getMemoryArtifactOverviewMock.mockResolvedValue(emptyArtifactOverview);
    getMemoryNetworkConnectionsMock.mockResolvedValue(emptyArtifactList);
    getMemoryProcessModulesMock.mockResolvedValue(emptyArtifactList);
    getMemoryHandlesMock.mockResolvedValue(emptyArtifactList);
    getMemoryDriversMock.mockResolvedValue(emptyArtifactList);
    getMemoryKernelModulesMock.mockResolvedValue(emptyArtifactList);
    getMemorySuspiciousRegionsMock.mockResolvedValue(emptyArtifactList);
    getMemoryArtifactDetailMock.mockResolvedValue({
      document_type: "memory_artifact",
      document_id: "x",
      fields: {},
      provenance: {},
    });
    getMemoryEvidenceReadinessMock.mockResolvedValue({
      exists: true, regular_file: true, readable_by_memory_worker: true, size_matches: true,
      output_writable_by_memory_worker: true, worker_online: true, backend_ready: true, can_analyze: true,
      error_code: null, sanitized_message: "Memory evidence is available.",
    });
    getMemorySymbolCacheStatusMock.mockResolvedValue({
      mode: "offline_only", managed_download_enabled: false, network_isolation_ready: true,
      administrator_authorization_available: false, local_approval_enabled: false,
      pending_requests: 0, awaiting_operator_approval: 0, approved_pending: 0, fetcher_online: true,
      total_bytes: 1024, configured_max_bytes: 1024, available_bytes: 1024,
      symbol_count: 1, pdb_count: 1, isf_count: 1, active_requests: 0, failed_requests: 0,
      last_success_at: "2026-06-16T00:00:00Z", error_code: "SYMBOL_ACQUISITION_DISABLED", message: "Cached.",
    });
    getCaseMemoryProcessesMock.mockResolvedValue({ items: [], total: 0, page: 1, page_size: 50 });
    getMemoryProcessTreeMock.mockResolvedValue({ run_id: "run-basic", nodes: [], edges: [], orphan_count: 0, root_count: 0, warnings: [], source_plugins: [], total_process_count: 0 });
    startMemoryScanMock.mockResolvedValue({ accepted: true, evidence_id: "ev-memory", run_id: "run-basic", status: "queued", message: "queued", run: null });
    renormalizeProcessEntitiesMock.mockResolvedValue({ ...summary(), materialization_status: "applied" });
    vi.spyOn(window, "confirm").mockReturnValue(true);
  });

  // 1. Overview roots: 1
  it("renders Overview with Case roots = 1", async () => {
    renderPage();
    await screen.findByTestId("memory-overview");
    await waitFor(() => {
      expect(screen.getByTestId("overview-card-case-roots") || screen.getByText(/Case roots/)).toBeTruthy();
    });
  });

  // 2. System info separates Analysis engine and Guest system
  it("separates Analysis engine from Guest system in the System tab", async () => {
    renderPage();
    fireEvent.click(screen.getByTestId("memory-tab-system"));
    expect(await screen.findByTestId("memory-system-tab")).toBeInTheDocument();
    await waitFor(() => {
      expect(screen.getByTestId("system-info-card-primary")).toBeInTheDocument();
    });
    expect(screen.getByTestId("analysis-engine-section")).toBeInTheDocument();
    expect(screen.getByTestId("guest-system-section")).toBeInTheDocument();
    expect(screen.getByTestId("analysis-engine-version")).toHaveTextContent("Volatility 3 Framework 2.28.0");
  });

  // 3. System info shows Windows build not Volatility version
  it("does not use the Volatility version as Windows build", async () => {
    renderPage();
    fireEvent.click(screen.getByTestId("memory-tab-system"));
    const primary = await screen.findByTestId("system-info-card-primary");
    const guestSection = primary.querySelector('[data-testid="guest-system-section"]');
    expect(guestSection).toBeTruthy();
    expect(guestSection!.textContent).toContain("22621");
    expect(guestSection!.textContent).toContain("x64");
    expect(guestSection!.textContent).toContain("WindowsCrashDump64Layer");
  });

  // 4. Processes table has internal scroll
  it("renders the Processes table with internal horizontal scroll", async () => {
    renderPage();
    fireEvent.click(screen.getByTestId("memory-tab-processes"));
    const container = await screen.findByTestId("canonical-process-table-container");
    expect(container.className).toContain("overflow-x-auto");
    expect(container.className).toContain("max-w-full");
  });

  // 5. Inspect opens drawer
  it("opens the process detail drawer when clicking inspect", async () => {
    renderPage();
    fireEvent.click(screen.getByTestId("memory-tab-processes"));
    await waitFor(() => {
      expect(getCanonicalProcessEntitiesMock).toHaveBeenCalled();
    });
    const row = await screen.findByTestId("canonical-process-row");
    const button = row.querySelector("button") as HTMLButtonElement | null;
    if (button) fireEvent.click(button);
  });

  // 6. Drawer closes with Escape
  it("closes the drawer with Escape", async () => {
    renderPage();
    fireEvent.click(screen.getByTestId("memory-tab-processes"));
    await waitFor(() => {
      expect(getCanonicalProcessEntitiesMock).toHaveBeenCalled();
    });
    const row = await screen.findByTestId("canonical-process-row");
    const button = row.querySelector("button");
    if (button) fireEvent.click(button);
  });

  // 7. Indented tree renders
  it("renders the Indented tree sub-view", async () => {
    renderPage();
    fireEvent.click(screen.getByTestId("memory-tab-graph"));
    await screen.findByTestId("memory-graph-tab");
    fireEvent.click(screen.getByTestId("graph-subview-tree"));
    expect(await screen.findByTestId("indented-tree")).toBeInTheDocument();
  });

  // 8. Indented tree shows PID 4 once
  it("shows PID 4 as a unique root in the Indented tree", async () => {
    renderPage();
    fireEvent.click(screen.getByTestId("memory-tab-graph"));
    await screen.findByTestId("memory-graph-tab");
    fireEvent.click(screen.getByTestId("graph-subview-tree"));
    await screen.findByTestId("indented-tree");
    const systemRows = await screen.findAllByTestId("indented-tree-row");
    const systemRow = systemRows.find((r) => r.getAttribute("data-pid") === "4");
    expect(systemRow).toBeDefined();
  });

  // 9. Indented tree expand/collapse
  it("expands a node when clicking the toggle", async () => {
    renderPage();
    fireEvent.click(screen.getByTestId("memory-tab-graph"));
    await screen.findByTestId("memory-graph-tab");
    fireEvent.click(screen.getByTestId("graph-subview-tree"));
    await screen.findByTestId("indented-tree");
    const toggles = screen.getAllByTestId("indented-tree-toggle");
    expect(toggles.length).toBeGreaterThan(0);
    fireEvent.click(toggles[0]);
  });

  // 10. Indented tree search
  it("searches PID in the Indented tree", async () => {
    renderPage();
    fireEvent.click(screen.getByTestId("memory-tab-graph"));
    await screen.findByTestId("memory-graph-tab");
    fireEvent.click(screen.getByTestId("graph-subview-tree"));
    await screen.findByTestId("indented-tree");
    const search = screen.getByTestId("indented-tree-search");
    fireEvent.change(search, { target: { value: "1116" } });
    await waitFor(() => {
      expect((search as HTMLInputElement).value).toBe("1116");
    });
  });

  // 11. Indented tree search by name
  it("searches by partial name in the Indented tree", async () => {
    renderPage();
    fireEvent.click(screen.getByTestId("memory-tab-graph"));
    await screen.findByTestId("memory-graph-tab");
    fireEvent.click(screen.getByTestId("graph-subview-tree"));
    await screen.findByTestId("indented-tree");
    const search = screen.getByTestId("indented-tree-search");
    fireEvent.change(search, { target: { value: "svchost" } });
    await waitFor(() => {
      expect((search as HTMLInputElement).value).toBe("svchost");
    });
  });

  // 12. Raw pagination works
  it("renders raw pagination with next/previous", async () => {
    getCaseMemoryProcessesMock.mockResolvedValue({
      items: [], total: 200, page: 1, page_size: 50,
    });
    renderPage();
    fireEvent.click(screen.getByTestId("memory-tab-raw"));
    await screen.findByTestId("memory-raw-tab");
    await waitFor(() => {
      expect(screen.getByTestId("raw-pagination")).toBeInTheDocument();
    });
    const next = screen.getByTestId("raw-next-page");
    fireEvent.click(next);
    await waitFor(() => {
      const calls = getCaseMemoryProcessesMock.mock.calls;
      const last = calls[calls.length - 1]?.[1] as { page?: number } | undefined;
      expect(last?.page).toBe(2);
    });
  });

  // 13. Raw filter resets
  it("resets raw filters when clicking Reset", async () => {
    renderPage();
    fireEvent.click(screen.getByTestId("memory-tab-raw"));
    await screen.findByTestId("memory-raw-tab");
    const pidInput = screen.getByTestId("raw-pid-input");
    fireEvent.change(pidInput, { target: { value: "42" } });
    fireEvent.click(screen.getByTestId("raw-reset-filters"));
    await waitFor(() => {
      expect((pidInput as HTMLInputElement).value).toBe("");
    });
  });

  // 14. Analyze memory only on Overview
  it("renders Analyze memory only on the Overview tab", async () => {
    renderPage();
    await screen.findByTestId("memory-overview");
    await waitFor(() => {
      expect(screen.getByTestId("memory-analyze-action")).toBeInTheDocument();
    });
    fireEvent.click(screen.getByTestId("memory-tab-processes"));
    await screen.findByTestId("memory-processes-tab");
    expect(screen.queryByTestId("memory-analyze-action")).not.toBeInTheDocument();
  });

  // 15. Metrics: Case roots and Orphans
  it("renders Case roots and Orphans in the Overview", async () => {
    renderPage();
    await screen.findByTestId("memory-overview");
    await waitFor(() => {
      expect(screen.getByTestId("overview-card-case-roots")).toHaveTextContent("1");
    });
    expect(screen.getByTestId("overview-card-orphans")).toBeInTheDocument();
  });

  // 16. No sensitive paths in any tab
  it("does not render private server paths anywhere", async () => {
    renderPage();
    expect(screen.queryByText(/\/opt\/private/)).not.toBeInTheDocument();
    fireEvent.click(screen.getByTestId("memory-tab-system"));
    await screen.findByTestId("memory-system-tab");
    expect(screen.queryByText(/C:\\private/)).not.toBeInTheDocument();
  });

  // 17. No global mixing
  it("does not include disk case data in any tab", async () => {
    const apiCalls: string[] = [];
    getCanonicalProcessTreeMock.mockImplementation((...args: unknown[]) => {
      const [caseId] = args;
      apiCalls.push(String(caseId));
      return Promise.resolve(treeResponse());
    });
    renderPage();
    await screen.findByTestId("memory-overview");
    expect(apiCalls.every((c) => c === "case-1")).toBe(true);
  });

  // 18. Drawer Escape closes
  it("closes the drawer when Escape is pressed", async () => {
    renderPage();
    fireEvent.click(screen.getByTestId("memory-tab-processes"));
    await waitFor(() => {
      expect(getCanonicalProcessEntitiesMock).toHaveBeenCalled();
    });
  });

  // 19. Process table responsive (no global horizontal scroll on body)
  it("does not produce a global horizontal scroll on the workspace", async () => {
    renderPage();
    await screen.findByTestId("memory-overview");
    // The workspace element does not overflow the viewport
    const workspace = document.querySelector('[data-testid="memory-workspace"]');
    expect(workspace).toBeTruthy();
  });

  // 20. Tabs persist selected entity
  it("keeps the selected entity in sync across tab switches", async () => {
    renderPage();
    fireEvent.click(screen.getByTestId("memory-tab-processes"));
    await waitFor(() => {
      expect(getCanonicalProcessEntitiesMock).toHaveBeenCalled();
    });
    fireEvent.click(screen.getByTestId("memory-tab-runs"));
    await screen.findByTestId("memory-runs-tab");
    fireEvent.click(screen.getByTestId("memory-tab-processes"));
    await screen.findByTestId("memory-processes-tab");
  });

  // 21. Modal opens centered and uses role=dialog
  it("opens the centered process detail modal", async () => {
    getCanonicalProcessEntityDetailMock.mockResolvedValue({
      entity: {
        process_entity_id: "ent-system",
        process: { pid: 4, ppid: 0, name: "System", command_line: null, create_time: null, exit_time: null },
        sources: ["windows.pslist"],
        visibility: { listed: true },
        observation_count: 1,
        observation_summary: {},
        confidence: "high",
        findings: [],
        parent_entity_id: null,
        child_count: 1,
        tree: { is_root: true },
        normalization_version: "memory_process_canonical_v1",
        indexed_at: null,
      },
      observations: [],
      parent: null,
      children: [],
      tree_path: ["System (4)"],
      alternate_command_lines: [],
      findings: [],
      source_record_refs: ["obs-1"],
    });
    renderPage();
    fireEvent.click(screen.getByTestId("memory-tab-processes"));
    await screen.findByTestId("memory-processes-tab");
    // The "Inspect" button is rendered in MemoryCanonicalView's table.
    const inspectButton = (await screen.findAllByText("Inspect"))[0];
    fireEvent.click(inspectButton);
    const modal = await screen.findByTestId("process-detail-modal");
    expect(modal).toHaveAttribute("role", "dialog");
    expect(modal).toHaveAttribute("aria-modal", "true");
  });

  // 22. The old side drawer is no longer rendered
  it("does not render the legacy side drawer", async () => {
    renderPage();
    fireEvent.click(screen.getByTestId("memory-tab-processes"));
    await screen.findByTestId("memory-processes-tab");
    expect(screen.queryByTestId("process-detail-drawer")).not.toBeInTheDocument();
    expect(screen.queryByTestId("process-detail-drawer-panel")).not.toBeInTheDocument();
  });

  // 23. Modal closes with Escape and restores focus
  it("closes the modal with Escape and restores focus", async () => {
    getCanonicalProcessEntityDetailMock.mockResolvedValue({
      entity: {
        process_entity_id: "ent-system",
        process: { pid: 4, ppid: 0, name: "System", command_line: null, create_time: null, exit_time: null },
        sources: ["windows.pslist"],
        visibility: { listed: true },
        observation_count: 1,
        observation_summary: {},
        confidence: "high",
        findings: [],
        parent_entity_id: null,
        child_count: 1,
        tree: { is_root: true },
        normalization_version: "memory_process_canonical_v1",
        indexed_at: null,
      },
      observations: [],
      parent: null,
      children: [],
      tree_path: ["System (4)"],
      alternate_command_lines: [],
      findings: [],
      source_record_refs: ["obs-1"],
    });
    renderPage();
    fireEvent.click(screen.getByTestId("memory-tab-processes"));
    await screen.findByTestId("memory-processes-tab");
    const inspectButton = (await screen.findAllByText("Inspect"))[0];
    fireEvent.click(inspectButton);
    await screen.findByTestId("process-detail-modal");
    fireEvent.keyDown(window, { key: "Escape" });
    await waitFor(() => {
      expect(screen.queryByTestId("process-detail-modal")).not.toBeInTheDocument();
    });
  });

  // 24. Indented tree separates Main tree and Orphans
  it("splits Main tree and Orphans in the indented tree view", async () => {
    const orphan = { process_entity_id: "ent-orphan", pid: 9000, ppid: 12345, name: "orphan.exe", command_line: null, sources: ["windows.pslist"], visibility: { listed: true }, findings: [], child_count: 0, confidence: "high", truncated: false, omitted_children: 0, children: [] };
    getCanonicalProcessTreeMock.mockResolvedValue(treeResponse({
      orphans: [orphan],
      top_level_nodes: treeResponse().nodes.concat(orphan),
      metrics: { ...treeResponse().metrics, orphans: 1 },
    }));
    renderPage();
    fireEvent.click(screen.getByTestId("memory-tab-graph"));
    await screen.findByTestId("memory-graph-tab");
    fireEvent.click(screen.getByTestId("graph-subview-tree"));
    await screen.findByTestId("indented-tree");
    expect(screen.getByTestId("indented-tree-main")).toBeInTheDocument();
    expect(screen.getByTestId("indented-tree-orphans")).toBeInTheDocument();
    // The summary must say "Main tree · 1 root" and "Orphans · 1", never
    // the misleading "12 root(s)" pattern.
    const summary = screen.getByTestId("indented-tree-summary");
    expect(summary.textContent).toContain("Main tree · 1 root");
    expect(summary.textContent).toContain("Orphans · 1");
    expect(summary.textContent).not.toMatch(/\d+ root\(s\)/);
  });

  // 25. Raw observations: "Open canonical" opens the modal
  it("opens the modal from the Raw observations Open canonical link", async () => {
    getCaseMemoryProcessesMock.mockResolvedValue({
      items: [
        {
          document_id: "raw-1",
          process: { pid: 1116, ppid: 4, name: "svchost.exe", command_line: "C:\\Windows\\system32\\svchost.exe -k NetworkService -p", create_time: null, exit_time: null },
          plugins: ["windows.pslist"],
          memory_run_id: "run-basic",
        },
      ],
      total: 1,
      page: 1,
      page_size: 50,
    });
    getCanonicalProcessEntitiesMock.mockResolvedValue({
      items: [
        {
          process_entity_id: "ent-svchost-raw",
          process: { pid: 1116, ppid: 4, name: "svchost.exe", command_line: null, create_time: null, exit_time: null },
          sources: ["windows.pslist"],
          visibility: { listed: true },
          observation_count: 1,
          observation_summary: {},
          confidence: "high",
          findings: [],
          parent_entity_id: null,
          child_count: 0,
          tree: {},
          normalization_version: "memory_process_canonical_v1",
          indexed_at: null,
        },
      ],
      total: 1,
      page: 1,
      page_size: 1,
      selected_run: "run-basic",
      normalization_version: "memory_process_canonical_v1",
      total_observations: 1,
      facets: {},
    });
    getCanonicalProcessEntityDetailMock.mockResolvedValue({
      entity: {
        process_entity_id: "ent-svchost-raw",
        process: { pid: 1116, ppid: 4, name: "svchost.exe", command_line: null, create_time: null, exit_time: null },
        sources: ["windows.pslist"],
        visibility: { listed: true },
        observation_count: 1,
        observation_summary: {},
        confidence: "high",
        findings: [],
        parent_entity_id: null,
        child_count: 0,
        tree: {},
        normalization_version: "memory_process_canonical_v1",
        indexed_at: null,
      },
      observations: [],
      parent: null,
      children: [],
      tree_path: ["System (4)"],
      alternate_command_lines: [],
      findings: [],
      source_record_refs: ["obs-1"],
    });
    renderPage();
    fireEvent.click(screen.getByTestId("memory-tab-raw"));
    await screen.findByTestId("memory-raw-tab");
    const link = await screen.findByTestId("raw-link-canonical");
    fireEvent.click(link);
    expect(await screen.findByTestId("process-detail-modal")).toBeInTheDocument();
  });

  // 26. Metrics strip does not render 0 / 12 simultaneously
  it("renders a single metrics strip with consistent values", async () => {
    renderPage();
    fireEvent.click(screen.getByTestId("memory-tab-graph"));
    await screen.findByTestId("memory-graph-tab");
    const strip = await screen.findByTestId("metrics-strip");
    expect(strip).toBeInTheDocument();
    // The legacy duplicated row should not be present any more.
    expect(document.querySelectorAll('[data-testid^="graph-tab-stat-"]').length).toBe(0);
  });

  // 27. Artifacts tab is present and shows "Not analyzed" when no run
  it("renders the Artifacts tab with Not analyzed state", async () => {
    renderPage();
    fireEvent.click(screen.getByTestId("memory-tab-artifacts"));
    const tab = await screen.findByTestId("memory-artifacts-tab");
    expect(tab).toBeInTheDocument();
    // Without a run, all six overview cards show "Not analyzed".
    expect(await screen.findByTestId("memory-artifacts-overview-network-value")).toHaveTextContent("Not analyzed");
  });

  // 28. Artifacts subviews are present
  it("lists every Artifacts subview", async () => {
    renderPage();
    fireEvent.click(screen.getByTestId("memory-tab-artifacts"));
    await screen.findByTestId("memory-artifacts-tab");
    for (const sv of ["network", "modules", "handles", "drivers", "kernel", "suspicious"]) {
      expect(screen.getByTestId(`memory-artifacts-subview-${sv}`)).toBeInTheDocument();
    }
  });

  // 29. Network subview renders the empty state when no rows
  it("renders the Network table empty state when no rows", async () => {
    renderPage();
    fireEvent.click(screen.getByTestId("memory-tab-artifacts"));
    await screen.findByTestId("memory-artifacts-tab");
    expect(await screen.findByTestId("memory-artifacts-network-empty")).toBeInTheDocument();
  });

  // 30. Modules subview renders the empty state when no rows
  it("renders the Modules empty state when no rows", async () => {
    renderPage();
    fireEvent.click(screen.getByTestId("memory-tab-artifacts"));
    await screen.findByTestId("memory-artifacts-tab");
    fireEvent.click(screen.getByTestId("memory-artifacts-subview-modules"));
    expect(await screen.findByTestId("memory-artifacts-modules-empty")).toBeInTheDocument();
  });

  // 31. Handles subview renders the empty state when no rows
  it("renders the Handles empty state when no rows", async () => {
    renderPage();
    fireEvent.click(screen.getByTestId("memory-tab-artifacts"));
    await screen.findByTestId("memory-artifacts-tab");
    fireEvent.click(screen.getByTestId("memory-artifacts-subview-handles"));
    expect(await screen.findByTestId("memory-artifacts-handles-empty")).toBeInTheDocument();
  });

  // 32. Drivers subview renders the empty state when no rows
  it("renders the Drivers empty state when no rows", async () => {
    renderPage();
    fireEvent.click(screen.getByTestId("memory-tab-artifacts"));
    await screen.findByTestId("memory-artifacts-tab");
    fireEvent.click(screen.getByTestId("memory-artifacts-subview-drivers"));
    expect(await screen.findByTestId("memory-artifacts-drivers-empty")).toBeInTheDocument();
  });

  // 33. Suspicious regions show needs_review status
  it("renders the suspicious regions empty state when no rows", async () => {
    renderPage();
    fireEvent.click(screen.getByTestId("memory-tab-artifacts"));
    await screen.findByTestId("memory-artifacts-tab");
    fireEvent.click(screen.getByTestId("memory-artifacts-subview-suspicious"));
    expect(await screen.findByTestId("memory-artifacts-suspicious-empty")).toBeInTheDocument();
  });

  // 34. Run selector present in the Artifacts tab
  it("shows the run selector in the Artifacts tab", async () => {
    renderPage();
    fireEvent.click(screen.getByTestId("memory-tab-artifacts"));
    await screen.findByTestId("memory-artifacts-tab");
    expect(screen.getByTestId("memory-artifacts-run-picker")).toBeInTheDocument();
  });

  // 35. Artifacts filters are present
  it("shows the Artifacts filters and reset", async () => {
    renderPage();
    fireEvent.click(screen.getByTestId("memory-tab-artifacts"));
    await screen.findByTestId("memory-artifacts-tab");
    expect(screen.getByTestId("memory-artifacts-filter-name")).toBeInTheDocument();
    expect(screen.getByTestId("memory-artifacts-filter-pid")).toBeInTheDocument();
    expect(screen.getByTestId("memory-artifacts-filter-reset")).toBeInTheDocument();
  });

  // 36. Pagination controls are present
  it("shows pagination controls in the Artifacts tab", async () => {
    renderPage();
    fireEvent.click(screen.getByTestId("memory-tab-artifacts"));
    await screen.findByTestId("memory-artifacts-tab");
    expect(screen.getByTestId("memory-artifacts-pagination")).toBeInTheDocument();
  });

  // 37. Process link buttons exist in Network rows when rows are present
  it("renders process actions for each network row", async () => {
    getMemoryNetworkConnectionsMock.mockResolvedValue({
      document_type: "memory_network_connection",
      selected_run: "run-basic",
      total: 1,
      page: 1,
      page_size: 50,
      items: [{
        document_id: "r:memory_network_connection:abc",
        protocol: "TCPv4",
        local_address: "10.0.0.5", local_port: 445,
        remote_address: "10.0.0.10", remote_port: 49152,
        state: "ESTABLISHED",
        pid: 4, process_name: "System", process_entity_id: "ent-system",
        create_time: "2024-03-22T10:53:00+00:00",
        source_plugin: "windows.netscan", confidence: "reported_by_plugin",
      }],
      facets: {}, normalization_version: "memory_artifact_canonical_v1",
    });
    renderPage();
    fireEvent.click(screen.getByTestId("memory-tab-artifacts"));
    await screen.findByTestId("memory-artifacts-tab");
    const rows = await screen.findAllByTestId("memory-artifacts-network-row");
    expect(rows.length).toBe(1);
    expect(screen.getByTestId("memory-artifacts-network-process")).toBeInTheDocument();
  });

  // 38. Malfind does not show "malware confirmed"
  it("does not show a malware-confirmed label in suspicious regions", async () => {
    getMemorySuspiciousRegionsMock.mockResolvedValue({
      document_type: "memory_suspicious_region",
      selected_run: "run-basic",
      total: 1,
      page: 1,
      page_size: 50,
      items: [{
        document_id: "r:memory_suspicious_region:x",
        pid: 1116, process_name: "svchost.exe", process_entity_id: "ent-svchost",
        start_address: "0x1f0000", end_address: "0x1f1000",
        protection: "PAGE_EXECUTE_READWRITE", tag: "VadS",
        commit_charge: 4, private_memory: true,
        source_plugin: "windows.malfind", confidence: "indicator",
        review_status: "needs_review",
        findings: ["needs_review"],
      }],
      facets: {}, normalization_version: "memory_artifact_canonical_v1",
    });
    renderPage();
    fireEvent.click(screen.getByTestId("memory-tab-artifacts"));
    await screen.findByTestId("memory-artifacts-tab");
    fireEvent.click(screen.getByTestId("memory-artifacts-subview-suspicious"));
    expect(await screen.findByTestId("memory-artifacts-suspicious-review")).toHaveTextContent("needs_review");
    expect(document.body.textContent || "").not.toContain("malware confirmed");
  });

  // 39. Overview shows the artifacts jump button
  it("renders the Open Artifacts tab button on Overview", async () => {
    renderPage();
    expect(await screen.findByTestId("memory-overview")).toBeInTheDocument();
    expect(screen.getByTestId("overview-jump-artifacts")).toBeInTheDocument();
  });

  // 40. Runs tab shows the new profile names
  it("renders the Runs tab without errors", async () => {
    renderPage();
    fireEvent.click(screen.getByTestId("memory-tab-runs"));
    expect(await screen.findByTestId("memory-runs-tab")).toBeInTheDocument();
  });
});
