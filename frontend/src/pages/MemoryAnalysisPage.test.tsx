import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { fireEvent, render, screen, waitFor } from "@testing-library/react";
import { MemoryRouter, Route, Routes } from "react-router-dom";
import { beforeEach, describe, expect, it, vi } from "vitest";
import MemoryAnalysisPage from "./MemoryAnalysisPage";

const getMemoryOverviewMock = vi.fn();
const getMemoryBackendOverviewMock = vi.fn();
const getCaseMemorySystemInfoMock = vi.fn();
const getCaseMemoryProcessesMock = vi.fn();
const getMemoryProcessTreeMock = vi.fn();
const startMemoryScanMock = vi.fn();

vi.mock("../api/client", () => ({
  api: {
    getMemoryBackendOverview: (...args: unknown[]) => getMemoryBackendOverviewMock(...args),
    getMemoryOverview: (...args: unknown[]) => getMemoryOverviewMock(...args),
    getCaseMemorySystemInfo: (...args: unknown[]) => getCaseMemorySystemInfoMock(...args),
    getCaseMemoryProcesses: (...args: unknown[]) => getCaseMemoryProcessesMock(...args),
    getMemoryProcessTree: (...args: unknown[]) => getMemoryProcessTreeMock(...args),
    startMemoryScan: (...args: unknown[]) => startMemoryScanMock(...args),
  },
}));

vi.mock("../context/ActiveCaseContext", () => ({
  useActiveCase: () => ({
    setActiveCaseId: vi.fn(),
  }),
}));

function renderPage() {
  const queryClient = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  return render(
    <MemoryRouter initialEntries={["/cases/case-1/memory"]}>
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
    memory_analysis_enabled: false,
    has_memory_evidence: false,
    has_memory_results: false,
    has_disk_events: false,
    mode: "empty",
    evidences: [],
    runs: [],
    message: "No disk events or memory evidence found for this case.",
    ...overrides,
  };
}

function backendStatus(overrides = {}) {
  return {
    backend: "volatility3",
    display_name: "Volatility 3",
    configured: true,
    executable_found: false,
    execution_allowed: false,
    available: false,
    ready: false,
    version: null,
    command_display: "vol",
    status: "not_found",
    message: "Volatility 3 is configured but was not found in the server environment.",
    checked_at: "2026-06-16T00:00:00Z",
    error_code: "executable_not_found",
    ...overrides,
  };
}

function backendOverview(overrides = {}) {
  return {
    memory_analysis_enabled: false,
    external_execution_allowed: false,
    preferred_backend: "volatility3",
    ready_backend_count: 0,
    message: "No external memory-analysis backend is ready. Disk-only workflows remain fully available.",
    backends: [
      backendStatus({ backend: "volatility3", display_name: "Volatility 3", command_display: "vol" }),
      backendStatus({ backend: "memprocfs", display_name: "MemProcFS", command_display: "memprocfs" }),
    ],
    ...overrides,
  };
}

describe("MemoryAnalysisPage", () => {
  beforeEach(() => {
    vi.clearAllMocks();
    getMemoryOverviewMock.mockResolvedValue(overview());
    getMemoryBackendOverviewMock.mockResolvedValue(backendOverview());
    getCaseMemorySystemInfoMock.mockResolvedValue([]);
    getCaseMemoryProcessesMock.mockResolvedValue({ items: [], total: 0, page: 1, page_size: 50 });
    getMemoryProcessTreeMock.mockResolvedValue({ run_id: "run-1", nodes: [], edges: [], orphan_count: 0, root_count: 0, warnings: [], source_plugins: [], total_process_count: 0 });
    vi.spyOn(window, "confirm").mockReturnValue(true);
    startMemoryScanMock.mockResolvedValue({ accepted: true, evidence_id: "ev-memory", run_id: "run-1", status: "queued", message: "Memory metadata analysis queued for windows.info.", run: null });
  });

  it("shows disabled state by default", async () => {
    renderPage();
    expect(
      await screen.findByText(
        "Memory Analysis is currently disabled. Kairon can still work with disk artifacts only. Enable memory analysis in backend configuration when you are ready to analyze authorized RAM evidence.",
      ),
    ).toBeInTheDocument();
    expect(await screen.findByText("Memory backends")).toBeInTheDocument();
    expect(screen.getByText(/Disk-only workflows remain fully available/i)).toBeInTheDocument();
  });

  it("shows installed but blocked backend state", async () => {
    getMemoryBackendOverviewMock.mockResolvedValueOnce(
      backendOverview({
        backends: [
          backendStatus({
            executable_found: true,
            available: true,
            status: "blocked",
            message: "Volatility 3 is detected, but external memory-tool execution is disabled.",
            version: "Volatility 3 Framework 2.8.0",
          }),
        ],
      }),
    );
    renderPage();
    expect(await screen.findByText("Installed but blocked")).toBeInTheDocument();
    expect(screen.getByText("Volatility 3 Framework 2.8.0")).toBeInTheDocument();
    expect(screen.getByText(/external memory-tool execution is disabled/i)).toBeInTheDocument();
  });

  it("shows not-found backend state", async () => {
    renderPage();
    expect(await screen.findAllByText("Not found")).toHaveLength(2);
    expect(screen.getAllByText(/configured but was not found/i).length).toBeGreaterThan(0);
  });

  it("shows ready backend state", async () => {
    getMemoryBackendOverviewMock.mockResolvedValueOnce(
      backendOverview({
        memory_analysis_enabled: true,
        external_execution_allowed: true,
        ready_backend_count: 1,
        message: "1 memory-analysis backend is ready for a future sprint.",
        backends: [
          backendStatus({
            executable_found: true,
            execution_allowed: true,
            available: true,
            ready: true,
            status: "available",
            message: "Volatility 3 is available and administratively enabled for future memory analysis.",
          }),
        ],
      }),
    );
    renderPage();
    expect(await screen.findByText("Ready")).toBeInTheDocument();
    expect(screen.getByText(/available and administratively enabled/i)).toBeInTheDocument();
  });

  it("shows failed-check state without exposing full paths", async () => {
    getMemoryBackendOverviewMock.mockResolvedValueOnce(
      backendOverview({
        backends: [
          backendStatus({
            executable_found: true,
            status: "check_failed",
            message: "Volatility 3 was found, but its harmless readiness check failed.",
            command_display: "vol",
            error_code: "check_failed",
          }),
        ],
      }),
    );
    renderPage();
    expect(await screen.findByText("Check failed")).toBeInTheDocument();
    expect(screen.queryByText(/\/opt\/private/i)).not.toBeInTheDocument();
  });

  it("shows no memory evidence empty state", async () => {
    getMemoryOverviewMock.mockResolvedValueOnce(overview({ memory_analysis_enabled: true }));
    renderPage();
    expect(await screen.findByText(/No memory evidence found for this case/i)).toBeInTheDocument();
    expect(screen.getByText(/disk artifacts only, memory artifacts only, or both/i)).toBeInTheDocument();
  });

  it("shows mode empty states", async () => {
    getMemoryOverviewMock.mockResolvedValueOnce(overview({ memory_analysis_enabled: true, mode: "disk_only", has_disk_events: true, message: "This case currently has disk artifacts only." }));
    renderPage();
    expect(await screen.findByText("Disk only")).toBeInTheDocument();
  });

  it("shows memory evidence list and runs metadata-only analysis when ready", async () => {
    getMemoryOverviewMock.mockResolvedValueOnce(
      overview({
        memory_analysis_enabled: true,
        mode: "memory_only",
        has_memory_evidence: true,
        evidences: [{ id: "ev-memory", case_id: "case-1", original_filename: "memory.mem", evidence_type: "memory_dump", size_bytes: 2048, ingest_status: "completed", created_at: "2026-06-16T00:00:00Z" }],
      }),
    );
    getMemoryBackendOverviewMock.mockResolvedValueOnce(
      backendOverview({
        memory_analysis_enabled: true,
        external_execution_allowed: true,
        ready_backend_count: 1,
        backends: [backendStatus({ executable_found: true, execution_allowed: true, available: true, ready: true, status: "available" })],
      }),
    );
    renderPage();
    expect(await screen.findByText("memory.mem")).toBeInTheDocument();
    fireEvent.click(screen.getByRole("button", { name: /Run metadata analysis/i }));
    expect(window.confirm).toHaveBeenCalledWith(expect.stringContaining("windows.info metadata plugin"));
    await waitFor(() => expect(startMemoryScanMock).toHaveBeenCalledWith("ev-memory", "metadata_only", true));
  });

  it("offers basic process analysis with exact confirmation copy", async () => {
    getMemoryOverviewMock.mockResolvedValueOnce(
      overview({
        memory_analysis_enabled: true,
        memory_process_profile_enabled: true,
        has_memory_evidence: true,
        evidences: [{ id: "ev-memory", case_id: "case-1", original_filename: "memory.mem", evidence_type: "memory_dump", size_bytes: 2048, ingest_status: "completed", created_at: "2026-06-16T00:00:00Z" }],
      }),
    );
    getMemoryBackendOverviewMock.mockResolvedValueOnce(
      backendOverview({
        memory_analysis_enabled: true,
        external_execution_allowed: true,
        ready_backend_count: 1,
        backends: [backendStatus({ executable_found: true, execution_allowed: true, available: true, ready: true, status: "available" })],
      }),
    );
    renderPage();
    expect(await screen.findByText("memory.mem")).toBeInTheDocument();
    fireEvent.click(screen.getByRole("button", { name: /Run basic process analysis/i }));
    expect(window.confirm).toHaveBeenCalledWith("I confirm that I own this memory image or am explicitly authorized to analyze it, and I understand that RAM may contain sensitive personal or authentication data.");
    expect(window.confirm).toHaveBeenCalledWith("This will analyze the selected authorized memory image using the externally configured Volatility 3 backend and the windows.info, windows.pslist, windows.pstree, and windows.cmdline plugins.");
    await waitFor(() => expect(startMemoryScanMock).toHaveBeenCalledWith("ev-memory", "processes_basic", true));
  });

  it("shows run list", async () => {
    getMemoryOverviewMock.mockResolvedValueOnce(
      overview({
        memory_analysis_enabled: true,
        has_memory_evidence: true,
        runs: [{ id: "run-1", case_id: "case-1", evidence_id: "ev-memory", backend: "volatility3", profile: "metadata_only", status: "completed", requested_plugin_count: 1, plugin_count: 1, plugins_completed: 1, plugins_failed: 0, started_at: null, completed_at: null, duration_ms: 1200, output_dir: null, metadata_json: {}, error_log: {}, backend_version: "Volatility 3 Framework 2.8.0", worker_task_id: "job-1", cancellation_requested: false, created_at: "2026-06-16T00:00:00Z" }],
      }),
    );
    renderPage();
    expect(await screen.findByText("Memory runs")).toBeInTheDocument();
    expect(screen.getByText("metadata_only")).toBeInTheDocument();
    expect(screen.getByText("Volatility 3 Framework 2.8.0")).toBeInTheDocument();
  });

  it("shows completed system information without raw JSON", async () => {
    getMemoryOverviewMock.mockResolvedValueOnce(overview({ memory_analysis_enabled: true }));
    getCaseMemorySystemInfoMock.mockResolvedValueOnce([
      {
        case_id: "case-1",
        evidence_id: "ev-memory",
        memory_run_id: "run-1",
        memory_plugin_run_id: "plugin-1",
        source_layer: "memory",
        memory_artifact_type: "memory_system_info",
        backend: "volatility3",
        plugin: "windows.info",
        host: { name: null },
        os: { family: "windows", kernel_base: "0xf8000000", kernel_version: null, machine_type: "x64" },
        memory: { layer_name: "Intel32e", dtb: null, kernel_symbols: "ntkrnlmp.pdb", system_time: "2026-06-16T00:00:00Z" },
        parsed_at: "2026-06-16T00:00:00Z",
        raw: { fields: { private_field: "hidden" } },
      },
    ]);
    renderPage();
    expect(await screen.findByText("System information")).toBeInTheDocument();
    expect(screen.getByText("0xf8000000")).toBeInTheDocument();
    expect(screen.getByText("ntkrnlmp.pdb")).toBeInTheDocument();
    expect(screen.queryByText("private_field")).not.toBeInTheDocument();
  });
});
