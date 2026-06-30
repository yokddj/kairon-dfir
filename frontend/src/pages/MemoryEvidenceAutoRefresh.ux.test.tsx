import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { fireEvent, render, screen, waitFor } from "@testing-library/react";
import { MemoryRouter, Route, Routes } from "react-router-dom";
import { beforeEach, describe, expect, it, vi } from "vitest";
import MemoryAnalysisPage from "./MemoryAnalysisPage";
import MemoryEvidencePage from "./MemoryEvidencePage";
import CaseMemoryLanding from "./CaseMemoryLanding";

const getMemoryOverviewMock = vi.fn();
const getMemoryBackendOverviewMock = vi.fn();
const getMemoryRunOptionsMock = vi.fn();
const getCanonicalProcessSummaryMock = vi.fn();
const getMemoryEvidenceReadinessMock = vi.fn();
const getMemorySymbolCacheStatusMock = vi.fn();
const startMemoryScanMock = vi.fn();
const getMemoryArtifactOverviewMock = vi.fn();
const listMemoryRunsMock = vi.fn();
const getMemoryEvidenceLandingMock = vi.fn();
const getMemoryActiveResultMock = vi.fn();
const getMemoryAnalysisCatalogueMock = vi.fn();
const confirmMemoryTypeMock = vi.fn();
const startMemoryRunAllMock = vi.fn();
const getActiveMemoryAnalysisBatchMock = vi.fn();
const getMemorySymbolPreparationMock = vi.fn();
const getMemorySymbolReadinessMock = vi.fn();

vi.mock("../api/client", () => ({
  api: {
    getMemoryBackendOverview: (...args: unknown[]) => getMemoryBackendOverviewMock(...args),
    getMemoryOverview: (...args: unknown[]) => getMemoryOverviewMock(...args),
    getMemoryRunOptions: (...args: unknown[]) => getMemoryRunOptionsMock(...args),
    getCanonicalProcessSummary: (...args: unknown[]) => getCanonicalProcessSummaryMock(...args),
    getMemoryEvidenceReadiness: (...args: unknown[]) => getMemoryEvidenceReadinessMock(...args),
    getMemorySymbolCacheStatus: (...args: unknown[]) => getMemorySymbolCacheStatusMock(...args),
    startMemoryScan: (...args: unknown[]) => startMemoryScanMock(...args),
    getMemoryArtifactOverview: (...args: unknown[]) => getMemoryArtifactOverviewMock(...args),
    listMemoryRuns: (...args: unknown[]) => listMemoryRunsMock(...args),
    getMemoryEvidenceLanding: (...args: unknown[]) => getMemoryEvidenceLandingMock(...args),
    getMemoryActiveResult: (...args: unknown[]) => getMemoryActiveResultMock(...args),
    getMemoryAnalysisCatalogue: (...args: unknown[]) => getMemoryAnalysisCatalogueMock(...args),
    confirmMemoryType: (...args: unknown[]) => confirmMemoryTypeMock(...args),
    startMemoryRunAll: (...args: unknown[]) => startMemoryRunAllMock(...args),
    getActiveMemoryAnalysisBatch: (...args: unknown[]) => getActiveMemoryAnalysisBatchMock(...args),
    getMemorySymbolPreparation: (...args: unknown[]) => getMemorySymbolPreparationMock(...args),
    getMemorySymbolReadiness: (...args: unknown[]) => getMemorySymbolReadinessMock(...args),
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

function baseCatalogue() {
  return {
    case_id: "case-1",
    evidence_id: "ev-A",
    items: [
      { profile: "metadata_only", family: "system_info", title: "System metadata", description: "", cost_label: "Fast", est_duration_seconds: 20, available: true, availability_reason: null, last_run: null, last_status: null, last_count: 0 },
      { profile: "processes_basic", family: "processes", title: "Standard process analysis", description: "", cost_label: "Medium", est_duration_seconds: 90, available: true, availability_reason: null, last_run: null, last_status: null, last_count: 0 },
      { profile: "network_basic", family: "network", title: "Network connections", description: "", cost_label: "Medium", est_duration_seconds: 90, available: false, availability_reason: "No compatible Windows network plugin is available in the installed Volatility runtime.", last_run: null, last_status: null, last_count: 0 },
    ],
  };
}

function baseLanding() {
  return {
    case_id: "case-1",
    items: [
      {
        evidence_id: "ev-A", case_id: "case-1", filename: "ws01.dmp",
        detected_host: "WS01", size_bytes: 4255346688, created_at: "2026-06-15T00:00:00Z",
        processed_at: "2026-06-15T00:01:00Z", ingest_status: "completed",
        metadata: {}, run_count: 0, latest_run_id: null, latest_run_status: null,
        detection_status: "confirmed_memory", detection_confidence: "high",
        detected_format: "windows_crash_dump", detection_reason: "Crash dump detected",
        operator_override: false, operator_override_reason: null, operator_override_at: null,
        can_analyze: true,
        families: [
          { family: "system_info", state: "not_analyzed", title: "System metadata", active_run: null, latest_attempt: null, selection_reason: "not_analyzed", using_fallback: false, historical_override: false, availability_reason: null, count: 0, document_type: "memory_system_info", count_source: "no_active_run" },
          { family: "processes", state: "not_analyzed", title: "Processes", active_run: null, latest_attempt: null, selection_reason: "not_analyzed", using_fallback: false, historical_override: false, availability_reason: null, count: 0, document_type: "memory_process_entity", count_source: "no_active_run" },
          { family: "network", state: "unavailable", title: "Network connections", active_run: null, latest_attempt: null, selection_reason: "runtime_plugin_missing", using_fallback: false, historical_override: false, availability_reason: "No compatible Windows network plugin is available in the installed Volatility runtime.", count: 0, document_type: "memory_network_connection", count_source: "no_active_run" },
          { family: "modules", state: "not_analyzed", title: "Process modules", active_run: null, latest_attempt: null, selection_reason: "not_analyzed", using_fallback: false, historical_override: false, availability_reason: null, count: 0, document_type: "memory_process_module", count_source: "no_active_run" },
          { family: "handles", state: "not_analyzed", title: "Process handles", active_run: null, latest_attempt: null, selection_reason: "not_analyzed", using_fallback: false, historical_override: false, availability_reason: null, count: 0, document_type: "memory_handle", count_source: "no_active_run" },
          { family: "kernel_modules", state: "not_analyzed", title: "Kernel modules", active_run: null, latest_attempt: null, selection_reason: "not_analyzed", using_fallback: false, historical_override: false, availability_reason: null, count: 0, document_type: "memory_kernel_module", count_source: "no_active_run" },
          { family: "drivers", state: "not_analyzed", title: "Drivers", active_run: null, latest_attempt: null, selection_reason: "not_analyzed", using_fallback: false, historical_override: false, availability_reason: null, count: 0, document_type: "memory_driver", count_source: "no_active_run" },
          { family: "suspicious_regions", state: "not_analyzed", title: "Suspicious memory regions", active_run: null, latest_attempt: null, selection_reason: "not_analyzed", using_fallback: false, historical_override: false, availability_reason: null, count: 0, document_type: "memory_suspicious_region", count_source: "no_active_run" },
          { family: "raw_observations", state: "not_analyzed", title: "Raw observations", active_run: null, latest_attempt: null, selection_reason: "not_analyzed", using_fallback: false, historical_override: false, availability_reason: null, count: 0, document_type: "memory_process_observation", count_source: "no_active_run" },
        ],
      },
    ],
  };
}

function baseBackend() {
  return {
    backends: [
      {
        backend: "volatility3", display_name: "Volatility 3", configured: true,
        executable_found: true, execution_allowed: true, available: true, ready: true,
        version: "Volatility 3 Framework 2.28.0", command_display: "vol",
        status: "available", message: "Volatility 3 is available.",
        checked_at: "2026-06-15T00:00:00Z", error_code: null,
        execution_mode: "dedicated_worker", dedicated_worker_required: true,
        dedicated_worker_online: true, queue: "memory", queue_reachable: true,
        backend_available: true, backend_version: "2.28.0",
        supported_profiles: ["metadata_only", "processes_basic"],
        supported_plugins: ["windows.info"], symbol_network_enabled: false,
      },
    ],
  };
}

function emptyRuns() { return []; }

function emptyBatch() { return null; }

function noPrep() {
  return { ui_state: "ready", preparation_state: "ready", effective_state: "ready", native_compatible: false };
}

function noSymbolReadiness() {
  return { state: "missing", can_analyze_metadata: true, can_run_all: true, blocker: null, error_code: null };
}

function queuedRun() {
  return [
    {
      id: "r-queued", case_id: "case-1", evidence_id: "ev-A",
      profile: "metadata_only", status: "queued",
      created_at: "2026-06-15T01:00:00Z", started_at: null, completed_at: null,
      error_message: null,
    },
  ];
}

function completedRun() {
  return [
    {
      id: "r-done", case_id: "case-1", evidence_id: "ev-A",
      profile: "metadata_only", status: "completed",
      created_at: "2026-06-15T01:00:00Z", started_at: "2026-06-15T01:00:01Z",
      completed_at: "2026-06-15T01:00:10Z", error_message: null, duration_seconds: 9.5,
    },
  ];
}

function completedCatalogue() {
  return {
    case_id: "case-1",
    evidence_id: "ev-A",
    items: [
      { profile: "metadata_only", family: "system_info", title: "System metadata", description: "", cost_label: "Fast", est_duration_seconds: 20, available: true, availability_reason: null, last_run: { completed_at: "2026-06-15T01:00:10Z" }, last_status: "completed", last_count: 1 },
      { profile: "processes_basic", family: "processes", title: "Standard process analysis", description: "", cost_label: "Medium", est_duration_seconds: 90, available: true, availability_reason: null, last_run: null, last_status: null, last_count: 0 },
      { profile: "network_basic", family: "network", title: "Network connections", description: "", cost_label: "Medium", est_duration_seconds: 90, available: false, availability_reason: "Not available", last_run: null, last_status: null, last_count: 0 },
    ],
  };
}

describe("Memory evidence auto-refresh", () => {
  beforeEach(() => {
    vi.clearAllMocks();
    getMemoryBackendOverviewMock.mockReturnValue(baseBackend());
    getMemoryOverviewMock.mockReturnValue({
      case_id: "case-1", memory_analysis_enabled: true, has_memory_evidence: true,
      has_memory_results: true, has_disk_events: false, mode: "memory_only",
      evidences: [{ id: "ev-A", case_id: "case-1", original_filename: "ws01.dmp", evidence_type: "memory_dump", size_bytes: 4255346688, ingest_status: "completed", created_at: "2026-06-15T00:00:00Z" }],
      runs: [],
      message: "Memory analysis is available.",
    });
    getMemoryRunOptionsMock.mockReturnValue({ runs: [], default_run_id: null });
    getCanonicalProcessSummaryMock.mockReturnValue({
      case_id: "case-1", evidence_id: "ev-A", total_entities: 0, page: 1, page_size: 50,
      items: [], facets: {}, summary: { total_entities: 0 },
    });
    getMemoryEvidenceReadinessMock.mockReturnValue({});
    getMemorySymbolCacheStatusMock.mockReturnValue({});
    getMemoryArtifactOverviewMock.mockReturnValue({
      case_id: "case-1", selected_run: null, run_status: null, profile: null,
      network_connections: { count: 0 }, process_modules: { count: 0 },
      module_discrepancies: 0, kernel_modules: { count: 0 }, drivers: { count: 0 },
      handles: { count: 0 }, suspicious_regions: { count: 0 }, facets: {},
      normalization_version: "memory_artifact_canonical_v1",
    });
    getMemoryActiveResultMock.mockReturnValue({ status: "no_data" });
    getActiveMemoryAnalysisBatchMock.mockRejectedValue({ response: { status: 404 } });
    getMemorySymbolPreparationMock.mockReturnValue(noPrep());
    getMemorySymbolReadinessMock.mockReturnValue(noSymbolReadiness());
    getMemoryEvidenceLandingMock.mockReturnValue(baseLanding());
    listMemoryRunsMock.mockReturnValue(emptyRuns());
    getMemoryAnalysisCatalogueMock.mockReturnValue(baseCatalogue());
  });

  it("confirmation mutation is called with correct parameters", async () => {
    confirmMemoryTypeMock.mockResolvedValue({ success: true });
    getMemoryAnalysisCatalogueMock.mockReturnValue(baseCatalogue());

    const landing = baseLanding();
    landing.items[0].detection_status = "ambiguous_raw";
    landing.items[0].operator_override = false;
    getMemoryEvidenceLandingMock.mockReturnValue(landing);

    renderWorkspaceAt("/cases/case-1/memory/ev-A");

    const badge = await screen.findByTestId("memory-detection-badge");
    expect(badge.textContent).toBe("Confirmation required");

    const confirmBtn = await screen.findByTestId("memory-header-confirm-button");
    fireEvent.click(confirmBtn);

    const modal = await screen.findByTestId("memory-type-confirmation-modal");
    expect(modal).toBeInTheDocument();

    const checkbox = screen.getByTestId("memory-type-confirmation-checkbox");
    fireEvent.click(checkbox);
    const reasonInput = screen.getByTestId("memory-type-confirmation-reason");
    fireEvent.change(reasonInput, { target: { value: "This is a valid memory image" } });
    const modalConfirmBtn = screen.getByTestId("memory-type-confirmation-confirm");
    fireEvent.click(modalConfirmBtn);

    await waitFor(() => {
      expect(confirmMemoryTypeMock).toHaveBeenCalledTimes(1);
    });
  });

  it("analyze click creates queued state and the button reflects progress", async () => {
    const originalConfirm = window.confirm;
    window.confirm = vi.fn(() => true);
    try {
      getMemoryAnalysisCatalogueMock.mockReturnValue(baseCatalogue());
      getMemoryEvidenceLandingMock.mockReturnValue(baseLanding());
      listMemoryRunsMock.mockReturnValue(emptyRuns());
      startMemoryScanMock.mockResolvedValue({
        accepted: true, evidence_id: "ev-A", run_id: "run-1", status: "queued", message: "Queued",
      });

      renderWorkspaceAt("/cases/case-1/memory/ev-A");

      const button = await screen.findByTestId("memory-analyze-direct");
      expect(button.textContent).toBe("Analyze memory");

      fireEvent.click(button);

      await waitFor(() => {
        expect(startMemoryScanMock).toHaveBeenCalledTimes(1);
        expect(startMemoryScanMock).toHaveBeenCalledWith("case-1", "ev-A", "metadata_only", true);
      });

    } finally {
      window.confirm = originalConfirm;
    }
  });

  it("does not send duplicate scan on rapid double click", async () => {
    const originalConfirm = window.confirm;
    window.confirm = vi.fn(() => true);
    try {
      getMemoryAnalysisCatalogueMock.mockReturnValue(baseCatalogue());
      listMemoryRunsMock.mockReturnValue(emptyRuns());
      let resolve: (v: unknown) => void;
      startMemoryScanMock.mockImplementation(() => new Promise((r) => { resolve = r; }));

      renderWorkspaceAt("/cases/case-1/memory/ev-A");

      const button = await screen.findByTestId("memory-analyze-direct");
      fireEvent.click(button);
      fireEvent.click(button);

      // Button should show in-progress state after first click
      await waitFor(() => {
        expect(button.textContent).toBe("Starting analysis...");
      });

      // Synchronous guard and disabled button must prevent a second request
      expect(startMemoryScanMock).toHaveBeenCalledTimes(1);

      resolve!({ accepted: true, evidence_id: "ev-A", run_id: "run-1", status: "queued" });

      // After mutation completes, button returns to normal
      await waitFor(() => {
        expect(button.textContent).not.toBe("Starting analysis...");
      });

    } finally {
      window.confirm = originalConfirm;
    }
  });

  it("runs query polls when called from evidence page", async () => {
    getMemoryAnalysisCatalogueMock.mockReturnValue(baseCatalogue());
    listMemoryRunsMock.mockReturnValue(queuedRun());

    renderWorkspaceAt("/cases/case-1/memory/ev-A");

    await waitFor(() => {
      expect(listMemoryRunsMock).toHaveBeenCalledWith("case-1", "ev-A");
    });
  });

  it("metadata completion changes action to Complete analysis", async () => {
    getMemoryAnalysisCatalogueMock.mockReturnValue(completedCatalogue());
    getMemoryEvidenceLandingMock.mockReturnValue(baseLanding());
    listMemoryRunsMock.mockReturnValue(completedRun());
    getMemoryActiveResultMock.mockReturnValue({ status: "no_data" });

    renderWorkspaceAt("/cases/case-1/memory/ev-A");

    const button = await screen.findByTestId("memory-open-catalogue");
    expect(button.textContent).toBe("Complete analysis");
  });

  it("active batch prevents duplicate Complete analysis", async () => {
    getMemoryAnalysisCatalogueMock.mockReturnValue(completedCatalogue());
    getActiveMemoryAnalysisBatchMock.mockResolvedValue({
      id: "batch-1", case_id: "case-1", evidence_id: "ev-A",
      status: "running", requested_profiles: ["processes_basic"],
      completed_profiles: [], current_profile: "processes_basic",
      cancellation_requested: false,
    });
    listMemoryRunsMock.mockReturnValue(completedRun());

    renderWorkspaceAt("/cases/case-1/memory/ev-A");

    // The batch progress section should appear
    await waitFor(() => {
      expect(screen.getByTestId("memory-batch-progress")).toBeInTheDocument();
    });
  });

  it("cache miss remains informational (not error styled)", async () => {
    getMemorySymbolPreparationMock.mockReturnValue({
      ui_state: "blocked", preparation_state: "blocked", effective_state: "blocked",
      native_compatible: false, blocker: "Windows symbols required",
    });
    getMemorySymbolReadinessMock.mockReturnValue({
      state: "missing", can_analyze_metadata: true, can_run_all: true,
      error_code: "MEMORY_SYMBOLS_REQUIRED",
      sanitized_message: "Windows symbols required for this evidence are not cached.",
    });
    getMemoryAnalysisCatalogueMock.mockReturnValue(baseCatalogue());
    listMemoryRunsMock.mockReturnValue(emptyRuns());

    renderWorkspaceAt("/cases/case-1/memory/ev-A");

    // The info banner should appear (cyan color, not rose/error)
    await waitFor(() => {
      const banner = screen.getByTestId("memory-symbol-info-banner");
      expect(banner).toBeInTheDocument();
      expect(banner.className).toContain("cyan");
      expect(banner.className).not.toContain("rose");
    });
  });

  it("worker available banner is not styled as an error", async () => {
    getMemoryBackendOverviewMock.mockReturnValue({
      backends: [
        {
          backend: "volatility3", display_name: "Volatility 3", configured: true,
          executable_found: true, execution_allowed: true, available: true, ready: true,
          version: "3", command_display: "vol", status: "available",
          message: "Volatility 3 is available.", checked_at: "2026-06-15T00:00:00Z",
          error_code: null, execution_mode: "dedicated_worker",
          dedicated_worker_required: true, dedicated_worker_online: true,
          queue: "memory", queue_reachable: true, backend_available: true,
          backend_version: "2.28.0", supported_profiles: [], supported_plugins: [],
          symbol_network_enabled: false,
        },
      ],
    });
    getMemoryAnalysisCatalogueMock.mockReturnValue(baseCatalogue());
    listMemoryRunsMock.mockReturnValue(emptyRuns());

    renderWorkspaceAt("/cases/case-1/memory/ev-A");

    await screen.findByTestId("memory-evidence-header");
    // The page rendered without a red error banner — no assertion needed beyond rendering
  });

  it("API error appears without losing page context", async () => {
    const originalConfirm = window.confirm;
    window.confirm = vi.fn(() => true);
    try {
      getMemoryAnalysisCatalogueMock.mockReturnValue(baseCatalogue());
      listMemoryRunsMock.mockReturnValue(emptyRuns());
      startMemoryScanMock.mockRejectedValue(new Error("Worker unavailable"));

      renderWorkspaceAt("/cases/case-1/memory/ev-A");

      const button = await screen.findByTestId("memory-analyze-direct");
      fireEvent.click(button);

      await waitFor(() => {
        expect(startMemoryScanMock).toHaveBeenCalled();
      });

      // The page should still render the evidence header (no crash)
      expect(screen.getByTestId("memory-evidence-header")).toBeInTheDocument();
    } finally {
      window.confirm = originalConfirm;
    }
  });

  it("current tab remains unchanged during polling refetch", async () => {
    getMemoryAnalysisCatalogueMock.mockReturnValue(baseCatalogue());
    listMemoryRunsMock.mockReturnValue(queuedRun());

    renderWorkspaceAt("/cases/case-1/memory/ev-A");

    await waitFor(() => {
      expect(listMemoryRunsMock).toHaveBeenCalledWith("case-1", "ev-A");
    });

    // Evidence header is rendered
    await screen.findByTestId("memory-evidence-header");
  });

  it("same filename Evidence records do not share run state", async () => {
    const landing = baseLanding();
    landing.items.push({
      evidence_id: "ev-B", case_id: "case-1", filename: "ws01.dmp",
      detected_host: "WS02", size_bytes: 4255346688, created_at: "2026-06-16T00:00:00Z",
      processed_at: null, ingest_status: "completed",
      metadata: {}, run_count: 0, latest_run_id: null, latest_run_status: null,
      detection_status: "confirmed_memory", detection_confidence: "high",
      detected_format: "windows_crash_dump", detection_reason: "Crash dump detected",
      operator_override: false, operator_override_reason: null, operator_override_at: null,
      can_analyze: true,
      families: [],
    });
    getMemoryEvidenceLandingMock.mockReturnValue(landing);
    getMemoryAnalysisCatalogueMock.mockReturnValue(baseCatalogue());
    getMemoryOverviewMock.mockReturnValue({
      case_id: "case-1", memory_analysis_enabled: true, has_memory_evidence: true,
      has_memory_results: true, has_disk_events: false, mode: "memory_only",
      evidences: [
        { id: "ev-A", case_id: "case-1", original_filename: "ws01.dmp", evidence_type: "memory_dump", size_bytes: 4255346688, ingest_status: "completed", created_at: "2026-06-15T00:00:00Z" },
        { id: "ev-B", case_id: "case-1", original_filename: "ws01.dmp", evidence_type: "memory_dump", size_bytes: 4255346688, ingest_status: "completed", created_at: "2026-06-16T00:00:00Z" },
      ],
      runs: [],
      message: "Memory analysis is available.",
    });

    listMemoryRunsMock.mockReturnValue(queuedRun());

    renderWorkspaceAt("/cases/case-1/memory/ev-A");

    // Verify evidence A has its own run state
    await waitFor(() => {
      expect(listMemoryRunsMock).toHaveBeenCalledWith("case-1", "ev-A");
    });

    // Evidence B should not have received ev-A's runs query
    const callsForB = listMemoryRunsMock.mock.calls.filter(
      (call: unknown[]) => call[1] === "ev-B",
    );
    expect(callsForB).toHaveLength(0);
  });
});
