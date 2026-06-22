/**
 * Tests for the per-evidence Windows symbol resolution flow.
 *
 * The analyst sees a per-evidence state badge, a "Probe symbol
 * requirements" button, an "Acquire symbols" button (only when
 * acquisition is supported), a structured acquisition modal, and
 * a Run analysis button that is disabled when the exact symbol is
 * not cached.
 */
import { describe, expect, it, vi, beforeEach } from "vitest";
import { render, screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { MemoryRouter, Route, Routes } from "react-router-dom";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { ActiveCaseProvider } from "../context/ActiveCaseContext";
import { type MemoryEvidenceLandingItem, type MemorySymbolReadiness, type MemoryAnalysisCatalogue } from "../api/client";
import MemoryEvidencePage from "./MemoryEvidencePage";

// Module-level mock holder; the vi.mock factory below uses this.
const mockApi: Record<string, ReturnType<typeof vi.fn>> = {};

vi.mock("../api/client", async () => {
  const actual = await vi.importActual<typeof import("../api/client")>("../api/client");
  // Re-export the types and keep all other named exports, but stub
  // the methods that the page calls.
  const apiProxy = new Proxy(
    {},
    {
      get(_target, prop: string) {
        if (prop in mockApi) {
          return mockApi[prop];
        }
        // Pass through to the real `api` for any method we did not
        // explicitly mock, so that the page does not crash on
        // unmocked helpers.
        return (actual.api as unknown as Record<string, unknown>)[prop];
      },
    },
  );
  return { ...actual, api: apiProxy };
});

const CASE_ID = "case-1";
const EVIDENCE_ID = "evidence-1";
const FILENAME = "DC02-20240322-125906.dmp";

function makeQueryClient(): QueryClient {
  return new QueryClient({
    defaultOptions: {
      queries: { retry: false, gcTime: 0, staleTime: 0 },
      mutations: { retry: false },
    },
  });
}

function makeEvidence(
  overrides: Partial<MemoryEvidenceLandingItem> = {},
): MemoryEvidenceLandingItem {
  return {
    evidence_id: EVIDENCE_ID,
    case_id: CASE_ID,
    filename: FILENAME,
    detected_host: "DC02",
    size_bytes: 4_255_670_272,
    created_at: "2026-06-22T11:00:00.000Z",
    processed_at: "2026-06-22T11:00:00.000Z",
    ingest_status: "completed",
    metadata: {},
    families: [],
    run_count: 3,
    latest_run_id: null,
    latest_run_status: "failed",
    detection_status: "confirmed_memory",
    detected_format: "windows_crash_dump",
    detection_confidence: "high",
    detection_reason: null,
    operator_override: false,
    operator_override_reason: null,
    operator_override_at: null,
    probe_version: "v1",
    probed_at: "2026-06-22T11:00:00.000Z",
    can_analyze: true,
    symbol_status: "missing",
    symbol_requirement: {
      pdb_name: "ntkrnlpa.pdb",
      pdb_guid: "12345678123456781234567812345678",
      pdb_age: 3,
      architecture: "x86",
    },
    symbol_blocker: "Windows symbols required for this evidence are not cached.",
    can_analyze_metadata: false,
    can_run_all: false,
    symbol_error_code: "MEMORY_SYMBOLS_REQUIRED",
    ...overrides,
  };
}

function makeReadiness(
  overrides: Partial<MemorySymbolReadiness> = {},
): MemorySymbolReadiness {
  return {
    evidence_id: EVIDENCE_ID,
    state: "missing",
    requirement: {
      pdb_name: "ntkrnlpa.pdb",
      pdb_guid: "12345678123456781234567812345678",
      pdb_age: 3,
      architecture: "x86",
    },
    cache: {
      cache_status: "miss",
      exact_match: false,
      required_identifier: "ntkrnlpa.pdb/12345678123456781234567812345678-3",
      cached_identifiers: [
        "ntoskrnl.pdb/AABBCCDDAABBCCDDAABBCCDDAABBCCDD-10",
      ],
      matched: null,
    },
    last_probe: "2026-06-22T11:00:00.000Z",
    last_acquisition: null,
    can_analyze_metadata: false,
    can_run_all: false,
    blocker: "Windows symbols required for this evidence are not cached.",
    error_code: "MEMORY_SYMBOLS_REQUIRED",
    sanitized_message: "Windows symbols required for this evidence are not cached.",
    acquisition_supported: true,
    pending_request_id: null,
    ...overrides,
  };
}

function makeCatalogue(): MemoryAnalysisCatalogue {
  return {
    case_id: CASE_ID,
    evidence_id: EVIDENCE_ID,
    items: [
      {
        profile: "metadata_only",
        family: "system_info",
        title: "System metadata",
        description: "windows.info block",
        cost_label: "Fast",
        est_duration_seconds: 20,
        available: false,
        availability_reason: "Symbols for this evidence are not cached (state: missing).",
        last_run: null,
        last_status: null,
        last_count: 0,
        requires_windows_symbols: true,
        can_run_without_symbols: false,
        supported_os_families: ["windows"],
      },
      {
        profile: "processes_basic",
        family: "processes",
        title: "Standard process analysis",
        description: "Active processes",
        cost_label: "Medium",
        est_duration_seconds: 90,
        available: false,
        availability_reason: "Symbols for this evidence are not cached (state: missing).",
        last_run: null,
        last_status: null,
        last_count: 0,
        requires_windows_symbols: true,
        can_run_without_symbols: false,
        supported_os_families: ["windows"],
      },
    ],
  };
}

type ApiMock = {
  [K in keyof typeof api]?: ReturnType<typeof vi.fn>;
};

function buildApiMock(): ApiMock {
  return {
    getMemoryOverview: vi.fn(async () => ({
      case_id: CASE_ID,
      memory_analysis_enabled: true,
      memory_process_profile_enabled: true,
      has_memory_evidence: true,
      has_memory_results: false,
      has_disk_events: false,
      mode: "memory_only",
      evidences: [
        {
          evidence_id: EVIDENCE_ID,
          case_id: CASE_ID,
          filename: FILENAME,
          detection_status: "confirmed_memory",
          detected_format: "windows_crash_dump",
          detection_confidence: "high",
          detection_reason: null,
          operator_override: false,
          probe_version: "v1",
          probed_at: "2026-06-22T11:00:00.000Z",
          can_analyze: true,
          run_count: 3,
          latest_run_status: "failed",
          ingest_status: "completed",
          last_profile_attempted: "metadata_only",
          last_error_code: "SYMBOLS_UNAVAILABLE",
          last_error_message: "windows.info could not resolve the required Windows symbols under offline-only mode.",
        },
      ],
      runs: [],
      message: "",
      run_count: 3,
      last_run_id: null,
      last_run_status: "failed",
      worker_online: true,
      worker_message: null,
    })),
    getMemoryEvidenceLanding: vi.fn(async () => ({
      case_id: CASE_ID,
      items: [makeEvidence()],
    })),
    getMemoryActiveResult: vi.fn(async () => ({
      case_id: CASE_ID,
      evidence_id: EVIDENCE_ID,
      family: "system_info",
      active_run: null,
      latest_attempt: null,
      using_fallback: false,
      historical_override: false,
      selection_reason: "no_active_run",
      analysis_state: "no_active_run",
    })),
    getMemoryAnalysisCatalogue: vi.fn(async () => makeCatalogue()),
    getMemoryBackendOverview: vi.fn(async () => ({
      backends: [
        {
          backend: "volatility3",
          ready: true,
          message: "Volatility 3 is ready",
          worker_dedicated: true,
          worker_image_id: "sha256:abc",
          worker_pid: 1,
        },
      ],
    })),
    getActiveMemoryAnalysisBatch: vi.fn(async () => {
      const err = new Error("not found");
      (err as { status?: number }).status = 404;
      throw err;
    }),
    getMemoryEvidenceReadiness: vi.fn(async () => ({
      evidence_id: EVIDENCE_ID,
      exists: true,
      regular_file: true,
      readable_by_memory_worker: true,
      size_matches: true,
      output_writable_by_memory_worker: true,
      can_analyze: true,
      error_code: null,
      sanitized_message: "Memory evidence is available to the dedicated memory worker.",
      symbols_required: true,
      symbol_identifier_present: true,
      acquisition_available: true,
      acquisition_status: "missing",
      can_analyze_offline: false,
    })),
    getMemorySymbolReadiness: vi.fn(async () => makeReadiness()),
    probeMemorySymbolRequirement: vi.fn(async () => ({
      evidence_id: EVIDENCE_ID,
      status: "identified",
      requirement: {
        pdb_name: "ntkrnlpa.pdb",
        pdb_guid: "12345678123456781234567812345678",
        pdb_age: 3,
        architecture: "x86",
      },
      probable_os: "windows",
      layer: null,
      confidence: "high",
      failure_reason: null,
      error_code: null,
      sanitized_message: null,
      duration_ms: 1234,
    })),
    requestMemorySymbolAcquisition: vi.fn(async () => ({
      request_id: "req-1",
      status: "awaiting_operator_approval",
      source_category: "official_microsoft_symbols",
      pending_request_id: "req-1",
      requirement_fingerprint: "deadbeef",
      error_code: null,
      message: "A symbol acquisition request was recorded.",
    })),
  };
}

function setup(
  apiMock: ApiMock,
  url = `/cases/${CASE_ID}/memory/${EVIDENCE_ID}?tab=overview`,
) {
  const client = makeQueryClient();
  // Inject the API mock into the module-level holder; the vi.mock
  // factory above exposes the right value when the page calls
  // ``api.<method>``.
  Object.keys(mockApi).forEach((key) => {
    delete mockApi[key];
  });
  Object.entries(apiMock).forEach(([key, value]) => {
    if (value) {
      mockApi[key] = value;
    }
  });
  window.history.pushState({}, "", url);
  return render(
    <QueryClientProvider client={client}>
      <ActiveCaseProvider>
        <MemoryRouter initialEntries={[url]}>
          <Routes>
            <Route
              path="/cases/:caseId/memory/:evidenceId"
              element={<MemoryEvidencePage />}
            />
          </Routes>
        </MemoryRouter>
      </ActiveCaseProvider>
    </QueryClientProvider>,
  );
}

beforeEach(() => {
  Object.keys(mockApi).forEach((key) => {
    delete mockApi[key];
  });
});

describe("Per-evidence Windows symbol resolution", () => {
  it("shows a per-evidence symbol badge with the required PDB / GUID / age", async () => {
    const apiMock = buildApiMock();
    setup(apiMock);
    const panel = await screen.findByTestId("memory-symbol-resolution-panel");
    expect(panel).toHaveAttribute("data-state", "missing");
    expect(within(panel).getByTestId("memory-symbol-state-label")).toHaveTextContent(
      /Missing for this evidence/i,
    );
    expect(within(panel).getByTestId("memory-symbol-pdb-name")).toHaveTextContent("ntkrnlpa.pdb");
    expect(within(panel).getByTestId("memory-symbol-architecture")).toHaveTextContent("x86");
    expect(within(panel).getByTestId("memory-symbol-pdb-guid")).toHaveTextContent(
      "12345678123456781234567812345678",
    );
    expect(within(panel).getByTestId("memory-symbol-pdb-age")).toHaveTextContent("3");
  });

  it("shows a missing symbols state with cache miss / exact_match=false", async () => {
    const apiMock = buildApiMock();
    setup(apiMock);
    const panel = await screen.findByTestId("memory-symbol-resolution-panel");
    expect(within(panel).getByTestId("memory-symbol-cache-status")).toHaveTextContent(/Cache status:\s*miss/);
    expect(within(panel).getByTestId("memory-symbol-cache-exact-match")).toHaveTextContent("false");
    expect(within(panel).getByTestId("memory-symbol-required-identifier")).toHaveTextContent(
      /required: ntkrnlpa\.pdb\/12345678123456781234567812345678-3/,
    );
  });

  it("disables the Run analysis button when symbols are missing", async () => {
    const apiMock = buildApiMock();
    setup(apiMock);
    const runButton = await screen.findByTestId("memory-open-catalogue");
    expect(runButton).toBeDisabled();
  });

  it("renders an Acquire symbols button when acquisition is supported", async () => {
    const apiMock = buildApiMock();
    setup(apiMock);
    expect(
      await screen.findByTestId("memory-symbol-acquire-button"),
    ).toBeInTheDocument();
  });

  it("opens the acquisition modal and exposes the PDB / GUID read-only", async () => {
    const user = userEvent.setup();
    const apiMock = buildApiMock();
    setup(apiMock);
    const acquire = await screen.findByTestId("memory-symbol-acquire-button");
    await user.click(acquire);
    const modal = await screen.findByTestId("memory-symbol-acquire-modal");
    expect(modal).toHaveAttribute("role", "dialog");
    expect(modal).toHaveAttribute("aria-modal", "true");
    expect(within(modal).getByTestId("memory-symbol-acquire-pdb")).toHaveTextContent("ntkrnlpa.pdb");
    expect(within(modal).getByTestId("memory-symbol-acquire-guid")).toHaveTextContent(
      "12345678123456781234567812345678",
    );
    expect(within(modal).getByTestId("memory-symbol-acquire-age")).toHaveTextContent("3");
    expect(within(modal).getByTestId("memory-symbol-acquire-arch")).toHaveTextContent("x86");
    // No arbitrary inputs: only the acknowledgement checkbox is
    // interactive; the identifier fields are not editable.
    expect(within(modal).queryByRole("textbox")).toBeNull();
  });

  it("requires the authorization checkbox before the acquisition can be requested", async () => {
    const user = userEvent.setup();
    const apiMock = buildApiMock();
    setup(apiMock);
    const acquire = await screen.findByTestId("memory-symbol-acquire-button");
    await user.click(acquire);
    const modal = await screen.findByTestId("memory-symbol-acquire-modal");
    const confirm = within(modal).getByTestId("memory-symbol-acquire-confirm");
    expect(confirm).toBeDisabled();
    const checkbox = within(modal).getByTestId("memory-symbol-acquire-ack-checkbox");
    await user.click(checkbox);
    expect(confirm).toBeEnabled();
    await user.click(confirm);
    await waitFor(() => {
      expect(apiMock.requestMemorySymbolAcquisition).toHaveBeenCalledWith(
        CASE_ID,
        EVIDENCE_ID,
        true,
      );
    });
  });

  it("does not expose a path or URL in the acquisition modal", async () => {
    const user = userEvent.setup();
    const apiMock = buildApiMock();
    setup(apiMock);
    const acquire = await screen.findByTestId("memory-symbol-acquire-button");
    await user.click(acquire);
    const modal = await screen.findByTestId("memory-symbol-acquire-modal");
    const text = modal.textContent || "";
    expect(text).not.toMatch(/https?:\/\//i);
    expect(text).not.toMatch(/\/var\/|\/tmp\/|\/home\//i);
    expect(text).not.toMatch(/download/i);
  });

  it("cancels the acquisition modal without calling the API", async () => {
    const user = userEvent.setup();
    const apiMock = buildApiMock();
    setup(apiMock);
    const acquire = await screen.findByTestId("memory-symbol-acquire-button");
    await user.click(acquire);
    const modal = await screen.findByTestId("memory-symbol-acquire-modal");
    await user.click(within(modal).getByTestId("memory-symbol-acquire-cancel"));
    expect(apiMock.requestMemorySymbolAcquisition).not.toHaveBeenCalled();
  });

  it("renders the structured blocker banner with error code when the symbol is missing", async () => {
    const apiMock = buildApiMock();
    setup(apiMock);
    const banner = await screen.findByTestId("memory-symbol-blocker-banner");
    expect(banner).toHaveAttribute("data-state", "missing");
    expect(within(banner).getByTestId("memory-symbol-blocker-message")).toHaveTextContent(
      /Windows symbols required for this evidence are not cached/i,
    );
    expect(within(banner).getByTestId("memory-symbol-blocker-code")).toHaveTextContent(
      "MEMORY_SYMBOLS_REQUIRED",
    );
  });

  it("does not display any raw server URL or 'server error' string", async () => {
    const apiMock = buildApiMock();
    setup(apiMock);
    await screen.findByTestId("memory-symbol-resolution-panel");
    const dom = document.body.textContent || "";
    expect(dom).not.toMatch(/server error/i);
    expect(dom).not.toMatch(/The analysis request failed on the server/i);
    expect(dom).not.toMatch(/https?:\/\/192\.168\./);
  });

  it("disables Run analysis with no generic server error when acquisition is unsupported", async () => {
    const apiMock = buildApiMock();
    (apiMock.getMemorySymbolReadiness as ReturnType<typeof vi.fn>).mockResolvedValue(
      makeReadiness({
        state: "missing",
        acquisition_supported: false,
        sanitized_message: "Offline-only mode is active. Acquisition is unavailable in this deployment.",
        blocker: "Offline-only mode is active. Acquisition is unavailable in this deployment.",
      }),
    );
    setup(apiMock);
    const runButton = await screen.findByTestId("memory-open-catalogue");
    expect(runButton).toBeDisabled();
    expect(runButton).toHaveAttribute("title");
    // No acquire button when acquisition is not supported.
    expect(screen.queryByTestId("memory-symbol-acquire-button")).toBeNull();
  });

  it("re-runs the probe via the button and refreshes the readiness", async () => {
    const user = userEvent.setup();
    const apiMock = buildApiMock();
    let state: MemorySymbolReadiness = makeReadiness({ state: "unknown" });
    (apiMock.getMemorySymbolReadiness as ReturnType<typeof vi.fn>).mockImplementation(
      async () => state,
    );
    (apiMock.probeMemorySymbolRequirement as ReturnType<typeof vi.fn>).mockImplementation(async () => {
      state = makeReadiness({ state: "identified" });
      return {
        evidence_id: EVIDENCE_ID,
        status: "identified",
        requirement: {
          pdb_name: "ntkrnlpa.pdb",
          pdb_guid: "12345678123456781234567812345678",
          pdb_age: 3,
          architecture: "x86",
        },
        probable_os: "windows",
        layer: null,
        confidence: "high",
        failure_reason: null,
        error_code: null,
        sanitized_message: null,
        duration_ms: 100,
      };
    });
    setup(apiMock);
    const probe = await screen.findByTestId("memory-symbol-probe-button");
    await user.click(probe);
    await waitFor(() => {
      expect(apiMock.probeMemorySymbolRequirement).toHaveBeenCalledWith(
        CASE_ID,
        EVIDENCE_ID,
      );
    });
  });
});
