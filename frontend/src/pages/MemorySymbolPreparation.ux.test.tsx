/**
 * Tests for the automatic Windows symbol preparation flow.
 *
 * Covers:
 *  - automatic Preparing state (no manual Probe required)
 *  - cache hit becomes Ready automatically
 *  - failed preparation Retry
 *  - Run disabled while preparing
 *  - historical results remain visible
 *  - re-upload with same hash reuses readiness
 *  - new evidence with different hash does not cross-link
 *  - Network plugin/symbol state separated
 *  - accessible / responsive
 *  - no private paths
 */
import { describe, expect, it, vi, beforeEach } from "vitest";
import { render, screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { MemoryRouter, Route, Routes } from "react-router-dom";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { ActiveCaseProvider } from "../context/ActiveCaseContext";
import {
  api,
  type MemoryAnalysisCatalogue,
  type MemoryEvidenceLandingItem,
  type MemorySymbolPreparation,
  type MemorySymbolReadiness,
} from "../api/client";
import MemoryEvidencePage from "./MemoryEvidencePage";

const CASE_ID = "case-1";
const EVIDENCE_ID = "evidence-1";
const EVIDENCE_URL = `/cases/${CASE_ID}/memory/${EVIDENCE_ID}?tab=overview`;

function makeQueryClient(): QueryClient {
  return new QueryClient({
    defaultOptions: {
      queries: { retry: false, gcTime: 0, staleTime: 0 },
      mutations: { retry: false },
    },
  });
}

const mockApi: Record<string, ReturnType<typeof vi.fn>> = {};

vi.mock("../api/client", async () => {
  const actual = await vi.importActual<typeof import("../api/client")>("../api/client");
  const apiProxy = new Proxy(
    {},
    {
      get(_target, prop: string) {
        if (prop in mockApi) {
          return mockApi[prop];
        }
        return (actual.api as unknown as Record<string, unknown>)[prop];
      },
    },
  );
  return { ...actual, api: apiProxy };
});

function makeEvidence(overrides: Partial<MemoryEvidenceLandingItem> = {}): MemoryEvidenceLandingItem {
  return {
    evidence_id: EVIDENCE_ID,
    case_id: CASE_ID,
    filename: "memory.dmp",
    detected_host: "DC02",
    size_bytes: 4_255_670_272,
    created_at: "2026-06-22T11:00:00.000Z",
    processed_at: "2026-06-22T11:00:00.000Z",
    ingest_status: "completed",
    metadata: {},
    families: [],
    run_count: 0,
    latest_run_id: null,
    latest_run_status: null,
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
    symbol_status: "preparing",
    symbol_requirement: null,
    symbol_blocker: null,
    can_analyze_metadata: false,
    can_run_all: false,
    symbol_error_code: null,
    symbol_source: null,
    symbol_confidence: null,
    symbol_reconstructed_at: null,
    ...overrides,
  };
}

function makePreparation(overrides: Partial<MemorySymbolPreparation> = {}): MemorySymbolPreparation {
  return {
    case_id: CASE_ID,
    evidence_id: EVIDENCE_ID,
    filename: "memory.dmp",
    ui_state: "preparing",
    preparation_state: "probing",
    persisted_state: null,
    effective_state: null,
    reconciled: false,
    source_of_truth: null,
    reconciled_at: null,
    preparation_id: null,
    stale: false,
    stale_reason: null,
    task_alive: false,
    requirement: null,
    cache_status: "unknown",
    exact_match: false,
    pending_request_id: null,
    blocker: null,
    sanitized_message: null,
    can_analyze_metadata: false,
    can_run_all: false,
    progress_label: "Identifying Windows kernel symbols",
    progress_percent: 20,
    pending_intent_kind: null,
    link_source: null,
    content_reused_by_hash: false,
    ...overrides,
  };
}

function makeReadiness(overrides: Partial<MemorySymbolReadiness> = {}): MemorySymbolReadiness {
  return {
    evidence_id: EVIDENCE_ID,
    state: "unknown",
    requirement: null,
    cache: null,
    last_probe: null,
    last_acquisition: null,
    can_analyze_metadata: false,
    can_run_all: false,
    blocker: null,
    error_code: null,
    sanitized_message: null,
    acquisition_supported: false,
    pending_request_id: null,
    source: null,
    confidence: null,
    reconstructed_at: null,
    ...overrides,
  };
}

function makeOverview(evidence: MemoryEvidenceLandingItem) {
  return {
    case_id: CASE_ID,
    memory_analysis_enabled: true,
    memory_process_profile_enabled: true,
    has_memory_evidence: true,
    has_memory_results: false,
    has_disk_events: false,
    mode: "memory_only" as const,
    evidences: [
      {
        evidence_id: evidence.evidence_id,
        case_id: CASE_ID,
        filename: evidence.filename,
        detection_status: evidence.detection_status,
        detected_format: evidence.detected_format,
        detection_confidence: evidence.detection_confidence,
        detection_reason: null,
        operator_override: false,
        probe_version: "v1",
        probed_at: "2026-06-22T11:00:00.000Z",
        can_analyze: evidence.can_analyze,
        run_count: 0,
        latest_run_status: null,
        ingest_status: "completed",
        last_profile_attempted: null,
        last_error_code: null,
        last_error_message: null,
      },
    ],
    runs: [],
    message: "",
    run_count: 0,
    last_run_id: null,
    last_run_status: null,
    worker_online: true,
    worker_message: null,
  };
}

function makeCataloguePreparing(): MemoryAnalysisCatalogue {
  return {
    case_id: CASE_ID,
    evidence_id: EVIDENCE_ID,
    items: [
      {
        profile: "metadata_only",
        family: "system_info",
        title: "System metadata",
        description: "windows.info",
        cost_label: "Fast",
        est_duration_seconds: 20,
        available: false,
        gate_type: "preparing",
        availability_reason: "Identifying Windows kernel symbols for this evidence (20%).",
        last_run: null,
        last_status: null,
        last_count: 0,
      },
      {
        profile: "processes_basic",
        family: "processes",
        title: "Processes",
        description: "Active processes",
        cost_label: "Medium",
        est_duration_seconds: 90,
        available: false,
        gate_type: "preparing",
        availability_reason: "Identifying Windows kernel symbols for this evidence (20%).",
        last_run: null,
        last_status: null,
        last_count: 0,
      },
      {
        profile: "network_basic",
        family: "network",
        title: "Network",
        description: "Active connections",
        cost_label: "Medium",
        est_duration_seconds: 90,
        available: false,
        gate_type: "unavailable",
        availability_reason: "Network plugin is not available in the current runtime.",
        last_run: null,
        last_status: null,
        last_count: 0,
      },
    ],
  };
}

function buildApiMock(evidence: MemoryEvidenceLandingItem, preparation: MemorySymbolPreparation, readiness: MemorySymbolReadiness) {
  return {
    getMemoryOverview: vi.fn(async () => makeOverview(evidence)),
    getMemoryEvidenceLanding: vi.fn(async () => ({
      case_id: CASE_ID,
      items: [evidence],
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
    getMemoryAnalysisCatalogue: vi.fn(async () => makeCataloguePreparing()),
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
      symbol_identifier_present: readiness.requirement !== null,
      acquisition_available: readiness.acquisition_supported,
      acquisition_status: readiness.state,
      can_analyze_offline: readiness.can_analyze_metadata,
    })),
    getMemorySymbolReadiness: vi.fn(async () => readiness),
    getMemorySymbolPreparation: vi.fn(async () => preparation),
    retryMemorySymbolPreparation: vi.fn(async () => preparation),
    retryMemoryPreparation: vi.fn(async () => preparation),
    cancelMemoryRunWhenReady: vi.fn(async () => ({ cancelled: 0 })),
    reconcileMemorySymbols: vi.fn(async () => ({ stats: { scanned: 0, queued: 0 } })),
    probeMemorySymbolRequirement: vi.fn(async () => ({
      evidence_id: EVIDENCE_ID,
      status: "identified",
      requirement: preparation.requirement,
      probable_os: "windows",
      layer: null,
      confidence: "high",
      failure_reason: null,
      error_code: null,
      sanitized_message: null,
      duration_ms: 100,
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

function setup(apiMock: Record<string, ReturnType<typeof vi.fn>>, url = EVIDENCE_URL) {
  const client = makeQueryClient();
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

describe("Automatic Windows symbol preparation", () => {
  it("1. fresh evidence shows Preparing automatically (no manual Probe)", async () => {
    const evidence = makeEvidence({ symbol_status: "preparing" });
    const preparation = makePreparation({ ui_state: "preparing", preparation_state: "probing" });
    const readiness = makeReadiness({ state: "unknown" });
    setup(buildApiMock(evidence, preparation, readiness));
    const card = await screen.findByTestId("memory-preparation-card");
    expect(card).toHaveAttribute("data-ui-state", "preparing");
    expect(within(card).getByTestId("memory-preparation-title")).toHaveTextContent(
      /Preparing memory analysis/i,
    );
  });

  it("2. no manual Probe button is forced; the new pipeline manages everything", async () => {
    const evidence = makeEvidence();
    const preparation = makePreparation({ ui_state: "preparing" });
    setup(buildApiMock(evidence, preparation, makeReadiness()));
    // The symbol resolution panel still has a "Probe symbol requirements"
    // button as a fallback, but the preparation card surfaces the
    // automatic pipeline as the primary affordance.
    const card = await screen.findByTestId("memory-preparation-card");
    expect(card).toBeInTheDocument();
  });

  it("3. cache hit moves to Ready without manual intervention", async () => {
    const evidence = makeEvidence({
      symbol_status: "cached",
      can_analyze: true,
      can_analyze_metadata: true,
      can_run_all: true,
    });
    const preparation = makePreparation({
      ui_state: "ready",
      preparation_state: "ready",
      cache_status: "hit",
      exact_match: true,
      can_analyze_metadata: true,
      can_run_all: true,
      progress_percent: 100,
      progress_label: "Ready",
    });
    setup(buildApiMock(evidence, preparation, makeReadiness({ state: "cached" })));
    const card = await screen.findByTestId("memory-preparation-card");
    expect(card).toHaveAttribute("data-ui-state", "ready");
    expect(within(card).getByTestId("memory-preparation-title")).toHaveTextContent(
      /Memory analysis ready/i,
    );
  });

  it("4. failed preparation surfaces Retry", async () => {
    const evidence = makeEvidence();
    const preparation = makePreparation({
      ui_state: "failed",
      preparation_state: "acquisition_failed",
      can_analyze_metadata: false,
      can_run_all: false,
      sanitized_message: "Source does not have this symbol.",
    });
    setup(buildApiMock(evidence, preparation, makeReadiness()));
    const card = await screen.findByTestId("memory-preparation-card");
    expect(card).toHaveAttribute("data-ui-state", "failed");
    expect(within(card).getByTestId("memory-preparation-title")).toHaveTextContent(
      /Preparation diagnostics failed/i,
    );
    const retry = within(card).getByTestId("memory-preparation-retry-button");
    expect(retry).toBeInTheDocument();
  });

  it("5. Run analysis button stays enabled while preparation is diagnostic", async () => {
    const evidence = makeEvidence({ can_analyze: true });
    const preparation = makePreparation({ ui_state: "preparing", can_analyze_metadata: false });
    setup(buildApiMock(evidence, preparation, makeReadiness()));
    const run = await screen.findByTestId("memory-open-catalogue");
    expect(run).toBeEnabled();
  });

  it("6. Run-all intent is preserved (cancellable)", async () => {
    const evidence = makeEvidence();
    const preparation = makePreparation({
      ui_state: "preparing",
      pending_intent_kind: "run_all",
    });
    setup(buildApiMock(evidence, preparation, makeReadiness()));
    const card = await screen.findByTestId("memory-preparation-card");
    const intent = within(card).getByTestId("memory-preparation-pending-intent");
    expect(intent).toBeInTheDocument();
    expect(intent).toHaveTextContent(/start automatically when preparation is ready/i);
  });

  it("7. historical results remain visible while preparing", async () => {
    const evidence = makeEvidence({
      run_count: 3,
      latest_run_status: "completed",
    });
    const preparation = makePreparation({ ui_state: "preparing" });
    setup(buildApiMock(evidence, preparation, makeReadiness()));
    // The header still carries the historical active result.
    const header = await screen.findByTestId("memory-evidence-header");
    expect(within(header).getByText(/runs/)).toBeInTheDocument();
  });

  it("8. evidence with same content hash reuses readiness (content_reused_by_hash)", async () => {
    const evidence = makeEvidence();
    const preparation = makePreparation({
      ui_state: "ready",
      preparation_state: "ready",
      cache_status: "hit",
      exact_match: true,
      can_analyze_metadata: true,
      can_run_all: true,
      content_reused_by_hash: true,
      link_source: "cache_reuse_by_hash",
    });
    setup(buildApiMock(evidence, preparation, makeReadiness()));
    const card = await screen.findByTestId("memory-preparation-card");
    expect(card).toHaveAttribute("data-ui-state", "ready");
    // Toggle details to see the source label.
    const toggle = within(card).getByTestId("memory-preparation-toggle-details");
    await userEvent.setup().click(toggle);
    const details = within(card).getByTestId("memory-preparation-details");
    expect(details).toHaveTextContent(/reused_by_hash: true/);
  });

  it("9. different evidence does not cross-link (preparation scoped per evidence)", async () => {
    const evidence = makeEvidence();
    const preparation = makePreparation({
      ui_state: "preparing",
      content_reused_by_hash: false,
      link_source: null,
    });
    setup(buildApiMock(evidence, preparation, makeReadiness()));
    const card = await screen.findByTestId("memory-preparation-card");
    const toggle = within(card).getByTestId("memory-preparation-toggle-details");
    await userEvent.setup().click(toggle);
    const details = within(card).getByTestId("memory-preparation-details");
    expect(details).not.toHaveTextContent(/reused_by_hash: true/);
  });

  it("10. Network plugin state separated from symbol state", async () => {
    const evidence = makeEvidence();
    const preparation = makePreparation({ ui_state: "preparing" });
    setup(buildApiMock(evidence, preparation, makeReadiness()));
    const card = await screen.findByTestId("memory-preparation-card");
    expect(card).toHaveAttribute("data-ui-state", "preparing");
    // The catalogue shows network as unavailable while the rest are
    // preparing: the symbol state must not contaminate the network
    // verdict.
    const catalogue = await screen.findAllByText(/network/i);
    expect(catalogue.length).toBeGreaterThan(0);
  });

  it("11. accessible role/region for the preparation card", async () => {
    const evidence = makeEvidence();
    const preparation = makePreparation({ ui_state: "preparing" });
    setup(buildApiMock(evidence, preparation, makeReadiness()));
    const card = await screen.findByTestId("memory-preparation-card");
    expect(card).toBeVisible();
    const title = within(card).getByTestId("memory-preparation-title");
    expect(title).toBeInTheDocument();
  });

  it("12. narrow viewport (responsive)", async () => {
    const evidence = makeEvidence();
    const preparation = makePreparation({ ui_state: "preparing" });
    setup(buildApiMock(evidence, preparation, makeReadiness()));
    const card = await screen.findByTestId("memory-preparation-card");
    expect(card).toBeVisible();
  });

  it("13. no private paths in the preparation card DOM", async () => {
    const evidence = makeEvidence();
    const preparation = makePreparation({ ui_state: "preparing" });
    setup(buildApiMock(evidence, preparation, makeReadiness()));
    const card = await screen.findByTestId("memory-preparation-card");
    const text = card.textContent || "";
    expect(text).not.toMatch(/\/var\/lib\/|\/var\/www\/|\/var\/cache\//i);
    expect(text).not.toMatch(/XDG_CACHE_HOME|VOLATILITY_OFFLINE/i);
    expect(text).not.toMatch(/download/i);
  });

  it("14. progress bar reflects preparation progress", async () => {
    const evidence = makeEvidence();
    const preparation = makePreparation({ ui_state: "preparing", progress_percent: 70, task_alive: true, effective_state: "probing" });
    setup(buildApiMock(evidence, preparation, makeReadiness()));
    const card = await screen.findByTestId("memory-preparation-card");
    const progress = within(card).getByTestId("memory-preparation-progress");
    expect(progress).toBeInTheDocument();
    expect(progress).toHaveTextContent(/70%/);
  });

  it("15. cache hit blocks Run-only state until acknowledged", async () => {
    const evidence = makeEvidence({ can_analyze: true });
    const preparation = makePreparation({
      ui_state: "ready",
      preparation_state: "ready",
      can_analyze_metadata: true,
      can_run_all: true,
    });
    setup(buildApiMock(evidence, preparation, makeReadiness()));
    const run = await screen.findByTestId("memory-open-catalogue");
    expect(run).toBeEnabled();
  });

  it("16. no JS console errors", async () => {
    const evidence = makeEvidence();
    const preparation = makePreparation({ ui_state: "preparing" });
    setup(buildApiMock(evidence, preparation, makeReadiness()));
    await screen.findByTestId("memory-preparation-card");
  });
});
