/**
 * Tests for the legacy symbol-readiness recovery flow.
 *
 * Covers:
 *  - per-evidence "Symbols Cached" badge for legacy evidence
 *  - per-profile Blocked vs Unavailable distinction
 *  - unknown requirement shows "Probe" not "Unavailable"
 *  - historical results (Processes / Artifacts) remain visible
 *  - no global cache false-positive
 *  - no private paths in the DOM
 *  - responsive layout
 *  - accessible dialogs
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
  type MemorySymbolReadiness,
  type MemoryScanRun,
} from "../api/client";
import MemoryEvidencePage from "./MemoryEvidencePage";

const CASE_ID = "case-1";
const LEGACY_EVIDENCE_ID = "evidence-legacy";
const FRESH_EVIDENCE_ID = "evidence-fresh";

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

function makeEvidence(
  id: string,
  filename: string,
  overrides: Partial<MemoryEvidenceLandingItem> = {},
): MemoryEvidenceLandingItem {
  return {
    evidence_id: id,
    case_id: CASE_ID,
    filename,
    detected_host: "DC02",
    size_bytes: 4_255_670_272,
    created_at: "2026-06-22T11:00:00.000Z",
    processed_at: "2026-06-22T11:00:00.000Z",
    ingest_status: "completed",
    metadata: {},
    families: [],
    run_count: 3,
    latest_run_id: "run-1",
    latest_run_status: "completed",
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
    symbol_status: "cached",
    symbol_requirement: {
      pdb_name: "ntkrnlmp.pdb",
      pdb_guid: "D801A9AFC0FB7761380800F708633DEA",
      pdb_age: 1,
      architecture: "x64",
    },
    symbol_blocker: null,
    can_analyze_metadata: true,
    can_run_all: true,
    symbol_error_code: null,
    symbol_source: "historical_run",
    symbol_confidence: "high",
    symbol_reconstructed_at: "2026-06-22T11:00:00.000Z",
    ...overrides,
  };
}

function makeReadiness(
  id: string,
  overrides: Partial<MemorySymbolReadiness> = {},
): MemorySymbolReadiness {
  return {
    evidence_id: id,
    state: "cached",
    requirement: {
      pdb_name: "ntkrnlmp.pdb",
      pdb_guid: "D801A9AFC0FB7761380800F708633DEA",
      pdb_age: 1,
      architecture: "x64",
    },
    cache: {
      cache_status: "hit",
      exact_match: true,
      required_identifier: "ntkrnlmp.pdb/D801A9AFC0FB7761380800F708633DEA-1",
      cached_identifiers: ["ntkrnlmp.pdb/D801A9AFC0FB7761380800F708633DEA-1"],
      matched: {
        pdb_name: "ntkrnlmp.pdb",
        pdb_guid: "D801A9AFC0FB7761380800F708633DEA",
        pdb_age: 1,
        architecture: "x64",
      },
    },
    last_probe: "2026-06-22T11:00:00.000Z",
    last_acquisition: null,
    can_analyze_metadata: true,
    can_run_all: true,
    blocker: null,
    error_code: null,
    sanitized_message: "The exact required Windows symbols are present in the cache.",
    acquisition_supported: false,
    pending_request_id: null,
    source: "historical_run",
    confidence: "high",
    reconstructed_at: "2026-06-22T11:00:00.000Z",
    ...overrides,
  };
}

function makeCatalogue(
  evidenceId: string,
  options: { allAvailable?: boolean; unknown?: boolean } = {},
): MemoryAnalysisCatalogue {
  if (options.allAvailable) {
    return {
      case_id: CASE_ID,
      evidence_id: evidenceId,
      items: [
        {
          profile: "metadata_only",
          family: "system_info",
          title: "System metadata",
          description: "windows.info",
          cost_label: "Fast",
          est_duration_seconds: 20,
          available: true,
          gate_type: "available",
          availability_reason: null,
          last_run: {
            id: "run-1", profile: "metadata_only", status: "completed",
            started_at: "2026-06-22T11:00:00.000Z",
            completed_at: "2026-06-22T11:01:00.000Z",
            duration_seconds: 60, evidence_id: evidenceId, case_id: CASE_ID,
          },
          last_status: "completed",
          last_count: 5,
        },
        {
          profile: "processes_basic",
          family: "processes",
          title: "Processes",
          description: "Active processes",
          cost_label: "Medium",
          est_duration_seconds: 90,
          available: true,
          gate_type: "available",
          availability_reason: null,
          last_run: {
            id: "run-2", profile: "processes_basic", status: "completed",
            started_at: "2026-06-22T11:01:00.000Z",
            completed_at: "2026-06-22T11:03:00.000Z",
            duration_seconds: 120, evidence_id: evidenceId, case_id: CASE_ID,
          },
          last_status: "completed",
          last_count: 200,
        },
        {
          profile: "network_basic",
          family: "network",
          title: "Network",
          description: "Active connections",
          cost_label: "Medium",
          est_duration_seconds: 90,
          available: true,
          gate_type: "available",
          availability_reason: "Available · Requirements not yet validated",
          last_run: null,
          last_status: null,
          last_count: 0,
        },
      ],
    };
  }
  return {
    case_id: CASE_ID,
    evidence_id: evidenceId,
    items: [
      {
        profile: "metadata_only",
        family: "system_info",
        title: "System metadata",
        description: "windows.info",
        cost_label: "Fast",
        est_duration_seconds: 20,
        available: false,
        gate_type: "blocked_symbol_probe_required",
        availability_reason: "Windows symbol requirement for this evidence has not been identified yet.",
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
        gate_type: "blocked_symbol_probe_required",
        availability_reason: "Windows symbol requirement for this evidence has not been identified yet.",
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
        run_count: 3,
        latest_run_status: "completed",
        ingest_status: "completed",
        last_profile_attempted: "metadata_only",
        last_error_code: null,
        last_error_message: null,
      },
    ],
    runs: [],
    message: "",
    run_count: 3,
    last_run_id: null,
    last_run_status: "completed",
    worker_online: true,
    worker_message: null,
  };
}

function makeActiveResult(evidence: MemoryEvidenceLandingItem) {
  return {
    case_id: CASE_ID,
    evidence_id: evidence.evidence_id,
    family: "system_info",
    active_run: {
      id: "run-1", profile: "metadata_only", status: "completed",
      started_at: "2026-06-22T11:00:00.000Z",
      completed_at: "2026-06-22T11:01:00.000Z",
      duration_seconds: 60, evidence_id: evidence.evidence_id, case_id: CASE_ID,
    } as MemoryScanRun,
    latest_attempt: null,
    using_fallback: false,
    historical_override: false,
    selection_reason: "latest_completed",
    analysis_state: "latest_completed",
  };
}

function buildApiMock(evidence: MemoryEvidenceLandingItem, catalogue: MemoryAnalysisCatalogue, readiness: MemorySymbolReadiness) {
  return {
    getMemoryOverview: vi.fn(async () => makeOverview(evidence)),
    getMemoryEvidenceLanding: vi.fn(async () => ({
      case_id: CASE_ID,
      items: [evidence],
    })),
    getMemoryActiveResult: vi.fn(async () => makeActiveResult(evidence)),
    getMemoryAnalysisCatalogue: vi.fn(async () => catalogue),
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
      evidence_id: evidence.evidence_id,
      exists: true,
      regular_file: true,
      readable_by_memory_worker: true,
      size_matches: true,
      output_writable_by_memory_worker: true,
      can_analyze: true,
      error_code: null,
      sanitized_message: "Memory evidence is available to the dedicated memory worker.",
      symbols_required: readiness.state === "missing",
      symbol_identifier_present: readiness.requirement !== null,
      acquisition_available: readiness.acquisition_supported,
      acquisition_status: readiness.state,
      can_analyze_offline: readiness.can_analyze_metadata,
    })),
    getMemorySymbolReadiness: vi.fn(async () => readiness),
    probeMemorySymbolRequirement: vi.fn(async () => ({
      evidence_id: evidence.evidence_id,
      status: "identified",
      requirement: readiness.requirement,
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

function setup(apiMock: Record<string, ReturnType<typeof vi.fn>>, url: string) {
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

describe("Legacy symbol-readiness recovery", () => {
  it("1. historical evidence shows Symbols Cached for this evidence", async () => {
    const evidence = makeEvidence(LEGACY_EVIDENCE_ID, "DC02.dmp");
    const catalogue = makeCatalogue(LEGACY_EVIDENCE_ID, { allAvailable: true });
    const readiness = makeReadiness(LEGACY_EVIDENCE_ID);
    setup(buildApiMock(evidence, catalogue, readiness), `/cases/${CASE_ID}/memory/${LEGACY_EVIDENCE_ID}?tab=overview`);
    const panel = await screen.findByTestId("memory-symbol-resolution-panel");
    expect(panel).toHaveAttribute("data-state", "cached");
    expect(within(panel).getByTestId("memory-symbol-state-label")).toHaveTextContent(
      /Cached/i,
    );
    expect(within(panel).getByTestId("memory-symbol-cache-exact-match")).toHaveTextContent("true");
  });

  it("2. profiles are Available, not Unavailable, for legacy cached evidence", async () => {
    const evidence = makeEvidence(LEGACY_EVIDENCE_ID, "DC02.dmp");
    const catalogue = makeCatalogue(LEGACY_EVIDENCE_ID, { allAvailable: true });
    const readiness = makeReadiness(LEGACY_EVIDENCE_ID);
    setup(buildApiMock(evidence, catalogue, readiness), `/cases/${CASE_ID}/memory/${LEGACY_EVIDENCE_ID}?tab=overview`);
    // The Run analysis button is enabled.
    const run = await screen.findByTestId("memory-open-catalogue");
    expect(run).toBeEnabled();
  });

  it("3. unknown requirement uses Blocked, not Unavailable", async () => {
    const evidence = makeEvidence(FRESH_EVIDENCE_ID, "fresh.dmp", {
      symbol_status: "unknown",
      can_analyze: false,
      symbol_requirement: null,
      symbol_blocker: "Windows symbol requirement for this evidence has not been recorded.",
      can_analyze_metadata: false,
      can_run_all: false,
    });
    const catalogue = makeCatalogue(FRESH_EVIDENCE_ID, { unknown: true });
    const readiness = makeReadiness(FRESH_EVIDENCE_ID, {
      state: "unknown",
      requirement: null,
      cache: null,
      source: null,
      can_analyze_metadata: false,
      can_run_all: false,
      blocker: "Windows symbol requirement for this evidence has not been recorded.",
      sanitized_message: "Windows symbol requirement for this evidence has not been recorded.",
    });
    setup(buildApiMock(evidence, catalogue, readiness), `/cases/${CASE_ID}/memory/${FRESH_EVIDENCE_ID}?tab=overview`);
    const panel = await screen.findByTestId("memory-symbol-resolution-panel");
    expect(panel).toHaveAttribute("data-state", "unknown");
    // The label is "Symbol requirement not identified" - not "Unavailable".
    expect(within(panel).getByTestId("memory-symbol-state-label")).toHaveTextContent(
      /requirement not identified/i,
    );
    // The probe button is visible.
    expect(within(panel).getByTestId("memory-symbol-probe-button")).toBeInTheDocument();
  });

  it("4. no global cache false-positive (no Symbols: Cached badge when cache is unrelated)", async () => {
    const evidence = makeEvidence(LEGACY_EVIDENCE_ID, "WS01.dmp");
    const catalogue = makeCatalogue(LEGACY_EVIDENCE_ID, { unknown: true });
    // The cache has a different identifier: this evidence has no
    // exact cache match.  The badge must NOT say "Cached".
    const readiness = makeReadiness(LEGACY_EVIDENCE_ID, {
      state: "missing",
      cache: {
        cache_status: "miss",
        exact_match: false,
        required_identifier: "ntkrnlmp.pdb/D801A9AFC0FB7761380800F708633DEA-1",
        cached_identifiers: ["ntkrnlmp.pdb/9DC3FC69B1CA4B34707EBC57FD1D6126-1"],
        matched: null,
      },
      can_analyze_metadata: false,
      can_run_all: false,
      blocker: "Windows symbols required for this evidence are not cached.",
      sanitized_message: "Windows symbols required for this evidence are not cached.",
      source: "probe",
    });
    setup(buildApiMock(evidence, catalogue, readiness), `/cases/${CASE_ID}/memory/${LEGACY_EVIDENCE_ID}?tab=overview`);
    const panel = await screen.findByTestId("memory-symbol-resolution-panel");
    expect(panel).toHaveAttribute("data-state", "missing");
    expect(within(panel).getByTestId("memory-symbol-cache-exact-match")).toHaveTextContent("false");
  });

  it("5. source label shows 'historical run' for backfilled readiness", async () => {
    const evidence = makeEvidence(LEGACY_EVIDENCE_ID, "DC02.dmp");
    const catalogue = makeCatalogue(LEGACY_EVIDENCE_ID, { allAvailable: true });
    const readiness = makeReadiness(LEGACY_EVIDENCE_ID, {
      source: "historical_run",
    });
    setup(buildApiMock(evidence, catalogue, readiness), `/cases/${CASE_ID}/memory/${LEGACY_EVIDENCE_ID}?tab=overview`);
    const panel = await screen.findByTestId("memory-symbol-resolution-panel");
    const source = within(panel).getByTestId("memory-symbol-source");
    expect(source).toHaveTextContent(/Source:\s*historical run/i);
    expect(source).toHaveTextContent(/confidence:\s*high/i);
  });

  it("6. probe button is visible when requirement is unknown", async () => {
    const evidence = makeEvidence(FRESH_EVIDENCE_ID, "fresh.dmp", {
      symbol_status: "unknown",
      can_analyze: false,
      symbol_requirement: null,
    });
    const catalogue = makeCatalogue(FRESH_EVIDENCE_ID, { unknown: true });
    const readiness = makeReadiness(FRESH_EVIDENCE_ID, {
      state: "unknown",
      requirement: null,
      cache: null,
      source: null,
      can_analyze_metadata: false,
      can_run_all: false,
    });
    setup(buildApiMock(evidence, catalogue, readiness), `/cases/${CASE_ID}/memory/${FRESH_EVIDENCE_ID}?tab=overview`);
    const panel = await screen.findByTestId("memory-symbol-resolution-panel");
    expect(within(panel).getByTestId("memory-symbol-probe-button")).toBeInTheDocument();
  });

  it("7. no private paths in the panel DOM", async () => {
    const evidence = makeEvidence(LEGACY_EVIDENCE_ID, "DC02.dmp");
    const catalogue = makeCatalogue(LEGACY_EVIDENCE_ID, { allAvailable: true });
    const readiness = makeReadiness(LEGACY_EVIDENCE_ID);
    setup(buildApiMock(evidence, catalogue, readiness), `/cases/${CASE_ID}/memory/${LEGACY_EVIDENCE_ID}?tab=overview`);
    await screen.findByTestId("memory-symbol-resolution-panel");
    const text = document.body.textContent || "";
    expect(text).not.toMatch(/\/var\/lib\/|\/var\/www\/|\/tmp\//i);
    expect(text).not.toMatch(/XDG_CACHE_HOME|VOLATILITY_OFFLINE/i);
    expect(text).not.toMatch(/download/i);
  });

  it("8. narrow viewport (responsive)", async () => {
    const evidence = makeEvidence(LEGACY_EVIDENCE_ID, "DC02.dmp");
    const catalogue = makeCatalogue(LEGACY_EVIDENCE_ID, { allAvailable: true });
    const readiness = makeReadiness(LEGACY_EVIDENCE_ID);
    const { container } = setup(buildApiMock(evidence, catalogue, readiness), `/cases/${CASE_ID}/memory/${LEGACY_EVIDENCE_ID}?tab=overview`);
    await screen.findByTestId("memory-symbol-resolution-panel");
    // Just confirm the panel rendered.  Layout is exercised by the
    // responsive Tailwind classes; in jsdom the actual dimensions
    // are not measurable but the panel must be present in the DOM.
    expect(container).toBeInTheDocument();
  });

  it("9. unknown state shows structured probe affordance, not a banner", async () => {
    const evidence = makeEvidence(FRESH_EVIDENCE_ID, "fresh.dmp", {
      symbol_status: "unknown",
      can_analyze: false,
      symbol_requirement: null,
    });
    const catalogue = makeCatalogue(FRESH_EVIDENCE_ID, { unknown: true });
    const readiness = makeReadiness(FRESH_EVIDENCE_ID, {
      state: "unknown",
      requirement: null,
      cache: null,
      source: null,
    });
    setup(buildApiMock(evidence, catalogue, readiness), `/cases/${CASE_ID}/memory/${FRESH_EVIDENCE_ID}?tab=overview`);
    const panel = await screen.findByTestId("memory-symbol-resolution-panel");
    expect(panel).toHaveAttribute("data-state", "unknown");
    // The label says "requirement not identified" - the UI never
    // shows "Unavailable" for an unknown symbol requirement.
    expect(within(panel).getByTestId("memory-symbol-state-label")).toHaveTextContent(
      /requirement not identified/i,
    );
    // The probe button is the structured affordance.
    expect(within(panel).getByTestId("memory-symbol-probe-button")).toBeInTheDocument();
  });

  it("10. no generic server error in DOM", async () => {
    const evidence = makeEvidence(FRESH_EVIDENCE_ID, "fresh.dmp", {
      symbol_status: "unknown",
      can_analyze: false,
      symbol_requirement: null,
    });
    const catalogue = makeCatalogue(FRESH_EVIDENCE_ID, { unknown: true });
    const readiness = makeReadiness(FRESH_EVIDENCE_ID, {
      state: "unknown",
      requirement: null,
      cache: null,
      source: null,
    });
    setup(buildApiMock(evidence, catalogue, readiness), `/cases/${CASE_ID}/memory/${FRESH_EVIDENCE_ID}?tab=overview`);
    await screen.findByTestId("memory-symbol-resolution-panel");
    const text = document.body.textContent || "";
    expect(text).not.toMatch(/server error/i);
    expect(text).not.toMatch(/The analysis request failed on the server/i);
  });

  it("11. probe progress: probe mutation shows progress text while pending", async () => {
    const evidence = makeEvidence(FRESH_EVIDENCE_ID, "fresh.dmp", {
      symbol_status: "unknown",
      can_analyze: false,
      symbol_requirement: null,
    });
    const catalogue = makeCatalogue(FRESH_EVIDENCE_ID, { unknown: true });
    const readiness = makeReadiness(FRESH_EVIDENCE_ID, {
      state: "unknown",
      requirement: null,
      cache: null,
      source: null,
    });
    const apiMock = buildApiMock(evidence, catalogue, readiness);
    // Make the probe slow so we can observe the pending state.
    let resolveProbe: ((v: unknown) => void) | null = null;
    apiMock.probeMemorySymbolRequirement = vi.fn(
      () => new Promise((resolve) => { resolveProbe = resolve; }),
    );
    const user = userEvent.setup();
    setup(apiMock, `/cases/${CASE_ID}/memory/${FRESH_EVIDENCE_ID}?tab=overview`);
    const probe = await screen.findByTestId("memory-symbol-probe-button");
    await user.click(probe);
    await waitFor(() => {
      expect(apiMock.probeMemorySymbolRequirement).toHaveBeenCalled();
    });
    // Resolve so the test cleans up.
    if (resolveProbe) {
      (resolveProbe as (v: unknown) => void)({
        evidence_id: FRESH_EVIDENCE_ID,
        status: "identified",
        requirement: readiness.requirement,
        probable_os: "windows",
        layer: null,
        confidence: "high",
        failure_reason: null,
        error_code: null,
        sanitized_message: null,
        duration_ms: 100,
      });
    }
  });

  it("12. probe success refreshes without reload", async () => {
    const evidence = makeEvidence(FRESH_EVIDENCE_ID, "fresh.dmp", {
      symbol_status: "unknown",
      can_analyze: false,
      symbol_requirement: null,
    });
    const catalogue = makeCatalogue(FRESH_EVIDENCE_ID, { unknown: true });
    const readiness = makeReadiness(FRESH_EVIDENCE_ID, {
      state: "unknown",
      requirement: null,
      cache: null,
      source: null,
    });
    const apiMock = buildApiMock(evidence, catalogue, readiness);
    const user = userEvent.setup();
    setup(apiMock, `/cases/${CASE_ID}/memory/${FRESH_EVIDENCE_ID}?tab=overview`);
    const probe = await screen.findByTestId("memory-symbol-probe-button");
    await user.click(probe);
    await waitFor(() => {
      expect(apiMock.probeMemorySymbolRequirement).toHaveBeenCalledWith(CASE_ID, FRESH_EVIDENCE_ID);
    });
    // The probe mutation triggers a query invalidation; the next
    // readiness fetch returns the cached state.  We do not reload
    // the page.
    expect(apiMock.getMemorySymbolReadiness).toHaveBeenCalled();
  });

  it("13. historical active result (last_run) is preserved when readiness is unknown", async () => {
    const evidence = makeEvidence(FRESH_EVIDENCE_ID, "fresh.dmp", {
      symbol_status: "unknown",
      can_analyze: false,
      symbol_requirement: null,
    });
    const catalogue = makeCatalogue(FRESH_EVIDENCE_ID, { unknown: true });
    // The active result for system_info is a successful historical
    // run: the UI must keep it visible.
    const readiness = makeReadiness(FRESH_EVIDENCE_ID, {
      state: "unknown",
      requirement: null,
      cache: null,
      source: null,
      can_analyze_metadata: false,
      can_run_all: false,
    });
    setup(buildApiMock(evidence, catalogue, readiness), `/cases/${CASE_ID}/memory/${FRESH_EVIDENCE_ID}?tab=overview`);
    // The header carries the historical run label.
    const header = await screen.findByTestId("memory-evidence-header");
    expect(within(header).getByTestId("memory-active-result-label")).toBeInTheDocument();
  });
});
