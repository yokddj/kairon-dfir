/** @vitest-environment jsdom */
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { fireEvent, render, screen, waitFor } from "@testing-library/react";
import { beforeEach, describe, expect, it, vi } from "vitest";
import { api } from "../../api/client";
import { MemoryPreparationCard } from "./MemoryPreparationCard";

vi.mock("../../api/client", () => ({
  api: {
    retryMemorySymbolPreparation: vi.fn(),
    cancelMemoryRunWhenReady: vi.fn(),
    retryMemoryPreparation: vi.fn(),
    directMemoryProbe: vi.fn(),
    getMemoryPreparationDiagnostics: vi.fn(),
    acquireExactMemorySymbols: vi.fn(),
  },
}));

const CASE = "case-1";
const EVIDENCE = "ev-1";

const renderCard = (preparation: any) => {
  const qc = new QueryClient({ defaultOptions: { queries: { retry: false, refetchOnWindowFocus: false } } });
  return render(
    <QueryClientProvider client={qc}>
      <MemoryPreparationCard
        caseId={CASE}
        evidenceId={EVIDENCE}
        preparation={preparation}
      />
    </QueryClientProvider>,
  );
};

const basePreparation = (overrides: any = {}) => ({
  id: "prep-blocked",
  case_id: CASE,
  evidence_id: EVIDENCE,
  filename: "DC02-20240322-125906.dmp",
  ui_state: "blocked",
  effective_state: "blocked_symbols",
  preparation_state: "blocked_symbols",
  progress_percent: 0,
  task_alive: false,
  cache_status: "miss",
  exact_match: false,
  pending_request_id: null,
  blocker: null,
  sanitized_message: "WINDOWS_EXACT_SYMBOLS_MISSING",
  can_analyze_metadata: false,
  can_run_all: false,
  progress_label: "Symbols required",
  pending_intent_kind: null,
  link_source: null,
  content_reused_by_hash: false,
  requirement: {
    pdb_name: "ntkrnlmp.pdb",
    pdb_guid: "D801A9AFC0FB7761380800F708633DEA",
    pdb_age: 1,
    architecture: "x64",
  },
  ...overrides,
});

describe("blocked_symbols acquisition UX (frontend)", () => {
  beforeEach(() => {
    vi.clearAllMocks();
  });

  it("1) the 'Acquire exact symbols' button has been removed from the simplified UI", () => {
    renderCard(basePreparation());
    expect(screen.queryByTestId("memory-preparation-acquire-button")).toBeNull();
  });

  it("2) shows the exact PDB / GUID / age / architecture inside 'Advanced diagnostics'", () => {
    renderCard(basePreparation());
    fireEvent.click(screen.getByTestId("memory-preparation-toggle-details"));
    const details = screen.getByTestId("memory-preparation-details");
    expect(details.textContent).toMatch(/ntkrnlmp\.pdb/);
    expect(details.textContent).toMatch(/D801A9AFC0FB7761380800F708633DEA/);
    expect(details.textContent).toMatch(/req age: 1/);
    expect(details.textContent).toMatch(/Arch: x64/);
  });

  it("3) shows the cache miss marker inside 'Advanced diagnostics'", () => {
    renderCard(basePreparation());
    fireEvent.click(screen.getByTestId("memory-preparation-toggle-details"));
    const miss = screen.getByTestId("memory-preparation-cache-miss");
    expect(miss.textContent).toMatch(/cache miss/i);
  });

  it("4) the title is 'Exact Windows symbols required'", () => {
    renderCard(basePreparation());
    expect(screen.getByTestId("memory-preparation-title").textContent).toMatch(
      /exact windows symbols required/i,
    );
  });

  it("5) the acquire button is not rendered; acquireExactMemorySymbols is never called", () => {
    renderCard(basePreparation());
    expect(screen.queryByTestId("memory-preparation-acquire-button")).toBeNull();
    expect(api.acquireExactMemorySymbols).not.toHaveBeenCalled();
  });

  it("6) the acquire button is not rendered; no pending mutation UI", () => {
    let resolveAcquire: (v: unknown) => void = () => {};
    (api.acquireExactMemorySymbols as ReturnType<typeof vi.fn>).mockReturnValue(
      new Promise((resolve) => {
        resolveAcquire = resolve;
      }),
    );
    renderCard(basePreparation());
    expect(screen.queryByTestId("memory-preparation-acquire-button")).toBeNull();
    resolveAcquire({
      state: "queued",
      task_alive: true,
      message: "",
      error_code: null,
    });
  });

  it("7) no acquire button exists, so no double-dispatch can occur", () => {
    renderCard(basePreparation());
    expect(screen.queryByTestId("memory-preparation-acquire-button")).toBeNull();
    expect(api.acquireExactMemorySymbols).not.toHaveBeenCalled();
  });

  it("8) does NOT call acquireExactMemorySymbols when the state is not blocked_symbols", () => {
    renderCard(basePreparation({ effective_state: "ready", ui_state: "ready" }));
    expect(
      screen.queryByTestId("memory-preparation-acquire-button"),
    ).not.toBeInTheDocument();
    expect(api.acquireExactMemorySymbols).not.toHaveBeenCalled();
  });

  it("9) the acquire button is removed; the subtitle surfaces the error message", () => {
    renderCard(
      basePreparation({
        error_code: "SYMBOL_ACQUISITION_FAILED",
        sanitized_message: "The exact PDB was not found at the official source.",
      }),
    );
    expect(screen.queryByTestId("memory-preparation-acquire-button")).toBeNull();
    expect(screen.getByTestId("memory-preparation-subtitle").textContent).toMatch(/not found/i);
  });

  it("10) does not render the requirement block for ready state (errors no longer shown)", () => {
    renderCard(basePreparation({ effective_state: "ready", ui_state: "ready" }));
    expect(
      screen.queryByTestId("memory-preparation-requirement"),
    ).not.toBeInTheDocument();
  });

  it("11) ready state renders collapsed details toggle that expands to show PDB info", () => {
    renderCard(basePreparation({ effective_state: "ready", ui_state: "ready" }));
    expect(
      screen.getByTestId("memory-preparation-toggle-details"),
    ).toBeInTheDocument();
    expect(
      screen.queryByTestId("memory-preparation-details"),
    ).not.toBeInTheDocument();
    fireEvent.click(screen.getByTestId("memory-preparation-toggle-details"));
    const details = screen.getByTestId("memory-preparation-details");
    expect(details).toBeInTheDocument();
    expect(details.textContent).toMatch(/ntkrnlmp\.pdb/);
    expect(details.textContent).toMatch(/D801A9AFC0FB7761380800F708633DEA/);
    expect(details.textContent).toMatch(/req age: 1/);
    expect(details.textContent).toMatch(/Arch: x64/);
  });

  it("12) native-compatible ready state renders ready card with success message", () => {
    renderCard(
      basePreparation({
        effective_state: "ready",
        ui_state: "ready",
        native_compatible: true,
        native_compatibility_reason: "VOLATILITY_NATIVE_SYMBOL_COMPATIBLE",
      }),
    );
    expect(screen.getByTestId("memory-preparation-title").textContent).toMatch(
      /memory analysis ready/i,
    );
    expect(screen.getByTestId("memory-preparation-subtitle").textContent).toMatch(
      /volatility successfully resolved/i,
    );
  });

  it("13) native-compatible ready state hides Acquire symbols and native probe buttons", () => {
    renderCard(
      basePreparation({
        effective_state: "ready",
        ui_state: "ready",
        native_compatible: true,
        native_compatibility_reason: "VOLATILITY_NATIVE_SYMBOL_COMPATIBLE",
      }),
    );
    expect(
      screen.queryByTestId("memory-preparation-acquire-button"),
    ).not.toBeInTheDocument();
    expect(
      screen.queryByTestId("memory-preparation-native-probe-button"),
    ).not.toBeInTheDocument();
  });

  it("14) native-compatible ready state shows native-compatible green banner", () => {
    renderCard(
      basePreparation({
        effective_state: "ready",
        ui_state: "ready",
        native_compatible: true,
        native_compatibility_reason: "VOLATILITY_NATIVE_SYMBOL_COMPATIBLE",
        acquisition: {
          identity_expected: { pdb_name: "ntkrnlmp.pdb", pdb_guid: "D801A9AFC0FB7761380800F708633DEA", pdb_age: 1, architecture: "x64" },
          identity_observed: { pdb_guid: "D801A9AFC0FB7761380800F708633DEA", pdb_age: 5 },
        },
      }),
    );
    expect(
      screen.getByTestId("memory-preparation-native-compatible"),
    ).toBeInTheDocument();
    expect(
      screen.queryByTestId("memory-preparation-experimental-banner"),
    ).not.toBeInTheDocument();
  });

  it("15) native-compatible ready state shows info note when exact_match is false", () => {
    renderCard(
      basePreparation({
        effective_state: "ready",
        ui_state: "ready",
        native_compatible: true,
        exact_match: false,
      }),
    );
    expect(screen.getByTestId("memory-preparation-info").textContent).toMatch(
      /exact pdb age differs/i,
    );
  });

  it("16) native-compatible ready state hides info note when exact_match is true", () => {
    renderCard(
      basePreparation({
        effective_state: "ready",
        ui_state: "ready",
        native_compatible: true,
        exact_match: true,
      }),
    );
    expect(
      screen.queryByTestId("memory-preparation-info"),
    ).not.toBeInTheDocument();
  });

  it("17) native-compatible ready collapsed details shows canonical state fields", () => {
    renderCard(
      basePreparation({
        effective_state: "ready",
        ui_state: "ready",
        native_compatible: true,
        native_compatibility_reason: "VOLATILITY_NATIVE_SYMBOL_COMPATIBLE",
        cache_status: "miss",
      }),
    );
    fireEvent.click(screen.getByTestId("memory-preparation-toggle-details"));
    const details = screen.getByTestId("memory-preparation-details");
    expect(details.textContent).toMatch(/compat: native/);
    expect(details.textContent).toMatch(/cache: miss/);
    expect(details.textContent).toMatch(/exact_match: false/);
  });
});
