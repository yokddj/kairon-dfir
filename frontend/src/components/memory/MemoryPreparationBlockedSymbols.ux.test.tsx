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

  it("1) renders an 'Acquire exact symbols' button when state is blocked_symbols", () => {
    renderCard(basePreparation());
    const button = screen.getByTestId("memory-preparation-acquire-button");
    expect(button).toBeInTheDocument();
    expect(button.textContent).toMatch(/acquire exact symbols/i);
  });

  it("2) shows the exact PDB / GUID / age / architecture on the card", () => {
    renderCard(basePreparation());
    const requirement = screen.getByTestId("memory-preparation-requirement");
    expect(requirement.textContent).toMatch(/ntkrnlmp\.pdb/);
    expect(requirement.textContent).toMatch(/D801A9AFC0FB7761380800F708633DEA/);
    expect(requirement.textContent).toMatch(/Age: 1/);
    expect(requirement.textContent).toMatch(/Arch: x64/);
  });

  it("3) shows the cache miss marker on the card", () => {
    renderCard(basePreparation());
    const miss = screen.getByTestId("memory-preparation-cache-miss");
    expect(miss.textContent).toMatch(/cache miss/i);
  });

  it("4) the title is 'Exact Windows symbols required'", () => {
    renderCard(basePreparation());
    expect(screen.getByTestId("memory-preparation-title").textContent).toMatch(
      /exact windows symbols required/i,
    );
  });

  it("5) clicking the button calls acquireExactMemorySymbols exactly once", async () => {
    (api.acquireExactMemorySymbols as ReturnType<typeof vi.fn>).mockResolvedValue({
      request_id: "req-1",
      acquisition_id: "acq-1",
      requirement_id: "rid-1",
      cached_symbol_id: null,
      state: "queued",
      queue: "memory-symbols",
      task_id: "rq-job-1",
      task_alive: true,
      retryable: false,
      source_category: "official_microsoft_symbols",
      pdb_name: "ntkrnlmp.pdb",
      pdb_guid: "D801A9AFC0FB7761380800F708633DEA",
      pdb_age: 1,
      architecture: "x64",
      symbol_key: "ntkrnlmp.pdb/D801A9AFC0FB7761380800F708633DEA-1",
      message: "The acquisition was queued on the isolated symbol-fetcher queue.",
      error_code: null,
    });
    renderCard(basePreparation());
    const button = screen.getByTestId("memory-preparation-acquire-button");
    fireEvent.click(button);
    await waitFor(() => {
      expect(api.acquireExactMemorySymbols).toHaveBeenCalledTimes(1);
    });
    expect(api.acquireExactMemorySymbols).toHaveBeenCalledWith(CASE, EVIDENCE);
  });

  it("6) the button is disabled while the mutation is pending", async () => {
    let resolveAcquire: (v: unknown) => void = () => {};
    (api.acquireExactMemorySymbols as ReturnType<typeof vi.fn>).mockReturnValue(
      new Promise((resolve) => {
        resolveAcquire = resolve;
      }),
    );
    renderCard(basePreparation());
    const button = screen.getByTestId("memory-preparation-acquire-button");
    fireEvent.click(button);
    await waitFor(() => {
      expect(button).toBeDisabled();
    });
    expect(button.textContent).toMatch(/acquiring/i);
    resolveAcquire({
      state: "queued",
      task_alive: true,
      message: "",
      error_code: null,
    });
  });

  it("7) double-click does not dispatch two acquisitions", async () => {
    (api.acquireExactMemorySymbols as ReturnType<typeof vi.fn>).mockResolvedValue({
      state: "queued",
      task_alive: true,
      message: "",
      error_code: null,
    });
    renderCard(basePreparation());
    const button = screen.getByTestId("memory-preparation-acquire-button");
    fireEvent.click(button);
    // After the first click the button must be disabled, which
    // means subsequent clicks are no-ops in the rendered DOM.
    await waitFor(() => {
      expect(button).toBeDisabled();
    });
    fireEvent.click(button);
    fireEvent.click(button);
    await waitFor(() => {
      expect(api.acquireExactMemorySymbols).toHaveBeenCalled();
    });
    expect(api.acquireExactMemorySymbols.mock.calls.length).toBe(1);
  });

  it("8) does NOT call acquireExactMemorySymbols when the state is not blocked_symbols", () => {
    renderCard(basePreparation({ effective_state: "ready", ui_state: "ready" }));
    expect(
      screen.queryByTestId("memory-preparation-acquire-button"),
    ).not.toBeInTheDocument();
    expect(api.acquireExactMemorySymbols).not.toHaveBeenCalled();
  });

  it("9) shows a safe error message when the API returns a failure", async () => {
    (api.acquireExactMemorySymbols as ReturnType<typeof vi.fn>).mockResolvedValue({
      request_id: "req-x",
      acquisition_id: "acq-x",
      state: "failed",
      task_alive: false,
      retryable: false,
      source_category: "official_microsoft_symbols",
      symbol_key: null,
      message: "The exact PDB was not found at the official source.",
      error_code: "SYMBOL_NOT_FOUND",
    });
    renderCard(basePreparation());
    fireEvent.click(screen.getByTestId("memory-preparation-acquire-button"));
    await waitFor(() => {
      expect(
        screen.getByTestId("memory-preparation-acquire-error"),
      ).toBeInTheDocument();
    });
    const err = screen.getByTestId("memory-preparation-acquire-error");
    expect(err.textContent).toMatch(/not found/i);
  });

  it("10) does not render the requirement block for non-blocked states", () => {
    renderCard(basePreparation({ effective_state: "ready", ui_state: "ready" }));
    expect(
      screen.queryByTestId("memory-preparation-requirement"),
    ).not.toBeInTheDocument();
  });
});
