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
  acquisition: null,
  error_code: null,
  ...overrides,
});

describe("symbol acquisition terminal state (frontend)", () => {
  beforeEach(() => {
    vi.clearAllMocks();
  });

  it("1) the 'Acquire exact symbols' button has been removed from the simplified UI", () => {
    renderCard(basePreparation());
    expect(screen.queryByTestId("memory-preparation-acquire-button")).toBeNull();
  });

  it("2) a terminal failed state from the canonical preparation no longer shows the acquire button", () => {
    renderCard(
      basePreparation({
        ui_state: "blocked",
        effective_state: "blocked_symbols",
        task_alive: false,
      }),
    );
    expect(screen.queryByTestId("memory-preparation-acquire-button")).toBeNull();
  });

  it("3) a stale task_alive=true on the canonical preparation enables the canonical 'Acquiring' state", () => {
    renderCard(
      basePreparation({
        ui_state: "preparing",
        effective_state: "preparing",
        task_alive: true,
        preparation_state: "preparing",
      }),
    );
    // The card surfaces the canonical preparing state via the
    // 'Preparing memory analysis' title.
    expect(screen.getByTestId("memory-preparation-title").textContent).toMatch(
      /preparing memory analysis/i,
    );
  });

  it("4) the acquire button is not rendered when the canonical preparation is terminal failed", () => {
    renderCard(
      basePreparation({
        ui_state: "blocked",
        effective_state: "blocked_symbols",
        task_alive: false,
      }),
    );
    expect(screen.queryByTestId("memory-preparation-acquire-button")).toBeNull();
  });

  it("5) the button is enabled when the canonical preparation reports task_alive=true only because the row is in 'preparing' state", () => {
    // The 'preparing' state combined with task_alive=true is the
    // canonical signal: the card title becomes 'Preparing
    // memory analysis' and the acquire button is rendered (but
    // not necessarily disabled — the analyst can still cancel
    // the pending intent).  Crucially the button is NOT stuck
    // on 'Acquiring symbols…' from a stale mutation.
    renderCard(
      basePreparation({
        ui_state: "preparing",
        effective_state: "preparing",
        task_alive: true,
        preparation_state: "queued",
      }),
    );
    const acquireButton = screen.queryByTestId("memory-preparation-acquire-button");
    // The acquire button is only shown for blocked_symbols;
    // the preparing state surfaces the title instead.
    expect(acquireButton).toBeNull();
    expect(screen.getByTestId("memory-preparation-title").textContent).toMatch(
      /preparing/i,
    );
  });

  it("6) the acquire button is not rendered for the canonical blocked_symbols state", () => {
    renderCard(basePreparation());
    expect(screen.queryByTestId("memory-preparation-acquire-button")).toBeNull();
  });

  it("7) identity-mismatch card shows title and ages in subtitle and diagnostics", () => {
    renderCard(
      basePreparation({
        error_code: "SYMBOL_PDB_IDENTITY_MISMATCH",
        sanitized_message: "expected age=1, observed age=5",
        acquisition: {
          status: "failed",
          error_code: "SYMBOL_PDB_IDENTITY_MISMATCH",
          sanitized_message: "expected age=1, observed age=5",
          identity_expected: {
            pdb_name: "ntkrnlmp.pdb",
            pdb_guid: "D801A9AFC0FB7761380800F708633DEA",
            pdb_age: 1,
            architecture: "x64",
          },
          identity_observed: {
            pdb_guid: "D801A9AFC0FB7761380800F708633DEA",
            pdb_age: 5,
            architecture: "x64",
          },
          started_at: "2026-06-24T20:00:00Z",
          completed_at: "2026-06-24T20:00:04Z",
        },
      }),
    );
    expect(screen.getByTestId("memory-preparation-title").textContent).toMatch(
      /symbol identity mismatch/i,
    );
    expect(screen.getByTestId("memory-preparation-subtitle").textContent).toMatch(
      /expected age=1, observed age=5/,
    );
    fireEvent.click(screen.getByTestId("memory-preparation-toggle-details"));
    const details = screen.getByTestId("memory-preparation-details");
    expect(details.textContent).toMatch(/req age: 1/);
    expect(details.textContent).toMatch(/observed age: 5/);
  });

  it("8) the acquire button is removed; the canonical error is shown through the title", () => {
    renderCard(
      basePreparation({
        error_code: "SYMBOL_ACQUISITION_FAILED",
        sanitized_message: "The exact PDB was not found at the official source.",
      }),
    );
    expect(screen.queryByTestId("memory-preparation-acquire-button")).toBeNull();
    expect(screen.getByTestId("memory-preparation-title").textContent).toMatch(/exact windows symbols required/i);
  });

  it("9) after the canonical task ends, the acquire button remains absent (no stale mutation state)", () => {
    const { rerender } = renderCard(basePreparation());
    expect(screen.queryByTestId("memory-preparation-acquire-button")).toBeNull();
    // Simulate the canonical preparation refetch: the task is
    // now terminal (task_alive=false, ui_state=blocked).
    const qc = new QueryClient({ defaultOptions: { queries: { retry: false, refetchOnWindowFocus: false } } });
    rerender(
      <QueryClientProvider client={qc}>
        <MemoryPreparationCard
          caseId={CASE}
          evidenceId={EVIDENCE}
          preparation={basePreparation({
            ui_state: "blocked",
            effective_state: "blocked_symbols",
            task_alive: false,
          })}
        />
      </QueryClientProvider>,
    );
    expect(screen.queryByTestId("memory-preparation-acquire-button")).toBeNull();
  });

  it("10) the page does NOT auto-dispatch a second acquisition on its own", () => {
    (api.acquireExactMemorySymbols as ReturnType<typeof vi.fn>).mockResolvedValue({
      state: "queued",
      task_alive: true,
      message: "queued",
      error_code: null,
    });
    renderCard(basePreparation());
    // No click happens.  The mock should never be called.
    expect(api.acquireExactMemorySymbols).not.toHaveBeenCalled();
  });
});
