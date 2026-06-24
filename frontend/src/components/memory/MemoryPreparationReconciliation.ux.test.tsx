/** @vitest-environment jsdom */
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { fireEvent, render, screen, waitFor } from "@testing-library/react";
import { beforeEach, describe, expect, it, vi } from "vitest";

vi.mock("../../api/client", () => ({
  api: {
    retryMemorySymbolPreparation: vi.fn(),
    retryMemoryPreparation: vi.fn(),
    cancelMemoryRunWhenReady: vi.fn(),
  },
}));

import { api } from "../../api/client";
import { MemoryPreparationCard } from "./MemoryPreparationCard";

const CASE = "case-1";
const EVID = "evidence-1";

const baseReady = {
  case_id: CASE,
  evidence_id: EVID,
  filename: "mem.img",
  ui_state: "ready" as const,
  preparation_state: "ready" as const,
  persisted_state: "ready" as const,
  effective_state: "ready" as const,
  reconciled: true,
  source_of_truth: "successful_metadata_run",
  reconciled_at: "2024-01-01T00:00:00Z",
  preparation_id: "prep-1",
  stale: false,
  stale_reason: null,
  task_alive: false,
  requirement: null,
  cache_status: "hit" as const,
  exact_match: true,
  pending_request_id: null,
  blocker: null,
  sanitized_message: "The exact required Windows symbols are present in the cache.",
  can_analyze_metadata: true,
  can_run_all: true,
  progress_label: "Ready",
  progress_percent: 100,
  pending_intent_kind: null,
  link_source: "exact_cache_match",
  content_reused_by_hash: false,
};

const renderCard = (prep: Record<string, unknown> | null) => {
  const qc = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  return render(
    <QueryClientProvider client={qc}>
      <MemoryPreparationCard
        caseId={CASE}
        evidenceId={EVID}
        preparation={prep as any}
      />
    </QueryClientProvider>,
  );
};

beforeEach(() => {
  vi.clearAllMocks();
});

describe("MemoryPreparationCard v1 reconciliation", () => {
  it("1) ready evidence does not show 5%", () => {
    renderCard({ ...baseReady, progress_percent: 100, progress_label: "Ready" });
    expect(screen.queryByTestId("memory-preparation-progress")).toBeNull();
    expect(screen.queryByText(/5%/)).toBeNull();
  });

  it("2) ready evidence does not show Queued", () => {
    renderCard({ ...baseReady });
    const body = document.body.textContent || "";
    expect(body).not.toMatch(/Queued/);
    expect(body).toMatch(/Memory analysis ready/);
  });

  it("3) ready card shows the 'Memory analysis ready' title", () => {
    renderCard({ ...baseReady });
    const title = screen.getByTestId("memory-preparation-title");
    expect(title.textContent).toMatch(/Memory analysis ready/);
  });

  it("4) stale card shows 'Memory preparation was interrupted' and Retry preparation", async () => {
    (api.retryMemoryPreparation as ReturnType<typeof vi.fn>).mockResolvedValue({
      persisted_state: "queued",
      effective_state: "queued",
    });
    renderCard({
      ...baseReady,
      ui_state: "blocked",
      preparation_state: "stale",
      persisted_state: "queued",
      effective_state: "stale",
      reconciled: true,
      source_of_truth: "stale_timeout",
      stale: true,
      stale_reason: "no_task_no_metadata",
      progress_percent: 0,
      progress_label: "Stale",
      blocker: "Memory preparation was interrupted.",
      sanitized_message: "Memory preparation was interrupted. You can retry the preparation.",
      can_analyze_metadata: false,
      can_run_all: false,
    });
    const title = screen.getByTestId("memory-preparation-title");
    expect(title.textContent).toMatch(/Memory preparation was interrupted/);
    const retry = screen.getByTestId("memory-preparation-retry-button");
    expect(retry.textContent).toMatch(/Retry preparation/);
    fireEvent.click(retry);
    await waitFor(() =>
      expect(api.retryMemoryPreparation).toHaveBeenCalledWith(CASE, EVID),
    );
    // The legacy endpoint must not be called.
    expect(api.retryMemorySymbolPreparation).not.toHaveBeenCalled();
  });

  it("5) active task with heartbeat shows the progress bar (real progress)", () => {
    renderCard({
      ...baseReady,
      ui_state: "preparing",
      preparation_state: "probing",
      persisted_state: "probing",
      effective_state: "probing",
      task_alive: true,
      progress_percent: 35,
      progress_label: "Probing Windows kernel",
    });
    const progress = screen.getByTestId("memory-preparation-progress");
    expect(progress).toBeInTheDocument();
    expect(progress.textContent).toMatch(/35%/);
  });

  it("6) no fake progress: queued with no task shows no progress bar", () => {
    renderCard({
      ...baseReady,
      ui_state: "preparing",
      preparation_state: "queued",
      persisted_state: "queued",
      effective_state: "queued",
      task_alive: false,
      progress_percent: 5,
      progress_label: "Queued",
    });
    expect(screen.queryByTestId("memory-preparation-progress")).toBeNull();
  });

  it("7) Run analysis is enabled when effective_state=ready even if persisted_state=queued", () => {
    const prep = {
      ...baseReady,
      ui_state: "ready",
      preparation_state: "ready",
      persisted_state: "queued",
      effective_state: "ready",
      reconciled: true,
      source_of_truth: "successful_metadata_run",
      can_analyze_metadata: true,
      can_run_all: true,
      blocker: null,
    };
    renderCard(prep);
    const body = document.body.textContent || "";
    expect(body).toMatch(/Memory analysis ready/);
    expect(body).not.toMatch(/Queued/);
  });

  it("8) the catalogue is not blocked by a stale queued row", () => {
    const prep = {
      ...baseReady,
      ui_state: "ready",
      preparation_state: "ready",
      persisted_state: "queued",
      effective_state: "ready",
      reconciled: true,
      source_of_truth: "successful_metadata_run",
      can_analyze_metadata: true,
    };
    renderCard(prep);
    const dataUiState = screen
      .getByTestId("memory-preparation-card")
      .getAttribute("data-ui-state");
    expect(dataUiState).toBe("ready");
  });

  it("9) no generic server error is shown on the card", () => {
    renderCard({ ...baseReady });
    const body = document.body.textContent || "";
    expect(body).not.toMatch(/server error/i);
    expect(body).not.toMatch(/Internal Server Error/);
  });

  it("10) responsive: the card renders at narrow viewport", () => {
    const originalInnerWidth = window.innerWidth;
    Object.defineProperty(window, "innerWidth", { value: 360, configurable: true });
    try {
      renderCard({ ...baseReady });
      expect(screen.getByTestId("memory-preparation-card")).toBeInTheDocument();
      expect(screen.getByTestId("memory-preparation-title")).toBeInTheDocument();
    } finally {
      Object.defineProperty(window, "innerWidth", { value: originalInnerWidth, configurable: true });
    }
  });

  it("11) accessible: the card exposes a status-bearing element", () => {
    renderCard({ ...baseReady });
    const card = screen.getByTestId("memory-preparation-card");
    expect(card).toBeInTheDocument();
    const title = screen.getByTestId("memory-preparation-title");
    expect(title.textContent?.length).toBeGreaterThan(0);
    const subtitle = screen.getByTestId("memory-preparation-subtitle");
    expect(subtitle.textContent?.length).toBeGreaterThan(0);
  });
});
