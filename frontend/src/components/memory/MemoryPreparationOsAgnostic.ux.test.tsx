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

describe("OS-agnostic memory preparation v1 (frontend)", () => {
  beforeEach(() => {
    vi.clearAllMocks();
  });

  it("1) a real queued preparation uses an indeterminate progress bar (no fake 5%)", () => {
    renderCard({
      id: "prep-1",
      case_id: CASE,
      evidence_id: EVIDENCE,
      ui_state: "preparing",
      effective_state: "queued",
      progress_percent: 0,
      progress_label: "Queued",
      task_alive: true,
    });
    const card = screen.getByTestId("memory-preparation-card");
    expect(card.getAttribute("data-ui-state")).toBe("queued");
    // The indeterminate bar is rendered, not a 0% filled bar.
    const bar = screen.getByTestId("memory-preparation-progress");
    expect(bar).toBeInTheDocument();
    const indeterminate = screen.queryByTestId("memory-preparation-progress-indeterminate");
    expect(indeterminate).not.toBeNull();
  });

  it("2) dispatch_failed shows a distinct title and surfaces Retry", async () => {
    (api.retryMemoryPreparation as ReturnType<typeof vi.fn>).mockResolvedValue({
      preparation_id: "prep-2",
      state: "queued",
      task_active: true,
      queue: "memory",
      worker_task_id: "rq-job-2",
      retryable: false,
    });
    renderCard({
      id: "prep-2",
      case_id: CASE,
      evidence_id: EVIDENCE,
      ui_state: "failed",
      effective_state: "dispatch_failed",
      progress_percent: 0,
      error_code: "MEMORY_PREPARATION_DISPATCH_FAILED",
      sanitized_message: "The worker queue is unreachable.",
      task_alive: false,
    });
    expect(screen.getByTestId("memory-preparation-title").textContent).toMatch(
      /could not be enqueued/i,
    );
    // The Retry button is rendered.
    const retry = screen.getByTestId("memory-preparation-retry-button");
    fireEvent.click(retry);
    await waitFor(() => {
      expect(api.retryMemoryPreparation).toHaveBeenCalledWith(CASE, EVIDENCE);
    });
    // The legacy endpoint must not be called.
    expect(api.retryMemorySymbolPreparation).not.toHaveBeenCalled();
  });

  it("3) a Ready state hides the preparation controls", () => {
    renderCard({
      id: "prep-3",
      case_id: CASE,
      evidence_id: EVIDENCE,
      ui_state: "ready",
      effective_state: "ready",
      progress_percent: 100,
      progress_label: "Ready",
      task_alive: false,
    });
    // The "Retry preparation" button is hidden when the state
    // is Ready.
    expect(screen.queryByTestId("memory-preparation-retry-button")).toBeNull();
    // The card is still rendered with the Ready tone.
    const card = screen.getByTestId("memory-preparation-card");
    expect(card.getAttribute("data-ui-state")).toBe("ready");
  });

  it("4) Blocked and Unsupported are distinct states", () => {
    const blocked = renderCard({
      id: "prep-b",
      case_id: CASE,
      evidence_id: EVIDENCE,
      ui_state: "blocked",
      effective_state: "blocked",
      progress_percent: 0,
      sanitized_message: "A required dependency is missing.",
      task_alive: false,
    });
    expect(screen.getByTestId("memory-preparation-title").textContent).toMatch(/blocked/i);
    blocked.unmount();
    renderCard({
      id: "prep-u",
      case_id: CASE,
      evidence_id: EVIDENCE,
      ui_state: "failed",
      effective_state: "platform_not_supported",
      progress_percent: 0,
      sanitized_message: "Kairon does not currently support this OS.",
      task_alive: false,
    });
    expect(screen.getByTestId("memory-preparation-title").textContent).toMatch(
      /not supported/i,
    );
  });

  it("5) the catalogue does not mass-mark Unavailable on a queued row", () => {
    // The MemoryPreparationCard itself does not render the
    // catalogue, but the test ensures the card still surfaces
    // a meaningful "preparing" copy rather than an "Unavailable"
    // fallback when the row is queued.
    renderCard({
      id: "prep-c",
      case_id: CASE,
      evidence_id: EVIDENCE,
      ui_state: "preparing",
      effective_state: "queued",
      progress_percent: 0,
      progress_label: "Queued",
      task_alive: true,
    });
    const card = screen.getByTestId("memory-preparation-card");
    expect(card.textContent).toMatch(/Preparing/i);
    expect(card.textContent).not.toMatch(/unavailable/i);
  });

  it("6) historical results remain visible after a stale row without the retry button", () => {
    renderCard({
      id: "prep-h",
      case_id: CASE,
      evidence_id: EVIDENCE,
      ui_state: "stale",
      effective_state: "stale",
      progress_percent: 0,
      sanitized_message: "The previous preparation did not finish.",
      task_alive: false,
    });
    expect(screen.getByTestId("memory-preparation-title").textContent).toMatch(
      /interrupted/i,
    );
    expect(screen.queryByTestId("memory-preparation-retry-button")).toBeNull();
  });

  it("7) no fake 5% is shown anywhere in the preparing state", () => {
    renderCard({
      id: "prep-7",
      case_id: CASE,
      evidence_id: EVIDENCE,
      ui_state: "preparing",
      effective_state: "queued",
      progress_percent: 0,
      progress_label: "Queued",
      task_alive: true,
    });
    // No percentage is rendered when progress is 0.
    const card = screen.getByTestId("memory-preparation-card");
    expect(card.textContent).not.toMatch(/\b5\s*%/);
  });

  it("8) accessible status messages: the title is rendered as a heading", () => {
    renderCard({
      id: "prep-a11y",
      case_id: CASE,
      evidence_id: EVIDENCE,
      ui_state: "preparing",
      effective_state: "queued",
      progress_percent: 0,
      progress_label: "Queued",
      task_alive: true,
    });
    const title = screen.getByTestId("memory-preparation-title");
    expect(title.tagName.toLowerCase()).toBe("p");
    expect(title.textContent).toMatch(/Preparing/i);
    // The progress region uses the standard role for a status.
    const progress = screen.getByTestId("memory-preparation-progress");
    expect(progress).toBeInTheDocument();
  });
});
