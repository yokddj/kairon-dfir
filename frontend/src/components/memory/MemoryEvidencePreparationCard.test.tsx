/** @vitest-environment jsdom */
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { render, screen, waitFor } from "@testing-library/react";
import { beforeEach, describe, expect, it, vi } from "vitest";
import { api, type MemoryEvidencePreparation } from "../../api/client";
import { MemoryEvidencePreparationCard } from "./MemoryEvidencePreparationCard";

const getMemoryEvidencePreparationMock = vi.fn();

vi.mock("../../api/client", () => ({
  api: {
    getMemoryEvidencePreparation: (...args: unknown[]) => getMemoryEvidencePreparationMock(...args),
  },
}));

const CASE = "case-1";
const EVIDENCE = "ev-1";

function preparation(overrides: Partial<MemoryEvidencePreparation> = {}): MemoryEvidencePreparation {
  return {
    evidence_id: EVIDENCE,
    platform: "windows",
    architecture: "x64",
    readiness: "ready",
    requires_symbols: true,
    can_start_analysis: true,
    human_message: "This evidence is ready to analyze.",
    ...overrides,
  };
}

function renderCard() {
  const qc = new QueryClient({ defaultOptions: { queries: { retry: false, refetchOnWindowFocus: false } } });
  return render(
    <QueryClientProvider client={qc}>
      <MemoryEvidencePreparationCard caseId={CASE} evidenceId={EVIDENCE} />
    </QueryClientProvider>,
  );
}

// The card renders an intermediate data-ui-state="loading" render while
// the query is in flight -- wait for the specific terminal state rather
// than the first element findByTestId happens to see.
async function waitForState(state: string) {
  await waitFor(() => expect(screen.getByTestId("memory-evidence-preparation-card").getAttribute("data-ui-state")).toBe(state));
  return screen.getByTestId("memory-evidence-preparation-card");
}

describe("MemoryEvidencePreparationCard (Phase 2, read-only)", () => {
  beforeEach(() => {
    vi.clearAllMocks();
  });

  it("fetches from the Phase 1/2 endpoint scoped to case and evidence", async () => {
    getMemoryEvidencePreparationMock.mockResolvedValue(preparation());
    renderCard();
    await waitFor(() => expect(getMemoryEvidencePreparationMock).toHaveBeenCalledWith(CASE, EVIDENCE));
  });

  it("READY: shows the exact required copy and good tone", async () => {
    getMemoryEvidencePreparationMock.mockResolvedValue(preparation({ readiness: "ready", can_start_analysis: true }));
    renderCard();
    await waitForState("ready");
    expect(screen.getByTestId("memory-evidence-preparation-status")).toHaveTextContent("✓ Ready for analysis");
  });

  it("SYMBOLS_REQUIRED: shows the exact required copy", async () => {
    getMemoryEvidencePreparationMock.mockResolvedValue(
      preparation({ readiness: "symbols_required", can_start_analysis: false, requires_symbols: true }),
    );
    renderCard();
    await waitForState("symbols_required");
    expect(screen.getByTestId("memory-evidence-preparation-status")).toHaveTextContent(
      "⚠ Additional resources are required before analysis can begin.",
    );
  });

  it("AWAITING_USER: shows the exact required copy", async () => {
    getMemoryEvidencePreparationMock.mockResolvedValue(
      preparation({ readiness: "awaiting_user", can_start_analysis: false, platform: "unknown", architecture: "unknown" }),
    );
    renderCard();
    await waitForState("awaiting_user");
    expect(screen.getByTestId("memory-evidence-preparation-status")).toHaveTextContent("User confirmation required.");
  });

  it("BLOCKED: shows the exact required copy", async () => {
    getMemoryEvidencePreparationMock.mockResolvedValue(
      preparation({ readiness: "blocked", can_start_analysis: false }),
    );
    renderCard();
    await waitForState("blocked");
    expect(screen.getByTestId("memory-evidence-preparation-status")).toHaveTextContent("Preparation cannot continue.");
  });

  it("FAILED: shows the exact required copy", async () => {
    getMemoryEvidencePreparationMock.mockResolvedValue(
      preparation({ readiness: "failed", can_start_analysis: false }),
    );
    renderCard();
    await waitForState("failed");
    expect(screen.getByTestId("memory-evidence-preparation-status")).toHaveTextContent("Preparation failed.");
  });

  it("INSPECTING: shows the exact required copy", async () => {
    getMemoryEvidencePreparationMock.mockResolvedValue(
      preparation({ readiness: "inspecting", can_start_analysis: false, platform: "unknown", architecture: "unknown" }),
    );
    renderCard();
    await waitForState("inspecting");
    expect(screen.getByTestId("memory-evidence-preparation-status")).toHaveTextContent("Inspecting memory...");
  });

  it("shows platform, architecture, requires_symbols and the human message", async () => {
    getMemoryEvidencePreparationMock.mockResolvedValue(
      preparation({
        platform: "linux",
        architecture: "x64",
        readiness: "symbols_required",
        requires_symbols: true,
        can_start_analysis: false,
        human_message: "This Linux dump requires Volatility symbols (ISF) Kairon does not currently have.",
      }),
    );
    renderCard();
    const card = await waitForState("symbols_required");
    expect(card).toHaveTextContent("Linux");
    expect(card).toHaveTextContent("X64");
    expect(card).toHaveTextContent("Not ready yet");
    expect(card).toHaveTextContent("Yes");
    expect(screen.getByTestId("memory-evidence-preparation-message")).toHaveTextContent(
      "This Linux dump requires Volatility symbols (ISF) Kairon does not currently have.",
    );
  });

  it("shows 'Ready to analyze' and 'No' when analysis can start without symbols", async () => {
    getMemoryEvidencePreparationMock.mockResolvedValue(
      preparation({ readiness: "ready", can_start_analysis: true, requires_symbols: false }),
    );
    renderCard();
    const card = await waitForState("ready");
    expect(card).toHaveTextContent("Ready to analyze");
  });

  it("renders no action buttons at all -- this is a read-only view", async () => {
    getMemoryEvidencePreparationMock.mockResolvedValue(preparation({ readiness: "symbols_required" }));
    renderCard();
    await waitForState("symbols_required");
    expect(screen.queryAllByRole("button")).toHaveLength(0);
  });

  it("shows a neutral unavailable message when the fetch fails, without a retry button", async () => {
    getMemoryEvidencePreparationMock.mockRejectedValue(new Error("network error"));
    renderCard();
    const card = await waitForState("unavailable");
    expect(card).toHaveTextContent(/not available/i);
    expect(screen.queryAllByRole("button")).toHaveLength(0);
  });
});
