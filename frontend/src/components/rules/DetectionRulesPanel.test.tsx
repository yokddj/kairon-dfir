/** @vitest-environment jsdom */
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { beforeEach, describe, expect, it, vi } from "vitest";

import { DetectionRulesPanel, coverageTotals } from "./DetectionRulesPanel";

const listRulesMock = vi.fn();
const getSigmaCoverageMock = vi.fn();
const listCaseRuleRunsMock = vi.fn();
const runRulesForCaseMock = vi.fn();
const updateRuleMock = vi.fn();

vi.mock("../../api/client", () => ({
  api: {
    listRules: (...args: unknown[]) => listRulesMock(...args),
    getSigmaCoverage: (...args: unknown[]) => getSigmaCoverageMock(...args),
    listCaseRuleRuns: (...args: unknown[]) => listCaseRuleRunsMock(...args),
    runRulesForCase: (...args: unknown[]) => runRulesForCaseMock(...args),
    updateRule: (...args: unknown[]) => updateRuleMock(...args),
    importRuleFile: vi.fn(),
    importRuleArchive: vi.fn(),
    getRuleImport: vi.fn(),
  },
}));

function renderPanel() {
  const qc = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  return render(
    <QueryClientProvider client={qc}>
      <DetectionRulesPanel open onClose={() => {}} caseId="case-1" />
    </QueryClientProvider>,
  );
}

describe("DetectionRulesPanel", () => {
  beforeEach(() => {
    vi.clearAllMocks();
    listRulesMock.mockResolvedValue({ total: 2, items: [
      { id: "r1", name: "one", title: "Rule one", engine: "sigma", severity: "high", enabled: true },
      { id: "r2", name: "two", title: "Rule two", engine: "sigma", severity: "low", enabled: false },
    ] });
    getSigmaCoverageMock.mockResolvedValue({
      by_support_status: { fully_supported: 1810, partially_supported: 469, unsupported: 1004 },
      by_compile_status: { compiled: 2279, unmapped_field: 858, keyword_only_detection: 58 },
    });
    listCaseRuleRunsMock.mockResolvedValue([]);
  });

  it("opens on the library, because that is the question asked first", async () => {
    renderPanel();
    expect(await screen.findByTestId("rules-panel-library")).toBeInTheDocument();
    expect(screen.queryByTestId("rules-panel-coverage")).not.toBeInTheDocument();
  });

  it("offers the engine as a filter, not as a place", async () => {
    // The screen this replaces had one tab per engine crossed with tabs per
    // object, so reaching anything meant holding both axes in your head.
    renderPanel();
    const filter = await screen.findByTestId("rules-panel-engine");
    expect(filter.tagName).toBe("SELECT");
  });

  it("says how many rules will actually run rather than just 'queued'", async () => {
    runRulesForCaseMock.mockResolvedValue({ accepted: true, status: "queued", queued_rules: 2279 });
    renderPanel();

    await userEvent.click(await screen.findByTestId("rules-panel-run"));

    const message = await screen.findByTestId("rules-panel-run-message");
    expect(message.textContent).toContain("2279");
  });

  it("moves to the runs zone once a run starts, so progress is where you are looking", async () => {
    runRulesForCaseMock.mockResolvedValue({ accepted: true, status: "queued", queued_rules: 10 });
    renderPanel();

    await userEvent.click(await screen.findByTestId("rules-panel-run"));

    expect(await screen.findByTestId("rules-panel-runs")).toBeInTheDocument();
  });

  it("shows why rules cannot be evaluated, ranked by how many they cost", async () => {
    renderPanel();
    await userEvent.click(await screen.findByTestId("rules-panel-zone-coverage"));

    const reasons = await screen.findByTestId("rules-panel-coverage-reasons");
    await waitFor(() => expect(reasons.textContent).toContain("858"));
    expect(reasons.textContent).toContain("Uses a field this engine cannot read");
  });

  it("toggles a rule without leaving the panel", async () => {
    updateRuleMock.mockResolvedValue({});
    renderPanel();

    await userEvent.click(await screen.findByText("Enabled"));

    await waitFor(() => expect(updateRuleMock).toHaveBeenCalledWith("r1", { enabled: false }));
  });
});

describe("coverageTotals", () => {
  it("ranks the reasons by cost", () => {
    const totals = coverageTotals({ by_support_status: { fully_supported: 7, partially_supported: 3, unsupported: 5 }, by_compile_status: { compiled: 10, a: 2, b: 3 } });
    expect(totals.reasons.map((row) => row.reason)).toEqual(["b", "a"]);
    expect(totals.evaluable).toBe(10);
    expect(totals.blocked).toBe(5);
  });

  it("never counts the compiled bucket as a reason", () => {
    const totals = coverageTotals({ by_support_status: { fully_supported: 10, unsupported: 5 }, by_compile_status: { compiled: 10, a: 5 } });
    expect(totals.reasons.map((row) => row.reason)).toEqual(["a"]);
  });

  it("survives an empty payload", () => {
    expect(coverageTotals(undefined)).toEqual({ evaluable: 0, blocked: 0, reasons: [] });
  });
});
