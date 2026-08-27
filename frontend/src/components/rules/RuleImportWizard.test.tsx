/** @vitest-environment jsdom */
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { beforeEach, describe, expect, it, vi } from "vitest";

import { RuleImportWizard, reasonLabel, unsupportedBreakdown } from "./RuleImportWizard";

const importRuleFileMock = vi.fn();
const importRuleArchiveMock = vi.fn();
const getRuleImportMock = vi.fn();

vi.mock("../../api/client", () => ({
  api: {
    importRuleFile: (...args: unknown[]) => importRuleFileMock(...args),
    importRuleArchive: (...args: unknown[]) => importRuleArchiveMock(...args),
    getRuleImport: (...args: unknown[]) => getRuleImportMock(...args),
  },
}));

function run(overrides: Record<string, unknown> = {}) {
  return {
    id: "run-1",
    status: "completed",
    current_phase: "done",
    total_files: 1,
    processed_files: 1,
    total_rules_found: 120,
    imported_count: 120,
    unsupported_count: 42,
    last_error: null,
    details_json: {
      sigma_unsupported_by_feature: { unmapped_field: 30, unsupported_modifier: 12 },
      sigma_coverage_examples: { unmapped_field: ["Suspicious Service Install"], unsupported_modifier: ["Encoded Payload"] },
    },
    ...overrides,
  };
}

function renderWizard(engine: "sigma" | "yara" = "sigma") {
  const qc = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  return render(
    <QueryClientProvider client={qc}>
      <RuleImportWizard open onClose={() => {}} engine={engine} />
    </QueryClientProvider>,
  );
}

async function importFile(name: string) {
  renderWizard();
  const input = screen.getByTestId("rule-wizard-file-input") as HTMLInputElement;
  await userEvent.upload(input, new File(["x"], name, { type: "text/plain" }));
  await userEvent.click(screen.getByTestId("rule-wizard-start"));
}

describe("RuleImportWizard", () => {
  beforeEach(() => {
    vi.clearAllMocks();
    getRuleImportMock.mockResolvedValue(run());
  });

  it("sends a single rule file to the file importer", async () => {
    importRuleFileMock.mockResolvedValue({ import_run_id: "run-1" });
    await importFile("rule.yml");
    await waitFor(() => expect(importRuleFileMock).toHaveBeenCalled());
    expect(importRuleArchiveMock).not.toHaveBeenCalled();
  });

  it("sends an archive to the archive importer", async () => {
    importRuleArchiveMock.mockResolvedValue({ import_run_id: "run-1" });
    await importFile("sigma-rules.zip");
    await waitFor(() => expect(importRuleArchiveMock).toHaveBeenCalled());
    expect(importRuleFileMock).not.toHaveBeenCalled();
  });

  it("says how many rules can actually be evaluated, not just how many were stored", async () => {
    // A pack half of which can never fire looks exactly like one that works
    // unless the wizard says otherwise -- which is the entire point of it.
    importRuleArchiveMock.mockResolvedValue({ import_run_id: "run-1" });
    await importFile("sigma-rules.zip");

    expect(await screen.findByTestId("rule-wizard-imported")).toHaveTextContent("120");
    expect(screen.getByTestId("rule-wizard-evaluable")).toHaveTextContent("78");
    expect(screen.getByTestId("rule-wizard-unsupported")).toHaveTextContent("42");
  });

  it("breaks the unusable rules down by reason with examples", async () => {
    importRuleArchiveMock.mockResolvedValue({ import_run_id: "run-1" });
    await importFile("sigma-rules.zip");

    const breakdown = await screen.findByTestId("rule-wizard-breakdown");
    expect(breakdown.textContent).toContain("30×");
    expect(breakdown.textContent).toContain("Uses a field this engine cannot read");
    expect(breakdown.textContent).toContain("Suspicious Service Install");
  });

  it("stays quiet when every rule is usable", async () => {
    importRuleArchiveMock.mockResolvedValue({ import_run_id: "run-1" });
    getRuleImportMock.mockResolvedValue(run({ unsupported_count: 0, details_json: {} }));
    await importFile("sigma-rules.zip");

    await screen.findByTestId("rule-wizard-review");
    expect(screen.queryByTestId("rule-wizard-breakdown")).not.toBeInTheDocument();
  });

  it("surfaces a failed start instead of pretending it worked", async () => {
    importRuleFileMock.mockRejectedValue(new Error("rule store unavailable"));
    await importFile("rule.yml");

    expect(await screen.findByTestId("rule-wizard-error")).toHaveTextContent("rule store unavailable");
    expect(screen.queryByTestId("rule-wizard-review")).not.toBeInTheDocument();
  });
});

describe("unsupportedBreakdown", () => {
  it("orders reasons by how many rules they cost", () => {
    const rows = unsupportedBreakdown(run() as never);
    expect(rows.map((row) => row.reason)).toEqual(["unmapped_field", "unsupported_modifier"]);
  });

  it("returns nothing when the run carries no breakdown", () => {
    expect(unsupportedBreakdown(run({ details_json: {} }) as never)).toEqual([]);
  });
});

describe("reasonLabel", () => {
  it("explains engine reasons in words an analyst can act on", () => {
    expect(reasonLabel("unmapped_field:LogonType")).toBe("Uses a field this engine cannot read");
    expect(reasonLabel("unsupported_correlation")).toBe("Correlation rule (near / within / by)");
  });

  it("falls back to a readable form of an unknown reason", () => {
    expect(reasonLabel("some_new_reason")).toBe("some new reason");
  });
});
