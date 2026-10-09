/** @vitest-environment jsdom */
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { fireEvent, render, screen, waitFor } from "@testing-library/react";
import { beforeEach, describe, expect, it, vi } from "vitest";
import type { MemoryActiveResult } from "../../api/client";
import { MemoryFindEvilTab } from "./MemoryFindEvilTab";

const getMemoryActiveResultMock = vi.fn();

vi.mock("../../api/client", () => ({
  api: {
    getMemoryActiveResult: (...args: unknown[]) => getMemoryActiveResultMock(...args),
  },
}));

function activeResult(overrides: Partial<MemoryActiveResult> = {}): MemoryActiveResult {
  return {
    case_id: "case-1",
    evidence_id: "ev-1",
    artifact_family: "find_evil",
    active_run: null,
    latest_attempt: null,
    selection_reason: "not_analyzed",
    using_fallback: false,
    historical_override: false,
    total: 0,
    items: [],
    page: 1,
    page_size: 50,
    count_source: null,
    analysis_state: "not_analyzed",
    ...overrides,
  };
}

function renderTab() {
  const qc = new QueryClient({ defaultOptions: { queries: { retry: false, refetchOnWindowFocus: false } } });
  return render(
    <QueryClientProvider client={qc}>
      <MemoryFindEvilTab caseId="case-1" evidenceId="ev-1" runOptions={null} selectedRunId={null} onSelectRunId={() => {}} />
    </QueryClientProvider>,
  );
}

const ROWS = [
  { document_id: "d1", pid: null, process_name: null, indicator_type: "AV_DETECT", review_priority: "high", explanation: "Antivirus detection event still in memory (Windows Defender).", address: "0x0", description: "AV:[Windows Defender] VirTool:Win32/Example.A" },
  { document_id: "d2", pid: 52, process_name: "WmiPrvSE.exe", indicator_type: "PROC_NOLINK", review_priority: "high", explanation: "Process missing from the kernel's active process list.", address: "0xffff988a4d6d60c0", description: null },
  { document_id: "d3", pid: 2152, process_name: "msedge.exe", indicator_type: "PRIVATE_RWX", review_priority: "low", explanation: "Private memory that is writable and executable.", address: "0x7ffae1950000", description: "p-rwx-" },
];

describe("MemoryFindEvilTab", () => {
  beforeEach(() => vi.clearAllMocks());

  it("says when Find Evil has not been run", async () => {
    getMemoryActiveResultMock.mockResolvedValue(activeResult());
    renderTab();
    expect(await screen.findByTestId("findevil-not-analyzed")).toHaveTextContent("Run all");
  });

  it("lists indicators with their priority, details and meaning", async () => {
    getMemoryActiveResultMock.mockResolvedValue(activeResult({ analysis_state: "analyzed_with_results", total: 3, items: ROWS as unknown as MemoryActiveResult["items"] }));
    renderTab();
    await waitFor(() => expect(screen.getAllByTestId("findevil-row")).toHaveLength(3));
    expect(screen.getAllByTestId("findevil-priority").map((cell) => cell.textContent)).toEqual(["high", "high", "low"]);
    const table = screen.getByTestId("findevil-table");
    expect(table).toHaveTextContent("VirTool:Win32/Example.A");
    expect(table).toHaveTextContent("0xffff988a4d6d60c0");
    expect(table).toHaveTextContent("Process missing from the kernel's active process list.");
    expect(screen.getByTestId("findevil-summary")).toHaveTextContent("3 indicators");
  });

  it("sends the priority and type filters to the API", async () => {
    getMemoryActiveResultMock.mockResolvedValue(activeResult({ analysis_state: "analyzed_with_results", total: 3, items: ROWS as unknown as MemoryActiveResult["items"] }));
    renderTab();
    await waitFor(() => expect(screen.getAllByTestId("findevil-row")).toHaveLength(3));
    fireEvent.click(screen.getByTestId("findevil-priority-high"));
    await waitFor(() => expect(getMemoryActiveResultMock).toHaveBeenLastCalledWith("case-1", "ev-1", "find_evil", undefined, expect.objectContaining({ review_priority: "high" })));
    fireEvent.change(screen.getByTestId("findevil-type-input"), { target: { value: "proc_nolink" } });
    await waitFor(() => expect(getMemoryActiveResultMock).toHaveBeenLastCalledWith("case-1", "ev-1", "find_evil", undefined, expect.objectContaining({ indicator_type: "PROC_NOLINK" })));
  });

  it("names the source of each indicator and flags a partial run", async () => {
    const rows = [
      { ...ROWS[1], source_plugin: "kairon.findevil", sources: ["kairon.findevil", "memprocfs.findevil"] },
      { ...ROWS[0], source_plugin: "memprocfs.findevil" },
    ];
    getMemoryActiveResultMock.mockResolvedValue(activeResult({ analysis_state: "partial", total: 2, items: rows as unknown as MemoryActiveResult["items"] }));
    renderTab();
    await waitFor(() => expect(screen.getAllByTestId("findevil-row")).toHaveLength(2));
    expect(screen.getAllByTestId("findevil-source").map((cell) => cell.textContent)).toEqual(["Kairon + MemProcFS", "MemProcFS"]);
    expect(screen.getByTestId("findevil-partial")).toHaveTextContent("Runs tab");
  });
});
