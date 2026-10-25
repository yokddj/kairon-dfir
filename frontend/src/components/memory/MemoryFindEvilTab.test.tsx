/** @vitest-environment jsdom */
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { fireEvent, render, screen, waitFor } from "@testing-library/react";
import { beforeEach, describe, expect, it, vi } from "vitest";
import type { MemoryActiveResult } from "../../api/client";
import { MemoryFindEvilTab } from "./MemoryFindEvilTab";

const getMemoryActiveResultMock = vi.fn();
const getMemoryFindEvilProcessesMock = vi.fn();
const markEventMock = vi.fn();
const deleteEventMarkingMock = vi.fn();

vi.mock("../../api/client", () => ({
  api: {
    getMemoryActiveResult: (...args: unknown[]) => getMemoryActiveResultMock(...args),
    getMemoryFindEvilProcesses: (...args: unknown[]) => getMemoryFindEvilProcessesMock(...args),
    markEvent: (...args: unknown[]) => markEventMock(...args),
    deleteEventMarking: (...args: unknown[]) => deleteEventMarkingMock(...args),
  },
}));

function triageProcess(pid: number | null, name: string | null, counts: { high?: number; medium?: number; low?: number }, marking: { id: string; status: string } | null = null) {
  const priority_counts = { high: counts.high ?? 0, medium: counts.medium ?? 0, low: counts.low ?? 0 };
  return {
    triage_id: `memory-findevil-process:ev-1:${pid ?? ""}:${name ?? ""}`,
    pid,
    process_name: name,
    indicator_count: priority_counts.high + priority_counts.medium + priority_counts.low,
    priority_counts,
    top_priority: priority_counts.high ? "high" : priority_counts.medium ? "medium" : "low",
    indicator_types: [{ value: "PROC_NOLINK", count: 1 }],
    marking: marking ? { ...marking, note: null } : null,
  };
}

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

function renderTab(onCreateFinding?: (kind: string, row: Record<string, unknown>) => void) {
  const qc = new QueryClient({ defaultOptions: { queries: { retry: false, refetchOnWindowFocus: false } } });
  return render(
    <QueryClientProvider client={qc}>
      <MemoryFindEvilTab caseId="case-1" evidenceId="ev-1" runOptions={null} selectedRunId={null} onSelectRunId={() => {}} onCreateFinding={onCreateFinding} />
    </QueryClientProvider>,
  );
}

const ROWS = [
  { document_id: "d1", pid: null, process_name: null, indicator_type: "AV_DETECT", review_priority: "high", explanation: "Antivirus detection event still in memory (Windows Defender).", address: "0x0", description: "AV:[Windows Defender] VirTool:Win32/Example.A" },
  { document_id: "d2", pid: 52, process_name: "WmiPrvSE.exe", indicator_type: "PROC_NOLINK", review_priority: "high", explanation: "Process missing from the kernel's active process list.", address: "0xffff988a4d6d60c0", description: null },
  { document_id: "d3", pid: 2152, process_name: "msedge.exe", indicator_type: "PRIVATE_RWX", review_priority: "low", explanation: "Private memory that is writable and executable.", address: "0x7ffae1950000", description: "p-rwx-" },
];

describe("MemoryFindEvilTab", () => {
  beforeEach(() => {
    vi.clearAllMocks();
    getMemoryFindEvilProcessesMock.mockResolvedValue({ case_id: "case-1", evidence_id: "ev-1", active_run: { id: "run-1" }, analysis_state: "analyzed_with_results", marking_artifact_type: "memory_findevil_process", processes: [] });
  });

  it("says when Find Evil has not been run", async () => {
    getMemoryActiveResultMock.mockResolvedValue(activeResult());
    renderTab();
    expect(await screen.findByTestId("findevil-not-analyzed")).toHaveTextContent("Run all");
  });

  it("lists indicators with their priority, details and meaning", async () => {
    getMemoryActiveResultMock.mockResolvedValue(activeResult({ analysis_state: "analyzed_with_results", total: 3, items: ROWS as unknown as MemoryActiveResult["items"] }));
    renderTab();
    fireEvent.click(await screen.findByTestId("findevil-view-all"));
    await waitFor(() => expect(screen.getAllByTestId("findevil-row")).toHaveLength(3));
    expect(screen.getAllByTestId("findevil-priority").map((cell) => cell.textContent)).toEqual(["high", "high", "low"]);
    const table = screen.getByTestId("findevil-table");
    expect(table).toHaveTextContent("VirTool:Win32/Example.A");
    expect(table).toHaveTextContent("0xffff988a4d6d60c0");
    expect(table).toHaveTextContent("Process missing from the kernel's active process list.");
    expect(screen.getByTestId("findevil-summary")).toHaveTextContent("3 indicators");
  });

  it("sends the priority and type filters to the API", async () => {
    getMemoryActiveResultMock.mockResolvedValue({
      ...activeResult({ analysis_state: "analyzed_with_results", total: 3, items: ROWS as unknown as MemoryActiveResult["items"] }),
      facets: {
        indicator_type: [{ value: "PROC_NOLINK", count: 2 }, { value: "PE_PATCHED", count: 1 }],
        review_priority: [{ value: "high", count: 1 }, { value: "low", count: 2 }],
      },
    });
    renderTab();
    fireEvent.click(await screen.findByTestId("findevil-view-all"));
    await waitFor(() => expect(screen.getAllByTestId("findevil-row")).toHaveLength(3));
    expect(getMemoryActiveResultMock).toHaveBeenLastCalledWith("case-1", "ev-1", "find_evil", undefined, expect.objectContaining({ facet_fields: ["indicator_type", "review_priority"] }));
    // Each priority shows how many indicators it has; "All" the total.
    expect(screen.getByTestId("findevil-priority-high")).toHaveTextContent("1");
    expect(screen.getByTestId("findevil-priority-all")).toHaveTextContent("3");
    fireEvent.click(screen.getByTestId("findevil-priority-high"));
    await waitFor(() => expect(getMemoryActiveResultMock).toHaveBeenLastCalledWith("case-1", "ev-1", "find_evil", undefined, expect.objectContaining({ review_priority: "high" })));
    // The type picker offers the types the run has, with their counts.
    const typeSelect = screen.getByTestId("findevil-type-input");
    expect(Array.from(typeSelect.querySelectorAll("option")).map((o) => o.textContent)).toEqual(["Any type", "PROC_NOLINK (2)", "PE_PATCHED (1)"]);
    fireEvent.change(typeSelect, { target: { value: "PROC_NOLINK" } });
    await waitFor(() => expect(getMemoryActiveResultMock).toHaveBeenLastCalledWith("case-1", "ev-1", "find_evil", undefined, expect.objectContaining({ indicator_type: "PROC_NOLINK" })));
  });

  it("names the source of each indicator and flags a partial run", async () => {
    const rows = [
      { ...ROWS[1], source_plugin: "kairon.findevil", sources: ["kairon.findevil", "memprocfs.findevil"] },
      { ...ROWS[0], source_plugin: "memprocfs.findevil" },
    ];
    getMemoryActiveResultMock.mockResolvedValue(activeResult({ analysis_state: "partial", total: 2, items: rows as unknown as MemoryActiveResult["items"] }));
    renderTab();
    fireEvent.click(await screen.findByTestId("findevil-view-all"));
    await waitFor(() => expect(screen.getAllByTestId("findevil-row")).toHaveLength(2));
    expect(screen.getAllByTestId("findevil-source").map((cell) => cell.textContent)).toEqual(["Kairon + MemProcFS", "MemProcFS"]);
    expect(screen.getByTestId("findevil-partial")).toHaveTextContent("Runs tab");
  });

  describe("by process", () => {
    beforeEach(() => {
      getMemoryActiveResultMock.mockResolvedValue(activeResult({ analysis_state: "analyzed_with_results", total: 3, items: ROWS as unknown as MemoryActiveResult["items"] }));
    });

    it("triages one row per process, most important first, and keeps settled ones apart", async () => {
      getMemoryFindEvilProcessesMock.mockResolvedValue({
        case_id: "case-1", evidence_id: "ev-1", active_run: { id: "run-1" }, analysis_state: "analyzed_with_results", marking_artifact_type: "memory_findevil_process",
        processes: [
          triageProcess(null, null, { high: 1 }),
          triageProcess(52, "WmiPrvSE.exe", { high: 1 }, { id: "m-s", status: "suspicious" }),
          triageProcess(2152, "msedge.exe", { low: 40 }, { id: "m-n", status: "not_relevant" }),
        ],
      });
      renderTab();

      await waitFor(() => expect(screen.getAllByTestId("findevil-process-row")).toHaveLength(2));
      expect(screen.getByTestId("findevil-processes-summary")).toHaveTextContent("2 processes to review · 1 reviewed or not relevant");
      const rows = screen.getAllByTestId("findevil-process-row");
      expect(rows[0]).toHaveTextContent("Not tied to a process");
      expect(rows[1]).toHaveTextContent("WmiPrvSE.exe (52)");
      expect(rows[1]).toHaveTextContent("Suspicious");

      fireEvent.click(screen.getByTestId("findevil-processes-toggle-settled"));
      expect(screen.getAllByTestId("findevil-process-row")).toHaveLength(3);
    });

    it("marks a process with a run-independent identity", async () => {
      getMemoryFindEvilProcessesMock.mockResolvedValue({
        case_id: "case-1", evidence_id: "ev-1", active_run: { id: "run-1" }, analysis_state: "analyzed_with_results", marking_artifact_type: "memory_findevil_process",
        processes: [triageProcess(2152, "msedge.exe", { low: 40 })],
      });
      markEventMock.mockResolvedValue({});
      renderTab();

      fireEvent.click(await screen.findByTestId("findevil-process-mark-not_relevant"));

      await waitFor(() =>
        expect(markEventMock).toHaveBeenCalledWith("memory-findevil-process:ev-1:2152:msedge.exe", expect.objectContaining({ case_id: "case-1", evidence_id: "ev-1", artifact_type: "memory_findevil_process", status: "not_relevant" })),
      );
      await waitFor(() => expect(getMemoryFindEvilProcessesMock).toHaveBeenCalledTimes(2));
    });

    it("opens a process's indicators in the full list", async () => {
      getMemoryFindEvilProcessesMock.mockResolvedValue({
        case_id: "case-1", evidence_id: "ev-1", active_run: { id: "run-1" }, analysis_state: "analyzed_with_results", marking_artifact_type: "memory_findevil_process",
        processes: [triageProcess(52, "WmiPrvSE.exe", { high: 1 })],
      });
      renderTab();

      fireEvent.click(await screen.findByTestId("findevil-process-show"));

      await waitFor(() => expect(getMemoryActiveResultMock).toHaveBeenLastCalledWith("case-1", "ev-1", "find_evil", undefined, expect.objectContaining({ pid: 52 })));
      expect(screen.getByTestId("findevil-view-all")).toHaveAttribute("aria-pressed", "true");
    });

    it("filters processes by priority", async () => {
      getMemoryFindEvilProcessesMock.mockResolvedValue({
        case_id: "case-1", evidence_id: "ev-1", active_run: { id: "run-1" }, analysis_state: "analyzed_with_results", marking_artifact_type: "memory_findevil_process",
        processes: [triageProcess(52, "WmiPrvSE.exe", { high: 1 }), triageProcess(2152, "msedge.exe", { low: 40 })],
      });
      renderTab();
      await waitFor(() => expect(screen.getAllByTestId("findevil-process-row")).toHaveLength(2));

      fireEvent.click(screen.getByTestId("findevil-priority-high"));

      await waitFor(() => expect(screen.getAllByTestId("findevil-process-row")).toHaveLength(1));
      expect(screen.getByTestId("findevil-process-row")).toHaveTextContent("WmiPrvSE.exe");
    });
  });

  it("creates a finding from an indicator and from a process", async () => {
    getMemoryActiveResultMock.mockResolvedValue(activeResult({ analysis_state: "analyzed_with_results", total: ROWS.length, items: ROWS }));
    getMemoryFindEvilProcessesMock.mockResolvedValue({ case_id: "case-1", evidence_id: "ev-1", active_run: { id: "run-1" }, analysis_state: "analyzed_with_results", marking_artifact_type: "memory_findevil_process", processes: [triageProcess(52, "WmiPrvSE.exe", { high: 1 })] });
    const onCreateFinding = vi.fn();
    renderTab(onCreateFinding);
    fireEvent.click(await screen.findByTestId("findevil-process-create-finding"));
    expect(onCreateFinding).toHaveBeenCalledWith("find_evil_process", expect.objectContaining({ pid: 52, process_name: "WmiPrvSE.exe" }));
    fireEvent.click(screen.getByTestId("findevil-view-all"));
    const buttons = await screen.findAllByTestId("findevil-create-finding");
    fireEvent.click(buttons[1]);
    expect(onCreateFinding).toHaveBeenLastCalledWith("find_evil_indicator", expect.objectContaining({ document_id: "d2", indicator_type: "PROC_NOLINK" }));
  });

  it("offers no finding button without a handler", async () => {
    getMemoryActiveResultMock.mockResolvedValue(activeResult({ analysis_state: "analyzed_with_results", total: ROWS.length, items: ROWS }));
    renderTab();
    fireEvent.click(await screen.findByTestId("findevil-view-all"));
    await screen.findAllByTestId("findevil-row");
    expect(screen.queryByTestId("findevil-create-finding")).toBeNull();
  });
});
