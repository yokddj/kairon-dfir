/** @vitest-environment jsdom */
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { render, screen, waitFor } from "@testing-library/react";
import { beforeEach, describe, expect, it, vi } from "vitest";
import type { MemoryActiveResult } from "../../api/client";
import { MemoryShellHistoryTab } from "./MemoryShellHistoryTab";

const getMemoryActiveResultMock = vi.fn();

vi.mock("../../api/client", () => ({
  api: {
    getMemoryActiveResult: (...args: unknown[]) => getMemoryActiveResultMock(...args),
  },
}));

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
    vi.clearAllMocks();
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
    expect(await screen.findByTestId("shell-history-empty-zero-results")).toHaveTextContent("No shell history was recovered from this memory image.");
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
});
