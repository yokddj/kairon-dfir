import { render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { MemoryRouter, Route, Routes, useLocation } from "react-router-dom";
import { beforeEach, describe, expect, it, vi } from "vitest";

import CommandHistoryPage from "./CommandHistoryPage";

const getCommandHistoryMock = vi.fn();
const markEventMock = vi.fn();

vi.mock("../api/client", () => ({
  api: {
    getCommandHistory: (...args: unknown[]) => getCommandHistoryMock(...args),
    markEvent: (...args: unknown[]) => markEventMock(...args),
  },
}));

function LocationProbe() {
  const location = useLocation();
  return <div data-testid="location">{`${location.pathname}${location.search}`}</div>;
}

function renderPage(path = "/cases/case-1/command-history?evidence_id=ev-1&host=HOSTA") {
  return render(
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
      </Routes>
    </MemoryRouter>,
  );
}

const response = {
  total: 1,
  page: 1,
  page_size: 100,
  items: [
    {
      id: "cmd-1",
      case_id: "case-1",
      evidence_id: "ev-1",
      host: "HOSTA",
      timestamp: "2024-03-22T12:00:00Z",
      timestamp_status: "forensic",
      command: "powershell.exe -ep bypass -File C:\\Users\\Public\\maintenance.ps1",
      command_normalized: "powershell.exe -ep bypass -file c:\\users\\public\\maintenance.ps1",
      shell: "powershell",
      shell_family: "powershell",
      launcher: "powershell.exe",
      launcher_path: "powershell.exe",
      classification_confidence: "high",
      parent_shell: "",
      parent_context: "",
      source_type: "sysmon_1",
      source_event_id: "1",
      source_file: "Sysmon.evtx",
      user: "EXAMPLECORP\\usera",
      process: { name: "powershell.exe", executable: "powershell.exe", pid: 4444, guid: "{GUID-1}", command_line: "powershell.exe -ep bypass -File C:\\Users\\Public\\maintenance.ps1" },
      parent_process: { name: "explorer.exe", executable: "explorer.exe", pid: 2000, guid: null, command_line: "explorer.exe" },
      working_directory: "C:\\Users\\Public",
      risk_score: 75,
      risk_reasons: ["PowerShell execution policy bypass", "Synthetic indicator"],
      confidence: "high",
      dedupe_key: "key",
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
    getCommandHistoryMock.mockResolvedValue(response);
    markEventMock.mockResolvedValue({ id: "mark-1", status: "suspicious" });
  });

  it("renders command history rows and full wrapped command text", async () => {
    renderPage();

    expect(await screen.findByText("Command History")).toBeInTheDocument();
    expect(screen.getByText(/powershell.exe -ep bypass/i)).toBeInTheDocument();
    expect(screen.getAllByText("powershell.exe").length).toBeGreaterThan(0);
    expect(screen.getByText(/Synthetic indicator/i)).toBeInTheDocument();
    expect(getCommandHistoryMock).toHaveBeenCalledWith(
      "case-1",
      expect.objectContaining({ evidence_id: "ev-1", host: "HOSTA", page_size: 100 }),
    );
  });

  it("updates URL filters and can mark the source event suspicious", async () => {
    const user = userEvent.setup();
    renderPage();

    await screen.findByText(/powershell.exe -ep bypass/i);
    await user.clear(screen.getByPlaceholderText(/maintenance.ps1/i));
    await user.type(screen.getByPlaceholderText(/maintenance.ps1/i), "remote-admin");
    await user.click(screen.getByRole("button", { name: /^Apply$/i }));

    await waitFor(() => expect(screen.getByTestId("location")).toHaveTextContent("q=remote-admin"));

    await user.click(screen.getByRole("button", { name: /Suspicious/i }));
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

    await screen.findByText(/powershell.exe -ep bypass/i);
    await user.click(screen.getByRole("link", { name: /Open process tree/i }));

    await waitFor(() => expect(screen.getByTestId("location")).toHaveTextContent("/cases/case-1/process-graph"));
    expect(screen.getByTestId("location")).toHaveTextContent("mode=execution_story");
    expect(screen.getByTestId("location")).toHaveTextContent("pid=4444");
    expect(screen.getByTestId("location")).toHaveTextContent("process_guid=%7BGUID-1%7D");
    expect(screen.getByTestId("location")).toHaveTextContent("source_event_id=1");
    expect(screen.getByTestId("location")).toHaveTextContent("timestamp=2024-03-22T12%3A00%3A00Z");
  });
});
