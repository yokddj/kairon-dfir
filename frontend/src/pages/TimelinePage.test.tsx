import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { fireEvent, render, screen, waitFor } from "@testing-library/react";
import { MemoryRouter, Route, Routes } from "react-router-dom";
import { beforeEach, describe, expect, it, vi } from "vitest";

import TimelinePage from "./TimelinePage";

const getTimelineMock = vi.fn();
const getTimelineQuickFiltersMock = vi.fn();
const listTimelineKeyEventsMock = vi.fn();
const createTimelineKeyEventMock = vi.fn();
const getTimelineAroundEventMock = vi.fn();
const getTimelineAroundFindingMock = vi.fn();

vi.mock("../api/client", () => ({
  api: {
    getTimeline: (...args: unknown[]) => getTimelineMock(...args),
    getTimelineQuickFilters: (...args: unknown[]) => getTimelineQuickFiltersMock(...args),
    listTimelineKeyEvents: (...args: unknown[]) => listTimelineKeyEventsMock(...args),
    createTimelineKeyEvent: (...args: unknown[]) => createTimelineKeyEventMock(...args),
    getTimelineAroundEvent: (...args: unknown[]) => getTimelineAroundEventMock(...args),
    getTimelineAroundFinding: (...args: unknown[]) => getTimelineAroundFindingMock(...args),
    exportTimelineKeyEventsMarkdown: vi.fn().mockResolvedValue("# export"),
  },
}));

vi.mock("../context/ActiveCaseContext", () => ({
  useActiveCase: () => ({
    activeCaseId: "case-1",
    selectedHost: "TEST-WIN10-01",
    selectedEvidenceId: "ev-1",
    setActiveCaseId: vi.fn(),
  }),
}));

vi.mock("../context/TimezoneContext", () => ({
  useTimezonePreference: () => ({
    effectiveTimezone: "UTC",
  }),
}));

vi.mock("../lib/time", () => ({
  formatTimestamp: (value: string) => value,
}));

function renderPage(path = "/cases/case-1/timeline") {
  const queryClient = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  return render(
    <MemoryRouter initialEntries={[path]}>
      <QueryClientProvider client={queryClient}>
        <Routes>
          <Route path="/cases/:caseId/timeline" element={<TimelinePage />} />
        </Routes>
      </QueryClientProvider>
    </MemoryRouter>,
  );
}

describe("TimelinePage", () => {
  beforeEach(() => {
    getTimelineMock.mockResolvedValue({
      case_id: "case-1",
      query: {},
      mode: "investigation",
      total: 2,
      page_size: 100,
      next_cursor: null,
      groups: [{ key: "2026-05-15T10:00:00Z", label: "15 May 2026 10:00", count: 2, high_risk_count: 1 }],
      facets: { artifact_type: { process: 1 }, event_type: { process_start: 1 } },
      warnings: [],
      items: [
        {
          id: "evt-1",
          kind: "event",
          timestamp: "2026-05-15T10:00:00Z",
          title: "Process created",
          summary: "WINWORD.EXE -> powershell.exe",
          artifact_type: "process",
          event_type: "process_start",
          risk_score: 95,
          host: "TEST-WIN10-01",
          user: "alex",
          key_entity: "powershell.exe -enc AAAA",
          related_process_node_ids: ["proc-1"],
          raw: { process: { name: "powershell.exe" } },
        },
        {
          id: "finding-1",
          kind: "finding",
          timestamp: "2026-05-15T10:05:00Z",
          title: "Office spawned PowerShell",
          summary: "Correlated finding",
          artifact_type: "finding",
          event_type: "office_powershell",
          risk_score: 90,
          host: "TEST-WIN10-01",
          user: "alex",
          related_finding_ids: ["finding-1"],
          raw: {},
        },
      ],
    });
    getTimelineQuickFiltersMock.mockResolvedValue({
      case_id: "case-1",
      items: [
        { id: "high_risk", label: "High risk", params: { risk_min: 70 } },
        { id: "defender_detections", label: "Defender detections", params: { artifact_type: ["defender", "detection"] } },
        { id: "process_executions", label: "Process executions", params: { event_type: ["process_start"] } },
        { id: "persistence", label: "Persistence", params: { event_category: ["persistence"] } },
      ],
    });
    listTimelineKeyEventsMock.mockResolvedValue([]);
    createTimelineKeyEventMock.mockResolvedValue({
      id: "bookmark-1",
      case_id: "case-1",
      event_id: "evt-1",
      title: "Process created",
      category: "execution",
      importance: "high",
      order_index: 0,
      include_in_report: true,
    });
    getTimelineAroundEventMock.mockResolvedValue({
      case_id: "case-1",
      query: {},
      mode: "full",
      total: 1,
      page_size: 100,
      next_cursor: null,
      groups: [],
      facets: {},
      warnings: [],
      items: [],
    });
    getTimelineAroundFindingMock.mockResolvedValue({
      case_id: "case-1",
      query: {},
      mode: "investigation",
      total: 1,
      page_size: 100,
      next_cursor: null,
      groups: [],
      facets: {},
      warnings: [],
      items: [],
      related_events: { items: [] },
    });
  });

  it("renders with global case context", async () => {
    renderPage();
    expect(await screen.findByText(/Case Timeline/i)).toBeInTheDocument();
    expect(screen.getAllByText(/Host: TEST-WIN10-01/i)).not.toHaveLength(0);
    expect(screen.getAllByText(/Evidence: ev-1/i)).not.toHaveLength(0);
    expect(screen.getByTestId("timeline-focus-chips")).toHaveTextContent(/Investigation timeline/i);
    expect(screen.getByTestId("timeline-focus-chips")).toHaveTextContent(/Host: TEST-WIN10-01/i);
  });

  it("loads evidence-scoped timeline with lightweight safeguards", async () => {
    renderPage("/cases/case-1/timeline?evidence_id=ev-1");
    await waitFor(() =>
      expect(getTimelineMock).toHaveBeenLastCalledWith(
        "case-1",
        expect.objectContaining({
          evidence_id: "ev-1",
          lightweight: true,
          include_facets: false,
        }),
      ),
    );
  });

  it("renders ntfs artifact label when present", async () => {
    getTimelineMock.mockResolvedValueOnce({
      case_id: "case-1",
      query: {},
      mode: "investigation",
      total: 1,
      page_size: 100,
      next_cursor: null,
      groups: [{ key: "2026-05-15T10:00:00Z", label: "15 May 2026 10:00", count: 1, high_risk_count: 1 }],
      facets: { artifact_type: { ntfs: 1 }, event_type: { file_zone_identifier_observed: 1 } },
      warnings: [],
      items: [
        {
          id: "evt-ntfs",
          kind: "event",
          timestamp: "2026-05-15T10:00:00Z",
          title: "Zone.Identifier observed",
          summary: "payload.exe marked from the Internet",
          artifact_type: "ntfs",
          event_type: "file_zone_identifier_observed",
          risk_score: 92,
          host: "TEST-WIN10-01",
          user: "user01",
          raw: {
            file: { path: "C:\\Users\\user01\\Downloads\\payload.exe", extension: ".exe" },
            ntfs: { zone_id: 3, host_url: "http://203.0.113.10/payload.exe" },
          },
        },
      ],
    });
    renderPage();
    expect(await screen.findByText("NTFS")).toBeInTheDocument();
  });

  it("renders windows ui artifact label when present", async () => {
    getTimelineMock.mockResolvedValueOnce({
      case_id: "case-1",
      query: {},
      mode: "investigation",
      total: 1,
      page_size: 100,
      next_cursor: null,
      groups: [{ key: "2026-05-15T11:00:00Z", label: "15 May 2026 11:00", count: 1, high_risk_count: 1 }],
      facets: { artifact_type: { windows_ui: 1 }, event_type: { notification_observed: 1 } },
      warnings: [],
      items: [
        {
          id: "evt-ui",
          kind: "event",
          timestamp: "2026-05-15T11:00:00Z",
          title: "Defender notification observed",
          summary: "Threat quarantined: Trojan:Win32/Test",
          artifact_type: "windows_ui",
          event_type: "notification_observed",
          risk_score: 85,
          host: "TEST-WIN10-01",
          user: "user01",
          raw: {
            notification: { title: "Threat quarantined: Trojan:Win32/Test" },
            app: { name: "Microsoft Defender" },
          },
        },
      ],
    });
    renderPage();
    expect(await screen.findByText("Windows UI")).toBeInTheDocument();
  });

  it("mode toggle calls API with selected mode", async () => {
    renderPage();
    await screen.findByText("WINWORD.EXE -> powershell.exe");
    fireEvent.click(screen.getByRole("button", { name: /Full Timeline/i }));
    await waitFor(() => expect(getTimelineMock).toHaveBeenLastCalledWith("case-1", expect.objectContaining({ mode: "full" })));
  });

  it("selecting item opens detail panel", async () => {
    renderPage();
    fireEvent.click(await screen.findByText("WINWORD.EXE -> powershell.exe"));
    await waitFor(() => expect(screen.getByText(/Entity:/i)).toBeInTheDocument());
    expect(screen.getByText(/Entity:/i)).toBeInTheDocument();
  });

  it("responsive detail drawer can close", async () => {
    renderPage();
    fireEvent.click(await screen.findByText("WINWORD.EXE -> powershell.exe"));
    expect(await screen.findByTestId("responsive-detail-overlay")).toBeInTheDocument();
    expect(document.body.style.overflow).toBe("hidden");
    fireEvent.click(screen.getByRole("button", { name: /close detail panel/i }));
    await waitFor(() => expect(screen.queryByTestId("responsive-detail-overlay")).not.toBeInTheDocument());
    expect(document.body.style.overflow).toBe("");
  });

  it("timeline headers sort visible items", async () => {
    renderPage();
    await screen.findByText("WINWORD.EXE -> powershell.exe");
    fireEvent.click(screen.getByRole("button", { name: /^Timestamp/i }));
    fireEvent.click(screen.getByRole("button", { name: /^Timestamp/i }));
    const rows = screen.getAllByRole("button", { name: /Open/i });
    fireEvent.click(rows[0]);
    await waitFor(() => expect(screen.getByRole("heading", { name: "Office spawned PowerShell" })).toBeInTheDocument());
  });

  it("quick filters apply params", async () => {
    renderPage();
    fireEvent.click(await screen.findByRole("button", { name: /High risk/i }));
    await waitFor(() => expect(getTimelineMock).toHaveBeenLastCalledWith("case-1", expect.objectContaining({ risk_min: 70 })));
  });

  it("quick filters apply artifact, event type and category params", async () => {
    renderPage();

    fireEvent.click(await screen.findByRole("button", { name: /Defender detections/i }));
    await waitFor(() =>
      expect(getTimelineMock).toHaveBeenLastCalledWith(
        "case-1",
        expect.objectContaining({ artifact_type: ["defender", "detection"] }),
      ),
    );

    fireEvent.click(await screen.findByRole("button", { name: /Process executions/i }));
    await waitFor(() =>
      expect(getTimelineMock).toHaveBeenLastCalledWith(
        "case-1",
        expect.objectContaining({ event_type: ["process_start"] }),
      ),
    );

    fireEvent.click(await screen.findByRole("button", { name: /Persistence/i }));
    await waitFor(() =>
      expect(getTimelineMock).toHaveBeenLastCalledWith(
        "case-1",
        expect.objectContaining({ event_category: ["persistence"] }),
      ),
    );
  });

  it("mark key event opens modal and calls API", async () => {
    renderPage();
    fireEvent.click(await screen.findByText("WINWORD.EXE -> powershell.exe"));
    fireEvent.click(screen.getByRole("button", { name: /Mark key/i }));
    expect(await screen.findByText(/Save key event/i)).toBeInTheDocument();
    fireEvent.click(screen.getByRole("button", { name: /Save key event/i }));
    await waitFor(() => expect(createTimelineKeyEventMock).toHaveBeenCalledWith("case-1", expect.objectContaining({ event_id: "evt-1" })));
  });

  it("loads focused around-event timeline from URL", async () => {
    renderPage("/cases/case-1/timeline?mode=full&around_event=evt-1&selected=evt-1");
    await waitFor(() => expect(getTimelineAroundEventMock).toHaveBeenCalledWith("case-1", "evt-1", expect.objectContaining({ window: "30m" })));
    expect(screen.getByTestId("timeline-focus-chips")).toHaveTextContent(/Around event/i);
  });

  it("loads focused finding timeline from URL", async () => {
    renderPage("/cases/case-1/timeline?mode=investigation&finding_id=finding-1");
    await waitFor(() => expect(getTimelineAroundFindingMock).toHaveBeenCalledWith("case-1", "finding-1", expect.objectContaining({ window: "30m" })));
    expect(screen.getByTestId("timeline-focus-chips")).toHaveTextContent(/Around finding/i);
  });
});
