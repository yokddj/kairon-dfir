import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { fireEvent, render, screen, waitFor } from "@testing-library/react";
import { MemoryRouter, Route, Routes } from "react-router-dom";
import { beforeEach, describe, expect, it, vi } from "vitest";

import IncidentTimelinePage from "./IncidentTimelinePage";

const getIncidentTimelineDraftMock = vi.fn();
const regenerateIncidentTimelineDraftMock = vi.fn();
const exportIncidentTimelineMarkdownMock = vi.fn();
const updateIncidentTimelineItemStatusMock = vi.fn();
const getIncidentTimelineStoryBundleMock = vi.fn();
let showValidationMatrix = false;

vi.mock("../api/client", () => ({
  api: {
    getIncidentTimelineDraft: (...args: unknown[]) => getIncidentTimelineDraftMock(...args),
    regenerateIncidentTimelineDraft: (...args: unknown[]) => regenerateIncidentTimelineDraftMock(...args),
    exportIncidentTimelineMarkdown: (...args: unknown[]) => exportIncidentTimelineMarkdownMock(...args),
    updateIncidentTimelineItemStatus: (...args: unknown[]) => updateIncidentTimelineItemStatusMock(...args),
    getIncidentTimelineStoryBundle: (...args: unknown[]) => getIncidentTimelineStoryBundleMock(...args),
  },
}));

vi.mock("../context/ActiveCaseContext", () => ({
  useActiveCase: () => ({
    activeCaseId: "case-1",
    selectedHost: "",
    selectedEvidenceId: "",
    setActiveCaseId: vi.fn(),
    caseContext: {
      summary: {
        validation_matrix: {
          show_validation_matrix: showValidationMatrix,
        },
      },
    },
  }),
}));

vi.mock("../context/TimezoneContext", () => ({
  useTimezonePreference: () => ({ effectiveTimezone: "UTC" }),
}));

vi.mock("../lib/time", () => ({
  formatTimestamp: (value: string) => value,
}));

function renderPage() {
  const queryClient = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  return render(
    <MemoryRouter initialEntries={["/cases/case-1/incident-timeline"]}>
      <QueryClientProvider client={queryClient}>
        <Routes>
          <Route path="/cases/:caseId/incident-timeline" element={<IncidentTimelinePage />} />
        </Routes>
      </QueryClientProvider>
    </MemoryRouter>,
  );
}

describe("IncidentTimelinePage", () => {
  beforeEach(() => {
    showValidationMatrix = false;
    Object.assign(navigator, {
      clipboard: { writeText: vi.fn().mockResolvedValue(undefined) },
    });
    getIncidentTimelineDraftMock.mockResolvedValue({
      case_id: "case-1",
      timeline_id: "timeline-1",
      query: {},
      total: 2,
      hosts: ["HOSTA", "HOSTB"],
      phases: ["execution", "lateral_movement"],
      groups: {},
      warnings: [],
      no_mft_flood_default: true,
      available_sources: ["marked_events", "command_history"],
      phase_options: ["execution", "lateral_movement", "impact", "unknown"],
      items: [
        {
          id: "item-1",
          timestamp: "2024-03-22T11:30:00Z",
          host: "HOSTA",
          phase: "lateral_movement",
          phase_confidence: "medium",
          title: "Remote admin movement",
          summary: "HOSTA to HOSTB",
          source: "command_history",
          source_type: "command_history",
          status: "accepted",
          confidence: "high",
          provenance_badge: "Command History",
          artifact_type: "command_history",
          risk_score: 90,
          search_url: "/cases/case-1/search?q=remote-admin.exe",
          execution_story_url: "/cases/case-1/process-graph?story_event_id=evt-1",
          story_target_type: "lateral_movement",
          story_target_confidence: "high",
          story_target_reason: "multi-host movement or remote execution indicator",
          story_primary_action: "Open Movement Story",
        },
      ],
    });
    regenerateIncidentTimelineDraftMock.mockResolvedValue({
      case_id: "case-1",
      timeline_id: "timeline-1",
      query: {},
      total: 1,
      hosts: ["HOSTA"],
      phases: ["lateral_movement"],
      groups: {},
      warnings: [],
      no_mft_flood_default: true,
      available_sources: ["marked_events", "command_history"],
      phase_options: ["execution", "lateral_movement", "impact", "unknown"],
      items: [],
      cache: { hit: false, persistent: true, status: "fresh" },
    });
    exportIncidentTimelineMarkdownMock.mockResolvedValue("## Incident Timeline");
    updateIncidentTimelineItemStatusMock.mockResolvedValue({ timeline_id: "timeline-1", item: {} });
    getIncidentTimelineStoryBundleMock.mockResolvedValue({
      case_id: "case-1",
      item: {
        id: "item-1",
        timestamp: "2024-03-22T11:30:00Z",
        host: "HOSTA",
        phase: "lateral_movement",
        title: "Remote admin movement",
        summary: "HOSTA to HOSTB",
        source: "command_history",
        story_target_type: "lateral_movement",
      },
      target: {
        type: "lateral_movement",
        confidence: "high",
        reason: "multi-host movement or remote execution indicator",
        primary_action: "Open Movement Story",
      },
      pivots: { find_this_file: "/cases/case-1/search?q=remote-admin.exe", open_artifact_evidence: "/cases/case-1/artifacts?host=HOSTA" },
      movement: { source_host: "HOSTA", destination_host: "HOSTB", window: "around timeline item timestamp" },
      file_story: null,
      linked_evidence: { source_type: "command_history", provenance: "Command History" },
    });
  });

  it("renders draft rows and source selector", async () => {
    renderPage();
    expect(await screen.findByText("Incident Timeline")).toBeInTheDocument();
    expect(screen.getByText(/Curated reportable story of the incident/i)).toBeInTheDocument();
    expect(await screen.findByText("Remote admin movement")).toBeInTheDocument();
    expect(screen.getAllByText("Command History").length).toBeGreaterThan(0);
    expect(screen.getByText("Movement")).toBeInTheDocument();
    expect(screen.getByRole("button", { name: /Open Movement Story/i })).toBeInTheDocument();
    expect(screen.getByRole("button", { name: /Official Timeline/i })).toBeInTheDocument();
    expect(screen.getByRole("button", { name: /Suggested Candidates/i })).toBeInTheDocument();
    expect(screen.getByText(/Raw MFT and broad EVTX excluded by default/i)).toBeInTheDocument();
    expect(screen.queryByText("Validation seeds")).not.toBeInTheDocument();
  });

  it("shows Validation seeds source only when validation is enabled for the case", async () => {
    showValidationMatrix = true;
    renderPage();
    expect(await screen.findByText("Incident Timeline")).toBeInTheDocument();
    expect(screen.getByText("Validation seeds")).toBeInTheDocument();
  });

  it("opens contextual movement evidence instead of forcing an execution story", async () => {
    renderPage();
    expect(await screen.findByText("Remote admin movement")).toBeInTheDocument();
    fireEvent.click(screen.getByRole("button", { name: /Open Movement Story/i }));
    expect(await screen.findByText("HOSTB")).toBeInTheDocument();
    expect(getIncidentTimelineStoryBundleMock).toHaveBeenCalledWith("case-1", "item-1");
  });

  it("keeps exact process items linked to Execution Story", async () => {
    getIncidentTimelineDraftMock.mockResolvedValueOnce({
      case_id: "case-1",
      timeline_id: "timeline-1",
      query: {},
      total: 1,
      hosts: ["HOSTA"],
      phases: ["execution"],
      groups: {},
      warnings: [],
      no_mft_flood_default: true,
      available_sources: ["command_history"],
      phase_options: ["execution", "unknown"],
      items: [
        {
          id: "exact-1",
          timestamp: "2024-03-22T11:30:00Z",
          host: "HOSTA",
          phase: "execution",
          title: "PowerShell script.ps1",
          summary: "powershell -ep bypass .\\f\\script.ps1",
          source: "command_history",
          source_type: "command_history",
          status: "accepted",
          confidence: "high",
          risk_score: 90,
          execution_story_url: "/cases/case-1/process-graph?story_event_id=evt-powershell",
          story_target_type: "exact_process",
          story_target_reason: "source event has process identity",
          story_primary_action: "Open Execution Story",
        },
      ],
    });
    renderPage();
    expect(await screen.findByText("PowerShell script.ps1")).toBeInTheDocument();
    const storyLink = screen.getByRole("link", { name: /Open Execution Story/i });
    expect(storyLink).toHaveAttribute("href", "/cases/case-1/process-graph?story_event_id=evt-powershell");
  });

  it("renders clean file story fields and clear pivots", async () => {
    getIncidentTimelineDraftMock.mockResolvedValueOnce({
      case_id: "case-1",
      timeline_id: "timeline-1",
      query: {},
      total: 1,
      hosts: ["HOSTA"],
      phases: ["initial_access"],
      groups: {},
      warnings: [],
      no_mft_flood_default: true,
      available_sources: ["ground_truth"],
      phase_options: ["initial_access", "unknown"],
      items: [
        {
          id: "file-1",
          timestamp: "2024-03-22T11:00:00Z",
          host: "HOSTA",
          phase: "initial_access",
          title: "Suspicious ISO appears on HOSTA",
          summary: "User activity and filesystem evidence identify the lure that starts the investigation. sample.iso",
          source: "validation_matrix",
          source_type: "validation_matrix",
          status: "accepted",
          artifact_type: "mft",
          query: "sample.iso",
          story_target_type: "file_artifact",
          story_primary_action: "Open File Story",
        },
      ],
    });
    getIncidentTimelineStoryBundleMock.mockResolvedValueOnce({
      case_id: "case-1",
      item: {
        id: "file-1",
        timestamp: "2024-03-22T11:00:00Z",
        host: "HOSTA",
        phase: "initial_access",
        title: "Suspicious ISO appears on HOSTA",
        source: "validation_matrix",
        story_target_type: "file_artifact",
      },
      target: { type: "file_artifact", primary_action: "Open File Story", reason: "artifact/file evidence only" },
      pivots: {
        find_this_file: "/cases/case-1/search?host=HOSTA&q=sample.iso",
        view_activity_around_time: "/cases/case-1/search?view=timeline&host=HOSTA&q=sample.iso",
        open_artifact_evidence: "/cases/case-1/artifacts?host=HOSTA",
      },
      movement: null,
      file_story: {
        file_name: "sample.iso",
        path_or_query: "sample.iso",
        resolution_status: "found_in_artifacts",
        found_in_mft: true,
      },
      linked_evidence: { source_type: "validation_matrix" },
    });
    renderPage();
    fireEvent.click(await screen.findByRole("button", { name: /Open File Story/i }));
    expect((await screen.findAllByText("sample.iso")).length).toBeGreaterThan(0);
    expect(screen.queryByText(/Suspicious ISO appears on HOSTA User activity/)).not.toBeInTheDocument();
    expect(screen.getByRole("link", { name: /Find this file/i })).toHaveAttribute("title", "Search for this filename/path across indexed evidence.");
    expect(screen.getByRole("link", { name: /View activity around this time/i })).toHaveAttribute("title", "Show events on this host around the item timestamp.");
  });

  it("removes a draft item without changing the story source", async () => {
    renderPage();
    expect(await screen.findByText("Remote admin movement")).toBeInTheDocument();
    fireEvent.click(screen.getByRole("button", { name: /Remove/i }));
    await waitFor(() => expect(screen.queryByText("Remote admin movement")).not.toBeInTheDocument());
  });

  it("exports visible timeline items as markdown", async () => {
    renderPage();
    await screen.findByText("Remote admin movement");
    fireEvent.click(screen.getByRole("button", { name: /Copy Markdown/i }));
    await waitFor(() => expect(exportIncidentTimelineMarkdownMock).toHaveBeenCalled());
    expect(exportIncidentTimelineMarkdownMock.mock.calls[0][1]).toMatchObject({ include_candidates: false });
    expect(navigator.clipboard.writeText).toHaveBeenCalledWith("## Incident Timeline");
  });

  it("can accept and dismiss suggested candidates", async () => {
    getIncidentTimelineDraftMock.mockResolvedValueOnce({
      case_id: "case-1",
      timeline_id: "timeline-1",
      query: {},
      total: 1,
      hosts: ["HOSTA"],
      phases: ["execution"],
      groups: {},
      warnings: [],
      no_mft_flood_default: true,
      available_sources: ["command_history"],
      phase_options: ["execution", "unknown"],
      items: [
        {
          id: "candidate-1",
          timestamp: "2024-03-22T11:30:00Z",
          host: "HOSTA",
          phase: "execution",
          title: "PowerShell candidate",
          summary: "powershell -ep bypass",
          source: "command_history",
          source_type: "command_history",
          status: "candidate",
          confidence: "medium",
          risk_score: 80,
          story_target_type: "candidate_process",
          story_target_reason: "event link exists but exact process identity is uncertain",
          story_primary_action: "Choose related process",
        },
      ],
    });
    renderPage();
    fireEvent.click(await screen.findByRole("button", { name: /Suggested Candidates/i }));
    expect(await screen.findByText("PowerShell candidate")).toBeInTheDocument();
    fireEvent.click(screen.getByRole("button", { name: /Needs review/i }));
    expect(screen.getByText("Needs Review")).toBeInTheDocument();
    fireEvent.click(screen.getByRole("button", { name: /Add to timeline/i }));
    fireEvent.click(screen.getByRole("button", { name: /Official Timeline/i }));
    expect(await screen.findByText("PowerShell candidate")).toBeInTheDocument();
  });

  it("shows cached and stale draft banners", async () => {
    getIncidentTimelineDraftMock.mockResolvedValueOnce({
      case_id: "case-1",
      timeline_id: "timeline-1",
      query: {},
      total: 1,
      hosts: ["HOSTA"],
      phases: ["execution"],
      groups: {},
      warnings: ["Timeline may be outdated."],
      no_mft_flood_default: true,
      available_sources: ["marked_events"],
      phase_options: ["execution", "unknown"],
      cache: { hit: true, persistent: true, status: "stale", stale: true, reason: "Relevant case data changed." },
      items: [],
    });
    renderPage();
    expect((await screen.findAllByText(/Timeline may be outdated/i)).length).toBeGreaterThan(0);
    expect(screen.getByRole("button", { name: /Regenerate/i })).toBeInTheDocument();
  });

  it("regenerates the persistent draft", async () => {
    renderPage();
    await screen.findByText("Remote admin movement");
    fireEvent.click(screen.getByRole("button", { name: /Regenerate/i }));
    await waitFor(() => expect(regenerateIncidentTimelineDraftMock).toHaveBeenCalled());
    expect(regenerateIncidentTimelineDraftMock.mock.calls[0][1]).toMatchObject({ max_items: 80 });
  });
});
