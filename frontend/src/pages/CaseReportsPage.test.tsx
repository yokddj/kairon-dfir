import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { fireEvent, render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { MemoryRouter, Route, Routes } from "react-router-dom";
import { beforeEach, describe, expect, it, vi } from "vitest";

import CaseReportsPage from "./CaseReportsPage";

const listReportTemplatesMock = vi.fn();
const listCaseReportsMock = vi.fn();
const createCaseReportDraftMock = vi.fn();
const getCaseReportMock = vi.fn();
const updateCaseReportMock = vi.fn();
const getCaseReportPreviewMock = vi.fn();
const listFindingsMock = vi.fn();
const listTimelineKeyEventsMock = vi.fn();
const exportCaseReportMock = vi.fn();

vi.mock("../api/client", () => ({
  api: {
    listReportTemplates: (...args: unknown[]) => listReportTemplatesMock(...args),
    listCaseReports: (...args: unknown[]) => listCaseReportsMock(...args),
    createCaseReportDraft: (...args: unknown[]) => createCaseReportDraftMock(...args),
    getCaseReport: (...args: unknown[]) => getCaseReportMock(...args),
    updateCaseReport: (...args: unknown[]) => updateCaseReportMock(...args),
    getCaseReportPreview: (...args: unknown[]) => getCaseReportPreviewMock(...args),
    listFindings: (...args: unknown[]) => listFindingsMock(...args),
    listTimelineKeyEvents: (...args: unknown[]) => listTimelineKeyEventsMock(...args),
    exportCaseReport: (...args: unknown[]) => exportCaseReportMock(...args),
  },
}));

vi.mock("../components/DebugExportDialog", () => ({
  default: () => null,
}));

vi.mock("../context/ActiveCaseContext", () => ({
  useActiveCase: () => ({
    setActiveCaseId: vi.fn(),
    selectedHost: "TEST-WIN10-01",
    selectedEvidenceId: "ev-1",
    caseContext: {
      hosts: [{ id: "host-1", canonical_name: "TEST-WIN10-01", display_name: "TEST-WIN10-01", confidence: "manual", source: "manual", event_count: 12, evidence_count: 1, findings_count: 2, high_risk_count: 1, aliases: [], alias_rows: [{ id: "alias-1", alias: "TEST-WIN10-01", normalized_alias: "test-win10-01", is_primary: true, event_count: 12 }], all_names: ["TEST-WIN10-01"], alias_count: 0 }],
      evidences: [{ id: "ev-1", name: "HOSTA.7z", status: "completed", storage_mode: "uploaded", is_external: false, events_indexed: 71033, parser_errors: 0, detected_host: "HOSTA" }],
    },
  }),
}));

function renderPage(path = "/cases/case-1/reports") {
  const queryClient = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  return render(
    <MemoryRouter initialEntries={[path]}>
      <QueryClientProvider client={queryClient}>
        <Routes>
          <Route path="/cases/:caseId/reports" element={<CaseReportsPage />} />
        </Routes>
      </QueryClientProvider>
    </MemoryRouter>,
  );
}

const reportDraft = {
  id: "report-1",
  case_id: "case-1",
  title: "Kairon DFIR Investigation Report - Case Alpha",
  status: "draft",
  template: "standard_investigation",
  created_at: "2026-05-18T07:00:00Z",
  updated_at: "2026-05-18T07:00:00Z",
  generated_at: null,
  author: null,
  time_range: {},
  filters: {
    host: "TEST-WIN10-01",
    evidence_id: "ev-1",
    min_severity: "medium",
    include_statuses: ["confirmed", "reviewed", "new"],
    detection_statuses: ["new", "reviewed", "confirmed"],
    detection_severities: ["medium", "high", "critical"],
    marking_statuses: ["suspicious", "important"],
    include_findings: true,
    include_detections: true,
    include_marked_events: true,
    include_timeline_events: true,
    include_command_history: true,
    command_only_suspicious: true,
    include_execution_stories: true,
    command_query: "",
    command_shell: "",
    command_family: "",
    command_launcher: "",
    command_source_type: "",
    command_risk_min: "",
    max_commands: 50,
    max_execution_stories: 10,
  },
  sections_enabled: {
    executive_summary: true,
    scope: true,
    evidence: true,
    hosts: true,
    findings: true,
    timeline: true,
    process_chains: true,
    command_history: true,
    iocs: true,
    persistence: true,
    network_cloud_usb: true,
    recommendations: true,
    appendix: true,
  },
  analyst_notes: {
    executive_summary: "",
    recommendations: "",
    limitations: "",
  },
  selected_finding_ids: ["finding-1"],
  selected_key_event_ids: ["bookmark-1"],
  selected_process_chain_ids: ["finding-1"],
  include_raw_appendix: false,
  include_debug_metadata: false,
};

describe("CaseReportsPage", () => {
  beforeEach(() => {
    Object.assign(navigator, { clipboard: { writeText: vi.fn().mockResolvedValue(undefined) } });
    URL.createObjectURL = vi.fn(() => "blob:test");
    URL.revokeObjectURL = vi.fn();
    listReportTemplatesMock.mockResolvedValue({ case_id: "case-1", items: [{ id: "standard_investigation", name: "Standard", description: "", sections: [] }] });
    listCaseReportsMock.mockResolvedValue([reportDraft]);
    createCaseReportDraftMock.mockResolvedValue(reportDraft);
    getCaseReportMock.mockResolvedValue(reportDraft);
    updateCaseReportMock.mockResolvedValue(reportDraft);
    getCaseReportPreviewMock.mockResolvedValue({
      title: reportDraft.title,
      warnings: [],
      stats: { selected_findings: 1, selected_key_events: 1, selected_process_chains: 1, ioc_count: 3 },
      counts: { findings_matched: 1, detections_matched: 3, marked_events_matched: 1, timeline_events_matched: 2, command_history_matched: 7, suspicious_commands_matched: 4, marked_commands_matched: 1, execution_stories_available: 2, commands_by_family: { powershell: 4 }, commands_by_launcher: { "powershell.exe": 4 } },
      filters_applied: { evidence_id: "ev-1", host: "TEST-WIN10-01", include_detections: true, include_marked_events: true, include_command_history: true, command_only_suspicious: true },
      sections: [
        { id: "executive_summary", title: "Executive Summary", markdown: "Analyst summary", warnings: [] },
        { id: "findings", title: "Findings", markdown: "Office spawned PowerShell", warnings: [] },
        { id: "command_history", title: "Suspicious Command History", markdown: "powershell.exe -ep bypass\n\n#### Execution Story: powershell.exe PID 6996", warnings: [] },
      ],
    });
    listFindingsMock.mockResolvedValue([
      { id: "finding-1", title: "Office spawned PowerShell", severity: "high", status: "confirmed", risk_score: 95, related_process_node_ids: ["proc-1"] },
    ]);
    listTimelineKeyEventsMock.mockResolvedValue([
      { id: "bookmark-1", title: "Payload executed", importance: "high", category: "execution", include_in_report: true },
    ]);
    exportCaseReportMock.mockResolvedValue({ blob: new Blob(["# Report"], { type: "text/markdown" }), filename: "case-report-case-1.md" });
  });

  it("renders reports page and preview", async () => {
    renderPage();
    expect(await screen.findByText(/Investigation narrative builder/i)).toBeInTheDocument();
    expect(await screen.findByTestId("report-preview")).toBeInTheDocument();
    expect(screen.getByRole("heading", { name: "Executive Summary" })).toBeInTheDocument();
    expect(screen.getByTestId("report-filter-chips")).toHaveTextContent("Marked events");
    expect(screen.queryByText(/Include ground truth coverage/i)).not.toBeInTheDocument();
    expect(screen.getByTestId("report-preview-counts")).toHaveTextContent("Detections");
    expect(screen.getByTestId("report-preview-counts")).toHaveTextContent("3");
    expect(screen.getByTestId("report-preview-counts")).toHaveTextContent("Commands");
    expect(screen.getByTestId("report-preview-counts")).toHaveTextContent("7");
    expect(screen.getByTestId("report-filters-applied")).toHaveTextContent("host=TEST-WIN10-01");
    expect(screen.getByText("Suspicious Command History")).toBeInTheDocument();
  });

  it("create report draft works", async () => {
    listCaseReportsMock.mockResolvedValueOnce([]);
    renderPage();
    await userEvent.click(await screen.findByRole("button", { name: /create investigation report/i }));
    await waitFor(() => expect(createCaseReportDraftMock).toHaveBeenCalled());
  });

  it("section checkboxes and notes update draft", async () => {
    renderPage();
    const appendixCheckbox = await screen.findByRole("checkbox", { name: /Appendix/i });
    await userEvent.click(appendixCheckbox);
    await waitFor(() => expect(updateCaseReportMock).toHaveBeenCalled());

    const note = screen.getByLabelText(/Executive summary note/i);
    await userEvent.clear(note);
    await userEvent.type(note, "Manual executive note");
    await userEvent.click(screen.getByRole("button", { name: /save draft/i }));
    await waitFor(() =>
      expect(updateCaseReportMock).toHaveBeenCalledWith(
        "case-1",
        "report-1",
        expect.objectContaining({
          analyst_notes: expect.objectContaining({ executive_summary: "Manual executive note" }),
        }),
      ),
    );
  });

  it("updates report filters and exposes advanced report filters", async () => {
    renderPage();

    await userEvent.selectOptions(await screen.findByLabelText(/Host filter/i), "TEST-WIN10-01");
    await waitFor(() =>
      expect(updateCaseReportMock).toHaveBeenCalledWith(
        "case-1",
        "report-1",
        expect.objectContaining({
          filters: expect.objectContaining({ host: "TEST-WIN10-01" }),
        }),
      ),
    );

    await userEvent.click(screen.getByRole("button", { name: /Advanced filters/i }));
    expect(await screen.findByTestId("advanced-report-filters")).toBeInTheDocument();
    await userEvent.click(screen.getAllByRole("checkbox", { name: /dismissed/i }).at(-1)!);
    await waitFor(() =>
      expect(updateCaseReportMock).toHaveBeenCalledWith(
        "case-1",
        "report-1",
        expect.objectContaining({
          filters: expect.objectContaining({ detection_statuses: expect.arrayContaining(["dismissed"]) }),
        }),
      ),
    );
  });

  it("updates command history report filters", async () => {
    renderPage();
    expect((await screen.findAllByText("Command History")).length).toBeGreaterThan(0);
    fireEvent.change(screen.getByPlaceholderText(/remote-admin, maintenance\.ps1/i), { target: { value: "remote-admin" } });
    await waitFor(() =>
      expect(updateCaseReportMock).toHaveBeenCalledWith(
        "case-1",
        "report-1",
        expect.objectContaining({
          filters: expect.objectContaining({ command_query: "remote-admin" }),
        }),
      ),
    );

    await userEvent.click(screen.getByRole("checkbox", { name: /Include execution stories/i }));
    await waitFor(() =>
      expect(updateCaseReportMock).toHaveBeenCalledWith(
        "case-1",
        "report-1",
        expect.objectContaining({
          filters: expect.objectContaining({ include_execution_stories: false }),
        }),
      ),
    );
  });

  it("lists findings and key events", async () => {
    renderPage();
    expect((await screen.findAllByText("Office spawned PowerShell")).length).toBeGreaterThan(0);
    expect(screen.getByText("Payload executed")).toBeInTheDocument();
  });

  it("export markdown button calls endpoint", async () => {
    renderPage();
    await userEvent.click(await screen.findByRole("button", { name: /export markdown/i }));
    await waitFor(() => expect(exportCaseReportMock).toHaveBeenCalledWith("case-1", "report-1", "markdown"));
  });

  it("pdf button shows error state on failure", async () => {
    exportCaseReportMock.mockRejectedValueOnce(new Error("renderer unavailable"));
    renderPage();
    await userEvent.click(await screen.findByRole("button", { name: /export pdf/i }));
    expect(await screen.findByText(/PDF export failed: renderer unavailable/i)).toBeInTheDocument();
  });

  it("pdf button calls endpoint", async () => {
    exportCaseReportMock.mockResolvedValueOnce({ blob: new Blob(["%PDF-1.4"], { type: "application/pdf" }), filename: "report.pdf" });
    renderPage();
    await userEvent.click(await screen.findByRole("button", { name: /export pdf/i }));
    await waitFor(() => expect(exportCaseReportMock).toHaveBeenCalledWith("case-1", "report-1", "pdf"));
  });
});
