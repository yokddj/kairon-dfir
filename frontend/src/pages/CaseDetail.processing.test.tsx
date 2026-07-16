import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { render, screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { MemoryRouter, Route, Routes } from "react-router-dom";
import { beforeEach, describe, expect, it, vi } from "vitest";

import CaseDetail from "./CaseDetail";

const getCaseMock = vi.fn();
const listEvidencesMock = vi.fn();
const listArtifactsMock = vi.fn();
const listFindingsMock = vi.fn();
const listDetectionsMock = vi.fn();
const getInvestigationSummaryMock = vi.fn();
const listCaseActivityMock = vi.fn();
const siemExternalLinksMock = vi.fn();
const getCaseProcessingMock = vi.fn();
const updateCaseMock = vi.fn();
const deleteCaseMock = vi.fn();
const archiveCaseMock = vi.fn();
const unarchiveCaseMock = vi.fn();
const closeCaseMock = vi.fn();
const reopenCaseMock = vi.fn();
const searchMock = vi.fn();
const timelineMock = vi.fn();

vi.mock("../api/client", () => ({
  api: {
    getCase: (...args: unknown[]) => getCaseMock(...args),
    listEvidences: (...args: unknown[]) => listEvidencesMock(...args),
    listArtifacts: (...args: unknown[]) => listArtifactsMock(...args),
    listFindings: (...args: unknown[]) => listFindingsMock(...args),
    listDetections: (...args: unknown[]) => listDetectionsMock(...args),
    getInvestigationSummary: (...args: unknown[]) => getInvestigationSummaryMock(...args),
    listCaseActivity: (...args: unknown[]) => listCaseActivityMock(...args),
    siemExternalLinks: (...args: unknown[]) => siemExternalLinksMock(...args),
    getCaseProcessing: (...args: unknown[]) => getCaseProcessingMock(...args),
    updateCase: (...args: unknown[]) => updateCaseMock(...args),
    deleteCase: (...args: unknown[]) => deleteCaseMock(...args),
    archiveCase: (...args: unknown[]) => archiveCaseMock(...args),
    unarchiveCase: (...args: unknown[]) => unarchiveCaseMock(...args),
    closeCase: (...args: unknown[]) => closeCaseMock(...args),
    reopenCase: (...args: unknown[]) => reopenCaseMock(...args),
    search: (...args: unknown[]) => searchMock(...args),
    timeline: (...args: unknown[]) => timelineMock(...args),
  },
}));

vi.mock("../context/ActiveCaseContext", () => ({
  useActiveCase: () => ({ activeCaseId: "case-1", clearActiveCase: vi.fn(), setActiveCase: vi.fn() }),
}));

const notifyMock = vi.fn();
vi.mock("../context/NotificationsContext", () => ({
  useNotifications: () => ({ notify: notifyMock }),
}));

vi.mock("../components/EvidenceUpload", () => ({ default: () => <div data-testid="evidence-upload" /> }));
vi.mock("../components/EventTable", () => ({ default: () => <div data-testid="event-table" /> }));
vi.mock("../components/FindingsWorkspace", () => ({ default: () => <div data-testid="findings-workspace" /> }));
vi.mock("../components/ProcessTreePanel", () => ({ default: () => <div data-testid="process-tree" /> }));
vi.mock("../components/Timeline", () => ({ default: () => <div data-testid="timeline" /> }));
vi.mock("../components/CreateFindingDialog", () => ({ default: () => null }));
vi.mock("../components/DebugExportDialog", () => ({ default: () => null }));
vi.mock("../components/ArtifactBadge", () => ({ default: ({ type }: { type: string }) => <span>{type}</span> }));

function processingFixture(overrides: Record<string, unknown> = {}) {
  const base = {
    case_id: "case-1",
    summary: { pending: 1, queued: 0, running: 1, completed: 1, completed_with_warnings: 1, failed: 1, cancelled: 0, unknown: 0 },
    items: [
      item({ evidence_id: "ev-complete", filename: "complete.zip", host: "WS-01", processing_status: "completed", successful_parser_count: 2, failed_parser_count: 0, artifact_count: 12 }),
      item({ evidence_id: "ev-running", filename: "running.zip", host: "WS-02", processing_status: "running", successful_parser_count: 1, failed_parser_count: 0, artifact_count: 3, runs: [{ run_id: "run-active", status: "running", started_at: "2026-01-01T00:02:00Z", finished_at: null, duration: null, triggered_by: "ingest", parser_family: "artifact", parser_name: "ingest", message: "Parsing", error_summary: null, error_details: {}, artifact_count: 3 }] }),
      item({ evidence_id: "ev-failed", filename: "failed.zip", host: "WS-03", processing_status: "failed", successful_parser_count: 0, failed_parser_count: 1, artifact_count: 0, last_error: "Parser crashed", errors: [{ parser: "evtx", summary: "Parser crashed", details: {} }], parser_runs: [{ parser: "evtx", family: "artifact", status: "failed", artifacts: 0, records: 0, error: "Parser crashed" }] }),
      item({ evidence_id: "ev-pending", filename: "pending.zip", host: "WS-04", processing_status: "pending", successful_parser_count: 0, failed_parser_count: 0, artifact_count: 0, runs: [], parser_runs: [] }),
    ],
  };
  return { ...base, ...overrides };
}

function item(overrides: Record<string, unknown>) {
  return {
    evidence_id: "ev-1",
    case_id: "case-1",
    filename: "evidence.zip",
    evidence_type: "velociraptor_zip",
    host: "WS-01",
    uploaded_at: "2026-01-01T00:00:00Z",
    processing_status: "completed",
    last_run_status: "completed",
    last_run_started_at: "2026-01-01T00:00:00Z",
    last_run_finished_at: "2026-01-01T00:01:00Z",
    duration: 60,
    parser_count: 1,
    successful_parser_count: 1,
    failed_parser_count: 0,
    warning_count: 0,
    artifact_count: 1,
    last_error: null,
    runs: [{ run_id: "run-1", status: "completed", started_at: "2026-01-01T00:00:00Z", finished_at: "2026-01-01T00:01:00Z", duration: 60, triggered_by: "ingest", parser_family: "artifact", parser_name: "ingest", message: "Run recorded", error_summary: null, error_details: {}, artifact_count: 1 }],
    parser_runs: [{ parser: "evtx", family: "artifact", status: "completed", artifacts: 1, records: 1, error: null }],
    errors: [],
    links: { evidence: "/evidences/ev-1", artifacts: "/cases/case-1/artifacts?evidence_id=ev-1", search: "/cases/case-1/search?evidence_id=ev-1" },
    ...overrides,
  };
}

function renderPage() {
  const queryClient = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  return render(
    <MemoryRouter initialEntries={["/cases/case-1?tab=processing"]}>
      <QueryClientProvider client={queryClient}>
        <Routes>
          <Route path="/cases/:caseId" element={<CaseDetail />} />
        </Routes>
      </QueryClientProvider>
    </MemoryRouter>,
  );
}

describe("CaseDetail Processing Queue", () => {
  beforeEach(() => {
    vi.clearAllMocks();
    getCaseMock.mockResolvedValue({ id: "case-1", name: "Queue Case", description: "Queue description", status: "active", priority: "critical", tags: ["ctf", "memory"], case_notes: "Queue notes", timezone: null, evidence_count: 4, host_count: 3, processing_summary: { completed: 1, running: 1, failed: 1 }, detections_count: 0, findings_count: 0, created_at: "2026-01-01T00:00:00Z", updated_at: "2026-01-02T00:00:00Z" });
    listEvidencesMock.mockResolvedValue([]);
    listArtifactsMock.mockResolvedValue([]);
    listFindingsMock.mockResolvedValue([]);
    listDetectionsMock.mockResolvedValue({ items: [] });
    getInvestigationSummaryMock.mockResolvedValue({ counts: { detections: 0, findings: 0 }, successful_logons: 0, failed_logons: 0, scheduled_task_events: 0, service_install_events: 0, deleted_files: 0, top_hosts: [], top_users: [], top_processes: [], top_domains: [], recent_high_severity_events: [] });
    listCaseActivityMock.mockResolvedValue([]);
    siemExternalLinksMock.mockResolvedValue({});
    getCaseProcessingMock.mockResolvedValue(processingFixture());
  });

  it("renders evidences, parser counts and all core statuses", async () => {
    renderPage();

    expect((await screen.findAllByText("complete.zip")).length).toBeGreaterThan(0);
    expect(screen.getByTestId("processing-queue-view")).toBeInTheDocument();
    expect(screen.getByText("running.zip")).toBeInTheDocument();
    expect(screen.getByText("failed.zip")).toBeInTheDocument();
    expect(screen.getByText("pending.zip")).toBeInTheDocument();
    expect(screen.getAllByText("completed").length).toBeGreaterThan(0);
    expect(screen.getAllByText("running").length).toBeGreaterThan(0);
    expect(screen.getAllByText("failed").length).toBeGreaterThan(0);
    expect(screen.getAllByText("pending").length).toBeGreaterThan(0);
    const failedRow = screen.getByText("failed.zip").closest("tr")!;
    expect(within(failedRow).getByText("1")).toBeInTheDocument();
  });

  it("opens processing detail and shows parser error state", async () => {
    renderPage();
    await screen.findByText("failed.zip");

    const failedRow = screen.getByText("failed.zip").closest("tr")!;
    await userEvent.click(within(failedRow).getByRole("button", { name: /View details/i }));

    expect(await screen.findByTestId("processing-detail-panel")).toHaveTextContent("failed.zip");
    expect(screen.getAllByText("Parser crashed").length).toBeGreaterThan(0);
    expect(screen.getAllByText("evtx").length).toBeGreaterThan(0);
    expect(within(failedRow).getByRole("link", { name: /Open evidence/i })).toHaveAttribute("href", "/evidences/ev-failed");
  });

  it("shows Linux source counts separately from parsed event counts", async () => {
    getCaseProcessingMock.mockResolvedValueOnce(processingFixture({
      items: [item({
        evidence_id: "ev-linux",
        filename: "ubuntu-disk.zip",
        host: "vm-101",
        linux_artifacts: [
          { name: "shell history", family: "linux_shell_history", status: "Parsed", paths: ["home/alice/.bash_history"], source_count: 1, records: 0 },
          { name: "packages", family: "packages", status: "Not inspected", paths: [], source_count: 0, records: 0 },
        ],
      })],
    }));
    renderPage();
    const row = (await screen.findAllByText("ubuntu-disk.zip"))[0].closest("tr")!;
    await userEvent.click(within(row).getByRole("button", { name: /View details/i }));

    const linuxTable = await screen.findByTestId("linux-processing-artifacts");
    expect(within(linuxTable).getByText("Sources found")).toBeInTheDocument();
    expect(within(linuxTable).getByText("Events parsed")).toBeInTheDocument();
    const shellRow = within(linuxTable).getByText("shell history").closest("tr")!;
    expect(within(shellRow).getByText("Parsed")).toBeInTheDocument();
    expect(within(shellRow).getByText("1")).toBeInTheDocument();
    expect(within(shellRow).getByText("0")).toBeInTheDocument();
    expect(within(linuxTable).getByText("Not inspected")).toBeInTheDocument();
  });

  it("shows empty state when there are no processing runs", async () => {
    getCaseProcessingMock.mockResolvedValueOnce(processingFixture({ summary: {}, items: [] }));
    renderPage();

    expect(await screen.findByText(/No processing runs yet/i)).toBeInTheDocument();
  });

  it("keeps the active case and supports multiple hosts", async () => {
    renderPage();

    expect(await screen.findByText("WS-01")).toBeInTheDocument();
    expect(screen.getByText("WS-02")).toBeInTheDocument();
    expect(screen.getByText("WS-03")).toBeInTheDocument();
    expect(getCaseProcessingMock).toHaveBeenCalledWith("case-1", { host_id: undefined, host: undefined });
  });

  it("shows case management metadata and saves edits", async () => {
    updateCaseMock.mockResolvedValue({ id: "case-1", name: "Queue Case", description: "Updated", status: "active", priority: "high", tags: ["lab"], case_notes: "Updated notes", timezone: null, evidence_count: 4, host_count: 3, processing_summary: {}, detections_count: 0, findings_count: 0, created_at: "2026-01-01T00:00:00Z", updated_at: "2026-01-02T00:00:00Z" });
    renderPage();
    const panel = await screen.findByTestId("case-management-metadata");
    await waitFor(() => expect(panel).toHaveTextContent("critical"));
    expect(panel).toHaveTextContent("ctf, memory");
    expect(panel).toHaveTextContent("Queue notes");
    await userEvent.click(screen.getByRole("button", { name: /Edit case/i }));
    const dialog = screen.getByRole("dialog", { name: /Edit case/i });
    await userEvent.selectOptions(within(dialog).getByLabelText(/Priority/i), "high");
    await userEvent.clear(within(dialog).getByLabelText(/Tags/i));
    await userEvent.type(within(dialog).getByLabelText(/Tags/i), "lab");
    await userEvent.click(within(dialog).getByRole("button", { name: /Save case/i }));
    await waitFor(() => expect(updateCaseMock).toHaveBeenCalledWith("case-1", expect.objectContaining({ priority: "high", tags: ["lab"] })));
  });

  it("archives and reopens via lifecycle actions", async () => {
    archiveCaseMock.mockResolvedValue({ id: "case-1", name: "Queue Case", status: "archived" });
    closeCaseMock.mockResolvedValue({ id: "case-1", name: "Queue Case", status: "closed" });
    vi.spyOn(window, "confirm").mockReturnValue(true);
    renderPage();
    await screen.findByRole("heading", { name: "Queue Case" });
    await userEvent.click(screen.getByRole("button", { name: /Archive case/i }));
    await waitFor(() => expect(archiveCaseMock).toHaveBeenCalledWith("case-1"));
    await userEvent.click(screen.getByRole("button", { name: /Close case/i }));
    await waitFor(() => expect(closeCaseMock).toHaveBeenCalledWith("case-1"));
  });

  it("requires typing the exact case name before the delete case action is enabled", async () => {
    renderPage();
    await screen.findByRole("heading", { name: "Queue Case" });

    await userEvent.click(screen.getByRole("button", { name: /Delete case/i }));
    const dialog = await screen.findByRole("dialog", { name: "Delete Case" });
    const confirmButton = within(dialog).getByRole("button", { name: "Delete Case" });
    expect(confirmButton).toBeDisabled();

    await userEvent.type(within(dialog).getByRole("textbox"), "Queue Cas");
    expect(confirmButton).toBeDisabled();
    expect(deleteCaseMock).not.toHaveBeenCalled();
  });

  it("deletes the case once its exact name is typed and confirmed", async () => {
    deleteCaseMock.mockResolvedValue({ status: "deleted", case_id: "case-1", cleanup: {} });
    renderPage();
    await screen.findByRole("heading", { name: "Queue Case" });

    await userEvent.click(screen.getByRole("button", { name: /Delete case/i }));
    const dialog = await screen.findByRole("dialog", { name: "Delete Case" });
    await userEvent.type(within(dialog).getByRole("textbox"), "Queue Case");
    await userEvent.click(within(dialog).getByRole("button", { name: "Delete Case" }));

    await waitFor(() => expect(deleteCaseMock).toHaveBeenCalledWith("case-1"));
  });
});
