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
const listResumableEvidenceUploadsMock = vi.fn();

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
    listResumableEvidenceUploads: (...args: unknown[]) => listResumableEvidenceUploadsMock(...args),
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
vi.mock("../components/EvidenceIngestionWizard", () => ({
  default: ({ open, onClose }: { open: boolean; onClose: () => void }) => (
    open ? (
      <div role="dialog" aria-label="Add Evidence" data-testid="evidence-ingestion-wizard">
        <button type="button" onClick={onClose}>Close wizard</button>
      </div>
    ) : null
  ),
}));
vi.mock("../components/EventTable", () => ({ default: () => <div data-testid="event-table" /> }));
vi.mock("../components/FindingsWorkspace", () => ({ default: () => <div data-testid="findings-workspace" /> }));
vi.mock("../components/ProcessTreePanel", () => ({ default: () => <div data-testid="process-tree" /> }));
vi.mock("../components/Timeline", () => ({ default: () => <div data-testid="timeline" /> }));
vi.mock("../components/CreateFindingDialog", () => ({ default: () => null }));
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

function renderPage(initialEntry = "/cases/case-1?tab=processing") {
  const queryClient = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  return render(
    <MemoryRouter initialEntries={[initialEntry]}>
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
    listResumableEvidenceUploadsMock.mockResolvedValue({ case_id: "case-1", sessions: [] });
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

  it("uses the guided wizard as the primary evidences tab ingestion action", async () => {
    renderPage("/cases/case-1?tab=evidences");

    expect(await screen.findByRole("heading", { name: "Queue Case" })).toBeInTheDocument();
    expect(screen.getByRole("button", { name: /^Add Evidence$/i })).toBeInTheDocument();
    expect(screen.queryByTestId("evidence-upload")).not.toBeInTheDocument();

    await userEvent.click(screen.getByRole("button", { name: /^Add Evidence$/i }));

    expect(screen.getByRole("dialog", { name: "Add Evidence" })).toBeInTheDocument();
  });

  it("replaces advanced upload with guidance to the canonical wizard", async () => {
    renderPage("/cases/case-1?tab=evidences");

    await screen.findByRole("heading", { name: "Queue Case" });
    expect(screen.queryByTestId("evidence-upload")).not.toBeInTheDocument();
    expect(screen.queryByText(/Advanced upload/i)).not.toBeInTheDocument();
    expect(screen.getByText(/intake now starts from the same Add Evidence wizard/i)).toBeInTheDocument();
  });

  it("returns to the evidences tab when the guided wizard is closed", async () => {
    renderPage("/cases/case-1?tab=evidences");

    await screen.findByRole("heading", { name: "Queue Case" });
    await userEvent.click(screen.getByRole("button", { name: /^Add Evidence$/i }));
    await userEvent.click(screen.getByRole("button", { name: /Close wizard/i }));

    expect(screen.queryByRole("dialog", { name: "Add Evidence" })).not.toBeInTheDocument();
    expect(screen.getByRole("button", { name: /^Add Evidence$/i })).toBeInTheDocument();
    expect(screen.getByText(/Use Add Evidence for guided ingestion/i)).toBeInTheDocument();
  });

  it("keeps the overview Add Evidence button wired to the guided wizard", async () => {
    renderPage("/cases/case-1");

    await screen.findByRole("heading", { name: "Queue Case" });
    await userEvent.click(screen.getByRole("button", { name: /^Add Evidence$/i }));

    expect(screen.getByRole("dialog", { name: "Add Evidence" })).toBeInTheDocument();
  });

  it("opens processing detail and shows parser error state", async () => {
    renderPage();
    await screen.findByText("failed.zip");

    await userEvent.click(screen.getByTestId("select-processing-ev-failed"));

    const panel = await screen.findByTestId("processing-detail-panel");
    expect(panel).toHaveTextContent("failed.zip");
    expect(screen.getAllByText("Parser crashed").length).toBeGreaterThan(0);
    expect(screen.getAllByText("evtx").length).toBeGreaterThan(0);
    expect(within(panel).getByTestId("processing-detail-open-evidence")).toHaveAttribute("href", "/evidences/ev-failed");
  });

  it("no longer renders a View details button -- selecting a row is done by clicking its filename", async () => {
    renderPage();
    await screen.findByText("failed.zip");

    expect(screen.queryByRole("button", { name: /View details/i })).not.toBeInTheDocument();
  });

  it("removes the Actions column and moves Open evidence / Open artifacts to the detail panel only", async () => {
    renderPage();
    await screen.findByText("failed.zip");

    expect(screen.queryByText("Actions")).not.toBeInTheDocument();
    const failedRow = screen.getByText("failed.zip").closest("tr")!;
    expect(within(failedRow).queryByRole("link", { name: /Open evidence/i })).not.toBeInTheDocument();
    expect(within(failedRow).queryByRole("link", { name: /Open artifacts/i })).not.toBeInTheDocument();

    await userEvent.click(screen.getByTestId("select-processing-ev-failed"));
    const panel = await screen.findByTestId("processing-detail-panel");
    expect(within(panel).getByTestId("processing-detail-open-evidence")).toBeInTheDocument();
  });

  it("keeps Open artifacts visible but disabled when the selected evidence has no artifacts yet", async () => {
    renderPage();
    await screen.findByText("pending.zip");

    await userEvent.click(screen.getByTestId("select-processing-ev-pending"));
    const panel = await screen.findByTestId("processing-detail-panel");
    const artifactsControl = within(panel).getByTestId("processing-detail-open-artifacts");
    expect(artifactsControl.tagName).toBe("BUTTON");
    expect(artifactsControl).toBeDisabled();
  });

  it("enables Open artifacts in the detail panel once artifacts exist", async () => {
    renderPage();
    await screen.findAllByText("complete.zip");

    await userEvent.click(await screen.findByTestId("select-processing-ev-complete"));
    const panel = await screen.findByTestId("processing-detail-panel");
    const artifactsControl = within(panel).getByTestId("processing-detail-open-artifacts");
    expect(artifactsControl.tagName).toBe("A");
    expect(artifactsControl).toHaveAttribute("href", "/cases/case-1/artifacts?evidence_id=ev-complete");
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
    await screen.findAllByText("ubuntu-disk.zip");
    await userEvent.click(screen.getByTestId("select-processing-ev-linux"));

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

  describe("resumable uploads panel on the Evidence tab", () => {
    function resumableSession(overrides: Record<string, unknown> = {}) {
      return {
        id: "resume-1",
        case_id: "case-1",
        backend: "unified",
        category: "memory_dump",
        original_filename: "capture.mem",
        expected_size_bytes: 32,
        bytes_received: 16,
        progress_percent: 50,
        status: "uploading",
        current_stage: "uploading",
        created_at: "2026-01-01T00:00:00Z",
        updated_at: "2026-01-01T00:00:00Z",
        expires_at: "2026-01-02T00:00:00Z",
        resumable: true,
        cancellable: true,
        promoted_evidence_id: null,
        failure_message: null,
        unified: null,
        ...overrides,
      };
    }

    it("shows an in-progress upload above Add Evidence", async () => {
      listResumableEvidenceUploadsMock.mockResolvedValue({ case_id: "case-1", sessions: [resumableSession()] });
      renderPage("/cases/case-1?tab=evidences");
      await screen.findByRole("heading", { name: "Queue Case" });

      const panel = await screen.findByTestId("case-resumable-uploads-panel");
      expect(within(panel).getByText("capture.mem")).toBeInTheDocument();
    });

    it("excludes a session that already reached 100% -- it's done, not interrupted or active", async () => {
      listResumableEvidenceUploadsMock.mockResolvedValue({
        case_id: "case-1",
        sessions: [resumableSession({ id: "resume-done", original_filename: "done.mem", progress_percent: 100, status: "staged" })],
      });
      renderPage("/cases/case-1?tab=evidences");
      await screen.findByRole("heading", { name: "Queue Case" });
      await screen.findByText("Add evidence");

      expect(screen.queryByTestId("case-resumable-uploads-panel")).not.toBeInTheDocument();
    });

    it("keeps an in-progress session visible next to one that already finished", async () => {
      listResumableEvidenceUploadsMock.mockResolvedValue({
        case_id: "case-1",
        sessions: [resumableSession(), resumableSession({ id: "resume-done", original_filename: "done.mem", progress_percent: 100, status: "staged" })],
      });
      renderPage("/cases/case-1?tab=evidences");
      await screen.findByRole("heading", { name: "Queue Case" });

      const panel = await screen.findByTestId("case-resumable-uploads-panel");
      expect(within(panel).getByText("capture.mem")).toBeInTheDocument();
      expect(within(panel).queryByText("done.mem")).not.toBeInTheDocument();
    });
  });
});
