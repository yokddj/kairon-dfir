import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { render, screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { MemoryRouter, Route, Routes } from "react-router-dom";
import { beforeEach, describe, expect, it, vi } from "vitest";

import EvidenceDetail from "./EvidenceDetail";

const mocks = {
  getEvidence: vi.fn(),
  getEvidenceRuns: vi.fn(),
  getEvidenceIndexingPlan: vi.fn(),
  getEvidenceSearchSummary: vi.fn(),
  getProblematicArtifacts: vi.fn(),
  getCaseHosts: vi.fn(),
  updateEvidenceHost: vi.fn(),
  runEvidenceIndexingPlan: vi.fn(),
  parseVelociraptorSelection: vi.fn(),
  pauseEvidenceIndexing: vi.fn(),
  cancelEvidenceIndexing: vi.fn(),
  retryProblematicArtifact: vi.fn(),
  retryProblematicArtifacts: vi.fn(),
  previewReprocessEvidence: vi.fn(),
  reprocessEvidence: vi.fn(),
  deleteEvidence: vi.fn(),
  getEvidenceIntegrity: vi.fn(),
  getEvidenceCustodyEvents: vi.fn(),
  verifyEvidenceIntegrity: vi.fn(),
  exportEvidenceManifest: vi.fn(),
  getEvidenceMftDiagnostic: vi.fn(),
  getEvidenceRegistryDiagnostic: vi.fn(),
  listArtifacts: vi.fn(),
  listSourceTables: vi.fn(),
};

vi.mock("../api/client", () => ({
  api: new Proxy({}, { get: (_target, key: string) => (...args: unknown[]) => (mocks as Record<string, (...a: unknown[]) => unknown>)[key]?.(...args) }),
}));

const notifyMock = vi.fn();
vi.mock("../context/NotificationsContext", () => ({ useNotifications: () => ({ notify: notifyMock }) }));
vi.mock("../context/ActiveCaseContext", () => ({
  useActiveCase: () => ({ caseContext: { hosts: [] }, setActiveCaseId: vi.fn() }),
}));
vi.mock("../lib/useInvestigationBreadcrumbs", () => ({ useInvestigationBreadcrumbs: () => [] }));
vi.mock("../components/InvestigationContext", () => ({ InvestigationBreadcrumbs: () => null }));

const RECENT = new Date(Date.now() - 20_000).toISOString();

function evidence(overrides: Record<string, unknown> = {}, metadata: Record<string, unknown> = {}) {
  return {
    id: "evidence-1",
    case_id: "case-1",
    original_filename: "collection.tar.gz",
    stored_path: "/data/evidence-1",
    original_path: null,
    evidence_type: "macos_triage",
    effective_platform: "macos",
    ingest_status: "completed",
    size_bytes: 2048,
    sha256: "ab".repeat(32),
    detected_host: "HOST-A",
    host_id: "host-1",
    provided_host: null,
    metadata_json: metadata,
    error_log: {},
    created_at: "2026-01-01T00:00:00Z",
    platform_profile: { categories: [] },
    ...overrides,
  };
}

function setup({
  ev = evidence(),
  runs = [] as unknown[],
  plan = { active: false, can_run: true, state: "ready" } as Record<string, unknown>,
  counts = { macos_logs: 120, browser: 40 } as Record<string, number>,
  problems = [] as unknown[],
} = {}) {
  mocks.getEvidence.mockResolvedValue(ev);
  mocks.getEvidenceRuns.mockResolvedValue(runs);
  mocks.getEvidenceIndexingPlan.mockResolvedValue(plan);
  mocks.getEvidenceSearchSummary.mockResolvedValue({ total_indexed_docs: Object.values(counts).reduce((a, b) => a + b, 0), artifact_type_counts: counts });
  mocks.getProblematicArtifacts.mockResolvedValue({ items: problems, summary: {} });
  mocks.getCaseHosts.mockResolvedValue({ case_id: "case-1", hosts: [{ id: "host-1", display_name: "HOST-A" }, { id: "host-2", display_name: "HOST-B" }], host_candidates: [] });
  mocks.getEvidenceIntegrity.mockResolvedValue({ integrity_status: "verified", sha256: "ab".repeat(32) });
  mocks.getEvidenceCustodyEvents.mockResolvedValue([]);
  mocks.listArtifacts.mockResolvedValue([]);
  mocks.listSourceTables.mockResolvedValue({ items: [] });
  mocks.getEvidenceMftDiagnostic.mockResolvedValue({});
  mocks.getEvidenceRegistryDiagnostic.mockResolvedValue({});
  const queryClient = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  return render(
    <MemoryRouter initialEntries={["/evidences/evidence-1"]}>
      <QueryClientProvider client={queryClient}>
        <Routes>
          <Route path="/evidences/:evidenceId" element={<EvidenceDetail />} />
        </Routes>
      </QueryClientProvider>
    </MemoryRouter>,
  );
}

function emptyFile(name: string) {
  return { artifact_id: name, name, source_path: `/x/${name}`, artifact_type: "macos_recent_items", parser: "sfl", status: "skipped_empty", records_read: 0, records_indexed: 0, data_loss_expected: false, retryable: false };
}

beforeEach(() => {
  Object.values(mocks).forEach((mock) => mock.mockReset());
  notifyMock.mockReset();
});

describe("EvidenceDetail", () => {
  it("shows a ready evidence with what was found, and empty files only as a note", async () => {
    setup({ problems: [emptyFile("a.sfl4"), emptyFile("b.sfl4")] });
    expect(await screen.findByTestId("evidence-status")).toHaveTextContent(/^Ready$/);
    const results = await screen.findByTestId("evidence-results");
    expect(within(results).getByText("160")).toBeInTheDocument();
    expect(within(results).getByText("120").closest("a")).toHaveAttribute("href", "/cases/case-1/artifacts?evidence_id=evidence-1&artifact_type=macos_logs");
    expect(within(results).getByTestId("evidence-empty-note")).toHaveTextContent("2 files held no records");
    expect(screen.queryByTestId("evidence-failures")).not.toBeInTheDocument();
    expect(screen.queryByTestId("evidence-warnings")).not.toBeInTheDocument();
    expect(screen.queryByText(/Choose what to index/)).not.toBeInTheDocument();
    expect(screen.getByRole("link", { name: "Search this evidence" })).toBeInTheDocument();
    expect(screen.getByRole("navigation", { name: "Open this evidence in" })).toHaveTextContent("Timeline");
  });

  it("claims nothing about the families while their counts are still loading", async () => {
    setup();
    mocks.getEvidenceSearchSummary.mockReturnValue(new Promise(() => {}));
    const results = await screen.findByTestId("evidence-results");
    expect(within(results).queryByText(/Nothing searchable was indexed/)).not.toBeInTheDocument();
  });

  it("lists real failures and retries only the retryable ones", async () => {
    mocks.retryProblematicArtifact.mockResolvedValue({});
    setup({
      problems: [
        { ...emptyFile("x"), artifact_id: "bad-1", name: "Security.evtx", status: "failed", error_message: "parser timeout", data_loss_expected: true, retryable: true },
        emptyFile("y"),
      ],
    });
    expect(await screen.findByTestId("evidence-status")).toHaveTextContent("Ready · 1 failed");
    const failures = await screen.findByTestId("evidence-failures");
    expect(within(failures).getByText("parser timeout")).toBeInTheDocument();
    await userEvent.click(within(failures).getByRole("button", { name: "Retry it" }));
    await waitFor(() => expect(mocks.retryProblematicArtifact).toHaveBeenCalledWith("evidence-1", "bad-1", expect.objectContaining({ mode: "higher_timeout" })));
  });

  it("shows one progress block with the current run's own numbers", async () => {
    mocks.pauseEvidenceIndexing.mockResolvedValue({});
    setup({
      ev: evidence({ ingest_status: "processing" }, { current_ingest_run_id: "old-run", elapsed_seconds: 3720, artifacts_total: 300, artifacts_done: 300 }),
      runs: [{ run_id: "run-2", run_type: "reprocess", status: "running", phase: "parsing", started_at: RECENT, heartbeat_at: RECENT, artifacts_done: 129, artifacts_total: 0, records_indexed: 5000 }],
      plan: { active: true, can_run: false },
    });
    const panel = await screen.findByTestId("evidence-processing");
    expect(within(panel).getByText(/129 artifacts/)).toBeInTheDocument();
    expect(within(panel).queryByText(/\/ 0/)).not.toBeInTheDocument();
    expect(within(panel).queryByText(/1h/)).not.toBeInTheDocument();
    expect(within(panel).getByTestId("evidence-progress-indeterminate")).toBeInTheDocument();
    expect(within(screen.getByTestId("evidence-processing-steps")).getByText(/Parse/).closest("[data-status]")).toHaveAttribute("data-status", "current");
    expect(screen.getAllByTestId("evidence-processing")).toHaveLength(1);
    expect(screen.queryByTestId("evidence-results")).not.toBeInTheDocument();
    await userEvent.click(within(panel).getByRole("button", { name: "Pause" }));
    await waitFor(() => expect(mocks.pauseEvidenceIndexing).toHaveBeenCalled());
  });

  it("offers to cancel a run whose worker went silent", async () => {
    mocks.cancelEvidenceIndexing.mockResolvedValue({});
    setup({
      ev: evidence({ ingest_status: "processing" }),
      runs: [{ run_id: "run-2", run_type: "ingest", status: "running", heartbeat_at: new Date(Date.now() - 30 * 60_000).toISOString() }],
    });
    expect(await screen.findByTestId("evidence-status")).toHaveTextContent("Stalled");
    await userEvent.click(screen.getByRole("button", { name: "Cancel stalled run" }));
    await waitFor(() => expect(mocks.cancelEvidenceIndexing).toHaveBeenCalled());
  });

  it("shows processing while an indexing-plan job runs after ingest completed", async () => {
    setup({ plan: { active: true, can_run: false } });
    expect(await screen.findByTestId("evidence-status")).toHaveTextContent("Processing");
    expect(screen.getByRole("button", { name: "Pause" })).toBeInTheDocument();
  });

  it("asks what to index with only the families discovery found", async () => {
    mocks.parseVelociraptorSelection.mockResolvedValue({});
    const candidates = [
      { id: "c1", category: "evtx", supported: true },
      { id: "c2", category: "evtx", supported: true },
      { id: "c3", category: "prefetch", supported: true },
      { id: "c4", category: "bits", supported: false },
    ];
    setup({
      ev: evidence(
        { ingest_status: "processing", evidence_type: "raw_collection", effective_platform: "windows", platform_profile: { categories: [{ id: "evtx", label: "Windows Events" }, { id: "prefetch", label: "Prefetch" }, { id: "macos_tcc", label: "TCC" }] } },
        { current_phase: "waiting_selection", velociraptor_discovery: { candidates } },
      ),
      counts: {},
    });
    const card = await screen.findByTestId("evidence-family-selection");
    expect(within(card).getAllByRole("checkbox")).toHaveLength(2);
    expect(within(card).queryByText("TCC")).not.toBeInTheDocument();
    await userEvent.click(within(card).getByText("Windows Events"));
    await userEvent.click(within(card).getByRole("button", { name: /Index selected \(2 files\)/ }));
    await waitFor(() => expect(mocks.parseVelociraptorSelection).toHaveBeenCalledWith(expect.objectContaining({ selected_candidate_ids: ["c1", "c2"] })));
  });

  it("starts recommended indexing for an evidence that was never indexed", async () => {
    mocks.runEvidenceIndexingPlan.mockResolvedValue({ queued_jobs: [] });
    setup({ ev: evidence({ ingest_status: "uploaded" }), plan: { active: false, can_run: true, state: "planned_not_started" }, counts: {} });
    expect(await screen.findByTestId("evidence-status")).toHaveTextContent("Not indexed");
    await userEvent.click(screen.getByRole("button", { name: "Start indexing" }));
    await waitFor(() => expect(mocks.runEvidenceIndexingPlan).toHaveBeenCalledWith("evidence-1", { profile: "recommended" }));
  });

  it("says why processing failed", async () => {
    setup({ ev: evidence({ ingest_status: "failed", error_log: { message: "Archive could not be opened" } }), counts: {} });
    expect(await screen.findByTestId("evidence-failed")).toHaveTextContent("Archive could not be opened");
    expect(screen.getByRole("button", { name: "Re-index…" })).toBeInTheDocument();
  });

  it("keeps secondary actions in one menu and requires DELETE to delete", async () => {
    mocks.deleteEvidence.mockResolvedValue({});
    setup();
    await screen.findByTestId("evidence-results");
    await userEvent.click(screen.getByRole("button", { name: "More actions" }));
    const menu = screen.getByRole("menu");
    expect(within(menu).getAllByRole("menuitem").map((item) => item.textContent)).toEqual(["Re-index…", "Browse files", "Add finding", "Verify integrity", "Export manifest", "Delete evidence"]);
    await userEvent.click(within(menu).getByRole("menuitem", { name: "Delete evidence" }));
    const dialog = screen.getByRole("dialog", { name: "Delete evidence" });
    const confirm = within(dialog).getByRole("button", { name: "Delete evidence" });
    expect(confirm).toBeDisabled();
    await userEvent.type(within(dialog).getByRole("textbox"), "DELETE");
    await userEvent.click(confirm);
    await waitFor(() => expect(mocks.deleteEvidence).toHaveBeenCalledWith("evidence-1"));
  });

  it("re-indexes the previous selection, and asks for REDISCOVER before a full scan", async () => {
    mocks.previewReprocessEvidence.mockResolvedValue({ previous_plan_available: true, summary: { previous_selected: 10, available_again: 10, missing: 0 }, selected_candidates: [] });
    mocks.reprocessEvidence.mockResolvedValue({ run_id: "run-9" });
    setup();
    await screen.findByTestId("evidence-results");
    await userEvent.click(screen.getByRole("button", { name: "More actions" }));
    await userEvent.click(screen.getByRole("menuitem", { name: "Re-index…" }));
    const dialog = screen.getByRole("dialog", { name: "Re-index evidence" });
    expect(await within(dialog).findByText(/10 of 10 files are still available/)).toBeInTheDocument();
    await userEvent.click(within(dialog).getByText("Scan the evidence again"));
    const start = within(dialog).getByRole("button", { name: "Re-index" });
    expect(start).toBeDisabled();
    await userEvent.type(within(dialog).getByRole("textbox"), "REDISCOVER");
    await userEvent.click(start);
    await waitFor(() => expect(mocks.reprocessEvidence).toHaveBeenCalledWith("evidence-1", expect.objectContaining({ mode: "full_rediscovery", explicit_confirm: true })));
  });

  it("changes the host from one picker without repeated options", async () => {
    mocks.updateEvidenceHost.mockResolvedValue(evidence({ host_id: "host-2" }));
    setup();
    await screen.findByTestId("evidence-results");
    await userEvent.click(screen.getByRole("button", { name: "change" }));
    const picker = screen.getByTestId("evidence-host-picker");
    const select = within(picker).getByRole("combobox");
    expect(within(select).getAllByRole("option").map((option) => option.textContent)).toEqual(["No host", "HOST-A", "HOST-B", "New host…"]);
    await userEvent.selectOptions(select, "host-2");
    await userEvent.click(within(picker).getByRole("button", { name: "Save" }));
    await waitFor(() => expect(mocks.updateEvidenceHost).toHaveBeenCalledWith("case-1", "evidence-1", expect.objectContaining({ host_id: "host-2" })));
  });

  it("says when an archive was cut off and what was recovered", async () => {
    setup({ ev: evidence({}, { extraction_diagnostics: { archive_truncated: { recovered_files: 1200, first_missing_path: "Users/x/file" } } }) });
    expect(await screen.findByTestId("evidence-archive-truncated")).toHaveTextContent("1,200 complete files");
  });
});
