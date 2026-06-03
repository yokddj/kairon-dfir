import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { fireEvent, render, screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { MemoryRouter, Route, Routes } from "react-router-dom";
import { beforeEach, describe, expect, it, vi } from "vitest";

import Detections from "./Detections";

const listCasesMock = vi.fn();
const listDetectionsMock = vi.fn();
const listAllDetectionsMock = vi.fn();
const getDetectionFacetsMock = vi.fn();
const getDetectionSummaryMock = vi.fn();
const updateDetectionMock = vi.fn();
const deleteDetectionMock = vi.fn();
const bulkDetectionsMock = vi.fn();
const previewBulkDetectionsMock = vi.fn();
const updateBulkDetectionsMock = vi.fn();
const deleteBulkDetectionsMock = vi.fn();
const promoteDetectionToFindingMock = vi.fn();
const getDetectionEventMock = vi.fn();
const siemExternalLinksMock = vi.fn();

vi.mock("../api/client", () => ({
  api: {
    listCases: (...args: unknown[]) => listCasesMock(...args),
    listDetections: (...args: unknown[]) => listDetectionsMock(...args),
    listAllDetections: (...args: unknown[]) => listAllDetectionsMock(...args),
    getDetectionFacets: (...args: unknown[]) => getDetectionFacetsMock(...args),
    getDetectionSummary: (...args: unknown[]) => getDetectionSummaryMock(...args),
    updateDetection: (...args: unknown[]) => updateDetectionMock(...args),
    deleteDetection: (...args: unknown[]) => deleteDetectionMock(...args),
    bulkDetections: (...args: unknown[]) => bulkDetectionsMock(...args),
    previewBulkDetections: (...args: unknown[]) => previewBulkDetectionsMock(...args),
    updateBulkDetections: (...args: unknown[]) => updateBulkDetectionsMock(...args),
    deleteBulkDetections: (...args: unknown[]) => deleteBulkDetectionsMock(...args),
    promoteDetectionToFinding: (...args: unknown[]) => promoteDetectionToFindingMock(...args),
    getDetectionEvent: (...args: unknown[]) => getDetectionEventMock(...args),
    siemExternalLinks: (...args: unknown[]) => siemExternalLinksMock(...args),
  },
}));

vi.mock("../context/ActiveCaseContext", () => ({
  useActiveCase: () => ({
    activeCaseId: "case-1",
    selectedEvidenceId: "ev-1",
    selectedHost: "TEST-WIN10-01",
    setActiveCaseId: vi.fn(),
  }),
}));

vi.mock("../lib/time", () => ({
  formatTimestamp: (value: string | null | undefined) => value || "-",
}));

function renderPage(initialEntry = "/cases/case-1/detections") {
  const queryClient = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  return render(
    <MemoryRouter initialEntries={[initialEntry]}>
      <QueryClientProvider client={queryClient}>
        <Routes>
          <Route path="/cases/:caseId/detections" element={<Detections />} />
        </Routes>
      </QueryClientProvider>
    </MemoryRouter>,
  );
}

describe("Detections", () => {
  beforeEach(() => {
    listCasesMock.mockResolvedValue([{ id: "case-1", name: "Synthetic Case" }]);
    listDetectionsMock.mockResolvedValue({
      total: 1,
      page: 1,
      page_size: 50,
      total_pages: 1,
      items: [
        {
          id: "det-1",
          case_id: "case-1",
          evidence_id: "ev-1",
          artifact_id: null,
          rule_id: "rule-1",
          rule_set_id: null,
          engine: "sigma",
          source_engine: "sigma",
          rule_name: "Encoded PowerShell",
          rule_title: "Encoded PowerShell",
          rule_version: "2026-05-18",
          rule_author: "DFIR",
          rule_level: "high",
          severity: "high",
          confidence: 0.9,
          event_id: "evt-1",
          event_index: "case-1-events",
          opensearch_id: "os-1",
          target_type: "event",
          target_path: "C:\\Users\\alex\\Downloads\\payload.exe",
          matched_at: "2026-05-18T19:00:00Z",
          matched_file_hash: null,
          matched_process_node_id: "proc-1",
          host_name: "TEST-WIN10-01",
          message: "PowerShell with encoded command",
          status: "new",
          analyst_note: null,
          matched_fields: { "CommandLine|contains": { expected: "-EncodedCommand" } },
          matched_strings: [],
          condition_summary: "selection",
          description: "Detect encoded PowerShell",
          false_positives: [],
          references: [],
          tags: ["sigma"],
          mitre: ["attack.execution"],
          related_event_ids: ["evt-1"],
          related_finding_ids: [],
          related_iocs: { files: ["C:\\Users\\alex\\Downloads\\payload.exe"], hashes: [], domains: [], ips: [], urls: [], registry: [] },
          risk_score: 90,
          dedup_fingerprint: "fp-1",
          engine_version: "rules_v2",
          data_quality: [],
          raw: {
            match_reason: "Matched encoded PowerShell",
            event_preview: { summary: "powershell.exe -EncodedCommand AAAA", timestamp: "2026-05-18T19:00:00Z", host: "TEST-WIN10-01", user: "user01", event_category: "process", event_type: "process_start" },
          },
          created_at: "2026-05-18T19:00:00Z",
          deleted_at: null,
          archived_at: null,
        },
      ],
    });
    listAllDetectionsMock.mockResolvedValue({ total: 0, page: 1, page_size: 50, total_pages: 0, items: [] });
    getDetectionFacetsMock.mockResolvedValue({
      engines: [{ value: "sigma", count: 1 }],
      sources: [{ value: "sigma", count: 1 }],
      severities: [{ value: "high", count: 1 }],
      statuses: [{ value: "new", count: 1 }],
      rule_names: [{ value: "Encoded PowerShell", count: 1 }],
      hosts: [{ value: "TEST-WIN10-01", count: 1 }],
      matched_object_types: [{ value: "event", count: 1 }],
      evidences: [{ id: "ev-1", name: "Evidence 1", count: 1 }],
      artifacts: [],
      has_linked_event: [{ value: true, count: 1 }, { value: false, count: 0 }],
      has_file_target: [{ value: true, count: 1 }, { value: false, count: 0 }],
    });
    getDetectionSummaryMock.mockResolvedValue({
      total: 1800,
      state: { active: 1800, soft_deleted: 0, dismissed: 50, reviewed: 50, confirmed: 0 },
      by_severity: { high: 1200, medium: 600 },
      by_status: { new: 1700, reviewed: 50, dismissed: 50 },
      by_rule: [
        {
          rule_id: "rule-1",
          rule_name: "Encoded PowerShell",
          severity: "high",
          count: 1200,
          new_count: 1190,
          reviewed_count: 10,
          dismissed_count: 0,
          confirmed_count: 0,
          unique_hosts: 3,
          unique_users: 5,
          unique_artifact_types: 1,
          unique_source_files: 2,
          first_seen: "2026-05-18T18:00:00Z",
          last_seen: "2026-05-18T19:00:00Z",
          sample_entities: ["powershell.exe"],
          sample_source_files: ["Security.evtx"],
          sample_event_ids: ["evt-1"],
          percentage: 66.67,
        },
      ],
      by_host: [{ key: "TEST-WIN10-01", count: 1200 }],
      by_user: [{ key: "user01", count: 800 }],
      by_evidence: [{ key: "ev-1", count: 1800 }],
      by_artifact_type: [{ key: "windows_event", count: 1800 }],
      by_source_file: [{ key: "Security.evtx", count: 1200 }],
      by_rule_run: [{ key: "run-123", count: 1800 }],
      top_noisy_rules: [
        {
          rule_id: "rule-1",
          rule_name: "Encoded PowerShell",
          severity: "high",
          count: 1200,
          new_count: 1190,
          reviewed_count: 10,
          dismissed_count: 0,
          confirmed_count: 0,
          unique_hosts: 3,
          unique_users: 5,
          unique_artifact_types: 1,
          unique_source_files: 2,
          first_seen: "2026-05-18T18:00:00Z",
          last_seen: "2026-05-18T19:00:00Z",
          sample_entities: ["powershell.exe"],
          sample_source_files: ["Security.evtx"],
          sample_event_ids: ["evt-1"],
          percentage: 66.67,
        },
      ],
      new_vs_reviewed: { new: 1700, reviewed: 50, dismissed: 50, confirmed: 0 },
    });
    updateDetectionMock.mockResolvedValue({});
    deleteDetectionMock.mockResolvedValue(undefined);
    bulkDetectionsMock.mockResolvedValue({ updated: 1 });
    previewBulkDetectionsMock.mockResolvedValue({
      matched: 1,
      by_source: { sigma: 1 },
      by_status: { new: 1 },
      by_severity: { high: 1 },
      by_rule: [{ rule_id: "rule-1", title: "Encoded PowerShell", count: 1 }],
      by_run: [{ rule_run_id: "run-123", count: 1 }],
      orphaned_rule_count: 0,
      protected_count: 0,
      warnings: ["Findings and reports are not automatically deleted. Review them separately."],
    });
    updateBulkDetectionsMock.mockResolvedValue({ matched: 1, updated: 1, deleted: 0, skipped: 0, errors: [], warnings: [], activity_id: "act-1" });
    deleteBulkDetectionsMock.mockResolvedValue({ matched: 1, updated: 0, deleted: 1, skipped: 0, errors: [], warnings: [], activity_id: "act-2" });
    promoteDetectionToFindingMock.mockResolvedValue({ id: "finding-1" });
    getDetectionEventMock.mockResolvedValue({ id: "evt-1", event: { message: "preview" } });
    siemExternalLinksMock.mockResolvedValue({ discover_url: "https://example.test" });
  });

  it("renders detections with rule and IOC context", async () => {
    renderPage();
    expect(await screen.findByText(/Automatic matches from rules and engines/i)).toBeInTheDocument();
    await userEvent.click(screen.getByRole("button", { name: /Raw detections/i }));
    const detectionCard = await screen.findByText("PowerShell with encoded command");
    expect(detectionCard).toBeInTheDocument();
    expect(screen.getByText(/Condition: selection/i)).toBeInTheDocument();
    expect(screen.getByText(/Matched fields: CommandLine\|contains/i)).toBeInTheDocument();
  });

  it("shows grouped triage by default with noisy rule summary", async () => {
    renderPage();
    expect(await screen.findByText(/Triage overview/i)).toBeInTheDocument();
    await waitFor(() => expect(getDetectionSummaryMock).toHaveBeenCalled());
    expect(screen.getByRole("button", { name: /Grouped/i })).toBeInTheDocument();
    expect(screen.getByText(/Top noisy rules/i)).toBeInTheDocument();
  });

  it("explains when detections are only soft-deleted instead of showing a false empty state", async () => {
    getDetectionSummaryMock.mockResolvedValueOnce({
      total: 0,
      state: { active: 0, soft_deleted: 12522, dismissed: 0, reviewed: 0, confirmed: 0 },
      by_severity: {},
      by_status: {},
      by_rule: [],
      by_host: [],
      by_user: [],
      by_evidence: [],
      by_artifact_type: [],
      by_source_file: [],
      by_rule_run: [],
      top_noisy_rules: [],
      new_vs_reviewed: { new: 0, reviewed: 0, dismissed: 0, confirmed: 0 },
    });
    renderPage();
    expect(await screen.findByText(/12522 soft-deleted detections exist/i)).toBeInTheDocument();
  });

  it("opens group detail as a main wide investigation view with tabs", async () => {
    renderPage();
    await screen.findByText(/Triage overview/i);
    const openButtons = await screen.findAllByRole("button", { name: /Open group/i });
    await userEvent.click(openButtons[0]);
    const detail = await screen.findByTestId("detection-group-detail-main");
    expect(detail).toBeInTheDocument();
    expect(within(detail).getByRole("button", { name: /Back to grouped detections/i })).toBeInTheDocument();
    expect(within(detail).getByText(/Encoded PowerShell/i)).toBeInTheDocument();
    expect(within(detail).getByRole("button", { name: /Overview/i })).toBeInTheDocument();
    expect(within(detail).getByRole("button", { name: /^Detections$/i })).toBeInTheDocument();
    expect(within(detail).getByRole("button", { name: /^Events$/i })).toBeInTheDocument();
    expect(within(detail).getByRole("button", { name: /Rule details/i })).toBeInTheDocument();
    expect(within(detail).getByRole("button", { name: /Notes/i })).toBeInTheDocument();
  });

  it("group detections tab paginates and exposes row actions", async () => {
    renderPage();
    await screen.findByText(/Triage overview/i);
    const openButtons = await screen.findAllByRole("button", { name: /Open group/i });
    await userEvent.click(openButtons[0]);
    const detail = await screen.findByTestId("detection-group-detail-main");
    await userEvent.click(within(detail).getByRole("button", { name: /^Detections$/i }));
    expect(await within(detail).findByText(/PowerShell with encoded command/i)).toBeInTheDocument();
    expect(within(detail).getAllByRole("button", { name: /Mark reviewed/i }).length).toBeGreaterThan(0);
    expect(within(detail).getByText(/1 detections in this group|matching detections/i)).toBeInTheDocument();
  });

  it("back from group detail returns to grouped detections", async () => {
    renderPage();
    await screen.findByText(/Triage overview/i);
    const openButtons = await screen.findAllByRole("button", { name: /Open group/i });
    await userEvent.click(openButtons[0]);
    await screen.findByTestId("detection-group-detail-main");
    await userEvent.click(screen.getByRole("button", { name: /Back to grouped detections/i }));
    await waitFor(() => expect(screen.queryByTestId("detection-group-detail-main")).not.toBeInTheDocument());
    expect(screen.getByLabelText(/Group by/i)).toBeInTheDocument();
  });

  it("requests grouped detection summary for the selected case", async () => {
    renderPage();
    await screen.findByText(/Top noisy rules/i);
    await waitFor(() => expect(getDetectionSummaryMock).toHaveBeenCalledWith(expect.objectContaining({ case_id: "case-1" })));
  });

  it("shows grouping controls for host-based triage", async () => {
    renderPage();
    await screen.findByText(/Triage overview/i);
    fireEvent.change(screen.getByLabelText(/Group by/i), { target: { value: "host" } });
    expect(screen.getByLabelText(/Group by/i)).toHaveValue("host");
  });

  it("filters by source facet and updates query", async () => {
    renderPage();
    await screen.findByText(/Triage overview/i);
    const searchBoxes = screen.getAllByRole("textbox");
    fireEvent.change(searchBoxes[0], { target: { value: "sigma" } });
    const sourceSelect = screen.getAllByRole("combobox")[1];
    fireEvent.change(sourceSelect, { target: { value: "sigma" } });
    expect(searchBoxes[0]).toHaveValue("sigma");
  });

  it("reads source and rule run filters from the URL", async () => {
    renderPage("/cases/case-1/detections?source=sigma&rule_run_id=run-123");
    await screen.findByText(/Triage overview/i);
    await waitFor(() =>
      expect(listDetectionsMock).toHaveBeenCalledWith(
        "case-1",
        expect.objectContaining({ source: "sigma", rule_run_id: "run-123" }),
      ),
    );
    expect(screen.getByText(/Rule run filter: run-123/i)).toBeInTheDocument();
  });

  it("status action buttons render", async () => {
    renderPage();
    await userEvent.click(await screen.findByRole("button", { name: /Raw detections/i }));
    await waitFor(() => expect(screen.getAllByRole("button", { name: /Mark reviewed/i }).length).toBeGreaterThan(0));
  });

  it("promote and open actions render", async () => {
    renderPage();
    await userEvent.click(await screen.findByRole("button", { name: /Raw detections/i }));
    const button = await screen.findByRole("button", { name: /Promote to finding/i });
    const card = button.closest("article");
    expect(card).not.toBeNull();
    if (!card) return;
    expect(within(card).getByRole("button", { name: /Open event/i })).toBeInTheDocument();
  });

  it("opens detection detail in a wide modal and locks body scroll", async () => {
    renderPage();
    await userEvent.click(await screen.findByRole("button", { name: /Raw detections/i }));
    await userEvent.click(await screen.findByTestId("detection-card-det-1"));
    expect(await screen.findByTestId("responsive-detail-overlay")).toBeInTheDocument();
    expect(await screen.findByTestId("detection-detail-panel")).toBeInTheDocument();
    expect(document.body.style.overflow).toBe("hidden");
    await userEvent.click(screen.getByRole("button", { name: /close detail panel/i }));
    await waitFor(() => expect(screen.queryByTestId("responsive-detail-overlay")).not.toBeInTheDocument());
    expect(document.body.style.overflow).toBe("");
  });

  it("supports select all matching and delete preview", async () => {
    renderPage("/cases/case-1/detections?rule_run_id=run-123");
    await userEvent.click(await screen.findByRole("button", { name: /Raw detections/i }));
    await screen.findByText("PowerShell with encoded command");
    await userEvent.click(screen.getByRole("button", { name: /Select all matching/i }));
    expect(screen.getByText(/All 1 matching detections selected/i)).toBeInTheDocument();
    await userEvent.click(screen.getByRole("button", { name: /Delete selected detections/i }));
    expect(await screen.findByTestId("detection-bulk-preview-modal")).toBeInTheDocument();
    expect(previewBulkDetectionsMock).toHaveBeenCalled();
    expect(screen.getByText(/Delete detections safely/i)).toBeInTheDocument();
    expect(screen.getByText(/DELETE 1 DETECTIONS/i)).toBeInTheDocument();
    expect(screen.getAllByText(/Encoded PowerShell/i).length).toBeGreaterThan(0);
  });
});
