import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { render, screen } from "@testing-library/react";
import { MemoryRouter, Route, Routes } from "react-router-dom";
import { beforeEach, describe, expect, it, vi } from "vitest";

import CaseOverviewPage from "./CaseOverviewPage";

const getCaseContextMock = vi.fn();
const listFindingsMock = vi.fn();
const getIncidentTimelineDraftMock = vi.fn();

vi.mock("../api/client", () => ({
  api: {
    getCaseContext: (...args: unknown[]) => getCaseContextMock(...args),
    listFindings: (...args: unknown[]) => listFindingsMock(...args),
    getIncidentTimelineDraft: (...args: unknown[]) => getIncidentTimelineDraftMock(...args),
  },
}));

vi.mock("../context/ActiveCaseContext", () => ({
  useActiveCase: () => ({
    setActiveCaseId: vi.fn(),
    setSelectedHost: vi.fn(),
    setSelectedEvidenceId: vi.fn(),
  }),
}));

function renderPage() {
  const queryClient = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  return render(
    <MemoryRouter initialEntries={["/cases/case-1/overview"]}>
      <QueryClientProvider client={queryClient}>
        <Routes>
          <Route path="/cases/:caseId/overview" element={<CaseOverviewPage />} />
        </Routes>
      </QueryClientProvider>
    </MemoryRouter>,
  );
}

function makeContext(overrides: Record<string, unknown> = {}) {
  const base = {
    case: { id: "case-1", name: "Synthetic Case", description: "Test case", status: "open", timezone: null, detections_count: 0, findings_count: 2, created_at: "2026-05-19T00:00:00Z", updated_at: "2026-05-19T00:00:00Z" },
    hosts: [{ id: "host-1", canonical_name: "test-win10-01", display_name: "TEST-WIN10-01", confidence: "manual", source: "manual", event_count: 12, evidence_count: 1, findings_count: 2, high_risk_count: 1, aliases: ["desktop-old01"], alias_rows: [{ id: "alias-1", alias: "TEST-WIN10-01", normalized_alias: "test-win10-01", is_primary: true, event_count: 12 }], all_names: ["TEST-WIN10-01", "desktop-old01"], alias_count: 1 }],
    evidences: [{ id: "ev-1", name: "Evidence.zip", status: "completed", storage_mode: "uploaded", is_external: false, events_indexed: 12, parser_errors: 0, detected_host: "TEST-WIN10-01" }],
    summary: {
      events_indexed: 12,
      findings_total: 2,
      findings_high: 1,
      parser_errors: 0,
      warnings: [],
      investigation_state: {
        state: "report_ready",
        evidence_count: 1,
        investigation_ready_evidence_count: 1,
        indexed_docs: 12,
        active_jobs: [],
        active_job_count: 0,
        findings_count: 2,
        official_timeline_count: 1,
        candidate_timeline_count: 1,
        marked_events_count: 0,
        parser_errors: 0,
        warnings: [],
        timeline_needs_review_count: 1,
      },
      next_actions: {
        primary: [
          { id: "generate_report", label: "Generate Report", href: "/cases/case-1/reports", priority: "primary", enabled: true },
          { id: "review_findings", label: "Review Findings", href: "/cases/case-1/findings", priority: "primary", enabled: true },
        ],
        secondary: [
          { id: "search_suspicious_commands", label: "Search suspicious commands", href: "/cases/case-1/search?q=powershell%20-ep%20bypass", priority: "primary", enabled: true },
          { id: "review_command_history", label: "Review Command History", href: "/cases/case-1/command-history", priority: "primary", enabled: true },
          { id: "review_artifacts", label: "Review Artifacts", href: "/cases/case-1/artifacts", priority: "primary", enabled: true },
          { id: "build_incident_timeline", label: "Build Incident Timeline", href: "/cases/case-1/incident-timeline", priority: "primary", enabled: true },
          { id: "add_more_evidence", label: "Add more evidence", href: "/cases/case-1/evidence", priority: "secondary", enabled: true },
        ],
        unavailable: [],
      },
    },
  };
  return { ...base, ...overrides, summary: { ...base.summary, ...((overrides.summary as Record<string, unknown>) ?? {}) } };
}

describe("CaseOverviewPage", () => {
  beforeEach(() => {
    getCaseContextMock.mockResolvedValue(makeContext());
    listFindingsMock.mockResolvedValue([
      { id: "finding-1", title: "PowerShell execution", severity: "high", summary: "Suspicious PowerShell", description: null, risk_score: 88 },
      { id: "finding-2", title: "BITS download", severity: "medium", summary: "Downloaded payload", description: null, risk_score: 60 },
    ]);
    getIncidentTimelineDraftMock.mockResolvedValue({
      items: [
        { id: "item-1", status: "accepted" },
        { id: "item-2", status: "candidate" },
        { id: "item-3", status: "needs_review" },
      ],
    });
  });

  it("transitions from loading to populated overview without hook-order crash", async () => {
    renderPage();
    expect(screen.getByText(/Loading case context/i)).toBeInTheDocument();
    expect(await screen.findByText("Synthetic Case")).toBeInTheDocument();
    expect(screen.getByText(/Report-ready investigation/i)).toBeInTheDocument();
    expect(screen.getByText(/Events indexed/i)).toBeInTheDocument();
    expect(screen.getAllByText(/TEST-WIN10-01/i).length).toBeGreaterThan(0);
    expect(screen.getByText(/Manage hosts/i)).toBeInTheDocument();
    expect(screen.getByText(/Build Incident Timeline/i)).toBeInTheDocument();
    expect(screen.getByText(/Review Artifacts/i)).toBeInTheDocument();
    expect(screen.getByRole("link", { name: /Add more evidence/i })).toBeInTheDocument();
    expect(screen.getByRole("link", { name: /Generate Report/i })).toBeInTheDocument();
    expect(screen.queryByText(/Review Validation Matrix/i)).not.toBeInTheDocument();
    expect(screen.queryByText(/Open Analyst Playbook/i)).not.toBeInTheDocument();
    expect(screen.queryByText(/Open Source Traceability/i)).not.toBeInTheDocument();
    expect(await screen.findByText(/Official: 1 · Candidates: 1 · Needs review: 1/i)).toBeInTheDocument();
  });

  it("empty case shows Add evidence primary and disables search actions", async () => {
    getCaseContextMock.mockResolvedValueOnce(
      makeContext({
        hosts: [],
        evidences: [],
        summary: {
          events_indexed: 0,
          findings_total: 0,
          findings_high: 0,
          investigation_state: { state: "empty_case", evidence_count: 0, investigation_ready_evidence_count: 0, indexed_docs: 0, active_jobs: [], active_job_count: 0, findings_count: 0, official_timeline_count: 0, candidate_timeline_count: 0, marked_events_count: 0, parser_errors: 0, warnings: [] },
          next_actions: {
            primary: [{ id: "add_evidence", label: "Add evidence", href: "/cases/case-1/evidence", priority: "primary", enabled: true }],
            secondary: [{ id: "read_upload_guide", label: "Read upload guide", href: "/docs/ingestion", priority: "secondary", enabled: true }],
            unavailable: [{ id: "search_suspicious_commands", label: "Search suspicious commands", href: "/cases/case-1/search", priority: "secondary", enabled: false, reason: "Add and index evidence before searching." }],
          },
        },
      }),
    );
    renderPage();
    expect(await screen.findByText(/Start a new investigation/i)).toBeInTheDocument();
    expect(screen.getByRole("link", { name: /^Add evidence$/i })).toBeInTheDocument();
    expect(screen.getByText(/Add and index evidence before searching/i)).toBeInTheDocument();
  });

  it("not-indexed case shows Index evidence for investigation", async () => {
    getCaseContextMock.mockResolvedValueOnce(
      makeContext({
        evidences: [{ id: "ev-1", name: "Evidence.zip", status: "pending", storage_mode: "uploaded", is_external: false, events_indexed: 0, parser_errors: 0, detected_host: null }],
        summary: {
          events_indexed: 0,
          findings_total: 0,
          findings_high: 0,
          investigation_state: { state: "evidence_uploaded_not_indexed", evidence_count: 1, investigation_ready_evidence_count: 0, indexed_docs: 0, active_jobs: [], active_job_count: 0, findings_count: 0, official_timeline_count: 0, candidate_timeline_count: 0, marked_events_count: 0, parser_errors: 0, warnings: [] },
          next_actions: {
            primary: [{ id: "index_evidence", label: "Index evidence for investigation", href: "/evidences/ev-1", priority: "primary", enabled: true }],
            secondary: [{ id: "add_more_evidence", label: "Add more evidence", href: "/cases/case-1/evidence", priority: "secondary", enabled: true }],
            unavailable: [],
          },
        },
      }),
    );
    renderPage();
    expect(await screen.findByText(/Evidence is ready to index/i)).toBeInTheDocument();
    expect(screen.getByRole("link", { name: /Index evidence for investigation/i })).toHaveAttribute("href", "/evidences/ev-1");
  });

  it("ready case shows Add more evidence and investigation actions", async () => {
    getCaseContextMock.mockResolvedValueOnce(
      makeContext({
        summary: {
          findings_total: 0,
          findings_high: 0,
          investigation_state: { state: "investigation_ready", evidence_count: 1, investigation_ready_evidence_count: 1, indexed_docs: 12, active_jobs: [], active_job_count: 0, findings_count: 0, official_timeline_count: 0, candidate_timeline_count: 0, marked_events_count: 0, parser_errors: 0, warnings: [] },
          next_actions: {
            primary: [
              { id: "search_suspicious_commands", label: "Search suspicious commands", href: "/cases/case-1/search", priority: "primary", enabled: true },
              { id: "review_command_history", label: "Review Command History", href: "/cases/case-1/command-history", priority: "primary", enabled: true },
            ],
            secondary: [{ id: "add_more_evidence", label: "Add more evidence", href: "/cases/case-1/evidence", priority: "secondary", enabled: true }],
            unavailable: [{ id: "generate_report", label: "Generate Report", href: "/cases/case-1/reports", priority: "secondary", enabled: false, reason: "Create findings or timeline items before generating a useful report." }],
          },
        },
      }),
    );
    renderPage();
    expect(await screen.findByText(/Investigation-ready case/i)).toBeInTheDocument();
    expect(screen.getByRole("link", { name: /Search suspicious commands/i })).toBeInTheDocument();
    expect(screen.getByRole("link", { name: /Add more evidence/i })).toBeInTheDocument();
    expect(screen.getByText(/Create findings or timeline items/i)).toBeInTheDocument();
  });
});
