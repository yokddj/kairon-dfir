import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { render, screen } from "@testing-library/react";
import { MemoryRouter, Route, Routes, useLocation } from "react-router-dom";
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
    listResumableEvidenceUploads: (...args: unknown[]) => listResumableEvidenceUploadsMock(...args),
  },
}));

vi.mock("../context/ActiveCaseContext", () => ({
  useActiveCase: () => ({ activeCaseId: "case-1", clearActiveCase: vi.fn(), setActiveCase: vi.fn() }),
}));

vi.mock("../context/NotificationsContext", () => ({
  useNotifications: () => ({ notify: vi.fn() }),
}));

vi.mock("../components/EvidenceUpload", () => ({ default: () => <div data-testid="evidence-upload" /> }));
vi.mock("../components/EvidenceIngestionWizard", () => ({ default: () => null }));
vi.mock("../components/EventTable", () => ({ default: () => <div data-testid="event-table" /> }));
vi.mock("../components/FindingsWorkspace", () => ({ default: () => <div data-testid="findings-workspace" /> }));
vi.mock("../components/ProcessTreePanel", () => ({ default: () => <div data-testid="process-tree" /> }));
vi.mock("../components/Timeline", () => ({ default: () => <div data-testid="timeline" /> }));
vi.mock("../components/CreateFindingDialog", () => ({ default: () => null }));
vi.mock("../components/DebugExportDialog", () => ({ default: () => null }));
vi.mock("../components/ArtifactBadge", () => ({ default: ({ type }: { type: string }) => <span>{type}</span> }));

function Sentinel({ label }: { label: string }) {
  const location = useLocation();
  return (
    <div data-testid="sentinel" data-search={location.search}>
      {label}
    </div>
  );
}

function renderPage(initialEntry: string) {
  const queryClient = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  return render(
    <MemoryRouter initialEntries={[initialEntry]}>
      <QueryClientProvider client={queryClient}>
        <Routes>
          <Route path="/cases/:caseId/evidence" element={<CaseDetail />} />
          <Route path="/cases/:caseId/overview" element={<Sentinel label="overview-page" />} />
          <Route path="/cases/:caseId/search" element={<Sentinel label="search-page" />} />
          <Route path="/cases/:caseId/artifacts" element={<Sentinel label="artifacts-page" />} />
          <Route path="/cases/:caseId/w/execution/stories" element={<Sentinel label="process-graph-page" />} />
          <Route path="/cases/:caseId/incident-timeline" element={<Sentinel label="incident-timeline-page" />} />
          <Route path="/cases/:caseId/detections" element={<Sentinel label="detections-page" />} />
          <Route path="/cases/:caseId/findings" element={<Sentinel label="findings-page" />} />
          <Route path="/activity" element={<Sentinel label="activity-page" />} />
        </Routes>
      </QueryClientProvider>
    </MemoryRouter>,
  );
}

describe("CaseDetail legacy tab redirects", () => {
  beforeEach(() => {
    vi.clearAllMocks();
    getCaseMock.mockResolvedValue({ id: "case-1", name: "Case One", status: "open" });
    listEvidencesMock.mockResolvedValue([]);
    listArtifactsMock.mockResolvedValue([]);
    listFindingsMock.mockResolvedValue([]);
    listDetectionsMock.mockResolvedValue([]);
    getInvestigationSummaryMock.mockResolvedValue({ counts: { detections: 0, findings: 0 } });
    listCaseActivityMock.mockResolvedValue([]);
    siemExternalLinksMock.mockResolvedValue([]);
    getCaseProcessingMock.mockResolvedValue({ case_id: "case-1", summary: {}, items: [] });
    searchMock.mockResolvedValue({ items: [], total: 0 });
    timelineMock.mockResolvedValue({ items: [] });
    listResumableEvidenceUploadsMock.mockResolvedValue({ sessions: [] });
  });

  it.each([
    ["overview", "overview-page"],
    ["search", "search-page"],
    ["artifacts", "artifacts-page"],
    ["artifact_explorer", "artifacts-page"],
    ["process_tree", "process-graph-page"],
    ["investigation_timeline", "incident-timeline-page"],
    ["detections", "detections-page"],
    ["findings", "findings-page"],
    ["activity", "activity-page"],
  ])("redirects ?tab=%s to the modern dedicated page", async (tab, expectedSentinel) => {
    renderPage(`/cases/case-1/evidence?tab=${tab}`);
    expect(await screen.findByTestId("sentinel")).toHaveTextContent(expectedSentinel);
  });

  it("preserves other query params across the redirect", async () => {
    renderPage("/cases/case-1/evidence?tab=search&q=failed+login");
    const sentinel = await screen.findByTestId("sentinel");
    expect(sentinel.dataset.search).toContain("q=failed+login");
    expect(sentinel.dataset.search).not.toContain("tab=");
  });

  it("does not redirect for the real evidences/processing tabs", async () => {
    renderPage("/cases/case-1/evidence?tab=processing");
    expect(await screen.findByTestId("case-management-metadata")).toBeInTheDocument();
    expect(screen.queryByTestId("sentinel")).not.toBeInTheDocument();
  });

  it("defaults to the Evidence tab when no ?tab= is present, not the legacy overview duplicate", async () => {
    renderPage("/cases/case-1/evidence");
    expect(await screen.findByTestId("case-management-metadata")).toBeInTheDocument();
    expect(screen.queryByTestId("sentinel")).not.toBeInTheDocument();
    expect(screen.getByRole("button", { name: "Evidence & Ingest" })).toHaveClass("bg-accent");
  });

  it("only shows the Evidence & Ingest and Processing tab buttons, not the superseded ones", async () => {
    renderPage("/cases/case-1/evidence?tab=processing");
    await screen.findByTestId("case-management-metadata");
    expect(screen.getByRole("button", { name: "Evidence & Ingest" })).toBeInTheDocument();
    expect(screen.getByRole("button", { name: "Processing" })).toBeInTheDocument();
    expect(screen.queryByRole("button", { name: "Search" })).not.toBeInTheDocument();
    expect(screen.queryByRole("button", { name: "Findings" })).not.toBeInTheDocument();
  });
});
