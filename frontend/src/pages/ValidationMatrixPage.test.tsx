import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { fireEvent, render, screen, waitFor } from "@testing-library/react";
import { MemoryRouter, Route, Routes } from "react-router-dom";
import { beforeEach, describe, expect, it, vi } from "vitest";

import ValidationMatrixPage from "./ValidationMatrixPage";

const getValidationMatrixMock = vi.fn();
const exportValidationMatrixMarkdownMock = vi.fn();

vi.mock("../api/client", () => ({
  api: {
    getValidationMatrix: (...args: unknown[]) => getValidationMatrixMock(...args),
    exportValidationMatrixMarkdown: (...args: unknown[]) => exportValidationMatrixMarkdownMock(...args),
  },
}));

vi.mock("../context/ActiveCaseContext", () => ({
  useActiveCase: () => ({
    setActiveCaseId: vi.fn(),
  }),
}));

function renderPage(path = "/cases/case-1/validation-matrix") {
  const queryClient = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  return render(
    <MemoryRouter initialEntries={[path]}>
      <QueryClientProvider client={queryClient}>
        <Routes>
          <Route path="/cases/:caseId/validation-matrix" element={<ValidationMatrixPage />} />
        </Routes>
      </QueryClientProvider>
    </MemoryRouter>,
  );
}

describe("ValidationMatrixPage", () => {
  beforeEach(() => {
    getValidationMatrixMock.mockResolvedValue({
      case_id: "case-1",
      validation_id: "synthetic-validation-v1",
      source_name: "Internal synthetic validation source",
      source_urls: { I: "https://example.test/i", II: "https://example.test/ii" },
      source_parts: ["I", "II", "III", "IV"],
      summary: {
        total_expected: 26,
        found: 21,
        partial: 3,
        memory_only: 1,
        not_present_in_evidence: 1,
        parser_gap: 0,
        ux_gap: 0,
      },
      filters: {
        hosts: ["HOSTA", "SERVERA"],
        phases: ["initial_access", "credential_access"],
        results: ["found", "partial", "memory_only", "not_present_in_evidence", "parser_gap", "ux_gap"],
        source_parts: ["I", "II", "III", "IV"],
      },
      generated_at: "2026-06-01T00:00:00Z",
      warnings: [],
      items: [
        {
          case_id: "case-1",
          validation_id: "synthetic-validation-v1",
          source_name: "Internal synthetic validation source",
          source_urls: {},
          finding_id: "GT-019",
          title: "Sample shortcut launches script",
          description: "The synthetic shortcut launches PowerShell.",
          phase: "execution",
          host: "HOSTA",
          result: "found",
          confidence: "high",
          expected_indicators: ["sample.lnk"],
          expected_artifacts: ["recentdocs"],
          evidence_source_used: ["User Activity", "Search"],
          supporting_event_ids: [],
          related_timeline_items: [],
          related_findings: [],
          notes: "Search sample.lnk returned 53 hits.",
          source_part: ["I", "IV"],
          memory_required: false,
          search_url: "/cases/case-1/search?q=sample.lnk&host=HOSTA",
          timeline_url: "/cases/case-1/incident-timeline?phase=execution&host=HOSTA",
        },
      ],
    });
    exportValidationMatrixMarkdownMock.mockResolvedValue({ blob: new Blob(["# Matrix"], { type: "text/markdown" }), filename: "matrix.md" });
  });

  it("renders summary cards, filters and rows", async () => {
    renderPage();

    expect(await screen.findByText("Validation Matrix")).toBeInTheDocument();
    expect(screen.getByText("26")).toBeInTheDocument();
    expect(screen.getByText("GT-019")).toBeInTheDocument();
    expect(screen.getByText("Sample shortcut launches script")).toBeInTheDocument();
    expect(screen.getAllByText("Part I").length).toBeGreaterThan(0);
  });

  it("opens item detail with evidence links and review controls", async () => {
    renderPage();

    fireEvent.click(await screen.findByText("GT-019"));
    expect(await screen.findByTestId("validation-detail")).toBeInTheDocument();
    expect(screen.getByText("Open related Search")).toBeInTheDocument();
    expect(screen.getByText("Mark reviewed")).toBeInTheDocument();
  });

  it("sends filter changes to the API through URL state", async () => {
    renderPage();

    await screen.findByText("Validation Matrix");
    fireEvent.change(screen.getByLabelText(/Result/i), { target: { value: "partial" } });
    await waitFor(() => expect(getValidationMatrixMock).toHaveBeenLastCalledWith("case-1", expect.objectContaining({ result: "partial" })));
  });

  it("explains validation matrix usage for normal cases without ground truth", async () => {
    getValidationMatrixMock.mockResolvedValueOnce({
      case_id: "normal-case",
      validation_id: "none",
      source_name: "No validation matrix",
      source_urls: {},
      source_parts: [],
      summary: {
        total_expected: 0,
        found: 0,
        partial: 0,
        memory_only: 0,
        not_present_in_evidence: 0,
        parser_gap: 0,
        ux_gap: 0,
      },
      filters: { hosts: [], phases: [], results: [], source_parts: [] },
      generated_at: "2026-06-01T00:00:00Z",
      warnings: [],
      items: [],
      visibility: {
        case_id: "normal-case",
        mode: "investigation",
        has_validation_matrix: false,
        show_validation_matrix: false,
        label: "Investigation case",
        reason: "No validation matrix is attached to this investigation case.",
      },
    });

    renderPage("/cases/normal-case/validation-matrix");

    expect(await screen.findByText("Validation Matrix is used for training cases, QA datasets, or imported ground-truth scenarios. Real investigations usually start with Findings and Incident Timeline.")).toBeInTheDocument();
    expect(screen.getByText(/Import validation matrix/)).toBeInTheDocument();
    expect(screen.getAllByText(/planned/).length).toBeGreaterThan(0);
  });
});
