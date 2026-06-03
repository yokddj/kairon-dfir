import type { ReactNode } from "react";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { render, screen } from "@testing-library/react";
import { within } from "@testing-library/react";
import { MemoryRouter } from "react-router-dom";
import { beforeEach, describe, expect, it, vi } from "vitest";
import Sidebar from "./Sidebar";
import Topbar from "./Topbar";

const listCasesMock = vi.fn();

const activeCaseState: any = {
  activeCase: { id: "case-1", name: "Case Alpha" },
  activeCaseId: "case-1",
  selectedHost: "TEST-WIN10-01",
  selectedEvidenceId: "ev-1",
  caseContext: {
    case: { id: "case-1", name: "Case Alpha" },
    hosts: [{ id: "host-1", canonical_name: "TEST-WIN10-01", display_name: "TEST-WIN10-01", confidence: "manual", source: "manual", event_count: 15000, evidence_count: 1, findings_count: 8, high_risk_count: 4, aliases: ["desktop-old01"], alias_rows: [{ id: "alias-1", alias: "TEST-WIN10-01", normalized_alias: "test-win10-01", is_primary: true, event_count: 15000 }], all_names: ["TEST-WIN10-01", "desktop-old01"], alias_count: 1 }],
    evidences: [{ id: "ev-1", name: "Collection.zip", status: "completed", storage_mode: "uploaded", is_external: false, events_indexed: 15000, parser_errors: 0, detected_host: "TEST-WIN10-01" }],
    summary: { events_indexed: 15000, findings_total: 8, findings_high: 4, parser_errors: 0, warnings: [] },
  },
  isCaseContextLoading: false,
  setActiveCase: vi.fn(),
  setActiveCaseId: vi.fn(),
  clearActiveCase: vi.fn(),
  setSelectedHost: vi.fn(),
  clearSelectedHost: vi.fn(),
  setSelectedEvidenceId: vi.fn(),
  clearSelectedEvidenceId: vi.fn(),
};

vi.mock("../api/client", () => ({
  API_BASE_URL: "http://127.0.0.1:8000/api",
  api: {
    listCases: (...args: unknown[]) => listCasesMock(...args),
  },
}));

vi.mock("../context/ActiveCaseContext", () => ({
  useActiveCase: () => activeCaseState,
}));

vi.mock("../context/TimezoneContext", () => ({
  useTimezonePreference: () => ({
    timezoneMode: "utc",
    setTimezoneMode: vi.fn(),
    effectiveTimezone: "UTC",
    userTimezone: "Europe/Madrid",
  }),
}));

function renderWithProviders(node: ReactNode) {
  const queryClient = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  return render(
    <MemoryRouter>
      <QueryClientProvider client={queryClient}>{node}</QueryClientProvider>
    </MemoryRouter>,
  );
}

describe("workspace navigation", () => {
  beforeEach(() => {
    listCasesMock.mockResolvedValue([{ id: "case-1", name: "Case Alpha" }]);
    activeCaseState.activeCase = { id: "case-1", name: "Case Alpha" };
    activeCaseState.activeCaseId = "case-1";
    activeCaseState.selectedHost = "TEST-WIN10-01";
    activeCaseState.selectedEvidenceId = "ev-1";
  });

  it("renders sidebar groups", async () => {
    renderWithProviders(<Sidebar />);
    const investigationGroup = screen.getByText(/^Investigation$/i).closest("section");
    const evidenceGroup = screen.getByText(/^Evidence$/i).closest("section");
    expect(screen.getByText(/Case Overview/i)).toBeInTheDocument();
    expect(investigationGroup).toBeInTheDocument();
    expect(evidenceGroup).toBeInTheDocument();
    expect(screen.getByText(/Advanced/i)).toBeInTheDocument();
    expect(screen.getByText(/Help/i)).toBeInTheDocument();
    expect(screen.getByText("Investigation Home")).toBeInTheDocument();
    expect(screen.getByText("Findings")).toBeInTheDocument();
    expect(screen.getByText("Search")).toBeInTheDocument();
    expect(screen.getByText("Command History")).toBeInTheDocument();
    expect(screen.getByText("Artifact Views")).toBeInTheDocument();
    expect(screen.queryByText(/^Timeline$/)).not.toBeInTheDocument();
    expect(screen.getByText("Execution Stories")).toBeInTheDocument();
    expect(screen.getByText("Evidence & Ingest")).toBeInTheDocument();
    expect(screen.getByText("Detections")).toBeInTheDocument();
    expect(screen.getByText("Reports")).toBeInTheDocument();
    expect(screen.getByText("Rules")).toBeInTheDocument();
    expect(screen.getByText("Debug Export")).toBeInTheDocument();
    expect(screen.getByText("Diagnostics: OpenSearch Console")).toBeInTheDocument();
    expect(screen.getByText("Jobs & Activity")).toBeInTheDocument();
    expect(screen.getByText("System / Performance")).toBeInTheDocument();
    expect(screen.getByText("Docs")).toBeInTheDocument();
    expect(screen.queryByText(/Análisis semiautomático/i)).not.toBeInTheDocument();
    expect(screen.queryByText(/^SIEM$/i)).not.toBeInTheDocument();
    expect(screen.queryByText(/^Activity$/i)).not.toBeInTheDocument();
    expect(within(investigationGroup as HTMLElement).getByText("Artifact Views")).toBeInTheDocument();
    expect(within(evidenceGroup as HTMLElement).queryByText("Artifact Views")).not.toBeInTheDocument();
    expect(within(evidenceGroup as HTMLElement).queryByText("Artifacts")).not.toBeInTheDocument();
  });

  it("points the System / Performance link to the tabbed route", () => {
    renderWithProviders(<Sidebar />);
    expect(screen.getByRole("link", { name: /System \/ Performance/i })).toHaveAttribute("href", "/system/performance");
  });

  it("renders topbar with active case, host and evidence selectors", async () => {
    renderWithProviders(<Topbar />);
    expect(await screen.findByRole("combobox", { name: /active case/i })).toBeInTheDocument();
    expect(screen.getByRole("combobox", { name: /host filter/i })).toBeInTheDocument();
    expect(screen.getByRole("combobox", { name: /evidence filter/i })).toBeInTheDocument();
    expect(screen.getByText(/Case: Case Alpha/i)).toBeInTheDocument();
    expect(screen.getByText(/includes 1 aliases/i)).toBeInTheDocument();
  });

  it("disables case workspace links when no case is selected", () => {
    activeCaseState.activeCase = null;
    activeCaseState.activeCaseId = "";
    activeCaseState.selectedHost = "";
    activeCaseState.selectedEvidenceId = "";
    renderWithProviders(<Sidebar />);
    expect(screen.getByText("Investigation Home")).toBeInTheDocument();
    expect(screen.queryByRole("link", { name: "Investigation Home" })).not.toBeInTheDocument();
    expect(screen.getAllByText(/Select or create a case first\./i).length).toBeGreaterThan(0);
    expect(screen.getByText("Investigation Home").closest("[data-disabled='true']")).toHaveAttribute("title", "Select or create a case first.");
  });

  it("enables case workspace links when a case is selected", () => {
    renderWithProviders(<Sidebar />);
    expect(screen.getByRole("link", { name: "Investigation Home" })).toHaveAttribute("href", "/cases/case-1/overview");
  });
});
