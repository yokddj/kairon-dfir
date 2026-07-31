import type { ReactNode } from "react";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { fireEvent, render, screen } from "@testing-library/react";
import { MemoryRouter } from "react-router-dom";
import { beforeEach, describe, expect, it, vi } from "vitest";

import App from "./App";

const listCasesMock = vi.fn();
const getMemoryOverviewMock = vi.fn();
const activeCaseState: any = {
  activeCaseId: "case-1",
  activeCase: { id: "case-1", name: "Case Alpha" },
  setActiveCaseId: vi.fn(),
};

vi.mock("./components/Layout", () => ({
  default: ({ children }: { children: ReactNode }) => <div>{children}</div>,
}));

vi.mock("./api/client", () => ({
  api: {
    listCases: (...args: unknown[]) => listCasesMock(...args),
    getMemoryOverview: (...args: unknown[]) => getMemoryOverviewMock(...args),
  },
}));

vi.mock("./context/ActiveCaseContext", () => ({
  ActiveCaseProvider: ({ children }: { children: ReactNode }) => <>{children}</>,
  useActiveCase: () => activeCaseState,
}));

vi.mock("./context/AuthContext", () => ({
  AuthProvider: ({ children }: { children: ReactNode }) => <>{children}</>,
  useAuth: () => ({
    user: {
      user_id: "test-user",
      username: "analyst",
      display_name: "Analyst",
      email: null,
      is_admin: true,
      is_active: true,
      created_at: "2026-01-01T00:00:00Z",
      last_login_at: null,
    },
    loading: false,
    login: vi.fn(),
    logout: vi.fn(),
  }),
}));

vi.mock("./context/NotificationsContext", () => ({
  NotificationsProvider: ({ children }: { children: ReactNode }) => <>{children}</>,
}));

vi.mock("./context/TimezoneContext", () => ({
  TimezoneProvider: ({ children }: { children: ReactNode }) => <>{children}</>,
  useTimezonePreference: () => ({ effectiveTimezone: "UTC" }),
}));

vi.mock("./pages/Dashboard", () => ({ default: () => <div>Dashboard Page</div> }));
vi.mock("./pages/Cases", () => ({ default: () => <div>Cases Page</div> }));
vi.mock("./pages/CaseDetail", () => ({ default: () => <div>Case Detail Page</div> }));
vi.mock("./pages/CaseOverviewPage", () => ({ default: () => <div>Overview Page</div> }));
vi.mock("./pages/CaseHostsPage", () => ({ default: () => <div>Hosts Page</div> }));
vi.mock("./pages/CaseProcessGraphPage", () => ({ default: () => <div>Process Graph Page</div> }));
vi.mock("./pages/CommandHistoryPage", () => ({ default: () => <div>Command History Page</div> }));
vi.mock("./pages/LinuxAuthenticationPage", () => ({ default: () => <div>Linux Authentication Page</div> }));
vi.mock("./pages/IncidentTimelinePage", () => ({ default: () => <div>Incident Timeline Page</div> }));
vi.mock("./pages/TimelinePage", () => ({ default: () => <div>Timeline Page</div> }));
vi.mock("./pages/CaseReportsPage", () => ({ default: () => <div>Reports Page</div> }));
vi.mock("./pages/DebugExportPage", () => ({ default: () => <div>Debug Export Page</div> }));
vi.mock("./pages/EvidenceDetail", () => ({ default: () => <div>Evidence Detail Page</div> }));
vi.mock("./pages/Search", () => ({ default: () => <div>Search Page</div> }));
vi.mock("./pages/ArtifactExplorer", () => ({ default: () => <div>Artifact Views Page</div> }));
vi.mock("./pages/Siem", () => ({ default: () => <div>OpenSearch Page</div> }));
vi.mock("./pages/ActivityPage", () => ({ default: () => <div>Activity Page</div> }));
vi.mock("./pages/Findings", () => ({ default: () => <div>Findings Page</div> }));
vi.mock("./pages/Rules", () => ({ default: () => <div>Rules Page</div> }));
vi.mock("./pages/Detections", () => ({ default: () => <div>Detections Page</div> }));
vi.mock("./pages/SystemPage", () => ({ default: () => <div>System Page</div> }));
vi.mock("./pages/DocsPage", () => ({ default: () => <div>Docs Page</div> }));
vi.mock("./pages/ParserCoveragePage", () => ({ default: () => <div>Parser Coverage Page</div> }));
vi.mock("./pages/MemoryEvidencePage", async () => {
  const { useLocation, useNavigate, useParams } = await vi.importActual<typeof import("react-router-dom")>("react-router-dom");
  return {
    default: () => {
      const location = useLocation();
      const navigate = useNavigate();
      // Exposes the raw :memoryTab route param App.tsx's route actually
      // captures -- the missing-Runs bug and the later ?tab= priority bug
      // both trace back to this being empty when the route only matched a
      // literal per-tab segment instead of a real :memoryTab parameter.
      const { memoryTab } = useParams();
      return (
        <div>
          Memory Evidence Page
          <span data-testid="memory-evidence-route">{location.pathname + location.search}</span>
          <span data-testid="memory-evidence-tab-param">{memoryTab ?? ""}</span>
          <button type="button" onClick={() => navigate(-1)}>Back</button>
        </div>
      );
    },
  };
});
vi.mock("./pages/WorkbenchOverviewPage", async () => {
  const { useLocation } = await vi.importActual<typeof import("react-router-dom")>("react-router-dom");
  return { default: ({ workbenchId }: { workbenchId: string }) => <div>{displayWorkbench(workbenchId)} Workbench Page<span data-testid="workbench-route">{useLocation().pathname + useLocation().search}</span></div> };
});
vi.mock("./components/MemoryWorkspace", () => ({ MemoryWorkspace: () => <div>Memory Workspace Page</div> }));

function displayWorkbench(value: string) {
  return value.charAt(0).toUpperCase() + value.slice(1);
}

function renderApp(initialEntry: string | string[]) {
  const queryClient = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  const entries = Array.isArray(initialEntry) ? initialEntry : [initialEntry];
  return render(
    <QueryClientProvider client={queryClient}>
      <MemoryRouter initialEntries={entries} initialIndex={entries.length - 1}>
        <App />
      </MemoryRouter>
    </QueryClientProvider>,
  );
}

describe("legacy navigation redirects", () => {
  beforeEach(() => {
    activeCaseState.activeCaseId = "case-1";
    activeCaseState.activeCase = { id: "case-1", name: "Case Alpha" };
    activeCaseState.setActiveCaseId = vi.fn();
    listCasesMock.mockResolvedValue([{ id: "demo-case", name: "Demo - ACME Incident 001" }]);
    getMemoryOverviewMock.mockResolvedValue({ evidences: [] });
  });

  it("redirects /process-tree to the active case process graph", async () => {
    renderApp("/process-tree");
    expect(await screen.findByText("Process Graph Page")).toBeInTheDocument();
  });

  it("redirects /timeline to the active case timeline", async () => {
    renderApp("/timeline");
    expect(await screen.findByText("Timeline Page")).toBeInTheDocument();
  });

  it("redirects /dashboard to the active case overview", async () => {
    renderApp("/dashboard");
    expect(await screen.findByText("Overview Page")).toBeInTheDocument();
  });

  it("shows a no-active-case state on direct case-centric routes without an active case", async () => {
    activeCaseState.activeCaseId = "";
    activeCaseState.activeCase = null;
    renderApp("/search");
    expect(await screen.findByText(/No active case selected/i)).toBeInTheDocument();
    expect(screen.getByRole("link", { name: /Select case/i })).toHaveAttribute("href", "/cases");
    expect(screen.getByRole("link", { name: /Create case/i })).toHaveAttribute("href", "/cases");
    expect(await screen.findByRole("link", { name: /Open demo case/i })).toHaveAttribute("href", "/cases/demo-case/overview");
  });

  it("shows the same empty state for legacy redirect routes without an active case", async () => {
    activeCaseState.activeCaseId = "";
    activeCaseState.activeCase = null;
    renderApp("/timeline");
    expect(await screen.findByText(/No active case selected/i)).toBeInTheDocument();
  });

  it("renders the canonical artifact views route", async () => {
    renderApp("/cases/case-1/artifacts");
    expect(await screen.findByText("Artifact Views Page")).toBeInTheDocument();
  });

  it("renders canonical platform workbench overview routes", async () => {
    renderApp("/cases/case-1/w");
    expect(await screen.findByText("Windows Workbench Page")).toBeInTheDocument();
  });

  it("keeps the legacy /cases/:caseId/artifact-search route working", async () => {
    renderApp("/cases/case-1/artifact-search");
    expect(await screen.findByText("Artifact Views Page")).toBeInTheDocument();
  });
});

describe("memory routes are registered", () => {
  beforeEach(() => {
    activeCaseState.activeCaseId = "case-1";
    activeCaseState.activeCase = { id: "case-1", name: "Case Alpha" };
    activeCaseState.setActiveCaseId = vi.fn();
    listCasesMock.mockResolvedValue([]);
    getMemoryOverviewMock.mockResolvedValue({ evidences: [] });
  });

  it("renders the canonical memory landing at /cases/:caseId/m", async () => {
    renderApp("/cases/case-1/m");
    expect(await screen.findByText("Memory Workbench Page")).toBeInTheDocument();
  });

  it("redirects legacy /cases/:caseId/memory with multiple memory images to the canonical memory landing", async () => {
    getMemoryOverviewMock.mockResolvedValue({ evidences: [{ id: "ev-A" }, { id: "ev-B" }] });
    renderApp("/cases/case-1/memory?tab=processes&filter=suspicious");
    expect(await screen.findByText("Memory Workbench Page")).toBeInTheDocument();
    expect(screen.getByTestId("workbench-route")).toHaveTextContent("/cases/case-1/m?filter=suspicious");
  });

  it("redirects legacy /cases/:caseId/memory with one memory image to the requested canonical tab", async () => {
    getMemoryOverviewMock.mockResolvedValue({ evidences: [{ id: "ev-A" }] });
    renderApp("/cases/case-1/memory?tab=graph");
    expect(await screen.findByText("Memory Evidence Page")).toBeInTheDocument();
    expect(screen.getByTestId("memory-evidence-route")).toHaveTextContent("/cases/case-1/m/ev-A/process-graph");
  });

  it("redirects legacy memory evidence bookmarks to canonical evidence routes", async () => {
    renderApp("/cases/case-1/memory/ev-A/graph?foo=bar");
    expect(await screen.findByText("Memory Evidence Page")).toBeInTheDocument();
    expect(screen.getByTestId("memory-evidence-route")).toHaveTextContent("/cases/case-1/m/ev-A/process-graph?foo=bar");
  });

  it("redirects legacy memory runs bookmarks to the canonical runs route", async () => {
    getMemoryOverviewMock.mockResolvedValue({ evidences: [{ id: "ev-A" }, { id: "ev-B" }] });
    renderApp("/cases/case-1/memory?tab=runs");
    expect(await screen.findByText("Memory Workspace Page")).toBeInTheDocument();
  });

  it("renders invalid memory image ids on the canonical evidence route for page-level validation", async () => {
    renderApp("/cases/case-1/m/not-a-real-image/processes");
    expect(await screen.findByText("Memory Evidence Page")).toBeInTheDocument();
    expect(screen.getByTestId("memory-evidence-route")).toHaveTextContent("/cases/case-1/m/not-a-real-image/processes");
  });

  it("supports refresh-style direct canonical memory deep links without redirecting", async () => {
    renderApp("/cases/case-1/m/ev-A/network?host=HOSTA");
    expect(await screen.findByText("Memory Evidence Page")).toBeInTheDocument();
    expect(screen.getByTestId("memory-evidence-route")).toHaveTextContent("/cases/case-1/m/ev-A/network?host=HOSTA");
  });

  // Regression: /cases/:caseId/m/:evidenceId/runs was the only Memory tab
  // route missing from this route table. Since it matched no <Route>, the
  // app fell through every specific match and hit the final catch-all
  // (`<Route path="*" element={<Navigate to="/" replace />} />`), which
  // sent the analyst to the global Dashboard -- silently dropping caseId
  // and evidenceId. This reproduces "click Runs -> global cases summary"
  // exactly, via the real route table (not a test-local one), and
  // confirms it no longer happens.
  it("opens the canonical evidence-scoped Runs route inside the Memory workspace, not the global dashboard (regression)", async () => {
    renderApp("/cases/case-1/m/ev-A/runs");
    expect(await screen.findByText("Memory Evidence Page")).toBeInTheDocument();
    expect(screen.getByTestId("memory-evidence-route")).toHaveTextContent("/cases/case-1/m/ev-A/runs");
    expect(screen.queryByText("Dashboard Page")).not.toBeInTheDocument();
    expect(screen.queryByText("Cases Page")).not.toBeInTheDocument();
  });

  it("supports refresh-style direct canonical Runs deep links without redirecting", async () => {
    renderApp("/cases/case-1/m/ev-A/runs?host=HOSTA");
    expect(await screen.findByText("Memory Evidence Page")).toBeInTheDocument();
    expect(screen.getByTestId("memory-evidence-route")).toHaveTextContent("/cases/case-1/m/ev-A/runs?host=HOSTA");
  });

  // Regression: App.tsx used to register one LITERAL <Route> per Memory tab
  // segment (path="/cases/:caseId/m/:evidenceId/processes", etc.), none of
  // which declared :memoryTab as an actual route parameter. That made
  // useParams().memoryTab empty for every single Memory tab in production,
  // which in turn made MemoryEvidencePage's tab resolution always fall
  // through to the ?tab= query param -- so every tab silently rendered
  // Overview regardless of the URL path. This asserts the real App.tsx
  // route captures the segment as :memoryTab for every tab, using the
  // actual route table (not a test-only one).
  it.each([
    "overview", "processes", "process-graph", "network", "modules",
    "handles", "suspicious", "vads", "system", "runs", "raw",
  ])("captures \"%s\" as the :memoryTab route param, not just a literal path match", async (segment) => {
    renderApp(`/cases/case-1/m/ev-A/${segment}`);
    expect(await screen.findByText("Memory Evidence Page")).toBeInTheDocument();
    expect(screen.getByTestId("memory-evidence-tab-param")).toHaveTextContent(segment);
  });

  it("supports browser Back from the canonical Runs route back to the previous screen", async () => {
    renderApp(["/cases/case-1/overview", "/cases/case-1/m/ev-A/runs"]);
    expect(await screen.findByText("Memory Evidence Page")).toBeInTheDocument();
    expect(screen.getByTestId("memory-evidence-route")).toHaveTextContent("/cases/case-1/m/ev-A/runs");
    fireEvent.click(screen.getByRole("button", { name: "Back" }));
    expect(await screen.findByText("Overview Page")).toBeInTheDocument();
  });

  it("replaces legacy memory bookmarks so the back button does not re-enter the redirect", async () => {
    renderApp(["/cases/case-1/overview", "/cases/case-1/memory/ev-A/graph"]);
    expect(await screen.findByText("Memory Evidence Page")).toBeInTheDocument();
    expect(screen.getByTestId("memory-evidence-route")).toHaveTextContent("/cases/case-1/m/ev-A/process-graph");
    fireEvent.click(screen.getByRole("button", { name: "Back" }));
    expect(await screen.findByText("Overview Page")).toBeInTheDocument();
  });

  it("redirects Memory Upload to the canonical Add Evidence wizard", async () => {
    renderApp("/cases/case-1/memory/upload");
    expect(await screen.findByText("Case Detail Page")).toBeInTheDocument();
    expect(screen.queryByText("Memory Upload Page")).not.toBeInTheDocument();
  });

  it("does not collapse /cases/:caseId/memory onto another route", async () => {
    renderApp("/cases/case-1/memory");
    expect(screen.queryByText("Overview Page")).not.toBeInTheDocument();
    expect(screen.queryByText("Case Detail Page")).not.toBeInTheDocument();
    expect(screen.queryByText("Detections Page")).not.toBeInTheDocument();
  });

  it("does not collapse /cases/:caseId/memory/upload onto memory analysis", async () => {
    renderApp("/cases/case-1/memory/upload");
    expect(screen.queryByText("Overview Page")).not.toBeInTheDocument();
    expect(screen.queryByText("Memory Analysis Page")).not.toBeInTheDocument();
  });
});
