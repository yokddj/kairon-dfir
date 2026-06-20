import type { ReactNode } from "react";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { render, screen } from "@testing-library/react";
import { MemoryRouter } from "react-router-dom";
import { beforeEach, describe, expect, it, vi } from "vitest";

import App from "./App";

const listCasesMock = vi.fn();
const activeCaseState: any = {
  activeCaseId: "case-1",
  activeCase: { id: "case-1", name: "Case Alpha" },
};

vi.mock("./components/Layout", () => ({
  default: ({ children }: { children: ReactNode }) => <div>{children}</div>,
}));

vi.mock("./api/client", () => ({
  api: {
    listCases: (...args: unknown[]) => listCasesMock(...args),
  },
}));

vi.mock("./context/ActiveCaseContext", () => ({
  ActiveCaseProvider: ({ children }: { children: ReactNode }) => <>{children}</>,
  useActiveCase: () => activeCaseState,
}));

vi.mock("./context/NotificationsContext", () => ({
  NotificationsProvider: ({ children }: { children: ReactNode }) => <>{children}</>,
}));

vi.mock("./context/TimezoneContext", () => ({
  TimezoneProvider: ({ children }: { children: ReactNode }) => <>{children}</>,
}));

vi.mock("./pages/Dashboard", () => ({ default: () => <div>Dashboard Page</div> }));
vi.mock("./pages/Cases", () => ({ default: () => <div>Cases Page</div> }));
vi.mock("./pages/CaseDetail", () => ({ default: () => <div>Case Detail Page</div> }));
vi.mock("./pages/CaseOverviewPage", () => ({ default: () => <div>Overview Page</div> }));
vi.mock("./pages/CaseProcessGraphPage", () => ({ default: () => <div>Process Graph Page</div> }));
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
vi.mock("./pages/MemoryAnalysisPage", () => ({ default: () => <div>Memory Analysis Page</div> }));
vi.mock("./pages/MemoryUploadPage", () => ({ default: () => <div>Memory Upload Page</div> }));

function renderApp(initialEntry: string) {
  const queryClient = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  return render(
    <QueryClientProvider client={queryClient}>
      <MemoryRouter initialEntries={[initialEntry]}>
        <App />
      </MemoryRouter>
    </QueryClientProvider>,
  );
}

describe("legacy navigation redirects", () => {
  beforeEach(() => {
    activeCaseState.activeCaseId = "case-1";
    activeCaseState.activeCase = { id: "case-1", name: "Case Alpha" };
    listCasesMock.mockResolvedValue([{ id: "demo-case", name: "Demo - ACME Incident 001" }]);
  });

  it("redirects /process-tree to the active case process graph", async () => {
    renderApp("/process-tree");
    expect(await screen.findByText("Process Graph Page")).toBeInTheDocument();
  });

  it("redirects /timeline to the active case Search timeline view", async () => {
    renderApp("/timeline");
    expect(await screen.findByText("Search Page")).toBeInTheDocument();
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

  it("keeps the legacy /cases/:caseId/artifact-search route working", async () => {
    renderApp("/cases/case-1/artifact-search");
    expect(await screen.findByText("Artifact Views Page")).toBeInTheDocument();
  });
});

describe("memory routes are registered", () => {
  beforeEach(() => {
    activeCaseState.activeCaseId = "case-1";
    activeCaseState.activeCase = { id: "case-1", name: "Case Alpha" };
    listCasesMock.mockResolvedValue([]);
  });

  it("renders Memory Analysis at /cases/:caseId/memory", async () => {
    renderApp("/cases/case-1/memory");
    expect(await screen.findByText("Memory Analysis Page")).toBeInTheDocument();
  });

  it("renders Memory Upload at /cases/:caseId/memory/upload", async () => {
    renderApp("/cases/case-1/memory/upload");
    expect(await screen.findByText("Memory Upload Page")).toBeInTheDocument();
  });

  it("does not collapse /cases/:caseId/memory onto another route", async () => {
    renderApp("/cases/case-1/memory");
    expect(screen.queryByText("Overview Page")).not.toBeInTheDocument();
    expect(screen.queryByText("Case Detail Page")).not.toBeInTheDocument();
    expect(screen.queryByText("Detections Page")).not.toBeInTheDocument();
  });

  it("does not collapse /cases/:caseId/memory/upload onto another route", async () => {
    renderApp("/cases/case-1/memory/upload");
    expect(screen.queryByText("Overview Page")).not.toBeInTheDocument();
    expect(screen.queryByText("Memory Analysis Page")).not.toBeInTheDocument();
  });
});
