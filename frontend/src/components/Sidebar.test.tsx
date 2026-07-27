import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { render, screen, within } from "@testing-library/react";
import { MemoryRouter } from "react-router-dom";
import { beforeEach, describe, expect, it, vi } from "vitest";

import Sidebar from "./Sidebar";

const getCaseCapabilitiesMock = vi.fn();
const logoutMock = vi.fn();

const activeCaseState: any = {
  activeCaseId: "case-1",
  activeCase: { id: "case-1", name: "Case Alpha" },
  caseContext: { summary: { validation_matrix: { show_validation_matrix: false } } },
  setActiveCaseId: vi.fn(),
};

vi.mock("../context/ActiveCaseContext", () => ({
  useActiveCase: () => activeCaseState,
}));

vi.mock("../context/AuthContext", () => ({
  useAuth: () => ({
    user: { username: "admin", display_name: "Admin", is_admin: true },
    logout: logoutMock,
  }),
}));

vi.mock("../api/client", () => ({
  api: {
    getCaseCapabilities: (...args: unknown[]) => getCaseCapabilitiesMock(...args),
  },
}));

type CapabilityPatch = Partial<{
  id: string;
  platform: string;
  evidence_domain: string;
  domain: string;
  title: string;
  route: string;
  artifact_families: string[];
  nav: { parent: string; order: number };
  search: { filters: Array<Record<string, unknown>>; presets: Array<Record<string, unknown>> };
  availability: string;
  readiness_source: string;
  artifact_count: number;
  record_count: number;
  status_counts: Record<string, unknown>;
  readiness: string;
  visible: boolean;
}>;

function capability(patch: CapabilityPatch) {
  return {
    id: "linux.access.authentication",
    platform: "linux",
    evidence_domain: "filesystem",
    domain: "access",
    title: "Authentication",
    route: "/cases/:caseId/linux-authentication",
    artifact_families: ["linux_auth"],
    nav: { parent: "linux/access", order: 10 },
    search: { filters: [], presets: [] },
    availability: "shipped",
    readiness_source: "artifact_counts",
    artifact_count: 1,
    record_count: 1,
    status_counts: {},
    readiness: "has_data",
    visible: true,
    ...patch,
  };
}

function registry({ workbenches = [], capabilities = [] }: { workbenches?: any[]; capabilities?: any[] } = {}) {
  return {
    registry_version: "test",
    generated_at: "2026-07-27T00:00:00Z",
    case: { id: "case-1", name: "Case Alpha", status: "active" },
    platforms: [],
    evidence_domains: [],
    workbenches,
    capabilities,
    hosts: [],
    evidence: [],
  };
}

const linuxAuth = capability({});
const windowsCommandHistory = capability({
  id: "windows.execution.command_history",
  platform: "windows",
  domain: "execution",
  title: "Command History",
  route: "/cases/:caseId/command-history",
  artifact_families: ["windows_event"],
  nav: { parent: "windows/execution", order: 20 },
});
const windowsExecutionStories = capability({
  id: "windows.execution.stories",
  platform: "windows",
  domain: "execution",
  title: "Execution Stories",
  route: "/cases/:caseId/process-graph",
  artifact_families: ["windows_event"],
  nav: { parent: "windows/execution", order: 10 },
});
const hiddenWindows = capability({
  id: "windows.hidden",
  platform: "windows",
  domain: "execution",
  title: "Hidden Windows",
  route: "/cases/:caseId/hidden",
  nav: { parent: "windows/execution", order: 1 },
  readiness: "not_applicable",
  visible: false,
});

function renderSidebar(initialEntry = "/cases/case-1/overview") {
  const queryClient = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  return render(
    <QueryClientProvider client={queryClient}>
      <MemoryRouter initialEntries={[initialEntry]}>
        <Sidebar />
      </MemoryRouter>
    </QueryClientProvider>,
  );
}

describe("registry-driven sidebar", () => {
  beforeEach(() => {
    activeCaseState.activeCaseId = "case-1";
    activeCaseState.activeCase = { id: "case-1", name: "Case Alpha" };
    getCaseCapabilitiesMock.mockReset();
    logoutMock.mockReset();
  });

  it("renders fixed Investigation and Case Tools groups", async () => {
    getCaseCapabilitiesMock.mockResolvedValue(registry());
    renderSidebar();

    const investigation = screen.getByText("Investigation").closest("section")!;
    for (const label of ["Overview", "Evidence", "Search", "Timeline", "Incident Timeline", "Detections", "Findings", "Reports"]) {
      expect(within(investigation).getByRole("link", { name: label })).toBeInTheDocument();
    }
    const tools = screen.getByText("Case Tools").closest("section")!;
    expect(within(tools).getByRole("link", { name: "Artifact Views" })).toHaveAttribute("href", "/cases/case-1/artifacts");
    expect(within(tools).getByRole("link", { name: "Validation Matrix" })).toHaveAttribute("href", "/cases/case-1/validation-matrix");
    expect(within(tools).getByRole("link", { name: "Debug Export" })).toHaveAttribute("href", "/cases/case-1/debug-export");
  });

  it("generates platform workbenches from registry visibility", async () => {
    getCaseCapabilitiesMock.mockResolvedValue(registry({
      workbenches: [
        { id: "linux", label: "Linux", kind: "platform", capability_ids: [linuxAuth.id], domains: [{ id: "access", capability_ids: [linuxAuth.id], record_count: 1 }] },
      ],
      capabilities: [linuxAuth, hiddenWindows],
    }));

    renderSidebar();

    const linux = await screen.findByTestId("workbench-linux");
    expect(within(linux).getByRole("link", { name: "Authentication" })).toHaveAttribute("href", "/cases/case-1/linux-authentication");
    expect(screen.queryByTestId("workbench-windows")).not.toBeInTheDocument();
    expect(screen.queryByText("Hidden Windows")).not.toBeInTheDocument();
  });

  it("orders capabilities with registry nav metadata", async () => {
    getCaseCapabilitiesMock.mockResolvedValue(registry({
      workbenches: [
        { id: "windows", label: "Windows", kind: "platform", capability_ids: [windowsCommandHistory.id, windowsExecutionStories.id], domains: [{ id: "execution", capability_ids: [windowsCommandHistory.id, windowsExecutionStories.id], record_count: 2 }] },
      ],
      capabilities: [windowsCommandHistory, windowsExecutionStories],
    }));

    renderSidebar();

    const windows = await screen.findByTestId("workbench-windows");
    const links = within(windows).getAllByRole("link").map((link) => link.textContent || "");
    expect(links[0]).toContain("Execution Stories");
    expect(links[1]).toContain("Command History");
  });

  it("renders unknown future capability and unknown future workbench generically", async () => {
    const cloudSync = capability({
      id: "cloud.sync.activity",
      platform: "cloud",
      domain: "cloud_sync",
      title: "Cloud Sync Activity",
      route: "/cases/:caseId/artifacts?artifact_type=cloud_sync",
      nav: { parent: "cloud/cloud_sync", order: 10 },
    });
    getCaseCapabilitiesMock.mockResolvedValue(registry({
      workbenches: [
        { id: "cloud", label: "Cloud", kind: "platform", capability_ids: [cloudSync.id], domains: [{ id: "cloud_sync", capability_ids: [cloudSync.id], record_count: 9 }] },
      ],
      capabilities: [cloudSync],
    }));

    renderSidebar();

    const cloud = await screen.findByTestId("workbench-cloud");
    expect(within(cloud).getByText("Cloud")).toBeInTheDocument();
    expect(within(cloud).getByRole("link", { name: "Cloud Sync Activity" })).toHaveAttribute("href", "/cases/case-1/artifacts?artifact_type=cloud_sync");
  });

  it("shows loading state while registry request is pending", () => {
    getCaseCapabilitiesMock.mockReturnValue(new Promise(() => {}));
    renderSidebar();
    expect(screen.getByRole("status")).toHaveTextContent("Loading workbenches");
  });

  it("shows API failure without inventing workbenches", async () => {
    getCaseCapabilitiesMock.mockRejectedValue(new Error("boom"));
    renderSidebar();
    expect(await screen.findByRole("alert")).toHaveTextContent("Capability registry unavailable");
    expect(screen.queryByTestId(/workbench-/)).not.toBeInTheDocument();
  });

  it("renders an empty registry with only fixed sections", async () => {
    getCaseCapabilitiesMock.mockResolvedValue(registry());
    renderSidebar();
    await screen.findByText("Case Tools");
    expect(screen.queryByTestId(/workbench-/)).not.toBeInTheDocument();
  });

  it("renders degraded, processing and failed capability states", async () => {
    const degraded = capability({ id: "linux.degraded", title: "Degraded", readiness: "degraded", nav: { parent: "linux/access", order: 10 } });
    const processing = capability({ id: "linux.processing", title: "Processing", readiness: "processing", nav: { parent: "linux/access", order: 20 } });
    const failed = capability({ id: "linux.failed", title: "Failed", readiness: "failed", nav: { parent: "linux/access", order: 30 } });
    getCaseCapabilitiesMock.mockResolvedValue(registry({
      workbenches: [
        { id: "linux", label: "Linux", kind: "platform", capability_ids: [degraded.id, processing.id, failed.id], domains: [{ id: "access", capability_ids: [degraded.id, processing.id, failed.id], record_count: 3 }] },
      ],
      capabilities: [degraded, processing, failed],
    }));

    renderSidebar();

    expect(await screen.findByLabelText("Degraded degraded")).toBeInTheDocument();
    expect(screen.getByLabelText("Processing processing")).toBeInTheDocument();
    expect(screen.getByLabelText("Failed failed")).toBeInTheDocument();
  });

  it("preserves selected memory evidence for registry memory routes", async () => {
    const memoryNetwork = capability({
      id: "memory.network",
      platform: "memory",
      evidence_domain: "memory",
      domain: "network",
      title: "Network",
      route: "/cases/:caseId/memory?tab=network",
      nav: { parent: "memory/network", order: 10 },
    });
    getCaseCapabilitiesMock.mockResolvedValue(registry({
      workbenches: [
        { id: "memory", label: "Memory", kind: "evidence_domain", capability_ids: [memoryNetwork.id], domains: [{ id: "network", capability_ids: [memoryNetwork.id], record_count: 1 }] },
      ],
      capabilities: [memoryNetwork],
    }));

    renderSidebar("/cases/case-1/memory/ev-A/processes");

    const memory = await screen.findByTestId("workbench-memory");
    expect(within(memory).getByRole("link", { name: "Network" })).toHaveAttribute("href", "/cases/case-1/memory/ev-A/network");
  });

  it("does not call the registry endpoint when no case is active", () => {
    activeCaseState.activeCaseId = "";
    activeCaseState.activeCase = null;
    renderSidebar();
    expect(getCaseCapabilitiesMock).not.toHaveBeenCalled();
    expect(screen.queryByTestId(/workbench-/)).not.toBeInTheDocument();
  });
});
