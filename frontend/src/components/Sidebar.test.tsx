import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { render, screen, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
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
    route: "/cases/:caseId/l/access/authentication",
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
  route: "/cases/:caseId/w/execution/command-history",
  artifact_families: ["windows_event"],
  nav: { parent: "windows/execution", order: 20 },
});
const windowsExecutionStories = capability({
  id: "windows.execution.stories",
  platform: "windows",
  domain: "execution",
  title: "Execution Stories",
  route: "/cases/:caseId/w/execution/stories",
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
    localStorage.clear();
  });

  it("renders fixed Investigation and Technical Tools groups", async () => {
    getCaseCapabilitiesMock.mockResolvedValue(registry());
    renderSidebar();

    const investigation = screen.getByText("Investigation").closest("section")!;
    for (const label of ["Overview", "Evidence", "Search", "Timeline", "Incident Timeline", "Detections", "Findings", "Reports"]) {
      expect(within(investigation).getByRole("link", { name: label })).toBeInTheDocument();
    }
    const tools = screen.getByText("Technical Tools").closest("section")!;
    expect(within(tools).getByRole("link", { name: "Artifact Views" })).toHaveAttribute("href", "/cases/case-1/artifacts");
    expect(within(tools).getByRole("link", { name: "Validation Matrix" })).toHaveAttribute("href", "/cases/case-1/validation-matrix");
    expect(within(tools).getByRole("link", { name: "Debug Export" })).toHaveAttribute("href", "/cases/case-1/debug-export");
  });

  it("generates platform workbenches from registry visibility", async () => {
    getCaseCapabilitiesMock.mockResolvedValue(registry({
      workbenches: [
        { id: "linux", label: "Linux", kind: "platform", overview_route: "/cases/case-1/l", capability_ids: [linuxAuth.id], domains: [{ id: "access", capability_ids: [linuxAuth.id], record_count: 1 }] },
      ],
      capabilities: [linuxAuth, hiddenWindows],
    }));

    renderSidebar();

    const linux = await screen.findByTestId("workbench-linux");
    expect(within(linux).getByRole("link", { name: "Linux overview" })).toHaveAttribute("href", "/cases/case-1/l");
    expect(within(linux).queryByRole("treeitem", { name: "Authentication" })).not.toBeInTheDocument();
    await userEvent.click(within(linux).getByRole("treeitem", { name: /linux/i }));
    await userEvent.click(within(linux).getByRole("treeitem", { name: /access/i }));
    expect(within(linux).getByRole("treeitem", { name: "Authentication" })).toHaveAttribute("href", "/cases/case-1/l/access/authentication");
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
    await userEvent.click(within(windows).getByRole("treeitem", { name: /windows/i }));
    await userEvent.click(within(windows).getByRole("treeitem", { name: /execution/i }));
    const links = within(windows).getAllByRole("treeitem").map((link) => link.textContent || "").filter((text) => ["Execution Stories", "Command History"].includes(text));
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
    await userEvent.click(within(cloud).getByRole("treeitem", { name: /cloud/i }));
    await userEvent.click(within(cloud).getByRole("treeitem", { name: /cloud sync/i }));
    expect(within(cloud).getByRole("treeitem", { name: "Cloud Sync Activity" })).toHaveAttribute("href", "/cases/case-1/artifacts?artifact_type=cloud_sync");
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
    await screen.findByText("Technical Tools");
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

    const linux = await screen.findByTestId("workbench-linux");
    await userEvent.click(within(linux).getByRole("treeitem", { name: /linux/i }));
    await userEvent.click(within(linux).getByRole("treeitem", { name: /access/i }));
    expect(screen.getByLabelText("Degraded degraded")).toBeInTheDocument();
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
      route: "/cases/:caseId/m/:evidenceId/network",
      nav: { parent: "memory/network", order: 10 },
    });
    getCaseCapabilitiesMock.mockResolvedValue(registry({
      workbenches: [
        { id: "memory", label: "Memory", kind: "evidence_domain", capability_ids: [memoryNetwork.id], domains: [{ id: "network", capability_ids: [memoryNetwork.id], record_count: 1 }] },
      ],
      capabilities: [memoryNetwork],
    }));

    renderSidebar("/cases/case-1/m/ev-A/processes");

    const memory = await screen.findByTestId("workbench-memory");
    await userEvent.click(within(memory).getByRole("treeitem", { name: /memory/i }));
    await userEvent.click(within(memory).getByRole("treeitem", { name: /network/i }));
    expect(within(memory).getByRole("treeitem", { name: "Network" })).toHaveAttribute("href", "/cases/case-1/m/ev-A/network");
  });

  it("does not call the registry endpoint when no case is active", () => {
    activeCaseState.activeCaseId = "";
    activeCaseState.activeCase = null;
    renderSidebar();
    expect(getCaseCapabilitiesMock).not.toHaveBeenCalled();
    expect(screen.queryByTestId(/workbench-/)).not.toBeInTheDocument();
  });

  it("persists collapsed and expanded navigation state", async () => {
    getCaseCapabilitiesMock.mockResolvedValue(registry({
      workbenches: [
        { id: "linux", label: "Linux", kind: "platform", capability_ids: [linuxAuth.id], domains: [{ id: "access", capability_ids: [linuxAuth.id], record_count: 1 }] },
      ],
      capabilities: [linuxAuth],
    }));
    const { unmount } = renderSidebar();
    const linux = await screen.findByTestId("workbench-linux");
    await userEvent.click(within(linux).getByRole("treeitem", { name: /linux/i }));
    await userEvent.click(within(linux).getByRole("treeitem", { name: /access/i }));
    expect(within(linux).getByRole("treeitem", { name: "Authentication" })).toBeInTheDocument();
    unmount();

    renderSidebar();

    const restoredLinux = await screen.findByTestId("workbench-linux");
    expect(within(restoredLinux).getByRole("treeitem", { name: "Authentication" })).toBeInTheDocument();
  });

  it("auto-expands parents for deep-linked Linux Authentication", async () => {
    getCaseCapabilitiesMock.mockResolvedValue(registry({
      workbenches: [
        { id: "linux", label: "Linux", kind: "platform", capability_ids: [linuxAuth.id], domains: [{ id: "access", capability_ids: [linuxAuth.id], record_count: 1 }] },
      ],
      capabilities: [linuxAuth],
    }));

    renderSidebar("/cases/case-1/l/access/authentication");

    const linux = await screen.findByTestId("workbench-linux");
    expect(within(linux).getByRole("treeitem", { name: /linux/i })).toHaveAttribute("aria-expanded", "true");
    expect(within(linux).getByRole("treeitem", { name: /access/i })).toHaveAttribute("aria-expanded", "true");
    expect(within(linux).getByRole("treeitem", { name: "Authentication" })).toHaveAttribute("aria-selected", "true");
  });

  it("auto-expands parents for deep-linked Memory Processes", async () => {
    const memoryProcesses = capability({
      id: "memory.processes",
      platform: "memory",
      evidence_domain: "memory",
      domain: "execution",
      title: "Processes",
      route: "/cases/:caseId/m/:evidenceId/processes",
      nav: { parent: "memory/execution", order: 10 },
    });
    getCaseCapabilitiesMock.mockResolvedValue(registry({
      workbenches: [
        { id: "memory", label: "Memory", kind: "evidence_domain", capability_ids: [memoryProcesses.id], domains: [{ id: "execution", capability_ids: [memoryProcesses.id], record_count: 1 }] },
      ],
      capabilities: [memoryProcesses],
    }));

    renderSidebar("/cases/case-1/m/ev-A/processes");

    const memory = await screen.findByTestId("workbench-memory");
    expect(within(memory).getByRole("treeitem", { name: /memory/i })).toHaveAttribute("aria-expanded", "true");
    expect(within(memory).getByRole("treeitem", { name: /execution/i })).toHaveAttribute("aria-expanded", "true");
    expect(within(memory).getByRole("treeitem", { name: "Processes" })).toBeInTheDocument();
  });

  it("searches visible registry metadata without rendering hidden capabilities", async () => {
    getCaseCapabilitiesMock.mockResolvedValue(registry({
      workbenches: [
        { id: "linux", label: "Linux", kind: "platform", capability_ids: [linuxAuth.id], domains: [{ id: "access", capability_ids: [linuxAuth.id], record_count: 1 }] },
        { id: "windows", label: "Windows", kind: "platform", capability_ids: [windowsExecutionStories.id, hiddenWindows.id], domains: [{ id: "execution", capability_ids: [windowsExecutionStories.id, hiddenWindows.id], record_count: 1 }] },
      ],
      capabilities: [linuxAuth, windowsExecutionStories, hiddenWindows],
    }));

    renderSidebar();
    await userEvent.type(await screen.findByLabelText("Filter capabilities"), "auth");

    expect(await screen.findByRole("treeitem", { name: "Authentication" })).toBeInTheDocument();
    expect(screen.queryByRole("treeitem", { name: "Execution Stories" })).not.toBeInTheDocument();
    expect(screen.queryByText("Hidden Windows")).not.toBeInTheDocument();
  });

  it("supports keyboard traversal and collapse controls", async () => {
    getCaseCapabilitiesMock.mockResolvedValue(registry({
      workbenches: [
        { id: "linux", label: "Linux", kind: "platform", capability_ids: [linuxAuth.id], domains: [{ id: "access", capability_ids: [linuxAuth.id], record_count: 1 }] },
      ],
      capabilities: [linuxAuth],
    }));

    renderSidebar();
    const linux = await screen.findByRole("treeitem", { name: /linux/i });
    linux.focus();
    await userEvent.keyboard("{ArrowRight}");
    expect(linux).toHaveAttribute("aria-expanded", "true");
    await userEvent.keyboard("{ArrowDown}");
    expect(screen.getByRole("treeitem", { name: /access/i })).toHaveFocus();
    await userEvent.keyboard("{Enter}");
    expect(screen.getByRole("treeitem", { name: /access/i })).toHaveAttribute("aria-expanded", "true");
    await userEvent.keyboard("{Escape}");
    expect(screen.getByLabelText("Filter capabilities")).toHaveFocus();
  });

  it("keeps large synthetic registries searchable without hardcoded workbench logic", async () => {
    const syntheticCapabilities = Array.from({ length: 160 }, (_, index) => capability({
      id: `future.workbench${Math.floor(index / 20)}.domain${Math.floor(index / 5)}.capability${index}`,
      platform: `future-${Math.floor(index / 20)}`,
      domain: `domain_${Math.floor(index / 5)}`,
      title: index === 137 ? "Needle Process Capability" : `Future Capability ${index}`,
      route: `/cases/:caseId/future-${Math.floor(index / 20)}/domain-${Math.floor(index / 5)}/capability-${index}`,
      nav: { parent: `future-${Math.floor(index / 20)}/domain_${Math.floor(index / 5)}`, order: index },
    }));
    const syntheticWorkbenches = Array.from({ length: 8 }, (_, workbenchIndex) => {
      const workbenchCapabilities = syntheticCapabilities.filter((item) => item.platform === `future-${workbenchIndex}`);
      return {
        id: `future-${workbenchIndex}`,
        label: `Future ${workbenchIndex}`,
        kind: "platform",
        capability_ids: workbenchCapabilities.map((item) => item.id),
        domains: Array.from({ length: 4 }, (_, domainOffset) => {
          const domainIndex = workbenchIndex * 4 + domainOffset;
          const domainCapabilities = workbenchCapabilities.filter((item) => item.domain === `domain_${domainIndex}`);
          return { id: `domain_${domainIndex}`, capability_ids: domainCapabilities.map((item) => item.id), record_count: domainCapabilities.length };
        }),
      };
    });
    getCaseCapabilitiesMock.mockResolvedValue(registry({ workbenches: syntheticWorkbenches, capabilities: syntheticCapabilities }));

    renderSidebar();
    await userEvent.type(await screen.findByLabelText("Filter capabilities"), "needle process");

    const match = await screen.findByRole("treeitem", { name: "Needle Process Capability" });
    expect(match).toHaveAttribute("href", "/cases/case-1/future-6/domain-27/capability-137");
    expect(screen.queryByRole("treeitem", { name: "Future Capability 12" })).not.toBeInTheDocument();
  });
});
