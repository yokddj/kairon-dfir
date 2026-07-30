import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { render, screen, within } from "@testing-library/react";
import { MemoryRouter } from "react-router-dom";
import { beforeEach, describe, expect, it, vi } from "vitest";

import Sidebar from "./Sidebar";
import { resolveSurfaceIcon } from "../lib/surfaceIcons";
import type { CaseCapabilitiesResponse } from "../api/client";

vi.mock("../lib/surfaceIcons", async () => {
  const actual = await vi.importActual<typeof import("../lib/surfaceIcons")>("../lib/surfaceIcons");
  return { ...actual, resolveSurfaceIcon: vi.fn(actual.resolveSurfaceIcon) };
});

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

type WorkbenchPatch = Partial<CaseCapabilitiesResponse["workbenches"][number]>;

function workbench(patch: WorkbenchPatch = {}): CaseCapabilitiesResponse["workbenches"][number] {
  return {
    id: "linux",
    label: "Linux",
    kind: "platform",
    icon: "shield-check",
    capability_ids: [],
    domains: [],
    overview_route: "/cases/case-1/l",
    ...patch,
  };
}

function registry(workbenches: CaseCapabilitiesResponse["workbenches"] = []): CaseCapabilitiesResponse {
  return {
    registry_version: "test",
    generated_at: "2026-07-27T00:00:00Z",
    case: { id: "case-1", name: "Case Alpha", status: "active" },
    platforms: [],
    evidence_domains: [],
    workbenches,
    capabilities: [],
    hosts: [],
    evidence: [],
  };
}

function svgClass(row: HTMLElement) {
  return row.querySelector("svg")?.getAttribute("class") ?? "";
}

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

  it("renders fixed Investigation and Technical Tools groups untouched", async () => {
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

  it("renders exactly one row per surface, in the order the backend returns", async () => {
    getCaseCapabilitiesMock.mockResolvedValue(registry([
      workbench({ id: "memory", label: "Memory", kind: "evidence_domain", icon: "cpu", overview_route: "/cases/case-1/m" }),
      workbench({ id: "windows", label: "Windows", icon: "hard-drive", overview_route: "/cases/case-1/w" }),
      workbench({ id: "linux", label: "Linux", icon: "shield-check", overview_route: "/cases/case-1/l" }),
    ]));

    renderSidebar();

    const surfaces = await screen.findByRole("region", { name: "Investigation Surfaces" });
    const rows = within(surfaces).getAllByTestId(/^surface-/);
    expect(rows.map((row) => row.getAttribute("data-testid"))).toEqual(["surface-memory", "surface-windows", "surface-linux"]);
  });

  it("resolves label, icon and href for a surface entirely from the registry payload", async () => {
    getCaseCapabilitiesMock.mockResolvedValue(registry([
      workbench({ id: "windows", label: "Windows", icon: "hard-drive", overview_route: "/cases/case-1/w" }),
    ]));

    renderSidebar();

    const row = await screen.findByTestId("surface-windows");
    expect(row).toHaveTextContent("Windows");
    expect(row).toHaveAttribute("href", "/cases/case-1/w");
    expect(svgClass(row)).toContain("lucide-hard-drive");
  });

  it("delegates icon resolution to the shared surfaceIcons module (not a local copy)", async () => {
    vi.mocked(resolveSurfaceIcon).mockClear();
    getCaseCapabilitiesMock.mockResolvedValue(registry([workbench({ id: "windows", icon: "hard-drive" })]));

    renderSidebar();
    await screen.findByTestId("surface-windows");

    expect(resolveSurfaceIcon).toHaveBeenCalledWith("hard-drive");
  });

  it("marks the surface row active when the URL is exactly its Surface Home", async () => {
    getCaseCapabilitiesMock.mockResolvedValue(registry([workbench({ overview_route: "/cases/case-1/l" })]));

    renderSidebar("/cases/case-1/l");

    expect(await screen.findByTestId("surface-linux")).toHaveAttribute("aria-current", "page");
  });

  it("marks the surface row active when the URL is a deep route under that surface", async () => {
    getCaseCapabilitiesMock.mockResolvedValue(registry([workbench({ overview_route: "/cases/case-1/l" })]));

    renderSidebar("/cases/case-1/l/access/authentication");

    expect(await screen.findByTestId("surface-linux")).toHaveAttribute("aria-current", "page");
  });

  it("does not mark the surface row active for an unrelated route", async () => {
    getCaseCapabilitiesMock.mockResolvedValue(registry([workbench({ overview_route: "/cases/case-1/l" })]));

    renderSidebar("/cases/case-1/w");

    expect(await screen.findByTestId("surface-linux")).not.toHaveAttribute("aria-current", "page");
  });

  it("falls back to a safe generic icon for an unrecognized icon identifier, without deriving anything from the surface id", async () => {
    getCaseCapabilitiesMock.mockResolvedValue(registry([
      workbench({ id: "windows", label: "Windows", icon: "some-icon-not-in-the-map" }),
    ]));

    renderSidebar();

    const row = await screen.findByTestId("surface-windows");
    expect(svgClass(row)).toContain("lucide-layers");
    expect(svgClass(row)).not.toContain("lucide-hard-drive");
  });

  it("falls back to the safe generic icon when icon is null", async () => {
    getCaseCapabilitiesMock.mockResolvedValue(registry([workbench({ icon: null })]));

    renderSidebar();

    const row = await screen.findByTestId("surface-linux");
    expect(svgClass(row)).toContain("lucide-layers");
  });

  it("renders an unknown future surface generically, with no Sidebar changes required", async () => {
    getCaseCapabilitiesMock.mockResolvedValue(registry([
      workbench({ id: "cloud", label: "Cloud", kind: "platform", icon: "cloud", overview_route: "/cases/case-1/cl", capability_ids: ["cloud.sync.activity"] }),
    ]));

    renderSidebar();

    const row = await screen.findByTestId("surface-cloud");
    expect(row).toHaveTextContent("Cloud");
    expect(row).toHaveAttribute("href", "/cases/case-1/cl");
    // "cloud" is not in the frontend's icon map yet -- must degrade safely,
    // never invent a workbench-id-specific icon for it.
    expect(svgClass(row)).toContain("lucide-layers");
  });

  it("renders no tree roles or tree controls -- the expandable Workbench/Domain/Capability tree is gone", async () => {
    getCaseCapabilitiesMock.mockResolvedValue(registry([
      workbench({ id: "linux", capability_ids: ["linux.access.authentication"], domains: [{ id: "access", capability_ids: ["linux.access.authentication"], record_count: 1 }] }),
    ]));

    renderSidebar();
    await screen.findByTestId("surface-linux");

    expect(screen.queryByRole("tree")).not.toBeInTheDocument();
    expect(screen.queryByRole("treeitem")).not.toBeInTheDocument();
    expect(screen.queryByLabelText("Filter capabilities")).not.toBeInTheDocument();
    expect(screen.queryByText("Authentication")).not.toBeInTheDocument();
    expect(screen.queryByText("Access")).not.toBeInTheDocument();
  });

  it("shows loading state while the registry request is pending", () => {
    getCaseCapabilitiesMock.mockReturnValue(new Promise(() => {}));
    renderSidebar();
    expect(screen.getByRole("status")).toHaveTextContent("Loading workbenches");
  });

  it("shows API failure without inventing surfaces", async () => {
    getCaseCapabilitiesMock.mockRejectedValue(new Error("boom"));
    renderSidebar();
    expect(await screen.findByRole("alert")).toHaveTextContent("Capability registry unavailable");
    expect(screen.queryByTestId(/^surface-/)).not.toBeInTheDocument();
  });

  it("renders an empty registry with only the fixed sections", async () => {
    getCaseCapabilitiesMock.mockResolvedValue(registry());
    renderSidebar();
    await screen.findByText("Technical Tools");
    expect(screen.queryByTestId(/^surface-/)).not.toBeInTheDocument();
  });

  it("does not call the registry endpoint when no case is active", () => {
    activeCaseState.activeCaseId = "";
    activeCaseState.activeCase = null;
    renderSidebar();
    expect(getCaseCapabilitiesMock).not.toHaveBeenCalled();
    expect(screen.queryByTestId(/^surface-/)).not.toBeInTheDocument();
  });
});
