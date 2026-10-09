import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { render, screen, within } from "@testing-library/react";
import { MemoryRouter } from "react-router-dom";
import { beforeEach, describe, expect, it, vi } from "vitest";

import Sidebar from "./Sidebar";
import type { CaseCapabilitiesResponse } from "../api/client";

const getCaseCapabilitiesMock = vi.fn();
const logoutMock = vi.fn();

const activeCaseState: any = {
  activeCaseId: "case-1",
  activeCase: { id: "case-1", name: "Case Alpha" },
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

  it("renders the fixed Investigation group untouched, including Artifact Views", async () => {
    getCaseCapabilitiesMock.mockResolvedValue(registry());
    renderSidebar();

    const investigation = screen.getByText("Investigation").closest("section")!;
    for (const label of ["Overview", "Evidence", "Host Information", "Search", "Artifact Views", "Timeline", "Incident Timeline", "Detections", "Findings", "Reports"]) {
      expect(within(investigation).getByRole("link", { name: label })).toBeInTheDocument();
    }
    expect(within(investigation).getByRole("link", { name: "Artifact Views" })).toHaveAttribute("href", "/cases/case-1/artifacts");
    expect(screen.queryByText("Technical Tools")).not.toBeInTheDocument();
  });

  it("lists every view in one flat list, with no Investigation Surfaces section", async () => {
    getCaseCapabilitiesMock.mockResolvedValue(registry([
      workbench({ id: "memory", label: "Memory", kind: "evidence_domain", icon: "cpu", overview_route: "/cases/case-1/m" }),
      workbench({ id: "windows", label: "Windows", icon: "hard-drive", overview_route: "/cases/case-1/w" }),
      workbench({ id: "linux", label: "Linux", icon: "shield-check", overview_route: "/cases/case-1/l" }),
    ]));
    renderSidebar();

    const investigation = screen.getByText("Investigation").closest("section")!;
    await within(investigation).findByRole("link", { name: "Memory" });
    const labels = within(investigation).getAllByRole("link").map((link) => link.textContent);
    expect(labels).toEqual([
      "Overview", "Evidence", "Host Information", "Search", "Artifact Views", "Command History", "Execution Stories",
      "Linux Authentication", "Source Tables", "Memory", "Timeline", "Incident Timeline", "Detections", "Findings", "Reports",
    ]);
    expect(screen.queryByText("Investigation Surfaces")).not.toBeInTheDocument();
    expect(screen.queryByTestId(/^surface-/)).not.toBeInTheDocument();
  });

  it("links straight to the evidence-specific views", async () => {
    getCaseCapabilitiesMock.mockResolvedValue(registry([
      workbench({ id: "memory" }),
      workbench({ id: "windows" }),
      workbench({ id: "linux" }),
    ]));
    renderSidebar();

    expect(await screen.findByRole("link", { name: "Memory" })).toHaveAttribute("href", "/cases/case-1/m");
    expect(screen.getByRole("link", { name: "Execution Stories" })).toHaveAttribute("href", "/cases/case-1/w/execution/stories");
    expect(screen.getByRole("link", { name: "Linux Authentication" })).toHaveAttribute("href", "/cases/case-1/l/access/authentication");
  });

  it("shows only the views the case has evidence for", async () => {
    getCaseCapabilitiesMock.mockResolvedValue(registry([workbench({ id: "memory" })]));
    renderSidebar();

    expect(await screen.findByRole("link", { name: "Memory" })).toBeInTheDocument();
    expect(screen.queryByRole("link", { name: "Execution Stories" })).not.toBeInTheDocument();
    expect(screen.queryByRole("link", { name: "Linux Authentication" })).not.toBeInTheDocument();
  });

  it("marks Memory active on any memory route", async () => {
    getCaseCapabilitiesMock.mockResolvedValue(registry([workbench({ id: "memory" })]));
    renderSidebar("/cases/case-1/m/ev-1/timeline");

    expect(await screen.findByRole("link", { name: "Memory" })).toHaveAttribute("aria-current", "page");
    expect(screen.getByRole("link", { name: "Timeline" })).not.toHaveAttribute("aria-current", "page");
  });

  it("hides evidence-specific views while the registry loads", () => {
    getCaseCapabilitiesMock.mockReturnValue(new Promise(() => {}));
    renderSidebar();
    expect(screen.getByRole("link", { name: "Timeline" })).toBeInTheDocument();
    expect(screen.queryByRole("link", { name: "Memory" })).not.toBeInTheDocument();
  });

  it("lists every evidence-specific view when the registry cannot be read, rather than hiding them", async () => {
    getCaseCapabilitiesMock.mockRejectedValue(new Error("boom"));
    renderSidebar();
    expect(await screen.findByRole("link", { name: "Memory" })).toBeInTheDocument();
    expect(screen.getByRole("link", { name: "Execution Stories" })).toBeInTheDocument();
    expect(screen.getByRole("link", { name: "Linux Authentication" })).toBeInTheDocument();
  });

  it("renders an empty registry with only the views every case has", async () => {
    getCaseCapabilitiesMock.mockResolvedValue(registry());
    renderSidebar();
    await screen.findByText("Investigation");
    expect(screen.getByRole("link", { name: "Artifact Views" })).toBeInTheDocument();
    expect(screen.queryByRole("link", { name: "Memory" })).not.toBeInTheDocument();
  });

  it("does not call the registry endpoint when no case is active", () => {
    activeCaseState.activeCaseId = "";
    activeCaseState.activeCase = null;
    renderSidebar();
    expect(getCaseCapabilitiesMock).not.toHaveBeenCalled();
    expect(screen.queryByRole("link", { name: "Memory" })).not.toBeInTheDocument();
  });
});
