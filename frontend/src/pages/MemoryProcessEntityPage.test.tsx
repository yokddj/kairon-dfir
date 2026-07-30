import { render, screen, within } from "@testing-library/react";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { MemoryRouter, Route, Routes } from "react-router-dom";
import { beforeEach, describe, expect, it, vi } from "vitest";
import MemoryProcessEntityPage from "./MemoryProcessEntityPage";
import { ActiveCaseProvider } from "../context/ActiveCaseContext";
import {
  ApiError,
  api,
  type CaseCapabilitiesResponse,
  type CaseCapability,
  type MemoryProcessEntity,
  type MemoryProcessEntityDetail,
} from "../api/client";

vi.mock("../api/client", async () => {
  const actual = await vi.importActual<typeof import("../api/client")>("../api/client");
  return {
    ...actual,
    api: {
      ...actual.api,
      listCases: vi.fn(),
      getCaseContext: vi.fn().mockResolvedValue(null),
      getCaseCapabilities: vi.fn(),
      getCanonicalProcessEntityDetail: vi.fn(),
    },
  };
});

function capability(patch: Partial<CaseCapability> = {}): CaseCapability {
  return {
    id: "memory.processes",
    platform: "memory",
    evidence_domain: "memory",
    domain: "execution",
    title: "Processes",
    route: "/cases/:caseId/m/:evidenceId/processes",
    artifact_families: [],
    nav: { parent: "memory/execution", order: 10 },
    search: { filters: [], presets: [] },
    availability: "shipped",
    readiness_source: "memory_artifact_counts",
    artifact_count: 0,
    record_count: 0,
    status_counts: {},
    readiness: "has_data",
    visible: true,
    ...patch,
  };
}

function registry(): CaseCapabilitiesResponse {
  return {
    registry_version: "test",
    generated_at: "2026-07-30T00:00:00Z",
    case: { id: "case-1", name: "Case Alpha", status: "active" },
    platforms: [],
    evidence_domains: [],
    workbenches: [
      {
        id: "memory",
        label: "Memory",
        kind: "evidence_domain",
        icon: "cpu",
        overview_route: "/cases/case-1/m",
        capability_ids: ["memory.processes"],
        domains: [],
      },
    ],
    capabilities: [capability()],
    hosts: [],
    evidence: [],
  } as never;
}

function entityFixture(overrides: Partial<MemoryProcessEntity> = {}): MemoryProcessEntity {
  return {
    document_type: "memory_process_entity",
    case_id: "case-1",
    evidence_id: "ev-memory",
    scan_run_id: "run-basic",
    host_id: null,
    process_entity_id: "entity-abc",
    process: {
      pid: 1840,
      ppid: 900,
      name: "powershell.exe",
      executable_name: "powershell.exe",
      command_line: "powershell.exe -enc AAA",
      create_time: "2026-01-01T00:00:00Z",
      exit_time: null,
      session_id: 1,
      wow64: null,
    },
    visibility: { listed: true },
    sources: ["windows.pslist", "windows.cmdline"],
    source_plugins: ["windows.pslist", "windows.cmdline"],
    observation_count: 2,
    observation_summary: { has_pslist: true, has_cmdline: true },
    confidence: "high",
    first_seen_run_id: "run-basic",
    latest_run_id: "run-basic",
    findings: [],
    findings_summary: [],
    normalization_version: "memory_process_canonical_v1",
    materialized_from_run_id: "run-basic",
    parent_entity_id: "entity-parent",
    child_count: 1,
    tree: { is_root: false },
    indexed_at: null,
    ...overrides,
  };
}

function detailFixture(overrides: Partial<MemoryProcessEntityDetail> = {}): MemoryProcessEntityDetail {
  return {
    entity: entityFixture(),
    observations: [
      {
        document_type: "memory_process_observation",
        case_id: "case-1",
        evidence_id: "ev-memory",
        scan_run_id: "run-basic",
        process_entity_id: "entity-abc",
        plugin_run_id: "run-basic",
        plugin_name: "windows.pslist",
        source_record_id: "doc-1",
        observed: { pid: 1840, name: "powershell.exe", command_line: "powershell.exe -enc AAA", create_time: "2026-01-01T00:00:00Z" },
        raw_status: "ok",
        source_fields: {},
        confidence: "high",
        indexed_at: null,
      },
    ],
    parent: entityFixture({ process_entity_id: "entity-parent", process: { pid: 900, name: "explorer.exe" } }),
    children: [entityFixture({ process_entity_id: "entity-child", process: { pid: 2000, name: "conhost.exe" } })],
    tree_path: [],
    alternate_command_lines: [],
    findings: [],
    source_record_refs: ["doc-1"],
    ...overrides,
  };
}

vi.mock("../components/memory/ProcessDetailModal", async () => {
  const actual = await vi.importActual<typeof import("../components/memory/ProcessDetailModal")>(
    "../components/memory/ProcessDetailModal",
  );
  return {
    ...actual,
    NetworkSection: () => <div data-testid="stub-network-section" />,
    HandlesSection: () => <div data-testid="stub-handles-section" />,
    ModulesSection: () => <div data-testid="stub-modules-section" />,
  };
});

beforeEach(() => {
  vi.clearAllMocks();
  localStorage.clear();
  localStorage.setItem("dfir.activeCaseId", "case-1");
  vi.mocked(api.listCases).mockResolvedValue([{ id: "case-1", name: "Case Alpha" } as never]);
  vi.mocked(api.getCaseCapabilities).mockResolvedValue(registry());
});

function renderPage(initialEntry = "/cases/case-1/entities/memory-process/entity-abc") {
  const queryClient = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  return render(
    <QueryClientProvider client={queryClient}>
      <ActiveCaseProvider>
        <MemoryRouter initialEntries={[initialEntry]}>
          <Routes>
            <Route path="/cases/:caseId/entities/memory-process/:entityId" element={<MemoryProcessEntityPage />} />
          </Routes>
        </MemoryRouter>
      </ActiveCaseProvider>
    </QueryClientProvider>,
  );
}

describe("MemoryProcessEntityPage", () => {
  it("reads caseId and entityId from the route and calls the real detail endpoint", async () => {
    vi.mocked(api.getCanonicalProcessEntityDetail).mockResolvedValue(detailFixture());
    renderPage();
    await screen.findByTestId("entity-page-title");
    expect(api.getCanonicalProcessEntityDetail).toHaveBeenCalledWith("case-1", "entity-abc");
  });

  it("shows a loading state before the query resolves", async () => {
    vi.mocked(api.getCanonicalProcessEntityDetail).mockReturnValue(new Promise(() => {}));
    renderPage();
    expect(await screen.findByTestId("memory-process-entity-loading")).toBeInTheDocument();
  });

  it("shows a not-found state on a 404 response", async () => {
    vi.mocked(api.getCanonicalProcessEntityDetail).mockRejectedValue(new ApiError(404, null, "not found", null));
    renderPage();
    expect(await screen.findByTestId("memory-process-entity-not-found")).toBeInTheDocument();
  });

  it("shows a generic error state on a non-404 failure", async () => {
    vi.mocked(api.getCanonicalProcessEntityDetail).mockRejectedValue(new Error("network down"));
    renderPage();
    expect(await screen.findByTestId("memory-process-entity-error")).toHaveTextContent("network down");
  });

  it("renders identity and metadata from the real payload", async () => {
    vi.mocked(api.getCanonicalProcessEntityDetail).mockResolvedValue(detailFixture());
    renderPage();
    const title = await screen.findByTestId("entity-page-title");
    expect(title).toHaveTextContent("powershell.exe");
    expect(title).toHaveTextContent("PID 1840");
    expect(screen.getByTestId("entity-visibility")).toHaveTextContent("Listed");
  });

  it("shows strong identity when confidence is high without the provisional finding", async () => {
    vi.mocked(api.getCanonicalProcessEntityDetail).mockResolvedValue(detailFixture());
    renderPage();
    await screen.findByTestId("entity-page-title");
    expect(screen.getByTestId("entity-identity-strength")).toHaveTextContent(/Strong/);
  });

  it("shows degraded identity when the backend flags identity_provisional", async () => {
    vi.mocked(api.getCanonicalProcessEntityDetail).mockResolvedValue(
      detailFixture({ entity: entityFixture({ findings: ["identity_provisional"] }) }),
    );
    renderPage();
    await screen.findByTestId("entity-page-title");
    expect(screen.getByTestId("entity-identity-strength")).toHaveTextContent(/Provisional/);
  });

  it("links the parent via the route builder", async () => {
    vi.mocked(api.getCanonicalProcessEntityDetail).mockResolvedValue(detailFixture());
    renderPage();
    const parentSection = await screen.findByTestId("entity-section-parent-children");
    const link = within(parentSection).getAllByTestId("entity-related-link")[0];
    expect(link).toHaveAttribute("href", "/cases/case-1/entities/memory-process/entity-parent");
    expect(link).toHaveTextContent("explorer.exe (PID 900)");
  });

  it("links each child via the route builder", async () => {
    vi.mocked(api.getCanonicalProcessEntityDetail).mockResolvedValue(detailFixture());
    renderPage();
    const parentSection = await screen.findByTestId("entity-section-parent-children");
    const links = within(parentSection).getAllByTestId("entity-related-link");
    const childLink = links.find((node) => node.getAttribute("href") === "/cases/case-1/entities/memory-process/entity-child");
    expect(childLink).toBeDefined();
    expect(childLink).toHaveTextContent("conhost.exe (PID 2000)");
  });

  it("shows an explicit empty state when there is no parent", async () => {
    vi.mocked(api.getCanonicalProcessEntityDetail).mockResolvedValue(detailFixture({ parent: null, children: [] }));
    renderPage();
    const parentSection = await screen.findByTestId("entity-section-parent-children");
    expect(within(parentSection).getByText("None (root)")).toBeInTheDocument();
    expect(within(parentSection).getByText("No children recorded.")).toBeInTheDocument();
  });

  it("renders the tree path section", async () => {
    vi.mocked(api.getCanonicalProcessEntityDetail).mockResolvedValue(detailFixture({ tree_path: ["explorer.exe (900)"] }));
    renderPage();
    const section = await screen.findByTestId("entity-section-tree-path");
    expect(within(section).getByTestId("modal-tree-path")).toBeInTheDocument();
  });

  it("renders observations from the real payload", async () => {
    vi.mocked(api.getCanonicalProcessEntityDetail).mockResolvedValue(detailFixture());
    renderPage();
    const table = await screen.findByTestId("entity-observations-table");
    expect(within(table).getByText("pslist")).toBeInTheDocument();
  });

  it("shows an explicit empty state when there are no findings", async () => {
    vi.mocked(api.getCanonicalProcessEntityDetail).mockResolvedValue(detailFixture({ findings: [] }));
    renderPage();
    const section = await screen.findByTestId("entity-section-findings");
    expect(within(section).getByText("No findings recorded for this entity.")).toBeInTheDocument();
  });

  it("renders real findings when present", async () => {
    vi.mocked(api.getCanonicalProcessEntityDetail).mockResolvedValue(detailFixture({ findings: ["command_line_missing"] }));
    renderPage();
    const list = await screen.findByTestId("entity-findings-list");
    expect(within(list).getByText("command_line_missing")).toBeInTheDocument();
  });

  it("shows an explicit empty state when there are no source records", async () => {
    vi.mocked(api.getCanonicalProcessEntityDetail).mockResolvedValue(detailFixture({ source_record_refs: [] }));
    renderPage();
    const section = await screen.findByTestId("entity-section-source-records");
    expect(within(section).getByText("No raw references recorded for this entity.")).toBeInTheDocument();
  });

  it("omits no core sections when the payload is fully populated (network, handles, modules render)", async () => {
    vi.mocked(api.getCanonicalProcessEntityDetail).mockResolvedValue(detailFixture());
    renderPage();
    await screen.findByTestId("entity-page-title");
    expect(screen.getByTestId("stub-network-section")).toBeInTheDocument();
    expect(screen.getByTestId("stub-handles-section")).toBeInTheDocument();
    expect(screen.getByTestId("stub-modules-section")).toBeInTheDocument();
  });

  it("renders the breadcrumb trail Case / Memory / Execution / Processes / entity label", async () => {
    vi.mocked(api.getCanonicalProcessEntityDetail).mockResolvedValue(detailFixture());
    renderPage();
    await screen.findByTestId("entity-page-title");
    const nav = await screen.findByRole("navigation", { name: "Investigation breadcrumbs" });
    expect(nav).toHaveTextContent("Memory");
    expect(nav).toHaveTextContent("Execution");
    expect(nav).toHaveTextContent("Processes");
    expect(nav).toHaveTextContent("powershell.exe (PID 1840)");
  });

  it("never shows the raw synthetic entity id anywhere in the breadcrumb", async () => {
    vi.mocked(api.getCanonicalProcessEntityDetail).mockResolvedValue(detailFixture());
    renderPage();
    await screen.findByRole("navigation", { name: "Investigation breadcrumbs" });
    const nav = screen.getByRole("navigation", { name: "Investigation breadcrumbs" });
    expect(nav.textContent).not.toContain("entity-abc");
  });

  it("works after a direct reload with no prior modal state (route params are the only input)", async () => {
    vi.mocked(api.getCanonicalProcessEntityDetail).mockResolvedValue(detailFixture());
    renderPage("/cases/case-1/entities/memory-process/entity-abc");
    expect(await screen.findByTestId("entity-page-title")).toHaveTextContent("powershell.exe");
  });
});
