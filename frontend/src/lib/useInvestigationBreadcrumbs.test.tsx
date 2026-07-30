import { render, screen } from "@testing-library/react";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { MemoryRouter } from "react-router-dom";
import { beforeEach, describe, expect, it, vi } from "vitest";
import { useInvestigationBreadcrumbs, type UseInvestigationBreadcrumbsOptions } from "./useInvestigationBreadcrumbs";
import { ActiveCaseProvider } from "../context/ActiveCaseContext";
import { api, type CaseCapabilitiesResponse, type CaseCapability } from "../api/client";

vi.mock("../api/client", async () => {
  const actual = await vi.importActual<typeof import("../api/client")>("../api/client");
  return {
    ...actual,
    api: {
      ...actual.api,
      listCases: vi.fn(),
      getCaseContext: vi.fn().mockResolvedValue(null),
      getCaseCapabilities: vi.fn(),
    },
  };
});

beforeEach(() => {
  localStorage.clear();
  vi.mocked(api.listCases).mockResolvedValue([{ id: "case-1", name: "Case Alpha" } as never]);
});

function capability(patch: Partial<CaseCapability>): CaseCapability {
  return {
    id: "linux.access.authentication",
    platform: "linux",
    evidence_domain: "filesystem",
    domain: "access",
    title: "Authentication",
    route: "/cases/:caseId/l/access/authentication",
    artifact_families: [],
    nav: { parent: "linux/access", order: 10 },
    search: { filters: [], presets: [] },
    availability: "shipped",
    readiness_source: "artifact_counts",
    artifact_count: 0,
    record_count: 0,
    status_counts: {},
    readiness: "has_data",
    visible: true,
    ...patch,
  };
}

function registry(): CaseCapabilitiesResponse {
  const caps = [
    capability({}),
    capability({ id: "windows.persistence.overview", platform: "windows", domain: "persistence", title: "Persistence", route: "/cases/:caseId/findings?preset=persistence" }),
    capability({ id: "linux.software.packages", domain: "software", title: "Packages", route: "/cases/:caseId/artifacts?artifact_type=linux_packages" }),
    capability({ id: "memory.processes", platform: "memory", evidence_domain: "memory", domain: "execution", title: "Processes", route: "/cases/:caseId/m/:evidenceId/processes" }),
  ];
  return {
    registry_version: "test",
    generated_at: "2026-07-30T00:00:00Z",
    case: { id: "case-1", name: "Case Alpha", status: "active" },
    platforms: [],
    evidence_domains: [],
    workbenches: [
      { id: "linux", label: "Linux", kind: "platform", icon: "shield-check", overview_route: "/cases/case-1/l", capability_ids: ["linux.access.authentication", "linux.software.packages"], domains: [] },
      { id: "windows", label: "Windows", kind: "platform", icon: "hard-drive", overview_route: "/cases/case-1/w", capability_ids: ["windows.persistence.overview"], domains: [] },
      { id: "memory", label: "Memory", kind: "evidence_domain", icon: "cpu", overview_route: "/cases/case-1/m", capability_ids: ["memory.processes"], domains: [] },
    ],
    capabilities: caps,
    hosts: [],
    evidence: [{ id: "ev-1", name: "evidence.raw", evidence_type: "memory_dump", evidence_domain: "memory", platform: "windows" } as never],
  };
}

function BreadcrumbsProbe({ options }: { options?: UseInvestigationBreadcrumbsOptions }) {
  const items = useInvestigationBreadcrumbs(options);
  return (
    <ol data-testid="breadcrumbs">
      {items.map((item, index) => (
        <li key={index} data-testid="crumb" data-linked={item.to ? "true" : "false"}>
          {item.to ? <a href={item.to}>{item.label}</a> : <span>{item.label}</span>}
        </li>
      ))}
    </ol>
  );
}

function renderProbe(options?: UseInvestigationBreadcrumbsOptions, initialEntry = "/cases/case-1/l") {
  const queryClient = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  localStorage.setItem("dfir.activeCaseId", "case-1");
  return render(
    <QueryClientProvider client={queryClient}>
      <ActiveCaseProvider>
        <MemoryRouter initialEntries={[initialEntry]}>
          <BreadcrumbsProbe options={options} />
        </MemoryRouter>
      </ActiveCaseProvider>
    </QueryClientProvider>,
  );
}

function crumbLabels() {
  return screen.getAllByTestId("crumb").map((node) => node.textContent);
}

describe("useInvestigationBreadcrumbs", () => {
  it("resolves Surface Home to Case / Surface", async () => {
    vi.mocked(api.getCaseCapabilities).mockResolvedValue(registry());
    renderProbe(undefined, "/cases/case-1/l");

    expect(await screen.findByText("Linux")).toBeInTheDocument();
    expect(crumbLabels()).toEqual(["Case Alpha", "Linux"]);
  });

  it("resolves a known capability to Case / Surface / Domain / Capability", async () => {
    vi.mocked(api.getCaseCapabilities).mockResolvedValue(registry());
    renderProbe(undefined, "/cases/case-1/l/access/authentication");

    await screen.findByText("Authentication");
    expect(crumbLabels()).toEqual(["Case Alpha", "Linux", "Access", "Authentication"]);
  });

  it("resolves a Memory capability with evidence to Case / Surface / Domain / Capability / evidence name", async () => {
    vi.mocked(api.getCaseCapabilities).mockResolvedValue(registry());
    renderProbe(undefined, "/cases/case-1/m/ev-1/processes");

    await screen.findByText("Processes");
    expect(crumbLabels()).toEqual(["Case Alpha", "Memory", "Execution", "Processes", "evidence.raw"]);
  });

  it("truncates at Capability when the evidence id has no matching name in the payload", async () => {
    vi.mocked(api.getCaseCapabilities).mockResolvedValue(registry());
    renderProbe(undefined, "/cases/case-1/m/unknown-evidence/processes");

    await screen.findByText("Processes");
    expect(crumbLabels()).toEqual(["Case Alpha", "Memory", "Execution", "Processes"]);
  });

  it("does not confuse Findings (Tier 1, lensLabel) with the Persistence capability that reuses its pathname", async () => {
    vi.mocked(api.getCaseCapabilities).mockResolvedValue(registry());

    renderProbe({ lensLabel: "Findings" }, "/cases/case-1/findings");
    await screen.findByText("Findings");
    expect(crumbLabels()).toEqual(["Case Alpha", "Findings"]);
  });

  it("resolves the Persistence capability trail when the same lensLabel page is reached via its query-qualified route", async () => {
    vi.mocked(api.getCaseCapabilities).mockResolvedValue(registry());

    renderProbe({ lensLabel: "Findings" }, "/cases/case-1/findings?preset=persistence");
    await screen.findByText("Windows");
    // Domain ("persistence") and Capability title ("Persistence") share the
    // same real registry label -- matches by count, not by ambiguous text.
    expect(crumbLabels()).toEqual(["Case Alpha", "Windows", "Persistence", "Persistence"]);
  });

  it("does not confuse Artifact Views (Tier 1, lensLabel) with a capability based on artifact_type", async () => {
    vi.mocked(api.getCaseCapabilities).mockResolvedValue(registry());

    const plain = renderProbe({ lensLabel: "Artifact Views" }, "/cases/case-1/artifacts");
    await screen.findByText("Artifact Views");
    expect(crumbLabels()).toEqual(["Case Alpha", "Artifact Views"]);
    plain.unmount();

    renderProbe({ lensLabel: "Artifact Views" }, "/cases/case-1/artifacts?artifact_type=linux_packages");
    await screen.findByText("Packages");
    expect(crumbLabels()).toEqual(["Case Alpha", "Linux", "Software", "Packages"]);
  });

  it("shows only the case while the capabilities payload is still loading", async () => {
    vi.mocked(api.getCaseCapabilities).mockReturnValue(new Promise(() => {}));
    renderProbe(undefined, "/cases/case-1/l");

    await screen.findByText("Case Alpha");
    expect(crumbLabels()).toEqual(["Case Alpha"]);
  });

  it("truncates to the case when the route is unknown and no lensLabel is given", async () => {
    vi.mocked(api.getCaseCapabilities).mockResolvedValue(registry());
    renderProbe(undefined, "/cases/case-1/does-not-exist");

    await screen.findByText("Case Alpha");
    expect(crumbLabels()).toEqual(["Case Alpha"]);
  });

  it("uses an explicit currentLabel for pages that don't belong to the registry (e.g. CaseDetail)", async () => {
    vi.mocked(api.getCaseCapabilities).mockResolvedValue(registry());
    renderProbe({ currentLabel: "Evidence" }, "/cases/case-1/evidence");

    await screen.findByText("Case Alpha");
    await screen.findByText("Evidence");
    expect(crumbLabels()).toEqual(["Case Alpha", "Evidence"]);
  });

  it("shows the real case name once the case is known", async () => {
    vi.mocked(api.getCaseCapabilities).mockResolvedValue(registry());
    renderProbe(undefined, "/cases/case-1/l");

    expect(await screen.findByText("Case Alpha")).toBeInTheDocument();
  });

  it("links only the Case and Surface levels; Domain, Capability and Context are informative", async () => {
    vi.mocked(api.getCaseCapabilities).mockResolvedValue(registry());
    renderProbe(undefined, "/cases/case-1/m/ev-1/processes");

    await screen.findByText("Processes");
    const crumbs = screen.getAllByTestId("crumb");
    expect(crumbs.map((node) => node.getAttribute("data-linked"))).toEqual(["true", "true", "false", "false", "false"]);
  });
});
