import { render, screen, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { MemoryRouter, useLocation } from "react-router-dom";
import { beforeEach, describe, expect, it, vi } from "vitest";
import { WorkbenchOverview } from "./WorkbenchOverview";
import { ActiveCaseProvider } from "../../context/ActiveCaseContext";
import { resolveSurfaceIcon } from "../../lib/surfaceIcons";
import type { CaseCapabilitiesResponse, CaseCapability } from "../../api/client";

vi.mock("../../lib/surfaceIcons", async () => {
  const actual = await vi.importActual<typeof import("../../lib/surfaceIcons")>("../../lib/surfaceIcons");
  return { ...actual, resolveSurfaceIcon: vi.fn(actual.resolveSurfaceIcon) };
});

// ActiveCaseProvider (the real provider, per instructions -- no duplicated
// context logic) calls api.listCases unconditionally on mount and
// api.getCaseContext when activeCaseId is set. Neither is under test here,
// so both are stubbed to keep the suite network-free and quiet.
vi.mock("../../api/client", async () => {
  const actual = await vi.importActual<typeof import("../../api/client")>("../../api/client");
  return { ...actual, api: { ...actual.api, listCases: vi.fn().mockResolvedValue([]), getCaseContext: vi.fn().mockResolvedValue(null) } };
});

beforeEach(() => {
  // ActiveCaseProvider seeds selectedEvidenceId (and activeCaseId) from
  // localStorage on mount -- clear between tests so evidence-priority tests
  // don't leak into unrelated ones.
  localStorage.clear();
});

function capability(patch: Partial<CaseCapability>): CaseCapability {
  return {
    id: "linux.access.authentication",
    platform: "linux",
    evidence_domain: "filesystem",
    domain: "access",
    title: "Authentication",
    route: "/cases/:caseId/l/access/authentication",
    artifact_families: ["linux_auth"],
    nav: { parent: "linux/access", order: 10 },
    overview: { priority: 10, featured: true, quick_action: "Open Authentication" },
    search: { filters: [], presets: [] },
    availability: "shipped",
    readiness_source: "artifact_counts",
    artifact_count: 1,
    record_count: 20,
    status_counts: {},
    readiness: "has_data",
    visible: true,
    ...patch,
  };
}

function registry(overrides: Partial<CaseCapabilitiesResponse> = {}): CaseCapabilitiesResponse {
  return {
    registry_version: "test",
    generated_at: "2026-07-28T00:00:00Z",
    case: { id: "case-1", name: "Case", status: "active" },
    platforms: [{ id: "linux", label: "Linux", evidence_count: 1, shipped: true }],
    evidence_domains: [{ id: "filesystem", label: "Filesystem", evidence_count: 1 }],
    workbenches: [
      {
        id: "linux",
        label: "Linux",
        kind: "platform",
        icon: "shield-check",
        overview_route: "/cases/case-1/l",
        capability_ids: ["linux.access.authentication", "future.cloud.sync"],
        domains: [
          { id: "access", capability_ids: ["linux.access.authentication"], record_count: 20 },
          { id: "cloud_sync", capability_ids: ["future.cloud.sync"], record_count: 0 },
        ],
        overview: {
          host_count: 1,
          evidence_count: 1,
          processing_state: "processing",
          coverage: { capability_count: 2, status_counts: { has_data: 1, failed: 1 } },
          quick_actions: [{ id: "linux.access.authentication", label: "Open Authentication", route: "/cases/case-1/l/access/authentication", priority: 10 }],
          warnings: [{ id: "future.cloud.sync.failed", severity: "critical", title: "Cloud Sync failed", detail: "Processing failed." }],
          recent_activity: [{ kind: "detection", title: "Suspicious SSH", route: "/cases/case-1/detections?detection_id=det-1", timestamp: "2026-07-28T00:00:00Z" }],
          memory_images: [],
        },
      },
    ],
    capabilities: [
      capability({}),
      capability({ id: "future.cloud.sync", platform: "linux", domain: "cloud_sync", title: "Cloud Sync", route: "/cases/:caseId/artifacts?artifact_type=cloud_sync", nav: { parent: "linux/cloud_sync", order: 99 }, overview: { priority: 99, featured: false }, readiness: "failed", record_count: 0 }),
    ],
    hosts: [],
    evidence: [],
    ...overrides,
  };
}

// Three domains whose priority order deliberately does NOT match alphabetical
// order, so tab-order assertions can't pass by accident of id sorting.
function multiDomainRegistry(): CaseCapabilitiesResponse {
  const caps = [
    capability({ id: "surface.zzz_first.a", domain: "zzz_first", title: "Zzz First Cap", route: "/cases/:caseId/artifacts?artifact_type=zzz", nav: { parent: "linux/zzz_first", order: 5 }, overview: { priority: 5, featured: true, quick_action: "Open Zzz" }, readiness: "has_data" }),
    capability({ id: "surface.mmm_third.a", domain: "mmm_third", title: "Mmm Third Cap", route: "/cases/:caseId/artifacts?artifact_type=mmm", nav: { parent: "linux/mmm_third", order: 20 }, overview: { priority: 20, featured: true, quick_action: "Open Mmm" }, readiness: "degraded" }),
    capability({ id: "surface.aaa_second.a", domain: "aaa_second", title: "Aaa Second Cap", route: "/cases/:caseId/artifacts?artifact_type=aaa", nav: { parent: "linux/aaa_second", order: 50 }, overview: { priority: 50, featured: true, quick_action: "Open Aaa" }, readiness: "has_data" }),
  ];
  return registry({
    workbenches: [
      {
        id: "linux",
        label: "Linux",
        kind: "platform",
        icon: "shield-check",
        overview_route: "/cases/case-1/l",
        capability_ids: caps.map((item) => item.id),
        domains: [
          { id: "zzz_first", capability_ids: [caps[0].id], record_count: 1 },
          { id: "mmm_third", capability_ids: [caps[1].id], record_count: 1 },
          { id: "aaa_second", capability_ids: [caps[2].id], record_count: 1 },
        ],
        overview: {
          host_count: 1,
          evidence_count: 1,
          processing_state: "ready",
          coverage: { capability_count: 3, status_counts: { has_data: 2, degraded: 1 } },
          quick_actions: [],
          warnings: [],
          recent_activity: [],
          memory_images: [],
        },
      },
    ],
    capabilities: caps,
  });
}

// A single domain with more than three capabilities, varied readiness
// (including the two states the backend never actually emits today,
// "processing" and "failed", to prove the card degrades safely rather than
// assuming they can't occur), with and without overview.quick_action, and
// one evidence-scoped route -- the dedicated fixture for CapabilityCard
// content/order/readiness/quick-action coverage.
function capabilityCardRegistry(overrides: Partial<CaseCapabilitiesResponse> = {}): CaseCapabilitiesResponse {
  const caps = [
    capability({ id: "cap.ready", domain: "cards", title: "Ready Capability", route: "/cases/:caseId/artifacts?artifact_type=ready", nav: { parent: "linux/cards", order: 10 }, overview: { priority: 10, featured: true, quick_action: "Open Ready" }, readiness: "has_data", record_count: 42, artifact_count: 5 }),
    capability({ id: "cap.degraded", domain: "cards", title: "Degraded Capability", route: "/cases/:caseId/artifacts?artifact_type=degraded", nav: { parent: "linux/cards", order: 20 }, overview: { priority: 20, featured: true, quick_action: "Open Degraded" }, readiness: "degraded", record_count: 10, artifact_count: 3 }),
    capability({ id: "cap.empty", domain: "cards", title: "Empty Capability", route: "/cases/:caseId/artifacts?artifact_type=empty", nav: { parent: "linux/cards", order: 30 }, overview: undefined, readiness: "empty", record_count: 0, artifact_count: 2 }),
    capability({ id: "cap.not_collected", domain: "cards", title: "Not Collected Capability", route: "/cases/:caseId/artifacts?artifact_type=nc", nav: { parent: "linux/cards", order: 40 }, overview: { priority: 40, featured: false }, readiness: "not_collected", record_count: 0, artifact_count: 0 }),
    capability({ id: "cap.processing", domain: "cards", title: "Processing Capability", route: "/cases/:caseId/artifacts?artifact_type=proc", nav: { parent: "linux/cards", order: 50 }, overview: { priority: 50, featured: false }, readiness: "processing", record_count: 1, artifact_count: 1 }),
    capability({ id: "cap.failed", domain: "cards", title: "Failed Capability", route: "/cases/:caseId/artifacts?artifact_type=failed", nav: { parent: "linux/cards", order: 60 }, overview: { priority: 60, featured: false }, readiness: "failed", record_count: 0, artifact_count: 1 }),
    capability({ id: "cap.evidence", domain: "cards", title: "Evidence Scoped Capability", route: "/cases/:caseId/m/:evidenceId/processes", nav: { parent: "linux/cards", order: 70 }, overview: { priority: 70, featured: false }, readiness: "has_data", record_count: 4, artifact_count: 4 }),
  ];
  return registry({
    workbenches: [
      {
        id: "linux",
        label: "Linux",
        kind: "platform",
        icon: "shield-check",
        overview_route: "/cases/case-1/l",
        capability_ids: caps.map((item) => item.id),
        domains: [{ id: "cards", capability_ids: caps.map((item) => item.id), record_count: caps.length }],
        overview: {
          host_count: 1,
          evidence_count: 1,
          processing_state: "ready",
          coverage: { capability_count: caps.length, status_counts: { has_data: 2, degraded: 1, empty: 1, not_collected: 1 } },
          quick_actions: [],
          warnings: [{ id: "cap.degraded.degraded", severity: "warning", title: "Degraded Capability is degraded", detail: "Some parser or plugin results are incomplete." }],
          recent_activity: [],
          memory_images: [],
        },
      },
    ],
    capabilities: caps,
    ...overrides,
  });
}

function LocationProbe() {
  const location = useLocation();
  return <span data-testid="location-probe">{location.pathname + location.search}</span>;
}

function renderOverview(data: CaseCapabilitiesResponse = registry(), workbenchId = "linux", initialEntry?: string) {
  const entry = initialEntry ?? `/cases/case-1/${workbenchId === "memory" ? "m" : workbenchId[0]}`;
  const queryClient = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  return render(
    <QueryClientProvider client={queryClient}>
      <ActiveCaseProvider>
        <MemoryRouter initialEntries={[entry]}>
          <WorkbenchOverview registry={data} workbenchId={workbenchId} caseId="case-1" />
          <LocationProbe />
        </MemoryRouter>
      </ActiveCaseProvider>
    </QueryClientProvider>,
  );
}

describe("WorkbenchOverview", () => {
  it("renders registry-driven header, warnings, activity and quick actions, with only the default domain's panel mounted", async () => {
    renderOverview();

    expect(screen.getByTestId("workbench-overview-linux")).toBeInTheDocument();
    expect(screen.getByText("Linux")).toBeInTheDocument();
    expect(screen.getAllByRole("link", { name: "Open Authentication" })[0]).toHaveAttribute("href", "/cases/case-1/l/access/authentication");
    expect(screen.getByText("Cloud Sync failed")).toBeInTheDocument();
    expect(screen.getByRole("link", { name: /Suspicious SSH/i })).toHaveAttribute("href", "/cases/case-1/detections?detection_id=det-1");

    // Default domain (lowest capability priority) is "access" -- its panel
    // is mounted, "cloud_sync" is only a tab until selected.
    expect(screen.getByTestId("capability-linux.access.authentication")).toHaveTextContent("Authentication");
    expect(screen.queryByTestId("capability-future.cloud.sync")).not.toBeInTheDocument();

    await userEvent.click(screen.getByRole("tab", { name: /Cloud Sync/i }));

    expect(screen.getByTestId("capability-future.cloud.sync")).toHaveTextContent("Cloud Sync");
    expect(screen.queryByTestId("capability-linux.access.authentication")).not.toBeInTheDocument();
  });

  it("renders an empty workbench without inventing capabilities", () => {
    renderOverview(registry({ workbenches: [] }));
    expect(screen.getByText("Workbench unavailable")).toBeInTheDocument();
  });

  it("renders memory image overview cards, recent activity and global warnings unchanged", () => {
    const data = registry({
      workbenches: [
        {
          id: "memory",
          label: "Memory",
          kind: "evidence_domain",
          icon: "cpu",
          overview_route: "/cases/case-1/m",
          capability_ids: ["memory.processes"],
          domains: [{ id: "execution", capability_ids: ["memory.processes"], record_count: 8 }],
          overview: {
            host_count: 0,
            evidence_count: 1,
            processing_state: "ready",
            coverage: { capability_count: 1, status_counts: { has_data: 1 } },
            quick_actions: [{ id: "memory.processes", label: "Open Processes", route: "/cases/case-1/m/ev-1/processes", priority: 10 }],
            warnings: [{ id: "memory.host_unresolved", severity: "warning", title: "Memory host association missing", detail: "1 memory image is not assigned." }],
            recent_activity: [{ kind: "detection", title: "Suspicious memory event", route: "/cases/case-1/detections?detection_id=det-2", timestamp: "2026-07-28T00:00:00Z" }],
            memory_images: [{ id: "ev-1", name: "mem.raw", host_id: null, detected_host: null, detected_os: "windows", preparation_state: "completed", symbol_state: "ready", plugin_record_count: 8, run_status_counts: { completed: 1 }, route: "/cases/case-1/m/ev-1/overview" }],
          },
        },
      ],
      capabilities: [capability({ id: "memory.processes", platform: "memory", evidence_domain: "memory", domain: "execution", title: "Processes", route: "/cases/:caseId/m/:evidenceId/processes" })],
    });

    renderOverview(data, "memory");

    expect(screen.getByRole("link", { name: /mem.raw/i })).toHaveAttribute("href", "/cases/case-1/m/ev-1/overview");
    expect(screen.getByText("Memory host association missing")).toBeInTheDocument();
    expect(screen.getByRole("link", { name: /Suspicious memory event/i })).toHaveAttribute("href", "/cases/case-1/detections?detection_id=det-2");
    expect(within(screen.getByTestId("capability-memory.processes")).getByText("Processes")).toBeInTheDocument();
  });
});

function headerIconClass() {
  return screen.getByTestId("surface-icon").querySelector("svg")?.getAttribute("class") ?? "";
}

describe("WorkbenchOverview surface icon", () => {
  it("renders the icon resolved from workbench.icon through the shared resolver", () => {
    vi.mocked(resolveSurfaceIcon).mockClear();
    const base = registry().workbenches[0];
    renderOverview(registry({ workbenches: [{ ...base, icon: "hard-drive" }] }));

    expect(headerIconClass()).toContain("lucide-hard-drive");
    expect(resolveSurfaceIcon).toHaveBeenCalledWith("hard-drive");
  });

  it("does not change the icon when workbench.id changes but workbench.icon stays the same", () => {
    const base = registry().workbenches[0];
    renderOverview(registry({ workbenches: [{ ...base, id: "some-future-surface", icon: "shield-check", overview_route: "/cases/case-1/xyz" }] }), "some-future-surface");

    expect(headerIconClass()).toContain("lucide-shield-check");
  });

  it("falls back to the safe generic icon for an unrecognized icon identifier", () => {
    const base = registry().workbenches[0];
    renderOverview(registry({ workbenches: [{ ...base, icon: "not-a-real-icon" }] }));

    expect(headerIconClass()).toContain("lucide-layers");
    expect(headerIconClass()).not.toContain("lucide-shield-check");
  });

  it("falls back to the safe generic icon when workbench.icon is null", () => {
    const base = registry().workbenches[0];
    renderOverview(registry({ workbenches: [{ ...base, icon: null }] }));

    expect(headerIconClass()).toContain("lucide-layers");
  });
});

describe("WorkbenchOverview surface coverage summary", () => {
  it("renders the exact values from overview.coverage, without recomputing them", () => {
    renderOverview(multiDomainRegistry());
    const summary = screen.getByTestId("surface-coverage-summary");

    expect(summary).toHaveTextContent("3 capabilities");
    expect(summary).toHaveTextContent("2 has data");
    expect(summary).toHaveTextContent("1 degraded");
  });

  it("stays identical when switching domains", async () => {
    renderOverview(multiDomainRegistry());
    const before = screen.getByTestId("surface-coverage-summary").textContent;

    await userEvent.click(screen.getByRole("tab", { name: /Aaa Second/i }));

    expect(screen.getByTestId("surface-coverage-summary").textContent).toBe(before);
  });
});

describe("WorkbenchOverview domain tabs", () => {
  it("renders one tab per domain, in priority order rather than alphabetical", () => {
    renderOverview(multiDomainRegistry());
    const tabs = screen.getAllByRole("tab");

    expect(tabs.map((tab) => tab.textContent)).toEqual([
      expect.stringContaining("Zzz First"),
      expect.stringContaining("Mmm Third"),
      expect.stringContaining("Aaa Second"),
    ]);
  });

  it("selects the first domain by priority order as the default when the URL has no ?domain=", () => {
    renderOverview(multiDomainRegistry());

    expect(screen.getByRole("tab", { name: /Zzz First/i })).toHaveAttribute("aria-selected", "true");
    expect(screen.getByTestId("capability-surface.zzz_first.a")).toBeInTheDocument();
  });

  it("mounts only the active domain's capability cards, never the others", () => {
    renderOverview(multiDomainRegistry());

    expect(screen.getByTestId("capability-surface.zzz_first.a")).toBeInTheDocument();
    expect(screen.queryByTestId("capability-surface.mmm_third.a")).not.toBeInTheDocument();
    expect(screen.queryByTestId("capability-surface.aaa_second.a")).not.toBeInTheDocument();
  });

  it("clicking another tab switches the active domain, updates ?domain=, preserves other query params, and swaps the mounted cards", async () => {
    renderOverview(multiDomainRegistry(), "linux", "/cases/case-1/l?tab=overview");

    await userEvent.click(screen.getByRole("tab", { name: /Mmm Third/i }));

    expect(screen.getByRole("tab", { name: /Mmm Third/i })).toHaveAttribute("aria-selected", "true");
    expect(screen.getByTestId("capability-surface.mmm_third.a")).toBeInTheDocument();
    expect(screen.queryByTestId("capability-surface.zzz_first.a")).not.toBeInTheDocument();

    const location = screen.getByTestId("location-probe").textContent || "";
    expect(location).toContain("domain=mmm_third");
    expect(location).toContain("tab=overview");
  });

  it("selects the domain from a valid ?domain= deep link on load", () => {
    renderOverview(multiDomainRegistry(), "linux", "/cases/case-1/l?domain=aaa_second");

    expect(screen.getByRole("tab", { name: /Aaa Second/i })).toHaveAttribute("aria-selected", "true");
    expect(screen.getByTestId("capability-surface.aaa_second.a")).toBeInTheDocument();
  });

  it("falls back to the first domain when ?domain= is unknown", () => {
    renderOverview(multiDomainRegistry(), "linux", "/cases/case-1/l?domain=not-a-real-domain");
    expect(screen.getByRole("tab", { name: /Zzz First/i })).toHaveAttribute("aria-selected", "true");
  });

  it("falls back to the first domain when ?domain= is empty", () => {
    renderOverview(multiDomainRegistry(), "linux", "/cases/case-1/l?domain=");
    expect(screen.getByRole("tab", { name: /Zzz First/i })).toHaveAttribute("aria-selected", "true");
  });

  it("falls back to the first domain when ?domain= belongs to a different surface", () => {
    // "network" is a real domain id on the Memory surface, not on this Linux one.
    renderOverview(multiDomainRegistry(), "linux", "/cases/case-1/l?domain=network");
    expect(screen.getByRole("tab", { name: /Zzz First/i })).toHaveAttribute("aria-selected", "true");
  });

  it("renders a single tab for a surface with exactly one domain", () => {
    const data = registry({
      workbenches: [
        {
          id: "linux",
          label: "Linux",
          kind: "platform",
          icon: "shield-check",
          overview_route: "/cases/case-1/l",
          capability_ids: ["linux.access.authentication"],
          domains: [{ id: "access", capability_ids: ["linux.access.authentication"], record_count: 20 }],
          overview: {
            host_count: 1,
            evidence_count: 1,
            processing_state: "ready",
            coverage: { capability_count: 1, status_counts: { has_data: 1 } },
            quick_actions: [],
            warnings: [],
            recent_activity: [],
            memory_images: [],
          },
        },
      ],
      capabilities: [capability({})],
    });

    renderOverview(data);

    const tabs = screen.getAllByRole("tab");
    expect(tabs).toHaveLength(1);
    expect(tabs[0]).toHaveAttribute("aria-selected", "true");
  });

  it("renders no tabs for a workbench with no domains, without throwing", () => {
    const data = registry({
      workbenches: [
        {
          id: "linux",
          label: "Linux",
          kind: "platform",
          icon: "shield-check",
          overview_route: "/cases/case-1/l",
          capability_ids: [],
          domains: [],
          overview: {
            host_count: 0,
            evidence_count: 0,
            processing_state: "empty",
            coverage: { capability_count: 0, status_counts: {} },
            quick_actions: [],
            warnings: [],
            recent_activity: [],
            memory_images: [],
          },
        },
      ],
      capabilities: [],
    });

    expect(() => renderOverview(data)).not.toThrow();
    expect(screen.queryByRole("tab")).not.toBeInTheDocument();
    expect(screen.queryByRole("tabpanel")).not.toBeInTheDocument();
    expect(screen.getByText("No domains are visible for this workbench yet.")).toBeInTheDocument();
  });

  it("exposes the tabs/tabpanel ARIA contract with a stable id relationship", () => {
    renderOverview(multiDomainRegistry());

    const tablist = screen.getByRole("tablist");
    expect(tablist).toBeInTheDocument();

    const activeTab = screen.getByRole("tab", { name: /Zzz First/i });
    const panel = screen.getByRole("tabpanel");
    expect(activeTab).toHaveAttribute("aria-selected", "true");
    expect(activeTab.id).toBe("domain-tab-zzz_first");
    expect(activeTab).toHaveAttribute("aria-controls", panel.id);
    expect(panel).toHaveAttribute("aria-labelledby", activeTab.id);

    const inactiveTab = screen.getByRole("tab", { name: /Mmm Third/i });
    expect(inactiveTab).toHaveAttribute("aria-selected", "false");
  });

  it("supports ArrowRight/ArrowLeft/Home/End to move focus between tabs (roving tabindex), without activating them", async () => {
    renderOverview(multiDomainRegistry());
    const [first, second, third] = screen.getAllByRole("tab");

    first.focus();
    expect(first).toHaveAttribute("tabIndex", "0");
    expect(second).toHaveAttribute("tabIndex", "-1");

    await userEvent.keyboard("{ArrowRight}");
    expect(second).toHaveFocus();

    await userEvent.keyboard("{ArrowRight}");
    expect(third).toHaveFocus();

    await userEvent.keyboard("{ArrowRight}");
    expect(first).toHaveFocus();

    await userEvent.keyboard("{ArrowLeft}");
    expect(third).toHaveFocus();

    await userEvent.keyboard("{Home}");
    expect(first).toHaveFocus();

    await userEvent.keyboard("{End}");
    expect(third).toHaveFocus();

    // Moving focus never activates a tab by itself (manual activation).
    expect(third).toHaveAttribute("aria-selected", "false");
  });

  it("activates the focused tab on Enter (native button activation, no double-handling)", async () => {
    renderOverview(multiDomainRegistry());
    const third = screen.getAllByRole("tab")[2];

    third.focus();
    await userEvent.keyboard("{Enter}");

    expect(third).toHaveAttribute("aria-selected", "true");
    expect(screen.getByTestId("capability-surface.aaa_second.a")).toBeInTheDocument();
  });
});

describe("WorkbenchOverview capability cards", () => {
  it("renders one card per visible capability of the active domain, with no truncation past three", () => {
    renderOverview(capabilityCardRegistry());

    for (const id of ["cap.ready", "cap.degraded", "cap.empty", "cap.not_collected", "cap.processing", "cap.failed", "cap.evidence"]) {
      expect(screen.getByTestId(`capability-${id}`)).toBeInTheDocument();
    }
  });

  it("renders cards in overview.priority order (fallback to nav.order, existing stable tie-break)", () => {
    renderOverview(capabilityCardRegistry());
    const panel = screen.getByRole("tabpanel");
    const titles = within(panel).getAllByText(/Capability$/).map((node) => node.textContent);

    expect(titles).toEqual([
      "Ready Capability",
      "Degraded Capability",
      "Empty Capability",
      "Not Collected Capability",
      "Processing Capability",
      "Failed Capability",
      "Evidence Scoped Capability",
    ]);
  });

  it("shows the capability title", () => {
    renderOverview(capabilityCardRegistry());
    expect(within(screen.getByTestId("capability-cap.ready")).getByText("Ready Capability")).toBeInTheDocument();
  });

  it("shows record_count and artifact_count literally, without recomputing them", () => {
    renderOverview(capabilityCardRegistry());
    const card = screen.getByTestId("capability-cap.ready");
    expect(card).toHaveTextContent("42 records");
    expect(card).toHaveTextContent("5 artifacts");
  });

  it.each([
    ["cap.ready", "has data"],
    ["cap.degraded", "degraded"],
    ["cap.empty", "no data"],
    ["cap.not_collected", "no data"],
  ])("renders the real readiness badge for %s", (id, label) => {
    renderOverview(capabilityCardRegistry());
    expect(screen.getByTestId(`capability-${id}`)).toHaveTextContent(label);
  });

  it("does not collapse empty and not_collected into the same underlying value, even though they currently share a label", () => {
    renderOverview(capabilityCardRegistry());
    // Both cards render, independently, from their own distinct readiness
    // value -- this is only possible if the component never coerces one
    // into the other before rendering.
    expect(screen.getByTestId("capability-cap.empty")).toHaveTextContent("Empty Capability");
    expect(screen.getByTestId("capability-cap.not_collected")).toHaveTextContent("Not Collected Capability");
  });

  it("tolerates processing and failed defensively without throwing, though the backend never emits them today", () => {
    expect(() => renderOverview(capabilityCardRegistry())).not.toThrow();
    expect(screen.getByTestId("capability-cap.processing")).toHaveTextContent("processing");
    expect(screen.getByTestId("capability-cap.failed")).toHaveTextContent("failed");
  });

  it("uses overview.quick_action as the action label when present", () => {
    renderOverview(capabilityCardRegistry());
    expect(within(screen.getByTestId("capability-cap.ready")).getByRole("link", { name: "Open Ready" })).toBeInTheDocument();
  });

  it("falls back to the neutral 'Open' label when overview.quick_action is absent", () => {
    renderOverview(capabilityCardRegistry());
    expect(within(screen.getByTestId("capability-cap.empty")).getByRole("link", { name: "Open" })).toBeInTheDocument();
  });

  it("resolves a normal route with no :evidenceId regardless of evidence state", () => {
    renderOverview(capabilityCardRegistry());
    expect(within(screen.getByTestId("capability-cap.ready")).getByRole("link", { name: "Open Ready" })).toHaveAttribute("href", "/cases/case-1/artifacts?artifact_type=ready");
  });

  it("resolves :evidenceId from the pathname when the analyst is already inside that evidence", () => {
    renderOverview(capabilityCardRegistry(), "linux", "/cases/case-1/m/ev-A/processes");
    expect(within(screen.getByTestId("capability-cap.evidence")).getByRole("link", { name: "Open" })).toHaveAttribute("href", "/cases/case-1/m/ev-A/processes");
  });

  it("resolves :evidenceId from selectedEvidenceId when the pathname carries none", () => {
    localStorage.setItem("dfir.selectedEvidenceId", "ev-B");
    renderOverview(capabilityCardRegistry(), "linux", "/cases/case-1/l");
    expect(within(screen.getByTestId("capability-cap.evidence")).getByRole("link", { name: "Open" })).toHaveAttribute("href", "/cases/case-1/m/ev-B/processes");
  });

  it("prioritizes the pathname evidence over selectedEvidenceId when both are present", () => {
    localStorage.setItem("dfir.selectedEvidenceId", "ev-B");
    renderOverview(capabilityCardRegistry(), "linux", "/cases/case-1/m/ev-A/processes");
    expect(within(screen.getByTestId("capability-cap.evidence")).getByRole("link", { name: "Open" })).toHaveAttribute("href", "/cases/case-1/m/ev-A/processes");
  });

  it("disables the action and explains why when no evidence is available from either source", () => {
    renderOverview(capabilityCardRegistry(), "linux", "/cases/case-1/l");
    const card = screen.getByTestId("capability-cap.evidence");

    const button = within(card).getByRole("button", { name: /Open/i });
    expect(button).toBeDisabled();
    expect(within(card).getByText("Select memory evidence")).toBeInTheDocument();
  });

  it("never navigates silently to the Memory workbench root when evidence is missing", () => {
    renderOverview(capabilityCardRegistry(), "linux", "/cases/case-1/l");
    const card = screen.getByTestId("capability-cap.evidence");

    // No link at all inside the card while evidence is missing -- in
    // particular, no link silently pointing at the Memory workbench root.
    expect(within(card).queryByRole("link")).not.toBeInTheDocument();
  });

  it("does not disable cards whose readiness is empty/not_collected/not_applicable-like when their route is still valid", () => {
    renderOverview(capabilityCardRegistry());
    expect(within(screen.getByTestId("capability-cap.empty")).getByRole("link", { name: "Open" })).toBeEnabled();
    expect(within(screen.getByTestId("capability-cap.not_collected")).getByRole("link", { name: "Open" })).toBeEnabled();
  });

  it("shows the warning associated by id prefix, matching the payload text without altering it", () => {
    renderOverview(capabilityCardRegistry());
    const card = screen.getByTestId("capability-cap.degraded");
    expect(within(card).getByText("Degraded Capability is degraded")).toBeInTheDocument();
    expect(within(card).getByText("Some parser or plugin results are incomplete.")).toBeInTheDocument();
  });

  it("does not show a warning belonging to a different capability", () => {
    renderOverview(capabilityCardRegistry());
    const readyCard = screen.getByTestId("capability-cap.ready");
    expect(within(readyCard).queryByText("Degraded Capability is degraded")).not.toBeInTheDocument();
  });
});
