import { render, screen, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { MemoryRouter, useLocation } from "react-router-dom";
import { describe, expect, it, vi } from "vitest";
import { WorkbenchOverview } from "./WorkbenchOverview";
import { resolveSurfaceIcon } from "../../lib/surfaceIcons";
import type { CaseCapabilitiesResponse, CaseCapability } from "../../api/client";

vi.mock("../../lib/surfaceIcons", async () => {
  const actual = await vi.importActual<typeof import("../../lib/surfaceIcons")>("../../lib/surfaceIcons");
  return { ...actual, resolveSurfaceIcon: vi.fn(actual.resolveSurfaceIcon) };
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

function LocationProbe() {
  const location = useLocation();
  return <span data-testid="location-probe">{location.pathname + location.search}</span>;
}

function renderOverview(data: CaseCapabilitiesResponse = registry(), workbenchId = "linux", initialEntry?: string) {
  const entry = initialEntry ?? `/cases/case-1/${workbenchId === "memory" ? "m" : workbenchId[0]}`;
  return render(
    <MemoryRouter initialEntries={[entry]}>
      <WorkbenchOverview registry={data} workbenchId={workbenchId} caseId="case-1" />
      <LocationProbe />
    </MemoryRouter>,
  );
}

describe("WorkbenchOverview", () => {
  it("renders registry-driven header, warnings, activity and quick actions, with only the default domain's panel mounted", async () => {
    renderOverview();

    expect(screen.getByTestId("workbench-overview-linux")).toBeInTheDocument();
    expect(screen.getByText("Linux")).toBeInTheDocument();
    expect(screen.getByRole("link", { name: "Open Authentication" })).toHaveAttribute("href", "/cases/case-1/l/access/authentication");
    expect(screen.getByText("Cloud Sync failed")).toBeInTheDocument();
    expect(screen.getByRole("link", { name: /Suspicious SSH/i })).toHaveAttribute("href", "/cases/case-1/detections?detection_id=det-1");

    // Default domain (lowest capability priority) is "access" -- its panel
    // is mounted, "cloud_sync" is only a tab until selected.
    expect(screen.getByTestId("coverage-access")).toHaveTextContent("Authentication");
    expect(screen.queryByTestId("coverage-cloud_sync")).not.toBeInTheDocument();

    await userEvent.click(screen.getByRole("tab", { name: /Cloud Sync/i }));

    expect(screen.getByTestId("coverage-cloud_sync")).toHaveTextContent("Cloud Sync");
    expect(screen.queryByTestId("coverage-access")).not.toBeInTheDocument();
  });

  it("renders an empty workbench without inventing capabilities", () => {
    renderOverview(registry({ workbenches: [] }));
    expect(screen.getByText("Workbench unavailable")).toBeInTheDocument();
  });

  it("renders memory image overview cards from registry payload", () => {
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
            recent_activity: [],
            memory_images: [{ id: "ev-1", name: "mem.raw", host_id: null, detected_host: null, detected_os: "windows", preparation_state: "completed", symbol_state: "ready", plugin_record_count: 8, run_status_counts: { completed: 1 }, route: "/cases/case-1/m/ev-1/overview" }],
          },
        },
      ],
      capabilities: [capability({ id: "memory.processes", platform: "memory", evidence_domain: "memory", domain: "execution", title: "Processes", route: "/cases/:caseId/m/:evidenceId/processes" })],
    });

    renderOverview(data, "memory");

    expect(screen.getByRole("link", { name: /mem.raw/i })).toHaveAttribute("href", "/cases/case-1/m/ev-1/overview");
    expect(screen.getByText("Memory host association missing")).toBeInTheDocument();
    const execution = screen.getByTestId("coverage-execution");
    expect(within(execution).getByText("Processes")).toBeInTheDocument();
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
    expect(screen.getByTestId("coverage-zzz_first")).toBeInTheDocument();
  });

  it("mounts only the active domain's panel, never the others", () => {
    renderOverview(multiDomainRegistry());

    expect(screen.getByTestId("coverage-zzz_first")).toBeInTheDocument();
    expect(screen.queryByTestId("coverage-mmm_third")).not.toBeInTheDocument();
    expect(screen.queryByTestId("coverage-aaa_second")).not.toBeInTheDocument();
  });

  it("clicking another tab switches the active domain, updates ?domain=, and preserves other query params", async () => {
    renderOverview(multiDomainRegistry(), "linux", "/cases/case-1/l?tab=overview");

    await userEvent.click(screen.getByRole("tab", { name: /Mmm Third/i }));

    expect(screen.getByRole("tab", { name: /Mmm Third/i })).toHaveAttribute("aria-selected", "true");
    expect(screen.getByTestId("coverage-mmm_third")).toBeInTheDocument();
    expect(screen.queryByTestId("coverage-zzz_first")).not.toBeInTheDocument();

    const location = screen.getByTestId("location-probe").textContent || "";
    expect(location).toContain("domain=mmm_third");
    expect(location).toContain("tab=overview");
  });

  it("selects the domain from a valid ?domain= deep link on load", () => {
    renderOverview(multiDomainRegistry(), "linux", "/cases/case-1/l?domain=aaa_second");

    expect(screen.getByRole("tab", { name: /Aaa Second/i })).toHaveAttribute("aria-selected", "true");
    expect(screen.getByTestId("coverage-aaa_second")).toBeInTheDocument();
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
    expect(screen.getByTestId("coverage-aaa_second")).toBeInTheDocument();
  });
});
