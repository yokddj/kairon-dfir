import { render, screen, within } from "@testing-library/react";
import { MemoryRouter } from "react-router-dom";
import { describe, expect, it } from "vitest";
import { WorkbenchOverview } from "./WorkbenchOverview";
import type { CaseCapabilitiesResponse, CaseCapability } from "../../api/client";

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

function renderOverview(data: CaseCapabilitiesResponse = registry(), workbenchId = "linux") {
  return render(
    <MemoryRouter initialEntries={[`/cases/case-1/${workbenchId === "memory" ? "m" : workbenchId[0]}`]}>
      <WorkbenchOverview registry={data} workbenchId={workbenchId} caseId="case-1" />
    </MemoryRouter>,
  );
}

describe("WorkbenchOverview", () => {
  it("renders registry-driven header, coverage, warnings, activity and quick actions", () => {
    renderOverview();

    expect(screen.getByTestId("workbench-overview-linux")).toBeInTheDocument();
    expect(screen.getByText("Linux")).toBeInTheDocument();
    expect(screen.getByRole("link", { name: "Open Authentication" })).toHaveAttribute("href", "/cases/case-1/l/access/authentication");
    expect(screen.getByTestId("coverage-access")).toHaveTextContent("Authentication");
    expect(screen.getByTestId("coverage-cloud_sync")).toHaveTextContent("Cloud Sync");
    expect(screen.getByText("Cloud Sync failed")).toBeInTheDocument();
    expect(screen.getByRole("link", { name: /Suspicious SSH/i })).toHaveAttribute("href", "/cases/case-1/detections?detection_id=det-1");
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
