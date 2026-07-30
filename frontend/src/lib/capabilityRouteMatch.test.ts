import { describe, expect, it } from "vitest";
import { matchCapabilityRoute, matchSurfaceHome } from "./capabilityRouteMatch";
import type { CaseCapability } from "../api/client";

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

describe("matchCapabilityRoute", () => {
  it("matches a route with no query", () => {
    const auth = capability({});
    const match = matchCapabilityRoute([auth], "/cases/case-1/l/access/authentication", "");
    expect(match?.capability.id).toBe("linux.access.authentication");
    expect(match?.evidenceId).toBeNull();
  });

  it("matches when the required query is present with the exact value", () => {
    const persistence = capability({ id: "windows.persistence.overview", route: "/cases/:caseId/findings?preset=persistence" });
    const match = matchCapabilityRoute([persistence], "/cases/case-1/findings", "?preset=persistence");
    expect(match?.capability.id).toBe("windows.persistence.overview");
  });

  it("matches regardless of query param order", () => {
    const cap = capability({ id: "two.params", route: "/cases/:caseId/artifacts?artifact_type=x&parser=y" });
    const match = matchCapabilityRoute([cap], "/cases/case-1/artifacts", "?parser=y&artifact_type=x");
    expect(match?.capability.id).toBe("two.params");
  });

  it("allows extra query params that aren't declared by the route", () => {
    const persistence = capability({ id: "windows.persistence.overview", route: "/cases/:caseId/findings?preset=persistence" });
    const match = matchCapabilityRoute([persistence], "/cases/case-1/findings", "?preset=persistence&finding_id=abc123");
    expect(match?.capability.id).toBe("windows.persistence.overview");
  });

  it("does not match when the required query param is absent", () => {
    const persistence = capability({ id: "windows.persistence.overview", route: "/cases/:caseId/findings?preset=persistence" });
    const match = matchCapabilityRoute([persistence], "/cases/case-1/findings", "");
    expect(match).toBeNull();
  });

  it("does not match when the required query param has a different value", () => {
    const persistence = capability({ id: "windows.persistence.overview", route: "/cases/:caseId/findings?preset=persistence" });
    const match = matchCapabilityRoute([persistence], "/cases/case-1/findings", "?preset=malware");
    expect(match).toBeNull();
  });

  it("does not confuse a Tier 1 lens's plain URL with a capability that reuses its pathname under a required query", () => {
    // Findings (Tier 1, no query) and windows.persistence.overview (same
    // pathname, requires ?preset=persistence) must never cross-match.
    const persistence = capability({ id: "windows.persistence.overview", route: "/cases/:caseId/findings?preset=persistence" });
    const plainFindings = matchCapabilityRoute([persistence], "/cases/case-1/findings", "");
    expect(plainFindings).toBeNull();
    const presetFindings = matchCapabilityRoute([persistence], "/cases/case-1/findings", "?preset=persistence");
    expect(presetFindings?.capability.id).toBe("windows.persistence.overview");
  });

  it("picks the most specific match among several capabilities matching the same pathname", () => {
    const generic = capability({ id: "generic", route: "/cases/:caseId/artifacts" });
    const specific = capability({ id: "specific", route: "/cases/:caseId/artifacts?artifact_type=linux_packages" });
    const match = matchCapabilityRoute([generic, specific], "/cases/case-1/artifacts", "?artifact_type=linux_packages");
    expect(match?.capability.id).toBe("specific");
  });

  it("breaks ties by more static path segments when required-query counts are equal", () => {
    const shallow = capability({ id: "shallow", route: "/cases/:caseId/artifacts" });
    const deeper = capability({ id: "deeper", route: "/cases/:caseId/artifacts/extra" });
    const match = matchCapabilityRoute([shallow, deeper], "/cases/case-1/artifacts/extra", "");
    expect(match?.capability.id).toBe("deeper");
  });

  it("breaks a full tie by stable registry order", () => {
    const first = capability({ id: "first", route: "/cases/:caseId/artifacts" });
    const second = capability({ id: "second", route: "/cases/:caseId/artifacts" });
    const match = matchCapabilityRoute([first, second], "/cases/case-1/artifacts", "");
    expect(match?.capability.id).toBe("first");
  });

  it("captures :evidenceId from the matched route", () => {
    const processes = capability({ id: "memory.processes", route: "/cases/:caseId/m/:evidenceId/processes" });
    const match = matchCapabilityRoute([processes], "/cases/case-1/m/ev-A/processes", "");
    expect(match?.evidenceId).toBe("ev-A");
  });

  it("returns null for an unknown route", () => {
    const auth = capability({});
    const match = matchCapabilityRoute([auth], "/cases/case-1/does-not-exist", "");
    expect(match).toBeNull();
  });

  it("returns null when the segment count differs, even with a matching prefix", () => {
    const auth = capability({ route: "/cases/:caseId/l/access/authentication" });
    const match = matchCapabilityRoute([auth], "/cases/case-1/l/access/authentication/extra", "");
    expect(match).toBeNull();
  });
});

describe("matchSurfaceHome", () => {
  it("matches a workbench whose overview_route equals the pathname exactly", () => {
    const workbenches = [{ id: "linux", overview_route: "/cases/case-1/l" }];
    expect(matchSurfaceHome(workbenches, "/cases/case-1/l")?.id).toBe("linux");
  });

  it("does not match a deeper route under the same surface", () => {
    const workbenches = [{ id: "linux", overview_route: "/cases/case-1/l" }];
    expect(matchSurfaceHome(workbenches, "/cases/case-1/l/access/authentication")).toBeNull();
  });

  it("returns null when no workbench matches", () => {
    const workbenches = [{ id: "linux", overview_route: "/cases/case-1/l" }];
    expect(matchSurfaceHome(workbenches, "/cases/case-1/w")).toBeNull();
  });
});
