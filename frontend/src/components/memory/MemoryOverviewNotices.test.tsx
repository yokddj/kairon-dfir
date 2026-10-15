import { describe, expect, it } from "vitest";
import { buildOverviewNotices, type OverviewFamily } from "./MemoryOverviewTab";

type Landing = Parameters<typeof buildOverviewNotices>[1];
type Readiness = Parameters<typeof buildOverviewNotices>[2];

const LANDING = {
  case_id: "case-1",
  evidence_id: "ev-1",
  host_id: "host-1",
  detection_status: "confirmed_memory",
  can_analyze: true,
  families: [],
} as unknown as Landing;

const READY = { can_analyze: true } as unknown as Readiness;

function family(name: string, title: string, state: string): OverviewFamily {
  return {
    family: name,
    title,
    state,
    activeRun: null,
    latestAttempt: null,
    usingFallback: false,
    availabilityReason: null,
    lastCount: 0,
  } as unknown as OverviewFamily;
}

function ids(landing: Landing, readiness: Readiness, families: OverviewFamily[]) {
  return buildOverviewNotices("case-1", landing, readiness, null, families).map((n) => n.id);
}

describe("Memory overview notices", () => {
  it("shows nothing when the evidence is healthy and fully analysed", () => {
    expect(ids(LANDING, READY, [family("processes", "Processes", "completed"), family("network", "Network", "analyzed_empty")])).toEqual([]);
  });

  it("does not treat families that cannot run on this image as pending work", () => {
    expect(ids(LANDING, READY, [family("processes", "Processes", "completed"), family("network", "Network", "unavailable")])).toEqual([]);
  });

  it("names the families still to analyse once analysis has started", () => {
    const [notice] = buildOverviewNotices("case-1", LANDING, READY, null, [
      family("processes", "Processes", "completed"),
      family("network", "Network", "not_analyzed"),
      family("suspicious_regions", "Suspicious memory", "not_analyzed"),
    ]);
    expect(notice.id).toBe("pending");
    expect(notice.message).toContain("Network, Suspicious memory");
    expect(notice.message).toContain("Complete analysis");
  });

  it("asks to start when nothing has run", () => {
    const [notice] = buildOverviewNotices("case-1", LANDING, READY, null, [family("processes", "Processes", "not_analyzed")]);
    expect(notice.message).toContain("Analyze memory");
  });

  it("reports failed families", () => {
    expect(ids(LANDING, READY, [family("processes", "Processes", "latest_attempt_failed"), family("handles", "Handles", "failed")])).toEqual(["failed"]);
  });

  it("uses the readiness endpoint as the single source for whether analysis can run", () => {
    const blocked = { can_analyze: false, sanitized_message: "The dedicated memory worker is offline." } as unknown as Readiness;
    const notices = buildOverviewNotices("case-1", LANDING, blocked, null, [family("processes", "Processes", "not_analyzed")]);
    expect(notices.map((n) => n.id)).toEqual(["readiness"]);
    expect(notices[0].message).toBe("The dedicated memory worker is offline.");
  });

  it("explains a blocked detection and suppresses pending work", () => {
    const landing = { ...LANDING, detection_status: "probable_disk", detection_reason: "Looks like a disk image." } as unknown as Landing;
    const notices = buildOverviewNotices("case-1", landing, READY, null, [family("processes", "Processes", "not_analyzed")]);
    expect(notices.map((n) => n.id)).toEqual(["detection"]);
    expect(notices[0].tone).toBe("danger");
    expect(notices[0].message).toBe("Looks like a disk image.");
  });

  it("offers to assign a host when none is set", () => {
    const landing = { ...LANDING, host_id: null } as unknown as Landing;
    const notices = buildOverviewNotices("case-1", landing, READY, null, []);
    expect(notices.map((n) => n.id)).toEqual(["host"]);
    expect(notices[0].action?.label).toBe("Assign host");
  });
});
