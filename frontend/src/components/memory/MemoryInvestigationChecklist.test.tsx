import { describe, expect, it } from "vitest";
import { buildInvestigationChecklist } from "./MemoryOverviewTab";

type Family = Parameters<typeof buildInvestigationChecklist>[2][number];

const LANDING = {
  case_id: "case-1",
  evidence_id: "ev-1",
  host_id: "host-1",
  detection_status: "confirmed_memory",
  can_analyze: true,
  families: [],
} as unknown as Parameters<typeof buildInvestigationChecklist>[0];

function family(name: string, title: string, state: string): Family {
  return {
    family: name,
    title,
    state,
    activeRun: null,
    latestAttempt: null,
    selectionReason: "not_analyzed",
    usingFallback: false,
    lastCount: 0,
  } as unknown as Family;
}

function analyzeStep(families: Family[]) {
  const items = buildInvestigationChecklist(LANDING, null, families, () => {});
  const step = items.find((item) => item.id === "analyze");
  if (!step) throw new Error("analyze step missing");
  return step;
}

describe("Memory Investigation checklist", () => {
  it("does not call the image analysed when only the first profile has run", () => {
    // The first run covers processes only. Reporting "Analyze memory ✔" here
    // told the analyst the image was done while network, suspicious regions and
    // handles had never been looked at -- the sole hint being the header button
    // quietly changing to "Complete analysis".
    const step = analyzeStep([
      family("processes", "Processes", "completed"),
      family("network", "Network", "not_analyzed"),
      family("suspicious_regions", "Suspicious memory", "not_analyzed"),
    ]);

    expect(step.status).toBe("next");
    expect(step.detail).toContain("not analyzed yet");
    expect(step.detail).toContain("Network");
    expect(step.detail).toContain("Suspicious memory");
    expect(step.detail).toContain("Complete analysis");
  });

  it("is done once every applicable family has been analysed", () => {
    const step = analyzeStep([
      family("processes", "Processes", "completed"),
      family("network", "Network", "analyzed_empty"),
      family("suspicious_regions", "Suspicious memory", "ready"),
    ]);

    expect(step.status).toBe("done");
  });

  it("ignores families that do not apply to this image", () => {
    // "unavailable" means the plugin cannot run against this image at all, so
    // it can never complete and must not hold the step open forever.
    const step = analyzeStep([
      family("processes", "Processes", "completed"),
      family("network", "Network", "unavailable"),
    ]);

    expect(step.status).toBe("done");
  });

  it("still asks the analyst to start when nothing has run", () => {
    const step = analyzeStep([
      family("processes", "Processes", "not_analyzed"),
      family("network", "Network", "not_analyzed"),
    ]);

    expect(step.status).toBe("next");
    expect(step.detail).toContain("Analyze memory");
  });

  it("treats a failed family as still pending", () => {
    const step = analyzeStep([
      family("processes", "Processes", "completed"),
      family("network", "Network", "failed"),
    ]);

    expect(step.status).toBe("next");
    expect(step.detail).toContain("Network");
  });
});
