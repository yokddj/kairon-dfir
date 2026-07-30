import { describe, expect, it } from "vitest";
import {
  describeIdentityStrength,
  describeProcessVisibility,
  processEntityLabel,
  processVisibilityToneClass,
  reportedValue,
  sourcePluginBadge,
} from "./memoryProcessEntityPresentation";
import type { MemoryProcessEntity } from "../api/client";

function baseEntity(overrides: Partial<MemoryProcessEntity> = {}): MemoryProcessEntity {
  return {
    document_type: "memory_process_entity",
    case_id: "case-1",
    evidence_id: "evidence-1",
    scan_run_id: "run-1",
    process_entity_id: "entity-1",
    process: { pid: 1840, name: "powershell.exe" },
    visibility: { listed: true },
    sources: ["windows.pslist"],
    source_plugins: ["windows.pslist"],
    observation_count: 1,
    observation_summary: {},
    confidence: "high",
    findings: [],
    findings_summary: [],
    normalization_version: "memory_process_canonical_v1",
    child_count: 0,
    tree: {},
    ...overrides,
  };
}

describe("reportedValue", () => {
  it("renders an em dash for null/undefined/empty", () => {
    expect(reportedValue(null)).toBe("—");
    expect(reportedValue(undefined)).toBe("—");
    expect(reportedValue("")).toBe("—");
  });

  it("stringifies real values", () => {
    expect(reportedValue(1840)).toBe("1840");
    expect(reportedValue("svchost.exe")).toBe("svchost.exe");
  });
});

describe("sourcePluginBadge", () => {
  it("strips the windows. prefix", () => {
    expect(sourcePluginBadge("windows.pslist")).toBe("pslist");
  });

  it("leaves non-windows plugin names untouched", () => {
    expect(sourcePluginBadge("linux.psaux")).toBe("linux.psaux");
  });
});

describe("describeProcessVisibility / processVisibilityToneClass", () => {
  it("returns em dash and neutral tone for a missing entity", () => {
    expect(describeProcessVisibility(null)).toBe("—");
    expect(processVisibilityToneClass(null)).toContain("text-muted");
  });

  it("prioritizes terminated over other flags", () => {
    const entity = baseEntity({ visibility: { terminated: true, hidden_candidate: true } });
    expect(describeProcessVisibility(entity)).toBe("Terminated");
  });

  it("flags hidden_candidate before scan_only", () => {
    const entity = baseEntity({ visibility: { hidden_candidate: true, scan_only: true } });
    expect(describeProcessVisibility(entity)).toBe("Hidden candidate");
  });

  it("flags scan_only", () => {
    const entity = baseEntity({ visibility: { scan_only: true } });
    expect(describeProcessVisibility(entity)).toBe("Scan only");
    expect(processVisibilityToneClass(entity)).toContain("rose");
  });

  it("flags unknown", () => {
    const entity = baseEntity({ visibility: { unknown: true } });
    expect(describeProcessVisibility(entity)).toBe("Unknown");
    expect(processVisibilityToneClass(entity)).toContain("amber");
  });

  it("defaults to Listed", () => {
    const entity = baseEntity({ visibility: { listed: true } });
    expect(describeProcessVisibility(entity)).toBe("Listed");
    expect(processVisibilityToneClass(entity)).toContain("sky");
  });
});

describe("describeIdentityStrength", () => {
  it("returns em dash for a missing entity", () => {
    expect(describeIdentityStrength(null)).toBe("—");
  });

  it("reports provisional identity when the backend flags identity_provisional, even with high confidence", () => {
    const entity = baseEntity({ confidence: "high", findings: ["identity_provisional"] });
    expect(describeIdentityStrength(entity)).toMatch(/Provisional/);
  });

  it("reports strong identity for high confidence without the provisional finding", () => {
    const entity = baseEntity({ confidence: "high", findings: [] });
    expect(describeIdentityStrength(entity)).toMatch(/Strong/);
  });

  it("reports moderate identity for medium confidence", () => {
    const entity = baseEntity({ confidence: "medium", findings: [] });
    expect(describeIdentityStrength(entity)).toMatch(/Moderate/);
  });

  it("reports low identity for low confidence", () => {
    const entity = baseEntity({ confidence: "low", findings: [] });
    expect(describeIdentityStrength(entity)).toMatch(/Low/);
  });
});

describe("processEntityLabel", () => {
  it("returns null for a missing entity", () => {
    expect(processEntityLabel(null)).toBeNull();
  });

  it("combines name and PID when both are known", () => {
    const entity = baseEntity({ process: { pid: 1840, name: "powershell.exe" } });
    expect(processEntityLabel(entity)).toBe("powershell.exe (PID 1840)");
  });

  it("falls back to the name alone when PID is missing", () => {
    const entity = baseEntity({ process: { pid: undefined as unknown as number, name: "powershell.exe" } });
    expect(processEntityLabel(entity)).toBe("powershell.exe");
  });

  it("falls back to PID alone when the name is missing", () => {
    const entity = baseEntity({ process: { pid: 1840, name: null } });
    expect(processEntityLabel(entity)).toBe("PID 1840");
  });

  it("returns null when neither name nor PID is known", () => {
    const entity = baseEntity({ process: { pid: undefined as unknown as number, name: null } });
    expect(processEntityLabel(entity)).toBeNull();
  });
});
