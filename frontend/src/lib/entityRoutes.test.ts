import { describe, expect, it } from "vitest";
import { memoryProcessEntityRoute } from "./entityRoutes";

describe("memoryProcessEntityRoute", () => {
  it("builds the case-scoped, path-addressable route", () => {
    expect(memoryProcessEntityRoute("case-1", "entity-abc")).toBe("/cases/case-1/entities/memory-process/entity-abc");
  });

  it("escapes special characters in both segments", () => {
    expect(memoryProcessEntityRoute("case 1", "entity/abc?x=1")).toBe(
      "/cases/case%201/entities/memory-process/entity%2Fabc%3Fx%3D1",
    );
  });

  it("returns null when caseId is missing", () => {
    expect(memoryProcessEntityRoute("", "entity-abc")).toBeNull();
  });

  it("returns null when entityId is missing", () => {
    expect(memoryProcessEntityRoute("case-1", "")).toBeNull();
  });

  it("returns null when both ids are missing", () => {
    expect(memoryProcessEntityRoute("", "")).toBeNull();
  });
});
