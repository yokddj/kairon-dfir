import { describe, it, expect } from "vitest";
import { readFileSync } from "node:fs";
import { resolve } from "node:path";

describe("Memory experimental panel mount", () => {
  it("mounts the experimental panel from the memory evidence page", () => {
    const source = readFileSync(resolve(process.cwd(), "src/pages/MemoryEvidencePage.tsx"), "utf-8");
    expect(source).toContain("MemoryExperimentalResultsPanel");
    expect(source).toContain("showExperimentalPanel ? (");
  });
});
