import { describe, it, expect } from "vitest";
import { readFileSync } from "node:fs";
import { resolve } from "node:path";

/*
 * Regression guard for a real, live bug found during Sprint 3 (Memory
 * Technical Debt Cleanup): MemoryEvidenceHeader's "Analyze memory"
 * button (rendered when isFirstAnalysis is true -- i.e. the exact same
 * "nothing has ever been analyzed yet" moment MemoryInitialAnalysisAction
 * targets from the wizard) called startMemoryScan with the literal
 * profile "metadata_only", which is unconditionally ineligible for Linux
 * evidence (see app.services.memory.capability_registry). This is a
 * second, independent first-analysis entry point from the wizard's
 * golden path -- reachable whenever a user opens MemoryEvidencePage
 * directly for evidence that was never routed through the wizard.
 *
 * The fix reuses MemoryInitialAnalysisAction's own exported
 * INITIAL_ANALYSIS_PROFILE constant ("processes_basic") instead of a
 * second hardcoded literal, so both first-analysis entry points can
 * never drift apart again. This test checks the source directly rather
 * than mounting the full page (754 lines, many query dependencies) --
 * matches the existing convention in memoryTabRouteContract.test.ts for
 * "this string must never reappear here" guards.
 */

function pageSource(): string {
  return readFileSync(resolve(process.cwd(), "src/pages/MemoryEvidencePage.tsx"), "utf-8");
}

describe("MemoryEvidencePage first-analysis profile", () => {
  it("never hardcodes the literal profile string \"metadata_only\" anywhere in the page", () => {
    const source = pageSource();
    expect(
      source.includes('"metadata_only"') || source.includes("'metadata_only'"),
      "MemoryEvidencePage.tsx must never hardcode \"metadata_only\" as a scan profile -- it is unconditionally ineligible for Linux evidence. Use INITIAL_ANALYSIS_PROFILE from MemoryInitialAnalysisAction instead.",
    ).toBe(false);
  });

  it("imports INITIAL_ANALYSIS_PROFILE from MemoryInitialAnalysisAction (the single source of truth for the first-analysis profile)", () => {
    const source = pageSource();
    expect(source.includes('import { INITIAL_ANALYSIS_PROFILE } from "../components/memory/MemoryInitialAnalysisAction"')).toBe(true);
  });

  it("passes INITIAL_ANALYSIS_PROFILE (not a literal) into the first-analysis startMemoryScan call", () => {
    const source = pageSource();
    const mutationStart = source.indexOf("const startScanMutation = useMutation(");
    expect(mutationStart, "startScanMutation not found -- has it been renamed?").toBeGreaterThan(-1);
    const mutationBlock = source.slice(mutationStart, mutationStart + 600);
    expect(mutationBlock.includes("api.startMemoryScan(caseId, evidenceId, INITIAL_ANALYSIS_PROFILE)")).toBe(true);
  });
});
