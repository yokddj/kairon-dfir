import { describe, it, expect } from "vitest";
import { readFileSync } from "node:fs";
import { resolve } from "node:path";
import { MEMORY_TABS, tabFromRouteSegment, routeSegmentFromTab } from "./memoryWorkspaceState";

/*
 * Regression guard for two related classes of Memory-tab navigation bugs
 * that have each shipped once already:
 *
 * 1. Missing route (fixed once for /runs): a tab's route segment was never
 *    registered in App.tsx at all, so navigating there fell through to the
 *    wildcard route and left the Memory/evidence context entirely. App.tsx
 *    now registers ONE parameterized route for every evidence-scoped
 *    Memory tab (/cases/:caseId/m/:evidenceId/:memoryTab) instead of one
 *    literal <Route> per tab -- the literal-per-tab form is what caused
 *    the /runs gap in the first place (an easy line to forget to add), and
 *    it ALSO caused a second, worse bug: none of those literal routes
 *    declared :memoryTab as a parameter, so useParams().memoryTab was
 *    always empty in production for every tab, not just the missing one.
 *
 * 2. Path-vs-query priority (the second bug above): with memoryTab always
 *    empty, MemoryEvidencePage's tab resolution always fell through to the
 *    ?tab= query param (routeTab null -> read searchParams), and a legacy
 *    fallback effect kept re-forcing ?tab=overview after every navigation
 *    -- so every tab silently rendered Overview regardless of which path
 *    segment was in the URL. This class of bug can reintroduce itself
 *    even with the route registered correctly, if the *priority* between
 *    path segment and query param regresses. That priority is exercised
 *    directly (not just via source-text matching) in
 *    MemoryAnalysisPage.test.tsx's "?tab= is stale" test suite.
 *
 * This file compares, automatically, the places a Memory tab's route
 * segment has to agree:
 *   1. tab definitions      -- MEMORY_TABS (memoryWorkspaceState.ts)
 *   2. route builder        -- routeSegmentFromTab (memoryViewPath uses this)
 *   3. route resolver       -- tabFromRouteSegment (MemoryEvidencePage uses
 *                               this to turn the :memoryTab route param back
 *                               into an active tab)
 *   4. App routes           -- the actual <Route> App.tsx mounts, extracted
 *                               from source text (no test-only route table)
 */

function appTsxSource(): string {
  return readFileSync(resolve(process.cwd(), "src/App.tsx"), "utf-8");
}

describe("Memory tab <-> route contract", () => {
  it("registers a single parameterized evidence-scoped Memory route that captures :memoryTab", () => {
    const source = appTsxSource();
    expect(
      source.includes('<Route path="/cases/:caseId/m/:evidenceId/:memoryTab" element={<MemoryEvidencePage />} />'),
      "App.tsx must register /cases/:caseId/m/:evidenceId/:memoryTab as ONE parameterized route -- not a literal <Route> per tab segment, which never captures :memoryTab into useParams() at all",
    ).toBe(true);
  });

  it("does not register a literal per-tab route for any Memory tab segment (the exact shape that caused this bug)", () => {
    const source = appTsxSource();
    for (const tab of MEMORY_TABS) {
      const segment = routeSegmentFromTab(tab.key);
      const literalRoute = `<Route path="/cases/:caseId/m/:evidenceId/${segment}"`;
      expect(source.includes(literalRoute), `Found a literal route for "${segment}" -- this segment must be handled by the single :memoryTab route, not its own <Route>`).toBe(false);
    }
  });

  it("round-trips every tab through routeSegmentFromTab -> tabFromRouteSegment back to itself", () => {
    for (const tab of MEMORY_TABS) {
      const segment = routeSegmentFromTab(tab.key);
      expect(tabFromRouteSegment(segment)).toBe(tab.key);
    }
  });

  it("resolves every contractually-required route segment back to a real tab (overview, processes, process-graph, network, modules, handles, suspicious, vads, system, runs, raw)", () => {
    const required = ["overview", "processes", "process-graph", "network", "modules", "handles", "suspicious", "vads", "system", "runs", "raw"];
    for (const segment of required) {
      expect(tabFromRouteSegment(segment), `route segment "${segment}" does not resolve to any MemoryTab`).not.toBeNull();
    }
  });

  it("checks the route segment before the ?tab= query param in MemoryEvidencePage's tab resolution (path must win)", () => {
    const source = readFileSync(resolve(process.cwd(), "src/pages/MemoryEvidencePage.tsx"), "utf-8");
    const tabComputation = source.slice(source.indexOf("const tab = useMemo"), source.indexOf("const tab = useMemo") + 400);
    const routeCheckIndex = tabComputation.indexOf("tabFromRouteSegment(memoryTab)");
    const queryCheckIndex = tabComputation.indexOf('searchParams.get("tab")');
    expect(routeCheckIndex, "tabFromRouteSegment(memoryTab) not found in the tab computation").toBeGreaterThan(-1);
    expect(queryCheckIndex, '?tab= fallback not found in the tab computation').toBeGreaterThan(-1);
    expect(routeCheckIndex, "the route segment must be checked BEFORE the ?tab= query param, so a stale/inherited ?tab= can never override the path").toBeLessThan(queryCheckIndex);
  });
});
