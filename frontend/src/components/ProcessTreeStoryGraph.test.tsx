import { describe, expect, it } from "vitest";

import { shouldDrawStoryGraph } from "./ProcessTreePanel";

/**
 * Execution Story used to draw its tree only when the target was matched by an
 * exact event id or ProcessGuid. A story resolved by PID + timestamp + host --
 * which is what the fallback produces, and what a name search usually gets --
 * left the canvas empty: "0 visible nodes" beside a narrative that named the
 * process, its PID, its command line and the child it launched.
 */
describe("shouldDrawStoryGraph", () => {
  const target = { id: "guid-1", name: "powershell.exe", pid: 6996 };

  it("draws a story whose identity was resolved by fallback", () => {
    expect(shouldDrawStoryGraph(target, 24)).toBe(true);
  });

  it("draws a story whose identity was exact", () => {
    expect(shouldDrawStoryGraph(target, 12)).toBe(true);
  });

  it("does not draw when no target was resolved", () => {
    // Nothing was found; the base graph must keep the canvas.
    expect(shouldDrawStoryGraph(null, 24)).toBe(false);
    expect(shouldDrawStoryGraph(undefined, 24)).toBe(false);
  });

  it("does not draw when the story carries an empty tree", () => {
    // A target with no tree would blank a canvas that had something in it.
    expect(shouldDrawStoryGraph(target, 0)).toBe(false);
  });
});
