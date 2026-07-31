/* Shared state for the Memory Analysis workspace.

The workspace uses URL search params to persist the active tab and
selected entity across reloads and deep links.  The rest of the
shared state (run selection, profile, search, filters) lives in the
parent component so all tabs see consistent values.

This file is the single source of truth for the tab <-> route segment
contract.  A tab's `key` (used for ?tab=, aria-selected, query cache
keys) and its `routeSegment` (the literal path segment registered in
App.tsx, e.g. "graph" -> "process-graph") are two different strings
for a handful of tabs -- keeping only one lookup table here, instead
of the key/segment mapping being reimplemented per-consumer, is what
prevents a mismatch (a tab whose route segment nobody registered, or
a resolver that checks the wrong side of the mapping) from shipping
unnoticed the way the missing Runs route did.
*/

import { useSearchParams } from "react-router-dom";

export type MemoryTab =
  | "overview"
  | "processes"
  | "graph"
  | "network"
  | "modules"
  | "handles"
  | "suspicious"
  | "vads"
  | "system"
  | "runs"
  | "raw"
  | "artifacts";

export const MEMORY_TABS: ReadonlyArray<{ key: MemoryTab; label: string; testId: string; routeSegment: string }> = [
  { key: "overview", label: "Overview", testId: "memory-tab-overview", routeSegment: "overview" },
  { key: "processes", label: "Processes", testId: "memory-tab-processes", routeSegment: "processes" },
  { key: "graph", label: "Graph", testId: "memory-tab-graph", routeSegment: "process-graph" },
  { key: "network", label: "Network", testId: "memory-tab-network", routeSegment: "network" },
  { key: "modules", label: "Modules & DLLs", testId: "memory-tab-modules", routeSegment: "modules" },
  { key: "handles", label: "Handles", testId: "memory-tab-handles", routeSegment: "handles" },
  { key: "suspicious", label: "Suspicious Memory", testId: "memory-tab-suspicious", routeSegment: "suspicious" },
  { key: "vads", label: "VADs", testId: "memory-tab-vads", routeSegment: "vads" },
  { key: "system", label: "System", testId: "memory-tab-system", routeSegment: "system" },
  { key: "runs", label: "Runs", testId: "memory-tab-runs", routeSegment: "runs" },
  { key: "raw", label: "Raw Observations", testId: "memory-tab-raw", routeSegment: "raw" },
];

// "artifacts" is a real route/subview (registered in App.tsx, rendered by
// MemoryWorkspace) but deliberately not a clickable tab in MEMORY_TABS --
// it's reached via family links/CTAs, not the tab bar. It still has to be
// a valid tab key everywhere a MemoryTab is accepted.
const TAB_KEYS: ReadonlyArray<string> = [...MEMORY_TABS.map((tab) => tab.key), "artifacts"];

const ROUTE_SEGMENT_TO_TAB = new Map<string, MemoryTab>(MEMORY_TABS.map((tab) => [tab.routeSegment, tab.key]));
const TAB_TO_ROUTE_SEGMENT = new Map<MemoryTab, string>(MEMORY_TABS.map((tab) => [tab.key, tab.routeSegment]));
// "artifacts" has no tab-bar entry above but is still a registered route
// segment identical to its key (MemoryWorkspace renders it directly).
ROUTE_SEGMENT_TO_TAB.set("artifacts", "artifacts");
TAB_TO_ROUTE_SEGMENT.set("artifacts", "artifacts");

export function isMemoryTab(value: string | null): value is MemoryTab {
  return value !== null && (TAB_KEYS as string[]).includes(value);
}

// The inverse of routeSegmentFromTab: resolves a literal /m/:evidenceId/<segment>
// URL path segment (e.g. "process-graph") back to its MemoryTab key (e.g. "graph").
// Returns null for a segment that isn't a real Memory route at all, so callers
// can tell "not on a memory route segment" apart from "on the overview tab".
export function tabFromRouteSegment(value: string | null): MemoryTab | null {
  if (value === null) return null;
  return ROUTE_SEGMENT_TO_TAB.get(value) ?? null;
}

// The inverse of tabFromRouteSegment: resolves a MemoryTab key to the
// literal route segment App.tsx registers for it.
export function routeSegmentFromTab(value: MemoryTab): string {
  return TAB_TO_ROUTE_SEGMENT.get(value) ?? value;
}

export function parseTabFromParams(params: URLSearchParams): MemoryTab {
  const raw = params.get("tab");
  return isMemoryTab(raw) ? raw : "overview";
}

export function useMemoryTab(): [MemoryTab, (next: MemoryTab) => void] {
  const [params, setParams] = useSearchParams();
  const tab = parseTabFromParams(params);
  const setTab = (next: MemoryTab) => {
    const updated = new URLSearchParams(params);
    updated.set("tab", next);
    setParams(updated, { replace: true });
  };
  return [tab, setTab];
}
