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
  | "find_evil"
  | "shell_history"
  | "timeline"
  | "memprocfs"
  | "network"
  | "modules"
  | "handles"
  | "drivers"
  | "kernel"
  | "suspicious"
  | "vads"
  | "files"
  | "system"
  | "runs"
  | "raw"
  | "artifacts";

export const MEMORY_TABS: ReadonlyArray<{ key: MemoryTab; label: string; testId: string; routeSegment: string }> = [
  { key: "overview", label: "Overview", testId: "memory-tab-overview", routeSegment: "overview" },
  { key: "processes", label: "Processes", testId: "memory-tab-processes", routeSegment: "processes" },
  { key: "graph", label: "Graph", testId: "memory-tab-graph", routeSegment: "process-graph" },
  { key: "find_evil", label: "Find Evil", testId: "memory-tab-find-evil", routeSegment: "find-evil" },
  { key: "shell_history", label: "Shell History", testId: "memory-tab-shell-history", routeSegment: "shell_history" },
  { key: "timeline", label: "Timeline", testId: "memory-tab-timeline", routeSegment: "timeline" },
  { key: "memprocfs", label: "MemProcFS", testId: "memory-tab-memprocfs", routeSegment: "memprocfs" },
  { key: "network", label: "Network", testId: "memory-tab-network", routeSegment: "network" },
  { key: "modules", label: "Modules & DLLs", testId: "memory-tab-modules", routeSegment: "modules" },
  { key: "handles", label: "Handles", testId: "memory-tab-handles", routeSegment: "handles" },
  { key: "drivers", label: "Drivers", testId: "memory-tab-drivers", routeSegment: "drivers" },
  { key: "kernel", label: "Kernel Modules", testId: "memory-tab-kernel", routeSegment: "kernel-modules" },
  { key: "suspicious", label: "Suspicious Memory", testId: "memory-tab-suspicious", routeSegment: "suspicious" },
  { key: "vads", label: "VADs", testId: "memory-tab-vads", routeSegment: "vads" },
  { key: "files", label: "Files", testId: "memory-tab-files", routeSegment: "files" },
  { key: "system", label: "System", testId: "memory-tab-system", routeSegment: "system" },
  { key: "runs", label: "Runs", testId: "memory-tab-runs", routeSegment: "runs" },
  { key: "raw", label: "Raw Observations", testId: "memory-tab-raw", routeSegment: "raw" },
];

// The tab bar groups the tabs by what the analyst is doing, so the first row
// stays short: a group with one view is a plain tab; a group with several
// shows them as a second row when it is active. Groups only change the bar --
// every tab keeps its own key and route, so links and deep links still work.
export type MemoryTabGroup = {
  key: string;
  label: string;
  tabs: ReadonlyArray<{ tab: MemoryTab; label: string }>;
};

export const MEMORY_TAB_GROUPS: ReadonlyArray<MemoryTabGroup> = [
  { key: "overview", label: "Overview", tabs: [{ tab: "overview", label: "Overview" }] },
  { key: "processes", label: "Processes", tabs: [{ tab: "processes", label: "List" }, { tab: "graph", label: "Graph" }] },
  { key: "find_evil", label: "Find Evil", tabs: [{ tab: "find_evil", label: "Find Evil" }] },
  { key: "shell_history", label: "Shell History", tabs: [{ tab: "shell_history", label: "Shell History" }] },
  { key: "timeline", label: "Timeline", tabs: [{ tab: "timeline", label: "Timeline" }] },
  { key: "network", label: "Network", tabs: [{ tab: "network", label: "Network" }] },
  {
    key: "code",
    label: "Code in memory",
    tabs: [
      { tab: "suspicious", label: "Suspicious Memory" },
      { tab: "modules", label: "Modules & DLLs" },
      { tab: "handles", label: "Handles" },
      { tab: "vads", label: "VADs" },
    ],
  },
  { key: "kernel", label: "Kernel", tabs: [{ tab: "kernel", label: "Kernel Modules" }, { tab: "drivers", label: "Drivers" }] },
  { key: "files", label: "Files", tabs: [{ tab: "files", label: "Files" }] },
  { key: "memprocfs", label: "MemProcFS", tabs: [{ tab: "memprocfs", label: "MemProcFS" }] },
  {
    key: "more",
    label: "More",
    tabs: [
      { tab: "system", label: "System" },
      { tab: "runs", label: "Runs" },
      { tab: "raw", label: "Raw Observations" },
    ],
  },
];

export function memoryTabGroupOf(tab: MemoryTab): MemoryTabGroup | undefined {
  return MEMORY_TAB_GROUPS.find((group) => group.tabs.some((item) => item.tab === tab));
}

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
