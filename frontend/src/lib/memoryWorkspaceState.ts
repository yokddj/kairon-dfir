/* Shared state for the Memory Analysis workspace.

The workspace uses URL search params to persist the active tab and
selected entity across reloads and deep links.  The rest of the
shared state (run selection, profile, search, filters) lives in the
parent component so all tabs see consistent values.
*/

import { useSearchParams } from "react-router-dom";

export type MemoryTab =
  | "overview"
  | "processes"
  | "graph"
  | "artifacts"
  | "system"
  | "runs"
  | "raw";

export const MEMORY_TABS: ReadonlyArray<{ key: MemoryTab; label: string; testId: string }> = [
  { key: "overview", label: "Overview", testId: "memory-tab-overview" },
  { key: "processes", label: "Processes", testId: "memory-tab-processes" },
  { key: "graph", label: "Graph", testId: "memory-tab-graph" },
  { key: "artifacts", label: "Artifacts", testId: "memory-tab-artifacts" },
  { key: "system", label: "System", testId: "memory-tab-system" },
  { key: "runs", label: "Runs", testId: "memory-tab-runs" },
  { key: "raw", label: "Raw observations", testId: "memory-tab-raw" },
];

const TAB_KEYS: ReadonlyArray<string> = MEMORY_TABS.map((tab) => tab.key);

export function isMemoryTab(value: string | null): value is MemoryTab {
  return value !== null && (TAB_KEYS as string[]).includes(value);
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
