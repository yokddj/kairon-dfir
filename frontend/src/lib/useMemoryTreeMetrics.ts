import { useQuery } from "@tanstack/react-query";
import { type MemoryProcessTreeEntity, api } from "../api/client";

export type TreeMetrics = {
  visible_processes: number;
  matching_processes: number;
  context_ancestors: number;
  collapsed_branches: number;
  processes_not_loaded: number;
  case_roots: number;
  current_view_roots: number;
  orphans: number;
  scan_only: number;
  hidden_candidates: number;
  terminated: number;
  unknown_parent: number;
  pid_zero_count: number;
  pid_4_count: number;
  cycles: number;
};

const ZERO_METRICS: TreeMetrics = {
  visible_processes: 0,
  matching_processes: 0,
  context_ancestors: 0,
  collapsed_branches: 0,
  processes_not_loaded: 0,
  case_roots: 0,
  current_view_roots: 0,
  orphans: 0,
  scan_only: 0,
  hidden_candidates: 0,
  terminated: 0,
  unknown_parent: 0,
  pid_zero_count: 0,
  pid_4_count: 0,
  cycles: 0,
};

/**
 * Single source of truth for memory process tree metrics.
 *
 * Backend `_build_tree_response.metrics` already returns these fields.
 * The hook is **always** deterministic:
 *   * While the request is pending or fails, it reports a fully-populated
 *     zero object so the UI shows a skeleton instead of contradictory
 *     "0 / 12" rows.
 *   * On success, it maps the API metrics 1:1 to the canonical UI shape.
 *
 * The hook also exposes the raw `tree` so the consumer can render the
 * graph / tree without making a second request.
 */
export function useMemoryTreeMetrics(caseId: string, params: {
  run_id?: string | null;
  root_entity_id?: string | null;
  depth?: number;
  max_nodes?: number;
  include_ancestors?: boolean;
  orphans_only?: boolean;
  visibility?: string;
  interesting_only?: boolean;
  search?: string;
}) {
  const treeQuery = useQuery<MemoryProcessTreeEntity>({
    queryKey: ["memory-tree-metrics", caseId, params],
    queryFn: () => api.getCanonicalProcessTree(caseId, params as any),
    enabled: Boolean(caseId && params.run_id),
    refetchOnWindowFocus: false,
    placeholderData: (previous: MemoryProcessTreeEntity | undefined) => previous,
  });

  const raw = treeQuery.data?.metrics;
  const metrics: TreeMetrics = raw
    ? {
        visible_processes: raw.visible_processes ?? raw.total_nodes ?? 0,
        matching_processes: (raw.search_results ?? treeQuery.data?.search_results ?? []).length,
        context_ancestors: raw.context_ancestors ?? 0,
        collapsed_branches: raw.collapsed_branches ?? 0,
        processes_not_loaded: raw.processes_not_loaded ?? 0,
        case_roots: raw.case_roots ?? raw.roots ?? 0,
        current_view_roots: raw.current_view_roots ?? 0,
        orphans: raw.orphans ?? 0,
        scan_only: raw.scan_only ?? 0,
        hidden_candidates: raw.hidden_candidates ?? 0,
        terminated: raw.terminated ?? 0,
        unknown_parent: raw.unknown_parent ?? 0,
        pid_zero_count: raw.pid_zero_count ?? 0,
        pid_4_count: raw.pid_4_count ?? 0,
        cycles: raw.cycles ?? 0,
      }
    : ZERO_METRICS;

  return {
    metrics,
    tree: treeQuery.data,
    isLoading: treeQuery.isLoading,
    isFetching: treeQuery.isFetching,
    error: treeQuery.error,
    hasLoaded: Boolean(treeQuery.data),
  };
}
