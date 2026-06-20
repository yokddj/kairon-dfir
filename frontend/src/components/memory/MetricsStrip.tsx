import type { TreeMetrics } from "../../lib/useMemoryTreeMetrics";

type Props = {
  metrics: TreeMetrics;
  isLoading: boolean;
  isFetching: boolean;
  hasLoaded: boolean;
};

const SKELETON = "h-4 w-12 animate-pulse rounded bg-abyss/60";

function Stat({ label, value, testId, isLoading, hasLoaded }: {
  label: string;
  value: number;
  testId: string;
  isLoading: boolean;
  hasLoaded: boolean;
}) {
  return (
    <div
      className="rounded-xl border border-line bg-abyss/60 px-3 py-2"
      data-testid={`metrics-strip-${testId}`}
    >
      <p className="text-[10px] uppercase tracking-[0.18em] text-muted">{label}</p>
      {isLoading && !hasLoaded ? (
        <div className={`mt-1 ${SKELETON}`} />
      ) : (
        <p className="mt-1 text-base font-semibold text-ink" data-testid={`metrics-strip-${testId}-value`}>
          {value}
        </p>
      )}
    </div>
  );
}

/**
 * Single source of metrics used by Graph and Indented-tree views.
 *
 * Layout: 9 columns on desktop, collapsing to fewer on small screens.
 * Each cell is independent: when the underlying query is loading and we
 * have not received any previous data yet, the cell renders a skeleton
 * bar instead of a misleading `0`.
 */
export function MetricsStrip({ metrics, isLoading, isFetching, hasLoaded }: Props) {
  const showSkeleton = isLoading && !hasLoaded;
  return (
    <div
      className="grid gap-2 md:grid-cols-3 xl:grid-cols-9"
      data-testid="metrics-strip"
      data-loading={isFetching ? "true" : "false"}
    >
      <Stat label="Visible" value={metrics.visible_processes} testId="visible" isLoading={showSkeleton} hasLoaded={hasLoaded} />
      <Stat label="Matching" value={metrics.matching_processes} testId="matching" isLoading={showSkeleton} hasLoaded={hasLoaded} />
      <Stat label="Context ancestors" value={metrics.context_ancestors} testId="ancestors" isLoading={showSkeleton} hasLoaded={hasLoaded} />
      <Stat label="Collapsed" value={metrics.collapsed_branches} testId="collapsed" isLoading={showSkeleton} hasLoaded={hasLoaded} />
      <Stat label="Not loaded" value={metrics.processes_not_loaded} testId="not-loaded" isLoading={showSkeleton} hasLoaded={hasLoaded} />
      <Stat label="Case roots" value={metrics.case_roots} testId="case-roots" isLoading={showSkeleton} hasLoaded={hasLoaded} />
      <Stat label="View roots" value={metrics.current_view_roots} testId="view-roots" isLoading={showSkeleton} hasLoaded={hasLoaded} />
      <Stat label="Orphans" value={metrics.orphans} testId="orphans" isLoading={showSkeleton} hasLoaded={hasLoaded} />
      <Stat label="Scan only" value={metrics.scan_only} testId="scan-only" isLoading={showSkeleton} hasLoaded={hasLoaded} />
    </div>
  );
}
