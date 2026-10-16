import type { TreeMetrics } from "../../lib/useMemoryTreeMetrics";

type Props = {
  metrics: TreeMetrics;
  isLoading: boolean;
  isFetching: boolean;
  hasLoaded: boolean;
};

function plural(count: number, one: string, many: string) {
  return `${count.toLocaleString("en-US")} ${count === 1 ? one : many}`;
}

/**
 * One line shared by the Graph and Indented-tree views: how many processes
 * the run has and how the tree starts, plus a note only for what deserves
 * a look (processes found only by scanning, hidden candidates, parent loops,
 * processes left out of the view).
 */
export function MetricsStrip({ metrics, isLoading, isFetching, hasLoaded }: Props) {
  if (isLoading && !hasLoaded) {
    return <div className="h-5 w-72 animate-pulse rounded bg-abyss/60" data-testid="metrics-strip" data-loading="true" />;
  }
  const notes: Array<{ key: string; text: string }> = [];
  if (metrics.scan_only) notes.push({ key: "scan-only", text: `${plural(metrics.scan_only, "process", "processes")} found only by memory scanning` });
  if (metrics.hidden_candidates) notes.push({ key: "hidden", text: `${plural(metrics.hidden_candidates, "possibly hidden process", "possibly hidden processes")}` });
  if (metrics.cycles) notes.push({ key: "cycles", text: `${plural(metrics.cycles, "process", "processes")} in a parent loop` });
  if (metrics.processes_not_loaded) notes.push({ key: "not-loaded", text: `${plural(metrics.processes_not_loaded, "process", "processes")} not shown in this view` });

  return (
    <div className="space-y-1 text-xs" data-testid="metrics-strip" data-loading={isFetching ? "true" : "false"}>
      <p className="text-muted">
        <span className="text-ink" data-testid="metrics-strip-processes">{plural(metrics.total_processes, "process", "processes")}</span>
        {" · "}
        <span data-testid="metrics-strip-top-level">{plural(metrics.current_view_roots, "top-level process", "top-level processes")}</span>
        {metrics.orphans ? (
          <>
            {" · "}
            <span data-testid="metrics-strip-orphans" title="Their parent process had already exited when memory was captured. Normal for csrss.exe, winlogon.exe or explorer.exe.">
              {plural(metrics.orphans, "whose parent exited", "whose parent exited")}
            </span>
          </>
        ) : null}
      </p>
      {notes.map((note) => (
        <p key={note.key} className="text-amber-200" data-testid={`metrics-strip-${note.key}`}>{note.text}</p>
      ))}
    </div>
  );
}
