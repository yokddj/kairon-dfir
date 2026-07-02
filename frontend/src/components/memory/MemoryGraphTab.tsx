import { useState } from "react";
import { useQuery } from "@tanstack/react-query";
import { type MemoryRunSelector, api } from "../../api/client";
import { MemoryProcessGraph } from "../MemoryProcessGraph";
import { IndentedTreeView } from "./IndentedTreeView";
import { MetricsStrip } from "./MetricsStrip";
import { ProcessDetailModal } from "./ProcessDetailModal";
import { useMemoryTreeMetrics } from "../../lib/useMemoryTreeMetrics";

type Props = {
  caseId: string;
  runId: string | null;
  runOptions: MemoryRunSelector | null;
  selectedRunId: string | null;
  onSelectRunId: (next: string | null) => void;
  selectedEntityId: string | null;
  onSelectEntityId: (next: string | null) => void;
  onOpenProcessDetails: (entityId: string) => void;
};

type SubView = "graph" | "tree";

export function MemoryGraphTab({
  caseId,
  runId,
  runOptions,
  selectedRunId,
  onSelectRunId,
  selectedEntityId,
  onSelectEntityId,
  onOpenProcessDetails,
}: Props) {
  const [subView, setSubView] = useState<SubView>("graph");
  const [inspectEntityId, setInspectEntityId] = useState<string | null>(null);

  const topologyRunId = runOptions?.runs.find(
    (run) => run.profile === "processes_basic" && (run.status === "completed" || run.status === "completed_with_errors"),
  )?.run_id ?? null;
  const effectiveRunId = runId || selectedRunId || topologyRunId || runOptions?.default_run_id || null;
  const { metrics, isLoading, isFetching, hasLoaded } = useMemoryTreeMetrics(caseId, {
    run_id: effectiveRunId,
    depth: 10,
    max_nodes: 500,
  });

  const inspectEntityDetail = useQuery({
    queryKey: ["memory-process-entity-detail-modal", caseId, inspectEntityId, effectiveRunId],
    queryFn: () => api.getCanonicalProcessEntityDetail(caseId, inspectEntityId as string, effectiveRunId || undefined),
    enabled: Boolean(caseId && inspectEntityId),
    refetchOnWindowFocus: false,
  });

  return (
    <div className="space-y-4" data-testid="memory-graph-tab">
      <section className="rounded-[28px] border border-line bg-panel/60 p-5 shadow-panel">
        <header className="flex flex-wrap items-center justify-between gap-3">
          <div>
            <h3 className="text-sm font-semibold uppercase tracking-[0.18em] text-muted">Process graph</h3>
            <p className="mt-1 text-xs text-muted">Run-isolated, filterable, click-to-focus. Detail opens as a centered modal.</p>
          </div>
          <div className="flex flex-wrap items-center gap-2">
            <div className="flex rounded-xl border border-line bg-abyss/70 p-0.5 text-xs" role="tablist" aria-label="Graph sub-view">
              <button
                type="button"
                role="tab"
                aria-selected={subView === "graph"}
                onClick={() => setSubView("graph")}
                data-testid="graph-subview-graph"
                className={`rounded-lg px-2 py-1 ${subView === "graph" ? "bg-accent text-abyss" : "text-muted"}`}
              >
                Visual graph
              </button>
              <button
                type="button"
                role="tab"
                aria-selected={subView === "tree"}
                onClick={() => setSubView("tree")}
                data-testid="graph-subview-tree"
                className={`rounded-lg px-2 py-1 ${subView === "tree" ? "bg-accent text-abyss" : "text-muted"}`}
              >
                Indented tree
              </button>
            </div>
            <RunPicker
              runId={runId}
              runOptions={runOptions}
              selectedRunId={selectedRunId}
              onSelectRunId={onSelectRunId}
            />
          </div>
        </header>

        <div className="mt-3">
          <MetricsStrip
            metrics={metrics}
            isLoading={isLoading}
            isFetching={isFetching}
            hasLoaded={hasLoaded}
          />
        </div>

        {subView === "graph" ? (
          <div className="mt-4">
            <MemoryProcessGraph
              caseId={caseId}
              runId={effectiveRunId}
              onOpenDetail={(entityId) => setInspectEntityId(entityId)}
              selectedEntityId={selectedEntityId}
              onSelectEntityId={onSelectEntityId}
            />
          </div>
        ) : (
          <div className="mt-4">
            <IndentedTreeView
              caseId={caseId}
              runId={effectiveRunId}
              runOptions={runOptions}
              selectedRunId={selectedRunId}
              onSelectRunId={onSelectRunId}
              selectedEntityId={selectedEntityId}
              onSelectEntityId={onSelectEntityId}
              onOpenProcessDetails={(entityId) => setInspectEntityId(entityId)}
            />
          </div>
        )}
      </section>
      <ProcessDetailModal
        open={Boolean(inspectEntityId)}
        detail={inspectEntityDetail.data ?? null}
        isLoading={inspectEntityDetail.isLoading}
        error={inspectEntityDetail.error instanceof Error ? inspectEntityDetail.error : null}
        caseId={caseId}
        evidenceId={"mem"}
        runId={effectiveRunId}
        onClose={() => setInspectEntityId(null)}
        onSelectEntityId={(next) => {
          setInspectEntityId(next);
          onSelectEntityId(next);
        }}
        onOpenInGraph={() => setSubView("graph")}
        onShowInTree={() => setSubView("tree")}
      />
    </div>
  );
}

function RunPicker({
  runId,
  runOptions,
  selectedRunId,
  onSelectRunId,
}: {
  runId: string | null;
  runOptions: MemoryRunSelector | null;
  selectedRunId: string | null;
  onSelectRunId: (next: string | null) => void;
}) {
  const effective = runId || selectedRunId || runOptions?.default_run_id || null;
  return (
    <div className="flex flex-wrap items-center gap-2 text-xs">
      <label className="text-muted" htmlFor="graph-run-picker">Run</label>
      <select
        id="graph-run-picker"
        value={effective || ""}
        onChange={(event) => onSelectRunId(event.target.value || null)}
        className="rounded-xl border border-line bg-abyss/70 px-2 py-1 text-sm"
        data-testid="graph-run-picker"
      >
        {(runOptions?.runs || [])
          .filter((r) => r.profile === "processes_basic" || r.profile === "processes_extended")
          .map((run) => (
            <option key={run.run_id} value={run.run_id}>
              {run.profile} · {run.status} · {(run.completed_at || run.created_at).slice(0, 16).replace("T", " ")} UTC
            </option>
          ))}
      </select>
    </div>
  );
}
