import { useState } from "react";
import { useQuery } from "@tanstack/react-query";
import { type MemoryRunSelector, api } from "../../api/client";
import { MemoryProcessGraph } from "../MemoryProcessGraph";

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

function Stat({ label, value, testId }: { label: string; value: string | number; testId: string }) {
  return (
    <div className="rounded-xl border border-line bg-abyss/60 px-3 py-2" data-testid={`graph-tab-stat-${testId}`}>
      <p className="text-[10px] uppercase tracking-[0.18em] text-muted">{label}</p>
      <p className="mt-1 text-base font-semibold text-ink">{value}</p>
    </div>
  );
}

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
  const [graphMetrics, setGraphMetrics] = useState<{
    visibleNodes: number;
    truncatedCount: number;
    caseRoots: number;
    currentViewRoots: number;
    orphans: number;
    scanOnly: number;
    searchResults: number;
  }>({
    visibleNodes: 0,
    truncatedCount: 0,
    caseRoots: 0,
    currentViewRoots: 0,
    orphans: 0,
    scanOnly: 0,
    searchResults: 0,
  });

  return (
    <div className="space-y-4" data-testid="memory-graph-tab">
      <section className="rounded-[28px] border border-line bg-panel/60 p-5 shadow-panel">
        <header className="flex flex-wrap items-center justify-between gap-3">
          <div>
            <h3 className="text-sm font-semibold uppercase tracking-[0.18em] text-muted">Process graph</h3>
            <p className="mt-1 text-xs text-muted">Run-isolated, filterable, click-to-focus. Detail panel is on the right.</p>
          </div>
          <RunPicker
            runId={runId}
            runOptions={runOptions}
            selectedRunId={selectedRunId}
            onSelectRunId={onSelectRunId}
          />
        </header>

        <div className="mt-3 grid gap-2 md:grid-cols-7">
          <Stat label="Visible" value={graphMetrics.visibleNodes} testId="visible" />
          <Stat label="Matching" value={graphMetrics.searchResults} testId="matching" />
          <Stat label="Context ancestors" value={0} testId="ancestors" />
          <Stat label="Collapsed" value={graphMetrics.truncatedCount} testId="collapsed" />
          <Stat label="Not loaded" value={0} testId="not-loaded" />
          <Stat label="Case roots" value={graphMetrics.caseRoots} testId="case-roots" />
          <Stat label="Orphans" value={graphMetrics.orphans} testId="orphans" />
        </div>

        <div className="mt-4 grid gap-4 lg:grid-cols-[minmax(0,2fr)_minmax(320px,1fr)]">
          <div className="min-w-0">
            <MemoryProcessGraph
              caseId={caseId}
              runId={runId}
              onOpenDetail={onOpenProcessDetails}
              selectedEntityId={selectedEntityId}
              onSelectEntityId={onSelectEntityId}
            />
          </div>
          <aside
            className="rounded-2xl border border-line bg-abyss/60 p-4"
            aria-label="Graph detail"
            data-testid="graph-side-panel"
          >
            <h4 className="text-sm font-semibold uppercase tracking-[0.18em] text-muted">Selected process</h4>
            {selectedEntityId ? (
              <SelectedEntitySummary
                caseId={caseId}
                entityId={selectedEntityId}
                runId={runId}
                onOpenProcessDetails={onOpenProcessDetails}
                onClose={() => onSelectEntityId(null)}
              />
            ) : (
              <p className="mt-3 text-xs text-muted">Click a node to inspect it here.</p>
            )}
          </aside>
        </div>
      </section>
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

function SelectedEntitySummary({
  caseId,
  entityId,
  runId,
  onOpenProcessDetails,
  onClose,
}: {
  caseId: string;
  entityId: string;
  runId: string | null;
  onOpenProcessDetails: (entityId: string) => void;
  onClose: () => void;
}) {
  const detailQuery = useSelectedEntityDetail(caseId, entityId, runId);
  if (detailQuery.isLoading) return <p className="mt-3 text-xs text-muted">Loading…</p>;
  if (detailQuery.error instanceof Error) return <p className="mt-3 text-xs text-rose-200">{detailQuery.error.message}</p>;
  if (!detailQuery.data) return <p className="mt-3 text-xs text-muted">No data.</p>;
  const entity = detailQuery.data.entity;
  return (
    <div className="mt-3 space-y-2 text-xs" data-testid="graph-side-detail">
      <div className="flex items-start justify-between gap-2">
        <p className="text-sm font-semibold">{(entity.process.name as string | undefined) || "—"} · PID {entity.process.pid}</p>
        <button type="button" onClick={onClose} className="rounded-md border border-line bg-abyss/70 px-2 py-0.5 text-[10px]">
          Clear
        </button>
      </div>
      <p className="text-muted">Entity {entity.process_entity_id} · Confidence {entity.confidence}</p>
      <p className="break-words text-ink" title={entity.process.command_line as string | undefined}>
        {entity.process.command_line || "—"}
      </p>
      <p className="text-muted">Sources: {(entity.sources || []).map((s) => s.replace("windows.", "")).join(", ") || "—"}</p>
      <p className="text-muted">Visibility: {describeVisibility(entity)}</p>
      <button
        type="button"
        onClick={() => onOpenProcessDetails(entity.process_entity_id)}
        className="mt-2 rounded-xl border border-accent/40 bg-accent/10 px-3 py-1 text-xs text-accent"
        data-testid="graph-side-open-detail"
      >
        Open process details
      </button>
    </div>
  );
}

function describeVisibility(entity: any): string {
  if (entity.visibility?.terminated) return "Terminated";
  if (entity.visibility?.hidden_candidate) return "Hidden candidate";
  if (entity.visibility?.scan_only) return "Scan only";
  if (entity.visibility?.unknown) return "Unknown";
  return "Listed";
}

function useSelectedEntityDetail(caseId: string, entityId: string, runId: string | null) {
  return useQuery({
    queryKey: ["memory-process-entity-detail", caseId, entityId, runId],
    queryFn: () => api.getCanonicalProcessEntityDetail(caseId, entityId, runId || undefined),
    enabled: Boolean(caseId && entityId),
    refetchOnWindowFocus: false,
  });
}
