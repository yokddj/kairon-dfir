import { useState } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { type EventMarkingStatus, type MemoryFindEvilProcess, api } from "../../api/client";

// Triage marks for a process. "Suspicious" keeps it in the list (flagged);
// "Reviewed" and "Not relevant" move it to the collapsed section below.
const ACTIONS: Array<{ status: EventMarkingStatus; label: string }> = [
  { status: "reviewed", label: "Reviewed" },
  { status: "suspicious", label: "Suspicious" },
  { status: "not_relevant", label: "Not relevant" },
];
const SETTLED: ReadonlySet<string> = new Set(["reviewed", "not_relevant", "false_positive"]);

const STATUS_LABEL: Record<string, string> = {
  reviewed: "Reviewed",
  suspicious: "Suspicious",
  not_relevant: "Not relevant",
  false_positive: "False positive",
  important: "Important",
};

const PRIORITY_CHIP: Record<string, string> = {
  high: "border-rose-400/40 bg-rose-500/10 text-rose-100",
  medium: "border-amber-400/40 bg-amber-500/10 text-amber-100",
  low: "border-line bg-abyss/70 text-muted",
};

export function findEvilProcessQueryKey(caseId: string, evidenceId?: string) {
  return ["memory-findevil-processes", caseId, evidenceId ?? ""] as const;
}

export function processLabel(process: Pick<MemoryFindEvilProcess, "pid" | "process_name">): string {
  if (process.pid === null && !process.process_name) return "Not tied to a process";
  return `${process.process_name || "Unknown process"}${process.pid !== null ? ` (${process.pid})` : ""}`;
}

export function PriorityChips({ counts }: { counts: MemoryFindEvilProcess["priority_counts"] }) {
  return (
    <span className="inline-flex flex-wrap gap-1">
      {(["high", "medium", "low"] as const).map((priority) =>
        counts[priority] ? (
          <span key={priority} className={`rounded-full border px-2 py-0.5 text-[10px] uppercase tracking-[0.1em] ${PRIORITY_CHIP[priority]}`} data-testid={`findevil-process-${priority}`}>
            {priority} {counts[priority]}
          </span>
        ) : null,
      )}
    </span>
  );
}

type Props = {
  caseId: string;
  evidenceId?: string;
  priority: string;
  indicatorType: string;
  onShowIndicators: (process: MemoryFindEvilProcess) => void;
};

/**
 * Find Evil by process: one row per process with indicators, most important
 * first, marked by the analyst as reviewed, suspicious or not relevant. The
 * mark is kept per evidence and process, so it survives re-running Find Evil.
 */
export function MemoryFindEvilProcesses({ caseId, evidenceId, priority, indicatorType, onShowIndicators }: Props) {
  const queryClient = useQueryClient();
  const [showSettled, setShowSettled] = useState(false);
  const query = useQuery({
    queryKey: findEvilProcessQueryKey(caseId, evidenceId),
    queryFn: () => api.getMemoryFindEvilProcesses(caseId, evidenceId || ""),
    enabled: Boolean(caseId && evidenceId),
    refetchOnWindowFocus: false,
  });
  const invalidate = () => queryClient.invalidateQueries({ queryKey: findEvilProcessQueryKey(caseId, evidenceId) });
  const mark = useMutation({
    mutationFn: ({ process, status }: { process: MemoryFindEvilProcess; status: EventMarkingStatus }) =>
      api.markEvent(process.triage_id, {
        case_id: caseId,
        evidence_id: evidenceId,
        artifact_type: query.data?.marking_artifact_type ?? "memory_findevil_process",
        status,
      }),
    onSuccess: invalidate,
  });
  const unmark = useMutation({
    mutationFn: (markingId: string) => api.deleteEventMarking(markingId),
    onSuccess: invalidate,
  });

  const processes = (query.data?.processes ?? []).filter(
    (process) =>
      (!priority || (process.priority_counts as Record<string, number>)[priority] > 0) &&
      (!indicatorType || process.indicator_types.some((t) => t.value === indicatorType)),
  );
  const open = processes.filter((process) => !process.marking || !SETTLED.has(process.marking.status));
  const settled = processes.filter((process) => process.marking && SETTLED.has(process.marking.status));
  const busy = mark.isPending || unmark.isPending;

  if (query.isLoading) return <p className="mt-3 text-xs text-muted">Loading…</p>;
  if (query.error instanceof Error) {
    return <p className="mt-3 rounded-2xl border border-rose-400/30 bg-rose-500/10 p-3 text-xs text-rose-200">{query.error.message}</p>;
  }
  if (!query.data?.processes.length) return null;

  const row = (process: MemoryFindEvilProcess) => {
    const types = process.indicator_types;
    return (
      <tr key={process.triage_id} data-testid="findevil-process-row">
        <td className="px-2 py-2 align-top">
          <p className="font-medium text-ink">{processLabel(process)}</p>
          {process.marking ? (
            <span className="mt-1 inline-block text-[10px] text-accent" data-testid="findevil-process-status">
              {STATUS_LABEL[process.marking.status] ?? process.marking.status}
            </span>
          ) : null}
        </td>
        <td className="px-2 py-2 align-top"><PriorityChips counts={process.priority_counts} /></td>
        <td className="px-2 py-2 align-top">
          <span className="flex flex-wrap gap-1 font-mono text-[10px] text-muted">
            {types.slice(0, 4).map((t) => (
              <span key={t.value} className="rounded-md border border-line bg-abyss/60 px-1.5 py-0.5">{t.value}{t.count > 1 ? ` ×${t.count}` : ""}</span>
            ))}
            {types.length > 4 ? <span className="px-1 py-0.5">+{types.length - 4}</span> : null}
          </span>
        </td>
        <td className="px-2 py-2 align-top">
          <button
            type="button"
            onClick={() => onShowIndicators(process)}
            className="whitespace-nowrap text-xs text-muted hover:text-accent"
            data-testid="findevil-process-show"
          >
            {process.indicator_count} indicator{process.indicator_count === 1 ? "" : "s"} →
          </button>
        </td>
        <td className="px-2 py-2 align-top">
          <span className="flex flex-wrap justify-end gap-1">
            {process.marking ? (
              <button
                type="button"
                disabled={busy}
                onClick={() => unmark.mutate(process.marking!.id)}
                className="rounded-lg border border-line px-2 py-1 text-[11px] text-muted hover:text-ink disabled:opacity-50"
                data-testid="findevil-process-undo"
              >
                Undo
              </button>
            ) : (
              ACTIONS.map((action) => (
                <button
                  key={action.status}
                  type="button"
                  disabled={busy}
                  onClick={() => mark.mutate({ process, status: action.status })}
                  className="rounded-lg border border-line px-2 py-1 text-[11px] text-muted hover:text-ink disabled:opacity-50"
                  data-testid={`findevil-process-mark-${action.status}`}
                >
                  {action.label}
                </button>
              ))
            )}
          </span>
        </td>
      </tr>
    );
  };

  return (
    <div className="mt-3 space-y-3" data-testid="findevil-processes">
      <p className="text-xs text-muted" data-testid="findevil-processes-summary">
        {open.length} process{open.length === 1 ? "" : "es"} to review
        {settled.length ? ` · ${settled.length} reviewed or not relevant` : ""}
      </p>
      {open.length ? (
        <div className="max-w-full overflow-x-auto rounded-2xl border border-line bg-abyss/40">
          <table className="w-full min-w-[860px] divide-y divide-line text-xs">
            <tbody className="divide-y divide-line">{open.map(row)}</tbody>
          </table>
        </div>
      ) : (
        <p className="text-xs text-muted" data-testid="findevil-processes-done">
          {processes.length ? "Every process here has been reviewed." : "No process matches these filters."}
        </p>
      )}
      {settled.length ? (
        <div>
          <button
            type="button"
            onClick={() => setShowSettled((value) => !value)}
            className="text-xs text-muted hover:text-ink"
            data-testid="findevil-processes-toggle-settled"
          >
            {showSettled ? "Hide" : "Show"} reviewed and not relevant ({settled.length})
          </button>
          {showSettled ? (
            <div className="mt-2 max-w-full overflow-x-auto rounded-2xl border border-line bg-abyss/20 opacity-80">
              <table className="w-full min-w-[860px] divide-y divide-line text-xs">
                <tbody className="divide-y divide-line">{settled.map(row)}</tbody>
              </table>
            </div>
          ) : null}
        </div>
      ) : null}
    </div>
  );
}
