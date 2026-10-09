import { useState } from "react";
import { useQuery } from "@tanstack/react-query";
import { type MemoryRunSelector, api } from "../../api/client";
import { MemoryPaginationControls } from "./MemoryPaginationControls";

type Props = {
  caseId: string;
  evidenceId?: string;
  runOptions: MemoryRunSelector | null;
  selectedRunId: string | null;
  onSelectRunId: (next: string | null) => void;
};

type FindEvilRow = {
  document_id?: string;
  pid?: number | null;
  process_name?: string | null;
  indicator_type?: string | null;
  indicator_category?: string | null;
  review_priority?: "high" | "medium" | "low" | string | null;
  explanation?: string | null;
  address?: string | null;
  description?: string | null;
  source_plugin?: string | null;
  sources?: string[] | null;
};

// Who reported the indicator: Kairon's own checks over Volatility's output, or MemProcFS FindEvil.
const SOURCE_LABEL: Record<string, string> = {
  "kairon.findevil": "Kairon",
  "memprocfs.findevil": "MemProcFS",
};

const PRIORITIES = [
  { value: "", label: "All" },
  { value: "high", label: "High" },
  { value: "medium", label: "Medium" },
  { value: "low", label: "Low" },
];

const PRIORITY_STYLE: Record<string, string> = {
  high: "border-rose-400/40 bg-rose-500/10 text-rose-200",
  medium: "border-amber-400/40 bg-amber-500/10 text-amber-200",
  low: "border-line bg-abyss/60 text-muted",
};

function reported(value: unknown): string {
  if (value === null || value === undefined || value === "") return "—";
  return String(value);
}

function RunPicker({ runOptions, selectedRunId, onSelectRunId }: Pick<Props, "runOptions" | "selectedRunId" | "onSelectRunId">) {
  const runs = (runOptions?.runs ?? []).filter((run) => run.profile === "find_evil");
  if (!runs.length) return null;
  return (
    <div className="flex flex-wrap items-center gap-2 text-xs">
      <label className="text-muted" htmlFor="findevil-run-picker">Run</label>
      <select
        id="findevil-run-picker"
        value={selectedRunId || ""}
        onChange={(event) => onSelectRunId(event.target.value || null)}
        className="rounded-xl border border-line bg-abyss/70 px-2 py-1 text-sm"
      >
        <option value="">Latest</option>
        {runs.map((run) => (
          <option key={run.run_id} value={run.run_id}>
            {run.status} · {(run.completed_at || run.created_at).slice(0, 16).replace("T", " ")} UTC
          </option>
        ))}
      </select>
    </div>
  );
}

export function MemoryFindEvilTab({ caseId, evidenceId, runOptions, selectedRunId, onSelectRunId }: Props) {
  const [page, setPage] = useState(1);
  const [priority, setPriority] = useState("");
  const [indicatorType, setIndicatorType] = useState("");
  const [pidFilter, setPidFilter] = useState("");
  const pageSize = 50;

  const activeResultQuery = useQuery({
    queryKey: ["memory-active-result", caseId, evidenceId, "find_evil", selectedRunId, page, priority, indicatorType, pidFilter],
    queryFn: () =>
      api.getMemoryActiveResult(caseId, evidenceId || "", "find_evil", selectedRunId || undefined, {
        review_priority: priority || undefined,
        indicator_type: indicatorType.trim().toUpperCase() || undefined,
        pid: pidFilter ? Number(pidFilter) : undefined,
        page,
        page_size: pageSize,
      }),
    enabled: Boolean(caseId && evidenceId),
    refetchOnWindowFocus: false,
  });

  const result = activeResultQuery.data;
  const items = (result?.items ?? []) as FindEvilRow[];
  const total = result?.total ?? 0;
  const totalPages = Math.max(1, Math.ceil(total / pageSize));
  const state = result?.analysis_state ?? "not_analyzed";
  const filtered = Boolean(priority || indicatorType || pidFilter);

  return (
    <div className="space-y-4" data-testid="memory-findevil-tab">
      <section className="rounded-[28px] border border-line bg-panel/60 p-5 shadow-panel">
        <header className="flex flex-wrap items-center justify-between gap-3">
          <div className="max-w-3xl">
            <h3 className="text-sm font-semibold uppercase tracking-[0.18em] text-muted">Find Evil</h3>
            <p className="mt-1 text-xs leading-5 text-muted">
              Indicators to review from two sources. Kairon's checks over Volatility's output: processes hidden from the process
              list, with an unexpected parent or masquerading as a system binary, programs run from temporary folders, suspicious
              command lines, injected code and unlinked modules. MemProcFS FindEvil, when its scan finishes: patched modules,
              unusual threads and Defender detections still in memory. They are leads, not verdicts: browsers and JIT runtimes
              produce many low-priority ones on a clean system. The list is sorted with the indicators most worth a look first.
            </p>
          </div>
          <RunPicker runOptions={runOptions} selectedRunId={selectedRunId} onSelectRunId={(next) => { onSelectRunId(next); setPage(1); }} />
        </header>

        <div className="mt-3 flex flex-wrap items-center gap-2 text-xs">
          <div className="flex rounded-xl border border-line bg-abyss/60 p-0.5" role="group" aria-label="Priority">
            {PRIORITIES.map((option) => (
              <button
                key={option.value || "all"}
                type="button"
                aria-pressed={priority === option.value}
                onClick={() => { setPriority(option.value); setPage(1); }}
                className={`rounded-lg px-3 py-1 ${priority === option.value ? "bg-accent/15 text-accent" : "text-muted hover:text-ink"}`}
                data-testid={`findevil-priority-${option.value || "all"}`}
              >
                {option.label}
              </button>
            ))}
          </div>
          <label className="text-muted" htmlFor="findevil-type">Type</label>
          <input
            id="findevil-type"
            value={indicatorType}
            onChange={(event) => { setIndicatorType(event.target.value); setPage(1); }}
            placeholder="PROC_NOLINK"
            className="w-36 rounded-xl border border-line bg-abyss/70 px-2 py-1 font-mono text-sm"
            data-testid="findevil-type-input"
          />
          <label className="text-muted" htmlFor="findevil-pid">PID</label>
          <input
            id="findevil-pid"
            type="number"
            min={0}
            value={pidFilter}
            onChange={(event) => { setPidFilter(event.target.value); setPage(1); }}
            className="w-24 rounded-xl border border-line bg-abyss/70 px-2 py-1 text-sm"
          />
          {filtered ? (
            <button type="button" onClick={() => { setPriority(""); setIndicatorType(""); setPidFilter(""); setPage(1); }} className="rounded-xl border border-line bg-abyss/70 px-3 py-1 text-xs">
              Reset
            </button>
          ) : null}
        </div>

        {activeResultQuery.isLoading ? <p className="mt-3 text-xs text-muted">Loading…</p> : null}
        {activeResultQuery.error instanceof Error ? (
          <p className="mt-3 rounded-2xl border border-rose-400/30 bg-rose-500/10 p-3 text-xs text-rose-200">{activeResultQuery.error.message}</p>
        ) : null}
        {!activeResultQuery.isLoading && !activeResultQuery.error && state === "not_analyzed" ? (
          <p className="mt-3 rounded-2xl border border-line bg-abyss/40 p-3 text-xs text-muted" data-testid="findevil-not-analyzed">
            Find Evil has not been run for this memory image. Run it from the analysis catalogue, or with Run all.
          </p>
        ) : null}
        {!activeResultQuery.isLoading && !activeResultQuery.error && (state === "failed" || state === "latest_attempt_failed") ? (
          <p className="mt-3 rounded-2xl border border-rose-400/30 bg-rose-500/10 p-3 text-xs text-rose-100" data-testid="findevil-failed">
            The latest Find Evil run did not complete. Its status and reason are in the Runs tab.
          </p>
        ) : null}
        {!activeResultQuery.isLoading && !activeResultQuery.error && state === "analyzed_empty" ? (
          <p className="mt-3 rounded-2xl border border-line bg-abyss/40 p-3 text-xs text-muted" data-testid="findevil-empty">
            {filtered ? "No indicator matches these filters." : "Find Evil reported no indicators for this memory image."}
          </p>
        ) : null}

        {!activeResultQuery.isLoading && !activeResultQuery.error && state === "partial" ? (
          <p className="mt-3 rounded-2xl border border-amber-400/30 bg-amber-500/10 p-3 text-xs text-amber-100" data-testid="findevil-partial">
            Part of Find Evil did not finish (the Runs tab says which and why); the indicators below are the ones that did.
          </p>
        ) : null}
        {!activeResultQuery.isLoading && !activeResultQuery.error && (state === "analyzed_with_results" || state === "partial") ? (
          <>
            <p className="mt-3 text-xs text-muted" data-testid="findevil-summary">
              {total} indicator{total === 1 ? "" : "s"} · page {page} of {totalPages}
            </p>
            <div className="mt-2 max-w-full overflow-x-auto rounded-2xl border border-line bg-abyss/40">
              <table className="w-full min-w-[960px] divide-y divide-line text-xs" data-testid="findevil-table">
                <thead className="bg-abyss/70 text-left text-[10px] uppercase tracking-[0.14em] text-muted">
                  <tr>
                    <th className="px-2 py-1">Priority</th>
                    <th className="px-2 py-1">Type</th>
                    <th className="px-2 py-1">PID</th>
                    <th className="px-2 py-1">Process</th>
                    <th className="px-2 py-1">Details</th>
                    <th className="px-2 py-1">What it means</th>
                    <th className="px-2 py-1">Source</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-line">
                  {items.map((row, idx) => (
                    <tr key={row.document_id || `${row.indicator_type}-${row.pid}-${idx}`} data-testid="findevil-row">
                      <td className="px-2 py-1">
                        <span className={`rounded-full border px-2 py-0.5 text-[10px] uppercase tracking-[0.12em] ${PRIORITY_STYLE[String(row.review_priority)] ?? PRIORITY_STYLE.low}`} data-testid="findevil-priority">
                          {reported(row.review_priority)}
                        </span>
                      </td>
                      <td className="px-2 py-1">
                        <button type="button" className="font-mono text-ink hover:text-accent" title="Show only this type" onClick={() => { setIndicatorType(row.indicator_type || ""); setPage(1); }}>
                          {reported(row.indicator_type)}
                        </button>
                      </td>
                      <td className="px-2 py-1 text-muted">{reported(row.pid)}</td>
                      <td className="px-2 py-1 text-ink">{reported(row.process_name)}</td>
                      <td className="max-w-[420px] px-2 py-1 font-mono text-[11px] text-muted">
                        <span className="break-all">{row.description || (row.address && row.address !== "0x0" ? row.address : "—")}</span>
                      </td>
                      <td className="max-w-[360px] px-2 py-1 text-muted">{reported(row.explanation)}</td>
                      <td className="px-2 py-1 text-muted" data-testid="findevil-source">
                        {(row.sources?.length ? row.sources : [row.source_plugin]).map((source) => SOURCE_LABEL[String(source)] ?? reported(source)).join(" + ")}
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
            <div className="mt-3 flex items-center justify-between text-xs">
              <span className="text-muted">
                {items.length === 0 ? "No rows on this page." : `Showing ${(page - 1) * pageSize + 1}-${(page - 1) * pageSize + items.length} of ${total}`}
              </span>
              <MemoryPaginationControls page={page} totalPages={totalPages} onPage={setPage} prevTestId="findevil-prev-page" nextTestId="findevil-next-page" />
            </div>
          </>
        ) : null}
      </section>
    </div>
  );
}
