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

type ShellHistoryRow = {
  document_id?: string;
  pid?: number | null;
  process_name?: string | null;
  command?: string | null;
  command_time?: string | null;
  source_plugin?: string | null;
  scan_run_id?: string | null;
};

function reported(value: unknown): string {
  if (value === null || value === undefined || value === "") return "—";
  return String(value);
}

function copyText(value: string) {
  if (typeof navigator !== "undefined" && navigator.clipboard) {
    navigator.clipboard.writeText(value).catch(() => undefined);
  }
}

function CommandCell({ command }: { command: string | null | undefined }) {
  const [copied, setCopied] = useState(false);
  if (!command) return <span className="text-muted">—</span>;
  return (
    <div className="flex max-w-[560px] items-start gap-2">
      <span className="whitespace-pre-wrap break-all font-mono text-xs text-ink" data-testid="shell-history-command-text">
        {command}
      </span>
      <button
        type="button"
        onClick={() => {
          copyText(command);
          setCopied(true);
          window.setTimeout(() => setCopied(false), 1500);
        }}
        className="shrink-0 rounded-md border border-line bg-abyss/70 px-1.5 py-0.5 text-[10px] text-muted hover:text-ink"
        data-testid="shell-history-copy-command"
        title="Copy command"
      >
        {copied ? "Copied" : "Copy"}
      </button>
    </div>
  );
}

function RunPicker({
  runOptions,
  selectedRunId,
  onSelectRunId,
}: {
  runOptions: MemoryRunSelector | null;
  selectedRunId: string | null;
  onSelectRunId: (next: string | null) => void;
}) {
  const runs = (runOptions?.runs || []).filter((r) => r.profile === "shell_history_basic");
  return (
    <div className="flex flex-wrap items-center gap-2 text-xs">
      <label className="text-muted" htmlFor="shell-history-run-picker">Run</label>
      <select
        id="shell-history-run-picker"
        value={selectedRunId || ""}
        onChange={(event) => onSelectRunId(event.target.value || null)}
        className="rounded-xl border border-line bg-abyss/70 px-2 py-1 text-sm"
        data-testid="shell-history-run-picker"
      >
        <option value="">Latest</option>
        {runs.map((run) => (
          <option key={run.run_id} value={run.run_id}>
            {run.profile} · {run.status} · {(run.completed_at || run.created_at).slice(0, 16).replace("T", " ")} UTC
          </option>
        ))}
      </select>
    </div>
  );
}

export function MemoryShellHistoryTab({ caseId, evidenceId, runOptions, selectedRunId, onSelectRunId }: Props) {
  const [page, setPage] = useState(1);
  const [pidFilter, setPidFilter] = useState("");
  const [processNameFilter, setProcessNameFilter] = useState("");
  const pageSize = 50;

  const activeResultQuery = useQuery({
    queryKey: ["memory-active-result", caseId, evidenceId, "shell_history", selectedRunId, page, pidFilter, processNameFilter],
    queryFn: () =>
      api.getMemoryActiveResult(caseId, evidenceId || "", "shell_history", selectedRunId || undefined, {
        pid: pidFilter ? Number(pidFilter) : undefined,
        process_name: processNameFilter || undefined,
        page,
        page_size: pageSize,
      }),
    enabled: Boolean(caseId && evidenceId),
    refetchOnWindowFocus: false,
  });

  const result = activeResultQuery.data;
  const items = (result?.items ?? []) as ShellHistoryRow[];
  const total = result?.total ?? 0;
  const totalPages = Math.max(1, Math.ceil(total / pageSize));
  const state = result?.analysis_state ?? "not_analyzed";

  function resetFilters() {
    setPidFilter("");
    setProcessNameFilter("");
    setPage(1);
  }

  return (
    <div className="space-y-4" data-testid="memory-shell-history-tab">
      <section className="rounded-[28px] border border-line bg-panel/60 p-5 shadow-panel">
        <header className="flex flex-wrap items-center justify-between gap-3">
          <div>
            <h3 className="text-sm font-semibold uppercase tracking-[0.18em] text-muted">Shell History</h3>
            <p className="mt-1 text-xs text-muted">
              Interactive shell command history recovered from memory (linux.bash on Linux evidence,
              windows.consoles on Windows evidence). Commands without a recovered timestamp remain
              valid, searchable observations.
            </p>
          </div>
          <RunPicker runOptions={runOptions} selectedRunId={selectedRunId} onSelectRunId={(next) => { onSelectRunId(next); setPage(1); }} />
        </header>

        <div className="mt-3 flex flex-wrap items-center gap-2 text-xs">
          <label className="text-muted" htmlFor="shell-history-pid">PID</label>
          <input
            id="shell-history-pid"
            type="number"
            min={0}
            value={pidFilter}
            onChange={(event) => { setPidFilter(event.target.value); setPage(1); }}
            className="w-24 rounded-xl border border-line bg-abyss/70 px-2 py-1 text-sm"
            data-testid="shell-history-pid-input"
          />
          <label className="text-muted" htmlFor="shell-history-process">Process</label>
          <input
            id="shell-history-process"
            value={processNameFilter}
            onChange={(event) => { setProcessNameFilter(event.target.value); setPage(1); }}
            className="rounded-xl border border-line bg-abyss/70 px-2 py-1 text-sm"
            data-testid="shell-history-process-input"
          />
          <button
            type="button"
            onClick={resetFilters}
            className="rounded-xl border border-line bg-abyss/70 px-3 py-1 text-xs"
            data-testid="shell-history-reset-filters"
          >
            Reset
          </button>
        </div>

        {activeResultQuery.isLoading ? <p className="mt-3 text-xs text-muted">Loading…</p> : null}
        {activeResultQuery.error instanceof Error ? (
          <p className="mt-3 rounded-2xl border border-rose-400/30 bg-rose-500/10 p-3 text-xs text-rose-200">
            {activeResultQuery.error.message}
          </p>
        ) : null}

        {!activeResultQuery.isLoading && !activeResultQuery.error && state === "not_analyzed" ? (
          <p className="mt-3 rounded-2xl border border-line bg-abyss/40 p-3 text-xs text-muted" data-testid="shell-history-empty-not-analyzed">
            Shell History has not been analyzed yet.
          </p>
        ) : null}

        {!activeResultQuery.isLoading && !activeResultQuery.error && (state === "failed" || state === "latest_attempt_failed") ? (
          <div className="mt-3 rounded-2xl border border-rose-400/30 bg-rose-500/10 p-3 text-xs text-rose-100" data-testid="shell-history-empty-failed">
            <p>The latest Shell History run did not complete successfully.</p>
            {result?.latest_attempt?.status ? <p className="mt-1 text-rose-200">Latest attempt status: {result.latest_attempt.status}</p> : null}
          </div>
        ) : null}

        {!activeResultQuery.isLoading && !activeResultQuery.error && state === "analyzed_empty" ? (
          <p className="mt-3 rounded-2xl border border-line bg-abyss/40 p-3 text-xs text-muted" data-testid="shell-history-empty-zero-results">
            No shell history was recovered from this memory image.
          </p>
        ) : null}

        {!activeResultQuery.isLoading && !activeResultQuery.error && (state === "analyzed_with_results" || state === "partial") ? (
          <>
            <p className="mt-3 text-xs text-muted" data-testid="shell-history-summary">
              {total} command{total === 1 ? "" : "s"} · page {page} of {totalPages}
            </p>
            <div className="mt-2 max-w-full overflow-x-auto rounded-2xl border border-line bg-abyss/40">
              <table className="min-w-[860px] w-full divide-y divide-line text-xs" data-testid="shell-history-table">
                <thead className="bg-abyss/70 text-left text-[10px] uppercase tracking-[0.14em] text-muted">
                  <tr>
                    <th className="px-2 py-1">Time</th>
                    <th className="px-2 py-1">PID</th>
                    <th className="px-2 py-1">Process</th>
                    <th className="px-2 py-1">Command</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-line">
                  {items.map((row, idx) => (
                    <tr key={row.document_id || `${row.scan_run_id}-${row.pid}-${idx}`} data-testid="shell-history-row">
                      <td className="px-2 py-1 text-muted" data-testid="shell-history-time">
                        {row.command_time ? reported(row.command_time) : <span className="text-muted" data-testid="shell-history-undated">Undated</span>}
                      </td>
                      <td className="px-2 py-1 text-muted">{reported(row.pid)}</td>
                      <td className="px-2 py-1 text-ink">{reported(row.process_name)}</td>
                      <td className="px-2 py-1">
                        <CommandCell command={row.command} />
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
            <div className="mt-3 flex items-center justify-between text-xs" data-testid="shell-history-pagination">
              <span className="text-muted">
                {items.length === 0 ? "No rows on this page." : `Showing ${(page - 1) * pageSize + 1}-${(page - 1) * pageSize + items.length} of ${total}`}
              </span>
              <MemoryPaginationControls
                page={page}
                totalPages={totalPages}
                onPage={setPage}
                prevTestId="shell-history-prev-page"
                nextTestId="shell-history-next-page"
              />
            </div>
          </>
        ) : null}
      </section>
    </div>
  );
}
