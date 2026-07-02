import { useState } from "react";
import { useQuery } from "@tanstack/react-query";
import { api, type CommandLineHistoryItem, type CommandLineHistoryResponse, type MemoryRunSelector } from "../../api/client";
import { ArrowUpDown, Copy, ExternalLink, Search, Filter, X } from "lucide-react";

type Props = {
  caseId: string;
  evidenceId: string;
  runId: string | null;
  runOptions: MemoryRunSelector | null;
  selectedRunId: string | null;
  onSelectRunId: (next: string | null) => void;
  onFocusGraph?: (entityId: string) => void;
  onInspectProcess?: (entityId: string) => void;
};



export function MemoryCommandLineHistoryTab({
  caseId,
  evidenceId,
  runId: _runId,
  runOptions,
  selectedRunId,
  onSelectRunId: _onSelectRunId,
  onFocusGraph,
  onInspectProcess,
}: Props) {
  const [page, setPage] = useState(1);
  const [pidFilter, setPidFilter] = useState("");
  const [ppidFilter, setPpidFilter] = useState("");
  const [nameFilter, setNameFilter] = useState("");
  const [cmdFilter, setCmdFilter] = useState("");
  const [sortOrder, setSortOrder] = useState("oldest_first");
  const [pageSize, setPageSize] = useState(100);

  const PAGE_SIZES = [50, 100, 250, 500];

  const effectiveRunId = _runId || selectedRunId || runOptions?.default_run_id || null;
  const params = {
    evidence_id: evidenceId,
    run_id: effectiveRunId ?? undefined,
    pid: pidFilter ? Number(pidFilter) : undefined,
    ppid: ppidFilter ? Number(ppidFilter) : undefined,
    process_name: nameFilter || undefined,
    command_contains: cmdFilter || undefined,
    sort_order: sortOrder,
    page,
    page_size: pageSize,
  };

  const query = useQuery<CommandLineHistoryResponse>({
    queryKey: ["memory-command-line-history", caseId, evidenceId, effectiveRunId, page, pageSize, pidFilter, ppidFilter, nameFilter, cmdFilter, sortOrder],
    queryFn: () => api.getCommandLineHistory(caseId, params as never),
    enabled: Boolean(caseId && evidenceId),
    refetchOnWindowFocus: false,
  });

  const data = query.data;
  const items = data?.items ?? [];
  const total = data?.total ?? 0;
  const totalPages = Math.max(1, Math.ceil(total / pageSize));
  const unknownTimestamps = data?.coverage?.unknown_timestamps ?? 0;

  function resetFilters() {
    setPidFilter("");
    setPpidFilter("");
    setNameFilter("");
    setCmdFilter("");
    setPage(1);
  }

  return (
    <div className="space-y-4" data-testid="memory-command-line-history-tab">
      <div className="rounded-[28px] border border-line bg-panel/60 p-5 shadow-panel">
        <h2 className="text-lg font-semibold">Command Line History</h2>
        <p className="mt-1 text-xs text-muted">
          Observed process command lines ordered by process creation time. This is not necessarily the complete interactive shell history.
        </p>

        {/* Filters */}
        <div className="mt-4 flex flex-wrap items-center gap-2">
          <input
            type="number"
            placeholder="PID"
            value={pidFilter}
            onChange={(e) => { setPidFilter(e.target.value); setPage(1); }}
            className="w-24 rounded-xl border border-line bg-abyss/80 px-3 py-1.5 text-xs outline-none"
            data-testid="history-filter-pid"
          />
          <input
            type="number"
            placeholder="PPID"
            value={ppidFilter}
            onChange={(e) => { setPpidFilter(e.target.value); setPage(1); }}
            className="w-24 rounded-xl border border-line bg-abyss/80 px-3 py-1.5 text-xs outline-none"
            data-testid="history-filter-ppid"
          />
          <input
            type="text"
            placeholder="Process name"
            value={nameFilter}
            onChange={(e) => { setNameFilter(e.target.value); setPage(1); }}
            className="w-40 rounded-xl border border-line bg-abyss/80 px-3 py-1.5 text-xs outline-none"
            data-testid="history-filter-name"
          />
          <input
            type="text"
            placeholder="Command contains"
            value={cmdFilter}
            onChange={(e) => { setCmdFilter(e.target.value); setPage(1); }}
            className="w-48 rounded-xl border border-line bg-abyss/80 px-3 py-1.5 text-xs outline-none"
            data-testid="history-filter-cmd"
          />
          <button
            type="button"
            onClick={() => setSortOrder(sortOrder === "oldest_first" ? "newest_first" : "oldest_first")}
            className="flex items-center gap-1 rounded-xl border border-line bg-abyss/70 px-3 py-1.5 text-xs text-muted"
            data-testid="history-sort-toggle"
          >
            <ArrowUpDown className="h-3 w-3" /> {sortOrder === "oldest_first" ? "Oldest first" : "Newest first"}
          </button>
          {(pidFilter || ppidFilter || nameFilter || cmdFilter) ? (
            <button
              type="button"
              onClick={resetFilters}
              className="flex items-center gap-1 rounded-xl border border-line bg-abyss/70 px-3 py-1.5 text-xs text-muted"
              data-testid="history-reset-filters"
            >
              <X className="h-3 w-3" /> Reset
            </button>
          ) : null}
          <select
            value={pageSize}
            onChange={(e) => { setPageSize(Number(e.target.value)); setPage(1); }}
            className="ml-auto rounded-xl border border-line bg-abyss/70 px-3 py-1.5 text-xs text-muted outline-none"
            data-testid="history-page-size"
          >
            {PAGE_SIZES.map((s) => <option key={s} value={s}>{s} per page</option>)}
          </select>
        </div>

        {/* Content */}
        <div className="mt-4">
          {query.isLoading ? (
            <p className="text-sm text-muted" role="status">Loading command-line history…</p>
          ) : query.isError ? (
            <p className="rounded-xl border border-rose-400/30 bg-rose-500/10 p-3 text-sm text-rose-100">
              Failed to load command-line history.
            </p>
          ) : items.length === 0 ? (
            <p className="text-sm text-muted">
              {effectiveRunId
                ? "No command-line observations found for the selected run. Run a profile containing windows.cmdline first."
                : "No completed process run available for this Evidence."}
            </p>
          ) : (
            <>
              <div className="mb-2 text-[10px] text-muted">
                {total} command line{total !== 1 ? "s" : ""}
                {unknownTimestamps > 0 ? ` · ${unknownTimestamps} with unknown timestamp` : ""}
                {data?.selected_run ? ` · Run: ${data.selected_run.profile}` : ""}
              </div>
              <PaginationTop page={page} totalPages={totalPages} total={total} pageSize={pageSize} setPage={setPage} />
              <div className="max-w-full overflow-x-auto rounded-2xl border border-line bg-abyss/40">
                <table className="min-w-[900px] w-full divide-y divide-line text-xs">
                  <thead className="bg-abyss/70 text-left text-[10px] uppercase tracking-[0.14em] text-muted">
                    <tr>
                      <th className="px-2 py-2">Time</th>
                      <th className="px-2 py-2">PID</th>
                      <th className="px-2 py-2">PPID</th>
                      <th className="px-2 py-2">Process</th>
                      <th className="px-2 py-2">Command line</th>
                      <th className="px-2 py-2">Sources</th>
                      <th className="px-2 py-2">Actions</th>
                    </tr>
                  </thead>
                  <tbody className="divide-y divide-line/60">
                    {items.map((row) => (
                      <tr key={row.process_entity_id + "-" + row.create_time} className="hover:bg-abyss/30" data-testid="history-row">
                        <td className="px-2 py-1.5 font-mono whitespace-nowrap text-muted">
                          {row.create_time ? row.create_time.replace("T", " ").substring(0, 19) : <span className="italic text-amber-200/70">Unknown</span>}
                        </td>
                        <td className="px-2 py-1.5 font-mono text-ink">{row.pid ?? "—"}</td>
                        <td className="px-2 py-1.5 font-mono text-muted">{row.ppid ?? "—"}</td>
                        <td className="px-2 py-1.5 font-medium text-ink">{row.process_name ?? "—"}</td>
                        <td className="px-2 py-1.5 font-mono text-muted max-w-md truncate" title={row.command_line}>{row.command_line}</td>
                        <td className="px-2 py-1.5 text-muted text-[10px]">{(row.source_plugins || []).map((p) => p.replace("windows.", "")).join(", ")}</td>
                        <td className="px-2 py-1.5">
                          <div className="flex gap-1">
                            {onInspectProcess ? (
                              <button type="button" onClick={() => onInspectProcess(row.process_entity_id)} className="rounded border border-line bg-abyss/70 px-1.5 py-0.5 text-[10px] text-accent" title="Inspect process" data-testid="history-inspect">
                                Inspect
                              </button>
                            ) : null}
                            {onFocusGraph ? (
                              <button type="button" onClick={() => onFocusGraph(row.process_entity_id)} className="rounded border border-line bg-abyss/70 px-1.5 py-0.5 text-[10px] text-accent" title="Focus in graph" data-testid="history-focus-graph">
                                Graph
                              </button>
                            ) : null}
                            <button type="button" onClick={() => { void navigator.clipboard.writeText(row.command_line); }} className="rounded border border-line bg-abyss/70 px-1.5 py-0.5 text-[10px] text-muted" title="Copy command line" data-testid="history-copy">
                              Copy
                            </button>
                          </div>
                        </td>
                      </tr>
                    ))}
            </tbody>
          </table>
        </div>
        <PaginationBottom page={page} totalPages={totalPages} total={total} pageSize={pageSize} setPage={setPage} />
            </>
          )}
        </div>
      </div>
    </div>
  );
}

function PaginationTop({ page, totalPages, total, pageSize, setPage }: { page: number; totalPages: number; total: number; pageSize: number; setPage: (p: number) => void }) {
  const start = (page - 1) * pageSize + 1;
  const end = Math.min(page * pageSize, total);
  return (
    <div className="flex items-center justify-between text-[10px] text-muted mb-2" data-testid="history-pagination-top">
      <span>{start}&ndash;{end} of {total}</span>
      <div className="flex items-center gap-1">
        <button disabled={page <= 1} onClick={() => setPage(Math.max(1, page - 1))} className="rounded border border-line bg-abyss/70 px-2 py-0.5 disabled:opacity-40" data-testid="history-prev-top">Previous</button>
        <span>Page {page} of {totalPages}</span>
        <button disabled={page >= totalPages} onClick={() => setPage(page + 1)} className="rounded border border-line bg-abyss/70 px-2 py-0.5 disabled:opacity-40" data-testid="history-next-top">Next</button>
      </div>
    </div>
  );
}

function PaginationBottom({ page, totalPages, total, pageSize, setPage }: { page: number; totalPages: number; total: number; pageSize: number; setPage: (p: number) => void }) {
  const start = (page - 1) * pageSize + 1;
  const end = Math.min(page * pageSize, total);
  return (
    <div className="mt-3 flex items-center justify-between text-xs" data-testid="history-pagination-bottom">
      <span className="text-muted">{start}&ndash;{end} of {total}</span>
      <div className="flex items-center gap-2">
        <button disabled={page <= 1} onClick={() => setPage(Math.max(1, page - 1))} className="rounded-xl border border-line bg-abyss/70 px-3 py-1.5 disabled:opacity-40" data-testid="history-prev">Previous</button>
        <span className="text-muted">Page {page} of {totalPages}</span>
        <button disabled={page >= totalPages} onClick={() => setPage(page + 1)} className="rounded-xl border border-line bg-abyss/70 px-3 py-1.5 disabled:opacity-40" data-testid="history-next">Next</button>
      </div>
    </div>
  );
}
