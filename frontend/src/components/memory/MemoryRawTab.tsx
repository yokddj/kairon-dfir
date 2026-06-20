import { useState } from "react";
import { useQueries, useQuery } from "@tanstack/react-query";
import { type MemoryProcess, type MemoryProcessList, type MemoryRunSelector, api } from "../../api/client";

type Props = {
  caseId: string;
  runOptions: MemoryRunSelector | null;
  selectedRunId: string | null;
  onSelectRunId: (next: string | null) => void;
};

type PluginFilter = "all" | "windows.pslist" | "windows.psscan" | "windows.pstree" | "windows.cmdline";

function reported(value: unknown): string {
  if (value === null || value === undefined || value === "") return "Not reported";
  return String(value);
}

function sourceBadge(plugin: string): string {
  return plugin.replace("windows.", "");
}

export function MemoryRawTab({ caseId, runOptions, selectedRunId, onSelectRunId }: Props) {
  const effectiveRunId = selectedRunId || runOptions?.default_run_id || null;
  const [plugin, setPlugin] = useState<PluginFilter>("all");
  const [pid, setPid] = useState("");
  const [processName, setProcessName] = useState("");
  const [showTree, setShowTree] = useState(false);

  const processQuery = useQuery({
    queryKey: ["raw-processes", caseId, effectiveRunId, plugin, pid, processName],
    queryFn: () => {
      const params: { run_id?: string; pid?: number; process_name?: string; page: number; page_size: number; source_plugin?: string } = {
        run_id: effectiveRunId || undefined,
        page: 1,
        page_size: 50,
      };
      if (plugin !== "all") params.source_plugin = plugin;
      if (pid) params.pid = Number(pid);
      if (processName) params.process_name = processName;
      return api.getCaseMemoryProcesses(caseId, params as any) as Promise<MemoryProcessList>;
    },
    enabled: Boolean(effectiveRunId),
    refetchOnWindowFocus: false,
  });

  const treeQuery = useQuery({
    queryKey: ["raw-tree", effectiveRunId],
    queryFn: () => api.getMemoryProcessTree(effectiveRunId as string),
    enabled: Boolean(effectiveRunId && showTree),
    refetchOnWindowFocus: false,
  });

  return (
    <div className="space-y-4" data-testid="memory-raw-tab">
      <section className="rounded-[28px] border border-line bg-panel/60 p-5 shadow-panel">
        <header className="flex flex-wrap items-center justify-between gap-3">
          <div>
            <h3 className="text-sm font-semibold uppercase tracking-[0.18em] text-muted">Raw plugin observations</h3>
            <p className="mt-1 text-xs text-muted">
              These records preserve plugin-level provenance and may contain duplicate observations for the same canonical process.
              Use the canonical Processes tab for the deduplicated entity model.
            </p>
          </div>
          <div className="flex flex-wrap items-center gap-2 text-xs">
            <label className="text-muted" htmlFor="raw-run-picker">Run</label>
            <select
              id="raw-run-picker"
              value={effectiveRunId || ""}
              onChange={(event) => onSelectRunId(event.target.value || null)}
              className="rounded-xl border border-line bg-abyss/70 px-2 py-1 text-sm"
              data-testid="raw-run-picker"
            >
              <option value="">Latest</option>
              {(runOptions?.runs || []).map((run) => (
                <option key={run.run_id} value={run.run_id}>
                  {run.profile} · {run.status}
                </option>
              ))}
            </select>
            <label className="text-muted" htmlFor="raw-plugin">Plugin</label>
            <select
              id="raw-plugin"
              value={plugin}
              onChange={(event) => setPlugin(event.target.value as PluginFilter)}
              className="rounded-xl border border-line bg-abyss/70 px-2 py-1 text-sm"
              data-testid="raw-plugin-filter"
            >
              <option value="all">All</option>
              <option value="windows.pslist">pslist</option>
              <option value="windows.psscan">psscan</option>
              <option value="windows.pstree">pstree</option>
              <option value="windows.cmdline">cmdline</option>
            </select>
          </div>
        </header>

        <div className="mt-3 flex flex-wrap items-center gap-2 text-xs">
          <label className="text-muted" htmlFor="raw-pid">PID</label>
          <input
            id="raw-pid"
            type="number"
            min={0}
            value={pid}
            onChange={(event) => setPid(event.target.value)}
            className="w-24 rounded-xl border border-line bg-abyss/70 px-2 py-1 text-sm"
            data-testid="raw-pid-input"
          />
          <label className="text-muted" htmlFor="raw-name">Process name</label>
          <input
            id="raw-name"
            value={processName}
            onChange={(event) => setProcessName(event.target.value)}
            className="rounded-xl border border-line bg-abyss/70 px-2 py-1 text-sm"
            data-testid="raw-name-input"
          />
          <button
            type="button"
            onClick={() => setShowTree((value) => !value)}
            aria-expanded={showTree}
            className="rounded-xl border border-line bg-abyss/70 px-3 py-1 text-xs"
            data-testid="raw-toggle-tree"
          >
            {showTree ? "Hide raw process tree" : "View raw process tree"}
          </button>
        </div>

        {processQuery.isLoading ? <p className="mt-3 text-xs text-muted">Loading…</p> : null}
        {processQuery.error instanceof Error ? (
          <p className="mt-3 rounded-2xl border border-rose-400/30 bg-rose-500/10 p-3 text-xs text-rose-200">
            {processQuery.error.message}
          </p>
        ) : null}
        {processQuery.data ? (
          <>
            <p className="mt-3 text-xs text-muted">
              {processQuery.data.total} raw rows · showing first 50 (legacy per-plugin layout).
            </p>
            <div className="mt-2 overflow-x-auto">
              <table className="min-w-full divide-y divide-line text-xs" data-testid="raw-table">
                <thead className="bg-abyss/70 text-left text-[10px] uppercase tracking-[0.14em] text-muted">
                  <tr>
                    <th className="px-2 py-1">Plugin</th>
                    <th className="px-2 py-1">PID</th>
                    <th className="px-2 py-1">PPID</th>
                    <th className="px-2 py-1">Name</th>
                    <th className="px-2 py-1">Command line</th>
                    <th className="px-2 py-1">Create</th>
                    <th className="px-2 py-1">Exit</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-line">
                  {processQuery.data.items.map((row: MemoryProcess) => (
                    <tr key={row.document_id || `${row.memory_run_id}-${row.process?.pid}-${row.plugins?.[0]}`}>
                      <td className="px-2 py-1 text-ink">{(row.plugins || []).map(sourceBadge).join(", ") || "—"}</td>
                      <td className="px-2 py-1 text-muted">{reported((row.process as any)?.pid)}</td>
                      <td className="px-2 py-1 text-muted">{reported((row.process as any)?.ppid)}</td>
                      <td className="px-2 py-1 text-ink">{reported((row.process as any)?.name)}</td>
                      <td className="px-2 py-1 text-muted">{reported((row.process as any)?.command_line)}</td>
                      <td className="px-2 py-1 text-muted">{reported((row.process as any)?.create_time)}</td>
                      <td className="px-2 py-1 text-muted">{reported((row.process as any)?.exit_time)}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </>
        ) : null}

        {showTree ? (
          <div className="mt-4">
            <h4 className="text-xs font-semibold uppercase tracking-[0.18em] text-muted">Raw process tree</h4>
            {treeQuery.isLoading ? <p className="mt-2 text-xs text-muted">Loading…</p> : null}
            {treeQuery.error instanceof Error ? (
              <p className="mt-2 rounded-2xl border border-rose-400/30 bg-rose-500/10 p-3 text-xs text-rose-200">
                {treeQuery.error.message}
              </p>
            ) : treeQuery.data ? (
              <p className="mt-2 text-xs text-muted">
                Total {treeQuery.data.total_process_count} · Roots {treeQuery.data.root_count} · Orphans {treeQuery.data.orphan_count} · Sources {treeQuery.data.source_plugins.map(sourceBadge).join(", ")}
              </p>
            ) : null}
          </div>
        ) : null}
      </section>
    </div>
  );
}
