import { useState } from "react";
import { useQuery } from "@tanstack/react-query";
import { type CommandLineHistoryItem, type MemoryRunSelector, api } from "../../api/client";
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
  working_directory?: string | null;
  recovered_from?: string | null;
  source_plugin?: string | null;
  user?: string | null;
  history_file?: string | null;
  scan_run_id?: string | null;
};

// Where a Windows command was recovered from (windows.consoles / windows.cmdscan): conhost's own
// command history (cmd.exe windows) or the console's screen text after the prompt (PowerShell
// windows keep their history elsewhere, so the screen is often the only place it survives), or
// PowerShell's own history file (PSReadLine), when Windows still had it cached (kairon.psreadline).
const RECOVERED_FROM_LABEL: Record<string, string> = {
  command_history: "Console history",
  screen: "Console screen",
  psreadline_history: "PowerShell history file",
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

function processState(item: CommandLineHistoryItem): string {
  if (item.visibility?.terminated) return "Exited";
  if (item.visibility?.scan_only) return "Not in process list";
  return "Running";
}

// Every process still in memory with its command line: what was executed, whether or not it was
// typed in a shell (programs started by a script, a scheduled task, a service, another program).
function LaunchedCommands({ caseId, evidenceId }: { caseId: string; evidenceId?: string }) {
  const [page, setPage] = useState(1);
  const [search, setSearch] = useState("");
  const pageSize = 50;
  const query = useQuery({
    queryKey: ["memory-command-line-history", caseId, evidenceId, page, search],
    queryFn: () =>
      api.getCommandLineHistory(caseId, {
        evidence_id: evidenceId || "",
        command_contains: search || undefined,
        sort_order: "oldest_first",
        page,
        page_size: pageSize,
      }),
    enabled: Boolean(caseId && evidenceId),
    refetchOnWindowFocus: false,
  });
  const items = query.data?.items ?? [];
  const total = query.data?.total ?? 0;
  const totalPages = Math.max(1, Math.ceil(total / pageSize));
  const analyzed = Boolean(query.data?.selected_run);

  return (
    <section className="rounded-[28px] border border-line bg-panel/60 p-5 shadow-panel" data-testid="shell-history-launched">
      <header className="flex flex-wrap items-center justify-between gap-3">
        <div className="max-w-3xl">
          <h3 className="text-sm font-semibold uppercase tracking-[0.18em] text-muted">Commands executed</h3>
          <p className="mt-1 text-xs text-muted">
            The command line of every process found in memory, in the order they started: what ran, whether it was typed in a
            shell or started by a script, a scheduled task, a service or another program. Processes that had already exited
            but were still found by scanning memory are included.
          </p>
        </div>
        <input
          value={search}
          onChange={(event) => { setSearch(event.target.value); setPage(1); }}
          placeholder="Filter command lines"
          aria-label="Filter command lines"
          className="w-64 rounded-xl border border-line bg-abyss/70 px-2 py-1 text-sm"
          data-testid="shell-history-launched-search"
        />
      </header>

      {query.isLoading ? <p className="mt-3 text-xs text-muted">Loading…</p> : null}
      {query.error instanceof Error ? (
        <p className="mt-3 rounded-2xl border border-rose-400/30 bg-rose-500/10 p-3 text-xs text-rose-200">{query.error.message}</p>
      ) : null}
      {!query.isLoading && !query.error && !analyzed ? (
        <p className="mt-3 rounded-2xl border border-line bg-abyss/40 p-3 text-xs text-muted" data-testid="shell-history-launched-not-analyzed">
          Run the Processes analysis to list the command line of every process in this memory image.
        </p>
      ) : null}
      {!query.isLoading && !query.error && analyzed && items.length === 0 ? (
        <p className="mt-3 rounded-2xl border border-line bg-abyss/40 p-3 text-xs text-muted" data-testid="shell-history-launched-empty">
          {search ? "No command line matches this filter." : "No process command line was recovered from this memory image."}
        </p>
      ) : null}
      {!query.isLoading && !query.error && items.length > 0 ? (
        <>
          <p className="mt-3 text-xs text-muted" data-testid="shell-history-launched-summary">
            {total} command line{total === 1 ? "" : "s"} · page {page} of {totalPages}
          </p>
          <div className="mt-2 max-w-full overflow-x-auto rounded-2xl border border-line bg-abyss/40">
            <table className="w-full min-w-[860px] divide-y divide-line text-xs" data-testid="shell-history-launched-table">
              <thead className="bg-abyss/70 text-left text-[10px] uppercase tracking-[0.14em] text-muted">
                <tr>
                  <th className="px-2 py-1">Started</th>
                  <th className="px-2 py-1">PID</th>
                  <th className="px-2 py-1">Parent</th>
                  <th className="px-2 py-1">Process</th>
                  <th className="px-2 py-1">Command line</th>
                  <th className="px-2 py-1">State</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-line">
                {items.map((item) => (
                  <tr key={item.process_entity_id || `${item.pid}-${item.create_time}`} data-testid="shell-history-launched-row">
                    <td className="whitespace-nowrap px-2 py-1 text-muted">{item.create_time ? item.create_time.replace("T", " ").slice(0, 19) : "—"}</td>
                    <td className="px-2 py-1 text-muted">{reported(item.pid)}</td>
                    <td className="px-2 py-1 text-muted">{reported(item.ppid)}</td>
                    <td className="px-2 py-1 text-ink">{reported(item.process_name)}</td>
                    <td className="px-2 py-1">
                      <CommandCell command={item.command_line} />
                    </td>
                    <td className="whitespace-nowrap px-2 py-1 text-muted">{processState(item)}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
          <div className="mt-3 flex items-center justify-end text-xs">
            <MemoryPaginationControls
              page={page}
              totalPages={totalPages}
              onPage={setPage}
              prevTestId="shell-history-launched-prev-page"
              nextTestId="shell-history-launched-next-page"
            />
          </div>
        </>
      ) : null}
    </section>
  );
}

// PowerShell's own event log records (4104 script blocks, 4103 command invocations, 400/800 engine
// starts) that MemProcFS's forensic scan (Find Evil) recovered from memory. Unlike console history,
// each one has the time PowerShell logged it.
function PowerShellEventLog({ caseId, evidenceId }: { caseId: string; evidenceId?: string }) {
  const [page, setPage] = useState(1);
  const [search, setSearch] = useState("");
  const pageSize = 50;
  const query = useQuery({
    queryKey: ["memory-powershell-log", caseId, evidenceId, page, search],
    queryFn: () => api.getMemoryPowerShellLog(caseId, evidenceId || "", { q: search || undefined, page, page_size: pageSize }),
    enabled: Boolean(caseId && evidenceId),
    refetchOnWindowFocus: false,
  });
  const items = query.data?.items ?? [];
  const total = query.data?.total ?? 0;
  const totalPages = Math.max(1, Math.ceil(total / pageSize));

  return (
    <section className="rounded-[28px] border border-line bg-panel/60 p-5 shadow-panel" data-testid="shell-history-powershell-log">
      <header className="flex flex-wrap items-center justify-between gap-3">
        <div className="max-w-3xl">
          <h3 className="text-sm font-semibold uppercase tracking-[0.18em] text-muted">PowerShell event log</h3>
          <p className="mt-1 text-xs text-muted">
            PowerShell's own event log records still in memory, recovered by MemProcFS's forensic scan (Find Evil): script blocks
            (4104), command invocations (4103) and engine starts with their command line (400, 800). Each has the time
            PowerShell logged it. They are only there when PowerShell logging recorded them.
          </p>
        </div>
        <input
          value={search}
          onChange={(event) => { setSearch(event.target.value); setPage(1); }}
          placeholder="Filter commands"
          aria-label="Filter PowerShell commands"
          className="w-64 rounded-xl border border-line bg-abyss/70 px-2 py-1 text-sm"
          data-testid="shell-history-powershell-search"
        />
      </header>
      {query.isLoading ? <p className="mt-3 text-xs text-muted">Loading…</p> : null}
      {query.error instanceof Error ? (
        <p className="mt-3 rounded-2xl border border-rose-400/30 bg-rose-500/10 p-3 text-xs text-rose-200">{query.error.message}</p>
      ) : null}
      {!query.isLoading && !query.error && items.length === 0 ? (
        <p className="mt-3 rounded-2xl border border-line bg-abyss/40 p-3 text-xs text-muted" data-testid="shell-history-powershell-empty">
          {search ? "No PowerShell record matches this filter." : "No PowerShell event log record was found in this memory image (or Find Evil has not run yet)."}
        </p>
      ) : null}
      {!query.isLoading && !query.error && items.length > 0 ? (
        <>
          <p className="mt-3 text-xs text-muted" data-testid="shell-history-powershell-summary">
            {total} record{total === 1 ? "" : "s"} · page {page} of {totalPages}
          </p>
          <div className="mt-2 max-w-full overflow-x-auto rounded-2xl border border-line bg-abyss/40">
            <table className="w-full min-w-[860px] divide-y divide-line text-xs" data-testid="shell-history-powershell-table">
              <thead className="bg-abyss/70 text-left text-[10px] uppercase tracking-[0.14em] text-muted">
                <tr>
                  <th className="px-2 py-1">Time</th>
                  <th className="px-2 py-1">Event</th>
                  <th className="px-2 py-1">PID</th>
                  <th className="px-2 py-1">Command</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-line">
                {items.map((item) => (
                  <tr key={item.id} data-testid="shell-history-powershell-row">
                    <td className="whitespace-nowrap px-2 py-1 text-muted">{item.timestamp.replace("T", " ").slice(0, 19)}</td>
                    <td className="whitespace-nowrap px-2 py-1 text-muted" title={item.channel || undefined}>
                      {reported(item.event_id)}
                      {item.part ? <span className="block text-[10px]">part {item.part}</span> : null}
                    </td>
                    <td className="px-2 py-1 text-muted">{reported(item.pid)}</td>
                    <td className="px-2 py-1" title={item.host_application || undefined}>
                      <CommandCell command={item.command} />
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
          <div className="mt-3 flex items-center justify-end text-xs">
            <MemoryPaginationControls
              page={page}
              totalPages={totalPages}
              onPage={setPage}
              prevTestId="shell-history-powershell-prev-page"
              nextTestId="shell-history-powershell-next-page"
            />
          </div>
        </>
      ) : null}
    </section>
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
            <h3 className="text-sm font-semibold uppercase tracking-[0.18em] text-muted">Typed in shells</h3>
            <p className="mt-1 text-xs text-muted">
              Commands typed in shells, recovered from memory: bash history on Linux; on Windows, the
              command history of console windows and the commands still visible on their screens
              (cmd.exe and PowerShell). Commands without a recovered timestamp remain valid, searchable
              observations. Everything that ran, typed or not, is listed under Commands executed below.
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
            No typed command was recovered from this memory image: no console window or shell kept one in memory.
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
                    <th className="px-2 py-1">Directory</th>
                    <th className="px-2 py-1">Command</th>
                    <th className="px-2 py-1">Source</th>
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
                      <td className="px-2 py-1 font-mono text-[11px] text-muted" data-testid="shell-history-directory">{reported(row.working_directory)}</td>
                      <td className="px-2 py-1">
                        <CommandCell command={row.command} />
                      </td>
                      <td className="px-2 py-1 text-muted" data-testid="shell-history-source" title={row.history_file || undefined}>
                        {row.recovered_from ? RECOVERED_FROM_LABEL[row.recovered_from] ?? row.recovered_from : reported(row.source_plugin)}
                        {row.user ? <span className="block text-[10px]">{row.user}</span> : null}
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
      <PowerShellEventLog caseId={caseId} evidenceId={evidenceId} />
      <LaunchedCommands caseId={caseId} evidenceId={evidenceId} />
    </div>
  );
}
