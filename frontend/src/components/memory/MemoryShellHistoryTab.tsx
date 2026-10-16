import { useEffect, useMemo, useState } from "react";
import { useQuery } from "@tanstack/react-query";
import { type CommandLineHistoryItem, type MemoryFindEvilProcess, type MemoryPlatformResultViews, type MemoryRunSelector, api } from "../../api/client";
import { type ShellHistorySource, shellHistorySourceApplies } from "../../lib/memoryPlatformViews";
import { FacetSelect, type Facet } from "./FacetSelect";
import { findEvilProcessQueryKey } from "./MemoryFindEvilProcesses";
import { MemoryPaginationControls } from "./MemoryPaginationControls";

type Props = {
  caseId: string;
  evidenceId?: string;
  runOptions: MemoryRunSelector | null;
  selectedRunId: string | null;
  onSelectRunId: (next: string | null) => void;
  // What analysis can produce on this evidence's platform; sources it cannot
  // produce (PowerShell's event log on Linux) are left out. Null keeps them all.
  resultViews?: MemoryPlatformResultViews | null;
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
  // Grouped duplicates: how many times the entry was recovered, and where.
  occurrences?: number;
  pids?: number[];
  sources?: string[];
};

// Where a Windows command was recovered from (windows.consoles / windows.cmdscan): conhost's own
// command history (cmd.exe windows) or the console's screen text after the prompt (PowerShell
// windows keep their history elsewhere, so the screen is often the only place it survives), or
// PowerShell's own history file (PSReadLine), when Windows still had it cached (kairon.psreadline).
const SOURCE_LABEL: Record<string, string> = {
  command_history: "Console history",
  screen: "Console screen",
  psreadline_history: "PowerShell history file",
  "linux.bash": "Bash history",
};

function sourceLabel(value: string | null | undefined): string {
  if (!value) return "—";
  return SOURCE_LABEL[value] ?? value;
}

const INPUT = "rounded-xl border border-line bg-abyss/70 px-2 py-1 text-sm";

function SectionHeader({ title, summary, detail, children }: { title: string; summary: string; detail: string; children?: React.ReactNode }) {
  return (
    <header className="flex flex-wrap items-center justify-between gap-3">
      <div className="max-w-3xl">
        <h3 className="text-sm font-semibold uppercase tracking-[0.18em] text-muted">{title}</h3>
        <p className="mt-1 text-xs text-muted">
          {summary}{" "}
          <span className="cursor-help underline decoration-dotted" title={detail} aria-label={detail}>ⓘ</span>
        </p>
      </div>
      {children}
    </header>
  );
}

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

// Processes Find Evil flagged, by PID, to mark their commands. Empty when
// Find Evil has not run: then nothing is marked.
function useFindEvilByPid(caseId: string, evidenceId?: string): Map<number, MemoryFindEvilProcess> {
  const query = useQuery({
    queryKey: findEvilProcessQueryKey(caseId, evidenceId),
    queryFn: () => api.getMemoryFindEvilProcesses(caseId, evidenceId || ""),
    enabled: Boolean(caseId && evidenceId),
    refetchOnWindowFocus: false,
    retry: false,
  });
  return useMemo(() => {
    const map = new Map<number, MemoryFindEvilProcess>();
    for (const process of query.data?.processes ?? []) {
      if (process.pid !== null) map.set(process.pid, process);
    }
    return map;
  }, [query.data]);
}

const FIND_EVIL_TONE: Record<string, string> = {
  high: "border-rose-400/40 bg-rose-500/10 text-rose-100",
  medium: "border-amber-400/40 bg-amber-500/10 text-amber-100",
  low: "border-line bg-abyss/70 text-muted",
};

function FindEvilMark({ pids, byPid }: { pids: Array<number | null | undefined>; byPid: Map<number, MemoryFindEvilProcess> }) {
  const flagged = pids.map((pid) => (pid === null || pid === undefined ? undefined : byPid.get(pid))).filter(Boolean) as MemoryFindEvilProcess[];
  if (!flagged.length) return null;
  const rank = { high: 3, medium: 2, low: 1 } as Record<string, number>;
  const top = flagged.reduce((best, p) => ((rank[p.top_priority ?? ""] ?? 0) > (rank[best.top_priority ?? ""] ?? 0) ? p : best));
  const count = flagged.reduce((sum, p) => sum + p.indicator_count, 0);
  return (
    <span
      className={`ml-1 inline-block rounded-full border px-1.5 py-0.5 text-[10px] ${FIND_EVIL_TONE[top.top_priority ?? "low"] ?? FIND_EVIL_TONE.low}`}
      title={`Find Evil found ${count} indicator${count === 1 ? "" : "s"} in ${flagged.map((p) => `${p.process_name ?? "process"} (${p.pid})`).join(", ")}. See the Find Evil tab.`}
      data-testid="shell-history-findevil"
    >
      Find Evil{top.top_priority ? ` · ${top.top_priority}` : ""}
    </span>
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

type SectionProps = { caseId: string; evidenceId?: string; onTotal: (total: number | null) => void };

// Every process still in memory with its command line: what was executed, whether or not it was
// typed in a shell (programs started by a script, a scheduled task, a service, another program).
function LaunchedCommands({ caseId, evidenceId, onTotal }: SectionProps) {
  const [page, setPage] = useState(1);
  const [search, setSearch] = useState("");
  const [visibility, setVisibility] = useState("");
  const [ppid, setPpid] = useState("");
  const [sortOrder, setSortOrder] = useState<"oldest_first" | "newest_first">("oldest_first");
  // Start-time range (UTC); only processes known to have started inside it.
  const [timeFrom, setTimeFrom] = useState("");
  const [timeTo, setTimeTo] = useState("");
  const findEvil = useFindEvilByPid(caseId, evidenceId);
  // Command lines that differ only in numbers (service hosts, kernel workers)
  // are one row with their count, run-once ones first.
  const [grouped, setGrouped] = useState(true);
  const pageSize = 50;
  const query = useQuery({
    queryKey: ["memory-command-line-history", caseId, evidenceId, page, search, visibility, ppid, sortOrder, grouped, timeFrom, timeTo],
    queryFn: () =>
      api.getCommandLineHistory(caseId, {
        evidence_id: evidenceId || "",
        command_contains: search || undefined,
        visibility: visibility || undefined,
        ppid: ppid ? Number(ppid) : undefined,
        sort_order: sortOrder,
        group_identical: grouped || undefined,
        time_from: timeFrom || undefined,
        time_to: timeTo ? `${timeTo}:59` : undefined,
        page,
        page_size: pageSize,
      }),
    enabled: Boolean(caseId && evidenceId),
    refetchOnWindowFocus: false,
    placeholderData: (previous) => previous,
  });
  const items = query.data?.items ?? [];
  const total = query.data?.total ?? 0;
  const totalPages = Math.max(1, Math.ceil(total / pageSize));
  const analyzed = Boolean(query.data?.selected_run);
  const filtered = Boolean(search || visibility || ppid || timeFrom || timeTo);
  useEffect(() => {
    if (query.data) onTotal(analyzed ? total : null);
  }, [query.data, analyzed, total, onTotal]);

  function reset() {
    setSearch("");
    setVisibility("");
    setPpid("");
    setTimeFrom("");
    setTimeTo("");
    setPage(1);
  }

  return (
    <section className="rounded-[28px] border border-line bg-panel/60 p-5 shadow-panel" data-testid="shell-history-launched">
      <SectionHeader
        title="Commands executed"
        summary="The command line of every process found in memory."
        detail="In the order they started: what ran, whether typed in a shell or started by a script, a scheduled task, a service or another program. Processes that had already exited but were still found by scanning memory are included."
      />
      <div className="mt-3 flex flex-wrap items-center gap-2 text-xs">
        <input
          value={search}
          onChange={(event) => { setSearch(event.target.value); setPage(1); }}
          placeholder="Search command lines"
          aria-label="Filter command lines"
          className={`w-64 ${INPUT}`}
          data-testid="shell-history-launched-search"
        />
        <select
          value={visibility}
          onChange={(event) => { setVisibility(event.target.value); setPage(1); }}
          aria-label="Process state"
          className={INPUT}
          data-testid="shell-history-launched-state"
        >
          <option value="">Any state</option>
          <option value="listed">Running</option>
          <option value="terminated">Exited</option>
          <option value="scan_only">Not in process list</option>
        </select>
        <input
          type="number"
          min={0}
          value={ppid}
          onChange={(event) => { setPpid(event.target.value); setPage(1); }}
          placeholder="Parent PID"
          aria-label="Parent PID"
          className={`w-28 ${INPUT}`}
          data-testid="shell-history-launched-ppid"
        />
        <label className="flex items-center gap-1 text-muted">
          Started from
          <input
            type="datetime-local"
            value={timeFrom}
            onChange={(event) => { setTimeFrom(event.target.value); setPage(1); }}
            aria-label="Started from (UTC)"
            className={INPUT}
            data-testid="shell-history-launched-from"
          />
        </label>
        <label className="flex items-center gap-1 text-muted">
          to
          <input
            type="datetime-local"
            value={timeTo}
            onChange={(event) => { setTimeTo(event.target.value); setPage(1); }}
            aria-label="Started to (UTC)"
            className={INPUT}
            data-testid="shell-history-launched-to"
          />
          <span className="text-[10px]">UTC</span>
        </label>
        <label className="flex items-center gap-1 text-muted">
          <input
            type="checkbox"
            checked={grouped}
            onChange={(event) => { setGrouped(event.target.checked); setPage(1); }}
            data-testid="shell-history-launched-grouped"
          />
          Group similar
        </label>
        {!grouped ? (
          <select
            value={sortOrder}
            onChange={(event) => { setSortOrder(event.target.value as "oldest_first" | "newest_first"); setPage(1); }}
            aria-label="Order"
            className={INPUT}
            data-testid="shell-history-launched-order"
          >
            <option value="oldest_first">Oldest first</option>
            <option value="newest_first">Newest first</option>
          </select>
        ) : null}
        {filtered ? (
          <button type="button" onClick={reset} className="rounded-xl border border-line bg-abyss/70 px-3 py-1 text-xs" data-testid="shell-history-launched-reset">
            Reset
          </button>
        ) : null}
      </div>

      {query.isLoading ? <p className="mt-3 text-xs text-muted">Loading…</p> : null}
      {query.error instanceof Error ? (
        <p className="mt-3 rounded-2xl border border-rose-400/30 bg-rose-500/10 p-3 text-xs text-rose-200">{query.error.message}</p>
      ) : null}
      {!query.isLoading && !query.error && !analyzed ? (
        <p className="mt-3 text-xs text-muted" data-testid="shell-history-launched-not-analyzed">
          Run the Processes analysis to list the command line of every process in this memory image.
        </p>
      ) : null}
      {!query.isLoading && !query.error && analyzed && items.length === 0 ? (
        <p className="mt-3 text-xs text-muted" data-testid="shell-history-launched-empty">
          {filtered ? "No command line matches these filters." : "No process command line was recovered from this memory image."}
        </p>
      ) : null}
      {!query.isLoading && !query.error && items.length > 0 ? (
        <>
          <p className="mt-3 text-xs text-muted" data-testid="shell-history-launched-summary">
            {total} {query.data?.grouped ? "distinct command line" : "command line"}{total === 1 ? "" : "s"}
            {query.data?.grouped ? " (similar ones grouped, run fewest times first)" : ""} · page {page} of {totalPages}
          </p>
          {query.data?.grouped ? (
            <div className="mt-2 max-w-full overflow-x-auto rounded-2xl border border-line bg-abyss/40">
              <table className="w-full min-w-[860px] divide-y divide-line text-xs" data-testid="shell-history-launched-grouped-table">
                <thead className="bg-abyss/70 text-left text-[10px] uppercase tracking-[0.14em] text-muted">
                  <tr>
                    <th className="px-2 py-1 text-right">Times</th>
                    <th className="px-2 py-1">Command line</th>
                    <th className="px-2 py-1">Process</th>
                    <th className="px-2 py-1">PIDs</th>
                    <th className="px-2 py-1">First started</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-line">
                  {items.map((item) => (
                    <tr key={item.process_entity_id || item.command_line} data-testid="shell-history-launched-group-row">
                      <td className="px-2 py-1 text-right tabular-nums text-ink">{item.count ?? 1}</td>
                      <td className="px-2 py-1">
                        <CommandCell command={item.command_line} />
                        {(item.variants ?? 1) > 1 ? (
                          <span className="text-[10px] text-muted" data-testid="shell-history-launched-variants">
                            {item.variants} variants differing only in numbers
                          </span>
                        ) : null}
                      </td>
                      <td className="px-2 py-1 text-ink">
                        {(item.process_names ?? [item.process_name]).filter(Boolean).join(", ") || "—"}
                        <FindEvilMark pids={item.pids ?? [item.pid]} byPid={findEvil} />
                      </td>
                      <td className="px-2 py-1 text-muted">
                        {(item.pids ?? []).slice(0, 5).join(", ")}
                        {(item.pids?.length ?? 0) > 5 ? ` +${(item.pids?.length ?? 0) - 5}` : ""}
                      </td>
                      <td className="whitespace-nowrap px-2 py-1 text-muted">{item.first_start ? item.first_start.replace("T", " ").slice(0, 19) : "—"}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          ) : (
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
                    <td className="px-2 py-1 text-muted">
                      {item.ppid !== null && item.ppid !== undefined ? (
                        <button
                          type="button"
                          onClick={() => { setPpid(String(item.ppid)); setPage(1); }}
                          className="hover:text-accent"
                          title="Show the commands started by this parent"
                        >
                          {item.ppid}
                        </button>
                      ) : "—"}
                    </td>
                    <td className="px-2 py-1 text-ink">
                      {reported(item.process_name)}
                      <FindEvilMark pids={[item.pid]} byPid={findEvil} />
                    </td>
                    <td className="px-2 py-1">
                      <CommandCell command={item.command_line} />
                    </td>
                    <td className="whitespace-nowrap px-2 py-1 text-muted">{processState(item)}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
          )}
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
function PowerShellEventLog({ caseId, evidenceId, onTotal }: SectionProps) {
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
  useEffect(() => {
    if (query.data) onTotal(total);
  }, [query.data, total, onTotal]);

  return (
    <section className="rounded-[28px] border border-line bg-panel/60 p-5 shadow-panel" data-testid="shell-history-powershell-log">
      <SectionHeader
        title="PowerShell event log"
        summary="PowerShell's own event log records still in memory, each with the time it was logged."
        detail="Recovered by MemProcFS's forensic scan (Find Evil): script blocks (4104), command invocations (4103) and engine starts with their command line (400, 800). They are only there when PowerShell logging recorded them."
      >
        <input
          value={search}
          onChange={(event) => { setSearch(event.target.value); setPage(1); }}
          placeholder="Search commands"
          aria-label="Filter PowerShell commands"
          className={`w-64 ${INPUT}`}
          data-testid="shell-history-powershell-search"
        />
      </SectionHeader>
      {query.isLoading ? <p className="mt-3 text-xs text-muted">Loading…</p> : null}
      {query.error instanceof Error ? (
        <p className="mt-3 rounded-2xl border border-rose-400/30 bg-rose-500/10 p-3 text-xs text-rose-200">{query.error.message}</p>
      ) : null}
      {!query.isLoading && !query.error && items.length === 0 ? (
        <p className="mt-3 text-xs text-muted" data-testid="shell-history-powershell-empty">
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

type TypedProps = SectionProps & {
  runOptions: MemoryRunSelector | null;
  selectedRunId: string | null;
  onSelectRunId: (next: string | null) => void;
};

function TypedCommands({ caseId, evidenceId, runOptions, selectedRunId, onSelectRunId, onTotal }: TypedProps) {
  const [page, setPage] = useState(1);
  const [search, setSearch] = useState("");
  const [source, setSource] = useState("");
  const [pidFilter, setPidFilter] = useState("");
  const [processNameFilter, setProcessNameFilter] = useState("");
  const [userFilter, setUserFilter] = useState("");
  const [datedFilter, setDatedFilter] = useState<"" | "dated" | "undated">("");
  // Every shell loads the same history file, and a console keeps a command in
  // its history and on screen: one row per (command, time) by default.
  const [groupDuplicates, setGroupDuplicates] = useState(true);
  const findEvil = useFindEvilByPid(caseId, evidenceId);
  const pageSize = 50;

  const activeResultQuery = useQuery({
    queryKey: ["memory-active-result", caseId, evidenceId, "shell_history", selectedRunId, page, search, source, pidFilter, processNameFilter, userFilter, datedFilter, groupDuplicates],
    queryFn: () =>
      api.getMemoryActiveResult(caseId, evidenceId || "", "shell_history", selectedRunId || undefined, {
        command: search || undefined,
        source: source || undefined,
        pid: pidFilter ? Number(pidFilter) : undefined,
        process_name: processNameFilter || undefined,
        user: userFilter || undefined,
        dated: datedFilter || undefined,
        group_duplicates: groupDuplicates || undefined,
        facet_fields: ["user"],
        page,
        page_size: pageSize,
      }),
    enabled: Boolean(caseId && evidenceId),
    refetchOnWindowFocus: false,
    // Keep the previous page (and its filter options) while a new filter loads.
    placeholderData: (previous) => previous,
  });

  const result = activeResultQuery.data;
  const items = (result?.items ?? []) as ShellHistoryRow[];
  const total = result?.total ?? 0;
  const totalPages = Math.max(1, Math.ceil(total / pageSize));
  const state = result?.analysis_state ?? "not_analyzed";
  const sourceFacets = (result as { source_facets?: Array<{ value: string; count: number }> } | undefined)?.source_facets ?? [];
  const userFacets: Facet[] = (result as { facets?: Record<string, Facet[]> } | undefined)?.facets?.user ?? [];
  const datedCounts = (result as { dated_counts?: { dated: number; undated: number } | null } | undefined)?.dated_counts ?? null;
  const grouped = Boolean((result as { grouped?: boolean } | undefined)?.grouped);
  const ungroupedTotal = (result as { ungrouped_total?: number } | undefined)?.ungrouped_total ?? total;
  const filtered = Boolean(search || source || pidFilter || processNameFilter || userFilter || datedFilter);
  const hasRows = state === "analyzed_with_results" || state === "partial";
  useEffect(() => {
    if (result) onTotal(hasRows ? total : state === "analyzed_empty" ? 0 : null);
  }, [result, hasRows, total, state, onTotal]);

  function resetFilters() {
    setSearch("");
    setSource("");
    setPidFilter("");
    setProcessNameFilter("");
    setUserFilter("");
    setDatedFilter("");
    setPage(1);
  }

  return (
    <section className="rounded-[28px] border border-line bg-panel/60 p-5 shadow-panel" data-testid="shell-history-typed">
      <SectionHeader
        title="Typed in shells"
        summary="Commands typed in shells, recovered from memory."
        detail="Bash history on Linux; on Windows, the command history of console windows, the commands still visible on their screens (cmd.exe and PowerShell) and PowerShell's history file. Commands without a recovered timestamp remain valid, searchable observations."
      >
        <RunPicker runOptions={runOptions} selectedRunId={selectedRunId} onSelectRunId={(next) => { onSelectRunId(next); setPage(1); }} />
      </SectionHeader>

      {hasRows || filtered ? (
        <div className="mt-3 flex flex-wrap items-center gap-2 text-xs">
          <input
            value={search}
            onChange={(event) => { setSearch(event.target.value); setPage(1); }}
            placeholder="Search commands"
            aria-label="Search typed commands"
            className={`w-64 ${INPUT}`}
            data-testid="shell-history-command-input"
          />
          {sourceFacets.length > 1 || source ? (
            <select
              value={source}
              onChange={(event) => { setSource(event.target.value); setPage(1); }}
              aria-label="Source"
              className={INPUT}
              data-testid="shell-history-source-select"
            >
              <option value="">All sources</option>
              {sourceFacets.map((facet) => (
                <option key={facet.value} value={facet.value}>
                  {sourceLabel(facet.value)} ({facet.count})
                </option>
              ))}
            </select>
          ) : null}
          <input
            id="shell-history-pid"
            type="number"
            min={0}
            value={pidFilter}
            onChange={(event) => { setPidFilter(event.target.value); setPage(1); }}
            placeholder="PID"
            aria-label="PID"
            className={`w-24 ${INPUT}`}
            data-testid="shell-history-pid-input"
          />
          <input
            id="shell-history-process"
            value={processNameFilter}
            onChange={(event) => { setProcessNameFilter(event.target.value); setPage(1); }}
            placeholder="Process"
            aria-label="Process"
            className={`w-36 ${INPUT}`}
            data-testid="shell-history-process-input"
          />
          {userFacets.length > 1 || userFilter ? (
            <FacetSelect
              value={userFilter}
              onChange={(next) => { setUserFilter(next); setPage(1); }}
              facets={userFacets}
              allLabel="Any user"
              ariaLabel="User"
              testId="shell-history-user-select"
              className={INPUT}
            />
          ) : null}
          {(datedCounts && datedCounts.dated > 0 && datedCounts.undated > 0) || datedFilter ? (
            <select
              value={datedFilter}
              onChange={(event) => { setDatedFilter(event.target.value as "" | "dated" | "undated"); setPage(1); }}
              aria-label="Recovered time"
              className={INPUT}
              data-testid="shell-history-dated-select"
            >
              <option value="">With or without time</option>
              <option value="dated">With time ({datedCounts?.dated ?? 0})</option>
              <option value="undated">Without time ({datedCounts?.undated ?? 0})</option>
            </select>
          ) : null}
          <label className="flex items-center gap-1 text-muted">
            <input
              type="checkbox"
              checked={groupDuplicates}
              onChange={(event) => { setGroupDuplicates(event.target.checked); setPage(1); }}
              data-testid="shell-history-group-duplicates"
            />
            Group duplicates
          </label>
          {filtered ? (
            <button
              type="button"
              onClick={resetFilters}
              className="rounded-xl border border-line bg-abyss/70 px-3 py-1 text-xs"
              data-testid="shell-history-reset-filters"
            >
              Reset
            </button>
          ) : null}
        </div>
      ) : null}

      {activeResultQuery.isLoading ? <p className="mt-3 text-xs text-muted">Loading…</p> : null}
      {activeResultQuery.error instanceof Error ? (
        <p className="mt-3 rounded-2xl border border-rose-400/30 bg-rose-500/10 p-3 text-xs text-rose-200">
          {activeResultQuery.error.message}
        </p>
      ) : null}

      {!activeResultQuery.isLoading && !activeResultQuery.error && state === "not_analyzed" ? (
        <p className="mt-3 text-xs text-muted" data-testid="shell-history-empty-not-analyzed">
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
        <p className="mt-3 text-xs text-muted" data-testid="shell-history-empty-zero-results">
          No typed command was recovered from this memory image: no console window or shell kept one in memory.
        </p>
      ) : null}

      {!activeResultQuery.isLoading && !activeResultQuery.error && hasRows && items.length === 0 ? (
        <p className="mt-3 text-xs text-muted" data-testid="shell-history-no-match">No typed command matches these filters.</p>
      ) : null}

      {!activeResultQuery.isLoading && !activeResultQuery.error && hasRows && items.length > 0 ? (
        <>
          <p className="mt-3 text-xs text-muted" data-testid="shell-history-summary">
            {total} command{total === 1 ? "" : "s"}
            {grouped && ungroupedTotal > total ? ` (${ungroupedTotal} recovered; the same command and time found in several processes or sources is one row)` : ""}
            {" · "}page {page} of {totalPages}
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
                    <td className="px-2 py-1 text-muted" data-testid="shell-history-pid">
                      {row.pids && row.pids.length > 1 ? row.pids.join(", ") : reported(row.pid)}
                    </td>
                    <td className="px-2 py-1 text-ink">
                      {reported(row.process_name)}
                      {(row.occurrences ?? 1) > 1 ? (
                        <span className="ml-1 text-[10px] text-muted" title="Recovered this many times" data-testid="shell-history-occurrences">×{row.occurrences}</span>
                      ) : null}
                      <FindEvilMark pids={row.pids ?? [row.pid]} byPid={findEvil} />
                    </td>
                    <td className="px-2 py-1 font-mono text-[11px] text-muted" data-testid="shell-history-directory">{reported(row.working_directory)}</td>
                    <td className="px-2 py-1">
                      <CommandCell command={row.command} />
                    </td>
                    <td className="px-2 py-1 text-muted" data-testid="shell-history-source" title={row.history_file || undefined}>
                      {row.sources && row.sources.length > 1 ? row.sources.map(sourceLabel).join(", ") : sourceLabel(row.recovered_from || row.source_plugin)}
                      {row.user ? <span className="block text-[10px]">{row.user}</span> : null}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
          <div className="mt-3 flex items-center justify-between text-xs" data-testid="shell-history-pagination">
            <span className="text-muted">
              {`Showing ${(page - 1) * pageSize + 1}-${(page - 1) * pageSize + items.length} of ${total}`}
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
  );
}

const SOURCE_TITLES: Record<ShellHistorySource, string> = {
  typed: "Typed in shells",
  powershell: "PowerShell event log",
  executed: "Commands executed",
};

/**
 * One source at a time. Each tab shows how many records its source has, so
 * the analyst sees where there is something without scrolling past empty
 * tables; the first source with records opens by default. Sources the
 * evidence's platform cannot produce are not offered.
 */
export function MemoryShellHistoryTab({ caseId, evidenceId, runOptions, selectedRunId, onSelectRunId, resultViews = null }: Props) {
  const sources = (["typed", "powershell", "executed"] as ShellHistorySource[]).filter((source) =>
    shellHistorySourceApplies(source, resultViews),
  );
  const [totals, setTotals] = useState<Partial<Record<ShellHistorySource, number | null>>>({});
  const [chosen, setChosen] = useState<ShellHistorySource | null>(null);
  const reporters = useReporters(setTotals);

  const allReported = sources.every((source) => source in totals);
  const firstWithRecords = sources.find((source) => (totals[source] ?? 0) > 0) ?? sources[0];
  const active = chosen && sources.includes(chosen) ? chosen : allReported ? firstWithRecords : sources[0];

  return (
    <div className="space-y-4" data-testid="memory-shell-history-tab">
      <nav className="flex flex-wrap gap-2" role="tablist" aria-label="Shell history sources" data-testid="shell-history-sources">
        {sources.map((source) => {
          const total = totals[source];
          const selected = source === active;
          return (
            <button
              key={source}
              type="button"
              role="tab"
              aria-selected={selected}
              onClick={() => setChosen(source)}
              className={`rounded-xl border px-3 py-1.5 text-xs ${
                selected ? "border-accent/50 bg-accent/15 text-ink" : total === 0 || total === null ? "border-line bg-abyss/40 text-muted/70" : "border-line bg-abyss/70 text-muted"
              }`}
              data-testid={`shell-history-source-tab-${source}`}
            >
              {SOURCE_TITLES[source]}
              <span className="ml-1.5 tabular-nums" data-testid={`shell-history-source-count-${source}`}>
                {total === undefined ? "…" : total === null ? "—" : total.toLocaleString("en-US")}
              </span>
            </button>
          );
        })}
      </nav>
      <div hidden={active !== "typed"}>
        <TypedCommands
          caseId={caseId}
          evidenceId={evidenceId}
          runOptions={runOptions}
          selectedRunId={selectedRunId}
          onSelectRunId={onSelectRunId}
          onTotal={reporters.typed}
        />
      </div>
      {sources.includes("powershell") ? (
        <div hidden={active !== "powershell"}>
          <PowerShellEventLog caseId={caseId} evidenceId={evidenceId} onTotal={reporters.powershell} />
        </div>
      ) : null}
      <div hidden={active !== "executed"}>
        <LaunchedCommands caseId={caseId} evidenceId={evidenceId} onTotal={reporters.executed} />
      </div>
    </div>
  );
}

// Stable per-source callbacks, so a section's effect does not re-run on every render.
function useReporters(setTotals: React.Dispatch<React.SetStateAction<Partial<Record<ShellHistorySource, number | null>>>>) {
  const [reporters] = useState(() => {
    const make = (source: ShellHistorySource) => (total: number | null) =>
      setTotals((prev) => (prev[source] === total && source in prev ? prev : { ...prev, [source]: total }));
    return { typed: make("typed"), powershell: make("powershell"), executed: make("executed") };
  });
  return reporters;
}
