import { useMemo, useState } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import {
  type MemoryProcessEntity,
  type MemoryProcessEntityDetail,
  type MemoryProcessEntityList,
  type MemoryProcessTreeEntity,
  type MemoryRenormalizeSummary,
  type MemoryRunSelector,
  api,
} from "../api/client";
import { MemoryProcessGraph } from "./MemoryProcessGraph";
import {
  buildRunOptions,
  confidenceTone,
  findingLabel,
  flattenTreeToRows,
  formatTreeNodeForTable,
  observationsToRows,
  reported,
  sourcePluginBadge,
  summarizeRenormalization,
  visibilityLabel,
  visibilityTone,
} from "../lib/memoryCanonical";

type VisibilityFilter = "listed" | "scan_only" | "terminated" | "unknown" | "hidden_candidate" | "";
type SourcePluginFilter = "windows.pslist" | "windows.psscan" | "windows.pstree" | "windows.cmdline" | "";
type InterestingFilter = "scan_only" | "hidden_candidate" | "missing_parent" | "name_conflict" | "command_line_missing" | "";

const TONE_CLASS: Record<string, string> = {
  good: "border-emerald-400/30 bg-emerald-500/10 text-emerald-100",
  warn: "border-amber-400/30 bg-amber-500/10 text-amber-100",
  danger: "border-rose-400/30 bg-rose-500/10 text-rose-100",
  info: "border-sky-400/30 bg-sky-500/10 text-sky-100",
  neutral: "border-line bg-abyss/70 text-muted",
};

type MemoryCanonicalViewProps = {
  caseId: string;
  runId?: string | null;
  processName?: string;
  onProcessName?: (next: string) => void;
  pidFilter?: string;
  onPidFilter?: (next: string) => void;
  selectedEntityId?: string | null;
  onSelectEntityId?: (next: string | null) => void;
};

export function MemoryCanonicalView({
  caseId,
  runId,
  processName: externalProcessName,
  onProcessName: externalOnProcessName,
  pidFilter: externalPidFilter,
  onPidFilter: externalOnPidFilter,
  selectedEntityId: externalSelectedEntityId,
  onSelectEntityId: externalOnSelectEntityId,
}: MemoryCanonicalViewProps) {
  const queryClient = useQueryClient();
  const [selectedRunId, setSelectedRunId] = useState<string | null>(null);
  const [visibility, setVisibility] = useState<VisibilityFilter>("");
  const [sourcePlugin, setSourcePlugin] = useState<SourcePluginFilter>("");
  const [internalProcessName, setInternalProcessName] = useState("");
  const [internalPidFilter, setInternalPidFilter] = useState("");
  const [interestingOnly, setInterestingOnly] = useState<InterestingFilter>("");
  const [page, setPage] = useState(1);
  const pageSize = 50;
  const [internalSelectedEntityId, setInternalSelectedEntityId] = useState<string | null>(null);
  const [dryRunMessage, setDryRunMessage] = useState<string | null>(null);
  const [applyMessage, setApplyMessage] = useState<string | null>(null);

  const processName = externalProcessName ?? internalProcessName;
  const setProcessName = externalOnProcessName ?? setInternalProcessName;
  const pidFilter = externalPidFilter ?? internalPidFilter;
  const setPidFilter = externalOnPidFilter ?? setInternalPidFilter;
  const selectedEntityId =
    externalSelectedEntityId !== undefined ? externalSelectedEntityId : internalSelectedEntityId;
  const setSelectedEntityId = externalOnSelectEntityId ?? setInternalSelectedEntityId;

  const runOptionsQuery = useQuery({
    queryKey: ["memory-run-options", caseId],
    queryFn: () => api.getMemoryRunOptions(caseId),
    enabled: Boolean(caseId),
    refetchOnWindowFocus: false,
  });

  const runSelector: MemoryRunSelector | undefined = runOptionsQuery.data;
  const effectiveRunId = runId || selectedRunId || runSelector?.default_run_id || null;
  const runOptionsList = useMemo(() => buildRunOptions(runSelector?.runs, effectiveRunId), [runSelector, effectiveRunId]);

  const entitiesQuery = useQuery({
    queryKey: ["canonical-entities", caseId, effectiveRunId, visibility, sourcePlugin, processName, pidFilter, interestingOnly, page],
    queryFn: () =>
      api.getCanonicalProcessEntities(caseId, {
        run_id: effectiveRunId || undefined,
        visibility: (visibility || undefined) as any,
        source_plugin: (sourcePlugin || undefined) as any,
        // Prefer the exact PID filter when set; the API uses an
        // exact match so typing 11184 selects the unique entity
        // and never falls back to a name substring search.
        pid: pidFilter ? Number(pidFilter) : undefined,
        process_name: processName || undefined,
        interesting_only: interestingOnly ? true : undefined,
        page,
        page_size: pageSize,
      }),
    enabled: Boolean(caseId && effectiveRunId),
    refetchOnWindowFocus: false,
  });

  const summaryQuery = useQuery({
    queryKey: ["canonical-summary", caseId, effectiveRunId],
    queryFn: () => api.getCanonicalProcessSummary(caseId, { run_id: effectiveRunId || undefined }),
    enabled: Boolean(caseId && effectiveRunId),
    refetchOnWindowFocus: false,
  });

  const treeQuery = useQuery({
    queryKey: ["canonical-tree", caseId, effectiveRunId, visibility, interestingOnly],
    queryFn: () =>
      api.getCanonicalProcessTree(caseId, {
        run_id: effectiveRunId || undefined,
        visibility: (visibility || undefined) as any,
        interesting_only: interestingOnly ? true : undefined,
        depth: 4,
      }),
    enabled: Boolean(caseId && effectiveRunId),
    refetchOnWindowFocus: false,
  });

  const detailQuery = useQuery({
    queryKey: ["canonical-entity-detail", caseId, selectedEntityId, effectiveRunId],
    queryFn: () => api.getCanonicalProcessEntityDetail(caseId, selectedEntityId as string, effectiveRunId || undefined),
    enabled: Boolean(caseId && selectedEntityId),
    refetchOnWindowFocus: false,
  });

  const renormalizeDryMutation = useMutation({
    mutationFn: () => api.renormalizeProcessEntities(caseId, effectiveRunId as string, true),
    onSuccess: (summary: MemoryRenormalizeSummary) => {
      const s = summarizeRenormalization(summary);
      setDryRunMessage(
        `Dry-run: ${s.totalEntities} canonical entities from ${summary.source_documents} source documents. ` +
          `Collapsed ${s.collapsed} duplicates. Roots=${s.roots} Orphans=${s.orphans} UnknownParent=${s.unknownParent}. ` +
          `ScanOnly=${s.scanOnly} HiddenCandidates=${s.hiddenCandidate} Terminated=${s.terminated}. ` +
          `PID 0=${s.pidZero} PID 4=${s.pid4}.`,
      );
    },
  });

  const renormalizeApplyMutation = useMutation({
    mutationFn: () => api.renormalizeProcessEntities(caseId, effectiveRunId as string, false),
    onSuccess: (summary: MemoryRenormalizeSummary) => {
      const s = summarizeRenormalization(summary);
      setApplyMessage(
        `Applied: ${s.totalEntities} canonical entities. Materialization version ${summary.normalization_version}.`,
      );
      queryClient.invalidateQueries({ queryKey: ["canonical-entities", caseId] });
      queryClient.invalidateQueries({ queryKey: ["canonical-summary", caseId] });
      queryClient.invalidateQueries({ queryKey: ["canonical-tree", caseId] });
    },
  });

  const list = entitiesQuery.data;
  const tree = treeQuery.data;
  const summary = summaryQuery.data;
  const detail = detailQuery.data;

  return (
    <section className="rounded-[28px] border border-line bg-panel/60 p-5 space-y-4">
      <header className="flex flex-wrap items-start justify-between gap-3">
        <div>
          <h3 className="text-lg font-semibold">Memory processes · canonical view</h3>
          <p className="mt-1 text-sm text-muted">
            One row per real process. Plugin results are observations, not duplicate processes.
            Run selection is explicit; mixed-run views require an opt-in.
          </p>
        </div>
        <div className="flex flex-wrap gap-2">
          <button
            type="button"
            onClick={() => renormalizeDryMutation.mutate()}
            disabled={!effectiveRunId || renormalizeDryMutation.isPending}
            className="rounded-xl border border-line bg-abyss/70 px-3 py-2 text-xs text-muted disabled:opacity-50"
          >
            {renormalizeDryMutation.isPending ? "Running dry-run..." : "Dry-run renormalize"}
          </button>
          <button
            type="button"
            onClick={() => renormalizeApplyMutation.mutate()}
            disabled={!effectiveRunId || renormalizeApplyMutation.isPending}
            className="rounded-xl bg-accent px-3 py-2 text-xs font-semibold text-abyss disabled:opacity-50"
          >
            {renormalizeApplyMutation.isPending ? "Applying..." : "Apply renormalization"}
          </button>
        </div>
      </header>

      {dryRunMessage ? <p className="rounded-2xl border border-sky-400/30 bg-sky-500/10 p-3 text-xs text-sky-100">{dryRunMessage}</p> : null}
      {applyMessage ? <p className="rounded-2xl border border-emerald-400/30 bg-emerald-500/10 p-3 text-xs text-emerald-100">{applyMessage}</p> : null}
      {renormalizeDryMutation.error instanceof Error ? <p className="text-xs text-rose-200">{renormalizeDryMutation.error.message}</p> : null}
      {renormalizeApplyMutation.error instanceof Error ? <p className="text-xs text-rose-200">{renormalizeApplyMutation.error.message}</p> : null}

      <div className="grid gap-3 md:grid-cols-4">
        <div className="rounded-2xl border border-line bg-abyss/60 p-4">
          <p className="text-xs uppercase tracking-[0.16em] text-muted">Run selector</p>
          <select
            value={effectiveRunId || ""}
            onChange={(event) => {
              setSelectedRunId(event.target.value || null);
              setPage(1);
            }}
            className="mt-2 w-full rounded-xl border border-line bg-abyss/70 px-3 py-2 text-sm"
          >
            {runOptionsList.length === 0 ? <option value="">No runs available</option> : null}
            {runOptionsList.map((opt) => (
              <option key={opt.runId} value={opt.runId}>
                {opt.label}
              </option>
            ))}
          </select>
        </div>
        <div className="rounded-2xl border border-line bg-abyss/60 p-4">
          <p className="text-xs uppercase tracking-[0.16em] text-muted">Visibility</p>
          <select
            value={visibility}
            onChange={(event) => {
              setVisibility(event.target.value as VisibilityFilter);
              setPage(1);
            }}
            className="mt-2 w-full rounded-xl border border-line bg-abyss/70 px-3 py-2 text-sm"
          >
            <option value="">All</option>
            <option value="listed">Listed</option>
            <option value="scan_only">Scan only</option>
            <option value="terminated">Terminated</option>
            <option value="unknown">Unknown</option>
            <option value="hidden_candidate">Hidden candidate</option>
          </select>
        </div>
        <div className="rounded-2xl border border-line bg-abyss/60 p-4">
          <p className="text-xs uppercase tracking-[0.16em] text-muted">Source plugin</p>
          <select
            value={sourcePlugin}
            onChange={(event) => {
              setSourcePlugin(event.target.value as SourcePluginFilter);
              setPage(1);
            }}
            className="mt-2 w-full rounded-xl border border-line bg-abyss/70 px-3 py-2 text-sm"
          >
            <option value="">All</option>
            <option value="windows.pslist">pslist</option>
            <option value="windows.psscan">psscan</option>
            <option value="windows.pstree">pstree</option>
            <option value="windows.cmdline">cmdline</option>
          </select>
        </div>
        <div className="rounded-2xl border border-line bg-abyss/60 p-4">
          <p className="text-xs uppercase tracking-[0.16em] text-muted">Interesting only</p>
          <select
            value={interestingOnly}
            onChange={(event) => {
              setInterestingOnly(event.target.value as InterestingFilter);
              setPage(1);
            }}
            className="mt-2 w-full rounded-xl border border-line bg-abyss/70 px-3 py-2 text-sm"
          >
            <option value="">Off</option>
            <option value="scan_only">Scan only</option>
            <option value="hidden_candidate">Hidden candidate</option>
            <option value="missing_parent">Missing parent</option>
            <option value="name_conflict">Name conflict</option>
            <option value="command_line_missing">Command line missing</option>
          </select>
        </div>
      </div>

      <div className="flex flex-wrap gap-2">
        <input
          value={pidFilter}
          onChange={(event) => {
            const v = event.target.value.trim();
            // Accept only digits; the API requires an exact PID.
            if (v && !/^\d+$/.test(v)) return;
            setPidFilter(v);
            setPage(1);
            // Selecting a PID also selects the exact entity once the
            // table reloads, so Processes and Graph stay in sync.
            if (v) {
              setProcessName("");
            }
          }}
          placeholder="Search by exact PID (e.g. 11184)"
          inputMode="numeric"
          data-testid="memory-canonical-pid-filter"
          aria-label="Search by exact PID"
          className="w-64 rounded-xl border border-line bg-abyss/70 px-3 py-2 text-sm outline-none"
        />
        <input
          value={processName}
          onChange={(event) => {
            setProcessName(event.target.value);
            setPage(1);
            if (event.target.value) {
              setPidFilter("");
            }
          }}
          placeholder="Filter by process name"
          className="w-64 rounded-xl border border-line bg-abyss/70 px-3 py-2 text-sm outline-none"
        />
      </div>

      {summary ? (
        <div className="grid gap-2 md:grid-cols-6 text-xs">
          <SummaryStat label="Entities" value={summary.candidate_entities} />
          <SummaryStat label="Observations" value={summary.observation_count} />
          <SummaryStat label="Collapsed" value={summary.duplicate_groups_collapsed} />
          <SummaryStat label="Roots" value={summary.tree_metrics.roots} />
          <SummaryStat label="Orphans" value={summary.tree_metrics.orphans} />
          <SummaryStat label="UnknownParent" value={summary.tree_metrics.unknown_parent} />
          <SummaryStat label="ScanOnly" value={summary.tree_metrics.scan_only} />
          <SummaryStat label="Hidden" value={summary.tree_metrics.hidden_candidates} />
          <SummaryStat label="Terminated" value={summary.tree_metrics.terminated} />
          <SummaryStat label="PID 0" value={summary.tree_metrics.pid_zero_count} />
          <SummaryStat label="PID 4" value={summary.tree_metrics.pid_4_count} />
          <SummaryStat label="Cycles" value={summary.tree_metrics.cycles} />
        </div>
      ) : null}

      <ProcessTable
        list={list}
        isLoading={entitiesQuery.isLoading}
        onSelect={(entityId) => setSelectedEntityId(entityId)}
        onPage={setPage}
        page={page}
        pageSize={pageSize}
      />

      {detail ? <ProcessDetailPanel detail={detail} onClose={() => setSelectedEntityId(null)} /> : null}

      <MemoryProcessGraph
        caseId={caseId}
        runId={effectiveRunId}
        onOpenDetail={(entityId) => setSelectedEntityId(entityId)}
      />

      <ProcessTreePanel tree={tree} onSelect={(entityId) => setSelectedEntityId(entityId)} />
    </section>
  );
}

function SummaryStat({ label, value }: { label: string; value: number }) {
  return (
    <div className="rounded-xl border border-line bg-abyss/60 px-3 py-2">
      <p className="text-[10px] uppercase tracking-[0.18em] text-muted">{label}</p>
      <p className="mt-1 text-base font-semibold text-ink">{value}</p>
    </div>
  );
}

function ProcessTable({
  list,
  isLoading,
  onSelect,
  onPage,
  page,
  pageSize,
}: {
  list: MemoryProcessEntityList | undefined;
  isLoading: boolean;
  onSelect: (entityId: string) => void;
  onPage: (page: number) => void;
  page: number;
  pageSize: number;
}) {
  if (isLoading) {
    return <p className="text-sm text-muted">Loading canonical processes...</p>;
  }
  if (!list) {
    return <p className="text-sm text-muted">No canonical data yet.</p>;
  }
  if (list.items.length === 0) {
    return (
      <p className="rounded-2xl border border-amber-400/30 bg-amber-500/10 p-4 text-sm text-amber-100">
        No canonical process entities for the current run. Run the dry-run or apply renormalization
        to materialize canonical entities from the existing plugin observations.
      </p>
    );
  }
  return (
    <div className="max-w-full overflow-x-auto" data-testid="canonical-process-table-container">
      <table className="min-w-[1100px] w-full divide-y divide-line text-sm" data-testid="canonical-process-table">
        <thead className="sticky top-0 z-10 bg-abyss/90 backdrop-blur text-left text-xs uppercase tracking-[0.14em] text-muted">
          <tr>
            <th className="sticky left-0 z-20 bg-abyss/90 px-4 py-3 text-left">PID</th>
            <th className="px-4 py-3">PPID</th>
            <th className="px-4 py-3">Process</th>
            <th className="px-4 py-3">Command line</th>
            <th className="px-4 py-3 hidden md:table-cell">Created</th>
            <th className="px-4 py-3 hidden md:table-cell">Exited</th>
            <th className="px-4 py-3 hidden lg:table-cell">Sources</th>
            <th className="px-4 py-3">Visibility</th>
            <th className="px-4 py-3 hidden lg:table-cell">Findings</th>
            <th className="px-4 py-3">Actions</th>
          </tr>
        </thead>
        <tbody className="divide-y divide-line">
          {list.items.map((entity) => (
            <tr key={entity.process_entity_id} data-testid="canonical-process-row">
              <td className="sticky left-0 z-10 bg-abyss/95 px-4 py-3 font-mono text-xs text-ink">
                {reported(entity.process.pid)}
              </td>
              <td className="px-4 py-3 text-muted">{reported(entity.process.ppid)}</td>
              <td className="px-4 py-3 text-ink">{reported(entity.process.name)}</td>
              <td className="max-w-[420px] truncate px-4 py-3 text-muted" title={reported(entity.process.command_line)}>
                {reported(entity.process.command_line)}
              </td>
              <td className="hidden px-4 py-3 text-muted md:table-cell">{reported(entity.process.create_time)}</td>
              <td className="hidden px-4 py-3 text-muted md:table-cell">{reported(entity.process.exit_time)}</td>
              <td className="hidden px-4 py-3 lg:table-cell">
                <div className="flex flex-wrap gap-1">
                  {(entity.sources || []).map((plugin) => (
                    <span key={plugin} className={`rounded-md border px-1.5 py-0.5 text-[10px] ${TONE_CLASS[plugin === "windows.psscan" ? "warn" : "info"]}`}>
                      {sourcePluginBadge(plugin)}
                    </span>
                  ))}
                </div>
              </td>
              <td className="px-4 py-3">
                <span className={`rounded-md border px-2 py-0.5 text-[11px] ${TONE_CLASS[visibilityTone(entity)]}`}>
                  {visibilityLabel(entity)}
                </span>
              </td>
              <td className="hidden px-4 py-3 lg:table-cell">
                <div className="flex flex-wrap gap-1">
                  {(entity.findings || []).map((finding) => (
                    <span key={finding} className="rounded-md border border-line bg-abyss/70 px-1.5 py-0.5 text-[10px] text-muted">
                      {findingLabel(finding)}
                    </span>
                  ))}
                </div>
              </td>
              <td className="px-4 py-3">
                <button
                  type="button"
                  className="rounded-xl border border-line bg-abyss/70 px-3 py-1 text-xs"
                  onClick={() => onSelect(entity.process_entity_id)}
                >
                  Inspect
                </button>
              </td>
            </tr>
          ))}
        </tbody>
      </table>
      <div className="flex items-center justify-end gap-2 border-t border-line p-3 text-xs">
        <span className="mr-auto text-muted">
          {list.items.length} of {list.total} entities
        </span>
        <button disabled={page <= 1} onClick={() => onPage(Math.max(1, page - 1))} className="rounded-xl border border-line px-3 py-1 disabled:opacity-50">
          Previous
        </button>
        <span>Page {page}</span>
        <button disabled={list.items.length < pageSize} onClick={() => onPage(page + 1)} className="rounded-xl border border-line px-3 py-1 disabled:opacity-50">
          Next
        </button>
      </div>
    </div>
  );
}

function ProcessDetailPanel({ detail, onClose }: { detail: MemoryProcessEntityDetail; onClose: () => void }) {
  const entity = detail.entity;
  return (
    <article className="rounded-2xl border border-line bg-abyss/60 p-4" data-testid="canonical-process-detail">
      <header className="flex flex-wrap items-start justify-between gap-3">
        <div>
          <h4 className="text-base font-semibold">
            {reported(entity.process.name)} · PID {entity.process.pid}
          </h4>
          <p className="mt-1 text-xs text-muted">
            Entity {entity.process_entity_id} · Confidence {entity.confidence}
          </p>
        </div>
        <button type="button" className="rounded-xl border border-line px-3 py-1 text-xs" onClick={onClose}>
          Close
        </button>
      </header>

      <dl className="mt-3 grid gap-2 md:grid-cols-2 text-sm">
        <DetailRow label="Command line" value={reported(entity.process.command_line)} />
        <DetailRow label="PPID" value={reported(entity.process.ppid)} />
        <DetailRow label="Create time" value={reported(entity.process.create_time)} />
        <DetailRow label="Exit time" value={reported(entity.process.exit_time)} />
        <DetailRow label="Sources" value={(entity.sources || []).map(sourcePluginBadge).join(", ")} />
        <DetailRow label="Visibility" value={visibilityLabel(entity)} />
        <DetailRow label="Parent" value={detail.parent ? `${reported(detail.parent.process.name)} (${detail.parent.process_entity_id})` : "None"} />
        <DetailRow label="Children" value={String(detail.children.length)} />
      </dl>

      <section className="mt-3">
        <h5 className="text-xs uppercase tracking-[0.18em] text-muted">Observations</h5>
        <table className="mt-2 min-w-full divide-y divide-line text-xs">
          <thead className="bg-abyss/70 text-left text-[10px] uppercase tracking-[0.14em] text-muted">
            <tr>
              <th className="px-2 py-2">Plugin</th>
              <th className="px-2 py-2">PID</th>
              <th className="px-2 py-2">PPID</th>
              <th className="px-2 py-2">Name</th>
              <th className="px-2 py-2">Command line</th>
              <th className="px-2 py-2">Create</th>
              <th className="px-2 py-2">Exit</th>
            </tr>
          </thead>
          <tbody className="divide-y divide-line">
            {observationsToRows(detail.observations).map((row) => (
              <tr key={row.key}>
                <td className="px-2 py-2 text-ink">{row.plugin}</td>
                <td className="px-2 py-2 text-muted">{row.pid}</td>
                <td className="px-2 py-2 text-muted">{row.ppid === null ? "Not reported" : row.ppid}</td>
                <td className="px-2 py-2 text-ink">{row.name}</td>
                <td className="px-2 py-2 text-muted">{row.commandLine}</td>
                <td className="px-2 py-2 text-muted">{row.createTime}</td>
                <td className="px-2 py-2 text-muted">{row.exitTime}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </section>

      {detail.alternate_command_lines.length > 0 ? (
        <section className="mt-3">
          <h5 className="text-xs uppercase tracking-[0.18em] text-muted">Alternate command lines</h5>
          <ul className="mt-2 list-disc pl-5 text-xs text-muted">
            {detail.alternate_command_lines.map((line) => (
              <li key={line}>{line}</li>
            ))}
          </ul>
        </section>
      ) : null}
    </article>
  );
}

function DetailRow({ label, value }: { label: string; value: string }) {
  return (
    <div className="rounded-xl border border-line bg-abyss/40 p-2 text-xs">
      <p className="text-[10px] uppercase tracking-[0.16em] text-muted">{label}</p>
      <p className="mt-1 break-words text-ink">{value}</p>
    </div>
  );
}

function ProcessTreePanel({ tree, onSelect }: { tree: MemoryProcessTreeEntity | undefined; onSelect: (entityId: string) => void }) {
  if (!tree) return null;
  if (tree.total_entities > 200) {
    return (
      <section className="rounded-2xl border border-amber-400/30 bg-amber-500/10 p-4 text-sm text-amber-100">
        <p className="font-semibold">The full process graph contains {tree.total_entities} canonical processes.</p>
        <p className="mt-1 text-xs">
          Select a root, search for a process, or use the filters above. Use the inspection button on any
          row to focus on a single process.
        </p>
      </section>
    );
  }
  const flat = flattenTreeToRows(tree.nodes as any);
  if (flat.length === 0) {
    return (
      <section className="rounded-2xl border border-line bg-abyss/60 p-4 text-sm text-muted">
        No tree to render. Apply renormalization or adjust filters to populate the canonical tree.
      </section>
    );
  }
  return (
    <section className="rounded-2xl border border-line bg-abyss/60 p-4">
      <h4 className="text-sm font-semibold">Process tree</h4>
      <p className="mt-1 text-xs text-muted">
        Roots: {tree.metrics.roots} · Orphans: {tree.metrics.orphans} · Unknown parent: {tree.metrics.unknown_parent} ·
        Hidden candidates: {tree.metrics.hidden_candidates} · Scan only: {tree.metrics.scan_only} · PID 0: {tree.metrics.pid_zero_count} ·
        PID 4: {tree.metrics.pid_4_count}
      </p>
      <table className="mt-3 min-w-full divide-y divide-line text-xs">
        <thead className="bg-abyss/70 text-left text-[10px] uppercase tracking-[0.14em] text-muted">
          <tr>
            <th className="px-2 py-2">Depth</th>
            <th className="px-2 py-2">PID</th>
            <th className="px-2 py-2">PPID</th>
            <th className="px-2 py-2">Name</th>
            <th className="px-2 py-2">Sources</th>
            <th className="px-2 py-2">Visibility</th>
            <th className="px-2 py-2">Findings</th>
            <th className="px-2 py-2">Children</th>
            <th className="px-2 py-2">Action</th>
          </tr>
        </thead>
        <tbody className="divide-y divide-line">
          {flat.map((row) => (
            <tr key={row.key}>
              <td className="px-2 py-2 text-muted">{"— ".repeat(row.depth)}{row.depth}</td>
              <td className="px-2 py-2 text-ink">{row.pid}</td>
              <td className="px-2 py-2 text-muted">{row.ppid === null ? "Not reported" : row.ppid}</td>
              <td className="px-2 py-2 text-ink">{row.name}</td>
              <td className="px-2 py-2 text-muted">{row.sources.join(", ")}</td>
              <td className="px-2 py-2 text-muted">{row.visibility}</td>
              <td className="px-2 py-2 text-muted">{row.findings.join(", ")}</td>
              <td className="px-2 py-2 text-muted">{row.childCount}</td>
              <td className="px-2 py-2">
                <button type="button" className="rounded-md border border-line bg-abyss/70 px-2 py-1 text-[10px]" onClick={() => onSelect(row.key)}>
                  Inspect
                </button>
              </td>
            </tr>
          ))}
        </tbody>
      </table>
    </section>
  );
}
