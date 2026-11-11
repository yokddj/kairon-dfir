import { Fragment, useMemo, useState } from "react";
import { useQuery } from "@tanstack/react-query";
import { type MemoryEvidenceLandingItem, type MemoryPluginRun, type MemoryRunDetail, type MemoryScanRun, api } from "../../api/client";

type Props = {
  caseId: string;
  evidenceId?: string;
  runs: MemoryScanRun[];
  landingItems: MemoryEvidenceLandingItem[];
};

// Filter options come from the runs themselves: profiles and statuses are
// whatever this evidence has actually run (they grow with every new profile
// and differ per platform), each with its count.
function countBy(runs: MemoryScanRun[], key: (run: MemoryScanRun) => string): Array<{ value: string; count: number }> {
  const counts = new Map<string, number>();
  for (const run of runs) counts.set(key(run), (counts.get(key(run)) ?? 0) + 1);
  return [...counts.entries()].map(([value, count]) => ({ value, count })).sort((a, b) => b.count - a.count || a.value.localeCompare(b.value));
}

function durationLabel(value: number | null | undefined): string {
  if (!value) return "Not reported";
  if (value < 1000) return `${value} ms`;
  return `${(value / 1000).toFixed(1)} s`;
}

function memoryRunError(run: MemoryScanRun): string {
  const code = String(run.error_log?.code || "");
  if (code === "SYMBOLS_UNAVAILABLE") return "The symbols for this image's kernel are not in the symbol cache. An administrator can let the memory worker download them from Microsoft (MEMORY_SYMBOL_DIRECT_DOWNLOAD_ENABLED=true) or import them.";
  if (code === "UNSUPPORTED_MEMORY_IMAGE") return "Volatility could not construct a supported memory layer for this image.";
  if (code === "INVALID_MEMORY_LAYER") return "Volatility could not find this image's page tables, so it cannot read it (kernel symbols would not help). Processes, network, Find Evil and console text come from MemProcFS instead.";
  if (code === "VOLATILITY_OUTPUT_INVALID") return "Volatility ran, but its output could not be parsed.";
  if (code === "MEMORY_SYMBOL_CACHE_NOT_WRITABLE") return "The controlled Volatility symbol cache is not writable.";
  if (["MEMORY_EVIDENCE_PERMISSION_DENIED", "MEMORY_OUTPUT_PERMISSION_DENIED"].includes(code)) return "Evidence unavailable to memory worker. No plugin was executed.";
  if (typeof run.error_log?.message === "string" && run.error_log.message) return run.error_log.message;
  if (run.plugins_failed > 0) {
    return `${run.plugins_failed} plugin${run.plugins_failed === 1 ? "" : "s"} failed. Open details for the cause.`;
  }
  return "None";
}

function formatSeconds(value: unknown): string | null {
  const seconds = typeof value === "number" ? value : Number(value);
  if (!Number.isFinite(seconds) || seconds <= 0) return null;
  if (seconds < 60) return `${Math.round(seconds)}s`;
  return `${Math.round(seconds / 60)}m`;
}

function memoryRunProgress(run: MemoryScanRun): string {
  const progress = (run.metadata_json?.progress ?? {}) as Record<string, unknown>;
  const policy = (run.metadata_json?.timeout_policy ?? {}) as Record<string, unknown>;
  const currentPlugin = typeof progress.current_plugin === "string" ? progress.current_plugin : null;
  const pluginIndex = typeof progress.plugin_index === "number" ? progress.plugin_index : null;
  const pluginTotal = typeof progress.plugin_total === "number" ? progress.plugin_total : run.plugin_count;
  const pluginTimeout = formatSeconds(progress.plugin_timeout_seconds);
  const profileTimeout = formatSeconds(policy.profile_timeout_seconds);
  if (currentPlugin) {
    const count = pluginIndex ? `Plugin ${pluginIndex} of ${pluginTotal}` : `Plugin ${run.plugins_completed + 1} of ${pluginTotal}`;
    return `Running ${currentPlugin} · ${count}${pluginTimeout ? ` · Timeout ${pluginTimeout}` : ""}`;
  }
  if (run.status === "running") return `Running · ${run.plugins_completed}/${run.plugin_count}${profileTimeout ? ` · Profile timeout ${profileTimeout}` : ""}`;
  if (run.error_log?.code === "PROFILE_TIMEOUT" && typeof run.error_log.message === "string") return run.error_log.message;
  const terminalReason = typeof run.metadata_json?.terminal_reason === "string" ? run.metadata_json.terminal_reason : null;
  if (terminalReason === "PROFILE_TIMEOUT") return "Profile timeout reached before all plugins started.";
  return "—";
}

function StatusBadge({ status }: { status: string }) {
  if (["completed", "completed_with_errors"].includes(status)) {
    return <span className="rounded-md border border-emerald-400/30 bg-emerald-500/10 px-2 py-0.5 text-[10px] text-emerald-100">{status}</span>;
  }
  if (status === "failed") {
    return <span className="rounded-md border border-rose-400/30 bg-rose-500/10 px-2 py-0.5 text-[10px] text-rose-100">{status}</span>;
  }
  if (["timed_out", "cancelled"].includes(status)) {
    return <span className="rounded-md border border-amber-400/30 bg-amber-500/10 px-2 py-0.5 text-[10px] text-amber-100">{status}</span>;
  }
  return <span className="rounded-md border border-sky-400/30 bg-sky-500/10 px-2 py-0.5 text-[10px] text-sky-100">{status}</span>;
}

function pluginErrorText(plugin: MemoryPluginRun): string | null {
  if (plugin.error_code || plugin.error_message) {
    return [plugin.error_code, plugin.error_message].filter(Boolean).join(" · ");
  }
  if (plugin.warning_code || plugin.warning_message) {
    return [plugin.warning_code, plugin.warning_message].filter(Boolean).join(" · ");
  }
  return null;
}

function PluginDetailRow({ plugin }: { plugin: MemoryPluginRun }) {
  const preview = typeof plugin.metadata_json?.stderr_preview === "string" ? plugin.metadata_json.stderr_preview : "";
  const errorText = pluginErrorText(plugin);
  return (
    <tr className="border-t border-line align-top" data-testid={`run-plugin-${plugin.id}`}>
      <td className="py-2 pr-3 font-mono text-ink">{plugin.plugin}</td>
      <td className="py-2 pr-3"><StatusBadge status={plugin.status} /></td>
      <td className="py-2 pr-3 text-muted">{durationLabel(plugin.duration_ms)}</td>
      <td className="py-2 pr-3 text-muted">{plugin.row_count}</td>
      <td className="py-2 pr-3">
        {errorText ? (
          <p className={plugin.error_code || plugin.error_message ? "text-rose-200" : "text-amber-200"}>{errorText}</p>
        ) : (
          <span className="text-muted">—</span>
        )}
        {preview ? (
          <details className="mt-1">
            <summary className="cursor-pointer text-accent">stderr preview</summary>
            <pre className="mt-1 max-h-48 overflow-auto whitespace-pre-wrap rounded-lg bg-abyss/70 p-2 text-[10px] text-muted">{preview}</pre>
          </details>
        ) : null}
      </td>
    </tr>
  );
}

function RunPluginDetails({ runId }: { runId: string }) {
  const detailQuery = useQuery<MemoryRunDetail>({
    queryKey: ["memory-run-detail", runId],
    queryFn: () => api.getMemoryRun(runId),
    refetchOnWindowFocus: false,
  });
  if (detailQuery.isLoading) {
    return <p className="px-3 py-2 text-xs text-muted" data-testid={`run-detail-${runId}-loading`}>Loading plugin details...</p>;
  }
  if (detailQuery.isError) {
    const message = detailQuery.error instanceof Error ? detailQuery.error.message : "Unknown error";
    return <p className="px-3 py-2 text-xs text-rose-200" data-testid={`run-detail-${runId}-error`}>Could not load plugin details: {message}</p>;
  }
  const plugins = detailQuery.data?.plugin_runs ?? [];
  if (!plugins.length) {
    return <p className="px-3 py-2 text-xs text-muted" data-testid={`run-detail-${runId}-empty`}>No plugin runs were recorded for this run.</p>;
  }
  return (
    <div className="px-3 py-3" data-testid={`run-detail-${runId}`}>
      <p className="mb-2 text-xs text-muted">
        Per-plugin results for this run. A failed plugin shows its own error code and a stderr preview.
      </p>
      <div className="overflow-x-auto">
        <table className="min-w-full text-xs" data-testid={`run-detail-${runId}-table`}>
          <thead>
            <tr className="text-left uppercase tracking-[0.14em] text-muted">
              <th className="py-1 pr-3">Plugin</th>
              <th className="py-1 pr-3">Status</th>
              <th className="py-1 pr-3">Duration</th>
              <th className="py-1 pr-3">Rows</th>
              <th className="py-1 pr-3">Error</th>
            </tr>
          </thead>
          <tbody>
            {plugins.map((plugin) => (
              <PluginDetailRow key={plugin.id} plugin={plugin} />
            ))}
          </tbody>
        </table>
      </div>
    </div>
  );
}

export function MemoryRunsTab({ evidenceId, runs, landingItems }: Props) {
  const [status, setStatus] = useState("all");
  const [profile, setProfile] = useState("all");
  const statusOptions = useMemo(() => countBy(runs, (run) => run.status), [runs]);
  const profileOptions = useMemo(() => countBy(runs, (run) => run.profile), [runs]);
  const [failuresOnly, setFailuresOnly] = useState(false);
  const [query, setQuery] = useState("");
  const [expandedRunId, setExpandedRunId] = useState<string | null>(null);

  const filtered = useMemo(() => {
    return runs
      .filter((run) => {
        if (status !== "all" && run.status !== status) return false;
        if (profile !== "all" && run.profile !== profile) return false;
        if (failuresOnly && run.plugins_failed === 0) return false;
        if (query) {
          const needle = query.toLowerCase();
          if (
            !(
              run.id.toLowerCase().includes(needle) ||
              run.profile.toLowerCase().includes(needle) ||
              String(run.error_log?.code || "").toLowerCase().includes(needle)
            )
          ) {
            return false;
          }
        }
        return true;
      })
      .sort((left, right) => (right.created_at > left.created_at ? 1 : -1));
  }, [runs, status, profile, failuresOnly, query]);
  const landingByEvidence = useMemo(() => new Map(landingItems.map((item) => [item.evidence_id, item])), [landingItems]);
  const scopeLabel = evidenceId ? "Selected evidence only" : "All memory evidence runs";
  const scopeDescription = evidenceId
    ? "Only runs for the currently selected memory evidence are shown here."
    : "Case-wide history across every memory evidence in this case. Newest first.";
  const selectedEvidence = evidenceId ? landingByEvidence.get(evidenceId) : null;

  return (
    <div className="space-y-4" data-testid="memory-runs-tab">
      <section className="rounded-[28px] border border-line bg-panel/60 p-5 shadow-panel">
        <header className="flex flex-wrap items-center justify-between gap-3">
          <div>
            <h3 className="text-sm font-semibold uppercase tracking-[0.18em] text-muted">{scopeLabel}</h3>
            <p className="mt-1 text-xs text-muted">{scopeDescription}</p>
            {selectedEvidence ? (
              <p className="mt-2 text-xs text-muted">
                Evidence: <span className="text-ink">{selectedEvidence.filename}</span>
                {" · "}
                Host: <span className="text-ink">{selectedEvidence.detected_host || "Unknown"}</span>
              </p>
            ) : null}
          </div>
          <div className="flex flex-wrap items-center gap-2 text-xs">
            <label className="text-muted" htmlFor="runs-status">Status</label>
            <select
              id="runs-status"
              value={status}
              onChange={(event) => setStatus(event.target.value)}
              className="rounded-xl border border-line bg-abyss/70 px-2 py-1 text-sm"
              data-testid="runs-status-filter"
            >
              <option value="all">All</option>
              {statusOptions.map((option) => (
                <option key={option.value} value={option.value}>{option.value} ({option.count})</option>
              ))}
            </select>
            <label className="text-muted" htmlFor="runs-profile">Profile</label>
            <select
              id="runs-profile"
              value={profile}
              onChange={(event) => setProfile(event.target.value)}
              className="rounded-xl border border-line bg-abyss/70 px-2 py-1 text-sm"
              data-testid="runs-profile-filter"
            >
              <option value="all">All</option>
              {profileOptions.map((option) => (
                <option key={option.value} value={option.value}>{option.value} ({option.count})</option>
              ))}
            </select>
            <label className="flex items-center gap-1 text-muted">
              <input
                type="checkbox"
                checked={failuresOnly}
                onChange={(event) => setFailuresOnly(event.target.checked)}
                data-testid="runs-failures-only"
              />
              <span>Failures only</span>
            </label>
            <input
              value={query}
              onChange={(event) => setQuery(event.target.value)}
              placeholder="Search run id, profile, error"
              className="rounded-xl border border-line bg-abyss/70 px-2 py-1 text-sm"
              data-testid="runs-search"
            />
          </div>
        </header>

        <p className="mt-2 text-xs text-muted">{filtered.length} of {runs.length} runs</p>

        <div className="mt-3 overflow-x-auto">
          <table className="min-w-full divide-y divide-line text-sm" data-testid="runs-table">
            <thead className="bg-abyss/70 text-left text-xs uppercase tracking-[0.14em] text-muted">
              <tr>
                <th className="px-3 py-2">Status</th>
                {!evidenceId ? <th className="px-3 py-2">Memory evidence</th> : null}
                {!evidenceId ? <th className="px-3 py-2">Host</th> : null}
                <th className="px-3 py-2">Profile</th>
                <th className="px-3 py-2">Created</th>
                <th className="px-3 py-2">Duration</th>
                <th className="px-3 py-2">Backend</th>
                <th className="px-3 py-2">Plugins</th>
                <th className="px-3 py-2">Progress</th>
                <th className="px-3 py-2">Failed</th>
                <th className="px-3 py-2">Skipped</th>
                <th className="px-3 py-2">Error</th>
                <th className="px-3 py-2">Details</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-line">
              {filtered.map((run) => {
                const expanded = expandedRunId === run.id;
                return (
                  <Fragment key={run.id}>
                    <tr data-testid={`run-row-${run.id}`}>
                      <td className="px-3 py-2"><StatusBadge status={run.status} /></td>
                      {!evidenceId ? <td className="px-3 py-2 text-muted">{landingByEvidence.get(run.evidence_id)?.filename || `${run.evidence_id.slice(0, 8)}...`}</td> : null}
                      {!evidenceId ? <td className="px-3 py-2 text-muted">{landingByEvidence.get(run.evidence_id)?.detected_host || "Unknown"}</td> : null}
                      <td className="px-3 py-2 text-muted">{run.profile}</td>
                      <td className="px-3 py-2 text-muted">{run.created_at}</td>
                      <td className="px-3 py-2 text-muted">{durationLabel(run.duration_ms)}</td>
                      <td className="px-3 py-2 text-muted">{run.backend || "—"}</td>
                      <td className="px-3 py-2 text-muted">{run.plugins_completed}/{run.plugin_count}</td>
                      <td className="px-3 py-2 text-muted">{memoryRunProgress(run)}</td>
                      <td className="px-3 py-2 text-muted" data-testid={`run-row-${run.id}-failed`}>{run.plugins_failed}</td>
                      <td className="px-3 py-2 text-muted" data-testid={`run-row-${run.id}-skipped`}>{run.plugins_skipped}</td>
                      <td className="px-3 py-2 text-muted">{memoryRunError(run)}</td>
                      <td className="px-3 py-2">
                        <button
                          type="button"
                          onClick={() => setExpandedRunId(expanded ? null : run.id)}
                          aria-expanded={expanded}
                          className="rounded-lg border border-line bg-abyss/70 px-2 py-1 text-xs text-muted hover:text-ink"
                          data-testid={`run-row-${run.id}-toggle`}
                        >
                          {expanded ? "Hide" : "Details"}
                        </button>
                      </td>
                    </tr>
                    {expanded ? (
                      <tr className="bg-abyss/40">
                        <td colSpan={evidenceId ? 11 : 13}>
                          <RunPluginDetails runId={run.id} />
                        </td>
                      </tr>
                    ) : null}
                  </Fragment>
                );
              })}
            </tbody>
          </table>
        </div>
        {filtered.length === 0 ? (
          <p className="mt-3 rounded-2xl border border-line bg-abyss/60 p-3 text-sm text-muted">No runs match the current filters.</p>
        ) : null}
      </section>
    </div>
  );
}
