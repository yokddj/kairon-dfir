import { useMemo, useState } from "react";
import { type MemoryEvidenceLandingItem, type MemoryScanRun } from "../../api/client";

type Props = {
  caseId: string;
  evidenceId?: string;
  runs: MemoryScanRun[];
  landingItems: MemoryEvidenceLandingItem[];
};

type StatusFilter = "all" | "completed" | "failed" | "running" | "queued" | "pending";
type ProfileFilter = "all" | "metadata_only" | "processes_basic" | "processes_extended";

function durationLabel(value: number | null | undefined): string {
  if (!value) return "Not reported";
  if (value < 1000) return `${value} ms`;
  return `${(value / 1000).toFixed(1)} s`;
}

function memoryRunError(run: MemoryScanRun): string {
  const code = String(run.error_log?.code || "");
  if (code === "SYMBOLS_UNAVAILABLE") return "windows.info could not resolve the required Windows symbols under offline-only mode.";
  if (code === "UNSUPPORTED_MEMORY_IMAGE" || code === "INVALID_MEMORY_LAYER") return "Volatility could not construct a supported Windows memory layer for this image.";
  if (code === "VOLATILITY_OUTPUT_INVALID") return "windows.info executed, but its output could not be parsed.";
  if (code === "MEMORY_SYMBOL_CACHE_NOT_WRITABLE") return "The controlled Volatility symbol cache is not writable.";
  if (["MEMORY_EVIDENCE_PERMISSION_DENIED", "MEMORY_OUTPUT_PERMISSION_DENIED"].includes(code)) return "Evidence unavailable to memory worker. No plugin was executed.";
  return typeof run.error_log?.message === "string" ? run.error_log.message : "None";
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
  return <span className="rounded-md border border-sky-400/30 bg-sky-500/10 px-2 py-0.5 text-[10px] text-sky-100">{status}</span>;
}

export function MemoryRunsTab({ evidenceId, runs, landingItems }: Props) {
  const [status, setStatus] = useState<StatusFilter>("all");
  const [profile, setProfile] = useState<ProfileFilter>("all");
  const [failuresOnly, setFailuresOnly] = useState(false);
  const [query, setQuery] = useState("");

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
              onChange={(event) => setStatus(event.target.value as StatusFilter)}
              className="rounded-xl border border-line bg-abyss/70 px-2 py-1 text-sm"
              data-testid="runs-status-filter"
            >
              <option value="all">All</option>
              <option value="completed">Completed</option>
              <option value="failed">Failed</option>
              <option value="running">Running</option>
              <option value="queued">Queued</option>
              <option value="pending">Pending</option>
            </select>
            <label className="text-muted" htmlFor="runs-profile">Profile</label>
            <select
              id="runs-profile"
              value={profile}
              onChange={(event) => setProfile(event.target.value as ProfileFilter)}
              className="rounded-xl border border-line bg-abyss/70 px-2 py-1 text-sm"
              data-testid="runs-profile-filter"
            >
              <option value="all">All</option>
              <option value="metadata_only">metadata_only</option>
              <option value="processes_basic">processes_basic</option>
              <option value="processes_extended">processes_extended</option>
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
                <th className="px-3 py-2">Error</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-line">
              {filtered.map((run) => (
                <tr key={run.id} data-testid={`run-row-${run.id}`}>
                  <td className="px-3 py-2"><StatusBadge status={run.status} /></td>
                  {!evidenceId ? <td className="px-3 py-2 text-muted">{landingByEvidence.get(run.evidence_id)?.filename || `${run.evidence_id.slice(0, 8)}...`}</td> : null}
                  {!evidenceId ? <td className="px-3 py-2 text-muted">{landingByEvidence.get(run.evidence_id)?.detected_host || "Unknown"}</td> : null}
                  <td className="px-3 py-2 text-muted">{run.profile}</td>
                  <td className="px-3 py-2 text-muted">{run.created_at}</td>
                  <td className="px-3 py-2 text-muted">{durationLabel(run.duration_ms)}</td>
                  <td className="px-3 py-2 text-muted">{run.backend || "—"}</td>
                  <td className="px-3 py-2 text-muted">{run.plugins_completed}/{run.plugin_count}</td>
                  <td className="px-3 py-2 text-muted">{memoryRunProgress(run)}</td>
                  <td className="px-3 py-2 text-muted">{run.plugins_failed}</td>
                  <td className="px-3 py-2 text-muted">{memoryRunError(run)}</td>
                </tr>
              ))}
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
