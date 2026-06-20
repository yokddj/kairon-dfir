import { useState } from "react";
import { Link } from "react-router-dom";
import {
  type MemoryBackendStatus,
  type MemoryOverview,
  type MemoryEvidenceReadiness,
  type MemoryRenormalizeSummary,
  type MemoryRunSelector,
  type MemorySymbolCacheStatus,
} from "../../api/client";
import { backendBadge } from "../MemoryWorkspace";
import type { MemoryTab } from "../../lib/memoryWorkspaceState";

type Props = {
  caseId: string;
  overview: MemoryOverview | null;
  backend: MemoryBackendStatus | null;
  symbolCache: MemorySymbolCacheStatus | null;
  runOptions: MemoryRunSelector | null;
  summary: MemoryRenormalizeSummary | null;
  readinessByEvidence: Map<string, MemoryEvidenceReadiness | undefined>;
  onJumpToTab: (tab: MemoryTab) => void;
  onOpenGraph: (entityId: string) => void;
  onOpenProcesses: (entityId: string) => void;
};

function Card({ label, value, tone }: { label: string; value: string | number; tone?: "ok" | "warn" | "info" }) {
  const toneClass =
    tone === "warn"
      ? "border-amber-400/30 bg-amber-500/10 text-amber-100"
      : tone === "info"
        ? "border-sky-400/30 bg-sky-500/10 text-sky-100"
        : "border-line bg-abyss/60 text-ink";
  return (
    <div className={`rounded-2xl border p-4 ${toneClass}`} data-testid={`overview-card-${label.toLowerCase().replace(/\s+/g, "-")}`}>
      <p className="text-[10px] uppercase tracking-[0.18em] opacity-80">{label}</p>
      <p className="mt-1 text-xl font-semibold">{value}</p>
    </div>
  );
}

function StatusBadge({ children, tone }: { children: React.ReactNode; tone: "ok" | "warn" | "info" | "neutral" }) {
  const toneClass =
    tone === "ok"
      ? "border-emerald-400/30 bg-emerald-500/10 text-emerald-100"
      : tone === "warn"
        ? "border-amber-400/30 bg-amber-500/10 text-amber-100"
        : tone === "info"
          ? "border-sky-400/30 bg-sky-500/10 text-sky-100"
          : "border-line bg-abyss/70 text-muted";
  return <span className={`rounded-md border px-2 py-0.5 text-[11px] ${toneClass}`}>{children}</span>;
}

function workerTone(backend: MemoryBackendStatus | null): "ok" | "warn" | "info" {
  if (!backend) return "info";
  if (backend.ready) return "ok";
  if (backend.dedicated_worker_online) return "info";
  return "warn";
}

function symbolsTone(cache: MemorySymbolCacheStatus | null): "ok" | "warn" | "info" {
  if (!cache) return "info";
  if (cache.symbol_count > 0 && cache.error_code !== "SYMBOL_ACQUISITION_DISABLED") return "ok";
  if (cache.symbol_count > 0) return "info";
  return "warn";
}

function latestRunLabel(options: MemoryRunSelector | null): { label: string; tone: "ok" | "warn" | "info" } {
  if (!options) return { label: "Loading", tone: "info" };
  const defaultId = options.default_run_id;
  const run = options.runs.find((r) => r.run_id === defaultId);
  if (!run) return { label: "None", tone: "warn" };
  return {
    label: `${run.profile} · ${run.status} · ${(run.completed_at || run.created_at).slice(0, 16).replace("T", " ")} UTC`,
    tone: run.status === "completed" || run.status === "completed_with_errors" ? "ok" : "warn",
  };
}

export function MemoryOverviewTab({
  caseId,
  overview,
  backend,
  symbolCache,
  runOptions,
  summary,
  readinessByEvidence,
  onJumpToTab,
  onOpenProcesses,
}: Props) {
  const [showBackendDetails, setShowBackendDetails] = useState(false);
  const evidenceCount = overview?.evidences.length ?? 0;
  const evidenceItems = overview?.evidences ?? [];
  const processProfile = overview?.memory_process_profile_enabled;

  return (
    <div className="space-y-6" data-testid="memory-overview">
      <section className="rounded-[28px] border border-line bg-panel/60 p-5 shadow-panel">
        <h3 className="text-sm font-semibold uppercase tracking-[0.18em] text-muted">Status</h3>
        <div className="mt-3 grid gap-3 md:grid-cols-4">
          <Card label="Evidence" value={`${evidenceCount} memory image${evidenceCount === 1 ? "" : "s"}`} />
          <Card
            label="Worker"
            value={backend ? backendBadge(backend) : "Loading"}
            tone={workerTone(backend)}
          />
          <Card
            label="Symbols"
            value={
              symbolCache
                ? symbolCache.symbol_count > 0
                  ? `Cached (${symbolCache.pdb_count} PDB / ${symbolCache.isf_count} ISF)`
                  : "Not cached"
                : "Loading"
            }
            tone={symbolsTone(symbolCache)}
          />
          <Card label="Latest run" value={latestRunLabel(runOptions).label} tone={latestRunLabel(runOptions).tone} />
        </div>
      </section>

      <section className="rounded-[28px] border border-line bg-panel/60 p-5 shadow-panel">
        <h3 className="text-sm font-semibold uppercase tracking-[0.18em] text-muted">Summary</h3>
        {summary ? (
          <div className="mt-3 grid gap-3 md:grid-cols-6">
            <Card label="Processes" value={summary.candidate_entities} />
            <Card label="Scan only" value={summary.tree_metrics.scan_only} tone="warn" />
            <Card label="Hidden candidates" value={summary.tree_metrics.hidden_candidates} tone="warn" />
            <Card label="Terminated" value={summary.tree_metrics.terminated} />
            <Card label="Orphans" value={summary.tree_metrics.orphans} tone="warn" />
            <Card label="Roots" value={summary.tree_metrics.roots} />
          </div>
        ) : (
          <p className="mt-3 text-sm text-muted">No canonical entities for the current run yet.</p>
        )}
      </section>

      <section className="rounded-[28px] border border-line bg-panel/60 p-5 shadow-panel">
        <h3 className="text-sm font-semibold uppercase tracking-[0.18em] text-muted">Memory engine status</h3>
        <div className="mt-3 flex flex-wrap gap-2 text-xs">
          <StatusBadge tone={backend?.ready ? "ok" : "warn"}>
            Volatility 3: {backend ? backendBadge(backend) : "—"}
          </StatusBadge>
          <StatusBadge tone={backend?.dedicated_worker_online ? "ok" : "warn"}>
            Memory worker: {backend?.dedicated_worker_online ? "Ready" : "Not enabled"}
          </StatusBadge>
          <StatusBadge tone={symbolCache?.symbol_count ? "ok" : "warn"}>
            Symbols: {symbolCache?.symbol_count ? "Cached" : "Not cached"}
          </StatusBadge>
          <StatusBadge tone="info">Symbol mode: {symbolCache?.acquisition_enabled ? "Managed" : "Offline"}</StatusBadge>
          <StatusBadge tone="neutral">MemProcFS: Not required for this workflow</StatusBadge>
        </div>
        <button
          type="button"
          onClick={() => setShowBackendDetails((value) => !value)}
          aria-expanded={showBackendDetails}
          className="mt-3 rounded-xl border border-line bg-abyss/70 px-3 py-1 text-xs text-muted"
          data-testid="overview-toggle-backend-details"
        >
          {showBackendDetails ? "Hide backend details" : "View backend details"}
        </button>
        {showBackendDetails && backend ? (
          <dl className="mt-3 grid gap-2 md:grid-cols-3 text-xs">
            <DetailRow label="Version" value={backend.version || "—"} />
            <DetailRow label="Execution mode" value={backend.execution_mode || "—"} />
            <DetailRow label="Queue" value={backend.queue || "memory"} />
            <DetailRow label="Ready backends" value={`${backend.ready ? "yes" : "no"}`} />
            <DetailRow label="Command" value={backend.command_display || "—"} />
            <DetailRow label="Status message" value={backend.message} />
          </dl>
        ) : null}
      </section>

      <section className="rounded-[28px] border border-line bg-panel/60 p-5 shadow-panel">
        <h3 className="text-sm font-semibold uppercase tracking-[0.18em] text-muted">Interesting findings</h3>
        <p className="mt-1 text-xs text-muted">
          Quick links into the Processes and Graph views with the matching filter applied.
        </p>
        {summary ? (
          <div className="mt-3 grid gap-2 md:grid-cols-2">
            <button
              type="button"
              onClick={() => onJumpToTab("processes")}
              className="rounded-2xl border border-line bg-abyss/60 p-4 text-left transition hover:border-accent/40"
              data-testid="finding-card-scan-only"
            >
              <p className="text-sm font-semibold">Scan-only processes</p>
              <p className="mt-1 text-xs text-muted">
                {summary.tree_metrics.scan_only} process(es) observed only in memory scanning. Needs review.
              </p>
            </button>
            <button
              type="button"
              onClick={() => onJumpToTab("processes")}
              className="rounded-2xl border border-line bg-abyss/60 p-4 text-left transition hover:border-accent/40"
              data-testid="finding-card-hidden-candidate"
            >
              <p className="text-sm font-semibold">Hidden candidates</p>
              <p className="mt-1 text-xs text-muted">
                {summary.tree_metrics.hidden_candidates} process(es) flagged as hidden. Analyst indicator only.
              </p>
            </button>
            <button
              type="button"
              onClick={() => onJumpToTab("graph")}
              className="rounded-2xl border border-line bg-abyss/60 p-4 text-left transition hover:border-accent/40"
              data-testid="finding-card-missing-parent"
            >
              <p className="text-sm font-semibold">Missing parent</p>
              <p className="mt-1 text-xs text-muted">
                {summary.tree_metrics.orphans} orphan(s) whose parent process is not in the canonical set.
              </p>
            </button>
            <button
              type="button"
              onClick={() => onJumpToTab("processes")}
              className="rounded-2xl border border-line bg-abyss/60 p-4 text-left transition hover:border-accent/40"
              data-testid="finding-card-terminated"
            >
              <p className="text-sm font-semibold">Terminated processes</p>
              <p className="mt-1 text-xs text-muted">
                {summary.tree_metrics.terminated} process(es) with explicit exit time.
              </p>
            </button>
          </div>
        ) : (
          <p className="mt-3 text-sm text-muted">No findings yet — apply renormalization to populate canonical entities.</p>
        )}
      </section>

      {evidenceItems.length > 0 ? (
        <section className="rounded-[28px] border border-line bg-panel/60 p-5 shadow-panel">
          <h3 className="text-sm font-semibold uppercase tracking-[0.18em] text-muted">Memory evidence</h3>
          <div className="mt-3 overflow-x-auto">
            <table className="min-w-full divide-y divide-line text-sm">
              <thead className="bg-abyss/70 text-left text-xs uppercase tracking-[0.14em] text-muted">
                <tr>
                  <th className="px-3 py-2">Evidence</th>
                  <th className="px-3 py-2">Size</th>
                  <th className="px-3 py-2">Status</th>
                  <th className="px-3 py-2">Created</th>
                  <th className="px-3 py-2">Analyze</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-line">
                {evidenceItems.map((evidence) => {
                  const readiness = readinessByEvidence.get(evidence.id);
                  return (
                    <tr key={evidence.id} data-testid={`overview-evidence-row-${evidence.id}`}>
                      <td className="px-3 py-2 font-medium text-ink">{evidence.original_filename}</td>
                      <td className="px-3 py-2 text-muted">{formatBytes(evidence.size_bytes)}</td>
                      <td className="px-3 py-2 text-muted">{evidence.ingest_status}</td>
                      <td className="px-3 py-2 text-muted">{evidence.created_at}</td>
                      <td className="px-3 py-2">
                        <Link
                          to={`/cases/${caseId}/memory?tab=processes&evidence_id=${evidence.id}`}
                          className="rounded-xl border border-line bg-abyss/70 px-3 py-1 text-xs text-muted"
                        >
                          View in Processes
                        </Link>
                        {readiness && !readiness.can_analyze && readiness.sanitized_message ? (
                          <p className="mt-1 max-w-xs text-[10px] text-rose-200">{readiness.sanitized_message}</p>
                        ) : null}
                      </td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
          </div>
          <p className="mt-3 text-[10px] text-muted">
            Memory profile enabled: {processProfile ? "yes" : "no"} · Latest symbols: {symbolCache?.symbol_count ?? 0}
          </p>
        </section>
      ) : null}

      <section className="rounded-2xl border border-line bg-abyss/40 p-4 text-xs text-muted">
        <p>
          Use the <strong>Analyze memory</strong> section at the bottom of the page to start a metadata, basic or extended process analysis.
        </p>
      </section>
    </div>
  );
}

function DetailRow({ label, value }: { label: string; value: string }) {
  return (
    <div className="rounded-xl border border-line bg-abyss/40 p-2">
      <p className="text-[10px] uppercase tracking-[0.16em] text-muted">{label}</p>
      <p className="mt-1 text-ink">{value}</p>
    </div>
  );
}

function formatBytes(value: number): string {
  if (value >= 1024 * 1024 * 1024) return `${(value / (1024 * 1024 * 1024)).toFixed(1)} GB`;
  if (value >= 1024 * 1024) return `${(value / (1024 * 1024)).toFixed(1)} MB`;
  if (value >= 1024) return `${(value / 1024).toFixed(1)} KB`;
  return `${value} B`;
}
