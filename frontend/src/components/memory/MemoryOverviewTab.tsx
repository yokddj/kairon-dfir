import { useMemo } from "react";
import { useQueries, useQuery } from "@tanstack/react-query";
import { Link } from "react-router-dom";
import {
  type MemoryAnalysisCatalogue,
  type MemoryBackendStatus,
  type MemoryEvidenceLandingItem,
  type MemoryFamilyState,
  type MemoryOverview,
  type MemoryActiveRun,
  type MemoryEvidenceReadiness,
  type MemorySymbolCacheStatus,
  api,
} from "../../api/client";
import { backendBadge } from "../MemoryWorkspace";
import type { MemoryTab } from "../../lib/memoryWorkspaceState";

type Props = {
  caseId: string;
  evidenceId: string;
  overview: MemoryOverview | null;
  backend: MemoryBackendStatus | null;
  symbolCache: MemorySymbolCacheStatus | null;
  readinessByEvidence: Map<string, MemoryEvidenceReadiness | undefined>;
  onJumpToTab: (tab: MemoryTab, artifact?: string) => void;
};

type OverviewFamily = {
  family: string;
  title: string;
  state: MemoryFamilyState;
  activeRun: MemoryActiveRun | null;
  latestAttempt: MemoryActiveRun | null;
  selectionReason: string;
  usingFallback: boolean;
  lastCount: number;
};

const FAMILIES: Array<{ family: string; title: string; tab: MemoryTab; artifact?: string }> = [
  { family: "system_info", title: "System information", tab: "system" },
  { family: "processes", title: "Processes", tab: "processes" },
  { family: "modules", title: "Modules and DLLs", tab: "artifacts", artifact: "modules" },
  { family: "handles", title: "Handles", tab: "artifacts", artifact: "handles" },
  { family: "kernel_modules", title: "Kernel modules", tab: "artifacts", artifact: "kernel_modules" },
  { family: "drivers", title: "Drivers", tab: "artifacts", artifact: "drivers" },
  { family: "suspicious_regions", title: "Suspicious memory regions", tab: "artifacts", artifact: "suspicious_regions" },
  { family: "network", title: "Network connections", tab: "artifacts", artifact: "network" },
];

function stateLabel(state: MemoryFamilyState | string | undefined): { label: string; tone: "ok" | "warn" | "muted" | "danger" | "info" } {
  switch (state) {
    case "completed":
    case "ready":
      return { label: "Completed", tone: "ok" };
    case "running":
    case "pending":
    case "queued":
      return { label: "Running", tone: "info" };
    case "latest_attempt_failed":
      return { label: "Latest attempt failed", tone: "warn" };
    case "unavailable":
      return { label: "Unavailable", tone: "muted" };
    case "not_analyzed":
      return { label: "Not analyzed", tone: "muted" };
    case "evidence_scope_required":
      return { label: "Evidence scope required", tone: "danger" };
    default:
      return { label: state ? String(state) : "Not analyzed", tone: "muted" };
  }
}

function formatCount(n: number): string {
  return n.toLocaleString("en-US");
}

function formatDate(iso: string | null | undefined): string {
  if (!iso) return "—";
  return iso.slice(0, 19).replace("T", " ");
}

function buildFamilies(
  landing: MemoryEvidenceLandingItem | null | undefined,
  catalogue: MemoryAnalysisCatalogue | null | undefined,
): OverviewFamily[] {
  const catalogueByFamily = new Map<string, { lastCount: number; lastStatus: string | null }>();
  if (catalogue) {
    for (const item of catalogue.items) {
      catalogueByFamily.set(item.family, {
        lastCount: item.last_count,
        lastStatus: item.last_status,
      });
    }
  }
  const landingByFamily = new Map<string, NonNullable<MemoryEvidenceLandingItem["families"]>[number]>();
  if (landing) {
    for (const f of landing.families) {
      landingByFamily.set(f.family, f);
    }
  }
  return FAMILIES.map(({ family, title }) => {
    const landingEntry = landingByFamily.get(family);
    const catalogueEntry = catalogueByFamily.get(family);
    // The landing carries the per-family count; the catalogue is
    // keyed by profile so it cannot distinguish ``kernel_modules``
    // from ``drivers`` (both come from ``kernel_basic``).  When the
    // landing is missing, fall back to the catalogue for the small
    // number of families that map to a single profile (e.g. handles).
    const landingCount = (landingEntry as { count?: number } | undefined)?.count;
    const lastCount =
      typeof landingCount === "number" ? landingCount : (catalogueEntry?.lastCount ?? 0);
    return {
      family,
      title,
      state: landingEntry?.state ?? "not_analyzed",
      activeRun: landingEntry?.active_run ?? null,
      latestAttempt: landingEntry?.latest_attempt ?? null,
      selectionReason: landingEntry?.selection_reason ?? "not_analyzed",
      usingFallback: Boolean(landingEntry?.using_fallback),
      lastCount,
    } satisfies OverviewFamily;
  });
}

export function MemoryOverviewTab({
  caseId,
  evidenceId,
  overview,
  backend,
  symbolCache,
  readinessByEvidence,
  onJumpToTab,
}: Props) {
  const readiness = readinessByEvidence.get(evidenceId) ?? null;
  const volatilityBackend = backend;
  const symbolsReady = Boolean(symbolCache && (symbolCache.symbol_count > 0 || symbolCache.error_code === "SYMBOL_ACQUISITION_DISABLED"));

  const landingQuery = useQuery({
    queryKey: ["memory-landing", caseId],
    queryFn: () => api.getMemoryEvidenceLanding(caseId),
    enabled: Boolean(caseId),
    refetchOnWindowFocus: false,
  });
  const catalogueQuery = useQuery({
    queryKey: ["memory-catalogue", caseId, evidenceId],
    queryFn: () => api.getMemoryAnalysisCatalogue(caseId, evidenceId),
    enabled: Boolean(caseId && evidenceId),
    refetchOnWindowFocus: false,
  });

  const landing = useMemo(
    () => landingQuery.data?.items.find((it) => it.evidence_id === evidenceId) ?? null,
    [landingQuery.data, evidenceId],
  );

  // Counts come from the landing endpoint which carries the per-family
  // ``count`` field.  The catalogue is keyed by profile (not family)
  // so the landing is the only source that distinguishes, e.g.,
  // ``kernel_modules`` from ``drivers`` even when both come from the
  // same ``kernel_basic`` run.
  const families = useMemo(
    () => buildFamilies(landing, catalogueQuery.data),
    [landing, catalogueQuery.data],
  );

  // 26+ checks: artifact cards are derived from the same family rows.
  const artifactCards = families.filter((f) => !["system_info", "processes"].includes(f.family));

  // Pre-fetch the canonical processes summary (latest successful
  // processes_extended > processes_basic) so we can render the
  // Summary block without referencing a global run id.
  const processesFamily = families.find((f) => f.family === "processes");

  const evidence = landing;
  const backendTone = volatilityBackend?.ready
    ? "ok"
    : volatilityBackend?.dedicated_worker_online
      ? "info"
      : "warn";

  return (
    <div className="space-y-6" data-testid="memory-overview">
      <section className="rounded-[28px] border border-line bg-panel/60 p-5 shadow-panel">
        <p className="font-mono text-[10px] uppercase tracking-[0.24em] text-muted">
          Showing the latest successful result for each analysis family.
        </p>
        <p className="mt-1 text-xs text-muted">
          Case <span className="font-mono">{caseId.slice(0, 8)}</span>
          {evidence ? (
            <>
              {" "}· Evidence <span className="font-mono">{evidence.evidence_id.slice(0, 8)}</span>
              {evidence.detected_host ? <> · Host {evidence.detected_host}</> : null}
            </>
          ) : null}
        </p>
      </section>

      <section
        className="rounded-[28px] border border-line bg-panel/60 p-5 shadow-panel"
        data-testid="memory-overview-status"
      >
        <h3 className="text-sm font-semibold uppercase tracking-[0.18em] text-muted">Memory engine status</h3>
        <div className="mt-3 grid gap-3 md:grid-cols-4">
          <StatusPill
            label="Volatility 3"
            value={volatilityBackend ? backendBadge(volatilityBackend) : "—"}
            tone={volatilityBackend?.ready ? "ok" : "warn"}
            testId="overview-backend-volatility"
          />
          <StatusPill
            label="Memory worker"
            value={volatilityBackend?.dedicated_worker_online ? "Ready" : "Not enabled"}
            tone={volatilityBackend?.dedicated_worker_online ? "ok" : "warn"}
            testId="overview-backend-worker"
          />
          <StatusPill
            label="Symbols"
            value={symbolsReady ? "Cached" : "Not cached"}
            tone={symbolsReady ? "ok" : "warn"}
            testId="overview-backend-symbols"
          />
          <StatusPill
            label="Evidence readiness"
            value={readiness?.can_analyze ? "Ready" : readiness ? "Blocked" : "—"}
            tone={readiness?.can_analyze ? "ok" : readiness ? "danger" : "info"}
            testId="overview-evidence-readiness"
          />
        </div>
      </section>

      <section
        className="rounded-[28px] border border-line bg-panel/60 p-5 shadow-panel"
        data-testid="memory-overview-family-status"
      >
        <h3 className="text-sm font-semibold uppercase tracking-[0.18em] text-muted">Analysis status</h3>
        <p className="mt-1 text-xs text-muted">
          Each row reflects the active result for that family. Completed runs with zero results are still shown.
        </p>
        <div className="mt-3 overflow-x-auto">
          <table className="min-w-full divide-y divide-line text-sm" data-testid="memory-family-table">
            <thead className="bg-abyss/70 text-left text-[10px] uppercase tracking-[0.14em] text-muted">
              <tr>
                <th className="px-3 py-2">Family</th>
                <th className="px-3 py-2">State</th>
                <th className="px-3 py-2">Profile</th>
                <th className="px-3 py-2">Count</th>
                <th className="px-3 py-2">Last success</th>
                <th className="px-3 py-2">Last attempt</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-line">
              {families.map((row) => {
                const meta = stateLabel(row.state);
                const lastSuccess = row.activeRun;
                const lastAttempt = row.latestAttempt;
                return (
                  <tr key={row.family} data-testid={`memory-family-row-${row.family}`}>
                    <td className="px-3 py-2 font-medium text-ink">
                      <FamilyLink caseId={caseId} evidenceId={evidenceId} family={row.family} label={row.title} onJumpToTab={onJumpToTab} />
                    </td>
                    <td className="px-3 py-2">
                      <span
                        className={`rounded-md border px-2 py-0.5 text-[10px] ${toneClass(meta.tone)}`}
                        data-testid={`memory-family-state-${row.family}`}
                        data-family-state={row.state}
                      >
                        {meta.label}
                      </span>
                      {row.usingFallback ? (
                        <span className="ml-2 rounded-md border border-amber-400/30 bg-amber-500/10 px-2 py-0.5 text-[10px] text-amber-100" data-testid={`memory-family-fallback-${row.family}`}>
                          showing last successful
                        </span>
                      ) : null}
                    </td>
                    <td className="px-3 py-2 text-muted">
                      {lastSuccess ? (
                        <span className="font-mono text-[10px]">{lastSuccess.profile}</span>
                      ) : (
                        <span className="text-[10px] text-muted">—</span>
                      )}
                    </td>
                    <td className="px-3 py-2 text-ink">
                      {row.state === "unavailable" ? (
                        <span className="text-[10px] text-muted">—</span>
                      ) : row.state === "completed" || row.state === "ready" || row.state === "latest_attempt_failed" ? (
                        <span data-testid={`memory-family-count-${row.family}`}>
                          {row.state === "completed" || row.state === "ready" ? "Completed" : "Latest attempt failed"} · {formatCount(row.lastCount)}
                          {row.lastCount === 0 ? (
                            <span className="ml-1 text-[10px] text-muted" data-testid={`memory-family-zero-${row.family}`}>
                              0 results
                            </span>
                          ) : null}
                        </span>
                      ) : (
                        <span className="text-[10px] text-muted">—</span>
                      )}
                    </td>
                    <td className="px-3 py-2 text-muted">
                      {lastSuccess ? formatDate(lastSuccess.completed_at ?? lastSuccess.started_at) : "—"}
                    </td>
                    <td className="px-3 py-2 text-muted">
                      {lastAttempt ? formatDate(lastAttempt.completed_at ?? lastAttempt.started_at) : "—"}
                    </td>
                  </tr>
                );
              })}
            </tbody>
          </table>
        </div>
      </section>

      <section
        className="rounded-[28px] border border-line bg-panel/60 p-5 shadow-panel"
        data-testid="memory-overview-processes"
      >
        <h3 className="text-sm font-semibold uppercase tracking-[0.18em] text-muted">Processes</h3>
        {processesFamily && (processesFamily.state === "completed" || processesFamily.state === "ready" || processesFamily.state === "latest_attempt_failed") ? (
          <div className="mt-3 grid gap-3 md:grid-cols-4">
            <SummaryCard label="Processes" value={processesFamily.lastCount} testId="overview-processes-processes" />
            <SummaryCard label="Last profile" value={processesFamily.activeRun?.profile ?? "—"} testId="overview-processes-profile" />
            <SummaryCard label="Last success" value={processesFamily.activeRun ? formatDate(processesFamily.activeRun.completed_at ?? processesFamily.activeRun.started_at) : "—"} testId="overview-processes-last" />
            <SummaryCard
              label="View"
              value="Open processes"
              tone="info"
              action
              testId="overview-processes-open"
              onAction={() => onJumpToTab("processes")}
            />
          </div>
        ) : (
          <div className="mt-3 space-y-2">
            <p className="text-sm text-muted" data-testid="overview-processes-empty">
              Processes have not been analyzed for this evidence.
            </p>
            <button
              type="button"
              onClick={() => onJumpToTab("processes")}
              data-testid="overview-processes-cta"
              className="rounded-xl border border-accent/40 bg-accent/10 px-3 py-1.5 text-xs text-accent"
            >
              Run process analysis
            </button>
          </div>
        )}
      </section>

      <section
        className="rounded-[28px] border border-line bg-panel/60 p-5 shadow-panel"
        data-testid="memory-overview-artifacts"
      >
        <h3 className="text-sm font-semibold uppercase tracking-[0.18em] text-muted">Core memory artifacts</h3>
        <p className="mt-1 text-xs text-muted">
          One card per artifact family. Counts are scoped to this evidence.
        </p>
        <div className="mt-3 grid gap-2 md:grid-cols-2 lg:grid-cols-3" data-testid="memory-overview-artifact-cards">
          {artifactCards.map((row) => {
            const meta = stateLabel(row.state);
            const isUnavailable = row.state === "unavailable";
            const isAnalyzed = row.state === "completed" || row.state === "ready" || row.state === "latest_attempt_failed";
            return (
              <div
                key={row.family}
                className="rounded-2xl border border-line bg-abyss/60 p-3"
                data-testid={`memory-artifact-card-${row.family}`}
              >
                <div className="flex flex-wrap items-center justify-between gap-2">
                  <p className="text-sm font-semibold text-ink">{row.title}</p>
                  <span className={`rounded-md border px-2 py-0.5 text-[10px] ${toneClass(meta.tone)}`}>
                    {meta.label}
                  </span>
                </div>
                <p className="mt-1 text-[10px] text-muted">
                  {isUnavailable
                    ? "Network plugin is not available in the installed Volatility runtime."
                    : isAnalyzed
                      ? `${row.lastCount.toLocaleString("en-US")} artifacts · last success ${row.activeRun ? formatDate(row.activeRun.completed_at ?? row.activeRun.started_at) : "—"}`
                      : "Not analyzed yet."}
                </p>
                <div className="mt-2 flex flex-wrap gap-2">
                  <button
                    type="button"
                    onClick={() => onJumpToTab("artifacts", FAMILIES.find((f) => f.family === row.family)?.artifact)}
                    className="rounded-xl border border-line bg-abyss/70 px-2 py-1 text-[10px] text-muted"
                    data-testid={`memory-artifact-card-open-${row.family}`}
                  >
                    Open subview
                  </button>
                </div>
              </div>
            );
          })}
        </div>
      </section>
    </div>
  );
}

function FamilyLink({
  caseId,
  evidenceId,
  family,
  label,
  onJumpToTab,
}: {
  caseId: string;
  evidenceId: string;
  family: string;
  label: string;
  onJumpToTab: (tab: MemoryTab, artifact?: string) => void;
}) {
  const target = FAMILIES.find((f) => f.family === family);
  if (!target) return <span>{label}</span>;
  return (
    <button
      type="button"
      onClick={() => onJumpToTab(target.tab, target.artifact)}
      className="text-left text-ink hover:text-accent"
      data-testid={`memory-family-link-${family}`}
    >
      {label}
    </button>
  );
}

function StatusPill({ label, value, tone, testId }: { label: string; value: string; tone: "ok" | "warn" | "info" | "danger"; testId?: string }) {
  return (
    <div className={`rounded-2xl border p-3 ${toneClass(tone)}`} data-testid={testId}>
      <p className="text-[10px] uppercase tracking-[0.18em] opacity-80">{label}</p>
      <p className="mt-1 text-sm font-semibold">{value}</p>
    </div>
  );
}

function SummaryCard({
  label,
  value,
  tone = "ok",
  action,
  testId,
  onAction,
}: {
  label: string;
  value: string | number;
  tone?: "ok" | "warn" | "info";
  action?: boolean;
  testId?: string;
  onAction?: () => void;
}) {
  return (
    <div
      className={`rounded-2xl border p-3 ${toneClass(tone)}`}
      data-testid={testId}
    >
      <p className="text-[10px] uppercase tracking-[0.18em] opacity-80">{label}</p>
      {action ? (
        <button
          type="button"
          onClick={onAction}
          className="mt-1 text-sm font-semibold text-ink hover:text-accent"
        >
          {value}
        </button>
      ) : (
        <p className="mt-1 text-sm font-semibold">{value}</p>
      )}
    </div>
  );
}

function toneClass(tone: "ok" | "warn" | "info" | "muted" | "danger"): string {
  switch (tone) {
    case "ok":
      return "border-emerald-400/30 bg-emerald-500/10 text-emerald-100";
    case "warn":
      return "border-amber-400/30 bg-amber-500/10 text-amber-100";
    case "info":
      return "border-sky-400/30 bg-sky-500/10 text-sky-100";
    case "danger":
      return "border-rose-400/30 bg-rose-500/10 text-rose-100";
    default:
      return "border-line bg-abyss/70 text-muted";
  }
}
