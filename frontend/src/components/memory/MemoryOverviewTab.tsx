import { useMemo } from "react";
import { useQuery } from "@tanstack/react-query";
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
  type MemoryPlatformResultViews,
  api,
} from "../../api/client";
import { backendBadge } from "../MemoryWorkspace";
import type { MemoryTab } from "../../lib/memoryWorkspaceState";
import { memoryFamilyApplies } from "../../lib/memoryPlatformViews";
import { commandHistoryRoute, memoryWorkbenchRoute } from "../../lib/canonicalRoutes";

type Props = {
  caseId: string;
  evidenceId: string;
  overview: MemoryOverview | null;
  backend: MemoryBackendStatus | null;
  symbolCache: MemorySymbolCacheStatus | null;
  readinessByEvidence: Map<string, MemoryEvidenceReadiness | undefined>;
  // What analysis can produce on this evidence's platform; families it
  // cannot produce (Handles on Linux) are left out. Null keeps them all.
  resultViews?: MemoryPlatformResultViews | null;
  onJumpToTab: (tab: MemoryTab, artifact?: string) => void;
};

export type OverviewFamily = {
  family: string;
  title: string;
  state: MemoryFamilyState;
  activeRun: MemoryActiveRun | null;
  latestAttempt: MemoryActiveRun | null;
  usingFallback: boolean;
  availabilityReason: string | null;
  lastCount: number;
};

const FAMILIES: Array<{ family: string; title: string; tab: MemoryTab; artifact?: string }> = [
  { family: "system_info", title: "System information", tab: "system" },
  { family: "find_evil", title: "Find Evil indicators", tab: "find_evil" },
  { family: "processes", title: "Processes", tab: "processes" },
  { family: "shell_history", title: "Shell history", tab: "shell_history" },
  { family: "modules", title: "Modules and DLLs", tab: "modules" },
  { family: "handles", title: "Handles", tab: "handles" },
  { family: "kernel_modules", title: "Kernel modules", tab: "modules" },
  { family: "drivers", title: "Drivers", tab: "modules" },
  { family: "suspicious_regions", title: "Suspicious memory regions", tab: "suspicious" },
  { family: "network", title: "Network connections", tab: "network" },
];

type Tone = "ok" | "warn" | "muted" | "danger" | "info";

function stateLabel(state: MemoryFamilyState | string | undefined): { label: string; tone: Tone } {
  switch (state) {
    case "completed":
    case "ready":
    case "analyzed_with_results":
      return { label: "Completed", tone: "ok" };
    case "analyzed_empty":
      return { label: "Completed (no results)", tone: "ok" };
    case "running":
    case "pending":
    case "queued":
      return { label: "Running", tone: "info" };
    case "partial":
      return { label: "Partially analyzed", tone: "warn" };
    case "latest_attempt_failed":
      return { label: "Latest attempt failed", tone: "warn" };
    case "failed":
      return { label: "Failed", tone: "danger" };
    case "unavailable":
      return { label: "Unavailable", tone: "muted" };
    case "not_analyzed":
      return { label: "Not analyzed", tone: "muted" };
    case "evidence_scope_required":
      return { label: "Evidence scope required", tone: "danger" };
    case "historical_override":
      return { label: "Showing historical run", tone: "info" };
    case "historical_override_invalid":
      return { label: "Historical run unavailable", tone: "warn" };
    case "unknown_family":
      return { label: "Unknown family", tone: "muted" };
    default:
      return { label: state ? String(state) : "Not analyzed", tone: "muted" };
  }
}

const ANALYZED_STATES = new Set<MemoryFamilyState>(["completed", "ready", "analyzed_with_results", "analyzed_empty"]);
const FAILED_STATES = new Set<MemoryFamilyState>(["failed", "latest_attempt_failed"]);

function isFamilyAnalyzed(state: MemoryFamilyState | undefined): boolean {
  return Boolean(state && ANALYZED_STATES.has(state));
}

// A row has a result worth counting when the family was analysed, or when its
// latest attempt failed but an earlier successful run is still being shown.
function hasResult(row: OverviewFamily): boolean {
  return isFamilyAnalyzed(row.state) || (row.state === "latest_attempt_failed" && row.activeRun !== null);
}

function formatDate(iso: string | null | undefined): string {
  if (!iso) return "—";
  return iso.slice(0, 19).replace("T", " ");
}

function buildFamilies(
  landing: MemoryEvidenceLandingItem | null | undefined,
  catalogue: MemoryAnalysisCatalogue | null | undefined,
): OverviewFamily[] {
  const catalogueCount = new Map<string, number>();
  for (const item of catalogue?.items ?? []) catalogueCount.set(item.family, item.last_count);
  const landingByFamily = new Map<string, NonNullable<MemoryEvidenceLandingItem["families"]>[number]>();
  for (const f of landing?.families ?? []) landingByFamily.set(f.family, f);
  return FAMILIES.map(({ family, title }) => {
    const entry = landingByFamily.get(family);
    // The landing carries the per-family count; the catalogue is keyed by
    // profile so it cannot tell ``kernel_modules`` from ``drivers`` (both come
    // from ``kernel_basic``). It is only a fallback when the landing has none.
    const landingCount = (entry as { count?: number } | undefined)?.count;
    return {
      family,
      title,
      state: entry?.state ?? "not_analyzed",
      activeRun: entry?.active_run ?? null,
      latestAttempt: entry?.latest_attempt ?? null,
      usingFallback: Boolean(entry?.using_fallback),
      availabilityReason: entry?.availability_reason ?? null,
      lastCount: typeof landingCount === "number" ? landingCount : (catalogueCount.get(family) ?? 0),
    } satisfies OverviewFamily;
  });
}

type DetectionReadiness = "recognized" | "needs_confirmation" | "blocked" | "unknown";

function detectionReadiness(status: string | null | undefined): DetectionReadiness {
  const s = (status || "").toLowerCase();
  if (!s) return "unknown";
  if (s === "confirmed_memory" || s === "probable_memory" || s === "ambiguous_raw_confirmed" || s === "probable_disk_confirmed_as_memory") return "recognized";
  if (s === "ambiguous_raw") return "needs_confirmation";
  if (s === "probable_disk" || s === "unsupported" || s === "invalid" || s === "probe_failed") return "blocked";
  return "unknown";
}

export type OverviewNotice = {
  id: string;
  tone: "danger" | "warn" | "info";
  message: string;
  action?: { label: string; href: string };
};

/**
 * What the analyst has to act on before the results can be trusted or
 * completed. Empty when nothing needs attention, so a healthy evidence shows
 * no status chrome at all -- only its results. Each notice is derived from
 * state the backend already reports, never from a particular image.
 */
// Exported for tests: the decisions live here, rendering only adds mocks.
export function buildOverviewNotices(
  caseId: string,
  landing: MemoryEvidenceLandingItem | null,
  readiness: MemoryEvidenceReadiness | null,
  backend: MemoryBackendStatus | null,
  families: OverviewFamily[],
): OverviewNotice[] {
  const notices: OverviewNotice[] = [];
  const detection = detectionReadiness(landing?.detection_status);
  if (detection === "blocked") {
    notices.push({ id: "detection", tone: "danger", message: landing?.detection_reason || "Kairon could not confirm this is a memory image." });
  } else if (detection === "needs_confirmation") {
    notices.push({ id: "detection", tone: "warn", message: "Confirm the evidence type before analysis can start." });
  }

  // The readiness endpoint folds in worker, backend and storage access, so it
  // is the one source for "can a new analysis run now". The backend status is
  // only consulted while readiness has not loaded.
  if (readiness && !readiness.can_analyze) {
    notices.push({ id: "readiness", tone: "warn", message: readiness.sanitized_message || "This evidence is not ready for memory analysis." });
  } else if (!readiness && backend && !backend.ready) {
    notices.push({ id: "readiness", tone: "warn", message: backend.message || `Volatility 3: ${backendBadge(backend)}` });
  }

  if (landing && !landing.host_id) {
    notices.push({
      id: "host",
      tone: "info",
      message: "No host is assigned to this evidence, so its results are not linked to the host's other evidence.",
      action: { label: "Assign host", href: memoryWorkbenchRoute(caseId) },
    });
  }

  const failed = families.filter((f) => FAILED_STATES.has(f.state));
  if (failed.length > 0) {
    notices.push({ id: "failed", tone: "warn", message: `Latest analysis failed: ${failed.map((f) => f.title).join(", ")}.` });
  }

  // Families that do not apply to this image ("unavailable") can never be
  // run, so they are not pending work.
  const blocked = notices.some((n) => n.id === "detection" || n.id === "readiness");
  const pending = families.filter((f) => f.state === "not_analyzed");
  if (!blocked && pending.length > 0) {
    const anyAnalyzed = families.some((f) => isFamilyAnalyzed(f.state));
    notices.push({
      id: "pending",
      tone: "info",
      message: anyAnalyzed
        ? `Not analyzed yet: ${pending.map((f) => f.title).join(", ")}. Use "Complete analysis" above to run them.`
        : 'Nothing has been analyzed yet. Use "Analyze memory" above to start.',
    });
  }
  return notices;
}

export function MemoryOverviewTab({
  caseId,
  evidenceId,
  backend,
  readinessByEvidence,
  resultViews = null,
  onJumpToTab,
}: Props) {
  const readiness = readinessByEvidence.get(evidenceId) ?? null;

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
  const families = useMemo(
    () => buildFamilies(landing, catalogueQuery.data).filter((f) => memoryFamilyApplies(f.family, resultViews)),
    [landing, catalogueQuery.data, resultViews],
  );
  const notices = useMemo(
    () => buildOverviewNotices(caseId, landing, readiness, backend, families),
    [caseId, landing, readiness, backend, families],
  );

  const scope = new URLSearchParams({ source_category: "Memory", evidence_id: evidenceId });

  return (
    <div className="space-y-4" data-testid="memory-overview">
      {notices.length > 0 ? (
        <ul className="space-y-2" data-testid="memory-overview-notices">
          {notices.map((notice) => (
            <li
              key={notice.id}
              className={`flex flex-wrap items-center justify-between gap-2 rounded-2xl border px-4 py-2.5 text-sm ${toneClass(notice.tone)}`}
              data-testid={`memory-overview-notice-${notice.id}`}
            >
              <span>{notice.message}</span>
              {notice.action ? (
                <Link to={notice.action.href} className="rounded-lg border border-white/20 px-2 py-1 text-xs">
                  {notice.action.label}
                </Link>
              ) : null}
            </li>
          ))}
        </ul>
      ) : null}

      <section
        className="rounded-[28px] border border-line bg-panel/60 p-5 shadow-panel"
        data-testid="memory-overview-family-status"
      >
        <div className="flex flex-wrap items-center justify-between gap-3">
          <h3 className="text-sm font-semibold uppercase tracking-[0.18em] text-muted">Results</h3>
          {evidenceId ? (
            <nav className="flex flex-wrap gap-3 text-xs text-muted" data-testid="memory-overview-context-actions">
              <Link to={`/cases/${caseId}/search?${scope}`} className="hover:text-accent">Search this evidence</Link>
              <Link to={`/cases/${caseId}/timeline?${scope}`} className="hover:text-accent">Timeline</Link>
              <Link to={commandHistoryRoute(caseId, scope)} className="hover:text-accent">Commands</Link>
            </nav>
          ) : null}
        </div>
        <table className="mt-3 w-full text-sm" data-testid="memory-family-table">
          <thead className="text-left text-[10px] uppercase tracking-[0.14em] text-muted">
            <tr className="border-b border-line">
              <th className="px-3 py-2 font-medium">Analysis</th>
              <th className="px-3 py-2 text-right font-medium">Results</th>
              <th className="px-3 py-2 font-medium">Status</th>
              <th className="hidden px-3 py-2 font-medium sm:table-cell">Analyzed</th>
            </tr>
          </thead>
          <tbody className="divide-y divide-line">
            {families.map((row) => (
              <FamilyRow key={row.family} row={row} onJumpToTab={onJumpToTab} />
            ))}
          </tbody>
        </table>
      </section>
    </div>
  );
}

function FamilyRow({ row, onJumpToTab }: { row: OverviewFamily; onJumpToTab: (tab: MemoryTab, artifact?: string) => void }) {
  const meta = stateLabel(row.state);
  const target = FAMILIES.find((f) => f.family === row.family);
  const open = () => target && onJumpToTab(target.tab, target.artifact);
  const showResult = hasResult(row);
  // Completed is the normal case: say it to assistive tech, but keep the eye
  // on the rows that differ.
  const quiet = meta.tone === "ok";
  return (
    <tr
      className="cursor-pointer hover:bg-abyss/50"
      onClick={open}
      data-testid={`memory-family-row-${row.family}`}
    >
      <td className="px-3 py-2">
        <button
          type="button"
          onClick={(event) => {
            event.stopPropagation();
            open();
          }}
          className="text-left font-medium text-ink hover:text-accent"
          data-testid={`memory-family-link-${row.family}`}
        >
          {row.title}
        </button>
      </td>
      <td className="px-3 py-2 text-right tabular-nums">
        {showResult ? (
          <span
            className={row.lastCount === 0 ? "text-muted" : "text-ink"}
            data-testid={`memory-family-count-${row.family}`}
          >
            {row.lastCount.toLocaleString("en-US")}
            {row.lastCount === 0 ? <span className="sr-only" data-testid={`memory-family-zero-${row.family}`}> results</span> : null}
          </span>
        ) : (
          <span className="text-muted">—</span>
        )}
      </td>
      <td className="px-3 py-2">
        <span
          className={quiet ? "sr-only" : `rounded-md border px-2 py-0.5 text-[10px] ${toneClass(meta.tone)}`}
          data-testid={`memory-family-state-${row.family}`}
          data-family-state={row.state}
        >
          {meta.label}
        </span>
        {row.state === "unavailable" ? (
          <span className="ml-2 text-[11px] text-muted">{row.availabilityReason || "Not available for this image."}</span>
        ) : null}
        {row.usingFallback && row.state !== "latest_attempt_failed" ? (
          <span className="ml-2 text-[11px] text-amber-100" data-testid={`memory-family-fallback-${row.family}`}>
            showing last successful run
          </span>
        ) : null}
      </td>
      <td className="hidden px-3 py-2 font-mono text-[11px] text-muted sm:table-cell">
        {row.activeRun ? formatDate(row.activeRun.completed_at ?? row.activeRun.started_at) : "—"}
      </td>
    </tr>
  );
}

function toneClass(tone: Tone): string {
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
