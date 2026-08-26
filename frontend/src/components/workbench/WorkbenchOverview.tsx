import { useRef, type KeyboardEvent } from "react";
import { AlertTriangle, Network } from "lucide-react";
import { Link, useLocation, useSearchParams } from "react-router-dom";
import type { CaseCapabilitiesResponse, CaseCapability } from "../../api/client";
import { useActiveCase } from "../../context/ActiveCaseContext";
import { displayLabel } from "../../lib/displayLabel";
import { resolveSurfaceIcon } from "../../lib/surfaceIcons";

type Workbench = CaseCapabilitiesResponse["workbenches"][number];

const STATUS_LABELS: Record<string, string> = {
  has_data: "has data",
  processing: "processing",
  degraded: "degraded",
  failed: "failed",
  not_collected: "no data",
  empty: "no data",
  not_applicable: "unsupported",
};

const STATUS_STYLES: Record<string, string> = {
  has_data: "border-mint/30 bg-mint/10 text-mint",
  processing: "border-sky-400/30 bg-sky-400/10 text-sky-200",
  degraded: "border-warning/40 bg-warning/10 text-warning",
  failed: "border-danger/40 bg-danger/10 text-danger",
  not_collected: "border-line bg-abyss/70 text-muted",
  empty: "border-line bg-abyss/70 text-muted",
  not_applicable: "border-line bg-abyss/40 text-muted/70",
};

// Evidence priority for routes that carry :evidenceId: (1) an evidence id
// already present in the current pathname -- the analyst is already inside
// that evidence's context, so it wins; (2) selectedEvidenceId from
// ActiveCaseContext -- the analyst's last-picked evidence elsewhere in the
// app; (3) none. No selector, no modal -- this is purely a priority lookup
// over data that already exists.
function resolveEvidenceId(pathname: string, selectedEvidenceId: string): string | null {
  const match = pathname.match(/^\/cases\/([^/]+)\/m\/([^/]+)/);
  if (match?.[2]) return match[2];
  return selectedEvidenceId || null;
}

// Routes without :evidenceId resolve unconditionally. Routes with
// :evidenceId return null when no evidence is available from either
// priority source -- callers must render an explicit "needs evidence"
// state instead of silently landing on the workbench root.
function resolveRoute(route: string, caseId: string, evidenceId: string | null): string | null {
  const base = route.replace(":caseId", caseId);
  if (!base.includes(":evidenceId")) return base;
  return evidenceId ? base.replace(":evidenceId", evidenceId) : null;
}

function readinessStyle(readiness: string) {
  return STATUS_STYLES[readiness] || "border-line bg-abyss/70 text-muted";
}

function pluralCapability(count: number) {
  return count === 1 ? "capability" : "capabilities";
}

// A domain requested via ?domain= that isn't in this workbench's own domain
// list (missing, unknown, empty, or left over from a different surface)
// falls back to the first domain of the already-sorted list -- the same
// domain a fresh visit with no ?domain= at all would land on. A workbench
// with no domains yields null; callers must not assume a domain exists.
function resolveActiveDomainId(domains: Array<{ id: string }>, requested: string | null): string | null {
  if (!domains.length) return null;
  if (requested && domains.some((domain) => domain.id === requested)) return requested;
  return domains[0].id;
}

// Severity order for the compact per-tab badge: the worst status present
// wins, so a tab with one failed capability among ten healthy ones still
// reads as "needs attention" at a glance.
const READINESS_SEVERITY = ["failed", "degraded", "processing", "not_collected", "empty", "has_data", "not_applicable"];

function readinessCounts(capabilities: CaseCapability[]): Record<string, number> {
  return capabilities.reduce<Record<string, number>>((acc, capability) => {
    acc[capability.readiness] = (acc[capability.readiness] || 0) + 1;
    return acc;
  }, {});
}

function dominantReadiness(counts: Record<string, number>): string | null {
  for (const status of READINESS_SEVERITY) {
    if (counts[status]) return status;
  }
  return Object.keys(counts)[0] ?? null;
}

function PlatformHeader({ workbench }: { workbench: Workbench }) {
  const Icon = resolveSurfaceIcon(workbench.icon);
  const overview = workbench.overview;
  return (
    <section className="rounded-[28px] border border-line bg-panel/75 p-6 shadow-panel">
      <div className="flex flex-col gap-4 md:flex-row md:items-start md:justify-between">
        <div className="flex items-start gap-4">
          <div className="rounded-2xl border border-accent/30 bg-accent/10 p-3 text-accent" data-testid="surface-icon"><Icon size={24} /></div>
          <div>
            <p className="font-mono text-xs uppercase tracking-[0.22em] text-accent">Workbench</p>
            <h1 className="mt-2 text-3xl font-semibold text-ink">{workbench.label}</h1>
            <p className="mt-2 text-sm text-muted">Evidence coverage, readiness, warnings and next actions for this investigation surface.</p>
          </div>
        </div>
        <div className="grid grid-cols-3 gap-2 text-center text-sm">
          <div className="rounded-2xl border border-line bg-abyss/70 px-4 py-3"><p className="font-mono text-[11px] uppercase tracking-[0.14em] text-muted">Hosts</p><p className="mt-1 text-xl text-ink">{overview?.host_count ?? 0}</p></div>
          <div className="rounded-2xl border border-line bg-abyss/70 px-4 py-3"><p className="font-mono text-[11px] uppercase tracking-[0.14em] text-muted">Evidence</p><p className="mt-1 text-xl text-ink">{overview?.evidence_count ?? 0}</p></div>
          <div className="rounded-2xl border border-line bg-abyss/70 px-4 py-3"><p className="font-mono text-[11px] uppercase tracking-[0.14em] text-muted">State</p><p className="mt-1 text-sm text-ink">{displayLabel(overview?.processing_state || "empty")}</p></div>
        </div>
      </div>
    </section>
  );
}

// Surface-wide Readiness/Coverage summary. Renders overview.coverage
// exactly as the registry computed it -- capability_count and
// status_counts are consumed literally, never recomputed here, so this
// stays identical no matter which domain tab is active.
function SurfaceCoverageSummary({ coverage }: { coverage: NonNullable<Workbench["overview"]>["coverage"] }) {
  const entries = Object.entries(coverage.status_counts);
  return (
    <section className="rounded-3xl border border-line bg-panel/55 p-5" data-testid="surface-coverage-summary">
      <div className="flex items-center justify-between gap-3">
        <p className="font-mono text-xs uppercase tracking-[0.18em] text-accent">Coverage</p>
        <span className="text-xs text-muted">{coverage.capability_count} {pluralCapability(coverage.capability_count)}</span>
      </div>
      <div className="mt-4 flex flex-wrap gap-2">
        {entries.length ? entries.map(([status, count]) => <span key={status} className={`rounded-full border px-2.5 py-1 text-[11px] ${readinessStyle(status)}`}>{count} {STATUS_LABELS[status] || displayLabel(status)}</span>) : <p className="text-sm text-muted">No capability data yet for this workbench.</p>}
      </div>
    </section>
  );
}

// One card per visible capability. The card itself is never a link -- only
// its action is -- so a missing-evidence state can be represented as a
// genuinely disabled control instead of a link with a fake or misleading
// destination. Readiness is purely informative here; it never drives
// whether the action is enabled (only missing evidence does).
function CapabilityCard({ capability, caseId, evidenceId, warnings }: { capability: CaseCapability; caseId: string; evidenceId: string | null; warnings: NonNullable<Workbench["overview"]>["warnings"] }) {
  const route = resolveRoute(capability.route, caseId, evidenceId);
  const warning = warnings.find((item) => item.id.startsWith(`${capability.id}.`));
  const actionLabel = capability.overview?.quick_action || "Open";
  return (
    <div className="rounded-3xl border border-line bg-panel/55 p-5" data-testid={`capability-${capability.id}`}>
      <div className="flex items-start justify-between gap-3">
        <p className="text-lg font-semibold text-ink">{capability.title}</p>
        <span className={`rounded-full border px-2.5 py-1 text-[11px] ${readinessStyle(capability.readiness)}`}>{STATUS_LABELS[capability.readiness] || displayLabel(capability.readiness)}</span>
      </div>
      <p className="mt-1 text-xs text-muted">{capability.record_count} records · {capability.artifact_count} artifacts</p>
      {warning ? (
        <div className="mt-3 rounded-2xl border border-warning/40 bg-warning/10 p-3 text-sm">
          <p className="flex items-center gap-2 font-semibold text-warning"><AlertTriangle size={15} />{warning.title}</p>
          <p className="mt-1 text-muted">{warning.detail}</p>
        </div>
      ) : null}
      <div className="mt-4">
        {route ? (
          <Link to={route} className="inline-block rounded-2xl border border-accent/40 bg-accent/10 px-4 py-2 text-sm font-semibold text-accent transition hover:bg-accent/20 focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-accent/60">
            {actionLabel}
          </Link>
        ) : (
          <div>
            <button type="button" disabled aria-label={`${actionLabel} unavailable -- evidence required`} className="cursor-not-allowed rounded-2xl border border-line bg-abyss/40 px-4 py-2 text-sm font-semibold text-muted/60">
              {actionLabel}
            </button>
            <p className="mt-2 text-xs text-muted">Select memory evidence</p>
          </div>
        )}
      </div>
    </div>
  );
}

type DomainTab = { id: string; capabilities: CaseCapability[] };

// WAI-ARIA Tabs pattern with manual activation: arrow/Home/End only move DOM
// focus between tabs (roving tabindex). Enter/Space are deliberately NOT
// handled here -- each tab is a real <button>, so the browser (and
// userEvent in tests) already fires a click from Enter/Space on a focused
// button. Handling them again here would double-activate the same
// selection and push two history entries for one user action.
function DomainTabBar({ domains, activeDomainId, onSelect }: { domains: DomainTab[]; activeDomainId: string; onSelect: (domainId: string) => void }) {
  const tabRefs = useRef<Record<string, HTMLButtonElement | null>>({});

  function focusDomain(domainId: string) {
    tabRefs.current[domainId]?.focus();
  }

  function handleKeyDown(event: KeyboardEvent<HTMLButtonElement>, index: number) {
    if (event.key === "ArrowRight") {
      event.preventDefault();
      focusDomain(domains[(index + 1) % domains.length].id);
    } else if (event.key === "ArrowLeft") {
      event.preventDefault();
      focusDomain(domains[(index - 1 + domains.length) % domains.length].id);
    } else if (event.key === "Home") {
      event.preventDefault();
      focusDomain(domains[0].id);
    } else if (event.key === "End") {
      event.preventDefault();
      focusDomain(domains[domains.length - 1].id);
    }
  }

  return (
    <div role="tablist" aria-label="Domains" className="flex flex-wrap gap-2">
      {domains.map((domain, index) => {
        const selected = domain.id === activeDomainId;
        const counts = readinessCounts(domain.capabilities);
        const dominant = dominantReadiness(counts);
        const total = domain.capabilities.length;
        return (
          <button
            key={domain.id}
            ref={(element) => { tabRefs.current[domain.id] = element; }}
            type="button"
            role="tab"
            id={`domain-tab-${domain.id}`}
            aria-selected={selected}
            aria-controls={`domain-panel-${domain.id}`}
            tabIndex={selected ? 0 : -1}
            onClick={() => onSelect(domain.id)}
            onKeyDown={(event) => handleKeyDown(event, index)}
            className={`flex items-center gap-2 rounded-2xl border px-4 py-2 text-sm font-semibold transition focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-accent/60 ${selected ? "border-accent/50 bg-accent/10 text-accent" : "border-line bg-panel/55 text-muted hover:border-accent/30 hover:text-ink"}`}
          >
            <span>{displayLabel(domain.id)}</span>
            {dominant ? <span className={`rounded-full border px-2 py-0.5 text-[10px] ${readinessStyle(dominant)}`}>{total}</span> : null}
          </button>
        );
      })}
    </div>
  );
}

function QuickActionsPanel({ actions }: { actions: NonNullable<Workbench["overview"]>["quick_actions"] }) {
  return (
    <section className="rounded-3xl border border-line bg-panel/55 p-5">
      <p className="font-mono text-xs uppercase tracking-[0.18em] text-accent">Quick actions</p>
      <div className="mt-4 flex flex-wrap gap-2">
        {actions.length ? actions.map((action) => <Link key={action.id} to={action.route} className="rounded-2xl border border-accent/40 bg-accent/10 px-4 py-2 text-sm font-semibold text-accent">{action.label}</Link>) : <p className="text-sm text-muted">No registry shortcuts are available for this workbench yet.</p>}
      </div>
    </section>
  );
}

function WarningPanel({ warnings }: { warnings: NonNullable<Workbench["overview"]>["warnings"] }) {
  return (
    <section className="rounded-3xl border border-line bg-panel/55 p-5">
      <p className="font-mono text-xs uppercase tracking-[0.18em] text-accent">Warnings</p>
      <div className="mt-4 space-y-2">
        {warnings.length ? warnings.map((warning) => <div key={warning.id} className="rounded-2xl border border-warning/40 bg-warning/10 p-3 text-sm"><p className="flex items-center gap-2 font-semibold text-warning"><AlertTriangle size={15} />{warning.title}</p><p className="mt-1 text-muted">{warning.detail}</p></div>) : <p className="text-sm text-muted">No investigation blockers reported by the registry.</p>}
      </div>
    </section>
  );
}

function RecentActivityPanel({ activity }: { activity: NonNullable<Workbench["overview"]>["recent_activity"] }) {
  return (
    <section className="rounded-3xl border border-line bg-panel/55 p-5">
      <p className="font-mono text-xs uppercase tracking-[0.18em] text-accent">Recent investigation activity</p>
      <div className="mt-4 space-y-2">
        {activity.length ? activity.map((item, index) => <Link key={`${item.kind}-${index}`} to={item.route} className="block rounded-2xl border border-line bg-abyss/70 p-3 text-sm hover:border-accent/40"><span className="text-ink">{item.title}</span><span className="ml-2 text-xs text-muted">{displayLabel(item.kind)}</span></Link>) : <p className="text-sm text-muted">No recent activity scoped to this workbench.</p>}
      </div>
    </section>
  );
}

function MemoryImagesPanel({ images }: { images: NonNullable<Workbench["overview"]>["memory_images"] }) {
  if (!images.length) return null;
  return (
    <section className="rounded-3xl border border-line bg-panel/55 p-5">
      <p className="font-mono text-xs uppercase tracking-[0.18em] text-accent">Memory images</p>
      <div className="mt-4 grid gap-3 lg:grid-cols-2">
        {images.map((image) => <Link key={image.id} to={image.route} className="rounded-2xl border border-line bg-abyss/70 p-4 hover:border-accent/50"><p className="font-semibold text-ink">{image.name}</p><p className="mt-1 text-xs text-muted">Host: {image.detected_host || image.host_id || "Unassigned"} · OS: {displayLabel(image.detected_os || "unknown")}</p><p className="mt-2 text-xs text-muted">Preparation: {displayLabel(image.preparation_state)} · Symbols: {displayLabel(image.symbol_state)} · Plugin records: {image.plugin_record_count}</p></Link>)}
      </div>
    </section>
  );
}

export function WorkbenchOverview({ registry, workbenchId, caseId }: { registry: CaseCapabilitiesResponse; workbenchId: string; caseId: string }) {
  const location = useLocation();
  const { selectedEvidenceId } = useActiveCase();
  const [searchParams, setSearchParams] = useSearchParams();
  const workbench = registry.workbenches.find((item) => item.id === workbenchId);
  if (!workbench) {
    return <section className="rounded-3xl border border-line bg-panel/55 p-6"><p className="text-lg font-semibold text-ink">Workbench unavailable</p><p className="mt-2 text-sm text-muted">The registry has no visible capabilities for this workbench in this case.</p></section>;
  }
  const capabilities = registry.capabilities.filter((capability) => capability.visible && workbench.capability_ids.includes(capability.id));
  const domains = [...workbench.domains].sort((a, b) => Math.min(...a.capability_ids.map((id) => capabilities.find((capability) => capability.id === id)?.overview?.priority ?? 999)) - Math.min(...b.capability_ids.map((id) => capabilities.find((capability) => capability.id === id)?.overview?.priority ?? 999)) || a.id.localeCompare(b.id));
  const overview = workbench.overview;

  const domainTabs: DomainTab[] = domains.map((domain) => ({ id: domain.id, capabilities: capabilities.filter((capability) => domain.capability_ids.includes(capability.id)) }));
  const activeDomainId = resolveActiveDomainId(domains, searchParams.get("domain"));
  const activeDomain = activeDomainId ? domains.find((domain) => domain.id === activeDomainId) : undefined;
  const activeDomainCapabilities = activeDomain
    ? [...capabilities.filter((capability) => activeDomain.capability_ids.includes(capability.id))].sort((a, b) => (a.overview?.priority ?? a.nav?.order ?? 999) - (b.overview?.priority ?? b.nav?.order ?? 999))
    : [];
  const evidenceId = resolveEvidenceId(location.pathname, selectedEvidenceId);

  function selectDomain(domainId: string) {
    setSearchParams((current) => {
      const next = new URLSearchParams(current);
      next.set("domain", domainId);
      return next;
    });
  }

  const isMemoryWorkbench = workbench.id === "memory";

  const coverageSection = (
    <section>
      <p className="mb-3 font-mono text-xs uppercase tracking-[0.18em] text-accent">Coverage</p>
      {activeDomainId ? (
        <>
          <DomainTabBar domains={domainTabs} activeDomainId={activeDomainId} onSelect={selectDomain} />
          {activeDomain ? (
            <div role="tabpanel" id={`domain-panel-${activeDomain.id}`} aria-labelledby={`domain-tab-${activeDomain.id}`} className="mt-4 grid gap-4 md:grid-cols-2 xl:grid-cols-3">
              {activeDomainCapabilities.map((capability) => <CapabilityCard key={capability.id} capability={capability} caseId={caseId} evidenceId={evidenceId} warnings={overview?.warnings ?? []} />)}
            </div>
          ) : null}
        </>
      ) : (
        <p className="text-sm text-muted">No domains are visible for this workbench yet.</p>
      )}
    </section>
  );

  if (isMemoryWorkbench) {
    return (
      <div className="space-y-5" data-testid={`workbench-overview-${workbench.id}`}>
        <PlatformHeader workbench={workbench} />
        <MemoryImagesPanel images={overview?.memory_images ?? []} />
        <details className="rounded-[28px] border border-line bg-panel/60 shadow-panel">
          <summary className="cursor-pointer px-5 py-4 font-mono text-xs uppercase tracking-[0.18em] text-accent">
            Capability coverage
          </summary>
          <div className="space-y-4 px-5 pb-5">
            <SurfaceCoverageSummary coverage={overview?.coverage ?? { capability_count: 0, status_counts: {} }} />
            <QuickActionsPanel actions={overview?.quick_actions ?? []} />
            {coverageSection}
          </div>
        </details>
        <div className="grid gap-4 lg:grid-cols-2">
          <RecentActivityPanel activity={overview?.recent_activity ?? []} />
          <WarningPanel warnings={overview?.warnings ?? []} />
        </div>
      </div>
    );
  }

  return (
    <div className="space-y-5" data-testid={`workbench-overview-${workbench.id}`}>
      <PlatformHeader workbench={workbench} />
      <SurfaceCoverageSummary coverage={overview?.coverage ?? { capability_count: 0, status_counts: {} }} />
      <QuickActionsPanel actions={overview?.quick_actions ?? []} />
      {coverageSection}
      <MemoryImagesPanel images={overview?.memory_images ?? []} />
      <div className="grid gap-4 lg:grid-cols-2">
        <RecentActivityPanel activity={overview?.recent_activity ?? []} />
        <WarningPanel warnings={overview?.warnings ?? []} />
      </div>
    </div>
  );
}
