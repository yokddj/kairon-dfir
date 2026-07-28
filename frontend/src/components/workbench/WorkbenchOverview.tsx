import { AlertTriangle, Cpu, Database, HardDrive, Network, ShieldCheck } from "lucide-react";
import { Link, useLocation } from "react-router-dom";
import type { CaseCapabilitiesResponse, CaseCapability } from "../../api/client";

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

function displayLabel(value: string) {
  return value.replace(/_/g, " ").replace(/\b\w/g, (letter) => letter.toUpperCase());
}

function resolveRoute(route: string, caseId: string, pathname: string): string {
  const base = route.replace(":caseId", caseId);
  if (!base.includes(":evidenceId")) return base;
  const match = pathname.match(/^\/cases\/([^/]+)\/m\/([^/]+)/);
  return match?.[2] ? base.replace(":evidenceId", match[2]) : `/cases/${caseId}/m`;
}

function readinessStyle(readiness: string) {
  return STATUS_STYLES[readiness] || "border-line bg-abyss/70 text-muted";
}

function pluralCapability(count: number) {
  return count === 1 ? "capability" : "capabilities";
}

function PlatformHeader({ workbench }: { workbench: Workbench }) {
  const Icon = workbench.id === "memory" ? Cpu : workbench.id === "linux" ? ShieldCheck : HardDrive;
  const overview = workbench.overview;
  return (
    <section className="rounded-[28px] border border-line bg-panel/75 p-6 shadow-panel">
      <div className="flex flex-col gap-4 md:flex-row md:items-start md:justify-between">
        <div className="flex items-start gap-4">
          <div className="rounded-2xl border border-accent/30 bg-accent/10 p-3 text-accent"><Icon size={24} /></div>
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

function CoverageCard({ domain, capabilities, caseId, pathname }: { domain: Workbench["domains"][number]; capabilities: CaseCapability[]; caseId: string; pathname: string }) {
  const ordered = [...capabilities].sort((a, b) => (a.overview?.priority ?? a.nav?.order ?? 999) - (b.overview?.priority ?? b.nav?.order ?? 999));
  const counts = ordered.reduce<Record<string, number>>((acc, capability) => {
    acc[capability.readiness] = (acc[capability.readiness] || 0) + 1;
    return acc;
  }, {});
  const target = ordered[0] ? resolveRoute(ordered[0].route, caseId, pathname) : `/cases/${caseId}/artifacts`;
  return (
    <Link to={target} className="block rounded-3xl border border-line bg-panel/55 p-5 transition hover:border-accent/50 hover:bg-panel/80" data-testid={`coverage-${domain.id}`}>
      <div className="flex items-start justify-between gap-3">
        <div>
          <p className="text-lg font-semibold text-ink">{displayLabel(domain.id)}</p>
          <p className="mt-1 text-xs text-muted">{ordered.length} {pluralCapability(ordered.length)} · {domain.record_count} records</p>
        </div>
        <Database size={18} className="text-muted" />
      </div>
      <div className="mt-4 flex flex-wrap gap-2">
        {Object.entries(counts).map(([status, count]) => <span key={status} className={`rounded-full border px-2.5 py-1 text-[11px] ${readinessStyle(status)}`}>{count} {STATUS_LABELS[status] || displayLabel(status)}</span>)}
      </div>
      <div className="mt-4 space-y-1 text-xs text-muted">
        {ordered.slice(0, 3).map((capability) => <p key={capability.id} className="flex justify-between gap-2"><span>{capability.title}</span><span className="text-ink">{STATUS_LABELS[capability.readiness] || capability.readiness}</span></p>)}
      </div>
    </Link>
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
  const workbench = registry.workbenches.find((item) => item.id === workbenchId);
  if (!workbench) {
    return <section className="rounded-3xl border border-line bg-panel/55 p-6"><p className="text-lg font-semibold text-ink">Workbench unavailable</p><p className="mt-2 text-sm text-muted">The registry has no visible capabilities for this workbench in this case.</p></section>;
  }
  const capabilities = registry.capabilities.filter((capability) => capability.visible && workbench.capability_ids.includes(capability.id));
  const domains = [...workbench.domains].sort((a, b) => Math.min(...a.capability_ids.map((id) => capabilities.find((capability) => capability.id === id)?.overview?.priority ?? 999)) - Math.min(...b.capability_ids.map((id) => capabilities.find((capability) => capability.id === id)?.overview?.priority ?? 999)) || a.id.localeCompare(b.id));
  const overview = workbench.overview;
  return (
    <div className="space-y-5" data-testid={`workbench-overview-${workbench.id}`}>
      <PlatformHeader workbench={workbench} />
      <QuickActionsPanel actions={overview?.quick_actions ?? []} />
      <section>
        <p className="mb-3 font-mono text-xs uppercase tracking-[0.18em] text-accent">Coverage</p>
      <div className="grid gap-4 lg:grid-cols-3">
        {domains.map((domain) => <CoverageCard key={domain.id} domain={domain} capabilities={capabilities.filter((capability) => domain.capability_ids.includes(capability.id))} caseId={caseId} pathname={location.pathname} />)}
      </div>
      </section>
      <MemoryImagesPanel images={overview?.memory_images ?? []} />
      <div className="grid gap-4 lg:grid-cols-2">
        <RecentActivityPanel activity={overview?.recent_activity ?? []} />
        <WarningPanel warnings={overview?.warnings ?? []} />
      </div>
    </div>
  );
}
