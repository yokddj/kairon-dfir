import { Link, useLocation } from "react-router-dom";

type BreadcrumbItem = {
  label: string;
  to?: string;
};

type ContextAction = {
  label: string;
  to: string;
  description?: string;
};

type InvestigationContextProps = {
  caseId?: string | null;
  caseName?: string | null;
  hostId?: string | null;
  host?: string | null;
  evidenceId?: string | null;
  evidenceName?: string | null;
  current: string;
  breadcrumbs?: BreadcrumbItem[];
  actions?: ContextAction[];
};

function shortId(value?: string | null) {
  if (!value) return "All evidence";
  return value.length > 12 ? `${value.slice(0, 8)}...` : value;
}

function appendScope(to: string, host?: string | null, evidenceId?: string | null, hostId?: string | null) {
  if (!host && !evidenceId && !hostId) return to;
  const [path, query = ""] = to.split("?");
  const params = new URLSearchParams(query);
  if (hostId && !params.has("host_id")) params.set("host_id", hostId);
  if (host && !params.has("host")) params.set("host", host);
  if (evidenceId && !params.has("evidence_id")) params.set("evidence_id", evidenceId);
  const nextQuery = params.toString();
  return nextQuery ? `${path}?${nextQuery}` : path;
}

export function InvestigationBreadcrumbs({ items }: { items: BreadcrumbItem[] }) {
  return (
    <nav aria-label="Investigation breadcrumbs" className="flex flex-wrap items-center gap-2 text-xs text-muted">
      {items.map((item, index) => (
        <span key={`${item.label}-${index}`} className="flex items-center gap-2">
          {index > 0 ? <span className="text-line">/</span> : null}
          {item.to ? <Link to={item.to} className="text-accent hover:underline">{item.label}</Link> : <span>{item.label}</span>}
        </span>
      ))}
    </nav>
  );
}

export default function InvestigationContext({ caseId, caseName, hostId, host, evidenceId, evidenceName, current, breadcrumbs, actions }: InvestigationContextProps) {
  const location = useLocation();
  const clearHostHref = (() => {
    const params = new URLSearchParams(location.search);
    params.delete("host_id");
    params.delete("host");
    const query = params.toString();
    return `${location.pathname}${query ? `?${query}` : ""}`;
  })();
  const baseCrumbs = breadcrumbs ?? [
    { label: "Cases", to: "/cases" },
    caseId ? { label: caseName || "Case", to: `/cases/${caseId}` } : { label: "No case" },
    { label: current },
  ];
  const defaultActions: ContextAction[] = caseId
    ? [
        { label: "Search", to: `/cases/${caseId}/search`, description: "Cross-artifact search" },
        { label: "Findings", to: `/cases/${caseId}/findings`, description: "Document notes and confirmed findings" },
        { label: "Timeline", to: `/cases/${caseId}/search?view=timeline&sort=@timestamp&order=asc`, description: "Chronological view" },
        { label: "Artifact Views", to: `/cases/${caseId}/artifacts`, description: "Focused artifact families" },
        { label: "Processing", to: `/cases/${caseId}?tab=processing`, description: "Evidence queue and runs" },
        { label: "Evidence", to: `/cases/${caseId}/evidence`, description: "Upload and ingest" },
      ]
    : [];
  const visibleActions = actions ?? defaultActions;

  return (
    <section className="rounded-3xl border border-line bg-panel/60 p-4 shadow-panel" data-testid="investigation-context">
      <InvestigationBreadcrumbs items={baseCrumbs} />
      <div className="mt-4 grid gap-3 lg:grid-cols-[1fr_auto] lg:items-start">
        <div className="grid gap-3 sm:grid-cols-3">
          <div className="rounded-2xl border border-line bg-abyss/70 px-4 py-3">
            <p className="font-mono text-[10px] uppercase tracking-[0.16em] text-muted">Case</p>
            <p className="mt-1 truncate text-sm font-semibold text-ink" title={caseName || caseId || "No case selected"}>{caseName || caseId || "No case selected"}</p>
          </div>
          <div className="rounded-2xl border border-line bg-abyss/70 px-4 py-3">
            <p className="font-mono text-[10px] uppercase tracking-[0.16em] text-muted">Active host</p>
            <p className="mt-1 truncate text-sm font-semibold text-ink" title={host || "All hosts"}>{host ? `Filtered by ${host}` : "All hosts"}</p>
            {host ? <Link to={clearHostHref} className="mt-1 inline-block text-xs text-accent hover:underline">Clear host filter</Link> : null}
          </div>
          <div className="rounded-2xl border border-line bg-abyss/70 px-4 py-3">
            <p className="font-mono text-[10px] uppercase tracking-[0.16em] text-muted">Evidence</p>
            <p className="mt-1 truncate text-sm font-semibold text-ink" title={evidenceName || evidenceId || "All evidence"}>{evidenceName || shortId(evidenceId)}</p>
          </div>
        </div>
        {visibleActions.length ? (
          <div className="flex flex-wrap gap-2 lg:max-w-md lg:justify-end" aria-label="Investigation pivots">
            {visibleActions.map((action) => (
              <Link key={action.label} to={appendScope(action.to, host, evidenceId, hostId)} title={action.description} className="rounded-full border border-line bg-abyss/80 px-3 py-1.5 text-xs font-medium text-muted hover:border-accent/40 hover:text-accent">
                {action.label}
              </Link>
            ))}
          </div>
        ) : null}
      </div>
    </section>
  );
}
