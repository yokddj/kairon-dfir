import { ExternalLink } from "lucide-react";
import { Link } from "react-router-dom";

import type { IndicatorResolutionResponse, IndicatorResolutionResult } from "../api/client";

type Props = {
  data?: IndicatorResolutionResponse | null;
  loading?: boolean;
  error?: Error | null;
};

function statusTone(status: string) {
  if (status === "found") return "border-emerald-400/40 bg-emerald-400/10 text-emerald-200";
  if (status === "command_only" || status === "partially_found") return "border-amber-400/40 bg-amber-400/10 text-amber-100";
  if (status === "referenced_not_found" || status === "not_found") return "border-rose-400/35 bg-rose-500/10 text-rose-100";
  return "border-line bg-white/5 text-muted";
}

function sourceSummary(item: IndicatorResolutionResult) {
  const entries = Object.entries(item.counts_by_source || {}).filter(([, count]) => Number(count) > 0);
  if (!entries.length) return "No indexed source confirmed";
  return entries.map(([source, count]) => `${source}: ${count}`).join(" · ");
}

export default function IndicatorResolutionPanel({ data, loading, error }: Props) {
  const results = data?.results ?? [];
  return (
    <div className="rounded-2xl border border-line bg-abyss/70 p-4">
      <div className="flex flex-wrap items-start justify-between gap-3">
        <div>
          <p className="font-mono text-[11px] uppercase tracking-[0.16em] text-muted">Indicators</p>
          <h3 className="mt-1 font-semibold text-ink">Evidence resolution</h3>
          <p className="mt-1 text-sm text-muted">Extracted indicators are resolved against indexed evidence without assuming presence.</p>
        </div>
        <span className="rounded-full border border-line bg-panel/70 px-2 py-1 text-xs text-muted">{results.length} indicators</span>
      </div>
      {loading ? <p className="mt-3 text-sm text-muted">Resolving indicators...</p> : null}
      {error ? <p className="mt-3 text-sm text-danger">{error.message}</p> : null}
      {!loading && !error && !results.length ? <p className="mt-3 text-sm text-muted">No indicators extracted from this context.</p> : null}
      {results.length ? (
        <div className="mt-4 space-y-3">
          {results.map((item) => (
            <div key={`${item.type}-${item.indicator}`} className="rounded-xl border border-line/70 bg-panel/40 p-3">
              <div className="flex flex-wrap items-center gap-2">
                <span className="break-all font-mono text-sm text-ink">{item.indicator}</span>
                <span className="rounded-full border border-line bg-abyss/70 px-2 py-1 text-[11px] uppercase tracking-[0.12em] text-muted">{item.type}</span>
                <span className={`rounded-full border px-2 py-1 text-[11px] uppercase tracking-[0.12em] ${statusTone(item.status)}`}>{item.status}</span>
              </div>
              <p className="mt-2 text-sm text-muted">{item.explanation}</p>
              <p className="mt-2 text-xs text-muted">{sourceSummary(item)}</p>
              {item.suggested_pivots?.length ? (
                <div className="mt-3 flex flex-wrap gap-2">
                  {item.suggested_pivots.map((pivot) => (
                    <Link key={`${item.indicator}-${pivot.label}-${pivot.url}`} to={pivot.url} className="inline-flex items-center gap-1 rounded-lg border border-line px-2.5 py-1.5 text-xs text-accent hover:border-accent/60">
                      <ExternalLink size={12} />
                      {pivot.label}
                    </Link>
                  ))}
                </div>
              ) : null}
            </div>
          ))}
        </div>
      ) : null}
    </div>
  );
}
