import { useMemo, useState } from "react";
import { Link } from "react-router-dom";

import coverageData from "../../../docs/data/parser-coverage.json";

type CoverageEntry = {
  family: string;
  display_name: string;
  status: string;
  input_formats: string[];
  source_tools: string[];
  views: string[];
  host_aware: boolean;
  timeline_supported: boolean;
  limitations: string[];
};

const entries = coverageData as CoverageEntry[];

export default function ParserCoveragePage() {
  const [query, setQuery] = useState("");
  const [status, setStatus] = useState("all");
  const [format, setFormat] = useState("all");
  const statuses = useMemo(() => ["all", ...Array.from(new Set(entries.map((item) => item.status))).sort()], []);
  const formats = useMemo(() => ["all", ...Array.from(new Set(entries.flatMap((item) => item.input_formats))).sort()], []);
  const filtered = useMemo(() => {
    const normalizedQuery = query.trim().toLowerCase();
    return entries.filter((item) => {
      const matchesQuery = !normalizedQuery || [item.family, item.display_name, ...item.input_formats, ...item.source_tools, ...item.views, ...item.limitations].join(" ").toLowerCase().includes(normalizedQuery);
      const matchesStatus = status === "all" || item.status === status;
      const matchesFormat = format === "all" || item.input_formats.includes(format);
      return matchesQuery && matchesStatus && matchesFormat;
    });
  }, [format, query, status]);

  return (
    <div className="space-y-6" data-testid="parser-coverage-page">
      <section className="rounded-[28px] border border-line bg-panel/70 p-6 shadow-panel">
        <div className="flex flex-col gap-4 lg:flex-row lg:items-start lg:justify-between">
          <div>
            <p className="font-mono text-xs uppercase tracking-[0.24em] text-accent">Parser Coverage</p>
            <h2 className="mt-2 text-3xl font-semibold">Parser Coverage Matrix</h2>
            <p className="mt-3 max-w-3xl text-sm text-muted">Search exact parser coverage by family, status, input format, source tool and views. This matrix is generated from the structured coverage source and uses conservative support labels.</p>
          </div>
          <Link to="/docs/parser-coverage" className="rounded-2xl border border-line bg-abyss/70 px-4 py-2 text-sm text-muted">Open documentation</Link>
        </div>
        <div className="mt-5 grid gap-3 lg:grid-cols-[1fr_220px_220px]">
          <input value={query} onChange={(event) => setQuery(event.target.value)} placeholder="Search family, fields, tools or limitations" className="rounded-2xl border border-line bg-abyss/80 px-4 py-3 text-sm outline-none focus:border-accent/50" />
          <select value={status} onChange={(event) => setStatus(event.target.value)} className="rounded-2xl border border-line bg-abyss/80 px-4 py-3 text-sm text-ink">
            {statuses.map((item) => <option key={item} value={item}>{item === "all" ? "All statuses" : item}</option>)}
          </select>
          <select value={format} onChange={(event) => setFormat(event.target.value)} className="rounded-2xl border border-line bg-abyss/80 px-4 py-3 text-sm text-ink">
            {formats.map((item) => <option key={item} value={item}>{item === "all" ? "All formats" : item}</option>)}
          </select>
        </div>
      </section>

      {!filtered.length ? (
        <div className="rounded-3xl border border-line bg-panel/40 p-5 text-sm text-muted">No parser coverage entries match the current filters. Try clearing the search, status or input format filter.</div>
      ) : (
        <section className="overflow-hidden rounded-3xl border border-line bg-panel/70 shadow-panel">
          <div className="overflow-x-auto">
            <table className="min-w-full text-left text-sm">
              <thead className="border-b border-line bg-abyss/70 font-mono text-[11px] uppercase tracking-[0.14em] text-muted">
                <tr>
                  <th className="px-4 py-3">Family</th>
                  <th className="px-4 py-3">Status</th>
                  <th className="px-4 py-3">Input formats</th>
                  <th className="px-4 py-3">Source tools</th>
                  <th className="px-4 py-3">Views</th>
                  <th className="px-4 py-3">Host-aware</th>
                  <th className="px-4 py-3">Timeline</th>
                  <th className="px-4 py-3">Limitations</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-line/70">
                {filtered.map((item) => (
                  <tr key={item.family}>
                    <td className="px-4 py-3"><p className="font-semibold text-ink">{item.display_name}</p><p className="mt-1 font-mono text-xs text-muted">{item.family}</p></td>
                    <td className="px-4 py-3"><span className={`rounded-full border px-3 py-1 font-mono text-[11px] uppercase tracking-[0.12em] ${statusClass(item.status)}`}>{item.status}</span></td>
                    <td className="max-w-[260px] px-4 py-3 text-muted">{item.input_formats.join(", ") || "-"}</td>
                    <td className="max-w-[260px] px-4 py-3 text-muted">{item.source_tools.join(", ") || "-"}</td>
                    <td className="max-w-[260px] px-4 py-3 text-muted">{item.views.join(", ") || "-"}</td>
                    <td className="px-4 py-3 text-muted">{item.host_aware ? "yes" : "no"}</td>
                    <td className="px-4 py-3 text-muted">{item.timeline_supported ? "yes" : "no"}</td>
                    <td className="max-w-[360px] px-4 py-3 text-muted">{item.limitations.slice(0, 2).join(" ") || "-"}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </section>
      )}
    </div>
  );
}

function statusClass(status: string) {
  if (status === "stable") return "border-mint/30 bg-mint/10 text-mint";
  if (status === "partial") return "border-amber/30 bg-amber/10 text-amber";
  if (status === "experimental") return "border-accent/30 bg-accent/10 text-accent";
  if (status === "unsupported" || status === "deprecated") return "border-danger/30 bg-danger/10 text-danger";
  return "border-line bg-abyss/60 text-muted";
}
