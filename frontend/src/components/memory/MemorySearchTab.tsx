import { useState } from "react";
import { useQuery } from "@tanstack/react-query";
import { api, type MemorySearchParams, type MemorySearchResult } from "../../api/client";
import type { MemoryTab } from "../../lib/memoryWorkspaceState";

const FAMILIES = [
  ["processes", "Processes"],
  ["command_lines", "Command lines"],
  ["network", "Network"],
  ["environment", "Environment"],
  ["sids", "SIDs"],
  ["privileges", "Privileges"],
  ["modules", "Modules"],
  ["handles", "Handles"],
  ["kernel", "Kernel"],
  ["drivers", "Drivers"],
  ["suspicious", "Suspicious memory"],
  ["vads", "VADs"],
  ["system", "System"],
] as const;

const PAGE_SIZES = [50, 100, 250, 500] as const;

type Props = {
  caseId: string;
  evidenceId?: string;
  selectedRunId: string | null;
  onSelectRunId: (runId: string | null) => void;
  onSelectEntityId: (entityId: string | null) => void;
  onJumpToTab: (tab: MemoryTab) => void;
};

function interpretation(query: string, server?: string): string {
  if (server && server !== "none") return server.replaceAll("_", " ");
  const text = query.trim();
  if (!text) return "No query yet";
  if (/^S-\d(-\d+)+$/i.test(text)) return "SID exact";
  if (/^\[?[a-f0-9:.]+\]?$/i.test(text) && text.includes(".")) return "IP address";
  if (/^\d+$/.test(text)) return "Numeric exact";
  return "Full text";
}

function Pagination({ page, totalPages, total, pageSize, onPage }: { page: number; totalPages: number; total: number; pageSize: number; onPage: (page: number) => void }) {
  const start = total === 0 ? 0 : (page - 1) * pageSize + 1;
  const end = Math.min(total, page * pageSize);
  return (
    <div className="flex flex-wrap items-center justify-between gap-3 text-xs text-muted" data-testid="memory-search-pagination">
      <span>{start}-{end} of {total} · page {page} of {totalPages || 1}</span>
      <div className="flex gap-2">
        <button type="button" className="rounded-lg border border-line px-2 py-1 disabled:opacity-40" disabled={page <= 1} onClick={() => onPage(page - 1)}>Previous</button>
        <button type="button" className="rounded-lg border border-line px-2 py-1 disabled:opacity-40" disabled={totalPages === 0 || page >= totalPages} onClick={() => onPage(page + 1)}>Next</button>
      </div>
    </div>
  );
}

function ResultRow({ result, onOpen }: { result: MemorySearchResult; onOpen: (result: MemorySearchResult, mode: "inspect" | "graph" | "source" | "raw") => void }) {
  return (
    <tr className="border-t border-line/60 align-top" data-testid="memory-search-result">
      <td className="p-3 text-xs text-muted">{result.artifact_family}<br /><span className="font-mono">{result.artifact_type}</span></td>
      <td className="p-3 text-xs">{result.timestamp || "Unknown"}</td>
      <td className="p-3 text-xs">{result.process_name || "-"}<br />{result.pid !== undefined && result.pid !== null ? <span className="font-mono text-muted">PID {result.pid}</span> : null}</td>
      <td className="max-w-xl p-3 text-sm"><div className="font-medium text-ink">{result.title}</div><div className="mt-1 truncate text-xs text-muted" title={result.summary || ""}>{result.summary || "No summary"}</div></td>
      <td className="p-3 text-xs"><span className="font-mono">{result.source_plugin || "unknown"}</span><br />Run <span className="font-mono">{String(result.memory_run_id || "-").slice(0, 8)}</span></td>
      <td className="p-3 text-xs">{result.matched_fields.length ? result.matched_fields.join(", ") : "exact/filter"}</td>
      <td className="p-3">
        <div className="flex flex-wrap gap-2">
          <button type="button" className="rounded-lg bg-accent px-2 py-1 text-xs text-abyss" onClick={() => onOpen(result, "inspect")}>Inspect</button>
          {result.process_entity_id ? <button type="button" className="rounded-lg border border-line px-2 py-1 text-xs" onClick={() => onOpen(result, "graph")}>Focus graph</button> : null}
          <button type="button" className="rounded-lg border border-line px-2 py-1 text-xs" onClick={() => onOpen(result, "source")}>Open source</button>
          <button type="button" className="rounded-lg border border-line px-2 py-1 text-xs" onClick={() => onOpen(result, "raw")}>Raw</button>
        </div>
      </td>
    </tr>
  );
}

export function MemorySearchTab({ caseId, evidenceId, selectedRunId, onSelectRunId, onSelectEntityId, onJumpToTab }: Props) {
  const [draft, setDraft] = useState("");
  const [query, setQuery] = useState("");
  const [families, setFamilies] = useState<string[]>([]);
  const [page, setPage] = useState(1);
  const [pageSize, setPageSize] = useState<number>(100);
  const [sort, setSort] = useState("relevance");
  const [facet, setFacet] = useState<{ key: string; value: string } | null>(null);
  const [hasSearched, setHasSearched] = useState(false);

  const params: MemorySearchParams = { evidence_id: evidenceId || "", query, page, page_size: pageSize, sort };
  if (families.length) params.artifact_types = families;
  if (selectedRunId) params.run_id = selectedRunId;
  if (facet?.key === "artifact_type") params.artifact_types = [facet.value];
  if (facet?.key === "source_plugin") params.source_plugin = facet.value;
  if (facet?.key === "protocol") params.protocol = facet.value;
  if (facet?.key === "network_state") params.state = facet.value;
  if (facet?.key === "has_process") params.has_process = facet.value === "linked";

  const searchQuery = useQuery({
    queryKey: ["memory-search", caseId, params],
    queryFn: () => api.searchMemoryArtifacts(caseId, params),
    enabled: Boolean(caseId && evidenceId && (hasSearched || query || families.length || facet || selectedRunId)),
    refetchOnWindowFocus: false,
  });

  const data = searchQuery.data;
  const submit = () => { setQuery(draft.trim()); setPage(1); setHasSearched(true); };
  const resetToFirst = (fn: () => void) => { fn(); setPage(1); };
  const onOpen = (result: MemorySearchResult, mode: "inspect" | "graph" | "source" | "raw") => {
    const target = result.navigation_target;
    if (target.run_id) onSelectRunId(target.run_id);
    if (target.process_entity_id) onSelectEntityId(target.process_entity_id);
    if (mode === "graph") onJumpToTab("graph");
    else if (mode === "raw") onJumpToTab("raw");
    else onJumpToTab((target.tab as any) || "artifacts");
  };

  if (!evidenceId) {
    return <section className="rounded-2xl border border-line bg-panel/60 p-5 text-sm text-muted">Select one memory Evidence to search normalized memory artifacts.</section>;
  }

  return (
    <section className="space-y-4" data-testid="memory-search-tab">
      <div className="rounded-2xl border border-line bg-panel/70 p-5">
        <div className="flex flex-col gap-3 lg:flex-row lg:items-end">
          <label className="flex-1 text-xs text-muted">Memory query
            <input value={draft} onChange={(event) => setDraft(event.target.value)} onKeyDown={(event) => { if (event.key === "Enter") submit(); }} placeholder="PID, IP, port, SID, command line, path..." className="mt-1 w-full rounded-xl border border-line bg-abyss px-3 py-2 text-sm text-ink" data-testid="memory-search-input" />
          </label>
          <button type="button" onClick={submit} className="rounded-xl bg-accent px-4 py-2 text-sm font-semibold text-abyss" data-testid="memory-search-submit">Search</button>
          <button type="button" onClick={() => { setDraft(""); setQuery(""); setFacet(null); setPage(1); setHasSearched(false); }} className="rounded-xl border border-line px-4 py-2 text-sm text-muted">Clear</button>
        </div>
        <div className="mt-3 flex flex-wrap gap-3 text-xs text-muted">
          <span data-testid="memory-search-interpretation">Interpretation: {interpretation(query || draft, data?.query_interpretation)}</span>
          <label>Sort <select value={sort} onChange={(e) => resetToFirst(() => setSort(e.target.value))} className="ml-1 rounded-lg border border-line bg-abyss px-2 py-1"><option value="relevance">Relevance</option><option value="newest">Newest</option><option value="oldest">Oldest</option><option value="artifact_type">Artifact type</option><option value="pid">PID</option><option value="process_name">Process name</option></select></label>
          <label>Page size <select value={pageSize} onChange={(e) => resetToFirst(() => setPageSize(Number(e.target.value)))} className="ml-1 rounded-lg border border-line bg-abyss px-2 py-1" data-testid="memory-search-page-size">{PAGE_SIZES.map((size) => <option key={size} value={size}>{size}</option>)}</select></label>
        </div>
      </div>

      <div className="rounded-2xl border border-line bg-panel/60 p-4" data-testid="memory-search-family-filters">
        <div className="mb-2 text-xs uppercase tracking-[0.18em] text-muted">Artifact families</div>
        <div className="flex flex-wrap gap-2">
          {FAMILIES.map(([key, label]) => {
            const active = families.includes(key);
            return <button key={key} type="button" onClick={() => resetToFirst(() => setFamilies(active ? families.filter((f) => f !== key) : [...families, key]))} className={`rounded-lg px-2 py-1 text-xs ${active ? "bg-accent text-abyss" : "border border-line text-muted"}`}>{label}</button>;
          })}
        </div>
      </div>

      {searchQuery.isError ? <div className="rounded-2xl border border-rose-400/30 bg-rose-500/10 p-4 text-sm text-rose-100" data-testid="memory-search-error">{searchQuery.error instanceof Error ? searchQuery.error.message : "Memory search failed"}</div> : null}
      {!searchQuery.isFetching && !data ? <div className="rounded-2xl border border-line bg-panel/60 p-5 text-sm text-muted" data-testid="memory-search-empty-initial">Enter a query or select a family to search this Evidence.</div> : null}

      {data ? (
        <div className="grid gap-4 xl:grid-cols-[260px_1fr]">
          <aside className="rounded-2xl border border-line bg-panel/60 p-4" data-testid="memory-search-facets">
            <div className="mb-2 flex items-center justify-between text-xs"><span className="uppercase tracking-[0.18em] text-muted">Facets</span>{facet ? <button type="button" className="text-accent" onClick={() => { setFacet(null); setPage(1); }}>Clear</button> : null}</div>
            {Object.entries(data.facets).map(([key, values]) => (
              <div key={key} className="mb-3">
                <div className="mb-1 text-xs font-semibold text-muted">{key.replaceAll("_", " ")}</div>
                {Object.entries(values).slice(0, 8).map(([value, count]) => <button key={`${key}:${value}`} type="button" className="block w-full rounded-lg px-2 py-1 text-left text-xs hover:bg-abyss" onClick={() => { setFacet({ key, value }); setPage(1); }}>{value} <span className="float-right text-muted">{count}</span></button>)}
              </div>
            ))}
            <div className="mt-4 text-xs text-muted" data-testid="memory-search-coverage">Available: {data.coverage.artifact_families_available.join(", ") || "none"}{data.coverage.raw_only_fallback ? " · raw-only fallback available" : ""}</div>
          </aside>
          <div className="space-y-3">
            <Pagination page={data.page} totalPages={data.total_pages} total={data.total} pageSize={data.page_size} onPage={setPage} />
            {data.total === 0 ? <div className="rounded-2xl border border-line bg-panel/60 p-5 text-sm text-muted" data-testid="memory-search-empty-results">No memory artifacts matched this query and scope.</div> : null}
            {data.results.length ? <div className="overflow-x-auto rounded-2xl border border-line bg-panel/70"><table className="min-w-full"><thead className="text-left text-xs uppercase tracking-[0.14em] text-muted"><tr><th className="p-3">Type</th><th className="p-3">Timestamp</th><th className="p-3">Process/PID</th><th className="p-3">Title</th><th className="p-3">Source</th><th className="p-3">Matched</th><th className="p-3">Actions</th></tr></thead><tbody>{data.results.map((result) => <ResultRow key={result.result_id} result={result} onOpen={onOpen} />)}</tbody></table></div> : null}
            <Pagination page={data.page} totalPages={data.total_pages} total={data.total} pageSize={data.page_size} onPage={setPage} />
          </div>
        </div>
      ) : null}
    </section>
  );
}
