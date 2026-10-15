import { useState } from "react";
import { useQuery } from "@tanstack/react-query";
import { api } from "../../api/client";
import { FacetSelect, type Facet } from "./FacetSelect";
import { MemoryPaginationControls } from "./MemoryPaginationControls";

const COPY = {
  modules: {
    noun: "module path",
    search: "Search paths",
    summary: "Each module path once, with how many processes load it. Rare first: a DLL loaded by one process stands out from the ones every process loads.",
  },
  handles: {
    noun: "object name",
    search: "Search object names",
    summary: "Each named object once, with how many processes hold a handle to it. Rare first: a mutex or file only one process opens stands out.",
  },
} as const;

type Props = {
  caseId: string;
  evidenceId: string;
  family: "modules" | "handles";
  // Object types (handles) to narrow the stack, from the run's own values.
  groupFacets?: Facet[];
  onOpenValue: (value: string, group: string | null) => void;
};

/**
 * Stacking (frequency analysis): the family's records grouped by value with
 * the number of processes that have each, rarest first. Nothing is hidden;
 * clicking a value opens its rows.
 */
export function MemoryStackView({ caseId, evidenceId, family, groupFacets = [], onOpenValue }: Props) {
  const [q, setQ] = useState("");
  const [group, setGroup] = useState("");
  const [order, setOrder] = useState<"rare" | "common">("rare");
  const [page, setPage] = useState(1);
  const pageSize = 50;
  const copy = COPY[family];
  const query = useQuery({
    queryKey: ["memory-stack", caseId, evidenceId, family, q, group, order, page],
    queryFn: () => api.getMemoryStack(caseId, evidenceId, { family, q: q || undefined, group: group || undefined, order, page, page_size: pageSize }),
    enabled: Boolean(caseId && evidenceId),
    refetchOnWindowFocus: false,
    placeholderData: (previous) => previous,
  });
  const data = query.data;
  const totalPages = Math.max(1, Math.ceil((data?.total_values ?? 0) / pageSize));

  return (
    <div className="space-y-3" data-testid={`memory-stack-${family}`}>
      <p className="text-xs text-muted">{copy.summary}</p>
      <div className="flex flex-wrap items-center gap-2 text-xs">
        <input
          value={q}
          onChange={(event) => { setQ(event.target.value); setPage(1); }}
          placeholder={copy.search}
          aria-label={copy.search}
          className="w-64 rounded-xl border border-line bg-abyss/70 px-3 py-1 text-xs"
          data-testid="memory-stack-search"
        />
        {family === "handles" ? (
          <FacetSelect
            value={group}
            onChange={(next) => { setGroup(next); setPage(1); }}
            facets={groupFacets}
            allLabel="Any object type"
            ariaLabel="Object type"
            testId="memory-stack-group"
            className="rounded-xl border border-line bg-abyss/70 px-3 py-1 text-xs"
          />
        ) : null}
        <select
          value={order}
          onChange={(event) => { setOrder(event.target.value as "rare" | "common"); setPage(1); }}
          aria-label="Order"
          className="rounded-xl border border-line bg-abyss/70 px-3 py-1 text-xs"
          data-testid="memory-stack-order"
        >
          <option value="rare">Rarest first</option>
          <option value="common">Most common first</option>
        </select>
      </div>

      {query.isLoading ? <p className="text-xs text-muted">Loading…</p> : null}
      {query.error instanceof Error ? (
        <p className="rounded-2xl border border-rose-400/30 bg-rose-500/10 p-3 text-xs text-rose-200">{query.error.message}</p>
      ) : null}
      {data && data.items.length === 0 && !query.isLoading ? (
        <p className="text-xs text-muted" data-testid="memory-stack-empty">
          {q || group ? `No ${copy.noun} matches these filters.` : `No ${copy.noun} was recorded for this memory image.`}
        </p>
      ) : null}
      {data && data.items.length > 0 ? (
        <>
          <p className="text-xs text-muted" data-testid="memory-stack-summary">
            {data.total_values.toLocaleString("en-US")} distinct {copy.noun}s across {data.run_process_count.toLocaleString("en-US")} processes · page {page} of {totalPages}
            {data.truncated ? " · only the first 10,000 values were grouped; narrow the search to see the rest" : ""}
          </p>
          <div className="max-w-full overflow-x-auto rounded-2xl border border-line bg-abyss/40">
            <table className="w-full min-w-[860px] divide-y divide-line text-xs" data-testid="memory-stack-table">
              <thead className="bg-abyss/70 text-left text-[10px] uppercase tracking-[0.14em] text-muted">
                <tr>
                  <th className="px-2 py-1 text-right">Processes</th>
                  <th className="px-2 py-1 text-right">Records</th>
                  {family === "handles" ? <th className="px-2 py-1">Type</th> : null}
                  <th className="px-2 py-1">{family === "modules" ? "Path" : "Name"}</th>
                  <th className="px-2 py-1">Seen in</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-line">
                {data.items.map((item) => (
                  <tr key={`${item.group ?? ""}|${item.value}`} data-testid="memory-stack-row">
                    <td className="whitespace-nowrap px-2 py-1 text-right tabular-nums text-ink" title={`${item.process_count} of ${data.run_process_count} processes`}>
                      {item.process_count}
                      <span className="text-muted"> / {data.run_process_count}</span>
                    </td>
                    <td className="px-2 py-1 text-right tabular-nums text-muted">{item.occurrences.toLocaleString("en-US")}</td>
                    {family === "handles" ? <td className="px-2 py-1 text-muted">{item.group ?? "—"}</td> : null}
                    <td className="max-w-[560px] px-2 py-1">
                      <button
                        type="button"
                        onClick={() => onOpenValue(item.value, item.group)}
                        className="break-all text-left font-mono text-[11px] text-ink hover:text-accent"
                        title="Show these records"
                        data-testid="memory-stack-open"
                      >
                        {item.value}
                      </button>
                    </td>
                    <td className="px-2 py-1 text-muted">
                      {item.process_names.slice(0, 3).join(", ")}
                      {item.process_names.length > 3 ? " …" : ""}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
          <div className="flex items-center justify-end text-xs">
            <MemoryPaginationControls page={page} totalPages={totalPages} onPage={setPage} prevTestId="memory-stack-prev-page" nextTestId="memory-stack-next-page" />
          </div>
        </>
      ) : null}
    </div>
  );
}
