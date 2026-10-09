import { useState } from "react";
import { useQuery } from "@tanstack/react-query";
import { api } from "../../api/client";
import { MemoryPaginationControls } from "./MemoryPaginationControls";

type Props = {
  caseId: string;
  evidenceId: string;
};

// MemProcFS's forensic inventories of this image (scheduled tasks, services, DNS cache, drivers,
// devices, Prefetch, Amcache, YARA), saved by the same scan Find Evil runs.
export function MemoryMemProcFSTab({ caseId, evidenceId }: Props) {
  const [table, setTable] = useState("tasks");
  const [search, setSearch] = useState("");
  const [page, setPage] = useState(1);
  const pageSize = 50;
  const query = useQuery({
    queryKey: ["memory-memprocfs-table", caseId, evidenceId, table, search, page],
    queryFn: () => api.getMemoryMemProcFSTable(caseId, evidenceId, { table, q: search || undefined, page, page_size: pageSize }),
    refetchOnWindowFocus: false,
  });
  const data = query.data;
  const current = data?.tables.find((item) => item.key === table);
  const totalPages = Math.max(1, Math.ceil((data?.total ?? 0) / pageSize));
  const groups = Array.from(new Set((data?.tables ?? []).map((item) => item.group)));

  return (
    <section className="rounded-3xl border border-line bg-panel/70 p-4" data-testid="memory-memprocfs-tab">
      <h2 className="text-lg font-semibold text-ink">MemProcFS</h2>
      <p className="mt-1 max-w-3xl text-xs text-muted">
        Inventories MemProcFS's forensic scan reads from this image, beyond what Volatility's tabs list. They come from the same scan Find Evil runs.
        Scheduled tasks and services also appear in the case's Persistence view.
      </p>

      {query.isLoading ? <p className="mt-3 text-xs text-muted">Loading…</p> : null}
      {query.error instanceof Error ? <p className="mt-3 text-xs text-rose-200">{query.error.message}</p> : null}

      {data && !data.available ? (
        <p className="mt-3 rounded-2xl border border-line bg-abyss/40 p-3 text-xs text-muted" data-testid="memory-memprocfs-unavailable">
          {data.run
            ? "The latest Find Evil run did not save MemProcFS's inventories (it ran before they were collected, or MemProcFS's scan did not finish). Run Find Evil again to collect them."
            : "Run Find Evil to collect MemProcFS's inventories of this image."}
        </p>
      ) : null}

      {data && data.available ? (
        <div className="mt-4 grid gap-4 lg:grid-cols-[220px_minmax(0,1fr)]">
          <nav className="space-y-3" data-testid="memory-memprocfs-tables">
            {groups.map((group) => (
              <div key={group}>
                <p className="text-[10px] uppercase tracking-[0.16em] text-muted">{group}</p>
                <div className="mt-1 space-y-1">
                  {data.tables
                    .filter((item) => item.group === group)
                    .map((item) => (
                      <button
                        key={item.key}
                        type="button"
                        onClick={() => { setTable(item.key); setPage(1); }}
                        aria-pressed={item.key === table}
                        className={`flex w-full justify-between rounded-xl border px-3 py-1.5 text-left text-xs ${item.key === table ? "border-accent/50 bg-accent/15 text-ink" : "border-line bg-abyss/60 text-muted"} ${item.count === 0 ? "opacity-50" : ""}`}
                        data-testid={`memory-memprocfs-table-${item.key}`}
                      >
                        <span>{item.label}</span>
                        <span>{item.count.toLocaleString("en-US")}</span>
                      </button>
                    ))}
                </div>
              </div>
            ))}
          </nav>
          <div className="min-w-0">
            <div className="flex flex-wrap items-start justify-between gap-3">
              <div className="max-w-2xl">
                <h3 className="text-sm font-semibold text-ink">{current?.label}</h3>
                <p className="mt-1 text-xs text-muted">{current?.description}</p>
              </div>
              <input
                value={search}
                onChange={(event) => { setSearch(event.target.value); setPage(1); }}
                placeholder="Filter rows"
                aria-label="Filter rows"
                className="w-56 rounded-xl border border-line bg-abyss/70 px-3 py-1.5 text-xs text-ink outline-none"
                data-testid="memory-memprocfs-search"
              />
            </div>
            {data.hidden > 0 ? (
              <p className="mt-2 text-xs text-muted" data-testid="memory-memprocfs-hidden">{data.hidden} unreadable entr{data.hidden === 1 ? "y" : "ies"} hidden.</p>
            ) : null}
            {data.items.length === 0 ? (
              <p className="mt-3 rounded-2xl border border-line bg-abyss/40 p-3 text-xs text-muted" data-testid="memory-memprocfs-empty">
                {search ? "No row matches this filter." : "MemProcFS found nothing for this inventory in this image."}
              </p>
            ) : (
              <>
                <p className="mt-3 text-xs text-muted">{data.total.toLocaleString("en-US")} row{data.total === 1 ? "" : "s"} · page {page} of {totalPages}</p>
                <div className="mt-2 max-w-full overflow-x-auto rounded-2xl border border-line bg-abyss/40">
                  <table className="w-full min-w-[760px] divide-y divide-line text-xs" data-testid="memory-memprocfs-table">
                    <thead className="bg-abyss/70 text-left text-[10px] uppercase tracking-[0.14em] text-muted">
                      <tr>
                        {data.columns.map((column) => (
                          <th key={column.key} className="px-2 py-1">{column.label}</th>
                        ))}
                      </tr>
                    </thead>
                    <tbody className="divide-y divide-line">
                      {data.items.map((row, index) => (
                        <tr key={`${page}-${index}`} data-testid="memory-memprocfs-row" title={Object.entries(row).filter(([, value]) => value).map(([key, value]) => `${key}: ${value}`).join("\n")}>
                          {data.columns.map((column) => (
                            <td key={column.key} className="break-all px-2 py-1 font-mono text-[11px] text-ink">{row[column.key] || <span className="text-muted">—</span>}</td>
                          ))}
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
                <div className="mt-3 flex justify-end text-xs">
                  <MemoryPaginationControls page={page} totalPages={totalPages} onPage={setPage} prevTestId="memory-memprocfs-prev" nextTestId="memory-memprocfs-next" />
                </div>
              </>
            )}
          </div>
        </div>
      ) : null}
    </section>
  );
}
