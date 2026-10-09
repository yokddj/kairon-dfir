import { useEffect, useState } from "react";
import { useQuery } from "@tanstack/react-query";
import { api } from "../../api/client";
import { useTimezonePreference } from "../../context/TimezoneContext";
import { formatTimestamp } from "../../lib/time";

type Props = {
  caseId: string;
  evidenceId: string;
};

// This memory image's own timeline: Volatility's dated events (process start/exit, network
// connections...) merged with MemProcFS's forensic timelines (event logs, tasks, NTFS, registry...).
// The same events are in the case Timeline next to everything else; this view shows only them.
const PRODUCER_LABEL: Record<string, string> = {
  volatility: "Volatility",
  memprocfs: "MemProcFS",
};

export function MemoryTimelineTab({ caseId, evidenceId }: Props) {
  const { effectiveTimezone } = useTimezonePreference();
  const [kinds, setKinds] = useState<string[] | null>(null);
  const [search, setSearch] = useState("");
  const [query, setQuery] = useState("");
  const [order, setOrder] = useState<"asc" | "desc">("asc");
  // Cursors of the pages already seen, so Previous goes back without offsets.
  const [cursors, setCursors] = useState<(string | null)[]>([null]);
  const cursor = cursors[cursors.length - 1];

  useEffect(() => {
    setCursors([null]);
  }, [kinds, query, order, evidenceId]);

  const timelineQuery = useQuery({
    queryKey: ["memory-evidence-timeline", caseId, evidenceId, kinds, query, order, cursor],
    queryFn: () => api.getMemoryEvidenceTimeline(caseId, evidenceId, { kinds: kinds ?? undefined, q: query || undefined, order, cursor, page_size: 100 }),
    refetchOnWindowFocus: false,
  });
  const data = timelineQuery.data;
  const selected = kinds ?? data?.selected_kinds ?? [];

  function toggleKind(key: string) {
    const next = selected.includes(key) ? selected.filter((item) => item !== key) : [...selected, key];
    setKinds(next);
  }

  return (
    <section className="rounded-3xl border border-line bg-panel/70 p-4" data-testid="memory-timeline-tab">
      <div className="flex flex-wrap items-start justify-between gap-3">
        <div>
          <h2 className="text-lg font-semibold text-ink">Timeline</h2>
          <p className="mt-1 max-w-3xl text-xs text-muted">
            Events with a time recovered from this memory image: process starts and exits and network connections (Volatility), and MemProcFS's timelines (event log records, scheduled tasks, browser history, Amcache, kernel objects, NTFS and registry). NTFS and registry are off by default: they can run to hundreds of thousands of rows.
          </p>
        </div>
        <div className="flex items-center gap-2 text-xs">
          <form
            onSubmit={(event) => {
              event.preventDefault();
              setQuery(search.trim());
            }}
          >
            <input
              value={search}
              onChange={(event) => setSearch(event.target.value)}
              placeholder="Search (Enter)"
              className="w-56 rounded-xl border border-line bg-abyss/70 px-3 py-1.5 text-ink outline-none"
              data-testid="memory-timeline-search"
            />
          </form>
          <button
            type="button"
            onClick={() => setOrder(order === "asc" ? "desc" : "asc")}
            className="rounded-xl border border-line bg-abyss/70 px-3 py-1.5 text-muted hover:text-ink"
            data-testid="memory-timeline-order"
          >
            {order === "asc" ? "Oldest first" : "Newest first"}
          </button>
        </div>
      </div>

      {data ? (
        <div className="mt-3 flex flex-wrap gap-2" data-testid="memory-timeline-kinds">
          {data.kinds.map((kind) => {
            const active = selected.includes(kind.key);
            const count = data.counts[kind.key] ?? 0;
            return (
              <button
                key={kind.key}
                type="button"
                onClick={() => toggleKind(kind.key)}
                aria-pressed={active}
                className={`rounded-full border px-3 py-1 text-xs ${active ? "border-accent/50 bg-accent/15 text-ink" : "border-line bg-abyss/60 text-muted"} ${count === 0 ? "opacity-50" : ""}`}
                data-testid={`memory-timeline-kind-${kind.key}`}
              >
                {kind.label} <span className="text-muted">{count.toLocaleString("en-US")}</span>
              </button>
            );
          })}
        </div>
      ) : null}

      {timelineQuery.isLoading ? <p className="mt-3 text-xs text-muted">Loading timeline…</p> : null}
      {timelineQuery.error ? <p className="mt-3 text-xs text-rose-200">The timeline could not be loaded.</p> : null}

      {data && data.items.length === 0 ? (
        <p className="mt-3 rounded-2xl border border-line bg-abyss/40 p-3 text-xs text-muted" data-testid="memory-timeline-empty">
          {Object.values(data.counts).some((value) => value > 0)
            ? "No event matches these filters."
            : "No dated event yet. Run Processes and Network for Volatility's events, and Find Evil for MemProcFS's timelines."}
        </p>
      ) : null}

      {data && data.items.length > 0 ? (
        <>
          <p className="mt-3 text-xs text-muted" data-testid="memory-timeline-summary">
            {data.total.toLocaleString("en-US")} event{data.total === 1 ? "" : "s"} · page {cursors.length}
          </p>
          <div className="mt-2 max-w-full overflow-x-auto rounded-2xl border border-line bg-abyss/40">
            <table className="w-full min-w-[860px] divide-y divide-line text-xs" data-testid="memory-timeline-table">
              <thead className="bg-abyss/70 text-left text-[10px] uppercase tracking-[0.14em] text-muted">
                <tr>
                  <th className="px-2 py-1">Time</th>
                  <th className="px-2 py-1">Source</th>
                  <th className="px-2 py-1">Type</th>
                  <th className="px-2 py-1">PID</th>
                  <th className="px-2 py-1">Event</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-line">
                {data.items.map((item) => (
                  <tr key={item.id} data-testid="memory-timeline-row">
                    <td className="whitespace-nowrap px-2 py-1 text-muted">{formatTimestamp(item.timestamp, effectiveTimezone)}</td>
                    <td className="px-2 py-1 text-muted">{PRODUCER_LABEL[item.producer] ?? item.producer}</td>
                    <td className="px-2 py-1 text-ink">{item.kind_label}</td>
                    <td className="px-2 py-1 text-muted">{item.pid ?? "—"}</td>
                    <td className="break-all px-2 py-1 font-mono text-[11px] text-ink" title={item.summary || undefined}>
                      {item.title}
                      {item.process_name && !(item.title || "").includes(item.process_name) ? <span className="text-muted"> · {item.process_name}</span> : null}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
          <div className="mt-3 flex justify-end gap-2 text-xs">
            <button
              type="button"
              disabled={cursors.length <= 1}
              onClick={() => setCursors(cursors.slice(0, -1))}
              className="rounded-md border border-line bg-abyss/70 px-2 py-1 disabled:opacity-50"
              data-testid="memory-timeline-prev"
            >
              Previous
            </button>
            <button
              type="button"
              disabled={!data.next_cursor}
              onClick={() => data.next_cursor && setCursors([...cursors, data.next_cursor])}
              className="rounded-md border border-line bg-abyss/70 px-2 py-1 disabled:opacity-50"
              data-testid="memory-timeline-next"
            >
              Next
            </button>
          </div>
        </>
      ) : null}
    </section>
  );
}
