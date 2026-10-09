import { useEffect, useMemo, useRef, useState } from "react";
import { useInfiniteQuery, useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { Link, useParams } from "react-router-dom";
import { ArrowDown, ArrowUp, Columns3, Download, ListFilter, Table2, Trash2, X } from "lucide-react";

import {
  api,
  type SourceTable,
  type SourceTableColumn,
  type SourceTableFilter,
  type SourceTableFilterOp,
  type SourceTableQuery,
} from "../api/client";
import EvidenceSourceTablesPanel from "../components/EvidenceSourceTablesPanel";
import ColumnResizeHandle from "../components/table/ColumnResizeHandle";
import { useResizableColumns } from "../components/table/useResizableColumns";
import { InvestigationBreadcrumbs } from "../components/InvestigationContext";
import { useInvestigationBreadcrumbs } from "../lib/useInvestigationBreadcrumbs";

const ROW_HEIGHT = 28;
const PAGE_SIZE = 500;
const OVERSCAN = 20;
const LINE_COLUMN_WIDTH = 72;

const STATUS_LABEL: Record<SourceTable["status"], string> = {
  pending: "Queued",
  building: "Building",
  ready: "Ready",
  failed: "Failed",
  unavailable: "Source missing",
};

const OP_LABEL: Record<SourceTableFilterOp, string> = {
  contains: "contains",
  not_contains: "does not contain",
  equals: "is",
  not_equals: "is not",
  empty: "is empty",
  not_empty: "is not empty",
};

function useDebounced<T>(value: T, delay = 300): T {
  const [debounced, setDebounced] = useState(value);
  useEffect(() => {
    const timer = window.setTimeout(() => setDebounced(value), delay);
    return () => window.clearTimeout(timer);
  }, [value, delay]);
  return debounced;
}

function readHidden(tableId: string): number[] {
  try {
    const parsed = JSON.parse(localStorage.getItem(`kairon.sourceTable.hidden.${tableId}`) || "[]") as unknown;
    return Array.isArray(parsed) ? parsed.filter((value): value is number => Number.isInteger(value)) : [];
  } catch {
    return [];
  }
}

function writeHidden(tableId: string, hidden: number[]) {
  try {
    localStorage.setItem(`kairon.sourceTable.hidden.${tableId}`, JSON.stringify(hidden));
  } catch {
    // Not remembering hidden columns is not worth failing over.
  }
}

function StatusBadge({ status }: { status: SourceTable["status"] }) {
  const tone =
    status === "ready" ? "border-emerald-500/40 text-emerald-300" : status === "failed" || status === "unavailable" ? "border-red-500/40 text-red-300" : "border-amber-500/40 text-amber-300";
  return <span className={`rounded-full border px-2 py-0.5 text-xs ${tone}`}>{STATUS_LABEL[status]}</span>;
}

export default function SourceTablesPage() {
  const { caseId = "", tableId } = useParams();
  const breadcrumbs = useInvestigationBreadcrumbs();
  if (!caseId) return <div className="rounded-2xl border border-line bg-panel p-6 text-sm text-muted">Select a case first.</div>;
  return (
    <main className="space-y-4">
      <InvestigationBreadcrumbs items={breadcrumbs} />
      {tableId ? <SourceTableView caseId={caseId} tableId={tableId} /> : <SourceTableList caseId={caseId} />}
    </main>
  );
}

function SourceTableList({ caseId }: { caseId: string }) {
  const queryClient = useQueryClient();
  const query = useQuery({
    queryKey: ["source-tables", caseId],
    queryFn: () => api.listSourceTables(caseId),
    refetchInterval: (current) => (current.state.data?.items.some((item) => item.status === "pending" || item.status === "building") ? 4000 : false),
  });
  const remove = useMutation({
    mutationFn: (tableId: string) => api.deleteSourceTable(caseId, tableId),
    onSuccess: () => queryClient.invalidateQueries({ queryKey: ["source-tables", caseId] }),
  });
  const items = query.data?.items ?? [];

  return (
    <section className="rounded-3xl border border-line bg-panel p-6">
      <div className="flex items-center gap-3">
        <Table2 className="h-5 w-5 text-accent" />
        <h2 className="text-2xl font-semibold">Source Tables</h2>
      </div>
      <p className="mt-2 max-w-3xl text-sm text-muted">
        CSV and TSV files indexed whole, with every column they bring, to sort and filter like a spreadsheet. Pick any CSV of the case under{" "}
        <span className="text-ink">Add a CSV</span> below (or turn it on for a whole upload in the evidence wizard). These rows are separate from Search, so nothing
        shows up twice.
      </p>
      {query.isLoading ? <p className="mt-6 text-sm text-muted">Loading…</p> : null}
      {query.error ? <p className="mt-6 text-sm text-red-300">{(query.error as Error).message}</p> : null}
      {!query.isLoading && !items.length ? (
        <p className="mt-6 rounded-2xl border border-dashed border-line p-6 text-sm text-muted">
          No source tables yet. Choose <span className="text-ink">Full table</span> on a CSV below.
        </p>
      ) : null}
      {items.length ? (
        <div className="mt-6 overflow-x-auto rounded-2xl border border-line">
          <table className="min-w-full text-sm">
            <thead className="bg-abyss/70 text-left text-xs uppercase tracking-[0.14em] text-muted">
              <tr>
                <th className="px-4 py-3">File</th>
                <th className="px-4 py-3">Status</th>
                <th className="px-4 py-3 text-right">Rows</th>
                <th className="px-4 py-3 text-right">Columns</th>
                <th className="px-4 py-3" />
              </tr>
            </thead>
            <tbody>
              {items.map((item) => (
                <tr key={item.id} className="border-t border-line/60">
                  <td className="px-4 py-3">
                    {item.status === "ready" ? (
                      <Link to={`/cases/${caseId}/tables/${item.id}`} className="font-medium text-accent hover:underline">
                        {item.name}
                      </Link>
                    ) : (
                      <span className="font-medium text-ink">{item.source_path === "*" ? "Every CSV of the evidence (waiting for the ingest)" : item.name}</span>
                    )}
                    {item.source_path !== "*" ? <p className="mt-0.5 break-all text-xs text-muted">{item.source_path}</p> : null}
                    {item.error ? <p className="mt-1 text-xs text-red-300">{item.error}</p> : null}
                  </td>
                  <td className="px-4 py-3">
                    <StatusBadge status={item.status} />
                  </td>
                  <td className="px-4 py-3 text-right tabular-nums">{item.status === "ready" ? item.row_count.toLocaleString() : "-"}</td>
                  <td className="px-4 py-3 text-right tabular-nums">{item.status === "ready" ? item.columns.length : "-"}</td>
                  <td className="px-4 py-3 text-right">
                    {item.status !== "building" ? (
                      <button
                        type="button"
                        className="rounded-lg p-1.5 text-muted hover:bg-abyss hover:text-red-300"
                        aria-label={`Delete table ${item.name}`}
                        title="Delete this table (the evidence and its events are kept)"
                        onClick={() => remove.mutate(item.id)}
                      >
                        <Trash2 className="h-4 w-4" />
                      </button>
                    ) : null}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      ) : null}
      <CsvCandidates caseId={caseId} />
    </section>
  );
}

// Every CSV/TSV of the case without a table yet, grouped by evidence, one click from a table.
function CsvCandidates({ caseId }: { caseId: string }) {
  const evidencesQuery = useQuery({ queryKey: ["case-evidences", caseId], queryFn: () => api.listEvidences(caseId) });
  const artifactsQuery = useQuery({ queryKey: ["case-artifacts", caseId], queryFn: () => api.listArtifacts(caseId) });
  const withCsv = new Set((artifactsQuery.data ?? []).filter((artifact) => /\.(csv|tsv)$/i.test(artifact.source_path)).map((artifact) => artifact.evidence_id));
  const evidences = (evidencesQuery.data ?? []).filter((evidence) => withCsv.has(evidence.id));
  if (!evidences.length) return null;
  return (
    <div className="mt-8" data-testid="source-table-add">
      <h3 className="text-lg font-semibold text-ink">Add a CSV</h3>
      <p className="mt-1 text-sm text-muted">CSV and TSV files of the case that have no table yet.</p>
      <div className="mt-3 space-y-3">
        {evidences.map((evidence) => (
          <EvidenceSourceTablesPanel key={evidence.id} caseId={caseId} evidenceId={evidence.id} evidenceName={evidence.original_filename} onlyMissing />
        ))}
      </div>
    </div>
  );
}

function ColumnValuesPopover({
  caseId,
  tableId,
  column,
  baseQuery,
  onPick,
  onClose,
}: {
  caseId: string;
  tableId: string;
  column: SourceTableColumn;
  baseQuery: SourceTableQuery;
  onPick: (filter: SourceTableFilter) => void;
  onClose: () => void;
}) {
  const values = useQuery({
    queryKey: ["source-table-values", caseId, tableId, column.index, baseQuery],
    queryFn: () => api.sourceTableColumnValues(caseId, tableId, { q: baseQuery.q, filters: baseQuery.filters, column: column.index, size: 50 }),
  });
  return (
    <div className="absolute left-0 top-full z-30 mt-1 w-72 rounded-xl border border-line bg-panel p-2 text-left text-xs normal-case tracking-normal text-ink shadow-xl" onClick={(event) => event.stopPropagation()}>
      <div className="mb-1 flex items-center justify-between px-1">
        <span className="font-semibold">{column.name}</span>
        <button type="button" onClick={onClose} aria-label="Close" className="text-muted hover:text-ink">
          <X className="h-3.5 w-3.5" />
        </button>
      </div>
      <div className="mb-2 flex gap-1 px-1">
        <button type="button" className="rounded-md border border-line px-2 py-0.5 hover:border-accent" onClick={() => onPick({ column: column.index, op: "empty" })}>
          Empty
        </button>
        <button type="button" className="rounded-md border border-line px-2 py-0.5 hover:border-accent" onClick={() => onPick({ column: column.index, op: "not_empty" })}>
          Not empty
        </button>
      </div>
      <div className="max-h-64 overflow-y-auto">
        {values.isLoading ? <p className="px-1 py-2 text-muted">Loading…</p> : null}
        {values.data?.items.map((item) => (
          <div key={item.value} className="flex items-center gap-1 rounded-md px-1 py-0.5 hover:bg-abyss">
            <button type="button" className="min-w-0 flex-1 truncate text-left" title={item.value || "(empty)"} onClick={() => onPick({ column: column.index, op: "equals", value: item.value })}>
              {item.value || <span className="italic text-muted">(empty)</span>}
            </button>
            <span className="tabular-nums text-muted">{item.count.toLocaleString()}</span>
            <button
              type="button"
              className="rounded px-1 text-muted hover:text-red-300"
              title="Exclude this value"
              aria-label={`Exclude ${item.value}`}
              onClick={() => onPick({ column: column.index, op: "not_equals", value: item.value })}
            >
              ≠
            </button>
          </div>
        ))}
      </div>
    </div>
  );
}

function SourceTableView({ caseId, tableId }: { caseId: string; tableId: string }) {
  const tableQuery = useQuery({ queryKey: ["source-table", caseId, tableId], queryFn: () => api.getSourceTable(caseId, tableId) });
  const table = tableQuery.data;
  const columns = table?.columns ?? [];

  const [search, setSearch] = useState("");
  const [columnText, setColumnText] = useState<Record<number, string>>({});
  const [pickedFilters, setPickedFilters] = useState<SourceTableFilter[]>([]);
  const [sort, setSort] = useState<{ column: number; order: "asc" | "desc" } | null>(null);
  const [hidden, setHidden] = useState<number[]>(() => readHidden(tableId));
  const [showColumns, setShowColumns] = useState(false);
  const [valuesFor, setValuesFor] = useState<number | null>(null);
  const [selectedRow, setSelectedRow] = useState<{ row: number; values: string[] } | null>(null);
  const [exporting, setExporting] = useState(false);

  const debouncedSearch = useDebounced(search);
  const debouncedColumnText = useDebounced(columnText);

  const visibleColumns = useMemo(() => columns.filter((column) => !hidden.includes(column.index)), [columns, hidden]);
  const emptyColumns = useMemo(() => columns.filter((column) => column.empty), [columns]);
  const visibleEmptyCount = emptyColumns.filter((column) => !hidden.includes(column.index)).length;
  const resizable = useMemo(() => visibleColumns.map((column) => ({ key: String(column.index), defaultWidth: 180 })), [visibleColumns]);
  const { widths, startResize, nudge, resizingKey } = useResizableColumns(`sourceTable.${tableId}`, resizable);

  const baseQuery: SourceTableQuery = useMemo(() => {
    const filters: SourceTableFilter[] = [
      ...Object.entries(debouncedColumnText)
        .filter(([, value]) => value.trim())
        .map(([column, value]) => ({ column: Number(column), op: "contains" as const, value: value.trim() })),
      ...pickedFilters,
    ];
    return { q: debouncedSearch.trim() || undefined, filters, sort_column: sort?.column ?? null, sort_order: sort?.order ?? "asc" };
  }, [debouncedColumnText, debouncedSearch, pickedFilters, sort]);

  const rows = useInfiniteQuery({
    queryKey: ["source-table-rows", caseId, tableId, baseQuery],
    queryFn: ({ pageParam }) => api.querySourceTableRows(caseId, tableId, { ...baseQuery, cursor: pageParam, size: PAGE_SIZE }),
    initialPageParam: null as string | null,
    getNextPageParam: (lastPage) => lastPage.next_cursor,
    enabled: table?.status === "ready",
  });
  const loadedRows = useMemo(() => rows.data?.pages.flatMap((page) => page.rows) ?? [], [rows.data]);
  const total = rows.data?.pages[0]?.total ?? 0;

  const scrollRef = useRef<HTMLDivElement>(null);
  const [scrollTop, setScrollTop] = useState(0);
  const [viewportHeight, setViewportHeight] = useState(600);
  useEffect(() => {
    const element = scrollRef.current;
    if (!element) return undefined;
    const observer = new ResizeObserver(() => setViewportHeight(element.clientHeight));
    observer.observe(element);
    return () => observer.disconnect();
  }, [table?.status]);
  useEffect(() => {
    if (scrollRef.current) scrollRef.current.scrollTop = 0;
    setScrollTop(0);
  }, [baseQuery]);

  const firstIndex = Math.max(0, Math.floor(scrollTop / ROW_HEIGHT) - OVERSCAN);
  const lastIndex = Math.min(loadedRows.length, Math.ceil((scrollTop + viewportHeight) / ROW_HEIGHT) + OVERSCAN);
  useEffect(() => {
    if (lastIndex >= loadedRows.length - OVERSCAN && rows.hasNextPage && !rows.isFetchingNextPage) void rows.fetchNextPage();
  }, [lastIndex, loadedRows.length, rows]);

  const toggleHidden = (index: number) => {
    const next = hidden.includes(index) ? hidden.filter((value) => value !== index) : [...hidden, index];
    setHidden(next);
    writeHidden(tableId, next);
  };

  const hideEmptyColumns = () => {
    const next = [...new Set([...hidden, ...emptyColumns.map((column) => column.index)])];
    setHidden(next);
    writeHidden(tableId, next);
  };

  const cycleSort = (index: number) => {
    setSort((current) => (current?.column !== index ? { column: index, order: "asc" } : current.order === "asc" ? { column: index, order: "desc" } : null));
  };

  const exportCsv = async () => {
    setExporting(true);
    try {
      const { blob, filename } = await api.exportSourceTable(caseId, tableId, { ...baseQuery, columns: visibleColumns.map((column) => column.index) });
      const url = URL.createObjectURL(blob);
      const anchor = document.createElement("a");
      anchor.href = url;
      anchor.download = filename;
      anchor.click();
      URL.revokeObjectURL(url);
    } finally {
      setExporting(false);
    }
  };

  if (tableQuery.isLoading) return <p className="text-sm text-muted">Loading…</p>;
  if (tableQuery.error || !table) return <p className="text-sm text-red-300">{(tableQuery.error as Error | null)?.message ?? "Table not found."}</p>;
  if (table.status !== "ready") {
    return (
      <section className="rounded-3xl border border-line bg-panel p-6 text-sm">
        <p>
          <span className="font-semibold">{table.name}</span> is not ready: <StatusBadge status={table.status} />
        </p>
        {table.error ? <p className="mt-2 text-red-300">{table.error}</p> : null}
        <Link to={`/cases/${caseId}/tables`} className="mt-4 inline-block text-accent hover:underline">
          Back to Source Tables
        </Link>
      </section>
    );
  }

  const totalWidth = LINE_COLUMN_WIDTH + visibleColumns.reduce((sum, column) => sum + (widths[String(column.index)] ?? 180), 0);
  const columnName = (index: number) => columns[index]?.name ?? `#${index}`;

  return (
    <section className="flex flex-col rounded-3xl border border-line bg-panel p-4" style={{ height: "calc(100vh - 140px)", minHeight: 480 }}>
      <div className="flex flex-wrap items-start justify-between gap-3">
        <div className="min-w-0">
          <Link to={`/cases/${caseId}/tables`} className="text-xs text-muted hover:text-accent">
            Source Tables
          </Link>
          <h2 className="truncate text-xl font-semibold" title={table.source_path}>
            {table.name}
          </h2>
          <p className="text-xs text-muted">
            {total.toLocaleString()} of {table.row_count.toLocaleString()} rows · {visibleColumns.length}/{columns.length} columns
            {visibleEmptyCount ? (
              <>
                {" · "}
                <button type="button" className="text-accent hover:underline" onClick={hideEmptyColumns} title={emptyColumns.map((column) => column.name).join(", ")}>
                  hide {visibleEmptyCount} empty column{visibleEmptyCount === 1 ? "" : "s"}
                </button>
              </>
            ) : null}
          </p>
        </div>
        <div className="flex items-center gap-2">
          <input
            value={search}
            onChange={(event) => setSearch(event.target.value)}
            placeholder="Search every column…"
            className="w-64 rounded-xl border border-line bg-abyss px-3 py-1.5 text-sm"
            aria-label="Search every column"
          />
          <div className="relative">
            <button type="button" className="flex items-center gap-1 rounded-xl border border-line px-3 py-1.5 text-sm hover:border-accent" onClick={() => setShowColumns((value) => !value)}>
              <Columns3 className="h-4 w-4" /> Columns
            </button>
            {showColumns ? (
              <div className="absolute right-0 top-full z-30 mt-1 max-h-96 w-72 overflow-y-auto rounded-xl border border-line bg-panel p-2 text-sm shadow-xl">
                <div className="mb-1 flex gap-2 px-1 text-xs">
                  <button type="button" className="text-accent hover:underline" onClick={() => { setHidden([]); writeHidden(tableId, []); }}>
                    Show all
                  </button>
                  {emptyColumns.length ? (
                    <button type="button" className="text-accent hover:underline" onClick={hideEmptyColumns}>
                      Hide empty ({emptyColumns.length})
                    </button>
                  ) : null}
                  <button type="button" className="text-muted hover:underline" onClick={() => setShowColumns(false)}>
                    Close
                  </button>
                </div>
                {columns.map((column) => (
                  <label key={column.index} className="flex items-center gap-2 rounded-md px-1 py-0.5 hover:bg-abyss">
                    <input type="checkbox" checked={!hidden.includes(column.index)} onChange={() => toggleHidden(column.index)} />
                    <span className={`truncate ${column.empty ? "text-muted" : ""}`}>{column.name}</span>
                    {column.empty ? <span className="ml-auto shrink-0 rounded-full border border-line px-1.5 text-[10px] uppercase tracking-wide text-muted">empty</span> : null}
                  </label>
                ))}
              </div>
            ) : null}
          </div>
          <button type="button" disabled={exporting} className="flex items-center gap-1 rounded-xl border border-line px-3 py-1.5 text-sm hover:border-accent disabled:opacity-50" onClick={() => void exportCsv()}>
            <Download className="h-4 w-4" /> {exporting ? "Exporting…" : "Export"}
          </button>
        </div>
      </div>

      {pickedFilters.length || sort ? (
        <div className="mt-2 flex flex-wrap gap-1.5 text-xs">
          {pickedFilters.map((filter, position) => (
            <span key={`${filter.column}-${filter.op}-${filter.value}-${position}`} className="flex items-center gap-1 rounded-full border border-line bg-abyss px-2 py-0.5">
              <span className="text-muted">{columnName(filter.column)}</span> {OP_LABEL[filter.op]} {filter.value !== undefined ? <span className="font-medium">"{filter.value}"</span> : null}
              <button type="button" aria-label="Remove filter" onClick={() => setPickedFilters((current) => current.filter((_, index) => index !== position))}>
                <X className="h-3 w-3" />
              </button>
            </span>
          ))}
          {sort ? (
            <span className="flex items-center gap-1 rounded-full border border-line bg-abyss px-2 py-0.5">
              sorted by <span className="font-medium">{columnName(sort.column)}</span> {sort.order}
              <button type="button" aria-label="Clear sort" onClick={() => setSort(null)}>
                <X className="h-3 w-3" />
              </button>
            </span>
          ) : null}
        </div>
      ) : null}

      <div
        ref={scrollRef}
        className="mt-3 min-h-0 flex-1 overflow-auto rounded-xl border border-line"
        onScroll={(event) => setScrollTop(event.currentTarget.scrollTop)}
        onClick={() => setValuesFor(null)}
      >
        <table className="table-fixed border-collapse text-xs" style={{ width: totalWidth }}>
          <colgroup>
            <col style={{ width: LINE_COLUMN_WIDTH }} />
            {visibleColumns.map((column) => (
              <col key={column.index} style={{ width: widths[String(column.index)] }} />
            ))}
          </colgroup>
          <thead className="sticky top-0 z-20 bg-abyss text-left text-muted">
            <tr>
              <th className="border-b border-line px-2 py-1.5 font-medium">Line</th>
              {visibleColumns.map((column) => (
                <th key={column.index} className="relative border-b border-l border-line/60 px-2 py-1.5 font-medium">
                  <div className="flex items-center gap-1">
                    <button
                      type="button"
                      className={`min-w-0 flex-1 truncate text-left hover:text-accent ${column.empty ? "italic text-muted" : "text-ink"}`}
                      title={column.empty ? `${column.name} — no values in the whole file` : `${column.name} — click to sort`}
                      onClick={() => cycleSort(column.index)}
                    >
                      {column.name}
                    </button>
                    {sort?.column === column.index ? sort.order === "asc" ? <ArrowUp className="h-3 w-3 shrink-0" /> : <ArrowDown className="h-3 w-3 shrink-0" /> : null}
                    <button
                      type="button"
                      className="shrink-0 rounded p-0.5 hover:bg-panel hover:text-accent"
                      aria-label={`Values of ${column.name}`}
                      title="Most frequent values"
                      onClick={(event) => {
                        event.stopPropagation();
                        setValuesFor((current) => (current === column.index ? null : column.index));
                      }}
                    >
                      <ListFilter className="h-3 w-3" />
                    </button>
                  </div>
                  {valuesFor === column.index ? (
                    <ColumnValuesPopover
                      caseId={caseId}
                      tableId={tableId}
                      column={column}
                      baseQuery={baseQuery}
                      onPick={(filter) => {
                        setPickedFilters((current) => [...current, filter]);
                        setValuesFor(null);
                      }}
                      onClose={() => setValuesFor(null)}
                    />
                  ) : null}
                  <ColumnResizeHandle
                    columnKey={String(column.index)}
                    label={column.name}
                    width={widths[String(column.index)]}
                    onStart={startResize}
                    onNudge={nudge}
                    active={resizingKey === String(column.index)}
                  />
                </th>
              ))}
            </tr>
            <tr>
              <th className="border-b border-line px-1 py-1" />
              {visibleColumns.map((column) => (
                <th key={column.index} className="border-b border-l border-line/60 px-1 py-1">
                  <input
                    value={columnText[column.index] ?? ""}
                    onChange={(event) => setColumnText((current) => ({ ...current, [column.index]: event.target.value }))}
                    placeholder="contains…"
                    aria-label={`Filter ${column.name}`}
                    className="w-full rounded border border-line/60 bg-panel px-1.5 py-0.5 font-normal text-ink"
                  />
                </th>
              ))}
            </tr>
          </thead>
          <tbody>
            {firstIndex > 0 ? (
              <tr style={{ height: firstIndex * ROW_HEIGHT }}>
                <td colSpan={visibleColumns.length + 1} />
              </tr>
            ) : null}
            {loadedRows.slice(firstIndex, lastIndex).map((row) => (
              <tr
                key={row.row}
                style={{ height: ROW_HEIGHT }}
                className={`cursor-pointer border-b border-line/40 ${selectedRow?.row === row.row ? "bg-accent/15" : "hover:bg-abyss/60"}`}
                onClick={() => setSelectedRow(row)}
              >
                <td className="truncate px-2 text-right tabular-nums text-muted">{row.row}</td>
                {visibleColumns.map((column) => (
                  <td key={column.index} className="truncate border-l border-line/30 px-2" title={row.values[column.index]}>
                    {row.values[column.index]}
                  </td>
                ))}
              </tr>
            ))}
            {lastIndex < loadedRows.length ? (
              <tr style={{ height: (loadedRows.length - lastIndex) * ROW_HEIGHT }}>
                <td colSpan={visibleColumns.length + 1} />
              </tr>
            ) : null}
          </tbody>
        </table>
        {rows.isLoading || rows.isFetchingNextPage ? <p className="p-3 text-xs text-muted">Loading rows…</p> : null}
        {rows.error ? <p className="p-3 text-xs text-red-300">{(rows.error as Error).message}</p> : null}
        {!rows.isLoading && !loadedRows.length && !rows.error ? <p className="p-3 text-xs text-muted">No rows match.</p> : null}
      </div>

      {selectedRow ? (
        <div className="mt-3 max-h-56 overflow-y-auto rounded-xl border border-line bg-abyss/60 p-3 text-xs">
          <div className="mb-2 flex items-center justify-between">
            <span className="font-semibold">Line {selectedRow.row}</span>
            <button type="button" aria-label="Close row detail" onClick={() => setSelectedRow(null)} className="text-muted hover:text-ink">
              <X className="h-3.5 w-3.5" />
            </button>
          </div>
          <dl className="grid grid-cols-[minmax(120px,220px)_1fr] gap-x-3 gap-y-1">
            {columns.map((column) => (
              <div key={column.index} className="contents">
                <dt className="truncate text-muted" title={column.name}>
                  {column.name}
                </dt>
                <dd className="whitespace-pre-wrap break-all">{selectedRow.values[column.index] || <span className="text-muted">—</span>}</dd>
              </div>
            ))}
          </dl>
        </div>
      ) : null}
    </section>
  );
}
