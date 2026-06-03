type Props = {
  page: number;
  totalPages: number;
  total: number;
  totalRelation?: string;
  pageSize: number;
  onPageChange: (page: number) => void;
  onPageSizeChange: (pageSize: number) => void;
};

export default function PaginationControls({ page, totalPages, total, totalRelation = "eq", pageSize, onPageChange, onPageSizeChange }: Props) {
  const atStart = page <= 1;
  const atEnd = totalPages === 0 || page >= totalPages;

  return (
    <div className="flex flex-wrap items-center justify-between gap-3 rounded-2xl border border-line bg-panel/60 px-4 py-3">
      <div className="flex flex-wrap items-center gap-2">
        <button type="button" disabled={atStart} onClick={() => onPageChange(1)} className="rounded-xl border border-line px-3 py-2 text-sm text-muted disabled:opacity-40">
          First
        </button>
        <button type="button" disabled={atStart} onClick={() => onPageChange(page - 1)} className="rounded-xl border border-line px-3 py-2 text-sm text-muted disabled:opacity-40">
          Previous
        </button>
        <button type="button" disabled={atEnd} onClick={() => onPageChange(page + 1)} className="rounded-xl border border-line px-3 py-2 text-sm text-muted disabled:opacity-40">
          Next
        </button>
        <button type="button" disabled={atEnd} onClick={() => onPageChange(totalPages)} className="rounded-xl border border-line px-3 py-2 text-sm text-muted disabled:opacity-40">
          Last
        </button>
      </div>
      <div className="flex flex-wrap items-center gap-3 text-sm text-muted">
        <span>
          Page {Math.min(page, Math.max(totalPages, 1))} / {Math.max(totalPages, 1)}
        </span>
        <span>{totalRelation === "gte" ? `${total}+ results` : `${total} results`}</span>
        <label className="flex items-center gap-2">
          <span>Page size</span>
          <select value={pageSize} onChange={(event) => onPageSizeChange(Number(event.target.value))} className="rounded-xl border border-line bg-abyss/70 px-2 py-1">
            {[25, 50, 100, 250, 500].map((size) => (
              <option key={size} value={size}>
                {size}
              </option>
            ))}
          </select>
        </label>
      </div>
    </div>
  );
}
