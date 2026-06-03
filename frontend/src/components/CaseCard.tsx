import { Link } from "react-router-dom";
import type { DfirCase } from "../api/client";
import { useActiveCase } from "../context/ActiveCaseContext";

export default function CaseCard({ item, onDelete }: { item: DfirCase; onDelete?: (item: DfirCase) => void }) {
  const { setActiveCase } = useActiveCase();

  return (
    <div className="rounded-3xl border border-line bg-panel/70 p-5 shadow-panel transition hover:border-accent/40">
      <div className="flex items-start justify-between gap-3">
        <Link to={`/cases/${item.id}/overview`} onClick={() => setActiveCase(item)} className="min-w-0 flex-1">
          <div className="flex items-center justify-between gap-3">
            <h3 className="text-base font-semibold">{item.name}</h3>
            <span className="rounded-full border border-accent/20 bg-accent/10 px-3 py-1 font-mono text-[11px] uppercase tracking-[0.24em] text-accent">
              {item.status}
            </span>
          </div>
          <p className="mt-3 line-clamp-3 text-sm text-muted">{item.description || "No description yet."}</p>
          <p className="mt-4 font-mono text-xs text-muted">Created {new Date(item.created_at).toLocaleString()}</p>
        </Link>
        {onDelete ? (
          <button
            type="button"
            onClick={() => onDelete(item)}
            className="rounded-2xl border border-danger/40 bg-danger/10 px-3 py-2 text-xs text-danger"
          >
            Delete
          </button>
        ) : null}
      </div>
    </div>
  );
}
