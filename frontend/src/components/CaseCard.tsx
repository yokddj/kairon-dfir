import { Link } from "react-router-dom";
import type { DfirCase } from "../api/client";
import { useActiveCase } from "../context/ActiveCaseContext";

type Props = {
  item: DfirCase;
  onEdit?: (item: DfirCase) => void;
  onArchive?: (item: DfirCase) => void;
  onUnarchive?: (item: DfirCase) => void;
  onClose?: (item: DfirCase) => void;
  onReopen?: (item: DfirCase) => void;
};

function processingLabel(summary: Record<string, number> | undefined): string {
  const entries = Object.entries(summary || {}).filter(([, count]) => count > 0);
  if (!entries.length) return "No processing yet";
  return entries.map(([status, count]) => `${count} ${status}`).join(" · ");
}

export default function CaseCard({ item, onEdit, onArchive, onUnarchive, onClose, onReopen }: Props) {
  const { setActiveCase } = useActiveCase();
  const status = item.status === "open" ? "active" : item.status;

  return (
    <div className="rounded-3xl border border-line bg-panel/70 p-5 shadow-panel transition hover:border-accent/40" data-testid="case-card">
      <div className="flex items-start justify-between gap-3">
        <Link to={`/cases/${item.id}/overview`} onClick={() => setActiveCase(item)} className="min-w-0 flex-1">
          <div className="flex items-center justify-between gap-3">
            <h3 className="text-base font-semibold">{item.name}</h3>
            <div className="flex flex-wrap justify-end gap-1.5">
              <span className="rounded-full border border-accent/20 bg-accent/10 px-3 py-1 font-mono text-[11px] uppercase tracking-[0.18em] text-accent">{status}</span>
              <span className="rounded-full border border-line bg-abyss/70 px-3 py-1 font-mono text-[11px] uppercase tracking-[0.18em] text-muted">{item.priority}</span>
            </div>
          </div>
          <p className="mt-3 line-clamp-3 text-sm text-muted">{item.description || "No description yet."}</p>
          <div className="mt-3 flex flex-wrap gap-1.5">
            {(item.tags || []).length ? item.tags.map((tag) => <span key={tag} className="rounded-full border border-line bg-abyss/60 px-2 py-0.5 text-[11px] text-muted">#{tag}</span>) : <span className="text-xs text-muted">No tags</span>}
          </div>
          <div className="mt-4 grid gap-2 text-xs text-muted sm:grid-cols-3">
            <span>{item.evidence_count ?? 0} evidences</span>
            <span>{item.host_count ?? 0} hosts</span>
            <span className="truncate" title={processingLabel(item.processing_summary)}>{processingLabel(item.processing_summary)}</span>
          </div>
          <p className="mt-4 font-mono text-xs text-muted">Updated {new Date(item.updated_at).toLocaleString()} · Created {new Date(item.created_at).toLocaleString()}</p>
        </Link>
      </div>
      <div className="mt-4 flex flex-wrap gap-2">
        {onEdit ? <button type="button" onClick={() => onEdit(item)} className="rounded-xl border border-line bg-abyss/70 px-3 py-2 text-xs text-muted">Edit case</button> : null}
        {status === "archived" ? <button type="button" onClick={() => onUnarchive?.(item)} className="rounded-xl border border-accent/40 bg-accent/10 px-3 py-2 text-xs text-accent">Unarchive</button> : <button type="button" onClick={() => onArchive?.(item)} className="rounded-xl border border-line bg-abyss/70 px-3 py-2 text-xs text-muted">Archive</button>}
        {status === "closed" ? <button type="button" onClick={() => onReopen?.(item)} className="rounded-xl border border-accent/40 bg-accent/10 px-3 py-2 text-xs text-accent">Reopen</button> : <button type="button" onClick={() => onClose?.(item)} className="rounded-xl border border-line bg-abyss/70 px-3 py-2 text-xs text-muted">Close</button>}
      </div>
    </div>
  );
}
