import { useEffect, useMemo, useState } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { useNavigate, useSearchParams } from "react-router-dom";
import { api, type DfirCase } from "../api/client";
import CaseCard from "../components/CaseCard";
import DeleteCaseDialog from "../components/DeleteCaseDialog";

const statuses = ["active", "closed", "archived", "on_hold"];
const priorities = ["low", "medium", "high", "critical"];
const sortOptions = [
  ["updated_desc", "Recent activity"],
  ["created_desc", "Created date"],
  ["priority", "Priority"],
  ["name", "Name"],
];

function tagsText(tags: string[] | undefined): string {
  return (tags || []).join(", ");
}

function parseTags(value: string): string[] {
  return value.split(",").map((tag) => tag.trim()).filter(Boolean);
}

export default function Cases() {
  const navigate = useNavigate();
  const queryClient = useQueryClient();
  const [searchParams, setSearchParams] = useSearchParams();
  const q = searchParams.get("q") || "";
  const status = searchParams.get("status") || "";
  const priority = searchParams.get("priority") || "";
  const tag = searchParams.get("tag") || "";
  const sort = searchParams.get("sort") || "updated_desc";
  const includeArchived = searchParams.get("include_archived") === "true";
  const [name, setName] = useState("");
  const [description, setDescription] = useState("");
  const [editing, setEditing] = useState<DfirCase | null>(null);
  const [deleting, setDeleting] = useState<DfirCase | null>(null);
  const [editName, setEditName] = useState("");
  const [editDescription, setEditDescription] = useState("");
  const [editPriority, setEditPriority] = useState("medium");
  const [editStatus, setEditStatus] = useState("active");
  const [editTags, setEditTags] = useState("");
  const [editNotes, setEditNotes] = useState("");

  const params = useMemo(() => ({ q, status, priority, tag, include_archived: includeArchived, sort }), [includeArchived, priority, q, sort, status, tag]);
  const { data, isLoading, error } = useQuery({ queryKey: ["cases", params], queryFn: () => api.listCases(params) });

  function updateFilter(key: string, value: string | boolean) {
    const next = new URLSearchParams(searchParams);
    if (value === "" || value === false) next.delete(key);
    else next.set(key, String(value));
    setSearchParams(next, { replace: true });
  }

  function clearFilters() {
    setSearchParams(new URLSearchParams(), { replace: true });
  }

  const createMutation = useMutation({
    mutationFn: () => api.createCase({ name, description, status: "active", priority: "medium", tags: [] }),
    onSuccess: (createdCase) => {
      setName("");
      setDescription("");
      void queryClient.invalidateQueries({ queryKey: ["cases"] });
      void navigate(`/cases/${createdCase.id}/overview`);
    },
  });

  const updateMutation = useMutation({
    mutationFn: () => {
      if (!editing) throw new Error("No case selected");
      return api.updateCase(editing.id, { name: editName, description: editDescription, priority: editPriority as DfirCase["priority"], status: editStatus as DfirCase["status"], tags: parseTags(editTags), case_notes: editNotes });
    },
    onSuccess: (updated) => {
      setEditing(null);
      void queryClient.invalidateQueries({ queryKey: ["cases"] });
      void queryClient.invalidateQueries({ queryKey: ["case", updated.id] });
    },
  });

  const statusMutation = useMutation({
    mutationFn: ({ action, item }: { action: "archive" | "unarchive" | "close" | "reopen"; item: DfirCase }) => {
      if (action === "archive") return api.archiveCase(item.id);
      if (action === "unarchive") return api.unarchiveCase(item.id);
      if (action === "close") return api.closeCase(item.id);
      return api.reopenCase(item.id);
    },
    onSuccess: (updated) => {
      void queryClient.invalidateQueries({ queryKey: ["cases"] });
      void queryClient.invalidateQueries({ queryKey: ["case", updated.id] });
    },
  });

  useEffect(() => {
    if (!editing) return;
    setEditName(editing.name || "");
    setEditDescription(editing.description || "");
    setEditPriority(editing.priority || "medium");
    setEditStatus(editing.status === "open" ? "active" : editing.status || "active");
    setEditTags(tagsText(editing.tags));
    setEditNotes(editing.case_notes || "");
  }, [editing]);

  const allTags = useMemo(() => Array.from(new Set((data || []).flatMap((item) => item.tags || []))).sort(), [data]);
  const hasFilters = Boolean(q || status || priority || tag || includeArchived || sort !== "updated_desc");
  const visibleCases = data || [];

  return (
    <div className="space-y-8">
      <section className="grid gap-6 lg:grid-cols-[1.1fr_1.9fr]">
        <div className="rounded-3xl border border-line bg-panel/70 p-6 shadow-panel">
          <p className="font-mono text-xs uppercase tracking-[0.18em] text-accent">Create case</p>
          <input value={name} onChange={(event) => setName(event.target.value)} placeholder="ACME Incident 001" className="mt-4 w-full rounded-2xl border border-line bg-abyss/80 px-4 py-3 text-sm outline-none focus:border-accent/50" />
          <textarea value={description} onChange={(event) => setDescription(event.target.value)} placeholder="Short description of the investigation scope" className="mt-3 h-32 w-full rounded-2xl border border-line bg-abyss/80 px-4 py-3 text-sm outline-none focus:border-accent/50" />
          {createMutation.error instanceof Error ? <p className="mt-3 text-sm text-danger">{createMutation.error.message}</p> : null}
          <button onClick={() => createMutation.mutate()} disabled={createMutation.isPending || !name.trim()} className="mt-4 rounded-2xl bg-accent px-4 py-2 text-sm font-semibold text-abyss disabled:cursor-not-allowed disabled:opacity-50">
            {createMutation.isPending ? "Creating..." : "Create Case"}
          </button>
          <p className="mt-3 text-xs text-muted">New cases start active with medium priority. Archive hides cases from the default list without deleting evidence.</p>
        </div>

        <div className="space-y-4">
          <div className="rounded-3xl border border-line bg-panel/70 p-4 shadow-panel" data-testid="case-filters">
            <div className="grid gap-3 md:grid-cols-3">
              <input value={q} onChange={(event) => updateFilter("q", event.target.value)} placeholder="Search name or description" className="rounded-2xl border border-line bg-abyss/80 px-4 py-2 text-sm" />
              <select value={status} onChange={(event) => updateFilter("status", event.target.value)} className="rounded-2xl border border-line bg-abyss/80 px-4 py-2 text-sm" aria-label="Status filter">
                <option value="">All statuses</option>
                {statuses.map((item) => <option key={item} value={item}>{item}</option>)}
              </select>
              <select value={priority} onChange={(event) => updateFilter("priority", event.target.value)} className="rounded-2xl border border-line bg-abyss/80 px-4 py-2 text-sm" aria-label="Priority filter">
                <option value="">All priorities</option>
                {priorities.map((item) => <option key={item} value={item}>{item}</option>)}
              </select>
              <select value={tag} onChange={(event) => updateFilter("tag", event.target.value)} className="rounded-2xl border border-line bg-abyss/80 px-4 py-2 text-sm" aria-label="Tag filter">
                <option value="">All tags</option>
                {allTags.map((item) => <option key={item} value={item}>{item}</option>)}
                {tag && !allTags.includes(tag) ? <option value={tag}>{tag}</option> : null}
              </select>
              <select value={sort} onChange={(event) => updateFilter("sort", event.target.value)} className="rounded-2xl border border-line bg-abyss/80 px-4 py-2 text-sm" aria-label="Sort cases">
                {sortOptions.map(([value, label]) => <option key={value} value={value}>{label}</option>)}
              </select>
              <label className="flex items-center gap-2 rounded-2xl border border-line bg-abyss/80 px-4 py-2 text-sm text-muted">
                <input type="checkbox" checked={includeArchived} onChange={(event) => updateFilter("include_archived", event.target.checked)} /> Include archived
              </label>
            </div>
            {hasFilters ? <button onClick={clearFilters} className="mt-3 rounded-xl border border-line bg-abyss/70 px-3 py-2 text-xs text-muted">Clear filters</button> : null}
          </div>

          {isLoading ? <p className="text-sm text-muted">Loading cases...</p> : null}
          {error instanceof Error ? <p className="text-sm text-danger">{error.message}</p> : null}
          {updateMutation.error instanceof Error ? <p className="text-sm text-danger">{updateMutation.error.message}</p> : null}
          {statusMutation.error instanceof Error ? <p className="text-sm text-danger">{statusMutation.error.message}</p> : null}

          <div className="grid gap-4 md:grid-cols-2">
            {visibleCases.map((item) => (
              <CaseCard
                key={item.id}
                item={item}
                onEdit={setEditing}
                onArchive={(selected) => window.confirm(`Archive case "${selected.name}"? Evidence and indexes are preserved.`) && statusMutation.mutate({ action: "archive", item: selected })}
                onUnarchive={(selected) => statusMutation.mutate({ action: "unarchive", item: selected })}
                onClose={(selected) => window.confirm(`Close case "${selected.name}"? You can reopen it later.`) && statusMutation.mutate({ action: "close", item: selected })}
                onReopen={(selected) => statusMutation.mutate({ action: "reopen", item: selected })}
                onDelete={(selected) => setDeleting(selected)}
              />
            ))}
          </div>
          {!isLoading && !error && !visibleCases.length ? (
            <div className="rounded-3xl border border-line bg-panel/40 p-6 text-sm text-muted">
              {includeArchived ? "No cases match your filters. Clear filters or create a new case." : "No active cases match your filters. Clear filters or include archived cases."}
            </div>
          ) : null}
        </div>
      </section>

      {editing ? (
        <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/60 p-4" role="dialog" aria-modal="true" aria-label="Edit case">
          <div className="w-full max-w-2xl rounded-3xl border border-line bg-panel p-6 shadow-panel">
            <div className="flex items-start justify-between gap-3">
              <div>
                <p className="font-mono text-xs uppercase tracking-[0.18em] text-accent">Edit case</p>
                <h2 className="mt-1 text-xl font-semibold">{editing.name}</h2>
              </div>
              <button onClick={() => setEditing(null)} className="rounded-xl border border-line px-3 py-2 text-xs text-muted">Cancel</button>
            </div>
            <div className="mt-4 grid gap-3">
              <label className="text-xs text-muted">Name<input value={editName} onChange={(event) => setEditName(event.target.value)} className="mt-1 w-full rounded-2xl border border-line bg-abyss/80 px-4 py-2 text-sm text-ink" /></label>
              <label className="text-xs text-muted">Description<textarea value={editDescription} onChange={(event) => setEditDescription(event.target.value)} className="mt-1 h-24 w-full rounded-2xl border border-line bg-abyss/80 px-4 py-2 text-sm text-ink" /></label>
              <div className="grid gap-3 md:grid-cols-2">
                <label className="text-xs text-muted">Priority<select value={editPriority} onChange={(event) => setEditPriority(event.target.value)} className="mt-1 w-full rounded-2xl border border-line bg-abyss/80 px-4 py-2 text-sm text-ink">{priorities.map((item) => <option key={item} value={item}>{item}</option>)}</select></label>
                <label className="text-xs text-muted">Status<select value={editStatus} onChange={(event) => setEditStatus(event.target.value)} className="mt-1 w-full rounded-2xl border border-line bg-abyss/80 px-4 py-2 text-sm text-ink">{statuses.map((item) => <option key={item} value={item}>{item}</option>)}</select></label>
              </div>
              <label className="text-xs text-muted">Tags<input value={editTags} onChange={(event) => setEditTags(event.target.value)} placeholder="ctf, memory, windows" className="mt-1 w-full rounded-2xl border border-line bg-abyss/80 px-4 py-2 text-sm text-ink" /></label>
              <label className="text-xs text-muted">Notes<textarea value={editNotes} onChange={(event) => setEditNotes(event.target.value)} className="mt-1 h-24 w-full rounded-2xl border border-line bg-abyss/80 px-4 py-2 text-sm text-ink" /></label>
            </div>
            <button onClick={() => updateMutation.mutate()} disabled={updateMutation.isPending || !editName.trim()} className="mt-5 rounded-2xl bg-accent px-4 py-2 text-sm font-semibold text-abyss disabled:opacity-50">
              {updateMutation.isPending ? "Saving..." : "Save case"}
            </button>
          </div>
        </div>
      ) : null}

      <DeleteCaseDialog open={Boolean(deleting)} caseItem={deleting} onClose={() => setDeleting(null)} />
    </div>
  );
}
