import { useMutation, useQuery } from "@tanstack/react-query";
import { FormEvent, useEffect, useMemo, useState } from "react";
import { useParams } from "react-router-dom";

import { api, type FseventsSearchResponse } from "../api/client";

const CHANGE_OPTIONS: { id: string; label: string }[] = [
  { id: "created", label: "Created" },
  { id: "removed", label: "Removed" },
  { id: "renamed", label: "Renamed" },
  { id: "modified", label: "Modified" },
  { id: "folder_created", label: "Folder created" },
  { id: "permissions_changed", label: "Permissions changed" },
  { id: "extended_attribute_modified", label: "Xattr modified" },
];

function fmt(value: string | null): string {
  if (!value) return "-";
  const date = new Date(value);
  return Number.isNaN(date.getTime()) ? value : date.toISOString().replace("T", " ").slice(0, 19) + " UTC";
}

export default function FseventsPage() {
  const { caseId = "" } = useParams();
  const evidencesQuery = useQuery({ queryKey: ["case-evidences", caseId], queryFn: () => api.listEvidences(caseId), enabled: Boolean(caseId) });
  const macosEvidences = useMemo(
    () => (evidencesQuery.data ?? []).filter((item) => String((item as { effective_platform?: string }).effective_platform || "") === "macos"),
    [evidencesQuery.data],
  );
  const [evidenceId, setEvidenceId] = useState("");
  const [pathText, setPathText] = useState("");
  const [changes, setChanges] = useState<string[]>([]);
  const [itemType, setItemType] = useState("");

  useEffect(() => {
    if (!evidenceId && macosEvidences.length) setEvidenceId(macosEvidences[0].id);
  }, [evidenceId, macosEvidences]);

  const summaryQuery = useQuery({
    queryKey: ["fsevents-summary", caseId, evidenceId],
    queryFn: () => api.getFseventsSummary(caseId, evidenceId),
    enabled: Boolean(caseId && evidenceId),
  });
  const search = useMutation<FseventsSearchResponse>({
    mutationFn: () => api.searchFsevents(caseId, evidenceId, { path_contains: pathText.trim(), changes, item_type: itemType || undefined, limit: 500 }),
  });

  const submit = (event: FormEvent) => {
    event.preventDefault();
    if (pathText.trim().length >= 2 && evidenceId) search.mutate();
  };
  const toggleChange = (id: string) => setChanges((prev) => (prev.includes(id) ? prev.filter((item) => item !== id) : [...prev, id]));
  const result = search.data;

  return (
    <div className="space-y-6" data-testid="fsevents-page">
      <section className="rounded-[28px] border border-line bg-panel/70 p-6 shadow-panel">
        <p className="font-mono text-xs uppercase tracking-[0.18em] text-accent">macOS &middot; File System Events</p>
        <h1 className="mt-2 text-2xl font-semibold text-ink">FSEvents</h1>
        <p className="mt-2 max-w-3xl text-sm text-muted">
          The change journal macOS keeps per volume: files and folders created, removed, renamed or modified, also for files that no longer exist.
          Searched on demand from the evidence (not indexed). Records carry no time of their own: they are ordered by event id, newest first, and the
          page time is when their page was written &mdash; the latest the change can have happened.
        </p>
        <form className="mt-5 flex flex-wrap items-end gap-3" onSubmit={submit}>
          {macosEvidences.length > 1 ? (
            <label className="text-xs text-muted">
              Evidence
              <select value={evidenceId} onChange={(event) => setEvidenceId(event.target.value)} className="mt-1 block rounded-xl border border-line bg-abyss/80 px-3 py-1.5 text-sm text-ink">
                {macosEvidences.map((item) => (
                  <option key={item.id} value={item.id}>{item.original_filename}</option>
                ))}
              </select>
            </label>
          ) : null}
          <label className="text-xs text-muted">
            Path contains
            <input
              value={pathText}
              onChange={(event) => setPathText(event.target.value)}
              placeholder="e.g. Downloads/ or .dmg"
              className="mt-1 block w-72 rounded-xl border border-line bg-abyss/80 px-3 py-1.5 text-sm text-ink placeholder:text-muted/60"
              data-testid="fsevents-path-input"
            />
          </label>
          <label className="text-xs text-muted">
            Type
            <select value={itemType} onChange={(event) => setItemType(event.target.value)} className="mt-1 block rounded-xl border border-line bg-abyss/80 px-3 py-1.5 text-sm text-ink">
              <option value="">Files and folders</option>
              <option value="file">Files</option>
              <option value="folder">Folders</option>
            </select>
          </label>
          <button
            type="submit"
            disabled={pathText.trim().length < 2 || !evidenceId || search.isPending}
            className="rounded-xl border border-accent/40 bg-accent/10 px-4 py-1.5 text-sm text-accent disabled:opacity-50"
            data-testid="fsevents-search-button"
          >
            {search.isPending ? "Searching…" : "Search"}
          </button>
          <div className="flex w-full flex-wrap gap-2">
            {CHANGE_OPTIONS.map((option) => (
              <label key={option.id} className="flex items-center gap-1 text-xs text-muted">
                <input type="checkbox" checked={changes.includes(option.id)} onChange={() => toggleChange(option.id)} />
                {option.label}
              </label>
            ))}
          </div>
        </form>
        {summaryQuery.data && !summaryQuery.data.available ? (
          <p className="mt-4 text-sm text-muted" data-testid="fsevents-unavailable">This evidence has no FSEvents journal (.fseventsd) in what was collected.</p>
        ) : null}
        {!evidencesQuery.isLoading && !macosEvidences.length ? <p className="mt-4 text-sm text-muted">No macOS evidence in this case.</p> : null}
        {search.isError ? <p className="mt-4 text-sm text-danger">{String((search.error as Error)?.message || "Search failed.")}</p> : null}
      </section>

      {result ? (
        <section className="rounded-[28px] border border-line bg-panel/70 p-6 shadow-panel" data-testid="fsevents-results">
          <p className="text-sm text-muted">
            {result.total_matches.toLocaleString()} matching records{result.truncated ? `, newest ${result.records.length} shown` : ""} &middot; {result.elapsed_seconds}s
          </p>
          <div className="mt-4 overflow-x-auto">
            <table className="min-w-full text-left text-sm">
              <thead className="border-b border-line bg-abyss/70 font-mono text-[11px] uppercase tracking-[0.14em] text-muted">
                <tr>
                  <th className="px-3 py-2">Path</th>
                  <th className="px-3 py-2">Changes</th>
                  <th className="px-3 py-2">Type</th>
                  <th className="px-3 py-2">Event id</th>
                  <th className="px-3 py-2">Page written</th>
                  <th className="px-3 py-2">Volume</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-line/70">
                {result.records.map((record) => (
                  <tr key={`${record.volume}-${record.event_id}-${record.path}`} data-testid="fsevents-row">
                    <td className="px-3 py-2 font-mono text-xs text-ink break-all">{record.path}</td>
                    <td className="px-3 py-2 text-xs text-muted">
                      {[...record.changes.map((change) => change.replaceAll("_", " ")), ...record.unknown_flags].join(", ") || "-"}
                    </td>
                    <td className="px-3 py-2 text-xs text-muted">{record.item_type || "-"}</td>
                    <td className="px-3 py-2 font-mono text-xs text-muted">{record.event_id}</td>
                    <td className="px-3 py-2 text-xs text-muted">{fmt(record.page_written)}</td>
                    <td className="px-3 py-2 font-mono text-xs text-muted">{record.volume}</td>
                  </tr>
                ))}
              </tbody>
            </table>
            {!result.records.length ? <p className="px-3 py-6 text-sm text-muted">No records match.</p> : null}
          </div>
        </section>
      ) : null}
    </div>
  );
}
