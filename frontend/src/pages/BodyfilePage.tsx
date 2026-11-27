import { useMutation, useQuery } from "@tanstack/react-query";
import { FormEvent, useEffect, useMemo, useState } from "react";
import { useParams } from "react-router-dom";

import { api, type BodyfileSearchResponse } from "../api/client";

const SORT_OPTIONS = [
  { id: "mtime", label: "Modified" },
  { id: "crtime", label: "Created" },
  { id: "ctime", label: "Metadata changed" },
  { id: "atime", label: "Accessed" },
];

function fmt(value: string | null): string {
  if (!value) return "-";
  const date = new Date(value);
  return Number.isNaN(date.getTime()) ? value : date.toISOString().replace("T", " ").slice(0, 19);
}

function fmtSize(value: number | null): string {
  if (value === null || value === undefined) return "-";
  if (value < 1024) return `${value} B`;
  if (value < 1024 * 1024) return `${(value / 1024).toFixed(1)} KB`;
  return `${(value / (1024 * 1024)).toFixed(1)} MB`;
}

export default function BodyfilePage() {
  const { caseId = "" } = useParams();
  const evidencesQuery = useQuery({ queryKey: ["case-evidences", caseId], queryFn: () => api.listEvidences(caseId), enabled: Boolean(caseId) });
  const candidates = useMemo(
    () => (evidencesQuery.data ?? []).filter((item) => ["macos", "linux"].includes(String((item as { effective_platform?: string }).effective_platform || ""))),
    [evidencesQuery.data],
  );
  const [evidenceId, setEvidenceId] = useState("");
  const [pathText, setPathText] = useState("");
  const [sort, setSort] = useState("mtime");

  useEffect(() => {
    if (!evidenceId && candidates.length) setEvidenceId(candidates[0].id);
  }, [evidenceId, candidates]);

  const summaryQuery = useQuery({
    queryKey: ["bodyfile-summary", caseId, evidenceId],
    queryFn: () => api.getBodyfileSummary(caseId, evidenceId),
    enabled: Boolean(caseId && evidenceId),
  });
  const search = useMutation<BodyfileSearchResponse>({
    mutationFn: () => api.searchBodyfile(caseId, evidenceId, { path_contains: pathText.trim(), sort, limit: 500 }),
  });
  const submit = (event: FormEvent) => {
    event.preventDefault();
    if (pathText.trim().length >= 2 && evidenceId) search.mutate();
  };
  const result = search.data;

  return (
    <div className="space-y-6" data-testid="bodyfile-page">
      <section className="rounded-[28px] border border-line bg-panel/70 p-6 shadow-panel">
        <p className="font-mono text-xs uppercase tracking-[0.18em] text-accent">UAC &middot; File System</p>
        <h1 className="mt-2 text-2xl font-semibold text-ink">File Listing (bodyfile)</h1>
        <p className="mt-2 max-w-3xl text-sm text-muted">
          Every file and folder of the collected system with its four times &mdash; the counterpart of an NTFS MFT listing. Type part of a path and
          search: UAC&apos;s bodyfile is read from the evidence on demand, it is not in Search or the Timeline. Times are UTC.
        </p>
        <form className="mt-5 flex flex-wrap items-end gap-3" onSubmit={submit}>
          {candidates.length > 1 ? (
            <label className="text-xs text-muted">
              Evidence
              <select value={evidenceId} onChange={(event) => setEvidenceId(event.target.value)} className="mt-1 block rounded-xl border border-line bg-abyss/80 px-3 py-1.5 text-sm text-ink">
                {candidates.map((item) => (
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
              placeholder="e.g. /Downloads/ or .sh"
              className="mt-1 block w-72 rounded-xl border border-line bg-abyss/80 px-3 py-1.5 text-sm text-ink placeholder:text-muted/60"
              data-testid="bodyfile-path-input"
            />
          </label>
          <label className="text-xs text-muted">
            Newest first by
            <select value={sort} onChange={(event) => setSort(event.target.value)} className="mt-1 block rounded-xl border border-line bg-abyss/80 px-3 py-1.5 text-sm text-ink">
              {SORT_OPTIONS.map((option) => (
                <option key={option.id} value={option.id}>{option.label}</option>
              ))}
            </select>
          </label>
          <button
            type="submit"
            disabled={pathText.trim().length < 2 || !evidenceId || search.isPending}
            className="rounded-xl border border-accent/40 bg-accent/10 px-4 py-1.5 text-sm text-accent disabled:opacity-50"
            data-testid="bodyfile-search-button"
          >
            {search.isPending ? "Searching…" : "Search"}
          </button>
        </form>
        {summaryQuery.data && !summaryQuery.data.available ? (
          <p className="mt-4 text-sm text-muted" data-testid="bodyfile-unavailable">This evidence has no UAC bodyfile (bodyfile/bodyfile.txt).</p>
        ) : null}
        {!evidencesQuery.isLoading && !candidates.length ? <p className="mt-4 text-sm text-muted">No macOS or Linux evidence in this case.</p> : null}
        {search.isError ? <p className="mt-4 text-sm text-danger">{String((search.error as Error)?.message || "Search failed.")}</p> : null}
      </section>

      {result ? (
        <section className="rounded-[28px] border border-line bg-panel/70 p-6 shadow-panel" data-testid="bodyfile-results">
          <p className="text-sm text-muted">
            {result.total_matches.toLocaleString()} matching files{result.truncated ? `, newest ${result.records.length} shown` : ""} &middot; {result.elapsed_seconds}s
          </p>
          <div className="mt-4 overflow-x-auto">
            <table className="min-w-full text-left text-sm">
              <thead className="border-b border-line bg-abyss/70 font-mono text-[11px] uppercase tracking-[0.14em] text-muted">
                <tr>
                  <th className="px-3 py-2">Path</th>
                  <th className="px-3 py-2">Size</th>
                  <th className="px-3 py-2">Mode</th>
                  <th className="px-3 py-2">UID</th>
                  <th className="px-3 py-2">Modified</th>
                  <th className="px-3 py-2">Created</th>
                  <th className="px-3 py-2">Changed</th>
                  <th className="px-3 py-2">Accessed</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-line/70">
                {result.records.map((record) => (
                  <tr key={`${record.inode}-${record.path}`} data-testid="bodyfile-row">
                    <td className="px-3 py-2 font-mono text-xs text-ink break-all">
                      {record.path}
                      {record.link_target ? <span className="text-muted"> &rarr; {record.link_target}</span> : null}
                    </td>
                    <td className="px-3 py-2 text-xs text-muted">{fmtSize(record.size)}</td>
                    <td className="px-3 py-2 font-mono text-xs text-muted">{record.mode}</td>
                    <td className="px-3 py-2 font-mono text-xs text-muted">{record.uid}</td>
                    <td className="px-3 py-2 text-xs text-muted">{fmt(record.mtime)}</td>
                    <td className="px-3 py-2 text-xs text-muted">{fmt(record.crtime)}</td>
                    <td className="px-3 py-2 text-xs text-muted">{fmt(record.ctime)}</td>
                    <td className="px-3 py-2 text-xs text-muted">{fmt(record.atime)}</td>
                  </tr>
                ))}
              </tbody>
            </table>
            {!result.records.length ? <p className="px-3 py-6 text-sm text-muted">No files match.</p> : null}
          </div>
        </section>
      ) : null}
    </div>
  );
}
