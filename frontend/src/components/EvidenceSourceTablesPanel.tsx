import { useMemo } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { Link } from "react-router-dom";

import { api, type SourceTable } from "../api/client";

const TABULAR = /\.(csv|tsv)$/i;

const STATUS_TEXT: Record<SourceTable["status"], string> = {
  pending: "Queued",
  building: "Building…",
  ready: "Open table",
  failed: "Failed — retry",
  unavailable: "Source missing — retry",
};

/**
 * The CSV/TSV files of one evidence and their full-column tables (Source Tables).
 * Renders nothing when the evidence has no tabular files.
 */
export default function EvidenceSourceTablesPanel({ caseId, evidenceId }: { caseId: string; evidenceId: string }) {
  const queryClient = useQueryClient();
  const artifactsQuery = useQuery({ queryKey: ["case-artifacts", caseId], queryFn: () => api.listArtifacts(caseId), enabled: Boolean(caseId) });
  const tablesQuery = useQuery({
    queryKey: ["source-tables", caseId, evidenceId],
    queryFn: () => api.listSourceTables(caseId, evidenceId),
    enabled: Boolean(caseId),
    refetchInterval: (current) => (current.state.data?.items.some((item) => item.status === "pending" || item.status === "building") ? 4000 : false),
  });
  const request = useMutation({
    mutationFn: (sourcePaths: string[] | null) => api.requestSourceTables(caseId, evidenceId, sourcePaths),
    onSuccess: () => {
      void queryClient.invalidateQueries({ queryKey: ["source-tables", caseId] });
    },
  });

  const files = useMemo(() => {
    const seen = new Map<string, { name: string; source_path: string; artifact_type: string }>();
    for (const artifact of artifactsQuery.data ?? []) {
      if (artifact.evidence_id === evidenceId && TABULAR.test(artifact.source_path) && !seen.has(artifact.source_path)) {
        seen.set(artifact.source_path, { name: artifact.name, source_path: artifact.source_path, artifact_type: artifact.artifact_type });
      }
    }
    return [...seen.values()].sort((left, right) => left.source_path.localeCompare(right.source_path));
  }, [artifactsQuery.data, evidenceId]);
  const tablesByPath = useMemo(() => new Map((tablesQuery.data?.items ?? []).map((table) => [table.source_path, table])), [tablesQuery.data]);
  const missing = files.filter((file) => !tablesByPath.has(file.source_path));

  if (!files.length) return null;

  return (
    <section className="rounded-[28px] border border-line bg-panel/70 p-6 shadow-panel" data-testid="evidence-source-tables">
      <div className="flex flex-wrap items-start justify-between gap-3">
        <div>
          <p className="font-mono text-xs uppercase tracking-[0.24em] text-accent">Source tables</p>
          <h3 className="mt-2 text-xl font-semibold text-ink">CSV files with all their columns</h3>
          <p className="mt-1 max-w-3xl text-sm text-muted">Index a CSV whole to sort and filter by any of its columns, like Timeline Explorer. Search is unaffected.</p>
        </div>
        {missing.length > 1 ? (
          <button
            type="button"
            disabled={request.isPending}
            onClick={() => request.mutate(missing.map((file) => file.source_path))}
            className="rounded-2xl border border-accent/40 bg-accent/10 px-4 py-2 text-sm text-accent disabled:opacity-50"
          >
            Full table for all {missing.length}
          </button>
        ) : null}
      </div>
      {request.error instanceof Error ? <p className="mt-3 text-sm text-danger">{request.error.message}</p> : null}
      <ul className="mt-4 divide-y divide-line rounded-2xl border border-line">
        {files.map((file) => {
          const table = tablesByPath.get(file.source_path);
          return (
            <li key={file.source_path} className="flex flex-wrap items-center justify-between gap-3 px-4 py-2.5 text-sm">
              <div className="min-w-0">
                <p className="font-medium text-ink">{file.name}</p>
                <p className="break-all text-xs text-muted">{file.source_path}</p>
                {table?.error ? <p className="mt-0.5 text-xs text-danger">{table.error}</p> : null}
              </div>
              {table?.status === "ready" ? (
                <Link to={`/cases/${caseId}/tables/${table.id}`} className="rounded-full border border-mint/40 bg-mint/10 px-3 py-1 text-xs text-mint">
                  Open table · {table.row_count.toLocaleString()} rows
                </Link>
              ) : table && (table.status === "pending" || table.status === "building") ? (
                <span className="rounded-full border border-line px-3 py-1 text-xs text-muted">{STATUS_TEXT[table.status]}</span>
              ) : (
                <button
                  type="button"
                  disabled={request.isPending}
                  onClick={() => request.mutate([file.source_path])}
                  className="rounded-full border border-accent/40 bg-accent/10 px-3 py-1 text-xs text-accent disabled:opacity-50"
                >
                  {table ? STATUS_TEXT[table.status] : "Full table"}
                </button>
              )}
            </li>
          );
        })}
      </ul>
    </section>
  );
}
