import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { useState } from "react";
import { Link } from "react-router-dom";
import { api } from "../../api/client";
import { memoryQueryKeys } from "../../lib/memoryQueryKeys";

function formatBytes(bytes: number): string {
  if (bytes < 1024) return `${bytes} B`;
  if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} KB`;
  if (bytes < 1024 * 1024 * 1024) return `${(bytes / (1024 * 1024)).toFixed(1)} MB`;
  return `${(bytes / (1024 * 1024 * 1024)).toFixed(1)} GB`;
}

function saveBlob(blob: Blob, filename: string) {
  const url = URL.createObjectURL(blob);
  const anchor = document.createElement("a");
  anchor.href = url;
  anchor.download = filename;
  document.body.append(anchor);
  anchor.click();
  anchor.remove();
  URL.revokeObjectURL(url);
}

/**
 * The evidence's one saved MemProcFS scan: when and how it was made, its files (download each or
 * all, open a CSV as a full Source Table) and a new scan on request. Every Windows analysis reads
 * this scan instead of scanning the image again.
 */
export function MemoryMemProcFSScanPanel({ caseId, evidenceId }: { caseId: string; evidenceId: string }) {
  const queryClient = useQueryClient();
  const [showFiles, setShowFiles] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [queued, setQueued] = useState(false);
  const scanQuery = useQuery({ queryKey: ["memprocfs-scan", caseId, evidenceId], queryFn: () => api.getMemProcFSScan(caseId, evidenceId), refetchOnWindowFocus: false });
  const tablesQuery = useQuery({ queryKey: ["source-tables", caseId, evidenceId], queryFn: () => api.listSourceTables(caseId, evidenceId), enabled: showFiles });
  const requestTable = useMutation({
    mutationFn: (sourcePath: string) => api.requestSourceTables(caseId, evidenceId, [sourcePath]),
    onSuccess: () => void queryClient.invalidateQueries({ queryKey: ["source-tables", caseId] }),
    onError: (err: Error) => setError(err.message),
  });
  const rescan = useMutation({
    mutationFn: () => api.rescanMemProcFS(caseId, evidenceId),
    onSuccess: () => {
      setQueued(true);
      for (const key of memoryQueryKeys.invalidateAfterMutation(caseId, evidenceId)) void queryClient.invalidateQueries({ queryKey: key });
    },
    onError: (err: Error) => setError(err.message),
  });
  const scan = scanQuery.data;
  if (!scan || !scan.exists) return null;
  const tablesByPath = new Map((tablesQuery.data?.items ?? []).map((table) => [table.source_path, table]));

  async function download(path: string | null) {
    setError(null);
    try {
      const { blob, filename } = await api.downloadMemProcFSScan(caseId, evidenceId, path);
      saveBlob(blob, filename);
    } catch (err) {
      setError(err instanceof Error ? err.message : "Download failed.");
    }
  }

  return (
    <div className="mt-3 rounded-2xl border border-line bg-abyss/40 p-3 text-xs" data-testid="memory-memprocfs-scan">
      <div className="flex flex-wrap items-center justify-between gap-2">
        <p className="text-muted">
          Saved MemProcFS scan{scan.scanned_at ? ` of ${scan.scanned_at.replace("T", " ").replace("Z", " UTC")}` : ""}
          {scan.memprocfs_version ? ` · MemProcFS ${scan.memprocfs_version}` : ""} · YARA rules {scan.yara_rules ? "included" : "not included"} · {scan.files.length} files,{" "}
          {formatBytes(scan.total_bytes)}. Every analysis of this image reads it instead of scanning again.
        </p>
        <div className="flex flex-wrap gap-2">
          <button type="button" onClick={() => setShowFiles(!showFiles)} className="rounded-xl border border-line px-3 py-1 text-muted hover:text-ink" aria-expanded={showFiles} data-testid="memory-memprocfs-scan-files-toggle">
            {showFiles ? "Hide files" : "Files"}
          </button>
          <button type="button" onClick={() => void download(null)} className="rounded-xl border border-line px-3 py-1 text-muted hover:text-ink" data-testid="memory-memprocfs-scan-download-all">
            Download all (ZIP)
          </button>
          <button type="button" disabled={rescan.isPending || queued} onClick={() => rescan.mutate()} className="rounded-xl border border-line px-3 py-1 text-muted hover:text-ink disabled:opacity-50" data-testid="memory-memprocfs-rescan">
            {queued ? "New scan queued" : "New MemProcFS scan"}
          </button>
        </div>
      </div>
      {scan.notices.includes("yara_rules_missing") ? (
        <p className="mt-2 text-amber" role="status" data-testid="memory-memprocfs-scan-notice">
          This scan was made without MemProcFS's YARA rules, which are now enabled: run a new MemProcFS scan to include their matches.
        </p>
      ) : null}
      {queued ? <p className="mt-2 text-muted">Find Evil runs with a new scan; the other analyses read it when they run again.</p> : null}
      {error ? <p className="mt-2 text-rose-200" role="alert">{error}</p> : null}
      {showFiles ? (
        <ul className="mt-3 max-h-96 divide-y divide-line overflow-auto rounded-xl border border-line" data-testid="memory-memprocfs-scan-files">
          {scan.files.map((file) => {
            const table = tablesByPath.get(file.source_path);
            return (
              <li key={file.path} className="flex flex-wrap items-center justify-between gap-2 px-3 py-1.5">
                <span className="break-all font-mono text-[11px] text-ink">
                  {file.path} <span className="text-muted">· {formatBytes(file.size)}</span>
                </span>
                <span className="flex gap-2">
                  {file.tabular ? (
                    table?.status === "ready" ? (
                      <Link to={`/cases/${caseId}/tables/${table.id}`} className="rounded-full border border-mint/40 bg-mint/10 px-2 py-0.5 text-mint">
                        Open table
                      </Link>
                    ) : table && (table.status === "pending" || table.status === "building") ? (
                      <span className="rounded-full border border-line px-2 py-0.5 text-muted">Building table…</span>
                    ) : (
                      <button type="button" disabled={requestTable.isPending} onClick={() => requestTable.mutate(file.source_path)} className="rounded-full border border-accent/40 bg-accent/10 px-2 py-0.5 text-accent disabled:opacity-50">
                        Full table
                      </button>
                    )
                  ) : null}
                  <button type="button" onClick={() => void download(file.path)} className="rounded-full border border-line px-2 py-0.5 text-muted hover:text-ink">
                    Download
                  </button>
                </span>
              </li>
            );
          })}
        </ul>
      ) : null}
    </div>
  );
}
