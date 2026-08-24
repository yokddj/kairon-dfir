import { type FormEvent, useState } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { type MemoryFileExtraction, api } from "../../api/client";

type Props = {
  caseId: string;
  evidenceId?: string;
};

const ACTIVE_STATUSES = new Set(["queued", "running"]);

function statusTone(status: string): string {
  if (status === "completed") return "border-emerald-400/40 bg-emerald-500/10 text-emerald-100";
  if (status === "not_found") return "border-amber-400/40 bg-amber-400/10 text-amber-100";
  if (status === "failed") return "border-rose-400/40 bg-rose-500/10 text-rose-200";
  if (ACTIVE_STATUSES.has(status)) return "border-cyan-400/40 bg-cyan-500/10 text-cyan-100";
  return "border-line bg-white/5 text-muted";
}

function formatBytes(bytes: number): string {
  if (bytes < 1024) return `${bytes} B`;
  if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} KB`;
  return `${(bytes / (1024 * 1024)).toFixed(1)} MB`;
}

function ExtractionCard({ caseId, evidenceId, extraction }: { caseId: string; evidenceId: string; extraction: MemoryFileExtraction }) {
  const [downloadError, setDownloadError] = useState<string | null>(null);

  async function handleDownload(resultIndex: number, filename: string) {
    setDownloadError(null);
    try {
      const { blob, filename: resolvedFilename } = await api.downloadMemoryFileExtractionResult(caseId, evidenceId, extraction.id, resultIndex, filename);
      const url = URL.createObjectURL(blob);
      const anchor = document.createElement("a");
      anchor.href = url;
      anchor.download = resolvedFilename;
      document.body.append(anchor);
      anchor.click();
      anchor.remove();
      URL.revokeObjectURL(url);
    } catch (err) {
      setDownloadError(err instanceof Error ? err.message : "Download failed.");
    }
  }

  return (
    <div className="rounded-2xl border border-line bg-abyss/70 p-4" data-testid="memory-file-extraction-card">
      <div className="flex flex-wrap items-start justify-between gap-2">
        <p className="break-all font-mono text-sm text-ink">{extraction.requested_path}</p>
        <span className={`shrink-0 rounded-full border px-2.5 py-1 font-mono text-[10px] uppercase tracking-[0.14em] ${statusTone(extraction.status)}`}>
          {extraction.status.replace("_", " ")}
        </span>
      </div>

      {ACTIVE_STATUSES.has(extraction.status) ? (
        <p className="mt-2 text-xs text-muted">Running windows.filescan, then windows.dumpfiles for any match. This can take a few minutes on a large image.</p>
      ) : null}

      {extraction.status === "not_found" ? (
        <p className="mt-2 text-xs text-muted">
          {extraction.filescan_matches.length
            ? `Found ${extraction.filescan_matches.length} matching file object(s) in memory, but no cached pages could be recovered from any of them.`
            : "No file object matching this path was found in memory. The OS may no longer hold it cached, or the path may not match exactly."}
        </p>
      ) : null}

      {extraction.status === "failed" ? (
        <p className="mt-2 text-xs text-rose-200">{extraction.error_message || "Extraction failed."}</p>
      ) : null}

      {extraction.results.length ? (
        <div className="mt-3 overflow-auto rounded-xl border border-line">
          <table className="min-w-full divide-y divide-line text-xs">
            <thead className="bg-panel/40 text-left font-mono uppercase tracking-[0.12em] text-muted">
              <tr>
                <th className="px-3 py-2">Recovered as</th>
                <th className="px-3 py-2">Cache type</th>
                <th className="px-3 py-2">Size</th>
                <th className="px-3 py-2">SHA-256</th>
                <th className="px-3 py-2">Action</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-line/70">
              {extraction.results.map((result, index) => (
                <tr key={`${extraction.id}-${index}`} className="align-top">
                  <td className="px-3 py-2 text-ink">{result.original_filename || result.output_filename}</td>
                  <td className="px-3 py-2 text-muted">{result.cache_type || "-"}</td>
                  <td className="px-3 py-2 text-muted">{formatBytes(result.size_bytes)}</td>
                  <td className="max-w-[16rem] break-all px-3 py-2 font-mono text-muted">{result.sha256}</td>
                  <td className="px-3 py-2">
                    <button
                      type="button"
                      onClick={() => void handleDownload(index, result.original_filename || result.output_filename)}
                      className="rounded-lg border border-accent/40 bg-accent/10 px-2.5 py-1 text-xs text-accent"
                    >
                      Download
                    </button>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      ) : null}
      {downloadError ? <p className="mt-2 text-xs text-rose-200">{downloadError}</p> : null}
    </div>
  );
}

export function MemoryFilesTab({ caseId, evidenceId }: Props) {
  const queryClient = useQueryClient();
  const [path, setPath] = useState("");

  const extractionsQuery = useQuery({
    queryKey: ["memory-file-extractions", caseId, evidenceId ?? ""],
    queryFn: () => api.listMemoryFileExtractions(caseId, evidenceId as string),
    enabled: Boolean(caseId && evidenceId),
    refetchOnWindowFocus: false,
    refetchInterval: (query) => {
      const items = query.state.data?.items ?? [];
      return items.some((item) => ACTIVE_STATUSES.has(item.status)) ? 3000 : false;
    },
  });

  const extractMutation = useMutation({
    mutationFn: (vars: { evidenceId: string; path: string }) => api.extractMemoryFile(caseId, vars.evidenceId, vars.path),
    onSuccess: () => {
      setPath("");
      queryClient.invalidateQueries({ queryKey: ["memory-file-extractions", caseId, evidenceId ?? ""] });
    },
  });

  if (!evidenceId) {
    return (
      <section className="rounded-2xl border border-line bg-panel/60 p-5 text-sm text-muted">
        Select a specific memory evidence above to recover files from it.
      </section>
    );
  }

  function handleSubmit(event: FormEvent) {
    event.preventDefault();
    if (!evidenceId || !path.trim()) return;
    extractMutation.mutate({ evidenceId, path: path.trim() });
  }

  const extractions = extractionsQuery.data?.items ?? [];

  return (
    <div className="space-y-4">
      <section className="rounded-[28px] border border-line bg-panel/70 p-5 shadow-panel">
        <h3 className="text-sm font-semibold uppercase tracking-[0.18em] text-muted">Recover a file from memory</h3>
        <p className="mt-1 max-w-2xl text-xs text-muted">
          Enter a Windows path seen elsewhere in the case (an event log, a JumpList, a persistence hit) that has no hash yet. This runs windows.filescan
          to locate it in memory, then windows.dumpfiles to recover whatever cached pages Windows still had for it. Recovery is best effort -- the file may
          no longer be cached.
        </p>
        <form onSubmit={handleSubmit} className="mt-3 flex flex-wrap items-end gap-2">
          <label className="min-w-[20rem] flex-1 text-xs text-muted" htmlFor="memory-file-path">
            File path
            <input
              id="memory-file-path"
              type="text"
              value={path}
              onChange={(event) => setPath(event.target.value)}
              placeholder="C:\Schtask\check-updates.ps1"
              className="mt-1 w-full rounded-xl border border-line bg-abyss/70 px-3 py-2 font-mono text-sm text-ink outline-none focus:border-accent/50"
              data-testid="memory-file-path-input"
            />
          </label>
          <button
            type="submit"
            disabled={!path.trim() || extractMutation.isPending}
            className="rounded-xl bg-accent px-4 py-2 text-xs font-semibold text-abyss disabled:opacity-50"
            data-testid="memory-file-extract-button"
          >
            {extractMutation.isPending ? "Starting..." : "Extract from memory"}
          </button>
        </form>
        {extractMutation.error instanceof Error ? <p className="mt-2 text-xs text-rose-200">{extractMutation.error.message}</p> : null}
      </section>

      {extractionsQuery.isLoading ? <p className="text-sm text-muted">Loading extraction history...</p> : null}
      {extractionsQuery.error instanceof Error ? <p className="text-sm text-rose-200">{extractionsQuery.error.message}</p> : null}

      {extractions.length === 0 && !extractionsQuery.isLoading ? (
        <p className="text-sm text-muted">No file recovery attempts yet for this evidence.</p>
      ) : (
        <div className="space-y-3">
          {extractions.map((extraction) => (
            <ExtractionCard key={extraction.id} caseId={caseId} evidenceId={evidenceId} extraction={extraction} />
          ))}
        </div>
      )}
    </div>
  );
}
