import { type FormEvent, useState } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { type MemoryFileExtraction, api } from "../../api/client";
import { MemoryPaginationControls } from "./MemoryPaginationControls";

type Props = {
  caseId: string;
  evidenceId?: string;
};

type FileObjectRow = {
  document_id?: string;
  name?: string | null;
  offset?: string | null;
};

function FileBrowser({ caseId, evidenceId, onPickPath }: { caseId: string; evidenceId: string; onPickPath: (path: string) => void }) {
  const [page, setPage] = useState(1);
  const [nameFilter, setNameFilter] = useState("");
  const pageSize = 50;

  const activeResultQuery = useQuery({
    queryKey: ["memory-active-result", caseId, evidenceId, "files", page, nameFilter],
    queryFn: () =>
      api.getMemoryActiveResult(caseId, evidenceId, "files", undefined, {
        name: nameFilter || undefined,
        page,
        page_size: pageSize,
      }),
    enabled: Boolean(caseId && evidenceId),
    refetchOnWindowFocus: false,
  });

  const result = activeResultQuery.data;
  const items = (result?.items ?? []) as FileObjectRow[];
  const total = result?.total ?? 0;
  const totalPages = Math.max(1, Math.ceil(total / pageSize));
  const state = result?.analysis_state ?? "not_analyzed";

  return (
    <section className="rounded-[28px] border border-line bg-panel/60 p-5 shadow-panel" data-testid="memory-file-browser">
      <header className="flex flex-wrap items-center justify-between gap-3">
        <div>
          <h3 className="text-sm font-semibold uppercase tracking-[0.18em] text-muted">Browse files seen in memory</h3>
          <p className="mt-1 max-w-2xl text-xs text-muted">
            Every file object Windows currently references (open handle, cached section, mapped image) --
            windows.filescan, image-wide. Being listed here means Windows still has a reference to the path,
            not that its bytes are recoverable; pick a path below to attempt recovery.
          </p>
        </div>
      </header>

      <div className="mt-3 flex flex-wrap items-center gap-2 text-xs">
        <label className="text-muted" htmlFor="memory-file-browser-search">Path contains</label>
        <input
          id="memory-file-browser-search"
          value={nameFilter}
          onChange={(event) => { setNameFilter(event.target.value); setPage(1); }}
          placeholder="schtask\\check-updates.ps1"
          className="min-w-[16rem] flex-1 rounded-xl border border-line bg-abyss/70 px-3 py-1.5 font-mono text-sm text-ink outline-none focus:border-accent/50"
          data-testid="memory-file-browser-search-input"
        />
      </div>

      {activeResultQuery.isLoading ? <p className="mt-3 text-xs text-muted">Loading...</p> : null}
      {activeResultQuery.error instanceof Error ? (
        <p className="mt-3 rounded-2xl border border-rose-400/30 bg-rose-500/10 p-3 text-xs text-rose-200">
          {activeResultQuery.error.message}
        </p>
      ) : null}

      {!activeResultQuery.isLoading && !activeResultQuery.error && state === "not_analyzed" ? (
        <p className="mt-3 rounded-2xl border border-line bg-abyss/40 p-3 text-xs text-muted" data-testid="memory-file-browser-empty-not-analyzed">
          Files has not been analyzed yet. Run the "Files" profile from Run analysis to browse what Windows currently references in this image.
        </p>
      ) : null}

      {!activeResultQuery.isLoading && !activeResultQuery.error && (state === "failed" || state === "latest_attempt_failed") ? (
        <div className="mt-3 rounded-2xl border border-rose-400/30 bg-rose-500/10 p-3 text-xs text-rose-100" data-testid="memory-file-browser-empty-failed">
          <p>The latest Files run did not complete successfully.</p>
          {result?.latest_attempt?.status ? <p className="mt-1 text-rose-200">Latest attempt status: {result.latest_attempt.status}</p> : null}
        </div>
      ) : null}

      {!activeResultQuery.isLoading && !activeResultQuery.error && state === "analyzed_empty" ? (
        <p className="mt-3 rounded-2xl border border-line bg-abyss/40 p-3 text-xs text-muted" data-testid="memory-file-browser-empty-zero-results">
          {nameFilter ? "No file object matched that search." : "No file objects were recovered from this memory image."}
        </p>
      ) : null}

      {!activeResultQuery.isLoading && !activeResultQuery.error && (state === "analyzed_with_results" || state === "partial") ? (
        <>
          <p className="mt-3 text-xs text-muted" data-testid="memory-file-browser-summary">
            {total} file object{total === 1 ? "" : "s"} · page {page} of {totalPages}
          </p>
          <div className="mt-2 max-w-full overflow-x-auto rounded-2xl border border-line bg-abyss/40">
            <table className="min-w-[720px] w-full divide-y divide-line text-xs" data-testid="memory-file-browser-table">
              <thead className="bg-abyss/70 text-left text-[10px] uppercase tracking-[0.14em] text-muted">
                <tr>
                  <th className="px-2 py-1">Path</th>
                  <th className="px-2 py-1">Offset</th>
                  <th className="px-2 py-1">Action</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-line">
                {items.map((row, idx) => (
                  <tr key={row.document_id || `${row.offset}-${idx}`} data-testid="memory-file-browser-row">
                    <td className="break-all px-2 py-1 font-mono text-ink">{row.name || "—"}</td>
                    <td className="px-2 py-1 font-mono text-muted">{row.offset || "—"}</td>
                    <td className="px-2 py-1">
                      <button
                        type="button"
                        onClick={() => row.name && onPickPath(row.name)}
                        disabled={!row.name}
                        className="rounded-lg border border-accent/40 bg-accent/10 px-2.5 py-1 text-xs text-accent disabled:opacity-50"
                        data-testid="memory-file-browser-use-path"
                      >
                        Use this path
                      </button>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
          <div className="mt-3 flex items-center justify-between text-xs">
            <span className="text-muted">
              {items.length === 0 ? "No rows on this page." : `Showing ${(page - 1) * pageSize + 1}-${(page - 1) * pageSize + items.length} of ${total}`}
            </span>
            <MemoryPaginationControls
              page={page}
              totalPages={totalPages}
              onPage={setPage}
              prevTestId="memory-file-browser-prev-page"
              nextTestId="memory-file-browser-next-page"
            />
          </div>
        </>
      ) : null}
    </section>
  );
}

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
      <FileBrowser caseId={caseId} evidenceId={evidenceId} onPickPath={setPath} />

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
