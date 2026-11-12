import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { Loader2 } from "lucide-react";
import { useState } from "react";
import { api, type VolatilityViewStatus } from "../../api/client";

function gib(bytes: number | null | undefined): string {
  return `${((bytes ?? 0) / 2 ** 30).toFixed(bytes && bytes < 10 * 2 ** 30 ? 1 : 0)} GiB`;
}

/**
 * Shown only when Volatility cannot read this image even with the page-table base MemProcFS finds,
 * or when an earlier version left a crash-dump copy for Volatility that is no longer needed.
 */
export function VolatilityCopyPanel({ caseId, evidenceId }: { caseId: string; evidenceId: string }) {
  const queryClient = useQueryClient();
  const queryKey = ["volatility-view", caseId, evidenceId];
  const [error, setError] = useState<string | null>(null);
  const query = useQuery({
    queryKey,
    queryFn: () => api.getVolatilityView(caseId, evidenceId),
    refetchInterval: (q) => ((q.state.data as VolatilityViewStatus | undefined)?.status === "removing" ? 5000 : false),
  });
  const remove = useMutation({
    mutationFn: () => api.removeVolatilityView(caseId, evidenceId),
    onSuccess: () => {
      setError(null);
      void queryClient.invalidateQueries({ queryKey });
    },
    onError: (err: Error) => setError(err.message),
  });
  const view = query.data;
  if (!view || (!view.needed && view.status === "none")) return null;

  return (
    <section className="mt-4 rounded-[28px] border border-amber-400/30 bg-panel/70 p-5" data-testid="volatility-copy-panel" data-state={view.status}>
      <p className="font-mono text-[10px] uppercase tracking-[0.24em] text-accent">Volatility</p>
      {view.status !== "none" ? (
        <>
          <p className="mt-1 text-sm font-semibold text-ink">The crash-dump copy for Volatility is no longer needed</p>
          <p className="mt-1 max-w-3xl text-xs text-muted">
            Volatility now reads the original image{view.layer ? ` with the page-table base MemProcFS found (${view.layer.page_map_offset})` : ""}; the copy (
            {gib(view.bytes)}) is not read any more. Removing it frees that space.
          </p>
          {view.status === "removing" ? (
            <p className="mt-3 flex items-center gap-2 text-xs text-muted" role="status">
              <Loader2 size={13} className="animate-spin" />
              Removing the copy…
            </p>
          ) : (
            <button type="button" disabled={remove.isPending} onClick={() => remove.mutate()} className="mt-3 rounded-xl border border-line px-3 py-1.5 text-xs text-muted hover:text-ink disabled:opacity-50">
              Remove the copy
            </button>
          )}
        </>
      ) : (
        <>
          <p className="mt-1 text-sm font-semibold text-ink">Volatility cannot read this image</p>
          <p className="mt-1 max-w-3xl text-xs text-muted">
            It found no page tables, and MemProcFS could not supply them either, so it builds no memory layer; kernel symbols would not help. Processes, network, Find Evil
            and console text come from MemProcFS where it reads the image.
          </p>
        </>
      )}
      {error ? <p className="mt-2 text-xs text-rose-200" role="alert">{error}</p> : null}
    </section>
  );
}
