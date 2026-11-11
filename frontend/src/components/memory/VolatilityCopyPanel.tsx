import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { Loader2 } from "lucide-react";
import { useState } from "react";
import { api, type VolatilityViewStatus } from "../../api/client";

function gib(bytes: number | null | undefined): string {
  return `${((bytes ?? 0) / 2 ** 30).toFixed(bytes && bytes < 10 * 2 ** 30 ? 1 : 0)} GiB`;
}

/**
 * Shown only when Volatility could not read this image (no memory layer: it found no page tables)
 * or a copy exists. MemProcFS can write the memory as a crash dump Volatility reads, about the size
 * of the image: the analyst decides, it is never written on its own.
 */
export function VolatilityCopyPanel({ caseId, evidenceId }: { caseId: string; evidenceId: string }) {
  const queryClient = useQueryClient();
  const queryKey = ["volatility-view", caseId, evidenceId];
  const [error, setError] = useState<string | null>(null);
  const query = useQuery({
    queryKey,
    queryFn: () => api.getVolatilityView(caseId, evidenceId),
    refetchInterval: (q) => {
      const state = (q.state.data as VolatilityViewStatus | undefined)?.status;
      return state === "queued" || state === "running" || state === "removing" ? 5000 : false;
    },
  });
  const onDone = {
    onSuccess: () => {
      setError(null);
      void queryClient.invalidateQueries({ queryKey });
    },
    onError: (err: Error) => setError(err.message),
  };
  const create = useMutation({ mutationFn: () => api.createVolatilityView(caseId, evidenceId), ...onDone });
  const remove = useMutation({ mutationFn: () => api.removeVolatilityView(caseId, evidenceId), ...onDone });
  const view = query.data;
  if (!view || (!view.needed && view.status === "none")) return null;

  const busy = view.status === "queued" || view.status === "running" || view.status === "removing";
  return (
    <section className="mt-4 rounded-[28px] border border-amber-400/30 bg-panel/70 p-5" data-testid="volatility-copy-panel" data-state={view.status}>
      <p className="font-mono text-[10px] uppercase tracking-[0.24em] text-accent">Volatility</p>
      {view.status === "created" ? (
        <>
          <p className="mt-1 text-sm font-semibold text-ink">Volatility reads this image through a crash-dump copy</p>
          <p className="mt-1 max-w-3xl text-xs text-muted">
            MemProcFS wrote the memory as a Windows crash dump ({gib(view.bytes)}), which Volatility, the symbol probe and the preparation read; MemProcFS's own analyses read
            the original image. Removing the copy frees that space, and Volatility can no longer read the image.
          </p>
          <button type="button" disabled={remove.isPending} onClick={() => remove.mutate()} className="mt-3 rounded-xl border border-line px-3 py-1.5 text-xs text-muted hover:text-ink disabled:opacity-50">
            Remove the copy
          </button>
        </>
      ) : (
        <>
          <p className="mt-1 text-sm font-semibold text-ink">Volatility cannot read this image</p>
          <p className="mt-1 max-w-3xl text-xs text-muted">
            It found no page tables, so it builds no memory layer; kernel symbols would not help. Processes, network, Find Evil and console text come from MemProcFS, which
            reads the image. For the Volatility analyses as well, MemProcFS can write the memory as a crash dump Volatility reads: about {gib(view.estimated_bytes)} of disk,
            next to the evidence's memory outputs, removed with the evidence or from here. Nothing that size is written without your request.
          </p>
          {view.status === "failed" || view.status === "skipped_disk_space" ? (
            <p className="mt-2 text-xs text-rose-200" role="alert">{view.message}</p>
          ) : null}
          {busy ? (
            <p className="mt-3 flex items-center gap-2 text-xs text-muted" role="status">
              <Loader2 size={13} className="animate-spin" />
              {view.status === "removing" ? "Removing the copy…" : view.status === "queued" ? "Queued on the memory worker…" : "Writing the copy (several minutes for a large image)…"}
            </p>
          ) : view.enabled ? (
            <button type="button" disabled={create.isPending} onClick={() => create.mutate()} className="mt-3 rounded-xl bg-accent/15 px-4 py-2 text-sm text-accent hover:bg-accent/25 disabled:opacity-50">
              Create the copy for Volatility (about {gib(view.estimated_bytes)})
            </button>
          ) : (
            <p className="mt-2 text-xs text-muted">Crash-dump copies are turned off on this instance (MEMORY_VOLATILITY_CRASHDUMP_VIEW_ENABLED=false).</p>
          )}
        </>
      )}
      {error ? <p className="mt-2 text-xs text-rose-200" role="alert">{error}</p> : null}
    </section>
  );
}
