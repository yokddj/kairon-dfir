import { useEffect, useState } from "react";
import { useMutation, useQueryClient } from "@tanstack/react-query";
import { Link } from "react-router-dom";
import { Loader2 } from "lucide-react";
import { api } from "../api/client";
import { memoryEvidenceRoute } from "../lib/canonicalRoutes";

export type BundledEvidenceItem = {
  path: string;
  kind: string;
  label: string;
  size_bytes?: number | null;
  registration_status?: "queued" | "running" | "registered" | "failed";
  registered_evidence_id?: string;
  registration_error?: string | null;
};

function formatBytes(value: number): string {
  const units = ["B", "KB", "MB", "GB", "TB"];
  let size = value;
  let unit = 0;
  while (size >= 1024 && unit < units.length - 1) {
    size /= 1024;
    unit += 1;
  }
  return `${size.toFixed(size >= 10 || unit === 0 ? 0 : 1)} ${units[unit]}`;
}

/**
 * Files a collection carried that are evidence of their own kind (a memory image, a packet
 * capture), left out of the collection's ingest. A memory image can be registered as its own
 * memory evidence from the file already extracted on the server, without uploading it again.
 */
export default function BundledEvidencePanel({
  caseId,
  evidenceId,
  items,
  defaultHost,
  hostNames,
}: {
  caseId: string;
  evidenceId: string;
  items: BundledEvidenceItem[];
  defaultHost: string;
  hostNames: string[];
}) {
  const queryClient = useQueryClient();
  const [openPath, setOpenPath] = useState<string | null>(null);
  const [host, setHost] = useState(defaultHost);
  const [error, setError] = useState<{ path: string; text: string } | null>(null);
  const inProgress = items.some((item) => item.registration_status === "queued" || item.registration_status === "running");

  // Follow a registration in progress (the evidence's metadata carries its state).
  useEffect(() => {
    if (!inProgress) return;
    const handle = window.setInterval(() => queryClient.invalidateQueries({ queryKey: ["evidence", evidenceId] }), 3000);
    return () => window.clearInterval(handle);
  }, [evidenceId, inProgress, queryClient]);

  const register = useMutation({
    mutationFn: (path: string) => api.registerBundledMemory(caseId, evidenceId, { path, provided_host: host.trim() }),
    onSuccess: () => {
      setOpenPath(null);
      setError(null);
      queryClient.invalidateQueries({ queryKey: ["evidence", evidenceId] });
    },
    onError: (err: Error, path) => setError({ path, text: err.message }),
  });

  const memoryCount = items.filter((item) => item.kind === "memory_dump").length;

  return (
    <div className="mt-5 rounded-3xl border border-amber/30 bg-amber/10 p-5" data-testid="evidence-bundled-unprocessed">
      <p className="font-mono text-[11px] uppercase tracking-[0.18em] text-amber">Not processed with this upload</p>
      <p className="mt-2 text-sm text-muted">
        These files are evidence of their own kind and were left out of this collection's ingest.
        {memoryCount ? " A memory image can be analysed as its own memory evidence from the file already on the server, without uploading it again." : ""}
        {items.some((item) => item.kind === "pcap") ? " Packet captures cannot be analysed yet." : ""}
      </p>
      <ul className="mt-3 space-y-3 text-sm">
        {items.map((item) => {
          const status = item.registration_status;
          const busy = status === "queued" || status === "running";
          return (
            <li key={item.path} className="break-all" data-testid="bundled-evidence-item">
              <div>
                <span className="text-ink">{item.label}</span> · <span className="font-mono text-xs text-muted">{item.path}</span>
                {typeof item.size_bytes === "number" ? <span className="text-xs text-muted"> · {formatBytes(item.size_bytes)}</span> : null}
              </div>
              {item.kind === "memory_dump" ? (
                <div className="mt-2">
                  {status === "registered" && item.registered_evidence_id ? (
                    <Link to={memoryEvidenceRoute(caseId, item.registered_evidence_id)} className="text-xs text-accent hover:underline" data-testid="bundled-memory-registered">
                      Registered as memory evidence — open it
                    </Link>
                  ) : busy ? (
                    <span className="flex items-center gap-2 text-xs text-muted" data-testid="bundled-memory-progress">
                      <Loader2 size={13} className="animate-spin" /> Hashing and inspecting the image ({status})… it then appears as its own memory evidence.
                    </span>
                  ) : openPath === item.path ? (
                    <form
                      className="flex flex-wrap items-end gap-2"
                      onSubmit={(event) => {
                        event.preventDefault();
                        if (host.trim()) register.mutate(item.path);
                      }}
                    >
                      <label className="text-xs text-muted">
                        Host it was captured on
                        <input
                          aria-label="Host it was captured on"
                          list={`bundled-hosts-${evidenceId}`}
                          value={host}
                          onChange={(event) => setHost(event.target.value)}
                          className="mt-1 block w-56 rounded-xl border border-line bg-black/30 px-3 py-1.5 text-sm text-ink"
                        />
                        <datalist id={`bundled-hosts-${evidenceId}`}>
                          {hostNames.map((name) => (
                            <option key={name} value={name} />
                          ))}
                        </datalist>
                      </label>
                      <button type="submit" disabled={register.isPending || !host.trim()} className="rounded-xl bg-accent/15 px-3 py-1.5 text-xs text-accent hover:bg-accent/25 disabled:opacity-50">
                        {register.isPending ? "Starting…" : "Analyse as memory evidence"}
                      </button>
                      <button type="button" onClick={() => setOpenPath(null)} className="text-xs text-muted hover:text-ink">
                        Cancel
                      </button>
                    </form>
                  ) : (
                    <button
                      type="button"
                      onClick={() => {
                        setOpenPath(item.path);
                        setHost(defaultHost);
                        setError(null);
                      }}
                      className="rounded-xl border border-accent/40 px-3 py-1.5 text-xs text-accent hover:bg-accent/10"
                    >
                      {status === "failed" ? "Try again as memory evidence" : "Analyse as memory evidence"}
                    </button>
                  )}
                  {status === "failed" && item.registration_error ? <p className="mt-1 text-xs text-danger">{item.registration_error}</p> : null}
                  {error?.path === item.path ? (
                    <p className="mt-1 text-xs text-danger" role="alert">
                      {error.text}
                    </p>
                  ) : null}
                </div>
              ) : null}
            </li>
          );
        })}
      </ul>
    </div>
  );
}
