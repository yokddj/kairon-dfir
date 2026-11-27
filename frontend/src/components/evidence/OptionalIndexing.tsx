import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";

import { api } from "../../api/client";
import { useNotifications } from "../../context/NotificationsContext";

type Row = { id: string; label: string; state: string; actions: Array<{ label: string; run: () => void; confirm?: string }> };

/**
 * Heavier Windows sources that are indexed on demand (full MFT, registry
 * persistence and user activity). Rendered only for the ones the evidence holds.
 */
export default function OptionalIndexing({ evidenceId, locked }: { evidenceId: string; locked: boolean }) {
  const queryClient = useQueryClient();
  const { notify } = useNotifications();
  const mftQuery = useQuery({ queryKey: ["evidence-mft-diagnostic", evidenceId], queryFn: () => api.getEvidenceMftDiagnostic(evidenceId), staleTime: 30_000 });
  const registryQuery = useQuery({ queryKey: ["evidence-registry-diagnostic", evidenceId], queryFn: () => api.getEvidenceRegistryDiagnostic(evidenceId), staleTime: 30_000 });

  const queue = useMutation({
    mutationFn: async (job: "mft_summary" | "mft_full" | "registry_persistence" | "user_activity") => {
      if (job === "mft_summary") return api.indexEvidenceMftSummary(evidenceId);
      if (job === "mft_full") return api.indexEvidenceMftFull(evidenceId, { force: true });
      if (job === "registry_persistence") return api.indexEvidenceRegistryPersistenceSummary(evidenceId, { force: true });
      return api.indexEvidenceRecmdUserActivity(evidenceId, { force: true });
    },
    onSuccess: () => {
      notify({ title: "Indexing queued", description: "Progress shows at the top of this page.", tone: "success" });
      for (const key of ["evidence", "evidence-runs", "evidence-search-summary", "evidence-mft-diagnostic", "evidence-registry-diagnostic"]) {
        void queryClient.invalidateQueries({ queryKey: [key, evidenceId] });
      }
    },
    onError: (error) => notify({ title: "Could not queue indexing", description: error instanceof Error ? error.message : "", tone: "error" }),
  });

  const rows: Row[] = [];
  const mft = mftQuery.data;
  const mftStatus = mft?.mft_status;
  if (mft && (mft.mft_present_in_evidence || mftStatus?.available || mftStatus?.raw_mft_found)) {
    const docs = Number(mftStatus?.indexed_docs ?? mft.mft_indexed_docs ?? 0);
    const tool = Boolean(mftStatus?.tool_available ?? mft.mft_backend_available);
    const running = mftStatus?.status === "indexing" || ["queued", "running"].includes(String(mft.mft_summary_status)) || ["queued", "running"].includes(String(mft.mft_full_status));
    rows.push({
      id: "mft",
      label: "File system ($MFT)",
      state: running ? "indexing…" : docs ? `${docs.toLocaleString()} records` : tool ? "not indexed" : "needs MFTECmd",
      actions: tool && !running
        ? [
            { label: docs ? "Re-index summary" : "Index summary", run: () => queue.mutate("mft_summary") },
            { label: docs ? "Re-index full" : "Index full", run: () => queue.mutate("mft_full"), confirm: "Index the full MFT? It can add millions of records and take a while." },
          ]
        : [],
    });
  }
  const registry = registryQuery.data;
  if (registry?.hives_present) {
    const persistenceStatus = String(registry.registry_status?.persistence_summary_status ?? registry.persistence_summary_status ?? "");
    const persistenceDocs = Number(registry.registry_status?.persistence_summary_docs ?? registry.registry_persistence_docs ?? 0);
    const activityStatus = String(registry.user_activity_status ?? "");
    const activityDocs = Number(registry.user_activity_docs ?? 0);
    const tool = Boolean(registry.tool_available);
    const busy = (value: string) => ["queued", "running", "indexing"].includes(value);
    rows.push({
      id: "registry_persistence",
      label: "Registry persistence",
      state: busy(persistenceStatus) ? "indexing…" : persistenceDocs ? `${persistenceDocs.toLocaleString()} keys` : "not indexed",
      actions: tool && !busy(persistenceStatus) ? [{ label: persistenceDocs ? "Rebuild" : "Index", run: () => queue.mutate("registry_persistence") }] : [],
    });
    rows.push({
      id: "user_activity",
      label: "Registry user activity",
      state: busy(activityStatus) ? "indexing…" : activityDocs ? `${activityDocs.toLocaleString()} records` : "not indexed",
      actions: tool && !busy(activityStatus) ? [{ label: activityDocs ? "Rebuild" : "Index", run: () => queue.mutate("user_activity") }] : [],
    });
  }
  if (!rows.length) return null;

  return (
    <div className="mt-5 border-t border-line pt-4" data-testid="evidence-optional-indexing">
      <p className="text-sm text-muted">Indexed on demand</p>
      <ul className="mt-2 divide-y divide-line/60">
        {rows.map((row) => (
          <li key={row.id} className="flex flex-wrap items-center justify-between gap-3 py-2 text-sm">
            <span className="text-ink">
              {row.label} <span className="text-muted">· {row.state}</span>
            </span>
            <span className="flex gap-2">
              {row.actions.map((action) => (
                <button
                  key={action.label}
                  type="button"
                  disabled={locked || queue.isPending}
                  onClick={() => {
                    if (!action.confirm || window.confirm(action.confirm)) action.run();
                  }}
                  className="rounded-full border border-line px-3 py-1 text-xs text-muted hover:border-accent/50 hover:text-accent disabled:opacity-40"
                >
                  {action.label}
                </button>
              ))}
            </span>
          </li>
        ))}
      </ul>
    </div>
  );
}
