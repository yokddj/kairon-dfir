import { useEffect, useMemo, useState } from "react";
import { useMutation, useQueryClient } from "@tanstack/react-query";

import { api, type Finding } from "../api/client";
import type { FindingPrefill } from "../lib/findingPrefill";
import Portal from "./Portal";

type FindingSeverity = "info" | "low" | "medium" | "high" | "critical";

type Props = {
  open: boolean;
  onClose: () => void;
  caseId: string;
  eventIds?: string[];
  detectionIds?: string[];
  defaultTitle?: string;
  defaultDescription?: string;
  defaultSeverity?: FindingSeverity;
  query?: string | null;
  prefill?: FindingPrefill | null;
  onCreated?: (finding: Finding) => void;
};

export default function CreateFindingDialog({
  open,
  onClose,
  caseId,
  eventIds = [],
  detectionIds = [],
  defaultTitle = "",
  defaultDescription = "",
  defaultSeverity = "medium",
  query = null,
  prefill = null,
  onCreated,
}: Props) {
  const queryClient = useQueryClient();
  const [title, setTitle] = useState(defaultTitle);
  const [description, setDescription] = useState(defaultDescription);
  const [severity, setSeverity] = useState<FindingSeverity>(defaultSeverity);
  const [status, setStatus] = useState<string>("draft");
  const [tags, setTags] = useState("");
  const [sourceSummary, setSourceSummary] = useState("");

  useEffect(() => {
    if (!open) return;
    setTitle(prefill?.title ?? defaultTitle);
    setDescription(prefill?.body ?? prefill?.description ?? defaultDescription);
    setSeverity(prefill?.severity ?? defaultSeverity);
    setStatus(prefill?.status ?? "draft");
    setTags((prefill?.tags ?? []).join(", "));
    setSourceSummary(prefill?.source_summary ?? "");
  }, [defaultDescription, defaultSeverity, defaultTitle, open, prefill]);

  const effectiveEventIds = useMemo(() => [...new Set(eventIds.filter(Boolean))], [eventIds]);
  const effectiveDetectionIds = useMemo(() => [...new Set(detectionIds.filter(Boolean))], [detectionIds]);

  const createMutation = useMutation({
    mutationFn: () =>
      api.createFinding(caseId, {
        title: title.trim() || undefined,
        body: description.trim() || undefined,
        severity,
        status: status as Finding["status"],
        query: query || prefill?.query || undefined,
        event_ids: effectiveEventIds.length ? effectiveEventIds : prefill?.event_ids ?? [],
        detection_ids: effectiveDetectionIds,
        related_hosts: prefill?.related_hosts ?? [],
        linked_evidence_id: prefill?.linked_evidence_id || undefined,
        linked_host_id: prefill?.linked_host_id || undefined,
        linked_artifact_id: prefill?.linked_artifact_id || undefined,
        linked_artifact_family: prefill?.linked_artifact_family || undefined,
        linked_artifact_type: prefill?.linked_artifact_type || undefined,
        linked_event_id: prefill?.linked_event_id || undefined,
        source_view: prefill?.source_view || undefined,
        source_route: prefill?.source_route || undefined,
        source_timestamp: prefill?.source_timestamp || undefined,
        source_label: prefill?.source_label || undefined,
        source_summary: sourceSummary.trim() || prefill?.source_summary || undefined,
        source_snapshot_json: prefill?.source_snapshot_json || undefined,
        tags: tags.split(",").map((item) => item.trim()).filter(Boolean),
      }),
    onSuccess: async (finding) => {
      await queryClient.invalidateQueries({ queryKey: ["findings-page"] });
      await queryClient.invalidateQueries({ queryKey: ["findings"] });
      await queryClient.invalidateQueries({ queryKey: ["case", caseId] });
      await queryClient.invalidateQueries({ queryKey: ["cases"] });
      await queryClient.invalidateQueries({ queryKey: ["investigation-summary", caseId] });
      await queryClient.invalidateQueries({ queryKey: ["dashboard-summary", caseId] });
      onCreated?.(finding);
      onClose();
    },
  });

  if (!open) return null;

  return (
    <Portal>
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-abyss/70 p-4 backdrop-blur-sm">
      <div className="flex max-h-[calc(100vh-2rem)] w-full max-w-2xl flex-col overflow-hidden rounded-[28px] border border-line bg-panel shadow-panel" role="dialog" aria-modal="true" aria-label="Create finding from source">
        <div className="shrink-0 border-b border-line/70 p-6 pb-4">
          <div className="flex items-start justify-between gap-4">
          <div>
            <p className="font-mono text-xs uppercase tracking-[0.18em] text-accent">Create finding</p>
            <h3 className="mt-2 text-xl font-semibold">Turn selected evidence into an investigative finding</h3>
            <p className="mt-2 text-sm text-muted">Create finding from this source item with editable context before saving.</p>
          </div>
          <button onClick={onClose} className="rounded-2xl border border-line bg-abyss/80 px-3 py-2 text-sm text-muted">
            Close
          </button>
          </div>
        </div>

        <div className="min-h-0 flex-1 overflow-y-auto overscroll-contain p-6" data-testid="create-finding-scroll-region">
        <div className="grid gap-4 md:grid-cols-2">
          <label className="block md:col-span-2">
            <span className="mb-2 block font-mono text-[11px] uppercase tracking-[0.16em] text-muted">Title</span>
            <input
              value={title}
              onChange={(event) => setTitle(event.target.value)}
              placeholder="Investigative lead from selected events"
              className="w-full rounded-2xl border border-line bg-abyss/80 px-4 py-3 text-sm outline-none focus:border-accent/50"
            />
          </label>
          <label className="block">
            <span className="mb-2 block font-mono text-[11px] uppercase tracking-[0.16em] text-muted">Severity</span>
            <select value={severity} onChange={(event) => setSeverity(event.target.value as FindingSeverity)} className="w-full rounded-2xl border border-line bg-abyss/80 px-4 py-3 text-sm outline-none focus:border-accent/50">
              <option value="info">info</option>
              <option value="low">low</option>
              <option value="medium">medium</option>
              <option value="high">high</option>
              <option value="critical">critical</option>
            </select>
          </label>
          <label className="block">
            <span className="mb-2 block font-mono text-[11px] uppercase tracking-[0.16em] text-muted">Status</span>
            <select value={status} onChange={(event) => setStatus(event.target.value)} className="w-full rounded-2xl border border-line bg-abyss/80 px-4 py-3 text-sm outline-none focus:border-accent/50">
              <option value="draft">draft</option>
              <option value="review">review</option>
              <option value="confirmed">confirmed</option>
              <option value="false_positive">false_positive</option>
            </select>
          </label>
          <label className="block md:col-span-2">
            <span className="mb-2 block font-mono text-[11px] uppercase tracking-[0.16em] text-muted">Tags</span>
            <input value={tags} onChange={(event) => setTags(event.target.value)} placeholder="browser, download, powershell" className="w-full rounded-2xl border border-line bg-abyss/80 px-4 py-3 text-sm outline-none focus:border-accent/50" />
          </label>
          <label className="block md:col-span-2">
            <span className="mb-2 block font-mono text-[11px] uppercase tracking-[0.16em] text-muted">Description</span>
            <textarea
              value={description}
              onChange={(event) => setDescription(event.target.value)}
              placeholder="Why is this relevant? What should be investigated next?"
              className="max-h-48 min-h-28 w-full resize-y rounded-2xl border border-line bg-abyss/80 px-4 py-3 text-sm outline-none focus:border-accent/50"
            />
          </label>
          {prefill ? (
            <details className="md:col-span-2 rounded-2xl border border-line bg-abyss/60 p-4">
              <summary className="cursor-pointer font-mono text-[11px] uppercase tracking-[0.16em] text-muted">Source artifact/event</summary>
              <div className="mt-3 grid gap-3 text-sm text-muted md:grid-cols-2">
                <div>Family: <span className="text-slate-100">{prefill.linked_artifact_family || "-"}</span></div>
                <div>Type: <span className="text-slate-100">{prefill.linked_artifact_type || "-"}</span></div>
                <div>Timestamp: <span className="text-slate-100">{prefill.source_timestamp || "-"}</span></div>
                <div>Source: <span className="text-slate-100">{prefill.source_view || "-"}</span></div>
                <label className="block md:col-span-2">
                  <span className="mb-2 block font-mono text-[11px] uppercase tracking-[0.16em] text-muted">Source summary</span>
                  <textarea value={sourceSummary} onChange={(event) => setSourceSummary(event.target.value)} className="max-h-36 min-h-20 w-full resize-y rounded-2xl border border-line bg-abyss/80 px-4 py-3 text-sm outline-none focus:border-accent/50" />
                </label>
              </div>
            </details>
          ) : null}
        </div>

        {createMutation.error instanceof Error ? (
          <div className="mt-4 rounded-2xl border border-danger/30 bg-danger/10 p-4 text-sm text-danger">{createMutation.error.message}</div>
        ) : null}
        </div>

        <div className="sticky bottom-0 shrink-0 border-t border-line/70 bg-panel/95 p-4 backdrop-blur" data-testid="create-finding-action-bar">
        <div className="flex flex-wrap gap-3">
          <button
            onClick={() => createMutation.mutate()}
            disabled={!caseId || createMutation.isPending}
            className="rounded-2xl bg-accent px-4 py-3 text-sm font-semibold text-abyss disabled:opacity-50"
          >
            {createMutation.isPending ? "Creating..." : "Create finding"}
          </button>
          <button onClick={onClose} className="rounded-2xl border border-line bg-abyss/80 px-4 py-3 text-sm text-muted">
            Cancel
          </button>
        </div>
        </div>
      </div>
    </div>
    </Portal>
  );
}
