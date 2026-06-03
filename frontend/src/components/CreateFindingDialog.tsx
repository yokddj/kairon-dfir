import { useEffect, useMemo, useState } from "react";
import { useMutation, useQueryClient } from "@tanstack/react-query";

import { api, type Finding } from "../api/client";

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
  onCreated,
}: Props) {
  const queryClient = useQueryClient();
  const [title, setTitle] = useState(defaultTitle);
  const [description, setDescription] = useState(defaultDescription);
  const [severity, setSeverity] = useState<FindingSeverity>(defaultSeverity);

  useEffect(() => {
    if (!open) return;
    setTitle(defaultTitle);
    setDescription(defaultDescription);
    setSeverity(defaultSeverity);
  }, [defaultDescription, defaultSeverity, defaultTitle, open]);

  const effectiveEventIds = useMemo(() => [...new Set(eventIds.filter(Boolean))], [eventIds]);
  const effectiveDetectionIds = useMemo(() => [...new Set(detectionIds.filter(Boolean))], [detectionIds]);

  const createMutation = useMutation({
    mutationFn: () =>
      api.createFinding(caseId, {
        title: title.trim() || undefined,
        description: description.trim() || undefined,
        severity,
        status: "open",
        query: query || undefined,
        event_ids: effectiveEventIds,
        detection_ids: effectiveDetectionIds,
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
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-abyss/70 px-4 backdrop-blur-sm">
      <div className="w-full max-w-2xl rounded-[28px] border border-line bg-panel p-6 shadow-panel">
        <div className="flex items-start justify-between gap-4">
          <div>
            <p className="font-mono text-xs uppercase tracking-[0.18em] text-accent">Create finding</p>
            <h3 className="mt-2 text-xl font-semibold">Turn selected evidence into an investigative finding</h3>
            <p className="mt-2 text-sm text-muted">
              {effectiveEventIds.length} linked event(s) · {effectiveDetectionIds.length} linked detection(s)
            </p>
          </div>
          <button onClick={onClose} className="rounded-2xl border border-line bg-abyss/80 px-3 py-2 text-sm text-muted">
            Close
          </button>
        </div>

        <div className="mt-5 grid gap-4 md:grid-cols-2">
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
          <div className="rounded-2xl border border-line bg-abyss/60 px-4 py-3 text-sm text-muted">
            Findings are created in the selected case and stay linked to the original event and/or detection IDs.
          </div>
          <label className="block md:col-span-2">
            <span className="mb-2 block font-mono text-[11px] uppercase tracking-[0.16em] text-muted">Description</span>
            <textarea
              value={description}
              onChange={(event) => setDescription(event.target.value)}
              placeholder="Why is this relevant? What should be investigated next?"
              className="h-36 w-full rounded-2xl border border-line bg-abyss/80 px-4 py-3 text-sm outline-none focus:border-accent/50"
            />
          </label>
        </div>

        {createMutation.error instanceof Error ? (
          <div className="mt-4 rounded-2xl border border-danger/30 bg-danger/10 p-4 text-sm text-danger">{createMutation.error.message}</div>
        ) : null}

        <div className="mt-5 flex flex-wrap gap-3">
          <button
            onClick={() => createMutation.mutate()}
            disabled={!caseId || (!effectiveEventIds.length && !effectiveDetectionIds.length) || createMutation.isPending}
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
  );
}
