import { useEffect, useMemo, useState } from "react";
import { useMutation, useQuery } from "@tanstack/react-query";

import { api } from "../../api/client";
import { artifactLabel } from "../../lib/artifactRegistry";

type Mode = "previous_selection" | "manual_selection" | "full_rediscovery";

/**
 * "Re-index…": same files as last time (default), a subset of them by family,
 * or a full rediscovery (typed confirmation, since it may parse a different set).
 */
export default function ReprocessDialog({
  evidenceId,
  providedHost,
  allowFamilyChoice,
  onClose,
  onStarted,
  onError,
}: {
  evidenceId: string;
  providedHost: string | null | undefined;
  allowFamilyChoice: boolean;
  onClose: () => void;
  onStarted: (runId: string) => void;
  onError: (message: string) => void;
}) {
  const [mode, setMode] = useState<Mode>("previous_selection");
  const [excludedTypes, setExcludedTypes] = useState<string[]>([]);
  const [confirmText, setConfirmText] = useState("");

  const preview = useQuery({
    queryKey: ["evidence-reprocess-preview", evidenceId, mode],
    queryFn: () => api.previewReprocessEvidence(evidenceId, { mode }),
    retry: false,
  });

  useEffect(() => {
    function onKey(event: KeyboardEvent) {
      if (event.key === "Escape") onClose();
    }
    window.addEventListener("keydown", onKey);
    const previous = document.body.style.overflow;
    document.body.style.overflow = "hidden";
    return () => {
      window.removeEventListener("keydown", onKey);
      document.body.style.overflow = previous;
    };
  }, [onClose]);

  const candidates = preview.data?.selected_candidates ?? [];
  const byType = useMemo(() => {
    const groups = new Map<string, string[]>();
    for (const candidate of candidates) {
      const key = candidate.artifact_type || "unknown";
      groups.set(key, [...(groups.get(key) ?? []), candidate.candidate_id]);
    }
    return [...groups.entries()].sort((left, right) => artifactLabel(left[0]).localeCompare(artifactLabel(right[0])));
  }, [candidates]);
  const manualIds = byType.filter(([type]) => !excludedTypes.includes(type)).flatMap(([, ids]) => ids);

  const start = useMutation({
    mutationFn: () =>
      api.reprocessEvidence(evidenceId, {
        mode,
        selected_candidate_ids: mode === "manual_selection" ? manualIds : undefined,
        parser_options: {},
        preserve_analyst_state: true,
        explicit_confirm: mode === "full_rediscovery",
        ingest_mode: "usable_search",
        provided_host: providedHost?.trim() || undefined,
        evtx_profile: "full",
      }),
    onSuccess: (result) => onStarted(result.run_id),
    onError: (error) => onError(error instanceof Error ? error.message : "The evidence could not be re-indexed."),
  });

  const noPreviousPlan = mode === "previous_selection" && preview.data && !preview.data.previous_plan_available;
  const canStart =
    !start.isPending &&
    !noPreviousPlan &&
    (mode !== "manual_selection" || manualIds.length > 0) &&
    (mode !== "full_rediscovery" || confirmText.trim() === "REDISCOVER");

  const options: Array<{ id: Mode; label: string; hint: string }> = [
    { id: "previous_selection", label: "Same files as last time", hint: "Re-parses what was indexed before, plus anything Kairon can read since." },
    ...(allowFamilyChoice ? [{ id: "manual_selection" as const, label: "Only some families", hint: "Pick which families of the previous selection to re-parse." }] : []),
    { id: "full_rediscovery", label: "Scan the evidence again", hint: "Discovers everything from scratch. May index a different set of files." },
  ];

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/70 p-4" role="dialog" aria-modal="true" aria-label="Re-index evidence">
      <div className="max-h-[90vh] w-full max-w-xl overflow-y-auto rounded-3xl border border-line bg-panel p-6 shadow-panel">
        <h3 className="text-xl font-semibold text-ink">Re-index evidence</h3>
        <p className="mt-1 text-sm text-muted">Findings, notes and tags are kept.</p>
        <div className="mt-4 space-y-2">
          {options.map((option) => (
            <label key={option.id} className={`flex cursor-pointer gap-3 rounded-2xl border px-4 py-3 ${mode === option.id ? "border-accent/50 bg-accent/10" : "border-line"}`}>
              <input type="radio" name="reprocess-mode" checked={mode === option.id} onChange={() => setMode(option.id)} className="mt-1" />
              <span>
                <span className="block text-sm font-medium text-ink">{option.label}</span>
                <span className="block text-xs text-muted">{option.hint}</span>
              </span>
            </label>
          ))}
        </div>

        {preview.isLoading ? <p className="mt-4 text-sm text-muted">Checking the previous selection…</p> : null}
        {preview.error instanceof Error ? <p className="mt-4 text-sm text-danger">{preview.error.message}</p> : null}
        {noPreviousPlan ? <p className="mt-4 text-sm text-amber">This evidence has no previous selection to repeat. Scan it again instead.</p> : null}
        {mode === "previous_selection" && preview.data?.previous_plan_available ? (
          <p className="mt-4 text-sm text-muted">
            {preview.data.summary.available_again.toLocaleString()} of {preview.data.summary.previous_selected.toLocaleString()} files are still available
            {preview.data.summary.missing ? ` · ${preview.data.summary.missing} missing` : ""}.
          </p>
        ) : null}
        {mode === "manual_selection" && byType.length ? (
          <div className="mt-4 flex flex-wrap gap-2">
            {byType.map(([type, ids]) => {
              const checked = !excludedTypes.includes(type);
              return (
                <label key={type} className={`flex cursor-pointer items-center gap-2 rounded-full border px-3 py-1.5 text-sm ${checked ? "border-accent/50 bg-accent/10 text-ink" : "border-line text-muted"}`}>
                  <input type="checkbox" checked={checked} onChange={() => setExcludedTypes((current) => (checked ? [...current, type] : current.filter((item) => item !== type)))} />
                  {artifactLabel(type)}
                  <span className="text-xs text-muted">{ids.length}</span>
                </label>
              );
            })}
          </div>
        ) : null}
        {mode === "full_rediscovery" ? (
          <label className="mt-4 block text-sm text-muted">
            Type REDISCOVER to confirm.
            <input value={confirmText} onChange={(event) => setConfirmText(event.target.value)} className="mt-2 w-full rounded-xl border border-line bg-abyss px-3 py-2 font-mono text-sm text-ink" />
          </label>
        ) : null}

        <div className="mt-6 flex justify-end gap-2">
          <button type="button" onClick={onClose} className="rounded-xl px-4 py-2 text-sm text-muted">
            Cancel
          </button>
          <button type="button" onClick={() => start.mutate()} disabled={!canStart} className="rounded-xl bg-accent px-4 py-2 text-sm font-semibold text-abyss disabled:opacity-50">
            {start.isPending ? "Starting…" : "Re-index"}
          </button>
        </div>
      </div>
    </div>
  );
}
