import { useState } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";

import { api, type AiFindingSuggestion, type AiFindingSuggestions as Suggestions } from "../api/client";

const LEAD_KINDS: Record<string, string> = {
  detection: "rule detections",
  command: "suspicious commands",
  antivirus: "antivirus detections in memory",
  memory_process: "marked memory processes",
  lateral: "remote logons",
};

function utc(value: string | null): string {
  return value ? value.replace("T", " ").replace(/\.\d+Z$|Z$/, "") : "";
}

function phaseLabel(phase: string | null): string | null {
  return phase ? phase.replace(/_/g, " ") : null;
}

function SuggestionCard({
  suggestion,
  state,
  error,
  onAccept,
  onDismiss,
}: {
  suggestion: AiFindingSuggestion;
  state: "open" | "saving" | "accepted" | "dismissed";
  error: string | null;
  onAccept: () => void;
  onDismiss: () => void;
}) {
  return (
    <li className="rounded-2xl border border-line bg-abyss/60 p-4 text-sm" data-testid="ai-suggestion">
      <div className="flex flex-wrap items-start justify-between gap-3">
        <div>
          <p className="font-medium text-ink">{suggestion.title}</p>
          <p className="mt-1 text-xs text-muted">
            {suggestion.severity}
            {suggestion.confidence ? ` · ${suggestion.confidence} confidence` : ""}
            {phaseLabel(suggestion.phase) ? ` · ${phaseLabel(suggestion.phase)}` : ""}
            {suggestion.mitre.length ? ` · ${suggestion.mitre.join(", ")}` : ""}
          </p>
        </div>
        {state === "accepted" ? (
          <span className="text-xs text-accent">Finding created</span>
        ) : (
          <div className="flex gap-2">
            <button
              type="button"
              onClick={onAccept}
              disabled={state === "saving"}
              className="rounded-xl border border-accent/40 bg-accent/10 px-3 py-1.5 text-xs text-accent disabled:opacity-60"
            >
              {state === "saving" ? "Creating..." : "Create finding"}
            </button>
            <button type="button" onClick={onDismiss} className="rounded-xl border border-line bg-abyss/80 px-3 py-1.5 text-xs text-muted">
              Dismiss
            </button>
          </div>
        )}
      </div>
      <p className="mt-2 whitespace-pre-wrap text-muted">{suggestion.description}</p>
      {suggestion.issues.length ? (
        <p className="mt-2 text-xs text-amber-300" data-testid="ai-suggestion-issues">
          Not in its leads, check before accepting: {suggestion.issues.map((issue) => issue.value).join(", ")}
        </p>
      ) : null}
      <ul className="mt-2 space-y-1 text-xs text-muted">
        {suggestion.leads.map((lead) => (
          <li key={lead.ref}>
            <span className="font-mono">[{lead.ref}]</span> {lead.time_utc ? <span className="font-mono">{utc(lead.time_utc)} </span> : null}
            {lead.host ? `${lead.host} · ` : ""}
            {lead.label}
          </li>
        ))}
      </ul>
      {error ? <p className="mt-2 text-xs text-rose-300">{error}</p> : null}
    </li>
  );
}

/**
 * Findings the configured AI proposes from the case's open leads (rule
 * detections, suspicious commands, memory, remote logons). Nothing is created
 * until the analyst accepts a suggestion; its links come from the leads.
 */
export default function AiFindingSuggestions({ caseId }: { caseId: string }) {
  const queryClient = useQueryClient();
  const aiStatusQuery = useQuery({ queryKey: ["ai-status"], queryFn: api.getAiStatus, staleTime: 60_000 });
  const [consentOpen, setConsentOpen] = useState(false);
  const [result, setResult] = useState<Suggestions | null>(null);
  const [states, setStates] = useState<Record<number, "saving" | "accepted" | "dismissed">>({});
  const [errors, setErrors] = useState<Record<number, string>>({});

  const suggest = useMutation({
    mutationFn: () => api.suggestFindingsWithAi(caseId),
    onSuccess: (data) => {
      setResult(data);
      setStates({});
      setErrors({});
      setConsentOpen(false);
    },
  });

  const accept = async (index: number, suggestion: AiFindingSuggestion) => {
    setStates((prev) => ({ ...prev, [index]: "saving" }));
    setErrors((prev) => ({ ...prev, [index]: "" }));
    try {
      await api.createFinding(caseId, suggestion.finding);
      setStates((prev) => ({ ...prev, [index]: "accepted" }));
      void queryClient.invalidateQueries({ queryKey: ["findings", caseId] });
    } catch (error) {
      setStates((prev) => {
        const next = { ...prev };
        delete next[index];
        return next;
      });
      setErrors((prev) => ({ ...prev, [index]: error instanceof Error ? error.message : "Could not create the finding." }));
    }
  };

  const status = aiStatusQuery.data;
  if (!status?.enabled) return null;
  const visible = (result?.suggestions ?? []).map((suggestion, index) => ({ suggestion, index })).filter(({ index }) => states[index] !== "dismissed");
  const leadSummary = result
    ? Object.entries(result.lead_counts).map(([kind, count]) => `${count} ${LEAD_KINDS[kind] ?? kind}`).join(", ")
    : "";

  return (
    <section className="rounded-[28px] border border-line bg-panel/70 p-5 shadow-panel" data-testid="ai-finding-suggestions">
      <div className="flex flex-wrap items-center justify-between gap-3">
        <div>
          <p className="font-mono text-xs uppercase tracking-[0.18em] text-accent">Suggest findings with AI</p>
          <p className="mt-1 max-w-3xl text-sm text-muted">
            Proposes findings from the leads no finding covers yet. Each one is a suggestion: review it, then create it or dismiss it.
          </p>
        </div>
        <button
          type="button"
          onClick={() => setConsentOpen(true)}
          disabled={suggest.isPending}
          className="rounded-2xl border border-accent/40 bg-accent/10 px-4 py-2 text-sm text-accent disabled:opacity-60"
        >
          {suggest.isPending ? "Suggesting..." : result ? "Suggest again" : "Suggest findings"}
        </button>
      </div>

      {consentOpen ? (
        <div role="dialog" aria-label="Suggest findings with AI" className="mt-4 rounded-2xl border border-accent/40 bg-abyss/70 p-4 text-sm text-muted">
          <p>
            The open leads of this case (rule detections, suspicious commands, antivirus detections and marked processes in memory, remote logons) and the
            titles of its findings will be sent to <span className="text-ink">{status.label ?? status.provider}</span>
            {status.model ? ` (${status.model})` : ""}. Nothing is created until you accept a suggestion.
          </p>
          {status.hosting !== "local" ? <p className="mt-2 text-amber-300">This provider is not local: that case material leaves this deployment.</p> : null}
          <div className="mt-3 flex gap-3">
            <button type="button" onClick={() => suggest.mutate()} className="rounded-2xl border border-accent/40 bg-accent/10 px-4 py-2 text-accent">
              Send and suggest
            </button>
            <button type="button" onClick={() => setConsentOpen(false)} className="rounded-2xl border border-line bg-abyss/80 px-4 py-2">
              Cancel
            </button>
          </div>
        </div>
      ) : null}

      {suggest.isPending ? <p className="mt-4 text-sm text-muted">Waiting for the model. A local model can take several minutes.</p> : null}
      {suggest.error instanceof Error ? (
        <p className="mt-4 rounded-2xl border border-rose-400/30 bg-rose-500/10 p-3 text-sm text-rose-200">{suggest.error.message}</p>
      ) : null}

      {result ? (
        <div className="mt-4 space-y-3">
          <p className="text-xs text-muted" data-testid="ai-suggestions-summary">
            {result.suggestions.length} suggestion{result.suggestions.length === 1 ? "" : "s"} from {leadSummary || "no leads"}
            {" · "}
            {result.provenance.provider} ({result.provenance.model})
            {result.dropped ? ` · ${result.dropped} left out: they cited no lead` : ""}
          </p>
          {result.unavailable_sources.length ? (
            <p className="text-xs text-amber-300">Could not read: {result.unavailable_sources.join(", ")}.</p>
          ) : null}
          {visible.length ? (
            <ul className="space-y-3">
              {visible.map(({ suggestion, index }) => (
                <SuggestionCard
                  key={index}
                  suggestion={suggestion}
                  state={states[index] ?? "open"}
                  error={errors[index] || null}
                  onAccept={() => void accept(index, suggestion)}
                  onDismiss={() => setStates((prev) => ({ ...prev, [index]: "dismissed" }))}
                />
              ))}
            </ul>
          ) : (
            <p className="text-sm text-muted">No suggestions left.</p>
          )}
        </div>
      ) : null}
    </section>
  );
}
