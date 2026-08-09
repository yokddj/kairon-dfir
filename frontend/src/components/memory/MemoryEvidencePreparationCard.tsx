import { useQuery } from "@tanstack/react-query";
import { api, type MemoryEvidencePreparation, type MemoryPreparationReadiness } from "../../api/client";

// Read-only Memory Evidence Preparation view (Phase 2). Backed entirely by
// GET /cases/{caseId}/memory/evidences/{evidenceId}/preparation, which is a
// pure passthrough to app.services.memory.preparation.get_preparation_status
// (Phase 1) -- no state, readiness, or symbol logic is computed here, only
// display formatting.
//
// DELIBERATELY distinct from MemoryPreparationCard.tsx in this same
// directory: that component drives the async MemorySymbolPreparation
// pipeline (retry / cancel / progress bar / native-probe actions). This
// component has no actions at all -- see the module docstring on the
// backend's app/services/memory/preparation/models.py for the full
// distinction between the two "preparation" concepts.

type Tone = "good" | "warn" | "bad" | "neutral";

const READINESS_COPY: Record<MemoryPreparationReadiness, { label: string; statusText: string; tone: Tone }> = {
  ready: { label: "Ready", statusText: "✓ Ready for analysis", tone: "good" },
  symbols_required: {
    label: "Symbols required",
    statusText: "⚠ Additional resources are required before analysis can begin.",
    tone: "warn",
  },
  awaiting_user: { label: "Awaiting confirmation", statusText: "User confirmation required.", tone: "warn" },
  blocked: { label: "Blocked", statusText: "Preparation cannot continue.", tone: "bad" },
  failed: { label: "Failed", statusText: "Preparation failed.", tone: "bad" },
  inspecting: { label: "Inspecting", statusText: "Inspecting memory...", tone: "neutral" },
};

const TONE_BORDER: Record<Tone, string> = {
  good: "border-mint/30 bg-mint/10",
  warn: "border-amber/30 bg-amber/10",
  bad: "border-danger/30 bg-danger/10",
  neutral: "border-line bg-abyss/60",
};

const TONE_TEXT: Record<Tone, string> = {
  good: "text-mint",
  warn: "text-amber",
  bad: "text-danger",
  neutral: "text-ink",
};

function formatEnumValue(value: string): string {
  return value
    .split("_")
    .map((part) => (part ? part[0].toUpperCase() + part.slice(1) : part))
    .join(" ");
}

type Props = {
  caseId: string;
  evidenceId: string;
};

export function MemoryEvidencePreparationCard({ caseId, evidenceId }: Props) {
  const query = useQuery({
    queryKey: ["memory-evidence-preparation", caseId, evidenceId],
    queryFn: () => api.getMemoryEvidencePreparation(caseId, evidenceId),
    enabled: Boolean(caseId && evidenceId),
    refetchOnWindowFocus: false,
  });

  const preparation: MemoryEvidencePreparation | undefined = query.data;

  if (query.isLoading) {
    return (
      <section
        className={`mt-4 rounded-2xl border p-4 ${TONE_BORDER.neutral}`}
        data-testid="memory-evidence-preparation-card"
        data-ui-state="loading"
      >
        <p className="font-mono text-[11px] uppercase tracking-[0.16em] text-accent">Memory Preparation</p>
        <p className="mt-2 text-sm text-ink">Inspecting memory...</p>
      </section>
    );
  }

  if (query.isError || !preparation) {
    return (
      <section
        className={`mt-4 rounded-2xl border p-4 ${TONE_BORDER.neutral}`}
        data-testid="memory-evidence-preparation-card"
        data-ui-state="unavailable"
      >
        <p className="font-mono text-[11px] uppercase tracking-[0.16em] text-accent">Memory Preparation</p>
        <p className="mt-2 text-sm text-muted">Preparation status is not available right now.</p>
      </section>
    );
  }

  const copy = READINESS_COPY[preparation.readiness];

  return (
    <section
      className={`mt-4 rounded-2xl border p-4 ${TONE_BORDER[copy.tone]}`}
      data-testid="memory-evidence-preparation-card"
      data-ui-state={preparation.readiness}
    >
      <p className="font-mono text-[11px] uppercase tracking-[0.16em] text-accent">Memory Preparation</p>
      <p className={`mt-2 text-sm font-semibold ${TONE_TEXT[copy.tone]}`} data-testid="memory-evidence-preparation-status">
        {copy.statusText}
      </p>
      <div className="mt-3 grid gap-2 text-sm text-muted sm:grid-cols-2">
        <p>
          Platform: <span className="text-ink">{formatEnumValue(preparation.platform)}</span>
        </p>
        <p>
          Architecture: <span className="text-ink">{formatEnumValue(preparation.architecture)}</span>
        </p>
        <p>
          Preparation status: <span className="text-ink">{copy.label}</span>
        </p>
        <p>
          Analysis readiness:{" "}
          <span className="text-ink">{preparation.can_start_analysis ? "Ready to analyze" : "Not ready yet"}</span>
        </p>
        <p>
          Symbols required: <span className="text-ink">{preparation.requires_symbols ? "Yes" : "No"}</span>
        </p>
      </div>
      {preparation.human_message ? (
        <p className="mt-3 text-xs text-muted" data-testid="memory-evidence-preparation-message">
          {preparation.human_message}
        </p>
      ) : null}
    </section>
  );
}
