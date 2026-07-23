export type Stage = { id: string; label: string; status: "done" | "current" | "upcoming" };

/**
 * A compact, reusable stage-progress rail: Upload -> Prepare -> Analyze ->
 * Investigate -> Report. Renders whatever stage list it's given -- the
 * mapping from backend state to stage status lives with the caller, this
 * component only draws it.
 */
export function StageProgress({ stages, testId }: { stages: Stage[]; testId?: string }) {
  return (
    <ol className="flex flex-wrap items-center gap-x-1 gap-y-2" data-testid={testId}>
      {stages.map((stage, index) => (
        <li key={stage.id} className="flex items-center">
          {index > 0 ? <span className="mx-1.5 h-px w-6 bg-line" aria-hidden="true" /> : null}
          <span
            data-status={stage.status}
            className={`flex items-center gap-1.5 rounded-full border px-3 py-1 font-mono text-[11px] uppercase tracking-[0.1em] ${
              stage.status === "done"
                ? "border-mint/30 bg-mint/10 text-mint"
                : stage.status === "current"
                  ? "border-accent/50 bg-accent/15 text-accent"
                  : "border-line bg-transparent text-muted"
            }`}
          >
            {stage.status === "done" ? "✔" : stage.status === "current" ? "●" : "○"} {stage.label}
          </span>
        </li>
      ))}
    </ol>
  );
}
