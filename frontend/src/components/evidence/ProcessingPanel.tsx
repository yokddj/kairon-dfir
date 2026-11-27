import { StageProgress, type Stage } from "../common/StageProgress";
import { formatDateTime, formatDuration } from "../../lib/evidenceDetailFormatting";
import { PROCESSING_STEPS, type LiveProgress } from "../../lib/evidenceStatus";

/**
 * The one progress block of the page: four real steps, a bar (indeterminate
 * when the total is unknown) and only the counters the current run reported.
 */
export default function ProcessingPanel({
  progress,
  stalled,
  heartbeatAt,
  onPause,
  onCancelStalled,
  busy,
}: {
  progress: LiveProgress;
  stalled: boolean;
  heartbeatAt: string | null;
  onPause: () => void;
  onCancelStalled: () => void;
  busy: boolean;
}) {
  const currentIndex = PROCESSING_STEPS.findIndex((step) => step.id === progress.step);
  const stages: Stage[] = PROCESSING_STEPS.map((step, index) => ({
    id: step.id,
    label: step.label,
    status: index < currentIndex ? "done" : index === currentIndex ? "current" : "upcoming",
  }));
  const facts = [
    progress.artifactsDone !== null ? `${progress.artifactsDone.toLocaleString()}${progress.artifactsTotal ? ` / ${progress.artifactsTotal.toLocaleString()}` : ""} artifacts` : null,
    progress.recordsIndexed ? `${progress.recordsIndexed.toLocaleString()} records indexed` : null,
    progress.elapsedSeconds !== null ? `${formatDuration(progress.elapsedSeconds)} elapsed` : null,
  ].filter(Boolean);

  return (
    <section className="rounded-3xl border border-line bg-panel/70 p-5" data-testid="evidence-processing">
      <div className="flex flex-wrap items-center justify-between gap-3">
        <div className="flex items-baseline gap-3">
          <h3 className="text-lg font-semibold text-ink">{stalled ? "Stalled" : progress.title}</h3>
          {progress.percent !== null && !stalled ? <span className="text-lg font-semibold text-accent">{progress.percent}%</span> : null}
        </div>
        {stalled ? (
          <button type="button" onClick={onCancelStalled} disabled={busy} className="rounded-xl border border-warning/50 bg-warning/15 px-3 py-1.5 text-sm font-semibold text-warning disabled:opacity-50">
            Cancel stalled run
          </button>
        ) : (
          <button type="button" onClick={onPause} disabled={busy} className="rounded-xl border border-line px-3 py-1.5 text-sm text-muted hover:text-ink disabled:opacity-50">
            Pause
          </button>
        )}
      </div>
      <div className="mt-4">
        <StageProgress stages={stages} testId="evidence-processing-steps" />
      </div>
      <div className="mt-4 h-2 overflow-hidden rounded-full bg-abyss/80">
        {progress.percent === null || stalled ? (
          <div className={`h-full w-full rounded-full ${stalled ? "bg-warning/40" : "animate-pulse bg-accent/40"}`} data-testid="evidence-progress-indeterminate" />
        ) : (
          <div className="h-full rounded-full bg-accent transition-all duration-500" style={{ width: `${progress.percent}%` }} />
        )}
      </div>
      {stalled ? (
        <p className="mt-3 text-sm text-ink">No worker activity since {formatDateTime(heartbeatAt)}. Cancel it, then re-index.</p>
      ) : (
        <>
          {facts.length ? <p className="mt-3 text-sm text-muted">{facts.join(" · ")}</p> : null}
          {progress.currentItem ? (
            <p className="mt-1 truncate font-mono text-xs text-muted" title={progress.currentItem}>
              {progress.currentItem}
            </p>
          ) : null}
        </>
      )}
    </section>
  );
}
