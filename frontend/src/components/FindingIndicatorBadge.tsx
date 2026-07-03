import { type FindingIndicatorSummary } from "../api/client";
import FindingIndicatorPopover from "./FindingIndicatorPopover";

function severityTone(severity: string | null | undefined) {
  if (severity === "critical") return "border-rose-500/50 bg-rose-500/15 text-rose-200";
  if (severity === "high") return "border-rose-400/40 bg-rose-400/10 text-rose-200";
  if (severity === "medium") return "border-amber-400/40 bg-amber-400/10 text-amber-200";
  if (severity === "low") return "border-emerald-400/40 bg-emerald-400/10 text-emerald-200";
  return "border-line bg-white/5 text-muted";
}

export default function FindingIndicatorBadge({
  indicator,
  caseId,
  compact = false,
  testId,
}: {
  indicator: FindingIndicatorSummary | null;
  caseId: string;
  compact?: boolean;
  testId?: string;
}) {
  if (!indicator || indicator.visible === 0) return null;

  const count = indicator.confirmed || indicator.visible;
  const tone = indicator.confirmed > 0
    ? severityTone(indicator.highest_severity)
    : "border-sky-400/30 bg-sky-400/5 text-sky-200";

  const badge = (
    <span
      data-testid={testId || "finding-indicator-badge"}
      className={"inline-flex items-center gap-1 rounded-full border px-2 py-0.5 font-mono text-[10px] font-semibold tracking-wide cursor-default " + tone}
    >
      <span>{count}</span>
    </span>
  );

  if (compact) return badge;
  return <FindingIndicatorPopover indicator={indicator} caseId={caseId} testId={testId}>{badge}</FindingIndicatorPopover>;
}
