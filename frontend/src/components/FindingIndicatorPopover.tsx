import { type ReactNode, useState } from "react";
import { Link } from "react-router-dom";
import { type FindingIndicatorSummary } from "../api/client";

function statusLabel(status: string): string {
  return status.charAt(0).toUpperCase() + status.slice(1).replace(/_/g, " ");
}

export default function FindingIndicatorPopover({
  indicator,
  caseId,
  children,
  testId,
}: {
  indicator: FindingIndicatorSummary;
  caseId: string;
  children: ReactNode;
  testId?: string;
}) {
  const [open, setOpen] = useState(false);
  const suppressText = indicator.suppressed_count > 0 ? " \u00b7 " + indicator.suppressed_count + " suppressed" : "";

  return (
    <span className="relative inline-flex" data-testid={testId || "finding-indicator-popover"}>
      <button type="button" className="cursor-pointer" onClick={() => setOpen(!open)} onBlur={() => setTimeout(() => setOpen(false), 150)}>
        {children}
      </button>
      {open && (
        <div className="absolute left-0 top-full z-50 mt-1 w-72 rounded-xl border border-line bg-panel shadow-xl" onMouseDown={(e) => e.preventDefault()}>
          <div className="p-3 space-y-2 text-xs">
            <div className="flex items-center justify-between">
              <p className="font-semibold text-ink">Findings ({indicator.total})</p>
              <span className="text-[10px] text-muted">{indicator.active} active{suppressText}</span>
            </div>
            {Object.entries(indicator.statuses).length > 0 && (
              <div className="flex flex-wrap gap-1">
                {Object.entries(indicator.statuses).map(([status, count]) => (
                  <span key={status} className="rounded-md border border-line bg-abyss/60 px-1.5 py-0.5 text-[10px] text-muted">
                    {statusLabel(status)}: {count}
                  </span>
                ))}
              </div>
            )}
            <div className="flex items-center gap-2 text-muted">
              {indicator.highest_severity && <span className="rounded border border-line px-1 py-0.5 text-[10px]">Sev: {indicator.highest_severity}</span>}
              {indicator.highest_confidence && <span className="rounded border border-line px-1 py-0.5 text-[10px]">Conf: {indicator.highest_confidence}</span>}
            </div>
            <Link to={`/cases/${caseId}/findings`} className="block rounded-lg border border-accent/40 bg-accent/10 px-2 py-1 text-center text-[10px] text-accent">
              Open Findings
            </Link>
          </div>
        </div>
      )}
    </span>
  );
}
