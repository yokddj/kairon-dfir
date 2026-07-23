import { Link } from "react-router-dom";

/**
 * A visible investigation state, not a wizard: each item reflects backend
 * state Kairon already computes (investigation_state, per-family analysis
 * state, host assignment, etc). This component renders that state -- it
 * never owns or duplicates it.
 */
export type InvestigationChecklistItem = {
  id: string;
  label: string;
  status: "done" | "next" | "locked" | "blocked";
  /** The "why" -- required whenever status is "next" or "blocked". */
  detail?: string;
  action?: { label: string; onClick?: () => void; href?: string };
};

type Props = {
  title?: string;
  items: InvestigationChecklistItem[];
  testId?: string;
};

const MARK: Record<InvestigationChecklistItem["status"], string> = {
  done: "✔",
  next: "▶",
  blocked: "!",
  locked: "○",
};

export function InvestigationChecklist({ title, items, testId }: Props) {
  return (
    <div className="overflow-hidden rounded-2xl border border-line bg-abyss/40" data-testid={testId}>
      {title ? (
        <p className="border-b border-line px-4 py-2.5 font-mono text-[11px] uppercase tracking-[0.16em] text-muted">{title}</p>
      ) : null}
      <div>
        {items.map((item, index) => {
          const isNext = item.status === "next";
          const isBlocked = item.status === "blocked";
          const isLocked = item.status === "locked";
          return (
            <div
              key={item.id}
              data-testid={testId ? `${testId}-item-${item.id}` : undefined}
              data-status={item.status}
              className={`flex items-start gap-3 px-4 py-3 ${index > 0 ? "border-t border-line/60" : ""} ${
                isNext ? "bg-accent/10" : isBlocked ? "bg-danger/10" : ""
              }`}
            >
              <span
                className={`mt-0.5 w-4 shrink-0 text-center font-mono text-sm ${
                  item.status === "done"
                    ? "text-mint"
                    : isNext
                      ? "text-accent"
                      : isBlocked
                        ? "text-danger"
                        : "text-muted"
                }`}
                aria-hidden="true"
              >
                {MARK[item.status]}
              </span>
              <div className="min-w-0 flex-1">
                <p className={`text-sm ${isNext ? "font-semibold text-ink" : isLocked ? "text-muted" : "text-ink"}`}>{item.label}</p>
                {item.detail ? <p className="mt-0.5 text-xs leading-5 text-muted">{item.detail}</p> : null}
              </div>
              {item.action && !isLocked ? (
                item.action.href ? (
                  <Link
                    to={item.action.href}
                    className={`shrink-0 rounded-xl px-3 py-1.5 text-xs font-semibold ${
                      isNext ? "bg-accent text-abyss" : "border border-line bg-panel/40 text-muted"
                    }`}
                  >
                    {item.action.label}
                  </Link>
                ) : (
                  <button
                    type="button"
                    onClick={item.action.onClick}
                    className={`shrink-0 rounded-xl px-3 py-1.5 text-xs font-semibold ${
                      isNext ? "bg-accent text-abyss" : "border border-line bg-panel/40 text-muted"
                    }`}
                  >
                    {item.action.label}
                  </button>
                )
              ) : null}
            </div>
          );
        })}
      </div>
    </div>
  );
}
