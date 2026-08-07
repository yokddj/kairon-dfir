import type { ReactNode } from "react";

type EmptyStateProps = {
  /** Short statement of what's missing, e.g. "No findings yet." */
  title: string;
  /** Explains what this view means and why it can be empty. */
  description: ReactNode;
  /** Buttons/links telling the analyst what to do next. */
  action?: ReactNode;
  testId?: string;
  className?: string;
};

/**
 * Shared empty-state block for list/table surfaces. Keeps the visual
 * language already used across the app (rounded panel, muted body text,
 * white semibold title) so every "no data" screen reads the same way:
 * what this is, why it can be empty, and what to do about it.
 */
export default function EmptyState({ title, description, action, testId, className }: EmptyStateProps) {
  return (
    <div className={`rounded-3xl border border-line bg-panel/40 p-6 text-sm text-muted ${className ?? ""}`} data-testid={testId}>
      <p className="text-base font-semibold text-white">{title}</p>
      <p className="mt-2">{description}</p>
      {action ? <div className="mt-4 flex flex-wrap gap-2">{action}</div> : null}
    </div>
  );
}
