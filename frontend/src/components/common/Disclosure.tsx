import { useState, type ReactNode } from "react";

/**
 * Reusable progressive-disclosure panel. One pattern, reused for every
 * "Technical details / Diagnostics / Metadata / Advanced" section in the
 * product so an analyst learns it once. Collapsed by default -- nothing it
 * wraps is removed, only deferred a click.
 */
type Props = {
  label: string;
  defaultOpen?: boolean;
  /** Optional inline hint shown next to the label while collapsed, e.g. "3 warnings". */
  summary?: ReactNode;
  children: ReactNode;
  testId?: string;
};

export function Disclosure({ label, defaultOpen = false, summary, children, testId }: Props) {
  const [open, setOpen] = useState(defaultOpen);
  return (
    <div className="rounded-2xl border border-line bg-abyss/40" data-testid={testId} data-open={open}>
      <button
        type="button"
        onClick={() => setOpen((value) => !value)}
        className="flex w-full items-center justify-between gap-3 px-4 py-3 text-left"
        aria-expanded={open}
      >
        <span className="flex items-center gap-2 font-mono text-[11px] uppercase tracking-[0.16em] text-muted">
          <span className={`inline-block transition-transform duration-150 ${open ? "rotate-90" : ""}`} aria-hidden="true">
            &#9656;
          </span>
          {label}
        </span>
        {!open && summary ? <span className="text-xs text-muted">{summary}</span> : null}
      </button>
      {open ? <div className="border-t border-line px-4 py-4">{children}</div> : null}
    </div>
  );
}
