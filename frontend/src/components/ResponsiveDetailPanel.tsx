import { useEffect, useState, type ReactNode } from "react";

export function useMinWidthQuery(minWidthPx: number) {
  const [matches, setMatches] = useState(() => {
    if (typeof window === "undefined" || typeof window.matchMedia !== "function") {
      return false;
    }
    return window.matchMedia(`(min-width: ${minWidthPx}px)`).matches;
  });

  useEffect(() => {
    if (typeof window === "undefined" || typeof window.matchMedia !== "function") return;
    const query = window.matchMedia(`(min-width: ${minWidthPx}px)`);
    const update = () => setMatches(query.matches);
    update();
    query.addEventListener("change", update);
    return () => query.removeEventListener("change", update);
  }, [minWidthPx]);

  return matches;
}

type Props = {
  open: boolean;
  onClose: () => void;
  heading: string;
  subheading?: string;
  children: ReactNode;
  actions?: ReactNode;
  mode?: "sidebar" | "stacked" | "drawer";
  widthClass?: string;
  testId?: string;
  overlayTestId?: string;
  contentClassName?: string;
};

export default function ResponsiveDetailPanel({
  open,
  onClose,
  heading,
  subheading,
  children,
  actions,
  mode = "drawer",
  widthClass = "",
  testId = "responsive-detail-panel",
  overlayTestId = "responsive-detail-overlay",
  contentClassName = "",
}: Props) {
  useEffect(() => {
    if (!open) return;
    function handleKeyDown(event: KeyboardEvent) {
      if (event.key === "Escape") onClose();
    }
    window.addEventListener("keydown", handleKeyDown);
    return () => window.removeEventListener("keydown", handleKeyDown);
  }, [onClose, open]);

  useEffect(() => {
    if (!open) return;
    const body = document.body;
    const previousOverflow = body.style.overflow;
    const previousOverscroll = body.style.overscrollBehavior;
    body.style.overflow = "hidden";
    body.style.overscrollBehavior = "contain";
    return () => {
      body.style.overflow = previousOverflow;
      body.style.overscrollBehavior = previousOverscroll;
    };
  }, [mode, open]);

  if (!open) return null;

  const shell = (
    <div
      data-testid={testId}
      className={`flex min-h-0 min-w-0 flex-col overflow-hidden rounded-[28px] border border-line bg-panel/95 shadow-panel backdrop-blur ${contentClassName}`.trim()}
    >
      <div className="sticky top-0 z-10 flex flex-wrap items-start justify-between gap-3 border-b border-line bg-panel/95 px-5 py-4 backdrop-blur">
        <div className="min-w-0 flex-1">
          <p className="font-mono text-[11px] uppercase tracking-[0.16em] text-accent">{heading}</p>
          {subheading ? <p className="mt-2 text-sm text-muted">{subheading}</p> : null}
        </div>
        <div className="flex flex-wrap items-center gap-2">
          {actions}
          <button type="button" aria-label="Close detail panel" onClick={onClose} className="rounded-xl border border-line px-3 py-2 text-xs text-muted">
            Close
          </button>
        </div>
      </div>
      <div data-testid={`${testId}-content`} className="min-h-0 min-w-0 flex-1 overflow-y-auto px-5 py-4">{children}</div>
    </div>
  );

  const resolvedWidthClass =
    widthClass || (mode === "drawer" ? "h-full w-full sm:w-[88vw] xl:w-[78vw]" : "w-full max-w-6xl");
  const frameClass =
    mode === "drawer"
      ? `h-full max-h-screen max-w-full min-h-0 ${resolvedWidthClass}`
      : `w-full max-w-full min-h-0 ${resolvedWidthClass}`;

  return (
    <div
      data-testid={overlayTestId}
      className={`fixed inset-0 z-40 flex overflow-hidden bg-abyss/55 backdrop-blur-sm ${mode === "drawer" ? "justify-end p-0" : "items-center justify-center p-4 md:p-6"}`}
      onClick={onClose}
    >
      <div className={frameClass} onClick={(event) => event.stopPropagation()}>
        <div className={`flex min-h-0 flex-col ${mode === "drawer" ? "h-full" : "max-h-[90vh]"}`}>{shell}</div>
      </div>
    </div>
  );
}
