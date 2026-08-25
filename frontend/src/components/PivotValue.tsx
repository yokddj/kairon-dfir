import { useEffect, useState, type ReactNode } from "react";
import { copyToClipboard } from "../lib/time";

export default function PivotValue({
  label,
  value,
  display,
  className = "",
  onFilter,
  onExclude,
}: {
  label: string;
  value: unknown;
  display?: ReactNode;
  className?: string;
  onFilter?: (value: string) => void;
  onExclude?: (value: string) => void;
}) {
  const [open, setOpen] = useState(false);
  const text = String(value ?? "").trim();
  const isUsable = Boolean(text && text !== "-") && Boolean(onFilter || onExclude);

  useEffect(() => {
    function handleClickOutside() {
      setOpen(false);
    }
    if (!open) return;
    window.addEventListener("click", handleClickOutside);
    return () => window.removeEventListener("click", handleClickOutside);
  }, [open]);

  if (!isUsable) {
    return <span className={className}>{display ?? text ?? "-"}</span>;
  }

  return (
    <span className="relative block min-w-0 align-top" onClick={(event) => event.stopPropagation()}>
      <button
        type="button"
        aria-label={`Pivot ${label}`}
        title={text}
        onClick={(event) => {
          event.stopPropagation();
          setOpen((current) => !current);
        }}
        className={`min-w-0 text-left underline decoration-accent/30 decoration-dotted underline-offset-4 hover:text-accent ${className}`}
      >
        {display ?? text}
      </button>
      {open ? (
        <span className="absolute left-0 z-30 mt-2 block min-w-56 rounded-2xl border border-line bg-abyss/95 p-2 text-xs shadow-2xl" onClick={(event) => event.stopPropagation()}>
          {onFilter ? (
            <button
              type="button"
              aria-label={`Filter by ${label}`}
              onClick={() => {
                setOpen(false);
                onFilter(text);
              }}
              className="block w-full rounded-xl px-3 py-2 text-left text-muted hover:bg-white/5"
            >
              Filter by this
            </button>
          ) : null}
          {onExclude ? (
            <button
              type="button"
              aria-label={`Exclude ${label}`}
              onClick={() => {
                setOpen(false);
                onExclude(text);
              }}
              className="block w-full rounded-xl px-3 py-2 text-left text-warning hover:bg-warning/10"
            >
              Exclude this
            </button>
          ) : null}
          <button
            type="button"
            aria-label={`Copy ${label}`}
            onClick={() => {
              setOpen(false);
              void copyToClipboard(text);
            }}
            className="block w-full rounded-xl px-3 py-2 text-left text-muted hover:bg-white/5"
          >
            Copy value
          </button>
        </span>
      ) : null}
    </span>
  );
}
