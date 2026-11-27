import { useEffect, useRef, useState } from "react";
import { Link } from "react-router-dom";

export type MenuItem =
  | { kind: "button"; label: string; onSelect: () => void; disabled?: boolean; danger?: boolean }
  | { kind: "link"; label: string; to: string };

/** The "⋯" menu holding the page's secondary actions. */
export default function ActionsMenu({ items }: { items: MenuItem[] }) {
  const [open, setOpen] = useState(false);
  const ref = useRef<HTMLDivElement | null>(null);

  useEffect(() => {
    if (!open) return;
    function close(event: MouseEvent | KeyboardEvent) {
      if (event instanceof KeyboardEvent ? event.key === "Escape" : !ref.current?.contains(event.target as Node)) setOpen(false);
    }
    document.addEventListener("mousedown", close);
    document.addEventListener("keydown", close);
    return () => {
      document.removeEventListener("mousedown", close);
      document.removeEventListener("keydown", close);
    };
  }, [open]);

  const itemClass = "block w-full px-4 py-2 text-left text-sm hover:bg-abyss/70 disabled:opacity-40";
  return (
    <div className="relative" ref={ref}>
      <button type="button" aria-label="More actions" aria-haspopup="menu" aria-expanded={open} onClick={() => setOpen((value) => !value)} className="rounded-xl border border-line px-3 py-2 text-sm text-muted hover:text-ink">
        ⋯
      </button>
      {open ? (
        <div role="menu" className="absolute right-0 top-full z-30 mt-2 w-56 overflow-hidden rounded-2xl border border-line bg-panel py-1 shadow-panel">
          {items.map((item) =>
            item.kind === "link" ? (
              <Link key={item.label} role="menuitem" to={item.to} className={`${itemClass} text-ink`} onClick={() => setOpen(false)}>
                {item.label}
              </Link>
            ) : (
              <button
                key={item.label}
                type="button"
                role="menuitem"
                disabled={item.disabled}
                onClick={() => {
                  setOpen(false);
                  item.onSelect();
                }}
                className={`${itemClass} ${item.danger ? "text-danger" : "text-ink"}`}
              >
                {item.label}
              </button>
            ),
          )}
        </div>
      ) : null}
    </div>
  );
}
