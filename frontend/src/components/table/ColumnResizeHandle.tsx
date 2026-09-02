import { MIN_COLUMN_WIDTH } from "./useResizableColumns";

const KEYBOARD_STEP = 24;

/**
 * The grip on a column border. Rendered inside the header cell, which must be
 * positioned, so it can sit on the boundary without affecting layout.
 */
export default function ColumnResizeHandle({
  columnKey,
  label,
  width,
  onStart,
  onNudge,
  active,
}: {
  columnKey: string;
  label: string;
  width: number;
  onStart: (key: string, clientX: number) => void;
  onNudge: (key: string, delta: number) => void;
  active: boolean;
}) {
  return (
    <div
      role="separator"
      aria-orientation="vertical"
      aria-label={`Resize column ${label}`}
      aria-valuenow={width}
      aria-valuemin={MIN_COLUMN_WIDTH}
      tabIndex={0}
      onMouseDown={(event) => {
        // Headers sort on click; resizing must not also sort.
        event.preventDefault();
        event.stopPropagation();
        onStart(columnKey, event.clientX);
      }}
      onKeyDown={(event) => {
        if (event.key === "ArrowRight") {
          event.preventDefault();
          onNudge(columnKey, KEYBOARD_STEP);
        } else if (event.key === "ArrowLeft") {
          event.preventDefault();
          onNudge(columnKey, -KEYBOARD_STEP);
        }
      }}
      className={`absolute right-0 top-0 h-full w-2 cursor-col-resize select-none touch-none after:absolute after:right-[3px] after:top-1/4 after:h-1/2 after:w-px after:bg-line hover:after:bg-accent focus:outline-none focus-visible:after:bg-accent ${
        active ? "after:bg-accent" : ""
      }`}
    />
  );
}
