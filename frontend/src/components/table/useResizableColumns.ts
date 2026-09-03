import { useCallback, useEffect, useMemo, useRef, useState } from "react";

/**
 * Column widths for a table, resizable by dragging and remembered per browser.
 *
 * Tables here were laid out automatically, which lets the browser size columns
 * from their content: a long command line widens its column until neighbouring
 * text is pushed over, and `max-width` on a cell is only a hint the algorithm
 * may ignore. Fixed layout plus explicit widths is what actually keeps a value
 * inside its own column -- and once widths are explicit, the analyst needs to
 * be able to change them, because which column deserves the room depends on
 * what they are reading.
 */

export const MIN_COLUMN_WIDTH = 72;
export const DEFAULT_COLUMN_WIDTH = 200;

export type ColumnWidths = Record<string, number>;

function storageKey(tableId: string) {
  return `kairon.columnWidths.${tableId}`;
}

function readStored(tableId: string): ColumnWidths {
  try {
    const raw = localStorage.getItem(storageKey(tableId));
    if (!raw) return {};
    const parsed = JSON.parse(raw) as unknown;
    if (!parsed || typeof parsed !== "object") return {};
    const widths: ColumnWidths = {};
    for (const [key, value] of Object.entries(parsed as Record<string, unknown>)) {
      const width = Number(value);
      if (Number.isFinite(width) && width >= MIN_COLUMN_WIDTH) widths[key] = width;
    }
    return widths;
  } catch {
    // Private windows and blocked storage are fine; defaults apply.
    return {};
  }
}

function writeStored(tableId: string, widths: ColumnWidths) {
  try {
    localStorage.setItem(storageKey(tableId), JSON.stringify(widths));
  } catch {
    // Not remembering a width is not worth failing over.
  }
}

export type ResizableColumn = { key: string; defaultWidth?: number };

export function useResizableColumns(tableId: string, columns: ResizableColumn[]) {
  const [overrides, setOverrides] = useState<ColumnWidths>(() => readStored(tableId));
  const dragRef = useRef<{ key: string; startX: number; startWidth: number } | null>(null);
  const [resizingKey, setResizingKey] = useState<string | null>(null);

  // A different table (or a different column set) starts from its own memory.
  useEffect(() => {
    setOverrides(readStored(tableId));
  }, [tableId]);

  const widths = useMemo(() => {
    const resolved: ColumnWidths = {};
    for (const column of columns) {
      resolved[column.key] =
        overrides[column.key] ?? column.defaultWidth ?? DEFAULT_COLUMN_WIDTH;
    }
    return resolved;
  }, [columns, overrides]);

  const applyWidth = useCallback(
    (key: string, width: number) => {
      const clamped = Math.max(MIN_COLUMN_WIDTH, Math.round(width));
      setOverrides((current) => {
        const next = { ...current, [key]: clamped };
        writeStored(tableId, next);
        return next;
      });
    },
    [tableId],
  );

  const startResize = useCallback(
    (key: string, clientX: number) => {
      dragRef.current = { key, startX: clientX, startWidth: widths[key] ?? DEFAULT_COLUMN_WIDTH };
      setResizingKey(key);
    },
    [widths],
  );

  useEffect(() => {
    if (!resizingKey) return undefined;

    const onMove = (event: MouseEvent) => {
      const drag = dragRef.current;
      if (!drag) return;
      applyWidth(drag.key, drag.startWidth + (event.clientX - drag.startX));
    };
    const onUp = () => {
      dragRef.current = null;
      setResizingKey(null);
    };

    window.addEventListener("mousemove", onMove);
    window.addEventListener("mouseup", onUp);
    return () => {
      window.removeEventListener("mousemove", onMove);
      window.removeEventListener("mouseup", onUp);
    };
  }, [applyWidth, resizingKey]);

  /** Keyboard resizing, so the feature is not mouse-only. */
  const nudge = useCallback(
    (key: string, delta: number) => applyWidth(key, (widths[key] ?? DEFAULT_COLUMN_WIDTH) + delta),
    [applyWidth, widths],
  );

  const reset = useCallback(() => {
    setOverrides({});
    writeStored(tableId, {});
  }, [tableId]);

  const isCustomised = useMemo(() => Object.keys(overrides).length > 0, [overrides]);

  return { widths, startResize, nudge, reset, resizingKey, isCustomised };
}
