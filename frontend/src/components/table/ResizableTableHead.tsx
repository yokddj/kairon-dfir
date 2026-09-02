import ColumnResizeHandle from "./ColumnResizeHandle";
import { useResizableColumns, type ResizableColumn } from "./useResizableColumns";

export type HeadColumn = ResizableColumn & { label: string };

/**
 * A table head whose columns can be dragged wider or narrower.
 *
 * Emits the `<colgroup>` as well as the `<thead>`, because fixed layout only
 * holds content inside a column when every column has an explicit width --
 * which is what stops a long path from spilling into its neighbour.
 */
export default function ResizableTableHead({
  tableId,
  columns,
  className = "bg-abyss/70 text-left text-xs uppercase tracking-[0.14em] text-muted",
}: {
  tableId: string;
  columns: HeadColumn[];
  className?: string;
}) {
  const { widths, startResize, nudge, resizingKey } = useResizableColumns(tableId, columns);

  return (
    <>
      <colgroup>
        {columns.map((column) => (
          <col key={column.key} style={{ width: widths[column.key] }} />
        ))}
      </colgroup>
      <thead className={className}>
        <tr>
          {columns.map((column) => (
            <th key={column.key} className="relative px-4 py-3">
              {column.label}
              <ColumnResizeHandle
                columnKey={column.key}
                label={column.label}
                width={widths[column.key]}
                onStart={startResize}
                onNudge={nudge}
                active={resizingKey === column.key}
              />
            </th>
          ))}
        </tr>
      </thead>
    </>
  );
}
