export type SortDirection = "asc" | "desc";

export function getNestedValue(record: unknown, path: string): unknown {
  if (!record || typeof record !== "object") return undefined;
  let current: unknown = record;
  for (const segment of path.split(".")) {
    if (!current || typeof current !== "object" || Array.isArray(current)) return undefined;
    current = (current as Record<string, unknown>)[segment];
  }
  return current;
}

function normalizeSortValue(value: unknown): number | string {
  if (typeof value === "number") return value;
  if (value instanceof Date) return value.getTime();
  if (typeof value === "string") {
    const trimmed = value.trim();
    if (!trimmed) return "";
    const asNumber = Number(trimmed);
    if (!Number.isNaN(asNumber) && trimmed === String(asNumber)) return asNumber;
    const asDate = Date.parse(trimmed);
    if (!Number.isNaN(asDate)) return asDate;
    return trimmed.toLocaleLowerCase();
  }
  if (typeof value === "boolean") return value ? 1 : 0;
  if (value == null) return "";
  return String(value).toLocaleLowerCase();
}

export function compareValues(left: unknown, right: unknown, direction: SortDirection): number {
  const normalizedLeft = normalizeSortValue(left);
  const normalizedRight = normalizeSortValue(right);

  const leftEmpty = normalizedLeft === "";
  const rightEmpty = normalizedRight === "";
  if (leftEmpty && rightEmpty) return 0;
  if (leftEmpty) return 1;
  if (rightEmpty) return -1;

  const base =
    typeof normalizedLeft === "number" && typeof normalizedRight === "number"
      ? normalizedLeft - normalizedRight
      : String(normalizedLeft).localeCompare(String(normalizedRight), undefined, { numeric: true, sensitivity: "base" });

  return direction === "asc" ? base : -base;
}

export function nextSortDirection(currentKey: string | null, currentDirection: SortDirection, nextKey: string) {
  if (currentKey === nextKey) return currentDirection === "asc" ? "desc" : "asc";
  return "asc";
}
