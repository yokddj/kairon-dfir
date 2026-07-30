// Shared "snake_case-ish id -> Title Case label" formatter. Used by Domain
// Tabs (WorkbenchOverview) and by the investigation breadcrumb resolver so
// a domain id renders identically in both places -- one formatter, not a
// duplicated copy per consumer.
export function displayLabel(value: string): string {
  return value.replace(/_/g, " ").replace(/\b\w/g, (letter) => letter.toUpperCase());
}
