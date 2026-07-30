// Pure presentation helpers shared between ProcessDetailModal and
// MemoryProcessEntityPage so both surfaces describe the same
// MemoryProcessEntity/MemoryProcessEntityDetail payload identically instead
// of maintaining two divergent copies of the same logic.
import type { MemoryProcessEntity } from "../api/client";

export function reportedValue(value: unknown): string {
  if (value === null || value === undefined || value === "") return "—";
  return String(value);
}

export function sourcePluginBadge(plugin: string): string {
  return plugin.replace("windows.", "");
}

export function describeProcessVisibility(entity: MemoryProcessEntity | null | undefined): string {
  if (!entity) return "—";
  if (entity.visibility?.terminated) return "Terminated";
  if (entity.visibility?.hidden_candidate) return "Hidden candidate";
  if (entity.visibility?.scan_only) return "Scan only";
  if (entity.visibility?.unknown) return "Unknown";
  return "Listed";
}

export function processVisibilityToneClass(entity: MemoryProcessEntity | null | undefined): string {
  if (!entity) return "border-line bg-abyss/70 text-muted";
  if (entity.visibility?.scan_only || entity.visibility?.hidden_candidate)
    return "border-rose-400/30 bg-rose-500/10 text-rose-100";
  if (entity.visibility?.terminated) return "border-line bg-abyss/70 text-muted";
  if (entity.visibility?.unknown) return "border-amber-400/30 bg-amber-500/10 text-amber-100";
  return "border-sky-400/30 bg-sky-500/10 text-sky-100";
}

// The backend reports identity strength only indirectly: `confidence`
// ("low" | "medium" | "high", derived from which plugins/sources agree) and
// the "identity_provisional" finding (set when visibility.unknown is true,
// i.e. the entity's process_entity_id fell back to a name- or PID-only
// hash instead of the create_time-anchored strong hash). There is no
// separate "strong_identity" / "name_identity" / "weak_identity" field on
// the payload, so this label is derived only from those two real fields --
// never invented beyond what the backend actually distinguishes.
export function describeIdentityStrength(entity: MemoryProcessEntity | null | undefined): string {
  if (!entity) return "—";
  if (entity.findings?.includes("identity_provisional")) return "Provisional (PID/name only, not globally unique)";
  if (entity.confidence === "high") return "Strong (multiple corroborating sources)";
  if (entity.confidence === "medium") return "Moderate (partial corroboration)";
  return "Low (single source, unverified)";
}

// Builds a human-readable "name (PID n)" label for a process entity,
// suitable for breadcrumbs, relationship links and headers alike. Returns
// null when there isn't enough of the payload to label it -- callers must
// never fabricate a placeholder in that case.
export function processEntityLabel(entity: MemoryProcessEntity | null | undefined): string | null {
  if (!entity) return null;
  const name = entity.process?.name;
  const pid = entity.process?.pid;
  if (name && pid != null) return `${name} (PID ${pid})`;
  if (name) return name;
  if (pid != null) return `PID ${pid}`;
  return null;
}
