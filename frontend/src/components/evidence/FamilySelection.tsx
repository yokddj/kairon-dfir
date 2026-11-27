import { useMemo, useState } from "react";

import type { VelociraptorCandidate } from "../../api/client";

export type FamilyOption = { id: string; label: string; candidateIds: string[] };

/** Families the discovery actually found, with how many parseable files each has. */
export function familiesFromCandidates(candidates: VelociraptorCandidate[], labels: Record<string, string>): FamilyOption[] {
  const byCategory = new Map<string, string[]>();
  for (const candidate of candidates) {
    if (!candidate.supported) continue;
    const key = candidate.category || "other";
    byCategory.set(key, [...(byCategory.get(key) ?? []), candidate.id]);
  }
  return [...byCategory.entries()]
    .map(([id, candidateIds]) => ({ id, label: labels[id] ?? id.replaceAll("_", " "), candidateIds }))
    .sort((left, right) => left.label.localeCompare(right.label));
}

/**
 * Shown only while a collection waits for a decision: index everything
 * recommended, or tick the families to index.
 */
export default function FamilySelection({
  families,
  onRecommended,
  onSelected,
  busy,
}: {
  families: FamilyOption[];
  onRecommended: () => void;
  onSelected: (candidateIds: string[]) => void;
  busy: boolean;
}) {
  const [picked, setPicked] = useState<string[]>([]);
  const selectedIds = useMemo(() => families.filter((family) => picked.includes(family.id)).flatMap((family) => family.candidateIds), [families, picked]);

  return (
    <section className="rounded-3xl border border-accent/30 bg-panel/70 p-5" data-testid="evidence-family-selection">
      <h3 className="text-lg font-semibold text-ink">Choose what to index</h3>
      <p className="mt-1 text-sm text-muted">The collection was scanned. Index everything that is supported, or only some families.</p>
      <button type="button" onClick={onRecommended} disabled={busy} className="mt-4 rounded-xl bg-accent px-4 py-2 text-sm font-semibold text-abyss disabled:opacity-50">
        Index all supported
      </button>
      {families.length ? (
        <div className="mt-5 border-t border-line pt-4">
          <p className="text-sm text-muted">Or only these:</p>
          <div className="mt-3 flex flex-wrap gap-2">
            {families.map((family) => {
              const checked = picked.includes(family.id);
              return (
                <label key={family.id} className={`flex cursor-pointer items-center gap-2 rounded-full border px-3 py-1.5 text-sm ${checked ? "border-accent/50 bg-accent/10 text-ink" : "border-line text-muted"}`}>
                  <input
                    type="checkbox"
                    checked={checked}
                    onChange={() => setPicked((current) => (checked ? current.filter((id) => id !== family.id) : [...current, family.id]))}
                    className="accent-current"
                  />
                  {family.label}
                  <span className="text-xs text-muted">{family.candidateIds.length}</span>
                </label>
              );
            })}
          </div>
          <button
            type="button"
            onClick={() => onSelected(selectedIds)}
            disabled={busy || !selectedIds.length}
            className="mt-4 rounded-xl border border-accent/40 bg-accent/10 px-4 py-2 text-sm font-semibold text-accent disabled:opacity-40"
          >
            Index selected{selectedIds.length ? ` (${selectedIds.length} files)` : ""}
          </button>
        </div>
      ) : null}
    </section>
  );
}
