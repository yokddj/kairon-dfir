import type { TextMatchMode } from "../api/client";

export const TEXT_MATCH_MODE_HELP: Record<TextMatchMode, string> = {
  smart: "Smart: words in any order; detects hashes, IPs, paths and commands; a bare stem also matches inside longer values (comsvcs → comsvcs.dll).",
  contains: "Contains: the whole text as a case-insensitive substring.",
  exact: "Exact: the whole text as an exact phrase, or an exact hash / IP / SID / GUID.",
};

export function parseTextMatchMode(value: string | null | undefined): TextMatchMode {
  return value === "contains" || value === "exact" ? value : "smart";
}

/**
 * Text match mode selector shared by Search, Timeline, Artifact Views and
 * Command History, backed by one engine on the server.
 */
export default function TextMatchModeSelect({ value, onChange, compact = false }: { value: TextMatchMode; onChange: (mode: TextMatchMode) => void; compact?: boolean }) {
  return (
    <label className="block" title={TEXT_MATCH_MODE_HELP[value]}>
      <span className="mb-2 block font-mono text-[11px] uppercase tracking-[0.16em] text-muted">Match</span>
      <select
        aria-label="Text match mode"
        value={value}
        onChange={(event) => onChange(parseTextMatchMode(event.target.value))}
        className={`w-full rounded-2xl border border-line bg-abyss/80 text-sm outline-none focus:border-accent/50 ${compact ? "px-3 py-2" : "px-4 py-3"}`}
      >
        <option value="smart">Smart</option>
        <option value="contains">Contains</option>
        <option value="exact">Exact</option>
      </select>
    </label>
  );
}
