import { useMemo, useState } from "react";

type Option = {
  value: string;
  label?: string;
  count?: number;
};

type Props = {
  label: string;
  value: string;
  options: Option[];
  placeholder?: string;
  onChange: (value: string) => void;
};

export default function SearchableFacetSelect({ label, value, options, placeholder = "All", onChange }: Props) {
  const [search, setSearch] = useState("");
  const filtered = useMemo(() => {
    const normalized = search.trim().toLowerCase();
    if (!normalized) return options;
    return options.filter((option) => `${option.label ?? option.value} ${option.value}`.toLowerCase().includes(normalized));
  }, [options, search]);

  return (
    <div className="rounded-2xl border border-line bg-abyss/80 p-3">
      <label className="block">
        <span className="mb-2 block font-mono text-[11px] uppercase tracking-[0.16em] text-muted">{label}</span>
        <input
          value={search}
          onChange={(event) => setSearch(event.target.value)}
          placeholder={`Search ${label.toLowerCase()} options`}
          className="mb-2 w-full rounded-xl border border-line bg-panel/70 px-3 py-2 text-sm outline-none focus:border-accent/50"
        />
      </label>
      <select
        value={value}
        onChange={(event) => onChange(event.target.value)}
        className="w-full rounded-xl border border-line bg-panel/70 px-3 py-2 text-sm outline-none focus:border-accent/50"
      >
        <option value="">{placeholder}</option>
        {filtered.map((option) => (
          <option key={option.value} value={option.value}>
            {option.label ?? option.value}
            {typeof option.count === "number" ? ` (${option.count})` : ""}
          </option>
        ))}
      </select>
      {!filtered.length ? <p className="mt-2 text-xs text-muted">No options.</p> : null}
    </div>
  );
}
