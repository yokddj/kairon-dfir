type SelectOption = string | { value: string; label: string };

function normalizeOption(option: SelectOption): { value: string; label: string } {
  return typeof option === "string" ? { value: option, label: option } : option;
}

export function SelectField({
  label,
  value,
  options,
  onChange,
  emptyLabel = "Any",
}: {
  label: string;
  value: string;
  options: SelectOption[];
  onChange: (value: string) => void;
  emptyLabel?: string;
}) {
  return (
    <label className="block">
      <span className="mb-2 block font-mono text-[11px] uppercase tracking-[0.16em] text-muted">{label}</span>
      <select aria-label={label} value={value} onChange={(event) => onChange(event.target.value)} className="w-full rounded-2xl border border-line bg-abyss/80 px-4 py-3 text-sm outline-none focus:border-accent/50">
        <option value="">{emptyLabel}</option>
        {options.map(normalizeOption).map((option) => (
          <option key={option.value} value={option.value}>
            {option.label}
          </option>
        ))}
      </select>
    </label>
  );
}

export function TextField({ label, value, onChange, placeholder }: { label: string; value: string; onChange: (value: string) => void; placeholder?: string }) {
  return (
    <label className="block">
      <span className="mb-2 block font-mono text-[11px] uppercase tracking-[0.16em] text-muted">{label}</span>
      <input aria-label={label} value={value} onChange={(event) => onChange(event.target.value)} placeholder={placeholder} className="w-full rounded-2xl border border-line bg-abyss/80 px-4 py-3 text-sm outline-none focus:border-accent/50" />
    </label>
  );
}

export function NumberField({ label, value, onChange, min = 0, max = 100 }: { label: string; value: string; onChange: (value: string) => void; min?: number; max?: number }) {
  return (
    <label className="block">
      <span className="mb-2 block font-mono text-[11px] uppercase tracking-[0.16em] text-muted">{label}</span>
      <input aria-label={label} type="number" min={min} max={max} value={value} onChange={(event) => onChange(event.target.value)} className="w-full rounded-2xl border border-line bg-abyss/80 px-4 py-3 text-sm outline-none focus:border-accent/50" />
    </label>
  );
}
