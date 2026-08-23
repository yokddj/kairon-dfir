import { fromDateTimeLocalValue, toDateTimeLocalValue } from "../lib/time";

export default function TimeField({ label, value, onChange }: { label: string; value: string; onChange: (value: string) => void }) {
  return (
    <label className="block">
      <span className="mb-2 block font-mono text-[11px] uppercase tracking-[0.16em] text-muted">{label}</span>
      <input
        aria-label={label}
        type="datetime-local"
        value={toDateTimeLocalValue(value)}
        onChange={(event) => onChange(fromDateTimeLocalValue(event.target.value))}
        className="w-full rounded-2xl border border-line bg-abyss/80 px-4 py-3 text-sm outline-none focus:border-accent/50"
      />
    </label>
  );
}
