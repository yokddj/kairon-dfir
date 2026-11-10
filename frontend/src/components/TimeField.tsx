import { useEffectiveTimezone } from "../hooks/useEffectiveTimezone";
import { fromDateTimeLocalValue, toDateTimeLocalValue } from "../lib/time";

/**
 * Date-time input shared by every time filter. The value is a UTC ISO instant;
 * the input shows and accepts wall-clock time in the timezone selected in the
 * top bar (user, case or UTC), the same one result timestamps are shown in.
 */
export default function TimeField({ label, value, onChange, compact = false, endOfMinute = false }: { label: string; value: string; onChange: (value: string) => void; compact?: boolean; endOfMinute?: boolean }) {
  const timezone = useEffectiveTimezone();
  return (
    <label className="block">
      <span className="mb-2 block font-mono text-[11px] uppercase tracking-[0.16em] text-muted">{label}</span>
      <input
        aria-label={label}
        type="datetime-local"
        step="1"
        title={`Interpreted in ${timezone}`}
        value={toDateTimeLocalValue(value, timezone)}
        onChange={(event) => onChange(fromDateTimeLocalValue(event.target.value, timezone, { endOfMinute }))}
        className={`w-full rounded-2xl border border-line bg-abyss/80 text-sm outline-none focus:border-accent/50 ${compact ? "px-3 py-2" : "px-4 py-3"}`}
      />
    </label>
  );
}
