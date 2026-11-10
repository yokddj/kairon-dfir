import { useEffectiveTimezone } from "../hooks/useEffectiveTimezone";
import TimeField from "./TimeField";

/**
 * From/To pair for the case-wide time window (see useGlobalTimeRange). Used by
 * every event view so the inputs, timezone handling and wording are the same
 * everywhere.
 */
export default function TimeRangeFilter({
  timeFrom,
  timeTo,
  onChange,
  invalid = false,
  compact = false,
  className = "",
}: {
  timeFrom: string;
  timeTo: string;
  onChange: (range: { from: string; to: string }) => void;
  invalid?: boolean;
  compact?: boolean;
  className?: string;
}) {
  const timezone = useEffectiveTimezone();
  const active = Boolean(timeFrom || timeTo);
  return (
    <div className={className} data-testid="time-range-filter">
      <div className="grid gap-3 sm:grid-cols-2">
        <TimeField label="Time from" compact={compact} value={timeFrom} onChange={(value) => onChange({ from: value, to: timeTo })} />
        <TimeField label="Time to" compact={compact} value={timeTo} onChange={(value) => onChange({ from: timeFrom, to: value })} />
      </div>
      <div className="mt-2 flex flex-wrap items-center gap-x-3 gap-y-1 text-xs text-muted">
        <span>{`Times in ${timezone}.`}</span>
        {active ? <span>Applies to every view of this case.</span> : null}
        {active ? (
          <button type="button" onClick={() => onChange({ from: "", to: "" })} className="text-accent hover:underline">
            Clear time
          </button>
        ) : null}
      </div>
      {invalid ? <p className="mt-2 rounded-2xl border border-danger/40 bg-danger/10 px-3 py-2 text-xs text-danger">Invalid time range: start time must be before end time.</p> : null}
    </div>
  );
}
