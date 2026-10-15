// A filter picker whose options are the values the data actually has, with
// their counts (from the backend's facets), instead of free text the analyst
// must already know or a fixed list that only fits one platform.
export type Facet = { value: string; count: number };

type Props = {
  value: string;
  onChange: (next: string) => void;
  facets: Facet[];
  allLabel: string;
  ariaLabel: string;
  testId?: string;
  label?: (value: string) => string;
  className?: string;
};

export function FacetSelect({ value, onChange, facets, allLabel, ariaLabel, testId, label = (v) => v, className }: Props) {
  // Keep a selected value listed even if the data no longer has it, so the
  // control never shows a selection that is not among its options.
  const options = value && !facets.some((f) => f.value === value) ? [...facets, { value, count: 0 }] : facets;
  return (
    <select
      value={value}
      onChange={(event) => onChange(event.target.value)}
      aria-label={ariaLabel}
      className={className ?? "rounded-xl border border-line bg-abyss/70 px-2 py-1 text-xs"}
      data-testid={testId}
    >
      <option value="">{allLabel}</option>
      {options.map((facet) => (
        <option key={facet.value} value={facet.value}>
          {label(facet.value)} ({facet.count.toLocaleString("en-US")})
        </option>
      ))}
    </select>
  );
}
