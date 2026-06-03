type Props = {
  value: string;
  onChange: (value: string) => void;
  placeholder?: string;
  ariaLabel?: string;
};

export default function SearchBar({ value, onChange, placeholder, ariaLabel }: Props) {
  return (
    <input
      aria-label={ariaLabel}
      value={value}
      onChange={(event) => onChange(event.target.value)}
      placeholder={placeholder ?? "Search powershell, 4624, rclone, Temp, .ps1"}
      className="w-full rounded-2xl border border-line bg-abyss/80 px-4 py-3 text-sm text-ink outline-none transition placeholder:text-muted focus:border-accent/50"
    />
  );
}
