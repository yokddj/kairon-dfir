import { useActiveCase } from "../context/ActiveCaseContext";

interface HostFilterProps {
  hostId: string | null;
  onChange: (hostId: string | null) => void;
  className?: string;
  showAllOption?: boolean;
  showUnassigned?: boolean;
}

export function HostFilter({ hostId, onChange, className, showAllOption = true, showUnassigned = true }: HostFilterProps) {
  const { caseContext } = useActiveCase();
  const hosts = caseContext?.hosts ?? [];

  return (
    <select
      value={hostId ?? "all"}
      onChange={(e) => {
        const value = e.target.value;
        onChange(value === "all" ? null : value);
      }}
      className={`rounded-md border border-zinc-700 bg-zinc-900 px-2 py-1 text-xs text-zinc-200 ${className ?? ""}`}
    >
      {showAllOption && <option value="all">All hosts</option>}
      {hosts.map((h) => (
        <option key={h.id} value={h.id}>{h.canonical_name}</option>
      ))}
      {showUnassigned && <option value="unassigned">Unassigned</option>}
      {/* Conflicted hidden until real conflict detection is implemented */}
    </select>
  );
}
