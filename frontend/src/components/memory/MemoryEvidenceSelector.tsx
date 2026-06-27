import type { MemoryEvidenceLandingItem } from "../../api/client";

type Props = {
  caseId: string;
  selectedEvidenceId: string | undefined;
  evidences: MemoryEvidenceLandingItem[];
  onChange: (evidenceId: string) => void;
};

function readinessBadge(item: MemoryEvidenceLandingItem): string | null {
  const detectionStatus = item.detection_status;
  if (!detectionStatus) return null;
  const s = detectionStatus.toLowerCase();
  if (s === "confirmed_memory" || s === "probable_memory" || s === "ambiguous_raw_confirmed" || s === "probable_disk_confirmed_as_memory" || item.operator_override) {
    return "Ready";
  }
  if (s === "ambiguous_raw") return "Confirmation needed";
  if (s === "probable_disk") return "Probable disk";
  return null;
}

function formatTimestamp(iso: string | null | undefined): string {
  if (!iso) return "";
  return iso.slice(0, 16).replace("T", " ");
}

function shortId(id: string): string {
  return id.length > 12 ? id.slice(0, 8) : id;
}

export function MemoryEvidenceSelector({ caseId: _caseId, selectedEvidenceId, evidences, onChange }: Props) {
  if (evidences.length <= 1) return null;

  return (
    <div className="rounded-[28px] border border-line bg-panel/70 p-4 shadow-panel" data-testid="memory-evidence-selector">
      <label className="text-[10px] uppercase tracking-[0.24em] text-muted" htmlFor="memory-evidence-select">
        Memory evidence
      </label>
      <select
        id="memory-evidence-select"
        value={selectedEvidenceId ?? ""}
        onChange={(event) => onChange(event.target.value)}
        className="mt-2 w-full rounded-xl border border-line bg-abyss/70 px-3 py-2 text-sm"
        data-testid="memory-evidence-select"
      >
        <option value="" disabled>Select an evidence image…</option>
        {evidences.map((item) => {
          const badge = readinessBadge(item);
          const hostname = item.detected_host;
          const timestamp = formatTimestamp(item.created_at);
          const parts: string[] = [];
          if (hostname) parts.push(hostname);
          if (timestamp) parts.push(`${timestamp} UTC`);
          if (badge) parts.push(badge);
          const label = parts.length > 0
            ? `${item.filename} · ${parts.join(" · ")}`
            : `${item.filename} · ${shortId(item.evidence_id)}`;
          return (
            <option key={item.evidence_id} value={item.evidence_id}>
              {label}
            </option>
          );
        })}
      </select>
    </div>
  );
}
