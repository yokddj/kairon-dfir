import { useEffect } from "react";
import { type MemoryProcessEntityDetail } from "../../api/client";
import { XCircle } from "lucide-react";

type Props = {
  open: boolean;
  detail: MemoryProcessEntityDetail | null;
  isLoading: boolean;
  error: Error | null;
  onClose: () => void;
};

function reported(value: unknown): string {
  if (value === null || value === undefined || value === "") return "—";
  return String(value);
}

function describeVisibility(entity: any): string {
  if (entity.visibility?.terminated) return "Terminated";
  if (entity.visibility?.hidden_candidate) return "Hidden candidate";
  if (entity.visibility?.scan_only) return "Scan only";
  if (entity.visibility?.unknown) return "Unknown";
  return "Listed";
}

function sourceBadge(plugin: string): string {
  return plugin.replace("windows.", "");
}

function Row({ label, value }: { label: string; value: string }) {
  return (
    <div className="rounded-xl border border-line bg-abyss/40 p-2">
      <p className="text-[10px] uppercase tracking-[0.16em] text-muted">{label}</p>
      <p className="mt-1 break-words text-ink">{value}</p>
    </div>
  );
}

export function ProcessDetailDrawer({ open, detail, isLoading, error, onClose }: Props) {
  useEffect(() => {
    if (!open) return;
    function onKey(event: KeyboardEvent) {
      if (event.key === "Escape") {
        onClose();
      }
    }
    window.addEventListener("keydown", onKey);
    return () => window.removeEventListener("keydown", onKey);
  }, [open, onClose]);

  if (!open) return null;
  const entity = detail?.entity;

  return (
    <div
      className="fixed inset-0 z-40 flex justify-end"
      role="dialog"
      aria-modal="true"
      aria-label="Process detail"
      data-testid="process-detail-drawer"
    >
      <div
        className="absolute inset-0 bg-abyss/70 backdrop-blur-sm"
        onClick={onClose}
        aria-hidden="true"
        data-testid="process-detail-drawer-overlay"
      />
      <aside
        className="relative h-full w-full max-w-md overflow-y-auto border-l border-line bg-panel/95 p-5 shadow-panel"
        data-testid="process-detail-drawer-panel"
      >
        <header className="flex items-start justify-between gap-2">
          <h2 className="text-base font-semibold">Process detail</h2>
          <button
            type="button"
            onClick={onClose}
            aria-label="Close process detail"
            data-testid="process-detail-drawer-close"
            className="rounded-md border border-line bg-abyss/70 px-2 py-1 text-xs"
          >
            <XCircle className="h-3.5 w-3.5" />
          </button>
        </header>
        {isLoading ? (
          <p className="mt-4 text-xs text-muted">Loading process detail…</p>
        ) : error ? (
          <p className="mt-4 rounded-2xl border border-rose-400/30 bg-rose-500/10 p-3 text-xs text-rose-200">
            {error.message}
          </p>
        ) : entity ? (
          <div className="mt-4 space-y-3 text-xs">
            <div>
              <h3 className="text-sm font-semibold">
                {reported(entity.process?.name)} · PID {entity.process?.pid}
              </h3>
              <p className="mt-1 text-muted">
                Entity {entity.process_entity_id} · Confidence {entity.confidence}
              </p>
            </div>
            <dl className="grid gap-2 md:grid-cols-2">
              <Row label="Command line" value={reported(entity.process?.command_line)} />
              <Row label="PPID" value={reported(entity.process?.ppid)} />
              <Row label="Create time" value={reported(entity.process?.create_time)} />
              <Row label="Exit time" value={reported(entity.process?.exit_time)} />
              <Row label="Sources" value={(entity.sources || []).map(sourceBadge).join(", ")} />
              <Row label="Visibility" value={describeVisibility(entity)} />
              <Row label="Parent" value={detail?.parent ? `${detail.parent.process?.name ?? ""} (${detail.parent.process_entity_id})` : "None"} />
              <Row label="Children" value={String(detail?.children.length ?? 0)} />
              <Row label="Tree path" value={detail?.tree_path.length ? detail.tree_path.join(" → ") : "Root"} />
              <Row label="Findings" value={(detail?.findings || []).join(", ") || "None"} />
              <Row label="Source records" value={String(detail?.source_record_refs.length ?? 0)} />
            </dl>
            <section>
              <h4 className="text-[10px] uppercase tracking-[0.18em] text-muted">Observations</h4>
              <table className="mt-1 min-w-full divide-y divide-line text-[10px]">
                <thead className="bg-abyss/70 text-left text-[9px] uppercase tracking-[0.14em] text-muted">
                  <tr>
                    <th className="px-2 py-1">Plugin</th>
                    <th className="px-2 py-1">PID</th>
                    <th className="px-2 py-1">PPID</th>
                    <th className="px-2 py-1">Command line</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-line">
                  {(detail?.observations ?? []).map((obs) => (
                    <tr key={obs.document_id || `${entity.process_entity_id}-${obs.plugin_name}`}>
                      <td className="px-2 py-1 text-ink">{sourceBadge(obs.plugin_name)}</td>
                      <td className="px-2 py-1 text-muted">{obs.observed?.pid ?? ""}</td>
                      <td className="px-2 py-1 text-muted">{obs.observed?.ppid ?? "—"}</td>
                      <td className="px-2 py-1 text-muted" title={obs.observed?.command_line ?? ""}>
                        {reported(obs.observed?.command_line)}
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </section>
            {detail && detail.alternate_command_lines.length > 0 ? (
              <section>
                <h4 className="text-[10px] uppercase tracking-[0.18em] text-muted">Alternate command lines</h4>
                <ul className="mt-1 list-disc pl-5 text-xs text-muted">
                  {detail.alternate_command_lines.map((line) => (
                    <li key={line}>{line}</li>
                  ))}
                </ul>
              </section>
            ) : null}
          </div>
        ) : (
          <p className="mt-4 text-xs text-muted">No process selected.</p>
        )}
      </aside>
    </div>
  );
}
