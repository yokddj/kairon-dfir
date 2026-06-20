import { useEffect } from "react";
import { useQuery } from "@tanstack/react-query";
import { type MemoryProcessEntityDetail, type MemoryRunSelector, api } from "../../api/client";
import { MemoryCanonicalView } from "../MemoryCanonicalView";

type Profile = "processes_basic" | "processes_extended" | "metadata_only" | null;

type Props = {
  caseId: string;
  runId: string | null;
  runOptions: MemoryRunSelector | null;
  selectedRunId: string | null;
  onSelectRunId: (next: string | null) => void;
  profile: Profile;
  onSelectProfile: (next: Profile) => void;
  search: string;
  onSearch: (next: string) => void;
  processName: string;
  onProcessName: (next: string) => void;
  selectedEntityId: string | null;
  onSelectEntityId: (next: string | null) => void;
};

function ProcessDetailPanel({
  detail,
  onClose,
}: {
  detail: MemoryProcessEntityDetail;
  onClose: () => void;
}) {
  const entity = detail.entity;
  return (
    <aside
      className="rounded-2xl border border-line bg-abyss/60 p-4"
      data-testid="process-detail-panel"
      aria-label={`Process detail ${entity.process.pid}`}
    >
      <header className="flex items-start justify-between gap-2">
        <div>
          <h4 className="text-base font-semibold">
            {(entity.process.name as string | undefined) || "—"} · PID {entity.process.pid}
          </h4>
          <p className="mt-1 text-xs text-muted">
            Entity {entity.process_entity_id} · Confidence {entity.confidence}
          </p>
        </div>
        <button
          type="button"
          onClick={onClose}
          className="rounded-xl border border-line bg-abyss/70 px-2 py-1 text-xs"
          aria-label="Close detail panel"
        >
          Close
        </button>
      </header>
      <dl className="mt-3 grid gap-2 text-xs md:grid-cols-2">
        <Row label="Command line" value={reported(entity.process.command_line)} />
        <Row label="PPID" value={reported(entity.process.ppid)} />
        <Row label="Create time" value={reported(entity.process.create_time)} />
        <Row label="Exit time" value={reported(entity.process.exit_time)} />
        <Row label="Sources" value={(entity.sources || []).map((s) => s.replace("windows.", "")).join(", ")} />
        <Row
          label="Visibility"
          value={entity.visibility?.scan_only ? "Scan only" : entity.visibility?.terminated ? "Terminated" : entity.visibility?.hidden_candidate ? "Hidden candidate" : "Listed"}
        />
        <Row label="Parent" value={detail.parent ? `${detail.parent.process.name ?? ""} (${detail.parent.process_entity_id})` : "None"} />
        <Row label="Children" value={String(detail.children.length)} />
        <Row label="Tree path" value={detail.tree_path.length ? detail.tree_path.join(" → ") : "Root"} />
        <Row label="Findings" value={(detail.findings || []).join(", ") || "None"} />
        <Row label="Source records" value={String(detail.source_record_refs.length)} />
      </dl>

      <section className="mt-3">
        <h5 className="text-[10px] uppercase tracking-[0.18em] text-muted">Observations</h5>
        <table className="mt-2 min-w-full divide-y divide-line text-[11px]">
          <thead className="bg-abyss/70 text-left text-[10px] uppercase tracking-[0.14em] text-muted">
            <tr>
              <th className="px-2 py-1">Plugin</th>
              <th className="px-2 py-1">PID</th>
              <th className="px-2 py-1">PPID</th>
              <th className="px-2 py-1">Name</th>
              <th className="px-2 py-1">Command line</th>
              <th className="px-2 py-1">Create</th>
              <th className="px-2 py-1">Exit</th>
            </tr>
          </thead>
          <tbody className="divide-y divide-line">
            {(detail.observations ?? []).map((obs) => (
              <tr key={obs.document_id || `${entity.process_entity_id}-${obs.plugin_name}`}>
                <td className="px-2 py-1 text-ink">{obs.plugin_name.replace("windows.", "")}</td>
                <td className="px-2 py-1 text-muted">{obs.observed?.pid ?? ""}</td>
                <td className="px-2 py-1 text-muted">{obs.observed?.ppid ?? "—"}</td>
                <td className="px-2 py-1 text-ink">{reported(obs.observed?.name)}</td>
                <td className="px-2 py-1 text-muted">{reported(obs.observed?.command_line)}</td>
                <td className="px-2 py-1 text-muted">{reported(obs.observed?.create_time)}</td>
                <td className="px-2 py-1 text-muted">{reported(obs.observed?.exit_time)}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </section>

      {detail.alternate_command_lines.length > 0 ? (
        <section className="mt-3">
          <h5 className="text-[10px] uppercase tracking-[0.18em] text-muted">Alternate command lines</h5>
          <ul className="mt-1 list-disc pl-5 text-xs text-muted">
            {detail.alternate_command_lines.map((line) => (
              <li key={line}>{line}</li>
            ))}
          </ul>
        </section>
      ) : null}
    </aside>
  );
}

function Row({ label, value }: { label: string; value: string }) {
  return (
    <div className="rounded-xl border border-line bg-abyss/40 p-2">
      <p className="text-[10px] uppercase tracking-[0.16em] text-muted">{label}</p>
      <p className="mt-1 break-words text-ink">{value}</p>
    </div>
  );
}

function reported(value: unknown): string {
  if (value === null || value === undefined || value === "") return "—";
  return String(value);
}

export function MemoryProcessesTab({
  caseId,
  runId,
  runOptions,
  selectedRunId,
  onSelectRunId,
  search,
  onSearch: _onSearch,
  processName,
  onProcessName,
  selectedEntityId,
  onSelectEntityId,
}: Props) {
  const effectiveRunId = selectedRunId || runOptions?.default_run_id || null;
  const detailQuery = useQuery({
    queryKey: ["memory-process-entity-detail", caseId, selectedEntityId, effectiveRunId],
    queryFn: () =>
      api.getCanonicalProcessEntityDetail(caseId, selectedEntityId as string, effectiveRunId || undefined),
    enabled: Boolean(caseId && selectedEntityId),
    refetchOnWindowFocus: false,
  });

  useEffect(() => {
    if (!selectedEntityId) return;
  }, [selectedEntityId]);

  return (
    <div className="space-y-4" data-testid="memory-processes-tab">
      <div className="grid gap-4 lg:grid-cols-[minmax(0,1.4fr)_minmax(360px,1fr)]">
        <div>
          <MemoryCanonicalView
            caseId={caseId}
            runId={effectiveRunId}
            processName={processName}
            onProcessName={onProcessName}
            selectedEntityId={selectedEntityId}
            onSelectEntityId={onSelectEntityId}
          />
        </div>
        <div className="space-y-3">
          {selectedEntityId ? (
            detailQuery.isLoading ? (
              <p className="text-xs text-muted">Loading process detail…</p>
            ) : detailQuery.data ? (
              <ProcessDetailPanel detail={detailQuery.data} onClose={() => onSelectEntityId(null)} />
            ) : detailQuery.error instanceof Error ? (
              <p className="rounded-2xl border border-rose-400/30 bg-rose-500/10 p-3 text-xs text-rose-200">
                {detailQuery.error.message}
              </p>
            ) : null
          ) : (
            <p className="rounded-2xl border border-line bg-abyss/40 p-3 text-xs text-muted">
              Click a row in the table to inspect the process.
            </p>
          )}
        </div>
      </div>
    </div>
  );
}
