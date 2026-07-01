import { useQuery } from "@tanstack/react-query";
import { type MemoryRunSelector, api } from "../../api/client";
import { MemoryCanonicalView } from "../MemoryCanonicalView";
import { ProcessDetailModal } from "./ProcessDetailModal";

type Profile = "processes_basic" | "processes_extended" | "metadata_only" | null;

type Props = {
  caseId: string;
  evidenceId?: string;
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
  pidFilter: string;
  onPidFilter: (next: string) => void;
  selectedEntityId: string | null;
  onSelectEntityId: (next: string | null) => void;
};

export function MemoryProcessesTab({
  caseId,
  evidenceId,
  runId,
  runOptions,
  selectedRunId,
  onSelectRunId,
  profile: _profile,
  onSelectProfile: _onSelectProfile,
  search: _onSearch,
  processName,
  onProcessName,
  pidFilter,
  onPidFilter,
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

  return (
    <div className="space-y-4" data-testid="memory-processes-tab">
      <div className="rounded-[28px] border border-line bg-panel/60 p-3 shadow-panel">
        <MemoryCanonicalView
          caseId={caseId}
          evidenceId={evidenceId}
          runId={effectiveRunId}
          processName={processName}
          onProcessName={onProcessName}
          pidFilter={pidFilter}
          onPidFilter={onPidFilter}
          selectedEntityId={selectedEntityId}
          onSelectEntityId={onSelectEntityId}
        />
      </div>
      <ProcessDetailModal
        open={Boolean(selectedEntityId)}
        detail={detailQuery.data ?? null}
        isLoading={detailQuery.isLoading}
        error={detailQuery.error instanceof Error ? detailQuery.error : null}
        caseId={caseId}
        evidenceId={evidenceId || ""}
        runId={effectiveRunId}
        onClose={() => onSelectEntityId(null)}
        onSelectEntityId={onSelectEntityId}
      />
    </div>
  );
}
