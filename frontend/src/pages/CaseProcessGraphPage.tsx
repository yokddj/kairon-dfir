import { useEffect } from "react";
import { useQuery } from "@tanstack/react-query";
import { useParams, useSearchParams } from "react-router-dom";
import { api } from "../api/client";
import ProcessTreePanel from "../components/ProcessTreePanel";
import { useActiveCase } from "../context/ActiveCaseContext";
import { HostFilter } from "../components/HostFilter";

export default function CaseProcessGraphPage() {
  const { caseId = "" } = useParams();
  const [searchParams, setSearchParams] = useSearchParams();
  const { setActiveCaseId, selectedEvidenceId, selectedHost, caseContext } = useActiveCase();
  const hostId = searchParams.get("host_id") ?? "";
  const hosts = caseContext?.hosts ?? [];
  const evidencesQuery = useQuery({
    queryKey: ["evidences", caseId],
    queryFn: () => api.listEvidences(caseId),
    enabled: Boolean(caseId),
    staleTime: 10_000,
    refetchOnWindowFocus: false,
  });

  useEffect(() => {
    if (caseId) setActiveCaseId(caseId);
  }, [caseId, setActiveCaseId]);

  if (!caseId) {
    return <div className="rounded-[28px] border border-line bg-panel/70 p-8 text-sm text-muted shadow-panel">Select a case to inspect the process graph.</div>;
  }

  const highlightedNodeIds = Array.from(
    new Set([
      ...searchParams.getAll("node_id"),
      ...searchParams.getAll("process_node_id"),
      ...(searchParams.get("process_node_id") ? [searchParams.get("process_node_id") ?? ""] : []),
    ].filter(Boolean)),
  );
  const requestedMode = searchParams.get("mode");
  const sourceEventId = searchParams.get("source_event_id") ?? searchParams.get("story_event_id") ?? searchParams.get("event_id") ?? "";
  const initialMode =
    requestedMode === "full"
      ? "full"
      : requestedMode === "finding_focus" || requestedMode === "process_focus" || requestedMode === "focused_chain" || requestedMode === "execution_story"
        ? "focused"
        : "suspicious";

  const filteredEvidences = hostId
    ? (evidencesQuery.data ?? []).filter(e => e.host_id === hostId)
    : (evidencesQuery.data ?? []);
  const evidenceIdFromUrl = searchParams.get("evidence_id") ?? selectedEvidenceId;
  const resolvedEvidenceId = evidenceIdFromUrl || "";

  return (
    <div className="space-y-6">
      <section className="rounded-[28px] border border-line bg-panel/70 p-6 shadow-panel">
        <p className="font-mono text-xs uppercase tracking-[0.24em] text-accent">Process Graph</p>
        <h2 className="mt-2 text-2xl font-semibold">Execution graph for the active case</h2>
        <p className="mt-2 text-sm text-muted">Use the global host/evidence filters to scope the graph before drilling into individual processes.</p>
        <div className="mt-4 flex flex-wrap items-center gap-3">
          <label className="flex items-center gap-2 text-xs text-muted">
            <span className="font-mono text-[11px] uppercase tracking-[0.16em]">Host ID</span>
            <HostFilter hostId={hostId || null} onChange={(value) => setSearchParams((prev) => { const next = new URLSearchParams(prev); if (value) next.set("host_id", value); else next.delete("host_id"); return next; })} className="rounded-xl border border-line bg-abyss/80 px-3 py-2" />
          </label>
          {hostId && filteredEvidences.length > 1 ? (
            <label className="flex items-center gap-2 text-xs text-muted">
              <span className="font-mono text-[11px] uppercase tracking-[0.16em]">Evidence</span>
              <select
                value={resolvedEvidenceId}
                onChange={(e) => setSearchParams((prev) => { const next = new URLSearchParams(prev); if (e.target.value) next.set("evidence_id", e.target.value); else next.delete("evidence_id"); return next; })}
                className="rounded-xl border border-line bg-abyss/80 px-3 py-2 text-xs"
              >
                <option value="">All evidence</option>
                {filteredEvidences.map((e) => (
                  <option key={e.id} value={e.id}>{e.original_filename || e.id}</option>
                ))}
              </select>
            </label>
          ) : null}
        </div>
      </section>
      <ProcessTreePanel
        caseId={caseId}
        evidences={evidencesQuery.data ?? []}
        initialEvidenceId={searchParams.get("evidence_id") ?? selectedEvidenceId}
        initialPid={searchParams.get("pid") ?? ""}
        initialProcessGuid={searchParams.get("process_guid") ?? searchParams.get("entity_id") ?? ""}
        initialSourceEventId={sourceEventId}
        initialTimestamp={searchParams.get("timestamp") ?? ""}
        initialProcessName={searchParams.get("process_name") ?? ""}
        initialCommandHistoryRowId={searchParams.get("command_history_row_id") ?? ""}
        initialOrigin={searchParams.get("origin") ?? ""}
        initialHighlightedNodeIds={highlightedNodeIds}
        initialFindingId={searchParams.get("finding_id") ?? ""}
        openedFromSearchEventId={searchParams.get("from_search_event_id") ?? (requestedMode === "execution_story" ? sourceEventId : "")}
        initialMode={initialMode}
        selectedHost={searchParams.get("host") ?? selectedHost}
        selectedEvidenceId={selectedEvidenceId}
      />
    </div>
  );
}
