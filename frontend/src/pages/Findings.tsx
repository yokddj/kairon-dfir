import { useEffect } from "react";
import { useParams, useSearchParams } from "react-router-dom";
import FindingsWorkspace from "../components/FindingsWorkspace";
import { useActiveCase } from "../context/ActiveCaseContext";
import { HostFilter } from "../components/HostFilter";

export default function Findings() {
  const { caseId: routeCaseId } = useParams();
  const { activeCaseId, selectedEvidenceId, selectedHost, setActiveCaseId } = useActiveCase();
  const [searchParams, setSearchParams] = useSearchParams();
  const selectedCaseId = routeCaseId || activeCaseId || "";
  const hostId = searchParams.get("host_id") ?? "";

  useEffect(() => {
    if (routeCaseId) setActiveCaseId(routeCaseId);
  }, [routeCaseId, setActiveCaseId]);

  return (
    <div className="space-y-6">
      <section className="rounded-[28px] border border-line bg-panel/70 p-6 shadow-panel">
        <p className="font-mono text-xs uppercase tracking-[0.24em] text-accent">Findings</p>
        <h2 className="mt-2 text-2xl font-semibold">Correlation-driven investigation workspace</h2>
        <p className="mt-2 text-sm text-muted">Work findings from the correlation engine as a prioritized investigation queue, not just a list of events.</p>
        <div className="mt-5 flex flex-wrap gap-2 text-xs text-muted">
          <span className="rounded-full border border-line bg-abyss/70 px-3 py-1.5">{selectedHost ? `Host filter: ${selectedHost}` : "Host filter: All hosts"}</span>
          <span className="rounded-full border border-line bg-abyss/70 px-3 py-1.5">{selectedEvidenceId ? `Evidence filter: ${selectedEvidenceId.slice(0, 8)}` : "Evidence filter: All evidence"}</span>
        </div>
        <div className="mt-4 flex flex-wrap items-center gap-3">
          <label className="flex items-center gap-2 text-xs text-muted">
            <span className="font-mono text-[11px] uppercase tracking-[0.16em]">Host ID</span>
            <HostFilter hostId={hostId || null} onChange={(value) => setSearchParams((prev) => { const next = new URLSearchParams(prev); if (value) next.set("host_id", value); else next.delete("host_id"); return next; })} className="rounded-xl border border-line bg-abyss/80 px-3 py-2" />
          </label>
        </div>
      </section>
      {selectedCaseId ? (
        <FindingsWorkspace caseId={selectedCaseId} evidenceId={selectedEvidenceId} host={selectedHost} hostId={hostId || undefined} />
      ) : (
        <div className="rounded-3xl border border-line bg-panel/40 p-6 text-sm text-muted">Select an active case to load findings.</div>
      )}
    </div>
  );
}
