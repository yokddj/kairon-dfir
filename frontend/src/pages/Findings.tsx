import { useEffect } from "react";
import { useParams } from "react-router-dom";
import FindingsWorkspace from "../components/FindingsWorkspace";
import { useActiveCase } from "../context/ActiveCaseContext";

export default function Findings() {
  const { caseId: routeCaseId } = useParams();
  const { activeCaseId, selectedEvidenceId, selectedHost, setActiveCaseId } = useActiveCase();
  const selectedCaseId = routeCaseId || activeCaseId || "";

  useEffect(() => {
    if (routeCaseId) setActiveCaseId(routeCaseId);
  }, [routeCaseId, setActiveCaseId]);

  return (
    <div className="space-y-6">
      <section className="rounded-[28px] border border-line bg-panel/70 p-6 shadow-panel">
        <p className="font-mono text-xs uppercase tracking-[0.24em] text-accent">Findings</p>
        <h2 className="mt-2 text-2xl font-semibold">Correlation-driven investigation workspace</h2>
        <p className="mt-2 text-sm text-muted">Trabaja los hallazgos del motor de correlación como una cola priorizada de investigación, no solo como una lista de eventos.</p>
        <div className="mt-5 flex flex-wrap gap-2 text-xs text-muted">
          <span className="rounded-full border border-line bg-abyss/70 px-3 py-1.5">{selectedHost ? `Host filter: ${selectedHost}` : "Host filter: all hosts"}</span>
          <span className="rounded-full border border-line bg-abyss/70 px-3 py-1.5">{selectedEvidenceId ? `Evidence filter: ${selectedEvidenceId.slice(0, 8)}` : "Evidence filter: all evidence"}</span>
        </div>
      </section>
      {selectedCaseId ? (
        <FindingsWorkspace caseId={selectedCaseId} evidenceId={selectedEvidenceId} host={selectedHost} />
      ) : (
        <div className="rounded-3xl border border-line bg-panel/40 p-6 text-sm text-muted">Select an active case to load findings.</div>
      )}
    </div>
  );
}
