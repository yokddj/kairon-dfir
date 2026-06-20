import { useParams } from "react-router-dom";
import { MemoryWorkspace } from "../components/MemoryWorkspace";

export default function MemoryAnalysisPage() {
  const { caseId = "" } = useParams();
  if (!caseId) {
    return <div className="rounded-[28px] border border-line bg-panel/70 p-8 text-sm text-muted shadow-panel">Select a case first.</div>;
  }
  return <MemoryWorkspace caseId={caseId} />;
}
