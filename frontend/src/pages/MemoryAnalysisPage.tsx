import { useEffect } from "react";
import { useParams } from "react-router-dom";
import { MemoryWorkspace } from "../components/MemoryWorkspace";
import CaseMemoryLanding from "./CaseMemoryLanding";
import { useQuery } from "@tanstack/react-query";
import { api } from "../api/client";

export default function MemoryAnalysisPage() {
  const { caseId = "" } = useParams();

  const overviewQuery = useQuery({
    queryKey: ["memory-overview", caseId],
    queryFn: () => api.getMemoryOverview(caseId),
    enabled: Boolean(caseId),
    refetchOnWindowFocus: false,
  });

  if (!caseId) {
    return <div className="rounded-[28px] border border-line bg-panel/70 p-8 text-sm text-muted shadow-panel">Select a case first.</div>;
  }
  if (overviewQuery.isLoading) {
    return <div className="rounded-[28px] border border-line bg-panel/70 p-8 text-sm text-muted shadow-panel">Loading memory evidence...</div>;
  }
  const evidenceCount = overviewQuery.data?.evidences.length ?? 0;
  if (evidenceCount > 0) {
    return <CaseMemoryLanding />;
  }
  if (evidenceCount === 0) {
    return <MemoryWorkspace caseId={caseId} />;
  }
  return <div className="rounded-[28px] border border-line bg-panel/70 p-8 text-sm text-muted shadow-panel">Opening evidence workspace...</div>;
}
