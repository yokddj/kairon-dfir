import { useEffect } from "react";
import { useLocation, useNavigate, useParams } from "react-router-dom";
import { MemoryWorkspace } from "../components/MemoryWorkspace";
import CaseMemoryLanding from "./CaseMemoryLanding";
import { useQuery } from "@tanstack/react-query";
import { api } from "../api/client";

export default function MemoryAnalysisPage() {
  const { caseId = "" } = useParams();
  const navigate = useNavigate();
  const location = useLocation();

  const overviewQuery = useQuery({
    queryKey: ["memory-overview", caseId],
    queryFn: () => api.getMemoryOverview(caseId),
    enabled: Boolean(caseId),
    refetchOnWindowFocus: false,
  });

  useEffect(() => {
    const overview = overviewQuery.data;
    if (!overview) return;
    if (overview.evidences.length === 1) {
      const onlyEvidenceId = overview.evidences[0].id;
      navigate(`/cases/${caseId}/memory/${onlyEvidenceId}${location.search || ""}`, { replace: true });
    }
  }, [overviewQuery.data, caseId, location.search, navigate]);

  if (!caseId) {
    return <div className="rounded-[28px] border border-line bg-panel/70 p-8 text-sm text-muted shadow-panel">Select a case first.</div>;
  }
  if (overviewQuery.isLoading) {
    return <div className="rounded-[28px] border border-line bg-panel/70 p-8 text-sm text-muted shadow-panel">Loading memory evidence...</div>;
  }
  const evidenceCount = overviewQuery.data?.evidences.length ?? 0;
  if (evidenceCount > 1) {
    return <CaseMemoryLanding />;
  }
  if (evidenceCount === 0) {
    return <MemoryWorkspace caseId={caseId} />;
  }
  return <div className="rounded-[28px] border border-line bg-panel/70 p-8 text-sm text-muted shadow-panel">Opening evidence workspace...</div>;
}
