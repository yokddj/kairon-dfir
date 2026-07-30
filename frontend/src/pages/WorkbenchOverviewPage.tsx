import { useEffect } from "react";
import { useQuery } from "@tanstack/react-query";
import { Navigate, useParams } from "react-router-dom";
import { api } from "../api/client";
import { InvestigationBreadcrumbs } from "../components/InvestigationContext";
import { WorkbenchOverview } from "../components/workbench/WorkbenchOverview";
import { useActiveCase } from "../context/ActiveCaseContext";
import { useInvestigationBreadcrumbs } from "../lib/useInvestigationBreadcrumbs";

export default function WorkbenchOverviewPage({ workbenchId }: { workbenchId: string }) {
  const { caseId = "" } = useParams();
  const { setActiveCaseId } = useActiveCase();
  const breadcrumbs = useInvestigationBreadcrumbs();
  const registryQuery = useQuery({
    queryKey: ["case-capabilities", caseId, "workbench-overview"],
    queryFn: () => api.getCaseCapabilities(caseId),
    enabled: Boolean(caseId),
    staleTime: 15_000,
    refetchOnWindowFocus: false,
  });

  useEffect(() => {
    if (caseId) setActiveCaseId(caseId);
  }, [caseId, setActiveCaseId]);

  if (!caseId) return <Navigate to="/cases" replace />;
  if (registryQuery.isLoading) return <div className="rounded-2xl border border-line bg-panel/70 p-6 text-sm text-muted">Loading workbench overview...</div>;
  if (registryQuery.isError || !registryQuery.data) return <div className="rounded-2xl border border-danger/40 bg-danger/10 p-6 text-sm text-danger">Capability registry unavailable.</div>;
  return (
    <div className="space-y-4">
      <InvestigationBreadcrumbs items={breadcrumbs} />
      <WorkbenchOverview registry={registryQuery.data} workbenchId={workbenchId} caseId={caseId} />
    </div>
  );
}
