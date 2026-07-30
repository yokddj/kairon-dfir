import { useMemo } from "react";
import { useQuery } from "@tanstack/react-query";
import { useLocation } from "react-router-dom";
import { api } from "../api/client";
import { useActiveCase } from "../context/ActiveCaseContext";
import { matchCapabilityRoute, matchSurfaceHome } from "./capabilityRouteMatch";
import { displayLabel } from "./displayLabel";

export type BreadcrumbItem = { label: string; to?: string };

export type UseInvestigationBreadcrumbsOptions = {
  // Skips capability/Surface Home matching entirely -- for pages that are
  // never a capability landing target (CaseDetail, EvidenceDetail).
  // Produces Case / currentLabel [/ context].
  currentLabel?: string;
  // Fallback identity used ONLY when neither Surface Home nor a capability
  // route matched -- for Tier 1 lenses that a capability route can also
  // land on (Search, Artifact Views, Memory's non-capability tabs).
  // Produces Case / lensLabel [/ context] in that fallback case; when a
  // capability DOES match (e.g. this same page reached via a capability's
  // own query-qualified route), the capability trail wins instead.
  lensLabel?: string;
  // Explicit trailing crumb. Overrides whatever terminal context would
  // otherwise be derived (e.g. an evidence name from :evidenceId) -- never
  // combined with it. Never derived automatically from ?view=/?tab=.
  context?: string;
};

function caseOverviewRoute(caseId: string) {
  return `/cases/${caseId}/overview`;
}

// Single derivation point for the Case / Surface / Domain / Capability /
// Context breadcrumb hierarchy. Reads location, ActiveCaseContext, and the
// same ["case-capabilities", caseId] query Sidebar and Surface Home already
// populate (reused via the same queryKey, not a second copy of the
// registry) -- if that cache is empty, this hook triggers the same fetch
// through the same mechanism, it does not invent a new endpoint.
export function useInvestigationBreadcrumbs(options: UseInvestigationBreadcrumbsOptions = {}): BreadcrumbItem[] {
  const location = useLocation();
  const { activeCaseId, activeCase } = useActiveCase();
  const capabilitiesQuery = useQuery({
    queryKey: ["case-capabilities", activeCaseId],
    queryFn: () => api.getCaseCapabilities(activeCaseId),
    enabled: Boolean(activeCaseId),
    staleTime: 15_000,
    refetchOnWindowFocus: false,
  });

  const { currentLabel, lensLabel, context } = options;
  const registry = capabilitiesQuery.data;

  return useMemo(() => {
    // Matches the existing InvestigationContext fallback convention
    // (`caseName || "Case"`, `"No case"` when there's no active case) --
    // not a new placeholder string.
    const caseCrumb: BreadcrumbItem = activeCaseId ? { label: activeCase?.name || "Case", to: caseOverviewRoute(activeCaseId) } : { label: "No case" };

    if (currentLabel) {
      const items: BreadcrumbItem[] = [caseCrumb, { label: currentLabel }];
      if (context) items.push({ label: context });
      return items;
    }

    if (!registry) {
      // Payload not loaded yet (or no active case): show what's already
      // known synchronously and nothing else -- never a placeholder
      // Surface/Domain/Capability.
      return [caseCrumb];
    }

    const surfaceHome = matchSurfaceHome(registry.workbenches, location.pathname);
    if (surfaceHome) {
      const items: BreadcrumbItem[] = [caseCrumb, { label: surfaceHome.label, to: surfaceHome.overview_route }];
      if (context) items.push({ label: context });
      return items;
    }

    const match = matchCapabilityRoute(registry.capabilities, location.pathname, location.search);
    if (match) {
      const workbench = registry.workbenches.find((item) => item.capability_ids.includes(match.capability.id));
      const items: BreadcrumbItem[] = [caseCrumb];
      if (workbench) items.push({ label: workbench.label, to: workbench.overview_route });
      items.push({ label: displayLabel(match.capability.domain) });
      items.push({ label: match.capability.title });
      if (context) {
        items.push({ label: context });
      } else if (match.evidenceId) {
        const evidence = registry.evidence.find((item) => item.id === match.evidenceId);
        // Id found but no matching evidence name in the payload: truncate
        // at Capability rather than showing the raw id.
        if (evidence) items.push({ label: evidence.name });
      }
      return items;
    }

    if (lensLabel) {
      const items: BreadcrumbItem[] = [caseCrumb, { label: lensLabel }];
      if (context) items.push({ label: context });
      return items;
    }

    return [caseCrumb];
  }, [activeCaseId, activeCase?.name, registry, location.pathname, location.search, currentLabel, lensLabel, context]);
}
