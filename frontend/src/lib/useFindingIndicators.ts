import { useQuery } from "@tanstack/react-query";
import { api, type FindingIndicatorResolveRequest, type FindingIndicatorSummary } from "../api/client";

export type FindingVisibility = "confirmed" | "confirmed_investigating" | "all" | "hidden";

export function useFindingIndicators(
  caseId: string | undefined,
  entities: FindingIndicatorResolveRequest["entities"] | null,
  visibility: FindingVisibility = "confirmed",
  enabled: boolean = true,
) {
  const visibilityKey = visibility;
  return useQuery({
    queryKey: ["finding-indicators", caseId, entities ? entities.length : 0, visibilityKey],
    queryFn: async () => {
      if (!caseId || !entities || entities.length === 0 || visibility === "hidden") return {} as Record<string, FindingIndicatorSummary>;
      const deduped = dedupeEntities(entities);
      if (deduped.length === 0) return {} as Record<string, FindingIndicatorSummary>;
      const statusesForVisibility: Record<string, string[]> = {
        confirmed: ["confirmed"],
        confirmed_investigating: ["confirmed", "investigating"],
        // draft/review are CreateFindingDialog's manual-workflow states (see
        // ALLOWED_TRANSITIONS in backend/app/models/finding.py) -- without
        // them here, a manually-created finding an analyst hasn't yet moved
        // past draft/review is invisible to indicator badges even with
        // visibility set to "all". archived stays excluded, matching how
        // findings list endpoints hide it by default (it's the outcome of
        // deleting a finding).
        all: ["new", "draft", "review", "triaged", "investigating", "confirmed", "false_positive", "accepted_risk", "resolved", "suppressed"],
        hidden: [],
      };
      try {
        const response = await api.resolveFindingIndicators(caseId, {
          entities: deduped.slice(0, 500),
          visibility: {
            statuses: statusesForVisibility[visibility] || ["confirmed"],
            include_rule_generated: true,
            include_suppressed: visibility === "all",
          },
        });
        return response.results || {};
      } catch {
        return {} as Record<string, FindingIndicatorSummary>;
      }
    },
    enabled: enabled && Boolean(caseId) && Boolean(entities && entities.length > 0) && visibility !== "hidden",
    staleTime: 15_000,
    refetchOnWindowFocus: false,
  });
}

function dedupeEntities(entities: FindingIndicatorResolveRequest["entities"]) {
  const seen = new Set<string>();
  return entities.filter((e) => {
    const key = e.key;
    if (seen.has(key)) return false;
    seen.add(key);
    return true;
  });
}
