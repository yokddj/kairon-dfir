import { useQuery } from "@tanstack/react-query";
import { api, type FindingIndicatorResolveRequest, type FindingIndicatorSummary } from "../api/client";

export function useFindingIndicators(
  caseId: string | undefined,
  entities: FindingIndicatorResolveRequest["entities"] | null,
  enabled: boolean = true,
) {
  return useQuery({
    queryKey: ["finding-indicators", caseId, entities ? entities.length : 0],
    queryFn: async () => {
      if (!caseId || !entities || entities.length === 0) return {} as Record<string, FindingIndicatorSummary>;
      const deduped = dedupeEntities(entities);
      if (deduped.length === 0) return {} as Record<string, FindingIndicatorSummary>;
      try {
        const response = await api.resolveFindingIndicators(caseId, { entities: deduped.slice(0, 500) });
        return response.results || {};
      } catch {
        return {} as Record<string, FindingIndicatorSummary>;
      }
    },
    enabled: enabled && Boolean(caseId) && Boolean(entities && entities.length > 0),
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
