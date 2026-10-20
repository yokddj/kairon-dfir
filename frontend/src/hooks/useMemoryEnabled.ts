import { useQuery } from "@tanstack/react-query";
import { api } from "../api/client";

// Whether this deployment runs Memory Analysis. The backend decides
// (settings.memory_enabled); until it answers, or if it cannot be read,
// Memory is treated as enabled so nothing is hidden by a failed request.
export function useMemoryEnabled(): boolean {
  const query = useQuery({
    queryKey: ["system-capabilities"],
    queryFn: api.getSystemCapabilities,
    staleTime: Infinity,
    refetchOnWindowFocus: false,
    retry: false,
  });
  return query.data?.memory?.enabled !== false;
}
