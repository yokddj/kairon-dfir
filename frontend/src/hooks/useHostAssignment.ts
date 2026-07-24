import { useEffect, useState } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { api } from "../api/client";
import { useNotifications } from "../context/NotificationsContext";
import { assignedHostMatchesDetected } from "../lib/evidenceDetailFormatting";

export type HostAssignmentMode = "existing" | "create";

export function useHostAssignment({
  caseId,
  evidenceId,
  currentHostId,
  detectedHost,
  ready,
}: {
  caseId: string | null | undefined;
  evidenceId: string;
  currentHostId: string | null | undefined;
  detectedHost: string | null | undefined;
  ready: boolean;
}) {
  const queryClient = useQueryClient();
  const { notify } = useNotifications();
  const [mode, setMode] = useState<HostAssignmentMode>("existing");
  const [selectedHostId, setSelectedHostId] = useState("");
  const [newHostName, setNewHostName] = useState("");

  const caseHostsQuery = useQuery({
    queryKey: ["case-hosts", caseId],
    queryFn: () =>
      typeof api.getCaseHosts === "function"
        ? api.getCaseHosts(caseId!)
        : Promise.resolve({ case_id: caseId!, hosts: [], host_candidates: [] }),
    enabled: Boolean(caseId),
    staleTime: 15_000,
    refetchOnWindowFocus: false,
  });

  const caseHosts = caseHostsQuery.data?.hosts ?? [];
  const assignedHost = caseHosts.find((host) => host.id === currentHostId) ?? null;
  const assignmentMismatch = Boolean(
    currentHostId && detectedHost && assignedHost && !assignedHostMatchesDetected(assignedHost, detectedHost),
  );

  useEffect(() => {
    if (!ready) return;
    setSelectedHostId(currentHostId || "");
    setMode("existing");
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [evidenceId, currentHostId, ready]);

  const mutation = useMutation({
    mutationFn: async () => {
      if (!caseId) throw new Error("Evidence case is not loaded.");
      if (mode === "create") {
        const name = newHostName.trim();
        if (!name) throw new Error("Enter a host name.");
        return api.updateEvidenceHost(caseId, evidenceId, { host_name: name, reason: "Assigned from Evidence Detail" });
      }
      return api.updateEvidenceHost(caseId, evidenceId, {
        host_id: selectedHostId || null,
        reason: selectedHostId ? "Assigned from Evidence Detail" : "Marked unassigned from Evidence Detail",
      });
    },
    onSuccess: (updated) => {
      queryClient.setQueryData(["evidence", evidenceId], updated);
      void queryClient.invalidateQueries({ queryKey: ["case-hosts", updated.case_id] });
      void queryClient.invalidateQueries({ queryKey: ["case-context", updated.case_id] });
      void queryClient.invalidateQueries({ queryKey: ["evidence-custody-events", updated.case_id, evidenceId] });
      setNewHostName("");
      notify({ title: "Host assignment updated", tone: "success" });
    },
    onError: (error: Error) => notify({ title: "Host assignment failed", description: error.message, tone: "error" }),
  });

  return {
    caseHosts,
    assignedHost,
    assignmentMismatch,
    mode,
    setMode,
    selectedHostId,
    setSelectedHostId,
    newHostName,
    setNewHostName,
    submit: () => mutation.mutate(),
    isSubmitting: mutation.isPending,
  };
}
