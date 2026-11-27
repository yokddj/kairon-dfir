import { useState } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { api, type HostAgentRequest, type HostAgentState } from "../../api/client";

export const HOST_AGENT_QUERY_KEY = ["admin-host-agent"];
const FINAL_STATES = new Set(["done", "failed", "refused"]);

function isActive(request: HostAgentRequest | undefined) {
  return Boolean(request && !FINAL_STATES.has(request.state));
}

/** The host agent's state; polled every few seconds while a request is waiting or running (the
 * backend itself restarts during an upgrade, so failed reads are retried). */
export function useHostAgent() {
  return useQuery<HostAgentState>({
    queryKey: HOST_AGENT_QUERY_KEY,
    queryFn: api.getHostAgent,
    retry: (count, error) => (error as { status?: number }).status !== 403 && count < 2,
    refetchInterval: (query) => (query.state.data?.requests.some((item) => isActive(item)) || query.state.error ? 3000 : 30000),
  });
}

export function latestRequest(state: HostAgentState | undefined, action: "restart" | "upgrade") {
  return state?.requests.find((item) => item.action === action);
}

/** Why the action cannot be asked for now, or null. */
export function blockedReason(state: HostAgentState | undefined): string | null {
  if (!state?.available) return "The host agent is not running.";
  if (state.active_jobs === null) return "Kairon's running jobs could not be checked.";
  if (state.active_jobs.total > 0) return `${state.active_jobs.total} job(s) are queued or running: this is possible once they finish.`;
  if (state.requests.some((item) => isActive(item))) return "Another request is still waiting or running.";
  return null;
}

const STATE_LABELS: Record<string, string> = {
  queued: "Waiting for the host agent",
  running: "Running",
  done: "Done",
  failed: "Failed",
  refused: "Not done",
};

export function AgentRequestStatus({ request }: { request: HostAgentRequest }) {
  const tone = request.state === "done" ? "text-mint" : request.state === "failed" || request.state === "refused" ? "text-red-300" : "text-amber";
  return (
    <div className="mt-4 rounded-2xl border border-line bg-abyss/60 p-4" data-testid={`host-agent-request-${request.action}`}>
      <p className={`text-sm font-semibold ${tone}`}>
        {STATE_LABELS[request.state] ?? request.state}
        {request.state === "running" && request.step ? ` · ${request.step}` : ""}
      </p>
      {request.message ? <p className="mt-1 text-sm text-muted">{request.message}</p> : null}
      {request.log_tail ? (
        <details className="mt-2" open={request.state === "failed"}>
          <summary className="cursor-pointer text-xs text-slate-400">Log</summary>
          <pre className="mt-2 max-h-72 overflow-auto rounded-xl bg-abyss/90 p-3 text-xs text-slate-200">{request.log_tail}</pre>
        </details>
      ) : null}
    </div>
  );
}

/** A button that asks the host agent for an action after an in-page confirmation. */
export function AgentActionButton({
  label,
  confirmText,
  payload,
  onRequested,
}: {
  label: string;
  confirmText: string;
  payload: { action: "restart" | "upgrade"; services?: string[] };
  onRequested?: () => void;
}) {
  const queryClient = useQueryClient();
  const agent = useHostAgent();
  const [confirming, setConfirming] = useState(false);
  const mutation = useMutation({
    mutationFn: () => api.requestHostAgentAction(payload),
    onSuccess: () => {
      setConfirming(false);
      onRequested?.();
      void queryClient.invalidateQueries({ queryKey: HOST_AGENT_QUERY_KEY });
    },
  });
  if (!agent.data?.available) return null;
  const blocked = blockedReason(agent.data);
  return (
    <div className="mt-3">
      {confirming ? (
        <div className="rounded-2xl border border-amber/40 bg-amber/10 p-3">
          <p className="text-sm text-ink">{confirmText}</p>
          <div className="mt-3 flex gap-2">
            <button type="button" onClick={() => mutation.mutate()} disabled={mutation.isPending} className="rounded-2xl bg-accent px-4 py-2 text-sm font-semibold text-abyss disabled:opacity-60">
              {mutation.isPending ? "Asking…" : `Confirm: ${label.toLowerCase()}`}
            </button>
            <button type="button" onClick={() => setConfirming(false)} className="rounded-2xl border border-line px-4 py-2 text-sm text-muted">
              Cancel
            </button>
          </div>
        </div>
      ) : (
        <button type="button" onClick={() => setConfirming(true)} disabled={Boolean(blocked)} className="rounded-2xl bg-accent px-4 py-2 text-sm font-semibold text-abyss disabled:cursor-not-allowed disabled:opacity-60">
          {label}
        </button>
      )}
      {blocked && !confirming ? <p className="mt-2 text-xs text-slate-400">{blocked}</p> : null}
      {mutation.isError ? <p className="mt-2 text-xs text-red-300">{(mutation.error as Error).message}</p> : null}
    </div>
  );
}
