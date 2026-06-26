import { useState } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { api } from "../../api/client";

/**
 * Experimental Mismatched-Symbol Analysis v1.
 *
 * The panel is intentionally separate from the validated
 * artefacts panel.  It carries a permanent warning banner,
 * per-row trust labels, and a single "Acknowledgement" gate
 * that the analyst must pass before a canary may start.
 *
 * The panel never reads from the validated OpenSearch index;
 * it queries the dedicated
 * ``GET .../experimental-runs/{id}/artifacts`` endpoint
 * which always returns the ``trust_level = "untrusted"`` rows.
 */

const TRUST_BADGE_TONE = "border-warning/40 bg-warning/15 text-warning";

const BANNER_TONE = "border-danger/40 bg-danger/15 text-danger";

type Props = {
  caseId: string;
  evidenceId: string;
};

export function MemoryExperimentalResultsPanel({ caseId, evidenceId }: Props) {
  const queryClient = useQueryClient();
  const [ackChecked, setAckChecked] = useState<Record<string, boolean>>({});
  const trustQuery = useQuery({
    queryKey: ["experimental-trust", caseId, evidenceId],
    queryFn: () => api.getExperimentalTrust(caseId, evidenceId),
  });
  const candidatesQuery = useQuery({
    queryKey: ["experimental-candidates", caseId, evidenceId],
    queryFn: () => api.listExperimentalCandidates(caseId, evidenceId),
  });
  const runsQuery = useQuery({
    queryKey: ["experimental-runs", caseId, evidenceId],
    queryFn: () => api.listExperimentalRuns(caseId, evidenceId),
    refetchInterval: (query) => {
      const data = query.state.data;
      const active = data?.items?.find(
        (item) => !["deleted", "cancelled", "completed_untrusted", "partial_untrusted", "failed_untrusted", "canary_failed", "canary_inconclusive"].includes(item.status),
      );
      return active ? 2000 : false;
    },
  });
  const warningQuery = useQuery({
    queryKey: ["experimental-warning", caseId, evidenceId],
    queryFn: () => api.getExperimentalWarning(caseId, evidenceId),
  });
  const catalogueQuery = useQuery({
    queryKey: ["experimental-catalogue", caseId, evidenceId],
    queryFn: () => api.getExperimentalProfileCatalogue(caseId, evidenceId),
  });
  const [selectedRunId, setSelectedRunId] = useState<string | null>(null);
  const activeRun =
    runsQuery.data?.items?.find((r) => r.id === selectedRunId) ??
    runsQuery.data?.items?.find((r) => r.status !== "cancelled" && r.status !== "deleted") ??
    null;
  const createRunMutation = useMutation({
    mutationFn: (payload: { requested_profiles?: string[] }) =>
      api.createExperimentalRun(caseId, evidenceId, payload),
    onSuccess: () => {
      queryClient.invalidateQueries({
        queryKey: ["experimental-runs", caseId, evidenceId],
      });
    },
  });
  const startCanaryMutation = useMutation({
    mutationFn: (runId: string) =>
      api.startExperimentalCanary(caseId, evidenceId, runId),
    onSuccess: () => {
      queryClient.invalidateQueries({
        queryKey: ["experimental-runs", caseId, evidenceId],
      });
    },
  });
  const acknowledgeMutation = useMutation({
    mutationFn: ({
      runId,
      payload,
    }: {
      runId: string;
      payload: Record<string, unknown>;
    }) =>
      api.acknowledgeExperimentalRun(caseId, evidenceId, runId, payload),
    onSuccess: () => {
      queryClient.invalidateQueries({
        queryKey: ["experimental-runs", caseId, evidenceId],
      });
    },
  });
  const continueMutation = useMutation({
    mutationFn: (runId: string) =>
      api.continueExperimentalRun(caseId, evidenceId, runId),
    onSuccess: () => {
      queryClient.invalidateQueries({
        queryKey: ["experimental-runs", caseId, evidenceId],
      });
    },
  });
  const cancelMutation = useMutation({
    mutationFn: ({
      runId,
      payload,
    }: {
      runId: string;
      payload: { client_actor_label?: string; reason: string };
    }) => api.cancelExperimentalRun(caseId, evidenceId, runId, payload),
    onSuccess: () => {
      queryClient.invalidateQueries({
        queryKey: ["experimental-runs", caseId, evidenceId],
      });
    },
  });
  const deleteMutation = useMutation({
    mutationFn: ({
      runId,
      payload,
    }: {
      runId: string;
      payload: { client_actor_label?: string; reason: string };
    }) => api.deleteExperimentalRun(caseId, evidenceId, runId, payload),
    onSuccess: () => {
      queryClient.invalidateQueries({
        queryKey: ["experimental-runs", caseId, evidenceId],
      });
    },
  });

  if (trustQuery.data && !trustQuery.data.enabled) {
    return (
      <section
        className="mt-4 rounded-2xl border border-line bg-abyss/60 p-4 text-sm text-muted"
        data-testid="memory-experimental-panel-disabled"
      >
        <p className="font-semibold text-danger">Experimental analysis is disabled.</p>
        <p className="mt-1 text-xs">
          The server-side flag{" "}
          <code>memory_symbol_experimental_mismatch_enabled</code> is off.  Ask the operator to enable
          it before using the experimental workflow.
        </p>
      </section>
    );
  }
  if (trustQuery.data && !trustQuery.data.has_active_candidate) {
    return null;
  }

  return (
    <section
      className="mt-4 rounded-2xl border border-warning/40 bg-abyss/60 p-4 text-sm"
      data-testid="memory-experimental-panel"
    >
      <div
        className={`mb-3 rounded-xl border p-3 text-xs ${BANNER_TONE}`}
        data-testid="memory-experimental-banner"
      >
        <p className="font-semibold">Experimental / Untrusted analysis</p>
        <p className="mt-1">
          This section runs plugins with a Windows symbol that does NOT exactly match the required
          identity.  Output MAY be incomplete, incorrect or misleading.  Detections and timeline
          events are not produced.  The absence of a result proves nothing.  This is not
          validated forensic evidence.
        </p>
      </div>

      <div className="grid grid-cols-1 gap-4 md:grid-cols-2">
        <div data-testid="memory-experimental-candidates">
          <h4 className="text-sm font-semibold text-warning">Symbol candidates</h4>
          {candidatesQuery.data?.items?.length ? (
            <ul className="mt-1 space-y-2 text-xs">
              {candidatesQuery.data.items.map((c) => (
                <li
                  key={c.id}
                  className="rounded-xl border border-line bg-abyss/40 p-2"
                >
                  <p className="font-mono">
                    Required age {c.required_identity.pdb_age} / observed age{" "}
                    {c.observed_identity.pdb_age}
                  </p>
                  <p className="text-muted">{c.symbol_warning}</p>
                  {c.revoked_at ? (
                    <p className="mt-1 text-danger">Revoked: {c.revocation_reason}</p>
                  ) : null}
                </li>
              ))}
            </ul>
          ) : (
            <p className="mt-1 text-xs text-muted">No active experimental candidates.</p>
          )}
        </div>

        <div data-testid="memory-experimental-runs">
          <h4 className="text-sm font-semibold text-warning">Runs</h4>
          {runsQuery.data?.items?.length ? (
            <ul className="mt-1 space-y-2 text-xs">
              {runsQuery.data.items.map((r) => (
                <li
                  key={r.id}
                  className={`rounded-xl border p-2 ${
                    r.id === activeRun?.id
                      ? "border-warning bg-abyss/80"
                      : "border-line bg-abyss/40"
                  }`}
                >
                  <button
                    type="button"
                    className="w-full text-left"
                    onClick={() => setSelectedRunId(r.id)}
                    data-testid="memory-experimental-run-button"
                  >
                    <p className="font-mono">
                      {r.id.slice(0, 8)} / {r.status} / canary={r.canary.status}
                    </p>
                    <p className="text-muted">
                      Profiles: {r.requested_profiles.join(", ") || "—"}
                    </p>
                  </button>
                  <div className="mt-2 flex flex-wrap gap-1">
                    {r.status === "acknowledgement_required" ? (
                      <label className="inline-flex items-center gap-1 text-[10px] text-warning">
                        <input
                          type="checkbox"
                          checked={Boolean(ackChecked[r.id])}
                          onChange={(event) =>
                            setAckChecked((current) => ({ ...current, [r.id]: event.target.checked }))
                          }
                        />
                        {warningQuery.data?.checkbox_text ?? "Acknowledge warning"}
                      </label>
                    ) : null}
                    {r.status === "acknowledgement_required" ? (
                      <button
                        type="button"
                        className="rounded border border-line bg-abyss/70 px-2 py-0.5 text-[10px]"
                        disabled={!ackChecked[r.id]}
                        onClick={() =>
                          acknowledgeMutation.mutate({
                            runId: r.id,
                            payload: buildAcknowledgementPayload(
                              warningQuery.data,
                              r,
                            ),
                          })
                        }
                        data-testid="memory-experimental-acknowledge-button"
                      >
                        Acknowledge
                      </button>
                    ) : null}
                    {r.status === "acknowledgement_required" ? (
                      <button
                        type="button"
                        className="rounded border border-line bg-abyss/70 px-2 py-0.5 text-[10px]"
                        disabled={!Boolean(r.acknowledgement.acknowledged_at)}
                        onClick={() =>
                          startCanaryMutation.mutate(r.id)
                        }
                        data-testid="memory-experimental-start-canary-button"
                      >
                        Start canary
                      </button>
                    ) : null}
                    {r.canary.status === "degraded" ? (
                      <button
                        type="button"
                        className="rounded border border-line bg-abyss/70 px-2 py-0.5 text-[10px]"
                        onClick={() =>
                          continueMutation.mutate(r.id)
                        }
                      >
                        Continue restricted set
                      </button>
                    ) : null}
                    {r.canary.status === "inconclusive" ? (
                      <span className="rounded border border-danger/40 bg-danger/10 px-2 py-0.5 text-[10px] text-danger">
                        Inconclusive canary cannot continue
                      </span>
                    ) : null}
                    {r.canary.status === "passed" ? (
                      <button
                        type="button"
                        className="rounded border border-line bg-abyss/70 px-2 py-0.5 text-[10px]"
                        onClick={() => continueMutation.mutate(r.id)}
                      >
                        Continue full run
                      </button>
                    ) : null}
                    {r.status !== "cancelled" && r.status !== "deleted" ? (
                      <button
                        type="button"
                        className="rounded border border-line bg-abyss/70 px-2 py-0.5 text-[10px]"
                        onClick={() =>
                            cancelMutation.mutate({
                              runId: r.id,
                              payload: { client_actor_label: "analyst", reason: "aborted" },
                            })
                          }
                      >
                        Cancel
                      </button>
                    ) : null}
                    <button
                      type="button"
                      className="rounded border border-danger/40 bg-danger/10 px-2 py-0.5 text-[10px] text-danger"
                      disabled={!["cancelled", "completed_untrusted", "partial_untrusted", "failed_untrusted", "canary_failed", "canary_inconclusive"].includes(r.status)}
                      onClick={() =>
                        deleteMutation.mutate({
                          runId: r.id,
                          payload: { client_actor_label: "analyst", reason: "removed" },
                        })
                      }
                    >
                      Delete
                    </button>
                  </div>
                </li>
              ))}
            </ul>
          ) : (
            <p className="mt-1 text-xs text-muted">No experimental runs.</p>
          )}
          <button
            type="button"
            className="mt-2 rounded-xl border border-warning/40 bg-warning/15 px-3 py-1.5 text-xs text-warning"
            disabled={!candidatesQuery.data?.items?.some((item) => !item.revoked_at)}
            onClick={() => {
              const profiles =
                catalogueQuery.data?.profiles?.map((p) => p.profile) ?? [];
              createRunMutation.mutate({ requested_profiles: profiles });
            }}
            data-testid="memory-experimental-create-run-button"
          >
            New experimental run
          </button>
        </div>
      </div>

      {activeRun ? (
        <ExperimentalRunDetail caseId={caseId} evidenceId={evidenceId} runId={activeRun.id} />
      ) : null}
    </section>
  );
}

function buildAcknowledgementPayload(
  _warning: { warning_version: string; warning_text: string } | undefined,
  _run: { acknowledgement: { required_identity: unknown; observed_identity: unknown } },
) {
  return {
    checkbox_confirmed: true,
    client_actor_label: "analyst",
  };
}

function ExperimentalRunDetail({
  caseId,
  evidenceId,
  runId,
}: {
  caseId: string;
  evidenceId: string;
  runId: string;
}) {
  const runQuery = useQuery({
    queryKey: ["experimental-run", caseId, evidenceId, runId],
    queryFn: () => api.getExperimentalRun(caseId, evidenceId, runId),
  });
  const artifactsQuery = useQuery({
    queryKey: ["experimental-run-artifacts", caseId, evidenceId, runId],
    queryFn: () => api.getExperimentalRunArtifacts(caseId, evidenceId, runId, {}),
  });
  if (runQuery.isLoading) {
    return <p className="mt-2 text-xs text-muted">Loading run…</p>;
  }
  if (!runQuery.data) {
    return null;
  }
  const run = runQuery.data;
  return (
    <div
      className="mt-3 rounded-xl border border-warning/40 bg-abyss/40 p-3 text-xs"
      data-testid="memory-experimental-run-detail"
    >
      <p className="font-mono">
        Status: {run.status} / canary: {run.canary.status}{" "}
        {run.canary.score !== null ? `(score ${run.canary.score})` : ""}
      </p>
      <p className="mt-1">
        Required age: <span className="font-mono">{run.acknowledgement.required_identity?.pdb_age}</span>{" "}
        / observed age:{" "}
        <span className="font-mono">
          {run.acknowledgement.observed_identity?.pdb_age}
        </span>
      </p>
      <p className="mt-1 text-muted">
        Acknowledged by client label: {run.acknowledgement.actor || "anonymous"} ({run.acknowledgement.actor_trust || "untrusted"})
      </p>
      {run.canary.status === "degraded" ? (
        <p className="mt-1 text-warning">Degraded canary: only the restricted server-side profile subset may continue.</p>
      ) : null}
      <div className="mt-2 grid grid-cols-1 gap-2 md:grid-cols-2">
        {run.canary.checks?.map((check) => (
          <div
            key={check.name}
            className={`rounded-xl border p-2 ${TRUST_BADGE_TONE}`}
            data-testid="memory-experimental-canary-check"
          >
            <p className="font-mono">{check.name}</p>
            <p>
              {check.status} — {check.detail}
            </p>
          </div>
        ))}
      </div>
      <div className="mt-3">
        <h5 className="text-xs font-semibold text-warning">Experimental artefacts</h5>
        {artifactsQuery.data?.items?.length ? (
          <ul className="mt-1 space-y-1 text-xs">
            {artifactsQuery.data.items.map((item) => (
              <li
                key={String(item.document_id)}
                className={`rounded border border-line bg-abyss/40 p-2 ${TRUST_BADGE_TONE}`}
                data-testid="memory-experimental-artifact-row"
              >
                <p>
                  <span className="font-mono">{String(item.document_type)}</span> —{" "}
                  {String(item.process_name ?? item.module_name ?? item.document_id)}
                </p>
                <p className="text-muted">Untrusted / Experimental</p>
              </li>
            ))}
          </ul>
        ) : (
          <p className="mt-1 text-muted">No artefacts yet.</p>
        )}
      </div>
    </div>
  );
}
