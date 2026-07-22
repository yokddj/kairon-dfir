import { useEffect, useState } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { useNavigate } from "react-router-dom";
import { api, type ActivityOperation, type DfirCase } from "../api/client";
import { useActiveCase } from "../context/ActiveCaseContext";
import { useTimezonePreference } from "../context/TimezoneContext";
import { formatTimestamp } from "../lib/time";

function bytes(value: number | null | undefined): string {
  if (value === null || value === undefined) return "-";
  let num = value;
  for (const unit of ["B", "KB", "MB", "GB", "TB"]) {
    if (num < 1024 || unit === "TB") return unit === "B" ? `${Math.round(num)} B` : `${num.toFixed(1)} ${unit}`;
    num /= 1024;
  }
  return `${num.toFixed(1)} TB`;
}

export default function ActivityPage() {
  const navigate = useNavigate();
  const queryClient = useQueryClient();
  const { activeCaseId } = useActiveCase();
  const { effectiveTimezone } = useTimezonePreference();
  const { data: cases } = useQuery({ queryKey: ["cases"], queryFn: api.listCases });
  const [caseId, setCaseId] = useState(activeCaseId);
  const activityQuery = useQuery({
    queryKey: ["activity", caseId],
    queryFn: () => api.listActivity(),
  });
  const operationsQuery = useQuery({
    queryKey: ["activity-center", caseId],
    queryFn: () => api.getCaseActivity(caseId || ""),
    enabled: Boolean(caseId),
    refetchInterval: 5000,
  });
  const cancelMutation = useMutation({
    mutationFn: ({ targetCaseId, sessionId }: { targetCaseId: string; sessionId: string }) => api.cancelEvidenceUploadSession(targetCaseId, sessionId),
    onSuccess: () => {
      void queryClient.invalidateQueries({ queryKey: ["activity-center", caseId] });
    },
  });
  const retryMutation = useMutation({
    mutationFn: ({ targetCaseId, operationId }: { targetCaseId: string; operationId: string }) => api.retryEvidenceOperation(targetCaseId, operationId),
    onSuccess: () => {
      void queryClient.invalidateQueries({ queryKey: ["activity-center", caseId] });
    },
  });
  const dismissMutation = useMutation({
    mutationFn: ({ targetCaseId, operationId }: { targetCaseId: string; operationId: string }) => api.dismissEvidenceOperation(targetCaseId, operationId),
    onSuccess: () => {
      void queryClient.invalidateQueries({ queryKey: ["activity-center", caseId] });
    },
  });

  useEffect(() => {
    setCaseId((current) => current || activeCaseId);
  }, [activeCaseId]);

  return (
    <div className="space-y-6">
      <section className="rounded-[28px] border border-line bg-panel/70 p-6 shadow-panel">
        <p className="font-mono text-xs uppercase tracking-[0.24em] text-accent">Jobs & Activity</p>
        <h2 className="mt-2 text-2xl font-semibold">Operational view for ingest jobs, background tasks and system activity.</h2>
        <p className="mt-2 text-sm text-muted">Use this page to review uploads, parsing jobs, rule executions, processing errors and other operational platform events.</p>
        {!caseId ? <p className="mt-2 text-sm text-amber-300">No active case selected. You are looking across all cases.</p> : null}
        <select value={caseId} onChange={(event) => setCaseId(event.target.value)} className="mt-5 rounded-2xl border border-line bg-abyss/80 px-4 py-3 text-sm outline-none focus:border-accent/50">
          <option value="">All cases</option>
          {(cases ?? []).map((item: DfirCase) => (
            <option key={item.id} value={item.id}>
              {item.name}
            </option>
          ))}
        </select>
      </section>
      {caseId ? (
        <section className="rounded-[28px] border border-line bg-panel/70 p-6 shadow-panel" data-testid="activity-center">
          <div className="flex flex-wrap items-start justify-between gap-4">
            <div>
              <p className="font-mono text-xs uppercase tracking-[0.24em] text-accent">Activity Center</p>
              <h2 className="mt-2 text-xl font-semibold">Evidence lifecycle operations</h2>
              <p className="mt-1 text-sm text-muted">Uploads, paused uploads, processing, memory, indexing, completed and failed work are read from server state.</p>
            </div>
            <button type="button" onClick={() => operationsQuery.refetch()} className="rounded-2xl border border-line bg-abyss/80 px-4 py-2 text-sm text-muted">Refresh</button>
          </div>
          <div className="mt-5 flex flex-wrap gap-2">
            {(Object.entries(operationsQuery.data?.summary ?? {}) as Array<[string, number]>).map(([key, value]) => (
              <span key={key} className="rounded-full border border-line bg-abyss/70 px-3 py-1 text-xs text-muted">{key}: <span className="text-ink">{value}</span></span>
            ))}
          </div>
          <div className="mt-5 space-y-3">
            {(operationsQuery.data?.operations ?? []).map((operation: ActivityOperation) => {
              const uploadSessionId = typeof operation.details.upload_session_id === "string" ? operation.details.upload_session_id : operation.kind === "upload" ? operation.id : null;
              const evidenceId = typeof operation.details.promoted_evidence_id === "string" ? operation.details.promoted_evidence_id : typeof operation.details.evidence_id === "string" ? operation.details.evidence_id : null;
              const operationId = typeof operation.details.operation_id === "string" ? operation.details.operation_id : operation.id;
              const jobs = Array.isArray(operation.details.jobs) ? operation.details.jobs as Array<Record<string, unknown>> : [];
              const canContinue = Boolean(uploadSessionId && operation.kind === "upload" && ["running", "paused"].includes(operation.status));
              const canCancel = Boolean(uploadSessionId && operation.kind === "upload" && ["running", "paused"].includes(operation.status));
              const canRetry = operation.status === "failed";
              const canDismiss = ["completed", "cancelled", "expired"].includes(operation.status);
              return (
              <article key={`${operation.kind}-${operation.id}`} className="rounded-2xl border border-line bg-abyss/60 p-4">
                <div className="flex flex-wrap items-start justify-between gap-3">
                  <div>
                    <p className="font-mono text-[11px] uppercase tracking-[0.18em] text-accent">{operation.category} / {operation.current_owner}</p>
                    <h3 className="mt-1 font-semibold text-ink">{operation.label}</h3>
                    <p className="mt-1 text-sm text-muted">Stage: {operation.stage} · Status: {operation.status}</p>
                  </div>
                  <div className="text-right text-xs text-muted">
                    <p>Last activity: {operation.last_activity_at ? formatTimestamp(operation.last_activity_at, effectiveTimezone) : "-"}</p>
                    <p>Elapsed: {operation.elapsed_seconds !== null ? `${Math.round(operation.elapsed_seconds)}s` : "-"}</p>
                  </div>
                </div>
                {operation.progress !== null ? (
                  <div className="mt-3">
                    <div className="h-2 rounded-full bg-abyss"><div className="h-2 rounded-full bg-accent" style={{ width: `${Math.max(4, Math.min(100, operation.progress))}%` }} /></div>
                    <p className="mt-1 text-xs text-muted">{operation.progress.toFixed(0)}% · {bytes(operation.bytes_received)} / {bytes(operation.expected_size_bytes)}</p>
                  </div>
                ) : null}
                {operation.details.failure_message ? <p className="mt-2 text-xs text-danger">Error: {String(operation.details.failure_message)}</p> : null}
                {jobs.length ? (
                  <div className="mt-3 rounded-xl border border-line bg-panel/40 p-3 text-xs text-muted">
                    <p className="font-mono uppercase tracking-[0.14em] text-accent">Jobs</p>
                    {jobs.slice(0, 4).map((job) => (
                      <p key={String(job.id)} className="mt-1">{String(job.job_type)} · {String(job.status)} · owner {String(job.owner)}{job.rq_job_id ? ` · ${String(job.rq_job_id).slice(0, 8)}` : ""}</p>
                    ))}
                  </div>
                ) : null}
                <div className="mt-3 flex flex-wrap gap-2 text-xs">
                  <button type="button" className="rounded-xl border border-line px-3 py-1.5 text-muted disabled:opacity-50" disabled={!canContinue} onClick={() => uploadSessionId && navigate(`/cases/${operation.case_id}?tab=evidences&resume_session=${uploadSessionId}`)}>Continue wizard</button>
                  <button type="button" className="rounded-xl border border-line px-3 py-1.5 text-muted disabled:opacity-50" disabled={!evidenceId} onClick={() => evidenceId && navigate(`/cases/${operation.case_id}?tab=processing&evidence_id=${evidenceId}`)}>Open evidence</button>
                  <button type="button" className="rounded-xl border border-line px-3 py-1.5 text-muted disabled:opacity-50" disabled={!evidenceId} onClick={() => evidenceId && navigate(`/cases/${operation.case_id}?tab=processing&evidence_id=${evidenceId}`)}>Open processing</button>
                  <button type="button" className="rounded-xl border border-line px-3 py-1.5 text-muted disabled:opacity-50" disabled={!canRetry || retryMutation.isPending} onClick={() => retryMutation.mutate({ targetCaseId: operation.case_id, operationId })}>Retry</button>
                  <button type="button" className="rounded-xl border border-line px-3 py-1.5 text-muted disabled:opacity-50" disabled={!canCancel || cancelMutation.isPending} onClick={() => uploadSessionId && cancelMutation.mutate({ targetCaseId: operation.case_id, sessionId: uploadSessionId })}>Cancel</button>
                  <button type="button" className="rounded-xl border border-line px-3 py-1.5 text-muted disabled:opacity-50" disabled={!canDismiss || dismissMutation.isPending} onClick={() => dismissMutation.mutate({ targetCaseId: operation.case_id, operationId })}>Dismiss completed</button>
                  {jobs.some((job) => job.rq_job_id) ? <span className="rounded-xl border border-line px-3 py-1.5 text-muted">Logs: RQ job shown</span> : null}
                  <span className="rounded-xl border border-line px-3 py-1.5 text-muted">Details: {operation.id.slice(0, 8)}</span>
                </div>
              </article>
              );
            })}
            {!operationsQuery.data?.operations?.length ? <div className="rounded-2xl border border-line bg-abyss/40 p-4 text-sm text-muted">No active lifecycle operations for this case.</div> : null}
          </div>
        </section>
      ) : null}
      <section className="space-y-4">
        {(activityQuery.data ?? []).map((activity) => (
          <article key={activity.id} className="rounded-3xl border border-line bg-panel/70 p-5 shadow-panel">
            <div className="flex items-start justify-between gap-4">
              <div>
                <p className="font-mono text-xs uppercase tracking-[0.18em] text-accent">{formatTimestamp(activity.created_at, effectiveTimezone)}</p>
                <h3 className="mt-2 text-base font-semibold">{activity.title}</h3>
                <p className="mt-2 text-sm text-muted">{activity.message}</p>
              </div>
              <span className={`rounded-full border px-3 py-1 font-mono text-[11px] uppercase tracking-[0.16em] ${activity.severity === "error" ? "border-danger/30 bg-danger/10 text-danger" : activity.severity === "warning" ? "border-amber/30 bg-amber/10 text-amber" : "border-accent/30 bg-accent/10 text-accent"}`}>
                {activity.severity}
              </span>
            </div>
            <p className="mt-3 font-mono text-xs text-muted">{activity.activity_type}</p>
          </article>
        ))}
        {!activityQuery.data?.length ? <div className="rounded-3xl border border-line bg-panel/40 p-6 text-sm text-muted">No workbench activity recorded yet.</div> : null}
      </section>
    </div>
  );
}
