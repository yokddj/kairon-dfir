import { useEffect, useState } from "react";
import { useQuery } from "@tanstack/react-query";
import { api, type DfirCase } from "../api/client";
import { useActiveCase } from "../context/ActiveCaseContext";
import { useTimezonePreference } from "../context/TimezoneContext";
import { formatTimestamp } from "../lib/time";

export default function ActivityPage() {
  const { activeCaseId } = useActiveCase();
  const { effectiveTimezone } = useTimezonePreference();
  const { data: cases } = useQuery({ queryKey: ["cases"], queryFn: api.listCases });
  const [caseId, setCaseId] = useState(activeCaseId);
  const activityQuery = useQuery({
    queryKey: ["activity", caseId],
    queryFn: () => (caseId ? api.listCaseActivity(caseId) : api.listActivity()),
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
