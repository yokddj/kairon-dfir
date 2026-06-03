import { Link } from "react-router-dom";
import { useQuery } from "@tanstack/react-query";
import { api } from "../api/client";
import CaseCard from "../components/CaseCard";
import { useActiveCase } from "../context/ActiveCaseContext";

function Stat({ label, value }: { label: string; value: string | number }) {
  return (
    <div className="rounded-3xl border border-line bg-panel/70 p-5 shadow-panel">
      <p className="font-mono text-xs uppercase tracking-[0.18em] text-muted">{label}</p>
      <p className="mt-3 text-3xl font-semibold text-ink">{value}</p>
    </div>
  );
}

function formatEventCount(count: number | undefined, relation: string | undefined) {
  if (!count) return "0";
  return relation === "gte" ? `${count.toLocaleString()}+` : count.toLocaleString();
}

export default function Dashboard() {
  const casesQuery = useQuery({ queryKey: ["cases"], queryFn: api.listCases });
  const { activeCase, setActiveCase } = useActiveCase();
  const summaryQuery = useQuery({
    queryKey: ["dashboard-summary", activeCase?.id],
    queryFn: () => api.getInvestigationSummary(activeCase?.id ?? ""),
    enabled: Boolean(activeCase?.id),
  });

  const cases = casesQuery.data ?? [];
  const openCases = cases.filter((item) => item.status === "open").length;

  return (
    <div className="space-y-8">
      <section className="rounded-[28px] border border-line bg-panel/70 p-6 shadow-panel">
        <p className="font-mono text-xs uppercase tracking-[0.24em] text-accent">Workspace context</p>
        <div className="mt-4 flex flex-wrap items-center gap-4">
          <select
            value={activeCase?.id ?? ""}
            onChange={(event) => setActiveCase(cases.find((item) => item.id === event.target.value) ?? null)}
            className="rounded-2xl border border-line bg-abyss/80 px-4 py-3 text-sm"
          >
            <option value="">Select active case</option>
            {cases.map((item) => (
              <option key={item.id} value={item.id}>
                {item.name}
              </option>
            ))}
          </select>
          <p className="text-sm text-muted">
            {activeCase ? `Current workspace is focused on ${activeCase.name}. Findings, Search, Timeline, Process Graph and detections will default to this case.` : "No active case selected. Select or create a case to start the investigation workflow."}
          </p>
        </div>
      </section>

      {activeCase ? (
        <section className="grid gap-4 md:grid-cols-4">
          <Stat label="Indexed Events" value={formatEventCount(summaryQuery.data?.event_count_info?.count ?? summaryQuery.data?.total_events, summaryQuery.data?.event_count_info?.relation)} />
          <Stat label="Detections" value={summaryQuery.data?.counts.detections ?? 0} />
          <Stat label="Findings" value={summaryQuery.data?.counts.findings ?? 0} />
          <Stat label="High severity" value={summaryQuery.data?.suspicious_events ?? 0} />
        </section>
      ) : (
      <section className="grid gap-4 md:grid-cols-4">
        <Stat label="Open Cases" value={openCases} />
        <Stat label="Recent Evidences" value={cases.length ? "Ready" : "0"} />
        <Stat label="Indexed Events" value="via OpenSearch" />
        <Stat label="Open Findings" value="Track by case" />
      </section>
      )}

      {activeCase ? (
        <section className="rounded-[28px] border border-line bg-panel/70 p-6 shadow-panel">
          <p className="font-mono text-xs uppercase tracking-[0.18em] text-accent">Continue investigation</p>
          <p className="mt-2 text-sm text-muted">Search pagination is limited to the first 10,000 results by the OpenSearch result window. Total indexed events can be higher.</p>
          <div className="mt-4 flex flex-wrap gap-3">
            <Link to={`/cases/${activeCase.id}/overview`} className="rounded-2xl border border-line bg-abyss/80 px-4 py-2 text-sm text-muted">Open overview</Link>
            <Link to={`/cases/${activeCase.id}/search`} className="rounded-2xl border border-line bg-abyss/80 px-4 py-2 text-sm text-muted">Search case</Link>
            <Link to={`/cases/${activeCase.id}/artifact-search`} className="rounded-2xl border border-line bg-abyss/80 px-4 py-2 text-sm text-muted">Artifact Search</Link>
            <Link to={`/cases/${activeCase.id}/timeline`} className="rounded-2xl border border-line bg-abyss/80 px-4 py-2 text-sm text-muted">Search Timeline</Link>
            <Link to={`/cases/${activeCase.id}/process-graph`} className="rounded-2xl border border-line bg-abyss/80 px-4 py-2 text-sm text-muted">Process Graph</Link>
            <Link to={`/cases/${activeCase.id}/detections`} className="rounded-2xl border border-line bg-abyss/80 px-4 py-2 text-sm text-muted">Detections</Link>
            <Link to={`/cases/${activeCase.id}/findings`} className="rounded-2xl border border-line bg-abyss/80 px-4 py-2 text-sm text-muted">Findings</Link>
            <Link to={`/cases/${activeCase.id}/reports`} className="rounded-2xl border border-line bg-abyss/80 px-4 py-2 text-sm text-muted">Reports</Link>
          </div>
          <div className="mt-5 grid gap-3 md:grid-cols-2 xl:grid-cols-4">
            <div className="rounded-2xl border border-line bg-abyss/70 p-4 text-sm text-muted">Failed logons: {summaryQuery.data?.failed_logons ?? 0}</div>
            <div className="rounded-2xl border border-line bg-abyss/70 p-4 text-sm text-muted">Successful logons: {summaryQuery.data?.successful_logons ?? 0}</div>
            <div className="rounded-2xl border border-line bg-abyss/70 p-4 text-sm text-muted">Persistence: {(summaryQuery.data?.scheduled_task_events ?? 0) + (summaryQuery.data?.service_install_events ?? 0)}</div>
            <div className="rounded-2xl border border-line bg-abyss/70 p-4 text-sm text-muted">Deleted files: {summaryQuery.data?.deleted_files ?? 0}</div>
          </div>
        </section>
      ) : null}

      <section>
        <div className="mb-4 flex items-end justify-between">
          <div>
            <p className="font-mono text-xs uppercase tracking-[0.18em] text-accent">{activeCase ? "Available cases" : "Active Investigations"}</p>
            <h2 className="mt-2 text-2xl font-semibold">{activeCase ? "Switch investigation context or open another case" : "Open cases and recent activity"}</h2>
          </div>
        </div>
        <div className="grid gap-4 md:grid-cols-2 xl:grid-cols-3">
          {cases.map((item) => (
            <CaseCard key={item.id} item={item} />
          ))}
        </div>
      </section>
    </div>
  );
}
