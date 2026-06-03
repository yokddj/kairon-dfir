import { useEffect, useMemo, useState } from "react";
import { useQuery } from "@tanstack/react-query";
import { Link, useParams } from "react-router-dom";
import { api, type CaseNextAction } from "../api/client";
import { useActiveCase } from "../context/ActiveCaseContext";
import { compareValues, nextSortDirection, type SortDirection } from "../lib/sorting";

function Stat({ label, value }: { label: string; value: string | number }) {
  return (
    <div className="rounded-2xl border border-line bg-abyss/70 p-4">
      <p className="font-mono text-[11px] uppercase tracking-[0.16em] text-muted">{label}</p>
      <p className="mt-2 text-xl font-semibold text-ink">{value}</p>
    </div>
  );
}

function ActionLink({ action }: { action: CaseNextAction }) {
  const className =
    action.priority === "primary"
      ? "rounded-2xl border border-accent/40 bg-accent/10 px-4 py-3 text-sm text-accent"
      : "rounded-2xl border border-line bg-abyss/70 px-4 py-3 text-sm text-muted";
  if (!action.enabled) {
    return (
      <div className="rounded-2xl border border-line/70 bg-abyss/40 px-4 py-3 text-sm text-muted opacity-80">
        <p className="font-medium text-muted">{action.label}</p>
        {action.reason ? <p className="mt-1 text-xs leading-5 text-muted">{action.reason}</p> : null}
      </div>
    );
  }
  return (
    <Link to={action.href} className={className}>
      {action.label}
    </Link>
  );
}

function stateCopy(state: string | undefined) {
  if (state === "empty_case") {
    return {
      title: "Start a new investigation",
      subtitle: "Add evidence to begin indexing and analysis.",
    };
  }
  if (state === "evidence_uploaded_not_indexed") {
    return {
      title: "Evidence is ready to index",
      subtitle: "Run recommended indexing before searching, reviewing command history or building reports.",
    };
  }
  if (state === "indexing_in_progress") {
    return {
      title: "Indexing is in progress",
      subtitle: "Track progress from the evidence page. Investigation pivots become useful as indexed documents appear.",
    };
  }
  if (state === "report_ready") {
    return {
      title: "Report-ready investigation",
      subtitle: "Findings or official timeline items are available. Continue review or generate a report.",
    };
  }
  if (state === "investigation_in_progress") {
    return {
      title: "Continue the investigation",
      subtitle: "Reviewed findings, timeline candidates or marked events exist. Continue curation and reporting.",
    };
  }
  return {
    title: "Investigation-ready case",
    subtitle: "Start from Search, Command History, artifacts and Incident Timeline. Add more evidence any time.",
  };
}

export default function CaseOverviewPage() {
  const { caseId = "" } = useParams();
  const { setActiveCaseId, setSelectedHost, setSelectedEvidenceId } = useActiveCase();
  const caseContextQuery = useQuery({
    queryKey: ["case-context", caseId],
    queryFn: () => api.getCaseContext(caseId),
    enabled: Boolean(caseId),
    staleTime: 15_000,
    refetchOnWindowFocus: false,
  });
  const contextPreview = caseContextQuery.data ?? null;
  const investigationStatePreview = contextPreview?.summary?.investigation_state;
  const shouldLoadInvestigationData = Boolean(caseId && (investigationStatePreview?.indexed_docs ?? 0) > 0);
  const findingsQuery = useQuery({
    queryKey: ["findings", caseId, "overview"],
    queryFn: () => api.listFindings(caseId),
    enabled: shouldLoadInvestigationData,
    staleTime: 10_000,
    refetchOnWindowFocus: false,
  });
  const timelineQuery = useQuery({
    queryKey: ["incident-timeline-draft", caseId, "overview"],
    queryFn: () => api.getIncidentTimelineDraft(caseId, { max_items: 80 }),
    enabled: shouldLoadInvestigationData,
    staleTime: 30_000,
    refetchOnWindowFocus: false,
  });
  useEffect(() => {
    if (caseId) setActiveCaseId(caseId);
  }, [caseId, setActiveCaseId]);
  const [hostsSortKey, setHostsSortKey] = useState<"display_name" | "event_count" | "findings_count" | "high_risk_count">("event_count");
  const [hostsSortDirection, setHostsSortDirection] = useState<SortDirection>("desc");
  const context = caseContextQuery.data ?? null;
  const investigationState = context?.summary.investigation_state;
  const currentState = investigationState?.state ?? "investigation_ready";
  const copy = stateCopy(currentState);
  const nextActions = context?.summary.next_actions ?? { primary: [], secondary: [], unavailable: [] };
  const findings = findingsQuery.data ?? [];
  const sortedHosts = useMemo(
    () => [...(context?.hosts ?? [])].sort((left, right) => compareValues(left[hostsSortKey], right[hostsSortKey], hostsSortDirection)),
    [context?.hosts, hostsSortDirection, hostsSortKey],
  );
  const topFindings = [...findings]
    .sort((left, right) => (right.risk_score ?? 0) - (left.risk_score ?? 0))
    .slice(0, 5);
  const readyEvidence = context?.evidences.filter((evidence) => evidence.status === "completed" || evidence.status === "completed_with_warnings").length ?? 0;
  const hostNames = (context?.hosts ?? []).map((host) => host.display_name || host.canonical_name).filter(Boolean);
  const validationVisibility = context?.summary?.validation_matrix;
  const showValidationMatrix = Boolean(validationVisibility?.show_validation_matrix);
  const timelineItems = timelineQuery.data?.items ?? [];
  const officialTimelineCount = investigationState?.official_timeline_count ?? timelineItems.filter((item) => item.status === "accepted").length;
  const candidateTimelineCount = investigationState?.candidate_timeline_count ?? timelineItems.filter((item) => item.status === "candidate").length;
  const timelineNeedsReviewCount = investigationState?.timeline_needs_review_count ?? timelineItems.filter((item) => item.status === "needs_review").length;

  if (!caseId) {
    return <div className="rounded-[28px] border border-line bg-panel/70 p-8 shadow-panel text-sm text-muted">Select a case to open the workspace overview.</div>;
  }

  if (caseContextQuery.isPending) {
    return <div className="rounded-[28px] border border-line bg-panel/70 p-8 shadow-panel text-sm text-muted">Loading case context…</div>;
  }

  if (caseContextQuery.error instanceof Error) {
    return <div className="rounded-[28px] border border-danger/40 bg-danger/10 p-8 text-sm text-danger shadow-panel">{caseContextQuery.error.message}</div>;
  }

  if (!context) {
    return <div className="rounded-[28px] border border-line bg-panel/70 p-8 shadow-panel text-sm text-muted">Case context is not available yet.</div>;
  }

  function handleHostsSort(key: "display_name" | "event_count" | "findings_count" | "high_risk_count") {
    setHostsSortDirection((current) => nextSortDirection(hostsSortKey, current, key));
    setHostsSortKey(key);
  }

  return (
    <div className="space-y-6">
      <section className="rounded-[28px] border border-line bg-panel/70 p-6 shadow-panel">
        <p className="font-mono text-xs uppercase tracking-[0.24em] text-accent">Case Investigation Home</p>
        <h2 className="mt-2 text-3xl font-semibold">{copy.title}</h2>
        <p className="mt-1 text-lg text-ink">{context.case.name}</p>
        <p className="mt-2 max-w-3xl text-sm text-muted">
          {copy.subtitle}
        </p>
        <div className="mt-4 flex flex-wrap gap-2 text-xs text-muted">
          <span className="rounded-full border border-line bg-abyss/70 px-3 py-1">Investigation-ready evidence: {readyEvidence}/{context.evidences.length}</span>
          <span className="rounded-full border border-line bg-abyss/70 px-3 py-1">State: {currentState.replaceAll("_", " ")}</span>
          {investigationState ? <span className="rounded-full border border-line bg-abyss/70 px-3 py-1">Active jobs: {investigationState.active_job_count}</span> : null}
          {hostNames.length ? <span className="rounded-full border border-line bg-abyss/70 px-3 py-1">Hosts: {hostNames.join(", ")}</span> : null}
          {validationVisibility && validationVisibility.mode !== "investigation" ? <span className="rounded-full border border-accent/40 bg-accent/10 px-3 py-1 text-accent">{validationVisibility.label}</span> : null}
        </div>
        {showValidationMatrix && currentState === "empty_case" ? (
          <div className="mt-4 rounded-2xl border border-accent/30 bg-accent/10 px-4 py-3 text-sm text-accent">
            Demo metadata is available, but evidence must be uploaded/indexed to activate pivots.
          </div>
        ) : null}
      </section>

      <section className="grid gap-4 md:grid-cols-3 xl:grid-cols-6">
        <Stat label="Evidence" value={context.evidences.length} />
        <Stat label="Events indexed" value={context.summary.events_indexed.toLocaleString()} />
        <Stat label="Findings" value={context.summary.findings_total} />
        <Stat label="High findings" value={context.summary.findings_high} />
        <Stat label="Parser errors" value={context.summary.parser_errors} />
        <Stat label="Warnings" value={context.summary.warnings.length} />
      </section>

      <section className="grid gap-6 xl:grid-cols-[1.2fr_1fr]">
        <div className="rounded-[28px] border border-line bg-panel/70 p-6 shadow-panel">
          <div className="flex items-center justify-between gap-3">
            <div>
              <p className="font-mono text-xs uppercase tracking-[0.18em] text-accent">Host Identity</p>
              <p className="mt-2 text-sm text-muted">Canonical hosts collapse historical names and aliases without removing the originally observed host values.</p>
            </div>
            <Link to={`/cases/${caseId}/hosts`} className="rounded-xl border border-line bg-abyss/70 px-3 py-1.5 text-xs text-muted">Manage hosts</Link>
          </div>
          <div className="mt-4 overflow-hidden rounded-2xl border border-line">
            <table className="w-full text-sm">
              <thead className="bg-abyss/80 font-mono text-[11px] uppercase tracking-[0.16em] text-muted">
                <tr>
                  <th className="px-4 py-3 text-left"><button type="button" onClick={() => handleHostsSort("display_name")} className="inline-flex items-center gap-2">Canonical host {hostsSortKey === "display_name" ? (hostsSortDirection === "asc" ? "↑" : "↓") : ""}</button></th>
                  <th className="px-4 py-3 text-left">Aliases</th>
                  <th className="px-4 py-3 text-left"><button type="button" onClick={() => handleHostsSort("event_count")} className="inline-flex items-center gap-2">Events {hostsSortKey === "event_count" ? (hostsSortDirection === "asc" ? "↑" : "↓") : ""}</button></th>
                  <th className="px-4 py-3 text-left"><button type="button" onClick={() => handleHostsSort("findings_count")} className="inline-flex items-center gap-2">Findings {hostsSortKey === "findings_count" ? (hostsSortDirection === "asc" ? "↑" : "↓") : ""}</button></th>
                  <th className="px-4 py-3 text-left"><button type="button" onClick={() => handleHostsSort("high_risk_count")} className="inline-flex items-center gap-2">High risk {hostsSortKey === "high_risk_count" ? (hostsSortDirection === "asc" ? "↑" : "↓") : ""}</button></th>
                  <th className="px-4 py-3 text-left">Action</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-line/60">
                {sortedHosts.map((host) => (
                  <tr key={host.id}>
                    <td className="px-4 py-3">
                      <div>{host.display_name}</div>
                      <div className="mt-1 text-xs text-muted">{host.confidence} · {host.source}</div>
                    </td>
                    <td className="px-4 py-3">
                      {host.aliases.length ? host.aliases.join(", ") : "No aliases"}
                    </td>
                    <td className="px-4 py-3">{host.event_count.toLocaleString()}</td>
                    <td className="px-4 py-3">{host.findings_count}</td>
                    <td className="px-4 py-3">{host.high_risk_count}</td>
                    <td className="px-4 py-3">
                      <button
                        type="button"
                        onClick={() => {
                          setSelectedHost(host.canonical_name);
                          setSelectedEvidenceId("");
                        }}
                        className="rounded-xl border border-line bg-abyss/70 px-3 py-1.5 text-xs text-muted"
                      >
                        Set host filter
                      </button>
                    </td>
                  </tr>
                ))}
                {!context.hosts.length ? (
                  <tr>
                    <td colSpan={6} className="px-4 py-4 text-muted">No host pivots detected yet.</td>
                  </tr>
                ) : null}
              </tbody>
            </table>
          </div>
        </div>

        <div className="rounded-[28px] border border-line bg-panel/70 p-6 shadow-panel">
          <p className="font-mono text-xs uppercase tracking-[0.18em] text-accent">Next actions</p>
          <p className="mt-2 text-sm text-muted">Actions are based on the current case state. Advanced routes remain available from the sidebar.</p>
          <div className="mt-4 grid gap-3">
            {[...nextActions.primary, ...nextActions.secondary].map((action) => (
              <ActionLink key={`${action.priority}-${action.id}`} action={action} />
            ))}
            <div className="rounded-2xl border border-line bg-abyss/60 px-4 py-3 text-sm text-muted">
              <p className="font-medium text-ink">Incident Timeline status</p>
              <p className="mt-1 text-xs">Official: {officialTimelineCount} · Candidates: {candidateTimelineCount} · Needs review: {timelineNeedsReviewCount}</p>
            </div>
            {nextActions.unavailable.length ? (
              <div className="rounded-2xl border border-line bg-abyss/50 p-3">
                <p className="text-xs font-semibold uppercase tracking-[0.16em] text-muted">Unavailable until ready</p>
                <div className="mt-3 grid gap-2">
                  {nextActions.unavailable.map((action) => (
                    <ActionLink key={`unavailable-${action.id}`} action={action} />
                  ))}
                </div>
              </div>
            ) : null}
            {showValidationMatrix ? <Link to={`/cases/${caseId}/validation-matrix`} className="rounded-2xl border border-accent/40 bg-accent/10 px-4 py-3 text-sm text-accent">Review Validation Matrix</Link> : null}
            {showValidationMatrix ? <Link to="/docs/generic-demo-guide" className="rounded-2xl border border-line bg-abyss/70 px-4 py-3 text-sm text-muted">Open Demo Guide</Link> : null}
            {showValidationMatrix ? <Link to="/docs/validation-matrix-format" className="rounded-2xl border border-line bg-abyss/70 px-4 py-3 text-sm text-muted">Open Validation Format</Link> : null}
          </div>
          <details className="mt-4 rounded-2xl border border-line bg-abyss/50 p-3 text-sm text-muted">
            <summary className="cursor-pointer text-ink">Known limitations for this case</summary>
            <ul className="mt-2 list-disc space-y-1 pl-5">
              <li>Memory-only steps require memory evidence and are tracked separately.</li>
              <li>SRUM requires a Windows parser worker.</li>
              <li>Advanced EZ rebuilds are optional comparison views, not the default workflow.</li>
            </ul>
          </details>
        </div>
      </section>

      <section className="grid gap-6 xl:grid-cols-[1.2fr_1fr]">
        <div className="rounded-[28px] border border-line bg-panel/70 p-6 shadow-panel">
          <p className="font-mono text-xs uppercase tracking-[0.18em] text-accent">Evidence summary</p>
          <div className="mt-4 space-y-3">
            {context.evidences.map((evidence) => (
              <div key={evidence.id} className="rounded-2xl border border-line bg-abyss/60 p-4">
                <div className="flex flex-wrap items-center justify-between gap-3">
                  <div className="min-w-0 flex-1">
                    <p className="truncate text-sm font-semibold">{evidence.name}</p>
                    <p className="mt-1 text-xs text-muted">
                      {evidence.storage_mode} · {evidence.is_external ? "external" : "internal"} · {evidence.events_indexed.toLocaleString()} events
                    </p>
                  </div>
                  <div className="flex flex-wrap gap-2">
                    <span className="rounded-full border border-line px-3 py-1 font-mono text-[10px] uppercase tracking-[0.14em] text-accent">{evidence.status}</span>
                    <button
                      type="button"
                      onClick={() => {
                        setSelectedEvidenceId(evidence.id);
                        if (evidence.detected_host) setSelectedHost(evidence.detected_host);
                      }}
                      className="rounded-xl border border-line bg-panel/40 px-3 py-1.5 text-xs text-muted"
                    >
                      Filter to evidence
                    </button>
                    <Link to={`/evidences/${evidence.id}`} className="rounded-xl border border-line bg-panel/40 px-3 py-1.5 text-xs text-muted">
                      Open
                    </Link>
                  </div>
                </div>
              </div>
            ))}
            {!context.evidences.length ? <p className="text-sm text-muted">No evidence yet. Add evidence to start processing this case.</p> : null}
          </div>
        </div>

        <div className="rounded-[28px] border border-line bg-panel/70 p-6 shadow-panel">
          <div className="flex items-center justify-between gap-3">
            <div>
              <p className="font-mono text-xs uppercase tracking-[0.18em] text-accent">Top findings</p>
              <p className="mt-2 text-sm text-muted">Use findings as the entry point for analyst triage.</p>
            </div>
            <Link to={`/cases/${caseId}/findings`} className="rounded-xl border border-line bg-abyss/70 px-3 py-1.5 text-xs text-muted">
              Open findings
            </Link>
          </div>
          <div className="mt-4 space-y-3">
            {topFindings.map((finding) => (
              <div key={finding.id} className="rounded-2xl border border-line bg-abyss/60 p-4">
                <div className="flex flex-wrap items-center justify-between gap-3">
                  <p className="text-sm font-semibold">{finding.title}</p>
                  <span className="rounded-full border border-line px-3 py-1 font-mono text-[10px] uppercase tracking-[0.14em] text-accent">
                    {finding.severity}
                  </span>
                </div>
                <p className="mt-2 text-sm text-muted">{finding.summary || finding.description || "No summary available."}</p>
              </div>
            ))}
            {!topFindings.length ? <p className="text-sm text-muted">No findings yet. Run correlation from Findings to generate investigation leads.</p> : null}
          </div>
        </div>
      </section>
    </div>
  );
}
