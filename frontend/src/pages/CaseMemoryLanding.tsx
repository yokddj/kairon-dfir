import { useEffect } from "react";
import { Link, useNavigate, useParams } from "react-router-dom";
import { useQuery } from "@tanstack/react-query";
import { api } from "../api/client";
import { useActiveCase } from "../context/ActiveCaseContext";

function shortId(id: string): string {
  if (!id) return "";
  return id.length > 8 ? id.slice(0, 8) : id;
}

function familyStateBadge(state: string): { label: string; tone: "ok" | "warn" | "muted" | "danger" | "info" } {
  switch (state) {
    case "completed":
    case "ready":
      return { label: "Ready", tone: "ok" };
    case "running":
    case "pending":
      return { label: "Running", tone: "info" };
    case "latest_attempt_failed":
      return { label: "Latest attempt failed", tone: "warn" };
    case "unavailable":
      return { label: "Unavailable", tone: "muted" };
    case "not_analyzed":
      return { label: "Not analyzed", tone: "muted" };
    case "historical_override":
      return { label: "Historical result", tone: "info" };
    case "evidence_scope_required":
      return { label: "Evidence scope required", tone: "danger" };
    case "historical_override_invalid":
      return { label: "Historical result invalid", tone: "danger" };
    default:
      return { label: state, tone: "muted" };
  }
}

function toneClasses(tone: "ok" | "warn" | "muted" | "danger" | "info"): string {
  switch (tone) {
    case "ok":
      return "border-emerald-400/30 bg-emerald-500/10 text-emerald-100";
    case "warn":
      return "border-amber-400/30 bg-amber-500/10 text-amber-100";
    case "danger":
      return "border-rose-400/30 bg-rose-500/10 text-rose-100";
    case "info":
      return "border-sky-400/30 bg-sky-500/10 text-sky-100";
    default:
      return "border-line bg-abyss/70 text-muted";
  }
}

function sizeLabel(bytes: number): string {
  if (!bytes) return "0 B";
  if (bytes >= 1024 ** 3) return `${(bytes / 1024 ** 3).toFixed(2)} GiB`;
  if (bytes >= 1024 ** 2) return `${(bytes / 1024 ** 2).toFixed(2)} MiB`;
  if (bytes >= 1024) return `${(bytes / 1024).toFixed(2)} KiB`;
  return `${bytes} B`;
}

export default function CaseMemoryLanding() {
  const { caseId = "" } = useParams();
  const navigate = useNavigate();
  const { setActiveCaseId } = useActiveCase();

  useEffect(() => {
    setActiveCaseId(caseId);
  }, [caseId, setActiveCaseId]);

  const overviewQuery = useQuery({
    queryKey: ["memory-overview", caseId],
    queryFn: () => api.getMemoryOverview(caseId),
    enabled: Boolean(caseId),
    refetchOnWindowFocus: false,
  });

  const landingQuery = useQuery({
    queryKey: ["memory-landing", caseId],
    queryFn: () => api.getMemoryEvidenceLanding(caseId),
    enabled: Boolean(caseId),
    refetchOnWindowFocus: false,
  });

  const overview = overviewQuery.data;
  const landing = landingQuery.data;

  useEffect(() => {
    if (!overview) return;
    if (overview.evidences.length === 1) {
      navigate(`/cases/${caseId}/memory/${overview.evidences[0].id}`, { replace: true });
    }
  }, [overview, navigate, caseId]);

  if (overviewQuery.isLoading) {
    return (
      <div className="rounded-[28px] border border-line bg-panel/70 p-8 text-sm text-muted shadow-panel" data-testid="memory-landing-loading">
        Loading memory evidence...
      </div>
    );
  }

  if (overviewQuery.error instanceof Error) {
    return (
      <div className="rounded-[28px] border border-rose-400/30 bg-rose-500/10 p-8 text-sm text-rose-100 shadow-panel">
        {overviewQuery.error.message}
      </div>
    );
  }

  if (!overview || overview.evidences.length === 0) {
    return (
      <div className="space-y-4">
        <div className="rounded-[28px] border border-line bg-panel/70 p-8 text-sm text-muted shadow-panel">
          <p className="font-mono text-xs uppercase tracking-[0.24em] text-accent">Memory Analysis</p>
          <h2 className="mt-2 text-3xl font-semibold">No memory evidence in this case</h2>
          <p className="mt-2 max-w-3xl text-sm text-muted">
            Register authorized RAM evidence to enable isolated memory analysis. The workspace will appear here as soon as an
            image has been uploaded and ingested.
          </p>
          <div className="mt-4 flex flex-wrap gap-2">
            <Link to={`/cases/${caseId}/memory/upload`} className="rounded-xl bg-accent px-3 py-2 text-xs font-semibold text-abyss">
              Add memory image
            </Link>
            <Link to={`/cases/${caseId}/evidence`} className="rounded-xl border border-line bg-abyss/70 px-3 py-2 text-xs text-muted">
              Evidence &amp; Ingest
            </Link>
          </div>
        </div>
      </div>
    );
  }

  const items = landing?.items || [];

  return (
    <div className="space-y-6" data-testid="memory-landing">
      <section className="rounded-[28px] border border-line bg-panel/70 p-6 shadow-panel">
        <p className="font-mono text-xs uppercase tracking-[0.24em] text-accent">Memory Analysis</p>
        <div className="mt-2 flex flex-wrap items-start justify-between gap-4">
          <div>
            <h2 className="text-3xl font-semibold">Authorized RAM evidence</h2>
            <p className="mt-2 max-w-3xl text-sm text-muted">
              {items.length} memory {items.length === 1 ? "image" : "images"} registered for this case. Open one to see its
              isolated analysis. Each evidence is independent — process trees, modules and handles never cross-link.
            </p>
          </div>
          <div className="flex flex-wrap gap-2">
            <Link to={`/cases/${caseId}/memory/upload`} className="rounded-xl bg-accent px-3 py-2 text-xs font-semibold text-abyss">
              Add memory image
            </Link>
            <Link to={`/cases/${caseId}/evidence`} className="rounded-xl border border-line bg-abyss/70 px-3 py-2 text-xs text-muted">
              Evidence &amp; Ingest
            </Link>
          </div>
        </div>
      </section>

      <div className="grid gap-4 md:grid-cols-2" data-testid="memory-evidence-cards">
        {items.map((item) => {
          const familySummaries = item.families.filter((family) => family.family !== "raw_observations");
          const completedFamilies = familySummaries.filter((family) => family.state === "completed" || family.state === "ready");
          const unavailableFamilies = familySummaries.filter((family) => family.state === "unavailable");
          const failedFamilies = familySummaries.filter((family) => family.state === "latest_attempt_failed");
          return (
            <Link
              key={item.evidence_id}
              to={`/cases/${caseId}/memory/${item.evidence_id}`}
              data-testid="memory-evidence-card"
              data-evidence-id={item.evidence_id}
              className="block rounded-[28px] border border-line bg-panel/70 p-5 shadow-panel transition hover:border-accent"
            >
              <div className="flex flex-wrap items-start justify-between gap-3">
                <div className="min-w-0 flex-1">
                  <p className="truncate text-base font-semibold text-ink">{item.filename}</p>
                  <p className="mt-1 text-xs text-muted">
                    {item.detected_host || "Host unknown"} · {sizeLabel(item.size_bytes)} · <span className="font-mono">{shortId(item.evidence_id)}</span>
                  </p>
                </div>
                <span className="rounded-md border border-line bg-abyss/70 px-2 py-0.5 text-[10px] text-muted">
                  {item.run_count} {item.run_count === 1 ? "run" : "runs"}
                </span>
              </div>

              <div className="mt-4 grid grid-cols-3 gap-2 text-[10px]">
                <div className="rounded-md border border-line bg-abyss/70 p-2 text-muted">
                  <div className="text-[9px] uppercase tracking-wider">Completed</div>
                  <div className="mt-0.5 text-sm font-semibold text-ink">{completedFamilies.length}/{familySummaries.length - unavailableFamilies.length || 1}</div>
                </div>
                <div className="rounded-md border border-line bg-abyss/70 p-2 text-muted">
                  <div className="text-[9px] uppercase tracking-wider">Unavailable</div>
                  <div className="mt-0.5 text-sm font-semibold text-ink">{unavailableFamilies.length}</div>
                </div>
                <div className="rounded-md border border-line bg-abyss/70 p-2 text-muted">
                  <div className="text-[9px] uppercase tracking-wider">Failed</div>
                  <div className="mt-0.5 text-sm font-semibold text-ink">{failedFamilies.length}</div>
                </div>
              </div>

              <div className="mt-4 flex flex-wrap gap-1.5" data-testid="memory-evidence-families">
                {familySummaries.map((family) => {
                  const badge = familyStateBadge(family.state);
                  return (
                    <span
                      key={family.family}
                      className={`rounded-md border px-2 py-0.5 text-[10px] ${toneClasses(badge.tone)}`}
                      data-testid={`memory-evidence-family-${family.family}`}
                      data-family-state={family.state}
                    >
                      {family.title}: {badge.label}
                    </span>
                  );
                })}
              </div>
            </Link>
          );
        })}
      </div>
    </div>
  );
}
