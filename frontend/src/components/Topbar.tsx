import { useQuery } from "@tanstack/react-query";
import { Link, useLocation, useNavigate } from "react-router-dom";
import { API_BASE_URL } from "../api/client";
import { api } from "../api/client";
import { useActiveCase } from "../context/ActiveCaseContext";
import { useTimezonePreference } from "../context/TimezoneContext";

function formatEvidenceStatus(status: string) {
  if (!status) return "unknown";
  return status.replaceAll("_", " ");
}

export default function Topbar() {
  const navigate = useNavigate();
  const location = useLocation();
  const {
    activeCase,
    activeCaseId,
    caseContext,
    isCaseContextLoading,
    selectedEvidenceId,
    selectedHost,
    setActiveCase,
    clearActiveCase,
    setSelectedHost,
    clearSelectedHost,
    setSelectedEvidenceId,
    clearSelectedEvidenceId,
  } = useActiveCase();
  const { timezoneMode, setTimezoneMode, effectiveTimezone, userTimezone } = useTimezonePreference();
  const { data: cases } = useQuery({ queryKey: ["cases"], queryFn: api.listCases });
  const now = new Intl.DateTimeFormat(undefined, {
    timeZone: effectiveTimezone,
    year: "numeric",
    month: "2-digit",
    day: "2-digit",
    hour: "2-digit",
    minute: "2-digit",
    second: "2-digit",
  }).format(new Date());

  const selectedEvidence = caseContext?.evidences.find((item) => item.id === selectedEvidenceId) ?? null;
  const selectedHostSummary = caseContext?.hosts.find((item) => item.canonical_name === selectedHost) ?? null;
  const warnings = caseContext?.summary.warnings ?? [];

  function handleCaseChange(caseId: string) {
    const nextCase = (cases ?? []).find((item) => item.id === caseId) ?? null;
    setActiveCase(nextCase);
    if (nextCase) {
      navigate(`/cases/${nextCase.id}/overview`);
      return;
    }
    navigate("/cases");
  }

  return (
    <header className="overflow-x-hidden border-b border-line/80 bg-panel/30 px-4 py-4 backdrop-blur md:px-6">
      <div className="flex min-w-0 flex-wrap items-start justify-between gap-4">
        <div className="min-w-0">
          <p className="font-mono text-xs uppercase tracking-[0.32em] text-accent">Kairon DFIR</p>
          <h1 className="mt-1 text-lg font-semibold text-ink">Evidence Console</h1>
          <p className="mt-2 text-xs text-muted">
            {activeCase ? `Case: ${activeCase.name}` : "No active case selected"} · Timezone: {effectiveTimezone}
          </p>
        </div>
        <div className="flex min-w-0 max-w-full flex-wrap items-center justify-end gap-2">
          <label className="block">
            <span className="sr-only">Active case</span>
            <select
              aria-label="Active case"
              value={activeCaseId}
              onChange={(event) => handleCaseChange(event.target.value)}
              className="rounded-full border border-line bg-abyss/80 px-4 py-2 text-xs text-muted"
            >
              <option value="">Case: Select case</option>
              {(cases ?? []).map((item) => (
                <option key={item.id} value={item.id}>
                  {item.name}
                </option>
              ))}
            </select>
          </label>
          <label className="block">
            <span className="sr-only">Host filter</span>
            <select
              aria-label="Host filter"
              value={selectedHost}
              disabled={!activeCaseId || isCaseContextLoading}
              onChange={(event) => {
                if (!event.target.value) clearSelectedHost();
                else setSelectedHost(event.target.value);
              }}
              className="rounded-full border border-line bg-abyss/80 px-4 py-2 text-xs text-muted disabled:opacity-50"
            >
              <option value="">Host: All hosts</option>
              {(caseContext?.hosts ?? []).map((item) => (
                <option key={item.id} value={item.canonical_name}>
                  {`${item.display_name} · ${item.event_count} events · ${item.alias_count} aliases`}
                </option>
              ))}
            </select>
          </label>
          <label className="block">
            <span className="sr-only">Evidence filter</span>
            <select
              aria-label="Evidence filter"
              value={selectedEvidenceId}
              disabled={!activeCaseId || isCaseContextLoading}
              onChange={(event) => {
                if (!event.target.value) clearSelectedEvidenceId();
                else setSelectedEvidenceId(event.target.value);
              }}
              className="max-w-[240px] rounded-full border border-line bg-abyss/80 px-4 py-2 text-xs text-muted disabled:opacity-50"
            >
              <option value="">Evidence: All evidence</option>
              {(caseContext?.evidences ?? []).map((item) => (
                <option key={item.id} value={item.id}>
                  {`${item.name} · ${formatEvidenceStatus(item.status)}`}
                </option>
              ))}
            </select>
          </label>
          <button
            onClick={() => {
              clearActiveCase();
              navigate("/cases");
            }}
            className="rounded-full border border-line bg-abyss/80 px-4 py-2 font-mono text-[11px] text-muted"
          >
            Clear case
          </button>
          <select value={timezoneMode} onChange={(event) => setTimezoneMode(event.target.value as "user" | "case" | "utc")} className="rounded-full border border-line bg-abyss/80 px-4 py-2 text-xs text-muted">
            <option value="user">TZ: User ({userTimezone})</option>
            <option value="case">TZ: Case</option>
            <option value="utc">TZ: UTC</option>
          </select>
          <div className="hidden max-w-[320px] truncate rounded-full border border-line bg-abyss/80 px-4 py-2 font-mono text-[11px] text-muted xl:block">
            API {API_BASE_URL}
          </div>
          {warnings.length ? (
            <div className="rounded-full border border-warning/40 bg-warning/10 px-4 py-2 font-mono text-[11px] text-warning">
              {warnings[0]}
            </div>
          ) : null}
          <div className="rounded-full border border-line bg-abyss/80 px-4 py-2 font-mono text-xs text-muted">{now}</div>
        </div>
      </div>

      <div className="mt-4 flex min-w-0 flex-wrap items-center gap-2 text-xs text-muted">
        {activeCase ? (
          <>
            <Link className="rounded-full border border-line bg-abyss/70 px-3 py-1.5" to={`/cases/${activeCase.id}/overview`}>
              Overview
            </Link>
            <span className="rounded-full border border-line bg-abyss/70 px-3 py-1.5">
              {selectedHostSummary ? `Host: ${selectedHostSummary.display_name}${selectedHostSummary.alias_count ? ` · includes ${selectedHostSummary.alias_count} aliases` : ""}` : "Host: All hosts"}
            </span>
            <span className="max-w-[280px] truncate rounded-full border border-line bg-abyss/70 px-3 py-1.5">
              {selectedEvidence ? `Evidence: ${selectedEvidence.name}` : "Evidence: All evidence"}
            </span>
          </>
        ) : (
          <div className="rounded-full border border-line bg-abyss/70 px-3 py-1.5">
            No active case selected. Select or create a case to start investigating.
          </div>
        )}
        {location.pathname === "/" && activeCase ? (
          <button type="button" onClick={() => navigate(`/cases/${activeCase.id}/overview`)} className="rounded-full border border-accent/30 bg-accent/8 px-3 py-1.5 text-accent">
            Open active case workspace
          </button>
        ) : null}
      </div>
    </header>
  );
}
