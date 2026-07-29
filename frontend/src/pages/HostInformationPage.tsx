import { useEffect, useMemo } from "react";
import { useQuery } from "@tanstack/react-query";
import { Link, useParams, useSearchParams } from "react-router-dom";
import { Fingerprint } from "lucide-react";

import { api, type HostFactObservation, type ResolvedHostFact } from "../api/client";
import { useActiveCase } from "../context/ActiveCaseContext";

type FactSlot = { factType: string; label: string };
type FactGroup = { id: string; title: string; slots: FactSlot[] };

// The complete MVP scope, in display order. A slot with no matching entry
// in the API response renders as "Not collected" -- Host Facts represent
// observations, so a fact Kairon never observed is shown as missing, never
// fabricated or silently omitted.
const FACT_GROUPS: FactGroup[] = [
  {
    id: "identity",
    title: "Identity",
    slots: [
      { factType: "host.hostname", label: "Hostname" },
      { factType: "host.fqdn", label: "FQDN" },
    ],
  },
  {
    id: "os",
    title: "Operating System",
    slots: [
      { factType: "host.distribution", label: "Distribution" },
      { factType: "host.distribution_version", label: "Version" },
    ],
  },
  {
    id: "platform",
    title: "Platform",
    slots: [
      { factType: "host.kernel", label: "Kernel" },
      { factType: "host.architecture", label: "Architecture" },
    ],
  },
  {
    id: "time",
    title: "Time",
    slots: [{ factType: "host.timezone", label: "Timezone" }],
  },
];

const STATUS_LABEL: Record<string, string> = {
  confirmed: "Confirmed",
  observed: "Observed",
  conflicting: "Conflicting",
  invalid: "Invalid",
  missing: "Not collected",
};

const STATUS_STYLES: Record<string, string> = {
  confirmed: "border-mint/40 bg-mint/10 text-mint",
  observed: "border-sky-400/30 bg-sky-400/10 text-sky-200",
  conflicting: "border-amber/40 bg-amber/10 text-amber",
  invalid: "border-danger/40 bg-danger/10 text-danger",
  missing: "border-line bg-abyss/40 text-muted",
};

const CONFIDENCE_STYLES: Record<string, string> = {
  high: "text-mint",
  medium: "text-amber",
  low: "text-muted",
};

function fmtTime(value?: string | null): string {
  if (!value) return "-";
  const date = new Date(value);
  return Number.isNaN(date.getTime()) ? value : date.toLocaleString();
}

function searchHref(caseId: string, hostId: string, query?: string | null): string {
  const params = new URLSearchParams({ host_id: hostId });
  if (query) params.set("q", query);
  return `/cases/${caseId}/search?${params.toString()}`;
}

function artifactHref(caseId: string, query?: string | null): string {
  const params = new URLSearchParams();
  if (query) params.set("q", query);
  return `/cases/${caseId}/artifacts${params.size ? `?${params.toString()}` : ""}`;
}

function ObservationCard({ caseId, kind, observation }: { caseId: string; kind: "supporting" | "conflicting" | "invalid"; observation: HostFactObservation }) {
  const kindLabel = kind === "supporting" ? "Agrees" : kind === "conflicting" ? "Conflicts" : "Invalid";
  const kindStyle = kind === "conflicting" ? "border-amber/40 text-amber" : kind === "invalid" ? "border-danger/40 text-danger" : "border-mint/30 text-mint";
  const displayValue = observation.normalized_value || observation.raw_value || "(no value)";
  return (
    <div className="rounded-xl border border-line/70 bg-abyss/40 px-3 py-2.5 text-xs text-muted" data-testid="fact-observation" data-kind={kind}>
      <div className="flex flex-wrap items-center justify-between gap-2">
        <span className={`rounded-full border px-2 py-0.5 text-[10px] uppercase tracking-[0.12em] ${kindStyle}`}>{kindLabel}</span>
        <span className="font-semibold text-ink">{displayValue}</span>
      </div>
      <p className="mt-1.5">
        <span className="text-ink">{observation.source_kind}</span> &middot; parser <span className="text-ink">{observation.parser}</span>
        {observation.source_path ? (
          <>
            {" "}
            &middot; <span className="text-ink">{observation.source_path}</span>
          </>
        ) : null}
      </p>
      <p className="mt-1">Confidence: <span className={CONFIDENCE_STYLES[observation.confidence] || "text-muted"}>{observation.confidence}</span> &middot; observed {fmtTime(observation.observed_at)}</p>
      <div className="mt-2 flex flex-wrap gap-2">
        <Link to={searchHref(caseId, observation.host_id || "", displayValue)} className="rounded-lg border border-line px-2 py-1 text-[11px] text-accent hover:bg-white/5" data-testid="pivot-search">
          View in Search
        </Link>
        {observation.source_path ? (
          <Link to={artifactHref(caseId, observation.source_path)} className="rounded-lg border border-line px-2 py-1 text-[11px] text-accent hover:bg-white/5" data-testid="pivot-artifact">
            View artifact
          </Link>
        ) : null}
      </div>
    </div>
  );
}

function FactRow({ caseId, hostId, label, fact }: { caseId: string; hostId: string; label: string; fact: ResolvedHostFact | null }) {
  const status = fact?.status ?? "missing";
  const preferredValue = fact?.preferred_value ?? null;
  const observationCount = fact?.observations.length ?? 0;
  const hasProvenance = observationCount > 0;

  return (
    <details className="group rounded-2xl border border-line bg-abyss/70 open:bg-abyss/80" data-testid="fact-row" data-fact-type={fact?.fact_type} data-status={status}>
      <summary className="flex cursor-pointer list-none flex-wrap items-center gap-3 px-4 py-3 [&::-webkit-details-marker]:hidden">
        <span className="w-32 shrink-0 text-xs uppercase tracking-[0.14em] text-muted">{label}</span>
        {preferredValue ? (
          <Link
            to={searchHref(caseId, hostId, preferredValue)}
            onClick={(event) => event.stopPropagation()}
            className="min-w-0 flex-1 truncate text-lg font-semibold text-ink hover:text-accent"
            data-testid="fact-preferred-value"
          >
            {preferredValue}
          </Link>
        ) : (
          <span className="min-w-0 flex-1 truncate text-lg font-semibold italic text-muted/70" data-testid="fact-missing-value">
            Not collected
          </span>
        )}
        <span className={`shrink-0 rounded-full border px-2.5 py-1 text-[10px] font-semibold uppercase tracking-[0.12em] ${STATUS_STYLES[status]}`} data-testid="fact-status">
          {STATUS_LABEL[status] || status}
        </span>
        {fact?.observations[0]?.confidence ? (
          <span className={`shrink-0 text-xs ${CONFIDENCE_STYLES[fact.observations[0].confidence] || "text-muted"}`}>{fact.observations[0].confidence} confidence</span>
        ) : null}
        <span className="shrink-0 text-xs text-muted">
          {observationCount} observation{observationCount === 1 ? "" : "s"}
        </span>
        {hasProvenance ? <span className="shrink-0 text-xs text-accent group-open:hidden">Show sources</span> : null}
        {hasProvenance ? <span className="hidden shrink-0 text-xs text-accent group-open:inline">Hide sources</span> : null}
      </summary>
      {hasProvenance ? (
        <div className="space-y-2 border-t border-line/70 px-4 py-3" data-testid="fact-provenance">
          {status === "conflicting" ? (
            <p className="text-xs text-amber">
              Sources disagree. The preferred value above is chosen by source reliability, not by majority alone -- every observation below is preserved so you can judge for yourself.
            </p>
          ) : null}
          {fact!.supporting.map((observation) => (
            <ObservationCard key={observation.id} caseId={caseId} kind="supporting" observation={observation} />
          ))}
          {fact!.conflicting.map((observation) => (
            <ObservationCard key={observation.id} caseId={caseId} kind="conflicting" observation={observation} />
          ))}
          {fact!.invalid.map((observation) => (
            <ObservationCard key={observation.id} caseId={caseId} kind="invalid" observation={observation} />
          ))}
        </div>
      ) : null}
    </details>
  );
}

function FactGroupCard({ caseId, hostId, group, factsByType }: { caseId: string; hostId: string; group: FactGroup; factsByType: Map<string, ResolvedHostFact> }) {
  return (
    <section className="rounded-[28px] border border-line bg-panel/70 p-6 shadow-panel">
      <p className="font-mono text-xs uppercase tracking-[0.18em] text-accent">{group.title}</p>
      <div className="mt-4 space-y-2">
        {group.slots.map((slot) => (
          <FactRow key={slot.factType} caseId={caseId} hostId={hostId} label={slot.label} fact={factsByType.get(slot.factType) ?? null} />
        ))}
      </div>
    </section>
  );
}

export default function HostInformationPage() {
  const { caseId = "" } = useParams();
  const { setActiveCaseId, caseContext, isCaseContextLoading } = useActiveCase();
  const [searchParams, setSearchParams] = useSearchParams();
  const selectedHostId = searchParams.get("host_id") || "";

  useEffect(() => {
    if (caseId) setActiveCaseId(caseId);
  }, [caseId, setActiveCaseId]);

  const hosts = useMemo(() => caseContext?.hosts ?? [], [caseContext]);

  // A single-host case never makes the analyst pick -- the selector only
  // appears once there is a real choice to make (never assume which host
  // in a multi-host case, but never force a needless click in the common
  // single-host case either).
  useEffect(() => {
    if (!selectedHostId && hosts.length === 1) {
      const next = new URLSearchParams(searchParams);
      next.set("host_id", hosts[0].id);
      setSearchParams(next, { replace: true });
    }
  }, [hosts, selectedHostId, searchParams, setSearchParams]);

  const factsQuery = useQuery({
    queryKey: ["case-host-facts", caseId, selectedHostId],
    queryFn: () => api.getCaseHostFacts(caseId, { host_id: selectedHostId }),
    enabled: Boolean(caseId && selectedHostId),
    refetchOnWindowFocus: false,
    // Host Facts only change when new evidence is ingested, not on every
    // remount -- a real staleTime is what actually stops a background
    // refetch when toggling back to a previously-viewed host.
    staleTime: 60_000,
  });

  const factsByType = useMemo(() => {
    const map = new Map<string, ResolvedHostFact>();
    for (const fact of factsQuery.data?.facts ?? []) map.set(fact.fact_type, fact);
    return map;
  }, [factsQuery.data]);

  const selectedHost = hosts.find((host) => host.id === selectedHostId) ?? null;

  if (!caseId) {
    return <div className="rounded-[28px] border border-line bg-panel/70 p-8 text-sm text-muted shadow-panel">Select a case first.</div>;
  }

  return (
    <div className="space-y-6">
      <section className="rounded-[28px] border border-line bg-panel/70 p-6 shadow-panel">
        <div className="flex flex-wrap items-start justify-between gap-4">
          <div>
            <p className="font-mono text-xs uppercase tracking-[0.24em] text-accent">Host Information</p>
            <h2 className="mt-2 text-3xl font-semibold">{selectedHost ? selectedHost.display_name : "What do we know about this host?"}</h2>
            <p className="mt-2 max-w-2xl text-sm text-muted">
              Consolidated identity aggregated from every artifact Kairon has parsed for this host -- not a raw artifact view. Every value below is traceable back to where it came from.
            </p>
          </div>
          <Fingerprint size={32} className="shrink-0 text-accent/60" aria-hidden="true" />
        </div>

        {hosts.length > 1 ? (
          <label className="mt-5 block max-w-sm text-xs text-muted">
            <span className="mb-1.5 block font-mono uppercase tracking-[0.14em]">Host</span>
            <select
              aria-label="Select host"
              value={selectedHostId}
              onChange={(event) => {
                const next = new URLSearchParams(searchParams);
                if (event.target.value) next.set("host_id", event.target.value);
                else next.delete("host_id");
                setSearchParams(next, { replace: true });
              }}
              className="w-full rounded-2xl border border-line bg-abyss/80 px-4 py-3 text-sm text-ink"
              data-testid="host-selector"
            >
              <option value="">Select a host&hellip;</option>
              {hosts.map((host) => (
                <option key={host.id} value={host.id}>
                  {host.display_name}
                </option>
              ))}
            </select>
          </label>
        ) : null}
      </section>

      {isCaseContextLoading ? <p className="text-sm text-muted">Loading hosts&hellip;</p> : null}

      {!isCaseContextLoading && hosts.length === 0 ? (
        <section className="rounded-[28px] border border-line bg-panel/70 p-8 text-sm text-muted shadow-panel" data-testid="no-hosts-state">
          No hosts have been identified in this case yet. Host identity is assigned automatically during evidence processing, or manually from{" "}
          <Link to={`/cases/${caseId}/hosts`} className="text-accent">
            Manage hosts
          </Link>
          .
        </section>
      ) : null}

      {hosts.length > 0 && !selectedHostId ? (
        <section className="rounded-[28px] border border-line bg-panel/70 p-8 text-sm text-muted shadow-panel" data-testid="no-host-selected-state">
          This case has {hosts.length} hosts. Select one above to view its consolidated identity.
        </section>
      ) : null}

      {selectedHostId ? (
        <>
          {factsQuery.isLoading ? <p className="text-sm text-muted">Loading host facts&hellip;</p> : null}
          {factsQuery.isError ? <p className="text-sm text-danger">{String((factsQuery.error as Error)?.message || "Could not load Host Facts for this host.")}</p> : null}
          {factsQuery.data ? (
            <div className="grid gap-6 lg:grid-cols-2" data-testid="host-fact-groups">
              {FACT_GROUPS.map((group) => (
                <FactGroupCard key={group.id} caseId={caseId} hostId={selectedHostId} group={group} factsByType={factsByType} />
              ))}
            </div>
          ) : null}
        </>
      ) : null}
    </div>
  );
}
