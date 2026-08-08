import { useEffect, useMemo, useState } from "react";
import { useQuery } from "@tanstack/react-query";
import { Link, useParams, useSearchParams } from "react-router-dom";
import { Fingerprint, Network as NetworkIcon, Users as UsersIcon } from "lucide-react";

import { api, type HostFactObservation, type HostNetworkAddress, type HostUserEntry, type HostUserFieldResolution, type HostUserObservation, type ResolvedHostFact } from "../api/client";
import EmptyState from "../components/EmptyState";
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

const NETWORK_CLASSIFICATION_LABEL: Record<string, string> = {
  private: "Private",
  public: "Public",
  loopback: "Loopback",
  "link-local": "Link-local",
  multicast: "Multicast",
  unspecified: "Unspecified",
};

const NETWORK_CLASSIFICATION_STYLES: Record<string, string> = {
  private: "border-mint/40 bg-mint/10 text-mint",
  public: "border-amber/40 bg-amber/10 text-amber",
  loopback: "border-line bg-abyss/60 text-muted",
  "link-local": "border-sky-400/30 bg-sky-400/10 text-sky-200",
  multicast: "border-line bg-abyss/60 text-muted",
  unspecified: "border-line bg-abyss/40 text-muted",
};

function NetworkObservationSourceRow({ source }: { source: HostNetworkAddress["sources"][number] }) {
  return (
    <div className="rounded-xl border border-line/70 bg-abyss/40 px-3 py-2.5 text-xs text-muted" data-testid="network-observation-source">
      <div className="flex flex-wrap items-center justify-between gap-2">
        <span className="text-ink">{source.source_label}</span>
        <span className="shrink-0 text-muted">
          {source.observation_count} observation{source.observation_count === 1 ? "" : "s"}
        </span>
      </div>
      <p className="mt-1">
        first {fmtTime(source.first_seen)} &middot; last {fmtTime(source.last_seen)}
      </p>
      {source.evidence_id ? (
        <div className="mt-2">
          <Link to={`/evidences/${source.evidence_id}`} className="rounded-lg border border-line px-2 py-1 text-[11px] text-accent hover:bg-white/5" data-testid="network-source-evidence-link">
            View evidence
          </Link>
        </div>
      ) : null}
    </div>
  );
}

function NetworkAddressRow({ address }: { address: HostNetworkAddress }) {
  return (
    <details className="group rounded-2xl border border-line bg-abyss/70 open:bg-abyss/80" data-testid="network-address-row" data-ip={address.ip} data-classification={address.classification}>
      <summary className="flex cursor-pointer list-none flex-wrap items-center gap-3 px-4 py-3 [&::-webkit-details-marker]:hidden">
        <span className="min-w-0 flex-1 truncate font-mono text-base font-semibold text-ink" data-testid="network-address-value">
          {address.ip}
        </span>
        <span className="shrink-0 rounded-full border border-line px-2 py-0.5 text-[10px] uppercase tracking-[0.1em] text-muted">IPv{address.ip_version}</span>
        <span className={`shrink-0 rounded-full border px-2.5 py-1 text-[10px] font-semibold uppercase tracking-[0.12em] ${NETWORK_CLASSIFICATION_STYLES[address.classification] || "text-muted"}`} data-testid="network-address-classification">
          {NETWORK_CLASSIFICATION_LABEL[address.classification] || address.classification}
        </span>
        <span className="shrink-0 text-xs text-muted">
          {address.observation_count} observation{address.observation_count === 1 ? "" : "s"}
        </span>
        <span className="shrink-0 text-xs text-muted" data-testid="network-address-last-seen">
          last seen {fmtTime(address.last_seen)}
        </span>
        <span className="shrink-0 text-xs text-accent group-open:hidden">Show sources</span>
        <span className="hidden shrink-0 text-xs text-accent group-open:inline">Hide sources</span>
      </summary>
      <div className="space-y-2 border-t border-line/70 px-4 py-3" data-testid="network-address-provenance">
        <p className="text-xs text-muted">
          First seen {fmtTime(address.first_seen)} &middot; last seen {fmtTime(address.last_seen)}
        </p>
        {address.sources.map((source, index) => (
          <NetworkObservationSourceRow key={`${source.source_kind}-${index}`} source={source} />
        ))}
      </div>
    </details>
  );
}

function NetworkSection({ addresses }: { addresses: HostNetworkAddress[] }) {
  return (
    <section className="rounded-[28px] border border-line bg-panel/70 p-6 shadow-panel" data-testid="network-section">
      <div className="flex items-center gap-2">
        <NetworkIcon size={18} className="text-accent/60" aria-hidden="true" />
        <p className="font-mono text-xs uppercase tracking-[0.18em] text-accent">Network ({addresses.length})</p>
      </div>
      {addresses.length === 0 ? (
        <EmptyState
          className="mt-4"
          testId="network-empty-state"
          title="No observed network identities"
          description="No reliable host network addresses were observed in the collected evidence."
        />
      ) : (
        <div className="mt-4 space-y-2">
          {addresses.map((address) => (
            <NetworkAddressRow key={address.ip} address={address} />
          ))}
        </div>
      )}
    </section>
  );
}

const ACCOUNT_STATUS_LABEL: Record<string, string> = { locked: "Locked", active: "Active", disabled: "Disabled", unknown: "Unknown" };
const ACCOUNT_STATUS_STYLES: Record<string, string> = {
  locked: "border-danger/40 bg-danger/10 text-danger",
  active: "border-mint/40 bg-mint/10 text-mint",
  disabled: "border-line bg-abyss/60 text-muted",
  unknown: "border-line bg-abyss/40 text-muted",
};
const PASSWORD_STATUS_LABEL: Record<string, string> = { locked: "Locked", set: "Password set", empty: "No password required", unavailable: "Unavailable" };

type UserSortKey = "username" | "uid" | "last_login" | "status";
type UserSortDirection = "asc" | "desc";

function UserObservationRow({ caseId, hostId, observation }: { caseId: string; hostId: string; observation: HostUserObservation }) {
  return (
    <div className="rounded-xl border border-line/70 bg-abyss/40 px-3 py-2 text-xs text-muted" data-testid="user-observation">
      <p>
        <span className="text-ink">{observation.source_kind}</span> &middot; parser <span className="text-ink">{observation.parser}</span>
        {observation.source_path ? (
          <>
            {" "}
            &middot; <span className="text-ink">{observation.source_path}</span>
          </>
        ) : null}
      </p>
      <p className="mt-1">observed {fmtTime(observation.observed_at)}</p>
      <div className="mt-2 flex flex-wrap gap-2">
        <Link to={searchHref(caseId, observation.host_id || hostId)} className="rounded-lg border border-line px-2 py-1 text-[11px] text-accent hover:bg-white/5" data-testid="pivot-search">
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

function UserFieldDetail({ caseId, hostId, label, resolution }: { caseId: string; hostId: string; label: string; resolution: HostUserFieldResolution }) {
  if (resolution.status === "missing") return null;
  return (
    <div className="rounded-xl border border-line/70 bg-abyss/50 px-3 py-2" data-testid="user-field-detail" data-field={resolution.field} data-status={resolution.status}>
      <div className="flex flex-wrap items-center justify-between gap-2">
        <span className="text-xs uppercase tracking-[0.12em] text-muted">{label}</span>
        {resolution.status === "conflicting" ? <span className="rounded-full border border-amber/40 px-2 py-0.5 text-[10px] uppercase tracking-[0.12em] text-amber">Conflicting</span> : null}
      </div>
      <p className="mt-1 font-mono text-sm text-ink">{resolution.preferred_value}</p>
      {resolution.status === "conflicting" ? (
        <div className="mt-2 space-y-1.5">
          {resolution.observations.map((observation) => (
            <UserObservationRow key={observation.id} caseId={caseId} hostId={hostId} observation={observation} />
          ))}
        </div>
      ) : null}
    </div>
  );
}

function UserRow({
  caseId, hostId, entry, expanded, onToggle, showPrimaryGroup, showShell, columnCount,
}: {
  caseId: string; hostId: string; entry: HostUserEntry; expanded: boolean; onToggle: () => void;
  showPrimaryGroup: boolean; showShell: boolean; columnCount: number;
}) {
  const { identity } = entry;
  const primaryGroupDisplay = entry.primary_group_name || identity.primary_gid.preferred_value;
  const idLabel = identity.id_kind.preferred_value === "rid" ? "RID" : identity.id_kind.preferred_value === "uid" ? "UID" : "ID";
  const accountStatusValue = entry.account_status.preferred_value || "unknown";
  const attributeEntries = Object.entries(entry.attributes);
  const hasConflict = [...Object.values(identity), entry.password_status, entry.account_status].some((field) => field.status === "conflicting");

  return (
    <>
      <tr className="align-top" data-testid="user-row" data-username={entry.username} data-account-status={accountStatusValue}>
        <td className="px-4 py-3">
          {entry.is_synthetic_username ? (
            <span className="font-mono text-sm italic text-muted" title="No passwd/SAM entry matched this identifier">
              {entry.username}
            </span>
          ) : (
            <Link to={searchHref(caseId, hostId, entry.username)} className="font-semibold text-ink hover:text-accent" data-testid="user-username-link">
              {entry.username}
            </Link>
          )}
          {identity.gecos.preferred_value ? <p className="mt-0.5 text-xs text-muted">{identity.gecos.preferred_value}</p> : null}
          {hasConflict ? <p className="mt-0.5 text-[11px] text-amber">Conflicting sources</p> : null}
        </td>
        <td className="px-4 py-3 font-mono text-xs text-muted" data-testid="user-uid">
          {identity.uid.preferred_value ? (
            <>
              {identity.uid.preferred_value}
              <span className="ml-1 text-[9px] uppercase tracking-[0.1em] text-muted/60">{idLabel}</span>
            </>
          ) : (
            <span className="italic text-muted/70">unknown</span>
          )}
        </td>
        {showPrimaryGroup ? (
          <td className="px-4 py-3 text-xs text-muted">{primaryGroupDisplay || <span className="italic text-muted/70">unknown</span>}</td>
        ) : null}
        <td className="px-4 py-3 font-mono text-xs text-muted">{identity.home.preferred_value || <span className="italic text-muted/70">unknown</span>}</td>
        {showShell ? (
          <td className="px-4 py-3 font-mono text-xs text-muted" data-testid="user-shell">
            {identity.shell.preferred_value || <span className="italic text-muted/70">unknown</span>}
            {identity.shell.preferred_value && entry.shell_classification === "non_login" ? (
              <span className="ml-1.5 rounded-full border border-line px-1.5 py-0.5 text-[9px] uppercase tracking-[0.1em] text-muted/70">non-login</span>
            ) : null}
          </td>
        ) : null}
        <td className="px-4 py-3">
          <div className="flex flex-wrap items-center gap-1.5">
            <span className={`rounded-full border px-2.5 py-1 text-[10px] font-semibold uppercase tracking-[0.12em] ${ACCOUNT_STATUS_STYLES[accountStatusValue]}`} data-testid="user-account-status">
              {ACCOUNT_STATUS_LABEL[accountStatusValue]}
            </span>
            {entry.effective_sudo.has_sudo ? (
              <span className="rounded-full border border-amber/40 bg-amber/10 px-2 py-0.5 text-[10px] font-semibold uppercase tracking-[0.1em] text-amber" data-testid="user-sudo-badge">
                sudo
              </span>
            ) : null}
          </div>
        </td>
        <td className="px-4 py-3 text-xs text-muted" data-testid="user-last-login">
          {entry.last_login ? (
            <>
              <p className="text-ink">{fmtTime(entry.last_login.timestamp)}</p>
              {entry.last_login.source_ip ? <p>{entry.last_login.source_ip}</p> : null}
            </>
          ) : (
            <span className="italic text-muted/70">Not observed</span>
          )}
        </td>
        <td className="px-4 py-3 text-right">
          <button type="button" onClick={onToggle} className="text-xs text-accent hover:underline" data-testid="user-expand-toggle">
            {expanded ? "Hide details" : "Details"}
          </button>
        </td>
      </tr>
      {expanded ? (
        <tr>
          <td colSpan={columnCount} className="border-t border-line/70 bg-abyss/30 px-4 py-4" data-testid="user-detail-panel">
            <div className="grid gap-2 md:grid-cols-2 xl:grid-cols-3">
              <UserFieldDetail caseId={caseId} hostId={hostId} label={idLabel} resolution={identity.uid} />
              {showPrimaryGroup ? <UserFieldDetail caseId={caseId} hostId={hostId} label="Primary GID" resolution={identity.primary_gid} /> : null}
              <UserFieldDetail caseId={caseId} hostId={hostId} label="Home directory" resolution={identity.home} />
              {showShell ? <UserFieldDetail caseId={caseId} hostId={hostId} label="Login shell" resolution={identity.shell} /> : null}
              <UserFieldDetail caseId={caseId} hostId={hostId} label="Full name" resolution={identity.gecos} />
              {attributeEntries.map(([key, resolution]) => (
                <UserFieldDetail key={key} caseId={caseId} hostId={hostId} label={key.replace(/_/g, " ")} resolution={resolution} />
              ))}
              <div className="rounded-xl border border-line/70 bg-abyss/50 px-3 py-2" data-testid="user-password-status">
                <span className="text-xs uppercase tracking-[0.12em] text-muted">Password status</span>
                <p className="mt-1 text-sm text-ink">{PASSWORD_STATUS_LABEL[entry.password_status.preferred_value || "unavailable"]}</p>
              </div>
              <div className="rounded-xl border border-line/70 bg-abyss/50 px-3 py-2" data-testid="user-effective-sudo">
                <span className="text-xs uppercase tracking-[0.12em] text-muted">Effective sudo</span>
                <p className="mt-1 text-sm text-ink">
                  {entry.effective_sudo.has_sudo
                    ? entry.effective_sudo.via === "direct"
                      ? "Yes -- direct sudoers rule"
                      : `Yes -- via group${entry.effective_sudo.granting_groups.length > 1 ? "s" : ""} ${entry.effective_sudo.granting_groups.join(", ")}`
                    : "No sudo rule observed"}
                </p>
              </div>
            </div>
            {entry.effective_sudo.has_sudo ? (
              <div className="mt-3 space-y-1.5" data-testid="user-sudo-provenance">
                <span className="text-xs uppercase tracking-[0.12em] text-muted">Sudo rule sources</span>
                {entry.effective_sudo.observations.map((observation) => (
                  <UserObservationRow key={observation.id} caseId={caseId} hostId={hostId} observation={observation} />
                ))}
              </div>
            ) : null}
            <div className="mt-3">
              <span className="text-xs uppercase tracking-[0.12em] text-muted">Secondary groups</span>
              {entry.secondary_groups.length > 0 ? (
                <div className="mt-1.5 flex flex-wrap gap-1.5" data-testid="user-secondary-groups">
                  {entry.secondary_groups.map((group) => (
                    <span key={group.group_name} className="rounded-full border border-line px-2.5 py-1 text-[11px] text-muted">
                      {group.group_name}
                    </span>
                  ))}
                </div>
              ) : (
                <p className="mt-1 text-xs italic text-muted/70" data-testid="user-secondary-groups-empty">
                  None observed
                </p>
              )}
            </div>
            {entry.last_login ? (
              <div className="mt-3 space-y-1.5" data-testid="user-last-login-provenance">
                <span className="text-xs uppercase tracking-[0.12em] text-muted">Last login sources</span>
                {entry.last_login.observations.map((observation) => (
                  <UserObservationRow key={observation.id} caseId={caseId} hostId={hostId} observation={observation} />
                ))}
              </div>
            ) : null}
          </td>
        </tr>
      ) : null}
    </>
  );
}

function UserInventorySection({ caseId, hostId, users }: { caseId: string; hostId: string; users: HostUserEntry[] }) {
  const [filterText, setFilterText] = useState("");
  const [sortKey, setSortKey] = useState<UserSortKey>("username");
  const [sortDirection, setSortDirection] = useState<UserSortDirection>("asc");
  const [expandedUsernames, setExpandedUsernames] = useState<Set<string>>(new Set());

  const toggleExpanded = (username: string) => {
    setExpandedUsernames((prev) => {
      const next = new Set(prev);
      if (next.has(username)) next.delete(username);
      else next.add(username);
      return next;
    });
  };

  const toggleSort = (key: UserSortKey) => {
    if (sortKey === key) {
      setSortDirection((prev) => (prev === "asc" ? "desc" : "asc"));
    } else {
      setSortKey(key);
      setSortDirection("asc");
    }
  };

  const filtered = useMemo(() => {
    const needle = filterText.trim().toLowerCase();
    const matches = needle
      ? users.filter((entry) => {
          const haystack = [entry.username, entry.identity.gecos.preferred_value, entry.identity.shell.preferred_value, entry.primary_group_name]
            .filter(Boolean)
            .join(" ")
            .toLowerCase();
          return haystack.includes(needle);
        })
      : users;
    const sorted = [...matches].sort((a, b) => {
      let comparison = 0;
      if (sortKey === "username") comparison = a.username.localeCompare(b.username);
      else if (sortKey === "uid") comparison = Number(a.identity.uid.preferred_value ?? Number.MAX_SAFE_INTEGER) - Number(b.identity.uid.preferred_value ?? Number.MAX_SAFE_INTEGER);
      else if (sortKey === "last_login") comparison = (a.last_login?.timestamp ?? "").localeCompare(b.last_login?.timestamp ?? "");
      else if (sortKey === "status") comparison = (a.account_status.preferred_value || "").localeCompare(b.account_status.preferred_value || "");
      return sortDirection === "asc" ? comparison : -comparison;
    });
    return sorted;
  }, [users, filterText, sortKey, sortDirection]);

  const sortButton = (key: UserSortKey, label: string) => (
    <button type="button" onClick={() => toggleSort(key)} className="flex items-center gap-1 hover:text-ink" data-testid={`user-sort-${key}`}>
      {label}
      {sortKey === key ? <span>{sortDirection === "asc" ? "↑" : "↓"}</span> : null}
    </button>
  );

  // Column visibility is data-driven, not platform-branched: Primary
  // group/Shell are POSIX-only concepts (no Windows producer ever
  // populates them), so an all-Windows host's table simply omits those
  // columns instead of showing "unknown" in every row.
  const showPrimaryGroup = users.some((entry) => Boolean(entry.primary_group_name || entry.identity.primary_gid.preferred_value));
  const showShell = users.some((entry) => Boolean(entry.identity.shell.preferred_value));
  const columnCount = 5 + (showPrimaryGroup ? 1 : 0) + (showShell ? 1 : 0);

  return (
    <section className="rounded-[28px] border border-line bg-panel/70 p-6 shadow-panel" data-testid="user-inventory-section">
      <div className="flex flex-wrap items-center justify-between gap-3">
        <div className="flex items-center gap-2">
          <UsersIcon size={18} className="text-accent/60" aria-hidden="true" />
          <p className="font-mono text-xs uppercase tracking-[0.18em] text-accent">Users ({users.length})</p>
        </div>
        <input
          type="text"
          value={filterText}
          onChange={(event) => setFilterText(event.target.value)}
          placeholder="Filter users&hellip;"
          className="w-56 rounded-xl border border-line bg-abyss/80 px-3 py-1.5 text-xs text-ink placeholder:text-muted/60"
          data-testid="user-filter-input"
        />
      </div>
      {users.length === 0 ? (
        <p className="mt-4 text-sm text-muted" data-testid="user-inventory-empty">
          No local accounts have been identified for this host yet. This appears once evidence with a supported source (Linux passwd/shadow, or a Windows SAM hive) has been processed and assigned to this host.
        </p>
      ) : (
        <div className="mt-4 overflow-x-auto">
          <table className="min-w-full text-left text-sm">
            <thead className="border-b border-line bg-abyss/70 font-mono text-[11px] uppercase tracking-[0.14em] text-muted">
              <tr>
                <th className="px-4 py-3">{sortButton("username", "Username")}</th>
                <th className="px-4 py-3">{sortButton("uid", "ID")}</th>
                {showPrimaryGroup ? <th className="px-4 py-3">Primary group</th> : null}
                <th className="px-4 py-3">Home</th>
                {showShell ? <th className="px-4 py-3">Shell</th> : null}
                <th className="px-4 py-3">{sortButton("status", "Status")}</th>
                <th className="px-4 py-3">{sortButton("last_login", "Last login")}</th>
                <th className="px-4 py-3" />
              </tr>
            </thead>
            <tbody className="divide-y divide-line/70">
              {filtered.map((entry) => (
                <UserRow
                  key={entry.username}
                  caseId={caseId}
                  hostId={hostId}
                  entry={entry}
                  expanded={expandedUsernames.has(entry.username)}
                  onToggle={() => toggleExpanded(entry.username)}
                  showPrimaryGroup={showPrimaryGroup}
                  showShell={showShell}
                  columnCount={columnCount}
                />
              ))}
            </tbody>
          </table>
          {filtered.length === 0 ? (
            <p className="px-4 py-6 text-sm text-muted" data-testid="user-filter-empty">
              No users match &ldquo;{filterText}&rdquo;.
            </p>
          ) : null}
        </div>
      )}
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

  const usersQuery = useQuery({
    queryKey: ["case-host-users", caseId, selectedHostId],
    queryFn: () => api.getCaseHostUsers(caseId, { host_id: selectedHostId }),
    enabled: Boolean(caseId && selectedHostId),
    refetchOnWindowFocus: false,
    staleTime: 60_000,
  });

  const networkQuery = useQuery({
    queryKey: ["case-host-network", caseId, selectedHostId],
    queryFn: () => api.getCaseHostNetwork(caseId, { host_id: selectedHostId }),
    enabled: Boolean(caseId && selectedHostId),
    refetchOnWindowFocus: false,
    staleTime: 60_000,
  });

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

          {networkQuery.isLoading ? <p className="text-sm text-muted">Loading network observations&hellip;</p> : null}
          {networkQuery.isError ? <p className="text-sm text-danger">{String((networkQuery.error as Error)?.message || "Could not load network observations for this host.")}</p> : null}
          {networkQuery.data ? <NetworkSection addresses={networkQuery.data.addresses} /> : null}

          {usersQuery.isLoading ? <p className="text-sm text-muted">Loading users&hellip;</p> : null}
          {usersQuery.isError ? <p className="text-sm text-danger">{String((usersQuery.error as Error)?.message || "Could not load Host User Inventory for this host.")}</p> : null}
          {usersQuery.data ? <UserInventorySection caseId={caseId} hostId={selectedHostId} users={usersQuery.data.users} /> : null}
        </>
      ) : null}
    </div>
  );
}
