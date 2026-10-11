import { useMemo, useState } from "react";
import type { ReactNode } from "react";
import { keepPreviousData, useQuery } from "@tanstack/react-query";
import { Link, useParams, useSearchParams } from "react-router-dom";
import { ShieldCheck } from "lucide-react";

import {
  api,
  type LinuxAuthAccount,
  type LinuxAuthAccountChange,
  type LinuxAuthCampaign,
  type LinuxAuthFailureGroup,
  type LinuxAuthFinding,
  type LinuxAuthPrivilege,
  type LinuxAuthSession,
  type LinuxAuthSource,
  type LinuxAuthenticationInvestigation,
} from "../api/client";
import { InvestigationBreadcrumbs } from "../components/InvestigationContext";
import { useInvestigationBreadcrumbs } from "../lib/useInvestigationBreadcrumbs";

const TABS = [
  { key: "overview", label: "Overview" },
  { key: "accounts", label: "Accounts" },
  { key: "sources", label: "Sources" },
  { key: "sessions", label: "Sessions" },
  { key: "failures", label: "Failed logins" },
  { key: "privilege", label: "sudo / su" },
  { key: "changes", label: "Account changes" },
  { key: "events", label: "Events" },
] as const;
type TabKey = (typeof TABS)[number]["key"];

const EVENT_GROUPS = [
  { key: "", label: "All authentication events" },
  { key: "logins", label: "Logins" },
  { key: "failures", label: "Failures" },
  { key: "sessions", label: "Sessions and logouts" },
  { key: "privilege", label: "sudo / su" },
  { key: "accounts", label: "Account changes" },
];
const EVENTS_PAGE = 50;

const SEVERITY_CLASS: Record<string, string> = {
  critical: "border-danger/40 bg-danger/15 text-danger",
  high: "border-amber/40 bg-amber/15 text-amber",
  medium: "border-accent/40 bg-accent/10 text-accent",
  low: "border-line bg-abyss/70 text-muted",
};
const PATTERN_LABEL: Record<string, string> = {
  brute_force: "Brute force",
  password_spray: "Password spray",
  repeated_failures: "Repeated failures",
  failed_logins: "Failed logins",
  none: "No failures",
};
const KIND_LABEL: Record<string, string> = { root: "root", system: "system", human: "user", unknown: "not in passwd" };
const CHANGE_LABEL: Record<string, string> = {
  user_created: "User created",
  user_deleted: "User deleted",
  group_created: "Group created",
  group_deleted: "Group deleted",
  group_member_added: "Added to group",
  group_member_removed: "Removed from group",
  group_members_set: "Group members set",
  password_changed: "Password changed",
  shell_changed: "Shell changed",
  account_info_changed: "Account info changed",
  password_expiry_changed: "Password expiry changed",
  user_locked: "Password locked",
  user_renamed: "User renamed",
  uid_changed: "UID changed",
};
const CARRIER_LABEL: Record<string, string> = { auth_log: "auth.log", journal: "journal", audit: "auditd", wtmp: "wtmp", btmp: "btmp", lastlog: "lastlog" };

function fmtTime(value?: string | null): string {
  if (!value) return "-";
  const date = new Date(value);
  return Number.isNaN(date.getTime()) ? value : date.toLocaleString();
}

function fmtDuration(seconds?: number | null): string {
  if (seconds === null || seconds === undefined) return "-";
  const abs = Math.abs(seconds);
  if (abs < 60) return `${seconds}s`;
  if (abs < 3600) return `${Math.round(seconds / 60)}m`;
  if (abs < 86400) return `${(seconds / 3600).toFixed(1)}h`;
  return `${(seconds / 86400).toFixed(1)}d`;
}

function eventHref(caseId: string, eventId: string): string {
  return `/cases/${caseId}/search?q=${encodeURIComponent(`event_id:"${eventId}"`)}`;
}

function toIso(local: string): string | undefined {
  if (!local) return undefined;
  const date = new Date(local);
  return Number.isNaN(date.getTime()) ? undefined : date.toISOString();
}

export default function LinuxAuthenticationPage() {
  const { caseId = "" } = useParams();
  const [searchParams, setSearchParams] = useSearchParams();
  const tab = (TABS.find((item) => item.key === searchParams.get("tab"))?.key ?? "overview") as TabKey;
  const [username, setUsername] = useState("");
  const [sourceIp, setSourceIp] = useState("");
  const [result, setResult] = useState("");
  const [service, setService] = useState("");
  const [timeFrom, setTimeFrom] = useState("");
  const [timeTo, setTimeTo] = useState("");
  const [showMore, setShowMore] = useState(false);
  const [eventGroup, setEventGroup] = useState("");
  const [eventOffset, setEventOffset] = useState(0);

  const params = useMemo(() => ({
    username: username.trim() || undefined,
    source_ip: sourceIp.trim() || undefined,
    result: result || undefined,
    service: service.trim() || undefined,
    time_from: toIso(timeFrom),
    time_to: toIso(timeTo),
    event_group: eventGroup || undefined,
    offset: eventOffset,
    limit: EVENTS_PAGE,
  }), [eventGroup, eventOffset, result, service, sourceIp, timeFrom, timeTo, username]);

  const query = useQuery({
    queryKey: ["linux-authentication", caseId, params],
    queryFn: () => api.getLinuxAuthentication(caseId, params),
    enabled: Boolean(caseId),
    placeholderData: keepPreviousData,
  });
  const data = query.data;
  const breadcrumbs = useInvestigationBreadcrumbs();
  const activeFilters = [
    username && { label: `Account: ${username}`, clear: () => setUsername("") },
    sourceIp && { label: `Source: ${sourceIp}`, clear: () => setSourceIp("") },
    result && { label: `Result: ${result}`, clear: () => setResult("") },
    service && { label: `Service: ${service}`, clear: () => setService("") },
    timeFrom && { label: `From ${fmtTime(toIso(timeFrom))}`, clear: () => setTimeFrom("") },
    timeTo && { label: `To ${fmtTime(toIso(timeTo))}`, clear: () => setTimeTo("") },
  ].filter(Boolean) as { label: string; clear: () => void }[];

  function selectTab(key: TabKey) {
    const next = new URLSearchParams(searchParams);
    next.set("tab", key);
    setSearchParams(next, { replace: true });
  }
  const focusAccount = (name: string) => { setUsername(name); setEventOffset(0); };
  const focusSource = (ip: string) => { if (ip && ip !== "(local)") { setSourceIp(ip); setEventOffset(0); } };

  if (!caseId) return <div className="rounded-2xl border border-line bg-panel p-6 text-sm text-muted">Select a case first.</div>;

  return (
    <main className="space-y-6">
      <InvestigationBreadcrumbs items={breadcrumbs} />
      <section className="rounded-[28px] border border-line bg-panel p-6 shadow-panel">
        <div className="flex flex-wrap items-start justify-between gap-4">
          <div>
            <p className="font-mono text-xs uppercase tracking-[0.22em] text-accent">Linux Authentication</p>
            <h1 className="mt-2 flex items-center gap-3 text-3xl font-semibold text-ink"><ShieldCheck size={28} />Authentication Investigation</h1>
            <p className="mt-2 max-w-3xl text-sm text-muted">Who logged in, from where, what was tried, and what was done with privileges -- from auth.log/secure, the systemd journal, auditd, wtmp/btmp/lastlog and /etc/passwd, with each attempt counted once.</p>
          </div>
          <Link to={`/cases/${caseId}/search?artifact_type=linux_auth`} className="rounded-2xl border border-line bg-abyss/80 px-4 py-2 text-sm text-muted">Open raw auth events</Link>
        </div>
        <div className="mt-5 flex flex-wrap items-center gap-2">
          <input aria-label="Account" value={username} onChange={(event) => { setUsername(event.target.value); setEventOffset(0); }} placeholder="account" className="w-40 rounded-2xl border border-line bg-abyss/80 px-3 py-2 text-sm" />
          <input aria-label="Source IP" value={sourceIp} onChange={(event) => { setSourceIp(event.target.value); setEventOffset(0); }} placeholder="source IP" className="w-40 rounded-2xl border border-line bg-abyss/80 px-3 py-2 text-sm" />
          <select aria-label="Result" value={result} onChange={(event) => { setResult(event.target.value); setEventOffset(0); }} className="rounded-2xl border border-line bg-abyss/80 px-3 py-2 text-sm"><option value="">Any result</option><option value="success">Success</option><option value="failure">Failure</option></select>
          <input aria-label="From" type="datetime-local" value={timeFrom} onChange={(event) => { setTimeFrom(event.target.value); setEventOffset(0); }} className="rounded-2xl border border-line bg-abyss/80 px-3 py-2 text-sm" />
          <input aria-label="To" type="datetime-local" value={timeTo} onChange={(event) => { setTimeTo(event.target.value); setEventOffset(0); }} className="rounded-2xl border border-line bg-abyss/80 px-3 py-2 text-sm" />
          <button type="button" onClick={() => setShowMore((value) => !value)} className="rounded-2xl border border-line bg-abyss/80 px-3 py-2 text-sm text-muted">{showMore ? "Fewer filters" : "More filters"}</button>
          {showMore ? <input aria-label="Service" value={service} onChange={(event) => { setService(event.target.value); setEventOffset(0); }} placeholder="service (sshd, login, su...)" className="w-56 rounded-2xl border border-line bg-abyss/80 px-3 py-2 text-sm" /> : null}
        </div>
        {activeFilters.length ? (
          <div className="mt-3 flex flex-wrap items-center gap-2" data-testid="active-filters">
            {activeFilters.map((filter) => <button key={filter.label} type="button" onClick={filter.clear} className="rounded-full border border-accent/40 bg-accent/10 px-3 py-1 text-xs text-accent">{filter.label} ×</button>)}
            <button type="button" onClick={() => { setUsername(""); setSourceIp(""); setResult(""); setService(""); setTimeFrom(""); setTimeTo(""); setEventOffset(0); }} className="text-xs text-muted underline">Clear all</button>
          </div>
        ) : null}
        <div className="mt-5 flex flex-wrap gap-2" role="tablist" aria-label="Authentication sections">
          {TABS.map((item) => (
            <button key={item.key} type="button" role="tab" aria-selected={tab === item.key} onClick={() => selectTab(item.key)}
              className={`rounded-full px-4 py-2 text-sm ${tab === item.key ? "bg-accent text-abyss" : "border border-line bg-panel/60 text-muted"}`}>
              {item.label}{data ? <TabCount tab={item.key} data={data} /> : null}
            </button>
          ))}
        </div>
      </section>

      {query.isLoading ? <p className="text-sm text-muted">Loading Linux authentication investigation...</p> : null}
      {query.isError ? <p className="text-sm text-danger">{String((query.error as Error)?.message || "Could not load Linux authentication investigation.")}</p> : null}
      {data ? <>
        {data.truncated ? <p className="rounded-2xl border border-amber/40 bg-amber/10 p-3 text-sm text-amber">This case has more authentication events than one analysis reads; the results cover the first part. Narrow the time range to see the rest.</p> : null}
        <Overview data={data} />
        {tab === "overview" ? <OverviewTab caseId={caseId} data={data} onAccount={focusAccount} onSource={focusSource} onTab={selectTab} /> : null}
        {tab === "accounts" ? <Section title="Accounts" subtitle="Every account seen in authentication data, typed from /etc/passwd."><AccountsTable rows={data.accounts} onAccount={focusAccount} /></Section> : null}
        {tab === "sources" ? <Section title="Sources" subtitle="One row per origin: what it tried and whether it got in."><SourcesTable rows={data.sources} onSource={focusSource} /></Section> : null}
        {tab === "sessions" ? <Section title="Sessions" subtitle="SSH, console and graphical logins with their end, newest first."><SessionsTable rows={data.sessions} onAccount={focusAccount} onSource={focusSource} /></Section> : null}
        {tab === "failures" ? <>
          <Section title="Attack campaigns" subtitle="Failures grouped by source over time, classified as brute force or password spraying."><CampaignsTable caseId={caseId} rows={data.campaigns} onSource={focusSource} /></Section>
          <Section title="Failed logins by source and account" subtitle="Each attempt counted once, even when sshd, PAM, btmp and auditd all recorded it."><FailuresTable rows={data.failures} onAccount={focusAccount} onSource={focusSource} /></Section>
        </> : null}
        {tab === "privilege" ? <Section title="sudo and su" subtitle="Privilege use and denials. su is attributed to the login name that ran it."><PrivilegeTable rows={data.privilege} onAccount={focusAccount} /></Section> : null}
        {tab === "changes" ? <Section title="Account changes" subtitle="Users, groups, passwords and shells changed on the host."><ChangesTable caseId={caseId} rows={data.account_changes} onAccount={focusAccount} /></Section> : null}
        {tab === "events" ? <Section title="Authentication events" subtitle="Normalised events from every source, newest first." action={
          <select aria-label="Event group" value={eventGroup} onChange={(event) => { setEventGroup(event.target.value); setEventOffset(0); }} className="rounded-2xl border border-line bg-abyss/80 px-3 py-2 text-sm">
            {EVENT_GROUPS.map((group) => <option key={group.key} value={group.key}>{group.label}</option>)}
          </select>
        }><EventsTable caseId={caseId} data={data} offset={eventOffset} onOffset={setEventOffset} /></Section> : null}
      </> : null}
    </main>
  );
}

function TabCount({ tab, data }: { tab: TabKey; data: LinuxAuthenticationInvestigation }) {
  const count = {
    overview: data.findings.length,
    accounts: data.accounts.length,
    sources: data.sources.length,
    sessions: data.sessions.length,
    failures: data.campaigns.filter((item) => item.pattern === "brute_force" || item.pattern === "password_spray").length,
    privilege: data.privilege.length,
    changes: data.account_changes.length,
    events: data.events.total,
  }[tab];
  return count ? <span className="ml-2 font-mono text-xs opacity-70">{count}</span> : null;
}

function Card({ label, value, detail, tone }: { label: string; value: ReactNode; detail?: string; tone?: string }) {
  return <div className="rounded-2xl border border-line bg-abyss/70 p-4"><p className="text-xs uppercase tracking-[0.16em] text-muted">{label}</p><p className={`mt-2 text-2xl font-semibold ${tone ?? "text-ink"}`}>{value}</p>{detail ? <p className="mt-1 text-xs text-muted">{detail}</p> : null}</div>;
}

function Overview({ data }: { data: LinuxAuthenticationInvestigation }) {
  const o = data.overview;
  const serious = (o.findings.critical ?? 0) + (o.findings.high ?? 0);
  return (
    <section className="grid gap-3 sm:grid-cols-3 xl:grid-cols-6" data-testid="auth-overview">
      <Card label="Findings" value={data.findings.length} detail={serious ? `${serious} critical/high` : "none critical or high"} tone={serious ? "text-danger" : undefined} />
      <Card label="Logins" value={o.successful_logins} detail={`${o.accounts_with_logins} account(s)`} />
      <Card label="Failed attempts" value={o.failed_attempts} detail={`${o.accounts_targeted} account(s) targeted`} tone={o.failed_attempts ? "text-amber" : undefined} />
      <Card label="Sources" value={o.source_ips} detail={o.attack_campaigns ? `${o.attack_campaigns} attack campaign(s)` : "no attack campaign"} />
      <Card label="sudo / su" value={o.privileged_actions} />
      <Card label="Account changes" value={o.account_changes} detail={o.first_event ? `${fmtTime(o.first_event)} → ${fmtTime(o.last_event)}` : undefined} />
    </section>
  );
}

function OverviewTab({ caseId, data, onAccount, onSource, onTab }: { caseId: string; data: LinuxAuthenticationInvestigation; onAccount: (name: string) => void; onSource: (ip: string) => void; onTab: (key: TabKey) => void }) {
  return <>
    <Section title="Findings" subtitle="Generic checks over all sources. Click an account or source to focus the whole page on it.">
      {data.findings.length ? (
        <ul className="space-y-3" data-testid="auth-findings">
          {data.findings.map((finding) => <FindingRow key={finding.id} caseId={caseId} finding={finding} onAccount={onAccount} onSource={onSource} />)}
        </ul>
      ) : <p className="text-sm text-muted">No findings for the current filters.</p>}
    </Section>
    <div className="grid gap-6 xl:grid-cols-2">
      <Section title="Top sources" action={<button type="button" className="text-sm text-accent" onClick={() => onTab("sources")}>All sources →</button>}>
        <SourcesTable rows={data.sources.slice(0, 5)} onSource={onSource} compact />
      </Section>
      <Section title="Data coverage" subtitle="Which carriers of authentication data the case holds, and the period each covers.">
        <table className="min-w-full text-left text-sm" data-testid="auth-coverage">
          <thead className="text-xs uppercase tracking-[0.14em] text-muted"><tr><th className="px-3 py-2">Source</th><th className="px-3 py-2">Events</th><th className="px-3 py-2">From</th><th className="px-3 py-2">To</th></tr></thead>
          <tbody>{data.coverage.map((row) => (
            <tr key={row.carrier} className="border-t border-line/70">
              <td className="px-3 py-2 text-ink">{row.label}</td>
              <td className={`px-3 py-2 ${row.events ? "" : "text-muted"}`}>{row.events ? row.events : "not present"}</td>
              <td className="px-3 py-2 text-muted">{fmtTime(row.first)}</td>
              <td className="px-3 py-2 text-muted">{fmtTime(row.last)}</td>
            </tr>
          ))}</tbody>
        </table>
      </Section>
    </div>
  </>;
}

function FindingRow({ caseId, finding, onAccount, onSource }: { caseId: string; finding: LinuxAuthFinding; onAccount: (name: string) => void; onSource: (ip: string) => void }) {
  return (
    <li className="rounded-2xl border border-line bg-abyss/50 p-4" data-testid="auth-finding">
      <div className="flex flex-wrap items-center gap-2">
        <span className={`rounded-full border px-2.5 py-0.5 font-mono text-[11px] uppercase tracking-[0.12em] ${SEVERITY_CLASS[finding.severity] ?? SEVERITY_CLASS.low}`}>{finding.severity}</span>
        <span className="font-semibold text-ink">{finding.title}</span>
        <span className="ml-auto text-xs text-muted">{fmtTime(finding.time)}</span>
      </div>
      <p className="mt-2 text-sm text-muted">{finding.detail}</p>
      <div className="mt-2 flex flex-wrap gap-2 text-xs">
        {finding.account ? <button type="button" onClick={() => onAccount(finding.account)} className="rounded-full border border-line px-2 py-0.5 text-ink hover:text-accent">account {finding.account}</button> : null}
        {finding.source_ip && finding.source_ip !== "(local)" ? <button type="button" onClick={() => onSource(finding.source_ip)} className="rounded-full border border-line px-2 py-0.5 text-ink hover:text-accent">source {finding.source_ip}</button> : null}
        {finding.event_ids.slice(0, 3).map((id, index) => <Link key={id} to={eventHref(caseId, id)} className="rounded-full border border-line px-2 py-0.5 text-muted hover:text-accent">event {index + 1}</Link>)}
      </div>
    </li>
  );
}

function Section({ title, subtitle, action, children }: { title: string; subtitle?: string; action?: ReactNode; children: ReactNode }) {
  return (
    <section className="rounded-[24px] border border-line bg-panel p-5 shadow-panel">
      <div className="flex flex-wrap items-start justify-between gap-3">
        <div><h2 className="text-xl font-semibold text-ink">{title}</h2>{subtitle ? <p className="mt-1 text-sm text-muted">{subtitle}</p> : null}</div>
        {action}
      </div>
      <div className="mt-4 overflow-x-auto">{children}</div>
    </section>
  );
}

function Table({ headers, empty, children, testId }: { headers: string[]; empty: string; children: ReactNode[]; testId?: string }) {
  if (!children.length) return <p className="text-sm text-muted">{empty}</p>;
  return (
    <table className="min-w-full text-left text-sm" data-testid={testId}>
      <thead className="text-xs uppercase tracking-[0.14em] text-muted"><tr>{headers.map((header) => <th key={header} className="whitespace-nowrap px-3 py-2">{header}</th>)}</tr></thead>
      <tbody>{children}</tbody>
    </table>
  );
}

function LinkButton({ value, onClick }: { value: string; onClick?: (value: string) => void }) {
  if (!value) return <span className="text-muted">-</span>;
  if (!onClick || value === "(local)" || value === "(unknown)") return <span>{value}</span>;
  return <button type="button" onClick={() => onClick(value)} className="text-ink hover:text-accent hover:underline">{value}</button>;
}

function Badge({ children, tone = "muted" }: { children: ReactNode; tone?: "muted" | "amber" | "danger" | "mint" | "accent" }) {
  const cls = { muted: "border-line text-muted", amber: "border-amber/40 text-amber", danger: "border-danger/40 text-danger", mint: "border-mint/40 text-mint", accent: "border-accent/40 text-accent" }[tone];
  return <span className={`whitespace-nowrap rounded-full border px-2 py-0.5 text-xs ${cls}`}>{children}</span>;
}

function AccountsTable({ rows, onAccount }: { rows: LinuxAuthAccount[]; onAccount: (name: string) => void }) {
  return (
    <Table testId="auth-accounts" headers={["Account", "Type", "Logins", "Failed", "Methods", "Logged in from", "Last login", "sudo", "su to", "Changes"]} empty="No accounts match the current filters.">
      {rows.map((row) => (
        <tr key={row.username} className="border-t border-line/70">
          <td className="px-3 py-2 font-semibold"><LinkButton value={row.username} onClick={onAccount} /></td>
          <td className="px-3 py-2"><Badge tone={row.kind === "system" && row.logins ? "danger" : row.kind === "root" ? "amber" : "muted"}>{KIND_LABEL[row.kind] ?? row.kind}{row.uid !== null && row.uid !== undefined ? ` · ${row.uid}` : ""}</Badge>{row.shell ? <p className="mt-1 font-mono text-[11px] text-muted">{row.shell}</p> : null}</td>
          <td className="px-3 py-2">{row.logins || "-"}</td>
          <td className={`px-3 py-2 ${row.failed_attempts ? "text-amber" : "text-muted"}`}>{row.failed_attempts || "-"}</td>
          <td className="px-3 py-2 text-muted">{row.methods.join(", ") || "-"}</td>
          <td className="px-3 py-2 text-muted">{row.sources.map((item) => item.source_ip).slice(0, 3).join(", ") || "-"}{row.sources.length > 3 ? ` +${row.sources.length - 3}` : ""}</td>
          <td className="px-3 py-2 text-muted">{fmtTime(row.last_login ?? row.lastlog?.time)}</td>
          <td className="px-3 py-2">{row.sudo_commands || "-"}{row.sudo_denied ? <span className="ml-1 text-amber">({row.sudo_denied} denied)</span> : null}</td>
          <td className="px-3 py-2 text-muted">{row.su_to.map((item) => `${item.target}×${item.count}`).join(", ") || "-"}</td>
          <td className="px-3 py-2">{row.changes || "-"}</td>
        </tr>
      ))}
    </Table>
  );
}

function SourcesTable({ rows, onSource, compact }: { rows: LinuxAuthSource[]; onSource: (ip: string) => void; compact?: boolean }) {
  const headers = compact ? ["Source", "Pattern", "Failed", "Logins"] : ["Source", "Pattern", "Failed", "Accounts tried", "Logins", "Logged in as", "First seen", "Last seen"];
  return (
    <Table testId="auth-sources" headers={headers} empty="No sources match the current filters.">
      {rows.map((row) => (
        <tr key={row.source_ip} className="border-t border-line/70">
          <td className="px-3 py-2 font-semibold"><LinkButton value={row.source_ip} onClick={onSource} /></td>
          <td className="px-3 py-2"><Badge tone={row.pattern === "brute_force" || row.pattern === "password_spray" ? (row.logins ? "danger" : "amber") : "muted"}>{PATTERN_LABEL[row.pattern] ?? row.pattern}</Badge></td>
          <td className={`px-3 py-2 ${row.failed_attempts ? "text-amber" : "text-muted"}`}>{row.failed_attempts || "-"}</td>
          {compact ? null : <td className="px-3 py-2 text-muted">{row.accounts_tried.slice(0, 4).map((item) => `${item.username} (${item.attempts})`).join(", ") || "-"}{row.accounts_tried_count > 4 ? ` +${row.accounts_tried_count - 4}` : ""}</td>}
          <td className={`px-3 py-2 ${row.logins && row.failed_attempts ? "font-semibold text-danger" : ""}`}>{row.logins || "-"}</td>
          {compact ? null : <>
            <td className="px-3 py-2">{row.login_accounts.join(", ") || "-"}</td>
            <td className="px-3 py-2 text-muted">{fmtTime(row.first_seen)}</td>
            <td className="px-3 py-2 text-muted">{fmtTime(row.last_seen)}</td>
          </>}
        </tr>
      ))}
    </Table>
  );
}

const SESSION_STATUS: Record<string, string> = { closed: "closed", ended_by_restart: "ended by restart", no_close_record: "no end recorded" };

function SessionsTable({ rows, onAccount, onSource }: { rows: LinuxAuthSession[]; onAccount: (name: string) => void; onSource: (ip: string) => void }) {
  const [kind, setKind] = useState("");
  const kinds = [...new Set(rows.map((row) => row.kind))];
  const shown = kind ? rows.filter((row) => row.kind === kind) : rows;
  return <>
    {kinds.length > 1 ? (
      <div className="mb-3 flex flex-wrap gap-2">
        {["", ...kinds].map((item) => <button key={item || "all"} type="button" onClick={() => setKind(item)} className={`rounded-full px-3 py-1 text-xs ${kind === item ? "bg-accent text-abyss" : "border border-line text-muted"}`}>{item || "all"} ({item ? rows.filter((row) => row.kind === item).length : rows.length})</button>)}
      </div>
    ) : null}
    <Table testId="auth-sessions" headers={["Start", "Kind", "Account", "Source", "Method", "Terminal", "Duration", "End", "Recorded by"]} empty="No sessions match the current filters.">
      {shown.map((row) => (
        <tr key={row.id} className="border-t border-line/70">
          <td className="whitespace-nowrap px-3 py-2">{fmtTime(row.start)}</td>
          <td className="px-3 py-2"><Badge>{row.kind}</Badge></td>
          <td className="px-3 py-2 font-semibold"><LinkButton value={row.username} onClick={onAccount} /></td>
          <td className="px-3 py-2"><LinkButton value={row.source_ip ?? ""} onClick={onSource} />{row.source_port ? <span className="text-muted">:{row.source_port}</span> : null}</td>
          <td className="px-3 py-2 text-muted">{row.method || "-"}</td>
          <td className="px-3 py-2 font-mono text-xs text-muted">{row.terminal || "-"}</td>
          <td className="px-3 py-2 font-semibold text-ink">{fmtDuration(row.duration_seconds)}</td>
          <td className="px-3 py-2 text-muted">{SESSION_STATUS[row.status] ?? row.status}</td>
          <td className="px-3 py-2 text-xs text-muted">{row.carriers.map((carrier) => CARRIER_LABEL[carrier] ?? carrier).join(", ")}</td>
        </tr>
      ))}
    </Table>
  </>;
}

function CampaignsTable({ caseId, rows, onSource }: { caseId: string; rows: LinuxAuthCampaign[]; onSource: (ip: string) => void }) {
  const relevant = rows.filter((row) => row.pattern !== "failed_logins");
  return (
    <Table testId="auth-campaigns" headers={["Source", "Pattern", "Attempts", "Accounts", "First", "Last", "Then", ""]} empty="No source made more than a handful of failed attempts.">
      {relevant.map((row) => (
        <tr key={row.id} className="border-t border-line/70">
          <td className="px-3 py-2 font-semibold"><LinkButton value={row.source_ip} onClick={onSource} /></td>
          <td className="px-3 py-2"><Badge tone={row.followed_by_success ? "danger" : "amber"}>{PATTERN_LABEL[row.pattern] ?? row.pattern}</Badge></td>
          <td className="px-3 py-2 font-semibold text-amber">{row.attempts}</td>
          <td className="px-3 py-2 text-muted">{row.accounts.slice(0, 4).map((item) => `${item.username} (${item.attempts})`).join(", ")}{row.account_count > 4 ? ` +${row.account_count - 4}` : ""}</td>
          <td className="whitespace-nowrap px-3 py-2 text-muted">{fmtTime(row.first_seen)}</td>
          <td className="whitespace-nowrap px-3 py-2 text-muted">{fmtTime(row.last_seen)}</td>
          <td className="px-3 py-2">{row.followed_by_success ? <span className="font-semibold text-danger">login as {row.success_account} {row.success_during_campaign ? "during the attack" : `after ${fmtDuration(row.seconds_to_success)}`}</span> : <span className="text-muted">no login</span>}</td>
          <td className="px-3 py-2">{row.event_ids[0] ? <Link to={eventHref(caseId, row.event_ids[0])} className="text-xs text-muted hover:text-accent">event</Link> : null}</td>
        </tr>
      ))}
    </Table>
  );
}

function FailuresTable({ rows, onAccount, onSource }: { rows: LinuxAuthFailureGroup[]; onAccount: (name: string) => void; onSource: (ip: string) => void }) {
  return (
    <Table testId="auth-failures" headers={["Source", "Account", "Service", "Attempts", "Connections", "First", "Last"]} empty="No failed logins match the current filters.">
      {rows.map((row) => (
        <tr key={`${row.source_ip}-${row.username}-${row.service}`} className="border-t border-line/70">
          <td className="px-3 py-2"><LinkButton value={row.source_ip} onClick={onSource} /></td>
          <td className="px-3 py-2 font-semibold"><LinkButton value={row.username} onClick={onAccount} /></td>
          <td className="px-3 py-2 text-muted">{row.service}</td>
          <td className="px-3 py-2 font-semibold text-amber">{row.attempts}</td>
          <td className="px-3 py-2 text-muted">{row.connections}</td>
          <td className="whitespace-nowrap px-3 py-2 text-muted">{fmtTime(row.first_seen)}</td>
          <td className="whitespace-nowrap px-3 py-2 text-muted">{fmtTime(row.last_seen)}</td>
        </tr>
      ))}
    </Table>
  );
}

function PrivilegeTable({ rows, onAccount }: { rows: LinuxAuthPrivilege[]; onAccount: (name: string) => void }) {
  return (
    <Table testId="auth-privilege" headers={["Time", "Tool", "Account", "As", "Command", "Directory", "Result"]} empty="No sudo or su activity matches the current filters.">
      {rows.map((row) => (
        <tr key={row.id} className="border-t border-line/70">
          <td className="whitespace-nowrap px-3 py-2">{fmtTime(row.time)}</td>
          <td className="px-3 py-2"><Badge>{row.tool}</Badge></td>
          <td className="px-3 py-2 font-semibold"><LinkButton value={row.user} onClick={onAccount} /></td>
          <td className="px-3 py-2">{row.target || "-"}</td>
          <td className="max-w-md truncate px-3 py-2 font-mono text-xs" title={row.command}>{row.command || "-"}</td>
          <td className="max-w-[12rem] truncate px-3 py-2 font-mono text-xs text-muted" title={row.cwd}>{row.cwd || "-"}</td>
          <td className="px-3 py-2">{row.result === "denied" ? <span className="text-amber">denied{row.reason ? ` (${row.reason})` : ""}</span> : <span className="text-muted">allowed</span>}</td>
        </tr>
      ))}
    </Table>
  );
}

function ChangesTable({ caseId, rows, onAccount }: { caseId: string; rows: LinuxAuthAccountChange[]; onAccount: (name: string) => void }) {
  return (
    <Table testId="auth-changes" headers={["Time", "Change", "Account", "Group", "By", "Details", ""]} empty="No account changes match the current filters.">
      {rows.map((row) => (
        <tr key={row.id} className={`border-t border-line/70 ${row.privileged ? "bg-danger/5" : ""}`}>
          <td className="whitespace-nowrap px-3 py-2">{fmtTime(row.time)}</td>
          <td className="px-3 py-2">{row.privileged ? <Badge tone="danger">{CHANGE_LABEL[row.action] ?? row.action}</Badge> : <span>{CHANGE_LABEL[row.action] ?? row.action}</span>}</td>
          <td className="px-3 py-2 font-semibold"><LinkButton value={row.account} onClick={onAccount} />{row.account_kind === "system" ? <span className="ml-1 text-xs text-muted">(system)</span> : null}</td>
          <td className="px-3 py-2">{row.group || "-"}</td>
          <td className="px-3 py-2 text-muted">{row.by || "-"}</td>
          <td className="max-w-md truncate px-3 py-2 font-mono text-xs text-muted" title={row.message}>{Object.entries(row.details).map(([key, value]) => `${key}=${value}`).join(" ") || row.message}</td>
          <td className="px-3 py-2"><Link to={eventHref(caseId, row.id)} className="text-xs text-muted hover:text-accent">event</Link></td>
        </tr>
      ))}
    </Table>
  );
}

function EventsTable({ caseId, data, offset, onOffset }: { caseId: string; data: LinuxAuthenticationInvestigation; offset: number; onOffset: (value: number) => void }) {
  const { total, items } = data.events;
  return <>
    <Table testId="auth-events" headers={["Time", "Kind", "Result", "Account", "Source", "Service", "From", "Message"]} empty="No events match the current filters.">
      {items.map((event) => (
        <tr key={event.id} className="border-t border-line/70">
          <td className="whitespace-nowrap px-3 py-2"><Link to={eventHref(caseId, event.id)} className="hover:text-accent hover:underline">{fmtTime(event.time)}</Link></td>
          <td className="px-3 py-2 text-muted">{event.kind.replaceAll("_", " ")}</td>
          <td className={`px-3 py-2 ${event.result === "failure" ? "text-amber" : "text-muted"}`}>{event.result}</td>
          <td className="px-3 py-2">{event.username || event.by || "-"}{event.target ? <span className="text-muted"> → {event.target}</span> : null}</td>
          <td className="px-3 py-2 text-muted">{event.source_ip || "-"}</td>
          <td className="px-3 py-2 text-muted">{event.service || event.process || "-"}</td>
          <td className="px-3 py-2 text-xs text-muted">{CARRIER_LABEL[event.carrier] ?? event.carrier}</td>
          <td className="max-w-xl truncate px-3 py-2 font-mono text-xs text-muted" title={event.message}>{event.message}</td>
        </tr>
      ))}
    </Table>
    {total > EVENTS_PAGE ? (
      <div className="mt-3 flex items-center justify-end gap-3 text-sm text-muted">
        <span>{offset + 1}–{Math.min(offset + EVENTS_PAGE, total)} of {total}</span>
        <button type="button" disabled={offset === 0} onClick={() => onOffset(Math.max(0, offset - EVENTS_PAGE))} className="rounded-xl border border-line px-3 py-1 disabled:opacity-40">Previous</button>
        <button type="button" disabled={offset + EVENTS_PAGE >= total} onClick={() => onOffset(offset + EVENTS_PAGE)} className="rounded-xl border border-line px-3 py-1 disabled:opacity-40">Next</button>
      </div>
    ) : null}
  </>;
}
