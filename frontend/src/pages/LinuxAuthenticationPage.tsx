import { useMemo, useState } from "react";
import type { ReactNode } from "react";
import { useQuery } from "@tanstack/react-query";
import { Link, useParams } from "react-router-dom";
import { ShieldCheck } from "lucide-react";

import { api, type LinuxAuthBruteForceGroup, type LinuxAuthEvent, type LinuxAuthSession } from "../api/client";

function fmtTime(value?: string | null): string {
  if (!value) return "-";
  const date = new Date(value);
  return Number.isNaN(date.getTime()) ? value : date.toLocaleString();
}

function fmtDuration(seconds?: number | null): string {
  if (seconds === null || seconds === undefined) return "-";
  if (seconds < 60) return `${seconds}s`;
  const mins = Math.floor(seconds / 60);
  const rest = seconds % 60;
  return rest ? `${mins}m ${rest}s` : `${mins}m`;
}

function SummaryCard({ label, value, detail }: { label: string; value: string | number; detail?: string }) {
  return <div className="rounded-2xl border border-line bg-abyss/70 p-4"><p className="text-xs uppercase tracking-[0.16em] text-muted">{label}</p><p className="mt-2 text-2xl font-semibold text-ink">{value}</p>{detail ? <p className="mt-1 text-xs text-muted">{detail}</p> : null}</div>;
}

export default function LinuxAuthenticationPage() {
  const { caseId = "" } = useParams();
  const [username, setUsername] = useState("");
  const [attemptedUsername, setAttemptedUsername] = useState("");
  const [sourceIp, setSourceIp] = useState("");
  const [sourcePort, setSourcePort] = useState("");
  const [result, setResult] = useState("");
  const [service, setService] = useState("");
  const [sessionState, setSessionState] = useState("");
  const [bruteForceOnly, setBruteForceOnly] = useState(false);
  const [followedBySuccess, setFollowedBySuccess] = useState("");

  const params = useMemo(() => ({
    username: username || undefined,
    attempted_username: attemptedUsername || undefined,
    source_ip: sourceIp || undefined,
    source_port: sourcePort ? Number(sourcePort) : undefined,
    result: result || undefined,
    service: service || undefined,
    session_state: sessionState || undefined,
    brute_force_only: bruteForceOnly || undefined,
    followed_by_success: followedBySuccess === "yes" ? true : followedBySuccess === "no" ? false : undefined,
  }), [attemptedUsername, bruteForceOnly, followedBySuccess, result, service, sessionState, sourceIp, sourcePort, username]);

  const query = useQuery({ queryKey: ["linux-authentication", caseId, params], queryFn: () => api.getLinuxAuthentication(caseId, params), enabled: Boolean(caseId) });
  const data = query.data;

  if (!caseId) return <div className="rounded-2xl border border-line bg-panel p-6 text-sm text-muted">Select a case first.</div>;

  return (
    <main className="space-y-6">
      <section className="rounded-[28px] border border-line bg-panel p-6 shadow-panel">
        <div className="flex flex-wrap items-start justify-between gap-4">
          <div>
            <p className="font-mono text-xs uppercase tracking-[0.22em] text-accent">Linux Authentication</p>
            <h1 className="mt-2 flex items-center gap-3 text-3xl font-semibold text-ink"><ShieldCheck size={28} />Authentication Investigation</h1>
            <p className="mt-2 max-w-3xl text-sm text-muted">Reconstructed SSH/PAM sessions, failed authentication, brute-force groups, and last-login records from Linux authentication artifacts.</p>
          </div>
          <Link to={`/cases/${caseId}/search?artifact_type=linux_auth`} className="rounded-2xl border border-line bg-abyss/80 px-4 py-2 text-sm text-muted">Open raw auth events</Link>
        </div>
        <div className="mt-5 grid gap-3 md:grid-cols-4">
          <input aria-label="Username" value={username} onChange={(event) => setUsername(event.target.value)} placeholder="username" className="rounded-2xl border border-line bg-abyss/80 px-4 py-3 text-sm" />
          <input aria-label="Attempted username" value={attemptedUsername} onChange={(event) => setAttemptedUsername(event.target.value)} placeholder="attempted username" className="rounded-2xl border border-line bg-abyss/80 px-4 py-3 text-sm" />
          <input aria-label="Source IP" value={sourceIp} onChange={(event) => setSourceIp(event.target.value)} placeholder="source IP" className="rounded-2xl border border-line bg-abyss/80 px-4 py-3 text-sm" />
          <input aria-label="Source port" value={sourcePort} onChange={(event) => setSourcePort(event.target.value)} placeholder="source port" className="rounded-2xl border border-line bg-abyss/80 px-4 py-3 text-sm" />
          <select aria-label="Result" value={result} onChange={(event) => setResult(event.target.value)} className="rounded-2xl border border-line bg-abyss/80 px-4 py-3 text-sm"><option value="">Any result</option><option value="success">Success</option><option value="failure">Failure</option></select>
          <input aria-label="Service" value={service} onChange={(event) => setService(event.target.value)} placeholder="service/process" className="rounded-2xl border border-line bg-abyss/80 px-4 py-3 text-sm" />
          <select aria-label="Session state" value={sessionState} onChange={(event) => setSessionState(event.target.value)} className="rounded-2xl border border-line bg-abyss/80 px-4 py-3 text-sm"><option value="">Any session state</option><option value="complete">Complete</option><option value="open_without_close">Open without close</option><option value="accepted_without_pam_session">Accepted without PAM</option></select>
          <select aria-label="Followed by success" value={followedBySuccess} onChange={(event) => setFollowedBySuccess(event.target.value)} className="rounded-2xl border border-line bg-abyss/80 px-4 py-3 text-sm"><option value="">Any follow-up</option><option value="yes">Followed by success</option><option value="no">No success after</option></select>
          <label className="flex items-center gap-2 rounded-2xl border border-line bg-abyss/80 px-4 py-3 text-sm text-muted"><input type="checkbox" checked={bruteForceOnly} onChange={(event) => setBruteForceOnly(event.target.checked)} /> Brute-force only</label>
          <button type="button" onClick={() => { setUsername(""); setAttemptedUsername(""); setSourceIp(""); setSourcePort(""); setResult(""); setService(""); setSessionState(""); setBruteForceOnly(false); setFollowedBySuccess(""); }} className="rounded-2xl border border-line bg-abyss/80 px-4 py-3 text-sm text-muted">Clear filters</button>
        </div>
      </section>

      {query.isLoading ? <p className="text-sm text-muted">Loading Linux authentication investigation...</p> : null}
      {query.isError ? <p className="text-sm text-danger">{String((query.error as Error)?.message || "Could not load Linux authentication investigation.")}</p> : null}
      {data ? <>
        <section className="grid gap-3 md:grid-cols-4">
          <SummaryCard label="Successful logins" value={data.overview.successful_logins} detail={data.overview.last_successful_login ? `Last: ${data.overview.last_successful_login.username}` : "No success observed"} />
          <SummaryCard label="Failed attempts" value={data.overview.effective_failed_attempts} detail={`${data.overview.failed_attempts} raw failed rows`} />
          <SummaryCard label="Reconstructed sessions" value={data.overview.reconstructed_sessions} detail="SSH/PAM pairing" />
          <SummaryCard label="Brute-force groups" value={data.overview.suspected_brute_force_groups} detail={`${data.overview.distinct_source_ips} distinct source IPs`} />
          <SummaryCard label="Last login source IPs" value={data.overview.lastlog_source_ip_count} detail={data.overview.lastlog_supported ? "lastlog records parsed" : "No parsed lastlog records"} />
        </section>

        <Section title="Sessions"><SessionTable rows={data.sessions} /></Section>
        <Section title="Failed Authentication"><FailureTable rows={data.failed_authentication} /></Section>
        <Section title="Brute Force"><BruteForceTable rows={data.brute_force} /></Section>
        <Section title="Last Login"><LastLoginTable rows={data.last_login} /></Section>
      </> : null}
    </main>
  );
}

function Section({ title, children }: { title: string; children: ReactNode }) {
  return <section className="rounded-[24px] border border-line bg-panel p-5 shadow-panel"><h2 className="text-xl font-semibold text-ink">{title}</h2><div className="mt-4 overflow-x-auto">{children}</div></section>;
}

function SessionTable({ rows }: { rows: LinuxAuthSession[] }) {
  if (!rows.length) return <p className="text-sm text-muted">No reconstructed SSH sessions match the current filters.</p>;
  return <table className="min-w-full text-left text-sm"><thead className="text-xs uppercase tracking-[0.14em] text-muted"><tr><th className="px-3 py-2">Start</th><th className="px-3 py-2">End</th><th className="px-3 py-2">Duration</th><th className="px-3 py-2">User</th><th className="px-3 py-2">Source IP</th><th className="px-3 py-2">Source port</th><th className="px-3 py-2">Service</th><th className="px-3 py-2">Status</th></tr></thead><tbody>{rows.map((row) => <tr key={row.id} className="border-t border-line/70"><td className="px-3 py-2">{fmtTime(row.start)}</td><td className="px-3 py-2">{fmtTime(row.end)}</td><td className="px-3 py-2 font-semibold text-ink">{fmtDuration(row.duration_seconds)}</td><td className="px-3 py-2">{row.username}</td><td className="px-3 py-2">{row.source_ip || "-"}</td><td className="px-3 py-2">{row.source_port ?? "-"}</td><td className="px-3 py-2">{row.service}</td><td className="px-3 py-2">{row.status}</td></tr>)}</tbody></table>;
}

function FailureTable({ rows }: { rows: LinuxAuthEvent[] }) {
  if (!rows.length) return <p className="text-sm text-muted">No failed authentication rows match the current filters.</p>;
  return <table className="min-w-full text-left text-sm"><thead className="text-xs uppercase tracking-[0.14em] text-muted"><tr><th className="px-3 py-2">Time</th><th className="px-3 py-2">Attempted user</th><th className="px-3 py-2">Source IP</th><th className="px-3 py-2">Source port</th><th className="px-3 py-2">Service</th><th className="px-3 py-2">Reason</th><th className="px-3 py-2">Effective count</th></tr></thead><tbody>{rows.map((row) => <tr key={row.id || `${row.event_time}-${row.message}`} className="border-t border-line/70"><td className="px-3 py-2">{fmtTime(row.event_time)}</td><td className="px-3 py-2 font-medium text-ink">{row.attempted_username || row.username || "-"}</td><td className="px-3 py-2">{row.source_ip || "-"}</td><td className="px-3 py-2">{row.source_port ?? "-"}</td><td className="px-3 py-2">{row.service || row.process || "-"}</td><td className="max-w-md px-3 py-2 text-muted">{row.message}</td><td className="px-3 py-2">{row.aggregate_failure_count ? `PAM +${row.aggregate_failure_count}` : row.explicit_failure_count || row.effective_failure_count || 1}</td></tr>)}</tbody></table>;
}

function BruteForceTable({ rows }: { rows: LinuxAuthBruteForceGroup[] }) {
  if (!rows.length) return <p className="text-sm text-muted">No suspected brute-force groups match the current filters.</p>;
  return <table className="min-w-full text-left text-sm"><thead className="text-xs uppercase tracking-[0.14em] text-muted"><tr><th className="px-3 py-2">First seen</th><th className="px-3 py-2">Last seen</th><th className="px-3 py-2">Target account</th><th className="px-3 py-2">Source IP</th><th className="px-3 py-2">Attempts</th><th className="px-3 py-2">Distinct users</th><th className="px-3 py-2">Followed by success</th><th className="px-3 py-2">Success account</th></tr></thead><tbody>{rows.map((row) => <tr key={row.id} className="border-t border-line/70"><td className="px-3 py-2">{fmtTime(row.first_seen)}</td><td className="px-3 py-2">{fmtTime(row.last_seen)}</td><td className="px-3 py-2 font-semibold text-ink">{row.target_account}</td><td className="px-3 py-2">{row.source_ip}</td><td className="px-3 py-2 font-semibold text-amber">{row.effective_attempts}</td><td className="px-3 py-2">{row.distinct_usernames.join(", ")}</td><td className="px-3 py-2">{row.followed_by_success ? `Yes (${fmtDuration(row.time_to_success_seconds)})` : "No"}</td><td className="px-3 py-2">{row.successful_username || "-"}</td></tr>)}</tbody></table>;
}

function LastLoginTable({ rows }: { rows: LinuxAuthEvent[] }) {
  if (!rows.length) return <p className="text-sm text-muted">No parsed lastlog records are available for this case. If `/var/log/lastlog` exists, it may need reprocessing with a supported binary layout.</p>;
  return <table className="min-w-full text-left text-sm"><thead className="text-xs uppercase tracking-[0.14em] text-muted"><tr><th className="px-3 py-2">User / UID</th><th className="px-3 py-2">Last login</th><th className="px-3 py-2">Terminal</th><th className="px-3 py-2">Source host/IP</th></tr></thead><tbody>{rows.map((row) => <tr key={row.id || `${row.uid}-${row.event_time}`} className="border-t border-line/70"><td className="px-3 py-2">{row.username || row.uid || "-"}</td><td className="px-3 py-2">{fmtTime(row.event_time)}</td><td className="px-3 py-2">{row.terminal || "-"}</td><td className="px-3 py-2">{row.source_ip || "-"}</td></tr>)}</tbody></table>;
}
