import { useEffect, useMemo, useState } from "react";
import { useQuery } from "@tanstack/react-query";
import { Link, useParams } from "react-router-dom";

import { api, type LateralMovementEdge } from "../api/client";
import EmptyState from "../components/EmptyState";
import { useActiveCase } from "../context/ActiveCaseContext";

const AUTH_EVENT_TYPES = "logon_success,logon_failed,login_success,login_failure,invalid_user,authentication_failure";

function utc(value: string | null): string {
  if (!value) return "-";
  return value.replace("T", " ").replace(/\.\d+Z$|Z$/, "");
}

function searchHref(caseId: string, edge: LateralMovementEdge): string {
  const params = new URLSearchParams({ host: edge.target_host, ip: edge.source_ip, event_type: AUTH_EVENT_TYPES, sort: "timestamp_asc" });
  if (edge.user) params.set("user", edge.user);
  return `/cases/${caseId}/search?${params.toString()}`;
}

function SourceCell({ edge }: { edge: LateralMovementEdge }) {
  return (
    <div>
      <p className="font-medium text-ink">
        {edge.source_hosts.length ? edge.source_hosts.join(" or ") : <span className="text-muted">Not a case host</span>}
      </p>
      <p className="font-mono text-[11px] text-muted">{edge.source_ip}</p>
      {edge.source_workstations.length ? (
        <p className="text-[11px] text-muted">Workstation name: <span className="font-mono">{edge.source_workstations.join(", ")}</span></p>
      ) : null}
      {edge.source_ambiguous ? (
        <p className="text-[11px] text-amber-300" data-testid="lateral-ambiguous">Address seen on several hosts</p>
      ) : null}
      {edge.workstation_mismatch ? (
        <p className="text-[11px] text-amber-300" data-testid="lateral-mismatch">Workstation name is not the host holding this address</p>
      ) : null}
    </div>
  );
}

/**
 * Remote authentications between machines: who reached which host, from
 * where, with which account and how, in the order they began. Built from the
 * normalized logon events of every platform; the source address is matched to
 * a case host only through addresses observed on that host.
 */
export default function LateralMovementPage() {
  const { caseId = "" } = useParams();
  const { setActiveCaseId } = useActiveCase();
  const [showRoutine, setShowRoutine] = useState(false);
  const [failedOnly, setFailedOnly] = useState(false);

  useEffect(() => {
    if (caseId) setActiveCaseId(caseId);
  }, [caseId, setActiveCaseId]);

  const query = useQuery({
    queryKey: ["lateral-movement", caseId],
    queryFn: () => api.getLateralMovement(caseId),
    enabled: Boolean(caseId),
    refetchOnWindowFocus: false,
    staleTime: 60_000,
  });

  const edges = query.data?.edges ?? [];
  const routineCount = edges.filter((edge) => edge.routine_reason).length;
  const visible = useMemo(
    () => edges.filter((edge) => (showRoutine || !edge.routine_reason) && (!failedOnly || edge.failures > 0)),
    [edges, showRoutine, failedOnly],
  );
  const addresses = query.data?.addresses ?? [];

  return (
    <div className="space-y-6">
      <section className="rounded-[28px] border border-line bg-panel/70 p-5 shadow-panel">
        <p className="font-mono text-xs uppercase tracking-[0.18em] text-accent">Lateral Movement</p>
        <p className="mt-2 max-w-3xl text-sm text-muted">
          Remote logons between machines, in the order they began: network and Remote Desktop logons on Windows, SSH and other remote logins on Linux.
          The source is named only when its address was observed on a case host. These are authentications, not proof of intent: read them with the findings and the timeline.
        </p>
      </section>

      {query.isLoading ? <p className="text-sm text-muted">Loading…</p> : null}
      {query.error instanceof Error ? (
        <p className="rounded-2xl border border-rose-400/30 bg-rose-500/10 p-3 text-sm text-rose-200">{query.error.message}</p>
      ) : null}

      {query.data && !edges.length ? (
        <EmptyState
          title="No remote logons found."
          description="No logon or login event in this case came from another address. Windows Security logs (4624/4625) and Linux authentication logs are the sources for this view."
          testId="lateral-empty"
        />
      ) : null}

      {edges.length ? (
        <section className="rounded-[28px] border border-line bg-panel/70 p-5 shadow-panel">
          <div className="flex flex-wrap items-center gap-4 text-sm text-muted">
            <span data-testid="lateral-summary">
              {visible.length} of {edges.length} connections
              {routineCount && !showRoutine ? ` · ${routineCount} routine hidden` : ""}
            </span>
            <label className="flex items-center gap-2">
              <input type="checkbox" checked={showRoutine} onChange={(event) => setShowRoutine(event.target.checked)} />
              Show routine (machine, anonymous and built-in accounts)
            </label>
            <label className="flex items-center gap-2">
              <input type="checkbox" checked={failedOnly} onChange={(event) => setFailedOnly(event.target.checked)} />
              Only with failed attempts
            </label>
          </div>
          {query.data?.truncated ? (
            <p className="mt-2 text-xs text-amber-300">Too many distinct connections: the list is incomplete. Narrow it in Search.</p>
          ) : null}
          <div className="mt-4 max-w-full overflow-x-auto">
            <table className="w-full min-w-[980px] text-sm">
              <thead className="text-left font-mono text-[11px] uppercase tracking-[0.14em] text-muted">
                <tr>
                  <th className="px-2 py-2">First / last (UTC)</th>
                  <th className="px-2 py-2">From</th>
                  <th className="px-2 py-2">To</th>
                  <th className="px-2 py-2">Account</th>
                  <th className="px-2 py-2">Method</th>
                  <th className="px-2 py-2">Result</th>
                  <th className="px-2 py-2" />
                </tr>
              </thead>
              <tbody className="divide-y divide-line">
                {visible.map((edge) => (
                  <tr key={`${edge.target_host}|${edge.source_ip}|${edge.user}|${edge.method}`} data-testid="lateral-row" className="align-top">
                    <td className="whitespace-nowrap px-2 py-2 font-mono text-xs text-muted">
                      {utc(edge.first_seen)}
                      {edge.last_seen && edge.last_seen !== edge.first_seen ? <span className="block">{utc(edge.last_seen)}</span> : null}
                    </td>
                    <td className="px-2 py-2"><SourceCell edge={edge} /></td>
                    <td className="px-2 py-2 font-medium text-ink">{edge.target_host}</td>
                    <td className="px-2 py-2">
                      <span className="text-ink">{edge.domain ? `${edge.domain}\\` : ""}{edge.user ?? "-"}</span>
                      {edge.routine_reason ? <span className="block text-[11px] text-muted">Routine: {edge.routine_reason}</span> : null}
                    </td>
                    <td className="px-2 py-2 text-xs text-muted">{edge.method}</td>
                    <td className="whitespace-nowrap px-2 py-2 text-xs">
                      {edge.successes ? <span className="text-ink">{edge.successes} succeeded</span> : null}
                      {edge.failures ? <span className="block text-amber-300">{edge.failures} failed</span> : null}
                    </td>
                    <td className="px-2 py-2 text-xs">
                      <Link to={searchHref(caseId, edge)} className="whitespace-nowrap text-muted hover:text-accent">Events →</Link>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </section>
      ) : null}

      {addresses.length ? (
        <section className="rounded-[28px] border border-line bg-panel/70 p-5 shadow-panel" data-testid="lateral-addresses">
          <p className="font-mono text-xs uppercase tracking-[0.18em] text-accent">Host addresses</p>
          <p className="mt-2 text-sm text-muted">Addresses observed on each case host (its own connections, DHCP leases, memory). They are how sources above are named.</p>
          <div className="mt-3 flex flex-wrap gap-2 text-xs">
            {addresses.map((item) => (
              <span key={item.ip} className={`rounded-xl border px-3 py-1.5 ${item.ambiguous ? "border-amber-300/40 text-amber-300" : "border-line text-muted"}`}>
                <span className="font-mono">{item.ip}</span> → {item.hosts.join(", ")}
              </span>
            ))}
          </div>
        </section>
      ) : null}
    </div>
  );
}
