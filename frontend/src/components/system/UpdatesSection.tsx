import { useEffect } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { api, type HostAgentRequest, type UpdateStatus } from "../../api/client";
import { AgentActionButton, AgentRequestStatus, latestRequest, useHostAgent } from "./HostAgent";

export const UPDATE_STATUS_QUERY_KEY = ["system-update-status"];

function formatDate(value?: string | null) {
  if (!value) return "";
  const date = new Date(value);
  return Number.isNaN(date.getTime()) ? value : date.toLocaleString();
}

function Summary({ status }: { status: UpdateStatus }) {
  const branch = status.branch || "main";
  switch (status.state) {
    case "update_available":
      return (
        <>
          <h3 className="mt-2 text-lg font-semibold" data-testid="update-summary">
            {status.commits_behind === 1 ? "1 new commit" : `${status.commits_behind} new commits`} on {branch}
          </h3>
          <p className="mt-2 text-sm text-muted">This instance runs commit <span className="font-mono text-ink">{status.running_commit}</span>.</p>
        </>
      );
    case "up_to_date":
      return (
        <h3 className="mt-2 text-lg font-semibold" data-testid="update-summary">
          Up to date with {branch} (commit <span className="font-mono">{status.running_commit}</span>)
        </h3>
      );
    case "disabled":
      return (
        <h3 className="mt-2 text-lg font-semibold" data-testid="update-summary">
          The update check is off. Turn it on in Instance settings.
        </h3>
      );
    case "unknown_commit":
      return (
        <>
          <h3 className="mt-2 text-lg font-semibold" data-testid="update-summary">This build does not record its commit</h3>
          <p className="mt-2 text-sm text-muted">It was built outside scripts/setup.sh. The next ./scripts/upgrade.sh records it.</p>
        </>
      );
    case "not_configured":
      return (
        <h3 className="mt-2 text-lg font-semibold" data-testid="update-summary">
          No repository to check: UPDATE_CHECK_REPOSITORY in .env must look like owner/name.
        </h3>
      );
    default:
      return (
        <>
          <h3 className="mt-2 text-lg font-semibold" data-testid="update-summary">Could not check for updates</h3>
          <p className="mt-2 text-sm text-muted">{status.error}</p>
        </>
      );
  }
}

/** A finished request stays on the page for a day; one waiting or running, until it ends. */
export function recentRequest(request: HostAgentRequest | undefined, now = Date.now()) {
  if (!request) return undefined;
  if (!request.finished_at) return request;
  const finished = Date.parse(request.finished_at);
  return Number.isNaN(finished) || now - finished < 24 * 3600 * 1000 ? request : undefined;
}

export default function UpdatesSection() {
  const queryClient = useQueryClient();
  const agent = useHostAgent();
  const upgrade = recentRequest(latestRequest(agent.data, "upgrade"));
  useEffect(() => {
    // After an upgrade the running commit changed: read the update status again.
    if (upgrade?.state === "done") void queryClient.invalidateQueries({ queryKey: UPDATE_STATUS_QUERY_KEY });
  }, [upgrade?.id, upgrade?.state, queryClient]);
  const statusQuery = useQuery({ queryKey: UPDATE_STATUS_QUERY_KEY, queryFn: api.getUpdateStatus, retry: false });
  const checkMutation = useMutation({
    mutationFn: api.checkForUpdates,
    onSuccess: (result) => queryClient.setQueryData(UPDATE_STATUS_QUERY_KEY, result),
  });
  const status = checkMutation.data ?? statusQuery.data;

  if (!status) {
    return (
      <section className="rounded-3xl border border-line bg-panel/70 p-5 shadow-panel">
        <p className="text-sm text-muted">{statusQuery.isError ? "The update status could not be read." : "Reading the update status…"}</p>
      </section>
    );
  }

  const canCheck = status.enabled && !["unknown_commit", "not_configured"].includes(status.state);
  return (
    <section className="space-y-6" data-testid="system-updates">
      <div className="rounded-3xl border border-line bg-panel/70 p-5 shadow-panel">
        <p className="font-mono text-xs uppercase tracking-[0.18em] text-accent">Updates · {status.repository || "no repository"}</p>
        <Summary status={status} />
        {status.checked_at ? <p className="mt-2 text-xs text-slate-400">Last checked {formatDate(status.checked_at)}. Checked again every {status.interval_hours} h while an administrator uses Kairon.</p> : null}
        {status.last_error ? <p className="mt-1 text-xs text-slate-400">The latest attempt failed ({status.last_error}); this is the result of {formatDate(status.last_good_check_at)}.</p> : null}
        {canCheck ? (
          <button
            type="button"
            onClick={() => checkMutation.mutate()}
            disabled={checkMutation.isPending}
            className="mt-4 rounded-2xl border border-line bg-abyss/80 px-4 py-2 text-sm text-muted disabled:opacity-60"
          >
            {checkMutation.isPending ? "Checking…" : "Check now"}
          </button>
        ) : null}
      </div>

      {status.state === "update_available" ? (
        <>
          <div className="rounded-3xl border border-line bg-panel/70 p-5 shadow-panel">
            <p className="font-mono text-xs uppercase tracking-[0.18em] text-accent">What changed</p>
            <ul className="mt-3 space-y-2 text-sm" data-testid="update-commits">
              {(status.commits ?? []).map((commit) => (
                <li key={commit.sha} className="flex gap-3">
                  <span className="font-mono text-xs text-slate-400">{commit.sha.slice(0, 8)}</span>
                  <span className="text-ink">{commit.title}</span>
                </li>
              ))}
            </ul>
            {(status.commits_behind ?? 0) > (status.commits?.length ?? 0) ? (
              <p className="mt-3 text-xs text-slate-400">Only the latest commits are listed, merge commits left out.</p>
            ) : null}
            {status.compare_url ? (
              <a href={status.compare_url} target="_blank" rel="noreferrer" className="mt-3 inline-block text-sm text-accent hover:underline">
                See every change on GitHub
              </a>
            ) : null}
          </div>
          <div className="rounded-3xl border border-line bg-panel/70 p-5 shadow-panel">
            <p className="font-mono text-xs uppercase tracking-[0.18em] text-accent">How to update</p>
            {agent.data?.available ? (
              <>
                <p className="mt-2 text-sm text-muted">The host agent backs up the database, then pulls, rebuilds and restarts Kairon. Cases and evidence are kept.</p>
                <AgentActionButton
                  label="Update now"
                  confirmText="Kairon will be unavailable for a few minutes while it rebuilds and restarts. This page reconnects by itself."
                  payload={{ action: "upgrade" }}
                />
              </>
            ) : (
              <>
                <p className="mt-2 text-sm text-muted">On the server, from the Kairon DFIR directory: back up the database, then upgrade (pull, rebuild and restart; cases and evidence are kept).</p>
                <pre className="mt-3 overflow-x-auto rounded-xl bg-abyss/90 p-3 text-sm text-slate-200">{"./scripts/dfir-backup.sh --db-only\n./scripts/upgrade.sh"}</pre>
                <p className="mt-2 text-xs text-slate-400">To update from this page instead, enable the host agent on the server: ./scripts/host-agent.sh enable</p>
              </>
            )}
          </div>
        </>
      ) : null}
      {upgrade ? (
        <div className="rounded-3xl border border-line bg-panel/70 p-5 shadow-panel">
          <p className="font-mono text-xs uppercase tracking-[0.18em] text-accent">Latest update</p>
          <AgentRequestStatus request={upgrade} />
        </div>
      ) : null}
    </section>
  );
}
