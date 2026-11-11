import { useState } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { AlertTriangle, CheckCircle2, Copy, KeyRound, Loader2, XCircle } from "lucide-react";
import { Link } from "react-router-dom";
import { api, type CreatedServiceToken, type ServiceToken } from "../api/client";
import { useAuth } from "../context/AuthContext";
import { useEffectiveTimezone } from "../hooks/useEffectiveTimezone";
import { copyToClipboard, formatTimestamp } from "../lib/time";

const INPUT = "mt-1 w-full rounded-xl border border-line bg-black/30 px-3 py-2 text-sm text-ink outline-none focus:border-accent/60";
const EXPIRY_OPTIONS: Array<{ label: string; days: number | null }> = [
  { label: "30 days", days: 30 },
  { label: "90 days", days: 90 },
  { label: "1 year", days: 365 },
  { label: "Never", days: null },
];

function tokenState(token: ServiceToken): { label: string; tone: string } {
  if (token.revoked_at) return { label: "Revoked", tone: "text-muted" };
  if (token.expires_at && Date.parse(token.expires_at) < Date.now()) return { label: "Expired", tone: "text-muted" };
  return { label: "Active", tone: "text-emerald-300" };
}

/**
 * Service tokens: read-only, every-case credentials for integrations that call Kairon's API
 * without a browser session -- the MCP server (docs/operations/mcp-server.md) or a script.
 * The secret is shown once, right after creation; only its hash is stored.
 */
export default function ServiceTokensPage() {
  const { user } = useAuth();
  const timezone = useEffectiveTimezone();
  const queryClient = useQueryClient();
  const tokensQuery = useQuery({ queryKey: ["service-tokens"], queryFn: api.listServiceTokens, enabled: Boolean(user?.is_admin) });
  const [name, setName] = useState("mcp-server");
  const [expiryDays, setExpiryDays] = useState<number | null>(90);
  const [created, setCreated] = useState<CreatedServiceToken | null>(null);
  const [copied, setCopied] = useState(false);
  const [confirmRevoke, setConfirmRevoke] = useState<string | null>(null);
  const [feedback, setFeedback] = useState<{ ok: boolean; text: string } | null>(null);

  const create = useMutation({
    mutationFn: () => api.createServiceToken({ name: name.trim(), expires_in_days: expiryDays }),
    onSuccess: (token) => {
      setCreated(token);
      setCopied(false);
      setFeedback(null);
      queryClient.invalidateQueries({ queryKey: ["service-tokens"] });
    },
    onError: (error: Error) => setFeedback({ ok: false, text: error.message }),
  });
  const revoke = useMutation({
    mutationFn: (tokenId: string) => api.revokeServiceToken(tokenId),
    onSuccess: (token) => {
      setConfirmRevoke(null);
      setFeedback({ ok: true, text: `Token "${token.name}" revoked: it no longer authenticates.` });
      if (created?.id === token.id) setCreated(null);
      queryClient.invalidateQueries({ queryKey: ["service-tokens"] });
    },
    onError: (error: Error) => setFeedback({ ok: false, text: error.message }),
  });

  if (!user?.is_admin) {
    return <div className="rounded-2xl border border-line bg-panel/60 p-6 text-sm text-muted">Service tokens are managed by administrators.</div>;
  }

  const tokens = tokensQuery.data ?? [];
  const when = (value: string | null) => (value ? formatTimestamp(value, timezone) : "—");

  return (
    <div className="space-y-5">
      <header className="space-y-1">
        <h1 className="flex items-center gap-2 text-lg font-semibold text-ink">
          <KeyRound size={18} className="text-accent" /> Service tokens
        </h1>
        <p className="max-w-3xl text-sm text-muted">
          Credentials for integrations that read Kairon without a browser session, such as the{" "}
          <Link to="/docs/operations/mcp-server" className="text-accent hover:underline">
            MCP server
          </Link>{" "}
          or a script. A service token reads every case and can never write or reach the administration settings.
        </p>
      </header>

      <div className="flex max-w-3xl items-start gap-3 rounded-2xl border border-amber-500/30 bg-amber-500/5 p-4 text-xs text-amber-200">
        <AlertTriangle size={16} className="mt-0.5 shrink-0" />
        <p>Anyone holding a token can read every case until it expires or is revoked. Give each integration its own token, prefer an expiry, and revoke a token as soon as it may have leaked.</p>
      </div>

      <section className="max-w-3xl rounded-2xl border border-line/80 bg-panel/60 p-4" aria-label="Create a service token">
        <h2 className="text-sm font-semibold text-ink">Create a token</h2>
        <form
          className="mt-3 grid gap-3 md:grid-cols-[1fr_12rem_auto]"
          onSubmit={(event) => {
            event.preventDefault();
            if (name.trim()) create.mutate();
          }}
        >
          <label className="text-xs text-muted">
            Name
            <input value={name} onChange={(event) => setName(event.target.value)} maxLength={120} placeholder="mcp-server" className={INPUT} />
          </label>
          <label className="text-xs text-muted">
            Expires
            <select
              aria-label="Expires"
              value={expiryDays === null ? "never" : String(expiryDays)}
              onChange={(event) => setExpiryDays(event.target.value === "never" ? null : Number(event.target.value))}
              className={INPUT}
            >
              {EXPIRY_OPTIONS.map((option) => (
                <option key={option.label} value={option.days === null ? "never" : String(option.days)}>
                  {option.label}
                </option>
              ))}
            </select>
          </label>
          <button type="submit" disabled={create.isPending || !name.trim()} className="self-end rounded-xl bg-accent/15 px-4 py-2 text-sm text-accent transition hover:bg-accent/25 disabled:opacity-50">
            {create.isPending ? <Loader2 size={14} className="animate-spin" /> : "Create"}
          </button>
        </form>

        {created ? (
          <div className="mt-4 space-y-2 rounded-2xl border border-emerald-500/30 bg-emerald-500/5 p-4" data-testid="created-service-token">
            <p className="text-sm font-semibold text-emerald-200">Copy the token now: it will not be shown again.</p>
            <div className="flex items-center gap-2">
              <code className="min-w-0 flex-1 break-all rounded-xl bg-black/40 px-3 py-2 font-mono text-xs text-ink" data-testid="created-service-token-value">
                {created.token}
              </code>
              <button
                type="button"
                onClick={async () => setCopied(await copyToClipboard(created.token))}
                className="flex shrink-0 items-center gap-1 rounded-xl border border-line px-3 py-2 text-xs text-muted hover:text-ink"
              >
                <Copy size={13} /> {copied ? "Copied" : "Copy"}
              </button>
            </div>
            <p className="text-xs text-muted">
              For the MCP server, put it in <code className="text-ink">KAIRON_MCP_SERVICE_TOKEN</code> (Docker Compose) or <code className="text-ink">KAIRON_SERVICE_TOKEN</code> (stdio). Only its hash is stored; if you lose it, create another.
            </p>
            <button type="button" onClick={() => setCreated(null)} className="text-xs text-muted underline hover:text-ink">
              I have stored it — hide it
            </button>
          </div>
        ) : null}
      </section>

      {feedback ? (
        <p role="status" className={`flex max-w-3xl items-start gap-2 text-xs ${feedback.ok ? "text-emerald-300" : "text-danger"}`}>
          {feedback.ok ? <CheckCircle2 size={13} className="mt-0.5" /> : <XCircle size={13} className="mt-0.5" />}
          {feedback.text}
        </p>
      ) : null}

      <section className="rounded-2xl border border-line/80 bg-panel/60 p-4" aria-label="Service tokens">
        <h2 className="text-sm font-semibold text-ink">Tokens</h2>
        {tokensQuery.isLoading ? <p className="mt-3 text-sm text-muted">Loading...</p> : null}
        {tokensQuery.isError ? (
          <p className="mt-3 text-sm text-danger" role="alert">
            Could not load the service tokens.
          </p>
        ) : null}
        {tokensQuery.isSuccess && tokens.length === 0 ? <p className="mt-3 text-sm text-muted">No service tokens yet.</p> : null}
        {tokens.length ? (
          <div className="mt-3 overflow-x-auto">
            <table className="w-full min-w-[720px] text-left text-sm">
              <thead className="text-[11px] uppercase tracking-[0.12em] text-muted">
                <tr>
                  <th className="py-2 pr-3">Name</th>
                  <th className="py-2 pr-3">Token</th>
                  <th className="py-2 pr-3">Status</th>
                  <th className="py-2 pr-3">Created</th>
                  <th className="py-2 pr-3">Expires</th>
                  <th className="py-2 pr-3">Last used</th>
                  <th className="py-2" />
                </tr>
              </thead>
              <tbody>
                {tokens.map((token) => {
                  const state = tokenState(token);
                  const usable = state.label === "Active";
                  return (
                    <tr key={token.id} className="border-t border-line/60" data-testid="service-token-row">
                      <td className="py-2 pr-3 text-ink">{token.name}</td>
                      <td className="py-2 pr-3 font-mono text-xs text-muted">{token.token_prefix}…</td>
                      <td className={`py-2 pr-3 text-xs ${state.tone}`}>{state.label}</td>
                      <td className="py-2 pr-3 text-xs text-muted">{when(token.created_at)}</td>
                      <td className="py-2 pr-3 text-xs text-muted">{token.revoked_at ? `revoked ${when(token.revoked_at)}` : token.expires_at ? when(token.expires_at) : "Never"}</td>
                      <td className="py-2 pr-3 text-xs text-muted">{token.last_used_at ? when(token.last_used_at) : "Never"}</td>
                      <td className="py-2 text-right">
                        {usable ? (
                          confirmRevoke === token.id ? (
                            <span className="flex items-center justify-end gap-2 text-xs">
                              <button type="button" disabled={revoke.isPending} onClick={() => revoke.mutate(token.id)} className="rounded-lg border border-danger/50 px-2 py-1 text-danger hover:bg-danger/10 disabled:opacity-50">
                                Confirm revoke
                              </button>
                              <button type="button" onClick={() => setConfirmRevoke(null)} className="text-muted hover:text-ink">
                                Cancel
                              </button>
                            </span>
                          ) : (
                            <button type="button" onClick={() => setConfirmRevoke(token.id)} className="rounded-lg border border-line px-2 py-1 text-xs text-danger hover:bg-danger/10">
                              Revoke
                            </button>
                          )
                        ) : null}
                      </td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
          </div>
        ) : null}
      </section>
    </div>
  );
}
