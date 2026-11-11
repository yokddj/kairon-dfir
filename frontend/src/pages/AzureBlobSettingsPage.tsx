import { useEffect, useState } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { AlertTriangle, CheckCircle2, Cloud, Loader2, XCircle } from "lucide-react";
import { api, type AzureBlobAuthMethod, type AzureBlobConfigResponse, type AzureBlobConfigUpdate } from "../api/client";
import { useAuth } from "../context/AuthContext";

type Draft = { account_url: string; auth_method: AzureBlobAuthMethod; account_name: string; tenant_id: string; client_id: string; secret: string; default_container: string };

const SECRET_LABEL: Record<AzureBlobAuthMethod, string> = {
  account_key: "Account key",
  sas_token: "SAS token",
  service_principal: "Client secret",
};

const METHOD_HELP: Record<AzureBlobAuthMethod, string> = {
  account_key: "One of the storage account's access keys. It grants full access to the account: prefer a SAS or a service principal.",
  sas_token: "A shared access signature for the account or one container, with read and list permissions (sp=rl). Paste it with or without the leading ?.",
  service_principal: "A Microsoft Entra ID application with the Storage Blob Data Reader role on the account or container.",
};

function draftFrom(config: AzureBlobConfigResponse): Draft {
  return {
    account_url: config.account_url,
    auth_method: config.auth_method,
    account_name: config.account_name,
    tenant_id: config.tenant_id,
    client_id: config.client_id,
    secret: "",
    default_container: config.default_container,
  };
}

function payloadFrom(draft: Draft): AzureBlobConfigUpdate {
  return {
    account_url: draft.account_url,
    auth_method: draft.auth_method,
    account_name: draft.account_name,
    tenant_id: draft.tenant_id,
    client_id: draft.client_id,
    default_container: draft.default_container,
    // Only sent when typed: omitting it keeps the stored secret.
    ...(draft.secret ? { secret: draft.secret } : {}),
  };
}

const INPUT = "mt-1 w-full rounded-xl border border-line bg-black/30 px-3 py-2 text-sm text-ink outline-none focus:border-accent/60";

export default function AzureBlobSettingsPage() {
  const { user } = useAuth();
  const queryClient = useQueryClient();
  const configQuery = useQuery({ queryKey: ["azure-blob-config"], queryFn: api.getAzureBlobConfig, enabled: Boolean(user?.is_admin) });
  const config = configQuery.data;
  const [draft, setDraft] = useState<Draft | null>(null);
  const [feedback, setFeedback] = useState<{ ok: boolean; text: string } | null>(null);

  useEffect(() => {
    if (config) setDraft(draftFrom(config));
  }, [config]);

  const save = useMutation({
    mutationFn: () => api.updateAzureBlobConfig(payloadFrom(draft!)),
    onSuccess: (next) => {
      queryClient.setQueryData(["azure-blob-config"], next);
      setFeedback({ ok: true, text: "Saved." });
    },
    onError: (error: Error) => setFeedback({ ok: false, text: error.message }),
  });
  const test = useMutation({
    mutationFn: () => api.testAzureBlobConfig(payloadFrom(draft!)),
    onSuccess: (result) => setFeedback(result.ok ? { ok: true, text: result.message ?? "Connected." } : { ok: false, text: result.error ?? "The connection failed." }),
    onError: (error: Error) => setFeedback({ ok: false, text: error.message }),
  });
  const clearSecret = useMutation({
    mutationFn: () => api.updateAzureBlobConfig({ secret: "" }),
    onSuccess: (next) => {
      queryClient.setQueryData(["azure-blob-config"], next);
      setFeedback({ ok: true, text: "Secret removed." });
    },
    onError: (error: Error) => setFeedback({ ok: false, text: error.message }),
  });
  const busy = save.isPending || test.isPending || clearSecret.isPending;

  if (!user?.is_admin) {
    return <div className="rounded-2xl border border-line bg-panel/60 p-6 text-sm text-muted">Azure Blob configuration is restricted to administrators.</div>;
  }

  // A stored secret belongs to the stored method; switching methods needs a new one.
  const secretStored = Boolean(config?.has_secret && draft && draft.auth_method === config.auth_method);

  return (
    <div className="space-y-5">
      <header className="space-y-1">
        <h1 className="flex items-center gap-2 text-lg font-semibold text-ink">
          <Cloud size={18} className="text-accent" /> Azure Blob evidence source
        </h1>
        <p className="max-w-3xl text-sm text-muted">
          A storage account analysts can import evidence from: in the evidence wizard they browse a container, pick one blob, and the server
          downloads it and processes it like any upload. Block, append and page blobs (an exported VM disk VHD) can be imported.
        </p>
      </header>

      <div className="flex max-w-3xl items-start gap-3 rounded-2xl border border-amber-500/30 bg-amber-500/5 p-4 text-xs text-amber-200">
        <AlertTriangle size={16} className="mt-0.5 shrink-0" />
        <div className="space-y-1">
          <p className="font-semibold">The server downloads from outside the lab</p>
          <p>Importing reaches the account below from the Kairon server. Use a credential that can only read and list the evidence container.</p>
        </div>
      </div>

      {configQuery.isLoading ? <p className="text-sm text-muted">Loading configuration...</p> : null}
      {configQuery.isError ? <p className="text-sm text-danger" role="alert">Could not load the Azure Blob configuration.</p> : null}

      {config && !config.enabled ? (
        <p className="max-w-3xl rounded-2xl border border-line bg-panel/60 p-4 text-sm text-muted" data-testid="azure-blob-disabled">
          Importing from Azure Blob Storage is turned off on this instance. Set <code className="text-ink">AZURE_BLOB_SOURCE_ENABLED=true</code> in the server's{" "}
          <code className="text-ink">.env</code> and restart the backend and worker to offer it in the evidence wizard. The settings below can be prepared meanwhile.
        </p>
      ) : null}

      {config && draft ? (
        <section className="max-w-3xl rounded-2xl border border-line/80 bg-panel/60 p-4">
          <div className="grid gap-3 md:grid-cols-2">
            <label className="text-xs text-muted md:col-span-2">
              Account URL
              <input value={draft.account_url} onChange={(event) => setDraft({ ...draft, account_url: event.target.value })} placeholder="https://<account>.blob.core.windows.net" className={INPUT} />
            </label>
            <label className="text-xs text-muted">
              Authentication
              <select
                aria-label="Authentication"
                value={draft.auth_method}
                onChange={(event) => setDraft({ ...draft, auth_method: event.target.value as AzureBlobAuthMethod, secret: "" })}
                className={INPUT}
              >
                <option value="sas_token">SAS token</option>
                <option value="service_principal">Service principal (Entra ID)</option>
                <option value="account_key">Account key</option>
              </select>
            </label>
            <label className="text-xs text-muted">
              Default container
              <input value={draft.default_container} onChange={(event) => setDraft({ ...draft, default_container: event.target.value })} placeholder="evidence" className={INPUT} />
            </label>
            {draft.auth_method === "account_key" ? (
              <label className="text-xs text-muted">
                Account name
                <input value={draft.account_name} onChange={(event) => setDraft({ ...draft, account_name: event.target.value })} placeholder="Taken from the URL if empty" className={INPUT} />
              </label>
            ) : null}
            {draft.auth_method === "service_principal" ? (
              <>
                <label className="text-xs text-muted">
                  Tenant ID
                  <input value={draft.tenant_id} onChange={(event) => setDraft({ ...draft, tenant_id: event.target.value })} placeholder="contoso.onmicrosoft.com or a GUID" autoComplete="off" className={INPUT} />
                </label>
                <label className="text-xs text-muted">
                  Client (application) ID
                  <input value={draft.client_id} onChange={(event) => setDraft({ ...draft, client_id: event.target.value })} placeholder="00000000-0000-0000-0000-000000000000" autoComplete="off" className={INPUT} />
                </label>
              </>
            ) : null}
            <label className="text-xs text-muted md:col-span-2">
              {SECRET_LABEL[draft.auth_method]}
              <input
                type="password"
                autoComplete="off"
                aria-label={SECRET_LABEL[draft.auth_method]}
                value={draft.secret}
                onChange={(event) => setDraft({ ...draft, secret: event.target.value })}
                placeholder={secretStored ? `Stored (${config.secret_masked ?? "********"}) — type to replace it` : "Not set"}
                className={INPUT}
              />
              <span className="mt-1 block text-[11px] text-muted">{METHOD_HELP[draft.auth_method]} Stored encrypted; it is never sent back to this page.</span>
            </label>
          </div>
          <div className="mt-3 flex flex-wrap items-center gap-2">
            <button type="button" disabled={busy} onClick={() => save.mutate()} className="rounded-xl bg-accent/15 px-3 py-1.5 text-xs text-accent transition hover:bg-accent/25 disabled:opacity-50">
              Save
            </button>
            <button type="button" disabled={busy} onClick={() => test.mutate()} className="rounded-xl border border-line px-3 py-1.5 text-xs text-muted transition hover:text-ink disabled:opacity-50">
              Test connection
            </button>
            {config.has_secret ? (
              <button type="button" disabled={busy} onClick={() => clearSecret.mutate()} className="ml-auto rounded-xl border border-line px-3 py-1.5 text-xs text-danger transition hover:bg-danger/10 disabled:opacity-50">
                Remove secret
              </button>
            ) : null}
          </div>
          {busy ? (
            <p className="mt-2 flex items-center gap-2 text-xs text-muted">
              <Loader2 size={13} className="animate-spin" /> Working...
            </p>
          ) : null}
          {feedback && !busy ? (
            <p role="status" className={`mt-2 flex items-start gap-2 text-xs ${feedback.ok ? "text-emerald-300" : "text-danger"}`}>
              {feedback.ok ? <CheckCircle2 size={13} className="mt-0.5" /> : <XCircle size={13} className="mt-0.5" />}
              {feedback.text}
            </p>
          ) : null}
        </section>
      ) : null}
    </div>
  );
}
