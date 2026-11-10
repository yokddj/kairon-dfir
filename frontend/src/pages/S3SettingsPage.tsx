import { useEffect, useState } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { AlertTriangle, CheckCircle2, Cloud, Loader2, XCircle } from "lucide-react";
import { api, type S3ConfigResponse, type S3ConfigUpdate } from "../api/client";
import { useAuth } from "../context/AuthContext";

type Draft = { endpoint_url: string; region: string; access_key_id: string; secret_access_key: string; default_bucket: string; path_style: boolean };

function draftFrom(config: S3ConfigResponse): Draft {
  return {
    endpoint_url: config.endpoint_url,
    region: config.region,
    access_key_id: config.access_key_id,
    secret_access_key: "",
    default_bucket: config.default_bucket,
    path_style: config.path_style,
  };
}

function payloadFrom(draft: Draft): S3ConfigUpdate {
  return {
    endpoint_url: draft.endpoint_url,
    region: draft.region,
    access_key_id: draft.access_key_id,
    default_bucket: draft.default_bucket,
    path_style: draft.path_style,
    // Only sent when typed: omitting it keeps the stored secret.
    ...(draft.secret_access_key ? { secret_access_key: draft.secret_access_key } : {}),
  };
}

const INPUT = "mt-1 w-full rounded-xl border border-line bg-black/30 px-3 py-2 text-sm text-ink outline-none focus:border-accent/60";

export default function S3SettingsPage() {
  const { user } = useAuth();
  const queryClient = useQueryClient();
  const configQuery = useQuery({ queryKey: ["s3-config"], queryFn: api.getS3Config, enabled: Boolean(user?.is_admin) });
  const config = configQuery.data;
  const [draft, setDraft] = useState<Draft | null>(null);
  const [feedback, setFeedback] = useState<{ ok: boolean; text: string } | null>(null);

  useEffect(() => {
    if (config) setDraft(draftFrom(config));
  }, [config]);

  const save = useMutation({
    mutationFn: () => api.updateS3Config(payloadFrom(draft!)),
    onSuccess: (next) => {
      queryClient.setQueryData(["s3-config"], next);
      setFeedback({ ok: true, text: "Saved." });
    },
    onError: (error: Error) => setFeedback({ ok: false, text: error.message }),
  });
  const test = useMutation({
    mutationFn: () => api.testS3Config(payloadFrom(draft!)),
    onSuccess: (result) => setFeedback(result.ok ? { ok: true, text: result.message ?? "Connected." } : { ok: false, text: result.error ?? "The connection failed." }),
    onError: (error: Error) => setFeedback({ ok: false, text: error.message }),
  });
  const clearSecret = useMutation({
    mutationFn: () => api.updateS3Config({ secret_access_key: "" }),
    onSuccess: (next) => {
      queryClient.setQueryData(["s3-config"], next);
      setFeedback({ ok: true, text: "Secret removed." });
    },
    onError: (error: Error) => setFeedback({ ok: false, text: error.message }),
  });
  const busy = save.isPending || test.isPending || clearSecret.isPending;

  if (!user?.is_admin) {
    return <div className="rounded-2xl border border-line bg-panel/60 p-6 text-sm text-muted">S3 configuration is restricted to administrators.</div>;
  }

  return (
    <div className="space-y-5">
      <header className="space-y-1">
        <h1 className="flex items-center gap-2 text-lg font-semibold text-ink">
          <Cloud size={18} className="text-accent" /> S3 evidence source
        </h1>
        <p className="max-w-3xl text-sm text-muted">
          A bucket analysts can import evidence from: in the evidence wizard they browse it, pick one object, and the server downloads it and
          processes it like any upload. Works with AWS S3 and S3-compatible stores (MinIO, Ceph, Wasabi...).
        </p>
      </header>

      <div className="flex max-w-3xl items-start gap-3 rounded-2xl border border-amber-500/30 bg-amber-500/5 p-4 text-xs text-amber-200">
        <AlertTriangle size={16} className="mt-0.5 shrink-0" />
        <div className="space-y-1">
          <p className="font-semibold">The server downloads from outside the lab</p>
          <p>
            Importing reaches the endpoint below from the Kairon server. Use a key that can only read (s3:ListBucket, s3:GetObject) the
            evidence bucket.
          </p>
        </div>
      </div>

      {configQuery.isLoading ? <p className="text-sm text-muted">Loading configuration...</p> : null}
      {configQuery.isError ? <p className="text-sm text-danger" role="alert">Could not load the S3 configuration.</p> : null}

      {config && !config.enabled ? (
        <p className="max-w-3xl rounded-2xl border border-line bg-panel/60 p-4 text-sm text-muted" data-testid="s3-disabled">
          Importing from S3 is turned off on this instance. Set <code className="text-ink">S3_SOURCE_ENABLED=true</code> in the server's <code className="text-ink">.env</code> and
          restart the backend and worker to offer it in the evidence wizard. The settings below can be prepared meanwhile.
        </p>
      ) : null}

      {config && draft ? (
        <section className="max-w-3xl rounded-2xl border border-line/80 bg-panel/60 p-4">
          <div className="grid gap-3 md:grid-cols-2">
            <label className="text-xs text-muted">
              Access key ID
              <input value={draft.access_key_id} onChange={(event) => setDraft({ ...draft, access_key_id: event.target.value })} placeholder="AKIA..." autoComplete="off" className={INPUT} />
            </label>
            <label className="text-xs text-muted">
              Secret access key
              <input
                type="password"
                autoComplete="off"
                value={draft.secret_access_key}
                onChange={(event) => setDraft({ ...draft, secret_access_key: event.target.value })}
                placeholder={config.has_secret_access_key ? `Stored (${config.secret_access_key_masked ?? "********"}) — type to replace it` : "Not set"}
                className={INPUT}
              />
              <span className="mt-1 block text-[11px] text-muted">Stored encrypted. It is never sent back to this page.</span>
            </label>
            <label className="text-xs text-muted">
              Region
              <input value={draft.region} onChange={(event) => setDraft({ ...draft, region: event.target.value })} placeholder="eu-west-1" className={INPUT} />
            </label>
            <label className="text-xs text-muted">
              Default bucket
              <input value={draft.default_bucket} onChange={(event) => setDraft({ ...draft, default_bucket: event.target.value })} placeholder="evidence-bucket" className={INPUT} />
            </label>
            <label className="text-xs text-muted md:col-span-2">
              Endpoint URL (only for S3-compatible stores)
              <input value={draft.endpoint_url} onChange={(event) => setDraft({ ...draft, endpoint_url: event.target.value })} placeholder="Empty for AWS S3, or https://minio.example:9000" className={INPUT} />
            </label>
            <label className="flex items-center gap-2 text-xs text-muted md:col-span-2">
              <input type="checkbox" checked={draft.path_style} onChange={(event) => setDraft({ ...draft, path_style: event.target.checked })} />
              Path-style addressing (most MinIO and Ceph setups need it)
            </label>
          </div>
          <div className="mt-3 flex flex-wrap items-center gap-2">
            <button type="button" disabled={busy} onClick={() => save.mutate()} className="rounded-xl bg-accent/15 px-3 py-1.5 text-xs text-accent transition hover:bg-accent/25 disabled:opacity-50">
              Save
            </button>
            <button type="button" disabled={busy} onClick={() => test.mutate()} className="rounded-xl border border-line px-3 py-1.5 text-xs text-muted transition hover:text-ink disabled:opacity-50">
              Test connection
            </button>
            {config.has_secret_access_key ? (
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
