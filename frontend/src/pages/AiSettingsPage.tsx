import { useEffect, useMemo, useState } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { AlertTriangle, Bot, CheckCircle2, Loader2, ServerCog, Trash2, XCircle } from "lucide-react";
import { api, type AiConfigResponse, type AiProviderEntry } from "../api/client";
import { useAuth } from "../context/AuthContext";

type Draft = { model: string; base_url: string; api_key: string };

function draftFrom(entry: AiProviderEntry): Draft {
  return { model: entry.model, base_url: entry.base_url, api_key: "" };
}

function HostingBadge({ hosting }: { hosting: string }) {
  if (hosting === "local") {
    return (
      <span className="rounded-full bg-emerald-500/10 px-2 py-0.5 text-[11px] text-emerald-300">
        Runs locally — nothing leaves the lab
      </span>
    );
  }
  if (hosting === "cloud") {
    return (
      <span className="rounded-full bg-amber-500/10 px-2 py-0.5 text-[11px] text-amber-300">
        Third party — case excerpts leave the lab
      </span>
    );
  }
  return (
    <span className="rounded-full bg-white/5 px-2 py-0.5 text-[11px] text-muted">
      Depends on the endpoint you point it at
    </span>
  );
}

function ProviderCard({
  entry,
  active,
  onSaved,
}: {
  entry: AiProviderEntry;
  active: boolean;
  onSaved: (config: AiConfigResponse) => void;
}) {
  const [draft, setDraft] = useState<Draft>(() => draftFrom(entry));
  const [models, setModels] = useState<string[]>([]);
  const [feedback, setFeedback] = useState<{ ok: boolean; text: string } | null>(null);

  useEffect(() => {
    setDraft(draftFrom(entry));
  }, [entry.provider, entry.model, entry.base_url]);

  const probe = () => ({
    model: draft.model,
    base_url: draft.base_url,
    ...(draft.api_key ? { api_key: draft.api_key } : {}),
  });

  const save = useMutation({
    mutationFn: () =>
      api.updateAiProvider(entry.provider, {
        model: draft.model,
        base_url: draft.base_url,
        // Only send the key when the operator typed one; omitting it keeps
        // whatever is already stored.
        ...(draft.api_key ? { api_key: draft.api_key } : {}),
      }),
    onSuccess: (config) => {
      setDraft((current) => ({ ...current, api_key: "" }));
      setFeedback({ ok: true, text: "Saved." });
      onSaved(config);
    },
    onError: (error: Error) => setFeedback({ ok: false, text: error.message }),
  });

  const test = useMutation({
    mutationFn: () => api.testAiProvider(entry.provider, probe()),
    onSuccess: (result) =>
      setFeedback(
        result.ok
          ? { ok: true, text: `Reachable. ${result.model_count ?? 0} models available.` }
          : { ok: false, text: result.error ?? "The provider rejected the request." },
      ),
    onError: (error: Error) => setFeedback({ ok: false, text: error.message }),
  });

  const loadModels = useMutation({
    mutationFn: () => api.listAiProviderModels(entry.provider, probe()),
    onSuccess: (result) => {
      setModels(result.models);
      setFeedback(
        result.ok
          ? { ok: true, text: `${result.models.length} models found.` }
          : { ok: false, text: result.error ?? "Could not list models." },
      );
    },
    onError: (error: Error) => setFeedback({ ok: false, text: error.message }),
  });

  const remove = useMutation({
    mutationFn: () => api.deleteAiProvider(entry.provider),
    onSuccess: (config) => {
      setFeedback(null);
      setModels([]);
      onSaved(config);
    },
  });

  const busy = save.isPending || test.isPending || loadModels.isPending || remove.isPending;

  return (
    <section
      className={`rounded-2xl border p-4 transition ${
        active ? "border-accent/50 bg-accent/5" : "border-line/80 bg-panel/60"
      }`}
    >
      <header className="mb-3 flex flex-wrap items-center justify-between gap-2">
        <div className="flex items-center gap-2">
          <ServerCog size={16} className="text-accent" />
          <h3 className="text-sm font-semibold text-ink">{entry.label}</h3>
          {entry.configured ? (
            <CheckCircle2 size={14} className="text-emerald-400" aria-label="Configured" />
          ) : null}
        </div>
        <HostingBadge hosting={entry.hosting} />
      </header>

      <p className="mb-3 text-xs text-muted">{entry.help}</p>

      <div className="grid gap-3 md:grid-cols-2">
        <label className="text-xs text-muted">
          Model
          <input
            list={`models-${entry.provider}`}
            value={draft.model}
            onChange={(event) => setDraft({ ...draft, model: event.target.value })}
            placeholder={entry.default_model || "model id"}
            className="mt-1 w-full rounded-xl border border-line bg-black/30 px-3 py-2 text-sm text-ink outline-none focus:border-accent/60"
          />
          <datalist id={`models-${entry.provider}`}>
            {models.map((model) => (
              <option key={model} value={model} />
            ))}
          </datalist>
        </label>

        <label className="text-xs text-muted">
          Endpoint URL
          <input
            value={draft.base_url}
            onChange={(event) => setDraft({ ...draft, base_url: event.target.value })}
            placeholder={entry.default_base_url ?? "provider default"}
            className="mt-1 w-full rounded-xl border border-line bg-black/30 px-3 py-2 text-sm text-ink outline-none focus:border-accent/60"
          />
        </label>

        <label className="text-xs text-muted md:col-span-2">
          API key {entry.requires_api_key ? "" : "(optional)"}
          <input
            type="password"
            autoComplete="off"
            value={draft.api_key}
            onChange={(event) => setDraft({ ...draft, api_key: event.target.value })}
            placeholder={entry.has_api_key ? "A key is stored — type to replace it" : "Not set"}
            className="mt-1 w-full rounded-xl border border-line bg-black/30 px-3 py-2 text-sm text-ink outline-none focus:border-accent/60"
          />
          <span className="mt-1 block text-[11px] text-muted">
            Stored encrypted. It is never sent back to this page.
          </span>
        </label>
      </div>

      <div className="mt-3 flex flex-wrap items-center gap-2">
        <button
          type="button"
          disabled={busy}
          onClick={() => save.mutate()}
          className="rounded-xl bg-accent/15 px-3 py-1.5 text-xs text-accent transition hover:bg-accent/25 disabled:opacity-50"
        >
          Save
        </button>
        <button
          type="button"
          disabled={busy}
          onClick={() => test.mutate()}
          className="rounded-xl border border-line px-3 py-1.5 text-xs text-muted transition hover:text-ink disabled:opacity-50"
        >
          Test connection
        </button>
        <button
          type="button"
          disabled={busy}
          onClick={() => loadModels.mutate()}
          className="rounded-xl border border-line px-3 py-1.5 text-xs text-muted transition hover:text-ink disabled:opacity-50"
        >
          Load models
        </button>
        <button
          type="button"
          disabled={busy}
          onClick={() => remove.mutate()}
          title="Remove this provider's stored configuration"
          className="ml-auto rounded-xl border border-line px-3 py-1.5 text-xs text-danger transition hover:bg-danger/10 disabled:opacity-50"
        >
          <Trash2 size={13} />
        </button>
      </div>

      {busy ? (
        <p className="mt-2 flex items-center gap-2 text-xs text-muted">
          <Loader2 size={13} className="animate-spin" /> Working...
        </p>
      ) : null}
      {feedback && !busy ? (
        <p
          role="status"
          className={`mt-2 flex items-start gap-2 text-xs ${feedback.ok ? "text-emerald-300" : "text-danger"}`}
        >
          {feedback.ok ? <CheckCircle2 size={13} className="mt-0.5" /> : <XCircle size={13} className="mt-0.5" />}
          {feedback.text}
        </p>
      ) : null}
    </section>
  );
}

export default function AiSettingsPage() {
  const { user } = useAuth();
  const queryClient = useQueryClient();
  const [error, setError] = useState("");

  const configQuery = useQuery({ queryKey: ["ai-config"], queryFn: api.getAiConfig });
  const config = configQuery.data;

  const applyConfig = (next: AiConfigResponse) => {
    queryClient.setQueryData(["ai-config"], next);
    queryClient.invalidateQueries({ queryKey: ["ai-status"] });
  };

  const general = useMutation({
    mutationFn: api.updateAiConfig,
    onSuccess: (next) => {
      setError("");
      applyConfig(next);
    },
    onError: (mutationError: Error) => setError(mutationError.message),
  });

  const activeEntry = useMemo(
    () => config?.providers.find((entry) => entry.provider === config.active_provider) ?? null,
    [config],
  );

  if (!user?.is_admin) {
    return (
      <div className="rounded-2xl border border-line bg-panel/60 p-6 text-sm text-muted">
        AI assistant configuration is restricted to administrators.
      </div>
    );
  }

  return (
    <div className="space-y-5">
      <header className="space-y-1">
        <h1 className="flex items-center gap-2 text-lg font-semibold text-ink">
          <Bot size={18} className="text-accent" /> AI assistant
        </h1>
        <p className="max-w-3xl text-sm text-muted">
          Connect the model provider of your choice. Analysts can then ask questions about the open
          case from any case view.
        </p>
      </header>

      <div className="flex max-w-3xl items-start gap-3 rounded-2xl border border-amber-500/30 bg-amber-500/5 p-4 text-xs text-amber-200">
        <AlertTriangle size={16} className="mt-0.5 shrink-0" />
        <div className="space-y-1">
          <p className="font-semibold">Before you point this at a hosted API</p>
          <p>
            Questions and the case briefing (names, hosts, evidence filenames, finding titles) are
            sent to the provider you configure. On engagements where that is not acceptable, use
            Ollama or another endpoint running on your own hardware.
          </p>
          <p>
            The assistant supports analysis. It is not evidence: every claim it makes must be
            verified against the artifacts before it reaches a report.
          </p>
        </div>
      </div>

      {configQuery.isLoading ? <p className="text-sm text-muted">Loading configuration...</p> : null}
      {configQuery.isError ? (
        <p className="text-sm text-danger" role="alert">
          Could not load the AI configuration.
        </p>
      ) : null}
      {error ? (
        <p className="text-sm text-danger" role="alert">
          {error}
        </p>
      ) : null}

      {config ? (
        <>
          <section className="rounded-2xl border border-line/80 bg-panel/60 p-4">
            <h2 className="mb-3 text-sm font-semibold text-ink">Active configuration</h2>
            <div className="grid gap-3 md:grid-cols-3">
              <label className="text-xs text-muted">
                Provider in use
                <select
                  value={config.active_provider ?? ""}
                  onChange={(event) => general.mutate({ active_provider: event.target.value })}
                  className="mt-1 w-full rounded-xl border border-line bg-black/30 px-3 py-2 text-sm text-ink outline-none focus:border-accent/60"
                >
                  <option value="" disabled>
                    Select a provider
                  </option>
                  {config.providers.map((entry) => (
                    <option key={entry.provider} value={entry.provider}>
                      {entry.label}
                      {entry.configured ? "" : " (not configured)"}
                    </option>
                  ))}
                </select>
              </label>

              <label className="text-xs text-muted">
                Answer length limit (tokens)
                <input
                  type="number"
                  min={256}
                  max={32000}
                  defaultValue={config.max_tokens}
                  onBlur={(event) => {
                    const value = Number(event.target.value);
                    if (Number.isFinite(value) && value !== config.max_tokens) {
                      general.mutate({ max_tokens: value });
                    }
                  }}
                  className="mt-1 w-full rounded-xl border border-line bg-black/30 px-3 py-2 text-sm text-ink outline-none focus:border-accent/60"
                />
              </label>

              <div className="text-xs text-muted">
                Assistant
                <button
                  type="button"
                  onClick={() => general.mutate({ enabled: !config.enabled })}
                  disabled={general.isPending}
                  className={`mt-1 w-full rounded-xl border px-3 py-2 text-sm transition ${
                    config.enabled
                      ? "border-emerald-500/40 bg-emerald-500/10 text-emerald-300"
                      : "border-line bg-black/30 text-muted hover:text-ink"
                  }`}
                >
                  {config.enabled ? "Enabled — click to disable" : "Disabled — click to enable"}
                </button>
                {config.enabled && activeEntry ? (
                  <span className="mt-1 block text-[11px]">
                    Answering with {activeEntry.label} / {activeEntry.model}
                  </span>
                ) : null}
              </div>
            </div>
          </section>

          <div className="grid gap-4 lg:grid-cols-2">
            {config.providers.map((entry) => (
              <ProviderCard
                key={entry.provider}
                entry={entry}
                active={entry.provider === config.active_provider}
                onSaved={applyConfig}
              />
            ))}
          </div>
        </>
      ) : null}
    </div>
  );
}
