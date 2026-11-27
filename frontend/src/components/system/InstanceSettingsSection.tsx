import { useState } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { api, type InstanceSettingEntry, type InstanceSettingValue, type InstanceSettingsResponse } from "../../api/client";
import { UPDATE_STATUS_QUERY_KEY } from "./UpdatesSection";

const QUERY_KEY = ["admin-instance-settings"];

const GROUP_LABELS: Record<string, string> = {
  general: "General",
  ingest: "Ingest and archives",
  disk: "Disk images",
  memory: "Memory analysis",
};

function formatBytes(value: number) {
  const units = ["B", "KiB", "MiB", "GiB", "TiB"];
  let size = value;
  let unit = 0;
  while (size >= 1024 && unit < units.length - 1) {
    size /= 1024;
    unit += 1;
  }
  return `${Number.isInteger(size) ? size : size.toFixed(1)} ${units[unit]}`;
}

export function formatSettingValue(entry: Pick<InstanceSettingEntry, "value_type" | "unit">, value: InstanceSettingValue | null | undefined) {
  if (value === null || value === undefined) return "";
  if (entry.value_type === "bool") return value ? "on" : "off";
  if (entry.unit === "bytes" && typeof value === "number") return formatBytes(value);
  if (entry.unit === "seconds" && typeof value === "number") return value % 3600 === 0 ? `${value / 3600} h` : value % 60 === 0 ? `${value / 60} min` : `${value} s`;
  if (entry.unit === "minutes") return `${value} min`;
  return String(value);
}

function current(entry: InstanceSettingEntry): InstanceSettingValue {
  return entry.override ?? entry.env_value;
}

function SettingControl({ entry, value, onChange }: { entry: InstanceSettingEntry; value: InstanceSettingValue; onChange: (value: InstanceSettingValue) => void }) {
  const id = `instance-setting-${entry.key}`;
  if (entry.value_type === "bool") {
    return (
      <label htmlFor={id} className="flex items-center gap-2 text-sm text-ink">
        <input id={id} type="checkbox" checked={Boolean(value)} onChange={(event) => onChange(event.target.checked)} aria-label={entry.label} />
        {value ? "On" : "Off"}
      </label>
    );
  }
  if (entry.value_type === "choice") {
    return (
      <select id={id} aria-label={entry.label} value={String(value)} onChange={(event) => onChange(event.target.value)} className="rounded-xl border border-line bg-abyss/80 px-3 py-2 text-sm text-ink">
        {entry.choices.map((choice) => (
          <option key={choice} value={choice}>
            {choice}
          </option>
        ))}
      </select>
    );
  }
  return (
    <div className="flex items-center gap-2">
      <input
        id={id}
        type="number"
        aria-label={entry.label}
        value={String(value)}
        min={entry.min ?? undefined}
        max={entry.max ?? undefined}
        step={1}
        onChange={(event) => onChange(event.target.value === "" ? "" : Number(event.target.value))}
        className="w-44 rounded-xl border border-line bg-abyss/80 px-3 py-2 text-sm text-ink"
      />
      {entry.unit && typeof value === "number" ? <span className="text-xs text-slate-400">{formatSettingValue(entry, value)}</span> : null}
    </div>
  );
}

function validationError(entry: InstanceSettingEntry, value: InstanceSettingValue): string | null {
  if (entry.value_type !== "int") return null;
  if (typeof value !== "number" || !Number.isInteger(value)) return "Enter a whole number.";
  if (entry.min !== null && value < entry.min) return `At least ${entry.min}.`;
  if (entry.max !== null && value > entry.max) return `At most ${entry.max}.`;
  return null;
}

export default function InstanceSettingsSection() {
  const queryClient = useQueryClient();
  const settingsQuery = useQuery({ queryKey: QUERY_KEY, queryFn: api.getInstanceSettings, retry: false });
  const [draft, setDraft] = useState<Record<string, InstanceSettingValue | null>>({});
  const [message, setMessage] = useState("");
  const [copied, setCopied] = useState(false);

  const saveMutation = useMutation({
    mutationFn: (changes: Record<string, InstanceSettingValue | null>) => api.updateInstanceSettings(changes),
    onSuccess: (result: InstanceSettingsResponse, changes) => {
      queryClient.setQueryData(QUERY_KEY, result);
      setDraft({});
      setMessage(`Saved ${Object.keys(changes).length === 1 ? "1 setting" : `${Object.keys(changes).length} settings`}.`);
      if ("UPDATE_CHECK_ENABLED" in changes) void queryClient.invalidateQueries({ queryKey: UPDATE_STATUS_QUERY_KEY });
    },
    onError: (error: Error) => setMessage(error.message),
  });

  const data = settingsQuery.data;
  if (!data) {
    return (
      <section className="rounded-3xl border border-line bg-panel/70 p-5 shadow-panel">
        <p className="text-sm text-muted">{settingsQuery.isError ? "The instance settings could not be read." : "Reading the instance settings…"}</p>
      </section>
    );
  }

  const errors = Object.fromEntries(
    data.settings.flatMap((entry) => (entry.key in draft && draft[entry.key] !== null ? [[entry.key, validationError(entry, draft[entry.key] as InstanceSettingValue)]] : [])).filter(([, error]) => error),
  ) as Record<string, string>;
  const changes = Object.fromEntries(
    Object.entries(draft).filter(([key, value]) => {
      const entry = data.settings.find((item) => item.key === key);
      return entry && (value === null ? entry.override !== null : value !== current(entry));
    }),
  );
  const groups = Array.from(new Set(data.settings.map((entry) => entry.group)));

  async function copyRestart(command: string) {
    try {
      await navigator.clipboard.writeText(command);
      setCopied(true);
    } catch {
      setCopied(false);
    }
  }

  return (
    <section className="space-y-6" data-testid="system-instance-settings">
      <div className="rounded-3xl border border-line bg-panel/70 p-5 shadow-panel">
        <p className="font-mono text-xs uppercase tracking-[0.18em] text-accent">Instance settings</p>
        <p className="mt-2 max-w-4xl text-sm text-muted">
          Settings that used to be changed in .env. A value saved here takes precedence over .env and applies when the listed services restart, unless it says it applies at once. "Use .env" removes the saved value.
        </p>
      </div>

      {data.restart_command ? (
        <div className="rounded-3xl border border-amber/40 bg-amber/10 p-5 shadow-panel" data-testid="instance-settings-restart">
          <p className="font-mono text-xs uppercase tracking-[0.18em] text-amber">Restart needed</p>
          <p className="mt-2 text-sm text-muted">Saved settings marked "restart needed" apply once these services restart. Run on the server, from the Kairon DFIR directory:</p>
          <pre className="mt-3 overflow-x-auto rounded-xl bg-abyss/90 p-3 text-sm text-slate-200">{data.restart_command}</pre>
          <button type="button" onClick={() => void copyRestart(data.restart_command as string)} className="mt-3 rounded-2xl border border-line bg-abyss/80 px-4 py-2 text-sm text-muted">
            {copied ? "Copied" : "Copy command"}
          </button>
        </div>
      ) : null}

      {groups.map((group) => (
        <div key={group} className="rounded-3xl border border-line bg-panel/70 p-5 shadow-panel">
          <p className="font-mono text-xs uppercase tracking-[0.18em] text-accent">{GROUP_LABELS[group] ?? group}</p>
          <div className="mt-4 divide-y divide-line/60">
            {data.settings
              .filter((entry) => entry.group === group)
              .map((entry) => {
                const drafted = entry.key in draft;
                const draftValue = draft[entry.key];
                const value = drafted ? (draftValue === null ? entry.env_value : (draftValue as InstanceSettingValue)) : current(entry);
                const saved = drafted ? draftValue !== null && (entry.override !== null || draftValue !== entry.env_value) : entry.override !== null;
                return (
                  <div key={entry.key} className="grid gap-3 py-4 md:grid-cols-[minmax(0,1fr)_auto]" data-testid={`instance-setting-${entry.key}`}>
                    <div className="min-w-0">
                      <p className="text-sm font-medium text-ink">
                        {entry.label}
                        {entry.pending_restart ? <span className="ml-2 rounded-full border border-amber/40 px-2 py-0.5 text-[11px] text-amber">restart needed</span> : null}
                      </p>
                      <p className="mt-1 text-sm text-muted">{entry.description}</p>
                      <p className="mt-1 text-xs text-slate-400">
                        <span className="font-mono">{entry.key}</span> · .env: {formatSettingValue(entry, entry.env_value)}
                        {saved ? " · saved here" : ""} · {entry.applies === "live" ? "applies at once" : `applies on restart of ${entry.services.join(", ")}`}
                      </p>
                      {errors[entry.key] ? <p className="mt-1 text-xs text-red-300">{errors[entry.key]}</p> : null}
                    </div>
                    <div className="flex flex-wrap items-center gap-3 md:justify-end">
                      <SettingControl entry={entry} value={value} onChange={(next) => setDraft((prev) => ({ ...prev, [entry.key]: next }))} />
                      {saved ? (
                        <button type="button" onClick={() => setDraft((prev) => ({ ...prev, [entry.key]: null }))} className="rounded-xl border border-line px-3 py-1.5 text-xs text-muted">
                          Use .env
                        </button>
                      ) : null}
                    </div>
                  </div>
                );
              })}
          </div>
        </div>
      ))}

      <div className="flex flex-wrap items-center gap-3">
        <button
          type="button"
          onClick={() => saveMutation.mutate(changes)}
          disabled={!Object.keys(changes).length || Object.keys(errors).length > 0 || saveMutation.isPending}
          className="rounded-2xl bg-accent px-4 py-2 text-sm font-semibold text-abyss disabled:cursor-not-allowed disabled:opacity-60"
        >
          {saveMutation.isPending ? "Saving…" : "Save changes"}
        </button>
        {Object.keys(draft).length ? (
          <button type="button" onClick={() => setDraft({})} className="rounded-2xl border border-line px-4 py-2 text-sm text-muted">
            Discard
          </button>
        ) : null}
        {message ? <p className="text-sm text-accent">{message}</p> : null}
      </div>

      <div className="rounded-3xl border border-line bg-panel/70 p-5 shadow-panel">
        <p className="font-mono text-xs uppercase tracking-[0.18em] text-accent">Changed only in .env</p>
        <p className="mt-2 text-sm text-muted">These let the server reach outside the lab or the host, so a web session cannot turn them on. Change them in .env on the server, then run docker compose up -d from the Kairon DFIR directory.</p>
        <ul className="mt-3 space-y-1 text-sm">
          {data.read_only.map((item) => (
            <li key={item.key} className="text-muted">
              <span className="font-mono text-ink">{item.key}</span> = {String(item.value)} · {item.reason}
            </li>
          ))}
        </ul>
      </div>
    </section>
  );
}
