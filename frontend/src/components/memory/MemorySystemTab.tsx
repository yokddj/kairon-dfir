import { useState } from "react";
import { useQuery } from "@tanstack/react-query";
import { type MemoryRunSelector, type MemorySystemInfo, api } from "../../api/client";

type Props = {
  caseId: string;
  runOptions: MemoryRunSelector | null;
  selectedRunId: string | null;
  onSelectRunId: (next: string | null) => void;
};

function Field({ label, value, missing }: { label: string; value: string; missing?: boolean }) {
  return (
    <div className="rounded-xl border border-line bg-abyss/40 p-2" data-testid={`system-field-${label.toLowerCase().replace(/\s+/g, "-")}`}>
      <p className="text-[10px] uppercase tracking-[0.16em] text-muted">{label}</p>
      <p className={`mt-1 break-words ${missing ? "text-muted" : "text-ink"}`}>{value}</p>
    </div>
  );
}

function SystemInfoCard({ item, runId, isPrimary }: { item: MemorySystemInfo; runId: string; isPrimary: boolean }) {
  const host = (item.host && (item.host.name as string | undefined)) || "—";
  const os = item.os || {};
  const memory = item.memory || {};
  const kernelBase = (os.kernel_base as string | undefined) || "—";
  const kernelVersion = (os.kernel_version as string | undefined) || "—";
  const arch = (os.machine_type as string | undefined) || "—";
  const layerName = (memory.layer_name as string | undefined) || "—";
  const dtb = (memory.dtb as string | undefined) || "—";
  const symbolTable = (memory.kernel_symbols as string | undefined) || "—";
  const systemTime = (memory.system_time as string | undefined) || "—";
  const raw = (item.raw as Record<string, unknown> | undefined) || {};
  const backendVersion = (raw.backend_version as string | undefined) || "—";
  const ntMajor = (os.nt_major_version as string | undefined) || "—";
  const ntMinor = (os.nt_minor_version as string | undefined) || "—";
  const family = (os.family as string | undefined) || "windows";

  const missingFields = [
    kernelBase === "—" && "kernel base",
    kernelVersion === "—" && "kernel version",
    arch === "—" && "architecture",
    layerName === "—" && "memory layer",
    symbolTable === "—" && "symbol table",
    systemTime === "—" && "system time",
  ].filter(Boolean) as string[];

  return (
    <article
      className={`rounded-2xl border p-4 ${isPrimary ? "border-accent/40 bg-accent/5" : "border-line bg-abyss/40"}`}
      data-testid={`system-info-card-${isPrimary ? "primary" : "secondary"}`}
    >
      <header className="flex flex-wrap items-start justify-between gap-2">
        <div>
          <p className="font-mono text-xs uppercase tracking-[0.18em] text-muted">
            {isPrimary ? "Latest successful windows.info" : "Historical system result"}
          </p>
          <h4 className="mt-1 text-base font-semibold">{family} · {arch}</h4>
        </div>
        <span className="rounded-md border border-line bg-abyss/60 px-2 py-0.5 text-[10px] text-muted">
          Run {runId.slice(0, 8)}…
        </span>
      </header>
        <dl className="mt-3 grid gap-2 text-xs md:grid-cols-2">
          <Field label="OS family" value={family} />
          <Field label="Architecture" value={arch} missing={arch === "—"} />
          <Field label="NT version" value={`${ntMajor}.${ntMinor}`} missing={ntMajor === "—"} />
          <Field label="Kernel base" value={kernelBase} missing={kernelBase === "—"} />
          <Field label="Kernel version" value={kernelVersion} missing={kernelVersion === "—"} />
          <Field label="Build" value={backendVersion} missing={backendVersion === "—"} />
          <Field label="Memory layer" value={layerName} missing={layerName === "—"} />
          <Field label="Symbol table" value={symbolTable} missing={symbolTable === "—"} />
          <Field label="DTB" value={dtb} missing={dtb === "—"} />
          <Field label="System time" value={systemTime} missing={systemTime === "—"} />
          <Field label="Host" value={host} missing={host === "—"} />
          <Field label="Normalization" value="memory_process_canonical_v1" />
        </dl>
      {missingFields.length > 0 ? (
        <p className="mt-2 rounded-md border border-amber-400/30 bg-amber-500/10 px-2 py-1 text-[10px] text-amber-100">
          Some fields were not normalized from the current Volatility output: {missingFields.join(", ")}.
        </p>
      ) : null}
    </article>
  );
}

export function MemorySystemTab({ caseId, runOptions, selectedRunId, onSelectRunId }: Props) {
  const effectiveRunId = selectedRunId || runOptions?.default_run_id || null;
  const systemInfoQuery = useQuery({
    queryKey: ["memory-system-info", caseId],
    queryFn: () => api.getCaseMemorySystemInfo(caseId),
    enabled: Boolean(caseId),
    refetchOnWindowFocus: false,
  });

  const [showHistorical, setShowHistorical] = useState(false);

  const infos = (systemInfoQuery.data || []).slice();
  const primary = infos[0];
  const historical = infos.slice(1);

  return (
    <div className="space-y-4" data-testid="memory-system-tab">
      <section className="rounded-[28px] border border-line bg-panel/60 p-5 shadow-panel">
        <header className="flex flex-wrap items-center justify-between gap-3">
          <div>
            <h3 className="text-sm font-semibold uppercase tracking-[0.18em] text-muted">System information</h3>
            <p className="mt-1 text-xs text-muted">
              The latest successful <span className="font-mono text-slate-200">windows.info</span> run. Older results are collapsed by default.
            </p>
          </div>
          <div className="flex flex-wrap items-center gap-2 text-xs">
            <label className="text-muted" htmlFor="system-run-picker">Run</label>
            <select
              id="system-run-picker"
              value={effectiveRunId || ""}
              onChange={(event) => onSelectRunId(event.target.value || null)}
              className="rounded-xl border border-line bg-abyss/70 px-2 py-1 text-sm"
              data-testid="system-run-picker"
            >
              <option value="">Latest</option>
              {(runOptions?.runs || []).map((run) => (
                <option key={run.run_id} value={run.run_id}>
                  {run.profile} · {run.status} · {(run.completed_at || run.created_at).slice(0, 16).replace("T", " ")} UTC
                </option>
              ))}
            </select>
          </div>
        </header>

        {systemInfoQuery.isLoading ? (
          <p className="mt-3 text-sm text-muted">Loading system information…</p>
        ) : systemInfoQuery.error instanceof Error ? (
          <p className="mt-3 rounded-2xl border border-rose-400/30 bg-rose-500/10 p-3 text-sm text-rose-200">
            {systemInfoQuery.error.message}
          </p>
        ) : primary ? (
          <div className="mt-4">
            <SystemInfoCard item={primary} runId={primary.memory_run_id} isPrimary />
            {historical.length > 0 ? (
              <div className="mt-4">
                <button
                  type="button"
                  onClick={() => setShowHistorical((value) => !value)}
                  aria-expanded={showHistorical}
                  className="rounded-xl border border-line bg-abyss/70 px-3 py-2 text-xs text-muted"
                  data-testid="system-toggle-historical"
                >
                  {showHistorical
                    ? `Hide historical results (${historical.length})`
                    : `View historical system results (${historical.length})`}
                </button>
                {showHistorical ? (
                  <div className="mt-3 grid gap-3 md:grid-cols-2">
                    {historical.map((item) => (
                      <SystemInfoCard
                        key={item.memory_plugin_run_id || item.memory_run_id}
                        item={item}
                        runId={item.memory_run_id}
                        isPrimary={false}
                      />
                    ))}
                  </div>
                ) : null}
              </div>
            ) : null}
          </div>
        ) : (
          <p className="mt-3 rounded-2xl border border-line bg-abyss/60 p-4 text-sm text-muted">
            No system information has been reported.
          </p>
        )}
      </section>
    </div>
  );
}
