import { useMemo, useState } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";

import { api, type Rule, type RuleRun } from "../../api/client";
import { RuleImportWizard } from "./RuleImportWizard";
import { reasonLabel } from "./RuleImportWizard";

/**
 * One panel, three questions, in the order an analyst asks them:
 * what am I detecting with, how much of it can this case answer, and what
 * happened when it ran.
 *
 * The screen this replaces had five tabs on two different axes -- three engines
 * beside two objects -- so reaching anything meant holding both in your head,
 * and each engine tab repeated its own import, selection, scope and run
 * controls: ninety interactive controls in total. The engine is a property of a
 * rule, so here it is a filter, not a place.
 */

type Zone = "library" | "coverage" | "runs";
type RunDepth = "fast_triage" | "balanced" | "exhaustive";

const ZONES: Array<{ id: Zone; label: string }> = [
  { id: "library", label: "Library" },
  { id: "coverage", label: "Coverage" },
  { id: "runs", label: "Runs" },
];

const DEPTHS: Array<{ id: RunDepth; label: string; hint: string }> = [
  { id: "fast_triage", label: "Fast", hint: "Skips rules that match very broadly" },
  { id: "balanced", label: "Normal", hint: "The usual choice" },
  { id: "exhaustive", label: "Exhaustive", hint: "Slower; examines more candidates per rule" },
];

const ACTIVE_RUN_STATUSES = new Set(["queued", "running", "pending"]);

export function coverageTotals(coverage: unknown): { evaluable: number; blocked: number; reasons: Array<{ reason: string; count: number }> } {
  const data = (coverage ?? {}) as Record<string, unknown>;
  const support = (data.by_support_status ?? {}) as Record<string, number>;
  const evaluable = (Number(support.fully_supported) || 0) + (Number(support.partially_supported) || 0);
  const blocked = Number(support.unsupported) || 0;
  // by_compile_status counts every rule; the compiled bucket is the evaluable
  // ones and is not a reason for anything, so it is dropped from the breakdown.
  const byStatus = (data.by_compile_status ?? {}) as Record<string, number>;
  const reasons = Object.entries(byStatus)
    .filter(([status]) => status !== "compiled")
    .map(([reason, count]) => ({ reason, count: Number(count) || 0 }))
    .sort((a, b) => b.count - a.count);
  return { evaluable, blocked, reasons };
}

type Props = {
  open: boolean;
  onClose: () => void;
  caseId: string;
};

export function DetectionRulesPanel({ open, onClose, caseId }: Props) {
  const queryClient = useQueryClient();
  const [zone, setZone] = useState<Zone>("library");
  const [search, setSearch] = useState("");
  const [engine, setEngine] = useState("");
  const [depth, setDepth] = useState<RunDepth>("balanced");
  const [wizardOpen, setWizardOpen] = useState(false);
  const [runMessage, setRunMessage] = useState<string | null>(null);

  const rulesQuery = useQuery({
    queryKey: ["rules", { search, engine }],
    queryFn: () => api.listRules({ search: search || undefined, engine: engine || undefined, page_size: 50 }),
    enabled: open,
  });
  const coverageQuery = useQuery({
    queryKey: ["sigma-coverage", caseId],
    queryFn: () => api.getSigmaCoverage({ case_id: caseId, scope: "all" }),
    enabled: open && zone === "coverage",
  });
  const runsQuery = useQuery({
    queryKey: ["case-rule-runs", caseId],
    queryFn: () => api.listCaseRuleRuns(caseId),
    enabled: open && zone === "runs",
    refetchInterval: (query) => {
      const runs = (query.state.data ?? []) as RuleRun[];
      return runs.some((run) => ACTIVE_RUN_STATUSES.has(String(run.status))) ? 3000 : false;
    },
  });

  const toggleMutation = useMutation({
    mutationFn: (rule: Rule) => api.updateRule(rule.id, { enabled: !rule.enabled }),
    onSuccess: () => void queryClient.invalidateQueries({ queryKey: ["rules"] }),
  });

  const runMutation = useMutation({
    mutationFn: () => api.runRulesForCase(caseId, { engines: ["sigma"], enabled_only: true, scope: "all", run_mode: depth }),
    onSuccess: (response) => {
      // Say how many rules are actually going to run. "Queued" alone hides the
      // difference between a full sweep and one that silently skipped half the
      // library.
      setRunMessage(
        response.queued_rules !== undefined
          ? `${response.queued_rules} rules queued. Follow it under Runs.`
          : response.message || "Run queued.",
      );
      setZone("runs");
      void queryClient.invalidateQueries({ queryKey: ["case-rule-runs", caseId] });
    },
    onError: (error: unknown) => setRunMessage(error instanceof Error ? error.message : "The run could not be started."),
  });

  const rules = rulesQuery.data?.items ?? [];
  const totals = useMemo(() => coverageTotals(coverageQuery.data), [coverageQuery.data]);

  if (!open) return null;

  return (
    <div className="fixed inset-0 z-40 flex justify-end bg-black/50" data-testid="detection-rules-panel">
      <aside className="flex h-full w-full max-w-3xl flex-col overflow-y-auto border-l border-line bg-abyss p-6">
        <div className="flex items-start justify-between gap-4">
          <div>
            <p className="font-mono text-[11px] uppercase tracking-[0.18em] text-accent">Detection rules</p>
            <h2 className="mt-1 text-lg font-semibold text-ink">What this case is being detected with</h2>
          </div>
          <button type="button" onClick={onClose} className="rounded-md border border-line px-2 py-1 text-xs text-muted" data-testid="rules-panel-close">
            Close
          </button>
        </div>

        <div className="mt-5 rounded-2xl border border-line bg-panel/50 p-4">
          <div className="flex flex-wrap items-center gap-2">
            <span className="text-sm text-ink">Run the rules over this case</span>
            <select
              value={depth}
              onChange={(event) => setDepth(event.target.value as RunDepth)}
              className="rounded-xl border border-line bg-abyss/70 px-3 py-1.5 text-sm"
              data-testid="rules-panel-depth"
            >
              {DEPTHS.map((item) => (
                <option key={item.id} value={item.id}>{item.label}</option>
              ))}
            </select>
            <button
              type="button"
              onClick={() => runMutation.mutate()}
              disabled={runMutation.isPending}
              className="rounded-2xl bg-accent px-4 py-2 text-sm font-semibold text-abyss disabled:opacity-50"
              data-testid="rules-panel-run"
            >
              {runMutation.isPending ? "Starting..." : "Run"}
            </button>
          </div>
          <p className="mt-2 text-xs text-muted">{DEPTHS.find((item) => item.id === depth)?.hint}</p>
          {runMessage ? <p className="mt-2 text-xs text-mint" data-testid="rules-panel-run-message">{runMessage}</p> : null}
        </div>

        <div className="mt-5 flex gap-2">
          {ZONES.map((item) => (
            <button
              key={item.id}
              type="button"
              onClick={() => setZone(item.id)}
              className={`rounded-full border px-4 py-1.5 text-sm ${zone === item.id ? "border-accent bg-accent/10 text-ink" : "border-line bg-abyss/70 text-muted"}`}
              data-testid={`rules-panel-zone-${item.id}`}
            >
              {item.label}
            </button>
          ))}
        </div>

        {zone === "library" ? (
          <div className="mt-4" data-testid="rules-panel-library">
            <div className="flex flex-wrap gap-2">
              <input
                value={search}
                onChange={(event) => setSearch(event.target.value)}
                placeholder="Search rules"
                className="min-w-[200px] flex-1 rounded-xl border border-line bg-abyss/70 px-3 py-2 text-sm"
                data-testid="rules-panel-search"
              />
              <select
                value={engine}
                onChange={(event) => setEngine(event.target.value)}
                className="rounded-xl border border-line bg-abyss/70 px-3 py-2 text-sm"
                data-testid="rules-panel-engine"
              >
                <option value="">All engines</option>
                <option value="sigma">Sigma</option>
                <option value="heuristic">Heuristic</option>
              </select>
              <button
                type="button"
                onClick={() => setWizardOpen(true)}
                className="rounded-2xl border border-line bg-abyss/70 px-4 py-2 text-sm text-ink"
                data-testid="rules-panel-import"
              >
                Import rules
              </button>
            </div>
            <p className="mt-3 text-xs text-muted">{rulesQuery.data?.total ?? 0} rules stored</p>
            <ul className="mt-2 space-y-1">
              {rules.map((rule) => (
                <li key={rule.id} className="flex items-center justify-between gap-3 rounded-xl border border-line bg-panel/40 px-3 py-2">
                  <div className="min-w-0">
                    <p className="truncate text-sm text-ink">{rule.title || rule.name}</p>
                    <p className="truncate text-[11px] text-muted">{rule.engine} · {rule.severity || rule.level || "unrated"}</p>
                  </div>
                  <button
                    type="button"
                    onClick={() => toggleMutation.mutate(rule)}
                    className={`shrink-0 rounded-full border px-3 py-1 text-[11px] ${rule.enabled ? "border-mint/40 text-mint" : "border-line text-muted"}`}
                  >
                    {rule.enabled ? "Enabled" : "Disabled"}
                  </button>
                </li>
              ))}
            </ul>
          </div>
        ) : null}

        {zone === "coverage" ? (
          <div className="mt-4" data-testid="rules-panel-coverage">
            {coverageQuery.isLoading ? <p className="text-sm text-muted">Working it out…</p> : null}
            <div className="grid gap-3 sm:grid-cols-2">
              <div className="rounded-2xl border border-line bg-panel/40 px-4 py-3">
                <p className="font-mono text-[11px] uppercase tracking-[0.16em] text-muted">Can be evaluated</p>
                <p className="mt-1 text-2xl font-semibold text-mint">{totals.evaluable}</p>
              </div>
              <div className="rounded-2xl border border-line bg-panel/40 px-4 py-3">
                <p className="font-mono text-[11px] uppercase tracking-[0.16em] text-muted">Cannot</p>
                <p className="mt-1 text-2xl font-semibold text-amber">{totals.blocked}</p>
              </div>
            </div>
            {totals.reasons.length ? (
              <ul className="mt-4 space-y-2" data-testid="rules-panel-coverage-reasons">
                {totals.reasons.map((item) => (
                  <li key={item.reason} className="text-xs text-muted">
                    <span className="font-semibold text-ink">{item.count}×</span> {reasonLabel(item.reason)}
                  </li>
                ))}
              </ul>
            ) : null}
            <p className="mt-4 text-xs text-muted">
              A rule that cannot be evaluated is stored but excluded from runs, so it never appears to fire on everything.
            </p>
          </div>
        ) : null}

        {zone === "runs" ? (
          <div className="mt-4" data-testid="rules-panel-runs">
            {(runsQuery.data ?? []).length === 0 ? (
              <p className="text-sm text-muted">No runs yet for this case.</p>
            ) : (
              <ul className="space-y-1">
                {(runsQuery.data ?? []).slice(0, 20).map((run) => (
                  <li key={run.id} className="rounded-xl border border-line bg-panel/40 px-3 py-2">
                    <div className="flex items-center justify-between gap-3">
                      <span className="text-sm text-ink">{run.status}</span>
                      <span className="text-[11px] text-muted">{run.processed_rules ?? 0} / {run.total_rules ?? 0} rules</span>
                    </div>
                    <p className="mt-1 text-[11px] text-muted">
                      {run.created_detections ?? 0} detections{run.current_phase ? ` · ${run.current_phase}` : ""}
                    </p>
                  </li>
                ))}
              </ul>
            )}
          </div>
        ) : null}

        <RuleImportWizard open={wizardOpen} onClose={() => setWizardOpen(false)} engine="sigma" caseId={caseId} />
      </aside>
    </div>
  );
}
