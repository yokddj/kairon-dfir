import { useMemo, useRef, useState } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";

import { api, type RuleImportRun } from "../../api/client";

/**
 * Three steps: pick the rules, watch them import, read what came of it.
 *
 * The last step is the point. Importing a Sigma pack tells you almost nothing
 * on its own -- what an analyst needs before trusting an alert is how many of
 * those rules this engine can actually evaluate, and why the rest cannot. That
 * breakdown already existed on the import run; it was never put in front of
 * anyone, so a pack half of which can never fire looked exactly like one that
 * works.
 */

const ARCHIVE_SUFFIXES = [".zip", ".7z", ".tar", ".gz", ".tgz", ".bz2", ".rar"];
const ACTIVE_STATUSES = new Set(["queued", "running", "pending"]);

type Step = "choose" | "importing" | "review";

function isArchive(file: File): boolean {
  const lower = file.name.toLowerCase();
  return ARCHIVE_SUFFIXES.some((suffix) => lower.endsWith(suffix));
}

export function unsupportedBreakdown(run: RuleImportRun | undefined): Array<{ reason: string; count: number; examples: string[] }> {
  const details = (run?.details_json ?? {}) as Record<string, unknown>;
  const byFeature = (details.sigma_unsupported_by_feature ?? details.unsupported_by_feature) as Record<string, number> | undefined;
  const examples = (details.sigma_coverage_examples ?? details.coverage_examples) as Record<string, string[]> | undefined;
  if (!byFeature) return [];
  return Object.entries(byFeature)
    .map(([reason, count]) => ({ reason, count: Number(count) || 0, examples: examples?.[reason] ?? [] }))
    .sort((a, b) => b.count - a.count);
}

export function reasonLabel(reason: string): string {
  if (reason.startsWith("unmapped_field")) return "Uses a field this engine cannot read";
  if (reason.startsWith("unsupported_modifier")) return "Sigma modifier not implemented";
  if (reason === "unsupported_correlation") return "Correlation rule (near / within / by)";
  if (reason === "unsupported_condition") return "Condition too complex to compile";
  if (reason === "compile_error") return "Rule did not compile";
  return reason.replace(/_/g, " ");
}

type Props = {
  open: boolean;
  onClose: () => void;
  engine: "sigma" | "yara";
  namespace?: string;
  caseId?: string;
};

export function RuleImportWizard({ open, onClose, engine, namespace, caseId }: Props) {
  const queryClient = useQueryClient();
  const inputRef = useRef<HTMLInputElement | null>(null);
  const [step, setStep] = useState<Step>("choose");
  const [file, setFile] = useState<File | null>(null);
  const [dragging, setDragging] = useState(false);
  const [importRunId, setImportRunId] = useState<string | null>(null);
  const [failure, setFailure] = useState<string | null>(null);

  const runQuery = useQuery({
    queryKey: ["rule-import-run", importRunId],
    queryFn: () => api.getRuleImport(importRunId as string),
    enabled: Boolean(importRunId),
    refetchInterval: (query) => {
      const current = query.state.data as RuleImportRun | undefined;
      return current && ACTIVE_STATUSES.has(current.status) ? 1500 : false;
    },
  });
  const run = runQuery.data;

  const startMutation = useMutation({
    mutationFn: async (selected: File): Promise<string | null> => {
      const options = {
        engine,
        import_mode: engine === "yara" ? (isArchive(selected) ? "rule_pack" : "auto") : "split",
        case_id: engine === "yara" ? caseId || undefined : undefined,
        namespace: namespace || undefined,
        enabled: true,
      };
      const response = isArchive(selected)
        ? await api.importRuleArchive(selected, options)
        : await api.importRuleFile(selected, options);
      return response.import_run_id ?? null;
    },
    onSuccess: (runId) => {
      setImportRunId(runId);
      setStep(runId ? "importing" : "review");
      void queryClient.invalidateQueries({ queryKey: ["rules"] });
    },
    onError: (error: unknown) => {
      setFailure(error instanceof Error ? error.message : "The import could not be started.");
      setStep("choose");
    },
  });

  const finished = Boolean(run && !ACTIVE_STATUSES.has(run.status));
  if (step === "importing" && finished) {
    setStep("review");
  }

  const breakdown = useMemo(() => unsupportedBreakdown(run), [run]);
  const evaluable = Math.max((run?.imported_count ?? 0) - (run?.unsupported_count ?? 0), 0);

  function reset() {
    setStep("choose");
    setFile(null);
    setImportRunId(null);
    setFailure(null);
  }

  function close() {
    reset();
    onClose();
  }

  if (!open) return null;

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/60 p-4" data-testid="rule-import-wizard">
      <div className="max-h-[90vh] w-full max-w-2xl overflow-y-auto rounded-2xl border border-line bg-abyss p-6">
        <div className="flex items-start justify-between gap-4">
          <div>
            <h2 className="text-lg font-semibold text-ink">Import {engine === "sigma" ? "Sigma" : "YARA"} rules</h2>
            <p className="mt-1 text-xs text-muted">
              Rules are stored once and reused for every run. You never upload them again to re-run them.
            </p>
          </div>
          <button type="button" onClick={close} className="rounded-md border border-line px-2 py-1 text-xs text-muted" data-testid="rule-wizard-close">
            Close
          </button>
        </div>

        {step === "choose" ? (
          <div className="mt-5">
            <div
              onDragOver={(event) => {
                event.preventDefault();
                setDragging(true);
              }}
              onDragLeave={() => setDragging(false)}
              onDrop={(event) => {
                event.preventDefault();
                setDragging(false);
                const dropped = event.dataTransfer.files?.[0];
                if (dropped) setFile(dropped);
              }}
              className={`rounded-2xl border border-dashed p-8 text-center ${dragging ? "border-accent bg-accent/5" : "border-line"}`}
              data-testid="rule-wizard-dropzone"
            >
              <p className="text-sm text-ink">{file ? file.name : "Drop a rule file or an archive of rules here"}</p>
              <p className="mt-1 text-xs text-muted">A single .yml, or a .zip / .7z / .tar.gz holding a whole ruleset.</p>
              <button
                type="button"
                onClick={() => inputRef.current?.click()}
                className="mt-3 rounded-2xl border border-line bg-abyss/70 px-4 py-2 text-sm text-ink"
                data-testid="rule-wizard-browse"
              >
                Choose a file
              </button>
              <input
                ref={inputRef}
                type="file"
                className="hidden"
                onChange={(event) => setFile(event.target.files?.[0] ?? null)}
                data-testid="rule-wizard-file-input"
              />
            </div>
            {failure ? <p className="mt-3 text-xs text-danger" data-testid="rule-wizard-error">{failure}</p> : null}
            <div className="mt-5 flex justify-end gap-2">
              <button type="button" onClick={close} className="rounded-2xl border border-line px-4 py-2 text-sm text-muted">
                Cancel
              </button>
              <button
                type="button"
                disabled={!file || startMutation.isPending}
                onClick={() => file && startMutation.mutate(file)}
                className="rounded-2xl bg-accent px-4 py-2 text-sm font-semibold text-abyss disabled:opacity-50"
                data-testid="rule-wizard-start"
              >
                {startMutation.isPending ? "Starting..." : "Import"}
              </button>
            </div>
          </div>
        ) : null}

        {step === "importing" ? (
          <div className="mt-5 rounded-2xl border border-line bg-abyss/60 p-4" data-testid="rule-wizard-importing">
            <p className="text-sm font-semibold text-ink">Importing…</p>
            <p className="mt-1 text-xs text-muted">
              {run?.current_phase || "starting"} · {run?.processed_files ?? 0} / {run?.total_files ?? 0} files · {run?.total_rules_found ?? 0} rules found
            </p>
          </div>
        ) : null}

        {step === "review" ? (
          <div className="mt-5" data-testid="rule-wizard-review">
            <div className="grid gap-3 sm:grid-cols-3">
              <div className="rounded-2xl border border-line bg-abyss/60 px-4 py-3">
                <p className="font-mono text-[11px] uppercase tracking-[0.16em] text-muted">Imported</p>
                <p className="mt-1 text-2xl font-semibold text-ink" data-testid="rule-wizard-imported">{run?.imported_count ?? 0}</p>
              </div>
              <div className="rounded-2xl border border-line bg-abyss/60 px-4 py-3">
                <p className="font-mono text-[11px] uppercase tracking-[0.16em] text-muted">Can be evaluated</p>
                <p className="mt-1 text-2xl font-semibold text-mint" data-testid="rule-wizard-evaluable">{evaluable}</p>
              </div>
              <div className="rounded-2xl border border-line bg-abyss/60 px-4 py-3">
                <p className="font-mono text-[11px] uppercase tracking-[0.16em] text-muted">Cannot</p>
                <p className="mt-1 text-2xl font-semibold text-amber" data-testid="rule-wizard-unsupported">{run?.unsupported_count ?? 0}</p>
              </div>
            </div>

            {(run?.unsupported_count ?? 0) > 0 ? (
              <div className="mt-4 rounded-2xl border border-amber-400/40 bg-amber-500/10 p-3">
                <p className="text-sm font-semibold text-amber-100">
                  {run?.unsupported_count} rules were stored but cannot fire on this data
                </p>
                <p className="mt-1 text-xs text-amber-100/80">
                  They are kept so the set stays complete, and excluded from runs rather than failing quietly.
                </p>
                {breakdown.length ? (
                  <ul className="mt-3 space-y-2" data-testid="rule-wizard-breakdown">
                    {breakdown.map((item) => (
                      <li key={item.reason} className="text-xs text-amber-100/90">
                        <span className="font-semibold">{item.count}×</span> {reasonLabel(item.reason)}
                        {item.examples.length ? <span className="text-amber-100/60"> — e.g. {item.examples.slice(0, 2).join(", ")}</span> : null}
                      </li>
                    ))}
                  </ul>
                ) : null}
              </div>
            ) : null}

            {run?.last_error ? <p className="mt-3 text-xs text-danger" data-testid="rule-wizard-run-error">{run.last_error}</p> : null}

            <div className="mt-5 flex justify-end gap-2">
              <button type="button" onClick={reset} className="rounded-2xl border border-line px-4 py-2 text-sm text-muted" data-testid="rule-wizard-import-more">
                Import more
              </button>
              <button type="button" onClick={close} className="rounded-2xl bg-accent px-4 py-2 text-sm font-semibold text-abyss" data-testid="rule-wizard-done">
                Done
              </button>
            </div>
          </div>
        ) : null}
      </div>
    </div>
  );
}
