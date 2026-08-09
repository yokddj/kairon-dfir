import { useMutation, useQuery } from "@tanstack/react-query";
import { useEffect, useRef, useState } from "react";
import { api, type LinuxSymbolIdentity, type LinuxSymbolValidationResult } from "../../api/client";

// Evidence-scoped Linux ISF upload + validate panel (Memory Preparation
// Phase 3). Shown by MemoryEvidencePreparationCard ONLY when
// platform === "linux" && readiness === "symbols_required".
//
// Validation runs asynchronously on the memory-worker -- the backend API
// process cannot write /volatility-cache (read-only mount by design), so
// POST .../linux-symbols/validate only enqueues a job and this panel
// polls GET .../linux-symbols/validate/{id} for the result, following
// the same refetchInterval-while-non-terminal pattern already used by
// MemoryPreparationCard.tsx's symbolPreparationQuery.
//
// DELIBERATELY a new, small component rather than a reuse of
// MemorySymbolImportPanel.tsx in this same directory: that component is
// tightly coupled to the admin-only, Windows PDB-requirement-scoped
// recovery flow. See the Phase 3 technical report for the audit that led
// to this decision -- the original panel is untouched.

type Stage =
  | { kind: "selecting" }
  | { kind: "selected"; file: File }
  | { kind: "polling"; file: File; validationId: string }
  | { kind: "done"; file: File; validationId: string; result: LinuxSymbolValidationResult }
  | { kind: "submit_failed"; file: File; message: string };

type Props = {
  caseId: string;
  evidenceId: string;
  architecture: string;
  onValidated: () => void;
};

const NON_TERMINAL: ReadonlySet<string> = new Set(["queued", "validating"]);

function formatBytes(bytes: number): string {
  if (bytes < 1024) return `${bytes} B`;
  const units = ["KB", "MB", "GB"];
  let value = bytes / 1024;
  let unitIndex = 0;
  while (value >= 1024 && unitIndex < units.length - 1) {
    value /= 1024;
    unitIndex += 1;
  }
  return `${value.toFixed(1)} ${units[unitIndex]}`;
}

function identityLine(identity: LinuxSymbolIdentity | null): string {
  if (!identity) return "Unknown";
  const parts = [identity.kernel_release, identity.architecture, identity.build_id ? `build ${identity.build_id}` : null].filter(Boolean);
  return parts.length ? parts.join(" · ") : "Unknown";
}

export function LinuxSymbolUploadPanel({ caseId, evidenceId, architecture, onValidated }: Props) {
  const [stage, setStage] = useState<Stage>({ kind: "selecting" });
  const fileInputRef = useRef<HTMLInputElement | null>(null);
  const notifiedValidationIdRef = useRef<string | null>(null);

  const requirementQuery = useQuery({
    queryKey: ["linux-symbol-requirement", caseId, evidenceId],
    queryFn: () => api.getLinuxSymbolRequirement(caseId, evidenceId),
    enabled: Boolean(caseId && evidenceId),
    refetchOnWindowFocus: false,
  });

  const activeValidationId = stage.kind === "polling" || stage.kind === "done" ? stage.validationId : null;
  const statusQuery = useQuery({
    queryKey: ["linux-symbol-validation", caseId, evidenceId, activeValidationId],
    queryFn: () => api.getLinuxSymbolValidationStatus(caseId, evidenceId, activeValidationId as string),
    enabled: Boolean(activeValidationId) && stage.kind === "polling",
    refetchOnWindowFocus: false,
    // Same non-aggressive polling interval Kairon already uses elsewhere
    // (MemoryEvidencePage.tsx's symbolPreparationQuery): poll only while
    // the job has not reached a terminal state, then stop.
    refetchInterval: (query) => {
      const data = query.state.data as LinuxSymbolValidationResult | undefined;
      return data && NON_TERMINAL.has(data.status) ? 2_000 : false;
    },
  });

  const submitMutation = useMutation({
    mutationFn: (file: File) => api.validateLinuxEvidenceSymbols(caseId, evidenceId, file),
    onSuccess: (enqueued, file) => {
      setStage({ kind: "polling", file, validationId: enqueued.validation_id });
    },
    onError: (error, file) => {
      setStage({ kind: "submit_failed", file, message: error instanceof Error ? error.message : "Upload failed." });
    },
  });

  useEffect(() => {
    if (stage.kind !== "polling") return;
    const data = statusQuery.data;
    if (!data || NON_TERMINAL.has(data.status)) return;
    setStage({ kind: "done", file: stage.file, validationId: stage.validationId, result: data });
    if (data.status === "valid" && notifiedValidationIdRef.current !== stage.validationId) {
      notifiedValidationIdRef.current = stage.validationId;
      onValidated();
    }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [stage, statusQuery.data]);

  function handleFileChosen(file: File | null) {
    if (!file) return;
    // Selecting a file never validates it automatically -- only sets the
    // pending selection. Validation happens on an explicit click.
    setStage({ kind: "selected", file });
  }

  function handleValidate() {
    if (stage.kind !== "selected") return;
    submitMutation.mutate(stage.file);
  }

  function handleChooseAnother() {
    setStage({ kind: "selecting" });
    if (fileInputRef.current) fileInputRef.current.value = "";
  }

  const result = stage.kind === "done" ? stage.result : null;
  // Prevent a second, concurrent validation of the same evidence: once a
  // file is selected, the file input and Validate button are hidden for
  // every stage except the initial "pick a file" and the terminal
  // failure states (where "Choose another file" explicitly resets).
  const showFilePicker = stage.kind === "selecting";
  const showValidateButton = stage.kind === "selected";
  const isSubmittingOrPolling = stage.kind === "polling" || submitMutation.isPending;

  return (
    <section className="mt-4 rounded-2xl border border-line bg-abyss/60 p-4" data-testid="linux-symbol-upload-panel">
      <p className="font-mono text-[11px] uppercase tracking-[0.16em] text-accent">Linux memory symbols</p>
      <p className="mt-2 text-sm text-ink">
        Kairon requires a compatible Volatility 3 ISF for this Linux kernel.
      </p>
      <div className="mt-3 grid gap-2 text-sm text-muted sm:grid-cols-2">
        <p>
          Expected kernel: <span className="text-ink">{identityLine(requirementQuery.data?.expected_identity ?? null)}</span>
        </p>
        <p>
          Architecture: <span className="text-ink">{architecture}</span>
        </p>
        <p className="sm:col-span-2">
          Accepted formats: <span className="text-ink">.json, .json.xz</span>
        </p>
      </div>

      {result?.status === "valid" ? (
        <div className="mt-4 rounded-xl border border-mint/30 bg-mint/10 p-3 text-sm" data-testid="linux-symbol-result-valid">
          <p className="font-semibold text-mint">✓ Compatible symbols</p>
          <div className="mt-2 grid gap-1 text-xs text-muted">
            <p>
              Expected kernel: <span className="text-ink">{identityLine(result.expected_identity)}</span>
            </p>
            <p>
              Detected kernel: <span className="text-ink">{identityLine(result.detected_identity)}</span>
            </p>
            <p>
              Architecture: <span className="text-ink">{result.detected_identity?.architecture ?? architecture}</span>
            </p>
            <p>
              Status: <span className="text-mint">Ready</span>
            </p>
          </div>
        </div>
      ) : result?.status === "invalid" ? (
        <div className="mt-4 rounded-xl border border-danger/30 bg-danger/10 p-3 text-sm" data-testid="linux-symbol-result-invalid">
          <p className="font-semibold text-danger">Symbols do not match this memory dump.</p>
          <div className="mt-2 grid gap-1 text-xs text-muted">
            <p>
              Expected: <span className="text-ink">{identityLine(result.expected_identity)}</span>
            </p>
            <p>
              Detected: <span className="text-ink">{identityLine(result.detected_identity)}</span>
            </p>
          </div>
          <button
            type="button"
            onClick={handleChooseAnother}
            className="mt-3 rounded-xl border border-line bg-abyss/70 px-3 py-1.5 text-xs text-muted"
            data-testid="linux-symbol-choose-another"
          >
            Choose another file
          </button>
        </div>
      ) : result?.status === "unsupported" ? (
        <div className="mt-4 rounded-xl border border-amber/30 bg-amber/10 p-3 text-sm" data-testid="linux-symbol-result-unsupported">
          <p className="font-semibold text-amber">Unsupported symbol file.</p>
          <button
            type="button"
            onClick={handleChooseAnother}
            className="mt-3 rounded-xl border border-line bg-abyss/70 px-3 py-1.5 text-xs text-muted"
            data-testid="linux-symbol-choose-another"
          >
            Choose another file
          </button>
        </div>
      ) : result?.status === "validation_failed" ? (
        <div className="mt-4 rounded-xl border border-danger/30 bg-danger/10 p-3 text-sm" data-testid="linux-symbol-result-validation-failed">
          <p className="font-semibold text-danger">Could not validate this symbol file.</p>
          <button
            type="button"
            onClick={handleChooseAnother}
            className="mt-3 rounded-xl border border-line bg-abyss/70 px-3 py-1.5 text-xs text-muted"
            data-testid="linux-symbol-choose-another"
          >
            Choose another file
          </button>
        </div>
      ) : stage.kind === "submit_failed" ? (
        <div className="mt-4 rounded-xl border border-danger/30 bg-danger/10 p-3 text-sm" data-testid="linux-symbol-result-validation-failed">
          <p className="font-semibold text-danger">Could not validate this symbol file.</p>
          <p className="mt-1 text-xs text-muted">{stage.message}</p>
          <button
            type="button"
            onClick={handleChooseAnother}
            className="mt-3 rounded-xl border border-line bg-abyss/70 px-3 py-1.5 text-xs text-muted"
            data-testid="linux-symbol-choose-another"
          >
            Choose another file
          </button>
        </div>
      ) : isSubmittingOrPolling ? (
        <div className="mt-4" data-testid="linux-symbol-validating">
          <p className="text-xs text-muted" data-testid="linux-symbol-selected-file">
            {stage.kind === "polling" ? stage.file.name : stage.kind === "selected" ? stage.file.name : ""}
          </p>
          <div className="mt-2 h-1.5 w-full overflow-hidden rounded-full bg-abyss/60">
            {/* Indeterminate progress -- validation duration is not
                predictable, so no fake/invented percentage is shown.
                Tailwind's built-in animate-pulse (no custom keyframe
                dependency needed) signals "in progress, duration unknown". */}
            <div className="h-full w-1/3 animate-pulse rounded-full bg-accent/70" data-testid="linux-symbol-validating-indeterminate" />
          </div>
          <p className="mt-2 text-xs text-muted">Validating symbols...</p>
        </div>
      ) : (
        <div className="mt-4">
          {showFilePicker ? (
            <div className="flex flex-wrap items-center gap-3">
              <label className="cursor-pointer rounded-xl border border-line bg-abyss/70 px-3 py-1.5 text-xs text-ink">
                Select symbols
                <input
                  ref={fileInputRef}
                  type="file"
                  accept=".json,.json.xz"
                  className="sr-only"
                  onChange={(event) => handleFileChosen(event.target.files?.[0] ?? null)}
                  data-testid="linux-symbol-file-input"
                />
              </label>
            </div>
          ) : (
            <p className="text-xs text-muted" data-testid="linux-symbol-selected-file">
              {stage.kind === "selected" ? `${stage.file.name} · ${formatBytes(stage.file.size)}` : ""}
            </p>
          )}
          {showValidateButton ? (
            <button
              type="button"
              onClick={handleValidate}
              className="mt-3 rounded-xl bg-accent px-3 py-1.5 text-xs font-semibold text-abyss"
              data-testid="linux-symbol-validate-button"
            >
              Validate symbols
            </button>
          ) : null}
        </div>
      )}
    </section>
  );
}
