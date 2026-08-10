import { useMutation } from "@tanstack/react-query";
import { useRef, useState } from "react";
import { api } from "../../api/client";

// Reusable VMware companion (.vmsn/.vmss) section (Phase 2). Mounted from
// BOTH MemoryEvidencePreparationCard.tsx (wizard) and MemoryEvidencePage.tsx
// (persistent evidence view) -- one component, two call sites, per the
// Phase 2 requirement not to duplicate this UI.
//
// Deliberately receives its companion state as PROPS derived from the
// Memory Preparation response (has_vmware_companion / vmware_companion_*)
// rather than fetching GET .../companions itself: the "is this VMware,
// should Kairon recommend a companion" decision is backend logic
// (app.services.memory.preparation.service._vmware_companion_applicable)
// and must not be re-derived here. This component only handles the
// upload/replace/remove MECHANICS against the already-existing Phase 1
// endpoints, and asks the parent (via onChanged) to refetch Preparation
// afterwards -- it never mutates or re-fetches Preparation itself.
//
// Synchronous, unlike LinuxSymbolUploadPanel.tsx's queued/polling flow:
// the backend does not need Volatility to validate a companion (only its
// extension, size and hash), so POST .../companions/vmware returns the
// final result directly -- no polling stage exists here.

const ACCEPTED_EXTENSIONS = ".vmsn,.vmss";

type Stage =
  | { kind: "idle" }
  | { kind: "picking" }
  | { kind: "selected"; file: File }
  | { kind: "uploading"; file: File }
  | { kind: "failed"; file: File | null; message: string }
  | { kind: "confirming_remove" }
  | { kind: "removing" };

export type VmwareCompanionSectionProps = {
  caseId: string;
  evidenceId: string;
  hasCompanion: boolean;
  companionId: string | null;
  companionType: string | null;
  companionFilename: string | null;
  companionSha256: string | null;
  companionSizeBytes: number | null;
  recommended: boolean;
  warningText: string | null;
  onChanged: () => void;
};

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

function shortHash(sha256: string | null): string {
  if (!sha256) return "";
  return `${sha256.slice(0, 12)}…`;
}

function companionTypeLabel(type: string | null): string {
  if (type === "vmware_vmsn") return ".vmsn";
  if (type === "vmware_vmss") return ".vmss";
  return type ?? "";
}

export function VmwareCompanionSection({
  caseId,
  evidenceId,
  hasCompanion,
  companionId,
  companionType,
  companionFilename,
  companionSha256,
  companionSizeBytes,
  recommended,
  warningText,
  onChanged,
}: VmwareCompanionSectionProps) {
  const [stage, setStage] = useState<Stage>({ kind: "idle" });
  const fileInputRef = useRef<HTMLInputElement | null>(null);

  const attachMutation = useMutation({
    mutationFn: (file: File) => api.attachVmwareCompanion(caseId, evidenceId, file),
    onSuccess: () => {
      setStage({ kind: "idle" });
      onChanged();
    },
    onError: (error, file) => {
      setStage({ kind: "failed", file, message: error instanceof Error ? error.message : "Could not attach VMware metadata." });
    },
  });

  const removeMutation = useMutation({
    mutationFn: () => {
      if (!companionId) return Promise.reject(new Error("No companion to remove."));
      return api.deleteVmwareCompanion(caseId, evidenceId, companionId);
    },
    onSuccess: () => {
      setStage({ kind: "idle" });
      onChanged();
    },
    onError: (error) => {
      setStage({ kind: "failed", file: null, message: error instanceof Error ? error.message : "Could not remove VMware metadata." });
    },
  });

  // Nothing to offer and nothing to show: neither a real VMware signal
  // nor an already-attached companion. Both call sites can mount this
  // unconditionally and trust it to hide itself.
  if (!hasCompanion && !recommended && stage.kind === "idle") {
    return null;
  }

  function handleFileChosen(file: File | null) {
    if (!file) return;
    setStage({ kind: "selected", file });
  }

  function handleAttach(file: File) {
    setStage({ kind: "uploading", file });
    attachMutation.mutate(file);
  }

  function handleRetry() {
    if (stage.kind !== "failed" || !stage.file) return;
    handleAttach(stage.file);
  }

  function handleChooseAnother() {
    setStage({ kind: "picking" });
    if (fileInputRef.current) fileInputRef.current.value = "";
  }

  function handleCancelSelection() {
    setStage({ kind: "idle" });
    if (fileInputRef.current) fileInputRef.current.value = "";
  }

  function handleConfirmRemove() {
    setStage({ kind: "removing" });
    removeMutation.mutate();
  }

  const isBusy = stage.kind === "uploading" || stage.kind === "removing";
  const actionLabel = hasCompanion ? "Replace metadata" : "Attach metadata";

  return (
    <section id="vmware-companion-section" className="mt-4 rounded-2xl border border-line bg-abyss/60 p-4" data-testid="vmware-companion-section">
      <p className="font-mono text-[11px] uppercase tracking-[0.16em] text-accent">VMware snapshot metadata</p>

      {stage.kind === "uploading" ? (
        <div className="mt-3" data-testid="vmware-companion-uploading">
          <p className="text-xs text-muted" data-testid="vmware-companion-selected-file">
            {stage.file.name}
          </p>
          <div className="mt-2 h-1.5 w-full overflow-hidden rounded-full bg-abyss/60">
            {/* Indeterminate: upload duration is not predictable, so no
                fabricated percentage is shown. */}
            <div className="h-full w-1/3 animate-pulse rounded-full bg-accent/70" data-testid="vmware-companion-uploading-indeterminate" />
          </div>
          <p className="mt-2 text-xs text-muted">Uploading VMware metadata...</p>
        </div>
      ) : stage.kind === "removing" ? (
        <div className="mt-3" data-testid="vmware-companion-removing">
          <div className="h-1.5 w-full overflow-hidden rounded-full bg-abyss/60">
            <div className="h-full w-1/3 animate-pulse rounded-full bg-accent/70" />
          </div>
          <p className="mt-2 text-xs text-muted">Removing VMware metadata...</p>
        </div>
      ) : stage.kind === "failed" ? (
        <div className="mt-3 rounded-xl border border-danger/30 bg-danger/10 p-3 text-sm" data-testid="vmware-companion-failed">
          <p className="font-semibold text-danger">Could not attach VMware metadata.</p>
          <p className="mt-1 text-xs text-muted">{stage.message}</p>
          <div className="mt-3 flex flex-wrap gap-2">
            {stage.file ? (
              <button
                type="button"
                onClick={handleRetry}
                className="rounded-xl bg-accent px-3 py-1.5 text-xs font-semibold text-abyss"
                data-testid="vmware-companion-retry-button"
              >
                Retry
              </button>
            ) : null}
            <button
              type="button"
              onClick={handleChooseAnother}
              className="rounded-xl border border-line bg-abyss/70 px-3 py-1.5 text-xs text-muted"
              data-testid="vmware-companion-choose-another"
            >
              Choose another file
            </button>
          </div>
        </div>
      ) : stage.kind === "confirming_remove" ? (
        <div className="mt-3 rounded-xl border border-amber/30 bg-amber/10 p-3 text-sm" data-testid="vmware-companion-confirm-remove">
          <p className="font-semibold text-amber">Remove VMware snapshot metadata?</p>
          <p className="mt-1 text-xs text-muted">
            Removing snapshot metadata may reduce the reliability of VMware memory analysis.
          </p>
          <div className="mt-3 flex flex-wrap gap-2">
            <button
              type="button"
              onClick={handleConfirmRemove}
              className="rounded-xl bg-danger px-3 py-1.5 text-xs font-semibold text-abyss"
              data-testid="vmware-companion-confirm-remove-button"
            >
              Remove
            </button>
            <button
              type="button"
              onClick={() => setStage({ kind: "idle" })}
              className="rounded-xl border border-line bg-abyss/70 px-3 py-1.5 text-xs text-muted"
              data-testid="vmware-companion-cancel-remove-button"
            >
              Cancel
            </button>
          </div>
        </div>
      ) : stage.kind === "selected" ? (
        <div className="mt-3">
          <p className="text-xs text-muted" data-testid="vmware-companion-selected-file">
            {stage.file.name} · {formatBytes(stage.file.size)}
          </p>
          <div className="mt-3 flex flex-wrap gap-2">
            <button
              type="button"
              onClick={() => handleAttach(stage.file)}
              className="rounded-xl bg-accent px-3 py-1.5 text-xs font-semibold text-abyss"
              data-testid="vmware-companion-attach-button"
            >
              {actionLabel}
            </button>
            <button
              type="button"
              onClick={handleCancelSelection}
              className="rounded-xl border border-line bg-abyss/70 px-3 py-1.5 text-xs text-muted"
              data-testid="vmware-companion-cancel-button"
            >
              Cancel
            </button>
          </div>
        </div>
      ) : stage.kind === "picking" ? (
        <div className="mt-3 flex flex-wrap items-center gap-3">
          <label className="cursor-pointer rounded-xl border border-line bg-abyss/70 px-3 py-1.5 text-xs text-ink">
            Select file
            <input
              ref={fileInputRef}
              type="file"
              accept={ACCEPTED_EXTENSIONS}
              className="sr-only"
              onChange={(event) => handleFileChosen(event.target.files?.[0] ?? null)}
              data-testid="vmware-companion-file-input"
            />
          </label>
          <button
            type="button"
            onClick={() => setStage({ kind: "idle" })}
            className="rounded-xl border border-line bg-abyss/70 px-3 py-1.5 text-xs text-muted"
            data-testid="vmware-companion-cancel-button"
          >
            Cancel
          </button>
        </div>
      ) : hasCompanion ? (
        <div className="mt-3 rounded-xl border border-mint/30 bg-mint/10 p-3 text-sm" data-testid="vmware-companion-associated">
          <p className="font-semibold text-mint" data-testid="vmware-companion-filename">
            {companionFilename}
          </p>
          <div className="mt-2 grid gap-1 text-xs text-muted">
            <p>
              Status: <span className="text-mint">Associated</span>
            </p>
            <p>
              Type: <span className="text-ink">{companionTypeLabel(companionType)}</span>
            </p>
            {companionSizeBytes != null ? (
              <p>
                Size: <span className="text-ink">{formatBytes(companionSizeBytes)}</span>
              </p>
            ) : null}
            {companionSha256 ? (
              <p>
                SHA-256: <span className="font-mono text-ink" data-testid="vmware-companion-sha256">{shortHash(companionSha256)}</span>
              </p>
            ) : null}
          </div>
          <div className="mt-3 flex flex-wrap gap-2">
            <button
              type="button"
              onClick={() => setStage({ kind: "picking" })}
              className="rounded-xl border border-line bg-abyss/70 px-3 py-1.5 text-xs text-ink"
              data-testid="vmware-companion-replace-button"
            >
              Replace
            </button>
            <button
              type="button"
              onClick={() => setStage({ kind: "confirming_remove" })}
              className="rounded-xl border border-danger/40 bg-danger/10 px-3 py-1.5 text-xs text-danger"
              data-testid="vmware-companion-remove-button"
            >
              Remove
            </button>
          </div>
        </div>
      ) : (
        <div className="mt-3" data-testid="vmware-companion-not-provided">
          <p className="text-sm text-ink">Not provided</p>
          <p className="mt-1 text-xs text-muted">
            {warningText ?? "VMware memory can sometimes be analyzed without snapshot metadata. A matching .vmsn or .vmss file may be required for reliable analysis."}
          </p>
          <button
            type="button"
            onClick={() => setStage({ kind: "picking" })}
            className="mt-3 rounded-xl border border-line bg-abyss/70 px-3 py-1.5 text-xs text-ink"
            data-testid="vmware-companion-add-button"
          >
            Add VMware metadata
          </button>
        </div>
      )}
    </section>
  );
}
