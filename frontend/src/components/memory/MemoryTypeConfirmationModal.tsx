import { useEffect, useRef, useState } from "react";

type Props = {
  open: boolean;
  filename: string;
  evidenceId: string;
  sizeBytes: number;
  host: string | null | undefined;
  detectionStatus: string;
  detectionReason: string | null | undefined;
  detectedFormat: string | null | undefined;
  detectionConfidence: string | null | undefined;
  onCancel: () => void;
  onConfirm: (reason: string) => Promise<void>;
  busy?: boolean;
  errorMessage?: string | null;
};

function shortId(id: string): string {
  return id.length > 12 ? id.slice(0, 12) : id;
}

function sizeLabel(bytes: number): string {
  if (!bytes) return "0 B";
  if (bytes >= 1024 ** 3) return `${(bytes / 1024 ** 3).toFixed(2)} GiB`;
  if (bytes >= 1024 ** 2) return `${(bytes / 1024 ** 2).toFixed(2)} MiB`;
  if (bytes >= 1024) return `${(bytes / 1024).toFixed(2)} KiB`;
  return `${bytes} B`;
}

export function MemoryTypeConfirmationModal({
  open,
  filename,
  evidenceId,
  sizeBytes,
  host,
  detectionStatus,
  detectionReason,
  detectedFormat,
  detectionConfidence,
  onCancel,
  onConfirm,
  busy = false,
  errorMessage,
}: Props) {
  const [acknowledged, setAcknowledged] = useState(false);
  const [reason, setReason] = useState("");
  const [touched, setTouched] = useState(false);
  const containerRef = useRef<HTMLDivElement | null>(null);
  const firstInputRef = useRef<HTMLInputElement | null>(null);
  const previousFocus = useRef<HTMLElement | null>(null);

  // Reset state when the modal opens.
  useEffect(() => {
    if (open) {
      setAcknowledged(false);
      setReason("");
      setTouched(false);
      previousFocus.current = document.activeElement as HTMLElement | null;
      // Focus the first interactive element after mount.
      window.setTimeout(() => firstInputRef.current?.focus(), 0);
    } else if (previousFocus.current) {
      previousFocus.current.focus();
      previousFocus.current = null;
    }
  }, [open]);

  // Escape closes; focus trap inside the modal.
  useEffect(() => {
    if (!open) return;
    function handleKey(event: KeyboardEvent) {
      if (event.key === "Escape") {
        event.preventDefault();
        onCancel();
      }
    }
    document.addEventListener("keydown", handleKey);
    return () => document.removeEventListener("keydown", handleKey);
  }, [open, onCancel]);

  if (!open) return null;

  const reasonError = touched && reason.trim().length === 0;
  const checkboxError = touched && !acknowledged;
  const canSubmit = acknowledged && reason.trim().length > 0 && !busy;

  async function handleConfirm() {
    setTouched(true);
    if (!canSubmit) return;
    try {
      await onConfirm(reason.trim());
    } catch {
      // The parent surfaces the error via the `errorMessage` prop.
    }
  }

  return (
    <div
      ref={containerRef}
      role="dialog"
      aria-modal="true"
      aria-labelledby="memory-type-confirmation-title"
      className="fixed inset-0 z-50 flex items-center justify-center bg-abyss/80 p-4"
      data-testid="memory-type-confirmation-modal"
    >
      <div className="w-full max-w-lg rounded-2xl border border-line bg-panel p-6 text-sm">
        <h2 id="memory-type-confirmation-title" className="text-xl font-semibold">
          Confirm memory evidence type
        </h2>
        <p className="mt-2 text-muted">
          The file was accepted as a RAW candidate, but Kairon could not confirm
          that it is a memory image. Please review the details below and confirm
          only if the file is an authorized memory acquisition.
        </p>

        <dl className="mt-4 grid gap-2 text-xs" data-testid="memory-type-confirmation-details">
          <div className="flex justify-between gap-2">
            <dt className="text-muted">File</dt>
            <dd className="font-mono text-ink">{filename}</dd>
          </div>
          <div className="flex justify-between gap-2">
            <dt className="text-muted">Size</dt>
            <dd className="text-ink">{sizeLabel(sizeBytes)}</dd>
          </div>
          <div className="flex justify-between gap-2">
            <dt className="text-muted">Host</dt>
            <dd className="text-ink">{host || "Unknown"}</dd>
          </div>
          <div className="flex justify-between gap-2">
            <dt className="text-muted">Evidence</dt>
            <dd className="font-mono text-ink">{shortId(evidenceId)}…</dd>
          </div>
          <div className="flex justify-between gap-2">
            <dt className="text-muted">Detection</dt>
            <dd className="text-ink">
              {detectionStatus}
              {detectedFormat ? ` · ${detectedFormat}` : ""}
              {detectionConfidence ? ` (${detectionConfidence})` : ""}
            </dd>
          </div>
          {detectionReason ? (
            <div className="rounded-md border border-warning/30 bg-warning/5 p-2 text-warning">
              {detectionReason}
            </div>
          ) : null}
        </dl>

        <div className="mt-4 rounded-xl border border-warning/30 bg-warning/5 p-3 text-xs text-warning">
          This file may be RAM or disk. Confirm only if you have verified the
          origin of the acquisition (e.g. captured with WinPmem, LiME, or a
          known forensic tool).
        </div>

        <label className="mt-4 flex items-start gap-2 text-xs">
          <input
            ref={firstInputRef}
            type="checkbox"
            checked={acknowledged}
            onChange={(event) => setAcknowledged(event.target.checked)}
            data-testid="memory-type-confirmation-checkbox"
          />
          <span>
            I confirm that this file is an authorized memory acquisition.
          </span>
        </label>
        {checkboxError ? (
          <p className="mt-1 text-[10px] text-rose-200" role="alert">
            Authorization acknowledgement is required.
          </p>
        ) : null}

        <label className="mt-3 block text-xs">
          <span className="text-muted">Reason for confirmation</span>
          <textarea
            value={reason}
            onChange={(event) => setReason(event.target.value)}
            onBlur={() => setTouched(true)}
            rows={3}
            placeholder="e.g. Captured with WinPmem from host XP-LAPTOP."
            data-testid="memory-type-confirmation-reason"
            className="mt-1 w-full rounded-md border border-line bg-abyss/80 p-2 text-sm outline-none"
          />
        </label>
        {reasonError ? (
          <p className="mt-1 text-[10px] text-rose-200" role="alert">
            A non-empty reason is required.
          </p>
        ) : null}

        {errorMessage ? (
          <p
            className="mt-3 rounded-md border border-rose-400/30 bg-rose-500/10 p-2 text-xs text-rose-100"
            role="alert"
            data-testid="memory-type-confirmation-error"
          >
            {errorMessage}
          </p>
        ) : null}

        <div className="mt-5 flex flex-wrap justify-end gap-2">
          <button
            type="button"
            onClick={onCancel}
            disabled={busy}
            data-testid="memory-type-confirmation-cancel"
            className="rounded-xl border border-line bg-abyss/70 px-4 py-2 text-sm text-muted disabled:opacity-60"
          >
            Cancel
          </button>
          <button
            type="button"
            onClick={handleConfirm}
            disabled={!canSubmit}
            data-testid="memory-type-confirmation-confirm"
            className="rounded-xl bg-accent px-4 py-2 text-sm font-semibold text-abyss disabled:opacity-60"
          >
            {busy ? "Confirming…" : "Confirm as memory evidence"}
          </button>
        </div>
      </div>
    </div>
  );
}
