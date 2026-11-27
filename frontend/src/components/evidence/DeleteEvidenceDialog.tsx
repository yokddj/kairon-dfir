import { useState } from "react";

export default function DeleteEvidenceDialog({
  filename,
  indexedDocs,
  busy,
  onCancel,
  onConfirm,
}: {
  filename: string;
  indexedDocs: number;
  busy: boolean;
  onCancel: () => void;
  onConfirm: () => void;
}) {
  const [text, setText] = useState("");
  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/70 p-4" role="dialog" aria-modal="true" aria-label="Delete evidence">
      <div className="w-full max-w-lg rounded-3xl border border-danger/40 bg-panel p-6 shadow-panel">
        <h3 className="text-xl font-semibold text-ink">Delete evidence</h3>
        <p className="mt-1 break-words text-sm text-ink">{filename}</p>
        <p className="mt-3 text-sm text-muted">
          Removes the evidence, its parsed artifacts and its {indexedDocs.toLocaleString()} indexed records. Whether the original upload is removed depends on the storage policy.
        </p>
        <label className="mt-4 block text-sm text-muted">
          Type DELETE to confirm.
          <input value={text} onChange={(event) => setText(event.target.value)} className="mt-2 w-full rounded-xl border border-line bg-abyss px-3 py-2 font-mono text-sm text-ink outline-none focus:border-danger" />
        </label>
        <div className="mt-5 flex justify-end gap-2">
          <button type="button" onClick={onCancel} className="rounded-xl px-4 py-2 text-sm text-muted">
            Cancel
          </button>
          <button type="button" onClick={onConfirm} disabled={text.trim() !== "DELETE" || busy} className="rounded-xl bg-danger px-4 py-2 text-sm font-semibold text-white disabled:opacity-50">
            {busy ? "Deleting…" : "Delete evidence"}
          </button>
        </div>
      </div>
    </div>
  );
}
