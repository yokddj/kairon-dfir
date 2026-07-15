import { useEffect, useState } from "react";
import { useMutation, useQueryClient } from "@tanstack/react-query";

import { api, type DfirCase } from "../api/client";
import { useNotifications } from "../context/NotificationsContext";

type Props = {
  open: boolean;
  caseItem: DfirCase | null;
  onClose: () => void;
  onDeleted?: (caseId: string) => void;
};

const REMOVED_ITEMS = [
  "Evidence",
  "Memory images",
  "Hosts",
  "Artifacts",
  "Search index",
  "Findings",
  "Detections",
  "Reports",
  "Processing history",
  "Upload metadata",
  "Timeline entries",
  "Any generated analysis",
];

export default function DeleteCaseDialog({ open, caseItem, onClose, onDeleted }: Props) {
  const queryClient = useQueryClient();
  const { notify } = useNotifications();
  const [confirmText, setConfirmText] = useState("");

  useEffect(() => {
    if (open) setConfirmText("");
  }, [open, caseItem?.id]);

  const deleteMutation = useMutation({
    mutationFn: () => {
      if (!caseItem) throw new Error("No case selected");
      return api.deleteCase(caseItem.id);
    },
    onSuccess: () => {
      if (!caseItem) return;
      const deletedId = caseItem.id;
      queryClient.setQueriesData<DfirCase[]>({ queryKey: ["cases"] }, (current) =>
        current ? current.filter((item) => item.id !== deletedId) : current,
      );
      void queryClient.invalidateQueries({ queryKey: ["cases"] });
      queryClient.removeQueries({ queryKey: ["case", deletedId] });
      notify({ title: "Case deleted", description: "Case deleted successfully.", tone: "success" });
      onDeleted?.(deletedId);
      onClose();
    },
    onError: (error) => {
      notify({
        title: "Delete failed",
        description: error instanceof Error ? error.message : "The case could not be deleted.",
        tone: "error",
      });
    },
  });

  if (!open || !caseItem) return null;

  const confirmationValid = confirmText === caseItem.name;

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/70 p-4" role="dialog" aria-modal="true" aria-label="Delete Case">
      <div className="w-full max-w-xl rounded-[28px] border border-danger/40 bg-panel p-6 shadow-panel">
        <p className="font-mono text-xs uppercase tracking-[0.24em] text-danger">Delete Case</p>
        <h3 className="mt-2 text-2xl font-semibold text-ink">{caseItem.name}</h3>
        <p className="mt-3 text-sm text-muted">
          You are about to permanently delete this investigation. This action cannot be undone. Everything associated with this case will be removed. This includes:
        </p>
        <ul className="mt-3 grid grid-cols-2 gap-x-4 gap-y-1 text-sm text-muted">
          {REMOVED_ITEMS.map((item) => (
            <li key={item} className="list-disc pl-1 marker:text-danger">{item}</li>
          ))}
        </ul>
        <label className="mt-5 block text-sm text-muted">
          Type <span className="font-mono text-ink">{caseItem.name}</span> to continue.
          <input
            value={confirmText}
            onChange={(event) => setConfirmText(event.target.value)}
            autoComplete="off"
            spellCheck={false}
            className="mt-2 w-full rounded-2xl border border-line bg-abyss px-4 py-3 font-mono text-sm text-ink outline-none focus:border-danger"
          />
        </label>
        {deleteMutation.error instanceof Error ? <p className="mt-3 text-sm text-danger">{deleteMutation.error.message}</p> : null}
        <div className="mt-5 flex flex-wrap justify-end gap-2">
          <button type="button" onClick={onClose} className="rounded-2xl border border-line bg-abyss/80 px-4 py-2 text-sm text-muted">
            Cancel
          </button>
          <button
            type="button"
            onClick={() => deleteMutation.mutate()}
            disabled={!confirmationValid || deleteMutation.isPending}
            className="rounded-2xl bg-danger px-4 py-2 text-sm font-semibold text-white disabled:opacity-50"
          >
            {deleteMutation.isPending ? "Deleting..." : "Delete Case"}
          </button>
        </div>
      </div>
    </div>
  );
}
