import { useState } from "react";
import { api } from "../api/client";

type Props = {
  caseId: string;
  selectedEventIds: string[];
  onCreated?: () => void;
};

export default function FindingDrawer({ caseId, selectedEventIds, onCreated }: Props) {
  const [title, setTitle] = useState("");

  async function submit() {
    if (!title.trim()) return;
    await api.createFinding(caseId, { title, event_ids: selectedEventIds, severity: "medium", status: "open" });
    setTitle("");
    onCreated?.();
  }

  return (
    <div className="rounded-3xl border border-line bg-panel/70 p-5 shadow-panel">
      <p className="font-mono text-xs uppercase tracking-[0.18em] text-accent">Create finding</p>
      <input
        value={title}
        onChange={(event) => setTitle(event.target.value)}
        placeholder="Suspicious PowerShell execution"
        className="mt-3 w-full rounded-2xl border border-line bg-abyss/80 px-4 py-3 text-sm outline-none focus:border-accent/50"
      />
      <button onClick={() => void submit()} className="mt-3 rounded-2xl bg-accent px-4 py-2 text-sm font-semibold text-abyss">
        Create from selection ({selectedEventIds.length})
      </button>
    </div>
  );
}

