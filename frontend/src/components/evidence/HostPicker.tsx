import { useState } from "react";

import type { useHostAssignment } from "../../hooks/useHostAssignment";

const NEW_HOST = "__new__";

/** "Host: NAME · Change" in the header, opening one small picker. */
export default function HostPicker({
  hostLabel,
  detectedHost,
  assignment,
  warnUnassigned,
}: {
  hostLabel: string;
  detectedHost: string | null | undefined;
  assignment: ReturnType<typeof useHostAssignment>;
  warnUnassigned: boolean;
}) {
  const [open, setOpen] = useState(false);
  const choice = assignment.mode === "create" ? NEW_HOST : assignment.selectedHostId;

  function choose(value: string) {
    if (value === NEW_HOST) {
      assignment.setMode("create");
    } else {
      assignment.setMode("existing");
      assignment.setSelectedHostId(value);
    }
  }

  return (
    <span className="relative inline-flex items-center gap-1.5">
      <span>
        Host <span className={warnUnassigned ? "text-amber" : "text-ink"}>{hostLabel || "unassigned"}</span>
      </span>
      <button type="button" onClick={() => setOpen((value) => !value)} className="text-accent hover:underline" aria-expanded={open}>
        change
      </button>
      {open ? (
        <div className="absolute left-0 top-full z-30 mt-2 w-80 rounded-2xl border border-line bg-panel p-4 shadow-panel" data-testid="evidence-host-picker">
          {detectedHost ? <p className="text-xs text-muted">Detected in the evidence: <span className="text-ink">{detectedHost}</span></p> : null}
          <label className="mt-2 block text-xs text-muted">
            Assign to
            <select value={choice} onChange={(event) => choose(event.target.value)} className="mt-1 w-full rounded-xl border border-line bg-abyss/80 px-3 py-2 text-sm text-ink">
              <option value="">No host</option>
              {assignment.caseHosts.map((host) => (
                <option key={host.id} value={host.id}>
                  {host.display_name}
                </option>
              ))}
              <option value={NEW_HOST}>New host…</option>
            </select>
          </label>
          {assignment.mode === "create" ? (
            <input
              autoFocus
              value={assignment.newHostName}
              onChange={(event) => assignment.setNewHostName(event.target.value)}
              placeholder="Host name"
              aria-label="New host name"
              className="mt-2 w-full rounded-xl border border-line bg-abyss/80 px-3 py-2 text-sm text-ink"
            />
          ) : null}
          <div className="mt-3 flex justify-end gap-2">
            <button type="button" onClick={() => setOpen(false)} className="rounded-xl px-3 py-1.5 text-sm text-muted">
              Cancel
            </button>
            <button
              type="button"
              disabled={assignment.isSubmitting || (assignment.mode === "create" && !assignment.newHostName.trim())}
              onClick={() => {
                assignment.submit();
                setOpen(false);
              }}
              className="rounded-xl bg-accent px-3 py-1.5 text-sm font-semibold text-abyss disabled:opacity-50"
            >
              Save
            </button>
          </div>
        </div>
      ) : null}
    </span>
  );
}
