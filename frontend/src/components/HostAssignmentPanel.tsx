export type HostAssignmentPanelProps = {
  hostId: string | null | undefined;
  detectedHost: string | null | undefined;
  providedHost: string | null | undefined;
  assignmentMismatch: boolean;
  isMemoryEvidence: boolean;
  assignedHostDisplayName: string | null | undefined;
  caseHosts: { id: string; display_name: string }[];
  hostAssignmentMode: "existing" | "create";
  onHostAssignmentModeChange: (mode: "existing" | "create") => void;
  hostAssignmentId: string;
  onHostAssignmentIdChange: (id: string) => void;
  hostAssignmentName: string;
  onHostAssignmentNameChange: (name: string) => void;
  onSubmit: () => void;
  isSubmitting: boolean;
};

export default function HostAssignmentPanel({
  hostId,
  detectedHost,
  providedHost,
  assignmentMismatch,
  isMemoryEvidence,
  assignedHostDisplayName,
  caseHosts,
  hostAssignmentMode,
  onHostAssignmentModeChange,
  hostAssignmentId,
  onHostAssignmentIdChange,
  hostAssignmentName,
  onHostAssignmentNameChange,
  onSubmit,
  isSubmitting,
}: HostAssignmentPanelProps) {
  return (
    <div className="mt-5 rounded-3xl border border-accent/30 bg-abyss/60 p-4" data-testid="evidence-host-assignment-panel">
      <div className="flex flex-wrap items-start justify-between gap-3">
        <div>
          <p className="font-mono text-[11px] uppercase tracking-[0.18em] text-accent">Host assignment</p>
          <p className="mt-1 text-base font-semibold text-ink">Change host assignment</p>
          <p className="mt-2 text-xs text-muted">Detected/provided host is preserved as metadata. Assigned host controls host filters, including Memory.</p>
        </div>
        <span className={`rounded-full border px-3 py-1 text-xs ${hostId ? (assignmentMismatch ? "border-amber/30 bg-amber/10 text-amber" : "border-mint/30 bg-mint/10 text-mint") : "border-line bg-panel/50 text-muted"}`}>
          {hostId ? (assignmentMismatch ? "mismatch" : "confirmed") : "unassigned"}
        </span>
      </div>
      {isMemoryEvidence && !hostId ? (
        <div className="mt-3 rounded-2xl border border-amber/30 bg-amber/10 p-3 text-xs text-amber" role="alert">
          This memory evidence is not assigned to a case host. Host filters may not include it until assigned.
        </div>
      ) : null}
      <div className="mt-4 grid gap-3 md:grid-cols-3">
        <div className="rounded-2xl border border-line bg-panel/50 px-4 py-3 text-sm text-muted"><p className="font-mono text-[11px] uppercase tracking-[0.16em]">Detected/provided host</p><p className="mt-1 text-base font-semibold text-ink">{detectedHost || providedHost || "-"}</p></div>
        <div className="rounded-2xl border border-line bg-panel/50 px-4 py-3 text-sm text-muted"><p className="font-mono text-[11px] uppercase tracking-[0.16em]">Assigned host</p><p className="mt-1 text-base font-semibold text-ink">{assignedHostDisplayName || "Unassigned"}</p></div>
        <div className="rounded-2xl border border-line bg-panel/50 px-4 py-3 text-sm text-muted"><p className="font-mono text-[11px] uppercase tracking-[0.16em]">Actions</p><p className="mt-1 text-xs text-muted">Assign to existing host, create a new host, or mark unassigned.</p></div>
      </div>
      <div className="mt-4 grid gap-3 md:grid-cols-[160px_1fr_auto] md:items-end">
        <label className="block text-xs text-muted">Change host<select value={hostAssignmentMode} onChange={(event) => onHostAssignmentModeChange(event.target.value as "existing" | "create")} className="mt-1 w-full rounded-xl border border-line bg-abyss/80 px-3 py-2 text-sm text-ink"><option value="existing">Assign to existing host</option><option value="create">Create new host</option></select></label>
        {hostAssignmentMode === "existing" ? <label className="block text-xs text-muted">Assign to existing host<select value={hostAssignmentId} onChange={(event) => onHostAssignmentIdChange(event.target.value)} className="mt-1 w-full rounded-xl border border-line bg-abyss/80 px-3 py-2 text-sm text-ink"><option value="">Mark unassigned</option>{caseHosts.map((host) => <option key={host.id} value={host.id}>{host.display_name}</option>)}</select></label> : <label className="block text-xs text-muted">Create new host<input value={hostAssignmentName} onChange={(event) => onHostAssignmentNameChange(event.target.value)} placeholder="WS-01" className="mt-1 w-full rounded-xl border border-line bg-abyss/80 px-3 py-2 text-sm text-ink" /></label>}
        <button type="button" onClick={onSubmit} disabled={isSubmitting || (hostAssignmentMode === "create" && !hostAssignmentName.trim())} className="rounded-xl bg-accent px-4 py-2 text-sm font-semibold text-abyss disabled:opacity-60">{isSubmitting ? "Saving..." : hostAssignmentMode === "create" ? "Create new host" : hostAssignmentId ? "Change host" : "Mark unassigned"}</button>
      </div>
    </div>
  );
}
