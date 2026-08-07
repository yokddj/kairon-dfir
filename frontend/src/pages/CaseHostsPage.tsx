import { useEffect, useState } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { Link, useParams } from "react-router-dom";
import { api, type CaseContextHostSummary } from "../api/client";
import { useActiveCase } from "../context/ActiveCaseContext";

export default function CaseHostsPage() {
  const { caseId = "" } = useParams();
  const { setActiveCaseId } = useActiveCase();
  const queryClient = useQueryClient();
  const [selectedHostIds, setSelectedHostIds] = useState<string[]>([]);
  const [canonicalHostId, setCanonicalHostId] = useState("");
  const [mergeReason, setMergeReason] = useState("Same endpoint renamed during investigation");
  const [renameDrafts, setRenameDrafts] = useState<Record<string, string>>({});
  const [deleteTarget, setDeleteTarget] = useState<CaseContextHostSummary | null>(null);

  useEffect(() => {
    if (caseId) setActiveCaseId(caseId);
  }, [caseId, setActiveCaseId]);

  const hostsQuery = useQuery({
    queryKey: ["case-hosts", caseId],
    queryFn: () => api.getCaseHosts(caseId),
    enabled: Boolean(caseId),
    refetchOnWindowFocus: false,
  });
  const auditQuery = useQuery({
    queryKey: ["case-host-audit", caseId],
    queryFn: () => api.getCaseHostAudit(caseId),
    enabled: Boolean(caseId),
    refetchOnWindowFocus: false,
  });

  const refreshHosts = async () => {
    await Promise.all([
      queryClient.invalidateQueries({ queryKey: ["case-hosts", caseId] }),
      queryClient.invalidateQueries({ queryKey: ["case-context", caseId] }),
      queryClient.invalidateQueries({ queryKey: ["case-host-audit", caseId] }),
      queryClient.invalidateQueries({ queryKey: ["search-v2-workspace", caseId] }),
      queryClient.invalidateQueries({ queryKey: ["case-timeline-v2", caseId] }),
    ]);
  };

  const mergeMutation = useMutation({
    mutationFn: async () => {
      const hosts = hostsQuery.data?.hosts ?? [];
      const selected = hosts.filter((item) => selectedHostIds.includes(item.id));
      const aliases = selected
        .filter((item) => item.id !== canonicalHostId)
        .flatMap((item) => item.all_names);
      return api.mergeCaseHosts(caseId, { canonical_host_id: canonicalHostId, aliases, reason: mergeReason });
    },
    onSuccess: refreshHosts,
  });

  const renameMutation = useMutation({
    mutationFn: async ({ hostId, value }: { hostId: string; value: string }) => api.renameCaseHost(caseId, hostId, { display_name: value, reason: "Analyst canonical rename" }),
    onSuccess: refreshHosts,
  });

  const splitMutation = useMutation({
    mutationFn: async ({ hostId, aliasId }: { hostId: string; aliasId: string }) => api.splitCaseHostAlias(caseId, hostId, aliasId, { reason: "Alias split by analyst" }),
    onSuccess: refreshHosts,
  });

  const [reassignTargetId, setReassignTargetId] = useState("");
  const [deleteConfirmText, setDeleteConfirmText] = useState("");
  const [deleteReason, setDeleteReason] = useState("");

  const closeDeleteDialog = () => {
    setDeleteTarget(null);
    setReassignTargetId("");
    setDeleteConfirmText("");
    setDeleteReason("");
  };

  const deletionPreviewQuery = useQuery({
    queryKey: ["case-host-deletion-preview", caseId, deleteTarget?.id],
    queryFn: () => api.getCaseHostDeletionPreview(caseId, deleteTarget!.id),
    enabled: Boolean(caseId && deleteTarget),
  });

  const deleteHostMutation = useMutation({
    mutationFn: async () => {
      if (!deleteTarget) throw new Error("No host selected");
      return api.deleteCaseHost(caseId, deleteTarget.id, {
        target_host_id: reassignTargetId || null,
        reason: deleteReason || null,
        analyst: null,
      });
    },
    onSuccess: async () => {
      await refreshHosts();
      closeDeleteDialog();
    },
  });

  const requiresReassignment = Boolean(deletionPreviewQuery.data?.requires_reassignment);
  const deleteConfirmationValid = deleteConfirmText.trim().toUpperCase() === "DELETE" && (!requiresReassignment || Boolean(reassignTargetId));

  const selectedHosts = (hostsQuery.data?.hosts ?? []).filter((item) => selectedHostIds.includes(item.id));

  if (!caseId) {
    return <div className="rounded-[28px] border border-line bg-panel/70 p-8 text-sm text-muted shadow-panel">Select a case first.</div>;
  }

  return (
    <div className="space-y-6">
      <section className="rounded-[28px] border border-line bg-panel/70 p-6 shadow-panel">
        <p className="font-mono text-xs uppercase tracking-[0.24em] text-accent">Host Identity</p>
        <h2 className="mt-2 text-3xl font-semibold">Manage host aliases</h2>
        <p className="mt-2 max-w-3xl text-sm text-muted">Merge historical or alternate hostnames into one canonical endpoint while preserving the originally observed name in event detail and exports.</p>
      </section>

      <section className="grid gap-6 xl:grid-cols-[1.2fr_0.8fr]">
        <div className="rounded-[28px] border border-line bg-panel/70 p-6 shadow-panel">
          <div className="flex items-center justify-between gap-3">
            <div>
              <p className="font-mono text-xs uppercase tracking-[0.18em] text-accent">Detected hosts</p>
              <p className="mt-2 text-sm text-muted">Choose multiple hosts, pick the canonical one, then merge the remaining names as aliases.</p>
            </div>
            <Link to={`/cases/${caseId}/overview`} className="rounded-xl border border-line bg-abyss/70 px-3 py-1.5 text-xs text-muted">Back to overview</Link>
          </div>

          <div className="mt-4 space-y-3">
            {(hostsQuery.data?.hosts ?? []).map((host) => {
              const checked = selectedHostIds.includes(host.id);
              const renameValue = renameDrafts[host.id] ?? host.display_name;
              return (
                <article key={host.id} className="rounded-2xl border border-line bg-abyss/60 p-4" data-testid="host-identity-row">
                  <div className="flex flex-wrap items-start justify-between gap-4">
                    <div className="flex min-w-0 flex-1 gap-3">
                      <input
                        aria-label={`Select ${host.display_name}`}
                        type="checkbox"
                        checked={checked}
                        onChange={(event) => {
                          setSelectedHostIds((current) => event.target.checked ? [...current, host.id] : current.filter((item) => item !== host.id));
                          if (!canonicalHostId || canonicalHostId === host.id) {
                            setCanonicalHostId(event.target.checked ? host.id : "");
                          }
                        }}
                        className="mt-1"
                      />
                      <div className="min-w-0 flex-1">
                        <div className="flex flex-wrap items-center gap-2">
                          <h3 className="text-lg font-semibold">{host.display_name}</h3>
                          <span className="rounded-full border border-line px-2 py-1 font-mono text-[10px] uppercase tracking-[0.14em] text-accent">{host.confidence}</span>
                          <span className="rounded-full border border-line px-2 py-1 font-mono text-[10px] uppercase tracking-[0.14em] text-muted">{host.source}</span>
                        </div>
                        <p className="mt-2 text-sm text-muted">{host.event_count.toLocaleString()} events · {host.evidence_count} evidence sources · {host.findings_count} findings</p>
                        <div className="mt-3 flex flex-wrap gap-2">
                          {host.alias_rows.map((alias) => (
                            <span key={alias.id} className="rounded-full border border-line bg-panel/40 px-3 py-1 text-xs text-muted">
                              {alias.alias}
                              {!alias.is_primary ? (
                                <button type="button" onClick={() => splitMutation.mutate({ hostId: host.id, aliasId: alias.id })} className="ml-2 text-accent">
                                  Split
                                </button>
                              ) : null}
                            </span>
                          ))}
                        </div>
                      </div>
                    </div>
                    {checked ? (
                      <label className="text-xs text-muted">
                        <span className="mb-2 block font-mono uppercase tracking-[0.16em]">Canonical</span>
                        <input
                          aria-label={`Canonical ${host.display_name}`}
                          type="radio"
                          name="canonical-host"
                          checked={canonicalHostId === host.id}
                          onChange={() => setCanonicalHostId(host.id)}
                        />
                      </label>
                    ) : null}
                  </div>
                  <div className="mt-4 flex flex-wrap gap-2">
                    <input
                      aria-label={`Rename ${host.display_name}`}
                      value={renameValue}
                      onChange={(event) => setRenameDrafts((current) => ({ ...current, [host.id]: event.target.value }))}
                      className="min-w-[240px] rounded-xl border border-line bg-panel/40 px-3 py-2 text-sm"
                    />
                    <button type="button" onClick={() => renameMutation.mutate({ hostId: host.id, value: renameValue })} className="rounded-xl border border-line bg-panel/40 px-3 py-2 text-xs text-muted">
                      Rename canonical host
                    </button>
                    <button
                      type="button"
                      onClick={() => setDeleteTarget(host)}
                      className="rounded-xl border border-danger/40 bg-danger/10 px-3 py-2 text-xs font-medium text-danger hover:bg-danger/20"
                      data-testid={`delete-host-${host.id}`}
                    >
                      Delete host&hellip;
                    </button>
                  </div>
                </article>
              );
            })}
          </div>
        </div>

        <div className="space-y-6">
          <section className="rounded-[28px] border border-line bg-panel/70 p-6 shadow-panel">
            <p className="font-mono text-xs uppercase tracking-[0.18em] text-accent">Merge selected</p>
            <p className="mt-2 text-sm text-muted">{selectedHosts.length ? `${selectedHosts.length} hosts selected.` : "Select at least two hosts to merge aliases."}</p>
            <textarea
              aria-label="Merge reason"
              value={mergeReason}
              onChange={(event) => setMergeReason(event.target.value)}
              className="mt-4 min-h-[96px] w-full rounded-2xl border border-line bg-abyss/80 px-4 py-3 text-sm"
            />
            <button
              type="button"
              disabled={selectedHosts.length < 2 || !canonicalHostId || mergeMutation.isPending}
              onClick={() => mergeMutation.mutate()}
              className="mt-4 rounded-2xl border border-line bg-abyss/80 px-4 py-3 text-sm text-muted disabled:opacity-50"
            >
              Merge selected hosts
            </button>
            {mergeMutation.error instanceof Error ? <p className="mt-3 text-sm text-rose-200">{mergeMutation.error.message}</p> : null}
          </section>

          <section className="rounded-[28px] border border-line bg-panel/70 p-6 shadow-panel">
            <p className="font-mono text-xs uppercase tracking-[0.18em] text-accent">Candidates</p>
            <div className="mt-4 space-y-3">
              {(hostsQuery.data?.host_candidates ?? []).length ? (
                hostsQuery.data?.host_candidates.map((candidate, index) => (
                  <div key={index} className="rounded-2xl border border-line bg-abyss/60 p-4 text-sm text-muted">
                    <p>{String((candidate as { candidate_type?: string }).candidate_type ?? "candidate")}</p>
                    <pre className="mt-2 overflow-x-auto text-xs text-slate-300">{JSON.stringify(candidate, null, 2)}</pre>
                  </div>
                ))
              ) : (
                <p className="text-sm text-muted">No unresolved alias candidates right now.</p>
              )}
            </div>
          </section>

          <section className="rounded-[28px] border border-line bg-panel/70 p-6 shadow-panel">
            <p className="font-mono text-xs uppercase tracking-[0.18em] text-accent">Audit</p>
            <div className="mt-4 space-y-3">
              {(auditQuery.data?.items ?? []).slice(0, 8).map((item) => (
                <div key={item.id} className="rounded-2xl border border-line bg-abyss/60 p-4 text-sm text-muted">
                  <p className="font-medium text-white">{item.action}</p>
                  <p className="mt-1">{item.reason || "No reason provided."}</p>
                </div>
              ))}
              {!auditQuery.data?.items?.length ? <p className="text-sm text-muted">No host identity changes recorded yet.</p> : null}
            </div>
          </section>
        </div>
      </section>

      {deleteTarget ? (
        <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/70 p-4">
          <div className="w-full max-w-xl rounded-[28px] border border-danger/40 bg-panel p-6 shadow-panel">
            <p className="font-mono text-xs uppercase tracking-[0.24em] text-danger">Delete host</p>
            <h3 className="mt-2 text-2xl font-semibold text-ink">{deleteTarget.display_name}</h3>

            {deletionPreviewQuery.isLoading ? (
              <p className="mt-4 text-sm text-muted">Checking evidence, findings and identity impact…</p>
            ) : deletionPreviewQuery.isError ? (
              <p className="mt-4 text-sm text-danger">Could not load the deletion impact preview. Try again.</p>
            ) : deletionPreviewQuery.data ? (
              <>
                <div className="mt-4 grid gap-2 text-sm text-muted">
                  <p>Evidence assigned: <span className="text-ink">{deletionPreviewQuery.data.evidence_count}</span></p>
                  <p>Findings linked: <span className="text-ink">{deletionPreviewQuery.data.findings_count}</span></p>
                  <p>Aliases: <span className="text-ink">{deleteTarget.all_names.join(", ")}</span></p>
                </div>

                {requiresReassignment ? (
                  <div className="mt-5 rounded-2xl border border-warning/40 bg-warning/10 p-4 text-sm">
                    <p className="font-medium text-warning">This host has evidence assigned</p>
                    <p className="mt-1 text-muted">
                      Kairon never leaves evidence without a host. Move the {deletionPreviewQuery.data.evidence_count} evidence item{deletionPreviewQuery.data.evidence_count === 1 ? "" : "s"} listed below to another host to continue, or cancel.
                    </p>
                    <ul className="mt-3 space-y-1 text-xs text-muted">
                      {deletionPreviewQuery.data.evidences.map((item) => (
                        <li key={item.id}>{item.name || item.id} <span className="text-muted/70">({item.evidence_type || "unknown"})</span></li>
                      ))}
                    </ul>
                    {deletionPreviewQuery.data.eligible_target_hosts.length ? (
                      <label className="mt-4 block text-xs text-muted">
                        <span className="mb-2 block font-mono uppercase tracking-[0.14em]">Move evidence to</span>
                        <select
                          aria-label="Move evidence to host"
                          value={reassignTargetId}
                          onChange={(event) => setReassignTargetId(event.target.value)}
                          className="w-full rounded-xl border border-line bg-abyss px-3 py-2 text-sm text-ink"
                        >
                          <option value="">Select a host…</option>
                          {deletionPreviewQuery.data.eligible_target_hosts.map((item) => (
                            <option key={item.id} value={item.id}>{item.display_name}</option>
                          ))}
                        </select>
                      </label>
                    ) : (
                      <p className="mt-4 text-xs text-danger">There is no other host in this case to move evidence to. Create one first, or cancel.</p>
                    )}
                  </div>
                ) : (
                  <p className="mt-4 text-sm text-muted">No evidence is assigned to this host. Deleting it will not affect any evidence.</p>
                )}

                <label className="mt-5 block text-sm text-muted">
                  Reason (optional, kept in the audit trail).
                  <input value={deleteReason} onChange={(event) => setDeleteReason(event.target.value)} className="mt-2 w-full rounded-2xl border border-line bg-abyss px-4 py-3 text-sm text-ink outline-none focus:border-danger" />
                </label>
                <label className="mt-4 block text-sm text-muted">
                  Type DELETE to confirm.
                  <input value={deleteConfirmText} onChange={(event) => setDeleteConfirmText(event.target.value)} className="mt-2 w-full rounded-2xl border border-line bg-abyss px-4 py-3 font-mono text-sm text-ink outline-none focus:border-danger" />
                </label>
                {deleteHostMutation.error instanceof Error ? <p className="mt-3 text-sm text-danger">{deleteHostMutation.error.message}</p> : null}
              </>
            ) : null}

            <div className="mt-5 flex flex-wrap justify-end gap-2">
              <button type="button" onClick={closeDeleteDialog} className="rounded-2xl border border-line bg-abyss/80 px-4 py-2 text-sm text-muted">Cancel</button>
              <button
                type="button"
                onClick={() => deleteHostMutation.mutate()}
                disabled={!deleteConfirmationValid || deleteHostMutation.isPending || deletionPreviewQuery.isLoading}
                className="rounded-2xl bg-danger px-4 py-2 text-sm font-semibold text-white disabled:opacity-50"
              >
                {deleteHostMutation.isPending ? "Deleting…" : "Delete host"}
              </button>
            </div>
          </div>
        </div>
      ) : null}
    </div>
  );
}
