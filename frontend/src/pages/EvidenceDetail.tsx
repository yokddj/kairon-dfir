import { useEffect, useMemo, useState } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { Link, useNavigate, useParams } from "react-router-dom";

import { api, type VelociraptorCandidate } from "../api/client";
import BundledEvidencePanel, { type BundledEvidenceItem } from "../components/BundledEvidencePanel";
import EvidenceSourceTablesPanel from "../components/EvidenceSourceTablesPanel";
import { InvestigationBreadcrumbs } from "../components/InvestigationContext";
import ActionsMenu, { type MenuItem } from "../components/evidence/ActionsMenu";
import DeleteEvidenceDialog from "../components/evidence/DeleteEvidenceDialog";
import EvidenceResults from "../components/evidence/EvidenceResults";
import FamilySelection, { familiesFromCandidates } from "../components/evidence/FamilySelection";
import HostPicker from "../components/evidence/HostPicker";
import OptionalIndexing from "../components/evidence/OptionalIndexing";
import ProcessingPanel from "../components/evidence/ProcessingPanel";
import ReprocessDialog from "../components/evidence/ReprocessDialog";
import TechnicalDetails from "../components/evidence/TechnicalDetails";
import { useActiveCase } from "../context/ActiveCaseContext";
import { useNotifications } from "../context/NotificationsContext";
import { useHostAssignment } from "../hooks/useHostAssignment";
import { isBrowsableCollection } from "../lib/browsableEvidence";
import { commandHistoryRoute, diskFilesRoute, memoryEvidenceRoute } from "../lib/canonicalRoutes";
import { evidenceTypeLabel, formatBytes, formatPlatform, isRawDiscoveryEvidenceLike } from "../lib/evidenceDetailFormatting";
import { bucketProblems, deriveEvidenceView, liveProgress, STATE_LABEL, STATE_TONE } from "../lib/evidenceStatus";
import { useInvestigationBreadcrumbs } from "../lib/useInvestigationBreadcrumbs";

const COMMAND_TYPES = /shell_history|powershell|command|bash|zsh/;

function failureReason(errorLog: Record<string, unknown> | undefined, statusReason: string | null | undefined) {
  for (const key of ["message", "error", "detail", "reason"]) {
    const value = errorLog?.[key];
    if (typeof value === "string" && value.trim()) return value;
  }
  return statusReason ? statusReason.replaceAll("_", " ") : null;
}

export default function EvidenceDetail() {
  const { evidenceId = "" } = useParams();
  const navigate = useNavigate();
  const queryClient = useQueryClient();
  const { notify } = useNotifications();
  const { setActiveCaseId, caseContext } = useActiveCase();
  const [nowMs, setNowMs] = useState(() => Date.now());
  const [dialog, setDialog] = useState<"reprocess" | "delete" | null>(null);
  const [busyPolling, setBusyPolling] = useState(false);

  const poll = (fast: number) => (busyPolling ? fast : false);
  const evidenceQuery = useQuery({
    queryKey: ["evidence", evidenceId],
    queryFn: () => api.getEvidence(evidenceId),
    enabled: Boolean(evidenceId),
    refetchInterval: (query) => {
      const status = query.state.data?.ingest_status;
      return status === "pending" || status === "processing" || busyPolling ? 3000 : false;
    },
    refetchIntervalInBackground: true,
  });
  const evidence = evidenceQuery.data;
  const runsQuery = useQuery({ queryKey: ["evidence-runs", evidenceId], queryFn: () => api.getEvidenceRuns(evidenceId), enabled: Boolean(evidenceId), refetchInterval: () => poll(3000) });
  const planQuery = useQuery({
    queryKey: ["evidence-indexing-plan", evidenceId, "recommended"],
    queryFn: () => api.getEvidenceIndexingPlan(evidenceId, "recommended"),
    enabled: Boolean(evidenceId),
    // On-demand jobs (full MFT, registry) keep running after ingest_status is final.
    refetchInterval: (query) => (busyPolling || query.state.data?.active ? 3000 : false),
  });
  const summaryQuery = useQuery({ queryKey: ["evidence-search-summary", evidenceId], queryFn: () => api.getEvidenceSearchSummary(evidenceId), enabled: Boolean(evidenceId), refetchInterval: () => poll(15000) });
  const problemsQuery = useQuery({ queryKey: ["evidence-problematic-artifacts", evidenceId], queryFn: () => api.getProblematicArtifacts(evidenceId), enabled: Boolean(evidenceId), refetchInterval: () => poll(10000) });

  useEffect(() => {
    if (evidence?.case_id) setActiveCaseId(evidence.case_id);
  }, [evidence?.case_id, setActiveCaseId]);
  const breadcrumbs = useInvestigationBreadcrumbs({ currentLabel: evidence?.original_filename || "Evidence" });

  const hostAssignment = useHostAssignment({ caseId: evidence?.case_id, evidenceId, currentHostId: evidence?.host_id, detectedHost: evidence?.detected_host, ready: Boolean(evidence) });

  const runs = runsQuery.data ?? [];
  const summary = summaryQuery.data;
  const indexedDocs = Number(summary?.total_indexed_docs ?? evidence?.metadata_json?.events_indexed ?? 0);
  const view = deriveEvidenceView({ evidence, runs, plan: planQuery.data, indexedDocs, nowMs });
  const working = view.state === "processing" || view.state === "stalled";
  const progress = liveProgress(evidence, view.activeRun, nowMs);
  const problems = useMemo(() => bucketProblems(problemsQuery.data?.items ?? []), [problemsQuery.data]);

  // Poll everything while work is in flight, and once more when it ends so the
  // final numbers replace the live ones without a reload.
  useEffect(() => {
    if (working) {
      setBusyPolling(true);
      const timer = window.setInterval(() => setNowMs(Date.now()), 1000);
      return () => window.clearInterval(timer);
    }
    if (busyPolling) {
      setBusyPolling(false);
      for (const key of ["evidence-search-summary", "evidence-problematic-artifacts", "evidence-runs", "evidence-mft-diagnostic", "evidence-registry-diagnostic"]) {
        void queryClient.invalidateQueries({ queryKey: [key, evidenceId] });
      }
    }
    return undefined;
  }, [working, busyPolling, evidenceId, queryClient]);

  function refreshAll() {
    for (const key of ["evidence", "evidence-runs", "evidence-indexing-plan", "evidence-search-summary", "evidence-problematic-artifacts"]) {
      void queryClient.invalidateQueries({ queryKey: [key, evidenceId] });
    }
  }
  const onFail = (title: string) => (error: unknown) => notify({ title, description: error instanceof Error ? error.message : "", tone: "error" });

  const startIndexing = useMutation({
    mutationFn: () => api.runEvidenceIndexingPlan(evidenceId, { profile: "recommended" }),
    onSuccess: () => {
      setBusyPolling(true);
      refreshAll();
    },
    onError: onFail("Indexing could not start"),
  });
  const parseSelected = useMutation({
    mutationFn: (candidateIds: string[]) =>
      api.parseVelociraptorSelection({
        evidence_id: evidenceId,
        selected_candidate_ids: candidateIds,
        ingest_mode: (evidence?.metadata_json?.ingest_mode as "usable_search" | "full_forensic" | undefined) ?? "usable_search",
        provided_host: evidence?.provided_host ?? undefined,
        evtx_profile: "full",
      }),
    onSuccess: () => {
      setBusyPolling(true);
      refreshAll();
    },
    onError: onFail("Indexing could not start"),
  });
  const pause = useMutation({
    mutationFn: () => api.pauseEvidenceIndexing(evidenceId, { reason: "Paused by analyst from Evidence Detail." }),
    onSuccess: () => {
      notify({ title: "Indexing paused", description: "Re-index to continue from where it stopped.", tone: "success" });
      refreshAll();
    },
    onError: onFail("Pause failed"),
  });
  const cancelStalled = useMutation({
    mutationFn: () => api.cancelEvidenceIndexing(evidenceId, { reason: "Cancelled from Evidence Detail: no worker activity." }),
    onSuccess: () => {
      notify({ title: "Stalled run cancelled", description: "You can re-index the evidence now.", tone: "success" });
      refreshAll();
    },
    onError: onFail("Cancel failed"),
  });
  const retry = useMutation({
    mutationFn: (artifactIds: string[]) =>
      artifactIds.length === 1
        ? api.retryProblematicArtifact(evidenceId, artifactIds[0], { mode: "higher_timeout", preserve_existing_events: true, replace_existing_events_for_artifact: false })
        : api.retryProblematicArtifacts(evidenceId, { artifact_ids: artifactIds, mode: "higher_timeout", preserve_existing_events: true, replace_existing_events_for_artifact: false }),
    onSuccess: () => {
      setBusyPolling(true);
      refreshAll();
    },
    onError: onFail("Retry failed"),
  });
  const verifyIntegrity = useMutation({
    mutationFn: () => api.verifyEvidenceIntegrity(evidence!.case_id, evidenceId),
    onSuccess: (result) => {
      const ok = result.integrity_status === "verified";
      notify({ title: ok ? "SHA-256 verified" : "Integrity problem", description: ok ? "The stored file matches its recorded hash." : String(result.integrity_status).replaceAll("_", " "), tone: ok ? "success" : "warning" });
      void queryClient.invalidateQueries({ queryKey: ["evidence", evidenceId] });
      void queryClient.invalidateQueries({ queryKey: ["evidence-integrity", evidence?.case_id, evidenceId] });
      void queryClient.invalidateQueries({ queryKey: ["evidence-custody-events", evidence?.case_id, evidenceId] });
    },
    onError: onFail("Integrity check failed"),
  });
  const exportManifest = useMutation({
    mutationFn: () => api.exportEvidenceManifest(evidence!.case_id, evidenceId),
    onSuccess: (manifest) => {
      const url = URL.createObjectURL(new Blob([JSON.stringify(manifest, null, 2)], { type: "application/json" }));
      const anchor = document.createElement("a");
      anchor.href = url;
      anchor.download = `kairon-evidence-manifest-${evidenceId}.json`;
      anchor.click();
      URL.revokeObjectURL(url);
      void queryClient.invalidateQueries({ queryKey: ["evidence-custody-events", evidence?.case_id, evidenceId] });
    },
    onError: onFail("Manifest export failed"),
  });
  const remove = useMutation({
    mutationFn: () => api.deleteEvidence(evidenceId),
    onSuccess: async () => {
      notify({ title: "Evidence deleted", tone: "success" });
      if (evidence?.case_id) {
        await queryClient.invalidateQueries({ queryKey: ["evidences", evidence.case_id] });
        navigate(`/cases/${evidence.case_id}`);
      } else {
        navigate("/cases");
      }
    },
    onError: onFail("Delete failed"),
  });

  if (evidenceQuery.error instanceof Error) {
    return <p className="rounded-2xl border border-danger/30 bg-danger/10 p-4 text-sm text-danger">{evidenceQuery.error.message}</p>;
  }
  if (!evidence) return <p className="p-4 text-sm text-muted">Loading evidence…</p>;

  const caseId = evidence.case_id;
  const metadata = evidence.metadata_json ?? {};
  const scope = `evidence_id=${encodeURIComponent(evidenceId)}`;
  const isMemory = String(evidence.evidence_type || "").toLowerCase().includes("memory") || evidence.effective_platform === "memory";
  const hostLabel = hostAssignment.assignedHost?.display_name || evidence.provided_host || evidence.detected_host || "";
  const candidates = ((metadata.velociraptor_discovery as { candidates?: VelociraptorCandidate[] } | undefined)?.candidates ?? []) as VelociraptorCandidate[];
  const categoryLabels = Object.fromEntries((evidence.platform_profile?.categories ?? []).map((category) => [category.id, category.label]));
  const archiveTruncation = (metadata.extraction_diagnostics as { archive_truncated?: { recovered_files: number; first_missing_path: string | null } } | undefined)?.archive_truncated ?? null;
  const bundledEvidence = (Array.isArray(metadata.bundled_evidence) ? metadata.bundled_evidence : []) as BundledEvidenceItem[];
  const artifactTypeCounts = summary?.artifact_type_counts ?? {};
  const hasCommands = Object.keys(artifactTypeCounts).some((type) => COMMAND_TYPES.test(type));
  const ready = view.state === "ready";
  const failures = problems.failures.length;
  const browsable = Boolean(evidence.disk_image) || isBrowsableCollection(evidence);

  const statusLabel = ready && failures ? `Ready · ${failures} failed` : STATE_LABEL[view.state];
  const statusTone = ready && failures ? "border-amber/30 bg-amber/10 text-amber" : STATE_TONE[view.state];

  const primary =
    view.state === "ready"
      ? isMemory
        ? { kind: "link" as const, label: "Open memory analysis", to: memoryEvidenceRoute(caseId, evidenceId) }
        : { kind: "link" as const, label: "Search this evidence", to: `/cases/${caseId}/search?${scope}&tab=results` }
      : view.state === "not_indexed"
        ? { kind: "button" as const, label: startIndexing.isPending ? "Starting…" : "Start indexing", onClick: () => startIndexing.mutate(), disabled: startIndexing.isPending || planQuery.data?.can_run === false }
        : view.state === "failed"
          ? { kind: "button" as const, label: "Re-index…", onClick: () => setDialog("reprocess"), disabled: false }
          : null;

  const menu: MenuItem[] = [
    { kind: "button", label: "Re-index…", onSelect: () => setDialog("reprocess"), disabled: working },
    ...(browsable ? [{ kind: "link" as const, label: "Browse files", to: diskFilesRoute(caseId, evidenceId) }] : []),
    { kind: "link", label: "Add finding", to: `/cases/${caseId}/findings?create=1&${scope}&title=${encodeURIComponent("Evidence note")}&source_view=evidence${evidence.host_id ? `&host_id=${encodeURIComponent(evidence.host_id)}` : ""}` },
    { kind: "button", label: "Verify integrity", onSelect: () => verifyIntegrity.mutate(), disabled: verifyIntegrity.isPending },
    { kind: "button", label: "Export manifest", onSelect: () => exportManifest.mutate(), disabled: exportManifest.isPending },
    { kind: "button", label: "Delete evidence", onSelect: () => setDialog("delete"), danger: true },
  ];

  const openIn = [
    { label: "Search", to: `/cases/${caseId}/search?${scope}&tab=results` },
    { label: "Timeline", to: `/cases/${caseId}/search?${scope}&view=timeline&sort=@timestamp&order=asc` },
    { label: "Artifact views", to: `/cases/${caseId}/artifacts?${scope}` },
    ...(hasCommands ? [{ label: "Command history", to: commandHistoryRoute(caseId, new URLSearchParams({ evidence_id: evidenceId })) }] : []),
    { label: "Findings", to: `/cases/${caseId}/findings?${scope}` },
    { label: "Report", to: `/cases/${caseId}/reports?${scope}` },
  ];

  const meta = [formatPlatform(evidence.effective_platform), evidenceTypeLabel(evidence.evidence_type), evidence.size_bytes ? formatBytes(evidence.size_bytes) : null].filter(Boolean);

  return (
    <div className="min-w-0 space-y-4">
      <InvestigationBreadcrumbs items={breadcrumbs} />

      <header className="rounded-3xl border border-line bg-panel/75 p-5 shadow-panel">
        <div className="flex flex-wrap items-start justify-between gap-4">
          <div className="min-w-0">
            <h2 className="break-words text-2xl font-semibold text-ink">{evidence.original_filename}</h2>
            <div className="mt-2 flex flex-wrap items-center gap-x-3 gap-y-1 text-sm text-muted">
              <span className={`rounded-full border px-2.5 py-0.5 text-xs font-medium ${statusTone}`} data-testid="evidence-status">
                {statusLabel}
              </span>
              <span>{meta.join(" · ")}</span>
              <HostPicker hostLabel={hostLabel} detectedHost={evidence.detected_host} assignment={hostAssignment} warnUnassigned={isMemory && !evidence.host_id} />
            </div>
          </div>
          <div className="flex items-center gap-2">
            {primary?.kind === "link" ? (
              <Link to={primary.to} className="rounded-xl bg-accent px-4 py-2 text-sm font-semibold text-abyss">
                {primary.label}
              </Link>
            ) : primary ? (
              <button type="button" onClick={primary.onClick} disabled={primary.disabled} className="rounded-xl bg-accent px-4 py-2 text-sm font-semibold text-abyss disabled:opacity-50">
                {primary.label}
              </button>
            ) : null}
            <ActionsMenu items={menu} />
          </div>
        </div>
        {ready && !isMemory ? (
          <nav className="mt-4 flex flex-wrap gap-x-5 gap-y-1 border-t border-line pt-3 text-sm" aria-label="Open this evidence in">
            {openIn.map((link) => (
              <Link key={link.label} to={link.to} className="text-muted hover:text-accent">
                {link.label}
              </Link>
            ))}
          </nav>
        ) : null}
      </header>

      {archiveTruncation ? (
        <div className="rounded-2xl border border-warning/40 bg-warning/10 p-4 text-sm" role="alert" data-testid="evidence-archive-truncated">
          <p className="font-semibold text-warning">Incomplete archive: part of the collection is missing</p>
          <p className="mt-1 text-ink">
            The archive ends before its file index (an interrupted copy or collection). The {archiveTruncation.recovered_files.toLocaleString("en-US")} complete files before the cut were analysed
            {archiveTruncation.first_missing_path ? <>; files from <span className="break-all font-mono text-xs">{archiveTruncation.first_missing_path}</span> on are missing</> : ""}. Upload a complete copy for the full
            collection.
          </p>
        </div>
      ) : null}

      {working && metadata.register_bundled_memory && !bundledEvidence.length ? (
        <p className="rounded-2xl border border-accent/30 bg-accent/5 p-4 text-sm text-ink" data-testid="compressed-memory-extracting">
          Compressed memory capture: the archive is being extracted (a large capture takes several minutes without visible progress). The memory image is then registered as its own evidence, linked here.
        </p>
      ) : null}

      {bundledEvidence.length ? (
        <BundledEvidencePanel caseId={caseId} evidenceId={evidence.id} items={bundledEvidence} defaultHost={hostLabel} hostNames={(caseContext?.hosts ?? []).map((host) => host.display_name).filter(Boolean)} />
      ) : null}

      {working ? (
        <ProcessingPanel progress={progress} stalled={view.state === "stalled"} heartbeatAt={view.heartbeatAt} onPause={() => pause.mutate()} onCancelStalled={() => cancelStalled.mutate()} busy={pause.isPending || cancelStalled.isPending} />
      ) : null}

      {view.state === "needs_selection" ? (
        <FamilySelection families={familiesFromCandidates(candidates, categoryLabels)} onRecommended={() => startIndexing.mutate()} onSelected={(ids) => parseSelected.mutate(ids)} busy={startIndexing.isPending || parseSelected.isPending} />
      ) : null}

      {view.state === "not_indexed" ? (
        <p className="rounded-2xl border border-line bg-panel/60 p-4 text-sm text-muted">Not indexed yet. Start indexing to parse every supported artifact; you can re-index a subset later.</p>
      ) : null}

      {view.state === "failed" ? (
        <section className="rounded-3xl border border-danger/30 bg-panel/70 p-5" data-testid="evidence-failed">
          <h3 className="text-lg font-semibold text-ink">Processing failed</h3>
          <p className="mt-1 break-words text-sm text-muted">{failureReason(evidence.error_log, evidence.status_reason) ?? "The worker reported no reason."}</p>
        </section>
      ) : null}

      {ready && !isMemory ? (
        <EvidenceResults
          caseId={caseId}
          evidenceId={evidenceId}
          totalDocs={indexedDocs}
          artifactTypeCounts={artifactTypeCounts}
          countsLoaded={Boolean(summary)}
          problems={problems}
          onRetry={(ids) => retry.mutate(ids)}
          retryBusy={retry.isPending}
          extra={evidence.effective_platform === "windows" ? <OptionalIndexing evidenceId={evidenceId} locked={working} /> : null}
        />
      ) : null}

      {ready && !isMemory ? <EvidenceSourceTablesPanel caseId={caseId} evidenceId={evidenceId} /> : null}

      <TechnicalDetails evidence={evidence} runs={runs} />

      {dialog === "reprocess" ? (
        <ReprocessDialog
          evidenceId={evidenceId}
          providedHost={evidence.provided_host}
          allowFamilyChoice={isRawDiscoveryEvidenceLike(evidence, candidates.length)}
          onClose={() => setDialog(null)}
          onStarted={() => {
            setDialog(null);
            setBusyPolling(true);
            refreshAll();
          }}
          onError={(message) => notify({ title: "Re-index failed", description: message, tone: "error" })}
        />
      ) : null}
      {dialog === "delete" ? (
        <DeleteEvidenceDialog filename={evidence.original_filename} indexedDocs={indexedDocs} busy={remove.isPending} onCancel={() => setDialog(null)} onConfirm={() => remove.mutate()} />
      ) : null}
    </div>
  );
}
