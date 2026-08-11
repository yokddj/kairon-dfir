import { useCallback, useEffect, useMemo, useRef, useState } from "react";
import { Link, useParams, useSearchParams, useNavigate } from "react-router-dom";
import { useMutation, useQueries, useQuery, useQueryClient } from "@tanstack/react-query";
import { api, type EvidencePlatformCapabilities } from "../api/client";
import { useActiveCase } from "../context/ActiveCaseContext";
import { MemoryWorkspace } from "../components/MemoryWorkspace";
import InvestigationContext from "../components/InvestigationContext";
import { useHostContext } from "../hooks/useHostContext";
import { useInvestigationBreadcrumbs } from "../lib/useInvestigationBreadcrumbs";
import { MemoryEvidenceHeader } from "../components/memory/MemoryEvidenceHeader";
import { MemoryEvidenceSelector } from "../components/memory/MemoryEvidenceSelector";
import { MemoryAnalysisCatalogueModal } from "../components/memory/MemoryAnalysisCatalogueModal";
import { MemoryHistoryPanel } from "../components/memory/MemoryHistoryPanel";
import { MemoryTypeConfirmationModal } from "../components/memory/MemoryTypeConfirmationModal";
import { MemorySymbolResolutionPanel } from "../components/memory/MemorySymbolResolutionPanel";
import { MemoryExperimentalResultsPanel } from "../components/memory/MemoryExperimentalResultsPanel";
import { MemoryPreparationCard } from "../components/memory/MemoryPreparationCard";
import { VmwareCompanionSection } from "../components/memory/VmwareCompanionSection";
import { ZeroResultWarningBanner } from "../components/memory/ZeroResultWarningBanner";
import { assignedHostMatchesDetected, normalizeEvidenceHostName } from "../lib/evidenceDetailFormatting";
import { capabilityEnabled } from "../lib/platformRegistry";
import { MEMORY_TABS, isMemoryTab, tabFromRouteSegment, routeSegmentFromTab, type MemoryTab } from "../lib/memoryWorkspaceState";
import { memoryQueryKeys } from "../lib/memoryQueryKeys";
import { linuxCommandHistoryRoute, memoryEvidenceRoute, memoryWorkbenchRoute } from "../lib/canonicalRoutes";
import type { CaseContextHostSummary, MemoryEvidenceLanding, MemoryEvidenceLandingItem, MemoryScanRun } from "../api/client";

const ARTIFACT_FAMILY_FROM_TAB: Record<string, string> = {
  processes: "processes",
  system: "system_info",
  network: "network",
  modules: "modules",
  handles: "handles",
  suspicious: "suspicious_regions",
  vads: "vads",
  raw: "raw_observations",
  artifacts: "artifacts",
};

function familyForTab(tab: MemoryTab, _artifact?: string | null): string {
  return ARTIFACT_FAMILY_FROM_TAB[tab] || "processes";
}

function assignedHost(item: MemoryEvidenceLandingItem | null, hosts: CaseContextHostSummary[]): CaseContextHostSummary | null {
  if (!item?.host_id) return null;
  return hosts.find((host) => host.id === item.host_id) ?? null;
}

function hostAssignmentStatus(item: MemoryEvidenceLandingItem | null, hosts: CaseContextHostSummary[]): { label: string; tone: string } {
  if (!item?.host_id) return { label: "Unassigned", tone: "border-line bg-panel/50 text-muted" };
  const host = assignedHost(item, hosts);
  const detected = normalizeEvidenceHostName(item.detected_host);
  if (!host || !detected) return { label: "Assigned", tone: "border-mint/30 bg-mint/10 text-mint" };
  return assignedHostMatchesDetected(host, item.detected_host)
    ? { label: "Assigned", tone: "border-mint/30 bg-mint/10 text-mint" }
    : { label: "Mismatch", tone: "border-amber/30 bg-amber/10 text-amber" };
}

export default function MemoryEvidencePage() {
  const { caseId = "", evidenceId = "", memoryTab = "" } = useParams();
  const [searchParams, setSearchParams] = useSearchParams();
  const navigate = useNavigate();
  const { setActiveCaseId } = useActiveCase();
  const { activeHost, activeHostId, hasHostFilter, clearHostFilter, withHostScope } = useHostContext();
  const [catalogueOpen, setCatalogueOpen] = useState(false);
  const [historyOpen, setHistoryOpen] = useState(false);
  const [confirmationOpen, setConfirmationOpen] = useState(false);
  const [confirmationError, setConfirmationError] = useState<string | null>(null);
  const [confirmationToast, setConfirmationToast] = useState<string | null>(null);
  const [hostAssignmentMode, setHostAssignmentMode] = useState<"existing" | "create">("existing");
  const [hostAssignmentId, setHostAssignmentId] = useState("");
  const [hostAssignmentName, setHostAssignmentName] = useState("");
  const [assignedHostOverrideId, setAssignedHostOverrideId] = useState<string | null | undefined>(undefined);
  const [assignedHostDisplayOverride, setAssignedHostDisplayOverride] = useState<string | null | undefined>(undefined);
  const queryClient = useQueryClient();
  const submittingRef = useRef(false);

  useEffect(() => {
    setActiveCaseId(caseId);
  }, [caseId, setActiveCaseId]);

  useEffect(() => {
    const legacyTab = searchParams.get("tab");
    if (!caseId || !evidenceId || !legacyTab) return;
    const params = new URLSearchParams();
    params.set("source_category", "Memory");
    params.set("evidence_id", evidenceId);
    if (activeHostId) params.set("host_id", activeHostId);
    if (activeHost) params.set("host", activeHost);
    const runId = searchParams.get("run_id");
    const processEntityId = searchParams.get("process_entity_id");
    const pid = searchParams.get("pid");
    if (runId) params.set("run_id", runId);
    if (processEntityId) params.set("process_entity_id", processEntityId);
    if (pid) params.set("pid", pid);
    if (legacyTab === "search") navigate(`/cases/${caseId}/search?${params.toString()}`, { replace: true });
    if (legacyTab === "timeline") navigate(`/cases/${caseId}/timeline?${params.toString()}`, { replace: true });
    if (legacyTab === "history") navigate(linuxCommandHistoryRoute(caseId, params), { replace: true });
  }, [activeHost, activeHostId, caseId, evidenceId, memoryTab, navigate, searchParams, setSearchParams]);

  const tab = useMemo<MemoryTab>(() => {
    const routeTab = tabFromRouteSegment(memoryTab);
    if (routeTab) return routeTab;
    const raw = searchParams.get("tab");
    return isMemoryTab(raw) ? raw : "overview";
  }, [memoryTab, searchParams]);

  const artifactParam = searchParams.get("artifact");
  const family = familyForTab(tab, artifactParam);

  const historicalRunId = searchParams.get("run_id") || null;

  const memoryViewPath = useCallback((targetEvidenceId: string, targetTab: MemoryTab = tab) => {
    const params = new URLSearchParams(searchParams);
    params.delete("tab");
    params.delete("run_id");
    const query = params.toString();
    return memoryEvidenceRoute(caseId, targetEvidenceId, routeSegmentFromTab(targetTab), query);
  }, [caseId, searchParams, tab]);

  const overviewQuery = useQuery({
    queryKey: ["memory-overview", caseId, activeHostId, activeHost],
    queryFn: () => api.getMemoryOverview(caseId, { host_id: activeHostId || undefined, host: activeHost || undefined }),
    enabled: Boolean(caseId),
    refetchOnWindowFocus: false,
  });

  const evidenceRunsQuery = useQuery({
    queryKey: memoryQueryKeys.runs(caseId, evidenceId),
    queryFn: () => api.listMemoryRuns(caseId, evidenceId),
    enabled: Boolean(caseId && evidenceId),
    refetchOnWindowFocus: false,
    refetchInterval: (query) => {
      const runs = (query.state.data ?? []) as MemoryScanRun[];
      return runs.some((run) => ["pending", "queued", "running"].includes(run.status)) ? 3000 : false;
    },
  });
  const hasActiveRuns = useMemo(
    () => (evidenceRunsQuery.data ?? []).some(
      (run: MemoryScanRun) => ["pending", "queued", "running"].includes(run.status),
    ),
    [evidenceRunsQuery.data],
  );

  const landingQuery = useQuery({
    queryKey: [...memoryQueryKeys.landing(caseId), activeHostId, activeHost],
    queryFn: () => api.getMemoryEvidenceLanding(caseId, { host_id: activeHostId || undefined, host: activeHost || undefined }),
    enabled: Boolean(caseId),
    refetchOnWindowFocus: false,
    refetchInterval: hasActiveRuns ? 3000 : false,
  });

  const caseHostsQuery = useQuery({
    queryKey: ["case-hosts", caseId],
    queryFn: () => typeof api.getCaseHosts === "function" ? api.getCaseHosts(caseId) : Promise.resolve({ case_id: caseId, hosts: [], host_candidates: [] }),
    enabled: Boolean(caseId),
    refetchOnWindowFocus: false,
  });

  const activeResultQuery = useQuery({
    queryKey: ["memory-active-result", caseId, evidenceId, family, historicalRunId],
    queryFn: () => api.getMemoryActiveResult(caseId, evidenceId, family, historicalRunId || undefined),
    enabled: Boolean(caseId && evidenceId && family),
    refetchOnWindowFocus: false,
  });

  const catalogueQuery = useQuery({
    queryKey: memoryQueryKeys.catalogue(caseId, evidenceId),
    queryFn: () => api.getMemoryAnalysisCatalogue(caseId, evidenceId),
    enabled: Boolean(caseId && evidenceId),
    refetchOnWindowFocus: false,
    refetchInterval: hasActiveRuns ? 3000 : false,
  });

  const backendQuery = useQuery({
    queryKey: ["memory-backends"],
    queryFn: () => api.getMemoryBackendOverview(),
    refetchOnWindowFocus: false,
  });

  const overview = overviewQuery.data;
  const evidence = landingQuery.data?.items?.find((item) => item.evidence_id === evidenceId) || null;
  // Tabs that are registered capabilities (processes, network) resolve to
  // the full Case/Surface/Domain/Capability trail on their own, with the
  // evidence name auto-derived from the registry; "Memory" is the fallback
  // for the other tabs (overview, modules, handles, ...), which aren't
  // registered capabilities. The evidence filename is passed explicitly
  // either way since this page already has it directly, rather than
  // depending on whether capability matching happened to fire.
  const breadcrumbs = useInvestigationBreadcrumbs({ lensLabel: "Memory", context: evidence?.filename || undefined });
  const evidencePlatformProfile = evidence?.platform_capabilities ? { capabilities: evidence.platform_capabilities as EvidencePlatformCapabilities } : null;
  const linuxMemoryHint = capabilityEnabled(evidencePlatformProfile, "supportsJournal") || capabilityEnabled(evidencePlatformProfile, "supportsPackages") || capabilityEnabled(evidencePlatformProfile, "supportsUsers");
  const caseHosts = caseHostsQuery.data?.hosts ?? [];
  const displayedEvidence = evidence && assignedHostOverrideId !== undefined ? { ...evidence, host_id: assignedHostOverrideId } : evidence;
  const currentAssignedHost = assignedHost(displayedEvidence, caseHosts);
  const selectedAssignedHost = hostAssignmentId ? caseHosts.find((host) => host.id === hostAssignmentId) ?? null : null;
  const currentHostStatus = hostAssignmentStatus(displayedEvidence, caseHosts);
  const volatilityBackend = backendQuery.data?.backends.find((b) => b.backend === "volatility3") || null;
  const canRun = Boolean(overview?.memory_analysis_enabled && volatilityBackend?.ready);

  useEffect(() => {
    setAssignedHostOverrideId(undefined);
    setAssignedHostDisplayOverride(undefined);
    setHostAssignmentId(evidence?.host_id || "");
    setHostAssignmentMode("existing");
  }, [evidence?.evidence_id]);

  useEffect(() => {
    if (assignedHostOverrideId !== undefined) return;
    setHostAssignmentId(evidence?.host_id || "");
  }, [assignedHostOverrideId, evidence?.host_id]);

  const hostAssignmentMutation = useMutation({
    mutationFn: async () => {
      if (!evidence) throw new Error("Memory evidence is not loaded.");
      if (hostAssignmentMode === "create") {
        const name = hostAssignmentName.trim();
        if (!name) throw new Error("Enter a host name.");
        const created = await api.createCaseHost(caseId, { host_name: name, reason: "Created from Memory evidence" });
        return api.updateEvidenceHost(caseId, evidence.evidence_id, { host_id: created.host.id, reason: "Assigned from Memory evidence" });
      }
      return api.updateEvidenceHost(caseId, evidence.evidence_id, { host_id: hostAssignmentId || null, reason: hostAssignmentId ? "Assigned from Memory evidence" : "Marked unassigned from Memory evidence" });
    },
    onSuccess: (updated) => {
      queryClient.setQueryData<MemoryEvidenceLanding | undefined>([...memoryQueryKeys.landing(caseId), activeHostId, activeHost], (current) => current ? {
        ...current,
        items: current.items.map((item) => item.evidence_id === evidenceId ? { ...item, host_id: updated.host_id ?? null } : item),
      } : current);
      setHostAssignmentName("");
      setHostAssignmentMode("existing");
      setHostAssignmentId(updated.host_id || "");
      setAssignedHostOverrideId(updated.host_id ?? null);
      setAssignedHostDisplayOverride(updated.host_id ? (caseHosts.find((host) => host.id === updated.host_id)?.display_name || updated.host_id) : null);
      void queryClient.invalidateQueries({ queryKey: ["case-hosts", caseId] });
      void queryClient.invalidateQueries({ queryKey: ["case-context", caseId] });
      void queryClient.invalidateQueries({ queryKey: ["memory-overview", caseId] });
      void queryClient.invalidateQueries({ queryKey: memoryQueryKeys.landing(caseId) });
    },
  });

  function saveHostAssignmentFromMemory() {
    if (hostAssignmentMode === "existing") {
      setAssignedHostOverrideId(hostAssignmentId || null);
      setAssignedHostDisplayOverride(hostAssignmentId ? (caseHosts.find((host) => host.id === hostAssignmentId)?.display_name || hostAssignmentId) : null);
    }
    hostAssignmentMutation.mutate();
  }

  const activeBatchQuery = useQuery({
    queryKey: ["memory-active-batch", caseId, evidenceId],
    enabled: Boolean(caseId && evidenceId),
    refetchOnWindowFocus: false,
    refetchInterval: 5_000,
    retry: false,
    queryFn: async () => {
      try {
        return await api.getActiveMemoryAnalysisBatch(caseId, evidenceId);
      } catch (err) {
        // 404 means "no active batch" - this is the normal end state.
        return null;
      }
    },
  });
  const activeBatch = activeBatchQuery.data ?? null;

  const cancelBatchMutation = useMutation({
    mutationFn: async () => {
      if (!activeBatch) return null;
      return api.cancelMemoryAnalysisBatch(caseId, evidenceId, activeBatch.id);
    },
    onSuccess: () => {
      activeBatchQuery.refetch();
    },
  });

  const confirmMemoryTypeMutation = useMutation({
    mutationFn: async (reason: string) =>
      api.confirmMemoryType(caseId, evidenceId, reason),
    onSuccess: () => {
      setConfirmationOpen(false);
      setConfirmationError(null);
      setConfirmationToast("Memory evidence type confirmed. Analysis is now available.");
      const keys = memoryQueryKeys.invalidateAfterMutation(caseId, evidenceId);
      for (const key of keys) {
        void queryClient.invalidateQueries({ queryKey: key });
      }
      void queryClient.invalidateQueries({ queryKey: ["memory-readiness", caseId, evidenceId] });
      window.setTimeout(() => setConfirmationToast(null), 5000);
    },
    onError: (error: Error & { errorCode?: string }) => {
      setConfirmationError(error.message || "Confirmation failed. Please try again.");
    },
  });

  const startScanMutation = useMutation({
    mutationFn: async () =>
      api.startMemoryScan(caseId, evidenceId, "metadata_only"),
    onSuccess: () => {
      const keys = memoryQueryKeys.invalidateAfterMutation(caseId, evidenceId);
      for (const key of keys) {
        void queryClient.invalidateQueries({ queryKey: key });
      }
    },
    onError: (_error: Error & { errorCode?: string }) => {
    },
    onSettled: () => {
      submittingRef.current = false;
    },
  });

  useEffect(() => {
    if (!overview) return;
    if (overview.evidences.length === 0) {
      // No memory evidence: let the parent route render the empty state.
    }
  }, [overview]);

  useEffect(() => {
    // memoryTab here is a route SEGMENT (e.g. "process-graph"), not a tab
    // key -- isMemoryTab() checks tab keys ("graph"), so it always missed
    // every route whose segment differs from its key, firing this legacy
    // ?tab= fallback (and a stray replace-navigation) on every load of
    // those tabs even though the route already resolved a valid tab.
    if (!evidenceId || tabFromRouteSegment(memoryTab) !== null) return;
    setSearchParams((current) => {
      const params = new URLSearchParams(current);
      if (!params.get("tab")) params.set("tab", "overview");
      return params;
    }, { replace: true });
  }, [evidenceId, memoryTab, setSearchParams]);

  useEffect(() => {
    if (catalogueQuery.data) return;
    if (catalogueOpen) {
      void catalogueQuery.refetch();
    }
  }, [catalogueOpen, catalogueQuery]);

  const evidenceReadinessQueries = useQueries({
    queries: (overview?.evidences || []).map((evidence) => ({
      queryKey: ["memory-evidence-readiness", caseId, evidence.id],
      queryFn: () => api.getMemoryEvidenceReadiness(caseId, evidence.id),
      refetchOnWindowFocus: false,
    })),
  });
  const readinessByEvidence = new Map(
    (overview?.evidences || []).map((evidence, index) => [evidence.id, evidenceReadinessQueries[index]?.data]),
  );

  // Per-evidence symbol readiness is diagnostic only.  Volatility
  // identifies layers and resolves symbols during the actual run.
  const symbolReadinessQuery = useQuery({
    queryKey: ["memory-symbol-readiness", caseId, evidenceId],
    queryFn: () => api.getMemorySymbolReadiness(caseId, evidenceId),
    enabled: Boolean(caseId && evidenceId),
    refetchOnWindowFocus: false,
  });
  const symbolReadiness = symbolReadinessQuery.data ?? null;

  // Automatic preparation pipeline.  This is the new state machine
  // the analyst sees in the "Memory preparation" card.  Polled
  // aggressively while preparation is in progress.
  const symbolPreparationQuery = useQuery({
    queryKey: ["memory-symbol-preparation", caseId, evidenceId],
    queryFn: () => api.getMemorySymbolPreparation(caseId, evidenceId),
    enabled: Boolean(caseId && evidenceId),
    refetchOnWindowFocus: false,
    refetchInterval: (query) => {
      const data = query.state.data as { ui_state?: string } | undefined;
      if (data?.ui_state && data.ui_state !== "ready" && data.ui_state !== "failed" && data.ui_state !== "blocked") {
        return 2_000;
      }
      return false;
    },
  });
  const symbolPreparation = symbolPreparationQuery.data ?? null;

  // Memory Evidence Preparation (Phase 1/2, app.services.memory.preparation)
  // -- a separate, platform-agnostic read-only snapshot from the
  // MemorySymbolPreparation pipeline above (see MemoryEvidencePreparationCard.tsx's
  // module docstring for the distinction). Only fetched here for its
  // vmware_companion_* fields, which VmwareCompanionSection needs -- this
  // page intentionally does not also render the rest of that card
  // (platform/architecture/readiness), which MemoryPreparationCard and
  // MemorySymbolResolutionPanel below already cover for this page.
  // Same query key as MemoryEvidencePreparationCard.tsx so the two never
  // disagree if ever mounted together.
  const evidencePreparationQueryKey = ["memory-evidence-preparation", caseId, evidenceId];
  const evidencePreparationQuery = useQuery({
    queryKey: evidencePreparationQueryKey,
    queryFn: () => api.getMemoryEvidencePreparation(caseId, evidenceId),
    enabled: Boolean(caseId && evidenceId),
    refetchOnWindowFocus: false,
  });
  const evidencePreparation = evidencePreparationQuery.data ?? null;

  const prepEffectiveState = symbolPreparation?.effective_state || symbolPreparation?.ui_state;
  const isBlockedSymbols = prepEffectiveState === "blocked_symbols";
  const isReadyState = prepEffectiveState === "ready";
  const isNativeReady = isReadyState && symbolPreparation?.native_compatible === true;

  const nativeProbeQuery = useQuery({
    queryKey: ["native-probe", caseId, evidenceId],
    queryFn: () => api.getNativeProbeStatus(caseId, evidenceId),
    enabled: Boolean(caseId && evidenceId && symbolPreparation
      && (isBlockedSymbols || isNativeReady)),
    refetchOnWindowFocus: false,
    refetchInterval: (query) => {
      const data = query.state.data as { status?: string } | undefined;
      const status = data?.status;
      if (status === "queued" || status === "running") {
        return 3_000;
      }
      return false;
    },
  });

  const showExperimentalPanel =
    Boolean(symbolPreparation) && isBlockedSymbols;

  const handleReturnToLatest = useCallback(() => {
    setSearchParams((current) => {
      const params = new URLSearchParams(current);
      params.delete("run_id");
      return params;
    }, { replace: true });
  }, [setSearchParams]);

  const landingItems = landingQuery.data?.items ?? [];

  if (overviewQuery.isLoading) {
    return <div className="rounded-[28px] border border-line bg-panel/70 p-8 text-sm text-muted shadow-panel">Loading evidence...</div>;
  }

  if (!evidence) {
    return (
      <div className="space-y-4 rounded-[28px] border border-rose-400/30 bg-rose-500/10 p-8 text-sm text-rose-100 shadow-panel">
        <p>{hasHostFilter ? `This memory evidence is not associated with active host ${activeHost}.` : "Memory evidence was not found for this case."}</p>
        <div className="flex flex-wrap gap-2">
          <Link to={withHostScope(memoryWorkbenchRoute(caseId))} className="rounded-xl border border-rose-200/40 bg-rose-950/30 px-3 py-2 text-xs text-rose-100">Open filtered memory selector</Link>
          {hasHostFilter ? <button type="button" onClick={clearHostFilter} className="rounded-xl border border-rose-200/40 bg-rose-950/30 px-3 py-2 text-xs text-rose-100">Clear host filter</button> : null}
        </div>
      </div>
    );
  }

  return (
    <div className="space-y-6" data-testid="memory-evidence-workspace">
      <InvestigationContext
        caseId={caseId}
        host={activeHost || evidence.detected_host}
        hostId={activeHostId || evidence.host_id}
        evidenceId={evidenceId}
        evidenceName={evidence.filename}
        current="Memory"
        breadcrumbs={breadcrumbs}
        actions={[
          { label: "Evidence Detail", to: `/evidences/${evidenceId}`, description: "Open integrity and processing details" },
          { label: "Search", to: `/cases/${caseId}/search?source_category=Memory`, description: "Search memory-derived documents" },
          { label: "Timeline", to: `/cases/${caseId}/search?source_category=Memory&view=timeline&sort=@timestamp&order=asc`, description: "Timeline memory-derived events" },
          { label: "Artifacts", to: `/cases/${caseId}/artifacts?source_category=Memory`, description: "Review artifact views with this scope" },
          { label: "Add finding", to: `/cases/${caseId}/findings?create=1&source_view=memory&artifact_family=${encodeURIComponent(family)}&evidence_id=${encodeURIComponent(evidenceId)}&title=${encodeURIComponent("Suspicious memory artifact")}${activeHostId || evidence.host_id ? `&host_id=${encodeURIComponent(activeHostId || evidence.host_id || "")}` : ""}`, description: "Create a contextual memory finding" },
          { label: "Processing", to: `/cases/${caseId}?tab=processing`, description: "Open processing queue" },
        ]}
      />
      {landingItems.length > 1 ? (
        <MemoryEvidenceSelector
          caseId={caseId}
          selectedEvidenceId={evidenceId}
          evidences={landingItems}
          hosts={caseHosts}
          onChange={(newEvidenceId) => {
            navigate(memoryViewPath(newEvidenceId));
          }}
        />
      ) : null}

      <section className="rounded-[28px] border border-accent/30 bg-panel/70 p-5 shadow-panel" data-testid="memory-host-assignment-panel">
        <div className="flex flex-wrap items-start justify-between gap-3">
          <div>
            <p className="font-mono text-[11px] uppercase tracking-[0.18em] text-accent">Host assignment</p>
            <h2 className="mt-1 text-lg font-semibold text-ink">Assign this memory evidence to a case host</h2>
            <p className="mt-2 max-w-3xl text-sm text-muted">Assigned host controls Memory host filters. Detected/provided host stays as evidence metadata.</p>
          </div>
          <span className={`rounded-full border px-3 py-1 text-xs ${currentHostStatus.tone}`} data-testid="memory-host-assignment-status">{currentHostStatus.label}</span>
        </div>
        {!displayedEvidence?.host_id ? (
          <div className="mt-3 rounded-2xl border border-amber/30 bg-amber/10 p-3 text-sm text-amber" role="alert">
            This memory evidence is not assigned to a case host. Host filters may not include it until assigned.
          </div>
        ) : null}
        <div className="mt-4 grid gap-3 md:grid-cols-3">
          <div className="rounded-2xl border border-line bg-abyss/60 px-4 py-3 text-sm text-muted">
            <p className="font-mono text-[11px] uppercase tracking-[0.16em]">Detected/provided host</p>
            <p className="mt-1 text-base font-semibold text-ink" data-testid="memory-detected-host">{evidence.detected_host || "Unknown"}</p>
          </div>
          <div className="rounded-2xl border border-line bg-abyss/60 px-4 py-3 text-sm text-muted">
            <p className="font-mono text-[11px] uppercase tracking-[0.16em]">Assigned host</p>
            <p className="mt-1 text-base font-semibold text-ink" data-testid="memory-assigned-host">{assignedHostDisplayOverride ?? selectedAssignedHost?.display_name ?? currentAssignedHost?.display_name ?? "Unassigned"}</p>
          </div>
          <div className="rounded-2xl border border-line bg-abyss/60 px-4 py-3 text-sm text-muted">
            <p className="font-mono text-[11px] uppercase tracking-[0.16em]">Evidence details</p>
            <Link to={`/evidences/${evidenceId}`} className="mt-2 inline-flex rounded-xl border border-line bg-panel/70 px-3 py-2 text-xs text-accent">
              Open evidence details
            </Link>
          </div>
        </div>
        <div className="mt-4 grid gap-3 md:grid-cols-[180px_1fr_auto] md:items-end">
          <label className="block text-xs text-muted">
            Change host
            <select value={hostAssignmentMode} onChange={(event) => setHostAssignmentMode(event.target.value as "existing" | "create")} className="mt-1 w-full rounded-xl border border-line bg-abyss/80 px-3 py-2 text-sm text-ink">
              <option value="existing">Assign to existing host</option>
              <option value="create">Create new host</option>
            </select>
          </label>
          {hostAssignmentMode === "existing" ? (
            <label className="block text-xs text-muted">
              Assign to existing host
              <select value={hostAssignmentId} onChange={(event) => setHostAssignmentId(event.target.value)} className="mt-1 w-full rounded-xl border border-line bg-abyss/80 px-3 py-2 text-sm text-ink" data-testid="memory-host-assignment-select">
                <option value="">Mark unassigned</option>
                {caseHosts.map((host) => <option key={host.id} value={host.id}>{host.display_name}</option>)}
              </select>
            </label>
          ) : (
            <label className="block text-xs text-muted">
              Create new host
              <input value={hostAssignmentName} onChange={(event) => setHostAssignmentName(event.target.value)} placeholder="WS-01" className="mt-1 w-full rounded-xl border border-line bg-abyss/80 px-3 py-2 text-sm text-ink" />
            </label>
          )}
          <button type="button" onClick={saveHostAssignmentFromMemory} disabled={hostAssignmentMutation.isPending || (hostAssignmentMode === "create" && !hostAssignmentName.trim())} className="rounded-xl bg-accent px-4 py-2 text-sm font-semibold text-abyss disabled:opacity-60" data-testid="memory-save-host-assignment">
            {hostAssignmentMutation.isPending ? "Saving..." : hostAssignmentMode === "create" ? "Create new host" : hostAssignmentId ? "Change host" : "Mark unassigned"}
          </button>
        </div>
        {hostAssignmentMutation.error instanceof Error ? <p className="mt-2 text-xs text-danger">{hostAssignmentMutation.error.message}</p> : null}
      </section>

      {linuxMemoryHint ? (
        <section className="rounded-[28px] border border-mint/30 bg-emerald-500/10 p-5 shadow-panel" data-testid="memory-linux-notice">
          <div className="flex items-start gap-3">
            <span className="mt-0.5 font-mono text-xs uppercase tracking-[0.18em] text-emerald-400">Linux</span>
            <div>
              <h3 className="text-lg font-semibold text-ink">Linux memory accepted</h3>
              <p className="mt-2 max-w-3xl text-sm text-muted">
                Advanced memory analysis is not available in this release. The image is
                preserved and can be assigned to a host for investigation. Use the
                Evidence Detail page to verify integrity and host assignment.
              </p>
              <p className="mt-2 text-sm text-muted">
                Findings can still be created from this evidence for documentation and
                tracking purposes.
              </p>
            </div>
          </div>
        </section>
      ) : null}

      <MemoryEvidenceHeader
        caseId={caseId}
        evidence={evidence}
        activeResult={activeResultQuery.data ?? null}
        family={family}
        historicalRunId={historicalRunId}
        onViewHistory={() => setHistoryOpen(true)}
        onReturnToLatest={handleReturnToLatest}
        catalogue={catalogueQuery.data ?? null}
        onOpenCatalogue={() => {
          const ds = evidence.detection_status || "";
          if (ds === "probable_disk" || (ds === "ambiguous_raw" && !evidence.operator_override)) {
            setConfirmationOpen(true);
            return;
          }
          setCatalogueOpen(true);
        }}
        onAnalyzeMemory={() => {
          if (submittingRef.current) return;
          if (!window.confirm(
            "I am authorized and responsible for analyzing this memory evidence. " +
            "I confirm this is a legitimate memory capture from an authorized source."
          )) return;
          submittingRef.current = true;
          startScanMutation.mutate();
        }}
        isAnalyzing={startScanMutation.isPending}
        symbolReadiness={symbolReadiness}
        symbolPreparation={symbolPreparation}
      />

      {confirmationToast ? (
        <div
          className="rounded-xl border border-mint/30 bg-mint/10 p-3 text-xs text-ink"
          data-testid="memory-confirmation-toast"
          role="status"
        >
          {confirmationToast}
        </div>
      ) : null}

      {evidence && symbolReadiness ? (
        <MemorySymbolResolutionPanel
          caseId={caseId}
          evidenceId={evidenceId}
          readiness={symbolReadiness}
        />
      ) : null}

      {evidence && symbolPreparation ? (
        <MemoryPreparationCard
          caseId={caseId}
          evidenceId={evidenceId}
          preparation={symbolPreparation}
          nativeProbeStatus={nativeProbeQuery.data ?? null}
        />
      ) : null}

      {evidence && evidencePreparation ? (
        <ZeroResultWarningBanner
          warningCode={evidencePreparation.zero_result_warning_code}
          warningMessage={evidencePreparation.zero_result_warning_message}
          pluginName={evidencePreparation.zero_result_warning_plugin}
          onOpenCompanionSection={() =>
            document.getElementById("vmware-companion-section")?.scrollIntoView({ behavior: "smooth", block: "center" })
          }
        />
      ) : null}

      {evidence && evidencePreparation ? (
        <VmwareCompanionSection
          caseId={caseId}
          evidenceId={evidenceId}
          hasCompanion={evidencePreparation.has_vmware_companion}
          companionId={evidencePreparation.vmware_companion_id}
          companionType={evidencePreparation.vmware_companion_type}
          companionFilename={evidencePreparation.vmware_companion_filename}
          companionSha256={evidencePreparation.vmware_companion_sha256}
          companionSizeBytes={evidencePreparation.vmware_companion_size_bytes}
          recommended={evidencePreparation.vmware_companion_recommended}
          warningText={evidencePreparation.vmware_companion_warning}
          onChanged={() => void queryClient.invalidateQueries({ queryKey: evidencePreparationQueryKey })}
        />
      ) : null}

      {showExperimentalPanel ? (
        <MemoryExperimentalResultsPanel caseId={caseId} evidenceId={evidenceId} />
      ) : null}

      {activeBatch ? (
        <section
          className="rounded-[28px] border border-line bg-panel/60 p-4 shadow-panel"
          data-testid="memory-batch-progress"
        >
          <p className="font-mono text-[10px] uppercase tracking-[0.24em] text-accent">
            Running all supported profiles
          </p>
          <p className="mt-1 text-sm" data-testid="memory-batch-progress-summary">
            {activeBatch.completed_profiles.length} of {activeBatch.requested_profiles.length} completed
            {activeBatch.current_profile ? <> · Current: <span className="font-mono">{activeBatch.current_profile}</span></> : null}
          </p>
          <div className="mt-2 flex flex-wrap gap-2">
            <Link
              to={memoryViewPath(evidenceId, "runs")}
              className="rounded-xl border border-line bg-abyss/70 px-3 py-1.5 text-xs text-muted"
              data-testid="memory-batch-progress-view"
            >
              View progress
            </Link>
            {activeBatch.cancellation_requested === false && (activeBatch.status === "queued" || activeBatch.status === "running") ? (
              <button
                type="button"
                onClick={() => cancelBatchMutation.mutate()}
                disabled={cancelBatchMutation.isPending}
                className="rounded-xl border border-line bg-abyss/70 px-3 py-1.5 text-xs text-muted disabled:opacity-50"
                data-testid="memory-batch-cancel"
              >
                {cancelBatchMutation.isPending ? "Cancelling…" : "Cancel remaining profiles"}
              </button>
            ) : null}
          </div>
        </section>
      ) : null}

      <MemoryWorkspace
        key={evidenceId}
        caseId={caseId}
        evidenceId={evidenceId}
        activeTab={tab}
        onTabChange={(nextTab) => navigate(memoryViewPath(evidenceId, nextTab))}
      />

      {catalogueOpen && catalogueQuery.data && evidence ? (
        <MemoryAnalysisCatalogueModal
          caseId={caseId}
          evidenceId={evidenceId}
          evidenceFilename={evidence.filename}
          evidenceHost={evidence.detected_host}
          evidenceSizeBytes={evidence.size_bytes}
          catalogue={catalogueQuery.data}
          volatilityBackend={volatilityBackend}
          canRun={canRun}
          onClose={() => setCatalogueOpen(false)}
        />
      ) : null}

      {historyOpen ? (
        <MemoryHistoryPanel
          caseId={caseId}
          evidenceId={evidenceId}
          family={family}
          onClose={() => setHistoryOpen(false)}
          onSelectRun={(runId) => {
            setSearchParams((current) => {
              const params = new URLSearchParams(current);
              params.set("run_id", runId);
              return params;
            }, { replace: true });
            setHistoryOpen(false);
          }}
          onReturnToLatest={handleReturnToLatest}
          selectedRunId={historicalRunId}
        />
      ) : null}

      <MemoryTypeConfirmationModal
        open={confirmationOpen && Boolean(evidence)}
        filename={evidence?.filename || ""}
        evidenceId={evidence?.evidence_id || ""}
        sizeBytes={evidence?.size_bytes || 0}
        host={evidence?.detected_host}
        detectionStatus={evidence?.detection_status || ""}
        detectionReason={evidence?.detection_reason}
        detectedFormat={evidence?.detected_format}
        detectionConfidence={evidence?.detection_confidence}
        busy={confirmMemoryTypeMutation.isPending}
        errorMessage={confirmationError}
        onCancel={() => {
          setConfirmationOpen(false);
          setConfirmationError(null);
        }}
        onConfirm={async (reason) => {
          setConfirmationError(null);
          await confirmMemoryTypeMutation.mutateAsync(reason);
        }}
      />
    </div>
  );
}

export type { MemoryTab };
export { MEMORY_TABS };
