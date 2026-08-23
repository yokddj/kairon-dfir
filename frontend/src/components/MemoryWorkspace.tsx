import { useCallback, useEffect, useMemo, useState } from "react";
import { useQueries, useQuery } from "@tanstack/react-query";
import { Link, useSearchParams } from "react-router-dom";
import {
  type MemoryBackendStatus,
  type MemoryOverview,
  api,
} from "../api/client";
import { useActiveCase } from "../context/ActiveCaseContext";
import { MEMORY_TABS, useMemoryTab, type MemoryTab } from "../lib/memoryWorkspaceState";
import { MemoryOverviewTab } from "./memory/MemoryOverviewTab";
import { MemoryProcessesTab } from "./memory/MemoryProcessesTab";
import { MemoryShellHistoryTab } from "./memory/MemoryShellHistoryTab";
import { MemoryGraphTab } from "./memory/MemoryGraphTab";
import { MemoryArtifactsTab } from "./memory/MemoryArtifactsTab";
import { MemorySystemTab } from "./memory/MemorySystemTab";
import { MemoryRunsTab } from "./memory/MemoryRunsTab";
import { MemoryRawTab } from "./memory/MemoryRawTab";
import { MemoryAnalyzeAction } from "./memory/MemoryAnalyzeAction";
import CreateFindingDialog from "./CreateFindingDialog";
import { buildFindingPrefillFromArtifact, type FindingPrefill } from "../lib/findingPrefill";

type RunProfile = "processes_basic" | "processes_extended" | "metadata_only";

type MemoryWorkspaceProps = {
  caseId: string;
  evidenceId?: string;
  activeTab?: MemoryTab;
  onTabChange?: (next: MemoryTab) => void;
};

function backendBadge(status: MemoryBackendStatus): string {
  if (status.ready) return "Ready";
  if (status.execution_mode === "dedicated_worker" && !status.dedicated_worker_online) return "Memory worker offline";
  switch (status.status) {
    case "disabled":
      return "Disabled";
    case "not_configured":
      return "Not configured";
    case "blocked":
      return status.available ? "Installed but blocked" : "Blocked";
    case "not_found":
      return "Not found";
    case "available":
      return "Available";
    case "check_failed":
      return "Check failed";
    default:
      return status.status;
  }
}

function modeLabel(mode: MemoryOverview["mode"]): string {
  switch (mode) {
    case "disk_only":
      return "Disk only";
    case "memory_only":
      return "Memory only";
    case "hybrid":
      return "Disk and memory";
    default:
      return "Empty case";
  }
}

export function MemoryWorkspace({ caseId, evidenceId: evidenceIdProp, activeTab, onTabChange: onTabChangeProp }: MemoryWorkspaceProps) {
  const { setActiveCaseId, caseContext } = useActiveCase();
  const [searchParams] = useSearchParams();
  const [urlTab, setUrlTab] = useMemoryTab();
  const tab = activeTab ?? urlTab;
  const [selectedRunId, setSelectedRunId] = useState<string | null>(null);
  const [profile, setProfile] = useState<RunProfile | null>(null);
  const [search, setSearch] = useState("");
  const [processName, setProcessName] = useState("");
  const [pidFilter, setPidFilter] = useState("");
  const [selectedEntityId, setSelectedEntityId] = useState<string | null>(null);
  const [processMode, setProcessMode] = useState<"auto" | "basic" | "extended">("auto");
  const [findingPrefill, setFindingPrefill] = useState<FindingPrefill | null>(null);

  useEffect(() => {
    setActiveCaseId(caseId);
  }, [caseId, setActiveCaseId]);

  useEffect(() => {
    setSelectedRunId(null);
    setProfile(null);
    setSearch("");
    setSelectedEntityId(searchParams.get("process_entity_id"));
    setPidFilter(searchParams.get("pid") || "");
  }, [evidenceIdProp, searchParams]);

  useEffect(() => {
    const entityId = searchParams.get("process_entity_id");
    const pid = searchParams.get("pid") || "";
    if (entityId) setSelectedEntityId(entityId);
    if (pid) setPidFilter(pid);
  }, [searchParams]);

  const overviewQuery = useQuery({
    queryKey: ["memory-overview", caseId],
    queryFn: () => api.getMemoryOverview(caseId),
    enabled: Boolean(caseId),
    refetchOnWindowFocus: false,
    refetchInterval: (query) => {
      const runs = query.state.data?.runs ?? [];
      return runs.some((run) => ["pending", "queued", "running"].includes(run.status)) ? 3000 : false;
    },
  });

  const backendQuery = useQuery({
    queryKey: ["memory-backends"],
    queryFn: () => api.getMemoryBackendOverview(),
    refetchOnWindowFocus: false,
  });

  const symbolCacheQuery = useQuery({
    queryKey: ["memory-symbol-cache"],
    queryFn: () => api.getMemorySymbolCacheStatus(),
    refetchOnWindowFocus: false,
  });

  const overview = overviewQuery.data;

  const landingQuery = useQuery({
    queryKey: ["memory-evidence-landing", caseId],
    queryFn: () => api.getMemoryEvidenceLanding(caseId),
    enabled: Boolean(caseId && tab === "runs"),
    refetchOnWindowFocus: false,
  });

  const runsQuery = useQuery({
    queryKey: ["memory-runs-tab", caseId, evidenceIdProp ?? "case"],
    queryFn: () => api.listMemoryRuns(caseId, evidenceIdProp || undefined),
    enabled: Boolean(caseId && tab === "runs"),
    refetchOnWindowFocus: false,
    refetchInterval: (query) => {
      const runs = query.state.data ?? [];
      return runs.some((run) => ["pending", "queued", "running"].includes(run.status)) ? 3000 : false;
    },
  });

  const effectiveEvidenceId =
    evidenceIdProp || (overview?.evidences?.length === 1 ? overview?.evidences?.[0]?.id : undefined);

  const runOptionsQuery = useQuery({
    queryKey: ["memory-run-options", caseId, effectiveEvidenceId ?? ""],
    queryFn: () =>
      effectiveEvidenceId
        ? api.getEvidenceMemoryRunOptions(caseId, effectiveEvidenceId)
        : api.getMemoryRunOptions(caseId),
    enabled: Boolean(caseId),
    refetchOnWindowFocus: false,
  });

  const summaryQuery = useQuery({
    queryKey: ["canonical-summary", caseId, effectiveEvidenceId ?? "", selectedRunId ?? runOptionsQuery.data?.default_run_id ?? null],
    queryFn: () =>
      api.getCanonicalProcessSummary(caseId, {
        run_id: selectedRunId || runOptionsQuery.data?.default_run_id || undefined,
      }),
    enabled: Boolean(caseId && (selectedRunId || runOptionsQuery.data?.default_run_id)),
    refetchOnWindowFocus: false,
  });

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

  const volatilityBackend = backendQuery.data?.backends.find((b) => b.backend === "volatility3");
  const canRunMetadata = Boolean(overview?.memory_analysis_enabled && volatilityBackend?.ready);
  const canRunProcessProfiles = Boolean(canRunMetadata && overview?.memory_process_profile_enabled);

  const effectiveRunId = selectedRunId || runOptionsQuery.data?.default_run_id || null;

  // Process context query for automatic federation mode
  const processContextQuery = useQuery({
    queryKey: ["memory-process-context", caseId, effectiveEvidenceId ?? ""],
    queryFn: () => api.getProcessContext(caseId, effectiveEvidenceId as string),
    enabled: Boolean(caseId && effectiveEvidenceId),
    refetchOnWindowFocus: false,
  });
  const processContext = processContextQuery.data as any;
  const federatedBasicRunId = processContext?.context?.basic_run_id || null;
  const federatedExtendedRunId = processContext?.context?.extended_run_id || null;

  // Effective process run based on mode
  const processEffectiveRunId =
    processMode === "auto" ? (federatedBasicRunId || effectiveRunId) :
    processMode === "basic" ? federatedBasicRunId || effectiveRunId :
    processMode === "extended" ? federatedExtendedRunId || effectiveRunId :
    effectiveRunId;

  const onTabChange = useCallback(
    (next: MemoryTab) => {
      if (onTabChangeProp) onTabChangeProp(next);
      else setUrlTab(next);
    },
    [onTabChangeProp, setUrlTab],
  );

  const tabsAriaProps = useMemo(
    () => ({
      role: "tablist" as const,
      "aria-label": "Memory analysis sections",
    }),
    [],
  );

  return (
    <div className="space-y-6" data-testid="memory-workspace">
      <section className="rounded-[28px] border border-line bg-panel/70 p-6 shadow-panel">
        <p className="font-mono text-xs uppercase tracking-[0.24em] text-accent">Memory Analysis</p>
        <div className="mt-2 flex flex-wrap items-start justify-between gap-4">
          <div>
            <h2 className="text-3xl font-semibold">Authorized RAM evidence</h2>
            <p className="mt-2 max-w-3xl text-sm text-muted">
              Isolated analysis for authorized memory evidence. Process results remain only in Memory Analysis and never enter global disk views.
            </p>
          </div>
          <div className="flex flex-wrap gap-2">
            <Link to={`/cases/${caseId}/evidence?add_evidence=1&expected_kind=memory_dump`} className="rounded-xl bg-accent px-3 py-2 text-xs font-semibold text-abyss">
              Add memory image
            </Link>
            <Link to={`/cases/${caseId}/evidence`} className="rounded-xl border border-line bg-abyss/70 px-3 py-2 text-xs text-muted">
              Evidence &amp; Ingest
            </Link>
          </div>
        </div>
        {overview ? (
          <p className="mt-3 text-xs text-muted">
            Mode: <span className="text-ink">{modeLabel(overview.mode)}</span> · {overview.evidences.length} memory evidence · {overview.runs.length} runs
          </p>
        ) : null}
      </section>

      {overviewQuery.isLoading ? (
        <section className="rounded-2xl border border-line bg-panel/60 p-5 text-sm text-muted">Loading memory overview...</section>
      ) : null}
      {overviewQuery.error instanceof Error ? (
        <section className="rounded-2xl border border-rose-400/30 bg-rose-500/10 p-5 text-sm text-rose-100">{overviewQuery.error.message}</section>
      ) : null}

      <nav
        {...tabsAriaProps}
        className="flex flex-wrap gap-2 rounded-[28px] border border-line bg-panel/60 p-3 shadow-panel"
        data-testid="memory-subview-tabs"
      >
        {MEMORY_TABS.map((item) => (
          <button
            key={item.key}
            type="button"
            id={`memory-tab-${item.key}`}
            role="tab"
            aria-selected={tab === item.key}
            aria-controls={`memory-tabpanel-${item.key}`}
            data-testid={item.testId}
            onClick={() => onTabChange(item.key)}
            className={
              "rounded-xl px-3 py-2 text-xs transition " +
              (tab === item.key
                ? "bg-accent text-abyss"
                : "border border-line bg-abyss/70 text-muted hover:text-ink")
            }
          >
            {item.label}
          </button>
        ))}
      </nav>

      <div role="tabpanel"
        id={`memory-tabpanel-${tab}`}
        aria-labelledby={`memory-tab-${tab}`}
        data-testid={`memory-tabpanel-${tab}`}
        className="space-y-6"
      >
        {tab === "overview" ? (
          <MemoryOverviewTab
            caseId={caseId}
            evidenceId={effectiveEvidenceId ?? ""}
            overview={overview ?? null}
            backend={volatilityBackend ?? null}
            symbolCache={symbolCacheQuery.data ?? null}
            readinessByEvidence={readinessByEvidence}
            onJumpToTab={onTabChange}
          />
        ) : null}

        {tab === "processes" ? (
          <MemoryProcessesTab
            caseId={caseId}
            evidenceId={effectiveEvidenceId}
            runId={processEffectiveRunId}
            runOptions={runOptionsQuery.data ?? null}
            selectedRunId={selectedRunId}
            onSelectRunId={setSelectedRunId}
            profile={profile}
            onSelectProfile={setProfile}
            search={search}
            onSearch={setSearch}
            processName={processName}
            onProcessName={setProcessName}
            pidFilter={pidFilter}
            onPidFilter={setPidFilter}
            selectedEntityId={selectedEntityId}
            onSelectEntityId={setSelectedEntityId}
            onCreateFinding={(entity) => setFindingPrefill(buildFindingPrefillFromArtifact({ ...entity, ...entity.process, plugin: (entity.sources || []).join(", ") }, { caseId, evidenceId: effectiveEvidenceId, hosts: caseContext?.hosts ?? [], sourceView: "memory", sourceRoute: window.location.pathname + window.location.search, artifactFamily: "memory", artifactType: "process", label: "Memory process" }))}
          />
        ) : null}

        {tab === "shell_history" ? (
          <MemoryShellHistoryTab
            caseId={caseId}
            evidenceId={effectiveEvidenceId}
            runOptions={runOptionsQuery.data ?? null}
            selectedRunId={selectedRunId}
            onSelectRunId={setSelectedRunId}
          />
        ) : null}

        {tab === "graph" ? (
          <MemoryGraphTab
            caseId={caseId}
            runId={processEffectiveRunId}
            runOptions={runOptionsQuery.data ?? null}
            selectedRunId={selectedRunId}
            onSelectRunId={setSelectedRunId}
            selectedEntityId={selectedEntityId}
            onSelectEntityId={setSelectedEntityId}
            onOpenProcessDetails={(entityId) => {
              setSelectedEntityId(entityId);
              onTabChange("processes");
            }}
          />
        ) : null}

        {tab === "network" ? (
          <MemoryArtifactsTab
            caseId={caseId}
            runOptions={runOptionsQuery.data ?? null}
            selectedRunId={selectedRunId}
            onSelectRunId={setSelectedRunId}
            onSelectEntity={(entityId) => { setSelectedEntityId(entityId); }}
            onJumpToProcesses={(entityId) => { setSelectedEntityId(entityId); onTabChange("processes"); }}
            onJumpToGraph={(entityId) => { setSelectedEntityId(entityId); onTabChange("graph"); }}
            onJumpToTree={(entityId) => { setSelectedEntityId(entityId); onTabChange("graph"); }}
            evidenceId={effectiveEvidenceId}
            initialSubView="network"
          />
        ) : null}
        {tab === "modules" ? (
          <MemoryArtifactsTab
            caseId={caseId}
            runOptions={runOptionsQuery.data ?? null}
            selectedRunId={selectedRunId}
            onSelectRunId={setSelectedRunId}
            onSelectEntity={(entityId) => { setSelectedEntityId(entityId); }}
            onJumpToProcesses={(entityId) => { setSelectedEntityId(entityId); onTabChange("processes"); }}
            onJumpToGraph={(entityId) => { setSelectedEntityId(entityId); onTabChange("graph"); }}
            onJumpToTree={(entityId) => { setSelectedEntityId(entityId); onTabChange("graph"); }}
            evidenceId={effectiveEvidenceId}
            initialSubView="modules"
          />
        ) : null}
        {tab === "handles" ? (
          <MemoryArtifactsTab
            caseId={caseId}
            runOptions={runOptionsQuery.data ?? null}
            selectedRunId={selectedRunId}
            onSelectRunId={setSelectedRunId}
            onSelectEntity={(entityId) => { setSelectedEntityId(entityId); }}
            onJumpToProcesses={(entityId) => { setSelectedEntityId(entityId); onTabChange("processes"); }}
            onJumpToGraph={(entityId) => { setSelectedEntityId(entityId); onTabChange("graph"); }}
            onJumpToTree={(entityId) => { setSelectedEntityId(entityId); onTabChange("graph"); }}
            evidenceId={effectiveEvidenceId}
            initialSubView="handles"
          />
        ) : null}
        {tab === "suspicious" ? (
          <MemoryArtifactsTab
            caseId={caseId}
            runOptions={runOptionsQuery.data ?? null}
            selectedRunId={selectedRunId}
            onSelectRunId={setSelectedRunId}
            onSelectEntity={(entityId) => { setSelectedEntityId(entityId); }}
            onJumpToProcesses={(entityId) => { setSelectedEntityId(entityId); onTabChange("processes"); }}
            onJumpToGraph={(entityId) => { setSelectedEntityId(entityId); onTabChange("graph"); }}
            onJumpToTree={(entityId) => { setSelectedEntityId(entityId); onTabChange("graph"); }}
            evidenceId={effectiveEvidenceId}
            initialSubView="suspicious"
          />
        ) : null}
        {tab === "vads" ? (
          <MemoryArtifactsTab
            caseId={caseId}
            runOptions={runOptionsQuery.data ?? null}
            selectedRunId={selectedRunId}
            onSelectRunId={setSelectedRunId}
            onSelectEntity={(entityId) => { setSelectedEntityId(entityId); }}
            onJumpToProcesses={(entityId) => { setSelectedEntityId(entityId); onTabChange("processes"); }}
            onJumpToGraph={(entityId) => { setSelectedEntityId(entityId); onTabChange("graph"); }}
            onJumpToTree={(entityId) => { setSelectedEntityId(entityId); onTabChange("graph"); }}
            evidenceId={effectiveEvidenceId}
            initialSubView="vads"
          />
        ) : null}

        {tab === "artifacts" ? (
          <MemoryArtifactsTab
            caseId={caseId}
            runOptions={runOptionsQuery.data ?? null}
            selectedRunId={selectedRunId}
            onSelectRunId={setSelectedRunId}
            onSelectEntity={(entityId) => { setSelectedEntityId(entityId); }}
            onJumpToProcesses={(entityId) => { setSelectedEntityId(entityId); onTabChange("processes"); }}
            onJumpToGraph={(entityId) => { setSelectedEntityId(entityId); onTabChange("graph"); }}
            onJumpToTree={(entityId) => { setSelectedEntityId(entityId); onTabChange("graph"); }}
            evidenceId={effectiveEvidenceId}
            initialSubView="network"
          />
        ) : null}

        {tab === "system" ? (
          <MemorySystemTab
            caseId={caseId}
            evidenceId={effectiveEvidenceId}
            runOptions={runOptionsQuery.data ?? null}
            selectedRunId={selectedRunId}
            onSelectRunId={setSelectedRunId}
          />
        ) : null}

        {tab === "runs" && runsQuery.error instanceof Error ? (
          <section className="rounded-2xl border border-rose-400/30 bg-rose-500/10 p-5 text-sm text-rose-100" data-testid="memory-runs-tab-error">
            {runsQuery.error.message}
          </section>
        ) : null}

        {tab === "runs" && !runsQuery.error ? (
          <MemoryRunsTab
            key={evidenceIdProp ?? "case-wide"}
            caseId={caseId}
            evidenceId={evidenceIdProp}
            runs={runsQuery.data ?? []}
            landingItems={landingQuery.data?.items ?? []}
          />
        ) : null}

      {tab === "raw" ? (
          <MemoryRawTab
            caseId={caseId}
            evidenceId={effectiveEvidenceId ?? ""}
            runId={effectiveRunId}
            runOptions={runOptionsQuery.data ?? null}
            selectedRunId={selectedRunId}
            onSelectRunId={setSelectedRunId}
          />
        ) : null}
      </div>

      {tab === "overview" && overview && overview.evidences.length > 0 && !evidenceIdProp ? (
        <MemoryAnalyzeAction
          caseId={caseId}
          overview={overview}
          evidenceId={effectiveEvidenceId}
          readinessByEvidence={readinessByEvidence}
          canRunMetadata={canRunMetadata}
          canRunProcessProfiles={canRunProcessProfiles}
          volatilityBackend={volatilityBackend ?? null}
        />
      ) : null}
      <CreateFindingDialog
        open={Boolean(findingPrefill)}
        onClose={() => setFindingPrefill(null)}
        caseId={caseId}
        prefill={findingPrefill}
        onCreated={() => setFindingPrefill(null)}
      />
    </div>
  );
}

export { backendBadge };
export type { MemoryTab };
