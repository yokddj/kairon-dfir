import { useMemo, useRef } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { useNavigate } from "react-router-dom";
import { api, type MemoryEvidencePreparation, type MemoryScanRun } from "../../api/client";
import { memoryQueryKeys } from "../../lib/memoryQueryKeys";
import { memoryEvidenceRoute } from "../../lib/canonicalRoutes";

// Golden-path "initial analysis" action (Memory Preparation Phase 3A).
// Reuses the EXACT same choke point as MemoryEvidencePage.tsx's Run
// Analysis flow -- same endpoint (api.startMemoryScan -> POST
// /evidences/{id}/memory/scan), same resume/polling query
// (api.listMemoryRuns via memoryQueryKeys.runs, same 3000ms interval and
// active-status set as MemoryEvidencePage.tsx). No new endpoint, model,
// profile, or polling protocol. The profile is always "processes_basic"
// -- never "metadata_only" (unconditionally ineligible for Linux
// evidence, see app.services.memory.capability_registry) and never
// "network_basic" (its only Linux plugin, linux.sockstat, hit the
// configured timeout on real evidence).
//
// Deliberately does not fetch or own Memory Preparation itself -- it
// reads the same ["memory-evidence-preparation", caseId, evidenceId]
// query key that MemoryEvidencePreparationCard.tsx already populates, so
// mounting both together (as EvidenceIngestionWizard step 6 does) never
// disagrees and never double-fetches. Gates on preparation.readiness
// (PreparationState from the wizard-facing preparation snapshot), never
// on app.services.memory.analysis_plan's ReadinessState -- those are two
// distinct enums that happen to share some member names. This is NOT a
// third Memory Preparation implementation: it owns no readiness logic of
// its own, only the start/resume/poll mechanics for one fixed profile.

export const INITIAL_ANALYSIS_PROFILE = "processes_basic";
const ACTIVE_RUN_STATUSES = new Set(["pending", "queued", "running"]);

type Tone = "good" | "warn" | "bad";

const TONE_TEXT: Record<Tone, string> = {
  good: "text-mint",
  warn: "text-amber",
  bad: "text-danger",
};

const TERMINAL_COPY: Record<string, { title: string; tone: Tone; retry: boolean }> = {
  completed: { title: "Initial analysis completed", tone: "good", retry: false },
  completed_with_errors: { title: "Initial analysis completed with warnings", tone: "warn", retry: false },
  failed: { title: "Initial analysis failed", tone: "bad", retry: true },
  timed_out: { title: "Initial analysis timed out", tone: "bad", retry: true },
  cancelled: { title: "Initial analysis was cancelled", tone: "warn", retry: true },
  invalid_evidence: { title: "Initial analysis failed", tone: "bad", retry: true },
  backend_unavailable: { title: "Initial analysis failed", tone: "bad", retry: true },
};

export type MemoryInitialAnalysisActionProps = {
  caseId: string;
  evidenceId: string;
  // Called immediately before navigating to View memory results, so a
  // host component (EvidenceIngestionWizard) can close/reset itself
  // first -- mirrors handleContinueFromPreparation's own handleClose()
  // + navigate() sequencing, just decomposed so this component still
  // owns the route construction and the navigate() call itself.
  onBeforeNavigateToResults?: () => void;
};

export function MemoryInitialAnalysisAction({ caseId, evidenceId, onBeforeNavigateToResults }: MemoryInitialAnalysisActionProps) {
  const queryClient = useQueryClient();
  const navigate = useNavigate();
  const submittingRef = useRef(false);

  const preparationQuery = useQuery({
    queryKey: ["memory-evidence-preparation", caseId, evidenceId],
    queryFn: () => api.getMemoryEvidencePreparation(caseId, evidenceId),
    enabled: Boolean(caseId && evidenceId),
    refetchOnWindowFocus: false,
  });

  const runsQuery = useQuery({
    queryKey: memoryQueryKeys.runs(caseId, evidenceId),
    queryFn: () => api.listMemoryRuns(caseId, evidenceId),
    enabled: Boolean(caseId && evidenceId),
    refetchOnWindowFocus: false,
    refetchInterval: (query) => {
      const runs = (query.state.data ?? []) as MemoryScanRun[];
      const initial = runs.find((run) => run.profile === INITIAL_ANALYSIS_PROFILE);
      return initial && ACTIVE_RUN_STATUSES.has(initial.status) ? 3000 : false;
    },
  });

  const initialRun = useMemo<MemoryScanRun | null>(() => {
    const runs = runsQuery.data ?? [];
    return runs.find((run) => run.profile === INITIAL_ANALYSIS_PROFILE) ?? null;
  }, [runsQuery.data]);

  const startMutation = useMutation({
    mutationFn: () => api.startMemoryScan(caseId, evidenceId, INITIAL_ANALYSIS_PROFILE),
    onSuccess: () => {
      const keys = memoryQueryKeys.invalidateAfterMutation(caseId, evidenceId);
      for (const key of keys) void queryClient.invalidateQueries({ queryKey: key });
      void queryClient.invalidateQueries({ queryKey: memoryQueryKeys.runs(caseId, evidenceId) });
    },
    onError: () => {
      // start_memory_scan can leave a real, terminal MemoryScanRun row
      // behind even when the HTTP response itself is an error (e.g. an
      // enqueue failure marks the run "failed" before the 500 is
      // raised) -- refetch so that row surfaces instead of silently
      // re-showing Start with no explanation.
      void queryClient.invalidateQueries({ queryKey: memoryQueryKeys.runs(caseId, evidenceId) });
    },
    onSettled: () => {
      submittingRef.current = false;
    },
  });

  function handleStart() {
    if (submittingRef.current || startMutation.isPending) return;
    submittingRef.current = true;
    startMutation.mutate();
  }

  function handleViewResults() {
    onBeforeNavigateToResults?.();
    navigate(memoryEvidenceRoute(caseId, evidenceId));
  }

  // Still resolving preparation/run state -- render nothing rather than
  // risk a flash of "Start memory analysis" for evidence that already
  // has an active or completed run (see the reanudación requirement).
  if (preparationQuery.isLoading || runsQuery.isLoading) {
    return null;
  }

  if (initialRun) {
    if (ACTIVE_RUN_STATUSES.has(initialRun.status)) {
      if (initialRun.status === "running") {
        const hasPluginCount = initialRun.plugin_count > 0;
        return (
          <div className="mt-5 rounded-2xl border border-line bg-abyss/60 p-4" data-testid="memory-initial-analysis-running">
            <p className="text-sm font-semibold text-ink">Analysis running</p>
            {hasPluginCount ? (
              <p className="mt-1 text-xs text-muted" data-testid="memory-initial-analysis-progress">
                {initialRun.plugins_completed} / {initialRun.plugin_count} plugins completed
              </p>
            ) : (
              <div className="mt-2 h-1.5 w-full overflow-hidden rounded-full bg-abyss/60" data-testid="memory-initial-analysis-indeterminate">
                <div className="h-full w-1/3 animate-pulse rounded-full bg-accent/70" />
              </div>
            )}
          </div>
        );
      }
      return (
        <div className="mt-5 rounded-2xl border border-line bg-abyss/60 p-4" data-testid="memory-initial-analysis-starting">
          <p className="text-sm font-semibold text-ink">Starting analysis...</p>
        </div>
      );
    }

    const copy = TERMINAL_COPY[initialRun.status] ?? { title: `Initial analysis ${initialRun.status.replace(/_/g, " ")}`, tone: "bad" as Tone, retry: true };
    const isSuccess = initialRun.status === "completed" || initialRun.status === "completed_with_errors";
    const testId = `memory-initial-analysis-${initialRun.status.replace(/_/g, "-")}`;

    return (
      <div className="mt-5 rounded-2xl border border-line bg-abyss/60 p-4" data-testid={testId}>
        <p className={`text-sm font-semibold ${TONE_TEXT[copy.tone]}`}>
          {isSuccess ? "✓ " : ""}
          {copy.title}
        </p>
        <div className="mt-3 flex flex-wrap gap-2">
          {isSuccess ? (
            <button
              type="button"
              onClick={handleViewResults}
              className="rounded-2xl bg-accent px-4 py-2 text-sm font-semibold text-abyss"
              data-testid="memory-initial-analysis-view-results-button"
            >
              View memory results
            </button>
          ) : null}
          {copy.retry ? (
            <button
              type="button"
              onClick={handleStart}
              disabled={startMutation.isPending}
              className="rounded-2xl border border-line bg-abyss/70 px-4 py-2 text-sm text-ink disabled:opacity-60"
              data-testid="memory-initial-analysis-retry-button"
            >
              Retry
            </button>
          ) : null}
        </div>
      </div>
    );
  }

  const preparation: MemoryEvidencePreparation | undefined = preparationQuery.data;
  if (!preparation || preparation.readiness !== "ready" || !preparation.can_start_analysis) {
    return null;
  }

  return (
    <div className="mt-5" data-testid="memory-initial-analysis-action">
      <button
        type="button"
        onClick={handleStart}
        disabled={startMutation.isPending}
        className="rounded-2xl bg-accent px-4 py-2 text-sm font-semibold text-abyss disabled:opacity-60"
        data-testid="memory-initial-analysis-start-button"
      >
        Start memory analysis
      </button>
      <p className="mt-2 text-xs text-muted">
        Kairon will run the initial memory analysis. You can run additional analysis profiles later from the memory workspace.
      </p>
      {startMutation.isError ? (
        <p className="mt-2 text-xs text-danger" data-testid="memory-initial-analysis-start-error">
          Could not start the initial analysis. Please try again.
        </p>
      ) : null}
    </div>
  );
}
