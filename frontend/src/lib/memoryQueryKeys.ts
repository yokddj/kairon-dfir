/**
 * Canonical query keys for memory analysis React Query caches.
 * All invalidation must target exact active queries.
 */
export const memoryQueryKeys = {
  overview: (caseId: string) => ["memory-overview", caseId] as const,
  landing: (caseId: string) => ["memory-landing", caseId] as const,
  landingEvidence: (caseId: string) => ["memory-evidence-landing", caseId] as const,
  backend: () => ["memory-backends"] as const,
  catalogue: (caseId: string, evidenceId: string) => ["memory-catalogue", caseId, evidenceId] as const,
  activeResult: (caseId: string, evidenceId: string, family: string, historicalRunId: string | null) =>
    ["memory-active-result", caseId, evidenceId, family, historicalRunId] as const,
  activeBatch: (caseId: string, evidenceId: string) => ["memory-active-batch", caseId, evidenceId] as const,
  runs: (caseId: string, evidenceId: string) => ["memory-runs-tab", caseId, evidenceId] as const,
  evidenceReadiness: (caseId: string, evidenceId: string) => ["memory-evidence-readiness", caseId, evidenceId] as const,
  symbolReadiness: (caseId: string, evidenceId: string) => ["memory-symbol-readiness", caseId, evidenceId] as const,
  symbolPreparation: (caseId: string, evidenceId: string) => ["memory-symbol-preparation", caseId, evidenceId] as const,
  nativeProbe: (caseId: string, evidenceId: string) => ["native-probe", caseId, evidenceId] as const,
  symbolCache: () => ["memory-symbol-cache"] as const,
  runOptions: (caseId: string, evidenceId: string) => ["memory-run-options", caseId, evidenceId] as const,
  historyRuns: (caseId: string, evidenceId: string, family: string) => ["memory-history-runs", caseId, evidenceId, family] as const,
  runAllPlan: (caseId: string, evidenceId: string, mode: string) => ["memory-run-all-plan", caseId, evidenceId, mode] as const,
  artifactOverview: (caseId: string, evidenceId: string) => ["memory-artifact-overview", caseId, evidenceId] as const,
  systemInfo: (caseId: string, evidenceId: string) => ["memory-system-info", caseId, evidenceId] as const,
  canonicalSummary: (caseId: string, evidenceId: string, runId: string | null) =>
    ["canonical-summary", caseId, evidenceId, runId] as const,
  /** Keys that should be invalidated after any memory analysis mutation on an evidence. */
  invalidateAfterMutation: (caseId: string, evidenceId: string) => [
    ["memory-overview", caseId],
    ["memory-landing", caseId],
    ["memory-evidence-landing", caseId],
    ["memory-catalogue", caseId, evidenceId],
    ["memory-runs-tab", caseId, evidenceId],
    ["memory-active-batch", caseId, evidenceId],
    ["memory-run-options", caseId, evidenceId],
  ] as const,
};
