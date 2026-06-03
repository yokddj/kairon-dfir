import { useEffect, useMemo, useState, type ReactNode } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { Link } from "react-router-dom";
import { api, type Rule, type RuleImportResponse, type RuleImportRun, type RuleRun, type RuleRunResult, type RuleSet, type SigmaSmokeResponse } from "../api/client";
import { useActiveCase } from "../context/ActiveCaseContext";

type RulesTab = "sigma" | "yara" | "heuristics" | "runs" | "library";
type SigmaSelectionMode = "all_enabled" | "selected_rules";
type SigmaRunMode = "fast_triage" | "balanced" | "exhaustive";
type YaraSelectionMode = "all_enabled" | "selected_rule" | "selected_pack";
type RunScope = "case" | "host" | "evidence";
type ImportEngine = "sigma" | "yara";
type PendingImportDescriptor = {
  engine: ImportEngine;
  sourceName: string;
  sourceType: "single_file" | "archive";
  startedAt: string;
};
type ImportFailureState = {
  engine: ImportEngine;
  sourceName: string;
  message: string;
};

type QueuedRunSummary = {
  engine: "sigma" | "yara";
  status: string;
  runId: string | null;
  message: string;
};

type LibraryItem =
  | { kind: "rule"; id: string; engine: string; title: string; namespace: string | null; severity: string | null; enabled: boolean; description: string | null; updated_at: string; source_label: string | null; import_run_id: string | null; source_pack: string | null; import_status: string | null; item: Rule }
  | { kind: "pack"; id: string; engine: string; title: string; namespace: string | null; severity: string | null; enabled: boolean; description: string | null; updated_at: string; source_label: string | null; import_run_id: string | null; source_pack: string | null; import_status: string | null; item: RuleSet };

type LibraryConfirmationAction = "delete_selected" | "delete_matching" | "delete_all_imported";
type PendingLibraryConfirmation =
  | {
      action: LibraryConfirmationAction;
      label: string;
      requirePhrase: string | null;
    }
  | null;

const tabLabels: Array<{ id: RulesTab; label: string }> = [
  { id: "sigma", label: "Sigma" },
  { id: "yara", label: "YARA" },
  { id: "heuristics", label: "Heuristics" },
  { id: "runs", label: "Rule Runs" },
  { id: "library", label: "Rule Library" },
];

const RULE_LIBRARY_DELETE_CONFIRMATION = "DELETE GLOBAL RULE LIBRARY";
const RULE_PACKS_DELETE_CONFIRMATION = "DELETE RULE PACKS";
const SIGMA_GLOBAL_PROMOTION_CONFIRMATION = "PROMOTE SIGMA RULES TO GLOBAL";

const archiveExtensions = [".zip", ".7z", ".tar", ".tgz", ".tar.gz", ".tar.bz2", ".tar.xz", ".txz", ".tbz2"];
const ACTIVE_IMPORT_STATUSES = new Set(["queued", "uploading", "extracting", "parsing", "validating", "compiling", "saving"]);
const TERMINAL_IMPORT_STATUSES = new Set(["completed", "completed_with_warnings", "failed", "cancelled"]);
const RULES_ACTIVE_IMPORT_ID_STORAGE_KEY = "dfir.rules.activeImportRunId";
const RULES_PENDING_IMPORT_STORAGE_KEY = "dfir.rules.pendingImport";
const RULES_DISMISSED_IMPORTS_STORAGE_KEY = "dfir.rules.dismissedImportRunIds";
const RULES_HIDE_TERMINAL_IMPORT_BANNER_STORAGE_KEY = "dfir.rules.hideTerminalImportBanner";

function isActiveImportStatus(status: string | null | undefined) {
  return Boolean(status && ACTIVE_IMPORT_STATUSES.has(status));
}

function isTerminalImportStatus(status: string | null | undefined) {
  return Boolean(status && TERMINAL_IMPORT_STATUSES.has(status));
}

function humanizeImportStatus(status: string) {
  switch (status) {
    case "queued":
      return "Queued";
    case "uploading":
      return "Uploading";
    case "extracting":
      return "Extracting archive";
    case "parsing":
      return "Parsing rule files";
    case "validating":
      return "Validating rules";
    case "compiling":
      return "Compiling rules";
    case "saving":
      return "Saving rules";
    case "completed":
      return "Completed";
    case "completed_with_warnings":
      return "Completed with warnings";
    case "cancelled":
      return "Cancelled";
    case "failed":
      return "Failed";
    default:
      return status.replaceAll("_", " ");
  }
}

function importBannerTone(status: string) {
  if (status === "failed") return "border-danger/40 bg-danger/10 text-danger";
  if (status === "cancelled") return "border-line bg-abyss/80 text-muted";
  if (status === "completed_with_warnings") return "border-amber-400/40 bg-amber-400/10 text-amber-100";
  if (status === "completed") return "border-emerald-400/40 bg-emerald-400/10 text-emerald-100";
  return "border-accent/40 bg-accent/10 text-ink";
}

function importProgressPercent(run: RuleImportRun) {
  if (run.total_files > 0) {
    return Math.max(0, Math.min(100, Math.round((run.processed_files / run.total_files) * 100)));
  }
  return null;
}

function readStoredString(key: string) {
  if (typeof window === "undefined") return null;
  const value = window.localStorage.getItem(key);
  return value && value.trim() ? value : null;
}

function readStoredJson<T>(key: string): T | null {
  if (typeof window === "undefined") return null;
  const raw = window.localStorage.getItem(key);
  if (!raw) return null;
  try {
    return JSON.parse(raw) as T;
  } catch {
    return null;
  }
}

function formatImportSummary(result: {
  imported_rules: number;
  imported_rule_sets: number;
  total_yara_rules_inside: number;
  skipped_count: number;
  errors: string[];
  sample_imported: string[];
  detected_engine_counts?: Record<string, number>;
}) {
  const engineBreakdown = Object.entries(result.detected_engine_counts ?? {})
    .map(([name, count]) => `${name}: ${count}`)
    .join(" · ");
  const parts = [
    `Imported single rules: ${result.imported_rules}`,
    `Imported rule packs: ${result.imported_rule_sets}`,
    `Skipped: ${result.skipped_count}`,
  ];
  if (result.total_yara_rules_inside) parts.push(`Rules inside packs: ${result.total_yara_rules_inside}`);
  if (engineBreakdown) parts.push(`Detected engines: ${engineBreakdown}`);
  if (result.sample_imported.length) parts.push(`Sample imported: ${result.sample_imported.slice(0, 5).join(" · ")}`);
  if (result.errors.length) parts.push(`Warnings/errors: ${result.errors.join(" · ")}`);
  return parts.join("\n");
}

function importStatusTone(status: string) {
  return status === "failed" || status === "completed_with_warnings" || status === "cancelled" ? "warning" : "default";
}

function renderImportSummary(result: RuleImportResponse | null, title: string) {
  if (!result) return null;
  return (
    <div className="mt-4 rounded-2xl border border-line bg-abyss/80 p-4">
      <p className="font-mono text-[11px] uppercase tracking-[0.16em] text-accent">{title}</p>
      <p className="mt-2 text-sm text-ink">{result.status.replaceAll("_", " ")}</p>
      <div className="mt-3 grid gap-3 md:grid-cols-2 xl:grid-cols-4">
        <div><p className="text-[11px] uppercase tracking-[0.16em] text-muted">Imported</p><p className="mt-1 text-sm text-ink">{result.imported_count}</p></div>
        <div><p className="text-[11px] uppercase tracking-[0.16em] text-muted">Updated</p><p className="mt-1 text-sm text-ink">{result.updated_count}</p></div>
        <div><p className="text-[11px] uppercase tracking-[0.16em] text-muted">Duplicates</p><p className="mt-1 text-sm text-ink">{result.duplicate_count}</p></div>
        <div><p className="text-[11px] uppercase tracking-[0.16em] text-muted">Invalid</p><p className="mt-1 text-sm text-ink">{result.invalid_count}</p></div>
        <div><p className="text-[11px] uppercase tracking-[0.16em] text-muted">Unsupported</p><p className="mt-1 text-sm text-ink">{result.unsupported_count}</p></div>
        <div><p className="text-[11px] uppercase tracking-[0.16em] text-muted">Compiled</p><p className="mt-1 text-sm text-ink">{result.compiled_count}</p></div>
        <div><p className="text-[11px] uppercase tracking-[0.16em] text-muted">Warnings</p><p className="mt-1 text-sm text-ink">{result.warning_count}</p></div>
        <div><p className="text-[11px] uppercase tracking-[0.16em] text-muted">Errors</p><p className="mt-1 text-sm text-ink">{result.error_count}</p></div>
      </div>
      {result.invalid_items.length ? <p className="mt-3 text-sm text-muted">Invalid items: {result.invalid_items.slice(0, 3).map((item) => String(item.file ?? item.rule ?? "item")).join(" · ")}</p> : null}
      {result.unsupported_items.length ? <p className="mt-2 text-sm text-muted">Unsupported items: {result.unsupported_items.slice(0, 3).map((item) => String(item.rule ?? item.file ?? "item")).join(" · ")}</p> : null}
      {result.warnings.length ? <p className="mt-2 text-sm text-muted">Warnings: {result.warnings.slice(0, 2).join(" · ")}</p> : null}
      {result.errors.length ? <p className="mt-2 text-sm text-warning">Errors: {result.errors.slice(0, 2).join(" · ")}</p> : null}
    </div>
  );
}

function describeImportProgress(run: RuleImportRun) {
  const phase = run.current_phase ? humanizeImportStatus(run.current_phase.replace(/-/g, "_")) : humanizeImportStatus(run.status);
  if (run.total_files > 0 && isActiveImportStatus(run.status)) {
    return `${phase} ${run.processed_files} / ${run.total_files} files`;
  }
  return phase;
}

function importCountsKnown(run: RuleImportRun | null | undefined) {
  if (!run) return false;
  return isTerminalImportStatus(run.status) || run.total_rules_found > 0 || run.imported_count > 0 || run.updated_count > 0 || run.duplicate_count > 0 || run.invalid_count > 0 || run.unsupported_count > 0;
}

function importIsTerminal(run: RuleImportRun | null | undefined) {
  return Boolean(run && (run.is_terminal || isTerminalImportStatus(run.status)));
}

function importCountValue(run: RuleImportRun, value: number, fallback: string) {
  if (importIsTerminal(run)) return String(value);
  return importCountsKnown(run) ? String(value) : fallback;
}

function importProgressValue(run: RuleImportRun) {
  if (run.total_files > 0) return `${run.processed_files} / ${run.total_files}`;
  return importIsTerminal(run) ? "0 / 0" : "Discovering...";
}

function importRulesFoundValue(run: RuleImportRun) {
  if (run.total_rules_found > 0) return String(run.total_rules_found);
  return importIsTerminal(run) ? "0" : "Discovering...";
}

function importProcessedRulesValue(run: RuleImportRun) {
  if (run.processed_rules > 0) return String(run.processed_rules);
  return importIsTerminal(run) ? "0" : "Pending";
}

function importPerformance(run: RuleImportRun) {
  const perf = (run.details_json?.performance ?? {}) as Record<string, unknown>;
  return {
    filesPerSecond: typeof run.files_per_sec === "number" ? run.files_per_sec : typeof perf.files_per_second === "number" && perf.files_per_second > 0 ? perf.files_per_second : null,
    rulesPerSecond: typeof run.rules_per_sec === "number" ? run.rules_per_sec : typeof perf.rules_per_second === "number" && perf.rules_per_second > 0 ? perf.rules_per_second : null,
  };
}

function importPerformanceLabel(run: RuleImportRun) {
  const perf = importPerformance(run);
  if (perf.filesPerSecond == null || perf.rulesPerSecond == null) {
    return importIsTerminal(run) ? "n/a" : "Calculating...";
  }
  return `${perf.filesPerSecond} files/s · ${perf.rulesPerSecond} rules/s`;
}

function importCoverageReport(run: RuleImportRun) {
  return ((run.details_json?.sigma_engine_coverage_report as Record<string, unknown> | undefined) ?? {});
}

function importPySigmaEvaluation(run: RuleImportRun) {
  return ((run.details_json?.pysigma_evaluation as Record<string, unknown> | undefined) ?? {});
}

function caseCompatibility(run: RuleRun) {
  return ((run.metadata_json?.case_compatibility as Record<string, unknown> | undefined) ?? {});
}

function humanizeCompatibilityKey(key: string) {
  return key
    .replace(/^unsupported_/, "")
    .replace(/^condition_/, "condition ")
    .replace(/^skipped_/, "skipped ")
    .replace(/_/g, " ")
    .replace(/\b\w/g, (char) => char.toUpperCase());
}

function engineFromFilename(filename: string) {
  const lower = filename.toLowerCase();
  if (lower.endsWith(".yml") || lower.endsWith(".yaml")) return "sigma";
  if (lower.endsWith(".yar") || lower.endsWith(".yara")) return "yara";
  if (archiveExtensions.some((ext) => lower.endsWith(ext))) return "archive";
  return "unknown";
}

function summarizeRunResponse(result: RuleRunResult, label: string): QueuedRunSummary {
  return {
    engine: result.engine === "yara" ? "yara" : "sigma",
    status: result.status,
    runId: result.run_id ?? null,
    message: result.error ?? `${label} queued for execution.`,
  };
}

function readRuleRunSource(run: RuleRun) {
  if (run.engine === "yara") return "yara";
  if (run.engine === "sigma" || run.engine === "heuristic") return run.engine;
  return "";
}

function formatElapsed(seconds: number | null) {
  if (seconds == null) return "-";
  if (seconds < 60) return `${seconds}s`;
  const minutes = Math.floor(seconds / 60);
  const remainder = seconds % 60;
  if (minutes < 60) return `${minutes}m ${remainder}s`;
  const hours = Math.floor(minutes / 60);
  return `${hours}h ${minutes % 60}m`;
}

function sigmaRunModeLabel(mode: string | null | undefined) {
  switch (mode) {
    case "fast_triage":
      return "Fast triage";
    case "exhaustive":
      return "Exhaustive";
    default:
      return "Balanced";
  }
}

function heartbeatLabel(timestamp: string | null) {
  if (!timestamp) return "no heartbeat yet";
  const date = new Date(timestamp);
  if (Number.isNaN(date.getTime())) return "heartbeat unavailable";
  const deltaSeconds = Math.max(0, Math.round((Date.now() - date.getTime()) / 1000));
  return `${deltaSeconds}s ago`;
}

function zeroScanExplanation(run: RuleRun) {
  const matchesFound = runMetric(run, "matches_found") ?? run.matched ?? 0;
  const duplicates = run.duplicates ?? 0;
  const queuedForLong = run.status === "queued" && (run.elapsed_seconds ?? 0) >= 600;
  const runningWithoutHeartbeat = run.status === "running" && !run.heartbeat_at;
  if (queuedForLong) return `Queued for ${formatElapsed(run.elapsed_seconds ?? null)}. Rules worker may not be processing jobs.`;
  if (runningWithoutHeartbeat) return "Worker did not start correctly. Mark stale and retry.";
  if (run.engine === "yara") {
    if (run.status === "queued" || run.status === "running" || run.status === "stale") return "Waiting for worker progress";
    return run.total_files === 0 ? "No preserved files matched the selected scope" : "No files were scanned";
  }
  if (run.status === "queued" || run.status === "running" || run.status === "stale") return "Waiting for worker progress";
  if (matchesFound > 0 || duplicates > 0) return "Matches were found in scope; review matches, duplicates and warnings.";
  return run.total_events === 0 ? "No indexed events matched the selected scope" : "No indexed events were scanned";
}

function displayRunStatus(run: RuleRun) {
  const displayStatus = run.metadata_json?.display_status;
  return typeof displayStatus === "string" && displayStatus ? displayStatus : run.status;
}

function runMetric(run: RuleRun | undefined, key: string) {
  const value = run?.metadata_json?.[key];
  return typeof value === "number" ? value : null;
}

function runMapMetric(run: RuleRun | undefined, key: string) {
  const value = run?.metadata_json?.[key];
  return value && typeof value === "object" && !Array.isArray(value) ? (value as Record<string, unknown>) : {};
}

function MetricCard({ label, value, detail }: { label: string; value: string; detail: string }) {
  return (
    <div className="rounded-2xl border border-line bg-abyss/75 p-4">
      <p className="font-mono text-[11px] uppercase tracking-[0.16em] text-accent">{label}</p>
      <p className="mt-3 text-2xl font-semibold">{value}</p>
      <p className="mt-2 text-sm text-muted">{detail}</p>
    </div>
  );
}

function SectionCard({ title, subtitle, children }: { title: string; subtitle: string; children: ReactNode }) {
  return (
    <section className="rounded-3xl border border-line bg-panel/70 p-5 shadow-panel">
      <h3 className="text-lg font-semibold">{title}</h3>
      <p className="mt-2 text-sm text-muted">{subtitle}</p>
      <div className="mt-4">{children}</div>
    </section>
  );
}

function Notice({ tone = "default", children }: { tone?: "default" | "warning"; children: ReactNode }) {
  return (
    <div className={`rounded-2xl border p-4 text-sm ${tone === "warning" ? "border-amber-400/30 bg-amber-400/10 text-amber-100" : "border-line bg-abyss/80 text-muted"}`}>
      {children}
    </div>
  );
}

export default function Rules() {
  const queryClient = useQueryClient();
  const { activeCaseId, selectedHost, selectedEvidenceId } = useActiveCase();
  const [tab, setTab] = useState<RulesTab>("sigma");
  const [scopeCaseId, setScopeCaseId] = useState(activeCaseId);
  const [namespace, setNamespace] = useState("");
  const [viewRuleId, setViewRuleId] = useState<string | null>(null);
  const [viewRuleSetId, setViewRuleSetId] = useState<string | null>(null);
  const [ruleSetPreviewSearch, setRuleSetPreviewSearch] = useState("");
  const [sigmaSelectionMode, setSigmaSelectionMode] = useState<SigmaSelectionMode>("all_enabled");
  const [selectedSigmaRuleIds, setSelectedSigmaRuleIds] = useState<string[]>([]);
  const [sigmaScope, setSigmaScope] = useState<RunScope>("case");
  const [sigmaRunMode, setSigmaRunMode] = useState<SigmaRunMode>("balanced");
  const [sigmaImportSummary, setSigmaImportSummary] = useState("");
  const [sigmaImportResult, setSigmaImportResult] = useState<RuleImportResponse | null>(null);
  const [sigmaRunSummary, setSigmaRunSummary] = useState<QueuedRunSummary | null>(null);
  const [smokeMode, setSmokeMode] = useState<"single_rule" | "subset" | "recommended">("recommended");
  const [smokeRuleId, setSmokeRuleId] = useState("");
  const [smokeKeyword, setSmokeKeyword] = useState("");
  const [smokeSeverity, setSmokeSeverity] = useState("");
  const [smokeMaxRules, setSmokeMaxRules] = useState(5);
  const [smokeResult, setSmokeResult] = useState<SigmaSmokeResponse | null>(null);
  const [smokeMessage, setSmokeMessage] = useState("");
  const [yaraSelectionMode, setYaraSelectionMode] = useState<YaraSelectionMode>("selected_pack");
  const [selectedYaraRuleId, setSelectedYaraRuleId] = useState("");
  const [selectedYaraPackId, setSelectedYaraPackId] = useState("");
  const [yaraScope, setYaraScope] = useState<RunScope>("case");
  const [yaraImportSummary, setYaraImportSummary] = useState("");
  const [yaraImportResult, setYaraImportResult] = useState<RuleImportResponse | null>(null);
  const [yaraRunSummary, setYaraRunSummary] = useState<QueuedRunSummary | null>(null);
  const [selectedImportRunId, setSelectedImportRunId] = useState<string | null>(null);
  const [bannerImportRunId, setBannerImportRunId] = useState<string | null>(() => readStoredString(RULES_ACTIVE_IMPORT_ID_STORAGE_KEY));
  const [pendingImport, setPendingImport] = useState<PendingImportDescriptor | null>(() => readStoredJson<PendingImportDescriptor>(RULES_PENDING_IMPORT_STORAGE_KEY));
  const [dismissedImportRunIds, setDismissedImportRunIds] = useState<string[]>(() => readStoredJson<string[]>(RULES_DISMISSED_IMPORTS_STORAGE_KEY) ?? []);
  const [hideTerminalImportBanner, setHideTerminalImportBanner] = useState<boolean>(() => readStoredString(RULES_HIDE_TERMINAL_IMPORT_BANNER_STORAGE_KEY) === "true");
  const [importRefreshError, setImportRefreshError] = useState<string | null>(null);
  const [importFailure, setImportFailure] = useState<ImportFailureState | null>(null);
  const [includeParsedOutputs, setIncludeParsedOutputs] = useState(false);
  const [includeArchives, setIncludeArchives] = useState(false);
  const [includeTextOutputs, setIncludeTextOutputs] = useState(false);
  const [maxFileSizeMb, setMaxFileSizeMb] = useState(100);
  const [librarySearch, setLibrarySearch] = useState("");
  const [libraryEngineFilter, setLibraryEngineFilter] = useState("");
  const [librarySeverityFilter, setLibrarySeverityFilter] = useState("");
  const [libraryNamespaceFilter, setLibraryNamespaceFilter] = useState("");
  const [libraryStateFilter, setLibraryStateFilter] = useState("");
  const [libraryImportRunFilter, setLibraryImportRunFilter] = useState("");
  const [librarySourcePackFilter, setLibrarySourcePackFilter] = useState("");
  const [libraryImportStatusFilter, setLibraryImportStatusFilter] = useState("");
  const [sigmaCoverageFilter, setSigmaCoverageFilter] = useState("");
  const [selectedLibraryRuleIds, setSelectedLibraryRuleIds] = useState<string[]>([]);
  const [selectedLibraryPackIds, setSelectedLibraryPackIds] = useState<string[]>([]);
  const [allMatchingLibraryRulesSelected, setAllMatchingLibraryRulesSelected] = useState(false);
  const [selectedRunIds, setSelectedRunIds] = useState<string[]>([]);
  const [selectedRunId, setSelectedRunId] = useState<string | null>(null);
  const [pendingLibraryConfirmation, setPendingLibraryConfirmation] = useState<PendingLibraryConfirmation>(null);
  const [confirmationPhrase, setConfirmationPhrase] = useState("");
  const [libraryBulkMessage, setLibraryBulkMessage] = useState("");
  const [runBulkMessage, setRunBulkMessage] = useState("");
  const { data: cases } = useQuery({ queryKey: ["cases"], queryFn: api.listCases });
  const enginesQuery = useQuery({ queryKey: ["rule-engines-status"], queryFn: api.getRuleEngineStatus });

  useEffect(() => {
    setScopeCaseId((current) => current || activeCaseId);
  }, [activeCaseId]);

  const sharedQueryParams = useMemo(
    () => ({
      case_id: scopeCaseId || undefined,
      scope: "all",
      page: 1,
      page_size: 250,
      import_run_id: libraryImportRunFilter || undefined,
      source_pack: librarySourcePackFilter || undefined,
    }),
    [libraryImportRunFilter, librarySourcePackFilter, scopeCaseId],
  );

  const rulesQuery = useQuery({
    queryKey: ["rules", sharedQueryParams],
    queryFn: () => api.listRules(sharedQueryParams),
  });
  const ruleSetsQuery = useQuery({
    queryKey: ["rule-sets", sharedQueryParams],
    queryFn: () => api.listRuleSets(sharedQueryParams),
  });
  const ruleRunsQuery = useQuery({
    queryKey: ["case-rule-runs", scopeCaseId],
    queryFn: () => api.listCaseRuleRuns(scopeCaseId as string),
    enabled: Boolean(scopeCaseId),
    refetchInterval: (query) => {
      const data = query.state.data as RuleRun[] | undefined;
      return data?.some((run) => run.status === "queued" || run.status === "running") ? 5000 : false;
    },
  });
  const ruleImportsQuery = useQuery({
    queryKey: ["rule-imports", "all-scopes"],
    queryFn: () => api.listRuleImports({ limit: 50 }),
    refetchInterval: (query) => {
      const items = (query.state.data as { items?: RuleImportRun[] } | undefined)?.items ?? [];
      return Boolean(pendingImport) || items.some((item) => isActiveImportStatus(item.status)) ? 1500 : false;
    },
  });
  const selectedImportRunQuery = useQuery({
    queryKey: ["rule-import", selectedImportRunId],
    queryFn: () => api.getRuleImport(selectedImportRunId as string),
    enabled: Boolean(selectedImportRunId),
    refetchInterval: (query) => {
      const item = query.state.data as RuleImportRun | undefined;
      return item && !importIsTerminal(item) ? 1500 : false;
    },
  });
  const selectedRunQuery = useQuery({
    queryKey: ["case-rule-run", scopeCaseId, selectedRunId],
    queryFn: () => api.getCaseRuleRun(scopeCaseId as string, selectedRunId as string),
    enabled: Boolean(scopeCaseId && selectedRunId),
    refetchInterval: (query) => {
      const run = query.state.data as RuleRun | undefined;
      return run && (run.status === "queued" || run.status === "running") ? 5000 : false;
    },
  });
  const sigmaDetectionsQuery = useQuery({
    queryKey: ["detections-summary", scopeCaseId, "sigma"],
    queryFn: () => api.listDetections(scopeCaseId as string, { source: "sigma", page: 1, page_size: 1 }),
    enabled: Boolean(scopeCaseId),
  });
  const yaraDetectionsQuery = useQuery({
    queryKey: ["detections-summary", scopeCaseId, "yara"],
    queryFn: () => api.listDetections(scopeCaseId as string, { source: "yara", page: 1, page_size: 1 }),
    enabled: Boolean(scopeCaseId),
  });
  const heuristicDetectionsQuery = useQuery({
    queryKey: ["detections-summary", scopeCaseId, "heuristic"],
    queryFn: () => api.listDetections(scopeCaseId as string, { source: "heuristic", page: 1, page_size: 1 }),
    enabled: Boolean(scopeCaseId),
  });
  const sigmaImportedCountQuery = useQuery({
    queryKey: ["rules-count", scopeCaseId, "sigma", "imported"],
    queryFn: () => api.listRules({ case_id: scopeCaseId || undefined, scope: "all", engine: "sigma", page: 1, page_size: 1 }),
    enabled: Boolean(scopeCaseId),
  });
  const sigmaEnabledCountQuery = useQuery({
    queryKey: ["rules-count", scopeCaseId, "sigma", "enabled"],
    queryFn: () => api.listRules({ case_id: scopeCaseId || undefined, scope: "all", engine: "sigma", enabled: true, page: 1, page_size: 1 }),
    enabled: Boolean(scopeCaseId),
  });
  const sigmaGlobalCountQuery = useQuery({
    queryKey: ["rules-count", "global", "sigma"],
    queryFn: () => api.listRules({ scope: "global", engine: "sigma", page: 1, page_size: 1 }),
  });
  const sigmaCaseCountQuery = useQuery({
    queryKey: ["rules-count", scopeCaseId, "case", "sigma"],
    queryFn: () => api.listRules({ case_id: scopeCaseId || undefined, scope: "case", engine: "sigma", page: 1, page_size: 1 }),
    enabled: Boolean(scopeCaseId),
  });
  const sigmaAllCaseScopedCountQuery = useQuery({
    queryKey: ["rules-count", "all-case-scoped", "sigma"],
    queryFn: () => api.listRules({ scope: "case", engine: "sigma", page: 1, page_size: 1 }),
  });
  const sigmaCoverageQuery = useQuery({
    queryKey: ["sigma-coverage", scopeCaseId || "global", scopeCaseId ? "all" : "global"],
    queryFn: () => api.getRuleCoverageSummary({ case_id: scopeCaseId || undefined, scope: scopeCaseId ? "all" : "global" }),
  });
  const sigmaCoverageListQuery = useQuery({
    queryKey: ["sigma-coverage-list", scopeCaseId || "global", sigmaCoverageFilter],
    queryFn: () => api.listRuleCoverage({ case_id: scopeCaseId || undefined, scope: scopeCaseId ? "all" : "global", status: sigmaCoverageFilter || undefined, page: 1, page_size: 25 }),
  });
  const yaraImportedCountQuery = useQuery({
    queryKey: ["rules-count", scopeCaseId, "yara", "imported"],
    queryFn: () => api.listRules({ case_id: scopeCaseId || undefined, scope: "all", engine: "yara", page: 1, page_size: 1 }),
    enabled: Boolean(scopeCaseId),
  });
  const yaraEnabledCountQuery = useQuery({
    queryKey: ["rules-count", scopeCaseId, "yara", "enabled"],
    queryFn: () => api.listRules({ case_id: scopeCaseId || undefined, scope: "all", engine: "yara", enabled: true, page: 1, page_size: 1 }),
    enabled: Boolean(scopeCaseId),
  });
  const yaraPackCountQuery = useQuery({
    queryKey: ["rule-set-count", scopeCaseId, "yara"],
    queryFn: () => api.listRuleSets({ case_id: scopeCaseId || undefined, scope: "all", engine: "yara", page: 1, page_size: 1 }),
    enabled: Boolean(scopeCaseId),
  });
  const viewRuleQuery = useQuery({ queryKey: ["rule", viewRuleId], queryFn: () => api.getRule(viewRuleId as string), enabled: Boolean(viewRuleId) });
  const viewRuleSetQuery = useQuery({ queryKey: ["rule-set", viewRuleSetId], queryFn: () => api.getRuleSet(viewRuleSetId as string), enabled: Boolean(viewRuleSetId) });

  const sigmaRules = useMemo(() => (rulesQuery.data?.items ?? []).filter((rule) => rule.engine === "sigma"), [rulesQuery.data?.items]);
  const heuristicRules = useMemo(() => (rulesQuery.data?.items ?? []).filter((rule) => rule.engine === "heuristic"), [rulesQuery.data?.items]);
  const yaraRules = useMemo(() => (rulesQuery.data?.items ?? []).filter((rule) => rule.engine === "yara"), [rulesQuery.data?.items]);
  const yaraRulePacks = useMemo(() => (ruleSetsQuery.data?.items ?? []).filter((ruleSet) => ruleSet.engine === "yara"), [ruleSetsQuery.data?.items]);
  const sigmaRuns = useMemo(() => (ruleRunsQuery.data ?? []).filter((run) => run.engine === "sigma" || run.engine === "heuristic" || (run.engine === "multi" && Array.isArray(run.metadata_json?.rule_types) && (run.metadata_json.rule_types as string[]).includes("sigma"))), [ruleRunsQuery.data]);
  const yaraRuns = useMemo(() => (ruleRunsQuery.data ?? []).filter((run) => run.engine === "yara"), [ruleRunsQuery.data]);
  const lastSigmaRun = sigmaRuns[0] ?? null;
  const lastYaraRun = yaraRuns[0] ?? null;
  const lastRunByRule = new Map((ruleRunsQuery.data ?? []).filter((run) => run.rule_id).map((run) => [run.rule_id, run] as const));
  const lastRunByRuleSet = new Map((ruleRunsQuery.data ?? []).filter((run) => run.rule_set_id).map((run) => [run.rule_set_id, run] as const));
  const sigmaImportedRules = sigmaImportedCountQuery.data?.total ?? sigmaRules.length;
  const sigmaEnabledRules = sigmaEnabledCountQuery.data?.total ?? sigmaRules.filter((rule) => rule.enabled).length;
  const sigmaGlobalRules = sigmaGlobalCountQuery.data?.total ?? 0;
  const sigmaCaseRules = sigmaCaseCountQuery.data?.total ?? 0;
  const sigmaAllCaseScopedRules = sigmaAllCaseScopedCountQuery.data?.total ?? sigmaCaseRules;
  const sigmaAvailableRules = scopeCaseId ? sigmaImportedRules : sigmaGlobalRules;
  const yaraImportedRules = yaraImportedCountQuery.data?.total ?? yaraRules.length;
  const yaraEnabledRules = yaraEnabledCountQuery.data?.total ?? yaraRules.filter((rule) => rule.enabled).length;
  const yaraImportedPacks = yaraPackCountQuery.data?.total ?? yaraRulePacks.length;
  const sigmaImportRuns = useMemo(() => (ruleImportsQuery.data?.items ?? []).filter((item) => item.engine === "sigma" || item.engine === "mixed" || (item.details_json?.detected_engine_counts as Record<string, number> | undefined)?.sigma), [ruleImportsQuery.data?.items]);
  const yaraImportRuns = useMemo(() => (ruleImportsQuery.data?.items ?? []).filter((item) => item.engine === "yara" || item.engine === "mixed" || (item.details_json?.detected_engine_counts as Record<string, number> | undefined)?.yara), [ruleImportsQuery.data?.items]);
  const rulesLoading = rulesQuery.isLoading || sigmaImportedCountQuery.isLoading || sigmaEnabledCountQuery.isLoading || sigmaGlobalCountQuery.isLoading || sigmaCaseCountQuery.isLoading || sigmaAllCaseScopedCountQuery.isLoading || ruleImportsQuery.isLoading || sigmaCoverageQuery.isLoading;
  const sigmaImportHistoryCount = sigmaImportRuns.reduce((total, item) => total + (item.imported_count ?? 0) + (item.updated_count ?? 0), 0);
  const sigmaLibraryMissingAfterImports = !rulesLoading && sigmaAvailableRules === 0 && sigmaGlobalRules === 0 && sigmaAllCaseScopedRules === 0 && sigmaImportHistoryCount > 0;
  const importRunFilterOptions = useMemo(() => (ruleImportsQuery.data?.items ?? []).map((item) => ({ id: item.id, label: item.source_name || item.pack_name || item.id })), [ruleImportsQuery.data?.items]);
  const sourcePackOptions = useMemo(() => Array.from(new Set((ruleImportsQuery.data?.items ?? []).map((item) => item.pack_name).filter((value): value is string => Boolean(value)))), [ruleImportsQuery.data?.items]);
  const discoveredActiveImportRun = useMemo(() => {
    const items = ruleImportsQuery.data?.items ?? [];
    if (pendingImport) {
      const matched = items.find((item) => {
        if (!isActiveImportStatus(item.status)) return false;
        if ((item.source_name || item.uploaded_filename || "") !== pendingImport.sourceName) return false;
        if (pendingImport.engine === "sigma") return item.engine === "sigma" || item.engine === "mixed";
        return item.engine === "yara" || item.engine === "mixed";
      });
      if (matched) return matched;
    }
    return items.find((item) => isActiveImportStatus(item.status) && !dismissedImportRunIds.includes(item.id)) ?? null;
  }, [dismissedImportRunIds, pendingImport, ruleImportsQuery.data?.items]);
  const bannerImportRun = useMemo(() => {
    const items = ruleImportsQuery.data?.items ?? [];
    if (bannerImportRunId) {
      return items.find((item) => item.id === bannerImportRunId) ?? null;
    }
    if (discoveredActiveImportRun) return discoveredActiveImportRun;
    if (hideTerminalImportBanner) return null;
    return items.find((item) => !dismissedImportRunIds.includes(item.id)) ?? null;
  }, [bannerImportRunId, discoveredActiveImportRun, dismissedImportRunIds, hideTerminalImportBanner, ruleImportsQuery.data?.items]);
  const visibleImportRun = bannerImportRun ?? discoveredActiveImportRun;
  const visibleImportPercent = visibleImportRun ? importProgressPercent(visibleImportRun) : null;

  useEffect(() => {
    if (typeof window === "undefined") return;
    if (bannerImportRunId) window.localStorage.setItem(RULES_ACTIVE_IMPORT_ID_STORAGE_KEY, bannerImportRunId);
    else window.localStorage.removeItem(RULES_ACTIVE_IMPORT_ID_STORAGE_KEY);
  }, [bannerImportRunId]);

  useEffect(() => {
    if (typeof window === "undefined") return;
    if (pendingImport) window.localStorage.setItem(RULES_PENDING_IMPORT_STORAGE_KEY, JSON.stringify(pendingImport));
    else window.localStorage.removeItem(RULES_PENDING_IMPORT_STORAGE_KEY);
  }, [pendingImport]);

  useEffect(() => {
    if (typeof window === "undefined") return;
    window.localStorage.setItem(RULES_DISMISSED_IMPORTS_STORAGE_KEY, JSON.stringify(dismissedImportRunIds));
  }, [dismissedImportRunIds]);

  useEffect(() => {
    if (typeof window === "undefined") return;
    if (hideTerminalImportBanner) window.localStorage.setItem(RULES_HIDE_TERMINAL_IMPORT_BANNER_STORAGE_KEY, "true");
    else window.localStorage.removeItem(RULES_HIDE_TERMINAL_IMPORT_BANNER_STORAGE_KEY);
  }, [hideTerminalImportBanner]);

  useEffect(() => {
    if (ruleImportsQuery.error) setImportRefreshError("Unable to refresh import status.");
    else if (ruleImportsQuery.data) setImportRefreshError(null);
  }, [ruleImportsQuery.data, ruleImportsQuery.error]);

  useEffect(() => {
    if (discoveredActiveImportRun && bannerImportRunId !== discoveredActiveImportRun.id) {
      setBannerImportRunId(discoveredActiveImportRun.id);
      setHideTerminalImportBanner(false);
    }
  }, [bannerImportRunId, discoveredActiveImportRun]);

  useEffect(() => {
    if (!visibleImportRun) return;
    if (isActiveImportStatus(visibleImportRun.status)) {
      setImportFailure(null);
    }
    if (isTerminalImportStatus(visibleImportRun.status)) {
      setPendingImport(null);
    }
  }, [visibleImportRun]);

  const namespaceOptions = useMemo(
    () =>
      Array.from(
        new Set([
          ...sigmaRules.map((rule) => rule.namespace).filter(Boolean),
          ...heuristicRules.map((rule) => rule.namespace).filter(Boolean),
          ...yaraRules.map((rule) => rule.namespace).filter(Boolean),
          ...yaraRulePacks.map((ruleSet) => ruleSet.namespace).filter(Boolean),
        ]),
      ) as string[],
    [heuristicRules, sigmaRules, yaraRulePacks, yaraRules],
  );

  const libraryItems = useMemo<LibraryItem[]>(() => {
    const rules = (rulesQuery.data?.items ?? []).map((rule) => ({
      kind: "rule" as const,
      id: rule.id,
      engine: rule.engine,
      title: rule.title || rule.name,
      namespace: rule.namespace,
      severity: rule.severity,
      enabled: rule.enabled,
      description: rule.description,
      updated_at: rule.updated_at,
      source_label: rule.source,
      import_run_id: String(rule.metadata_json?.import_run_id ?? "") || null,
      source_pack: String(rule.metadata_json?.source_pack ?? "") || null,
      import_status: String(rule.metadata_json?.last_import_status ?? "") || null,
      item: rule,
    }));
    const packs = (ruleSetsQuery.data?.items ?? []).map((ruleSet) => ({
      kind: "pack" as const,
      id: ruleSet.id,
      engine: ruleSet.engine,
      title: ruleSet.name,
      namespace: ruleSet.namespace,
      severity: ruleSet.severity,
      enabled: ruleSet.enabled,
      description: ruleSet.description,
      updated_at: ruleSet.updated_at,
      source_label: ruleSet.source_filename,
      import_run_id: String(ruleSet.metadata_json?.import_run_id ?? "") || null,
      source_pack: String(ruleSet.metadata_json?.source_pack ?? "") || null,
      import_status: String(ruleSet.metadata_json?.last_import_status ?? "") || null,
      item: ruleSet,
    }));
    return [...rules, ...packs];
  }, [ruleSetsQuery.data?.items, rulesQuery.data?.items]);

  const filteredLibraryItems = useMemo(() => {
    const token = librarySearch.trim().toLowerCase();
    return libraryItems.filter((item) => {
      if (libraryEngineFilter && item.engine !== libraryEngineFilter) return false;
      if (librarySeverityFilter && (item.severity || "") !== librarySeverityFilter) return false;
      if (libraryNamespaceFilter && (item.namespace || "") !== libraryNamespaceFilter) return false;
      if (libraryStateFilter) {
        if (libraryStateFilter === "enabled" && !item.enabled) return false;
        if (libraryStateFilter === "disabled" && item.enabled) return false;
      }
      if (libraryImportRunFilter && (item.import_run_id || "") !== libraryImportRunFilter) return false;
      if (librarySourcePackFilter && (item.source_pack || "") !== librarySourcePackFilter) return false;
      if (libraryImportStatusFilter && (item.import_status || "") !== libraryImportStatusFilter) return false;
      if (!token) return true;
      return [item.title, item.description || "", item.namespace || "", item.source_label || "", item.source_pack || "", item.import_run_id || ""].some((value) => value.toLowerCase().includes(token));
    });
  }, [libraryEngineFilter, libraryImportRunFilter, libraryImportStatusFilter, libraryItems, libraryNamespaceFilter, librarySearch, librarySeverityFilter, librarySourcePackFilter, libraryStateFilter]);

  const visibleRuleSetNames = useMemo(() => {
    const preview = (viewRuleSetQuery.data?.metadata_json?.first_rules as string[] | undefined) ?? [];
    const token = ruleSetPreviewSearch.trim().toLowerCase();
    if (!token) return preview;
    return preview.filter((name) => name.toLowerCase().includes(token));
  }, [ruleSetPreviewSearch, viewRuleSetQuery.data?.metadata_json]);

  function openLibraryForImport(run: RuleImportRun) {
    setLibraryImportRunFilter(run.id);
    setLibrarySourcePackFilter(run.pack_name || "");
    setLibraryImportStatusFilter("");
    setSelectedImportRunId(null);
    setTab("library");
  }

  const importSingleMutation = useMutation({
    mutationFn: ({ file, engine }: { file: File; engine: "sigma" | "yara" }) => api.importRuleFile(file, { engine, import_mode: engine === "yara" ? "auto" : "split", case_id: engine === "sigma" ? undefined : scopeCaseId || undefined, namespace: namespace || undefined, enabled: true }),
    onMutate: ({ file, engine }) => {
      setImportFailure(null);
      setImportRefreshError(null);
      setHideTerminalImportBanner(false);
      setPendingImport({
        engine,
        sourceName: file.name,
        sourceType: "single_file",
        startedAt: new Date().toISOString(),
      });
    },
    onSuccess: (result, variables) => {
      const summary = formatImportSummary(result);
      if (variables.engine === "sigma") {
        setSigmaImportSummary(summary);
        setSigmaImportResult(result);
      } else {
        setYaraImportSummary(summary);
        setYaraImportResult(result);
      }
      if (result.import_run_id) {
        setSelectedImportRunId(result.import_run_id);
        setBannerImportRunId(result.import_run_id);
        setHideTerminalImportBanner(false);
        setDismissedImportRunIds((current) => current.filter((item) => item !== result.import_run_id));
      }
      setPendingImport(null);
      void queryClient.invalidateQueries({ queryKey: ["rules"] });
      void queryClient.invalidateQueries({ queryKey: ["rule-sets"] });
      void queryClient.invalidateQueries({ queryKey: ["rule-imports"] });
      void queryClient.invalidateQueries({ queryKey: ["rules-count"] });
      void queryClient.invalidateQueries({ queryKey: ["sigma-coverage"] });
    },
    onError: (error, variables) => {
      setPendingImport(null);
      setImportFailure({
        engine: variables.engine,
        sourceName: variables.file.name,
        message: error instanceof Error ? error.message : "Rule import failed.",
      });
    },
  });

  const importArchiveMutation = useMutation({
    mutationFn: ({ file, engine }: { file: File; engine: "sigma" | "yara" }) => api.importRuleArchive(file, { engine, import_mode: engine === "yara" ? "rule_pack" : "split", case_id: engine === "sigma" ? undefined : scopeCaseId || undefined, namespace: namespace || undefined, enabled: true }),
    onMutate: ({ file, engine }) => {
      setImportFailure(null);
      setImportRefreshError(null);
      setHideTerminalImportBanner(false);
      setPendingImport({
        engine,
        sourceName: file.name,
        sourceType: "archive",
        startedAt: new Date().toISOString(),
      });
    },
    onSuccess: (result, variables) => {
      const summary = formatImportSummary(result);
      if (variables.engine === "sigma") {
        setSigmaImportSummary(summary);
        setSigmaImportResult(result);
      } else {
        setYaraImportSummary(summary);
        setYaraImportResult(result);
      }
      if (result.import_run_id) {
        setSelectedImportRunId(result.import_run_id);
        setBannerImportRunId(result.import_run_id);
        setHideTerminalImportBanner(false);
        setDismissedImportRunIds((current) => current.filter((item) => item !== result.import_run_id));
      }
      setPendingImport(null);
      void queryClient.invalidateQueries({ queryKey: ["rules"] });
      void queryClient.invalidateQueries({ queryKey: ["rule-sets"] });
      void queryClient.invalidateQueries({ queryKey: ["rule-imports"] });
      void queryClient.invalidateQueries({ queryKey: ["rules-count"] });
      void queryClient.invalidateQueries({ queryKey: ["sigma-coverage"] });
    },
    onError: (error, variables) => {
      setPendingImport(null);
      setImportFailure({
        engine: variables.engine,
        sourceName: variables.file.name,
        message: error instanceof Error ? error.message : "Rule import failed.",
      });
    },
  });

  const promoteSigmaMutation = useMutation({
    mutationFn: ({ caseId, confirm }: { caseId: string; confirm: string }) => api.promoteCaseSigmaRulesToGlobal({ case_id: caseId, confirm, mode: "copy_keep_case" }),
    onSuccess: (result) => {
      setLibraryBulkMessage(`Promoted ${result.promoted} Sigma rules to global. Skipped ${result.skipped_duplicates} existing global duplicates. Snapshot: ${result.after_snapshot.path}`);
      void queryClient.invalidateQueries({ queryKey: ["rules"] });
      void queryClient.invalidateQueries({ queryKey: ["rule-sets"] });
      void queryClient.invalidateQueries({ queryKey: ["rules-count"] });
      void queryClient.invalidateQueries({ queryKey: ["sigma-coverage"] });
    },
    onError: (error) => {
      setLibraryBulkMessage(error instanceof Error ? error.message : "Sigma promotion failed.");
    },
  });

  const cancelImportMutation = useMutation({
    mutationFn: (importRunId: string) => api.cancelRuleImport(importRunId),
    onSuccess: (run) => {
      setBannerImportRunId(run.id);
      setSelectedImportRunId(run.id);
      void queryClient.invalidateQueries({ queryKey: ["rule-imports"] });
      void queryClient.invalidateQueries({ queryKey: ["rule-import", run.id] });
    },
  });

  const runRuleMutation = useMutation({
    mutationFn: ({ ruleId, engine }: { ruleId: string; engine: "sigma" | "yara" | "heuristic" }) =>
      api.runRule(ruleId, {
        case_id: scopeCaseId as string,
        evidence_id: selectedEvidenceId || undefined,
        mode: engine === "yara" ? "files" : "events",
        dry_run: false,
        include_parsed_outputs: includeParsedOutputs,
        include_archives: includeArchives,
        include_text_outputs: includeTextOutputs,
        max_file_size_mb: maxFileSizeMb,
      }),
    onSuccess: (result, variables) => {
      const summary = summarizeRunResponse(result, variables.engine === "yara" ? "YARA rule" : "Rule");
      if (variables.engine === "yara") setYaraRunSummary(summary);
      else setSigmaRunSummary(summary);
      void queryClient.invalidateQueries({ queryKey: ["case-rule-runs"] });
    },
  });

  const runRuleSetMutation = useMutation({
    mutationFn: (ruleSetId: string) =>
      api.runRuleSet(ruleSetId, {
        case_id: scopeCaseId as string,
        evidence_id: selectedEvidenceId || undefined,
        mode: "files",
        dry_run: false,
        include_parsed_outputs: includeParsedOutputs,
        include_archives: includeArchives,
        include_text_outputs: includeTextOutputs,
        max_file_size_mb: maxFileSizeMb,
      }),
    onSuccess: (result) => {
      setYaraRunSummary(summarizeRunResponse(result, "YARA rule pack"));
      void queryClient.invalidateQueries({ queryKey: ["case-rule-runs"] });
    },
  });

  const bulkRunRulesMutation = useMutation({
    mutationFn: (payload: {
      engine: "sigma" | "yara";
      rule_ids?: string[];
      host?: string;
      evidence_id?: string;
      run_mode?: SigmaRunMode;
    }) =>
      api.runRulesForCase(scopeCaseId as string, {
        rule_ids: payload.rule_ids,
        engine: payload.engine,
        host: payload.host,
        evidence_id: payload.evidence_id,
        enabled_only: true,
        include_parsed_outputs: includeParsedOutputs,
        include_archives: includeArchives,
        include_text_outputs: includeTextOutputs,
        max_file_size_mb: maxFileSizeMb,
        run_mode: payload.run_mode,
      }),
    onSuccess: (result, variables) => {
      const summary: QueuedRunSummary = {
        engine: variables.engine,
        status: result.status,
        runId: result.run_id ?? null,
        message: result.message || `Queued ${result.queued_rules ?? 0} ${variables.engine.toUpperCase()} rules.`,
      };
      if (variables.engine === "sigma") setSigmaRunSummary(summary);
      else setYaraRunSummary(summary);
      void queryClient.invalidateQueries({ queryKey: ["case-rule-runs"] });
    },
  });

  const smokePreflightMutation = useMutation({
    mutationFn: (payload: ReturnType<typeof smokePayload>) => api.preflightSigmaSmoke(payload),
    onSuccess: (result) => {
      setSmokeResult(result);
      setSmokeMessage(`Preflight checked ${result.rules_selected} rules. Ready: ${result.rules.filter((rule) => rule.status === "ready").length}.`);
    },
    onError: (error) => {
      setSmokeMessage(error instanceof Error ? error.message : "Sigma smoke preflight failed.");
    },
  });

  const smokeRunMutation = useMutation({
    mutationFn: (payload: ReturnType<typeof smokePayload>) => api.runSigmaSmoke(payload),
    onSuccess: (result) => {
      setSmokeResult(result);
      setSmokeMessage(`Smoke run completed. Matched ${result.matched} rules and created ${result.created_detections} smoke detections.`);
      void queryClient.invalidateQueries({ queryKey: ["case-rule-runs"] });
      void queryClient.invalidateQueries({ queryKey: ["detections"] });
      void queryClient.invalidateQueries({ queryKey: ["detections-summary"] });
    },
    onError: (error) => {
      setSmokeMessage(error instanceof Error ? error.message : "Sigma smoke run failed.");
    },
  });

  const toggleRuleMutation = useMutation({
    mutationFn: (ruleId: string) => api.toggleRule(ruleId),
    onSuccess: () => void queryClient.invalidateQueries({ queryKey: ["rules"] }),
  });
  const toggleRuleSetMutation = useMutation({
    mutationFn: (ruleSetId: string) => api.toggleRuleSet(ruleSetId),
    onSuccess: () => void queryClient.invalidateQueries({ queryKey: ["rule-sets"] }),
  });
  const bulkRuleUpdateMutation = useMutation({
    mutationFn: ({ enabled, mode, ruleIds, importRunId, sourcePack }: { enabled: boolean; mode: "selected" | "matching"; ruleIds?: string[]; importRunId?: string; sourcePack?: string }) =>
      api.bulkUpdateRules({
        rule_ids: ruleIds,
        mode,
        enabled,
        case_id: scopeCaseId || undefined,
        engine: libraryEngineFilter || undefined,
        namespace: libraryNamespaceFilter || undefined,
        severity: librarySeverityFilter || undefined,
        import_run_id: importRunId,
        source_pack: sourcePack,
        scope: "all",
        search: librarySearch || undefined,
      }),
    onSuccess: (result) => {
      setLibraryBulkMessage(`Updated ${result.updated} rules.`);
      setSelectedLibraryRuleIds([]);
      void queryClient.invalidateQueries({ queryKey: ["rules"] });
    },
  });
  const bulkRuleDeleteMutation = useMutation({
    mutationFn: (payload: { mode: "selected" | "matching" | "all_imported"; ruleIds?: string[]; confirm?: string; importRunId?: string; sourcePack?: string }) =>
      api.bulkDeleteRules({
        rule_ids: payload.ruleIds,
        mode: payload.mode,
        confirm: payload.confirm,
        case_id: scopeCaseId || undefined,
        engine: payload.mode === "all_imported" && !libraryEngineFilter ? "all" : libraryEngineFilter || undefined,
        namespace: libraryNamespaceFilter || undefined,
        severity: librarySeverityFilter || undefined,
        import_run_id: payload.importRunId,
        source_pack: payload.sourcePack,
        enabled: libraryStateFilter === "enabled" ? true : libraryStateFilter === "disabled" ? false : null,
        scope: "all",
        search: librarySearch || undefined,
      }),
    onSuccess: (result) => {
      setLibraryBulkMessage(`Deleted ${result.deleted} rules. Skipped ${result.skipped}.`);
      setSelectedLibraryRuleIds([]);
      setPendingLibraryConfirmation(null);
      setConfirmationPhrase("");
      void queryClient.invalidateQueries({ queryKey: ["rules"] });
    },
  });
  const bulkPackDeleteMutation = useMutation({
    mutationFn: ({ mode, packIds, confirm }: { mode: "selected" | "matching"; packIds?: string[]; confirm?: string }) =>
      api.bulkDeleteRuleSets({
        pack_ids: packIds,
        mode,
        confirm,
        case_id: scopeCaseId || undefined,
        engine: libraryEngineFilter || undefined,
        namespace: libraryNamespaceFilter || undefined,
        enabled: libraryStateFilter === "enabled" ? true : libraryStateFilter === "disabled" ? false : null,
        scope: "all",
        search: librarySearch || undefined,
      }),
    onSuccess: (result) => {
      setLibraryBulkMessage(`Deleted ${result.deleted} rule packs.`);
      setSelectedLibraryPackIds([]);
      void queryClient.invalidateQueries({ queryKey: ["rule-sets"] });
      void queryClient.invalidateQueries({ queryKey: ["rules"] });
    },
  });
  const cancelRunMutation = useMutation({
    mutationFn: (runId: string) => api.cancelRuleRun(runId),
    onSuccess: (result) => {
      setRunBulkMessage(result.message);
      void queryClient.invalidateQueries({ queryKey: ["case-rule-runs"] });
      if (selectedRunId === result.run.id) void queryClient.invalidateQueries({ queryKey: ["case-rule-run", scopeCaseId, selectedRunId] });
    },
  });
  const markStaleRunMutation = useMutation({
    mutationFn: (runId: string) => api.markRuleRunStale(runId),
    onSuccess: (result) => {
      setRunBulkMessage(result.message);
      void queryClient.invalidateQueries({ queryKey: ["case-rule-runs"] });
      if (selectedRunId === result.run.id) void queryClient.invalidateQueries({ queryKey: ["case-rule-run", scopeCaseId, selectedRunId] });
    },
  });
  const retryRunMutation = useMutation({
    mutationFn: (runId: string) => api.retryRuleRun(runId),
    onSuccess: (result) => {
      setRunBulkMessage(result.message);
      void queryClient.invalidateQueries({ queryKey: ["case-rule-runs"] });
    },
  });
  const deleteRunMutation = useMutation({
    mutationFn: (runId: string) => api.deleteRuleRun(runId),
    onSuccess: () => {
      setRunBulkMessage("Deleted run record.");
      setSelectedRunIds([]);
      setSelectedRunId(null);
      void queryClient.invalidateQueries({ queryKey: ["case-rule-runs"] });
    },
  });
  const bulkRunActionMutation = useMutation({
    mutationFn: ({ action, mode, runIds }: { action: "cancel" | "mark_stale" | "retry" | "delete"; mode: "selected" | "matching"; runIds?: string[] }) => {
      const payload = {
        run_ids: runIds,
        mode,
        case_id: scopeCaseId || undefined,
        statuses: action === "mark_stale" ? ["queued", "running"] : undefined,
        older_than_minutes: action === "mark_stale" ? 10 : undefined,
      };
      if (action === "cancel") return api.bulkCancelRuleRuns(payload);
      if (action === "mark_stale") return api.bulkMarkStaleRuleRuns(payload);
      if (action === "retry") return api.bulkRetryRuleRuns(payload);
      return api.bulkDeleteRuleRuns(payload);
    },
    onSuccess: (result, variables) => {
      if (variables.action === "retry") setRunBulkMessage(`Queued ${result.created_run_ids.length} retry runs.`);
      else if (variables.action === "delete") setRunBulkMessage(`Deleted ${result.deleted} run records.`);
      else setRunBulkMessage(`Updated ${result.updated} runs.`);
      setSelectedRunIds([]);
      void queryClient.invalidateQueries({ queryKey: ["case-rule-runs"] });
    },
  });

  function effectiveScope(scope: RunScope) {
    return {
      host: scope === "host" ? selectedHost || undefined : undefined,
      evidence_id: scope === "evidence" ? selectedEvidenceId || undefined : undefined,
    };
  }

  function buildDetectionsHref(source: string, runId: string | null) {
    if (!scopeCaseId) return "/detections";
    const params = new URLSearchParams();
    params.set("source", source);
    if (runId) params.set("rule_run_id", runId);
    if (selectedHost) params.set("host", selectedHost);
    if (selectedEvidenceId) params.set("evidence_id", selectedEvidenceId);
    return `/cases/${scopeCaseId}/detections?${params.toString()}`;
  }

  function buildSearchHref(source: string) {
    if (!scopeCaseId) return "/search";
    const params = new URLSearchParams({ tab: "results", q: `detection.source:${source}` });
    if (selectedHost) params.set("host", selectedHost);
    if (selectedEvidenceId) params.set("evidence_id", selectedEvidenceId);
    return `/cases/${scopeCaseId}/search?${params.toString()}`;
  }

  function buildTimelineHref() {
    if (!scopeCaseId) return "/timeline";
    const params = new URLSearchParams({ mode: "investigation" });
    if (selectedHost) params.set("host", selectedHost);
    if (selectedEvidenceId) params.set("evidence_id", selectedEvidenceId);
    return `/cases/${scopeCaseId}/timeline?${params.toString()}`;
  }

  function validateSingleRuleImport(file: File, expected: "sigma" | "yara") {
    const detected = engineFromFilename(file.name);
    if (expected === "sigma" && detected === "yara") {
      setSigmaImportSummary("This looks like a YARA rule. Switch to the YARA tab to import it.");
      return false;
    }
    if (expected === "yara" && detected === "sigma") {
      setYaraImportSummary("This looks like a Sigma rule. Switch to the Sigma tab to import it.");
      return false;
    }
    if (detected !== expected) {
      const message = expected === "sigma" ? "Upload one .yml or .yaml Sigma rule." : "Upload one .yar or .yara YARA rule.";
      if (expected === "sigma") setSigmaImportSummary(message);
      else setYaraImportSummary(message);
      return false;
    }
    return true;
  }

  function validateArchiveImport(file: File, expected: "sigma" | "yara") {
    if (engineFromFilename(file.name) !== "archive") {
      const message = expected === "sigma" ? "Upload a ZIP/TAR/7z archive containing Sigma rules." : "Upload a ZIP/TAR/7z archive containing YARA rules.";
      if (expected === "sigma") setSigmaImportSummary(message);
      else setYaraImportSummary(message);
      return false;
    }
    return true;
  }

  function handleSigmaFileImport(file: File) {
    if (!validateSingleRuleImport(file, "sigma")) return;
    importSingleMutation.mutate({ file, engine: "sigma" });
  }

  function handleSigmaArchiveImport(file: File) {
    if (!validateArchiveImport(file, "sigma")) return;
    importArchiveMutation.mutate({ file, engine: "sigma" });
  }

  function promoteCurrentCaseSigmaRules() {
    if (!scopeCaseId) {
      setLibraryBulkMessage("Select a case with case-scoped Sigma rules before promoting.");
      return;
    }
    const confirm = window.prompt(`Type ${SIGMA_GLOBAL_PROMOTION_CONFIRMATION} to promote case-scoped Sigma rules to global without duplicating rules.`);
    if (confirm !== SIGMA_GLOBAL_PROMOTION_CONFIRMATION) {
      setLibraryBulkMessage("Sigma promotion cancelled.");
      return;
    }
    promoteSigmaMutation.mutate({ caseId: scopeCaseId, confirm });
  }

  function handleYaraFileImport(file: File) {
    if (!validateSingleRuleImport(file, "yara")) return;
    importSingleMutation.mutate({ file, engine: "yara" });
  }

  function handleYaraArchiveImport(file: File) {
    if (!validateArchiveImport(file, "yara")) return;
    importArchiveMutation.mutate({ file, engine: "yara" });
  }

  function dismissImportBanner() {
    if (visibleImportRun?.id) {
      setDismissedImportRunIds((current) => (current.includes(visibleImportRun.id) ? current : [...current, visibleImportRun.id]));
    }
    setBannerImportRunId(null);
    setHideTerminalImportBanner(true);
    setImportFailure(null);
  }

  function requestCancelImport(run: RuleImportRun) {
    if (!isActiveImportStatus(run.status)) return;
    if (!window.confirm("Cancel this import? Rules already imported may remain.")) return;
    cancelImportMutation.mutate(run.id);
  }

  function toggleSigmaRule(ruleId: string) {
    setSelectedSigmaRuleIds((current) => (current.includes(ruleId) ? current.filter((item) => item !== ruleId) : [...current, ruleId]));
  }

  function toggleLibraryRule(ruleId: string) {
    setAllMatchingLibraryRulesSelected(false);
    setSelectedLibraryRuleIds((current) => (current.includes(ruleId) ? current.filter((item) => item !== ruleId) : [...current, ruleId]));
  }

  function toggleLibraryPack(packId: string) {
    setAllMatchingLibraryRulesSelected(false);
    setSelectedLibraryPackIds((current) => (current.includes(packId) ? current.filter((item) => item !== packId) : [...current, packId]));
  }

  function toggleRunSelection(runId: string) {
    setSelectedRunIds((current) => (current.includes(runId) ? current.filter((item) => item !== runId) : [...current, runId]));
  }

  function selectVisibleLibraryItems() {
    setAllMatchingLibraryRulesSelected(false);
    setSelectedLibraryRuleIds(filteredLibraryItems.filter((item) => item.kind === "rule").map((item) => item.id));
    setSelectedLibraryPackIds(filteredLibraryItems.filter((item) => item.kind === "pack").map((item) => item.id));
  }

  function selectAllMatchingLibraryRules() {
    setAllMatchingLibraryRulesSelected(true);
    setSelectedLibraryRuleIds(filteredLibraryItems.filter((item) => item.kind === "rule").map((item) => item.id));
    setSelectedLibraryPackIds(filteredLibraryItems.filter((item) => item.kind === "pack").map((item) => item.id));
  }

  function clearLibrarySelection() {
    setSelectedLibraryRuleIds([]);
    setSelectedLibraryPackIds([]);
    setAllMatchingLibraryRulesSelected(false);
  }

  function confirmLibraryAction(action: LibraryConfirmationAction, label: string, requirePhrase: string | null) {
    setPendingLibraryConfirmation({ action, label, requirePhrase });
    setConfirmationPhrase("");
  }

  function executePendingLibraryAction() {
    if (!pendingLibraryConfirmation) return;
    if (pendingLibraryConfirmation.requirePhrase && confirmationPhrase !== pendingLibraryConfirmation.requirePhrase) return;
    if (pendingLibraryConfirmation.action === "delete_selected") {
      bulkRuleDeleteMutation.mutate({ mode: "selected", ruleIds: selectedLibraryRuleIds, confirm: "DELETE RULES" });
      if (selectedLibraryPackIds.length) bulkPackDeleteMutation.mutate({ mode: "selected", packIds: selectedLibraryPackIds, confirm: RULE_PACKS_DELETE_CONFIRMATION });
      return;
    }
    if (pendingLibraryConfirmation.action === "delete_matching") {
      bulkRuleDeleteMutation.mutate({ mode: "matching", confirm: RULE_LIBRARY_DELETE_CONFIRMATION });
      return;
    }
    bulkRuleDeleteMutation.mutate({ mode: "all_imported", confirm: RULE_LIBRARY_DELETE_CONFIRMATION });
  }

  function deleteRulesFromImport(run: RuleImportRun) {
    const label = `Delete all rules from import ${run.source_name || run.pack_name || run.id}? Existing detections will remain unless explicitly deleted.`;
    setPendingLibraryConfirmation({ action: "delete_matching", label, requirePhrase: "DELETE RULES" });
    setConfirmationPhrase("");
    setLibraryImportRunFilter(run.id);
    setLibrarySourcePackFilter(run.pack_name || "");
  }

  function disableRulesFromImport(run: RuleImportRun) {
    bulkRuleUpdateMutation.mutate({ enabled: false, mode: "matching", importRunId: run.id, sourcePack: run.pack_name || undefined });
  }

  function runSigma() {
    if (!scopeCaseId) {
      setSigmaRunSummary({ engine: "sigma", status: "blocked", runId: null, message: "Select a case before running Sigma." });
      return;
    }
    const scope = effectiveScope(sigmaScope);
    if (sigmaScope === "host" && !selectedHost) {
      setSigmaRunSummary({ engine: "sigma", status: "blocked", runId: null, message: "Select a host first, or run Sigma on the current case." });
      return;
    }
    if (sigmaScope === "evidence" && !selectedEvidenceId) {
      setSigmaRunSummary({ engine: "sigma", status: "blocked", runId: null, message: "Select evidence first, or run Sigma on the current case." });
      return;
    }
    if (sigmaRunMode === "exhaustive" && !window.confirm("Run Sigma in Exhaustive mode? This may take a long time and create many detections.")) {
      return;
    }
    if (sigmaSelectionMode === "selected_rules") {
      if (!selectedSigmaRuleIds.length) {
        setSigmaRunSummary({ engine: "sigma", status: "blocked", runId: null, message: "Select at least one Sigma rule." });
        return;
      }
      bulkRunRulesMutation.mutate({ engine: "sigma", rule_ids: selectedSigmaRuleIds, run_mode: sigmaRunMode, ...scope });
      return;
    }
    bulkRunRulesMutation.mutate({ engine: "sigma", run_mode: sigmaRunMode, ...scope });
  }

  function smokePayload() {
    if (!scopeCaseId) {
      throw new Error("Select a case before running Sigma smoke.");
    }
    if (smokeMode === "single_rule" && !smokeRuleId) {
      throw new Error("Select one Sigma rule for single-rule smoke.");
    }
    return {
      case_id: scopeCaseId,
      evidence_id: selectedEvidenceId || undefined,
      host: selectedHost || undefined,
      mode: smokeMode,
      rule_id: smokeMode === "single_rule" ? smokeRuleId : undefined,
      rule_ids: smokeMode === "subset" ? selectedSigmaRuleIds : undefined,
      keyword: smokeKeyword || undefined,
      severity: smokeSeverity || undefined,
      max_rules: smokeMaxRules,
      max_detections_per_rule: 10,
      max_events_per_rule: 5000,
    };
  }

  function preflightSmoke() {
    try {
      smokePreflightMutation.mutate(smokePayload());
    } catch (error) {
      setSmokeMessage(error instanceof Error ? error.message : "Smoke preflight failed.");
    }
  }

  function runSmoke() {
    try {
      smokeRunMutation.mutate(smokePayload());
    } catch (error) {
      setSmokeMessage(error instanceof Error ? error.message : "Smoke run failed.");
    }
  }

  function runYara() {
    if (!scopeCaseId) {
      setYaraRunSummary({ engine: "yara", status: "blocked", runId: null, message: "Select a case before running YARA." });
      return;
    }
    if (yaraScope === "host" && !selectedHost) {
      setYaraRunSummary({ engine: "yara", status: "blocked", runId: null, message: "Select a host first, or run YARA on the current case." });
      return;
    }
    if (yaraScope === "evidence" && !selectedEvidenceId) {
      setYaraRunSummary({ engine: "yara", status: "blocked", runId: null, message: "Select evidence first, or run YARA on the current case." });
      return;
    }
    if (yaraSelectionMode === "selected_pack") {
      if (!selectedYaraPackId) {
        setYaraRunSummary({ engine: "yara", status: "blocked", runId: null, message: "Select one YARA rule pack." });
        return;
      }
      runRuleSetMutation.mutate(selectedYaraPackId);
      return;
    }
    if (yaraSelectionMode === "selected_rule") {
      if (!selectedYaraRuleId) {
        setYaraRunSummary({ engine: "yara", status: "blocked", runId: null, message: "Select one YARA rule." });
        return;
      }
      runRuleMutation.mutate({ ruleId: selectedYaraRuleId, engine: "yara" });
      return;
    }
    bulkRunRulesMutation.mutate({ engine: "yara", ...effectiveScope(yaraScope) });
  }

  async function handleDeleteLibraryItem(item: LibraryItem) {
    if (item.kind === "rule") await api.deleteRule(item.id);
    else await api.deleteRuleSet(item.id);
    await queryClient.invalidateQueries({ queryKey: [item.kind === "rule" ? "rules" : "rule-sets"] });
  }

  return (
    <div className="space-y-6">
      <section className="rounded-[28px] border border-line bg-panel/70 p-6 shadow-panel">
        <p className="font-mono text-xs uppercase tracking-[0.24em] text-accent">Rules</p>
        <h2 className="mt-2 text-2xl font-semibold">Sigma-first detection workflow for indexed events and preserved files.</h2>
        <p className="mt-2 text-sm text-muted">Use Sigma for indexed events, YARA for preserved files, and heuristics for built-in detections. Results always land in Detections so you can pivot into Search, Timeline, Findings and Reports.</p>
        <div className="mt-4 grid gap-3 md:grid-cols-4">
          {Object.entries(enginesQuery.data ?? {}).map(([engineName, engineStatus]) => (
            <div key={engineName} className="rounded-2xl border border-line bg-abyss/80 p-4 text-sm text-muted">
              <p className="font-mono text-[11px] uppercase tracking-[0.16em] text-accent">{engineName}</p>
              <p className="mt-2">{engineStatus.available ? "available" : "unavailable"}</p>
              <p className="mt-1 text-xs">Runs on: {engineStatus.runs_on}</p>
              {engineStatus.error ? <p className="mt-1 text-xs text-amber-300">{engineStatus.error}</p> : null}
            </div>
          ))}
        </div>
        <div className="mt-5 grid gap-4 md:grid-cols-[minmax(0,1fr)_minmax(0,1.6fr)]">
          <div className="rounded-2xl border border-line bg-abyss/80 p-4">
            <label className="block">
              <span className="mb-2 block font-mono text-[11px] uppercase tracking-[0.16em] text-muted">Current case scope</span>
              <select value={scopeCaseId} onChange={(event) => setScopeCaseId(event.target.value)} className="w-full rounded-xl border border-line bg-panel/70 px-3 py-2 text-sm">
                <option value="">No case selected</option>
                {(cases ?? []).map((item) => (
                  <option key={item.id} value={item.id}>
                    {item.name}
                  </option>
                ))}
              </select>
            </label>
            <label className="mt-3 block">
              <span className="mb-2 block font-mono text-[11px] uppercase tracking-[0.16em] text-muted">Import namespace</span>
              <input value={namespace} onChange={(event) => setNamespace(event.target.value)} placeholder="Optional namespace" className="w-full rounded-xl border border-line bg-panel/70 px-3 py-2 text-sm" />
            </label>
          </div>
          <Notice>
            <p className="font-semibold text-white">Where do results go?</p>
            <ul className="mt-3 space-y-2">
              <li>Detections: every Sigma, YARA or heuristic hit is stored here.</li>
              <li>Search: query detection hits such as <span className="font-mono">detection.source:sigma</span> or <span className="font-mono">detection.source:yara</span>.</li>
              <li>Timeline: pivot around detections to understand surrounding activity.</li>
              <li>Findings and Reports: reviewed detections can be promoted and included in analyst output.</li>
            </ul>
          </Notice>
        </div>
      </section>

      <section className="rounded-3xl border border-line bg-panel/70 p-5 shadow-panel">
        <div className="flex flex-wrap gap-2">
          {tabLabels.map((item) => (
            <button key={item.id} type="button" onClick={() => setTab(item.id)} className={`rounded-full border px-4 py-2 text-sm ${tab === item.id ? "border-accent bg-accent/10 text-ink" : "border-line bg-abyss/80 text-muted"}`}>
              {item.label}
            </button>
          ))}
        </div>
      </section>

      {visibleImportRun || pendingImport || importFailure ? (
        <section className={`rounded-3xl border p-5 shadow-panel ${visibleImportRun ? importBannerTone(visibleImportRun.status) : "border-danger/40 bg-danger/10 text-danger"}`}>
          {(() => {
            const perf = visibleImportRun ? importPerformance(visibleImportRun) : null;
            return (
          <>
          <div className="flex flex-wrap items-start justify-between gap-4">
            <div>
              <p className="font-mono text-xs uppercase tracking-[0.18em]">{visibleImportRun ? (isActiveImportStatus(visibleImportRun.status) ? "Active import" : "Latest import") : importFailure ? "Import failed" : "Importing rules"}</p>
              <h3 className="mt-2 text-xl font-semibold text-white">
                {visibleImportRun
                  ? isActiveImportStatus(visibleImportRun.status)
                    ? `${visibleImportRun.engine === "yara" ? "Importing YARA rule pack" : visibleImportRun.engine === "sigma" ? "Importing Sigma rule pack" : "Importing rule pack"}`
                    : `${visibleImportRun.engine === "yara" ? "YARA import" : visibleImportRun.engine === "sigma" ? "Sigma import" : "Rule import"} ${humanizeImportStatus(visibleImportRun.status).toLowerCase()}`
                  : importFailure
                    ? `Import failed for ${importFailure.sourceName}`
                    : pendingImport
                      ? `Importing ${pendingImport.engine === "yara" ? "YARA" : "Sigma"} ${pendingImport.sourceType === "archive" ? "rule pack" : "rule file"}...`
                      : "Importing rules..."}
              </h3>
              <p className="mt-2 text-sm text-muted">
                {visibleImportRun
                  ? `${describeImportProgress(visibleImportRun)}${visibleImportRun.current_file ? ` · Current file: ${visibleImportRun.current_file}` : ""}`
                  : importFailure
                    ? importFailure.message
                    : pendingImport
                      ? `${pendingImport.sourceType === "archive" ? "Extracting archive and discovering rules." : "Uploading and validating selected rule file."} The status card will stay visible while the import is in progress.`
                      : "Import in progress."}
              </p>
              {visibleImportRun?.cancel_requested && isActiveImportStatus(visibleImportRun.status) ? <p className="mt-2 text-sm text-amber-200">Cancel requested. The import will stop at the next checkpoint.</p> : null}
              {importRefreshError ? <p className="mt-2 text-sm text-amber-200">{importRefreshError}</p> : null}
            </div>
            <div className="flex flex-wrap gap-2">
              {visibleImportRun ? <button type="button" onClick={() => setSelectedImportRunId(visibleImportRun.id)} className="rounded-2xl border border-line bg-abyss/80 px-4 py-2 text-sm text-muted">View details</button> : null}
              {visibleImportRun ? <button type="button" onClick={() => openLibraryForImport(visibleImportRun)} className="rounded-2xl border border-line bg-abyss/80 px-4 py-2 text-sm text-muted">View imported rules</button> : null}
              {visibleImportRun && isActiveImportStatus(visibleImportRun.status) ? <button type="button" onClick={() => requestCancelImport(visibleImportRun)} disabled={visibleImportRun.cancel_requested || cancelImportMutation.isPending} className="rounded-2xl border border-danger/30 bg-danger/10 px-4 py-2 text-sm text-danger disabled:opacity-40">Cancel import</button> : null}
              {visibleImportRun && isTerminalImportStatus(visibleImportRun.status) ? <button type="button" onClick={dismissImportBanner} className="rounded-2xl border border-line bg-abyss/80 px-4 py-2 text-sm text-muted">Dismiss</button> : null}
            </div>
          </div>
          <div className="mt-4 overflow-hidden rounded-full bg-abyss/80">
            <div
              className={`h-3 rounded-full transition-all ${visibleImportRun ? (visibleImportRun.status === "failed" ? "bg-danger" : visibleImportRun.status === "completed_with_warnings" ? "bg-amber-300" : visibleImportRun.status === "completed" ? "bg-emerald-400" : "bg-accent") : "w-2/5 animate-pulse bg-danger"}`}
              style={visibleImportRun && visibleImportPercent != null ? { width: `${visibleImportPercent}%` } : visibleImportRun ? { width: "40%" } : undefined}
            />
          </div>
          <div className="mt-4 grid gap-3 md:grid-cols-2 xl:grid-cols-5">
            <div className="rounded-2xl border border-line bg-abyss/70 p-3 text-sm text-muted">
              <p className="font-mono text-[11px] uppercase tracking-[0.16em] text-accent">Phase</p>
              <p className="mt-1 text-white">{visibleImportRun ? humanizeImportStatus(visibleImportRun.current_phase || visibleImportRun.status) : importFailure ? "Failed" : "Uploading"}</p>
            </div>
            <div className="rounded-2xl border border-line bg-abyss/70 p-3 text-sm text-muted">
              <p className="font-mono text-[11px] uppercase tracking-[0.16em] text-accent">Progress</p>
              <p className="mt-1 text-white">
                {visibleImportRun
                  ? visibleImportPercent != null
                    ? `${visibleImportPercent}% · ${visibleImportRun.processed_files}/${visibleImportRun.total_files} files`
                    : humanizeImportStatus(visibleImportRun.status)
                  : pendingImport
                    ? "Working..."
                    : "-"}
              </p>
            </div>
            <div className="rounded-2xl border border-line bg-abyss/70 p-3 text-sm text-muted">
              <p className="font-mono text-[11px] uppercase tracking-[0.16em] text-accent">Imported</p>
              <p className="mt-1 text-white">{importCountsKnown(visibleImportRun) ? `${visibleImportRun?.imported_count ?? 0} · updated ${visibleImportRun?.updated_count ?? 0}` : "Discovering rules..."}</p>
            </div>
            <div className="rounded-2xl border border-line bg-abyss/70 p-3 text-sm text-muted">
              <p className="font-mono text-[11px] uppercase tracking-[0.16em] text-accent">Validation</p>
              <p className="mt-1 text-white">{importCountsKnown(visibleImportRun) ? `invalid ${visibleImportRun?.invalid_count ?? 0} · unsupported ${visibleImportRun?.unsupported_count ?? 0}` : "Waiting for validation..."}</p>
            </div>
            <div className="rounded-2xl border border-line bg-abyss/70 p-3 text-sm text-muted">
              <p className="font-mono text-[11px] uppercase tracking-[0.16em] text-accent">Duplicates</p>
              <p className="mt-1 text-white">{importCountsKnown(visibleImportRun) ? `${visibleImportRun?.duplicate_count ?? 0} · warnings ${visibleImportRun?.warning_count ?? 0}` : "Not counted yet"}</p>
            </div>
            <div className="rounded-2xl border border-line bg-abyss/70 p-3 text-sm text-muted">
              <p className="font-mono text-[11px] uppercase tracking-[0.16em] text-accent">Performance</p>
              <p className="mt-1 text-white">{visibleImportRun ? `${perf?.filesPerSecond ?? 0} files/s · ${perf?.rulesPerSecond ?? 0} rules/s` : "-"}</p>
            </div>
          </div>
          </>
            );
          })()}
        </section>
      ) : null}

      {tab === "sigma" ? (
        <div className="space-y-6">
          <section className="grid gap-4 md:grid-cols-2 xl:grid-cols-4">
            <MetricCard label="Available Sigma rules" value={rulesLoading ? "Loading..." : String(sigmaAvailableRules)} detail={`${sigmaCaseRules} case-scoped · ${sigmaGlobalRules} global Sigma rules available.`} />
            <MetricCard label="Global Sigma rules" value={rulesLoading ? "Loading..." : String(sigmaGlobalRules)} detail="Global rules remain available when a case is selected." />
            <MetricCard label="Case Sigma rules" value={rulesLoading ? "Loading..." : String(sigmaCaseRules)} detail={scopeCaseId ? `Rules scoped to the selected case. ${sigmaAllCaseScopedRules} case-scoped Sigma rules exist across all cases.` : `${sigmaAllCaseScopedRules} case-scoped Sigma rules exist across all cases.`} />
            <MetricCard label="Enabled Sigma rules" value={rulesLoading ? "Loading..." : String(sigmaEnabledRules)} detail="Rules currently runnable in this scope when you choose all enabled Sigma rules." />
            <MetricCard label="Last Sigma run" value={lastSigmaRun?.status ?? "none"} detail={lastSigmaRun ? `${lastSigmaRun.created_detections} detections · ${lastSigmaRun.matched} matches` : "No Sigma run has been recorded yet."} />
            <MetricCard label="Sigma detections" value={String(sigmaDetectionsQuery.data?.total ?? 0)} detail="Current case detections with source=sigma." />
            <MetricCard label="Scope" value={scopeCaseId ? "case active" : "no case"} detail={`${selectedHost ? `Host ${selectedHost}` : "All hosts"} · ${selectedEvidenceId ? `Evidence ${selectedEvidenceId.slice(0, 8)}` : "All evidence"}`} />
          </section>

          {!rulesLoading && scopeCaseId && sigmaCaseRules === 0 && sigmaGlobalRules > 0 ? (
            <Notice>
              0 case-scoped rules · {sigmaGlobalRules} global Sigma rules available for this case.
            </Notice>
          ) : null}

          {!rulesLoading && scopeCaseId && sigmaAvailableRules === 0 && sigmaGlobalRules === 0 && sigmaAllCaseScopedRules > 0 ? (
            <Notice tone="warning">
              0 rules available for the selected case · {sigmaAllCaseScopedRules} Sigma rules exist in other case scopes. Select that case or import/promote rules deliberately.
            </Notice>
          ) : null}

          {sigmaLibraryMissingAfterImports ? (
            <Notice tone="warning">
              <p className="font-semibold text-white">Sigma import history exists, but no Sigma rules are currently stored.</p>
              <p className="mt-2">The rule library is empty in the database for this scope. Imports remain visible for audit, but their rule rows are missing and must be restored or reimported deliberately.</p>
            </Notice>
          ) : null}

          <SectionCard title="Sigma coverage and scope" subtitle="Coverage is based on the current Sigma compiler, logsource support and normalized field mappings. It is a support report, not an assumption that every rule is safe to run.">
            <div className="grid gap-4 md:grid-cols-2 xl:grid-cols-4">
              <MetricCard label="Fully supported" value={sigmaCoverageQuery.isLoading ? "Loading..." : String(sigmaCoverageQuery.data?.fully_supported ?? 0)} detail="Compiled rules with known logsource and non-generic mappings." />
              <MetricCard label="Partial support" value={sigmaCoverageQuery.isLoading ? "Loading..." : String(sigmaCoverageQuery.data?.partial ?? 0)} detail="Runnable rules with missing/ambiguous logsource or generic field mappings." />
              <MetricCard label="Unsupported" value={sigmaCoverageQuery.isLoading ? "Loading..." : String(sigmaCoverageQuery.data?.unsupported ?? 0)} detail="Rules skipped by the current internal Sigma engine." />
              <MetricCard label="Mapping risk" value={sigmaCoverageQuery.isLoading ? "Loading..." : String(sigmaCoverageQuery.data?.false_positive_risk_count ?? 0)} detail="Field/logsource conditions that need analyst caution." />
            </div>
            <div className="mt-4 flex flex-wrap items-center gap-3">
              <span className="text-sm text-muted">Filter coverage:</span>
              {[
                ["", "All"],
                ["fully_supported", "Fully supported"],
                ["partially_supported", "Partial"],
                ["unsupported", "Unsupported"],
              ].map(([value, label]) => (
                <button key={value || "all"} type="button" onClick={() => setSigmaCoverageFilter(value)} className={`rounded-2xl border px-3 py-1.5 text-sm ${sigmaCoverageFilter === value ? "border-accent bg-accent/15 text-white" : "border-line bg-abyss/80 text-muted"}`}>
                  {label}
                </button>
              ))}
            </div>
            <div className="mt-4 grid gap-4 lg:grid-cols-3">
              <div className="rounded-2xl border border-line bg-abyss/80 p-4 text-sm text-muted">
                <p className="font-semibold text-white">Top products</p>
                <div className="mt-3 space-y-2">
                  {Object.entries(sigmaCoverageQuery.data?.by_product ?? {}).slice(0, 6).map(([key, value]) => (
                    <div key={key} className="flex justify-between gap-3"><span>{key}</span><span className="font-mono text-white">{value}</span></div>
                  ))}
                </div>
              </div>
              <div className="rounded-2xl border border-line bg-abyss/80 p-4 text-sm text-muted">
                <p className="font-semibold text-white">Top categories</p>
                <div className="mt-3 space-y-2">
                  {Object.entries(sigmaCoverageQuery.data?.by_category ?? {}).slice(0, 6).map(([key, value]) => (
                    <div key={key} className="flex justify-between gap-3"><span>{key}</span><span className="font-mono text-white">{value}</span></div>
                  ))}
                </div>
              </div>
              <div className="rounded-2xl border border-line bg-abyss/80 p-4 text-sm text-muted">
                <p className="font-semibold text-white">Top missing fields</p>
                <div className="mt-3 space-y-2">
                  {(sigmaCoverageQuery.data?.top_missing_fields ?? []).slice(0, 6).map((item) => (
                    <div key={String(item.field)} className="flex justify-between gap-3"><span>{String(item.field)}</span><span className="font-mono text-white">{String(item.count)}</span></div>
                  ))}
                  {!(sigmaCoverageQuery.data?.top_missing_fields ?? []).length ? <p>No missing field mappings detected in this scope.</p> : null}
                </div>
              </div>
            </div>
            <div className="mt-4 overflow-x-auto rounded-2xl border border-line">
              <table className="min-w-full divide-y divide-line text-sm">
                <thead className="bg-abyss/80 text-left text-[11px] uppercase tracking-[0.16em] text-muted">
                  <tr>
                    <th className="px-3 py-3">Rule</th>
                    <th className="px-3 py-3">Coverage</th>
                    <th className="px-3 py-3">Logsource</th>
                    <th className="px-3 py-3">Reasons</th>
                    <th className="px-3 py-3">Action</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-line bg-panel/50 text-muted">
                  {(sigmaCoverageListQuery.data?.items ?? []).map((item) => (
                    <tr key={String(item.rule_id)}>
                      <td className="px-3 py-3 text-white">{String(item.title || item.name || item.rule_id)}</td>
                      <td className="px-3 py-3">{String(item.status || item.support_status || "-")}</td>
                      <td className="px-3 py-3">{String((item.logsource as Record<string, unknown> | undefined)?.product || "unknown")} / {String((item.logsource as Record<string, unknown> | undefined)?.category || "unknown")} / {String((item.logsource as Record<string, unknown> | undefined)?.service || "unknown")}</td>
                      <td className="px-3 py-3">{((item.unsupported_reasons as string[] | undefined) ?? (item.risky_reasons as string[] | undefined) ?? []).slice(0, 3).join(", ") || "-"}</td>
                      <td className="px-3 py-3"><button type="button" onClick={() => setViewRuleId(String(item.rule_id))} className="rounded-xl border border-line px-3 py-1 text-xs text-muted">Details</button></td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
            {scopeCaseId && sigmaCaseRules > 0 ? (
              <div className="mt-4 rounded-2xl border border-accent/30 bg-accent/10 p-4 text-sm text-muted">
                <p className="font-semibold text-white">Promote case-scoped Sigma rules to global</p>
                <p className="mt-2">Global Sigma rules are recommended for imports because they remain available to every case. Promotion copies case rules into the global library, keeps the case copy, creates before/after snapshots, and suppresses duplicate execution.</p>
                <button type="button" onClick={promoteCurrentCaseSigmaRules} disabled={promoteSigmaMutation.isPending} className="mt-4 rounded-2xl bg-accent px-4 py-2 text-sm font-semibold text-abyss disabled:cursor-not-allowed disabled:opacity-50">
                  Promote case Sigma rules to global
                </button>
              </div>
            ) : null}
            {libraryBulkMessage ? <p className="mt-3 text-sm text-muted">{libraryBulkMessage}</p> : null}
          </SectionCard>

          <SectionCard title="Sigma rules" subtitle="Run behavior rules against indexed events in the selected case, host or evidence.">
            <Notice>
              Sigma scans indexed events. It does not scan raw files.
            </Notice>
            <div className="mt-4 grid gap-4 md:grid-cols-2">
              <div className="rounded-2xl border border-line bg-abyss/80 p-4">
                <p className="font-semibold">Import Sigma rule</p>
                <p className="mt-2 text-sm text-muted">Upload one <span className="font-mono">.yml</span> or <span className="font-mono">.yaml</span> Sigma rule. Global import is the default and recommended scope.</p>
                <label className="mt-4 inline-flex cursor-pointer rounded-2xl border border-line bg-panel/50 px-4 py-2 text-sm text-muted">
                  Import global Sigma rule
                  <input className="hidden" type="file" onChange={(event) => event.target.files?.[0] && handleSigmaFileImport(event.target.files[0])} />
                </label>
              </div>
              <div className="rounded-2xl border border-line bg-abyss/80 p-4">
                <p className="font-semibold">Import Sigma rule pack</p>
                <p className="mt-2 text-sm text-muted">Upload a ZIP/TAR/7z containing multiple Sigma YAML rules. Global import is recommended so the pack is available to all cases.</p>
                <label className="mt-4 inline-flex cursor-pointer rounded-2xl border border-line bg-panel/50 px-4 py-2 text-sm text-muted">
                  Import global Sigma rule pack
                  <input className="hidden" type="file" onChange={(event) => event.target.files?.[0] && handleSigmaArchiveImport(event.target.files[0])} />
                </label>
              </div>
            </div>
            {sigmaImportSummary ? <pre className="mt-4 whitespace-pre-wrap rounded-2xl border border-line bg-abyss/80 p-4 text-sm text-muted">{sigmaImportSummary}</pre> : null}
            {renderImportSummary(sigmaImportResult, "Latest Sigma import")}
          </SectionCard>

          <SectionCard title="Rule Imports" subtitle="Recent Sigma or mixed import runs, including duplicates, unsupported rules and invalid files.">
            <div className="overflow-x-auto rounded-2xl border border-line">
              <table className="min-w-full divide-y divide-line text-sm">
                <thead className="bg-abyss/80 text-left text-[11px] uppercase tracking-[0.16em] text-muted">
                  <tr>
                    <th className="px-3 py-3">Source</th>
                    <th className="px-3 py-3">Status</th>
                    <th className="px-3 py-3">Imported</th>
                    <th className="px-3 py-3">Updated</th>
                    <th className="px-3 py-3">Duplicates</th>
                    <th className="px-3 py-3">Invalid</th>
                    <th className="px-3 py-3">Unsupported</th>
                    <th className="px-3 py-3">Duration</th>
                    <th className="px-3 py-3">Actions</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-line bg-panel/50 text-muted">
                  {sigmaImportRuns.length ? sigmaImportRuns.map((run) => (
                    <tr key={run.id}>
                      <td className="px-3 py-3">{run.source_name || run.pack_name || run.id}</td>
                      <td className="px-3 py-3">{run.status}</td>
                      <td className="px-3 py-3">{run.imported_count}</td>
                      <td className="px-3 py-3">{run.updated_count}</td>
                      <td className="px-3 py-3">{run.duplicate_count}</td>
                      <td className="px-3 py-3">{run.invalid_count}</td>
                      <td className="px-3 py-3">{run.unsupported_count}</td>
                      <td className="px-3 py-3">{formatElapsed(run.elapsed_seconds ? Math.round(run.elapsed_seconds) : null)}</td>
                      <td className="px-3 py-3">
                        <div className="flex flex-wrap gap-2">
                          <button type="button" onClick={() => setSelectedImportRunId(run.id)} className="rounded-xl border border-line bg-abyss/80 px-3 py-2 text-xs text-muted">Open import details</button>
                          <button type="button" onClick={() => openLibraryForImport(run)} className="rounded-xl border border-line bg-abyss/80 px-3 py-2 text-xs text-muted">View imported rules</button>
                        </div>
                      </td>
                    </tr>
                  )) : <tr><td className="px-3 py-4 text-sm text-muted" colSpan={9}>No Sigma import history yet.</td></tr>}
                </tbody>
              </table>
            </div>
          </SectionCard>

          <SectionCard title="Sigma Smoke Test" subtitle="Validate one rule or a small compatible subset without running the whole pack. Smoke detections are tagged separately.">
            <div className="grid gap-4 lg:grid-cols-5">
              <label className="block rounded-2xl border border-line bg-abyss/80 p-4">
                <span className="mb-2 block font-mono text-[11px] uppercase tracking-[0.16em] text-muted">Mode</span>
                <select value={smokeMode} onChange={(event) => setSmokeMode(event.target.value as typeof smokeMode)} className="w-full rounded-xl border border-line bg-panel/70 px-3 py-2 text-sm">
                  <option value="recommended">Recommended set</option>
                  <option value="single_rule">Single rule</option>
                  <option value="subset">Selected subset</option>
                </select>
              </label>
              <label className="block rounded-2xl border border-line bg-abyss/80 p-4">
                <span className="mb-2 block font-mono text-[11px] uppercase tracking-[0.16em] text-muted">Rule</span>
                <select value={smokeRuleId} onChange={(event) => setSmokeRuleId(event.target.value)} disabled={smokeMode !== "single_rule"} className="w-full rounded-xl border border-line bg-panel/70 px-3 py-2 text-sm disabled:opacity-50">
                  <option value="">Select a rule</option>
                  {sigmaRules.slice(0, 250).map((rule) => <option key={rule.id} value={rule.id}>{rule.title || rule.name}</option>)}
                </select>
              </label>
              <label className="block rounded-2xl border border-line bg-abyss/80 p-4">
                <span className="mb-2 block font-mono text-[11px] uppercase tracking-[0.16em] text-muted">Keyword</span>
                <input value={smokeKeyword} onChange={(event) => setSmokeKeyword(event.target.value)} placeholder="powershell, remote-admin..." className="w-full rounded-xl border border-line bg-panel/70 px-3 py-2 text-sm" />
              </label>
              <label className="block rounded-2xl border border-line bg-abyss/80 p-4">
                <span className="mb-2 block font-mono text-[11px] uppercase tracking-[0.16em] text-muted">Severity</span>
                <select value={smokeSeverity} onChange={(event) => setSmokeSeverity(event.target.value)} className="w-full rounded-xl border border-line bg-panel/70 px-3 py-2 text-sm">
                  <option value="">Any</option>
                  <option value="critical">Critical</option>
                  <option value="high">High</option>
                  <option value="medium">Medium</option>
                  <option value="low">Low</option>
                </select>
              </label>
              <label className="block rounded-2xl border border-line bg-abyss/80 p-4">
                <span className="mb-2 block font-mono text-[11px] uppercase tracking-[0.16em] text-muted">Max rules</span>
                <input type="number" min={1} max={10} value={smokeMaxRules} onChange={(event) => setSmokeMaxRules(Number(event.target.value) || 5)} className="w-full rounded-xl border border-line bg-panel/70 px-3 py-2 text-sm" />
              </label>
            </div>
            <div className="mt-4 flex flex-wrap items-center gap-3">
              <button type="button" onClick={preflightSmoke} disabled={!scopeCaseId || smokePreflightMutation.isPending || smokeRunMutation.isPending} className="rounded-2xl border border-line bg-panel/50 px-4 py-2 text-sm text-muted disabled:cursor-not-allowed disabled:opacity-50">
                Preflight smoke
              </button>
              <button type="button" onClick={runSmoke} disabled={!scopeCaseId || smokePreflightMutation.isPending || smokeRunMutation.isPending} className="rounded-2xl bg-accent px-4 py-2 text-sm font-semibold text-abyss disabled:cursor-not-allowed disabled:opacity-50">
                Run smoke test
              </button>
              {smokeResult?.run_id ? <Link to={`/cases/${smokeResult.case_id}/detections?rule_run_id=${smokeResult.run_id}&run_type=smoke`} className="rounded-2xl border border-line bg-abyss/80 px-4 py-2 text-sm text-muted">Open smoke detections</Link> : null}
              <span className="text-xs text-muted">Caps: 10 detections per rule · 5,000 candidate events per rule.</span>
            </div>
            {smokeMessage ? <p className="mt-3 text-sm text-muted">{smokeMessage}</p> : null}
            {smokeResult ? (
              <div className="mt-4 overflow-x-auto rounded-2xl border border-line">
                <table className="min-w-full divide-y divide-line text-sm">
                  <thead className="bg-abyss/80 text-left text-[11px] uppercase tracking-[0.16em] text-muted">
                    <tr>
                      <th className="px-3 py-3">Rule</th>
                      <th className="px-3 py-3">Status</th>
                      <th className="px-3 py-3">Matches</th>
                      <th className="px-3 py-3">Scanned</th>
                      <th className="px-3 py-3">Logsource</th>
                      <th className="px-3 py-3">Fields</th>
                    </tr>
                  </thead>
                  <tbody className="divide-y divide-line bg-panel/50 text-muted">
                    {smokeResult.rules.map((rule) => (
                      <tr key={rule.rule_id}>
                        <td className="px-3 py-3">
                          <p className="font-semibold text-white">{rule.title || rule.rule_name}</p>
                          {rule.sample_detection_ids[0] ? <Link className="text-xs text-accent" to={`/cases/${smokeResult.case_id}/detections?rule_run_id=${smokeResult.run_id}&run_type=smoke`}>Open sample detection</Link> : null}
                        </td>
                        <td className="px-3 py-3">{rule.status.replaceAll("_", " ")}</td>
                        <td className="px-3 py-3">{rule.matched} · {rule.created_detections} created</td>
                        <td className="px-3 py-3">{rule.scanned_events}</td>
                        <td className="px-3 py-3"><pre className="max-w-xs whitespace-pre-wrap text-xs">{JSON.stringify(rule.expected_logsource)}</pre></td>
                        <td className="px-3 py-3">{rule.missing_fields.length ? `Missing: ${rule.missing_fields.join(", ")}` : `${Object.keys(rule.field_mappings).length} mappings`}</td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            ) : null}
          </SectionCard>

          <SectionCard title="Run Sigma" subtitle="Choose scope and selection. Sigma runs against indexed events already normalized into the selected case.">
            <div className="grid gap-4 lg:grid-cols-4">
              <label className="block rounded-2xl border border-line bg-abyss/80 p-4">
                <span className="mb-2 block font-mono text-[11px] uppercase tracking-[0.16em] text-muted">Scope</span>
                <select aria-label="Sigma scope" value={sigmaScope} onChange={(event) => setSigmaScope(event.target.value as RunScope)} className="w-full rounded-xl border border-line bg-panel/70 px-3 py-2 text-sm">
                  <option value="case">Current case</option>
                  <option value="host">Current host</option>
                  <option value="evidence">Current evidence</option>
                </select>
              </label>
              <label className="block rounded-2xl border border-line bg-abyss/80 p-4">
                <span className="mb-2 block font-mono text-[11px] uppercase tracking-[0.16em] text-muted">Rule selection</span>
                <select aria-label="Sigma rule selection" value={sigmaSelectionMode} onChange={(event) => setSigmaSelectionMode(event.target.value as SigmaSelectionMode)} className="w-full rounded-xl border border-line bg-panel/70 px-3 py-2 text-sm">
                  <option value="all_enabled">All enabled Sigma rules</option>
                  <option value="selected_rules">Selected rules</option>
                </select>
              </label>
              <label className="block rounded-2xl border border-line bg-abyss/80 p-4">
                <span className="mb-2 block font-mono text-[11px] uppercase tracking-[0.16em] text-muted">Run mode</span>
                <select aria-label="Sigma run mode" value={sigmaRunMode} onChange={(event) => setSigmaRunMode(event.target.value as SigmaRunMode)} className="w-full rounded-xl border border-line bg-panel/70 px-3 py-2 text-sm">
                  <option value="fast_triage">Fast triage</option>
                  <option value="balanced">Balanced</option>
                  <option value="exhaustive">Exhaustive</option>
                </select>
                <p className="mt-2 text-xs text-muted">
                  {sigmaRunMode === "fast_triage"
                    ? "Quick first pass. Caps noisy rules and prioritizes signal."
                    : sigmaRunMode === "exhaustive"
                      ? "Runs more broadly. May take longer and create many detections."
                      : "Recommended. Runs compatible rules with safety limits."}
                </p>
              </label>
              <div className="rounded-2xl border border-line bg-abyss/80 p-4">
                <span className="mb-2 block font-mono text-[11px] uppercase tracking-[0.16em] text-muted">Selected scope</span>
                <p className="text-sm text-muted">{sigmaScope === "host" ? (selectedHost || "No host selected") : sigmaScope === "evidence" ? (selectedEvidenceId || "No evidence selected") : scopeCaseId || "No case selected"}</p>
              </div>
            </div>
            {sigmaSelectionMode === "selected_rules" ? (
              <div className="mt-4 rounded-2xl border border-line bg-abyss/80 p-4">
                <p className="text-sm font-semibold">Selected Sigma rules</p>
                <div className="mt-3 grid gap-2 md:grid-cols-2">
                  {sigmaRules.map((rule) => (
                    <label key={rule.id} className="flex items-start gap-3 rounded-xl border border-line bg-panel/40 px-3 py-3 text-sm text-muted">
                      <input type="checkbox" checked={selectedSigmaRuleIds.includes(rule.id)} onChange={() => toggleSigmaRule(rule.id)} />
                      <span>
                        <span className="block text-white">{rule.title || rule.name}</span>
                        <span className="mt-1 block text-xs">{rule.namespace || "no namespace"} · {rule.severity || "no severity"}</span>
                      </span>
                    </label>
                  ))}
                </div>
              </div>
            ) : null}
            <div className="mt-4 flex flex-wrap items-center gap-3">
              <button type="button" onClick={runSigma} disabled={!scopeCaseId || bulkRunRulesMutation.isPending || runRuleMutation.isPending} className="rounded-2xl bg-accent px-4 py-2 text-sm font-semibold text-abyss disabled:cursor-not-allowed disabled:opacity-50">
                Run Sigma on selected scope
              </button>
              <Link to={buildSearchHref("sigma")} className="rounded-2xl border border-line bg-abyss/80 px-4 py-2 text-sm text-muted">
                Search Sigma hits
              </Link>
            </div>
            {sigmaRunSummary ? (
              <div className="mt-4 rounded-2xl border border-line bg-abyss/80 p-4">
                <p className="font-semibold text-white">Sigma run summary</p>
                <p className="mt-2 text-sm text-muted">{sigmaRunSummary.message}</p>
                <p className="mt-1 text-xs text-muted">Status: {sigmaRunSummary.status}{sigmaRunSummary.runId ? ` · run id ${sigmaRunSummary.runId}` : ""}</p>
                <div className="mt-4 flex flex-wrap gap-3">
                  <Link to={buildDetectionsHref("sigma", sigmaRunSummary.runId)} className="rounded-2xl border border-line bg-panel/50 px-4 py-2 text-sm text-muted">
                    Open Detections
                  </Link>
                  <Link to={buildSearchHref("sigma")} className="rounded-2xl border border-line bg-panel/50 px-4 py-2 text-sm text-muted">
                    Search Sigma hits
                  </Link>
                  <Link to={buildTimelineHref()} className="rounded-2xl border border-line bg-panel/50 px-4 py-2 text-sm text-muted">
                    Open Search Timeline around detections
                  </Link>
                </div>
              </div>
            ) : null}
          </SectionCard>
        </div>
      ) : null}

      {tab === "yara" ? (
        <div className="space-y-6">
          <section className="grid gap-4 md:grid-cols-2 xl:grid-cols-4">
            <MetricCard label="Imported YARA rules" value={String(yaraImportedRules)} detail="Single-file YARA rules imported into the current scope." />
            <MetricCard label="Enabled YARA rules" value={String(yaraEnabledRules)} detail="Rules currently runnable when you choose all enabled YARA rules." />
            <MetricCard label="Last YARA run" value={lastYaraRun?.status ?? "none"} detail={lastYaraRun ? `${lastYaraRun.created_detections} detections · ${lastYaraRun.scanned_files} files scanned` : "No YARA run has been recorded yet."} />
            <MetricCard label="YARA packs / detections" value={`${yaraImportedPacks} / ${yaraDetectionsQuery.data?.total ?? 0}`} detail="Imported YARA rule packs and current case detections with source=yara." />
          </section>

          <SectionCard title="YARA rules" subtitle="Scan preserved files, scripts and documents. YARA does not run over indexed event logs.">
            <Notice>
              Large file scans can take time. Use filters and max file size to keep runs focused.
            </Notice>
            <div className="mt-4 grid gap-4 md:grid-cols-2">
              <div className="rounded-2xl border border-line bg-abyss/80 p-4">
                <p className="font-semibold">Import YARA rule</p>
                <p className="mt-2 text-sm text-muted">Upload one <span className="font-mono">.yar</span> or <span className="font-mono">.yara</span> file.</p>
                <label className="mt-4 inline-flex cursor-pointer rounded-2xl border border-line bg-panel/50 px-4 py-2 text-sm text-muted">
                  Import YARA rule
                  <input className="hidden" type="file" onChange={(event) => event.target.files?.[0] && handleYaraFileImport(event.target.files[0])} />
                </label>
              </div>
              <div className="rounded-2xl border border-line bg-abyss/80 p-4">
                <p className="font-semibold">Import YARA rule pack</p>
                <p className="mt-2 text-sm text-muted">Upload a ZIP/TAR/7z with multiple YARA files.</p>
                <label className="mt-4 inline-flex cursor-pointer rounded-2xl border border-line bg-panel/50 px-4 py-2 text-sm text-muted">
                  Import YARA rule pack
                  <input className="hidden" type="file" onChange={(event) => event.target.files?.[0] && handleYaraArchiveImport(event.target.files[0])} />
                </label>
              </div>
            </div>
            {yaraImportSummary ? <pre className="mt-4 whitespace-pre-wrap rounded-2xl border border-line bg-abyss/80 p-4 text-sm text-muted">{yaraImportSummary}</pre> : null}
            {renderImportSummary(yaraImportResult, "Latest YARA import")}
          </SectionCard>

          <SectionCard title="Rule Imports" subtitle="Recent YARA or mixed imports with validation and duplicate/update feedback.">
            <div className="overflow-x-auto rounded-2xl border border-line">
              <table className="min-w-full divide-y divide-line text-sm">
                <thead className="bg-abyss/80 text-left text-[11px] uppercase tracking-[0.16em] text-muted">
                  <tr>
                    <th className="px-3 py-3">Source</th>
                    <th className="px-3 py-3">Status</th>
                    <th className="px-3 py-3">Imported</th>
                    <th className="px-3 py-3">Updated</th>
                    <th className="px-3 py-3">Duplicates</th>
                    <th className="px-3 py-3">Invalid</th>
                    <th className="px-3 py-3">Warnings</th>
                    <th className="px-3 py-3">Duration</th>
                    <th className="px-3 py-3">Actions</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-line bg-panel/50 text-muted">
                  {yaraImportRuns.length ? yaraImportRuns.map((run) => (
                    <tr key={run.id}>
                      <td className="px-3 py-3">{run.source_name || run.pack_name || run.id}</td>
                      <td className="px-3 py-3">{run.status}</td>
                      <td className="px-3 py-3">{run.imported_count}</td>
                      <td className="px-3 py-3">{run.updated_count}</td>
                      <td className="px-3 py-3">{run.duplicate_count}</td>
                      <td className="px-3 py-3">{run.invalid_count}</td>
                      <td className="px-3 py-3">{run.warning_count}</td>
                      <td className="px-3 py-3">{formatElapsed(run.elapsed_seconds ? Math.round(run.elapsed_seconds) : null)}</td>
                      <td className="px-3 py-3">
                        <div className="flex flex-wrap gap-2">
                          <button type="button" onClick={() => setSelectedImportRunId(run.id)} className="rounded-xl border border-line bg-abyss/80 px-3 py-2 text-xs text-muted">Open import details</button>
                          <button type="button" onClick={() => openLibraryForImport(run)} className="rounded-xl border border-line bg-abyss/80 px-3 py-2 text-xs text-muted">View imported rules</button>
                        </div>
                      </td>
                    </tr>
                  )) : <tr><td className="px-3 py-4 text-sm text-muted" colSpan={9}>No YARA import history yet.</td></tr>}
                </tbody>
              </table>
            </div>
          </SectionCard>

          <SectionCard title="Run YARA file scan" subtitle="Choose a YARA rule or rule pack, then limit the scan scope to the current case, host or evidence when possible.">
            <Notice>
              YARA scans preserved files, not indexed event logs.
            </Notice>
            <div className="mt-4 grid gap-4 lg:grid-cols-3">
              <label className="block rounded-2xl border border-line bg-abyss/80 p-4">
                <span className="mb-2 block font-mono text-[11px] uppercase tracking-[0.16em] text-muted">Scope</span>
                <select aria-label="YARA scope" value={yaraScope} onChange={(event) => setYaraScope(event.target.value as RunScope)} className="w-full rounded-xl border border-line bg-panel/70 px-3 py-2 text-sm">
                  <option value="case">Current case</option>
                  <option value="host">Current host</option>
                  <option value="evidence">Current evidence</option>
                </select>
              </label>
              <label className="block rounded-2xl border border-line bg-abyss/80 p-4">
                <span className="mb-2 block font-mono text-[11px] uppercase tracking-[0.16em] text-muted">Run mode</span>
                <select aria-label="YARA rule selection" value={yaraSelectionMode} onChange={(event) => setYaraSelectionMode(event.target.value as YaraSelectionMode)} className="w-full rounded-xl border border-line bg-panel/70 px-3 py-2 text-sm">
                  <option value="selected_pack">Selected YARA rule pack</option>
                  <option value="selected_rule">Selected single YARA rule</option>
                  <option value="all_enabled">All enabled YARA rules</option>
                </select>
              </label>
              <div className="rounded-2xl border border-line bg-abyss/80 p-4">
                <span className="mb-2 block font-mono text-[11px] uppercase tracking-[0.16em] text-muted">Selected scope</span>
                <p className="text-sm text-muted">{yaraScope === "host" ? (selectedHost || "No host selected") : yaraScope === "evidence" ? (selectedEvidenceId || "No evidence selected") : scopeCaseId || "No case selected"}</p>
              </div>
            </div>
            <div className="mt-4 grid gap-4 lg:grid-cols-2">
              <label className="block rounded-2xl border border-line bg-abyss/80 p-4">
                <span className="mb-2 block font-mono text-[11px] uppercase tracking-[0.16em] text-muted">Selected YARA rule</span>
                <select aria-label="Selected YARA rule" value={selectedYaraRuleId} onChange={(event) => setSelectedYaraRuleId(event.target.value)} className="w-full rounded-xl border border-line bg-panel/70 px-3 py-2 text-sm">
                  <option value="">Choose a YARA rule</option>
                  {yaraRules.map((rule) => (
                    <option key={rule.id} value={rule.id}>
                      {rule.title || rule.name}
                    </option>
                  ))}
                </select>
              </label>
              <label className="block rounded-2xl border border-line bg-abyss/80 p-4">
                <span className="mb-2 block font-mono text-[11px] uppercase tracking-[0.16em] text-muted">Selected YARA rule pack</span>
                <select aria-label="Selected YARA rule pack" value={selectedYaraPackId} onChange={(event) => setSelectedYaraPackId(event.target.value)} className="w-full rounded-xl border border-line bg-panel/70 px-3 py-2 text-sm">
                  <option value="">Choose a YARA rule pack</option>
                  {yaraRulePacks.map((ruleSet) => (
                    <option key={ruleSet.id} value={ruleSet.id}>
                      {ruleSet.name}
                    </option>
                  ))}
                </select>
              </label>
            </div>
            <div className="mt-4 grid gap-3 rounded-2xl border border-line bg-abyss/80 p-4 md:grid-cols-2 xl:grid-cols-4">
              <label className="flex items-center gap-3 text-sm text-muted">
                <input type="checkbox" checked={includeParsedOutputs} onChange={(event) => setIncludeParsedOutputs(event.target.checked)} />
                Include parsed CSV/JSON outputs
              </label>
              <label className="flex items-center gap-3 text-sm text-muted">
                <input type="checkbox" checked={includeArchives} onChange={(event) => setIncludeArchives(event.target.checked)} />
                Include archives
              </label>
              <label className="flex items-center gap-3 text-sm text-muted">
                <input type="checkbox" checked={includeTextOutputs} onChange={(event) => setIncludeTextOutputs(event.target.checked)} />
                Include text/log files
              </label>
              <label className="flex items-center gap-3 text-sm text-muted">
                Max file size MB
                <input type="number" min={1} max={2048} value={maxFileSizeMb} onChange={(event) => setMaxFileSizeMb(Number(event.target.value) || 100)} className="w-24 rounded-xl border border-line bg-panel/60 px-3 py-2 text-sm" />
              </label>
            </div>
            <div className="mt-4 flex flex-wrap items-center gap-3">
              <button type="button" onClick={runYara} disabled={!scopeCaseId || bulkRunRulesMutation.isPending || runRuleMutation.isPending || runRuleSetMutation.isPending || !enginesQuery.data?.yara?.available} className="rounded-2xl bg-accent px-4 py-2 text-sm font-semibold text-abyss disabled:cursor-not-allowed disabled:opacity-50">
                Run YARA file scan
              </button>
              <Link to={buildSearchHref("yara")} className="rounded-2xl border border-line bg-abyss/80 px-4 py-2 text-sm text-muted">
                Search YARA hits
              </Link>
            </div>
            {yaraRunSummary ? (
              <div className="mt-4 rounded-2xl border border-line bg-abyss/80 p-4">
                <p className="font-semibold text-white">YARA run summary</p>
                <p className="mt-2 text-sm text-muted">{yaraRunSummary.message}</p>
                <p className="mt-1 text-xs text-muted">Status: {yaraRunSummary.status}{yaraRunSummary.runId ? ` · run id ${yaraRunSummary.runId}` : ""}</p>
                <div className="mt-4 flex flex-wrap gap-3">
                  <Link to={buildDetectionsHref("yara", yaraRunSummary.runId)} className="rounded-2xl border border-line bg-panel/50 px-4 py-2 text-sm text-muted">
                    Open Detections
                  </Link>
                  <Link to={buildSearchHref("yara")} className="rounded-2xl border border-line bg-panel/50 px-4 py-2 text-sm text-muted">
                    Search YARA hits
                  </Link>
                </div>
              </div>
            ) : null}
          </SectionCard>
        </div>
      ) : null}

      {tab === "heuristics" ? (
        <div className="space-y-6">
          <section className="grid gap-4 md:grid-cols-2 xl:grid-cols-4">
            <MetricCard label="Available heuristic rules" value={String(heuristicRules.length)} detail="Built-in and uploaded heuristic rules over normalized events." />
            <MetricCard label="Heuristic detections" value={String(heuristicDetectionsQuery.data?.total ?? 0)} detail="Current case detections with source=heuristic." />
            <MetricCard label="Last heuristic run" value={sigmaRuns.find((run) => run.engine === "heuristic")?.status ?? "automatic"} detail="Heuristic detections are usually generated automatically during ingest and correlation." />
            <MetricCard label="Destination" value="Detections" detail="Review heuristic hits in Detections before promoting them to findings." />
          </section>
          <SectionCard title="Heuristics" subtitle="Built-in heuristic detections are generated automatically from normalized events during ingest and correlation.">
            <Notice>
              Heuristics are not file scans. They operate on normalized event context and appear in Detections alongside Sigma and YARA results.
            </Notice>
            <div className="mt-4 flex flex-wrap gap-3">
              <Link to={buildDetectionsHref("heuristic", null)} className="rounded-2xl border border-line bg-abyss/80 px-4 py-2 text-sm text-muted">
                Open heuristic detections
              </Link>
              <Link to="/system/performance" className="rounded-2xl border border-line bg-abyss/80 px-4 py-2 text-sm text-muted">
                Review heuristic settings
              </Link>
            </div>
          </SectionCard>
        </div>
      ) : null}

      {tab === "runs" ? (
        <SectionCard title="Rule Runs" subtitle="Review queued and completed Sigma, YARA and heuristic runs for the current case.">
          <div className="mb-4 flex flex-wrap gap-3">
            <button type="button" onClick={() => api.markAbandonedRuleRunsStale({ case_id: scopeCaseId || undefined, older_than_minutes: 10 }).then((result) => { setRunBulkMessage(`Marked ${result.updated} abandoned runs stale.`); void queryClient.invalidateQueries({ queryKey: ["case-rule-runs"] }); })} className="rounded-2xl border border-line bg-abyss/80 px-4 py-2 text-sm text-muted">
              Mark abandoned runs stale
            </button>
            <button type="button" onClick={() => bulkRunActionMutation.mutate({ action: "mark_stale", mode: "matching" })} className="rounded-2xl border border-line bg-abyss/80 px-4 py-2 text-sm text-muted">
              Mark stale runs
            </button>
            <button type="button" onClick={() => bulkRunActionMutation.mutate({ action: "cancel", mode: "selected", runIds: selectedRunIds })} disabled={!selectedRunIds.length} className="rounded-2xl border border-line bg-abyss/80 px-4 py-2 text-sm text-muted disabled:opacity-40">
              Cancel selected
            </button>
            <button type="button" onClick={() => bulkRunActionMutation.mutate({ action: "retry", mode: "selected", runIds: selectedRunIds })} disabled={!selectedRunIds.length} className="rounded-2xl border border-line bg-abyss/80 px-4 py-2 text-sm text-muted disabled:opacity-40">
              Retry selected
            </button>
            <button type="button" onClick={() => bulkRunActionMutation.mutate({ action: "delete", mode: "selected", runIds: selectedRunIds })} disabled={!selectedRunIds.length} className="rounded-2xl border border-danger/30 bg-danger/10 px-4 py-2 text-sm text-danger disabled:opacity-40">
              Delete selected run records
            </button>
          </div>
          {runBulkMessage ? <Notice>{runBulkMessage}</Notice> : null}
          <div className="overflow-x-auto">
            <table className="min-w-full divide-y divide-line text-sm">
              <thead className="text-left text-muted">
                <tr>
                  <th className="px-3 py-2">
                    <input aria-label="Select all rule runs" type="checkbox" checked={Boolean(ruleRunsQuery.data?.length) && selectedRunIds.length === (ruleRunsQuery.data?.length ?? 0)} onChange={(event) => setSelectedRunIds(event.target.checked ? (ruleRunsQuery.data ?? []).map((run) => run.id) : [])} />
                  </th>
                  <th className="px-3 py-2">Run id</th>
                  <th className="px-3 py-2">Engine</th>
                  <th className="px-3 py-2">Scope</th>
                  <th className="px-3 py-2">Status</th>
                  <th className="px-3 py-2">Progress</th>
                  <th className="px-3 py-2">Rules</th>
                  <th className="px-3 py-2">Scanned</th>
                  <th className="px-3 py-2">Detections</th>
                  <th className="px-3 py-2">Started</th>
                  <th className="px-3 py-2">Elapsed</th>
                  <th className="px-3 py-2">Actions</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-line/60">
                {(ruleRunsQuery.data ?? []).map((run) => {
                  const runSource = readRuleRunSource(run);
                  const eventsInScope = runMetric(run, "events_in_scope") ?? run.total_events ?? 0;
                  const candidateEvaluations = runMetric(run, "candidate_event_evaluations") ?? runMetric(run, "candidate_events_prefiltered") ?? run.scanned_events;
                  const scannedValue = run.engine === "yara"
                    ? `${run.scanned_files} / ${run.total_files || 0} files`
                    : `${eventsInScope} events in scope · ${candidateEvaluations} candidate evaluations`;
                  return (
                    <tr key={run.id}>
                      <td className="px-3 py-3">
                        <input aria-label={`Select run ${run.id}`} type="checkbox" checked={selectedRunIds.includes(run.id)} onChange={() => toggleRunSelection(run.id)} />
                      </td>
                      <td className="px-3 py-3 font-mono text-xs text-muted">{run.id}</td>
                      <td className="px-3 py-3">{run.engine}</td>
                      <td className="px-3 py-3">{run.scope}</td>
                      <td className="px-3 py-3">
                        <div className="flex flex-col gap-1">
                          <span>{displayRunStatus(run)}</span>
                          {run.stale ? <span className="text-xs text-amber-300">No heartbeat for {heartbeatLabel(run.heartbeat_at)}</span> : null}
                        </div>
                      </td>
                      <td className="px-3 py-3">
                        <div className="min-w-44">
                          <div className="h-2 overflow-hidden rounded-full bg-abyss/80">
                            <div
                              className="h-full rounded-full bg-accent transition-all"
                              style={{ width: `${Math.max(0, Math.min(100, run.percent_complete ?? 0))}%` }}
                            />
                          </div>
                          <p className="mt-2 text-xs text-muted">
                            {run.percent_complete != null ? `${run.percent_complete}%` : "progress unavailable"} · {run.processed_rules} / {run.total_rules || 0} rules
                          </p>
                          <p className="mt-1 text-xs text-muted">phase: {run.current_phase || "unknown"} · heartbeat: {heartbeatLabel(run.heartbeat_at)}</p>
                          {run.stale ? <p className="mt-1 text-xs text-amber-300">stale</p> : null}
                        </div>
                      </td>
                      <td className="px-3 py-3">{run.processed_rules} / {run.total_rules || 0}</td>
                      <td className="px-3 py-3">
                        <div className="flex flex-col gap-1">
                          <span>{scannedValue}</span>
                          {(run.scanned_events === 0 && run.scanned_files === 0) || (run.total_events === 0 && run.total_files === 0) ? <span className="text-xs text-muted">{zeroScanExplanation(run)}</span> : null}
                        </div>
                      </td>
                      <td className="px-3 py-3">{runMetric(run, "matches_found") ?? run.matched} matches · {run.created_detections} created · {run.duplicates} duplicates</td>
                      <td className="px-3 py-3">{run.started_at ? new Date(run.started_at).toLocaleString() : "-"}</td>
                      <td className="px-3 py-3">{formatElapsed(run.elapsed_seconds)}</td>
                      <td className="px-3 py-3">
                        <div className="flex flex-wrap gap-2">
                          {runSource ? (
                            <Link to={buildDetectionsHref(runSource, run.id)} className="rounded-xl border border-line bg-abyss/80 px-3 py-1.5 text-xs text-muted">
                              Open detections
                            </Link>
                          ) : null}
                          {runSource ? (
                            <Link to={buildSearchHref(runSource)} className="rounded-xl border border-line bg-abyss/80 px-3 py-1.5 text-xs text-muted">
                              Search hits
                            </Link>
                          ) : null}
                          <button type="button" onClick={() => setSelectedRunId(run.id)} className="rounded-xl border border-line bg-abyss/80 px-3 py-1.5 text-xs text-muted">
                            View run details
                          </button>
                          {(run.can_cancel ?? (run.status === "queued" || run.status === "running" || run.status === "stale")) ? (
                            <button type="button" onClick={() => cancelRunMutation.mutate(run.id)} className="rounded-xl border border-line bg-abyss/80 px-3 py-1.5 text-xs text-muted">
                              Cancel run
                            </button>
                          ) : null}
                          {run.stale ? (
                            <button type="button" onClick={() => markStaleRunMutation.mutate(run.id)} className="rounded-xl border border-amber-400/40 bg-amber-400/10 px-3 py-1.5 text-xs text-amber-100">
                              Mark failed/stale
                            </button>
                          ) : null}
                          {(run.can_retry ?? ["completed", "failed", "cancelled", "stale", "skipped"].includes(run.status)) ? (
                            <button type="button" onClick={() => retryRunMutation.mutate(run.id)} className="rounded-xl border border-line bg-abyss/80 px-3 py-1.5 text-xs text-muted">
                              Retry run
                            </button>
                          ) : null}
                          <button type="button" onClick={() => deleteRunMutation.mutate(run.id)} className="rounded-xl border border-danger/30 bg-danger/10 px-3 py-1.5 text-xs text-danger">
                            Delete run record
                          </button>
                        </div>
                      </td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
          </div>
          {selectedRunId ? (
            <div role="dialog" aria-label="Rule run details" className="mt-6 rounded-2xl border border-line bg-abyss/80 p-4">
              <div className="flex items-start justify-between gap-4">
                <div>
                  <h3 className="text-base font-semibold text-white">Rule run details</h3>
                  <p className="mt-1 font-mono text-xs text-muted">{selectedRunId}</p>
                </div>
                <button type="button" onClick={() => setSelectedRunId(null)} className="rounded-xl border border-line bg-panel/50 px-3 py-1.5 text-xs text-muted">
                  Close
                </button>
              </div>
              {selectedRunQuery.data ? (
                <div className="mt-4 grid gap-4 md:grid-cols-2">
                  <div className="rounded-2xl border border-line bg-panel/40 p-4 text-sm text-muted">
                    <p>Engine: <span className="text-white">{selectedRunQuery.data.engine}</span></p>
                    <p className="mt-2">Run mode: <span className="text-white">{sigmaRunModeLabel(String(selectedRunQuery.data.metadata_json?.sigma_run_mode || ""))}</span></p>
                    <p className="mt-2">Scope: <span className="text-white">{selectedRunQuery.data.scope}</span></p>
                    <p className="mt-2">Status: <span className="text-white">{displayRunStatus(selectedRunQuery.data)}</span></p>
                    <p className="mt-2">Phase: <span className="text-white">{selectedRunQuery.data.current_phase || "unknown"}</span></p>
                    <p className="mt-2">Elapsed: <span className="text-white">{formatElapsed(selectedRunQuery.data.elapsed_seconds)}</span></p>
                    <p className="mt-2">Heartbeat: <span className="text-white">{heartbeatLabel(selectedRunQuery.data.heartbeat_at)}</span></p>
                    <p className="mt-2">Cancel requested: <span className="text-white">{selectedRunQuery.data.cancel_requested ? "yes" : "no"}</span></p>
                    <p className="mt-2">Stale reason: <span className="text-white">{selectedRunQuery.data.stale_reason || "-"}</span></p>
                  </div>
                  <div className="rounded-2xl border border-line bg-panel/40 p-4 text-sm text-muted">
                    <p>Rules: <span className="text-white">{selectedRunQuery.data.processed_rules} / {selectedRunQuery.data.total_rules}</span></p>
                    <p className="mt-2">Considered / runnable: <span className="text-white">{runMetric(selectedRunQuery.data, "total_rules_considered") ?? selectedRunQuery.data.total_rules} / {runMetric(selectedRunQuery.data, "total_rules_runnable") ?? selectedRunQuery.data.processed_rules}</span></p>
                    <p className="mt-2">Executed / skipped: <span className="text-white">{runMetric(selectedRunQuery.data, "total_rules_executed") ?? selectedRunQuery.data.processed_rules} / {runMetric(selectedRunQuery.data, "total_rules_skipped") ?? 0}</span></p>
                    <p className="mt-2">Events in scope: <span className="text-white">{runMetric(selectedRunQuery.data, "events_in_scope") ?? selectedRunQuery.data.total_events}</span></p>
                    <p className="mt-2">Candidate evaluations: <span className="text-white">{runMetric(selectedRunQuery.data, "candidate_event_evaluations") ?? runMetric(selectedRunQuery.data, "candidate_events_prefiltered") ?? selectedRunQuery.data.scanned_events}</span></p>
                    <p className="mt-2">Scanned files: <span className="text-white">{selectedRunQuery.data.scanned_files} / {selectedRunQuery.data.total_files}</span></p>
                    <p className="mt-2">Matches found: <span className="text-white">{runMetric(selectedRunQuery.data, "matches_found") ?? selectedRunQuery.data.matched}</span></p>
                    <p className="mt-2">Detections: <span className="text-white">{selectedRunQuery.data.created_detections}</span></p>
                    <p className="mt-2">Duplicates: <span className="text-white">{selectedRunQuery.data.duplicates}</span></p>
                    <p className="mt-2">Warnings: <span className="text-white">{selectedRunQuery.data.warnings.length}</span></p>
                    <p className="mt-2">Runtime errors: <span className="text-white">{runMetric(selectedRunQuery.data, "rules_runtime_error") ?? 0}</span></p>
                    <p className="mt-2">Query / dedupe / write: <span className="text-white">{runMetric(selectedRunQuery.data, "query_time_ms_total") ?? 0}ms / {runMetric(selectedRunQuery.data, "dedupe_time_ms_total") ?? 0}ms / {runMetric(selectedRunQuery.data, "write_time_ms_total") ?? 0}ms</span></p>
                    <p className="mt-2">Noisy / capped rules: <span className="text-white">{runMetric(selectedRunQuery.data, "noisy_rules_count") ?? 0} / {runMetric(selectedRunQuery.data, "capped_rules_count") ?? 0}</span></p>
                    <p className="mt-2">Skipped too broad / matches capped / detections capped: <span className="text-white">{runMetric(selectedRunQuery.data, "skipped_too_broad_count") ?? 0} / {runMetric(selectedRunQuery.data, "matches_capped_count") ?? 0} / {runMetric(selectedRunQuery.data, "detections_capped_count") ?? 0}</span></p>
                    {runMetric(selectedRunQuery.data, "current_rule_matches") != null ? (
                      <div className="mt-3 rounded-2xl border border-line/60 bg-abyss/60 p-3">
                        <p className="text-xs font-semibold uppercase tracking-[0.22em] text-muted">Current rule</p>
                        <p className="mt-2 text-xs">Title: <span className="text-white">{(selectedRunQuery.data.metadata_json?.current_rule_title as string) || "-"}</span></p>
                        <p className="mt-1 text-xs">Matches / created / duplicates: <span className="text-white">{runMetric(selectedRunQuery.data, "current_rule_matches") ?? 0} / {runMetric(selectedRunQuery.data, "current_rule_created") ?? 0} / {runMetric(selectedRunQuery.data, "current_rule_duplicates") ?? 0}</span></p>
                        <p className="mt-1 text-xs">Duration: <span className="text-white">{runMetric(selectedRunQuery.data, "current_rule_duration_ms") ?? 0}ms</span></p>
                      </div>
                    ) : null}
                    {(runMetric(selectedRunQuery.data, "capped_rules_count") ?? 0) > 0 ? (
                      <div className="mt-3 rounded-2xl border border-amber-400/30 bg-amber-400/10 p-3 text-xs text-amber-100">
                        Some rules produced too many matches and were capped to keep the run usable.
                      </div>
                    ) : null}
                    {Array.isArray(selectedRunQuery.data.metadata_json?.top_noisy_rules) && selectedRunQuery.data.metadata_json?.top_noisy_rules.length ? (
                      <div className="mt-3 rounded-2xl border border-line/60 bg-abyss/60 p-3">
                        <p className="text-xs font-semibold uppercase tracking-[0.22em] text-muted">Top noisy rules</p>
                        <div className="mt-2 space-y-1 text-xs">
                          {(selectedRunQuery.data.metadata_json?.top_noisy_rules as Array<Record<string, unknown>>).slice(0, 5).map((item, index) => (
                            <p key={`${String(item.rule_id ?? item.rule_name ?? index)}`}>{String(item.rule_name ?? item.rule_id ?? `Rule ${index + 1}`)}: <span className="text-white">{String(item.matches_found ?? item.duplicates ?? 0)}</span>{item.reason ? <span className="text-muted"> · {String(item.reason)}</span> : null}</p>
                          ))}
                        </div>
                      </div>
                    ) : null}
                    {Object.keys(runMapMetric(selectedRunQuery.data, "skipped_by_reason")).length ? (
                      <div className="mt-3 rounded-2xl border border-line/60 bg-abyss/60 p-3">
                        <p className="text-xs font-semibold uppercase tracking-[0.22em] text-muted">Skipped by reason</p>
                        <div className="mt-2 space-y-1 text-xs">
                          {Object.entries(runMapMetric(selectedRunQuery.data, "skipped_by_reason")).map(([reason, count]) => (
                            <p key={reason}>{reason}: <span className="text-white">{String(count)}</span></p>
                          ))}
                        </div>
                      </div>
                    ) : null}
                    <div className="mt-3 rounded-2xl border border-line/60 bg-abyss/60 p-3">
                      <p className="text-xs font-semibold uppercase tracking-[0.22em] text-muted">Case compatibility</p>
                      <div className="mt-2 space-y-1 text-xs">
                        <p>Applicable to case: <span className="text-white">{String(caseCompatibility(selectedRunQuery.data).applicable_to_case ?? 0)}</span></p>
                        <p>Skipped platform: <span className="text-white">{String(caseCompatibility(selectedRunQuery.data).skipped_platform ?? 0)}</span></p>
                        <p>Skipped logsource: <span className="text-white">{String(caseCompatibility(selectedRunQuery.data).skipped_logsource ?? 0)}</span></p>
                        <p>Skipped missing fields in case: <span className="text-white">{String(caseCompatibility(selectedRunQuery.data).skipped_missing_fields_in_case ?? 0)}</span></p>
                        <p>Skipped too broad: <span className="text-white">{String(caseCompatibility(selectedRunQuery.data).skipped_too_broad ?? 0)}</span></p>
                        <p>Runtime error: <span className="text-white">{String(caseCompatibility(selectedRunQuery.data).runtime_error ?? 0)}</span></p>
                      </div>
                    </div>
                  </div>
                </div>
              ) : (
                <p className="mt-4 text-sm text-muted">Loading run details…</p>
              )}
            </div>
          ) : null}
        </SectionCard>
      ) : null}

      {tab === "library" ? (
        <div className="space-y-6">
          <SectionCard title="Rule Library" subtitle="Manage Sigma, YARA, heuristic rules and imported rule packs from a single table.">
            <div className="grid gap-4 md:grid-cols-2 xl:grid-cols-4">
              <input value={librarySearch} onChange={(event) => setLibrarySearch(event.target.value)} placeholder="Search title, description or source" className="rounded-2xl border border-line bg-abyss/80 px-4 py-3 text-sm" />
              <select value={libraryEngineFilter} onChange={(event) => setLibraryEngineFilter(event.target.value)} className="rounded-2xl border border-line bg-abyss/80 px-4 py-3 text-sm">
                <option value="">All engines</option>
                <option value="sigma">sigma</option>
                <option value="yara">yara</option>
                <option value="heuristic">heuristic</option>
              </select>
              <select value={librarySeverityFilter} onChange={(event) => setLibrarySeverityFilter(event.target.value)} className="rounded-2xl border border-line bg-abyss/80 px-4 py-3 text-sm">
                <option value="">All severities</option>
                <option value="critical">critical</option>
                <option value="high">high</option>
                <option value="medium">medium</option>
                <option value="low">low</option>
                <option value="info">info</option>
              </select>
              <select value={libraryNamespaceFilter} onChange={(event) => setLibraryNamespaceFilter(event.target.value)} className="rounded-2xl border border-line bg-abyss/80 px-4 py-3 text-sm">
                <option value="">All namespaces</option>
                {namespaceOptions.map((option) => (
                  <option key={option} value={option}>
                    {option}
                  </option>
                ))}
              </select>
              <select value={libraryStateFilter} onChange={(event) => setLibraryStateFilter(event.target.value)} className="rounded-2xl border border-line bg-abyss/80 px-4 py-3 text-sm">
                <option value="">All states</option>
                <option value="enabled">Enabled</option>
                <option value="disabled">Disabled</option>
              </select>
            </div>
            <div className="mt-4 grid gap-4 md:grid-cols-3">
              <select value={libraryImportRunFilter} onChange={(event) => setLibraryImportRunFilter(event.target.value)} className="rounded-2xl border border-line bg-abyss/80 px-4 py-3 text-sm">
                <option value="">All import runs</option>
                {importRunFilterOptions.map((option) => (
                  <option key={option.id} value={option.id}>{option.label}</option>
                ))}
              </select>
              <select value={librarySourcePackFilter} onChange={(event) => setLibrarySourcePackFilter(event.target.value)} className="rounded-2xl border border-line bg-abyss/80 px-4 py-3 text-sm">
                <option value="">All source packs</option>
                {sourcePackOptions.map((option) => (
                  <option key={option} value={option}>{option}</option>
                ))}
              </select>
              <select value={libraryImportStatusFilter} onChange={(event) => setLibraryImportStatusFilter(event.target.value)} className="rounded-2xl border border-line bg-abyss/80 px-4 py-3 text-sm">
                <option value="">All import statuses</option>
                <option value="imported">Imported</option>
                <option value="updated">Updated</option>
                <option value="duplicate">Duplicate</option>
              </select>
            </div>
            <div className="mt-4 flex flex-wrap gap-3">
              <button type="button" onClick={selectVisibleLibraryItems} className="rounded-2xl border border-line bg-abyss/80 px-4 py-2 text-sm text-muted">
                Select visible page
              </button>
              <button type="button" onClick={selectAllMatchingLibraryRules} className="rounded-2xl border border-line bg-abyss/80 px-4 py-2 text-sm text-muted">
                Select all matching
              </button>
              <button type="button" onClick={clearLibrarySelection} className="rounded-2xl border border-line bg-abyss/80 px-4 py-2 text-sm text-muted">
                Clear selection
              </button>
              <button type="button" onClick={() => bulkRuleUpdateMutation.mutate({ enabled: true, mode: "selected", ruleIds: selectedLibraryRuleIds })} disabled={!selectedLibraryRuleIds.length} className="rounded-2xl border border-line bg-abyss/80 px-4 py-2 text-sm text-muted disabled:opacity-40">
                Enable selected
              </button>
              <button type="button" onClick={() => bulkRuleUpdateMutation.mutate({ enabled: false, mode: "selected", ruleIds: selectedLibraryRuleIds })} disabled={!selectedLibraryRuleIds.length} className="rounded-2xl border border-line bg-abyss/80 px-4 py-2 text-sm text-muted disabled:opacity-40">
                Disable selected
              </button>
              <button type="button" onClick={() => confirmLibraryAction("delete_selected", `Delete ${selectedLibraryRuleIds.length + selectedLibraryPackIds.length} selected rules/packs?`, null)} disabled={!selectedLibraryRuleIds.length && !selectedLibraryPackIds.length} className="rounded-2xl border border-danger/30 bg-danger/10 px-4 py-2 text-sm text-danger disabled:opacity-40">
                Delete selected
              </button>
              <button type="button" onClick={() => confirmLibraryAction("delete_matching", `Delete all ${filteredLibraryItems.filter((item) => item.kind === "rule").length} rules matching current filters? This cannot be undone.`, RULE_LIBRARY_DELETE_CONFIRMATION)} className="rounded-2xl border border-danger/30 bg-danger/10 px-4 py-2 text-sm text-danger">
                Delete all matching
              </button>
              <button type="button" onClick={() => confirmLibraryAction("delete_all_imported", "Delete all imported rules. Built-in heuristics will be protected.", RULE_LIBRARY_DELETE_CONFIRMATION)} className="rounded-2xl border border-danger/30 bg-danger/10 px-4 py-2 text-sm text-danger">
                Delete all imported rules
              </button>
            </div>
            <p className="mt-3 text-sm text-muted">
              {allMatchingLibraryRulesSelected
                ? `All ${filteredLibraryItems.length} matching rules/packs selected.`
                : `${selectedLibraryRuleIds.length + selectedLibraryPackIds.length} selected.`}
            </p>
            <p className="mt-3 text-xs text-muted">Built-in heuristic rules are protected from delete-imported operations.</p>
            <p className="mt-1 text-xs text-muted">Existing detections will remain unless explicitly deleted in a separate cleanup flow.</p>
            {libraryBulkMessage ? <div className="mt-4"><Notice>{libraryBulkMessage}</Notice></div> : null}
            {pendingLibraryConfirmation ? (
              <div className="mt-4 rounded-2xl border border-danger/30 bg-danger/10 p-4">
                <p className="text-sm font-semibold text-white">{pendingLibraryConfirmation.label}</p>
                <p className="mt-2 text-sm text-muted">Future runs will not use deleted rules. Existing detections will remain.</p>
                {pendingLibraryConfirmation.requirePhrase ? (
                  <label className="mt-3 block">
                    <span className="mb-2 block text-sm text-muted">Type <span className="font-mono text-white">{pendingLibraryConfirmation.requirePhrase}</span> to confirm.</span>
                    <input value={confirmationPhrase} onChange={(event) => setConfirmationPhrase(event.target.value)} className="w-full rounded-xl border border-line bg-abyss/80 px-3 py-2 text-sm" />
                  </label>
                ) : null}
                <div className="mt-3 flex gap-3">
                  <button type="button" onClick={executePendingLibraryAction} disabled={Boolean(pendingLibraryConfirmation.requirePhrase) && confirmationPhrase !== pendingLibraryConfirmation.requirePhrase} className="rounded-2xl border border-danger/30 bg-danger/20 px-4 py-2 text-sm text-danger disabled:opacity-40">
                    Confirm
                  </button>
                  <button type="button" onClick={() => { setPendingLibraryConfirmation(null); setConfirmationPhrase(""); }} className="rounded-2xl border border-line bg-abyss/80 px-4 py-2 text-sm text-muted">
                    Cancel
                  </button>
                </div>
              </div>
            ) : null}
          </SectionCard>
          <section className="space-y-4">
            {filteredLibraryItems.map((item) => {
              const lastRun = item.kind === "rule" ? lastRunByRule.get(item.id) : lastRunByRuleSet.get(item.id);
              return (
                <article key={`${item.kind}-${item.id}`} className="rounded-3xl border border-line bg-panel/70 p-5 shadow-panel">
                  <div className="flex flex-wrap items-start justify-between gap-4">
                    <div className="flex gap-3">
                      <input
                        aria-label={item.kind === "pack" ? `Select pack ${item.title}` : `Select rule ${item.title}`}
                        type="checkbox"
                        checked={item.kind === "pack" ? selectedLibraryPackIds.includes(item.id) : selectedLibraryRuleIds.includes(item.id)}
                        onChange={() => (item.kind === "pack" ? toggleLibraryPack(item.id) : toggleLibraryRule(item.id))}
                      />
                      <div>
                      <div className="flex flex-wrap items-center gap-2">
                        <h3 className="text-base font-semibold">{item.title}</h3>
                        <span className="rounded-full border border-line px-3 py-1 font-mono text-[11px] uppercase tracking-[0.16em] text-accent">{item.engine}</span>
                        <span className="rounded-full border border-line px-3 py-1 font-mono text-[11px] uppercase tracking-[0.16em] text-muted">{item.kind === "pack" ? "rule pack" : "single rule"}</span>
                        <span className={`rounded-full border px-3 py-1 font-mono text-[11px] uppercase tracking-[0.16em] ${item.enabled ? "border-mint/30 bg-mint/10 text-mint" : "border-line bg-abyss/70 text-muted"}`}>{item.enabled ? "enabled" : "disabled"}</span>
                      </div>
                      <p className="mt-2 text-sm text-muted">{item.description || "No description."}</p>
                      <p className="mt-3 text-xs text-muted">{item.namespace || "no namespace"} · {item.severity || "no severity"} · {item.source_label || "no source label"}</p>
                      <p className="mt-1 text-xs text-muted">Import run: {item.import_run_id || "n/a"} · Source pack: {item.source_pack || "n/a"} · Import status: {item.import_status || "n/a"}</p>
                      </div>
                    </div>
                    <div className="text-right text-xs text-muted">
                      <p>Updated {new Date(item.updated_at).toLocaleString()}</p>
                      {lastRun ? <p className="mt-1">Last run: {lastRun.status} · {lastRun.created_detections} detections</p> : null}
                    </div>
                  </div>
                  <div className="mt-4 flex flex-wrap gap-3">
                    <button type="button" onClick={() => (item.kind === "rule" ? setViewRuleId(item.id) : setViewRuleSetId(item.id))} className="rounded-2xl border border-line bg-abyss/80 px-4 py-2 text-sm text-muted">
                      View rule
                    </button>
                    <button type="button" onClick={() => (item.kind === "rule" ? toggleRuleMutation.mutate(item.id) : toggleRuleSetMutation.mutate(item.id))} className="rounded-2xl border border-line bg-abyss/80 px-4 py-2 text-sm text-muted">
                      {item.enabled ? "Disable" : "Enable"}
                    </button>
                    {item.kind === "rule" ? (
                      <button type="button" disabled={!scopeCaseId} onClick={() => runRuleMutation.mutate({ ruleId: item.id, engine: item.engine === "yara" ? "yara" : "sigma" })} className="rounded-2xl border border-line bg-abyss/80 px-4 py-2 text-sm text-muted disabled:cursor-not-allowed disabled:opacity-50">
                        Run selected
                      </button>
                    ) : (
                      <button type="button" disabled={!scopeCaseId} onClick={() => runRuleSetMutation.mutate(item.id)} className="rounded-2xl border border-line bg-abyss/80 px-4 py-2 text-sm text-muted disabled:cursor-not-allowed disabled:opacity-50">
                        Run selected
                      </button>
                    )}
                    <button type="button" onClick={() => void handleDeleteLibraryItem(item)} className="rounded-2xl border border-danger/30 bg-danger/10 px-4 py-2 text-sm text-danger">
                      Delete
                    </button>
                  </div>
                </article>
              );
            })}
          </section>
        </div>
      ) : null}

      {viewRuleId && viewRuleQuery.data ? (
        <section className="rounded-3xl border border-line bg-panel/85 p-5 shadow-panel">
          <div className="flex items-center justify-between gap-4">
            <div>
              <p className="font-mono text-xs uppercase tracking-[0.18em] text-accent">Rule content</p>
              <h3 className="mt-2 text-xl font-semibold">{viewRuleQuery.data.name}</h3>
            </div>
            <button onClick={() => setViewRuleId(null)} className="rounded-2xl border border-line bg-abyss/80 px-4 py-2 text-sm text-muted">Close</button>
          </div>
          <div className="mt-4 grid gap-3 md:grid-cols-4">
            <div className="rounded-2xl border border-line bg-abyss/80 p-3 text-sm text-muted">Engine: {viewRuleQuery.data.engine}</div>
            <div className="rounded-2xl border border-line bg-abyss/80 p-3 text-sm text-muted">Severity: {viewRuleQuery.data.severity || "-"}</div>
            <div className="rounded-2xl border border-line bg-abyss/80 p-3 text-sm text-muted">Namespace: {viewRuleQuery.data.namespace || "-"}</div>
            <div className="rounded-2xl border border-line bg-abyss/80 p-3 text-sm text-muted">Scope: {viewRuleQuery.data.case_id ? "case" : "global"}</div>
          </div>
          {viewRuleQuery.data.engine === "sigma" ? (
            <div className="mt-4 rounded-2xl border border-line bg-abyss/80 p-4 text-sm text-muted">
              {(() => {
                const coverage = (viewRuleQuery.data.metadata_json?.sigma_coverage as Record<string, unknown> | undefined) ?? {};
                const logsource = (coverage.logsource as Record<string, unknown> | undefined) ?? {};
                const fieldMappings = (coverage.field_mapping_details as Array<Record<string, unknown>> | undefined) ?? [];
                return (
                  <div className="mb-4 rounded-2xl border border-line bg-panel/50 p-3">
                    <p>Coverage status: <span className="text-white">{String(coverage.status || coverage.support_status || "unknown")}</span></p>
                    <p className="mt-2">Logsource: <span className="text-white">{String(logsource.product || "unknown")} / {String(logsource.category || "unknown")} / {String(logsource.service || "unknown")}</span></p>
                    <p className="mt-2">Unsupported reasons: <span className="text-white">{((coverage.unsupported_reasons as string[] | undefined) ?? []).join(", ") || "-"}</span></p>
                    <p className="mt-2">Risk reasons: <span className="text-white">{((coverage.risky_reasons as string[] | undefined) ?? []).join(", ") || "-"}</span></p>
                    {fieldMappings.length ? (
                      <div className="mt-3 overflow-x-auto">
                        <table className="min-w-full text-xs">
                          <thead className="text-left uppercase tracking-[0.14em] text-muted">
                            <tr><th className="py-2 pr-3">Sigma field</th><th className="py-2 pr-3">Normalized fields</th><th className="py-2 pr-3">Status</th></tr>
                          </thead>
                          <tbody>
                            {fieldMappings.slice(0, 12).map((item) => (
                              <tr key={String(item.sigma_field)}>
                                <td className="py-1 pr-3 text-white">{String(item.sigma_field)}</td>
                                <td className="py-1 pr-3">{((item.normalized_fields as string[] | undefined) ?? []).join(", ") || "-"}</td>
                                <td className="py-1 pr-3">{String(item.status || "-")} · {String(item.confidence || "-")}</td>
                              </tr>
                            ))}
                          </tbody>
                        </table>
                      </div>
                    ) : null}
                  </div>
                );
              })()}
              <p>Compile status: <span className="text-white">{String(viewRuleQuery.data.metadata_json?.compile_status || "unknown")}</span></p>
              <p className="mt-2">Compiler version: <span className="text-white">{String(viewRuleQuery.data.metadata_json?.compile_version || "-")}</span></p>
              <p className="mt-2">Original condition: <span className="text-white">{String(viewRuleQuery.data.metadata_json?.condition || "-")}</span></p>
              <p className="mt-2">Expanded condition summary: <span className="text-white">{String(((viewRuleQuery.data.metadata_json?.sigma_compilation as Record<string, unknown> | undefined)?.expanded_condition_summary as Record<string, unknown> | undefined)?.expanded || (viewRuleQuery.data.metadata_json?.condition as string) || "-")}</span></p>
              {String(viewRuleQuery.data.metadata_json?.compile_error || "") ? <p className="mt-2">Not executable: <span className="text-white">{String(viewRuleQuery.data.metadata_json?.compile_error)}</span></p> : null}
            </div>
          ) : null}
          <pre className="mt-4 max-h-[32rem] overflow-auto whitespace-pre-wrap break-all rounded-2xl border border-line bg-abyss/80 p-4 text-xs text-muted">{viewRuleQuery.data.content}</pre>
        </section>
      ) : null}

      {viewRuleSetId && viewRuleSetQuery.data ? (
        <section className="rounded-3xl border border-line bg-panel/85 p-5 shadow-panel">
          <div className="flex items-center justify-between gap-4">
            <div>
              <p className="font-mono text-xs uppercase tracking-[0.18em] text-accent">Rule pack</p>
              <h3 className="mt-2 text-xl font-semibold">{viewRuleSetQuery.data.name}</h3>
            </div>
            <button onClick={() => { setViewRuleSetId(null); setRuleSetPreviewSearch(""); }} className="rounded-2xl border border-line bg-abyss/80 px-4 py-2 text-sm text-muted">Close</button>
          </div>
          <div className="mt-4 grid gap-3 md:grid-cols-4">
            <div className="rounded-2xl border border-line bg-abyss/80 p-3 text-sm text-muted">Engine: {viewRuleSetQuery.data.engine}</div>
            <div className="rounded-2xl border border-line bg-abyss/80 p-3 text-sm text-muted">Rules inside: {viewRuleSetQuery.data.rules_count.toLocaleString()}</div>
            <div className="rounded-2xl border border-line bg-abyss/80 p-3 text-sm text-muted">Namespace: {viewRuleSetQuery.data.namespace || "-"}</div>
            <div className="rounded-2xl border border-line bg-abyss/80 p-3 text-sm text-muted">Source: {viewRuleSetQuery.data.source_filename || "-"}</div>
          </div>
          <div className="mt-4 rounded-2xl border border-line bg-abyss/80 p-4 text-sm text-muted">
            <p>Package: {String(viewRuleSetQuery.data.metadata_json?.package ?? "-")}</p>
            <p className="mt-1">Creation date: {String(viewRuleSetQuery.data.metadata_json?.creation_date ?? "-")}</p>
            <p className="mt-1">Description: {String(viewRuleSetQuery.data.metadata_json?.description ?? viewRuleSetQuery.data.description ?? "-")}</p>
          </div>
          <div className="mt-4 rounded-2xl border border-line bg-abyss/80 p-4">
            <div className="flex flex-wrap items-center justify-between gap-3">
              <p className="text-sm text-muted">Preview of first rules inside pack</p>
              <input value={ruleSetPreviewSearch} onChange={(event) => setRuleSetPreviewSearch(event.target.value)} placeholder="Search rule names in preview" className="rounded-2xl border border-line bg-panel/60 px-4 py-2 text-sm" />
            </div>
            <div className="mt-3 grid gap-2 md:grid-cols-2">
              {visibleRuleSetNames.slice(0, 50).map((name) => (
                <div key={name} className="rounded-xl border border-line bg-panel/40 px-3 py-2 font-mono text-xs text-muted">
                  {name}
                </div>
              ))}
            </div>
          </div>
          <details className="mt-4 rounded-2xl border border-line bg-abyss/80 p-4">
            <summary className="cursor-pointer text-sm text-muted">Show raw content</summary>
            <pre className="mt-4 max-h-[28rem] overflow-auto whitespace-pre-wrap break-all text-xs text-muted">{viewRuleSetQuery.data.content}</pre>
          </details>
        </section>
      ) : null}

      {selectedImportRunQuery.data ? (
        <div className="fixed inset-0 z-50 flex items-center justify-center bg-abyss/70 p-4">
          <div className="max-h-[85vh] w-full max-w-4xl overflow-hidden rounded-3xl border border-line bg-panel shadow-panel">
            <div className="flex items-center justify-between border-b border-line px-5 py-4">
              <div>
                <p className="font-mono text-[11px] uppercase tracking-[0.16em] text-accent">Rule import details</p>
                <h3 className="mt-1 text-lg font-semibold">{selectedImportRunQuery.data.source_name || selectedImportRunQuery.data.pack_name || selectedImportRunQuery.data.id}</h3>
              </div>
              <button type="button" onClick={() => setSelectedImportRunId(null)} className="rounded-2xl border border-line bg-abyss/80 px-4 py-2 text-sm text-muted">Close</button>
            </div>
            <div className="max-h-[calc(85vh-80px)] overflow-y-auto px-5 py-4">
              <div className="grid gap-4 md:grid-cols-2 xl:grid-cols-4">
                <MetricCard label={importIsTerminal(selectedImportRunQuery.data) ? "Imported" : "Imported so far"} value={importCountValue(selectedImportRunQuery.data, selectedImportRunQuery.data.imported_count, "Pending")} detail={importIsTerminal(selectedImportRunQuery.data) ? "New rules or packs created." : "Rules saved so far while the import is still running."} />
                <MetricCard label={importIsTerminal(selectedImportRunQuery.data) ? "Updated" : "Updated so far"} value={importCountValue(selectedImportRunQuery.data, selectedImportRunQuery.data.updated_count, "Pending")} detail="Existing rules updated in place." />
                <MetricCard label={importIsTerminal(selectedImportRunQuery.data) ? "Duplicates" : "Duplicates so far"} value={importCountValue(selectedImportRunQuery.data, selectedImportRunQuery.data.duplicate_count, "Pending")} detail="Already present with identical content." />
                <MetricCard label={importIsTerminal(selectedImportRunQuery.data) ? "Invalid / unsupported" : "Invalid / unsupported so far"} value={`${importCountValue(selectedImportRunQuery.data, selectedImportRunQuery.data.invalid_count, "Pending")} / ${importCountValue(selectedImportRunQuery.data, selectedImportRunQuery.data.unsupported_count, "Pending")}`} detail="Files or rules that could not be fully used." />
              </div>
              <div className="mt-5 grid gap-5 lg:grid-cols-2">
                <Notice tone={importStatusTone(selectedImportRunQuery.data.status)}>
                  <p className="font-semibold text-white">Summary</p>
                  {!importIsTerminal(selectedImportRunQuery.data) ? <p className="mt-2">Import still running. Counts are updated as phases complete. Final totals will be available when the import finishes.</p> : null}
                  <p className="mt-2">Status: {selectedImportRunQuery.data.status}</p>
                  <p className="mt-1">Phase: {selectedImportRunQuery.data.current_phase || "unknown"} · Rules discovered: {importRulesFoundValue(selectedImportRunQuery.data)} · Processed files: {importProgressValue(selectedImportRunQuery.data)}</p>
                  <p className="mt-1">Progress: {selectedImportRunQuery.data.progress_pct != null ? `${selectedImportRunQuery.data.progress_pct}%` : selectedImportRunQuery.data.total_files > 0 ? `${Math.round((selectedImportRunQuery.data.processed_files / selectedImportRunQuery.data.total_files) * 100)}%` : importIsTerminal(selectedImportRunQuery.data) ? "100%" : "Calculating..."}</p>
                  <p className="mt-1">Processed rules: {importProcessedRulesValue(selectedImportRunQuery.data)} · Elapsed: {formatElapsed(selectedImportRunQuery.data.elapsed_seconds ? Math.round(selectedImportRunQuery.data.elapsed_seconds) : null)}</p>
                  <p className="mt-1">Warnings: {selectedImportRunQuery.data.warning_count} · Errors: {selectedImportRunQuery.data.error_count}</p>
                  {selectedImportRunQuery.data.current_file ? <p className="mt-1 break-all">Current file: {selectedImportRunQuery.data.current_file}</p> : null}
                  {selectedImportRunQuery.data.cancel_requested ? <p className="mt-1">Cancel requested: yes</p> : null}
                  {selectedImportRunQuery.data.cancelled_at ? <p className="mt-1">Cancelled at: {selectedImportRunQuery.data.cancelled_at}</p> : null}
                </Notice>
                <Notice>
                  <p className="font-semibold text-white">Breakdown</p>
                  <p className="mt-2">Engine counts: {Object.entries((selectedImportRunQuery.data.details_json?.detected_engine_counts as Record<string, number> | undefined) ?? {}).map(([name, count]) => `${name}:${count}`).join(" · ") || "n/a"}</p>
                  <p className="mt-1">By product: {Object.entries((selectedImportRunQuery.data.details_json?.sigma_rules_by_product as Record<string, number> | undefined) ?? {}).slice(0, 4).map(([name, count]) => `${name}:${count}`).join(" · ") || "n/a"}</p>
                  <p className="mt-1">By category: {Object.entries((selectedImportRunQuery.data.details_json?.sigma_rules_by_category as Record<string, number> | undefined) ?? {}).slice(0, 4).map(([name, count]) => `${name}:${count}`).join(" · ") || "n/a"}</p>
                  <p className="mt-1">Performance: {importPerformanceLabel(selectedImportRunQuery.data)}</p>
                </Notice>
              </div>
              <div className="mt-5 grid gap-5 lg:grid-cols-2">
                <div className="rounded-2xl border border-line bg-abyss/70 p-4 text-sm text-muted">
                  <p className="font-semibold text-white">Engine compatibility</p>
                  <p className="mt-2">Executable by current engine: <span className="text-white">{importIsTerminal(selectedImportRunQuery.data) || importCoverageReport(selectedImportRunQuery.data).executable_by_current_engine != null ? String(importCoverageReport(selectedImportRunQuery.data).executable_by_current_engine ?? 0) : "Pending"}</span></p>
                  <p className="mt-1">Not executable by current engine: <span className="text-white">{importIsTerminal(selectedImportRunQuery.data) || importCoverageReport(selectedImportRunQuery.data).not_executable_by_current_engine != null ? String(importCoverageReport(selectedImportRunQuery.data).not_executable_by_current_engine ?? 0) : "Pending"}</span></p>
                  <p className="mt-1">Supported by condition expansion: <span className="text-white">{importIsTerminal(selectedImportRunQuery.data) || importCoverageReport(selectedImportRunQuery.data).newly_supported_condition_1_of != null ? String(importCoverageReport(selectedImportRunQuery.data).newly_supported_condition_1_of ?? 0) : "Pending"}</span> `1 of` · <span className="text-white">{importIsTerminal(selectedImportRunQuery.data) || importCoverageReport(selectedImportRunQuery.data).newly_supported_condition_all_of != null ? String(importCoverageReport(selectedImportRunQuery.data).newly_supported_condition_all_of ?? 0) : "Pending"}</span> `all of`</p>
                  <p className="mt-1">Unsupported condition / compile error: <span className="text-white">{importIsTerminal(selectedImportRunQuery.data) || selectedImportRunQuery.data.details_json?.compile_error_count != null || selectedImportRunQuery.data.details_json?.unsupported_condition_count != null ? `${String(selectedImportRunQuery.data.details_json?.compile_error_count ?? 0)} / ${String(selectedImportRunQuery.data.details_json?.unsupported_condition_count ?? 0)}` : "Pending"}</span></p>
                  <p className="mt-1">Import compatibility is about engine support, not whether a rule applies to this case.</p>
                  <p className="mt-2">pySigma evaluation: <span className="text-white">{importPySigmaEvaluation(selectedImportRunQuery.data).available ? "Available for evaluation" : "Not available in this deployment"}</span></p>
                  {typeof importPySigmaEvaluation(selectedImportRunQuery.data).reason === "string" ? <p className="mt-1">{String(importPySigmaEvaluation(selectedImportRunQuery.data).reason)}</p> : null}
                  <p className="mt-2">Supported Sigma features: <span className="text-white">simple selection · 1 of selection* · all of selection* · 1 of them · all of them · selection and not filter*</span></p>
                </div>
                <div className="rounded-2xl border border-line bg-abyss/70 p-4 text-sm text-muted">
                  <p className="font-semibold text-white">Coverage report</p>
                  <div className="mt-2 space-y-1">
                    {Object.entries((importCoverageReport(selectedImportRunQuery.data).unsupported_by_feature as Record<string, number> | undefined) ?? {}).length ? (
                      Object.entries((importCoverageReport(selectedImportRunQuery.data).unsupported_by_feature as Record<string, number> | undefined) ?? {}).map(([name, count]) => (
                        <p key={name}>{humanizeCompatibilityKey(name)}: <span className="text-white">{String(count)}</span></p>
                      ))
                    ) : (
                      <p>No unsupported engine features were recorded for this import.</p>
                    )}
                  </div>
                  {Object.entries((importCoverageReport(selectedImportRunQuery.data).examples_by_feature as Record<string, string[]> | undefined) ?? {}).length ? (
                    <div className="mt-3 space-y-2">
                      {Object.entries((importCoverageReport(selectedImportRunQuery.data).examples_by_feature as Record<string, string[]> | undefined) ?? {}).slice(0, 4).map(([name, examples]) => (
                        <p key={name}>{humanizeCompatibilityKey(name)} examples: <span className="text-white">{examples.join(" · ")}</span></p>
                      ))}
                    </div>
                  ) : null}
                </div>
              </div>
              <div className="mt-5 flex flex-wrap gap-3">
                <button type="button" onClick={() => openLibraryForImport(selectedImportRunQuery.data)} className="rounded-2xl border border-line bg-abyss/80 px-4 py-2 text-sm text-muted">View imported rules</button>
                <button type="button" onClick={() => disableRulesFromImport(selectedImportRunQuery.data)} className="rounded-2xl border border-line bg-abyss/80 px-4 py-2 text-sm text-muted">Disable rules from this import</button>
                <button type="button" onClick={() => deleteRulesFromImport(selectedImportRunQuery.data)} className="rounded-2xl border border-danger/30 bg-danger/10 px-4 py-2 text-sm text-danger">Delete rules from this import</button>
              </div>
              {selectedImportRunQuery.data.invalid_items.length ? (
                <div className="mt-5 rounded-2xl border border-line bg-abyss/70 p-4">
                  <p className="font-semibold text-white">Invalid items</p>
                  <div className="mt-3 space-y-2 text-sm text-muted">
                    {selectedImportRunQuery.data.invalid_items.slice(0, 20).map((item, index) => (
                      <p key={`${String(item.file ?? item.rule ?? index)}`}>{String(item.file ?? item.rule ?? `Item ${index + 1}`)}: <span className="text-white">{String(item.reason ?? item.status ?? "invalid")}</span></p>
                    ))}
                  </div>
                </div>
              ) : null}
              {selectedImportRunQuery.data.unsupported_items.length ? (
                <div className="mt-5 rounded-2xl border border-line bg-abyss/70 p-4">
                  <p className="font-semibold text-white">Unsupported items</p>
                  <div className="mt-3 space-y-2 text-sm text-muted">
                    {selectedImportRunQuery.data.unsupported_items.slice(0, 20).map((item, index) => (
                      <p key={`${String(item.file ?? item.rule ?? index)}`}>{String(item.rule ?? item.file ?? `Item ${index + 1}`)}: <span className="text-white">{String(item.reason ?? item.status ?? "unsupported")}</span></p>
                    ))}
                  </div>
                </div>
              ) : null}
              {selectedImportRunQuery.data.warnings_summary.length || selectedImportRunQuery.data.errors_summary.length ? (
                <div className="mt-5 rounded-2xl border border-line bg-abyss/70 p-4">
                  <p className="font-semibold text-white">Errors / warnings</p>
                  <div className="mt-3 space-y-2 text-sm text-muted">
                    {[...selectedImportRunQuery.data.warnings_summary, ...selectedImportRunQuery.data.errors_summary].slice(0, 20).map((item) => (
                      <p key={item}>{item}</p>
                    ))}
                  </div>
                </div>
              ) : null}
            </div>
          </div>
        </div>
      ) : null}
    </div>
  );
}
