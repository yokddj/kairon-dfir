import type { MemoryProcessEntity, MemoryProcessObservation, MemoryProcessTreeEntity, MemoryRunOption, MemoryRenormalizeSummary } from "../api/client";

export type VisibilityFilter = "listed" | "scan_only" | "terminated" | "unknown" | "hidden_candidate" | null;
export type SourcePluginFilter = "windows.pslist" | "windows.psscan" | "windows.pstree" | "windows.cmdline" | null;
export type InterestingFilter = boolean | null;

export function sourcePluginBadge(plugin: string): string {
  return plugin.replace("windows.", "");
}

export function visibilityLabel(entity: MemoryProcessEntity): string {
  if (entity.visibility?.terminated) return "Terminated";
  if (entity.visibility?.scan_only) return "Scan only";
  if (entity.visibility?.hidden_candidate) return "Hidden candidate";
  if (entity.visibility?.unknown) return "Unknown";
  return "Listed";
}

export function visibilityTone(entity: MemoryProcessEntity): "neutral" | "warn" | "danger" | "info" {
  if (entity.visibility?.terminated) return "neutral";
  if (entity.visibility?.hidden_candidate) return "danger";
  if (entity.visibility?.scan_only) return "warn";
  if (entity.visibility?.unknown) return "warn";
  return "info";
}

export function confidenceTone(confidence: MemoryProcessEntity["confidence"]): "neutral" | "good" | "warn" {
  if (confidence === "high") return "good";
  if (confidence === "medium") return "neutral";
  return "warn";
}

export function reported(value: unknown): string {
  if (value === null || value === undefined || value === "") return "Not reported";
  if (typeof value === "boolean") return value ? "Yes" : "No";
  return String(value);
}

export function findingLabel(finding: string): string {
  const labels: Record<string, string> = {
    scan_only: "Scan only",
    hidden_candidate: "Hidden candidate",
    terminated: "Terminated",
    identity_provisional: "Identity provisional",
    missing_parent_in_pslist_or_pstree: "Missing parent",
    name_conflict: "Name conflict",
    command_line_missing: "Command line missing",
  };
  return labels[finding] || finding;
}

export function buildRunOptions(
  options: MemoryRunOption[] | undefined,
  selectedRunId: string | null,
): Array<{ runId: string; label: string; selected: boolean }> {
  if (!options) return [];
  return options.map((opt) => {
    const date = (opt.completed_at || opt.created_at || "").slice(0, 16).replace("T", " ");
    return {
      runId: opt.run_id,
      label: `${opt.profile} · ${opt.status} · ${date} UTC · ${opt.plugins_completed}/${opt.plugin_count} plugins`,
      selected: selectedRunId === opt.run_id,
    };
  });
}

export function summarizeRenormalization(summary: MemoryRenormalizeSummary): {
  totalEntities: number;
  observations: number;
  collapsed: number;
  roots: number;
  orphans: number;
  unknownParent: number;
  scanOnly: number;
  hiddenCandidate: number;
  terminated: number;
  pidZero: number;
  pid4: number;
} {
  return {
    totalEntities: summary.candidate_entities,
    observations: summary.observation_count,
    collapsed: summary.duplicate_groups_collapsed,
    roots: summary.tree_metrics.roots,
    orphans: summary.tree_metrics.orphans,
    unknownParent: summary.tree_metrics.unknown_parent,
    scanOnly: summary.tree_metrics.scan_only,
    hiddenCandidate: summary.tree_metrics.hidden_candidates,
    terminated: summary.tree_metrics.terminated,
    pidZero: summary.tree_metrics.pid_zero_count,
    pid4: summary.tree_metrics.pid_4_count,
  };
}

export function formatTreeNodeForTable(node: {
  process_entity_id: string;
  pid: number;
  ppid?: number | null;
  name?: string | null;
  command_line?: string | null;
  sources: string[];
  visibility: Record<string, boolean>;
  findings: string[];
  child_count: number;
  children: Array<Record<string, unknown>>;
}): {
  key: string;
  pid: number;
  ppid: number | null;
  name: string;
  commandLine: string;
  sources: string[];
  visibility: string;
  findings: string[];
  childCount: number;
} {
  return {
    key: node.process_entity_id,
    pid: node.pid,
    ppid: node.ppid ?? null,
    name: reported(node.name),
    commandLine: reported(node.command_line),
    sources: (node.sources || []).map(sourcePluginBadge),
    visibility: visibilityLabelFromFlags(node.visibility || {}),
    findings: (node.findings || []).map(findingLabel),
    childCount: node.child_count || 0,
  };
}

function visibilityLabelFromFlags(flags: Record<string, boolean>): string {
  if (flags.terminated) return "Terminated";
  if (flags.scan_only) return "Scan only";
  if (flags.hidden_candidate) return "Hidden candidate";
  if (flags.unknown) return "Unknown";
  return "Listed";
}

export type CanonicalEntityRow = ReturnType<typeof formatTreeNodeForTable>;

export function flattenTreeToRows(nodes: Array<{
  process_entity_id: string;
  pid: number;
  ppid?: number | null;
  name?: string | null;
  command_line?: string | null;
  sources: string[];
  visibility: Record<string, boolean>;
  findings: string[];
  child_count: number;
  children: Array<any>;
}>, depth = 0, maxDepth = 4): Array<CanonicalEntityRow & { depth: number }> {
  const out: Array<CanonicalEntityRow & { depth: number }> = [];
  for (const n of nodes) {
    out.push({ ...formatTreeNodeForTable(n), depth });
    if (depth < maxDepth && n.children && n.children.length) {
      out.push(...flattenTreeToRows(n.children, depth + 1, maxDepth));
    }
  }
  return out;
}

export function observationsToRows(observations: MemoryProcessObservation[]): Array<{
  key: string;
  plugin: string;
  pid: number;
  ppid: number | null;
  name: string;
  commandLine: string;
  createTime: string;
  exitTime: string;
  confidence: string;
}> {
  return observations.map((obs) => ({
    key: obs.document_id || `${obs.scan_run_id}-${obs.process_entity_id}-${obs.plugin_name}`,
    plugin: sourcePluginBadge(obs.plugin_name),
    pid: obs.observed?.pid ?? 0,
    ppid: obs.observed?.ppid ?? null,
    name: reported(obs.observed?.name),
    commandLine: reported(obs.observed?.command_line),
    createTime: reported(obs.observed?.create_time),
    exitTime: reported(obs.observed?.exit_time),
    confidence: obs.confidence,
  }));
}
