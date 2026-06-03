import { Component, useEffect, useMemo, useRef, useState, type ErrorInfo, type ReactNode } from "react";
import { useQuery } from "@tanstack/react-query";
import {
  AlertTriangle,
  ArrowDownToLine,
  ChevronDown,
  ChevronRight,
  CircleDashed,
  Copy,
  ExternalLink,
  Eye,
  FileText,
  Filter,
  Globe,
  Network,
  RefreshCw,
  Search,
  Shield,
  Sparkles,
  TerminalSquare,
  Workflow,
} from "lucide-react";
import { useNavigate } from "react-router-dom";

import { api, type Evidence, type ExecutionStory, type Finding, type ProcessTreeBundle, type ProcessTreeEdge, type ProcessTreeNode } from "../api/client";
import ResponsiveDetailPanel, { useMinWidthQuery } from "./ResponsiveDetailPanel";
import { copyToClipboard } from "../lib/time";

type Props = {
  caseId: string;
  evidences: Evidence[];
  initialEvidenceId?: string;
  initialPid?: string;
  initialProcessGuid?: string;
  initialSourceEventId?: string;
  initialTimestamp?: string;
  initialProcessName?: string;
  initialHighlightedNodeIds?: string[];
  initialFindingId?: string;
  openedFromSearchEventId?: string;
  initialMode?: "suspicious" | "focused" | "full";
  selectedHost?: string;
  selectedEvidenceId?: string;
  debugThrowRenderError?: boolean;
};

type ProcessFocus = {
  scope: "case" | "evidence";
  evidence_id?: string;
  host?: string;
  pid?: number;
  process_name?: string;
  entity_id?: string;
  source_event_id?: string;
  timestamp?: string;
};

const EDGE_TYPE_OPTIONS = [
  { id: "parent_child", label: "Process tree" },
  { id: "network_activity", label: "Network" },
  { id: "dns_activity", label: "DNS" },
  { id: "file_activity", label: "File" },
  { id: "registry_activity", label: "Registry" },
];

type GraphMode = "suspicious" | "full" | "focused";
type FocusKind = "none" | "chain" | "finding" | "process";
type ExpansionType = "children" | "parents" | "siblings" | "activity";
type StoryTab = "overview" | "parents" | "children" | "activity" | "commands" | "source" | "advanced";

type QuickFilterId =
  | "suspicious"
  | "high_risk"
  | "lolbins"
  | "powershell"
  | "office"
  | "browser"
  | "defender"
  | "downloads"
  | "autorun";

type TreeBranch = {
  node: ProcessTreeNode;
  edge?: ProcessTreeEdge;
  depth: number;
  children: TreeBranch[];
};

type ChainView = {
  id: string;
  title: string;
  reasons: string[];
  nodes: ProcessTreeNode[];
  edge?: ProcessTreeEdge;
  riskScore: number;
  isInternalNoise: boolean;
};

type GraphWarningGroup = {
  key: string;
  message: string;
  count: number;
  samples: string[];
};

type GraphLayoutNode = {
  id: string;
  x: number;
  y: number;
  width: number;
  height: number;
  depth: number;
};

type GraphLayout = {
  width: number;
  height: number;
  nodes: GraphLayoutNode[];
};

type BoundaryProps = {
  children: ReactNode;
};

type BoundaryState = {
  hasError: boolean;
  errorMessage: string;
};

class ProcessGraphErrorBoundary extends Component<BoundaryProps, BoundaryState> {
  constructor(props: BoundaryProps) {
    super(props);
    this.state = { hasError: false, errorMessage: "" };
  }

  static getDerivedStateFromError(error: Error): BoundaryState {
    return {
      hasError: true,
      errorMessage: error.message || "Unknown render error",
    };
  }

  componentDidCatch(_error: Error, _info: ErrorInfo) {}

  render() {
    if (this.state.hasError) {
      return (
        <div className="rounded-[28px] border border-danger/40 bg-danger/10 p-8 shadow-panel">
          <p className="font-mono text-xs uppercase tracking-[0.18em] text-danger">Process Graph</p>
          <h3 className="mt-2 text-xl font-semibold">Process graph could not be rendered</h3>
          <p className="mt-2 text-sm text-muted">The graph UI failed during render. Use Search or Timeline while the graph issue is investigated.</p>
          <details className="mt-4 rounded-2xl border border-line bg-abyss/60 p-4">
            <summary className="cursor-pointer font-mono text-[11px] uppercase tracking-[0.16em] text-muted">Technical details</summary>
            <pre className="mt-3 whitespace-pre-wrap break-all text-xs text-muted">{this.state.errorMessage}</pre>
          </details>
        </div>
      );
    }
    return this.props.children;
  }
}

function ProcessGraphCrashTrigger(): ReactNode {
  throw new Error("debug render error");
}

const MAX_RENDER_NODES = 260;
const FOCUSED_RENDER_NODES = 120;
const FULL_RENDER_NODES = 320;
const FULL_GRAPH_CONFIRM_THRESHOLD = 300;
const GRAPH_CARD_WIDTH = 220;
const GRAPH_CARD_HEIGHT = 96;
const GRAPH_COLUMN_GAP = 88;
const GRAPH_ROW_GAP = 28;
const GRAPH_PADDING = 28;

function toNodeLabel(node: ProcessTreeNode) {
  return node.name || node.path || node.command_line || node.id;
}

function compactTimestamp(value: string | null) {
  if (!value) return "—";
  return value.replace("T", " ").replace(".000000+00:00", "Z");
}

function riskTone(score: number) {
  if (score >= 90) return "border-rose-400/50 bg-rose-500/15 text-rose-200";
  if (score >= 70) return "border-orange-400/50 bg-orange-500/15 text-orange-100";
  if (score >= 40) return "border-amber-300/40 bg-amber-300/10 text-amber-100";
  return "border-line bg-white/5 text-muted";
}

function confidenceTone(value: string | null | undefined) {
  const normalized = (value || "").toLowerCase();
  if (normalized === "high") return "border-emerald-400/40 bg-emerald-500/10 text-emerald-200";
  if (normalized === "medium") return "border-amber-400/40 bg-amber-400/10 text-amber-100";
  return "border-line bg-white/5 text-muted";
}

function badgeTone(badge: string) {
  if (badge === "suspicious_chain" || badge === "browser_child") return "border-orange-400/40 bg-orange-500/10 text-orange-100";
  if (badge === "office_child" || badge === "encoded_command") return "border-rose-400/40 bg-rose-500/10 text-rose-200";
  if (badge === "defender_detection") return "border-emerald-400/40 bg-emerald-500/10 text-emerald-200";
  if (badge === "browser_internal_child" || badge === "low_noise_process") return "border-line bg-white/5 text-muted";
  if (badge === "browser_download" || badge === "bits_download" || badge === "network_activity") return "border-cyan-400/40 bg-cyan-500/10 text-cyan-100";
  if (badge === "autorun") return "border-fuchsia-400/40 bg-fuchsia-500/10 text-fuchsia-100";
  return "border-line bg-white/5 text-muted";
}

function normalizeValue(value: string | null | undefined) {
  return value && value.trim() ? value.trim() : "—";
}

function nodePidLabel(node: ProcessTreeNode | null | undefined) {
  if (!node) return "—";
  return node.pid !== null && node.pid !== undefined ? `PID ${node.pid}` : "PID —";
}

function nodeIcon(node: ProcessTreeNode) {
  const name = String(node.name || "").toLowerCase();
  const badges = node.badges || [];
  if (badges.includes("defender_detection")) return <Shield className="h-4 w-4 text-emerald-300" />;
  if (name.includes("powershell") || name.includes("cmd.exe") || name.includes("pwsh.exe")) return <TerminalSquare className="h-4 w-4 text-orange-200" />;
  if (badges.includes("office_child") || /winword|excel|powerpnt|outlook/.test(name)) return <FileText className="h-4 w-4 text-rose-200" />;
  if (/chrome|msedge|firefox|brave/.test(name)) return <Globe className="h-4 w-4 text-cyan-200" />;
  if (badges.includes("browser_download") || badges.includes("bits_download")) return <ArrowDownToLine className="h-4 w-4 text-cyan-200" />;
  if (badges.includes("autorun")) return <Sparkles className="h-4 w-4 text-fuchsia-200" />;
  return <Workflow className="h-4 w-4 text-muted" />;
}

function isSuspiciousNode(node: ProcessTreeNode, relatedFindingCount: number) {
  if ((node.badges || []).includes("browser_internal_child") && (node.risk_score || 0) < 70) return false;
  return (node.risk_score || 0) >= 70 || relatedFindingCount > 0 || (node.risk_reasons || []).length > 0 || (node.badges || []).some((badge) => ["suspicious_chain", "office_child", "browser_child", "defender_detection", "browser_download", "bits_download", "autorun", "encoded_command"].includes(badge));
}

function matchesQuickFilters(node: ProcessTreeNode, filters: Set<QuickFilterId>, relatedFindingCount: number) {
  if (!filters.size) return true;
  const badges = new Set(node.badges || []);
  const name = String(node.name || "").toLowerCase();
  for (const filter of filters) {
    if (filter === "suspicious" && !isSuspiciousNode(node, relatedFindingCount)) return false;
    if (filter === "high_risk" && (node.risk_score || 0) < 70) return false;
    if (filter === "lolbins" && !badges.has("lolbin")) return false;
    if (filter === "powershell" && !badges.has("powershell") && !name.includes("powershell") && !name.includes("pwsh.exe")) return false;
    if (filter === "office" && !badges.has("office_child") && !/winword|excel|powerpnt|outlook/.test(name)) return false;
    if (filter === "browser" && !/chrome|msedge|firefox|brave/.test(name) && !badges.has("browser_child") && !badges.has("browser_internal_child")) return false;
    if (filter === "defender" && !badges.has("defender_detection")) return false;
    if (filter === "downloads" && !badges.has("browser_download") && !badges.has("bits_download") && !badges.has("browser_child")) return false;
    if (filter === "autorun" && !badges.has("autorun")) return false;
  }
  return true;
}

function buildForest(nodes: ProcessTreeNode[], edges: ProcessTreeEdge[]) {
  const nodeMap = new Map(nodes.map((node) => [node.id, node]));
  const childrenByParent = new Map<string, Array<{ edge: ProcessTreeEdge; child: ProcessTreeNode }>>();
  const childIds = new Set<string>();

  for (const edge of edges) {
    const parent = nodeMap.get(edge.source);
    const child = nodeMap.get(edge.target);
    if (!parent || !child || edge.source === edge.target) continue;
    childIds.add(child.id);
    const current = childrenByParent.get(parent.id) ?? [];
    current.push({ edge, child });
    childrenByParent.set(parent.id, current);
  }

  const roots = nodes.filter((node) => !childIds.has(node.id));
  const visited = new Set<string>();
  const descend = (node: ProcessTreeNode, depth: number, edge?: ProcessTreeEdge): TreeBranch => {
    const key = `${node.id}:${depth}`;
    if (visited.has(key)) return { node, edge, depth, children: [] };
    visited.add(key);
    const children = (childrenByParent.get(node.id) ?? [])
      .sort((a, b) => (b.child.risk_score || 0) - (a.child.risk_score || 0))
      .map(({ child, edge: childEdge }) => descend(child, depth + 1, childEdge));
    return { node, edge, depth, children };
  };

  return roots.sort((a, b) => (b.risk_score || 0) - (a.risk_score || 0)).map((root) => descend(root, 0));
}

function flattenForest(branches: TreeBranch[], expandedNodeIds: Set<string>) {
  const rows: TreeBranch[] = [];
  const walk = (branch: TreeBranch) => {
    rows.push(branch);
    if (branch.children.length && expandedNodeIds.has(branch.node.id)) {
      branch.children.forEach(walk);
    }
  };
  branches.forEach(walk);
  return rows;
}

function lineageForNode(selectedNodeId: string | null, edges: ProcessTreeEdge[]) {
  const parentByChild = new Map<string, string>();
  for (const edge of edges) parentByChild.set(edge.target, edge.source);
  const lineage = new Set<string>();
  let current = selectedNodeId;
  let guard = 0;
  while (current && guard < 128) {
    lineage.add(current);
    current = parentByChild.get(current) ?? null;
    guard += 1;
  }
  return lineage;
}

function collectConnectedIds(seedIds: string[], edges: ProcessTreeEdge[]) {
  const related = new Set(seedIds.filter(Boolean));
  const pending = [...related];
  while (pending.length) {
    const current = pending.pop()!;
    for (const edge of edges) {
      if (edge.source === current && !related.has(edge.target)) {
        related.add(edge.target);
        pending.push(edge.target);
      }
      if (edge.target === current && !related.has(edge.source)) {
        related.add(edge.source);
        pending.push(edge.source);
      }
    }
  }
  return related;
}

function expandFocusedIds(
  seedIds: string[],
  edges: ProcessTreeEdge[],
  nodeMap: Map<string, ProcessTreeNode>,
  parentDepth: number,
  childDepth: number,
  includeSiblings: boolean,
) {
  const parentsByChild = new Map<string, string[]>();
  const childrenByParent = new Map<string, string[]>();
  for (const edge of edges) {
    if (!nodeMap.has(edge.source) || !nodeMap.has(edge.target) || edge.source === edge.target) continue;
    const parents = parentsByChild.get(edge.target) ?? [];
    parents.push(edge.source);
    parentsByChild.set(edge.target, parents);
    const children = childrenByParent.get(edge.source) ?? [];
    children.push(edge.target);
    childrenByParent.set(edge.source, children);
  }

  const related = new Set(seedIds.filter((id) => nodeMap.has(id)));
  let parentFrontier = [...related];
  for (let depth = 0; depth < parentDepth; depth += 1) {
    const next: string[] = [];
    for (const id of parentFrontier) {
      for (const parentId of parentsByChild.get(id) ?? []) {
        if (related.has(parentId)) continue;
        related.add(parentId);
        next.push(parentId);
      }
    }
    if (!next.length) break;
    parentFrontier = next;
  }

  let childFrontier = [...related];
  for (let depth = 0; depth < childDepth; depth += 1) {
    const next: string[] = [];
    for (const id of childFrontier) {
      for (const childId of childrenByParent.get(id) ?? []) {
        if (related.has(childId)) continue;
        related.add(childId);
        next.push(childId);
      }
    }
    if (!next.length) break;
    childFrontier = next;
  }

  if (includeSiblings) {
    const snapshot = Array.from(related);
    for (const id of snapshot) {
      for (const parentId of parentsByChild.get(id) ?? []) {
        for (const siblingId of childrenByParent.get(parentId) ?? []) {
          if (nodeMap.has(siblingId)) related.add(siblingId);
        }
      }
    }
  }

  return related;
}

function chainViews(bundle: ProcessTreeBundle | undefined, nodeMap: Map<string, ProcessTreeNode>) {
  return (bundle?.sample_chains ?? []).map((item, index) => {
    const rawChain = Array.isArray(item.chain) ? (item.chain as Array<Record<string, unknown>>) : [];
    const nodes = rawChain
      .map((entry) => {
        const id = String(entry.id ?? "");
        return (
          nodeMap.get(id) ?? {
            id,
            pid: entry.pid ? Number(entry.pid) : null,
            name: entry.name ? String(entry.name) : null,
            path: entry.path ? String(entry.path) : null,
            command_line: entry.command_line ? String(entry.command_line) : null,
            user: null,
            sid: null,
            host: null,
            first_seen: null,
            last_seen: null,
            source_events: [],
            risk_score: Number(entry.risk_score ?? 0),
            risk_reasons: [],
            badges: Array.isArray(entry.badges) ? (entry.badges as string[]) : [],
            data_quality: [],
            confidence: "low",
          } satisfies ProcessTreeNode
        );
      })
      .filter((node) => Boolean(node.id));
    const child = nodes[nodes.length - 1];
    const badges = child?.badges || [];
    return {
      id: `${String((item.edge as Record<string, unknown> | undefined)?.source ?? "")}:${String((item.edge as Record<string, unknown> | undefined)?.target ?? "")}:${index}`,
      title: nodes.map((node) => toNodeLabel(node)).join(" → "),
      reasons: Array.isArray(item.reasons) ? (item.reasons as string[]) : [],
      nodes,
      edge: (item.edge as ProcessTreeEdge | undefined) ?? undefined,
      riskScore: Number(child?.risk_score ?? 0),
      isInternalNoise: badges.includes("browser_internal_child") && Number(child?.risk_score ?? 0) < 70,
    } satisfies ChainView;
  });
}

function edgeIdentity(edge: ProcessTreeEdge) {
  return edge.id || `${edge.source}->${edge.target}:${edge.type}:${edge.source_event_id || ""}`;
}

function mergeNodes(base: ProcessTreeNode[], additions: ProcessTreeNode[]) {
  const map = new Map<string, ProcessTreeNode>();
  for (const node of base) map.set(node.id, node);
  for (const node of additions) {
    const existing = map.get(node.id);
    map.set(
      node.id,
      existing
        ? {
            ...existing,
            ...node,
            badges: Array.from(new Set([...(existing.badges || []), ...(node.badges || [])])),
            data_quality: Array.from(new Set([...(existing.data_quality || []), ...(node.data_quality || [])])),
          }
        : node,
    );
  }
  return Array.from(map.values());
}

function mergeEdges(base: ProcessTreeEdge[], additions: ProcessTreeEdge[]) {
  const map = new Map<string, ProcessTreeEdge>();
  for (const edge of base) map.set(edgeIdentity(edge), edge);
  for (const edge of additions) map.set(edgeIdentity(edge), edge);
  return Array.from(map.values());
}

function groupGraphWarnings(summary: Record<string, unknown> | undefined) {
  const warnings = Array.isArray(summary?.warnings) ? (summary?.warnings as string[]) : [];
  const samples = Array.isArray(summary?.warnings_samples) ? (summary?.warnings_samples as string[]) : [];
  const warningsSummary = summary?.warnings_summary && typeof summary.warnings_summary === "object"
    ? (summary.warnings_summary as Record<string, unknown>)
    : null;

  const groups: GraphWarningGroup[] = [];
  if (warningsSummary) {
    const ambiguous = Number(warningsSummary.ambiguous_parent_candidates ?? 0);
    const ambiguousRelaxed = Number(warningsSummary.ambiguous_relaxed_parent_candidates ?? 0);
    const parentNotFound = Number(warningsSummary.parent_not_found ?? 0);
    const pidReuse = Number(warningsSummary.possible_pid_reuse ?? 0);
    if (ambiguous > 0) {
      groups.push({
        key: "ambiguous_parent_candidates",
        count: ambiguous,
        message: `${ambiguous} ambiguous parent candidates. Some edges were omitted to avoid incorrect parent-child links.`,
        samples: samples.filter((item) => item.startsWith("Ambiguous parent candidates for node ")).slice(0, 10),
      });
    }
    if (ambiguousRelaxed > 0) {
      groups.push({
        key: "ambiguous_relaxed_parent_candidates",
        count: ambiguousRelaxed,
        message: `${ambiguousRelaxed} relaxed parent candidates remained ambiguous after inference.`,
        samples: samples.filter((item) => item.startsWith("Ambiguous relaxed parent candidates for node ")).slice(0, 10),
      });
    }
    if (parentNotFound > 0) {
      groups.push({
        key: "parent_not_found",
        count: parentNotFound,
        message: `${parentNotFound} nodes could not be linked to a parent.`,
        samples: [],
      });
    }
    if (pidReuse > 0) {
      groups.push({
        key: "possible_pid_reuse",
        count: pidReuse,
        message: `${pidReuse} nodes were marked with possible PID reuse.`,
        samples: [],
      });
    }
  }

  if (!groups.length && warnings.length) {
    const grouped = new Map<string, GraphWarningGroup>();
    for (const warning of warnings) {
      const key = warning.startsWith("Ambiguous parent candidates for node ")
        ? "ambiguous_parent_candidates"
        : warning.startsWith("Ambiguous relaxed parent candidates for node ")
          ? "ambiguous_relaxed_parent_candidates"
          : warning;
      const existing = grouped.get(key);
      if (existing) {
        existing.count += 1;
        if (existing.samples.length < 10 && existing.message !== warning) existing.samples.push(warning);
        continue;
      }
      grouped.set(key, {
        key,
        count: 1,
        message:
          key === "ambiguous_parent_candidates"
            ? "Ambiguous parent candidates were detected. Some edges were omitted to avoid incorrect parent-child links."
            : key === "ambiguous_relaxed_parent_candidates"
              ? "Relaxed parent candidate inference remained ambiguous for some nodes."
              : warning,
        samples: key === warning ? [] : [warning],
      });
    }
    return Array.from(grouped.values());
  }

  return groups;
}

function buildGraphLayout(nodes: ProcessTreeNode[], edges: ProcessTreeEdge[]) {
  const incoming = new Map<string, number>();
  const childrenByParent = new Map<string, string[]>();
  for (const node of nodes) incoming.set(node.id, 0);
  for (const edge of edges) {
    if (!incoming.has(edge.source) || !incoming.has(edge.target) || edge.source === edge.target) continue;
    incoming.set(edge.target, (incoming.get(edge.target) ?? 0) + 1);
    const current = childrenByParent.get(edge.source) ?? [];
    current.push(edge.target);
    childrenByParent.set(edge.source, current);
  }

  const nodeOrder = [...nodes].sort((left, right) => (right.risk_score || 0) - (left.risk_score || 0) || toNodeLabel(left).localeCompare(toNodeLabel(right)));
  const roots = nodeOrder.filter((node) => (incoming.get(node.id) ?? 0) === 0);
  const depthById = new Map<string, number>();
  const queue = roots.map((node) => node.id);
  roots.forEach((node) => depthById.set(node.id, 0));
  while (queue.length) {
    const currentId = queue.shift()!;
    const currentDepth = depthById.get(currentId) ?? 0;
    for (const childId of childrenByParent.get(currentId) ?? []) {
      const nextDepth = currentDepth + 1;
      if ((depthById.get(childId) ?? -1) < nextDepth) {
        depthById.set(childId, nextDepth);
        queue.push(childId);
      }
    }
  }
  for (const node of nodeOrder) {
    if (!depthById.has(node.id)) depthById.set(node.id, 0);
  }

  const columns = new Map<number, ProcessTreeNode[]>();
  for (const node of nodeOrder) {
    const depth = depthById.get(node.id) ?? 0;
    const current = columns.get(depth) ?? [];
    current.push(node);
    columns.set(depth, current);
  }

  const layoutNodes: GraphLayoutNode[] = [];
  let maxDepth = 0;
  let maxRows = 0;
  for (const [depth, columnNodes] of [...columns.entries()].sort((a, b) => a[0] - b[0])) {
    maxDepth = Math.max(maxDepth, depth);
    maxRows = Math.max(maxRows, columnNodes.length);
    columnNodes.forEach((node, index) => {
      layoutNodes.push({
        id: node.id,
        depth,
        x: GRAPH_PADDING + depth * (GRAPH_CARD_WIDTH + GRAPH_COLUMN_GAP),
        y: GRAPH_PADDING + index * (GRAPH_CARD_HEIGHT + GRAPH_ROW_GAP),
        width: GRAPH_CARD_WIDTH,
        height: GRAPH_CARD_HEIGHT,
      });
    });
  }

  return {
    width: Math.max(420, GRAPH_PADDING * 2 + (maxDepth + 1) * GRAPH_CARD_WIDTH + maxDepth * GRAPH_COLUMN_GAP),
    height: Math.max(280, GRAPH_PADDING * 2 + maxRows * GRAPH_CARD_HEIGHT + Math.max(0, maxRows - 1) * GRAPH_ROW_GAP),
    nodes: layoutNodes,
  } satisfies GraphLayout;
}

function SummaryBadge({ label, value }: { label: string; value: number | string }) {
  return (
    <div className="rounded-2xl border border-line bg-panel/60 px-4 py-3">
      <p className="font-mono text-[11px] uppercase tracking-[0.16em] text-muted">{label}</p>
      <p className="mt-2 text-lg font-semibold">{value}</p>
    </div>
  );
}

function Pill({ children, className = "" }: { children: ReactNode; className?: string }) {
  return <span className={`rounded-full border px-2.5 py-1 font-mono text-[10px] uppercase tracking-[0.14em] ${className}`}>{children}</span>;
}

function downloadBlob(filename: string, content: string, type: string) {
  const blob = new Blob([content], { type });
  const url = URL.createObjectURL(blob);
  const anchor = document.createElement("a");
  anchor.href = url;
  anchor.download = filename;
  document.body.appendChild(anchor);
  anchor.click();
  document.body.removeChild(anchor);
  URL.revokeObjectURL(url);
}

export default function ProcessTreePanel({
  caseId,
  evidences,
  initialEvidenceId = "",
  initialPid = "",
  initialProcessGuid = "",
  initialSourceEventId = "",
  initialTimestamp = "",
  initialProcessName = "",
  initialHighlightedNodeIds = [],
  initialFindingId = "",
  openedFromSearchEventId = "",
  initialMode = initialHighlightedNodeIds.length || initialPid || initialProcessGuid || initialSourceEventId || initialProcessName || initialFindingId ? "focused" : "suspicious",
  selectedHost = "",
  selectedEvidenceId = "",
  debugThrowRenderError = false,
}: Props) {
  const navigate = useNavigate();
  const isDesktopLayout = useMinWidthQuery(1280);
  const graphViewportRef = useRef<HTMLDivElement | null>(null);
  const treeViewportRef = useRef<HTMLDivElement | null>(null);
  const initialStoryLoadRef = useRef(false);
  const defaultEvidenceId = initialEvidenceId || selectedEvidenceId;
  const [scope, setScope] = useState<"case" | "evidence">(defaultEvidenceId ? "evidence" : "case");
  const [evidenceId, setEvidenceId] = useState(defaultEvidenceId);
  const [pid, setPid] = useState(initialPid);
  const [processGuid, setProcessGuid] = useState(initialProcessGuid);
  const [processName, setProcessName] = useState(initialProcessName);
  const [mode, setMode] = useState<GraphMode>(initialMode);
  const [focusKind, setFocusKind] = useState<FocusKind>(initialFindingId ? "finding" : initialHighlightedNodeIds.length || initialPid || initialProcessGuid || initialSourceEventId || initialProcessName ? "process" : "chain");
  const [processFilter, setProcessFilter] = useState("");
  const [userFilter, setUserFilter] = useState("");
  const [riskMin, setRiskMin] = useState<number>(initialMode === "full" ? 0 : 40);
  const [showFilters, setShowFilters] = useState(false);
  const [selectedNodeId, setSelectedNodeId] = useState<string | null>(initialHighlightedNodeIds[0] || null);
  const [selectedChainId, setSelectedChainId] = useState<string | null>(null);
  const [detailDismissed, setDetailDismissed] = useState(false);
  const [contextDepthParents, setContextDepthParents] = useState<number>(initialMode === "focused" ? 1 : 0);
  const [contextDepthChildren, setContextDepthChildren] = useState<number>(initialMode === "focused" ? 1 : 0);
  const [includeSiblings, setIncludeSiblings] = useState(false);
  const [fullGraphConfirmed, setFullGraphConfirmed] = useState(false);
  const [includeActivity, setIncludeActivity] = useState(false);
  const [maxNodes, setMaxNodes] = useState(50);
  const [maxActivityPerProcess, setMaxActivityPerProcess] = useState(10);
  const [onlySuspiciousGraph, setOnlySuspiciousGraph] = useState(false);
  const [onlyMarkedGraph, setOnlyMarkedGraph] = useState(false);
  const [edgeTypes, setEdgeTypes] = useState<Set<string>>(() => new Set(["parent_child"]));
  const [expandedWarningGroups, setExpandedWarningGroups] = useState<Set<string>>(new Set());
  const [quickFilters, setQuickFilters] = useState<Set<QuickFilterId>>(() => new Set(mode === "suspicious" ? ["suspicious"] : []));
  const [expandedNodeIds, setExpandedNodeIds] = useState<Set<string>>(new Set(initialHighlightedNodeIds));
  const [submittedFocus, setSubmittedFocus] = useState<ProcessFocus | null>({
    scope: defaultEvidenceId ? "evidence" : "case",
    evidence_id: defaultEvidenceId || undefined,
    host: selectedHost || undefined,
    pid: initialPid ? Number(initialPid) : undefined,
    process_name: initialProcessName || undefined,
    entity_id: initialProcessGuid || initialHighlightedNodeIds[0] || undefined,
    source_event_id: initialSourceEventId || undefined,
    timestamp: initialTimestamp || undefined,
  });
  const [expansionNodes, setExpansionNodes] = useState<ProcessTreeNode[]>([]);
  const [expansionEdges, setExpansionEdges] = useState<ProcessTreeEdge[]>([]);
  const [expansionGroups, setExpansionGroups] = useState<Array<Record<string, unknown>>>([]);
  const [expansionOmittedCounts, setExpansionOmittedCounts] = useState<Record<string, number>>({});
  const [expansionNotice, setExpansionNotice] = useState<string | null>(null);
  const [expandingAction, setExpandingAction] = useState<string | null>(null);
  const [executionStory, setExecutionStory] = useState<ExecutionStory | null>(null);
  const [storyTab, setStoryTab] = useState<StoryTab>("overview");
  const [storyError, setStoryError] = useState<string | null>(null);
  const requestedStoryEventId = initialSourceEventId;
  const searchOriginEventId = openedFromSearchEventId;
  const isExactStoryContext =
    Boolean(requestedStoryEventId) ||
    executionStory?.quality?.identity_resolution?.method === "source_event_id" ||
    executionStory?.quality?.identity_resolution?.method === "process_guid";

  useEffect(() => {
    setEvidenceId(defaultEvidenceId);
    setScope(defaultEvidenceId ? "evidence" : "case");
  }, [defaultEvidenceId]);

  useEffect(() => {
    setSubmittedFocus((current) =>
      current
        ? {
            ...current,
            host: selectedHost || undefined,
            evidence_id: current.scope === "evidence" ? evidenceId || undefined : undefined,
          }
        : current,
    );
  }, [evidenceId, selectedHost]);

  useEffect(() => {
    setExpansionNodes([]);
    setExpansionEdges([]);
    setExpansionGroups([]);
    setExpansionOmittedCounts({});
    setExpansionNotice(null);
    setStoryError(null);
  }, [submittedFocus, includeActivity, maxNodes, maxActivityPerProcess, onlySuspiciousGraph, onlyMarkedGraph, edgeTypes]);

  useEffect(() => {
    setRiskMin(mode === "full" ? 0 : Math.max(riskMin, 40));
  }, [mode]);

  useEffect(() => {
    if (mode !== "full") {
      setFullGraphConfirmed(false);
    }
  }, [mode]);

  const query = useQuery({
    queryKey: ["process-tree-v2", caseId, submittedFocus, includeActivity, maxNodes, maxActivityPerProcess, onlySuspiciousGraph, onlyMarkedGraph, Array.from(edgeTypes).sort().join(",")],
    queryFn: () =>
      api.getProcessTree(caseId, {
        scope: submittedFocus?.scope ?? "case",
        evidence_id: submittedFocus?.scope === "evidence" ? submittedFocus.evidence_id : undefined,
        host: submittedFocus?.host,
        pid: submittedFocus?.pid,
        process_name: submittedFocus?.process_name,
        entity_id: submittedFocus?.entity_id,
        include_activity: includeActivity,
        aggregate_activity: true,
        edge_types: Array.from(edgeTypes).sort().join(","),
        max_nodes: maxNodes,
        max_activity_per_process: maxActivityPerProcess,
        only_suspicious: onlySuspiciousGraph,
        only_marked: onlyMarkedGraph,
      }),
    enabled: Boolean(caseId && submittedFocus),
    refetchOnWindowFocus: false,
  });

  const findingsQuery = useQuery({
    queryKey: ["process-graph-findings", caseId, selectedHost, evidenceId],
    queryFn: () => api.listFindings(caseId, { host: selectedHost || undefined, evidence_id: evidenceId || undefined }),
    enabled: Boolean(caseId),
    staleTime: 15_000,
    refetchOnWindowFocus: false,
  });

  const baseApiNodes = query.data?.graph.nodes ?? [];
  const baseApiEdges = query.data?.graph.edges ?? [];
  const apiNodes = useMemo(() => mergeNodes(baseApiNodes, expansionNodes), [baseApiNodes, expansionNodes]);
  const apiEdges = useMemo(() => mergeEdges(baseApiEdges, expansionEdges), [baseApiEdges, expansionEdges]);
  const activityGroups = useMemo(() => {
    const map = new Map<string, Record<string, unknown>>();
    for (const group of [...(query.data?.graph.groups ?? []), ...expansionGroups]) {
      map.set(String(group.id || `${group.source || ""}:${group.group || ""}`), group);
    }
    return Array.from(map.values());
  }, [expansionGroups, query.data?.graph.groups]);
  const omittedCounts = useMemo(() => {
    const merged: Record<string, number> = { ...((query.data?.graph.omitted_counts ?? {}) as Record<string, number>) };
    for (const [key, value] of Object.entries(expansionOmittedCounts)) {
      merged[key] = Number(merged[key] || 0) + Number(value || 0);
    }
    return merged;
  }, [expansionOmittedCounts, query.data?.graph.omitted_counts]);
  const apiNodeMap = useMemo(() => new Map(apiNodes.map((node) => [node.id, node])), [apiNodes]);
  const rawChainViews = useMemo(
    () =>
      chainViews(query.data, apiNodeMap)
        .filter((chain) => !chain.isInternalNoise)
        .sort((left, right) => right.riskScore - left.riskScore),
    [apiNodeMap, query.data],
  );
  const reconstructedNodes = useMemo(() => {
    const missing = new Map<string, ProcessTreeNode>();
    for (const chain of rawChainViews) {
      for (const node of chain.nodes) {
        if (apiNodeMap.has(node.id) || missing.has(node.id)) continue;
        missing.set(node.id, {
          ...node,
          data_quality: Array.from(new Set([...(node.data_quality || []), "chain_nodes_reconstructed"])),
          confidence: node.confidence || "low",
        });
      }
    }
    return Array.from(missing.values());
  }, [apiNodeMap, rawChainViews]);
  const rawNodes = useMemo(() => [...apiNodes, ...reconstructedNodes], [apiNodes, reconstructedNodes]);
  const reconstructedEdges = useMemo(() => {
    const existing = new Set(apiEdges.map((edge) => `${edge.source}->${edge.target}`));
    const missing: ProcessTreeEdge[] = [];
    for (const chain of rawChainViews) {
      if (!chain.edge) continue;
      const key = `${chain.edge.source}->${chain.edge.target}`;
      if (existing.has(key)) continue;
      missing.push({
        ...chain.edge,
        id: chain.edge.id || `reconstructed:${key}`,
      });
      existing.add(key);
    }
    return missing;
  }, [apiEdges, rawChainViews]);
  const rawEdges = useMemo(() => [...apiEdges, ...reconstructedEdges], [apiEdges, reconstructedEdges]);
  const nodeMap = useMemo(() => new Map(rawNodes.map((node) => [node.id, node])), [rawNodes]);
  const findingsByNodeId = useMemo(() => {
    const map = new Map<string, Finding[]>();
    for (const finding of findingsQuery.data ?? []) {
      for (const nodeId of finding.related_process_node_ids ?? []) {
        const current = map.get(nodeId) ?? [];
        current.push(finding);
        map.set(nodeId, current);
      }
    }
    return map;
  }, [findingsQuery.data]);
  const chains = rawChainViews;

  const matchesBaseFilters = (node: ProcessTreeNode) => {
    if (selectedHost && node.host && node.host !== selectedHost) return false;
    if (userFilter && !String(node.user || "").toLowerCase().includes(userFilter.toLowerCase())) return false;
    if (processFilter) {
      const haystack = `${node.name || ""} ${node.path || ""} ${node.command_line || ""}`.toLowerCase();
      if (!haystack.includes(processFilter.toLowerCase())) return false;
    }
    return true;
  };

  const matchesRiskAndQuickFilters = (node: ProcessTreeNode) => {
    if (riskMin && (node.risk_score || 0) < riskMin) return false;
    return matchesQuickFilters(node, quickFilters, (findingsByNodeId.get(node.id) ?? []).length);
  };

  const baseFilteredNodes = useMemo(() => rawNodes.filter(matchesBaseFilters), [rawNodes, processFilter, selectedHost, userFilter]);
  const suspiciousChains = useMemo(
    () =>
      chains.filter((chain) => {
        if (chain.riskScore < riskMin) return false;
        return chain.nodes.some((node) => matchesBaseFilters(node) && matchesRiskAndQuickFilters(node));
      }),
    [chains, findingsByNodeId, processFilter, quickFilters, rawNodes, riskMin, selectedHost, userFilter],
  );
  const activeChain = useMemo(() => {
    if (selectedChainId) {
      const selected = suspiciousChains.find((chain) => chain.id === selectedChainId) ?? chains.find((chain) => chain.id === selectedChainId) ?? null;
      if (selected) return selected;
    }
    return suspiciousChains[0] ?? null;
  }, [chains, selectedChainId, suspiciousChains]);
  const focusedFindingFromUrl = useMemo(
    () => (initialFindingId ? (findingsQuery.data ?? []).find((finding) => finding.id === initialFindingId) ?? null : null),
    [findingsQuery.data, initialFindingId],
  );
  const focusedProcessIds = useMemo(() => {
    const explicitIds = initialHighlightedNodeIds.filter((id) => nodeMap.has(id));
    if (explicitIds.length) return explicitIds;
    if (selectedNodeId && nodeMap.has(selectedNodeId)) return [selectedNodeId];
    if (initialPid.trim()) {
      const pidValue = Number(initialPid.trim());
      return baseFilteredNodes.filter((node) => node.pid === pidValue).slice(0, 8).map((node) => node.id);
    }
    if (initialProcessGuid.trim()) {
      const guid = initialProcessGuid.trim();
      return baseFilteredNodes.filter((node) => node.id === guid).slice(0, 8).map((node) => node.id);
    }
    if (initialProcessName.trim()) {
      const needle = initialProcessName.trim().toLowerCase();
      return baseFilteredNodes
        .filter((node) => `${node.name || ""} ${node.path || ""} ${node.command_line || ""}`.toLowerCase().includes(needle))
        .sort((left, right) => (right.risk_score || 0) - (left.risk_score || 0))
        .slice(0, 8)
        .map((node) => node.id);
    }
    return [];
  }, [baseFilteredNodes, initialHighlightedNodeIds, initialPid, initialProcessGuid, initialProcessName, nodeMap, selectedNodeId]);
  const focusSeedIds = useMemo(() => {
    if (focusKind === "finding") {
      const findingNodeIds = focusedFindingFromUrl?.related_process_node_ids?.filter((id) => nodeMap.has(id)) ?? [];
      if (findingNodeIds.length) return findingNodeIds;
    }
    if (focusKind === "process") {
      if (focusedProcessIds.length) return focusedProcessIds;
    }
    if (activeChain?.nodes.length) {
      return activeChain.nodes.map((node) => node.id).filter((id) => nodeMap.has(id));
    }
    if (selectedNodeId && nodeMap.has(selectedNodeId)) return [selectedNodeId];
    return [];
  }, [activeChain, focusKind, focusedFindingFromUrl?.related_process_node_ids, focusedProcessIds, nodeMap, selectedNodeId]);

  const visibleIds = useMemo(() => {
    if (mode === "full") {
      return new Set(baseFilteredNodes.filter(matchesRiskAndQuickFilters).map((node) => node.id));
    }
    if (mode === "focused") {
      const expanded = expandFocusedIds(focusSeedIds, rawEdges, nodeMap, contextDepthParents, contextDepthChildren, includeSiblings);
      const focusedIds = baseFilteredNodes.filter((node) => expanded.has(node.id)).map((node) => node.id);
      return new Set(focusedIds.length ? focusedIds : focusSeedIds.filter((id) => nodeMap.has(id)));
    }
    if (activeChain?.nodes.length) {
      return new Set(activeChain.nodes.map((node) => node.id).filter((id) => nodeMap.has(id)));
    }
    return new Set<string>();
  }, [
    activeChain,
    baseFilteredNodes,
    contextDepthChildren,
    contextDepthParents,
    focusSeedIds,
    includeSiblings,
    mode,
    nodeMap,
    rawEdges,
  ]);

  const visibleNodes = useMemo(() => rawNodes.filter((node) => visibleIds.has(node.id)), [rawNodes, visibleIds]);
  const visibleEdges = useMemo(() => rawEdges.filter((edge) => visibleIds.has(edge.source) && visibleIds.has(edge.target)), [rawEdges, visibleIds]);

  const maxRenderNodes = mode === "full" ? FULL_RENDER_NODES : FOCUSED_RENDER_NODES;
  const limitedNodes = useMemo(() => {
    if (visibleNodes.length <= maxRenderNodes) return visibleNodes;
    const priorityIds = new Set<string>([
      ...focusSeedIds,
      ...(selectedNodeId ? [selectedNodeId] : []),
      ...initialHighlightedNodeIds,
    ]);
    return [...visibleNodes]
      .sort((left, right) => {
        const leftPriority = priorityIds.has(left.id) ? 1 : 0;
        const rightPriority = priorityIds.has(right.id) ? 1 : 0;
        if (leftPriority !== rightPriority) return rightPriority - leftPriority;
        return (right.risk_score || 0) - (left.risk_score || 0);
      })
      .slice(0, maxRenderNodes);
  }, [focusSeedIds, initialHighlightedNodeIds, maxRenderNodes, selectedNodeId, visibleNodes]);

  const limitedNodeIds = useMemo(() => new Set(limitedNodes.map((node) => node.id)), [limitedNodes]);
  const limitedEdges = useMemo(() => visibleEdges.filter((edge) => limitedNodeIds.has(edge.source) && limitedNodeIds.has(edge.target)), [limitedNodeIds, visibleEdges]);
  const storyVisualNodes = useMemo(() => executionStory?.visual_tree?.nodes ?? [], [executionStory?.visual_tree?.nodes]);
  const storyVisualEdges = useMemo(() => executionStory?.visual_tree?.edges ?? [], [executionStory?.visual_tree?.edges]);
  const storyVisualTargetId = executionStory?.target_node_id || executionStory?.default_selected_node_id || executionStory?.target?.id || null;
  const isExactStoryActive = Boolean(isExactStoryContext && executionStory?.target && storyVisualNodes.length);
  const graphNodes = useMemo(() => (isExactStoryActive ? storyVisualNodes : limitedNodes), [isExactStoryActive, limitedNodes, storyVisualNodes]);
  const graphNodeIds = useMemo(() => new Set(graphNodes.map((node) => node.id)), [graphNodes]);
  const graphEdges = useMemo(
    () => (isExactStoryActive ? storyVisualEdges.filter((edge) => graphNodeIds.has(edge.source) && graphNodeIds.has(edge.target)) : limitedEdges),
    [graphNodeIds, isExactStoryActive, limitedEdges, storyVisualEdges],
  );
  const exactStoryTargetMissing = Boolean(isExactStoryActive && storyVisualTargetId && !graphNodeIds.has(storyVisualTargetId));
  const visibleChains = useMemo(() => {
    if (mode !== "full") return suspiciousChains;
    const chainList = suspiciousChains.filter((chain) => chain.nodes.every((node) => limitedNodeIds.has(node.id)));
    if (chainList.length) return chainList;
    return suspiciousChains.filter((chain) => chain.nodes.some((node) => limitedNodeIds.has(node.id)));
  }, [limitedNodeIds, mode, suspiciousChains]);
  const graphWarningGroups = useMemo(() => {
    const groups = groupGraphWarnings((query.data?.graph.summary as Record<string, unknown> | undefined) ?? undefined);
    if (visibleNodes.length > maxRenderNodes) {
      groups.unshift({
        key: "graph_truncated",
        count: visibleNodes.length - maxRenderNodes,
        message: `Graph truncated to ${maxRenderNodes} nodes. Refine filters or switch to focused mode.`,
        samples: [],
      });
    }
    return groups;
  }, [maxRenderNodes, query.data?.graph.summary, visibleNodes.length]);
  const orphanDiagnostics = useMemo(() => {
    const raw = (query.data?.graph.summary as Record<string, unknown> | undefined)?.orphan_diagnostics;
    return Array.isArray(raw) ? (raw as Array<Record<string, unknown>>) : [];
  }, [query.data?.graph.summary]);
  const graphLayout = useMemo(() => buildGraphLayout(graphNodes, graphEdges), [graphEdges, graphNodes]);
  const graphLayoutMap = useMemo(() => new Map(graphLayout.nodes.map((node) => [node.id, node])), [graphLayout.nodes]);

  const forest = useMemo(() => buildForest(graphNodes, graphEdges), [graphEdges, graphNodes]);
  const lineageIds = useMemo(() => lineageForNode(selectedNodeId, graphEdges), [graphEdges, selectedNodeId]);

  useEffect(() => {
    const next = new Set<string>();
    for (const branch of forest) next.add(branch.node.id);
    for (const id of initialHighlightedNodeIds) next.add(id);
    for (const id of lineageIds) next.add(id);
    setExpandedNodeIds((current) => {
      let changed = false;
      const merged = new Set(current);
      next.forEach((id) => {
        if (!merged.has(id)) {
          merged.add(id);
          changed = true;
        }
      });
      return changed ? merged : current;
    });
  }, [forest, initialHighlightedNodeIds, lineageIds]);

  useEffect(() => {
    if (!isDesktopLayout && detailDismissed && !selectedNodeId) return;
    if (isExactStoryActive) {
      if (selectedNodeId) return;
      setSelectedNodeId(storyVisualTargetId || graphNodes[0]?.id || null);
      return;
    }
    if (selectedNodeId && graphNodeIds.has(selectedNodeId)) return;
    const preferredId = activeChain?.nodes[activeChain.nodes.length - 1]?.id || initialHighlightedNodeIds[0] || (isDesktopLayout ? graphNodes[0]?.id : null) || null;
    setSelectedNodeId(preferredId);
  }, [activeChain, detailDismissed, graphNodeIds, graphNodes, initialHighlightedNodeIds, isDesktopLayout, isExactStoryActive, selectedNodeId, storyVisualTargetId]);

  const selectedNode = selectedNodeId ? graphNodes.find((node) => node.id === selectedNodeId) ?? nodeMap.get(selectedNodeId) ?? null : null;
  const isPreviewingStoryNode = Boolean(isExactStoryActive && selectedNode && storyVisualTargetId && selectedNode.id !== storyVisualTargetId);
  const selectedRelatedFindings = selectedNode ? findingsByNodeId.get(selectedNode.id) ?? [] : [];
  const selectedChildNodes = useMemo(() => {
    if (!selectedNode) return [];
    const childIds = new Set(rawEdges.filter((edge) => edge.source === selectedNode.id && ["spawned", "parent_child"].includes(edge.type)).map((edge) => edge.target));
    return Array.from(childIds).map((id) => nodeMap.get(id)).filter(Boolean) as ProcessTreeNode[];
  }, [nodeMap, rawEdges, selectedNode]);
  const selectedSiblingNodes = useMemo(() => {
    if (!selectedNode) return [];
    const parentIds = new Set(rawEdges.filter((edge) => edge.target === selectedNode.id && ["spawned", "parent_child"].includes(edge.type)).map((edge) => edge.source));
    if (!parentIds.size) return [];
    const siblingIds = new Set(
      rawEdges
        .filter((edge) => parentIds.has(edge.source) && edge.target !== selectedNode.id && ["spawned", "parent_child"].includes(edge.type))
        .map((edge) => edge.target),
    );
    return Array.from(siblingIds).map((id) => nodeMap.get(id)).filter(Boolean) as ProcessTreeNode[];
  }, [nodeMap, rawEdges, selectedNode]);
  const selectedActivitySummary = useMemo(() => {
    if (!selectedNode) return { file: 0, registry: 0, network: 0, dns: 0 };
    const summary = { file: 0, registry: 0, network: 0, dns: 0 };
    for (const group of activityGroups) {
      if (String(group.source || "") !== selectedNode.id) continue;
      const key = String(group.group || "");
      if (key in summary) summary[key as keyof typeof summary] += Number(group.count || 0);
    }
    for (const edge of rawEdges) {
      if (edge.source !== selectedNode.id) continue;
      if (edge.type === "file_activity") summary.file += 1;
      else if (edge.type === "registry_activity") summary.registry += 1;
      else if (edge.type === "network_activity") summary.network += 1;
      else if (edge.type === "dns_activity") summary.dns += 1;
    }
    return summary;
  }, [activityGroups, rawEdges, selectedNode]);
  const selectedParentSentence = useMemo(() => {
    if (!selectedNode) return "";
    const processLabel = selectedNode.name || selectedNode.path || "this process";
    const pidLabel = selectedNode.pid !== null && selectedNode.pid !== undefined ? ` PID ${selectedNode.pid}` : "";
    if (selectedNode.parent_link_status === "linked" && (selectedNode.parent_name || (selectedNode.parent_pid !== null && selectedNode.parent_pid !== undefined))) {
      const parentLabel = selectedNode.parent_name || "its parent process";
      const parentPid = selectedNode.parent_pid !== null && selectedNode.parent_pid !== undefined ? ` PID ${selectedNode.parent_pid}` : "";
      return `This ${processLabel}${pidLabel} was launched by ${parentLabel}${parentPid}.`;
    }
    return "Parent process could not be linked from available events.";
  }, [selectedNode]);
  const focusedFinding = useMemo(() => {
    if (focusedFindingFromUrl) return focusedFindingFromUrl;
    const candidateNodeIds = activeChain?.nodes.map((node) => node.id) ?? (selectedNode ? [selectedNode.id] : []);
    for (const nodeId of candidateNodeIds) {
      const finding = (findingsByNodeId.get(nodeId) ?? [])[0];
      if (finding) return finding;
    }
    return null;
  }, [activeChain?.nodes, findingsByNodeId, focusedFindingFromUrl, selectedNode]);
  const focusChipLabel = useMemo(() => {
    if (isExactStoryContext && executionStory?.target) return `Exact story: ${toNodeLabel(executionStory.target)}`;
    if (focusKind === "finding" && focusedFinding) return `Focused on finding: ${focusedFinding.title}`;
    if (focusKind === "process") {
      const firstFocusedNode = focusSeedIds.map((id) => nodeMap.get(id)).find(Boolean) ?? null;
      return `Focused on process: ${firstFocusedNode ? toNodeLabel(firstFocusedNode) : initialProcessName || "selected process"}`;
    }
    if (activeChain) return `Focused on suspicious chain: ${activeChain.title}`;
    return "Focused on process chain";
  }, [activeChain, executionStory?.target, focusKind, focusSeedIds, focusedFinding, initialProcessName, isExactStoryContext, nodeMap]);
  const modeBanner = useMemo(() => {
    if (mode === "full") {
      return {
        title: "Advanced graph",
        message: "Broader graph view. Filters and noise controls may hide context.",
        tone: "border-amber-400/30 bg-amber-400/10 text-amber-100",
      };
    }
    if (isExactStoryContext) {
      return {
        title: "Exact story",
        message: "Built from a selected event or process identity. Parent and direct children stay visible even when they are low risk.",
        tone: "border-emerald-400/30 bg-emerald-500/10 text-emerald-100",
      };
    }
    if (mode === "focused") {
      return {
        title: "Process search",
        message: focusKind === "process" ? "Select a process candidate to build an exact story." : "Showing the selected chain plus nearby parent/child context.",
        tone: "border-cyan-400/30 bg-cyan-500/10 text-cyan-100",
      };
    }
    return {
      title: "Process search",
      message: "Select a chain to inspect. Low-noise browser internals are hidden by default.",
      tone: "border-emerald-400/30 bg-emerald-500/10 text-emerald-100",
    };
  }, [focusKind, isExactStoryContext, mode]);
  const storyTarget = executionStory?.target ?? selectedNode ?? null;
  const storySubtitle = storyTarget
    ? `Investigating ${storyTarget.name || storyTarget.path || "process"}${storyTarget.pid !== null && storyTarget.pid !== undefined ? ` PID ${storyTarget.pid}` : ""}${storyTarget.host ? ` on ${storyTarget.host}` : selectedHost ? ` on ${selectedHost}` : ""}`
    : "Select a process to build a story";
  const storyIdentityLabel = executionStory?.quality?.identity_resolution?.method === "source_event_id"
    ? "source event"
    : executionStory?.quality?.identity_resolution?.method === "process_guid"
      ? "process guid"
      : executionStory?.quality?.identity_resolution?.method === "pid_time"
        ? "PID and time"
        : executionStory?.quality?.identity_resolution?.method || "process identity";
  const storyHasParentUncertainty = Boolean(
    executionStory?.quality?.missing_parent ||
    (selectedNode?.parent_link_status && !["linked", "unknown"].includes(selectedNode.parent_link_status)),
  );

  function copyText(value?: string | null) {
    if (!value) return;
    void navigator.clipboard?.writeText(value);
  }

  const selectedNodeDetail = selectedNode ? (
    <div className="mt-4 space-y-4" data-testid="selected-node-detail">
      <div className="rounded-2xl border border-line bg-abyss/70 p-4">
        <div className="flex flex-wrap items-center gap-2">
          {nodeIcon(selectedNode)}
          <span className="break-words text-base font-semibold">{toNodeLabel(selectedNode)}</span>
          <Pill className={riskTone(selectedNode.risk_score || 0)}>risk {selectedNode.risk_score || 0}</Pill>
          {isPreviewingStoryNode ? (
            <Pill className="border-amber-300/40 bg-amber-300/10 text-amber-100">Previewing node</Pill>
          ) : null}
        </div>
        <div className="mt-3 space-y-2 text-sm text-muted">
          {isPreviewingStoryNode && executionStory?.target ? (
            <p className="rounded-xl border border-emerald-400/20 bg-emerald-500/10 px-3 py-2 text-emerald-100">
              Story target remains {toNodeLabel(executionStory.target)}. Use Make target to change it.
            </p>
          ) : null}
          <p className="rounded-xl border border-cyan-400/20 bg-cyan-500/10 px-3 py-2 text-cyan-100">{selectedParentSentence}</p>
          <p><span className="text-white/90">PID:</span> {selectedNode.pid ?? "—"}</p>
          <p className="break-words"><span className="text-white/90">Path:</span> {normalizeValue(selectedNode.path)}</p>
          <p className="break-words"><span className="text-white/90">Command:</span> {normalizeValue(selectedNode.command_line)}</p>
          <p className="break-words"><span className="text-white/90">User:</span> {normalizeValue(selectedNode.user)}</p>
          <p className="break-words"><span className="text-white/90">Host:</span> {normalizeValue(selectedNode.host)}</p>
          <p className="break-words"><span className="text-white/90">Parent:</span> {normalizeValue(selectedNode.parent_name)} ({selectedNode.parent_pid ?? "—"})</p>
          <p className="break-words">
            <span className="text-white/90">Children:</span> {selectedChildNodes.length} direct · suspicious {selectedChildNodes.filter((node) => (node.risk_score || 0) >= 40).length}
            {selectedChildNodes.length ? ` · ${selectedChildNodes.slice(0, 5).map((node) => node.name || node.path || node.id).join(", ")}` : ""}
          </p>
          <p className="break-words"><span className="text-white/90">Siblings:</span> {selectedSiblingNodes.length}</p>
          <p className="break-words">
            <span className="text-white/90">Activity:</span> file {selectedActivitySummary.file} · registry {selectedActivitySummary.registry} · network {selectedActivitySummary.network} · dns {selectedActivitySummary.dns}
          </p>
        </div>
        <div className="mt-4 grid gap-3">
          <div>
            <p className="font-mono text-[11px] uppercase tracking-[0.16em] text-muted">Primary</p>
            <div className="mt-2 flex flex-wrap gap-2">
              <button type="button" onClick={() => openFocusedTree(selectedNode)} disabled={expandingAction === `focused:${selectedNode.id}`} title="Build story for this exact process event." className="rounded-xl border border-accent/40 bg-accent/10 px-3 py-1.5 text-xs text-accent disabled:opacity-50">
                {expandingAction === `focused:${selectedNode.id}` ? "Building…" : "Make target"}
              </button>
              <button type="button" onClick={() => navigateToSearch("process_name", selectedNode.name || "")} className="rounded-xl border border-line bg-panel/40 px-3 py-1.5 text-xs text-muted">
                Open Search
              </button>
              <button type="button" onClick={() => openCommandHistory(selectedNode)} className="rounded-xl border border-line bg-panel/40 px-3 py-1.5 text-xs text-muted">
                Command History
              </button>
            </div>
          </div>

          <div>
            <p className="font-mono text-[11px] uppercase tracking-[0.16em] text-muted">Explore</p>
            <div className="mt-2 flex flex-wrap gap-2">
              <button type="button" onClick={() => expandNode(selectedNode, "parents")} disabled={expandingAction === `parents:${selectedNode.id}`} className="rounded-xl border border-cyan-400/30 bg-cyan-500/10 px-3 py-1.5 text-xs text-cyan-100 disabled:opacity-50">
                {expandingAction === `parents:${selectedNode.id}` ? "Expanding…" : "Parents"}
              </button>
              <button type="button" onClick={() => expandNode(selectedNode, "children")} disabled={expandingAction === `children:${selectedNode.id}`} className="rounded-xl border border-cyan-400/30 bg-cyan-500/10 px-3 py-1.5 text-xs text-cyan-100 disabled:opacity-50">
                {expandingAction === `children:${selectedNode.id}` ? "Expanding…" : "Children"}
              </button>
              <button type="button" onClick={() => expandNode(selectedNode, "siblings")} disabled={expandingAction === `siblings:${selectedNode.id}`} className="rounded-xl border border-cyan-400/30 bg-cyan-500/10 px-3 py-1.5 text-xs text-cyan-100 disabled:opacity-50">
                {expandingAction === `siblings:${selectedNode.id}` ? "Expanding…" : "Siblings"}
              </button>
              <button type="button" onClick={() => expandNode(selectedNode, "activity")} disabled={expandingAction === `activity:${selectedNode.id}`} className="rounded-xl border border-cyan-400/30 bg-cyan-500/10 px-3 py-1.5 text-xs text-cyan-100 disabled:opacity-50">
                {expandingAction === `activity:${selectedNode.id}` ? "Loading…" : "Activity"}
              </button>
            </div>
          </div>

          <div>
            <p className="font-mono text-[11px] uppercase tracking-[0.16em] text-muted">Evidence</p>
            <div className="mt-2 flex flex-wrap gap-2">
              {selectedNode.source_events?.[0] ? (
                <button type="button" onClick={() => openSourceEvent(selectedNode)} className="rounded-xl border border-line bg-panel/40 px-3 py-1.5 text-xs text-muted">
                  Source event
                </button>
              ) : null}
              <button type="button" onClick={() => openInTimeline(selectedNode)} className="rounded-xl border border-line bg-panel/40 px-3 py-1.5 text-xs text-muted">
                Timeline
              </button>
              {selectedNode.command_line ? (
                <button type="button" onClick={() => copyText(selectedNode.command_line)} className="rounded-xl border border-line bg-panel/40 px-3 py-1.5 text-xs text-muted">
                  Copy command
                </button>
              ) : null}
              {selectedNode.path ? (
                <button type="button" onClick={() => copyText(selectedNode.path)} className="rounded-xl border border-line bg-panel/40 px-3 py-1.5 text-xs text-muted">
                  Copy path
                </button>
              ) : null}
            </div>
          </div>

          <details className="rounded-xl border border-line/80 bg-panel/30 p-3">
            <summary className="cursor-pointer font-mono text-[11px] uppercase tracking-[0.16em] text-muted">Advanced / Diagnostics</summary>
            <div className="mt-3 space-y-3 text-xs text-muted">
              <div className="grid gap-2">
                <p className="break-all"><span className="text-white/90">ProcessGuid:</span> {normalizeValue(selectedNode.id)}</p>
                <p className="break-words"><span className="text-white/90">Source:</span> {normalizeValue(selectedNode.source_type)} · event {normalizeValue(selectedNode.source_event_id || selectedNode.source_events?.[0])}</p>
                <p><span className="text-white/90">First seen:</span> {compactTimestamp(selectedNode.first_seen)}</p>
                <p><span className="text-white/90">Last seen:</span> {compactTimestamp(selectedNode.last_seen)}</p>
                <p className="break-words"><span className="text-white/90">Parent status:</span> {normalizeValue(selectedNode.parent_link_status || "unknown")} · {normalizeValue(selectedNode.parent_link_confidence || "none")}</p>
                <p className="break-words"><span className="text-white/90">Parent reason:</span> {normalizeValue(selectedNode.parent_link_reason)}</p>
                {selectedNode.parent_fields ? (
                  <p className="break-words">
                    <span className="text-white/90">Parent fields:</span>{" "}
                    name={normalizeValue(selectedNode.parent_fields.parent_name)} · pid={selectedNode.parent_fields.parent_pid ?? "—"} · guid={normalizeValue(selectedNode.parent_fields.parent_entity_id)}
                  </p>
                ) : null}
              </div>
              <div className="flex flex-wrap gap-2">
                {selectedNode.parent_name || selectedNode.parent_pid ? (
                  <button type="button" onClick={() => navigateToSearch("q", selectedNode.parent_name || String(selectedNode.parent_pid || ""))} className="rounded-xl border border-line bg-panel/40 px-3 py-1.5 text-xs text-muted">
                    Search parent candidate
                  </button>
                ) : null}
                <button type="button" onClick={() => navigateToSearch("q", selectedNode.command_line || selectedNode.name || "")} className="rounded-xl border border-line bg-panel/40 px-3 py-1.5 text-xs text-muted">
                  Search command
                </button>
                {selectedNode.path ? (
                  <button type="button" onClick={() => navigateToSearch("file_path", selectedNode.path || "")} className="rounded-xl border border-line bg-panel/40 px-3 py-1.5 text-xs text-muted">
                    Search path
                  </button>
                ) : null}
                {expansionNodes.length || expansionEdges.length || expansionGroups.length ? (
                  <button type="button" onClick={clearExpansions} className="rounded-xl border border-line bg-panel/40 px-3 py-1.5 text-xs text-muted">
                    Collapse expansions
                  </button>
                ) : null}
                <button type="button" onClick={exportVisibleGraphJson} className="rounded-xl border border-line bg-panel/40 px-3 py-1.5 text-xs text-muted">
                  Export JSON
                </button>
              </div>
            </div>
          </details>
        </div>
      </div>

      <div className="rounded-2xl border border-line bg-abyss/70 p-4">
        <p className="font-mono text-[11px] uppercase tracking-[0.16em] text-muted">Badges & quality</p>
        <div className="mt-3 flex flex-wrap gap-2">
          {(selectedNode.badges || []).map((badge) => (
            <Pill key={`${selectedNode.id}-${badge}`} className={badgeTone(badge)}>
              {badge}
            </Pill>
          ))}
          {(selectedNode.data_quality || []).map((flag) => (
            <Pill key={`${selectedNode.id}-${flag}`} className="border-line bg-white/5 text-muted">
              {flag}
            </Pill>
          ))}
          {!(selectedNode.badges || []).length && !(selectedNode.data_quality || []).length ? <span className="text-sm text-muted">No badges or quality flags.</span> : null}
        </div>
      </div>

      <div className="rounded-2xl border border-line bg-abyss/70 p-4">
        <p className="font-mono text-[11px] uppercase tracking-[0.16em] text-muted">Risk reasons</p>
        <div className="mt-3 space-y-2">
          {(selectedNode.risk_reasons || []).length ? (selectedNode.risk_reasons || []).map((reason) => (
            <p key={`${selectedNode.id}-${reason}`} className="break-words rounded-xl border border-line/70 bg-panel/40 px-3 py-2 text-sm text-muted">
              {reason}
            </p>
          )) : <p className="text-sm text-muted">No explicit reasons attached.</p>}
        </div>
      </div>

      <div className="rounded-2xl border border-line bg-abyss/70 p-4">
        <p className="font-mono text-[11px] uppercase tracking-[0.16em] text-muted">Related findings</p>
        <div className="mt-3 space-y-2">
          {selectedRelatedFindings.length ? selectedRelatedFindings.map((finding) => (
            <button key={finding.id} type="button" onClick={() => openRelatedFinding(finding)} className="w-full rounded-2xl border border-line/70 bg-panel/40 p-3 text-left text-sm">
              <div className="flex items-center justify-between gap-3">
                <span className="break-words font-semibold">{finding.title}</span>
                <Pill className={riskTone(finding.risk_score || 0)}>{finding.severity}</Pill>
              </div>
              <p className="mt-1 break-words text-xs text-muted">{finding.summary || finding.finding_type || "Related finding"}</p>
            </button>
          )) : <p className="text-sm text-muted">No related findings for this node.</p>}
        </div>
      </div>

      {!isExactStoryActive && activeChain?.edge ? (
        <div className="rounded-2xl border border-line bg-abyss/70 p-4">
          <p className="font-mono text-[11px] uppercase tracking-[0.16em] text-muted">Focused edge</p>
          <div className="mt-3 space-y-2 text-sm text-muted">
            <p className="break-all"><span className="text-white/90">Parent:</span> {activeChain.edge.source}</p>
            <p className="break-all"><span className="text-white/90">Child:</span> {activeChain.edge.target}</p>
            <p><span className="text-white/90">Confidence:</span> {activeChain.edge.confidence}</p>
            <p className="break-words"><span className="text-white/90">Reason:</span> {activeChain.edge.reason}</p>
            <p className="break-all"><span className="text-white/90">Source event:</span> {normalizeValue(activeChain.edge.source_event_id)}</p>
          </div>
        </div>
      ) : null}
    </div>
  ) : (
    <p className="mt-4 text-sm text-muted">Select a node or a suspicious chain to inspect its context.</p>
  );
  const storyTabs: Array<{ id: StoryTab; label: string }> = [
    { id: "overview", label: "Overview" },
    { id: "parents", label: "Parents" },
    { id: "children", label: "Children" },
    { id: "activity", label: "Activity" },
    { id: "commands", label: "Commands" },
    { id: "source", label: "Source events" },
    { id: "advanced", label: "Advanced" },
  ];
  const storyPanel = executionStory || storyTarget ? (
    <div className="rounded-[28px] border border-accent/30 bg-panel/75 p-5 shadow-panel">
      <div className="flex flex-wrap items-start justify-between gap-4">
        <div className="min-w-0">
          <h4 className="text-xl font-semibold">Execution Story</h4>
          <p className="mt-2 max-w-4xl text-sm text-muted">{storySubtitle}</p>
        </div>
        {storyTarget ? (
          <div className="flex flex-wrap gap-2">
            {isExactStoryContext ? (
              <Pill className="border-emerald-400/40 bg-emerald-500/10 text-emerald-100">Exact story</Pill>
            ) : executionStory ? (
              <Pill className="border-warning/40 bg-warning/10 text-warning">Fallback resolved</Pill>
            ) : null}
            {searchOriginEventId ? <Pill className="border-accent/40 bg-accent/10 text-accent">Opened from Search event</Pill> : null}
            {executionStory ? <Pill className="border-line bg-white/5 text-muted">Identity: {storyIdentityLabel}</Pill> : null}
            {storyTarget.host ? <Pill className="border-cyan-400/40 bg-cyan-500/10 text-cyan-100">Host {storyTarget.host}</Pill> : null}
            {evidenceId ? <Pill className="border-line bg-white/5 text-muted">Evidence</Pill> : null}
            {isPreviewingStoryNode && selectedNode ? (
              <Pill className="border-amber-300/40 bg-amber-300/10 text-amber-100">Current preview: {toNodeLabel(selectedNode)}</Pill>
            ) : null}
            {searchOriginEventId ? (
              <button type="button" onClick={backToSearchEvent} className="rounded-xl border border-line bg-abyss/70 px-3 py-1 text-xs text-muted">
                Back to Search event
              </button>
            ) : null}
          </div>
        ) : null}
      </div>

      {storyError ? <p className="mt-4 rounded-2xl border border-danger/40 bg-danger/10 p-3 text-sm text-danger">{storyError}</p> : null}
      {exactStoryTargetMissing ? (
        <p className="mt-4 rounded-2xl border border-danger/40 bg-danger/10 p-3 text-sm text-danger">
          Exact story target missing from visual tree.
        </p>
      ) : null}
      {requestedStoryEventId && executionStory && executionStory.quality?.identity_resolution?.method !== "source_event_id" ? (
        <p className="mt-4 rounded-2xl border border-warning/40 bg-warning/10 p-3 text-sm text-warning">
          Exact event id was not available in the resolved graph; the story was resolved by {executionStory.quality?.identity_resolution?.method || "fallback"}.
        </p>
      ) : null}
      {mode === "focused" && riskMin > 0 ? (
        <p className="mt-4 rounded-2xl border border-line bg-abyss/70 p-3 text-sm text-muted">
          Risk filters only affect candidate search, suspicious chain suggestions and extra context. They do not hide the exact target, parents or direct children.
        </p>
      ) : null}
      {storyHasParentUncertainty ? (
        <p className="mt-4 rounded-2xl border border-amber-400/30 bg-amber-400/10 p-3 text-sm text-amber-100">
          Some parent links are uncertain. Details available in Diagnostics.
        </p>
      ) : null}

      {executionStory && !storyTarget && executionStory.quality?.response_mode === "lightweight" ? (
        <div className="mt-5 rounded-2xl border border-warning/40 bg-warning/10 p-4">
          <div className="flex flex-wrap items-start justify-between gap-3">
            <div>
              <p className="font-mono text-[11px] uppercase tracking-[0.16em] text-warning">
                {executionStory.quality.target_quality === "generic" ? "Generic event" : "Process-related event"}
              </p>
              <h3 className="mt-2 text-lg font-semibold text-warning">This is not an exact process creation event.</h3>
              <p className="mt-2 max-w-3xl text-sm text-muted">
                Select a candidate process to build an exact story. Heavy graph and activity expansion were skipped for the first response.
              </p>
            </div>
            {executionStory.quality.cache?.hit ? <Pill className="border-line bg-white/5 text-muted">Cached</Pill> : null}
          </div>
          {executionStory.event_summary ? (
            <div className="mt-4 grid gap-3 rounded-xl border border-line bg-abyss/70 p-3 text-sm text-muted md:grid-cols-2">
              <p><span className="text-white/90">Source:</span> {normalizeValue(String(executionStory.event_summary.source || ""))}</p>
              <p><span className="text-white/90">Host:</span> {normalizeValue(String(executionStory.event_summary.host || ""))}</p>
              <p><span className="text-white/90">Timestamp:</span> {compactTimestamp(String(executionStory.event_summary.timestamp || ""))}</p>
              <p className="break-words"><span className="text-white/90">Event:</span> {normalizeValue(String(executionStory.event_summary.title || executionStory.event_summary.summary || ""))}</p>
            </div>
          ) : null}
          <div className="mt-4">
            <p className="font-mono text-[11px] uppercase tracking-[0.16em] text-muted">Candidate processes</p>
            <div className="mt-2 grid gap-2">
              {(executionStory.candidate_processes || []).length ? executionStory.candidate_processes!.map((candidate) => (
                <button
                  key={`candidate-${candidate.id}`}
                  type="button"
                  onClick={() => openFocusedTree(candidate)}
                  className="rounded-xl border border-line bg-panel/50 p-3 text-left text-sm transition hover:border-accent/50 hover:bg-accent/10"
                  title="Build exact story from this process"
                >
                  <span className="font-semibold">{toNodeLabel(candidate)}</span>
                  <span className="ml-2 text-xs text-muted">{compactTimestamp(candidate.first_seen)} · {normalizeValue(candidate.host)}</span>
                  <span className="mt-1 block break-words text-xs text-muted">{normalizeValue(candidate.command_line || candidate.path)}</span>
                </button>
              )) : (
                <p className="rounded-xl border border-line bg-abyss/70 p-3 text-sm text-muted">
                  No nearby process candidates were found. Use Search around the event or Command History around the same time window.
                </p>
              )}
            </div>
          </div>
        </div>
      ) : null}

      {storyTarget ? (
        <div className="mt-5 grid gap-4 xl:grid-cols-[0.95fr_1.2fr]">
          <div className="rounded-2xl border border-line bg-abyss/70 p-4">
            <p className="font-mono text-[11px] uppercase tracking-[0.16em] text-muted">Investigation target</p>
            <div className="mt-3 space-y-2 text-sm text-muted">
              <p><span className="text-white/90">Process:</span> {normalizeValue(storyTarget.name)}</p>
              <p><span className="text-white/90">PID:</span> {storyTarget.pid ?? "—"}</p>
              <p className="break-words"><span className="text-white/90">Host/User:</span> {normalizeValue(storyTarget.host)} · {normalizeValue(storyTarget.user)}</p>
              <p><span className="text-white/90">Timestamp:</span> {compactTimestamp(storyTarget.first_seen)}</p>
              <p className="break-words"><span className="text-white/90">Command:</span> {normalizeValue(storyTarget.command_line || storyTarget.path)}</p>
            </div>
          </div>

          <div className="rounded-2xl border border-line bg-abyss/70 p-4">
            <p className="font-mono text-[11px] uppercase tracking-[0.16em] text-muted">What happened</p>
            <div className="mt-3 grid gap-2 text-sm">
              {(executionStory?.story.parent_sentence || selectedParentSentence) ? (
                <p className="rounded-xl border border-cyan-400/20 bg-cyan-500/10 px-3 py-2 text-cyan-100">{executionStory?.story.parent_sentence || selectedParentSentence}</p>
              ) : null}
              {executionStory?.story.children_sentence ? (
                <p className="rounded-xl border border-line bg-panel/40 px-3 py-2 text-muted">{executionStory.story.children_sentence}</p>
              ) : (
                <p className="rounded-xl border border-line bg-panel/40 px-3 py-2 text-muted">
                  {selectedChildNodes.length ? `It launched ${selectedChildNodes.length} direct child processes: ${selectedChildNodes.slice(0, 5).map((node) => toNodeLabel(node)).join(", ")}.` : "No child processes were observed for this process."}
                </p>
              )}
              {executionStory?.story.activity_sentence ? (
                <p className="rounded-xl border border-line bg-panel/40 px-3 py-2 text-muted">{executionStory.story.activity_sentence}</p>
              ) : (
                <p className="rounded-xl border border-line bg-panel/40 px-3 py-2 text-muted">
                  No file, registry, network or DNS activity was linked to this process.
                </p>
              )}
              {(executionStory?.story.risk_sentence || (storyTarget.risk_reasons || []).length) ? (
                <p className="rounded-xl border border-orange-400/20 bg-orange-500/10 px-3 py-2 text-orange-100">
                  {executionStory?.story.risk_sentence || `Suspicious because ${(storyTarget.risk_reasons || []).slice(0, 3).join(", ")}.`}
                </p>
              ) : null}
            </div>
          </div>
        </div>
      ) : null}

      <div className="mt-5 flex flex-wrap gap-2 border-b border-line/70 pb-2">
        {storyTabs.map((tab) => (
          <button
            key={tab.id}
            type="button"
            onClick={() => setStoryTab(tab.id)}
            className={`rounded-xl border px-3 py-1.5 text-xs ${storyTab === tab.id ? "border-accent/50 bg-accent/15 text-accent" : "border-line bg-abyss/70 text-muted"}`}
          >
            {tab.label}
          </button>
        ))}
      </div>

      <div className="mt-4">
        {storyTab === "overview" ? (
          <div className="grid gap-3 md:grid-cols-4">
            <SummaryBadge label="Parents" value={executionStory?.parents.length ?? (selectedNode?.parent_name ? 1 : 0)} />
            <SummaryBadge label="Children" value={executionStory?.children.length ?? selectedChildNodes.length} />
            <SummaryBadge label="Siblings" value={executionStory?.siblings.length ?? selectedSiblingNodes.length} />
            <SummaryBadge label="Source events" value={executionStory?.source_events.length ?? storyTarget?.source_events?.length ?? 0} />
          </div>
        ) : null}

        {storyTab === "parents" ? (
          <div className="grid gap-2">
            {(executionStory?.parents ?? []).length ? (executionStory?.parents ?? []).map((node) => (
              <button key={`parent-${node.id}`} type="button" onClick={() => setSelectedNodeId(node.id)} className="rounded-2xl border border-line bg-abyss/70 p-3 text-left text-sm">
                <span className="font-semibold">{toNodeLabel(node)}</span>
                <span className="ml-2 text-muted">{nodePidLabel(node)} · {compactTimestamp(node.first_seen)}</span>
                <span className="mt-1 block break-words text-xs text-muted">{node.command_line || node.path || "No command line"}</span>
              </button>
            )) : <p className="text-sm text-muted">Parent process could not be linked from available events.</p>}
          </div>
        ) : null}

        {storyTab === "children" ? (
          <div className="overflow-auto rounded-2xl border border-line">
            <table className="min-w-full divide-y divide-line text-sm">
              <thead className="bg-abyss/70 text-left font-mono text-[11px] uppercase tracking-[0.14em] text-muted">
                <tr><th className="px-3 py-2">Time</th><th className="px-3 py-2">Child process</th><th className="px-3 py-2">PID</th><th className="px-3 py-2">Command line</th><th className="px-3 py-2">Risk</th><th className="px-3 py-2">Actions</th></tr>
              </thead>
              <tbody className="divide-y divide-line/70">
                {((executionStory?.children ?? selectedChildNodes)).length ? (executionStory?.children ?? selectedChildNodes).map((node) => (
                  <tr key={`child-${node.id}`} className="align-top">
                    <td className="whitespace-nowrap px-3 py-2 text-muted">{compactTimestamp(node.first_seen)}</td>
                    <td className="px-3 py-2 font-semibold">{toNodeLabel(node)}</td>
                    <td className="px-3 py-2 text-muted">{node.pid ?? "—"}</td>
                    <td className="max-w-[34rem] break-words px-3 py-2 text-muted">{node.command_line || node.path || "No command line"}</td>
                    <td className="px-3 py-2"><Pill className={riskTone(node.risk_score || 0)}>risk {node.risk_score || 0}</Pill></td>
                    <td className="px-3 py-2"><button type="button" onClick={() => openFocusedTree(node)} className="rounded-xl border border-accent/40 bg-accent/10 px-3 py-1 text-xs text-accent">Make target</button></td>
                  </tr>
                )) : (
                  <tr><td colSpan={6} className="px-3 py-4 text-sm text-muted">No child processes were observed for this process.</td></tr>
                )}
              </tbody>
            </table>
          </div>
        ) : null}

        {storyTab === "activity" ? (
          <div className="grid gap-2 md:grid-cols-2 xl:grid-cols-4">
            {["dns", "network", "file", "registry"].map((kind) => {
              const group = (executionStory?.activity_groups.items ?? activityGroups).find((item) => String(item.group) === kind);
              const count = Number(group?.count ?? executionStory?.activity_groups.omitted_counts?.[kind] ?? selectedActivitySummary[kind as keyof typeof selectedActivitySummary] ?? 0);
              return (
                <div key={kind} className="rounded-2xl border border-line bg-abyss/70 p-4">
                  <p className="font-mono text-[11px] uppercase tracking-[0.16em] text-muted">{kind}</p>
                  <p className="mt-2 text-2xl font-semibold">{count}</p>
                  <button type="button" onClick={() => storyTarget && expandNode(storyTarget, "activity")} className="mt-3 rounded-xl border border-line bg-panel/40 px-3 py-1.5 text-xs text-muted">
                    Activity
                  </button>
                </div>
              );
            })}
          </div>
        ) : null}

        {storyTab === "commands" ? (
          <div className="rounded-2xl border border-line bg-abyss/70 p-4">
            <p className="text-sm text-muted">Command History shows deduplicated commands and supporting events for this process.</p>
            {storyTarget ? (
              <button type="button" onClick={() => openCommandHistory(storyTarget)} className="mt-3 rounded-xl border border-accent/40 bg-accent/10 px-3 py-1.5 text-xs text-accent">Command History</button>
            ) : null}
          </div>
        ) : null}

        {storyTab === "source" ? (
          <div className="grid gap-2">
            {(executionStory?.source_events ?? storyTarget?.source_events ?? []).length ? (executionStory?.source_events ?? storyTarget?.source_events ?? []).map((eventId) => (
              <button key={eventId} type="button" onClick={() => storyTarget && openSourceEvent({ ...storyTarget, source_events: [eventId] })} className="rounded-xl border border-line bg-abyss/70 px-3 py-2 text-left text-xs text-muted">
                {eventId}
              </button>
            )) : <p className="text-sm text-muted">No source events attached to the current story target.</p>}
          </div>
        ) : null}

        {storyTab === "advanced" ? (
          <p className="rounded-2xl border border-line bg-abyss/70 p-4 text-sm text-muted">
            The technical graph remains below. Node clicks select a process for preview; they do not change the story target until you choose Make target.
          </p>
        ) : null}
      </div>
    </div>
  ) : null;
  const flattened = useMemo(() => flattenForest(forest, expandedNodeIds), [expandedNodeIds, forest]);

  const summary = useMemo(() => {
    return {
      totalGraphNodes: rawNodes.length,
      nodes: graphNodes.length,
      edges: graphEdges.length,
      hiddenNodes: Math.max(rawNodes.length - graphNodes.length, 0),
      highRisk: graphNodes.filter((node) => (node.risk_score || 0) >= 70).length,
      suspiciousChains: visibleChains.length,
    };
  }, [graphEdges.length, graphNodes, rawNodes.length, visibleChains.length]);

  function submitFocus(nextMode?: GraphMode) {
    const normalizedMode = nextMode ?? mode;
    setMode(normalizedMode);
    if (normalizedMode === "focused" && focusKind === "none") setFocusKind("chain");
    if (normalizedMode === "suspicious" && !quickFilters.has("suspicious")) {
      setQuickFilters((current) => new Set(current).add("suspicious"));
    }
    if (normalizedMode === "full" && quickFilters.has("suspicious")) {
      setQuickFilters((current) => {
        const next = new Set(current);
        next.delete("suspicious");
        return next;
      });
    }
    setSubmittedFocus({
      scope,
      evidence_id: scope === "evidence" ? evidenceId || undefined : undefined,
      host: selectedHost || undefined,
      pid: pid.trim() ? Number(pid.trim()) : undefined,
      process_name: processName.trim() || undefined,
      entity_id: processGuid.trim() || (normalizedMode === "focused" ? selectedNodeId || initialHighlightedNodeIds[0] || undefined : undefined),
      source_event_id: initialSourceEventId || undefined,
      timestamp: initialTimestamp || undefined,
    });
  }

  function resetWorkspace() {
    setMode(initialMode);
    setFocusKind(initialFindingId ? "finding" : initialHighlightedNodeIds.length || initialPid || initialProcessGuid || initialSourceEventId || initialProcessName ? "process" : "chain");
    setProcessFilter("");
    setUserFilter("");
    setRiskMin(initialMode === "full" ? 0 : 40);
    setQuickFilters(new Set(["suspicious"]));
    setSelectedChainId(null);
    setSelectedNodeId(initialHighlightedNodeIds[0] || null);
    setDetailDismissed(false);
    setContextDepthParents(initialMode === "focused" ? 1 : 0);
    setContextDepthChildren(initialMode === "focused" ? 1 : 0);
    setIncludeSiblings(false);
    setFullGraphConfirmed(false);
    setExpandedNodeIds(new Set(initialHighlightedNodeIds));
    setScope(defaultEvidenceId ? "evidence" : "case");
    setEvidenceId(defaultEvidenceId);
    setPid(initialPid);
    setProcessGuid(initialProcessGuid);
    setProcessName(initialProcessName);
    setSubmittedFocus({
      scope: defaultEvidenceId ? "evidence" : "case",
      evidence_id: defaultEvidenceId || undefined,
      host: selectedHost || undefined,
      pid: initialPid ? Number(initialPid) : undefined,
      process_name: initialProcessName || undefined,
      entity_id: initialProcessGuid || initialHighlightedNodeIds[0] || undefined,
      source_event_id: initialSourceEventId || undefined,
      timestamp: initialTimestamp || undefined,
    });
  }

  function toggleQuickFilter(filter: QuickFilterId) {
    setQuickFilters((current) => {
      const next = new Set(current);
      if (next.has(filter)) next.delete(filter);
      else next.add(filter);
      return next;
    });
  }

  function expandAll() {
    setExpandedNodeIds(new Set(graphNodes.map((node) => node.id)));
  }

  function collapseLowRisk() {
    const next = new Set<string>();
    for (const branch of forest) next.add(branch.node.id);
    for (const id of initialHighlightedNodeIds) next.add(id);
    for (const id of lineageIds) next.add(id);
    setExpandedNodeIds(next);
    setMode("suspicious");
    setRiskMin(Math.max(riskMin, 40));
    setQuickFilters((current) => new Set(current).add("suspicious"));
  }

  function focusChain(chain: ChainView) {
    setDetailDismissed(false);
    setSelectedChainId(chain.id);
    setSelectedNodeId(chain.nodes[chain.nodes.length - 1]?.id ?? chain.nodes[0]?.id ?? null);
    setFocusKind("chain");
    setContextDepthParents(1);
    setContextDepthChildren(1);
    setIncludeSiblings(false);
    setMode("focused");
  }

  function previewChain(chain: ChainView) {
    setDetailDismissed(false);
    setSelectedChainId(chain.id);
    setSelectedNodeId(chain.nodes[chain.nodes.length - 1]?.id ?? chain.nodes[0]?.id ?? null);
  }

  function resetFocusedContext() {
    setContextDepthParents(0);
    setContextDepthChildren(0);
    setIncludeSiblings(false);
  }

  function backToChains() {
    setDetailDismissed(false);
    setMode("suspicious");
    setFocusKind("chain");
    resetFocusedContext();
  }

  function exportVisibleGraphJson() {
    downloadBlob(
      `process-graph-${caseId}.json`,
      JSON.stringify(
        {
          case_id: caseId,
          host: selectedHost || null,
          evidence_id: scope === "evidence" ? evidenceId || null : null,
          mode,
          nodes: graphNodes,
          edges: graphEdges,
          warnings: graphWarningGroups.map((item) => item.message),
        },
        null,
        2,
      ),
      "application/json",
    );
  }

  function exportFocusedChainMarkdown() {
    if (!activeChain) return;
    const lines = [
      `# Process chain`,
      ``,
      `- Case: ${caseId}`,
      `- Host: ${selectedHost || "any"}`,
      `- Risk: ${activeChain.riskScore}`,
      `- Title: ${activeChain.title}`,
      ``,
      `## Reasons`,
      ...(activeChain.reasons.length ? activeChain.reasons.map((reason) => `- ${reason}`) : ["- No explicit reasons attached"]),
      ``,
      `## Nodes`,
      ...activeChain.nodes.map((node) => `- ${toNodeLabel(node)} | pid=${node.pid ?? "-"} | host=${node.host ?? "-"} | risk=${node.risk_score}`),
    ];
    downloadBlob(`process-chain-${activeChain.id}.md`, lines.join("\n"), "text/markdown");
  }

  function navigateToSearch(field: "process_name" | "q" | "file_path", value: string) {
    if (!value.trim()) return;
    const params = new URLSearchParams();
    params.set(field, value);
    if (selectedHost) params.set("host", selectedHost);
    if (evidenceId) params.set("evidence_id", evidenceId);
    navigate(`/cases/${caseId}/search?${params.toString()}`);
  }

  function openInTimeline(node: ProcessTreeNode) {
    const params = new URLSearchParams();
    params.set("process_node_id", node.id);
    if (selectedHost) params.set("host", selectedHost);
    if (evidenceId) params.set("evidence_id", evidenceId);
    navigate(`/cases/${caseId}/timeline?${params.toString()}`);
  }

  function openRelatedFinding(finding: Finding) {
    navigate(`/cases/${caseId}/findings?finding_id=${encodeURIComponent(finding.id)}`);
  }

  function openSourceEvent(node: ProcessTreeNode) {
    const eventId = node.source_events?.[0];
    if (!eventId) return;
    const params = new URLSearchParams({ event_id: eventId, tab: "results" });
    if (evidenceId) params.set("evidence_id", evidenceId);
    if (selectedHost) params.set("host", selectedHost);
    navigate(`/cases/${caseId}/search?${params.toString()}`);
  }

  function backToSearchEvent() {
    if (!searchOriginEventId) return;
    const params = new URLSearchParams({ event_id: searchOriginEventId, tab: "results" });
    if (evidenceId) params.set("evidence_id", evidenceId);
    if (selectedHost) params.set("host", selectedHost);
    navigate(`/cases/${caseId}/search?${params.toString()}`);
  }

  function openCommandHistory(node: ProcessTreeNode) {
    const params = new URLSearchParams();
    const q = node.command_line || node.name || "";
    if (q) params.set("q", q);
    if (evidenceId) params.set("evidence_id", evidenceId);
    if (selectedHost || node.host) params.set("host", selectedHost || node.host || "");
    navigate(`/cases/${caseId}/command-history${params.toString() ? `?${params.toString()}` : ""}`);
  }

  function clearExpansions() {
    setExpansionNodes([]);
    setExpansionEdges([]);
    setExpansionGroups([]);
    setExpansionOmittedCounts({});
    setExpansionNotice(null);
  }

  async function loadFocusedTree(params: { node?: ProcessTreeNode; pid?: number; processGuid?: string; processName?: string; sourceEventId?: string; timestamp?: string }) {
    const node = params.node;
    const actionLabel = `focused:${node?.id || params.processGuid || params.pid || "filters"}`;
    const exactSourceEventId = params.sourceEventId || node?.source_event_id || node?.source_events?.[0] || undefined;
    const exactProcessGuid = params.processGuid || node?.id || undefined;
    const exactPid = params.pid ?? node?.pid ?? undefined;
    const exactTimestamp = params.timestamp || node?.first_seen || node?.last_seen || undefined;
    const exactHost = selectedHost || node?.host || undefined;
    const hasStableIdentity = Boolean(exactSourceEventId || exactProcessGuid || exactPid);
    const fallbackProcessName = hasStableIdentity ? undefined : params.processName || node?.name || processName || undefined;
    setExpandingAction(actionLabel);
    setExpansionNotice(null);
    setStoryError(null);
    try {
      const story = await api.getExecutionStory(caseId, {
        scope,
        evidence_id: scope === "evidence" ? evidenceId || undefined : undefined,
        host: exactHost,
        pid: exactPid,
        process_guid: exactProcessGuid,
        source_event_id: exactSourceEventId,
        q: fallbackProcessName,
        timestamp: exactTimestamp,
        parent_depth: 2,
        child_depth: 2,
        include_activity: true,
        time_window_before: 1800,
        time_window_after: 1800,
        max_nodes: maxNodes,
      });
      setExecutionStory(story);
      setStoryTab("overview");
      const storyNodes = story.visual_tree?.nodes ?? [];
      const storyEdges = story.visual_tree?.edges ?? [];
      const storyGroups = story.activity_groups?.items ?? [];
      setExpansionNodes((current) => mergeNodes(current, storyNodes));
      setExpansionEdges((current) => mergeEdges(current, storyEdges));
      setExpansionGroups((current) => {
        const map = new Map<string, Record<string, unknown>>();
        for (const group of [...current, ...storyGroups]) {
          map.set(String(group.id || `${group.source || ""}:${group.group || ""}`), group);
        }
        return Array.from(map.values());
      });
      setExpansionOmittedCounts((current) => {
        const next = { ...current };
        for (const [key, value] of Object.entries(story.activity_groups?.omitted_counts ?? {})) {
          next[key] = Number(next[key] || 0) + Number(value || 0);
        }
        return next;
      });
      const focus = story.target ?? node ?? null;
      if (focus?.id) {
        setSelectedNodeId(focus.id);
        setExpandedNodeIds((current) => new Set([...current, focus.id, ...storyNodes.map((item) => item.id)]));
      }
      setMode("focused");
      setFocusKind("process");
      setContextDepthParents(2);
      setContextDepthChildren(2);
      setIncludeSiblings(true);
      setSubmittedFocus({
        scope,
        evidence_id: scope === "evidence" ? evidenceId || undefined : undefined,
        host: exactHost,
        pid: exactPid,
        process_name: fallbackProcessName,
        entity_id: exactProcessGuid,
        source_event_id: exactSourceEventId,
        timestamp: exactTimestamp,
      });
      const identity = story.quality?.identity_resolution;
      const ambiguity = identity?.ambiguous_candidates?.length ? ` ${identity.ambiguous_candidates.length} ambiguous PID candidates returned.` : "";
      const wrongTarget = (exactSourceEventId || exactProcessGuid) && identity?.target_identity_matches === false
        ? "Could not build exact story for selected process. The resolved target did not match the requested identity."
        : "";
      const missingExact = (exactSourceEventId || exactProcessGuid) && !story.target
        ? "Could not build exact story for selected process. The selected event or ProcessGuid was not found in the current host/evidence/time filters."
        : "";
      const missingPid = exactPid && !story.target ? `PID ${exactPid} was not found in the current host/evidence/time filters. Clear conflicting filters or broaden the scope.` : "";
      const summaryText = missingPid || story.story?.summary || "Execution story loaded.";
      const exactError = wrongTarget || missingExact || missingPid;
      if (exactError) setStoryError(exactError);
      setExpansionNotice(`${summaryText} Loaded ${storyNodes.length} nodes and ${storyEdges.length} edges.${ambiguity}`.trim());
      const urlParams = new URLSearchParams();
      urlParams.set("mode", "execution_story");
      if (scope === "evidence" && evidenceId) urlParams.set("evidence_id", evidenceId);
      if (exactHost) urlParams.set("host", exactHost);
      if (exactSourceEventId) {
        urlParams.set("source_event_id", exactSourceEventId);
        urlParams.set("story_event_id", exactSourceEventId);
      }
      if (exactProcessGuid) urlParams.set("process_guid", exactProcessGuid);
      if (exactPid !== undefined) urlParams.set("pid", String(exactPid));
      if (exactTimestamp) urlParams.set("timestamp", exactTimestamp);
      if (searchOriginEventId) urlParams.set("from_search_event_id", searchOriginEventId);
      navigate(`/cases/${caseId}/process-graph?${urlParams.toString()}`, { replace: false });
    } catch (error) {
      const message = error instanceof Error ? error.message : "Execution story failed.";
      setStoryError(message);
      setExpansionNotice(message);
    } finally {
      setExpandingAction(null);
    }
  }

  function openFocusedTree(node: ProcessTreeNode) {
    void loadFocusedTree({ node });
  }

  function buildFocusedTreeFromFilters() {
    const primarySearch = processName.trim();
    const searchLooksLikePid = /^\d+$/.test(primarySearch);
    void loadFocusedTree({
      pid: pid.trim() ? Number(pid.trim()) : searchLooksLikePid ? Number(primarySearch) : undefined,
      processGuid: processGuid.trim() || undefined,
      processName: searchLooksLikePid ? undefined : primarySearch || undefined,
      sourceEventId: initialSourceEventId || undefined,
      timestamp: initialTimestamp || undefined,
    });
  }

  useEffect(() => {
    if (!requestedStoryEventId || initialStoryLoadRef.current) return;
    initialStoryLoadRef.current = true;
    void loadFocusedTree({
      pid: initialPid ? Number(initialPid) : undefined,
      processGuid: initialProcessGuid || undefined,
      sourceEventId: requestedStoryEventId,
      timestamp: initialTimestamp || undefined,
    });
    // This should only auto-open the exact story requested by the URL.
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [requestedStoryEventId]);

  async function expandNode(node: ProcessTreeNode, expansionType: ExpansionType) {
    const actionLabel = `${expansionType}:${node.id}`;
    setExpandingAction(actionLabel);
    setExpansionNotice(null);
    try {
      const result = await api.expandProcessTree(caseId, {
        scope,
        evidence_id: scope === "evidence" ? evidenceId || undefined : undefined,
        host: selectedHost || node.host || undefined,
        node_id: node.id,
        process_guid: node.id,
        process_pid: node.pid,
        process_name: node.name,
        timestamp: node.first_seen || node.last_seen,
        expansion_type: expansionType,
        depth: expansionType === "parents" ? Math.max(contextDepthParents + 1, 1) : 1,
        time_window_before: 1800,
        time_window_after: 1800,
        max_nodes: maxNodes,
        max_activity: maxActivityPerProcess,
      });
      const previousNodeCount = expansionNodes.length;
      const previousEdgeCount = expansionEdges.length;
      setExpansionNodes((current) => mergeNodes(current, result.added_nodes ?? []));
      setExpansionEdges((current) => mergeEdges(current, result.added_edges ?? []));
      setExpansionGroups((current) => {
        const map = new Map<string, Record<string, unknown>>();
        for (const group of [...current, ...(result.activity_groups ?? [])]) {
          map.set(String(group.id || `${group.source || ""}:${group.group || ""}`), group);
        }
        return Array.from(map.values());
      });
      setExpansionOmittedCounts((current) => {
        const next = { ...current };
        for (const [key, value] of Object.entries(result.omitted_counts ?? {})) {
          next[key] = Number(next[key] || 0) + Number(value || 0);
        }
        return next;
      });
      setMode("focused");
      setFocusKind("process");
      setSelectedNodeId(node.id);
      setExpandedNodeIds((current) => new Set([...current, node.id, ...(result.added_nodes ?? []).map((item) => item.id)]));
      if (expansionType === "children") setContextDepthChildren((current) => Math.max(current, 1));
      if (expansionType === "parents") setContextDepthParents((current) => Math.max(current + 1, 1));
      if (expansionType === "siblings") setIncludeSiblings(true);
      const addedNodes = Math.max((result.added_nodes ?? []).length - previousNodeCount, 0);
      const addedEdges = Math.max((result.added_edges ?? []).length - previousEdgeCount, 0);
      const warnings = result.warnings ?? [];
      const message = warnings[0] || `Expansion loaded ${addedNodes} nodes and ${addedEdges} edges.`;
      setExpansionNotice(message);
    } catch (error) {
      setExpansionNotice(error instanceof Error ? error.message : "Process graph expansion failed.");
    } finally {
      setExpandingAction(null);
    }
  }

  const quickFilterButtons: Array<{ id: QuickFilterId; label: string }> = [
    { id: "suspicious", label: "Suspicious" },
    { id: "high_risk", label: "High risk" },
    { id: "lolbins", label: "LOLBins" },
    { id: "powershell", label: "PowerShell" },
    { id: "office", label: "Office chains" },
    { id: "browser", label: "Browser chains" },
    { id: "defender", label: "Defender-linked" },
    { id: "downloads", label: "Download-linked" },
    { id: "autorun", label: "Autorun-linked" },
  ];

  return (
    <ProcessGraphErrorBoundary>
    {debugThrowRenderError ? <ProcessGraphCrashTrigger /> : null}
    <section className="space-y-4">
      <div className="rounded-[28px] border border-line bg-panel/70 p-5 shadow-panel">
        <div className="flex flex-wrap items-start justify-between gap-4">
          <div>
            <h3 className="text-2xl font-semibold">Execution Story</h3>
            <p className="mt-2 max-w-3xl text-sm text-muted">
              Start with a process, PID, command or path. The story explains who launched it, what it launched, what it did, and which source events support that chain.
            </p>
          </div>
          <div className="flex flex-wrap gap-2">
            {selectedHost ? <Pill className="border-cyan-400/40 bg-cyan-500/10 text-cyan-100">Host {selectedHost}</Pill> : null}
            {evidenceId ? <Pill className="border-line bg-white/5 text-muted">Evidence scoped</Pill> : null}
            <Pill className="border-line bg-white/5 text-muted">{modeBanner.title}</Pill>
            {(mode === "focused" || mode === "suspicious") && (isExactStoryActive || activeChain || focusedFinding || focusKind === "process") ? <Pill className="border-accent/40 bg-accent/10 text-accent">{focusChipLabel}</Pill> : null}
          </div>
        </div>

        <div data-testid="process-graph-mode-banner" className={`mt-4 rounded-2xl border p-4 text-sm ${modeBanner.tone}`}>
          <p className="font-mono text-[11px] uppercase tracking-[0.16em]">{modeBanner.title}</p>
          <p className="mt-2">{modeBanner.message}</p>
        </div>

        <div className="mt-5 grid gap-3 xl:grid-cols-[1.1fr_0.95fr_auto]">
          <label className="block">
              <span className="mb-2 block font-mono text-[11px] uppercase tracking-[0.16em] text-muted">Search process, PID, command or path</span>
            <input value={processName} onChange={(event) => setProcessName(event.target.value)} placeholder="powershell.exe, 12720, maintenance.ps1" className="w-full rounded-2xl border border-line bg-abyss/80 px-4 py-3 text-sm outline-none focus:border-accent/50" />
          </label>
          <div className="grid gap-3 sm:grid-cols-3">
            <label className="block">
              <span className="mb-2 block font-mono text-[11px] uppercase tracking-[0.16em] text-muted">View</span>
              <select aria-label="Graph mode" value={mode} onChange={(event) => setMode(event.target.value as GraphMode)} className="w-full rounded-2xl border border-line bg-abyss/80 px-4 py-3 text-sm">
                <option value="suspicious">Process search</option>
                <option value="focused">Execution story</option>
                <option value="full">Advanced graph</option>
              </select>
            </label>
            <label className="block">
              <span className="mb-2 block font-mono text-[11px] uppercase tracking-[0.16em] text-muted">
                {isExactStoryContext ? "Extra context risk" : mode === "full" ? "Graph risk filter" : "Candidate risk filter"}
              </span>
              <select aria-label="Minimum risk" value={String(riskMin)} onChange={(event) => setRiskMin(Number(event.target.value))} className="w-full rounded-2xl border border-line bg-abyss/80 px-4 py-3 text-sm">
                <option value="0">Any</option>
                <option value="40">40+</option>
                <option value="70">70+</option>
                <option value="90">90+</option>
              </select>
              <span className="mt-1 block text-[11px] text-muted">
                {isExactStoryContext ? "Exact target, parents and direct children stay visible." : mode === "full" ? "Filters visible graph nodes." : "Filters process candidates."}
              </span>
            </label>
            <label className="block">
              <span className="mb-2 block font-mono text-[11px] uppercase tracking-[0.16em] text-muted">Scope</span>
              <select aria-label="Graph scope" value={scope} onChange={(event) => setScope(event.target.value as "case" | "evidence")} className="w-full rounded-2xl border border-line bg-abyss/80 px-4 py-3 text-sm">
                <option value="case">Case</option>
                <option value="evidence">Evidence</option>
              </select>
            </label>
          </div>
          <div className="flex flex-wrap items-end gap-2">
            <button type="button" onClick={() => submitFocus()} className="rounded-2xl border border-accent/40 bg-accent/10 px-4 py-3 text-sm text-accent">
              Back to results
            </button>
            {!isExactStoryContext ? (
              <button type="button" onClick={() => buildFocusedTreeFromFilters()} className="rounded-2xl border border-cyan-400/40 bg-cyan-500/10 px-4 py-3 text-sm text-cyan-100">
                Build story
              </button>
            ) : null}
            <button type="button" onClick={resetWorkspace} className="rounded-2xl border border-line bg-abyss/80 px-4 py-3 text-sm text-muted">
              Reset
            </button>
          </div>
        </div>

        <div className="mt-4 flex flex-wrap gap-2">
          <button type="button" onClick={() => setShowFilters((current) => !current)} className="rounded-2xl border border-line bg-abyss/80 px-3 py-2 text-xs text-muted">
            <Filter className="mr-2 inline h-3.5 w-3.5" />
            {showFilters ? "Hide advanced filters" : "Advanced filters"}
          </button>
          <button
            type="button"
            onClick={() => {
              graphViewportRef.current?.scrollTo({ top: 0, left: 0, behavior: "smooth" });
              treeViewportRef.current?.scrollTo({ top: 0, left: 0, behavior: "smooth" });
            }}
            className="rounded-2xl border border-line bg-abyss/80 px-3 py-2 text-xs text-muted"
          >
            <Eye className="mr-2 inline h-3.5 w-3.5" />
            Fit to view
          </button>
          {mode === "focused" ? (
            <>
              <button type="button" onClick={() => setContextDepthParents((current) => Math.min(current + 1, 3))} className="rounded-2xl border border-line bg-abyss/80 px-3 py-2 text-xs text-muted">Parents</button>
              <button type="button" onClick={() => setContextDepthChildren((current) => Math.min(current + 1, 3))} className="rounded-2xl border border-line bg-abyss/80 px-3 py-2 text-xs text-muted">Children</button>
              <button type="button" onClick={() => setIncludeSiblings((current) => !current)} className={`rounded-2xl border px-3 py-2 text-xs ${includeSiblings ? "border-accent/50 bg-accent/15 text-accent" : "border-line bg-abyss/80 text-muted"}`}>Siblings</button>
            </>
          ) : null}
        </div>
        <details className="mt-4 rounded-2xl border border-line bg-abyss/50 p-4">
          <summary className="cursor-pointer font-mono text-[11px] uppercase tracking-[0.16em] text-muted">Advanced / diagnostics</summary>
          <div className="mt-3 flex flex-wrap gap-2">
            <button type="button" onClick={expandAll} className="rounded-2xl border border-line bg-abyss/80 px-3 py-2 text-xs text-muted">Expand all visible nodes</button>
            <button type="button" onClick={collapseLowRisk} className="rounded-2xl border border-line bg-abyss/80 px-3 py-2 text-xs text-muted">Collapse to suspicious context</button>
            <button type="button" onClick={() => { backToChains(); submitFocus("suspicious"); }} className="rounded-2xl border border-line bg-abyss/80 px-3 py-2 text-xs text-muted">Back to suspicious chains</button>
            {mode === "focused" ? (
              <>
                <button type="button" onClick={resetFocusedContext} className="rounded-2xl border border-line bg-abyss/80 px-3 py-2 text-xs text-muted">Hide added context</button>
                <button type="button" onClick={() => { setFullGraphConfirmed(false); submitFocus("full"); }} className="rounded-2xl border border-amber-400/30 bg-amber-400/10 px-3 py-2 text-xs text-amber-100">Advanced graph</button>
              </>
            ) : null}
            <button type="button" onClick={exportVisibleGraphJson} className="rounded-2xl border border-line bg-abyss/80 px-3 py-2 text-xs text-muted">Export graph JSON</button>
            <button type="button" onClick={exportFocusedChainMarkdown} disabled={!activeChain} className="rounded-2xl border border-line bg-abyss/80 px-3 py-2 text-xs text-muted disabled:opacity-40">Export chain Markdown</button>
            <button type="button" disabled className="rounded-2xl border border-line bg-abyss/80 px-3 py-2 text-xs text-muted opacity-40">Export image next</button>
          </div>
          <div className="flex flex-wrap items-center justify-between gap-3">
            <div>
              <p className="font-mono text-[11px] uppercase tracking-[0.16em] text-muted">Noise controls</p>
              <p className="mt-1 text-xs text-muted">The default graph keeps the process chain visible and collapses file, registry, network and DNS activity.</p>
            </div>
            <label className="flex items-center gap-2 text-xs text-muted">
              <input type="checkbox" checked={includeActivity} onChange={(event) => setIncludeActivity(event.target.checked)} />
              Expand activity edges
            </label>
          </div>
          <div className="mt-3 grid gap-3 md:grid-cols-4">
            <label className="text-xs text-muted">
              Max nodes
              <select aria-label="Max nodes" value={String(maxNodes)} onChange={(event) => setMaxNodes(Number(event.target.value))} className="mt-1 w-full rounded-xl border border-line bg-panel px-3 py-2">
                <option value="25">25</option>
                <option value="50">50</option>
                <option value="100">100</option>
                <option value="250">250</option>
              </select>
            </label>
            <label className="text-xs text-muted">
              Max activity per process
              <select aria-label="Max activity per process" value={String(maxActivityPerProcess)} onChange={(event) => setMaxActivityPerProcess(Number(event.target.value))} className="mt-1 w-full rounded-xl border border-line bg-panel px-3 py-2">
                <option value="10">10</option>
                <option value="25">25</option>
                <option value="100">100</option>
              </select>
            </label>
            <label className="flex items-end gap-2 text-xs text-muted">
              <input type="checkbox" checked={onlySuspiciousGraph} onChange={(event) => setOnlySuspiciousGraph(event.target.checked)} />
              Only suspicious/high risk
            </label>
            <label className="flex items-end gap-2 text-xs text-muted">
              <input type="checkbox" checked={onlyMarkedGraph} onChange={(event) => setOnlyMarkedGraph(event.target.checked)} />
              Only marked
            </label>
          </div>
          <div className="mt-3 flex flex-wrap gap-2">
            {EDGE_TYPE_OPTIONS.map((option) => {
              const active = edgeTypes.has(option.id);
              return (
                <button
                  key={option.id}
                  type="button"
                  onClick={() =>
                    setEdgeTypes((current) => {
                      const next = new Set(current);
                      if (next.has(option.id)) next.delete(option.id);
                      else next.add(option.id);
                      if (!next.size) next.add("parent_child");
                      if (option.id !== "parent_child" && next.has(option.id)) setIncludeActivity(true);
                      return next;
                    })
                  }
                  className={`rounded-full border px-3 py-1.5 text-xs ${active ? "border-accent/50 bg-accent/15 text-accent" : "border-line bg-panel/60 text-muted"}`}
                >
                  {option.label}
                </button>
              );
            })}
          </div>
        </details>
      </div>

      {storyPanel}

      <div className="grid gap-4 xl:grid-cols-6">
        <SummaryBadge label="Total graph" value={query.isPending ? "…" : summary.totalGraphNodes} />
        <SummaryBadge label="Visible nodes" value={query.isPending ? "…" : summary.nodes} />
        <SummaryBadge label="Visible edges" value={query.isPending ? "…" : summary.edges} />
        <SummaryBadge label="High risk" value={query.isPending ? "…" : summary.highRisk} />
        <SummaryBadge label="Chains" value={query.isPending ? "…" : summary.suspiciousChains} />
      </div>

      {expansionNotice ? (
        <div className="rounded-2xl border border-cyan-400/30 bg-cyan-500/10 p-3 text-sm text-cyan-100">
          {expansionNotice}
        </div>
      ) : null}

      {activityGroups.length || Object.keys(omittedCounts).length ? (
        <div className="rounded-2xl border border-line bg-panel/60 p-4">
          <div className="flex flex-wrap items-center justify-between gap-3">
            <div>
              <p className="font-mono text-[11px] uppercase tracking-[0.16em] text-muted">Collapsed activity</p>
              <p className="mt-1 text-sm text-muted">Activity edges are grouped until you enable activity expansion.</p>
            </div>
            <div className="flex flex-wrap gap-2">
              {Object.entries(omittedCounts).map(([key, value]) => (
                <Pill key={key} className="border-line bg-abyss/80 text-muted">
                  {key}: {value}
                </Pill>
              ))}
            </div>
          </div>
          {activityGroups.length ? (
            <div className="mt-3 grid gap-2 md:grid-cols-2 xl:grid-cols-3">
              {activityGroups.slice(0, 12).map((group) => (
                <button
                  key={String(group.id)}
                  type="button"
                  onClick={() => {
                    setIncludeActivity(true);
                    setEdgeTypes((current) => new Set([...current, `${String(group.group)}_activity`]));
                  }}
                  className="rounded-xl border border-line bg-abyss/70 p-3 text-left text-xs text-muted hover:border-accent/40 hover:text-ink"
                >
                  <span className="font-semibold text-ink">{String(group.group)}</span> · {String(group.count)} events
                  <span className="mt-1 block truncate">{String(group.source_process || "")}</span>
                </button>
              ))}
            </div>
          ) : null}
        </div>
      ) : null}

      {graphWarningGroups.length ? (
        <div className="rounded-2xl border border-amber-400/40 bg-amber-400/10 p-4 text-sm text-amber-100">
          <div className="space-y-3">
            {graphWarningGroups.map((warning) => {
              const expanded = expandedWarningGroups.has(warning.key);
              return (
                <div key={warning.key} className="space-y-2">
                  <p className="flex items-start gap-2">
                    <AlertTriangle className="mt-0.5 h-4 w-4 shrink-0" />
                    <span>{warning.message}</span>
                  </p>
                  {warning.samples.length ? (
                    <div className="pl-6">
                      <button
                        type="button"
                        onClick={() =>
                          setExpandedWarningGroups((current) => {
                            const next = new Set(current);
                            if (next.has(warning.key)) next.delete(warning.key);
                            else next.add(warning.key);
                            return next;
                          })
                        }
                        className="rounded-xl border border-amber-300/30 bg-amber-200/10 px-3 py-1 text-xs text-amber-50"
                      >
                        {expanded ? "Hide samples" : "Show samples"}
                      </button>
                      {expanded ? (
                        <div className="mt-2 space-y-1 text-xs text-amber-50/90">
                          {warning.samples.map((sample) => (
                            <p key={sample}>{sample}</p>
                          ))}
                        </div>
                      ) : null}
                    </div>
                  ) : null}
                </div>
              );
            })}
          </div>
        </div>
      ) : null}

      {orphanDiagnostics.length ? (
        <details className="rounded-2xl border border-amber-400/40 bg-amber-400/10 p-4 text-sm text-amber-100">
          <summary className="cursor-pointer font-semibold">
            Diagnostics · {orphanDiagnostics.length} parent links need review
          </summary>
          <div className="mt-3 grid gap-2 lg:grid-cols-2">
            {orphanDiagnostics.slice(0, 20).map((item) => {
              const parentFields = item.parent_fields && typeof item.parent_fields === "object" ? (item.parent_fields as Record<string, unknown>) : {};
              const nodeId = String(item.id || `${item.process_name || "node"}-${item.pid || ""}`);
              return (
                <div key={nodeId} className="rounded-xl border border-amber-300/25 bg-abyss/60 p-3 text-xs">
                  <div className="flex flex-wrap items-center gap-2">
                    <span className="font-semibold text-amber-50">{String(item.process_name || "Unknown process")}</span>
                    <span>pid {String(item.pid ?? "—")}</span>
                    <span>{compactTimestamp(String(item.timestamp || ""))}</span>
                  </div>
                  <p className="mt-1 break-words text-amber-50/90">{String(item.parent_link_status || "parent_not_found")} · {String(item.parent_link_reason || "Parent was not linked.")}</p>
                  <p className="mt-1 break-words text-amber-50/80">
                    Parent fields: name={String(parentFields.parent_name || "—")} · pid={String(parentFields.parent_pid ?? "—")} · guid={String(parentFields.parent_entity_id || "—")}
                  </p>
                  {item.command_line ? <p className="mt-1 break-words text-amber-50/70">{String(item.command_line)}</p> : null}
                </div>
              );
            })}
          </div>
        </details>
      ) : null}

      {showFilters ? (
        <div className="rounded-[28px] border border-line bg-panel/60 p-5 shadow-panel">
          <div className="grid gap-4 lg:grid-cols-5">
            <label className="block">
              <span className="mb-2 block font-mono text-[11px] uppercase tracking-[0.16em] text-muted">Evidence</span>
              <select aria-label="Evidence filter" value={evidenceId} disabled={scope !== "evidence"} onChange={(event) => setEvidenceId(event.target.value)} className="w-full rounded-2xl border border-line bg-abyss/80 px-4 py-3 text-sm disabled:opacity-50">
                <option value="">Any</option>
                {evidences.map((evidence) => (
                  <option key={evidence.id} value={evidence.id}>
                    {evidence.original_filename}
                  </option>
                ))}
              </select>
            </label>
            <label className="block">
              <span className="mb-2 block font-mono text-[11px] uppercase tracking-[0.16em] text-muted">PID</span>
              <input value={pid} onChange={(event) => setPid(event.target.value)} placeholder="1234" className="w-full rounded-2xl border border-line bg-abyss/80 px-4 py-3 text-sm" />
            </label>
            <label className="block">
              <span className="mb-2 block font-mono text-[11px] uppercase tracking-[0.16em] text-muted">ProcessGuid</span>
              <input value={processGuid} onChange={(event) => setProcessGuid(event.target.value)} placeholder="{guid} or Sysmon ProcessGuid" className="w-full rounded-2xl border border-line bg-abyss/80 px-4 py-3 text-sm" />
            </label>
            <label className="block">
              <span className="mb-2 block font-mono text-[11px] uppercase tracking-[0.16em] text-muted">Filter process text</span>
              <input value={processFilter} onChange={(event) => setProcessFilter(event.target.value)} placeholder="downloads\\payload.exe" className="w-full rounded-2xl border border-line bg-abyss/80 px-4 py-3 text-sm" />
            </label>
            <label className="block">
              <span className="mb-2 block font-mono text-[11px] uppercase tracking-[0.16em] text-muted">User</span>
              <input value={userFilter} onChange={(event) => setUserFilter(event.target.value)} placeholder="user01" className="w-full rounded-2xl border border-line bg-abyss/80 px-4 py-3 text-sm" />
            </label>
          </div>
          <div className="mt-4 flex flex-wrap gap-2">
            {quickFilterButtons.map((item) => (
              <button
                key={item.id}
                type="button"
                onClick={() => toggleQuickFilter(item.id)}
                className={`rounded-full border px-3 py-1.5 text-xs ${quickFilters.has(item.id) ? "border-accent/50 bg-accent/15 text-accent" : "border-line bg-abyss/70 text-muted"}`}
              >
                {item.label}
              </button>
            ))}
          </div>
        </div>
      ) : null}

      {query.isPending ? (
        <div className="rounded-[28px] border border-line bg-panel/70 p-8 text-sm text-muted shadow-panel">Loading process graph…</div>
      ) : query.error instanceof Error ? (
        <div className="rounded-[28px] border border-danger/40 bg-danger/10 p-8 text-sm text-danger shadow-panel">{query.error.message}</div>
      ) : !rawNodes.length ? (
        <div className="rounded-[28px] border border-line bg-panel/70 p-8 text-sm text-muted shadow-panel">
          <p className="text-sm text-white/90">No process graph nodes found for the current filters.</p>
          <div className="mt-3 space-y-1 text-sm text-muted">
            <p>Clear filters and reset the workspace.</p>
            <p>Switch to Full graph if the current mode is too restrictive.</p>
            <p>Check that process_start events were indexed for this case/evidence.</p>
          </div>
          <button type="button" onClick={resetWorkspace} className="mt-4 rounded-2xl border border-line bg-abyss/80 px-4 py-2 text-sm text-muted">
            Reset filters
          </button>
        </div>
      ) : !graphNodes.length ? (
        <div className="rounded-[28px] border border-line bg-panel/70 p-8 text-sm text-muted shadow-panel">
          <p className="text-sm text-white/90">{mode === "suspicious" ? "No suspicious process chains found." : "No process graph nodes match the current focus."}</p>
          <div className="mt-3 space-y-1 text-sm text-muted">
            <p>{mode === "suspicious" ? "Try Full graph or lower the risk threshold." : "Relax filters or switch to Full graph."}</p>
            <p>If you opened the graph from a pivot, the focused node or chain may be outside the current filters.</p>
          </div>
          <button type="button" onClick={resetWorkspace} className="mt-4 rounded-2xl border border-line bg-abyss/80 px-4 py-2 text-sm text-muted">
            Reset filters
          </button>
        </div>
      ) : (
        <div className="grid min-w-0 gap-4 2xl:grid-cols-[minmax(0,1.3fr)_minmax(340px,0.9fr)]">
          <div className="min-w-0 space-y-4">
            <div className="rounded-[28px] border border-line bg-panel/70 p-5 shadow-panel">
              <div className="flex flex-wrap items-center justify-between gap-3">
                <div>
                  <p className="font-mono text-xs uppercase tracking-[0.18em] text-accent">Graph canvas</p>
                  <p className="mt-1 text-sm text-muted">Visual node and edge view of the current execution graph.</p>
                  <p className="mt-2 text-xs text-muted">
                    {isExactStoryActive
                      ? "Showing the exact execution story visual tree. Suspicious chains are listed separately and do not change this canvas unless you investigate them."
                      : mode === "suspicious"
                      ? "Showing one suspicious chain at a time. Low-noise browser internals stay hidden by default."
                      : mode === "focused"
                        ? `Showing focused chain/process context with parents=${contextDepthParents}, children=${contextDepthChildren}${includeSiblings ? ", siblings on" : ""}.`
                        : "Full graph can be noisy on large cases. Use Suspicious only or Focused chain for investigation."}
                  </p>
                </div>
                <div className="text-xs text-muted">
                  Showing {graphNodes.length} of {isExactStoryActive ? graphNodes.length : visibleNodes.length || graphNodes.length} visible nodes · hidden {Math.max(summary.totalGraphNodes - graphNodes.length, 0)}
                </div>
              </div>

              {mode === "full" && visibleNodes.length > FULL_GRAPH_CONFIRM_THRESHOLD && !fullGraphConfirmed ? (
                <div className="mt-4 rounded-2xl border border-amber-400/30 bg-amber-400/10 p-5 text-sm text-amber-100">
                  <p className="font-semibold">This full graph has {visibleNodes.length} visible nodes.</p>
                  <p className="mt-2">Rendering the whole graph can be noisy and slow. Continue only if you need broad context.</p>
                  <div className="mt-4 flex flex-wrap gap-2">
                    <button type="button" onClick={() => setFullGraphConfirmed(true)} className="rounded-2xl border border-amber-300/40 bg-amber-200/10 px-4 py-2 text-xs text-amber-50">
                      Continue with full graph
                    </button>
                    <button type="button" onClick={() => { backToChains(); submitFocus("suspicious"); }} className="rounded-2xl border border-line bg-abyss/80 px-4 py-2 text-xs text-muted">
                      Back to suspicious chains
                    </button>
                  </div>
                </div>
              ) : (
                <div ref={graphViewportRef} className="mt-4 max-h-[38rem] overflow-auto rounded-2xl border border-line bg-abyss/50 p-3">
                  <div className="relative" style={{ width: graphLayout.width, height: graphLayout.height }}>
                    <svg className="absolute inset-0 h-full w-full" width={graphLayout.width} height={graphLayout.height} aria-label="Graph canvas">
                      {graphEdges.map((edge) => {
                        const source = graphLayoutMap.get(edge.source);
                        const target = graphLayoutMap.get(edge.target);
                        if (!source || !target) return null;
                        const highlighted = Boolean(
                          !isExactStoryActive && activeChain?.edge && activeChain.edge.source === edge.source && activeChain.edge.target === edge.target,
                        );
                        return (
                          <line
                            key={edge.id || `${edge.source}-${edge.target}`}
                            x1={source.x + source.width}
                            y1={source.y + source.height / 2}
                            x2={target.x}
                            y2={target.y + target.height / 2}
                            stroke={highlighted ? "rgba(116, 223, 221, 0.95)" : "rgba(148, 163, 184, 0.4)"}
                            strokeWidth={highlighted ? 3 : 1.5}
                          />
                        );
                      })}
                    </svg>
                    {graphLayout.nodes.map((layoutNode) => {
                      const node = graphNodes.find((item) => item.id === layoutNode.id) ?? nodeMap.get(layoutNode.id);
                      if (!node) return null;
                      const relatedFindingCount = (findingsByNodeId.get(node.id) ?? []).length;
                      const isSelected = selectedNodeId === node.id;
                      const isStoryTarget = isExactStoryActive && storyVisualTargetId === node.id;
                      const isLineage = lineageIds.has(node.id);
                      const isChainNode = !isExactStoryActive && (activeChain?.nodes.some((item) => item.id === node.id) ?? false);
                      return (
                        <button
                          key={`canvas-${node.id}`}
                          type="button"
                          onClick={() => {
                            setDetailDismissed(false);
                            setSelectedNodeId(node.id);
                          }}
                          className={`absolute rounded-2xl border p-3 text-left shadow-panel transition ${isSelected ? "border-accent/60 bg-accent/12" : isStoryTarget ? "border-emerald-400/60 bg-emerald-500/10" : isChainNode ? "border-cyan-400/40 bg-cyan-500/10" : isLineage ? "border-amber-300/40 bg-amber-300/8" : "border-line bg-panel/85"}`}
                          style={{ left: layoutNode.x, top: layoutNode.y, width: layoutNode.width, height: layoutNode.height }}
                        >
                          <div className="flex items-start justify-between gap-2">
                            <div className="min-w-0">
                              <div className="flex items-center gap-2">
                                {nodeIcon(node)}
                                <span className="block truncate text-sm font-semibold">{toNodeLabel(node)}</span>
                              </div>
                              <p className="mt-2 truncate text-xs text-muted">{node.command_line || node.path || "No command line"}</p>
                            </div>
                            <Pill className={riskTone(node.risk_score || 0)}>risk {node.risk_score || 0}</Pill>
                          </div>
                          <div className="mt-2 flex flex-wrap gap-2 text-[11px] text-muted">
                            <span>PID {node.pid ?? "—"}</span>
                            {relatedFindingCount ? <span>{relatedFindingCount} findings</span> : null}
                          </div>
                        </button>
                      );
                    })}
                  </div>
                </div>
              )}
            </div>

            <div className="rounded-[28px] border border-line bg-panel/70 p-5 shadow-panel">
              <div className="flex flex-wrap items-center justify-between gap-3">
                <div>
                  <p className="font-mono text-xs uppercase tracking-[0.18em] text-accent">Suspicious chains</p>
                  <p className="mt-1 text-sm text-muted">{isExactStoryActive ? "Suspicious chains are secondary suggestions. Previewing them does not change the exact story target." : "Focus on the chain and dim the rest of the graph."}</p>
                </div>
                <button type="button" onClick={() => setSelectedChainId(null)} className="rounded-xl border border-line bg-abyss/70 px-3 py-1.5 text-xs text-muted">
                  Clear focus
                </button>
              </div>
              <div className="mt-4 grid gap-3 xl:grid-cols-2">
                {visibleChains.length ? (
                  visibleChains.slice(0, 8).map((chain) => (
                    <div
                      key={chain.id}
                      className={`rounded-2xl border p-4 text-left ${selectedChainId === chain.id || activeChain?.id === chain.id ? "border-accent/50 bg-accent/10" : "border-line bg-abyss/70"}`}
                    >
                      <div className="flex items-start justify-between gap-3">
                        <div>
                          <p className="text-sm font-semibold">{chain.title}</p>
                          <p className="mt-1 text-xs text-muted">{chain.reasons.slice(0, 2).join(" · ") || "Suspicious execution chain"}</p>
                        </div>
                        <Pill className={riskTone(chain.riskScore)}>risk {chain.riskScore}</Pill>
                      </div>
                      <div className="mt-3 flex flex-wrap gap-2">
                        {chain.nodes.map((node) => (
                          <Pill key={`${chain.id}-${node.id}`} className={badgeTone((node.badges || [])[0] || "")}>
                            {toNodeLabel(node)}
                          </Pill>
                        ))}
                      </div>
                      <div className="mt-4 flex flex-wrap gap-2">
                        <button type="button" onClick={() => (isExactStoryActive ? previewChain(chain) : focusChain(chain))} className="rounded-xl border border-accent/40 bg-accent/10 px-3 py-1.5 text-xs text-accent">
                          {isExactStoryActive ? "Preview chain" : "Focus"}
                        </button>
                        <button type="button" onClick={() => { previewChain(chain); if (!isExactStoryActive) setMode("suspicious"); }} className="rounded-xl border border-line bg-panel/40 px-3 py-1.5 text-xs text-muted">
                          Preview
                        </button>
                        {focusedFinding ? (
                          <button type="button" onClick={() => openRelatedFinding(focusedFinding)} className="rounded-xl border border-line bg-panel/40 px-3 py-1.5 text-xs text-muted">
                            Open finding
                          </button>
                        ) : null}
                        <button type="button" onClick={exportFocusedChainMarkdown} disabled={activeChain?.id !== chain.id} className="rounded-xl border border-line bg-panel/40 px-3 py-1.5 text-xs text-muted disabled:opacity-40">
                          Export chain Markdown
                        </button>
                      </div>
                    </div>
                  ))
                ) : (
                  <div className="rounded-2xl border border-line bg-abyss/60 p-4 text-sm text-muted">No suspicious process chains found. Try Full graph or lower the risk threshold.</div>
                )}
              </div>
            </div>

            <div className="rounded-[28px] border border-line bg-panel/70 p-5 shadow-panel">
              <div className="flex flex-wrap items-center justify-between gap-3">
                <div>
                  <p className="font-mono text-xs uppercase tracking-[0.18em] text-accent">Fallback tree view</p>
                  <p className="mt-1 text-sm text-muted">Auxiliary hierarchical list view of the same graph model shown in the canvas.</p>
                </div>
                <div className="flex flex-wrap gap-2">
                  {selectedNode ? (
                    <>
                      <button type="button" onClick={() => navigateToSearch("process_name", selectedNode.name || "")} className="rounded-xl border border-line bg-abyss/70 px-3 py-1.5 text-xs text-muted">
                        <Search className="mr-2 inline h-3.5 w-3.5" />
                        Open selected in Search
                      </button>
                      <button type="button" onClick={() => openInTimeline(selectedNode)} className="rounded-xl border border-line bg-abyss/70 px-3 py-1.5 text-xs text-muted">
                        <Network className="mr-2 inline h-3.5 w-3.5" />
                        Open selected in Timeline
                      </button>
                    </>
                  ) : null}
                </div>
              </div>

              <div ref={treeViewportRef} className="mt-4 max-h-[58rem] overflow-auto rounded-2xl border border-line bg-abyss/50 p-3">
                <div className="space-y-3">
                  {flattened.map((branch) => {
                    const isExpanded = expandedNodeIds.has(branch.node.id);
                    const isSelected = selectedNodeId === branch.node.id;
                    const isLineage = lineageIds.has(branch.node.id);
                    const relatedFindingCount = (findingsByNodeId.get(branch.node.id) ?? []).length;
                    return (
                      <div key={`${branch.node.id}-${branch.depth}`} className="min-w-0" style={{ marginLeft: `${branch.depth * 18}px` }}>
                        <div
                          className={`rounded-2xl border p-3 transition ${isSelected ? "border-accent/50 bg-accent/10" : isLineage ? "border-cyan-400/30 bg-cyan-500/5" : "border-line bg-panel/50"}`}
                        >
                          <div className="flex min-w-0 flex-wrap items-start justify-between gap-3">
                            <div className="min-w-0 flex-1">
                              <div className="flex min-w-0 flex-wrap items-center gap-2">
                                {branch.children.length ? (
                                  <button type="button" onClick={() => setExpandedNodeIds((current) => {
                                    const next = new Set(current);
                                    if (next.has(branch.node.id)) next.delete(branch.node.id);
                                    else next.add(branch.node.id);
                                    return next;
                                  })} className="rounded-full border border-line bg-panel/40 px-2 py-1 text-[11px] text-muted">
                                    {isExpanded ? <ChevronDown className="h-3.5 w-3.5" /> : <ChevronRight className="h-3.5 w-3.5" />}
                                  </button>
                                ) : (
                                  <span className="rounded-full border border-line bg-panel/40 px-2 py-1 text-[11px] text-muted">
                                    <CircleDashed className="h-3.5 w-3.5" />
                                  </span>
                                )}
                                {nodeIcon(branch.node)}
                                <button type="button" onClick={() => {
                                  setDetailDismissed(false);
                                  setSelectedNodeId(branch.node.id);
                                }} className="min-w-0 flex-1 text-left">
                                  <span className="block truncate text-sm font-semibold">{toNodeLabel(branch.node)}</span>
                                </button>
                                <Pill className={riskTone(branch.node.risk_score || 0)}>risk {branch.node.risk_score || 0}</Pill>
                                <Pill className={confidenceTone(branch.node.confidence)}>confidence {branch.node.confidence}</Pill>
                                {relatedFindingCount ? <Pill className="border-warning/40 bg-warning/10 text-warning">{relatedFindingCount} findings</Pill> : null}
                              </div>
                              <p className="mt-2 truncate text-xs text-muted" title={branch.node.command_line || branch.node.path || ""}>
                                {branch.node.command_line || branch.node.path || "No command line"}
                              </p>
                              <div className="mt-2 flex flex-wrap gap-3 text-[11px] text-muted">
                                <span>PID {branch.node.pid ?? "—"}</span>
                                <span>host {normalizeValue(branch.node.host)}</span>
                                <span>user {normalizeValue(branch.node.user)}</span>
                                <span>seen {compactTimestamp(branch.node.first_seen)}</span>
                              </div>
                              {branch.edge ? (
                                <p className="mt-2 text-[11px] text-muted">
                                  edge: <span className="text-white/90">{branch.edge.reason}</span> · confidence {branch.edge.confidence}
                                </p>
                              ) : null}
                            </div>
                            <div className="flex flex-wrap justify-end gap-2">
                              {(branch.node.badges || []).slice(0, 4).map((badge) => (
                                <Pill key={`${branch.node.id}-${badge}`} className={badgeTone(badge)}>
                                  {badge}
                                </Pill>
                              ))}
                            </div>
                          </div>
                        </div>
                      </div>
                    );
                  })}
                </div>
              </div>
            </div>
          </div>

          <div className="space-y-4">
            <div className="rounded-[28px] border border-line bg-panel/70 p-5 shadow-panel">
              <div className="flex items-center justify-between gap-3">
                <p className="font-mono text-xs uppercase tracking-[0.18em] text-accent">Selected detail</p>
                {selectedNode ? (
                  <button type="button" onClick={() => void copyToClipboard(selectedNode.command_line || selectedNode.path || selectedNode.name || "")} className="rounded-xl border border-line bg-abyss/70 px-3 py-1.5 text-xs text-muted">
                    <Copy className="mr-2 inline h-3.5 w-3.5" />
                    Copy IOC/path
                  </button>
                ) : null}
              </div>
              {isDesktopLayout ? selectedNodeDetail : <p className="mt-4 text-sm text-muted">Select a node to open its responsive detail drawer.</p>}
            </div>
          </div>
        </div>
      )}

      {!isDesktopLayout && selectedNode ? (
        <ResponsiveDetailPanel
          open
          mode="drawer"
          widthClass="w-full sm:w-[90vw] xl:w-[82vw]"
          heading="Selected detail"
          subheading="Responsive process detail drawer for narrower workspaces."
          onClose={() => {
            setDetailDismissed(true);
            setSelectedNodeId(null);
            setSelectedChainId(null);
          }}
        >
          {selectedNodeDetail}
        </ResponsiveDetailPanel>
      ) : null}
    </section>
    </ProcessGraphErrorBoundary>
  );
}
