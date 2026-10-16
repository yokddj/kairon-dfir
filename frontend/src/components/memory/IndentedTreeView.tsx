import { useEffect, useMemo, useState } from "react";
import { useQuery } from "@tanstack/react-query";
import { type MemoryProcessTreeEntity, api } from "../../api/client";
import {
  ChevronDown,
  ChevronRight,
  Eye,
  GitBranch,
  Network,
  Package,
  Search,
  ShieldAlert,
  Sparkles,
  XCircle,
} from "lucide-react";

type Props = {
  caseId: string;
  runId: string | null;
  runOptions: { default_run_id: string | null; runs: Array<{ run_id: string; profile: string; status: string }> } | null;
  selectedRunId: string | null;
  onSelectRunId: (next: string | null) => void;
  selectedEntityId: string | null;
  onSelectEntityId: (next: string | null) => void;
  onOpenProcessDetails: (entityId: string) => void;
};

// The whole tree is loaded at once: the backend already reads every process
// of the run, and a capped tree hides processes without saying where.
export const TREE_DEPTH = 64;
export const TREE_MAX_NODES = 2000;

type TreeNode = {
  process_entity_id: string;
  pid: number;
  ppid: number | null;
  name: string;
  command_line: string | null;
  sources: string[];
  visibility: Record<string, boolean>;
  confidence: string;
  children: TreeNode[];
  truncated?: boolean;
  child_count?: number;
  // Top-level process whose parent had exited, or that sat in a parent loop.
  parent_exited?: boolean;
  parent_loop?: boolean;
  is_group?: boolean;
  group_count?: number;
  group_children?: TreeNode[];
};

type GroupSummary = {
  group: string;
  items: TreeNode[];
};

const TONE: Record<string, string> = {
  info: "border-sky-400/40 bg-sky-500/10 text-sky-100",
  warn: "border-amber-400/30 bg-amber-500/10 text-amber-100",
  danger: "border-rose-400/30 bg-rose-500/10 text-rose-100",
  neutral: "border-line bg-abyss/70 text-muted",
  good: "border-emerald-400/40 bg-emerald-500/10 text-emerald-100",
};

function visibilityTone(node: TreeNode): keyof typeof TONE {
  if (node.visibility.scan_only || node.visibility.hidden_candidate) return "danger";
  if (node.visibility.terminated) return "neutral";
  if (node.visibility.unknown) return "warn";
  return "info";
}

function visibilityLabel(node: TreeNode): string {
  if (node.visibility.terminated) return "Terminated";
  if (node.visibility.hidden_candidate) return "Hidden candidate";
  if (node.visibility.scan_only) return "Scan only";
  if (node.visibility.unknown) return "Unknown";
  return "Listed";
}

function sourceBadge(plugin: string): string {
  return plugin.replace("windows.", "");
}

function reported(value: unknown): string {
  if (value === null || value === undefined || value === "") return "—";
  return String(value);
}

function nodeIcon(node: TreeNode) {
  const name = (node.name || "").toLowerCase();
  if (node.is_group) return <Package className="h-3.5 w-3.5 text-muted" />;
  if (node.visibility.scan_only || node.visibility.hidden_candidate) return <ShieldAlert className="h-3.5 w-3.5 text-rose-300" />;
  if (node.visibility.terminated) return <XCircle className="h-3.5 w-3.5 text-muted" />;
  if (name.includes("svchost")) return <Sparkles className="h-3.5 w-3.5 text-cyan-200" />;
  if (name.includes("powershell") || name.includes("cmd")) return <Network className="h-3.5 w-3.5 text-orange-200" />;
  if (name.includes("system") || node.pid === 4) return <GitBranch className="h-3.5 w-3.5 text-emerald-200" />;
  return <Network className="h-3.5 w-3.5 text-muted" />;
}

function toTreeNode(node: any): TreeNode {
  return {
    process_entity_id: node.process_entity_id,
    pid: node.pid,
    ppid: node.ppid ?? null,
    name: node.name ?? "",
    command_line: node.command_line ?? null,
    sources: Array.isArray(node.sources) ? node.sources : [],
    visibility: node.visibility || {},
    confidence: node.confidence || "low",
    child_count: node.child_count ?? 0,
    truncated: Boolean(node.truncated),
    parent_exited: Boolean(node.tree?.is_orphan),
    parent_loop: Boolean(node.tree?.is_cycle),
    children: Array.isArray(node.children) ? node.children.map(toTreeNode) : [],
  };
}

/** Group children that share the same (name, command_line) and exceed the threshold. */
function groupChildren(children: TreeNode[]): { expanded: TreeNode[]; groups: GroupSummary[] } {
  const expanded: TreeNode[] = [];
  const groups: GroupSummary[] = [];
  const GROUP_THRESHOLD = 3;
  const byName = new Map<string, TreeNode[]>();
  for (const child of children) {
    if (!child.name) {
      expanded.push(child);
      continue;
    }
    const key = `${child.name}|${child.command_line ?? ""}`;
    if (!byName.has(key)) byName.set(key, []);
    byName.get(key)!.push(child);
  }
  for (const items of byName.values()) {
    if (items.length >= GROUP_THRESHOLD) {
      groups.push({ group: items[0].name, items });
    } else {
      expanded.push(...items);
    }
  }
  return { expanded, groups };
}

function NodeRow({
  node,
  depth,
  expanded,
  expandedGroups,
  selectedEntityId,
  onSelectEntityId,
  onOpenProcessDetails,
  ancestors,
  toggleExpand,
  toggleGroup,
  searchMatch,
  connector,
}: {
  node: TreeNode;
  depth: number;
  expanded: Set<string>;
  expandedGroups: Set<string>;
  selectedEntityId: string | null;
  onSelectEntityId: (next: string | null) => void;
  onOpenProcessDetails: (entityId: string) => void;
  ancestors: Set<string>;
  toggleExpand: (entityId: string) => void;
  toggleGroup: (key: string) => void;
  searchMatch: boolean;
  connector: "root" | "child" | "last" | "leaf";
}) {
  const hasChildren = node.children.length > 0 || (node.child_count && node.child_count > 0);
  const isSelected = selectedEntityId === node.process_entity_id;
  const isAncestor = ancestors.has(node.process_entity_id);
  const isExpanded = expanded.has(node.process_entity_id) || isAncestor || isSelected;
  const tone = visibilityTone(node);
  const isGroup = node.is_group;
  const groupKey = isGroup ? `group:${node.process_entity_id}` : "";

  // Visual connectors: vertical line at the left and a "├─"/"└─" prefix.
  const connectorLabel =
    connector === "root" ? "" : connector === "last" ? "└─" : "├─";

  return (
    <>
      <div
        className={`flex items-start gap-2 rounded-md border px-2 py-1 text-xs transition ${
          isSelected
            ? "border-accent/60 bg-accent/10"
            : isAncestor
              ? "border-amber-300/40 bg-amber-300/8"
              : isGroup
                ? "border-line bg-abyss/60"
                : `border-line ${TONE[tone]}`
        }`}
        style={{ marginLeft: depth * 14 }}
        data-testid="indented-tree-row"
        data-pid={node.pid}
        data-search-match={searchMatch ? "true" : "false"}
      >
        <div className="flex w-4 shrink-0 items-center">
          {hasChildren ? (
            <button
              type="button"
              onClick={() => (isGroup ? toggleGroup(groupKey) : toggleExpand(node.process_entity_id))}
              aria-label={isGroup ? (expandedGroups.has(groupKey) ? "Collapse group" : "Expand group") : isExpanded ? "Collapse" : "Expand"}
              data-testid={isGroup ? "indented-tree-toggle-group" : "indented-tree-toggle"}
              className="rounded p-0.5 hover:bg-abyss/40"
            >
              {isGroup ? (
                expandedGroups.has(groupKey) ? <ChevronDown className="h-3 w-3" /> : <ChevronRight className="h-3 w-3" />
              ) : isExpanded ? (
                <ChevronDown className="h-3 w-3" />
              ) : (
                <ChevronRight className="h-3 w-3" />
              )}
            </button>
          ) : null}
        </div>
        {depth > 0 ? (
          <span
            aria-hidden="true"
            className="select-none whitespace-pre font-mono text-[10px] text-muted"
            data-testid="indented-tree-connector"
          >
            {connectorLabel}
          </span>
        ) : null}
        {nodeIcon(node)}
        <div className="min-w-0 flex-1">
          <div className="flex flex-wrap items-center gap-1">
            <button
              type="button"
              onClick={() => onSelectEntityId(node.process_entity_id)}
              className="truncate text-left font-mono text-xs text-ink"
            >
              {isGroup
                ? `${node.name} × ${node.group_count}`
                : `${node.name || "—"} (${node.pid})`}
            </button>
            {typeof node.child_count === "number" && node.child_count > 0 ? (
              <span className="rounded-md border border-line bg-abyss/60 px-1.5 py-0.5 text-[10px] text-muted" data-testid="indented-tree-child-count">
                {node.child_count} children
              </span>
            ) : null}
            {!isGroup ? (
              <span className={`rounded-md border px-1.5 py-0.5 text-[10px] ${TONE[tone]}`}>
                {visibilityLabel(node)}
              </span>
            ) : null}
            {depth === 0 && node.parent_exited && node.ppid !== null ? (
              <span className="text-[10px] text-muted" title="The parent process had already exited when memory was captured" data-testid="indented-tree-parent-exited">
                parent {node.ppid} exited
              </span>
            ) : null}
            {depth === 0 && node.parent_loop ? (
              <span className="text-[10px] text-amber-200" title="The recorded parents of these processes point at each other" data-testid="indented-tree-parent-loop">
                parent loop
              </span>
            ) : null}
            {node.sources.length > 0 && !isGroup ? (
              <span className="flex flex-wrap gap-0.5 text-[10px] text-muted">
                {node.sources.map((plugin) => (
                  <span key={plugin} className="rounded border border-line bg-abyss/70 px-1 py-0">
                    {sourceBadge(plugin)}
                  </span>
                ))}
              </span>
            ) : null}
          </div>
          {!isGroup && node.command_line ? (
            <p className="mt-0.5 truncate text-[10px] text-muted" title={node.command_line}>
              {node.command_line}
            </p>
          ) : null}
        </div>
        {!isGroup ? (
          <button
            type="button"
            onClick={() => onOpenProcessDetails(node.process_entity_id)}
            className="rounded-md border border-line bg-abyss/70 px-2 py-0.5 text-[10px] text-muted hover:border-accent/40"
            data-testid="indented-tree-inspect"
          >
            <Eye className="mr-0.5 inline h-3 w-3" />
            Inspect
          </button>
        ) : null}
      </div>
      {!isGroup && isExpanded && node.children.length > 0 ? (
        <TreeChildren
          children={node.children}
          depth={depth + 1}
          expanded={expanded}
          expandedGroups={expandedGroups}
          selectedEntityId={selectedEntityId}
          onSelectEntityId={onSelectEntityId}
          onOpenProcessDetails={onOpenProcessDetails}
          ancestors={ancestors}
          toggleExpand={toggleExpand}
          toggleGroup={toggleGroup}
          searchMatch={searchMatch}
        />
      ) : null}
      {isGroup && expandedGroups.has(groupKey) && node.group_children ? (
        <TreeChildren
          ungrouped
          children={node.group_children}
          depth={depth + 1}
          expanded={expanded}
          expandedGroups={expandedGroups}
          selectedEntityId={selectedEntityId}
          onSelectEntityId={onSelectEntityId}
          onOpenProcessDetails={onOpenProcessDetails}
          ancestors={ancestors}
          toggleExpand={toggleExpand}
          toggleGroup={toggleGroup}
          searchMatch={searchMatch}
        />
      ) : null}
    </>
  );
}

function TreeChildren(props: {
  children: TreeNode[];
  depth: number;
  expanded: Set<string>;
  expandedGroups: Set<string>;
  selectedEntityId: string | null;
  onSelectEntityId: (next: string | null) => void;
  onOpenProcessDetails: (entityId: string) => void;
  ancestors: Set<string>;
  toggleExpand: (entityId: string) => void;
  toggleGroup: (key: string) => void;
  searchMatch: boolean;
  // The members of an expanded group, listed as they are.
  ungrouped?: boolean;
}) {
  const { ungrouped, children, depth, expanded, expandedGroups, selectedEntityId, onSelectEntityId, onOpenProcessDetails, ancestors, toggleExpand, toggleGroup, searchMatch } = props;
  const { expanded: expandedChildren, groups } = useMemo(
    () => (ungrouped ? { expanded: children, groups: [] } : groupChildren(children)),
    [children, ungrouped],
  );
  // A group stands for every sibling it folds; expanding it lists them all.
  const groupNodes: TreeNode[] = groups.map((g) => {
    const first = g.items[0];
    return {
      ...first,
      process_entity_id: `group-${first.process_entity_id}`,
      child_count: g.items.length,
      truncated: false,
      is_group: true,
      group_count: g.items.length,
      group_children: g.items,
      children: [],
    };
  });
  const merged: TreeNode[] = [...expandedChildren, ...groupNodes].sort((a, b) => a.pid - b.pid);
  return (
    <>
      {merged.map((child, index) => (
        <NodeRow
          key={child.process_entity_id}
          node={child}
          depth={depth}
          expanded={expanded}
          expandedGroups={expandedGroups}
          selectedEntityId={selectedEntityId}
          onSelectEntityId={onSelectEntityId}
          onOpenProcessDetails={onOpenProcessDetails}
          ancestors={ancestors}
          toggleExpand={toggleExpand}
          toggleGroup={toggleGroup}
          searchMatch={searchMatch}
          connector={index === merged.length - 1 ? "last" : "child"}
        />
      ))}
    </>
  );
}

export function IndentedTreeView({
  caseId,
  runId,
  runOptions,
  selectedRunId,
  onSelectRunId,
  selectedEntityId,
  onSelectEntityId,
  onOpenProcessDetails,
}: Props) {
  const [search, setSearch] = useState("");
  const [expanded, setExpanded] = useState<Set<string>>(new Set());
  const [expandedGroups, setExpandedGroups] = useState<Set<string>>(new Set());

  const effectiveRunId = selectedRunId || runId || runOptions?.default_run_id || null;
  const numericSearchPid = /^\d+$/.test(search.trim()) ? Number(search.trim()) : null;
  const treeQuery = useQuery<MemoryProcessTreeEntity>({
    queryKey: ["indented-tree", caseId, effectiveRunId, selectedEntityId, numericSearchPid],
    queryFn: () => selectedEntityId || numericSearchPid !== null
      ? api.getCanonicalProcessLineage(caseId, {
        run_id: effectiveRunId || undefined,
        entity_id: selectedEntityId || undefined,
        pid: selectedEntityId ? undefined : numericSearchPid ?? undefined,
        descendant_depth: 3,
        max_nodes: 200,
      })
      : api.getCanonicalProcessTree(caseId, { run_id: effectiveRunId || undefined, depth: TREE_DEPTH, max_nodes: TREE_MAX_NODES }),
    enabled: Boolean(caseId && effectiveRunId),
    refetchOnWindowFocus: false,
    placeholderData: (previous) => previous,
  });

  const tree = treeQuery.data;
  const rootNodes: TreeNode[] = useMemo(() => (tree?.nodes ?? []).map(toTreeNode), [tree?.nodes]);

  useEffect(() => {
    const nextSelected = (tree as any)?.selected_entity_id;
    if (numericSearchPid !== null && tree && nextSelected !== selectedEntityId) {
      onSelectEntityId(nextSelected ?? null);
    }
  }, [tree, numericSearchPid, selectedEntityId, onSelectEntityId]);

  // Parent of every loaded node, from the tree itself (PIDs can be reused).
  const parentOf = useMemo(() => {
    const map = new Map<string, string>();
    const visit = (n: TreeNode) => {
      n.children.forEach((c) => {
        map.set(c.process_entity_id, n.process_entity_id);
        visit(c);
      });
    };
    rootNodes.forEach(visit);
    return map;
  }, [rootNodes]);

  const pathTo = (entityId: string, into: Set<string>) => {
    let cur: string | undefined = entityId;
    while (cur && !into.has(cur)) {
      into.add(cur);
      cur = parentOf.get(cur);
    }
  };

  const ancestors = useMemo(() => {
    const set = new Set<string>();
    if (selectedEntityId) pathTo(selectedEntityId, set);
    return set;
  }, [selectedEntityId, parentOf]);

  const matchingEntities = useMemo(() => {
    if (!search) return new Set<string>();
    const needle = search.toLowerCase();
    const set = new Set<string>();
    const visit = (n: TreeNode) => {
      if (
        String(n.pid).includes(needle) ||
        (n.name || "").toLowerCase().includes(needle) ||
        (n.command_line || "").toLowerCase().includes(needle)
      ) {
        set.add(n.process_entity_id);
      }
      n.children.forEach(visit);
    };
    rootNodes.forEach(visit);
    return set;
  }, [search, rootNodes]);

  // Open the branches that lead to a search match so it can be seen.
  const shownExpanded = useMemo(() => {
    if (!matchingEntities.size) return expanded;
    const set = new Set(expanded);
    const path = new Set<string>();
    matchingEntities.forEach((id) => {
      const parent = parentOf.get(id);
      if (parent) pathTo(parent, path);
    });
    path.forEach((id) => set.add(id));
    return set;
  }, [expanded, matchingEntities, parentOf]);

  function toggleExpand(entityId: string) {
    setExpanded((prev) => {
      const next = new Set(prev);
      if (next.has(entityId)) next.delete(entityId);
      else next.add(entityId);
      return next;
    });
  }

  function toggleGroup(key: string) {
    setExpandedGroups((prev) => {
      const next = new Set(prev);
      if (next.has(key)) next.delete(key);
      else next.add(key);
      return next;
    });
  }

  function copyPid(pid: number) {
    if (typeof navigator !== "undefined" && navigator.clipboard) {
      navigator.clipboard.writeText(String(pid)).catch(() => undefined);
    }
  }

  const showSkeleton = treeQuery.isLoading && !tree;

  if (showSkeleton) {
    return (
      <div className="space-y-3" data-testid="indented-tree-skeleton" role="status">
        <p className="text-sm text-muted">Loading indented tree…</p>
        <div className="space-y-2">
          {Array.from({ length: 4 }).map((_, i) => (
            <div key={i} className="h-8 animate-pulse rounded-md border border-line bg-abyss/40" />
          ))}
        </div>
      </div>
    );
  }
  if (treeQuery.error instanceof Error) {
    return <p className="rounded-2xl border border-rose-400/30 bg-rose-500/10 p-3 text-sm text-rose-200">{treeQuery.error.message}</p>;
  }
  if (!rootNodes.length) {
    return <p className="rounded-2xl border border-line bg-abyss/60 p-4 text-sm text-muted">No canonical processes for this run yet.</p>;
  }

  return (
    <div className="space-y-3" data-testid="indented-tree">
      <header className="flex flex-wrap items-center gap-2">
        <div className="flex flex-1 items-center gap-2 rounded-xl border border-line bg-abyss/70 px-3 py-1 text-sm">
          <Search className="h-3.5 w-3.5 text-muted" />
          <input
            value={search}
            onChange={(event) => setSearch(event.target.value)}
            placeholder="Search PID, name or command line"
            className="flex-1 bg-transparent outline-none"
            data-testid="indented-tree-search"
          />
        </div>
      </header>
      <p className="text-xs text-muted" data-testid="indented-tree-summary">
        {rootNodes.length} top-level process{rootNodes.length === 1 ? "" : "es"}
        {search ? ` · ${matchingEntities.size} match${matchingEntities.size === 1 ? "" : "es"} for "${search}"` : ""}
      </p>

      <section
        className="space-y-2 rounded-2xl border border-line bg-abyss/30 p-3"
        data-testid="indented-tree-main"
        aria-label="Process tree"
      >
        <div className="space-y-1 overflow-y-auto" style={{ maxHeight: "70vh" }}>
          {rootNodes.map((root) => (
            <NodeRow
              key={root.process_entity_id}
              node={root}
              depth={0}
              expanded={shownExpanded}
              expandedGroups={expandedGroups}
              selectedEntityId={selectedEntityId}
              onSelectEntityId={onSelectEntityId}
              onOpenProcessDetails={onOpenProcessDetails}
              ancestors={ancestors}
              toggleExpand={toggleExpand}
              toggleGroup={toggleGroup}
              searchMatch={matchingEntities.has(root.process_entity_id)}
              connector="root"
            />
          ))}
        </div>
      </section>

      {selectedEntityId ? (
        <button
          type="button"
          onClick={() => selectedEntityId && copyPid(rootNodes.find((n) => n.process_entity_id === selectedEntityId)?.pid ?? 0)}
          data-testid="indented-tree-copy-pid"
          className="rounded-md border border-line bg-abyss/70 px-2 py-1 text-xs"
        >
          Copy PID
        </button>
      ) : null}
    </div>
  );
}
