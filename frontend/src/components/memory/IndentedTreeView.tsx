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
  is_group?: boolean;
  group_count?: number;
  group_children?: TreeNode[];
};

type GroupSummary = {
  group: string;
  count: number;
  example: TreeNode;
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
  for (const [key, items] of byName) {
    if (items.length >= GROUP_THRESHOLD) {
      const first = items[0];
      const groupName = first.name;
      groups.push({ group: groupName, count: items.length, example: first });
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
}) {
  const { children, depth, expanded, expandedGroups, selectedEntityId, onSelectEntityId, onOpenProcessDetails, ancestors, toggleExpand, toggleGroup, searchMatch } = props;
  const { expanded: expandedChildren, groups } = useMemo(() => groupChildren(children), [children]);
  const groupNodes: TreeNode[] = groups.map((g) => ({
    process_entity_id: `group-${g.group}-${g.example.process_entity_id}`,
    pid: g.example.pid,
    ppid: g.example.ppid,
    name: g.group,
    command_line: g.example.command_line,
    sources: g.example.sources,
    visibility: g.example.visibility,
    confidence: g.example.confidence,
    child_count: g.count,
    truncated: false,
    is_group: true,
    group_count: g.count,
    group_children: [g.example, ...g.example.children ? [g.example] : []].filter((n, i, arr) => i === 0).concat([]),
    children: g.example.children,
  } as TreeNode));
  const finalChildren: TreeNode[] = [];
  const consumedNames = new Set<string>();
  for (const g of groups) consumedNames.add(g.group);
  for (const c of expandedChildren) {
    if (consumedNames.has(c.name) && groups.find((g) => g.group === c.name)?.example.process_entity_id === c.process_entity_id) {
      continue;
    }
    finalChildren.push(c);
  }
  groupNodes.sort((a, b) => (b.group_count || 0) - (a.group_count || 0));
  const merged: TreeNode[] = [];
  const groupInjected = new Set<string>();
  for (const c of finalChildren) {
    if (consumedNames.has(c.name) && !groupInjected.has(c.name)) {
      const g = groupNodes.find((g) => g.name === c.name);
      if (g) {
        merged.push(g);
        groupInjected.add(c.name);
      }
    }
    merged.push(c);
  }
  for (const g of groupNodes) {
    if (!groupInjected.has(g.name)) merged.push(g);
  }
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
  const [orphansExpanded, setOrphansExpanded] = useState<boolean>(false);

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
      : api.getCanonicalProcessTree(caseId, { run_id: effectiveRunId || undefined, depth: 3, max_nodes: 200 }),
    enabled: Boolean(caseId && effectiveRunId),
    refetchOnWindowFocus: false,
    placeholderData: (previous) => previous,
  });

  const tree = treeQuery.data;
  const rootNodes: TreeNode[] = useMemo(() => (tree?.nodes ?? []).map(toTreeNode), [tree?.nodes]);
  const orphanNodes: TreeNode[] = useMemo(() => selectedEntityId || numericSearchPid !== null ? [] : (tree?.orphans ?? []).map(toTreeNode), [tree?.orphans, selectedEntityId, numericSearchPid]);

  useEffect(() => {
    const nextSelected = (tree as any)?.selected_entity_id;
    if (numericSearchPid !== null && tree && nextSelected !== selectedEntityId) {
      onSelectEntityId(nextSelected ?? null);
    }
  }, [tree, numericSearchPid, selectedEntityId, onSelectEntityId]);

  const ancestors = useMemo(() => {
    if (!selectedEntityId) return new Set<string>();
    const set = new Set<string>();
    const byId = new Map<string, TreeNode>();
    const visit = (n: TreeNode) => {
      byId.set(n.process_entity_id, n);
      n.children.forEach(visit);
    };
    [...rootNodes, ...orphanNodes].forEach(visit);
    let cur: string | undefined = selectedEntityId;
    while (cur) {
      const node = byId.get(cur);
      if (!node) break;
      set.add(node.process_entity_id);
      cur = node.ppid != null
        ? [...byId.values()].find((n) => n.pid === node.ppid && !set.has(n.process_entity_id))?.process_entity_id
        : undefined;
    }
    return set;
  }, [selectedEntityId, rootNodes, orphanNodes]);

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
    [...rootNodes, ...orphanNodes].forEach(visit);
    return set;
  }, [search, rootNodes, orphanNodes]);

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
  if (!rootNodes.length && !orphanNodes.length) {
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
        Main tree · {rootNodes.length} root{rootNodes.length === 1 ? "" : "s"}
        {" · "}
        Orphans · {orphanNodes.length}
        {search ? ` · ${matchingEntities.size} match(es) for "${search}"` : ""}
      </p>

      <section
        className="space-y-2 rounded-2xl border border-line bg-abyss/30 p-3"
        data-testid="indented-tree-main"
        aria-label="Main tree"
      >
        <h4 className="text-[10px] font-semibold uppercase tracking-[0.18em] text-muted">Main tree · {rootNodes.length} root</h4>
        <div className="space-y-1 overflow-y-auto" style={{ maxHeight: "60vh" }}>
          {rootNodes.map((root) => (
            <NodeRow
              key={root.process_entity_id}
              node={root}
              depth={0}
              expanded={expanded}
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

      <section
        className="space-y-2 rounded-2xl border border-line bg-abyss/30 p-3"
        data-testid="indented-tree-orphans"
        aria-label="Orphans"
      >
        <header className="flex flex-wrap items-center justify-between gap-2">
          <h4 className="text-[10px] font-semibold uppercase tracking-[0.18em] text-muted">
            Orphans · {orphanNodes.length}
          </h4>
          <button
            type="button"
            onClick={() => setOrphansExpanded((v) => !v)}
            aria-expanded={orphansExpanded}
            data-testid="indented-tree-orphans-toggle"
            className="rounded-md border border-line bg-abyss/70 px-2 py-0.5 text-[10px] text-muted"
          >
            {orphansExpanded ? "Hide orphan processes" : "Show orphan processes"}
          </button>
        </header>
        {!orphansExpanded ? (
          <p className="text-[11px] text-muted" data-testid="indented-tree-orphans-summary">
            Parent process is not present in the selected run. {orphanNodes.length} orphan
            process{orphanNodes.length === 1 ? "" : "es"} detected.
          </p>
        ) : (
          <div className="space-y-1 overflow-y-auto" style={{ maxHeight: "32vh" }}>
            {orphanNodes.map((orphan, index) => (
              <NodeRow
                key={orphan.process_entity_id}
                node={orphan}
                depth={0}
                expanded={expanded}
                expandedGroups={expandedGroups}
                selectedEntityId={selectedEntityId}
                onSelectEntityId={onSelectEntityId}
                onOpenProcessDetails={onOpenProcessDetails}
                ancestors={ancestors}
                toggleExpand={toggleExpand}
                toggleGroup={toggleGroup}
                searchMatch={matchingEntities.has(orphan.process_entity_id)}
                connector={index === orphanNodes.length - 1 ? "last" : "child"}
              />
            ))}
          </div>
        )}
      </section>

      {selectedEntityId ? (
        <button
          type="button"
          onClick={() => selectedEntityId && copyPid(rootNodes.find((n) => n.process_entity_id === selectedEntityId)?.pid ?? orphanNodes.find((n) => n.process_entity_id === selectedEntityId)?.pid ?? 0)}
          data-testid="indented-tree-copy-pid"
          className="rounded-md border border-line bg-abyss/70 px-2 py-1 text-xs"
        >
          Copy PID
        </button>
      ) : null}
    </div>
  );
}
