import { useEffect, useMemo, useRef, useState } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import {
  ChevronDown,
  ChevronRight,
  Copy,
  Eye,
  GitBranch,
  Layers,
  Network,
  RotateCcw,
  Search,
  ShieldAlert,
  Table as TableIcon,
  Workflow,
  XCircle,
  ZoomIn,
  ZoomOut,
} from "lucide-react";
import {
  type MemoryProcessEntity,
  type MemoryProcessEntityDetail,
  type MemoryProcessTreeEntity,
  api,
} from "../api/client";
import { buildProcessGraphLayout, type GraphEdgeLike, GRAPH_CARD_HEIGHT, GRAPH_CARD_WIDTH } from "../lib/processGraphLayout";

type ViewMode = "graph" | "table";
type VisibilityFilter =
  | "all"
  | "listed"
  | "scan_only"
  | "terminated"
  | "orphans"
  | "hidden_candidate"
  | "interesting";
type Scope = "main" | "orphans";

type NodeShape = {
  process_entity_id: string;
  pid: number;
  ppid: number | null;
  name: string;
  command_line: string | null;
  sources: string[];
  visibility: { listed?: boolean; scan_only?: boolean; terminated?: boolean; hidden_candidate?: boolean; unknown?: boolean };
  findings: string[];
  child_count: number;
  truncated?: boolean;
  omitted_children?: number;
  confidence?: string;
  children: NodeShape[];
};

type TreeResponse = MemoryProcessTreeEntity;

const TONE: Record<string, string> = {
  info: "border-sky-400/40 bg-sky-500/10 text-sky-100",
  warn: "border-amber-400/40 bg-amber-500/10 text-amber-100",
  danger: "border-rose-400/40 bg-rose-500/10 text-rose-100",
  neutral: "border-line bg-abyss/70 text-muted",
  good: "border-emerald-400/40 bg-emerald-500/10 text-emerald-100",
};

function visibilityTone(node: NodeShape): keyof typeof TONE {
  if (node.visibility.scan_only || node.visibility.hidden_candidate) return "danger";
  if (node.visibility.terminated) return "neutral";
  if (node.visibility.unknown) return "warn";
  return "info";
}

function visibilityLabel(node: NodeShape): string {
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

function nodeLabel(n: NodeShape): string {
  if (n.truncated) return `… ${reported(n.pid)}`;
  return `${reported(n.name || reported(n.pid))}`;
}

function toNodeShape(node: any): NodeShape {
  return {
    process_entity_id: node.process_entity_id,
    pid: node.pid,
    ppid: node.ppid ?? null,
    name: node.name ?? "",
    command_line: node.command_line ?? null,
    sources: Array.isArray(node.sources) ? node.sources : [],
    visibility: node.visibility || {},
    findings: Array.isArray(node.findings) ? node.findings : [],
    child_count: node.child_count ?? 0,
    truncated: Boolean(node.truncated),
    omitted_children: node.omitted_children ?? 0,
    confidence: node.confidence,
    children: Array.isArray(node.children) ? node.children.map(toNodeShape) : [],
  };
}

type MemoryProcessGraphProps = {
  caseId: string;
  runId: string | null;
  onOpenDetail: (entityId: string) => void;
  selectedEntityId?: string | null;
  onSelectEntityId?: (next: string | null) => void;
};

export function MemoryProcessGraph({
  caseId,
  runId,
  onOpenDetail,
  selectedEntityId: externalSelectedEntityId,
  onSelectEntityId: externalOnSelectEntityId,
}: MemoryProcessGraphProps) {
  const queryClient = useQueryClient();
  const [viewMode, setViewMode] = useState<ViewMode>("graph");
  const [scope, setScope] = useState<Scope>("main");
  const [visibility, setVisibility] = useState<VisibilityFilter>("all");
  const [depth, setDepth] = useState(2);
  const [maxNodes, setMaxNodes] = useState(60);
  const [search, setSearch] = useState("");
  const [internalSelectedEntityId, setInternalSelectedEntityId] = useState<string | null>(null);
  const [focusedEntityId, setFocusedEntityId] = useState<string | null>(null);
  const selectedEntityId =
    externalSelectedEntityId !== undefined ? externalSelectedEntityId : internalSelectedEntityId;
  const setSelectedEntityId = externalOnSelectEntityId ?? setInternalSelectedEntityId;
  const [zoom, setZoom] = useState(1);
  const [pan, setPan] = useState({ x: 0, y: 0 });
  const [dragStart, setDragStart] = useState<{ x: number; y: number; pan: { x: number; y: number } } | null>(null);
  const [message, setMessage] = useState<string | null>(null);
  const [expandedIds, setExpandedIds] = useState<Set<string>>(new Set());
  const containerRef = useRef<HTMLDivElement | null>(null);

  const treeParams = useMemo(() => {
    const params: any = { run_id: runId || undefined, depth, max_nodes: maxNodes };
    if (scope === "orphans") {
      params.orphans_only = true;
    } else if (visibility === "orphans") {
      params.orphans_only = true;
    }
    if (visibility !== "all" && visibility !== "orphans") {
      params.visibility = visibility;
    }
    if (visibility === "interesting") {
      params.interesting_only = true;
    }
    if (search) {
      params.search = search;
    }
    return params;
  }, [runId, depth, maxNodes, scope, visibility, search]);

  const treeQuery = useQuery({
    queryKey: ["memory-process-graph", caseId, runId, treeParams],
    queryFn: () => api.getCanonicalProcessTree(caseId, treeParams),
    enabled: Boolean(caseId && runId),
    refetchOnWindowFocus: false,
  });

  const ancestorsQuery = useQuery({
    queryKey: ["memory-process-ancestors", caseId, runId, focusedEntityId],
    queryFn: () => api.getCanonicalProcessTree(caseId, { run_id: runId || undefined, root_entity_id: focusedEntityId || undefined, depth: 8, max_nodes: 30, include_ancestors: true }),
    enabled: false,
    refetchOnWindowFocus: false,
  });

  const detailQuery = useQuery({
    queryKey: ["memory-process-entity-detail", caseId, focusedEntityId, runId],
    queryFn: () => api.getCanonicalProcessEntityDetail(caseId, focusedEntityId as string, runId || undefined),
    enabled: Boolean(caseId && focusedEntityId),
    refetchOnWindowFocus: false,
  });

  const tree = treeQuery.data;
  const shape: NodeShape[] = useMemo(() => (tree?.nodes ?? []).map(toNodeShape), [tree?.nodes]);

  // Layout
  const layout = useMemo(() => {
    const flat: any[] = [];
    const collect = (n: NodeShape) => {
      flat.push(n);
      n.children.forEach(collect);
    };
    shape.forEach(collect);
    return buildProcessGraphLayout(flat as any, []);
  }, [shape]);

  // Re-center on focused entity
  useEffect(() => {
    if (!focusedEntityId) return;
    const target = layout.byId.get(focusedEntityId);
    if (!target) return;
    const el = containerRef.current;
    if (!el) return;
    const desired = {
      x: el.clientWidth / 2 - (target.x + target.width / 2) * zoom,
      y: el.clientHeight / 2 - (target.y + target.height / 2) * zoom,
    };
    setPan(desired);
  }, [focusedEntityId, layout, zoom]);

  // Track visible (non-truncated) nodes for stats
  const visibleNodeCount = useMemo(() => {
    let count = 0;
    const visit = (n: NodeShape) => {
      if (!n.truncated) count += 1;
      n.children.forEach(visit);
    };
    shape.forEach(visit);
    return count;
  }, [shape]);

  const truncatedCount = useMemo(() => {
    let count = 0;
    const visit = (n: NodeShape) => {
      if (n.truncated) count += 1;
      n.children.forEach(visit);
    };
    shape.forEach(visit);
    return count;
  }, [shape]);

  function focusNode(entityId: string) {
    setFocusedEntityId(entityId);
  }

  function showAncestors() {
    if (!focusedEntityId) return;
    ancestorsQuery.refetch();
  }

  function expandBranch(entityId: string) {
    setExpandedIds((prev) => new Set(prev).add(entityId));
  }

  function collapseBranch(entityId: string) {
    setExpandedIds((prev) => {
      const next = new Set(prev);
      next.delete(entityId);
      return next;
    });
  }

  function copyPid(pid: number) {
    if (typeof navigator !== "undefined" && navigator.clipboard) {
      navigator.clipboard.writeText(String(pid)).catch(() => undefined);
    }
    setMessage(`PID ${pid} copied to clipboard.`);
    window.setTimeout(() => setMessage(null), 2000);
  }

  function handleWheel(event: React.WheelEvent) {
    if (event.ctrlKey || event.metaKey) {
      event.preventDefault();
      const delta = event.deltaY < 0 ? 0.1 : -0.1;
      setZoom((z) => Math.max(0.5, Math.min(2.5, z + delta)));
    }
  }

  function handleMouseDown(event: React.MouseEvent) {
    if (event.button !== 0) return;
    setDragStart({ x: event.clientX, y: event.clientY, pan });
  }

  function handleMouseMove(event: React.MouseEvent) {
    if (!dragStart) return;
    setPan({ x: dragStart.pan.x + (event.clientX - dragStart.x), y: dragStart.pan.y + (event.clientY - dragStart.y) });
  }

  function handleMouseUp() {
    setDragStart(null);
  }

  function resetView() {
    setZoom(1);
    setPan({ x: 0, y: 0 });
  }

  return (
    <section
      className="rounded-[28px] border border-line bg-panel/60 p-5 space-y-4"
      data-testid="memory-process-graph"
      aria-label="Interactive memory process graph"
    >
      <header className="flex flex-wrap items-start justify-between gap-3">
        <div>
          <h3 className="text-lg font-semibold flex items-center gap-2">
            <Network className="h-4 w-4 text-accent" />
            Memory process graph
          </h3>
          <p className="mt-1 text-sm text-muted">
            Interactive parent/child view of canonical memory entities. Renders the selected
            run only and never mixes basic/extended results.
          </p>
        </div>
        <div className="flex flex-wrap gap-2" role="group" aria-label="View mode">
          <button
            type="button"
            onClick={() => setViewMode("graph")}
            aria-pressed={viewMode === "graph"}
            data-testid="view-mode-graph"
            className={`rounded-xl px-3 py-2 text-xs font-semibold ${viewMode === "graph" ? "bg-accent text-abyss" : "border border-line bg-abyss/70 text-muted"}`}
          >
            <Network className="mr-1 inline h-3.5 w-3.5" />
            Graph
          </button>
          <button
            type="button"
            onClick={() => setViewMode("table")}
            aria-pressed={viewMode === "table"}
            data-testid="view-mode-table"
            className={`rounded-xl px-3 py-2 text-xs font-semibold ${viewMode === "table" ? "bg-accent text-abyss" : "border border-line bg-abyss/70 text-muted"}`}
          >
            <TableIcon className="mr-1 inline h-3.5 w-3.5" />
            Table
          </button>
        </div>
      </header>

      {message ? <p className="rounded-2xl border border-sky-400/30 bg-sky-500/10 p-3 text-xs text-sky-100" role="status">{message}</p> : null}

      <div className="grid gap-3 md:grid-cols-4">
        <div className="rounded-2xl border border-line bg-abyss/60 p-3">
          <label className="text-[10px] uppercase tracking-[0.18em] text-muted" htmlFor="graph-scope">Scope</label>
          <select
            id="graph-scope"
            value={scope}
            onChange={(event) => setScope(event.target.value as Scope)}
            className="mt-1 w-full rounded-xl border border-line bg-abyss/70 px-2 py-1 text-sm"
          >
            <option value="main">Main tree</option>
            <option value="orphans">Orphans</option>
          </select>
        </div>
        <div className="rounded-2xl border border-line bg-abyss/60 p-3">
          <label className="text-[10px] uppercase tracking-[0.18em] text-muted" htmlFor="graph-visibility">Visibility</label>
          <select
            id="graph-visibility"
            value={visibility}
            onChange={(event) => setVisibility(event.target.value as VisibilityFilter)}
            className="mt-1 w-full rounded-xl border border-line bg-abyss/70 px-2 py-1 text-sm"
          >
            <option value="all">All</option>
            <option value="listed">Listed</option>
            <option value="scan_only">Scan only</option>
            <option value="terminated">Terminated</option>
            <option value="hidden_candidate">Hidden candidates</option>
            <option value="interesting">Interesting only</option>
            <option value="orphans">Orphans</option>
          </select>
        </div>
        <div className="rounded-2xl border border-line bg-abyss/60 p-3">
          <label className="text-[10px] uppercase tracking-[0.18em] text-muted" htmlFor="graph-depth">Initial depth</label>
          <input
            id="graph-depth"
            type="number"
            min={1}
            max={6}
            value={depth}
            onChange={(event) => setDepth(Math.max(1, Math.min(6, Number(event.target.value) || 1)))}
            className="mt-1 w-full rounded-xl border border-line bg-abyss/70 px-2 py-1 text-sm"
          />
        </div>
        <div className="rounded-2xl border border-line bg-abyss/60 p-3">
          <label className="text-[10px] uppercase tracking-[0.18em] text-muted" htmlFor="graph-max">Max nodes</label>
          <input
            id="graph-max"
            type="number"
            min={5}
            max={500}
            value={maxNodes}
            onChange={(event) => setMaxNodes(Math.max(5, Math.min(500, Number(event.target.value) || 60)))}
            className="mt-1 w-full rounded-xl border border-line bg-abyss/70 px-2 py-1 text-sm"
          />
        </div>
      </div>

      <div className="flex flex-wrap items-center gap-2">
        <div className="flex flex-1 items-center gap-2 rounded-xl border border-line bg-abyss/70 px-3 py-1.5 text-sm">
          <Search className="h-3.5 w-3.5 text-muted" />
          <input
            value={search}
            onChange={(event) => setSearch(event.target.value)}
            placeholder="Search PID, name or command line"
            className="flex-1 bg-transparent outline-none"
            data-testid="memory-graph-search"
            aria-label="Search by PID, name or command line"
          />
        </div>
        <button
          type="button"
          onClick={() => setZoom((z) => Math.min(2.5, z + 0.1))}
          aria-label="Zoom in"
          className="rounded-xl border border-line bg-abyss/70 px-2 py-1 text-xs"
        >
          <ZoomIn className="h-3.5 w-3.5" />
        </button>
        <button
          type="button"
          onClick={() => setZoom((z) => Math.max(0.5, z - 0.1))}
          aria-label="Zoom out"
          className="rounded-xl border border-line bg-abyss/70 px-2 py-1 text-xs"
        >
          <ZoomOut className="h-3.5 w-3.5" />
        </button>
        <button
          type="button"
          onClick={resetView}
          className="rounded-xl border border-line bg-abyss/70 px-2 py-1 text-xs"
          data-testid="memory-graph-reset"
        >
          <RotateCcw className="mr-1 inline h-3.5 w-3.5" />
          Reset
        </button>
      </div>

      <div className="grid gap-2 md:grid-cols-3 text-xs">
        <Stat label="Visible (canvas)" value={visibleNodeCount} />
        <Stat label="Truncated branches" value={truncatedCount} />
        <Stat label="Omitted by tree cap" value={tree?.omitted_count ?? 0} />
      </div>

      {treeQuery.isLoading ? (
        <p className="text-sm text-muted" role="status">Loading memory process graph…</p>
      ) : treeQuery.error instanceof Error ? (
        <p className="rounded-2xl border border-rose-400/30 bg-rose-500/10 p-4 text-sm text-rose-100">
          {treeQuery.error.message}
        </p>
      ) : viewMode === "table" ? (
        <ProcessTableView nodes={shape} runId={runId} onFocus={focusNode} />
      ) : !shape.length ? (
        <EmptyState scope={scope} />
      ) : visibleNodeCount === 0 && truncatedCount > 0 ? (
        <TruncationMessage tree={tree} />
      ) : (
        <div
          ref={containerRef}
          onWheel={handleWheel}
          onMouseDown={handleMouseDown}
          onMouseMove={handleMouseMove}
          onMouseUp={handleMouseUp}
          onMouseLeave={handleMouseUp}
          className="relative h-[28rem] overflow-hidden rounded-2xl border border-line bg-abyss/60"
          data-testid="memory-process-canvas"
          aria-label="Memory process graph canvas"
        >
          <div
            className="absolute left-0 top-0 origin-top-left"
            style={{ transform: `translate(${pan.x}px, ${pan.y}px) scale(${zoom})`, width: layout.width, height: layout.height }}
          >
            <svg
              className="absolute inset-0 h-full w-full"
              width={layout.width}
              height={layout.height}
              aria-hidden="true"
            >
              {layout.nodes.map((layoutNode) => {
                const targetChildren = shape
                  .flatMap((n) => n.children)
                  .filter((c) => c.ppid === null ? false : true);
                // We need parent->child edges, but layout doesn't carry that. Build children map.
                return null;
              })}
              {buildEdges(layout, shape).map((edge, idx) => {
                const source = layout.byId.get(edge.source);
                const target = layout.byId.get(edge.target);
                if (!source || !target) return null;
                const isRelated = selectedEntityId && (edge.source === selectedEntityId || edge.target === selectedEntityId);
                const isFaded = selectedEntityId && !isRelated;
                return (
                  <line
                    key={`edge-${idx}-${edge.source}-${edge.target}`}
                    x1={source.x + source.width}
                    y1={source.y + source.height / 2}
                    x2={target.x}
                    y2={target.y + target.height / 2}
                    stroke={isRelated ? "rgba(116, 223, 221, 0.95)" : isFaded ? "rgba(148, 163, 184, 0.15)" : "rgba(148, 163, 184, 0.5)"}
                    strokeWidth={isRelated ? 2.5 : 1.4}
                  />
                );
              })}
            </svg>
            {layout.nodes.map((layoutNode) => {
              const node = lookupNode(shape, layoutNode.id);
              if (!node) return null;
              const tone = visibilityTone(node);
              const isSelected = selectedEntityId === node.process_entity_id;
              const isFocused = focusedEntityId === node.process_entity_id;
              return (
                <button
                  key={`node-${node.process_entity_id}`}
                  type="button"
                  onClick={() => {
                    setSelectedEntityId(node.process_entity_id);
                    setFocusedEntityId(node.process_entity_id);
                  }}
                  onDoubleClick={() => onOpenDetail(node.process_entity_id)}
                  className={`absolute rounded-2xl border p-2 text-left transition shadow-panel ${isSelected ? "border-accent/70 bg-accent/15" : isFocused ? "border-sky-400/60 bg-sky-500/10" : `border-line ${TONE[tone]}`}`}
                  style={{ left: layoutNode.x, top: layoutNode.y, width: layoutNode.width, height: layoutNode.height }}
                  data-testid="memory-graph-node"
                  aria-label={`PID ${node.pid} ${node.name || ""}`}
                >
                  <div className="flex items-start justify-between gap-2">
                    <div className="min-w-0">
                      <div className="flex items-center gap-1.5">
                        <NodeIcon node={node} />
                        <span className="block truncate text-sm font-semibold">{nodeLabel(node)}</span>
                      </div>
                      <p className="mt-1 truncate text-[11px] text-muted" title={node.command_line || ""}>
                        {node.command_line || "—"}
                      </p>
                    </div>
                    <span className={`rounded-md border px-1.5 py-0.5 text-[10px] ${TONE[tone]}`}>
                      {visibilityLabel(node)}
                    </span>
                  </div>
                  <div className="mt-1 flex flex-wrap items-center gap-1 text-[10px] text-muted">
                    <span>PID {node.pid}</span>
                    {node.ppid !== null ? <span>PPID {node.ppid}</span> : null}
                    {node.child_count > 0 ? <span>{node.child_count} children</span> : null}
                    {(node.omitted_children ?? 0) > 0 ? <span className="text-amber-300">+{node.omitted_children} hidden</span> : null}
                    {node.truncated ? <span className="text-amber-300">truncated</span> : null}
                  </div>
                </button>
              );
            })}
          </div>
        </div>
      )}

      <Legend />
      <DetailPanel
        detail={detailQuery.data ?? null}
        onClose={() => setFocusedEntityId(null)}
        onShowAncestors={showAncestors}
        onCopyPid={copyPid}
        onOpenDetail={onOpenDetail}
        ancestorsData={ancestorsQuery.data ?? null}
      />
      <SelectedActions
        selectedNode={selectedEntityId ? lookupNode(shape, selectedEntityId) : null}
        onExpand={expandBranch}
        onCollapse={collapseBranch}
        onCopyPid={copyPid}
        onOpenDetail={onOpenDetail}
        onShowAncestors={showAncestors}
      />
    </section>
  );
}

function buildEdges(layout: ReturnType<typeof buildProcessGraphLayout>, shape: NodeShape[]): GraphEdgeLike[] {
  const byId = new Map<string, NodeShape>();
  const visit = (n: NodeShape) => {
    byId.set(n.process_entity_id, n);
    n.children.forEach(visit);
  };
  shape.forEach(visit);
  const edges: GraphEdgeLike[] = [];
  for (const [id, node] of byId) {
    if (!node.ppid) continue;
    for (const candidate of byId.values()) {
      if (candidate.pid === node.ppid && candidate.process_entity_id !== id) {
        edges.push({ source: candidate.process_entity_id, target: id });
        break;
      }
    }
  }
  return edges;
}

function lookupNode(shape: NodeShape[], id: string): NodeShape | null {
  for (const n of shape) {
    if (n.process_entity_id === id) return n;
    const found = lookupNode(n.children, id);
    if (found) return found;
  }
  return null;
}

function NodeIcon({ node }: { node: NodeShape }) {
  const name = (node.name || "").toLowerCase();
  if (node.visibility.scan_only || node.visibility.hidden_candidate) return <ShieldAlert className="h-3.5 w-3.5 text-rose-300" />;
  if (node.visibility.terminated) return <XCircle className="h-3.5 w-3.5 text-muted" />;
  if (name.includes("svchost")) return <Layers className="h-3.5 w-3.5 text-cyan-200" />;
  if (name.includes("powershell") || name.includes("cmd")) return <Workflow className="h-3.5 w-3.5 text-orange-200" />;
  if (name.includes("system") || node.pid === 4) return <GitBranch className="h-3.5 w-3.5 text-emerald-200" />;
  return <Workflow className="h-3.5 w-3.5 text-muted" />;
}

function Stat({ label, value }: { label: string; value: number }) {
  return (
    <div className="rounded-xl border border-line bg-abyss/60 px-3 py-2">
      <p className="text-[10px] uppercase tracking-[0.18em] text-muted">{label}</p>
      <p className="mt-1 text-base font-semibold text-ink" data-testid={`graph-stat-${label.toLowerCase().replace(/\s+/g, "-")}`}>{value}</p>
    </div>
  );
}

function EmptyState({ scope }: { scope: Scope }) {
  return (
    <div className="rounded-2xl border border-amber-400/30 bg-amber-500/10 p-4 text-sm text-amber-100" role="status">
      {scope === "orphans"
        ? "No orphan processes for the current run. Every process has a known parent in the canonical set."
        : "No memory processes for the current run and filters. Run renormalization or change filters."}
    </div>
  );
}

function TruncationMessage({ tree }: { tree: TreeResponse | undefined }) {
  const total = tree?.total_entities ?? 0;
  const omitted = tree?.omitted_count ?? 0;
  return (
    <div className="rounded-2xl border border-amber-400/30 bg-amber-500/10 p-4 text-sm text-amber-100" role="status">
      <p className="font-semibold">The full process graph contains {total} canonical processes.</p>
      <p className="mt-1 text-xs">
        Showing the initial view (max_nodes / depth cap) with {omitted} hidden. Use search,
        focus a root, or use the filters to navigate.
      </p>
      <ul className="mt-2 list-disc pl-5 text-xs">
        <li>Show System tree</li>
        <li>Show user processes</li>
        <li>Show scan-only</li>
        <li>Show hidden candidates</li>
        <li>Find PID</li>
        <li>Find process name</li>
      </ul>
    </div>
  );
}

function Legend() {
  return (
    <div className="flex flex-wrap items-center gap-2 text-[10px] text-muted" aria-label="Graph legend">
      <span className="rounded-md border border-sky-400/30 bg-sky-500/10 px-2 py-0.5 text-sky-100">Listed</span>
      <span className="rounded-md border border-rose-400/30 bg-rose-500/10 px-2 py-0.5 text-rose-100">Scan only</span>
      <span className="rounded-md border border-rose-400/30 bg-rose-500/10 px-2 py-0.5 text-rose-100">Hidden candidate</span>
      <span className="rounded-md border border-line bg-abyss/70 px-2 py-0.5">Terminated</span>
      <span className="rounded-md border border-amber-400/30 bg-amber-500/10 px-2 py-0.5 text-amber-100">Unknown</span>
      <span className="rounded-md border border-line bg-abyss/70 px-2 py-0.5">Orphan</span>
    </div>
  );
}

function DetailPanel({
  detail,
  onClose,
  onShowAncestors,
  onCopyPid,
  onOpenDetail,
  ancestorsData,
}: {
  detail: MemoryProcessEntityDetail | null;
  onClose: () => void;
  onShowAncestors: () => void;
  onCopyPid: (pid: number) => void;
  onOpenDetail: (entityId: string) => void;
  ancestorsData: TreeResponse | null | undefined;
}) {
  if (!detail) return null;
  const entity = detail.entity;
  return (
    <article className="rounded-2xl border border-line bg-abyss/60 p-4 space-y-3" data-testid="memory-graph-detail">
      <header className="flex flex-wrap items-start justify-between gap-2">
        <div>
          <h4 className="text-base font-semibold">
            {reported(entity.process?.name)} · PID {entity.process?.pid}
          </h4>
          <p className="mt-1 text-xs text-muted">
            Entity {entity.process_entity_id} · Confidence {entity.confidence}
          </p>
        </div>
        <div className="flex flex-wrap gap-2">
          <button type="button" onClick={() => onCopyPid(entity.process?.pid ?? 0)} className="rounded-xl border border-line bg-abyss/70 px-2 py-1 text-xs">
            <Copy className="mr-1 inline h-3.5 w-3.5" /> Copy PID
          </button>
          <button type="button" onClick={onShowAncestors} className="rounded-xl border border-line bg-abyss/70 px-2 py-1 text-xs">
            <Eye className="mr-1 inline h-3.5 w-3.5" /> Show ancestors
          </button>
          <button type="button" onClick={() => onOpenDetail(entity.process_entity_id)} className="rounded-xl border border-accent/40 bg-accent/10 px-2 py-1 text-xs text-accent">
            Open details
          </button>
          <button type="button" onClick={onClose} className="rounded-xl border border-line bg-abyss/70 px-2 py-1 text-xs">
            Close
          </button>
        </div>
      </header>
      <dl className="grid gap-2 md:grid-cols-2 text-xs">
        <Row label="Command line" value={reported(entity.process?.command_line)} />
        <Row label="PPID" value={reported(entity.process?.ppid)} />
        <Row label="Create time" value={reported(entity.process?.create_time)} />
        <Row label="Exit time" value={reported(entity.process?.exit_time)} />
        <Row label="Sources" value={(entity.sources ?? []).map(sourceBadge).join(", ")} />
        <Row label="Visibility" value={entity.visibility?.scan_only ? "Scan only" : entity.visibility?.terminated ? "Terminated" : entity.visibility?.hidden_candidate ? "Hidden candidate" : "Listed"} />
      </dl>
      <section>
        <h5 className="text-[10px] uppercase tracking-[0.18em] text-muted">Observations</h5>
        <table className="mt-1 min-w-full divide-y divide-line text-[11px]">
          <thead className="bg-abyss/70 text-left text-[10px] uppercase tracking-[0.14em] text-muted">
            <tr>
              <th className="px-2 py-1">Plugin</th>
              <th className="px-2 py-1">PID</th>
              <th className="px-2 py-1">PPID</th>
              <th className="px-2 py-1">Command line</th>
            </tr>
          </thead>
          <tbody className="divide-y divide-line">
            {(detail.observations ?? []).map((obs) => (
              <tr key={obs.document_id || `${entity.process_entity_id}-${obs.plugin_name}`}>
                <td className="px-2 py-1 text-ink">{sourceBadge(obs.plugin_name)}</td>
                <td className="px-2 py-1 text-muted">{obs.observed?.pid ?? ""}</td>
                <td className="px-2 py-1 text-muted">{obs.observed?.ppid ?? "—"}</td>
                <td className="px-2 py-1 text-muted">{reported(obs.observed?.command_line)}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </section>
      {ancestorsData && (ancestorsData.nodes ?? []).length > 0 ? (
        <p className="text-xs text-muted" data-testid="ancestors-loaded">
          Ancestors loaded: {ancestorsData.nodes.length} top-level nodes ({ancestorsData.total_entities} entities in scope).
        </p>
      ) : null}
    </article>
  );
}

function Row({ label, value }: { label: string; value: string }) {
  return (
    <div className="rounded-xl border border-line bg-abyss/40 p-2">
      <p className="text-[10px] uppercase tracking-[0.16em] text-muted">{label}</p>
      <p className="mt-1 break-words text-ink">{value}</p>
    </div>
  );
}

function SelectedActions({
  selectedNode,
  onExpand,
  onCollapse,
  onCopyPid,
  onOpenDetail,
  onShowAncestors,
}: {
  selectedNode: NodeShape | null;
  onExpand: (id: string) => void;
  onCollapse: (id: string) => void;
  onCopyPid: (pid: number) => void;
  onOpenDetail: (id: string) => void;
  onShowAncestors: () => void;
}) {
  if (!selectedNode) return null;
  return (
    <div className="flex flex-wrap gap-2 rounded-2xl border border-line bg-abyss/40 p-3 text-xs" data-testid="selected-actions">
      <span className="self-center text-muted">Selected: PID {selectedNode.pid} · {selectedNode.name || "—"}</span>
      <button type="button" onClick={() => onExpand(selectedNode.process_entity_id)} className="rounded-xl border border-line bg-abyss/70 px-2 py-1 text-xs">
        <ChevronDown className="mr-1 inline h-3.5 w-3.5" /> Expand branch
      </button>
      <button type="button" onClick={() => onCollapse(selectedNode.process_entity_id)} className="rounded-xl border border-line bg-abyss/70 px-2 py-1 text-xs">
        <ChevronRight className="mr-1 inline h-3.5 w-3.5" /> Collapse branch
      </button>
      <button type="button" onClick={onShowAncestors} className="rounded-xl border border-line bg-abyss/70 px-2 py-1 text-xs">
        <Eye className="mr-1 inline h-3.5 w-3.5" /> Show ancestors
      </button>
      <button type="button" onClick={() => onCopyPid(selectedNode.pid)} className="rounded-xl border border-line bg-abyss/70 px-2 py-1 text-xs">
        <Copy className="mr-1 inline h-3.5 w-3.5" /> Copy PID
      </button>
      <button type="button" onClick={() => onOpenDetail(selectedNode.process_entity_id)} className="rounded-xl border border-accent/40 bg-accent/10 px-2 py-1 text-xs text-accent">
        Open process details
      </button>
    </div>
  );
}

function ProcessTableView({ nodes, runId, onFocus }: { nodes: NodeShape[]; runId: string | null; onFocus: (id: string) => void }) {
  const flat: NodeShape[] = [];
  const visit = (n: NodeShape, depth: number) => {
    flat.push({ ...n, children: n.children });
    n.children.forEach((c) => visit(c, depth + 1));
  };
  nodes.forEach((n) => visit(n, 0));
  if (!flat.length) {
    return <p className="rounded-2xl border border-line bg-abyss/60 p-4 text-sm text-muted">No processes to show.</p>;
  }
  return (
    <div className="overflow-x-auto rounded-2xl border border-line bg-abyss/40">
      <table className="min-w-full divide-y divide-line text-sm" data-testid="memory-graph-table">
        <thead className="bg-abyss/70 text-left text-xs uppercase tracking-[0.14em] text-muted">
          <tr>
            <th className="px-3 py-2">PID</th>
            <th className="px-3 py-2">Name</th>
            <th className="px-3 py-2">Command line</th>
            <th className="px-3 py-2">Visibility</th>
            <th className="px-3 py-2">Sources</th>
            <th className="px-3 py-2">Findings</th>
            <th className="px-3 py-2">Action</th>
          </tr>
        </thead>
        <tbody className="divide-y divide-line">
          {flat.map((n) => (
            <tr key={n.process_entity_id}>
              <td className="px-3 py-2 text-ink">{reported(n.pid)}</td>
              <td className="px-3 py-2 text-ink">{reported(n.name)}</td>
              <td className="max-w-md truncate px-3 py-2 text-muted" title={n.command_line || ""}>
                {reported(n.command_line)}
              </td>
              <td className="px-3 py-2 text-muted">{visibilityLabel(n)}</td>
              <td className="px-3 py-2 text-muted">{n.sources.map(sourceBadge).join(", ")}</td>
              <td className="px-3 py-2 text-muted">{(n.findings ?? []).join(", ")}</td>
              <td className="px-3 py-2">
                <button type="button" onClick={() => onFocus(n.process_entity_id)} className="rounded-md border border-line bg-abyss/70 px-2 py-1 text-[11px]">
                  Focus
                </button>
              </td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}
