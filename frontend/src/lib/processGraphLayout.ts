/* Generic BFS process graph layout.

Used by the Memory Process Graph and reusable for any domain that
models a parent/child process tree.  Mirrors the visual conventions
of the existing ``ProcessTreePanel`` (Execution Stories):

  * columns by depth;
  * rows ordered by PID ascending within a column;
  * explicit width/height of each node card;
  * a "truncated" placeholder is included but laid out at the
    correct depth so edges still terminate cleanly.

The renderer is the same pattern as ProcessTreePanel: an absolutely
positioned container with an SVG for edges and HTML buttons for the
node cards.  This module only computes positions; the React
component owns the rendering.
*/

export type GraphNodeLike = {
  process_entity_id: string;
  pid: number;
  child_count?: number;
  truncated?: boolean;
  omitted_children?: number;
  children?: GraphNodeLike[];
};

export type GraphEdgeLike = {
  id?: string;
  source: string;
  target: string;
};

export type GraphLayoutNode = {
  id: string;
  depth: number;
  x: number;
  y: number;
  width: number;
  height: number;
  truncated?: boolean;
};

export type GraphLayout = {
  width: number;
  height: number;
  nodes: GraphLayoutNode[];
  edges: GraphEdgeLike[];
  byId: Map<string, GraphLayoutNode>;
  maxDepth: number;
};

export const GRAPH_PADDING = 24;
export const GRAPH_CARD_WIDTH = 220;
export const GRAPH_CARD_HEIGHT = 88;
export const GRAPH_COLUMN_GAP = 36;
export const GRAPH_ROW_GAP = 12;

export function buildProcessGraphLayout(
  nodes: GraphNodeLike[],
  edges: GraphEdgeLike[],
  options: { cardWidth?: number; cardHeight?: number; columnGap?: number; rowGap?: number } = {},
): GraphLayout {
  const cardW = options.cardWidth ?? GRAPH_CARD_WIDTH;
  const cardH = options.cardHeight ?? GRAPH_CARD_HEIGHT;
  const colGap = options.columnGap ?? GRAPH_COLUMN_GAP;
  const rowGap = options.rowGap ?? GRAPH_ROW_GAP;

  const childrenByParent = new Map<string, string[]>();
  const incoming = new Map<string, number>();
  for (const node of nodes) incoming.set(node.process_entity_id, 0);
  for (const edge of edges) {
    if (!incoming.has(edge.source) || !incoming.has(edge.target) || edge.source === edge.target) continue;
    incoming.set(edge.target, (incoming.get(edge.target) ?? 0) + 1);
    const list = childrenByParent.get(edge.source) ?? [];
    list.push(edge.target);
    childrenByParent.set(edge.source, list);
  }

  // Build a parent chain from the nodes' own children array.  This
  // is robust to edges that the caller may not have sent.
  for (const node of nodes) {
    for (const child of node.children ?? []) {
      const list = childrenByParent.get(node.process_entity_id) ?? [];
      if (!list.includes(child.process_entity_id)) {
        list.push(child.process_entity_id);
        childrenByParent.set(node.process_entity_id, list);
      }
      if (incoming.has(child.process_entity_id)) {
        incoming.set(child.process_entity_id, (incoming.get(child.process_entity_id) ?? 0) + 1);
      }
    }
  }

  // Use child-bearing order for visual grouping; ties broken by PID.
  const sortedNodes = [...nodes].sort((a, b) => {
    const aChildren = (childrenByParent.get(a.process_entity_id) ?? []).length;
    const bChildren = (childrenByParent.get(b.process_entity_id) ?? []).length;
    if (aChildren !== bChildren) return bChildren - aChildren;
    return a.pid - b.pid;
  });

  const roots = sortedNodes.filter((n) => (incoming.get(n.process_entity_id) ?? 0) === 0);
  // A node whose parent is in roots should not be a separate root
  // (avoids duplicate rendering of a single entity under two parents).
  const rootIds = new Set(roots.map((r) => r.process_entity_id));
  const filteredRoots = roots.filter((r) => {
    const parentEdge = edges.find((e) => e.target === r.process_entity_id);
    if (parentEdge && rootIds.has(parentEdge.source)) return false;
    return true;
  });

  // BFS depth assignment.
  const depthById = new Map<string, number>();
  const queue: string[] = filteredRoots.map((n) => n.process_entity_id);
  filteredRoots.forEach((n) => depthById.set(n.process_entity_id, 0));
  while (queue.length) {
    const cur = queue.shift()!;
    const depth = depthById.get(cur) ?? 0;
    for (const childId of childrenByParent.get(cur) ?? []) {
      const next = depth + 1;
      if ((depthById.get(childId) ?? -1) < next) {
        depthById.set(childId, next);
        queue.push(childId);
      }
    }
  }
  for (const node of sortedNodes) {
    if (!depthById.has(node.process_entity_id)) depthById.set(node.process_entity_id, 0);
  }

  // Bucket by depth and order within column.
  const columns = new Map<number, GraphNodeLike[]>();
  for (const node of sortedNodes) {
    const depth = depthById.get(node.process_entity_id) ?? 0;
    const list = columns.get(depth) ?? [];
    list.push(node);
    columns.set(depth, list);
  }

  const layoutNodes: GraphLayoutNode[] = [];
  let maxDepth = 0;
  let maxRows = 0;
  for (const [depth, columnNodes] of [...columns.entries()].sort((a, b) => a[0] - b[0])) {
    maxDepth = Math.max(maxDepth, depth);
    maxRows = Math.max(maxRows, columnNodes.length);
    columnNodes.forEach((node, index) => {
      layoutNodes.push({
        id: node.process_entity_id,
        depth,
        x: GRAPH_PADDING + depth * (cardW + colGap),
        y: GRAPH_PADDING + index * (cardH + rowGap),
        width: cardW,
        height: cardH,
        truncated: node.truncated,
      });
    });
  }

  const layout: GraphLayout = {
    width: Math.max(420, GRAPH_PADDING * 2 + (maxDepth + 1) * cardW + maxDepth * colGap),
    height: Math.max(280, GRAPH_PADDING * 2 + maxRows * cardH + Math.max(0, maxRows - 1) * rowGap),
    nodes: layoutNodes,
    edges,
    byId: new Map(layoutNodes.map((n) => [n.id, n])),
    maxDepth,
  };
  return layout;
}
