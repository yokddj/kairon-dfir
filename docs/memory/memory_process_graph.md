# Memory Process Graph & Indented Tree

## Architecture

Memory analysis uses two complementary process exploration views:

* **Visual Graph** — A canvas-based process tree using a force-directed layout.
  Provides a high-level topology overview with search and node focus.
* **Indented Tree** — A collapsible hierarchical list view. Shows parent-child
  relationships with expand/collapse and precise child counts.

Both views share the same canonical process entity identities and
parent-child edges derived from Volatility's `windows.pstree` output.

## Federated process context

Both views consume the same **federated process context**:

```text
processes_basic (pslist, pstree, cmdline)  → topology + identity + commands
processes_extended (psscan, envars, getsids, privileges) → enrichment
```

In Automatic mode, the backend resolves the latest compatible runs for
both profiles and merges them by PID identity. The visual graph and
indented tree use the basic run for parent-child edges (pstree) and
the extended run for visibility enrichment (scan-only classification).

## Node identity

Nodes are identified by `process_entity_id`, a stable canonical process
identifier. PIDs are display-only. The same entity ID is used in:
* Process table
* Visual graph
* Indented tree
* ProcessDetailModal
* Command Line History

## Search behavior

### Exact numeric search (graph)

When the search input is a valid integer:
1. Exact PID match takes highest priority.
2. If exactly one entity matches, it is focused and centered.
3. If multiple incarnations share the PID, the first exact match is selected.
4. PPID, entity ID, process name, and command-line matches are never substituted
   for an exact PID match.
5. If zero exact PID matches exist, "No exact PID match" is shown and no entity
   is auto-focused.

### Text search (graph)

For non-numeric input, matches are performed against process name and command
line. All matches are shown; no single result is silently selected.

### Indented tree search

The indented tree performs client-side substring matching on PID, process name,
and command line. Matching entities are highlighted and, when focused, ancestors
are automatically revealed.

## Tree depth and expansion

### Visual Graph
Default initial depth: 8 levels. The graph renders the process tree within
this depth boundary. Nodes beyond the depth limit or exceeding the max-nodes
cap are listed as "not loaded" in the metrics.

### Indented Tree
Default tree depth: 10 levels, max 500 nodes. The tree can be expanded
per-node to reveal deeper descendants on demand. Each node shows:

* Process name and PID
* Visibility badge (Listed, Scan only, Terminated, Hidden candidate)
* Child count with expand/collapse toggle
* Source plugins

The indented tree does not inherit the visual graph's node cap — it operates
independently with its own max_nodes limit.

## Selection synchronization

All process views share selection state:

* Inspect from process table → selects entity in graph and tree
* Focus from graph → selects entity in table and detail modal
* Focus from Command Line History → passes canonical entity ID to graph
* Open parent/child → navigates by entity ID, preserving Evidence and run context
* Changing Evidence → clears selection in all views

## Coverage semantics

The tree metrics distinguish between:
* **Total entities** — all canonical process entities for the selected run context
* **Entities in pstree** — entities with parent-child relationships from windows.pstree
* **Scan-only entities** — entities observed only in psscan, not in pstree
* **Orphans** — entities whose parent PID does not resolve to a known entity
* **Roots** — entities with PPID 0 or explicit root classification
* **Loaded nodes** — currently rendered in the tree
* **Collapsed nodes** — available but not expanded
* **Omitted nodes** — beyond the depth or node limit
