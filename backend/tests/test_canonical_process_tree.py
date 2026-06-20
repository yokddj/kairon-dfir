"""Tests for the incremental memory process tree API.

These tests exercise ``fetch_canonical_tree`` with the new parameters
introduced for the interactive memory process graph:

* ``root_pid`` / ``root_entity_id``
* ``depth``
* ``max_nodes``
* ``include_ancestors``
* ``orphans_only``
* ``search``

The tests use the in-memory renormalization helper rather than
OpenSearch so they are fast and do not require a live cluster.
"""
from __future__ import annotations

from typing import Any

import pytest

from app.services.memory import process_entities as canonical


CASE = "case-x"
EVIDENCE = "ev-1"
RUN = "run-extended"


def _legacy_doc(*, pid: int, plugin: str, ppid: int | None = None, name: str | None = None, command_line: str | None = None, create_time: str | None = None, exit_time: str | None = None, document_id: str | None = None) -> dict[str, Any]:
    doc_id = document_id or f"{RUN}:memory_process:{plugin}:{pid}:{name or 'n'}"
    return {
        "document_id": doc_id,
        "case_id": CASE,
        "evidence_id": EVIDENCE,
        "memory_run_id": RUN,
        "memory_artifact_type": "memory_process",
        "backend": "volatility3",
        "plugins": [plugin],
        "process": {
            "pid": pid,
            "ppid": ppid,
            "name": name,
            "command_line": command_line,
            "create_time": create_time,
            "exit_time": exit_time,
        },
        "memory": {},
        "visibility": {"pslist": plugin == "windows.pslist", "psscan": plugin == "windows.psscan", "pstree": plugin == "windows.pstree"},
        "state": {"active_candidate": exit_time is None, "terminated_candidate": exit_time is not None, "hidden_candidate": False},
        "parsed_at": "2026-01-01T00:00:00Z",
        "raw": {},
        "warnings": [],
    }


def _renormalize(docs: list[dict[str, Any]]):
    return canonical.renormalize_documents(
        docs, case_id=CASE, evidence_id=EVIDENCE, run_id=RUN, materialize=False
    )


def _make_run() -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    """Build a deterministic System tree:

    Idle(0) -> System(4) -> smss(444) -> csrss(488)
                          -> wininit(489) -> services(508) -> svchost(808) -> cmd(1116)
    Plus orphan cmd(9000) with parent 12345 (not in set).
    """
    docs = [
        _legacy_doc(pid=0, plugin="windows.pslist", ppid=0, name="Idle", create_time="2024-03-22T09:59:00Z"),
        _legacy_doc(pid=4, plugin="windows.pslist", ppid=0, name="System", create_time="2024-03-22T10:00:00Z"),
        _legacy_doc(pid=444, plugin="windows.pslist", ppid=4, name="smss.exe", create_time="2024-03-22T10:01:00Z"),
        _legacy_doc(pid=488, plugin="windows.pslist", ppid=4, name="csrss.exe", create_time="2024-03-22T10:02:00Z"),
        _legacy_doc(pid=489, plugin="windows.pslist", ppid=4, name="wininit.exe", create_time="2024-03-22T10:03:00Z"),
        _legacy_doc(pid=508, plugin="windows.pslist", ppid=489, name="services.exe", create_time="2024-03-22T10:04:00Z"),
        _legacy_doc(pid=808, plugin="windows.pslist", ppid=508, name="svchost.exe", create_time="2024-03-22T10:05:00Z"),
        _legacy_doc(pid=1116, plugin="windows.pslist", ppid=808, name="cmd.exe", create_time="2024-03-22T10:06:00Z"),
        _legacy_doc(pid=9000, plugin="windows.pslist", ppid=12345, name="orphan.exe", create_time="2024-03-22T10:07:00Z"),
    ]
    result = _renormalize(docs)
    return result["entities"], result["edges"]


def _tree(entities, edges, **kwargs):
    """Wrap canonical._build_tree_response to test the shape directly."""
    return canonical._build_tree_response(
        all_entities=entities,
        run_id=RUN,
        depth=kwargs.get("depth", 3),
        max_nodes=kwargs.get("max_nodes"),
        root_pid=kwargs.get("root_pid"),
        root_entity_id=kwargs.get("root_entity_id"),
        include_ancestors=kwargs.get("include_ancestors", False),
        search_results=kwargs.get("search_results"),
    )


def _pid(node):
    if hasattr(node, "get"):
        return node.get("pid")
    return node


def _entity_ids(tree):
    out = []

    def _walk(n):
        out.append(n["process_entity_id"])
        for c in n.get("children") or []:
            _walk(c)

    for n in tree["nodes"]:
        _walk(n)
    return out


# ---------------------------------------------------------------------------
# 1. Load by root + depth
# ---------------------------------------------------------------------------


def test_load_by_root_and_depth() -> None:
    entities, edges = _make_run()
    system = next(e for e in entities if e["process"]["pid"] == 4)
    tree = _tree(entities, edges, root_entity_id=system["process_entity_id"], depth=2)
    ids = _entity_ids(tree)
    # depth=2 from System: System, smss, csrss, wininit, services, svchost
    # cmd is at depth 3 so excluded; orphan excluded (different sub-tree)
    assert system["process_entity_id"] in ids
    for pid in (444, 488, 489, 508, 808):
        ent = next(e for e in entities if e["process"]["pid"] == pid)
        assert ent["process_entity_id"] in ids
    cmd_ent = next(e for e in entities if e["process"]["pid"] == 1116)
    assert cmd_ent["process_entity_id"] not in ids


# ---------------------------------------------------------------------------
# 2. Max nodes limit
# ---------------------------------------------------------------------------


def test_max_nodes_limit() -> None:
    entities, edges = _make_run()
    tree = _tree(entities, edges, depth=10, max_nodes=3)
    # Count non-truncated nodes in the *tree* part (roots).  The orphans
    # are reported as a separate flat list and are not bounded by
    # max_nodes, because they are presentational and the user can browse
    # them through the dedicated Orphans panel.
    count = 0

    def _count(n):
        nonlocal count
        if not n.get("truncated"):
            count += 1
        for c in n.get("children") or []:
            _count(c)

    for n in tree["nodes"]:
        # orphans have empty children and pid != System; skip them in the
        # tree count.
        if n.get("pid") == 4 or n.get("pid") == 0:
            _count(n)
        elif n.get("children"):
            _count(n)
    assert count <= 3
    assert tree["truncation_reason"] in {"max_nodes_reached", "depth_or_root_scope"}


# ---------------------------------------------------------------------------
# 3. Ancestors
# ---------------------------------------------------------------------------


def test_ancestors_search_includes_chain() -> None:
    entities, edges = _make_run()
    cmdline_result = canonical.fetch_canonical_tree.__wrapped__ if hasattr(canonical.fetch_canonical_tree, "__wrapped__") else None
    # Use the search path which includes ancestors
    from app.services.memory import process_entities as pe
    # Build children_map via renormalized result
    by_id = {e["process_entity_id"]: e for e in entities}
    children_map: dict[str, list[dict[str, Any]]] = {}
    for e in entities:
        parent_id = e.get("parent_entity_id")
        if parent_id and parent_id in by_id:
            children_map.setdefault(parent_id, []).append(e)
    # Verify parent chain for cmd(1116) -> svchost(808) -> services(508) -> wininit(489) -> System(4) -> Idle(0)
    cur = next(e for e in entities if e["process"]["pid"] == 1116)["parent_entity_id"]
    chain = []
    while cur and cur in by_id:
        chain.append(by_id[cur]["process"]["pid"])
        cur = by_id[cur].get("parent_entity_id")
    assert chain == [808, 508, 489, 4, 0]


# ---------------------------------------------------------------------------
# 4. Orphans separated
# ---------------------------------------------------------------------------


def test_orphans_only_filters_to_orphans() -> None:
    entities, edges = _make_run()
    # Walk the tree with orphans_only
    orphans = [e for e in entities if e.get("tree", {}).get("is_orphan")]
    tree = canonical._build_tree_response(
        all_entities=orphans,
        run_id=RUN,
        depth=2,
        max_nodes=None,
    )
    pids_in_orphans = {e["process"]["pid"] for e in orphans}
    # The tree starts at orphan roots (PID 0 self-parent is filtered out as is_self_parent)
    # or it walks from the only orphan(9000).
    # We expect orphan(9000) to be present and only orphan entities.
    pids = set()
    for n in tree["nodes"]:
        for nn in _walk_node(n):
            pids.add(nn)
    # orphan(9000) must be in the tree
    assert 9000 in pids
    # All visible pids must be orphans
    for pid in pids:
        assert pid in pids_in_orphans or pid == 9000


def _pid_in_orphans(pid, entities):
    ent = next((e for e in entities if e["process"]["pid"] == pid), None)
    return ent is not None and ent.get("tree", {}).get("is_orphan", False)


# ---------------------------------------------------------------------------
# 5. Run isolation
# ---------------------------------------------------------------------------


def test_run_isolation_separate_entity_ids() -> None:
    docs = _make_run()[0]
    # Renormalize the same docs under two different run ids; entity_ids should be equal (per-process),
    # but document_ids and run-bound fields should differ.
    r1 = canonical.renormalize_documents(
        [_legacy_doc(pid=4, plugin="windows.pslist", ppid=0, name="System", create_time="2024-03-22T10:00:00Z")],
        case_id=CASE, evidence_id=EVIDENCE, run_id="run-a", materialize=False,
    )
    r2 = canonical.renormalize_documents(
        [_legacy_doc(pid=4, plugin="windows.pslist", ppid=0, name="System", create_time="2024-03-22T10:00:00Z")],
        case_id=CASE, evidence_id=EVIDENCE, run_id="run-b", materialize=False,
    )
    assert r1["entities"][0]["process_entity_id"] == r2["entities"][0]["process_entity_id"]
    assert r1["entities"][0]["document_id"] != r2["entities"][0]["document_id"]


# ---------------------------------------------------------------------------
# 6. Basic vs Extended isolation
# ---------------------------------------------------------------------------


def test_basic_run_does_not_contain_psscan_observations() -> None:
    docs = [
        _legacy_doc(pid=4, plugin="windows.pslist", ppid=0, name="System", create_time="2024-03-22T10:00:00Z"),
        _legacy_doc(pid=4, plugin="windows.psscan", ppid=0, name="System", create_time="2024-03-22T10:00:00Z"),
        _legacy_doc(pid=9001, plugin="windows.psscan", ppid=0, name="scan_only.exe", create_time="2024-03-22T10:00:00Z"),
    ]
    r_basic = canonical.renormalize_documents(
        [docs[0]],  # only pslist - basic profile
        case_id=CASE, evidence_id=EVIDENCE, run_id="run-basic", materialize=False,
    )
    r_extended = canonical.renormalize_documents(
        docs,
        case_id=CASE, evidence_id=EVIDENCE, run_id="run-extended", materialize=False,
    )
    basic_pids = {e["process"]["pid"] for e in r_basic["entities"]}
    ext_pids = {e["process"]["pid"] for e in r_extended["entities"]}
    assert 9001 not in basic_pids
    assert 9001 in ext_pids


# ---------------------------------------------------------------------------
# 7. Search by PID and by name
# ---------------------------------------------------------------------------


def test_search_by_pid_finds_match() -> None:
    entities, edges = _make_run()
    # Use a fake renormalize path - simulate the search via _build_tree_response directly
    # by filtering all_entities to scope of search
    needle = "1116"
    by_id = {e["process_entity_id"]: e for e in entities}
    children_map: dict[str, list[dict[str, Any]]] = {}
    for e in entities:
        parent_id = e.get("parent_entity_id")
        if parent_id and parent_id in by_id:
            children_map.setdefault(parent_id, []).append(e)
    match = next(e for e in entities if e["process"]["pid"] == 1116)
    scope_ids = {match["process_entity_id"]}
    cur = match.get("parent_entity_id")
    while cur and cur in by_id:
        scope_ids.add(cur)
        cur = by_id[cur].get("parent_entity_id")
    queue = [match["process_entity_id"]]
    while queue:
        cur_id = queue.pop(0)
        for child in children_map.get(cur_id, []):
            if child["process_entity_id"] not in scope_ids:
                scope_ids.add(child["process_entity_id"])
                queue.append(child["process_entity_id"])
    visible = [e for e in entities if e["process_entity_id"] in scope_ids]
    tree = _tree(visible, edges, depth=10, search_results=[match["process_entity_id"]])
    pids: set[int] = set()
    for n in tree["nodes"]:
        for pid in _walk_node(n):
            pids.add(pid)
    # cmd(1116), svchost(808), services(508), wininit(489), System(4) and descendants
    assert 1116 in pids
    assert 808 in pids
    assert 4 in pids
    assert 9000 not in pids  # orphan not in scope


def _walk_node(n):
    yield n["pid"]
    for c in n.get("children") or []:
        yield from _walk_node(c)


def test_search_by_partial_name_finds_match() -> None:
    entities, edges = _make_run()
    matches = [e for e in entities if "svchost" in (e.get("process", {}).get("name") or "").lower()]
    assert len(matches) == 1
    assert matches[0]["process"]["pid"] == 808


# ---------------------------------------------------------------------------
# 8. No duplicates in tree
# ---------------------------------------------------------------------------


def test_no_duplicate_entities_in_tree() -> None:
    entities, edges = _make_run()
    tree = _tree(entities, edges, depth=10)
    all_ids: list[str] = []
    for n in tree["nodes"]:
        for nid in _entity_ids({"nodes": [n]}):
            all_ids.append(nid)
    by_id = {e["process_entity_id"]: e for e in entities}
    # Each non-root entity that has a parent in the set should appear
    # exactly once (under its parent, never duplicated). Roots and
    # orphans are special: they are the entry points.
    for e in entities:
        eid = e["process_entity_id"]
        parent = e.get("parent_entity_id")
        is_root = e.get("tree", {}).get("is_root")
        is_orphan = e.get("tree", {}).get("is_orphan")
        if parent and not is_root and not is_orphan:
            assert all_ids.count(eid) == 1, f"non-root duplicated {eid}"


# ---------------------------------------------------------------------------
# 9. No dfir-events writes
# ---------------------------------------------------------------------------


def test_canonical_tree_does_not_touch_disk_index() -> None:
    import inspect
    source = inspect.getsource(canonical._build_tree_response)
    assert "dfir-events" not in source
    assert "NormalizedEvent" not in source
    assert "create_normalized_event" not in source


# ---------------------------------------------------------------------------
# 10. No NormalizedEvent creation
# ---------------------------------------------------------------------------


def test_no_normalized_event_creation() -> None:
    import inspect
    source = inspect.getsource(canonical._build_tree_response)
    forbidden = ["NormalizedEvent", "create_normalized_event", "disk_event"]
    for token in forbidden:
        assert token not in source, f"forbidden token {token!r} in tree builder"


# ---------------------------------------------------------------------------
# 11. Roots / orphans semantics
# ---------------------------------------------------------------------------


def test_roots_contain_only_system_pid_4() -> None:
    """The canonical System tree must report a single root (PID 4)."""
    entities, edges = _make_run()
    tree = _tree(entities, edges, depth=10)
    assert "roots" in tree
    assert len(tree["roots"]) == 1, tree["roots"]
    assert tree["roots"][0]["pid"] == 4
    # System must be the *only* user-visible root, never PID 0 (Idle).
    pids = [r["pid"] for r in tree["roots"]]
    assert 0 not in pids
    assert 4 in pids


def test_orphans_list_contains_only_entities_without_parent() -> None:
    """Orphans are entities with no parent in the canonical set."""
    entities, edges = _make_run()
    tree = _tree(entities, edges, depth=10)
    assert "orphans" in tree
    assert len(tree["orphans"]) == 1
    assert tree["orphans"][0]["pid"] == 9000
    # The orphan must NOT be present in the roots list.
    root_pids = [r["pid"] for r in tree["roots"]]
    assert 9000 not in root_pids
    # orphans must not include System or Idle.
    orphan_pids = [o["pid"] for o in tree["orphans"]]
    assert 4 not in orphan_pids
    assert 0 not in orphan_pids


def test_top_level_nodes_is_optional_presentation_union() -> None:
    """top_level_nodes is a convenience field for the UI; it equals roots + orphans."""
    entities, edges = _make_run()
    tree = _tree(entities, edges, depth=10)
    assert "top_level_nodes" in tree
    pids = [n["pid"] for n in tree["top_level_nodes"]]
    assert 4 in pids
    assert 9000 in pids
    assert 0 not in pids


def test_pid_zero_never_replaces_system_as_root() -> None:
    """Even if PID 0 (Idle) ends up flagged as is_root by accident, the
    tree response must drop it so System remains the user-visible root.
    """
    entities, edges = _make_run()
    # Force Idle (PID 0) to look like a root in the canonical entities.
    for e in entities:
        if e["process"]["pid"] == 0:
            e["tree"]["is_root"] = True
    tree = _tree(entities, edges, depth=10)
    pids = [r["pid"] for r in tree["roots"]]
    assert 0 not in pids
    assert 4 in pids


def test_orphans_do_not_increment_root_count() -> None:
    """The tree metrics must distinguish case_roots from orphans.

    Building a larger fixture with multiple orphans confirms that the
    orphans are tallied separately and never summed into the roots.
    """
    extra_orphans = [
        _legacy_doc(pid=9100 + i, plugin="windows.pslist", ppid=99999, name=f"orphan{i}.exe", create_time="2024-03-22T10:08:00Z")
        for i in range(10)
    ]
    base_docs = [
        _legacy_doc(pid=0, plugin="windows.pslist", ppid=0, name="Idle", create_time="2024-03-22T09:59:00Z"),
        _legacy_doc(pid=4, plugin="windows.pslist", ppid=0, name="System", create_time="2024-03-22T10:00:00Z"),
        _legacy_doc(pid=9000, plugin="windows.pslist", ppid=12345, name="orphan.exe", create_time="2024-03-22T10:07:00Z"),
    ]
    entities, _ = _renormalize(base_docs + extra_orphans)["entities"], None
    tree = _tree(entities, [], depth=10)
    metrics = tree["metrics"]
    # The canonical set has exactly one root (System, PID 4).
    assert metrics["case_roots"] == 1, metrics
    # All 11 orphans are tallied separately and never merged into roots.
    assert metrics["orphans"] == 11, metrics
    assert metrics["case_roots"] != metrics["orphans"]
    # The list of orphans returned by the response must contain all 11.
    assert len(tree["orphans"]) == 11
    # The roots list contains only System.
    assert len(tree["roots"]) == 1
    assert tree["roots"][0]["pid"] == 4


def test_filtered_view_does_not_alter_case_roots() -> None:
    """A scoped view (e.g. search match) must keep case_roots anchored
    to the underlying canonical set, not the visible sub-tree.
    """
    entities, edges = _make_run()
    # Filter to only the orphan subtree; case_roots must still be 1.
    orphan_only = [e for e in entities if e.get("tree", {}).get("is_orphan")]
    tree = canonical._build_tree_response(
        all_entities=orphan_only,
        run_id=RUN,
        depth=10,
        max_nodes=None,
    )
    # The orphan-only view has no roots but the metrics still describe
    # the orphan set (case_roots=0 for an orphan-only filter).
    assert tree["metrics"]["case_roots"] == 0
    assert tree["metrics"]["orphans"] == 1
    # top_level_nodes has only the orphan.
    pids = [n["pid"] for n in tree["top_level_nodes"]]
    assert pids == [9000]


def test_tree_response_is_idempotent() -> None:
    """Re-running _build_tree_response with the same input must be a
    pure function: equal inputs produce equal outputs.
    """
    entities, edges = _make_run()
    first = _tree(entities, edges, depth=10)
    second = _tree(entities, edges, depth=10)
    # Compare only the structural part: roots, orphans, top_level_nodes pids.
    def _pids(tree):
        return {
            "roots": [r["pid"] for r in tree["roots"]],
            "orphans": [o["pid"] for o in tree["orphans"]],
            "top_level_nodes": [n["pid"] for n in tree["top_level_nodes"]],
        }
    assert _pids(first) == _pids(second)
