"""Regression: collections (Velociraptor or other ZIP/TAR) must not read a disk-image-only variable.

Since 2026-10-01 every collection ingest aborted with "cannot access local variable
'disk_image_materialization'": the platform detection read it for all evidence, while only the
disk-image branch assigned it. It must be assigned before the branches split.
"""
from __future__ import annotations

import ast
from pathlib import Path

TASKS = Path(__file__).resolve().parents[1] / "app" / "workers" / "tasks.py"


def _ingest_body() -> list[ast.stmt]:
    tree = ast.parse(TASKS.read_text(encoding="utf-8"))
    function = next(node for node in ast.walk(tree) if isinstance(node, ast.FunctionDef) and node.name == "ingest_evidence")
    # The branches live inside the function's main try block.
    for node in ast.walk(function):
        if isinstance(node, (ast.Try, ast.FunctionDef)):
            for body in (getattr(node, "body", []),):
                if any(isinstance(stmt, ast.If) and "is_selected_velociraptor" in ast.unparse(stmt.test) for stmt in body):
                    return body
    raise AssertionError("ingest_evidence no longer branches on is_selected_velociraptor; update this test")


def test_the_disk_image_result_is_set_before_the_collection_and_disk_image_branches_split():
    body = _ingest_body()
    branch = next(index for index, stmt in enumerate(body) if isinstance(stmt, ast.If) and "is_selected_velociraptor" in ast.unparse(stmt.test))
    assigned_before = any(
        isinstance(stmt, ast.Assign) and any(isinstance(target, ast.Name) and target.id == "disk_image_materialization" for target in stmt.targets)
        for stmt in body[:branch]
    )
    assert assigned_before, "disk_image_materialization must be assigned before the collection / disk-image branches"
