from __future__ import annotations

import ast
from pathlib import Path

APP_ROOT = Path(__file__).resolve().parents[1] / "app"


def _duplicate_keys(tree: ast.AST) -> list[tuple[int, str]]:
    found: list[tuple[int, str]] = []
    for node in ast.walk(tree):
        if not isinstance(node, ast.Dict):
            continue
        seen: dict[object, int] = {}
        for key in node.keys:
            if not isinstance(key, ast.Constant) or not isinstance(key.value, (str, int)):
                continue
            if key.value in seen:
                found.append((key.lineno, str(key.value)))
            else:
                seen[key.value] = key.lineno
    return found


def test_no_duplicate_keys_in_dict_literals() -> None:
    """A repeated key in a dict literal silently discards the earlier value.

    This is not a style nit here: it is how the OpenSearch events mapping lost
    every PSReadLine field (the later, narrower "powershell" block won, so
    those fields were never indexed and no exists/term query could match them),
    and how BITS transfers ended up with an event.category no filter looks for.
    Both were invisible until an analyst noticed missing evidence.
    """
    offenders: list[str] = []
    for path in sorted(APP_ROOT.rglob("*.py")):
        try:
            tree = ast.parse(path.read_text(encoding="utf-8"))
        except SyntaxError:  # pragma: no cover - syntax is covered elsewhere
            continue
        for lineno, key in _duplicate_keys(tree):
            offenders.append(f"{path.relative_to(APP_ROOT.parent)}:{lineno} duplicate key {key!r}")
    assert not offenders, "Duplicate dict keys silently drop values:\n" + "\n".join(offenders)
