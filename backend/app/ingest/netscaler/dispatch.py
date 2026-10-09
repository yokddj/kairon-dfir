"""NetScaler parser dispatch helpers -- mirrors app.ingest.linux.dispatch's
shape (one registry entry per parser key, routed by module+function) so
another NetScaler file type can be added the same way without a new
dispatch mechanism.
"""
from __future__ import annotations

import importlib
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path
from typing import Any


class NetscalerParserDispatchError(RuntimeError):
    """Raised when a recognized NetScaler artifact cannot be routed."""


class NetscalerParserExecutionError(RuntimeError):
    """Raised when a NetScaler parser fails after dispatch."""


@dataclass(frozen=True)
class NetscalerParserTarget:
    parser: str
    module: str
    function: str
    binary: bool = False


NETSCALER_PARSER_TARGETS: dict[str, NetscalerParserTarget] = {
    "netscaler_config_raw": NetscalerParserTarget("netscaler_config_raw", "config", "parse_ns_conf"),
}


def resolve_netscaler_parser(parser: str | None) -> tuple[NetscalerParserTarget, Callable[..., list[dict[str, Any]]]]:
    parser_key = str(parser or "").strip().lower()
    target = NETSCALER_PARSER_TARGETS.get(parser_key)
    if target is None:
        raise NetscalerParserDispatchError(f"No NetScaler parser dispatch target configured for parser '{parser_key or 'unknown'}'.")
    module = importlib.import_module(f"app.ingest.netscaler.{target.module}")
    parse_func = getattr(module, target.function, None)
    if not callable(parse_func):
        raise NetscalerParserDispatchError(
            f"NetScaler parser target app.ingest.netscaler.{target.module}.{target.function} for '{parser_key}' is not callable."
        )
    return target, parse_func


def parse_netscaler_artifact_file(path: Path, *, parser: str | None, source_path: str) -> list[dict[str, Any]]:
    target, parse_func = resolve_netscaler_parser(parser)
    try:
        if target.binary:
            return parse_func(path.read_bytes(), source_path=source_path)
        return parse_func(path.read_text(encoding="utf-8", errors="replace"), source_path=source_path)
    except NetscalerParserDispatchError:
        raise
    except Exception as exc:  # noqa: BLE001
        raise NetscalerParserExecutionError(f"NetScaler parser '{parser}' failed for '{source_path}': {exc}") from exc
