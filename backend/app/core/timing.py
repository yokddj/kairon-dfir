"""Lightweight phase-timing instrumentation.

Diagnostic-only: logs when a named phase starts/ends and how long it
took. Never changes control flow, return values, timeouts, or behavior
of the code it wraps -- purely observational, so it is safe to leave in
production code paths that are hard to reproduce outside a real
deployment (e.g. finalize of a large evidence upload).
"""
from __future__ import annotations

import logging
import time
from contextlib import contextmanager
from typing import Iterator

logger = logging.getLogger("kairon.timing")


def _format_context(context: dict) -> str:
    return " ".join(f"{key}={value}" for key, value in context.items())


@contextmanager
def timed_phase(name: str, **context) -> Iterator[None]:
    start = time.perf_counter()
    start_wall = time.time()
    extra = _format_context(context)
    logger.info("phase_start phase=%s start_ts=%.3f%s", name, start_wall, f" {extra}" if extra else "")
    try:
        yield
    finally:
        elapsed = time.perf_counter() - start
        finish_wall = time.time()
        logger.info(
            "phase_end phase=%s finish_ts=%.3f elapsed_seconds=%.3f%s",
            name, finish_wall, elapsed, f" {extra}" if extra else "",
        )
