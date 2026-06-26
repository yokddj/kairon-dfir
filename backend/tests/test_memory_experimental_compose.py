from __future__ import annotations

from pathlib import Path

import pytest


COMPOSE_PATH = Path(__file__).parents[2] / "docker-compose.yml"


def _service_block(compose: str, name: str) -> str:
    lines = compose.splitlines()
    inside = False
    collected: list[str] = []
    for line in lines:
        if line.startswith(f"  {name}:"):
            inside = True
            continue
        if inside and line.startswith("  ") and not line.startswith("    ") and line.rstrip().endswith(":"):
            break
        if inside:
            collected.append(line)
    return "\n".join(collected)


def test_compose_has_experimental_worker_service() -> None:
    if not COMPOSE_PATH.exists():
        pytest.skip("Compose source is not copied into the backend test image.")
    compose = COMPOSE_PATH.read_text()
    service = _service_block(compose, "experimental-worker")
    assert "profiles:" in service
    assert "- experimental" in service
    assert "python\", \"-m\", \"app.workers.experimental_worker\"" in service
    assert "MEMORY_EXPERIMENTAL_TASK_QUEUE: memory-experimental" in service
    assert "./data/experimental-symbol-cache:/app/data/experimental-symbol-cache:ro" in service
    assert 'user: "10001:10001"' in service
    assert "healthcheck:" in service


def test_normal_memory_worker_does_not_consume_experimental_queue() -> None:
    if not COMPOSE_PATH.exists():
        pytest.skip("Compose source is not copied into the backend test image.")
    compose = COMPOSE_PATH.read_text()
    service = _service_block(compose, "memory-worker")
    assert "memory-experimental" not in service
