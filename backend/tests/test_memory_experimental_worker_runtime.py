from __future__ import annotations

import os
import sys
from pathlib import Path

os.environ.setdefault("DATABASE_URL", "sqlite:///:memory:")
os.environ.setdefault("REDIS_URL", "redis://localhost:6379/0")

_BACKEND = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
if _BACKEND not in sys.path:
    sys.path.insert(0, _BACKEND)


def test_experimental_worker_module_imports() -> None:
    import app.services.memory.experimental_worker as module

    assert hasattr(module, "run_experimental_canary")
    assert hasattr(module, "run_experimental_profile")


def test_experimental_worker_uses_real_executor_abstraction() -> None:
    source = (Path(__file__).parents[1] / "app" / "services" / "memory" / "experimental_worker.py").read_text()
    assert "run_plugin(" in source
    assert "_read_cached_output" not in source


def test_experimental_worker_listens_on_experimental_queue(monkeypatch) -> None:
    monkeypatch.setenv("MEMORY_SYMBOL_EXPERIMENTAL_MISMATCH_ENABLED", "true")
    monkeypatch.setenv("MEMORY_EXPERIMENTAL_TASK_QUEUE", "memory-experimental")
    from app.workers import experimental_worker

    captured = {}

    class FakeWorker:
        def __init__(self, queues, connection=None):
            captured["queues"] = queues

        def work(self):
            captured["worked"] = True

    monkeypatch.setattr(experimental_worker, "Worker", FakeWorker)
    monkeypatch.setattr(experimental_worker, "Redis", type("FakeRedis", (), {"from_url": staticmethod(lambda url: object())}))
    monkeypatch.setattr(experimental_worker, "is_experimental_enabled", lambda: True)
    monkeypatch.setattr(experimental_worker, "init_db", lambda: None)
    experimental_worker.main()
    assert captured["queues"] == ["memory-experimental"]
    assert captured["worked"] is True
