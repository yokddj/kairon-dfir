"""Coverage for the shared distributed upload lock (app.services.upload_locks),
extracted from the memory upload pipeline so both the memory and evidence
upload session backends serialize concurrent requests against the same
session/chunk/finalize key.
"""
from __future__ import annotations

import pytest

from app.services import upload_locks


class _FakeRedis:
    def __init__(self):
        self.store: dict[str, str] = {}

    def set(self, key, value, nx=False, ex=None):
        if nx and key in self.store:
            return None
        self.store[key] = value
        return True

    def eval(self, script, numkeys, key, token):
        if self.store.get(key) == token:
            del self.store[key]
            return 1
        return 0


def test_redis_upload_lock_acquires_and_releases(monkeypatch):
    fake = _FakeRedis()
    monkeypatch.setattr(upload_locks.redis.Redis, "from_url", classmethod(lambda cls, url: fake))

    with upload_locks.redis_upload_lock("kairon:test:key"):
        assert "kairon:test:key" in fake.store

    assert "kairon:test:key" not in fake.store


def test_redis_upload_lock_rejects_concurrent_holder(monkeypatch):
    fake = _FakeRedis()
    monkeypatch.setattr(upload_locks.redis.Redis, "from_url", classmethod(lambda cls, url: fake))

    with upload_locks.redis_upload_lock("kairon:test:key"):
        with pytest.raises(upload_locks.UploadLockBusyError):
            with upload_locks.redis_upload_lock("kairon:test:key"):
                pass  # pragma: no cover - must not be entered

    # Released by the outer lock's __exit__, so a later caller can acquire it.
    with upload_locks.redis_upload_lock("kairon:test:key"):
        assert "kairon:test:key" in fake.store


def test_redis_upload_lock_only_releases_if_still_owned(monkeypatch):
    fake = _FakeRedis()
    monkeypatch.setattr(upload_locks.redis.Redis, "from_url", classmethod(lambda cls, url: fake))

    with upload_locks.redis_upload_lock("kairon:test:key", ttl=1):
        # Simulate the lock expiring and a different holder acquiring it
        # before this holder's context exits.
        fake.store["kairon:test:key"] = "someone-else-token"

    # The expired holder's release must not delete the new owner's lock.
    assert fake.store.get("kairon:test:key") == "someone-else-token"
