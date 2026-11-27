"""Unified Logs rows are folded and ordered on disk: the same result as the in-memory rule, with
memory that does not grow with the number of rows. Synthetic rows only."""

from __future__ import annotations

import gc
import random
import tracemalloc
from pathlib import Path

from app.ingest.macos.logs import collapse_repeats
from app.ingest.macos.row_store import collapse_to_disk
from app.ingest.normalizer import NormalizedRows


def _rows(count: int, seed: int = 7) -> list[dict]:
    generator = random.Random(seed)
    rows = []
    for index in range(count):
        hour = generator.randint(0, 5)
        minute = generator.randint(0, 59)
        stamp = "" if generator.random() < 0.02 else f"2026-01-02T0{hour}:{minute:02d}:{generator.randint(0, 59):02d}Z"
        message = generator.choice(["session opened for pid {n}", "login by user", "mount disk{n}", "policy check 0x{h}"]).format(n=generator.randint(1, 50), h=format(generator.randint(1, 4000), "x"))
        rows.append({"timestamp": stamp, "message": message, "index": index})
    return rows


def test_same_result_as_folding_in_memory(tmp_path: Path) -> None:
    rows = _rows(3000)
    expected = collapse_repeats(sorted((dict(row) for row in rows), key=lambda row: str(row.get("timestamp") or "")))
    stored = collapse_to_disk((dict(row) for row in rows), temp_dir=tmp_path)
    assert len(stored) == len(expected)
    assert list(stored) == expected
    assert stored[5] == expected[5] and stored[-1] == expected[-1] and stored[10:20] == expected[10:20]


def test_memory_does_not_grow_with_the_rows(tmp_path: Path) -> None:
    def letters(number: int) -> str:
        # Numbers are masked when folding; letters keep every message distinct.
        word = ""
        while True:
            number, rest = divmod(number, 26)
            word += chr(97 + rest)
            if not number:
                return word

    def generate(count: int):
        for index in range(count):
            yield {"timestamp": f"2026-01-02T{index % 24:02d}:00:{index % 60:02d}Z", "message": f"distinct message {letters(index)} " + "x" * 200, "n": index}

    tracemalloc.start()
    stored = collapse_to_disk(generate(200_000), temp_dir=tmp_path)
    _current, peak = tracemalloc.get_traced_memory()
    tracemalloc.stop()
    assert len(stored) == 200_000
    # Held in a list these rows take hundreds of megabytes; on disk the peak stays small.
    assert peak < 40 * 1024 * 1024


def test_documents_are_normalized_a_batch_at_a_time_and_the_file_goes_away(tmp_path: Path) -> None:
    stored = collapse_to_disk(iter(_rows(50)), temp_dir=tmp_path)
    calls = []
    documents = NormalizedRows(stored, lambda row: calls.append(1) or {"event": row["message"]})
    assert len(documents) == len(stored) and calls == []
    batch = documents[0:10]
    assert len(batch) == 10 and len(calls) == 10
    assert sum(1 for _ in documents) == len(stored)
    assert list(tmp_path.glob("collapsed-rows-*.sqlite"))
    del documents, stored, batch
    gc.collect()
    assert not list(tmp_path.glob("collapsed-rows-*.sqlite"))
