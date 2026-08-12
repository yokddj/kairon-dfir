"""Platform-agnostic dispatcher for deriving Host Facts observations from
one artifact's already-normalized documents.

This exists so the ingest orchestration loop (app.workers.tasks) never has
to grow a per-platform branch to decide whether Host Facts extraction
applies to this batch of documents -- it calls exactly one function here,
forever, regardless of how many platforms end up contributing Host Facts.

Two ways a document ends up contributing a fact:

1. Inline: some normalizers (e.g. app.ingest.linux.os_info /
   app.ingest.linux.timezone, via normalize_linux_row) already parse a
   dedicated, single-purpose source (a whole file) into a document that IS
   the observation -- for those, the normalizer sets doc["host_fact"]
   itself, and this module only has to collect them.

2. Derived: some platforms have no dedicated "who am I" artifact at all --
   the identifying value is a side-channel field repeated across many
   unrelated documents (e.g. every Windows Event Log record carries the
   generating machine's name). For those, a registered extractor inspects
   a whole artifact's document batch and returns a small number of NEW,
   synthetic observation documents -- it never mutates the real documents,
   which stay exactly as parsed and headed to the search index unchanged.

Adding support for a new platform means adding one registration call in
that platform's own ingest package (see app.ingest.windows.host_facts for
the reference implementation) and importing that package once, below --
this file and app.workers.tasks never change again after that.
"""
from __future__ import annotations

from collections.abc import Callable

HostFactExtractor = Callable[[list[dict]], list[dict]]

_EXTRACTORS: list[HostFactExtractor] = []


def register_host_fact_extractor(fn: HostFactExtractor) -> HostFactExtractor:
    """Decorator: register a function that derives Host Fact observations
    from a batch of already-normalized documents for one artifact.

    ``fn`` receives the full ``documents`` list for one artifact and must
    return a list of NEW dicts, each carrying a ``host_fact`` key shaped
    like app.services.host_facts.create_host_fact_observations expects
    (fact_type, artifact_family, artifact_type, source_file, raw_value,
    normalized_value, confidence, parse_status, reason). It must never
    mutate or return the input documents themselves.
    """
    _EXTRACTORS.append(fn)
    return fn


def extract_host_fact_documents(documents: list[dict]) -> list[dict]:
    """Collect every Host Fact observation for one artifact's documents,
    from both inline (already-tagged) documents and every registered
    derived extractor. Returns [] when nothing in this batch produces a
    Host Fact -- the caller should treat that as "nothing to do", not an
    error.
    """
    inline = [doc for doc in documents if doc.get("host_fact")]
    derived: list[dict] = []
    for extractor in _EXTRACTORS:
        derived.extend(extractor(documents))
    return inline + derived


# Import every platform's Host Facts extractor module here so its
# @register_host_fact_extractor calls run at import time. This is the only
# place that needs to change when a new platform gains Host Facts support;
# app.workers.tasks only ever calls extract_host_fact_documents() above.
from app.ingest.windows import host_facts as _windows_host_facts  # noqa: E402,F401
