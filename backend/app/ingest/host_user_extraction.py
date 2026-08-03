"""Platform-agnostic dispatcher for deriving Host User Fact observations
from one artifact's already-normalized documents.

Mirrors app.ingest.host_facts_extraction exactly, for the same reason: the
ingest orchestration loop (app.workers.tasks) must never grow a per-
platform branch to decide whether Host User Facts extraction applies to a
batch of documents -- it calls exactly one function here, forever,
regardless of how many platforms end up contributing local-account
observations.

Two ways a document ends up contributing an observation:

1. Inline: a producer whose own parser already emits one document per
   account record (the Windows SAM/ProfileList raw parsers -- see
   app.ingest.windows.sam_identity) sets doc["host_user_fact"] itself, and
   this module only has to collect them.

2. Derived: Linux identity data (passwd/shadow/group/lastlog/sudoers) is
   normalized into general-purpose doc["linux"] documents by parsers whose
   job is broader than Host User Facts (they also feed the raw artifact
   search index) -- a registered extractor inspects the whole batch and
   returns NEW, synthetic observation documents, without mutating the real
   documents that stay headed to the search index unchanged. See
   app.ingest.linux.host_user_facts for the reference implementation.

Adding support for a new platform/source means adding one registration
call in that platform's own ingest package and importing that package once
below -- this file and app.workers.tasks never change again after that.
"""
from __future__ import annotations

from collections.abc import Callable

HostUserFactExtractor = Callable[[list[dict]], list[dict]]

_EXTRACTORS: list[HostUserFactExtractor] = []


def register_host_user_fact_extractor(fn: HostUserFactExtractor) -> HostUserFactExtractor:
    """Decorator: register a function that derives Host User Fact
    observations from a batch of already-normalized documents for one
    artifact.

    ``fn`` receives the full ``documents`` list for one artifact and must
    return a list of NEW dicts, each carrying a ``host_user_fact`` key
    shaped like app.services.host_users.create_host_user_fact_observations
    expects. It must never mutate or return the input documents themselves.
    """
    _EXTRACTORS.append(fn)
    return fn


def extract_host_user_documents(documents: list[dict]) -> list[dict]:
    """Collect every Host User Fact observation for one artifact's
    documents, from both inline (already-tagged) documents and every
    registered derived extractor. Returns [] when nothing in this batch
    produces a Host User Fact -- the caller should treat that as "nothing
    to do", not an error.
    """
    inline = [doc for doc in documents if doc.get("host_user_fact")]
    derived: list[dict] = []
    for extractor in _EXTRACTORS:
        derived.extend(extractor(documents))
    return inline + derived


# Import every platform's Host User Facts extractor module here so its
# @register_host_user_fact_extractor calls run at import time. This is the
# only place that needs to change when a new platform/source gains Host
# User Facts support; app.workers.tasks only ever calls
# extract_host_user_documents() above.
from app.ingest.linux import host_user_facts as _linux_host_user_facts  # noqa: E402,F401
