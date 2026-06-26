"""Tests for the experimental OpenSearch indexing helpers.

The tests cover:
* index isolation: the experimental index never accepts a
  document whose trust_level is not ``untrusted`` or whose
  analysis_mode is not ``experimental``;
* the search helper refuses to run without an
  ``experimental_run_id``;
* the delete-by-run helper only deletes documents matching
  the trust + analysis_mode + run-id filters.
"""
from __future__ import annotations

import os
from unittest.mock import MagicMock

import pytest


os.environ.setdefault("DATABASE_URL", "sqlite:///:memory:")
os.environ.setdefault("REDIS_URL", "redis://localhost:6379/0")


@pytest.fixture
def mocked_opensearch():
    """Patch the OpenSearch client so the indexing helpers run
    without a live cluster.
    """
    from app.services.memory import experimental_indexing

    client = MagicMock()
    client.indices.exists.return_value = True
    # The bulk call returns a per-document success.
    client.bulk.return_value = {
        "items": [
            {"index": {"_id": "doc-1"}},
            {"index": {"_id": "doc-2"}},
        ]
    }
    original = experimental_indexing.get_opensearch_client
    experimental_indexing.get_opensearch_client = lambda: client
    yield client
    experimental_indexing.get_opensearch_client = original


class TestTrustFieldEnforcement:
    """Trust fields are mandatory on every document."""

    def test_wrong_trust_level_overridden(self, mocked_opensearch):
        from app.services.memory.experimental_indexing import (
            index_experimental_documents,
        )

        result = index_experimental_documents(
            "case-1",
            [
                {
                    "document_id": "doc-1",
                    "document_type": "memory_process",
                    "trust_level": "validated",  # WRONG
                    "analysis_mode": "experimental",
                }
            ],
            experimental_run_id="run-1",
        )
        assert result["indexed"] >= 1
        assert result["errors"] == 0
        payload = mocked_opensearch.bulk.call_args.kwargs["body"][1]
        assert payload["trust_level"] == "untrusted"

    def test_wrong_analysis_mode_overridden(self, mocked_opensearch):
        from app.services.memory.experimental_indexing import (
            index_experimental_documents,
        )

        result = index_experimental_documents(
            "case-1",
            [
                {
                    "document_id": "doc-1",
                    "document_type": "memory_process",
                    "trust_level": "untrusted",
                    "analysis_mode": "validated",  # WRONG
                }
            ],
            experimental_run_id="run-1",
        )
        assert result["indexed"] >= 1
        assert result["errors"] == 0
        payload = mocked_opensearch.bulk.call_args.kwargs["body"][1]
        assert payload["analysis_mode"] == "experimental"

    def test_missing_document_id_rejected(self, mocked_opensearch):
        from app.services.memory.experimental_indexing import (
            index_experimental_documents,
        )

        result = index_experimental_documents(
            "case-1",
            [
                {
                    "document_type": "memory_process",
                }
            ],
            experimental_run_id="run-1",
        )
        assert result["indexed"] == 0
        assert result["errors"] == 1

    def test_valid_documents_indexed(self, mocked_opensearch):
        from app.services.memory.experimental_indexing import (
            index_experimental_documents,
        )

        result = index_experimental_documents(
            "case-1",
            [
                {
                    "document_id": "doc-1",
                    "document_type": "memory_process",
                },
                {
                    "document_id": "doc-2",
                    "document_type": "memory_process",
                },
            ],
            experimental_run_id="run-1",
        )
        assert result["indexed"] == 2
        assert result["errors"] == 0


class TestSearchRequiresRunId:
    """The search helper refuses to run without an
    ``experimental_run_id``.
    """

    def test_search_rejects_empty_run_id(self, mocked_opensearch):
        from app.services.memory.experimental_indexing import (
            search_experimental_documents,
        )

        result = search_experimental_documents(
            "case-1", experimental_run_id="", evidence_id="e-1",
        )
        assert result["items"] == []
        assert result["error"] == "experimental_run_id_required"

    def test_delete_rejects_empty_run_id(self, mocked_opensearch):
        from app.services.memory.experimental_indexing import (
            delete_experimental_documents_by_run,
        )

        result = delete_experimental_documents_by_run(
            "case-1", experimental_run_id="", evidence_id="e-1",
        )
        assert result["deleted"] == 0
        assert result["error"] == "experimental_run_id_required"

    def test_delete_builds_trust_filter(self, mocked_opensearch):
        from app.services.memory.experimental_indexing import (
            delete_experimental_documents_by_run,
        )

        mocked_opensearch.delete_by_query.return_value = {
            "deleted": 5,
            "version_conflicts": 0,
        }
        result = delete_experimental_documents_by_run(
            "case-1", experimental_run_id="run-1", evidence_id="e-1",
        )
        assert result["deleted"] == 5
        # Verify the call included the trust + analysis-mode
        # filters so a client cannot bypass them.
        call = mocked_opensearch.delete_by_query.call_args
        body = call.kwargs.get("body") or call.args[1]
        filters = body["query"]["bool"]["filter"]
        # Build a flat {field: value} map from the term filters.
        flat = {
            field: value
            for f in filters
            for field, value in f.get("term", {}).items()
        }
        assert flat.get("experimental_run_id") == "run-1"
        assert flat.get("evidence_id") == "e-1"
        assert flat.get("trust_level") == "untrusted"
        assert flat.get("analysis_mode") == "experimental"


class TestIndexIsolation:
    """The experimental index is a dedicated prefix."""

    def test_index_uses_experimental_prefix(self):
        from app.core.config import get_settings
        from app.core.opensearch import get_memory_experimental_index

        prefix = get_settings().opensearch_memory_experimental_index_prefix
        assert prefix == "dfir-memory-experimental"
        assert get_memory_experimental_index("case-1") == (
            f"{prefix}-case-1"
        )
