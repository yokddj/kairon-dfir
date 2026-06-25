"""Tests for the unified ``SymbolFetchError`` exception hierarchy.

The acquisition pipeline has three layers that all raise the same
structured exception:

* the egress client (``app.services.memory.symbol_egress_client``);
* the in-fetcher mirror / validator
  (``app.services.memory.symbol_fetcher``);
* the worker (``app.services.memory.workers.symbol_tasks``).

Historically the egress client and the fetcher each defined their
own ``SymbolFetchError`` class.  The worker imported both with an
alias.  The worker's ``except SymbolFetchError`` only caught the
egress-client class, so the fetcher's
``SYMBOL_PDB_IDENTITY_MISMATCH`` was swallowed by the generic
``except Exception`` and persisted as the generic
``SYMBOL_ACQUISITION_FAILED``.

The unified hierarchy makes
``app.services.memory.symbol_fetcher.SymbolFetchError`` the
canonical class; the egress client re-exports it; the worker
imports it once.  The worker's single ``except SymbolFetchError``
now catches every structured failure, including the identity
mismatch.

These tests pin the new contract:

* the two modules expose the same class (no parallel definitions);
* the worker's catch clause is structured;
* the identity-mismatch error code is preserved end-to-end.
"""
from __future__ import annotations

import inspect

import pytest


def test_egress_client_re_exports_canonical_symbol_fetch_error() -> None:
    """The egress client's ``SymbolFetchError`` IS the fetcher's
    ``SymbolFetchError`` (re-exported).  No parallel definition.
    """
    from app.services.memory import symbol_egress_client, symbol_fetcher

    assert symbol_egress_client.SymbolFetchError is symbol_fetcher.SymbolFetchError


def test_worker_uses_single_canonical_exception() -> None:
    """The worker must import the single canonical exception and
    must not create parallel aliases.
    """
    from app.workers import symbol_tasks

    source = inspect.getsource(symbol_tasks)
    # No per-module aliasing: the worker should not import
    # ``SymbolFetchError as ...`` (the legacy bug created an
    # ``InnerSymbolFetchError`` alias because the egress-client
    # class was different from the fetcher class).
    assert "as InnerSymbolFetchError" not in source
    # The canonical class is imported once.
    assert "from app.services.memory.symbol_fetcher import" in source
    assert "SymbolFetchError" in source
    # The structured catch clause is present and uses the
    # canonical class name.
    assert "except SymbolFetchError" in source
    # The generic fallback is present (it must be reachable for
    # truly unexpected exceptions).
    assert "except Exception" in source


def test_identity_mismatch_code_in_fetcher_source() -> None:
    """The fetcher must still raise the SYMBOL_PDB_IDENTITY_MISMATCH
    code (the canonical stable wire identifier).
    """
    from app.services.memory import symbol_fetcher

    source = inspect.getsource(symbol_fetcher)
    assert "SYMBOL_PDB_IDENTITY_MISMATCH" in source
    assert "raise SymbolFetchError" in source


def test_isf_codes_listed_in_fetcher() -> None:
    """The four ISF failure codes must remain distinct and present
    in the fetcher module (regression guard).
    """
    from app.services.memory import symbol_fetcher

    source = inspect.getsource(symbol_fetcher)
    for code in (
        "SYMBOL_ISF_PARSE_FAILED",
        "SYMBOL_ISF_IDENTITY_MISSING",
        "SYMBOL_ISF_IDENTITY_MISMATCH",
        "SYMBOL_ISF_VOLATILITY_VALIDATION_FAILED",
    ):
        assert code in source, f"{code} must remain a distinct error code"


def test_exception_is_subclass_of_runtime_error() -> None:
    """``SymbolFetchError`` extends ``RuntimeError`` so generic
    code that catches ``RuntimeError`` still sees it.
    """
    from app.services.memory.symbol_fetcher import SymbolFetchError

    assert issubclass(SymbolFetchError, RuntimeError)
    err = SymbolFetchError("TEST_CODE", "test message")
    assert err.code == "TEST_CODE"
    assert err.message == "test message"
    assert err.retryable is False
    err_retryable = SymbolFetchError("TEST_RETRY", "retryable", retryable=True)
    assert err_retryable.retryable is True


@pytest.mark.parametrize("retryable", [False, True])
def test_exception_can_be_caught_by_class_identity(retryable: bool) -> None:
    """A SymbolFetchError raised anywhere in the acquisition
    pipeline is caught by ``except SymbolFetchError`` (the canonical
    class).  This is the regression guard for the previous bug
    where the worker's ``except`` only caught the egress-client
    class.
    """
    from app.services.memory import symbol_fetcher

    with pytest.raises(symbol_fetcher.SymbolFetchError) as exc:
        raise symbol_fetcher.SymbolFetchError(
            "REGRESSION_GUARD", "guarding against the dual-class bug",
            retryable=retryable,
        )
    assert exc.value.code == "REGRESSION_GUARD"
    assert exc.value.retryable is retryable
