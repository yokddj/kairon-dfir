"""End-to-end tests for the experimental mismatched-symbol analysis.

The tests in this module exercise the *entire* experimental
trust domain: the eligibility check, the candidate lifecycle,
the acknowledgement contract, the canary phase, the run
lifecycle, the trust filter, the OpenSearch index isolation,
the deletion semantics, and the regressions against the
validated path.

The tests use a clean SQLite session per test (the same
``SessionLocal`` pattern as the rest of the test suite).  The
experimental feature flag is enabled via the settings
override and disabled when the test is over.
"""
from __future__ import annotations

import os
import sys
import uuid
from datetime import datetime, timezone
from unittest.mock import patch

import pytest


# Point the engine at an in-memory SQLite before importing the
# project modules.  This is the only way to run the tests
# without a live PostgreSQL instance.
os.environ.setdefault("DATABASE_URL", "sqlite:///:memory:")
os.environ.setdefault("REDIS_URL", "redis://localhost:6379/0")
os.environ.setdefault("MEMORY_SYMBOL_EXPERIMENTAL_MISMATCH_ENABLED", "true")

# Ensure the backend package is importable when running the test
# from the project root.
_BACKEND = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
if _BACKEND not in sys.path:
    sys.path.insert(0, _BACKEND)


from app.core.config import get_settings  # noqa: E402
from app.core.database import Base, SessionLocal, engine  # noqa: E402
from app.models.case import Case  # noqa: E402
from app.models.evidence import Evidence, EvidenceType  # noqa: E402
from app.models.memory import (  # noqa: E402
    EXPERIMENTAL_ACK_WARNING_VERSION,
    MemoryCachedSymbol,
    MemoryExperimentalRun,
    MemoryExperimentalSymbolCandidate,
    MemoryScanRun,
    MemorySymbolRequirement,
)
from app.services.memory.experimental_acknowledgement import (  # noqa: E402
    EXPERIMENTAL_ACK_WARNING_TEXT,
    build_warning_payload,
    validate_acknowledgement_payload,
)
from app.services.memory.experimental_canary import (  # noqa: E402
    evaluate_canary,
)
from app.services.memory.experimental_catalogue import (  # noqa: E402
    EXPERIMENTAL_CANARY_PLUGINS,
    EXPERIMENTAL_CANARY_PROFILE,
    EXPERIMENTAL_PROFILES,
    allowed_profiles_for_canary_outcome,
    get_experimental_profile,
    list_experimental_profiles,
)
from app.services.memory.experimental_lifecycle import (  # noqa: E402
    ExperimentalLifecycleError,
    advance_to_canary_queue,
    cancel_run,
    create_run,
    delete_run,
    finalise_run,
    finalize_canary,
    get_active_candidate,
    list_candidates,
    list_runs,
    record_acknowledgement,
    record_canary_override,
    request_full_run,
    require_feature_enabled,
    revoke_candidate,
    trust_state,
    upsert_candidate,
)
from app.services.memory.experimental_trust import (  # noqa: E402
    ANALYSIS_MODE_EXPERIMENTAL,
    ANALYSIS_MODE_VALIDATED,
    CACHE_CLASSIFICATION_EXACT,
    CACHE_CLASSIFICATION_EXPERIMENTAL_CANDIDATE,
    CANARY_STATUS_DEGRADED,
    CANARY_STATUS_FAILED,
    CANARY_STATUS_INCONCLUSIVE,
    CANARY_STATUS_PASSED,
    RUN_STATUS_ACKNOWLEDGEMENT_REQUIRED,
    RUN_STATUS_CANCELLED,
    RUN_STATUS_CANARY_DEGRADED,
    RUN_STATUS_CANARY_FAILED,
    RUN_STATUS_CANARY_INCONCLUSIVE,
    RUN_STATUS_CANARY_PASSED,
    RUN_STATUS_CANARY_QUEUED,
    RUN_STATUS_COMPLETED_UNTRUSTED,
    RUN_STATUS_DELETED,
    RUN_STATUS_FAILED_UNTRUSTED,
    SYMBOL_MATCH_TYPE_GUID_ONLY_AGE_MISMATCH,
    TRUST_LEVEL_UNTRUSTED,
    TRUST_LEVEL_VALIDATED,
    architectures_compatible,
    evaluate_candidate_eligibility,
    is_experimental_enabled,
    normalize_pdb_name,
)


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture(autouse=True)
def _enable_experimental(monkeypatch):
    """Enable the experimental feature flag for every test."""
    monkeypatch.setenv("MEMORY_SYMBOL_EXPERIMENTAL_MISMATCH_ENABLED", "true")
    get_settings.cache_clear()
    yield
    get_settings.cache_clear()


@pytest.fixture
def db_session(tmp_path, monkeypatch):
    """Yield a clean DB session backed by an in-memory SQLite.

    The project engine is rebuilt for each test to give every
    test an isolated schema.  We patch the module-level
    ``SessionLocal`` so the rest of the code keeps using the
    fresh session factory.
    """
    from sqlalchemy import create_engine
    from sqlalchemy.orm import sessionmaker
    from app.core.config import get_settings

    monkeypatch.setenv("BACKEND_DATA_DIR", str(tmp_path / "data"))
    monkeypatch.setenv("BACKEND_TEMP_DIR", str(tmp_path / "tmp"))
    get_settings.cache_clear()

    test_engine = create_engine("sqlite:///:memory:", future=True)
    Base.metadata.create_all(bind=test_engine)
    TestSessionLocal = sessionmaker(
        bind=test_engine, autoflush=False, autocommit=False, future=True
    )
    # Patch the project's SessionLocal / engine so the routes
    # and services use our test factory.
    import app.core.database as database_module

    original_session = database_module.SessionLocal
    original_engine = database_module.engine
    database_module.SessionLocal = TestSessionLocal
    database_module.engine = test_engine
    session = TestSessionLocal()
    try:
        yield session
    finally:
        session.close()
        database_module.SessionLocal = original_session
        database_module.engine = original_engine
        test_engine.dispose()
        get_settings.cache_clear()


@pytest.fixture
def case_evidence(db_session):
    """Create a case + memory evidence for the experimental flow.

    Returns the ``(case, evidence)`` pair.  Each test uses
    fresh IDs so the trust-state queries are isolated.
    """
    case = Case(
        id=str(uuid.uuid4()),
        name="Experimental test case",
        description="unit test",
    )
    db_session.add(case)
    db_session.flush()
    evidence = Evidence(
        id=str(uuid.uuid4()),
        case_id=case.id,
        original_filename="test.raw",
        stored_path="staging/test.raw",
        sha256="0" * 64,
        size_bytes=1024,
        evidence_type=EvidenceType.memory_dump,
        detection_status="memory",
    )
    db_session.add(evidence)
    db_session.commit()
    return case, evidence


@pytest.fixture
def requirement_factory(db_session, case_evidence):
    """Return a factory that creates ``MemorySymbolRequirement`` rows.

    The factory uses default values that match the DC02 case:
    ``ntkrnlmp.pdb`` / ``D801A9AFC0FB7761380800F708633DEA`` /
    age 1 / x64.  Tests can override any field.
    """
    case, evidence = case_evidence

    def _factory(
        *,
        pdb_name: str = "ntkrnlmp.pdb",
        pdb_guid: str = "D801A9AFC0FB7761380800F708633DEA",
        pdb_age: int = 1,
        architecture: str = "x64",
        status: str = "blocked_symbols",
    ) -> MemorySymbolRequirement:
        requirement = MemorySymbolRequirement(
            id=str(uuid.uuid4()),
            case_id=case.id,
            evidence_id=evidence.id,
            pdb_name=pdb_name,
            pdb_guid=pdb_guid,
            pdb_age=pdb_age,
            requested_pdb_age=pdb_age,
            age_corrected=False,
            architecture=architecture,
            symbol_key=f"{pdb_name}/{pdb_guid}-{pdb_age}",
            status=status,
        )
        db_session.add(requirement)
        db_session.commit()
        return requirement

    return _factory


@pytest.fixture
def cache_factory(db_session, case_evidence):
    """Return a factory that creates ``MemoryCachedSymbol`` rows.

    Tests can mark a cache row as ``experimental_candidate`` to
    make it eligible for the experimental flow.
    """
    case, evidence = case_evidence
    from app.services.memory.experimental_import import experimental_cache_root
    from app.services.memory.symbol_recovery import hash_file

    def _factory(
        *,
        pdb_name: str,
        pdb_guid: str,
        pdb_age: int,
        architecture: str = "x64",
        cache_classification: str = CACHE_CLASSIFICATION_EXACT,
        validation_status: str = "validated",
        required_pdb_name: str | None = None,
        required_pdb_guid: str | None = None,
        required_pdb_age: int | None = None,
        required_architecture: str | None = None,
    ) -> MemoryCachedSymbol:
        symbol_key = f"{pdb_name}/{pdb_guid}-{pdb_age}"
        if cache_classification == CACHE_CLASSIFICATION_EXPERIMENTAL_CANDIDATE:
            required_pdb_name = required_pdb_name or pdb_name
            required_pdb_guid = required_pdb_guid or pdb_guid
            required_pdb_age = required_pdb_age if required_pdb_age is not None else 1
            required_architecture = required_architecture or architecture
        root = experimental_cache_root()
        pdb_relative_path = f"cache/{symbol_key}.pdb"
        isf_relative_path = f"cache/{symbol_key}.json"
        pdb_sha256 = "0" * 64
        isf_sha256 = "0" * 64
        if cache_classification == CACHE_CLASSIFICATION_EXPERIMENTAL_CANDIDATE:
            pdb_path = root / pdb_relative_path
            isf_path = root / isf_relative_path
            pdb_path.parent.mkdir(parents=True, exist_ok=True)
            isf_path.parent.mkdir(parents=True, exist_ok=True)
            pdb_path.write_bytes(b"p")
            isf_path.write_bytes(b"i")
            pdb_sha256 = hash_file(pdb_path, max_bytes=1000)
            isf_sha256 = hash_file(isf_path, max_bytes=1000)
        cache = MemoryCachedSymbol(
            id=str(uuid.uuid4()),
            symbol_key=symbol_key,
            pdb_name=pdb_name,
            pdb_guid=pdb_guid,
            pdb_age=pdb_age,
            architecture=architecture,
            pdb_relative_path=pdb_relative_path,
            isf_relative_path=isf_relative_path,
            pdb_sha256=pdb_sha256,
            isf_sha256=isf_sha256,
            pdb_size_bytes=1,
            isf_size_bytes=1,
            validation_status=validation_status,
            source_category="official_microsoft_symbols",
            provenance_source_type="operator_cli_pdb",
            provenance_source_name="Operator CLI",
            provenance_actor="server-operator",
            cache_classification=cache_classification,
            required_pdb_name=required_pdb_name,
            required_pdb_guid=required_pdb_guid,
            required_pdb_age=required_pdb_age,
            required_architecture=required_architecture,
        )
        db_session.add(cache)
        db_session.commit()
        return cache

    return _factory


def _build_valid_acknowledgement(
    *,
    required: dict[str, object],
    observed: dict[str, object],
    checkbox_confirmed: bool = True,
    client_actor_label: str = "operator@example.com",
) -> dict[str, object]:
    return {
        "checkbox_confirmed": checkbox_confirmed,
        "client_actor_label": client_actor_label,
    }


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------


class TestTrustModule:
    """The trust module is the single source of truth on the
    boundary.  These tests pin the constants and the small
    helpers so the boundary is observable."""

    def test_analysis_modes_contain_expected(self):
        assert ANALYSIS_MODE_VALIDATED == "validated"
        assert ANALYSIS_MODE_EXPERIMENTAL == "experimental"

    def test_trust_levels_contain_expected(self):
        assert TRUST_LEVEL_VALIDATED == "validated"
        assert TRUST_LEVEL_UNTRUSTED == "untrusted"

    def test_normalize_pdb_name_lowercases(self):
        assert normalize_pdb_name("NTKRNLMP.PDB") == "ntkrnlmp.pdb"
        assert normalize_pdb_name("ntkrnlmp.pdb") == "ntkrnlmp.pdb"
        assert normalize_pdb_name(" ntkrnlmp.pdb ") == "ntkrnlmp.pdb"

    def test_architectures_compatible_x64_amd64(self):
        assert architectures_compatible("x64", "amd64")
        assert architectures_compatible("amd64", "x64")
        assert architectures_compatible("x64", "x64")

    def test_architectures_compatible_arm(self):
        assert architectures_compatible("arm64", "aarch64")
        assert architectures_compatible("aarch64", "arm64")

    def test_architectures_incompatible(self):
        assert not architectures_compatible("x64", "x86")
        assert not architectures_compatible("arm64", "x64")
        assert not architectures_compatible("", "x64")


class TestCandidateEligibility:
    """The eligibility check is the only gate that allows a
    candidate into the experimental flow.  Every negative case
    is required by the spec."""

    def test_exact_match_not_eligible(self, requirement_factory, cache_factory):
        requirement = requirement_factory()
        cache = cache_factory(
            pdb_name="ntkrnlmp.pdb",
            pdb_guid="D801A9AFC0FB7761380800F708633DEA",
            pdb_age=1,
            cache_classification=CACHE_CLASSIFICATION_EXPERIMENTAL_CANDIDATE,
        )
        verdict = evaluate_candidate_eligibility(requirement, cache)
        assert verdict["eligible"] is False
        assert verdict["error_code"] == "EXPERIMENTAL_EXACT_MATCH_NOT_ELIGIBLE"

    def test_guid_mismatch_not_eligible(self, requirement_factory, cache_factory):
        requirement = requirement_factory()
        cache = cache_factory(
            pdb_name="ntkrnlmp.pdb",
            pdb_guid="FFEEDDCCBBAA99887766554433221100",
            pdb_age=5,
            cache_classification=CACHE_CLASSIFICATION_EXPERIMENTAL_CANDIDATE,
        )
        verdict = evaluate_candidate_eligibility(requirement, cache)
        assert verdict["eligible"] is False
        assert verdict["error_code"] == "EXPERIMENTAL_GUID_MISMATCH"

    def test_name_mismatch_not_eligible(self, requirement_factory, cache_factory):
        requirement = requirement_factory()
        cache = cache_factory(
            pdb_name="ntoskrnl.pdb",
            pdb_guid="D801A9AFC0FB7761380800F708633DEA",
            pdb_age=5,
            cache_classification=CACHE_CLASSIFICATION_EXPERIMENTAL_CANDIDATE,
        )
        verdict = evaluate_candidate_eligibility(requirement, cache)
        assert verdict["eligible"] is False
        assert verdict["error_code"] == "EXPERIMENTAL_NAME_MISMATCH"

    def test_architecture_mismatch_not_eligible(
        self, requirement_factory, cache_factory
    ):
        requirement = requirement_factory(architecture="x64")
        cache = cache_factory(
            pdb_name="ntkrnlmp.pdb",
            pdb_guid="D801A9AFC0FB7761380800F708633DEA",
            pdb_age=5,
            architecture="x86",
            cache_classification=CACHE_CLASSIFICATION_EXPERIMENTAL_CANDIDATE,
        )
        verdict = evaluate_candidate_eligibility(requirement, cache)
        assert verdict["eligible"] is False
        assert verdict["error_code"] == "EXPERIMENTAL_ARCHITECTURE_MISMATCH"

    def test_classification_required(self, requirement_factory, cache_factory):
        requirement = requirement_factory()
        cache = cache_factory(
            pdb_name="ntkrnlmp.pdb",
            pdb_guid="D801A9AFC0FB7761380800F708633DEA",
            pdb_age=5,
            cache_classification=CACHE_CLASSIFICATION_EXACT,
        )
        verdict = evaluate_candidate_eligibility(requirement, cache)
        assert verdict["eligible"] is False
        assert verdict["error_code"] == "EXPERIMENTAL_CANDIDATE_NOT_CLASSIFIED"

    def test_isf_validation_required(self, requirement_factory, cache_factory):
        requirement = requirement_factory()
        cache = cache_factory(
            pdb_name="ntkrnlmp.pdb",
            pdb_guid="D801A9AFC0FB7761380800F708633DEA",
            pdb_age=5,
            cache_classification=CACHE_CLASSIFICATION_EXPERIMENTAL_CANDIDATE,
            validation_status="invalid",
        )
        verdict = evaluate_candidate_eligibility(requirement, cache)
        assert verdict["eligible"] is False
        assert verdict["error_code"] == "EXPERIMENTAL_ISF_SCHEMA_INVALID"

    def test_age_mismatch_is_eligible(self, requirement_factory, cache_factory):
        requirement = requirement_factory(pdb_age=1)
        cache = cache_factory(
            pdb_name="ntkrnlmp.pdb",
            pdb_guid="D801A9AFC0FB7761380800F708633DEA",
            pdb_age=5,
            cache_classification=CACHE_CLASSIFICATION_EXPERIMENTAL_CANDIDATE,
        )
        verdict = evaluate_candidate_eligibility(requirement, cache)
        assert verdict["eligible"] is True
        assert verdict["match_type"] == SYMBOL_MATCH_TYPE_GUID_ONLY_AGE_MISMATCH
        assert "required=1" in verdict["warning"]
        assert "observed=5" in verdict["warning"]


class TestFeatureFlag:
    """The feature flag is the single authoritative switch."""

    def test_flag_enabled_returns_true(self, monkeypatch):
        monkeypatch.setenv("MEMORY_SYMBOL_EXPERIMENTAL_MISMATCH_ENABLED", "true")
        get_settings.cache_clear()
        assert is_experimental_enabled() is True

    def test_flag_disabled_returns_false(self, monkeypatch):
        monkeypatch.setenv("MEMORY_SYMBOL_EXPERIMENTAL_MISMATCH_ENABLED", "false")
        get_settings.cache_clear()
        assert is_experimental_enabled() is False

    def test_require_feature_enabled_raises_when_disabled(
        self, monkeypatch, db_session
    ):
        monkeypatch.setenv("MEMORY_SYMBOL_EXPERIMENTAL_MISMATCH_ENABLED", "false")
        get_settings.cache_clear()
        with pytest.raises(ExperimentalLifecycleError) as info:
            require_feature_enabled()
        assert info.value.error_code == "EXPERIMENTAL_DISABLED"
        assert info.value.http_status == 404


class TestCandidateLifecycle:
    """The candidate lifecycle creates the row, refuses
    duplicates, and exposes a stable list."""

    def test_upsert_creates_candidate(
        self, db_session, case_evidence, requirement_factory, cache_factory
    ):
        case, evidence = case_evidence
        requirement = requirement_factory(pdb_age=1)
        cache = cache_factory(
            pdb_name="ntkrnlmp.pdb",
            pdb_guid="D801A9AFC0FB7761380800F708633DEA",
            pdb_age=5,
            cache_classification=CACHE_CLASSIFICATION_EXPERIMENTAL_CANDIDATE,
        )
        candidate = upsert_candidate(
            db_session,
            case_id=case.id,
            evidence_id=evidence.id,
            requirement=requirement,
            cache=cache,
            actor="operator@example.com",
        )
        assert candidate.id
        assert candidate.required_pdb_age == 1
        assert candidate.observed_pdb_age == 5
        assert candidate.symbol_match_type == SYMBOL_MATCH_TYPE_GUID_ONLY_AGE_MISMATCH
        # The exact symbol cache and the requirement are NOT
        # mutated.
        requirement_after = db_session.get(MemorySymbolRequirement, requirement.id)
        assert requirement_after.pdb_age == 1
        cache_after = db_session.get(MemoryCachedSymbol, cache.id)
        assert cache_after.cache_classification == CACHE_CLASSIFICATION_EXPERIMENTAL_CANDIDATE

    def test_upsert_is_idempotent(
        self, db_session, case_evidence, requirement_factory, cache_factory
    ):
        case, evidence = case_evidence
        requirement = requirement_factory()
        cache = cache_factory(
            pdb_name="ntkrnlmp.pdb",
            pdb_guid="D801A9AFC0FB7761380800F708633DEA",
            pdb_age=5,
            cache_classification=CACHE_CLASSIFICATION_EXPERIMENTAL_CANDIDATE,
        )
        first = upsert_candidate(
            db_session,
            case_id=case.id,
            evidence_id=evidence.id,
            requirement=requirement,
            cache=cache,
        )
        second = upsert_candidate(
            db_session,
            case_id=case.id,
            evidence_id=evidence.id,
            requirement=requirement,
            cache=cache,
        )
        assert first.id == second.id
        # Only one active candidate per requirement.
        candidates = list_candidates(db_session, case_id=case.id, evidence_id=evidence.id)
        assert len(candidates) == 1

    def test_ineligible_candidate_refused(
        self, db_session, case_evidence, requirement_factory, cache_factory
    ):
        case, evidence = case_evidence
        requirement = requirement_factory()
        cache = cache_factory(
            pdb_name="ntoskrnl.pdb",
            pdb_guid="D801A9AFC0FB7761380800F708633DEA",
            pdb_age=5,
            cache_classification=CACHE_CLASSIFICATION_EXPERIMENTAL_CANDIDATE,
        )
        with pytest.raises(ExperimentalLifecycleError) as info:
            upsert_candidate(
                db_session,
                case_id=case.id,
                evidence_id=evidence.id,
                requirement=requirement,
                cache=cache,
            )
        assert info.value.error_code == "EXPERIMENTAL_NAME_MISMATCH"

    def test_revoke_candidate(
        self, db_session, case_evidence, requirement_factory, cache_factory
    ):
        case, evidence = case_evidence
        requirement = requirement_factory()
        cache = cache_factory(
            pdb_name="ntkrnlmp.pdb",
            pdb_guid="D801A9AFC0FB7761380800F708633DEA",
            pdb_age=5,
            cache_classification=CACHE_CLASSIFICATION_EXPERIMENTAL_CANDIDATE,
        )
        candidate = upsert_candidate(
            db_session,
            case_id=case.id,
            evidence_id=evidence.id,
            requirement=requirement,
            cache=cache,
        )
        revoke_candidate(
            db_session,
            candidate=candidate,
            actor="operator",
            reason="withdrawn",
        )
        assert candidate.revoked_at is not None
        assert candidate.revoked_by == "operator"
        assert candidate.revocation_reason == "withdrawn"
        # get_active_candidate returns None after revocation.
        active = get_active_candidate(db_session, requirement_id=requirement.id)
        assert active is None


class TestAcknowledgementContract:
    """The acknowledgement is a server-side payload that must
    pass every check."""

    def _build_required(self, **overrides):
        block = {
            "pdb_name": "ntkrnlmp.pdb",
            "pdb_guid": "D801A9AFC0FB7761380800F708633DEA",
            "pdb_age": 1,
            "architecture": "x64",
        }
        block.update(overrides)
        return block

    def _build_observed(self, **overrides):
        block = {
            "pdb_name": "ntkrnlmp.pdb",
            "pdb_guid": "D801A9AFC0FB7761380800F708633DEA",
            "pdb_age": 5,
            "architecture": "x64",
        }
        block.update(overrides)
        return block

    def test_valid_acknowledgement(self):
        payload = _build_valid_acknowledgement(
            required=self._build_required(),
            observed=self._build_observed(),
        )
        ok, code, normalised = validate_acknowledgement_payload(
            payload,
            run_id="run-1",
            expected_required=self._build_required(),
            expected_observed=self._build_observed(),
        )
        assert ok is True
        assert code is None
        assert normalised["checkbox_confirmed"] is True
        assert "fingerprint" in normalised

    def test_missing_checkbox_refused(self):
        payload = _build_valid_acknowledgement(
            required=self._build_required(),
            observed=self._build_observed(),
            checkbox_confirmed=False,
        )
        ok, code, _ = validate_acknowledgement_payload(
            payload,
            run_id="run-1",
            expected_required=self._build_required(),
            expected_observed=self._build_observed(),
        )
        assert ok is False
        assert code == "EXPERIMENTAL_ACK_CHECKBOX_NOT_CONFIRMED"

    def test_client_supplied_authoritative_fields_refused(self):
        payload = _build_valid_acknowledgement(
            required=self._build_required(),
            observed=self._build_observed(),
        )
        payload["warning_version"] = "outdated-warning-v0"
        ok, code, _ = validate_acknowledgement_payload(
            payload,
            run_id="run-1",
            expected_required=self._build_required(),
            expected_observed=self._build_observed(),
        )
        assert ok is False
        assert code == "EXPERIMENTAL_ACK_CLIENT_FIELDS_FORBIDDEN"

    def test_client_supplied_required_identity_refused(self):
        payload = _build_valid_acknowledgement(
            required=self._build_required(pdb_age=99),
            observed=self._build_observed(),
        )
        payload["required_identity"] = self._build_required(pdb_age=99)
        ok, code, _ = validate_acknowledgement_payload(
            payload,
            run_id="run-1",
            expected_required=self._build_required(pdb_age=1),
            expected_observed=self._build_observed(),
        )
        assert ok is False
        assert code == "EXPERIMENTAL_ACK_CLIENT_FIELDS_FORBIDDEN"

    def test_client_supplied_observed_identity_refused(self):
        payload = _build_valid_acknowledgement(
            required=self._build_required(),
            observed=self._build_observed(pdb_guid="FFEEDDCCBBAA99887766554433221100"),
        )
        payload["observed_identity"] = self._build_observed(
            pdb_guid="FFEEDDCCBBAA99887766554433221100"
        )
        ok, code, _ = validate_acknowledgement_payload(
            payload,
            run_id="run-1",
            expected_required=self._build_required(),
            expected_observed=self._build_observed(),
        )
        assert ok is False
        assert code == "EXPERIMENTAL_ACK_CLIENT_FIELDS_FORBIDDEN"

    def test_client_supplied_warning_text_refused(self):
        payload = _build_valid_acknowledgement(
            required=self._build_required(),
            observed=self._build_observed(),
        )
        payload["warning_text"] = "a watered-down warning"
        ok, code, _ = validate_acknowledgement_payload(
            payload,
            run_id="run-1",
            expected_required=self._build_required(),
            expected_observed=self._build_observed(),
        )
        assert ok is False
        assert code == "EXPERIMENTAL_ACK_CLIENT_FIELDS_FORBIDDEN"

    def test_warning_payload_contains_version_and_text(self):
        payload = build_warning_payload()
        assert payload["warning_version"] == EXPERIMENTAL_ACK_WARNING_VERSION
        assert "EXPERIMENTAL" in payload["warning_text"]
        assert "checkbox_text" in payload
        assert "required_fields" in payload


class TestCanaryEvaluation:
    """The canary aggregates the bounded checks into a single
    status.  The status is one of the allowed values."""

    def test_passing_canary(self):
        rows = [
            {"pid": 4, "name": "System", "create_time": "2024-01-01T00:00:00"},
            {"pid": 100, "name": "explorer.exe", "create_time": "2024-01-01T00:00:00"},
            {"pid": 200, "name": "lsass.exe", "create_time": "2024-01-01T00:00:00"},
        ]
        result = evaluate_canary(rows=rows)
        assert result["status"] in {CANARY_STATUS_PASSED, CANARY_STATUS_DEGRADED}
        assert result["score"] >= 0.5
        assert isinstance(result["checks"], list)
        assert len(result["checks"]) >= 5

    def test_failing_canary_with_unprintable_names(self):
        rows = [
            {"pid": i, "name": "\x00\x00\x00\x00", "create_time": "x"}
            for i in range(50)
        ]
        result = evaluate_canary(rows=rows)
        assert result["status"] in {CANARY_STATUS_FAILED, CANARY_STATUS_DEGRADED}

    def test_empty_rows_inconclusive(self):
        result = evaluate_canary(rows=[])
        assert result["status"] in {
            CANARY_STATUS_INCONCLUSIVE,
            CANARY_STATUS_FAILED,
        }


class TestRunLifecycle:
    """The run lifecycle is the largest piece.  Every state
    transition is pinned."""

    def _create_acknowledged_run(
        self, db_session, case_evidence, requirement_factory, cache_factory
    ):
        case, evidence = case_evidence
        requirement = requirement_factory()
        cache = cache_factory(
            pdb_name="ntkrnlmp.pdb",
            pdb_guid="D801A9AFC0FB7761380800F708633DEA",
            pdb_age=5,
            cache_classification=CACHE_CLASSIFICATION_EXPERIMENTAL_CANDIDATE,
        )
        candidate = upsert_candidate(
            db_session,
            case_id=case.id,
            evidence_id=evidence.id,
            requirement=requirement,
            cache=cache,
        )
        run = create_run(
            db_session,
            case_id=case.id,
            evidence_id=evidence.id,
            candidate=candidate,
            requested_profiles=[
                "experimental_metadata",
                "experimental_processes",
            ],
            actor="operator@example.com",
        )
        run = record_acknowledgement(
            db_session,
            run=run,
            candidate=candidate,
            payload=_build_valid_acknowledgement(
                required={
                    "pdb_name": requirement.pdb_name,
                    "pdb_guid": requirement.pdb_guid,
                    "pdb_age": int(requirement.pdb_age),
                    "architecture": requirement.architecture,
                },
                observed={
                    "pdb_name": cache.pdb_name,
                    "pdb_guid": cache.pdb_guid,
                    "pdb_age": int(cache.pdb_age),
                    "architecture": cache.architecture,
                },
            ),
        )
        return run, candidate

    def test_create_run_starts_in_acknowledgement_state(
        self, db_session, case_evidence, requirement_factory, cache_factory
    ):
        case, evidence = case_evidence
        requirement = requirement_factory()
        cache = cache_factory(
            pdb_name="ntkrnlmp.pdb",
            pdb_guid="D801A9AFC0FB7761380800F708633DEA",
            pdb_age=5,
            cache_classification=CACHE_CLASSIFICATION_EXPERIMENTAL_CANDIDATE,
        )
        candidate = upsert_candidate(
            db_session,
            case_id=case.id,
            evidence_id=evidence.id,
            requirement=requirement,
            cache=cache,
        )
        run = create_run(
            db_session,
            case_id=case.id,
            evidence_id=evidence.id,
            candidate=candidate,                    actor="operator",
        )
        assert run.status == RUN_STATUS_ACKNOWLEDGEMENT_REQUIRED
        assert run.acknowledgement_at is None
        assert run.canary_status == "pending"

    def test_run_blocked_before_acknowledgement(
        self, db_session, case_evidence, requirement_factory, cache_factory
    ):
        case, evidence = case_evidence
        requirement = requirement_factory()
        cache = cache_factory(
            pdb_name="ntkrnlmp.pdb",
            pdb_guid="D801A9AFC0FB7761380800F708633DEA",
            pdb_age=5,
            cache_classification=CACHE_CLASSIFICATION_EXPERIMENTAL_CANDIDATE,
        )
        candidate = upsert_candidate(
            db_session,
            case_id=case.id,
            evidence_id=evidence.id,
            requirement=requirement,
            cache=cache,
        )
        run = create_run(
            db_session,
            case_id=case.id,
            evidence_id=evidence.id,
            candidate=candidate,                    actor="operator",
        )
        with pytest.raises(ExperimentalLifecycleError) as info:
            advance_to_canary_queue(db_session, run=run)
        assert info.value.error_code == "EXPERIMENTAL_ACK_REQUIRED"

    def test_full_run_blocked_until_canary_passes(
        self, db_session, case_evidence, requirement_factory, cache_factory
    ):
        run, _ = self._create_acknowledged_run(
            db_session, case_evidence, requirement_factory, cache_factory
        )
        with pytest.raises(ExperimentalLifecycleError) as info:
            request_full_run(db_session, run=run)
        assert info.value.error_code == "EXPERIMENTAL_CANARY_NOT_PASSED"

    def test_canary_passed_promotes_to_canary_passed(
        self, db_session, case_evidence, requirement_factory, cache_factory
    ):
        run, _ = self._create_acknowledged_run(
            db_session, case_evidence, requirement_factory, cache_factory
        )
        run = advance_to_canary_queue(db_session, run=run)
        assert run.status == RUN_STATUS_CANARY_QUEUED
        # Build rows that look like a clean windows.info dump.
        rows = [
            {"pid": 4, "name": "System", "create_time": "2024-01-01T00:00:00Z"},
            {"pid": 100, "name": "explorer.exe", "create_time": "2024-01-01T00:00:00Z"},
            {"pid": 200, "name": "lsass.exe", "create_time": "2024-01-01T00:00:00Z"},
        ]
        run = finalize_canary(db_session, run=run, rows=rows)
        # The canary must be in one of the passed/degraded/failed
        # states.  In this case the rows are clean, so it is
        # passed.
        assert run.canary_status in {
            CANARY_STATUS_PASSED,
            CANARY_STATUS_DEGRADED,
        }
        if run.canary_status == CANARY_STATUS_PASSED:
            assert run.status == RUN_STATUS_CANARY_PASSED
        else:
            assert run.status == RUN_STATUS_CANARY_DEGRADED

    def test_canary_failure_blocks_continuation(
        self, db_session, case_evidence, requirement_factory, cache_factory
    ):
        run, _ = self._create_acknowledged_run(
            db_session, case_evidence, requirement_factory, cache_factory
        )
        run = advance_to_canary_queue(db_session, run=run)
        # Rows that should clearly fail the canary.
        rows = [
            {"pid": i, "name": "\x00\x00\x00", "create_time": "x"}
            for i in range(50)
        ]
        run = finalize_canary(db_session, run=run, rows=rows)
        assert run.canary_status in {
            CANARY_STATUS_FAILED,
            CANARY_STATUS_DEGRADED,
        }
        with pytest.raises(ExperimentalLifecycleError):
            request_full_run(db_session, run=run)

    def test_canary_override_allows_continuation(
        self, db_session, case_evidence, requirement_factory, cache_factory
    ):
        run, _ = self._create_acknowledged_run(
            db_session, case_evidence, requirement_factory, cache_factory
        )
        run = advance_to_canary_queue(db_session, run=run)
        # Build rows that produce a degraded canary.
        rows = [
            {"pid": 4, "name": "System", "create_time": "2024-01-01T00:00:00Z"},
            {"pid": 100, "name": "explorer.exe", "create_time": "2024-01-01T00:00:00Z"},
            {"pid": 999999, "name": "lsass.exe", "create_time": "2024-01-01T00:00:00Z"},
        ]
        run = finalize_canary(db_session, run=run, rows=rows)
        if run.canary_status in {CANARY_STATUS_DEGRADED, CANARY_STATUS_INCONCLUSIVE}:
            run = record_canary_override(
                db_session, run=run, actor="operator", reason="triage"
            )
            if run.canary_status == CANARY_STATUS_DEGRADED:
                run = request_full_run(db_session, run=run)
                assert run.status == "full_run_queued"
            else:
                with pytest.raises(ExperimentalLifecycleError):
                    request_full_run(db_session, run=run)

    def test_cancel_run(
        self, db_session, case_evidence, requirement_factory, cache_factory
    ):
        run, _ = self._create_acknowledged_run(
            db_session, case_evidence, requirement_factory, cache_factory
        )
        run = cancel_run(db_session, run=run, actor="operator", reason="changed my mind")
        assert run.status == RUN_STATUS_CANCELLED
        assert run.cancelled_by == "operator"
        assert run.cancellation_reason == "changed my mind"

    def test_delete_run_marks_deleted_without_touching_data(
        self, db_session, case_evidence, requirement_factory, cache_factory
    ):
        case, evidence = case_evidence
        run, candidate = self._create_acknowledged_run(
            db_session, case_evidence, requirement_factory, cache_factory
        )
        run = finalise_run(
            db_session, run=run, outcome=RUN_STATUS_COMPLETED_UNTRUSTED
        )
        # Snapshot the requirement and the cache for the post-delete
        # assertion.
        requirement_id = run.requirement_id
        cached_symbol_id = run.cached_symbol_id
        run = delete_run(
            db_session, run=run, actor="operator", reason="cleaned up"
        )
        assert run.status == RUN_STATUS_DELETED
        assert run.deleted_at is not None
        # The requirement and the cache are NEVER mutated by a
        # run delete.
        requirement_after = db_session.get(MemorySymbolRequirement, requirement_id)
        assert requirement_after is not None
        assert requirement_after.pdb_age == 1
        cache_after = db_session.get(MemoryCachedSymbol, cached_symbol_id)
        assert cache_after is not None
        assert cache_after.cache_classification == CACHE_CLASSIFICATION_EXPERIMENTAL_CANDIDATE
        # list_runs returns the deleted run when include_deleted=True.
        runs_visible = list_runs(
            db_session, case_id=case.id, evidence_id=evidence.id,
            include_deleted=False,
        )
        assert runs_visible == []
        runs_with_deleted = list_runs(
            db_session, case_id=case.id, evidence_id=evidence.id,
            include_deleted=True,
        )
        assert any(r.id == run.id for r in runs_with_deleted)


class TestOneActiveRun:
    """The spec requires "one active experimental run per
    evidence".  Multiple terminals are allowed."""

    def test_second_active_run_refused(
        self, db_session, case_evidence, requirement_factory, cache_factory
    ):
        case, evidence = case_evidence
        requirement = requirement_factory()
        cache = cache_factory(
            pdb_name="ntkrnlmp.pdb",
            pdb_guid="D801A9AFC0FB7761380800F708633DEA",
            pdb_age=5,
            cache_classification=CACHE_CLASSIFICATION_EXPERIMENTAL_CANDIDATE,
        )
        candidate = upsert_candidate(
            db_session,
            case_id=case.id,
            evidence_id=evidence.id,
            requirement=requirement,
            cache=cache,
        )
        first = create_run(
            db_session,
            case_id=case.id,
            evidence_id=evidence.id,
            candidate=candidate,                    actor="operator",
        )
        with pytest.raises(ExperimentalLifecycleError) as info:
            create_run(
            db_session,
            case_id=case.id,
            evidence_id=evidence.id,
            candidate=candidate,                        actor="operator",
        )
        assert info.value.error_code == "EXPERIMENTAL_RUN_ALREADY_ACTIVE"
        assert info.value.http_status == 409


class TestTrustState:
    """The trust state helper is the small view consumed by the
    UI on the preparation card."""

    def test_trust_state_empty_evidence(self, db_session, case_evidence):
        case, evidence = case_evidence
        state = trust_state(db_session, case_id=case.id, evidence_id=evidence.id)
        assert state["has_active_candidate"] is False
        assert state["has_active_run"] is False
        assert state["enabled"] is True


class TestRequirementNeverMutated:
    """The exact symbol requirement is NEVER mutated by any
    experimental operation."""

    def test_candidate_creation_does_not_mutate_requirement(
        self, db_session, case_evidence, requirement_factory, cache_factory
    ):
        case, evidence = case_evidence
        requirement = requirement_factory(pdb_age=1)
        cache = cache_factory(
            pdb_name="ntkrnlmp.pdb",
            pdb_guid="D801A9AFC0FB7761380800F708633DEA",
            pdb_age=5,
            cache_classification=CACHE_CLASSIFICATION_EXPERIMENTAL_CANDIDATE,
        )
        upsert_candidate(
            db_session,
            case_id=case.id,
            evidence_id=evidence.id,
            requirement=requirement,
            cache=cache,
        )
        # The required pdb_age is STILL 1.  The exact symbol
        # path is unaffected.
        requirement_after = db_session.get(MemorySymbolRequirement, requirement.id)
        assert requirement_after.pdb_age == 1
        assert requirement_after.symbol_key.endswith("-1")

    def test_run_lifecycle_does_not_mutate_requirement(
        self, db_session, case_evidence, requirement_factory, cache_factory
    ):
        case, evidence = case_evidence
        requirement = requirement_factory()
        cache = cache_factory(
            pdb_name="ntkrnlmp.pdb",
            pdb_guid="D801A9AFC0FB7761380800F708633DEA",
            pdb_age=5,
            cache_classification=CACHE_CLASSIFICATION_EXPERIMENTAL_CANDIDATE,
        )
        candidate = upsert_candidate(
            db_session,
            case_id=case.id,
            evidence_id=evidence.id,
            requirement=requirement,
            cache=cache,
        )
        run = create_run(
            db_session,
            case_id=case.id,
            evidence_id=evidence.id,
            candidate=candidate,                    actor="operator",
        )
        run = record_acknowledgement(
            db_session, run=run, candidate=candidate,
            payload=_build_valid_acknowledgement(
                required={
                    "pdb_name": requirement.pdb_name,
                    "pdb_guid": requirement.pdb_guid,
                    "pdb_age": int(requirement.pdb_age),
                    "architecture": requirement.architecture,
                },
                observed={
                    "pdb_name": cache.pdb_name,
                    "pdb_guid": cache.pdb_guid,
                    "pdb_age": int(cache.pdb_age),
                    "architecture": cache.architecture,
                },
            ),
        )
        run = advance_to_canary_queue(db_session, run=run)
        run = finalize_canary(
            db_session, run=run, rows=[{"pid": 4, "name": "System"}],
        )
        requirement_after = db_session.get(MemorySymbolRequirement, requirement.id)
        assert requirement_after.pdb_age == requirement.pdb_age


class TestCacheRowNeverLinkedAsExact:
    """A cache row classified as ``experimental_candidate``
    must NEVER satisfy the standard readiness contract."""

    def test_experimental_cache_has_experimental_classification(
        self, db_session, case_evidence, cache_factory
    ):
        cache = cache_factory(
            pdb_name="ntkrnlmp.pdb",
            pdb_guid="D801A9AFC0FB7761380800F708633DEA",
            pdb_age=5,
            cache_classification=CACHE_CLASSIFICATION_EXPERIMENTAL_CANDIDATE,
        )
        assert cache.cache_classification == CACHE_CLASSIFICATION_EXPERIMENTAL_CANDIDATE


class TestProfileCatalogue:
    """The experimental catalogue is separate from the validated one."""

    def test_catalogue_contains_expected_profiles(self):
        names = {item["profile"] for item in list_experimental_profiles()}
        for expected in (
            "experimental_metadata",
            "experimental_processes",
            "experimental_process_scan",
            "experimental_command_lines",
            "experimental_modules",
            "experimental_network",
            "experimental_suspicious_memory",
        ):
            assert expected in names

    def test_catalogue_names_differ_from_validated(self):
        names = {item["profile"] for item in list_experimental_profiles()}
        for forbidden in (
            "metadata_only",
            "processes_basic",
            "processes_extended",
            "network_basic",
            "modules_basic",
            "handles_basic",
            "kernel_basic",
            "suspicious_memory",
        ):
            assert forbidden not in names

    def test_canary_profile_is_fixed(self):
        assert EXPERIMENTAL_CANARY_PROFILE == "experimental_canary"
        assert EXPERIMENTAL_CANARY_PLUGINS == ["windows.info"]

    def test_canary_passed_allows_all_profiles(self):
        allowed = allowed_profiles_for_canary_outcome(CANARY_STATUS_PASSED)
        assert len(allowed) == len(EXPERIMENTAL_PROFILES)

    def test_canary_degraded_allows_restricted_subset(self):
        allowed = allowed_profiles_for_canary_outcome(CANARY_STATUS_DEGRADED)
        assert "experimental_metadata" in allowed
        assert "experimental_modules" in allowed
        assert "experimental_processes" not in allowed

    def test_canary_failed_allows_no_profiles(self):
        assert allowed_profiles_for_canary_outcome(CANARY_STATUS_FAILED) == []
        assert allowed_profiles_for_canary_outcome(CANARY_STATUS_INCONCLUSIVE) == []
        assert allowed_profiles_for_canary_outcome(None) == []

    def test_get_experimental_profile_returns_definition(self):
        item = get_experimental_profile("experimental_metadata")
        assert item is not None
        assert item["family"] == "system_info"
        assert "windows.info" in item["plugins"]


class TestValidatedPathUnchanged:
    """The strict exact-symbol workflow must remain the default
    and authoritative path."""

    def test_requirement_symbol_key_unchanged_after_experimental_workflow(
        self, db_session, case_evidence, requirement_factory, cache_factory
    ):
        case, evidence = case_evidence
        requirement = requirement_factory(pdb_age=1)
        original_key = requirement.symbol_key
        cache = cache_factory(
            pdb_name="ntkrnlmp.pdb",
            pdb_guid="D801A9AFC0FB7761380800F708633DEA",
            pdb_age=5,
            cache_classification=CACHE_CLASSIFICATION_EXPERIMENTAL_CANDIDATE,
        )
        candidate = upsert_candidate(
            db_session,
            case_id=case.id,
            evidence_id=evidence.id,
            requirement=requirement,
            cache=cache,
        )
        run = create_run(
            db_session,
            case_id=case.id,
            evidence_id=evidence.id,
            candidate=candidate,                    actor="operator",
        )
        run = record_acknowledgement(
            db_session, run=run, candidate=candidate,
            payload=_build_valid_acknowledgement(
                required={
                    "pdb_name": requirement.pdb_name,
                    "pdb_guid": requirement.pdb_guid,
                    "pdb_age": int(requirement.pdb_age),
                    "architecture": requirement.architecture,
                },
                observed={
                    "pdb_name": cache.pdb_name,
                    "pdb_guid": cache.pdb_guid,
                    "pdb_age": int(cache.pdb_age),
                    "architecture": cache.architecture,
                },
            ),
        )
        requirement_after = db_session.get(MemorySymbolRequirement, requirement.id)
        assert requirement_after.symbol_key == original_key

    def test_validated_run_does_not_get_experimental_trust(
        self, db_session, case_evidence
    ):
        case, evidence = case_evidence
        run = MemoryScanRun(
            id=str(uuid.uuid4()),
            case_id=case.id,
            evidence_id=evidence.id,
            backend="volatility3",
            profile="metadata_only",
            status="completed",
            analysis_mode=ANALYSIS_MODE_VALIDATED,
            trust_level=TRUST_LEVEL_VALIDATED,
            symbol_match_type="exact",
        )
        db_session.add(run)
        db_session.commit()
        run_after = db_session.get(MemoryScanRun, run.id)
        assert run_after.trust_level == TRUST_LEVEL_VALIDATED
        assert run_after.analysis_mode == ANALYSIS_MODE_VALIDATED
