"""Permanent case deletion.

delete_case() is the single reusable entry point for destroying a case and
every resource that belongs to it: database rows, the case's OpenSearch
indices (events, memory, memory-experimental), and on-disk storage (evidence,
extracted/staging directories, generated report files, and rule library
snapshot audit files that reference the case).

Design:
- The database portion is transactional: every case-scoped row is deleted in
  one SQLAlchemy transaction, committed once at the end. If any step raises,
  the transaction is rolled back and the case is left untouched.
- OpenSearch and filesystem cleanup happen only after the DB commit succeeds,
  since they cannot participate in a SQL transaction (a deleted file cannot be
  "rolled back"). Once the DB rows are gone, the case is considered deleted;
  cleanup failures for the index/storage are reported back but do not
  resurrect the case.
- AuditEvent rows are deliberately left untouched. They are the platform's
  security/access audit trail, not investigation data, and audit trails are
  expected to survive deletion of the resource they describe (including the
  deletion action itself). case_id there is an informational tag, not an
  enforced foreign key.
- Callers must check case_has_active_processing() (or catch
  CaseDeletionBlockedError) before assuming deletion is safe; delete_case()
  enforces this itself and raises rather than silently deleting a case with
  in-flight work.
"""
from __future__ import annotations

from dataclasses import dataclass, field
import logging
import re

from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.orm import Session

from app.core.config import get_settings
from app.core.opensearch import delete_case_index, delete_case_memory_indices
from app.core.storage import case_storage_root, safe_remove
from app.models.activity import AppActivityEvent
from app.models.artifact import Artifact
from app.models.assignment_history import AssignmentHistory
from app.models.case import Case
from app.models.case_access import CaseAccess
from app.models.case_analysis_job import CaseAnalysisJob, CaseAnalysisJobStatus
from app.models.case_host import CaseHost
from app.models.case_host_alias import CaseHostAlias
from app.models.case_host_identity_audit import CaseHostIdentityAudit
from app.models.case_report import CaseReport
from app.models.detection_result import DetectionResult
from app.models.disk_image import DiskImage, DiskVolume, OSInstallation
from app.models.event_marking import EventMarking
from app.models.evidence import Evidence, IngestStatus
from app.models.finding import Finding
from app.models.incident_timeline_draft import IncidentTimelineDraft
from app.models.memory import (
    MemoryAnalysisBatch,
    MemoryArtifactSummary,
    MemoryEvidenceSymbolLink,
    MemoryExperimentalRun,
    MemoryExperimentalSymbolCandidate,
    MemoryNativeProbe,
    MemoryPluginRun,
    MemoryScanRun,
    MemorySymbolAcquisition,
    MemorySymbolAcquisitionRequest,
    MemorySymbolApproval,
    MemorySymbolPendingAnalysis,
    MemorySymbolPreparation,
    MemorySymbolRecoveryAttempt,
    MemorySymbolRequirement,
    MemoryUpload,
)
from app.models.rule import Rule
from app.models.rule_import_run import RuleImportRun
from app.models.rule_run import RuleRun
from app.models.rule_set import RuleSet
from app.models.tag import Tag
from app.models.timeline_bookmark import TimelineBookmark

logger = logging.getLogger(__name__)


class CaseNotFoundError(Exception):
    """Raised when the case does not exist."""


class CaseDeletionBlockedError(Exception):
    """Raised when the case cannot be deleted because processing is active."""


@dataclass
class CaseDeletionResult:
    case_id: str
    status: str = "deleted"
    index_deleted: dict[str, bool] = field(default_factory=dict)
    storage_deleted: bool = False
    reports_removed: int = 0
    snapshots_removed: int = 0
    cleanup_errors: list[str] = field(default_factory=list)


def case_has_active_processing(db: Session, case_id: str) -> bool:
    """True if evidence ingest, a case analysis job, or a memory batch is in flight for this case."""
    active_evidence = (
        db.query(Evidence.id)
        .filter(Evidence.case_id == case_id, Evidence.ingest_status == IngestStatus.processing)
        .first()
    )
    if active_evidence is not None:
        return True
    active_job = (
        db.query(CaseAnalysisJob.id)
        .filter(
            CaseAnalysisJob.case_id == case_id,
            CaseAnalysisJob.status.in_([CaseAnalysisJobStatus.queued, CaseAnalysisJobStatus.running]),
        )
        .first()
    )
    if active_job is not None:
        return True
    active_memory_batch = (
        db.query(MemoryAnalysisBatch.id)
        .filter(MemoryAnalysisBatch.case_id == case_id, MemoryAnalysisBatch.status.in_(("queued", "running")))
        .first()
    )
    return active_memory_batch is not None


def _remove_case_rule_library_snapshots(case_id: str) -> int:
    """Best-effort removal of rule-library snapshot JSON files that reference this case.

    These snapshots (backend/app/api/routes_rules.py: _create_sigma_rule_library_snapshot)
    are not tracked in any table, so they cannot be found by a case_id FK. The filename is
    caller-controlled and does not reliably embed case_id, so each file is opened and its
    case_id field is checked before removal.
    """
    import json

    settings = get_settings()
    snapshot_dir = settings.backend_data_dir / "rule_library_snapshots"
    if not snapshot_dir.exists():
        return 0
    removed = 0
    for snapshot_path in snapshot_dir.glob("*.json"):
        try:
            payload = json.loads(snapshot_path.read_text(encoding="utf-8"))
        except Exception:  # noqa: BLE001
            continue
        if payload.get("case_id") == case_id:
            try:
                snapshot_path.unlink()
                removed += 1
            except OSError as exc:
                logger.warning("Could not remove rule library snapshot %s: %s", snapshot_path, exc)
    return removed


_SAFE_LABEL_RE = re.compile(r"[^A-Za-z0-9_.-]+")


def delete_case(db: Session, case_id: str) -> CaseDeletionResult:
    case = db.get(Case, case_id)
    if case is None:
        raise CaseNotFoundError(case_id)

    if case_has_active_processing(db, case_id):
        raise CaseDeletionBlockedError("Case cannot be deleted while processing is active.")

    settings = get_settings()

    # Snapshot ids needed for tables that only link to the case transitively,
    # before their parent rows are deleted.
    evidence_ids = [row.id for row in db.query(Evidence.id).filter(Evidence.case_id == case_id).all()]
    disk_image_ids = (
        [row.id for row in db.query(DiskImage.id).filter(DiskImage.evidence_id.in_(evidence_ids)).all()]
        if evidence_ids
        else []
    )
    disk_volume_ids = (
        [row.id for row in db.query(DiskVolume.id).filter(DiskVolume.disk_image_id.in_(disk_image_ids)).all()]
        if disk_image_ids
        else []
    )
    requirement_ids = [
        row.id for row in db.query(MemorySymbolRequirement.id).filter(MemorySymbolRequirement.case_id == case_id).all()
    ]
    acquisition_request_ids = [
        row.id
        for row in db.query(MemorySymbolAcquisitionRequest.id)
        .filter(MemorySymbolAcquisitionRequest.case_id == case_id)
        .all()
    ]
    report_ids = [row.id for row in db.query(CaseReport.id).filter(CaseReport.case_id == case_id).all()]

    try:
        # Transitive-only tables (children before the parents they hang off).
        if disk_volume_ids:
            db.query(OSInstallation).filter(OSInstallation.disk_volume_id.in_(disk_volume_ids)).delete(synchronize_session=False)
        if disk_image_ids:
            db.query(DiskVolume).filter(DiskVolume.disk_image_id.in_(disk_image_ids)).delete(synchronize_session=False)
        if evidence_ids:
            db.query(DiskImage).filter(DiskImage.evidence_id.in_(evidence_ids)).delete(synchronize_session=False)
        if requirement_ids:
            db.query(MemorySymbolAcquisition).filter(MemorySymbolAcquisition.requirement_id.in_(requirement_ids)).delete(synchronize_session=False)
        if acquisition_request_ids:
            db.query(MemorySymbolApproval).filter(MemorySymbolApproval.request_id.in_(acquisition_request_ids)).delete(synchronize_session=False)

        # Direct case_id tables.
        db.query(AppActivityEvent).filter(AppActivityEvent.case_id == case_id).delete(synchronize_session=False)
        db.query(DetectionResult).filter(DetectionResult.case_id == case_id).delete(synchronize_session=False)
        db.query(Finding).filter(Finding.case_id == case_id).delete(synchronize_session=False)
        db.query(RuleRun).filter(RuleRun.case_id == case_id).delete(synchronize_session=False)
        db.query(EventMarking).filter(EventMarking.case_id == case_id).delete(synchronize_session=False)
        db.query(TimelineBookmark).filter(TimelineBookmark.case_id == case_id).delete(synchronize_session=False)
        db.query(IncidentTimelineDraft).filter(IncidentTimelineDraft.case_id == case_id).delete(synchronize_session=False)
        db.query(CaseReport).filter(CaseReport.case_id == case_id).delete(synchronize_session=False)
        db.query(CaseAnalysisJob).filter(CaseAnalysisJob.case_id == case_id).delete(synchronize_session=False)
        db.query(AssignmentHistory).filter(AssignmentHistory.case_id == case_id).delete(synchronize_session=False)
        db.query(CaseHostIdentityAudit).filter(CaseHostIdentityAudit.case_id == case_id).delete(synchronize_session=False)
        db.query(CaseHostAlias).filter(CaseHostAlias.case_id == case_id).delete(synchronize_session=False)
        db.query(CaseHost).filter(CaseHost.case_id == case_id).delete(synchronize_session=False)

        db.query(MemoryUpload).filter(MemoryUpload.case_id == case_id).delete(synchronize_session=False)
        db.query(MemoryScanRun).filter(MemoryScanRun.case_id == case_id).delete(synchronize_session=False)
        db.query(MemoryPluginRun).filter(MemoryPluginRun.case_id == case_id).delete(synchronize_session=False)
        db.query(MemoryArtifactSummary).filter(MemoryArtifactSummary.case_id == case_id).delete(synchronize_session=False)
        db.query(MemoryEvidenceSymbolLink).filter(MemoryEvidenceSymbolLink.case_id == case_id).delete(synchronize_session=False)
        db.query(MemorySymbolPreparation).filter(MemorySymbolPreparation.case_id == case_id).delete(synchronize_session=False)
        db.query(MemorySymbolPendingAnalysis).filter(MemorySymbolPendingAnalysis.case_id == case_id).delete(synchronize_session=False)
        db.query(MemorySymbolRequirement).filter(MemorySymbolRequirement.case_id == case_id).delete(synchronize_session=False)
        db.query(MemorySymbolAcquisitionRequest).filter(MemorySymbolAcquisitionRequest.case_id == case_id).delete(synchronize_session=False)
        db.query(MemoryAnalysisBatch).filter(MemoryAnalysisBatch.case_id == case_id).delete(synchronize_session=False)
        db.query(MemorySymbolRecoveryAttempt).filter(MemorySymbolRecoveryAttempt.case_id == case_id).delete(synchronize_session=False)
        db.query(MemoryExperimentalSymbolCandidate).filter(MemoryExperimentalSymbolCandidate.case_id == case_id).delete(synchronize_session=False)
        db.query(MemoryExperimentalRun).filter(MemoryExperimentalRun.case_id == case_id).delete(synchronize_session=False)
        db.query(MemoryNativeProbe).filter(MemoryNativeProbe.case_id == case_id).delete(synchronize_session=False)

        db.query(Artifact).filter(Artifact.case_id == case_id).delete(synchronize_session=False)
        db.query(Evidence).filter(Evidence.case_id == case_id).delete(synchronize_session=False)
        db.query(Rule).filter(Rule.case_id == case_id).delete(synchronize_session=False)
        db.query(RuleSet).filter(RuleSet.case_id == case_id).delete(synchronize_session=False)
        db.query(RuleImportRun).filter(RuleImportRun.case_id == case_id).delete(synchronize_session=False)
        db.query(Tag).filter(Tag.case_id == case_id).delete(synchronize_session=False)
        db.query(CaseAccess).filter(CaseAccess.case_id == case_id).delete(synchronize_session=False)
        db.query(Case).filter(Case.id == case_id).delete(synchronize_session=False)
        db.commit()
    except SQLAlchemyError:
        db.rollback()
        logger.exception("Could not delete case %s from database", case_id)
        raise

    # From here on the case is gone from the database. Cleanup below is
    # best-effort: failures are reported but do not resurrect the case.
    result = CaseDeletionResult(case_id=case_id)

    result.index_deleted["events"] = delete_case_index(case_id)
    try:
        result.index_deleted.update(delete_case_memory_indices(case_id))
    except Exception as exc:  # noqa: BLE001
        result.cleanup_errors.append(f"memory index cleanup failed: {exc}")

    try:
        case_root = case_storage_root(case_id)
        result.storage_deleted = case_root.exists()
        safe_remove(case_root)
    except Exception as exc:  # noqa: BLE001
        result.cleanup_errors.append(f"storage cleanup failed: {exc}")
        logger.warning("Could not remove storage for case %s: %s", case_id, exc)

    for report_id in report_ids:
        try:
            report_dir = settings.backend_data_dir / "reports" / report_id
            if report_dir.exists():
                safe_remove(report_dir)
                result.reports_removed += 1
        except Exception as exc:  # noqa: BLE001
            result.cleanup_errors.append(f"report {report_id} cleanup failed: {exc}")
            logger.warning("Could not remove report directory for report %s (case %s): %s", report_id, case_id, exc)

    try:
        result.snapshots_removed = _remove_case_rule_library_snapshots(case_id)
    except Exception as exc:  # noqa: BLE001
        result.cleanup_errors.append(f"rule library snapshot cleanup failed: {exc}")
        logger.warning("Could not remove rule library snapshots for case %s: %s", case_id, exc)

    return result
