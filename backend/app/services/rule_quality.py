from __future__ import annotations

from collections import defaultdict
from typing import Any

from sqlalchemy.orm import Session

from app.models.finding import Finding, FindingStatus, ACTIVE_STATUSES


REVIEWED_STATUSES = frozenset({"triaged", "investigating", "confirmed", "false_positive", "accepted_risk", "resolved", "suppressed"})
CONFIRMED_TERMINALS = frozenset({"confirmed"})
FALSE_POSITIVE_TERMINALS = frozenset({"false_positive"})
MINIMUM_REVIEWED_SAMPLE = 20


def compute_rule_quality_metrics(
    db: Session,
    *,
    case_id: str | None = None,
    rule_id: str | None = None,
    rule_version: str | None = None,
    evidence_id: str | None = None,
) -> list[dict[str, Any]]:
    query = db.query(Finding)
    if case_id:
        query = query.filter(Finding.case_id == case_id)

    findings = query.all()
    if not findings:
        return []

    by_rule: dict[str, list[Finding]] = defaultdict(list)
    for f in findings:
        rule_key = f.finding_type or f.correlation_version or "unknown"
        version = f.correlation_version or "1.0.0"
        key = f"{rule_key}|{version}"
        if rule_id and rule_key != rule_id:
            continue
        if rule_version and f.correlation_version != rule_version:
            continue
        by_rule[key].append(f)

    results: list[dict[str, Any]] = []
    for key, items in sorted(by_rule.items()):
        rule_id_str, version_str = key.rsplit("|", 1) if "|" in key else (key, "1.0.0")
        metric = _compute_metric(rule_id_str, version_str, items)
        results.append(metric)

    return results


def _compute_metric(rule_id: str, version: str, findings: list[Finding]) -> dict[str, Any]:
    total = len(findings)

    def _s(f: Finding) -> str:
        return f.status.value if hasattr(f.status, "value") else str(f.status)

    reviewed = [f for f in findings if _s(f) in REVIEWED_STATUSES]
    confirmed_list = [f for f in findings if _s(f) == "confirmed"]
    false_positive_list = [f for f in findings if _s(f) == "false_positive"]
    suppressed_list = [f for f in findings if _s(f) == "suppressed"]
    accepted_risk_list = [f for f in findings if _s(f) == "accepted_risk"]
    resolved_list = [f for f in findings if _s(f) == "resolved"]
    investigating_list = [f for f in findings if _s(f) == "investigating"]
    triaged_list = [f for f in findings if _s(f) == "triaged"]
    unreviewed = [f for f in findings if _s(f) == "new"]

    reviewed_count = len(reviewed)
    confirmed_count = len(confirmed_list)
    fp_count = len(false_positive_list)
    suppressed_count = len(suppressed_list)
    sample_size = reviewed_count

    confirmation_rate = (confirmed_count / reviewed_count) if reviewed_count > 0 else None
    fp_rate = (fp_count / reviewed_count) if reviewed_count > 0 else None

    review_coverage = (reviewed_count / total) if total > 0 else None

    sufficient_sample = sample_size >= MINIMUM_REVIEWED_SAMPLE

    quality_status = _derive_quality_status(
        sample_size=sample_size,
        confirmation_rate=confirmation_rate,
        fp_rate=fp_rate,
        sufficient_sample=sufficient_sample,
        suppressed_count=suppressed_count,
        total=total,
        reviewed_count=reviewed_count,
    )

    return {
        "rule_id": rule_id,
        "version": version,
        "total_findings": total,
        "unreviewed_findings": len(unreviewed),
        "reviewed_findings": reviewed_count,
        "triaged_findings": len(triaged_list),
        "investigating_findings": len(investigating_list),
        "confirmed_findings": confirmed_count,
        "false_positive_findings": fp_count,
        "suppressed_findings": suppressed_count,
        "accepted_risk_findings": len(accepted_risk_list),
        "resolved_findings": len(resolved_list),
        "review_coverage": round(review_coverage, 3) if review_coverage is not None else None,
        "observed_confirmation_rate": round(confirmation_rate, 3) if confirmation_rate is not None else None,
        "observed_false_positive_rate": round(fp_rate, 3) if fp_rate is not None else None,
        "sample_size": sample_size,
        "minimum_sample": MINIMUM_REVIEWED_SAMPLE,
        "sufficient_sample": sufficient_sample,
        "quality_status": quality_status,
    }


def _derive_quality_status(
    *,
    sample_size: int,
    confirmation_rate: float | None,
    fp_rate: float | None,
    sufficient_sample: bool,
    suppressed_count: int,
    total: int,
    reviewed_count: int,
) -> str:
    if total == 0:
        return "inactive"
    if not sufficient_sample:
        return "insufficient_sample"
    if fp_rate is not None and fp_rate >= 0.4 and suppressed_count >= 3:
        return "high_noise"
    if suppressed_count >= total * 0.3 and reviewed_count >= 5:
        return "needs_tuning"
    if confirmation_rate is not None and confirmation_rate >= 0.3:
        return "promising"
    if reviewed_count >= 5 and confirmation_rate is not None and confirmation_rate < 0.1:
        return "needs_tuning"
    if reviewed_count == 0:
        return "insufficient_sample"
    return "promising"
