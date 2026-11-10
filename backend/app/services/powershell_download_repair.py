"""Undo URL-only "downloads" on PowerShell events indexed before 2026-11-10.

Until then any URL in PowerShell text counted as a download cradle: module
and script help text (``.LINK https://go.microsoft.com/fwlink/...``) made a
system module a "download" (``download.*`` pointing at the script itself),
tagged it ``download_cradle`` + ``suspicious`` and gave it risk 72. The
detector now needs a download verb (Invoke-WebRequest, DownloadFile,
Start-BitsTransfer...). This pass re-evaluates the stored text of the
events still flagged that way with the current rule and, where no verb is
present, removes the download, the indicator, the tag and the reason, and
recomputes the PowerShell risk. Each event is checked once (``powershell.
download_rule``), so it is cheap to run at every start.
"""

from __future__ import annotations

import logging
from typing import Any

from opensearchpy import helpers

from app.core.opensearch import get_opensearch_client
from app.ingest.powershell.helpers import POWERSHELL_DOWNLOAD_RULE_VERSION, detect_powershell_download, powershell_suspicion

logger = logging.getLogger(__name__)

RULE_VERSION = POWERSHELL_DOWNLOAD_RULE_VERSION
DOWNLOAD_REASON = "PowerShell download cradle"
INDEX_PATTERN = "dfir-events-*"


def _text(source: dict[str, Any]) -> str:
    powershell = source.get("powershell") or {}
    parts = [powershell.get("command") or powershell.get("raw_payload") or "", powershell.get("decoded_command_preview") or ""]
    return "\n".join(str(part) for part in parts if part)


def repaired_fields(source: dict[str, Any]) -> dict[str, Any]:
    """Fields to write for one flagged event (only the rule marker if it really is a download)."""
    powershell = dict(source.get("powershell") or {})
    text = _text(source)
    if not text or detect_powershell_download(text):
        return {"powershell": {**powershell, "download_rule": RULE_VERSION}}
    is_script = powershell.get("artifact_type") == "powershell_script"
    new_tags, new_reasons, new_risk = powershell_suspicion(text, file_path=(source.get("file") or {}).get("path"), is_script=is_script)
    old_reasons = [reason for reason in source.get("suspicious_reasons") or [] if reason != DOWNLOAD_REASON]
    reasons = sorted(set(old_reasons) | set(new_reasons))
    tags = {tag for tag in source.get("tags") or [] if tag != "download_cradle"} | set(new_tags)
    if not reasons:
        tags.discard("suspicious")
    old_risk = int(source.get("risk_score") or 0)
    # Lower the risk only when PowerShell's own scoring set it: a reason
    # from another source (a rule, a correlation) keeps its score.
    foreign_reasons = set(old_reasons) - set(new_reasons)
    risk = old_risk if foreign_reasons else min(old_risk, new_risk) if old_risk else new_risk
    powershell.update(
        {
            "has_download": False,
            "indicators": sorted(item for item in powershell.get("indicators") or [] if item != "download_cradle"),
            "download_rule": RULE_VERSION,
        }
    )
    fields: dict[str, Any] = {"powershell": powershell, "tags": sorted(tags), "suspicious_reasons": reasons, "risk_score": risk}
    # BITS transfer fields mean a real transfer: keep that download record.
    bits = source.get("bits") or {}
    if not any(bits.get(key) for key in ("state", "bytes_total", "bytes_transferred", "remote_url")):
        fields["download"] = None
    return fields


def repair_powershell_url_only_downloads(client=None) -> int:  # noqa: ANN001
    client = client or get_opensearch_client()
    if not client.indices.exists(index=INDEX_PATTERN, allow_no_indices=False):
        return 0
    # Indices are dynamic: false, so the marker needs a mapping to be queryable.
    client.indices.put_mapping(index=INDEX_PATTERN, body={"properties": {"powershell": {"properties": {"download_rule": {"type": "integer"}}}}})
    query = {
        "query": {
            "bool": {
                "filter": [{"term": {"artifact.type": "powershell"}}, {"term": {"powershell.indicators": "download_cradle"}}],
                "must_not": [{"term": {"powershell.download_rule": RULE_VERSION}}],
            }
        }
    }
    actions = []
    for hit in helpers.scan(client, index=INDEX_PATTERN, query=query, params={"ignore_unavailable": "true"}, size=500):
        actions.append({"_op_type": "update", "_index": hit["_index"], "_id": hit["_id"], "doc": repaired_fields(hit["_source"])})
    if not actions:
        return 0
    helpers.bulk(client, actions, chunk_size=500, raise_on_error=False)
    return sum(1 for action in actions if "tags" in action["doc"])
