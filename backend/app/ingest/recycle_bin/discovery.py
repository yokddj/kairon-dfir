from __future__ import annotations

from app.ingest.recycle_bin.helpers import extract_sid_from_recycle_path, is_recycle_i_path, is_recycle_r_path, recycle_pair_id_from_path


def classify_recycle_entry(path: str) -> dict | None:
    normalized = path.replace("/", "\\")
    sid = extract_sid_from_recycle_path(normalized)
    if not sid:
        return None
    pair_id = recycle_pair_id_from_path(normalized)
    if not pair_id:
        return None
    if is_recycle_i_path(normalized):
        return {"kind": "i", "sid": sid, "pair_id": pair_id}
    if is_recycle_r_path(normalized):
        return {"kind": "r", "sid": sid, "pair_id": pair_id}
    return None
