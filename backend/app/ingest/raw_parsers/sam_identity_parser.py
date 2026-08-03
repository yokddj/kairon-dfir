"""Windows Host User Facts (local account inventory) from the SAM registry
hive.

Reuses the exact hive-opening mechanism already proven by
app.ingest.raw_parsers.system_hive_identity_parser (python-registry /
Registry.Registry) against a different physical file -- SAM, not SYSTEM.
Binary field decoding lives in app.ingest.windows.sam_identity, kept
separate and pure so it can be unit-tested against real byte layouts
without needing a real hive file.

Walks SAM\\Domains\\Account\\Users\\Names\\<username> for the account list
(the RID lives in the value's *type* field -- see sam_identity.py), then
SAM\\Domains\\Account\\Users\\<RID hex>\\F and \\V for account-control
flags/timestamps and username/full-name/comment respectively. Emits one
inline-tagged document per account -- this parser needs no derived
extractor registration; app.ingest.host_user_extraction.extract_host_user_documents
picks up doc["host_user_fact"] the same way it already does for any other
inline producer.

Never decodes password hashes. Never reads local group membership
(SAM\\Domains\\Builtin\\Aliases) -- documented gap, not this sprint.
"""
from __future__ import annotations

from pathlib import Path
import importlib
import time

from app.ingest.raw_parsers.audit import build_raw_parser_audit
from app.ingest.raw_parsers.base import BaseRawParser
from app.ingest.raw_parsers.models import RawParserResult
from app.ingest.velociraptor.path_utils import normalize_velociraptor_path
from app.ingest.windows.sam_identity import (
    decode_f_value,
    decode_machine_sid,
    decode_rid_from_names_value,
    decode_v_string,
    format_rid_subkey_name,
    format_sid,
    V_COMMENT_HEADER_OFFSET,
    V_FULL_NAME_HEADER_OFFSET,
    V_USERNAME_HEADER_OFFSET,
)

SOURCE_KIND_SAM_ACCOUNT = "sam_account"


def windows_sam_identity_native_available() -> bool:
    try:
        importlib.import_module("Registry.Registry")
        return True
    except Exception:  # noqa: BLE001
        return False


def _load_registry_module():
    return importlib.import_module("Registry.Registry")


def _process_account_key(
    name_key, users_key, machine_sid: str | None, *,
    parser_name: str, case_id: str, evidence_id: str, artifact_id: str,
    normalized_source_path: str, warnings: list[str],
) -> dict | None:
    """Decode one SAM\\...\\Users\\Names\\<username> entry into a single
    inline-tagged document, or None if this specific account could not be
    recovered at all (never raises -- any unexpected failure here must
    never stop the rest of the accounts, or the rest of the evidence,
    from being processed). Field-level failures (F or V unreadable) are
    individually caught below so one bad field never discards an
    otherwise-decodable account -- only a missing username or an
    unresolvable RID subkey skips the account entirely.
    """
    try:
        username = str(name_key.name() or "").strip()
        if not username:
            return None
        values = name_key.values()
        if not values:
            warnings.append("sam_name_entry_missing_rid_value")
            return None
        rid = decode_rid_from_names_value(values[0].value_type())
    except Exception as exc:  # noqa: BLE001
        warnings.append(f"sam_rid_decode_failed: {exc}")
        return None

    try:
        user_key = users_key.subkey(format_rid_subkey_name(rid))
    except Exception as exc:  # noqa: BLE001
        warnings.append(f"sam_user_key_not_found:{username}:{exc}")
        return None

    attributes: dict = {"rid": str(rid)}
    if machine_sid:
        attributes["sid"] = format_sid(machine_sid, rid)

    account_status: str | None = None
    last_logon_at = None
    try:
        f_value = user_key.value("F").value()
        decoded_f = decode_f_value(f_value)
        if "account_status" in decoded_f:
            account_status = decoded_f["account_status"]
            attributes["account_flags"] = ",".join(decoded_f.get("flag_labels") or [])
        if "logon_count" in decoded_f:
            attributes["logon_count"] = str(decoded_f["logon_count"])
        if "bad_password_count" in decoded_f:
            attributes["bad_password_count"] = str(decoded_f["bad_password_count"])
        if decoded_f.get("last_password_set"):
            attributes["last_password_set"] = decoded_f["last_password_set"].isoformat()
        last_logon_at = decoded_f.get("last_logon")
    except Exception as exc:  # noqa: BLE001
        warnings.append(f"sam_f_value_read_failed:{username}:{exc}")

    gecos = None
    try:
        v_value = user_key.value("V").value()
        full_name = decode_v_string(v_value, V_FULL_NAME_HEADER_OFFSET)
        comment = decode_v_string(v_value, V_COMMENT_HEADER_OFFSET)
        gecos = full_name or comment or None
        if full_name and comment and full_name != comment:
            gecos = f"{full_name} ({comment})"
    except Exception as exc:  # noqa: BLE001
        warnings.append(f"sam_v_value_read_failed:{username}:{exc}")

    fact = {
        "source_kind": SOURCE_KIND_SAM_ACCOUNT,
        "username": username,
        "uid": str(rid),
        "id_kind": "rid",
        "gecos": gecos,
        "account_status": account_status,
        "last_login_at": last_logon_at,
        "attributes": attributes,
        "parser": parser_name,
        "source_file": normalized_source_path,
    }
    return _document(
        case_id=case_id, evidence_id=evidence_id, artifact_id=artifact_id,
        source_file=normalized_source_path, fact=fact,
    )


def _document(*, case_id: str, evidence_id: str, artifact_id: str, source_file: str, fact: dict) -> dict:
    from app.ingest.normalizer import base_document

    username = fact.get("username") or "unknown"
    doc = base_document(
        case_id,
        evidence_id,
        artifact_id,
        {},
        {
            "artifact_type": "windows_sam_identity",
            "parser": "windows_sam_identity",
            "source_tool": "native_registry",
            "source_format": "registry_hive",
            "name": "SAM",
            "source_path": source_file,
        },
    )
    doc["event"].update({
        "category": "host",
        "type": "windows_sam_account_observed",
        "action": "windows_sam_account_observed",
        "message": f"SAM local account observed: {username} (RID {fact.get('attributes', {}).get('rid')})",
        "severity": "info",
    })
    doc["host_user_fact"] = fact
    return doc


class WindowsSamIdentityRawParser(BaseRawParser):
    parser_name = "windows_sam_identity"
    artifact_type = "windows_sam_identity"

    def can_parse(self, candidate_or_path: object) -> bool:
        artifact_type = str(getattr(candidate_or_path, "artifact_type", "") or "").lower()
        path = str(getattr(candidate_or_path, "original_path", candidate_or_path) or "").lower()
        normalized = normalize_velociraptor_path(path).lower()
        return artifact_type == "windows_sam_identity" or normalized.endswith("windows\\system32\\config\\sam")

    def parse(self, path: Path, *, case_id: str, evidence_id: str, artifact_id: str, artifact_meta: dict) -> RawParserResult:
        start = time.perf_counter()
        warnings: list[str] = []
        errors: list[str] = []
        events: list[dict] = []
        original_source_path = str(artifact_meta.get("source_path") or path)
        normalized_source_path = str(
            artifact_meta.get("velociraptor_normalized_windows_path")
            or normalize_velociraptor_path(original_source_path)
            or original_source_path
        )

        try:
            registry_module = _load_registry_module()
            hive = registry_module.Registry(str(path))
        except Exception as exc:  # noqa: BLE001
            return RawParserResult(
                parser_name=self.parser_name,
                artifact_type=self.artifact_type,
                source_path=normalized_source_path,
                warnings=warnings,
                errors=[f"sam_hive_dependency_or_open_failed: {exc}"],
                parser_status="failed_unsupported",
                metadata={
                    "parser_selected": self.parser_name,
                    "records_extracted": 0,
                    "warnings": warnings,
                    "errors": [f"sam_hive_dependency_or_open_failed: {exc}"],
                    "reason_if_zero_records": "sam_hive_dependency_or_open_failed",
                    "parse_duration_ms": int((time.perf_counter() - start) * 1000),
                },
            )

        try:
            account_key = hive.root().subkey("SAM").subkey("Domains").subkey("Account")
        except Exception as exc:  # noqa: BLE001
            warnings.append(f"sam_account_key_not_found: {exc}")
            account_key = None

        machine_sid: str | None = None
        if account_key is not None:
            try:
                account_v = account_key.value("V").value()
                machine_sid = decode_machine_sid(account_v)
                if not machine_sid:
                    warnings.append("machine_sid_undecodable")
            except Exception as exc:  # noqa: BLE001
                warnings.append(f"machine_sid_read_failed: {exc}")

        users_key = None
        if account_key is not None:
            try:
                users_key = account_key.subkey("Users")
            except Exception as exc:  # noqa: BLE001
                warnings.append(f"sam_users_key_not_found: {exc}")

        names_subkeys = []
        if users_key is not None:
            try:
                names_subkeys = list(users_key.subkey("Names").subkeys())
            except Exception as exc:  # noqa: BLE001
                warnings.append(f"sam_names_key_not_found: {exc}")

        for name_key in names_subkeys:
            # Outer safety net: _process_account_key() already catches
            # every known failure mode internally (missing username,
            # unresolvable RID subkey, unreadable F/V) and returns None
            # for those -- this wrapper is defense-in-depth against any
            # OTHER unexpected exception, so a single malformed account
            # entry can never abort the rest of the SAM hive, let alone
            # the rest of the evidence's other artifacts.
            try:
                document = _process_account_key(
                    name_key, users_key, machine_sid,
                    parser_name=self.parser_name, case_id=case_id, evidence_id=evidence_id,
                    artifact_id=artifact_id, normalized_source_path=normalized_source_path,
                    warnings=warnings,
                )
            except Exception as exc:  # noqa: BLE001
                warnings.append(f"sam_account_processing_failed: {exc}")
                continue
            if document is not None:
                events.append(document)

        parser_status = "parsed_native" if events else "parsed_empty"
        result = RawParserResult(
            parser_name=self.parser_name,
            artifact_type=self.artifact_type,
            source_path=normalized_source_path,
            records_read=len(events),
            events=events,
            warnings=warnings,
            errors=errors,
            parser_status=parser_status,
            metadata={
                "parser_selected": self.parser_name,
                "records_extracted": len(events),
                "warnings": warnings,
                "errors": errors,
                "parse_duration_ms": int((time.perf_counter() - start) * 1000),
            },
        )
        result.metadata["audit"] = build_raw_parser_audit(result)
        return result
