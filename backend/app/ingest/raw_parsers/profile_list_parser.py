"""Windows profile-path corroborating evidence from the SOFTWARE registry
hive's ProfileList key.

ProfileList (SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\ProfileList)
records one entry per profile Windows has ever loaded on this machine,
keyed by SID -- but a SID here is NOT proof of a local account: domain
accounts that logged on interactively get a cached profile here too, under
their own domain's SID, which for a domain-joined machine has a completely
different authority than this machine's own SAM SID (verified against a
real case during this sprint's audit -- see the delivery report).

This producer therefore NEVER creates a Host User Facts entry by itself.
It emits one "profile_list" observation per ProfileList SID, carrying the
SID and the profile path but no username -- app.services.host_users
.resolve_host_users() is the only place that may attach one of these to an
account, and only when the SID's local RID matches a SAM account's own
RID AND the SID's authority (everything before the RID) matches the SAM
account's own machine SID (attributes.sid, computed by
app.ingest.raw_parsers.sam_identity_parser). A ProfileList SID whose
authority does not match is simply never surfaced in Local Accounts --
still fully searchable via the raw artifact index, exactly like any other
parsed registry data, just not folded into the account inventory.
"""
from __future__ import annotations

from pathlib import Path
import importlib
import time

from app.ingest.raw_parsers.audit import build_raw_parser_audit
from app.ingest.raw_parsers.base import BaseRawParser
from app.ingest.raw_parsers.models import RawParserResult
from app.ingest.velociraptor.path_utils import normalize_velociraptor_path

SOURCE_KIND_PROFILE_LIST = "profile_list"
_PROFILE_LIST_KEY_PATH = ("Microsoft", "Windows NT", "CurrentVersion", "ProfileList")

# Well-known service SIDs whose ProfileList entry is never a human local
# account -- excluding them here is a documented allowlist of SIDs Windows
# itself defines, not a guess about this specific machine.
_SERVICE_SIDS = {"S-1-5-18", "S-1-5-19", "S-1-5-20"}


def windows_profile_list_native_available() -> bool:
    try:
        importlib.import_module("Registry.Registry")
        return True
    except Exception:  # noqa: BLE001
        return False


def _load_registry_module():
    return importlib.import_module("Registry.Registry")


def _document(*, case_id: str, evidence_id: str, artifact_id: str, source_file: str, fact: dict) -> dict:
    from app.ingest.normalizer import base_document

    sid = fact.get("attributes", {}).get("sid")
    doc = base_document(
        case_id,
        evidence_id,
        artifact_id,
        {},
        {
            "artifact_type": "windows_profile_list",
            "parser": "windows_profile_list",
            "source_tool": "native_registry",
            "source_format": "registry_hive",
            "name": "SOFTWARE",
            "source_path": source_file,
        },
    )
    doc["event"].update({
        "category": "host",
        "type": "windows_profile_list_entry_observed",
        "action": "windows_profile_list_entry_observed",
        "message": f"ProfileList entry observed: {sid} -> {fact.get('home')}",
        "severity": "info",
    })
    doc["host_user_fact"] = fact
    return doc


class WindowsProfileListRawParser(BaseRawParser):
    parser_name = "windows_profile_list"
    artifact_type = "windows_profile_list"

    def can_parse(self, candidate_or_path: object) -> bool:
        artifact_type = str(getattr(candidate_or_path, "artifact_type", "") or "").lower()
        path = str(getattr(candidate_or_path, "original_path", candidate_or_path) or "").lower()
        normalized = normalize_velociraptor_path(path).lower()
        return artifact_type == "windows_profile_list" or normalized.endswith("windows\\system32\\config\\software")

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
                errors=[f"software_hive_dependency_or_open_failed: {exc}"],
                parser_status="failed_unsupported",
                metadata={
                    "parser_selected": self.parser_name,
                    "records_extracted": 0,
                    "warnings": warnings,
                    "errors": [f"software_hive_dependency_or_open_failed: {exc}"],
                    "reason_if_zero_records": "software_hive_dependency_or_open_failed",
                    "parse_duration_ms": int((time.perf_counter() - start) * 1000),
                },
            )

        try:
            key = hive.root()
            for part in _PROFILE_LIST_KEY_PATH:
                key = key.subkey(part)
            sid_subkeys = list(key.subkeys())
        except Exception as exc:  # noqa: BLE001
            warnings.append(f"profilelist_key_not_found: {exc}")
            sid_subkeys = []

        for sid_key in sid_subkeys:
            try:
                sid = str(sid_key.name() or "").strip()
            except Exception:  # noqa: BLE001
                continue
            if not sid or sid in _SERVICE_SIDS:
                continue
            profile_path = None
            state = None
            for value in sid_key.values():
                try:
                    name = str(value.name() or "")
                except Exception:  # noqa: BLE001
                    continue
                if name.lower() == "profileimagepath":
                    raw = value.value()
                    profile_path = str(raw).strip() if raw else None
                elif name.lower() == "state":
                    try:
                        state = int(value.value())
                    except Exception:  # noqa: BLE001
                        state = None
            if not profile_path:
                warnings.append(f"profilelist_entry_missing_path:{sid}")
                continue
            attributes = {"sid": sid}
            if state is not None:
                attributes["profile_state"] = str(state)
            fact = {
                "source_kind": SOURCE_KIND_PROFILE_LIST,
                "username": None,
                "home": profile_path,
                "attributes": attributes,
                "parser": self.parser_name,
                "source_file": normalized_source_path,
            }
            events.append(_document(
                case_id=case_id,
                evidence_id=evidence_id,
                artifact_id=artifact_id,
                source_file=normalized_source_path,
                fact=fact,
            ))

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
