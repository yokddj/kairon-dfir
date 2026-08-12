"""Windows Host Facts from the SYSTEM registry hive.

Reuses the exact SYSTEM-hive-opening mechanism already proven by
app.ingest.raw_parsers.service_parser (python-registry / Registry.Registry)
-- this is a THIRD independent parser over the same physical SYSTEM hive
file, mirroring how shimcache_raw and windows_service_registry already
both parse it for their own unrelated purposes (see
app.ingest.velociraptor.discovery._detect_priority_registry_raw_candidate,
which registers all three as separate candidates over the same file).

Reads only a small number of well-known, unambiguous values:

- CurrentControlSet\\Control\\ComputerName\\ComputerName\\ComputerName
  -- the NetBIOS/short computer name (host.hostname). No domain suffix
  lives here, so this never produces an FQDN.
- CurrentControlSet\\Control\\TimeZoneInformation\\TimeZoneKeyName
  -- the machine's configured Windows timezone identifier (host.timezone),
  a genuine regional name (e.g. "Romance Standard Time"), never a raw UTC
  offset. Older SYSTEM hives that predate this key (pre-Vista) simply
  produce no timezone fact -- this parser never derives a timezone from
  Bias/DaylightBias/StandardBias alone.
- Software\\Microsoft\\BuildLayers\\DesktopEditions -- a SYSTEM-hive-local
  mirror of Windows Setup's own build labeling (BuildNumber, MajorVersion,
  MinorVersion, BuildArch), independent of and consistent with what
  Volatility's windows.info reports from a memory image of the same
  machine (see app.ingest.windows.memory_host_facts). This is NOT the
  SOFTWARE hive's CurrentVersion key (ProductName/EditionID/DisplayVersion
  live there and are not available here) -- host.distribution is set to
  the literal "Windows" family only, never a marketing edition name.
  Deliberately not read: BuildQfe from this same location, which differs
  across DesktopEditions/OnecoreUAP/OSClient/ShellCommon sub-layers with
  no single one being the canonical "UBR" for the whole system -- picking
  one would be a guess, not an observation.

CurrentControlSet is resolved via Select\\Current (a single, unambiguous
REG_DWORD), not by inspecting every ControlSetNNN and guessing.
"""
from __future__ import annotations

from pathlib import Path
import importlib
import time

from app.ingest.raw_parsers.audit import build_raw_parser_audit
from app.ingest.raw_parsers.base import BaseRawParser
from app.ingest.raw_parsers.models import RawParserResult
from app.ingest.velociraptor.path_utils import normalize_velociraptor_path
from app.ingest.linux.os_info import FACT_ARCHITECTURE, FACT_DISTRIBUTION, FACT_DISTRIBUTION_VERSION, FACT_HOSTNAME
from app.ingest.linux.timezone import FACT_TYPE_TIMEZONE

SOURCE_KIND_COMPUTERNAME = "system_hive_computername"
SOURCE_KIND_TIMEZONE_KEY_NAME = "system_hive_timezone_key_name"
SOURCE_KIND_BUILDLAB = "system_hive_buildlab"

_ARCH_LABELS = {
    "amd64": "x64",
    "x86": "x86",
    "arm64": "ARM64",
    "arm": "ARM",
    "ia64": "IA64",
}


def windows_system_hive_facts_native_available() -> bool:
    try:
        importlib.import_module("Registry.Registry")
        return True
    except Exception:  # noqa: BLE001
        return False


def _load_registry_module():
    return importlib.import_module("Registry.Registry")


def _subkey_by_name(key, name: str):
    for child in key.subkeys():
        try:
            if str(child.name() or "").lower() == name.lower():
                return child
        except Exception:  # noqa: BLE001
            continue
    return None


def _value_by_name(key, name: str):
    for value in key.values():
        try:
            if str(value.name() or "").lower() == name.lower():
                return value.value()
        except Exception:  # noqa: BLE001
            continue
    return None


def _resolve_current_control_set(hive, warnings: list[str]):
    try:
        select = hive.open("Select")
        current = _value_by_name(select, "Current")
        if current is None:
            warnings.append("select_current_missing")
            return None
        control_set_name = f"ControlSet{int(current):03d}"
        control_set = _subkey_by_name(hive.root(), control_set_name)
        if control_set is None:
            warnings.append(f"resolved_control_set_not_found:{control_set_name}")
            return None
        return control_set
    except Exception as exc:  # noqa: BLE001
        warnings.append(f"select_current_resolution_failed:{exc}")
        return None


def _extract_computer_name(control_set, warnings: list[str]) -> str | None:
    try:
        key = control_set.subkey("Control").subkey("ComputerName").subkey("ComputerName")
    except Exception:  # noqa: BLE001
        warnings.append("computername_key_not_found")
        return None
    value = _value_by_name(key, "ComputerName")
    if not isinstance(value, str) or not value.strip():
        warnings.append("computername_value_missing")
        return None
    return value.strip()


def _extract_timezone_key_name(control_set, warnings: list[str]) -> str | None:
    try:
        key = control_set.subkey("Control").subkey("TimeZoneInformation")
    except Exception:  # noqa: BLE001
        warnings.append("timezoneinformation_key_not_found")
        return None
    value = _value_by_name(key, "TimeZoneKeyName")
    if not isinstance(value, str) or not value.strip():
        # Deliberately no fallback to Bias/DaylightBias/StandardBias here --
        # those are raw UTC offsets, not a regional identifier, and this
        # parser must never turn an offset into a named timezone.
        warnings.append("timezonekeyname_missing")
        return None
    return value.strip()


def _extract_build_info(hive, warnings: list[str]) -> dict | None:
    try:
        key = hive.root().subkey("Software").subkey("Microsoft").subkey("BuildLayers").subkey("DesktopEditions")
    except Exception:  # noqa: BLE001
        warnings.append("buildlayers_desktopeditions_key_not_found")
        return None
    build_number = _value_by_name(key, "BuildNumber")
    major = _value_by_name(key, "MajorVersion")
    minor = _value_by_name(key, "MinorVersion")
    arch_raw = _value_by_name(key, "BuildArch")
    if build_number is None or major is None or minor is None:
        warnings.append("buildlayers_desktopeditions_incomplete")
        return None
    return {
        "build_number": str(build_number).strip(),
        "major_version": str(major).strip(),
        "minor_version": str(minor).strip(),
        "arch_raw": str(arch_raw).strip() if arch_raw is not None else None,
    }


def _document(
    *,
    case_id: str,
    evidence_id: str,
    artifact_id: str,
    source_file: str,
    fact_type: str,
    source_kind: str,
    raw_value: str,
    normalized_value: str,
) -> dict:
    from app.ingest.normalizer import base_document

    doc = base_document(
        case_id,
        evidence_id,
        artifact_id,
        {},
        {
            "artifact_type": "windows_system_hive_facts",
            "parser": "windows_system_hive_facts",
            "source_tool": "native_registry",
            "source_format": "registry_hive",
            "name": "SYSTEM",
            "source_path": source_file,
        },
    )
    doc["event"].update(
        {
            "category": "host",
            "type": "windows_system_hive_fact_observed",
            "action": "windows_system_hive_fact_observed",
            "message": f"Windows {fact_type} observation ({source_kind}): {normalized_value}",
            "severity": "info",
        }
    )
    doc["host_fact"] = {
        "fact_type": fact_type,
        "artifact_family": "windows_system_hive_facts",
        "artifact_type": source_kind,
        "source_file": source_file,
        "raw_value": raw_value,
        "normalized_value": normalized_value,
        # The SYSTEM hive's own persisted configuration values, read
        # directly -- the same tier of reliability as Linux's /etc/hostname
        # or /etc/timezone (a genuine on-disk configuration record, not a
        # heuristic or a copy of anything already assigned to this case).
        "confidence": "high",
        "parse_status": "valid",
        "reason": "",
    }
    return doc


class WindowsSystemHiveIdentityRawParser(BaseRawParser):
    parser_name = "windows_system_hive_facts"
    artifact_type = "windows_system_hive_facts"

    def can_parse(self, candidate_or_path: object) -> bool:
        artifact_type = str(getattr(candidate_or_path, "artifact_type", "") or "").lower()
        path = str(getattr(candidate_or_path, "original_path", candidate_or_path) or "").lower()
        normalized = normalize_velociraptor_path(path).lower()
        return artifact_type == "windows_system_hive_facts" or normalized.endswith("windows\\system32\\config\\system")

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
                errors=[f"system_hive_dependency_or_open_failed: {exc}"],
                parser_status="failed_unsupported",
                metadata={
                    "parser_selected": self.parser_name,
                    "records_extracted": 0,
                    "warnings": warnings,
                    "errors": [f"system_hive_dependency_or_open_failed: {exc}"],
                    "reason_if_zero_records": "system_hive_dependency_or_open_failed",
                    "parse_duration_ms": int((time.perf_counter() - start) * 1000),
                },
            )

        control_set = _resolve_current_control_set(hive, warnings)

        if control_set is not None:
            computer_name = _extract_computer_name(control_set, warnings)
            if computer_name:
                events.append(
                    _document(
                        case_id=case_id,
                        evidence_id=evidence_id,
                        artifact_id=artifact_id,
                        source_file=normalized_source_path,
                        fact_type=FACT_HOSTNAME,
                        source_kind=SOURCE_KIND_COMPUTERNAME,
                        raw_value=computer_name,
                        normalized_value=computer_name,
                    )
                )

            timezone_key_name = _extract_timezone_key_name(control_set, warnings)
            if timezone_key_name:
                events.append(
                    _document(
                        case_id=case_id,
                        evidence_id=evidence_id,
                        artifact_id=artifact_id,
                        source_file=normalized_source_path,
                        fact_type=FACT_TYPE_TIMEZONE,
                        source_kind=SOURCE_KIND_TIMEZONE_KEY_NAME,
                        raw_value=timezone_key_name,
                        normalized_value=timezone_key_name,
                    )
                )
        else:
            warnings.append("current_control_set_unresolved_no_hostname_or_timezone")

        build_info = _extract_build_info(hive, warnings)
        if build_info:
            version_raw = f"{build_info['major_version']}.{build_info['minor_version']}.{build_info['build_number']}"
            events.append(
                _document(
                    case_id=case_id,
                    evidence_id=evidence_id,
                    artifact_id=artifact_id,
                    source_file=normalized_source_path,
                    fact_type=FACT_DISTRIBUTION,
                    source_kind=SOURCE_KIND_BUILDLAB,
                    raw_value="Windows",
                    normalized_value="Windows",
                )
            )
            events.append(
                _document(
                    case_id=case_id,
                    evidence_id=evidence_id,
                    artifact_id=artifact_id,
                    source_file=normalized_source_path,
                    fact_type=FACT_DISTRIBUTION_VERSION,
                    source_kind=SOURCE_KIND_BUILDLAB,
                    raw_value=version_raw,
                    normalized_value=version_raw,
                )
            )
            arch_raw = build_info.get("arch_raw")
            if arch_raw:
                arch_label = _ARCH_LABELS.get(arch_raw.lower(), arch_raw)
                events.append(
                    _document(
                        case_id=case_id,
                        evidence_id=evidence_id,
                        artifact_id=artifact_id,
                        source_file=normalized_source_path,
                        fact_type=FACT_ARCHITECTURE,
                        source_kind=SOURCE_KIND_BUILDLAB,
                        raw_value=arch_raw,
                        normalized_value=arch_label,
                    )
                )

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
