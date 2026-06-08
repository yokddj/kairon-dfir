from __future__ import annotations

from collections.abc import Iterable
from dataclasses import dataclass
from datetime import UTC
import hashlib
import re
from pathlib import Path
import subprocess
from typing import Any
from urllib.parse import unquote

from app.core.storage import build_evidence_root, evidence_staging_dir, sanitize_relative_path


PARSER_NAME = "registry_persistence_summary"
REGISTRY_ARTIFACT_TYPE = "registry_persistence"
HIVE_BASENAMES = {"software", "system", "ntuser.dat", "usrclass.dat"}
USER_PROFILE_RE = re.compile(r"(?:^|/|\\)Users(?:/|\\)([^/\\]+)(?:/|\\)", re.IGNORECASE)
SUSPICIOUS_LOLBINS = {
    "bitsadmin.exe",
    "certutil.exe",
    "cmd.exe",
    "cscript.exe",
    "mshta.exe",
    "powershell.exe",
    "pwsh.exe",
    "regsvr32.exe",
    "rundll32.exe",
    "schtasks.exe",
    "wscript.exe",
}
USER_WRITABLE_TOKENS = (
    "\\users\\",
    "\\appdata\\",
    "\\downloads\\",
    "\\desktop\\",
    "\\temp\\",
    "\\users\\public\\",
    "\\programdata\\",
)


@dataclass(frozen=True)
class HiveSource:
    hive: str
    source_path: str
    local_path: Path
    root_key: str
    user_hint: str | None = None
    user_sid: str | None = None


def registry_reader_available() -> bool:
    try:
        from Registry import Registry as _Registry  # noqa: F401

        return True
    except Exception:
        return False


def detect_registry_persistence_backend() -> dict[str, Any]:
    if registry_reader_available():
        return {"available": True, "backend": "python-registry", "parser": PARSER_NAME}
    return {"available": False, "backend": "python-registry", "parser": PARSER_NAME, "error": "python-registry is not installed"}


def discover_registry_hives(*, case_id: str, evidence_id: str, metadata: dict[str, Any], manifest: dict[str, Any]) -> list[HiveSource]:
    candidates = _candidate_entries(metadata, manifest)
    sources: list[HiveSource] = []
    seen: set[str] = set()
    for entry in candidates:
        source_path = _entry_path(entry)
        basename = _basename(source_path)
        if basename not in HIVE_BASENAMES:
            continue
        local_path = _resolve_local_path(case_id, evidence_id, source_path)
        if not local_path or not local_path.is_file():
            continue
        key = str(local_path.resolve())
        if key in seen:
            continue
        seen.add(key)
        hive_name = "NTUSER.DAT" if basename == "ntuser.dat" else "UsrClass.dat" if basename == "usrclass.dat" else basename.upper()
        root_key = "HKCU" if basename in {"ntuser.dat", "usrclass.dat"} else "HKLM"
        sources.append(HiveSource(hive=hive_name, source_path=source_path, local_path=local_path, root_key=root_key, user_hint=_infer_user_hint(source_path)))
    return sources


def iter_registry_persistence_batches(
    *,
    case_id: str,
    evidence_id: str,
    artifact_id: str,
    artifact_meta: dict[str, Any],
    metadata: dict[str, Any],
    manifest: dict[str, Any],
    batch_size: int,
) -> Iterable[tuple[list[dict[str, Any]], dict[str, Any]]]:
    backend = detect_registry_persistence_backend()
    if not backend.get("available"):
        raise RuntimeError(str(backend.get("error") or "Registry backend is not available"))
    hives = discover_registry_hives(case_id=case_id, evidence_id=evidence_id, metadata=metadata, manifest=manifest)
    records_indexed = 0
    keys_scanned = 0
    errors: list[str] = []
    batch: list[dict[str, Any]] = []
    host = str(artifact_meta.get("detected_host") or artifact_meta.get("provided_host") or "").strip() or None
    for hive_index, hive in enumerate(hives, start=1):
        try:
            for row in _extract_hive_rows(hive):
                keys_scanned += 1
                doc = _build_document(case_id, evidence_id, artifact_id, artifact_meta, hive, row, host)
                batch.append(doc)
                records_indexed += 1
                if len(batch) >= batch_size:
                    yield batch, _progress(backend, hives, hive_index, keys_scanned, records_indexed, hive, errors)
                    batch = []
        except Exception as exc:  # noqa: BLE001
            errors.append(f"{hive.source_path}: {exc.__class__.__name__}: {exc}")
        yield [], _progress(backend, hives, hive_index, keys_scanned, records_indexed, hive, errors)
    if batch:
        yield batch, _progress(backend, hives, len(hives), keys_scanned, records_indexed, hives[-1] if hives else None, errors)
    if not hives:
        yield [], _progress(backend, hives, 0, keys_scanned, records_indexed, None, errors)


def _candidate_entries(metadata: dict[str, Any], manifest: dict[str, Any]) -> list[dict[str, Any]]:
    discovery = dict(metadata.get("velociraptor_discovery") or {})
    ingest_plan = dict(metadata.get("ingest_plan") or {})
    entries: list[dict[str, Any]] = []
    for container in (
        manifest.get("artifacts") or [],
        manifest.get("files") or [],
        discovery.get("candidates") or [],
        metadata.get("folder_entries") or [],
        ingest_plan.get("disabled_candidates") or [],
    ):
        if isinstance(container, list):
            entries.extend(item for item in container if isinstance(item, dict))
    return entries


def _entry_path(entry: dict[str, Any]) -> str:
    return str(entry.get("source_path") or entry.get("relative_path") or entry.get("path") or entry.get("original_path") or entry.get("display_name") or entry.get("name") or "")


def _basename(path: str) -> str:
    return unquote(path).replace("/", "\\").rstrip("\\").rsplit("\\", 1)[-1].lower()


def _resolve_local_path(case_id: str, evidence_id: str, source_path: str) -> Path | None:
    if not source_path:
        return None
    raw_candidates = [source_path, unquote(source_path)]
    root = build_evidence_root(case_id, evidence_id)
    bases = [evidence_staging_dir(case_id, evidence_id), root / "extracted", root / "original_folder", root / "original", root]
    for raw in raw_candidates:
        try:
            relative = sanitize_relative_path(raw)
        except ValueError:
            continue
        for base in bases:
            candidate = base / relative
            if candidate.is_file():
                return candidate
        extracted = _extract_from_original_archive(root, relative)
        if extracted and extracted.is_file():
            return extracted
    basename = _basename(source_path)
    if basename:
        for base in bases[:3]:
            for candidate in base.rglob("*"):
                if candidate.is_file() and candidate.name.lower() == basename:
                    return candidate
    return None


def _extract_from_original_archive(root: Path, relative: Path) -> Path | None:
    archive_dir = root / "original"
    archives = sorted(path for path in archive_dir.glob("*") if path.is_file() and path.suffix.lower() in {".zip", ".7z"})
    if not archives:
        return None
    extract_dir = root / "derived" / "registry_persistence_hives" / hashlib.sha1(str(relative).encode("utf-8", "ignore")).hexdigest()[:16]
    target = extract_dir / relative.name
    if target.is_file():
        return target
    extract_dir.mkdir(parents=True, exist_ok=True)
    for archive_path in archives:
        try:
            result = subprocess.run(
                ["7z", "e", str(archive_path), str(relative), f"-o{extract_dir}", "-y"],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                timeout=600,
                check=False,
            )
        except Exception:
            continue
        if result.returncode == 0 and target.is_file():
            return target
    return None


def _infer_user_hint(source_path: str) -> str | None:
    match = USER_PROFILE_RE.search(unquote(source_path))
    if not match:
        return None
    user = match.group(1).strip()
    if user.lower() in {"default", "public", "all users", "systemprofile", "localservice", "networkservice"}:
        return None
    return user


def _extract_hive_rows(hive: HiveSource) -> Iterable[dict[str, Any]]:
    from Registry import Registry

    reg = Registry.Registry(str(hive.local_path))
    if hive.hive == "SOFTWARE":
        yield from _extract_values(reg, hive, "Microsoft\\Windows\\CurrentVersion\\Run", "autorun", "HKLM Run")
        yield from _extract_values(reg, hive, "Microsoft\\Windows\\CurrentVersion\\RunOnce", "autorun", "HKLM RunOnce")
        yield from _extract_values(reg, hive, "Microsoft\\Windows\\CurrentVersion\\Policies\\Explorer\\Run", "autorun", "HKLM Policies Explorer Run")
        yield from _extract_values(reg, hive, "WOW6432Node\\Microsoft\\Windows\\CurrentVersion\\Run", "autorun", "HKLM WOW6432Node Run")
        yield from _extract_values(reg, hive, "WOW6432Node\\Microsoft\\Windows\\CurrentVersion\\RunOnce", "autorun", "HKLM WOW6432Node RunOnce")
        yield from _extract_values(reg, hive, "Microsoft\\Windows NT\\CurrentVersion\\Winlogon", "winlogon", "Winlogon", value_names={"Shell", "Userinit", "GinaDLL"})
        yield from _extract_values(reg, hive, "Microsoft\\Windows NT\\CurrentVersion\\Windows", "appinit", "AppInit / Windows Load", value_names={"AppInit_DLLs", "LoadAppInit_DLLs", "Load", "Run"})
        yield from _extract_ifeo(reg, hive)
        yield from _extract_task_cache(reg, hive)
        yield from _extract_defender(reg, hive)
        yield from _extract_active_setup(reg, hive, "Microsoft\\Active Setup\\Installed Components", "HKLM Active Setup")
    elif hive.hive == "SYSTEM":
        control_set = _current_control_set(reg)
        yield from _extract_services(reg, hive, f"{control_set}\\Services")
        yield from _extract_values(reg, hive, f"{control_set}\\Control\\Terminal Server", "rdp", "Terminal Server", value_names={"fDenyTSConnections"})
        yield from _extract_values(reg, hive, f"{control_set}\\Control\\Terminal Server\\WinStations\\RDP-Tcp", "rdp", "RDP-Tcp", value_names={"UserAuthentication", "PortNumber"})
    elif hive.hive in {"NTUSER.DAT", "UsrClass.dat"}:
        yield from _extract_values(reg, hive, "Software\\Microsoft\\Windows\\CurrentVersion\\Run", "autorun", "HKCU Run")
        yield from _extract_values(reg, hive, "Software\\Microsoft\\Windows\\CurrentVersion\\RunOnce", "autorun", "HKCU RunOnce")
        yield from _extract_values(reg, hive, "Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\Explorer\\Run", "autorun", "HKCU Policies Explorer Run")
        yield from _extract_active_setup(reg, hive, "Software\\Microsoft\\Active Setup\\Installed Components", "HKCU Active Setup")


def _open_key(reg: Any, key_path: str) -> Any | None:
    try:
        return reg.open(key_path)
    except Exception:
        return None


def _extract_values(reg: Any, hive: HiveSource, key_path: str, category: str, mechanism: str, *, value_names: set[str] | None = None) -> Iterable[dict[str, Any]]:
    key = _open_key(reg, key_path)
    if not key:
        return
    for value in key.values():
        value_name = str(value.name() or "(Default)")
        if value_names and value_name not in value_names:
            continue
        yield _row(hive, key_path, value_name, _value_type(value), _value_data(value), category, mechanism, _last_write(key))


def _extract_ifeo(reg: Any, hive: HiveSource) -> Iterable[dict[str, Any]]:
    base = "Microsoft\\Windows NT\\CurrentVersion\\Image File Execution Options"
    key = _open_key(reg, base)
    if not key:
        return
    for subkey in key.subkeys():
        sub_path = f"{base}\\{subkey.name()}"
        for value in subkey.values():
            value_name = str(value.name() or "(Default)")
            if value_name in {"Debugger", "GlobalFlag"}:
                yield _row(hive, sub_path, value_name, _value_type(value), _value_data(value), "ifeo", f"IFEO {value_name}", _last_write(subkey))
        silent = _open_key(reg, f"Microsoft\\Windows NT\\CurrentVersion\\SilentProcessExit\\{subkey.name()}")
        if silent:
            for value in silent.values():
                yield _row(hive, f"Microsoft\\Windows NT\\CurrentVersion\\SilentProcessExit\\{subkey.name()}", str(value.name() or "(Default)"), _value_type(value), _value_data(value), "ifeo", "SilentProcessExit", _last_write(silent))


def _extract_task_cache(reg: Any, hive: HiveSource) -> Iterable[dict[str, Any]]:
    for base in ("Microsoft\\Windows NT\\CurrentVersion\\Schedule\\TaskCache\\Tree", "Microsoft\\Windows NT\\CurrentVersion\\Schedule\\TaskCache\\Tasks"):
        key = _open_key(reg, base)
        if not key:
            continue
        for subkey in _walk_subkeys(key, base):
            for value in subkey["key"].values():
                yield _row(hive, subkey["path"], str(value.name() or "(Default)"), _value_type(value), _value_data(value), "task_cache", "Scheduled Task Cache", _last_write(subkey["key"]))


def _extract_defender(reg: Any, hive: HiveSource) -> Iterable[dict[str, Any]]:
    for key_path, mechanism in (
        ("Microsoft\\Windows Defender\\Exclusions\\Paths", "Defender path exclusion"),
        ("Microsoft\\Windows Defender\\Exclusions\\Processes", "Defender process exclusion"),
        ("Microsoft\\Windows Defender\\Exclusions\\Extensions", "Defender extension exclusion"),
        ("Microsoft\\Windows Defender\\Real-Time Protection", "Defender real-time configuration"),
        ("Policies\\Microsoft\\Windows Defender", "Defender policy"),
    ):
        yield from _extract_values(reg, hive, key_path, "defender_exclusion", mechanism)


def _extract_active_setup(reg: Any, hive: HiveSource, base: str, mechanism: str) -> Iterable[dict[str, Any]]:
    key = _open_key(reg, base)
    if not key:
        return
    for subkey in key.subkeys():
        sub_path = f"{base}\\{subkey.name()}"
        for value in subkey.values():
            value_name = str(value.name() or "(Default)")
            if value_name in {"StubPath", "Localized Name", "Version", "IsInstalled"}:
                yield _row(hive, sub_path, value_name, _value_type(value), _value_data(value), "active_setup", mechanism, _last_write(subkey))


def _extract_services(reg: Any, hive: HiveSource, services_path: str) -> Iterable[dict[str, Any]]:
    key = _open_key(reg, services_path)
    if not key:
        return
    for service_key in key.subkeys():
        service_path = f"{services_path}\\{service_key.name()}"
        wanted = {"ImagePath", "Start", "Type", "ObjectName", "DisplayName", "Description"}
        for value in service_key.values():
            if str(value.name() or "") in wanted:
                yield _row(hive, service_path, str(value.name() or "(Default)"), _value_type(value), _value_data(value), "service", f"Service {service_key.name()}", _last_write(service_key))
        params = _open_key(reg, f"{service_path}\\Parameters")
        if params:
            for value in params.values():
                if str(value.name() or "") == "ServiceDll":
                    yield _row(hive, f"{service_path}\\Parameters", "ServiceDll", _value_type(value), _value_data(value), "service", f"ServiceDll {service_key.name()}", _last_write(params))


def _walk_subkeys(key: Any, key_path: str) -> Iterable[dict[str, Any]]:
    yield {"key": key, "path": key_path}
    for subkey in key.subkeys():
        yield from _walk_subkeys(subkey, f"{key_path}\\{subkey.name()}")


def _current_control_set(reg: Any) -> str:
    select = _open_key(reg, "Select")
    if select:
        for value in select.values():
            if str(value.name() or "") == "Current":
                try:
                    return f"ControlSet{int(value.value()):03d}"
                except Exception:
                    break
    return "ControlSet001"


def _row(hive: HiveSource, key_path: str, value_name: str, value_type: str, value_data: str, category: str, mechanism: str, last_write: str | None) -> dict[str, Any]:
    return {
        "hive": hive.hive,
        "root_key": hive.root_key,
        "key_path": key_path,
        "value_name": value_name,
        "value_type": value_type,
        "value_data": value_data,
        "category": category,
        "persistence_mechanism": mechanism,
        "last_write": last_write,
    }


def _value_type(value: Any) -> str:
    try:
        return str(value.value_type_str())
    except Exception:
        return str(getattr(value, "value_type", "") or "unknown")


def _value_data(value: Any) -> str:
    try:
        data = value.value()
    except Exception:
        return ""
    if isinstance(data, bytes):
        return data.hex()
    if isinstance(data, (list, tuple)):
        return "; ".join(str(item) for item in data)
    return str(data)


def _last_write(key: Any) -> str | None:
    try:
        value = key.timestamp()
        if value.tzinfo is None:
            value = value.replace(tzinfo=UTC)
        return value.astimezone(UTC).isoformat()
    except Exception:
        return None


def _build_document(case_id: str, evidence_id: str, artifact_id: str, artifact_meta: dict[str, Any], hive: HiveSource, row: dict[str, Any], host: str | None) -> dict[str, Any]:
    full_key = f"{row['root_key']}\\{row['key_path']}"
    value_data = str(row.get("value_data") or "")
    value_summary = _clip(value_data, 512)
    key_entity = f"{full_key}\\{row['value_name']}"
    risk_level, risk_score, risk_reasons = _risk(row)
    event_id = _stable_id(case_id, evidence_id, hive.source_path, row.get("key_path"), row.get("value_name"), value_data)
    user_name = hive.user_hint if hive.root_key == "HKCU" else None
    snippet = f"{row['persistence_mechanism']}: {row['value_name']} -> {value_summary or '(empty)'}"
    tags = ["registry", "persistence", str(row["category"])]
    if risk_score >= 50:
        tags.append("suspicious")
    return {
        "event_id": event_id,
        "case_id": case_id,
        "evidence_id": evidence_id,
        "artifact_id": artifact_id,
        "source_file": hive.source_path,
        "source_tool": "python-registry",
        "source_format": "registry_hive",
        "@timestamp": row.get("last_write"),
        "timestamp_precision": "key_last_write" if row.get("last_write") else None,
        "timestamp_semantics": "registry_key_last_write",
        "timezone": "UTC" if row.get("last_write") else None,
        "os": {"type": "windows", "version": None},
        "host": {"name": host, "hostname": host, "ip": [], "os": "Windows"},
        "user": {"name": user_name, "sid": hive.user_sid},
        "artifact": {"type": REGISTRY_ARTIFACT_TYPE, "name": "Registry Persistence Summary", "source_path": hive.source_path, "parser": PARSER_NAME},
        "event": {
            "category": "persistence",
            "type": "registry_persistence_value_observed",
            "action": "registry_persistence_value_observed",
            "severity": risk_level,
            "message": snippet,
            "timeline_include": True,
        },
        "registry": {
            "hive": hive.hive,
            "hive_path": hive.source_path,
            "root_key": row["root_key"],
            "key_path": full_key,
            "relative_key_path": row["key_path"],
            "value_name": row["value_name"],
            "value_type": row["value_type"],
            "value_data": value_data,
            "value_data_summary": value_summary,
            "category": row["category"],
            "persistence_mechanism": row["persistence_mechanism"],
            "last_write": row.get("last_write"),
            "timestamp_semantics": "registry_key_last_write",
            "source": "hive",
            "parser": PARSER_NAME,
        },
        "persistence": {
            "name": row["value_name"],
            "category": row["category"],
            "mechanism": row["persistence_mechanism"],
            "path": value_data,
            "command": value_data,
            "source": "registry_hive",
            "last_modified": row.get("last_write"),
            "timestamp_semantics": "registry_key_last_write",
            "user": user_name,
        },
        "process": {"name": _process_name(value_data), "path": None, "command_line": value_data or None},
        "file": {"path": _path_like(value_data), "name": Path(_path_like(value_data) or "").name or None},
        "key_entity": key_entity,
        "key_entity_type": "registry_value",
        "snippet": snippet,
        "summary": snippet,
        "risk_score": risk_score,
        "risk": {"level": risk_level, "reasons": risk_reasons},
        "risk_reasons": risk_reasons,
        "suspicious_reasons": risk_reasons,
        "tags": tags,
        "data_quality": ["registry_key_last_write_not_value_modification_time"],
        "raw_summary": snippet,
        "search_text": " | ".join(str(part or "") for part in (full_key, row["value_name"], value_data, row["category"], row["persistence_mechanism"], user_name, host)),
        "raw_payload": {"key_path": full_key, "value_name": row["value_name"], "value_type": row["value_type"], "value_data": value_data, "last_write": row.get("last_write")},
        "raw": {"registry": row, "hive": hive.source_path},
    }


def _risk(row: dict[str, Any]) -> tuple[str, int, list[str]]:
    value_data = str(row.get("value_data") or "")
    lowered = value_data.lower()
    category = str(row.get("category") or "")
    reasons: list[str] = []
    score = 15
    if category in {"autorun", "winlogon", "ifeo", "appinit", "defender_exclusion"}:
        score += 20
        reasons.append(f"{category}_persistence_mechanism")
    if category == "service":
        score += 10
        reasons.append("service_configuration")
    if any(token in lowered for token in USER_WRITABLE_TOKENS):
        score += 30
        reasons.append("user_writable_path")
    if any(name in lowered for name in SUSPICIOUS_LOLBINS):
        score += 25
        reasons.append("lolbin_or_script_launcher")
    if "-enc" in lowered or "encodedcommand" in lowered:
        score += 25
        reasons.append("encoded_powershell")
    if lowered.startswith("\\\\"):
        score += 20
        reasons.append("unc_path")
    if "http://" in lowered or "https://" in lowered:
        score += 20
        reasons.append("url_in_registry_value")
    if category == "defender_exclusion":
        score += 20
        reasons.append("defender_configuration")
    if category == "rdp":
        score = max(score, 25)
        reasons.append("remote_access_configuration")
    if not reasons:
        reasons.append("registry_persistence_candidate")
    score = min(score, 100)
    level = "high" if score >= 70 else "medium" if score >= 40 else "low"
    return level, score, sorted(set(reasons))


def _process_name(value: str) -> str | None:
    match = re.search(r"([A-Za-z0-9_.-]+\.exe)\b", value or "", re.IGNORECASE)
    return match.group(1) if match else None


def _path_like(value: str) -> str | None:
    match = re.search(r"([A-Za-z]:\\[^\s\"']+)", value or "")
    return match.group(1) if match else None


def _clip(value: str, limit: int) -> str:
    text = str(value or "").replace("\x00", "").strip()
    return text if len(text) <= limit else f"{text[: limit - 1].rstrip()}…"


def _stable_id(*parts: Any) -> str:
    digest = hashlib.sha256("|".join(str(part or "") for part in parts).encode("utf-8", errors="ignore")).hexdigest()
    return f"registry-persistence-{digest[:32]}"


def _progress(backend: dict[str, Any], hives: list[HiveSource], hives_done: int, keys_scanned: int, records_indexed: int, current_hive: HiveSource | None, errors: list[str]) -> dict[str, Any]:
    return {
        "backend": backend.get("backend") or "python-registry",
        "backend_version": backend.get("version") or "",
        "hives_total": len(hives),
        "hives_processed": hives_done,
        "hives_failed": len(errors),
        "keys_scanned": keys_scanned,
        "records_indexed": records_indexed,
        "current_hive": current_hive.hive if current_hive else None,
        "current_key": None,
        "errors": errors[:20],
    }
