from __future__ import annotations

from dataclasses import asdict, dataclass
from pathlib import PureWindowsPath
import re
from typing import Any, Iterable


PLACEHOLDER_VALUES = {"", "-", "--", "0x", "0x0", "0x00", "0x00000000", "null", "none", "n/a", "na", "unknown", "{}", "[]"}
SYSTEM_SIDS = {"s-1-5-18", "s-1-5-19", "s-1-5-20"}
LOCALIZED_PAYLOAD_TOKENS = (
    "gravedad =",
    "nombre de host =",
    "versión de host =",
    "version de host =",
    "aplicación host =",
    "aplicacion host =",
    "usuario =",
)
PAYLOAD_TOKENS = (
    "eventdata",
    "contextinfo",
    "hostapplication=",
    "host application =",
    "scriptblocktext",
    "payloaddata",
    "payload:",
    "<event",
    "<eventdata",
    "data name=",
    "\"@name\"",
    "\"\"@name\"\"",
) + LOCALIZED_PAYLOAD_TOKENS
GENERIC_USER_NAMES = {"system", "local service", "network service", "nt authority\\system"}
WINDOWS_PATH_RE = re.compile(r"(?i)([a-z]:\\[^\r\n\"'<>|]+|\\\\[^\r\n\"'<>|]+)")
SCRIPT_OR_EXECUTABLE_RE = re.compile(r"(?i)([a-z]:\\[^\r\n\"'<>|]+\.(?:ps1|psm1|psd1|exe|bat|cmd|js|vbs|dll|msc|msi))")
REGISTRY_PATH_RE = re.compile(r"(?i)\b(?:HKLM|HKCU|HKCR|HKU|HKCC):?\\[^\r\n\"']+")
URL_RE = re.compile(r"(?i)\bhttps?://[^\s\"'<>]+")
DOMAIN_RE = re.compile(r"(?i)\b(?:[a-z0-9-]+\.)+[a-z]{2,63}\b")
IP_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
EMAIL_RE = re.compile(r"(?i)\b[a-z0-9._%+-]+@[a-z0-9.-]+\.[a-z]{2,63}\b")


@dataclass(frozen=True)
class NormalizedField:
    value: str
    quality: str = "clean"
    source: str = ""
    confidence: str = "unknown"

    def as_dict(self) -> dict[str, str]:
        return asdict(self)


def normalize_event_fields(document: dict[str, Any]) -> dict[str, Any]:
    """Apply presentation-safe field quality rules to any event document."""
    warnings: list[str] = list(document.get("field_quality_warnings") or [])
    raw_payload = collect_raw_payload(document)
    if raw_payload:
        document.setdefault("normalized_raw_payload", raw_payload)

    user = document.setdefault("user", {})
    if isinstance(user, dict):
        cleaned_user = clean_user(user.get("name"), raw_fields=document)
        if cleaned_user.value:
            if user.get("name") != cleaned_user.value:
                warnings.append(f"user_{cleaned_user.quality}")
            user["name"] = cleaned_user.value
            user.setdefault("confidence", cleaned_user.confidence)
        else:
            if user.get("name"):
                warnings.append(cleaned_user.quality)
            user["name"] = None
            user.setdefault("confidence", "unknown")

    key_entity = clean_key_entity(document.get("key_entity"), raw_fields=document, artifact_type=_artifact_type(document), event_type=_event_type(document))
    if not key_entity.value:
        key_entity = choose_best_key_entity(_key_entity_candidates(document), {"artifact_type": _artifact_type(document), "event_type": _event_type(document)})
        warnings.append(key_entity.quality)
    elif key_entity.value != document.get("key_entity"):
        warnings.append(key_entity.quality)
    if key_entity.value:
        document["key_entity"] = key_entity.value
        document["key_entity_quality"] = key_entity.quality
        document["key_entity_confidence"] = key_entity.confidence

    command = _current_command(document)
    cleaned_command = clean_command(command, raw_fields=document)
    if cleaned_command.value:
        _set_command(document, cleaned_command.value)
        if command and command != cleaned_command.value:
            warnings.append(cleaned_command.quality)

    snippet_source = _event_message(document) or document.get("search_text") or raw_payload
    snippet = clean_snippet(snippet_source, raw_fields=document)
    if snippet.value:
        document["snippet"] = snippet.value

    if warnings:
        document["field_quality_warnings"] = sorted(set(warnings))
    return document


def clean_user(value: Any, raw_fields: dict[str, Any] | None = None) -> NormalizedField:
    text = _clean(value)
    if not text:
        extracted = _extract_user_from_context(raw_fields or {})
        if extracted:
            return NormalizedField(extracted, "fallback", "raw_fields", "medium")
        return NormalizedField("-", "unknown", "", "unknown")
    if is_placeholder(text):
        return NormalizedField("-", "placeholder_rejected", "input", "unknown")
    if is_payload_blob(text) or is_probably_command(text) or is_probably_path(text):
        extracted = _extract_user_from_context(raw_fields or {})
        if extracted:
            return NormalizedField(extracted, "fallback", "raw_fields", "medium")
        return NormalizedField("-", "raw_payload_rejected", "input", "unknown")
    if is_probably_user(text):
        return NormalizedField(text, "clean", "input", "high")
    extracted_from_path = _extract_user_from_path(text)
    if extracted_from_path:
        return NormalizedField(extracted_from_path, "fallback", "path", "medium")
    return NormalizedField("-", "raw_payload_rejected", "input", "unknown")


def clean_key_entity(value: Any, raw_fields: dict[str, Any] | None = None, artifact_type: str | None = None, event_type: str | None = None, allow_payload_extract: bool = True) -> NormalizedField:
    text = _clean(value)
    if not text:
        return NormalizedField("", "unknown", "", "unknown")
    if is_placeholder(text):
        return NormalizedField("", "placeholder_rejected", "input", "unknown")
    if is_payload_blob(text):
        if not allow_payload_extract:
            return NormalizedField("", "raw_payload_rejected", "input", "unknown")
        extracted = choose_best_key_entity(_raw_extraction_candidates(text), {"artifact_type": artifact_type, "event_type": event_type})
        if extracted.value:
            return NormalizedField(extracted.value, "fallback", "payload_extraction", extracted.confidence)
        return NormalizedField("", "raw_payload_rejected", "input", "unknown")
    if len(text) > 220 and not (is_probably_command(text) or is_probably_path(text) or URL_RE.search(text)):
        return NormalizedField("", "raw_payload_rejected", "input", "unknown")
    return NormalizedField(_short_value(text), "clean", "input", "high")


def clean_command(value: Any, raw_fields: dict[str, Any] | None = None) -> NormalizedField:
    text = _clean(value)
    if not text or is_placeholder(text):
        fallback = choose_best_key_entity(_command_candidates(raw_fields or {}), {"event_type": _event_type(raw_fields or {})})
        return NormalizedField(fallback.value, "placeholder_rejected" if text else "unknown", fallback.source, fallback.confidence)
    if is_payload_blob(text):
        fallback = choose_best_key_entity(_command_candidates(raw_fields or {}) + _raw_extraction_candidates(text), {"event_type": _event_type(raw_fields or {})})
        return NormalizedField(fallback.value, "raw_payload_rejected", fallback.source, fallback.confidence)
    return NormalizedField(_one_line(text, 512), "clean", "input", "high" if is_probably_command(text) else "medium")


def clean_snippet(value: Any, raw_fields: dict[str, Any] | None = None) -> NormalizedField:
    text = _clean(value)
    if not text or is_placeholder(text):
        return NormalizedField("", "unknown", "", "unknown")
    if is_payload_blob(text):
        command = clean_command("", raw_fields=raw_fields)
        if command.value:
            return NormalizedField(command.value, "fallback", "command", command.confidence)
    return NormalizedField(_one_line(text, 240), "clean", "input", "medium")


def is_placeholder(value: Any) -> bool:
    text = _clean(value).lower()
    if text in PLACEHOLDER_VALUES:
        return True
    if re.fullmatch(r"0x[0-9a-f]{1,8}", text):
        return True
    if re.fullmatch(r"[0-9a-f]{1,16}", text) and len(text) not in {32, 40, 64}:
        return True
    return False


def is_payload_blob(value: Any) -> bool:
    text = _clean(value)
    if not text:
        return False
    lower = text.lower()
    if any(token in lower for token in PAYLOAD_TOKENS):
        return True
    if text.count("\n") >= 3 or text.count("\\n") >= 3:
        return True
    if len(text) > 200 and any(token in text for token in ("{", "}", "<", ">", "=", ":")):
        return True
    return False


def is_probably_user(value: Any) -> bool:
    text = _clean(value)
    if not text or is_placeholder(text) or is_payload_blob(text):
        return False
    lower = text.lower()
    if lower in SYSTEM_SIDS:
        return False
    if re.fullmatch(r"s-\d-\d+(?:-\d+){1,12}", lower):
        return True
    if re.fullmatch(r"[a-z0-9_.-]{1,64}\\[a-z0-9_.@$ -]{1,64}", text, flags=re.IGNORECASE):
        return True
    if EMAIL_RE.fullmatch(text):
        return True
    if lower in GENERIC_USER_NAMES:
        return True
    if re.fullmatch(r"[a-z0-9_.@$-]{1,64}", text, flags=re.IGNORECASE) and not _looks_like_machine_or_field(text):
        return True
    return False


def is_probably_command(value: Any) -> bool:
    text = _clean(value)
    lower = text.lower()
    if not text or is_placeholder(text):
        return False
    return bool(
        SCRIPT_OR_EXECUTABLE_RE.search(text)
        or re.search(r"(?i)\b(?:powershell|pwsh|cmd|wscript|cscript|mshta|rundll32|regsvr32|certutil|schtasks|reg|net|whoami|ipconfig|systeminfo|tasklist)(?:\.exe)?\b", text)
        or " -" in lower
        or lower.startswith(("./", ".\\"))
    )


def is_probably_path(value: Any) -> bool:
    text = _clean(value)
    return bool(WINDOWS_PATH_RE.search(text) or REGISTRY_PATH_RE.search(text))


def choose_best_key_entity(candidates: Iterable[tuple[Any, str] | dict[str, Any]], context: dict[str, Any] | None = None) -> NormalizedField:
    context = context or {}
    for raw_candidate in candidates:
        if isinstance(raw_candidate, dict):
            value = raw_candidate.get("value")
            source = str(raw_candidate.get("source") or "")
        else:
            value, source = raw_candidate
        cleaned = clean_key_entity(value, artifact_type=context.get("artifact_type"), event_type=context.get("event_type"), allow_payload_extract=False)
        if cleaned.value:
            confidence = "high" if source in {"key_entity", "process", "script_path", "file", "registry", "task", "service", "url"} else cleaned.confidence
            quality = "fallback" if source != "key_entity" else cleaned.quality
            return NormalizedField(cleaned.value, quality, source, confidence)
    fallback = str(context.get("event_type") or context.get("artifact_type") or "").strip()
    if fallback:
        return NormalizedField(fallback, "fallback", "event_type", "low")
    return NormalizedField("", "unknown", "", "unknown")


def collect_raw_payload(document: dict[str, Any]) -> str:
    parts: list[str] = []
    for source in (
        document.get("raw"),
        _obj(_obj(document.get("windows")).get("event_data")),
        _obj(_obj(document.get("windows")).get("event_data")).get("payload_columns"),
        _obj(document.get("windows")).get("payload"),
        _obj(document.get("powershell")).get("raw_payload"),
    ):
        if isinstance(source, dict):
            for key, value in source.items():
                if isinstance(value, (dict, list)):
                    continue
                if value and (str(key).lower().startswith("payload") or str(key).lower() in {"message", "contextinfo", "context_info"}):
                    parts.append(str(value))
        elif source:
            parts.append(str(source))
    return "\n".join(dict.fromkeys(_clean(part) for part in parts if _clean(part)))


def _key_entity_candidates(document: dict[str, Any]) -> list[tuple[Any, str]]:
    process = _obj(document.get("process"))
    file_data = _obj(document.get("file"))
    registry = _obj(document.get("registry"))
    task = _obj(document.get("task"))
    service = _obj(document.get("service"))
    url = _obj(document.get("url"))
    event = _obj(document.get("event"))
    artifact = _obj(document.get("artifact"))
    return [
        (document.get("key_entity"), "key_entity"),
        (process.get("command_line"), "process"),
        (process.get("path"), "process"),
        (process.get("name"), "process"),
        (file_data.get("path"), "file"),
        (file_data.get("name"), "file"),
        (registry.get("key_path") or registry.get("key") or registry.get("value_name") or registry.get("value_data"), "registry"),
        (task.get("name") or task.get("path") or task.get("command"), "task"),
        (service.get("name") or service.get("image_path"), "service"),
        (url.get("full") or url.get("domain"), "url"),
        (event.get("type"), "event_type"),
        (artifact.get("type"), "artifact_type"),
    ]


def _command_candidates(document: dict[str, Any]) -> list[tuple[Any, str]]:
    powershell = _obj(document.get("powershell"))
    process = _obj(document.get("process"))
    task = _obj(document.get("task"))
    return [
        (powershell.get("command"), "powershell.command"),
        (powershell.get("command_preview"), "powershell.command_preview"),
        (process.get("command_line"), "process.command_line"),
        (task.get("command"), "task.command"),
        (document.get("key_entity"), "key_entity"),
    ]


def _raw_extraction_candidates(text: str) -> list[tuple[Any, str]]:
    candidates: list[tuple[Any, str]] = []
    for label, source in (
        ("ScriptName", "script_path"),
        ("CommandLine", "command"),
        ("CommandInvocation", "command"),
        ("HostApplication", "process"),
        ("ProviderName", "provider"),
    ):
        match = re.search(rf"(?im)(?:^|[\n,;]\s*){re.escape(label)}\s*(?:=|:)\s*(.*?)(?=(?:\n|,\s*\w[\w ]{{1,32}}\s*(?:=|:))|$)", text)
        if match:
            candidates.append((match.group(1).strip(" ,;\r\""), source))
    for regex, source in (
        (SCRIPT_OR_EXECUTABLE_RE, "script_or_executable"),
        (REGISTRY_PATH_RE, "registry"),
        (URL_RE, "url"),
        (EMAIL_RE, "email"),
        (IP_RE, "ip"),
        (DOMAIN_RE, "domain"),
    ):
        match = regex.search(text)
        if match:
            candidates.append((match.group(1) if match.groups() else match.group(0), source))
    return candidates


def _extract_user_from_context(document: dict[str, Any]) -> str | None:
    values = _walk_values(document)
    for value in values:
        text = _clean(value)
        if not text:
            continue
        for label in ("UserId", "User", "UserName", "AccountName", "SubjectUserName", "Connected User", "ConnectedUser", "Usuario"):
            match = re.search(rf"(?im)(?:^|[\n,;]\s*|\b){re.escape(label)}\s*(?:=|:)\s*([^\n,;]+)", text)
            if match:
                candidate = match.group(1).strip()
                if is_probably_user(candidate):
                    return candidate
        path_user = _extract_user_from_path(text)
        if path_user:
            return path_user
    return None


def _extract_user_from_path(value: str) -> str | None:
    match = re.search(r"(?i)(?:^|[\\/])Users[\\/]([^\\/]+)[\\/]", value.replace("/", "\\"))
    if not match:
        return None
    candidate = match.group(1)
    if candidate.lower() in {"public", "default", "default user", "all users"}:
        return None
    return candidate if is_probably_user(candidate) else None


def _current_command(document: dict[str, Any]) -> Any:
    return _obj(document.get("powershell")).get("command") or _obj(document.get("process")).get("command_line") or _obj(document.get("task")).get("command")


def _set_command(document: dict[str, Any], value: str) -> None:
    if "powershell" in document and isinstance(document.get("powershell"), dict):
        document["powershell"]["command"] = value
        document["powershell"].setdefault("command_preview", _one_line(value, 240))
    process = document.setdefault("process", {})
    if isinstance(process, dict) and (is_placeholder(process.get("command_line")) or is_payload_blob(process.get("command_line"))):
        process["command_line"] = value


def _event_message(document: dict[str, Any]) -> Any:
    return _obj(document.get("event")).get("message")


def _artifact_type(document: dict[str, Any]) -> str:
    return str(_obj(document.get("artifact")).get("type") or "")


def _event_type(document: dict[str, Any]) -> str:
    return str(_obj(document.get("event")).get("type") or "")


def _walk_values(value: Any, *, limit: int = 200) -> list[str]:
    output: list[str] = []
    stack = [value]
    while stack and len(output) < limit:
        current = stack.pop()
        if isinstance(current, dict):
            stack.extend(current.values())
        elif isinstance(current, list):
            stack.extend(current)
        elif current not in (None, ""):
            output.append(str(current))
    return output


def _short_value(value: str) -> str:
    text = _one_line(value, 240)
    path_match = SCRIPT_OR_EXECUTABLE_RE.search(text)
    if path_match:
        return path_match.group(1)
    if len(text) <= 180:
        return text
    try:
        name = PureWindowsPath(text.replace("/", "\\")).name
        if name and len(name) < len(text) and len(name) <= 180:
            return name
    except Exception:  # noqa: BLE001
        pass
    return text[:177].rstrip() + "..."


def _one_line(value: Any, limit: int) -> str:
    text = re.sub(r"\s+", " ", _clean(value)).strip()
    return text if len(text) <= limit else text[: limit - 3].rstrip() + "..."


def _clean(value: Any) -> str:
    if value is None:
        return ""
    text = str(value).strip().strip("\x00")
    if len(text) >= 2 and text[0] == text[-1] and text[0] in {'"', "'"}:
        text = text[1:-1].strip()
    return text


def _looks_like_machine_or_field(value: str) -> bool:
    lower = value.lower()
    return lower in {"consolehost", "powershell", "eventdata", "hostapplication"} or lower.endswith("=")


def _obj(value: Any) -> dict[str, Any]:
    return value if isinstance(value, dict) else {}
