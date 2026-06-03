from __future__ import annotations

import importlib.util
import re
from collections import Counter
from collections.abc import Iterable

import yaml


SIGMA_FIELD_MAP = {
    "EventID": ["windows.event_id"],
    "EventId": ["windows.event_id"],
    "Channel": ["windows.channel"],
    "Provider_Name": ["windows.provider"],
    "Computer": ["host.name"],
    "User": ["user.name"],
    "TargetUserName": ["user.name"],
    "SubjectUserName": ["user.name"],
    "Image": ["process.executable", "process.path", "process.name"],
    "NewProcessName": ["process.executable", "process.path", "process.name"],
    "ProcessName": ["process.name", "process.executable", "process.path"],
    "CommandLine": ["process.command_line"],
    "ParentImage": ["process.parent.executable", "process.parent.path", "process.parent_path", "process.parent_name", "parent.process.executable", "parent.process.path", "parent.process.name"],
    "ParentProcessName": ["process.parent.name", "process.parent.path", "process.parent_name", "process.parent_path", "parent.process.name", "parent.process.path"],
    "ParentCommandLine": ["process.parent.command_line", "process.parent_command_line", "parent.process.command_line"],
    "TargetFilename": ["file.path", "target.filename"],
    "ImageLoaded": ["image.loaded.path", "module.path", "file.path"],
    "DestinationIp": ["destination.ip", "network.destination_ip"],
    "DestinationPort": ["destination.port", "network.destination_port"],
    "SourceIp": ["source.ip", "network.source_ip"],
    "SourcePort": ["source.port", "network.source_port"],
    "DestinationHostname": ["destination.hostname", "url.domain", "dns.domain"],
    "QueryName": ["dns.question.name", "dns.query", "dns.domain", "dns.name"],
    "Hashes": ["process.hash.sha256", "process.hash.sha1", "process.hash.md5", "process.hashes.sha256", "process.hashes.sha1", "process.hashes.md5", "file.hash.sha256", "file.hash.sha1", "file.hash.md5", "file.sha256", "file.sha1", "file.md5"],
    "TargetObject": ["registry.path", "registry.key_path"],
    "Details": ["registry.data", "registry.value_data"],
    "EventType": ["registry.event_type", "event.action", "event.type"],
    "GrantedAccess": ["process.granted_access", "windows.event_data.GrantedAccess", "winlog.event_data.GrantedAccess"],
    "ScriptBlockText": ["powershell.script_block_text", "search_text"],
    "Url": ["url.full", "download.url"],
}

MODIFIER_SUFFIXES = ("|contains", "|endswith", "|startswith", "|re", "|all")
SEARCH_TEXT_FALLBACK_FIELDS = {"ScriptBlockText", "Details", "CommandLine", "ParentCommandLine"}
CONDITION_TOKENS_RE = re.compile(r"\(|\)|\band\b|\bor\b|\bnot\b|[A-Za-z0-9_*]+", re.IGNORECASE)
UNSUPPORTED_CONDITION_RE = re.compile(r"\bnear\b|\bwithin\b|\bby\b|\b(?:\d+|all)\s+of\b|\bthem\b", re.IGNORECASE)
SIGMA_EVENT_ID_HINTS = {
    "process_creation": [1, 4688],
    "registry_set": [12, 13, 14],
    "file_event": [11, 15, 23, 26],
    "network_connection": [3],
    "image_load": [7],
    "pipe_created": [17, 18],
    "powershell": [400, 403, 4103, 4104, 600, 800],
}
SIGMA_CATEGORY_EVENT_TYPE_HINTS = {
    "process_creation": ["process_creation", "process_created", "sysmon_process_created", "security_process_created"],
    "registry_set": ["registry_set", "registry_value_set", "sysmon_registry_set"],
    "file_event": ["file_event", "file_create", "file_created", "sysmon_file_created"],
    "network_connection": ["network_connection", "network_connected", "sysmon_network_connection"],
    "image_load": ["image_load", "image_loaded", "sysmon_image_loaded"],
    "pipe_created": ["pipe_created", "named_pipe_created", "sysmon_pipe_created"],
    "powershell": ["powershell", "script_block", "powershell_script_block"],
}
SIGMA_FIELD_CATEGORY_HINTS = {
    "process.command_line": "process_creation",
    "process.executable": "process_creation",
    "process.path": "process_creation",
    "process.name": "process_creation",
    "process.parent.executable": "process_creation",
    "process.parent.path": "process_creation",
    "process.parent.name": "process_creation",
    "process.parent.command_line": "process_creation",
    "process.parent_path": "process_creation",
    "process.parent_name": "process_creation",
    "process.parent_command_line": "process_creation",
    "registry.path": "registry_set",
    "registry.key_path": "registry_set",
    "registry.data": "registry_set",
    "registry.value_data": "registry_set",
    "registry.event_type": "registry_set",
    "file.path": "file_event",
    "target.filename": "file_event",
    "image.loaded.path": "image_load",
    "module.path": "image_load",
    "network.destination_ip": "network_connection",
    "network.destination_port": "network_connection",
    "network.source_ip": "network_connection",
    "network.source_port": "network_connection",
    "destination.ip": "network_connection",
    "destination.port": "network_connection",
    "source.ip": "network_connection",
    "source.port": "network_connection",
    "destination.hostname": "network_connection",
    "destination.domain": "network_connection",
    "dns.question.name": "network_connection",
    "dns.query": "network_connection",
    "dns.domain": "network_connection",
    "dns.name": "network_connection",
    "process.hash.sha256": "process_creation",
    "process.hash.sha1": "process_creation",
    "process.hash.md5": "process_creation",
    "file.hash.sha256": "file_event",
    "file.hash.sha1": "file_event",
    "file.hash.md5": "file_event",
    "url.domain": "network_connection",
    "url.full": "network_connection",
    "powershell.script_block_text": "powershell",
}
SIGMA_SERVICE_CHANNEL_HINTS = {
    "sysmon": ["sysmon"],
    "security": ["security"],
    "powershell": ["powershell"],
    "defender": ["defender"],
    "taskscheduler": ["taskscheduler", "task scheduler"],
}
SIGMA_CATEGORY_SERVICE_HINTS = {
    "process_creation": ["sysmon", "security"],
    "registry_set": ["sysmon"],
    "file_event": ["sysmon"],
    "network_connection": ["sysmon"],
    "image_load": ["sysmon"],
    "pipe_created": ["sysmon"],
    "powershell": ["powershell"],
}
ENGINE_COMPATIBILITY_VERSION = "rules_v3"
SUPPORTED_MODIFIERS = {"contains", "endswith", "startswith", "re", "all"}
UNSUPPORTED_FEATURE_PATTERNS: list[tuple[str, re.Pattern[str]]] = [
    ("unsupported_correlation", re.compile(r"\bnear\b|\bwithin\b|\bby\b", re.IGNORECASE)),
]
SIGMA_EXPANSION_PATTERN = re.compile(
    r"(?<!\S)(1|all)\s+of\s+(them|[A-Za-z0-9_][A-Za-z0-9_*]*)(?=$|\s|[)])",
    re.IGNORECASE,
)
MAX_EXPANDED_SELECTORS_PER_RULE = 100
MAX_TOTAL_LEAF_CONDITIONS = 200


def parse_sigma_rule(content: str) -> list[dict]:
    docs = [doc for doc in yaml.safe_load_all(content) if doc]
    rules: list[dict] = []
    for doc in docs:
        if isinstance(doc, list):
            rules.extend(item for item in doc if isinstance(item, dict))
        elif isinstance(doc, dict):
            rules.append(doc)
    return rules


def validate_sigma_rule_content(content: str) -> dict:
    rules = parse_sigma_rule(content)
    if not rules:
        raise ValueError("No Sigma rules found in YAML content.")
    normalized = []
    for index, rule in enumerate(rules, start=1):
        title = str(rule.get("title") or rule.get("id") or f"Sigma rule {index}").strip()
        detection = rule.get("detection")
        if not isinstance(detection, dict):
            raise ValueError(f"{title}: detection section must be a mapping.")
        condition = str(detection.get("condition") or "").strip()
        if not condition:
            raise ValueError(f"{title}: detection.condition is required.")
        normalized.append(extract_sigma_metadata(rule))
    return {"valid": True, "rules_count": len(normalized), "rules": normalized}


def extract_sigma_metadata(rule_data: dict) -> dict:
    tags = [str(item) for item in (rule_data.get("tags") or []) if str(item).strip()]
    return {
        "id": str(rule_data.get("id") or "").strip() or None,
        "name": str(rule_data.get("title") or rule_data.get("id") or "Unnamed Sigma rule").strip(),
        "title": str(rule_data.get("title") or rule_data.get("id") or "Unnamed Sigma rule").strip(),
        "description": str(rule_data.get("description") or "").strip() or None,
        "author": str(rule_data.get("author") or "").strip() or None,
        "rule_version": str(rule_data.get("modified") or rule_data.get("date") or "").strip() or None,
        "level": str(rule_data.get("level") or "").strip().lower() or None,
        "status": str(rule_data.get("status") or "valid").strip().lower() or "valid",
        "references": [str(item) for item in (rule_data.get("references") or []) if str(item).strip()],
        "false_positives": [str(item) for item in (rule_data.get("falsepositives") or rule_data.get("false_positives") or []) if str(item).strip()],
        "tags": tags,
        "mitre": [tag for tag in tags if tag.lower().startswith("attack.")],
        "logsource": dict(rule_data.get("logsource") or {}),
        "condition": str((rule_data.get("detection") or {}).get("condition") or "").strip(),
    }


def extract_sigma_detection_fields(rule_data: dict) -> list[str]:
    detection = dict(rule_data.get("detection") or {})
    fields: list[str] = []
    for selection_name, selection in detection.items():
        if selection_name == "condition" or not isinstance(selection, dict):
            continue
        for sigma_field in selection.keys():
            base_field, _ = _split_field_and_modifier(str(sigma_field))
            fields.append(base_field)
    return sorted(dict.fromkeys(fields))


def _sigma_detection_block_names(rule_data: dict) -> list[str]:
    detection = dict(rule_data.get("detection") or {})
    return [
        str(name)
        for name, selection in detection.items()
        if name != "condition" and isinstance(selection, dict) and selection
    ]


def _selector_matches(selector: str, candidates: list[str]) -> list[str]:
    if selector == "them":
        return candidates
    if "*" not in selector:
        return [selector] if selector in candidates else []
    pattern = re.compile("^" + re.escape(selector).replace("\\*", ".*") + "$")
    return [name for name in candidates if pattern.match(name)]


def expand_sigma_condition_terms(
    rule_data: dict,
    *,
    max_expanded_selectors: int = MAX_EXPANDED_SELECTORS_PER_RULE,
    max_total_leaf_conditions: int = MAX_TOTAL_LEAF_CONDITIONS,
) -> dict:
    detection = dict(rule_data.get("detection") or {})
    original_condition = str(detection.get("condition") or "").strip()
    block_names = _sigma_detection_block_names(rule_data)
    non_filter_block_names = [name for name in block_names if not name.lower().startswith("filter")]
    filter_block_names = [name for name in block_names if name.lower().startswith("filter")]
    matched_selectors: dict[str, list[str]] = {}
    warnings: list[str] = []
    supported_features: list[str] = []
    leaf_conditions = 0

    if not original_condition:
        return {
            "supported": False,
            "expanded_condition": "",
            "unsupported_features": ["empty_condition"],
            "matched_selectors": {},
            "warnings": [],
            "reason": "empty_condition",
            "supported_features": [],
        }

    def replace_match(match: re.Match[str]) -> str:
        nonlocal leaf_conditions
        quantifier = str(match.group(1) or "").lower()
        selector = str(match.group(2) or "")
        selector_key = selector.lower()
        names = _selector_matches(
            selector,
            non_filter_block_names if selector_key == "them" else block_names,
        )
        if selector_key == "them" and filter_block_names:
            warnings.append("condition_them_excluded_filter_blocks")
        if not names:
            raise ValueError("unsupported_condition_empty_selector")
        if len(names) > max_expanded_selectors:
            raise ValueError("expanded_condition_too_large")
        leaf_conditions += len(names)
        if leaf_conditions > max_total_leaf_conditions:
            raise ValueError("expanded_condition_too_large")
        matched_selectors[selector] = names
        if selector_key == "them":
            supported_features.append(f"condition_{quantifier}_of_them")
        else:
            supported_features.append(f"condition_{quantifier}_of")
        operator = " or " if quantifier == "1" else " and "
        expanded = operator.join(names)
        return f"({expanded})" if len(names) > 1 else expanded

    expanded_condition = original_condition
    try:
        for _ in range(8):
            updated = SIGMA_EXPANSION_PATTERN.sub(replace_match, expanded_condition)
            if updated == expanded_condition:
                break
            expanded_condition = updated
    except ValueError as exc:
        reason = str(exc) or "unsupported_condition"
        return {
            "supported": False,
            "expanded_condition": expanded_condition,
            "unsupported_features": [reason],
            "matched_selectors": matched_selectors,
            "warnings": sorted(dict.fromkeys(warnings)),
            "reason": reason,
            "supported_features": sorted(dict.fromkeys(supported_features)),
        }
    unresolved = SIGMA_EXPANSION_PATTERN.search(expanded_condition)
    if unresolved:
        return {
            "supported": False,
            "expanded_condition": expanded_condition,
            "unsupported_features": ["unsupported_condition"],
            "matched_selectors": matched_selectors,
            "warnings": sorted(dict.fromkeys(warnings)),
            "reason": "unsupported_condition",
            "supported_features": sorted(dict.fromkeys(supported_features)),
        }
    return {
        "supported": True,
        "expanded_condition": expanded_condition,
        "unsupported_features": [],
        "matched_selectors": matched_selectors,
        "warnings": sorted(dict.fromkeys(warnings)),
        "reason": "expanded" if matched_selectors else "simple_condition",
        "supported_features": sorted(dict.fromkeys(supported_features)),
    }


def _detect_unsupported_modifiers(rule_data: dict) -> list[str]:
    detection = dict(rule_data.get("detection") or {})
    unsupported: list[str] = []
    for selection_name, selection in detection.items():
        if selection_name == "condition" or not isinstance(selection, dict):
            continue
        for sigma_field in selection.keys():
            _, modifier = _split_field_and_modifier(str(sigma_field))
            if modifier and modifier not in SUPPORTED_MODIFIERS:
                unsupported.append(modifier)
    return sorted(dict.fromkeys(unsupported))


def analyze_sigma_engine_compatibility(rule_data: dict) -> dict:
    metadata = extract_sigma_metadata(rule_data)
    condition = metadata.get("condition") or ""
    required_fields = extract_sigma_detection_fields(rule_data)
    unsupported_features: list[str] = []
    supported_features: list[str] = []
    primary_status = "executable_by_current_engine"
    reason = "compiled"

    unsupported_modifiers = _detect_unsupported_modifiers(rule_data)
    if unsupported_modifiers:
        unsupported_features.extend([f"unsupported_modifier:{modifier}" for modifier in unsupported_modifiers])
        primary_status = "unsupported_modifier"
        reason = ",".join(unsupported_modifiers)

    for feature_name, pattern in UNSUPPORTED_FEATURE_PATTERNS:
        if pattern.search(condition):
            unsupported_features.append(feature_name)
            if primary_status == "executable_by_current_engine":
                primary_status = feature_name
                reason = feature_name

    expansion = expand_sigma_condition_terms(rule_data)
    if not expansion.get("supported"):
        reason = str(expansion.get("reason") or "unsupported_condition")
        primary_status = reason
        unsupported_features.extend(list(expansion.get("unsupported_features") or [reason]))
    supported, compile_reason = sigma_condition_supported(str(expansion.get("expanded_condition") or condition))
    if not supported:
        if compile_reason == "unsupported_condition" and primary_status == "executable_by_current_engine":
            primary_status = "unsupported_condition"
            reason = compile_reason
            unsupported_features.append("unsupported_condition")
        elif primary_status == "executable_by_current_engine":
            primary_status = "compile_error"
            reason = compile_reason or "compile_error"
            unsupported_features.append(reason)

    if not unsupported_features:
        supported_features.extend(["basic_condition", "mapped_fields", "compiled_internal_query"])
        supported_features.extend(list(expansion.get("supported_features") or []))
        if condition:
            supported_features.append("condition_rpn")
        modifiers = []
        detection = dict(rule_data.get("detection") or {})
        for selection_name, selection in detection.items():
            if selection_name == "condition" or not isinstance(selection, dict):
                continue
            for sigma_field in selection.keys():
                _, modifier = _split_field_and_modifier(str(sigma_field))
                if modifier:
                    modifiers.append(modifier)
        supported_features.extend([f"modifier:{modifier}" for modifier in sorted(dict.fromkeys(modifiers))])

    not_executable = primary_status != "executable_by_current_engine"
    return {
        "valid_yaml": True,
        "compile_source": "internal",
        "compile_version": ENGINE_COMPATIBILITY_VERSION,
        "executable_by_current_engine": not not_executable,
        "not_executable_by_current_engine": not_executable,
        "engine_status": primary_status,
        "engine_reason": reason,
        "supported_features": sorted(dict.fromkeys(supported_features)),
        "unsupported_features": sorted(dict.fromkeys(unsupported_features)),
        "required_fields": required_fields,
        "logsource": metadata.get("logsource") or {},
        "condition": condition,
        "expanded_condition": str(expansion.get("expanded_condition") or condition),
        "matched_selectors": dict(expansion.get("matched_selectors") or {}),
        "expansion_warnings": list(expansion.get("warnings") or []),
    }


def pysigma_capabilities() -> dict:
    sigma_spec = importlib.util.find_spec("sigma")
    return {
        "available": sigma_spec is not None,
        "compile_source": "pysigma" if sigma_spec is not None else "internal_only",
        "reason": None if sigma_spec is not None else "pySigma is not installed in this deployment.",
    }


def compile_sigma_rule(rule_data: dict) -> dict:
    metadata = extract_sigma_metadata(rule_data)
    condition = metadata.get("condition") or ""
    fields = extract_sigma_detection_fields(rule_data)
    compatibility = analyze_sigma_engine_compatibility(rule_data)
    expanded_condition = str(compatibility.get("expanded_condition") or condition)
    supported, reason = sigma_condition_supported(expanded_condition)
    if compatibility.get("not_executable_by_current_engine"):
        supported = False
        reason = str(compatibility.get("engine_status") or compatibility.get("engine_reason") or "compile_error")
    condition_rpn = _to_rpn(_tokenize_condition(expanded_condition)) if supported else []
    compiled = {
        "compile_status": "compiled" if supported else f"skipped_{reason or 'compile_error'}",
        "compile_error": None if supported else reason,
        "compile_warnings": list(compatibility.get("expansion_warnings") or []),
        "supported_engine_version": ENGINE_COMPATIBILITY_VERSION,
        "compile_source": "internal",
        "compile_version": ENGINE_COMPATIBILITY_VERSION,
        "engine_compatibility": compatibility,
        "sigma_logsource": metadata.get("logsource") or {},
        "sigma_required_fields": fields,
        "sigma_field_mappings": {field: _mapped_sigma_fields(field)[0] for field in fields},
        "supported_features": list(compatibility.get("supported_features") or []),
        "unsupported_features": list(compatibility.get("unsupported_features") or []),
        "condition": condition,
        "expanded_condition": expanded_condition,
        "expanded_condition_summary": {
            "original": condition,
            "expanded": expanded_condition,
            "matched_selectors": dict(compatibility.get("matched_selectors") or {}),
        },
        "compile_features": list(compatibility.get("supported_features") or []),
        "condition_rpn": condition_rpn,
        "compiled_query": {
            "selections": {},
            "condition": expanded_condition,
            "condition_rpn": condition_rpn,
            "expanded_condition": expanded_condition,
        },
    }
    if not supported:
        return compiled
    detection = dict(rule_data.get("detection") or {})
    selections: dict[str, list[dict[str, object]]] = {}
    for selection_name, selection in detection.items():
        if selection_name == "condition" or not isinstance(selection, dict):
            continue
        compiled_selection: list[dict[str, object]] = []
        for sigma_field, expected in selection.items():
            mapped_fields, used_fallback = _mapped_sigma_fields(str(sigma_field))
            _, modifier = _split_field_and_modifier(str(sigma_field))
            compiled_selection.append(
                {
                    "sigma_field": str(sigma_field),
                    "base_field": _split_field_and_modifier(str(sigma_field))[0],
                    "mapped_fields": mapped_fields,
                    "modifier": modifier,
                    "expected": _flatten_values(expected),
                    "used_fallback": used_fallback,
                }
            )
        selections[str(selection_name)] = compiled_selection
    compiled["compiled_query"]["selections"] = selections
    return compiled


def sigma_condition_supported(condition: str) -> tuple[bool, str | None]:
    normalized = str(condition or "").strip()
    if not normalized:
        return False, "empty_condition"
    if UNSUPPORTED_CONDITION_RE.search(normalized):
        return False, "unsupported_condition"
    try:
        _to_rpn(_tokenize_condition(normalized))
    except ValueError:
        return False, "unsupported_condition"
    return True, None


def build_sigma_case_profile(events: list[dict], *, total_events: int | None = None) -> dict:
    artifact_types: Counter[str] = Counter()
    parsers: Counter[str] = Counter()
    channels: Counter[str] = Counter()
    event_ids: Counter[str] = Counter()
    available_fields: Counter[str] = Counter()
    products: set[str] = set()

    def _mark_field(name: str, present: bool) -> None:
        if present:
            available_fields[name] += 1

    for event in events:
        artifact = dict(event.get("artifact") or {})
        windows = dict(event.get("windows") or {})
        process = dict(event.get("process") or {})
        registry = dict(event.get("registry") or {})
        file_obj = dict(event.get("file") or {})
        network = dict(event.get("network") or {})
        module = dict(event.get("module") or {})
        image = dict(event.get("image") or {})
        powershell = dict(event.get("powershell") or {})
        host = dict(event.get("host") or {})
        user = dict(event.get("user") or {})
        source = dict(event.get("source") or {})
        destination = dict(event.get("destination") or {})
        dns = dict(event.get("dns") or {})

        artifact_type = str(artifact.get("type") or "").strip()
        if artifact_type:
            artifact_types[artifact_type] += 1
        parser_name = str(artifact.get("parser") or "").strip()
        if parser_name:
            parsers[parser_name] += 1
        channel = str(windows.get("channel") or "").strip()
        if channel:
            channels[channel] += 1
            lowered = channel.lower()
            if "sysmon" in lowered:
                products.update({"windows", "sysmon"})
            if lowered == "security":
                products.update({"windows", "security"})
            if "powershell" in lowered:
                products.update({"windows", "powershell"})
            if "defender" in lowered:
                products.update({"windows", "defender"})
            if "taskscheduler" in lowered or "task scheduler" in lowered:
                products.update({"windows", "taskscheduler"})
        event_id = windows.get("event_id")
        if event_id is not None and str(event_id).strip():
            event_ids[str(event_id)] += 1
        if windows or parser_name == "evtx_raw" or artifact_type == "windows_event":
            products.add("windows")

        _mark_field("windows.event_id", windows.get("event_id") is not None)
        _mark_field("windows.channel", bool(windows.get("channel")))
        _mark_field("windows.provider", bool(windows.get("provider")))
        _mark_field("host.name", bool(host.get("name")))
        _mark_field("user.name", bool(user.get("name")))
        _mark_field("process.path", bool(process.get("path") or process.get("executable")))
        _mark_field("process.executable", bool(process.get("executable") or process.get("path")))
        _mark_field("process.name", bool(process.get("name")))
        _mark_field("process.command_line", bool(process.get("command_line")))
        _mark_field("process.parent_path", bool(process.get("parent_path") or process.get("parent", {}).get("executable")))
        _mark_field("process.parent_name", bool(process.get("parent_name") or process.get("parent", {}).get("name")))
        _mark_field("process.parent_command_line", bool(process.get("parent_command_line")))
        _mark_field("process.parent.executable", bool(process.get("parent", {}).get("executable") or process.get("parent_path")))
        _mark_field("process.parent.path", bool(process.get("parent", {}).get("path") or process.get("parent_path")))
        _mark_field("process.parent.name", bool(process.get("parent", {}).get("name") or process.get("parent_name")))
        _mark_field("process.parent.command_line", bool(process.get("parent", {}).get("command_line") or process.get("parent_command_line")))
        for hash_name in ("md5", "sha1", "sha256"):
            _mark_field(f"process.hash.{hash_name}", bool((process.get("hash") or {}).get(hash_name) or (process.get("hashes") or {}).get(hash_name)))
            _mark_field(f"process.hashes.{hash_name}", bool((process.get("hashes") or {}).get(hash_name)))
            _mark_field(f"file.hash.{hash_name}", bool((file_obj.get("hash") or {}).get(hash_name) or file_obj.get(hash_name)))
        _mark_field("file.path", bool(file_obj.get("path")))
        _mark_field("target.filename", bool((event.get("target") or {}).get("filename")))
        _mark_field("module.path", bool(module.get("path")))
        _mark_field("image.loaded.path", bool((image.get("loaded") or {}).get("path")))
        _mark_field("network.destination_ip", bool(network.get("destination_ip")))
        _mark_field("network.destination_port", bool(network.get("destination_port")))
        _mark_field("network.source_ip", bool(network.get("source_ip")))
        _mark_field("network.source_port", bool(network.get("source_port")))
        _mark_field("destination.ip", bool(network.get("destination_ip") or destination.get("ip")))
        _mark_field("destination.port", bool(network.get("destination_port") or destination.get("port")))
        _mark_field("destination.hostname", bool(destination.get("hostname")))
        _mark_field("destination.domain", bool(destination.get("domain")))
        _mark_field("source.ip", bool(network.get("source_ip") or source.get("ip")))
        _mark_field("source.port", bool(network.get("source_port") or source.get("port")))
        _mark_field("dns.question.name", bool((dns.get("question") or {}).get("name")))
        _mark_field("dns.query", bool(dns.get("query")))
        _mark_field("dns.domain", bool(dns.get("domain")))
        _mark_field("dns.name", bool(dns.get("name")))
        _mark_field("url.domain", bool(event.get("url", {}).get("domain")))
        _mark_field("url.full", bool(event.get("url", {}).get("full")))
        _mark_field("registry.path", bool(registry.get("path") or registry.get("key_path")))
        _mark_field("registry.key_path", bool(registry.get("key_path") or registry.get("path")))
        _mark_field("registry.data", bool(registry.get("data") or registry.get("value_data")))
        _mark_field("registry.value_data", bool(registry.get("value_data") or registry.get("data") or registry.get("value")))
        _mark_field("registry.event_type", bool(registry.get("event_type")))
        _mark_field("powershell.script_block_text", bool(powershell.get("script_block_text")))
        _mark_field("search_text", bool(event.get("search_text")))

    aliases = {
        sigma_field: mapped_fields
        for sigma_field, mapped_fields in SIGMA_FIELD_MAP.items()
        if any(field in available_fields for field in mapped_fields)
    }
    return {
        "total_events": int(total_events if total_events is not None else len(events)),
        "artifact_types_present": dict(artifact_types),
        "parsers_present": dict(parsers),
        "channels_present": dict(channels),
        "event_ids_present": dict(event_ids),
        "available_fields": sorted(available_fields.keys()),
        "field_coverage": dict(available_fields),
        "source_products": sorted(products),
        "field_aliases": aliases,
    }


def build_sigma_rule_prefilter(rule_data: dict, case_profile: dict) -> dict:
    metadata = extract_sigma_metadata(rule_data)
    logsource = metadata.get("logsource") or {}
    product = str(logsource.get("product") or "").strip().lower()
    service = str(logsource.get("service") or "").strip().lower()
    category = str(logsource.get("category") or "").strip().lower()
    channels_present = list((case_profile.get("channels_present") or {}).keys())
    artifact_types_present = set((case_profile.get("artifact_types_present") or {}).keys())
    event_ids_present = {int(str(key)) for key in (case_profile.get("event_ids_present") or {}).keys() if str(key).isdigit()}

    candidate_event_ids: set[int] = set()
    candidate_channels: set[str] = set()
    artifact_types: set[str] = set()
    field_exists: set[str] = set()

    if product == "windows":
        artifact_types.update({"windows_event", "evtx_raw"} & artifact_types_present or {"windows_event"})
    if service:
        for channel in channels_present:
            lowered = channel.lower()
            if any(hint in lowered for hint in SIGMA_SERVICE_CHANNEL_HINTS.get(service, [])):
                candidate_channels.add(channel)
    if category:
        candidate_event_ids.update(SIGMA_EVENT_ID_HINTS.get(category, []))
        for mapped_field, hinted_category in SIGMA_FIELD_CATEGORY_HINTS.items():
            if hinted_category == category:
                field_exists.add(mapped_field)
        if not candidate_channels:
            for hinted_service in SIGMA_CATEGORY_SERVICE_HINTS.get(category, []):
                for channel in channels_present:
                    lowered = channel.lower()
                    if any(hint in lowered for hint in SIGMA_SERVICE_CHANNEL_HINTS.get(hinted_service, [])):
                        candidate_channels.add(channel)
    for field in extract_sigma_detection_fields(rule_data):
        mapped_fields, _ = _mapped_sigma_fields(field)
        for mapped_field in mapped_fields:
            field_exists.add(mapped_field)
            hinted_category = SIGMA_FIELD_CATEGORY_HINTS.get(mapped_field)
            if hinted_category:
                candidate_event_ids.update(SIGMA_EVENT_ID_HINTS.get(hinted_category, []))
    if event_ids_present and candidate_event_ids:
        candidate_event_ids.intersection_update(event_ids_present)

    return {
        "product": product or None,
        "service": service or None,
        "category": category or None,
        "artifact_types": sorted(artifact_types),
        "event_ids": sorted(candidate_event_ids),
        "channels": sorted(candidate_channels),
        "field_exists": sorted(field_exists),
    }


def build_sigma_rule_prefilter_from_compiled(compiled_rule: dict, case_profile: dict) -> dict:
    metadata = {
        "logsource": dict(compiled_rule.get("sigma_logsource") or {}),
        "condition": str(compiled_rule.get("condition") or ""),
    }
    pseudo_rule = {
        "logsource": metadata["logsource"],
        "detection": {"condition": metadata["condition"]},
    }
    selections = {}
    for selection_name, clauses in dict((compiled_rule.get("compiled_query") or {}).get("selections") or {}).items():
        selection: dict[str, object] = {}
        for clause in clauses or []:
            selection[str(clause.get("sigma_field") or clause.get("base_field") or "field")] = clause.get("expected")
        selections[str(selection_name)] = selection
    pseudo_rule["detection"].update(selections)
    return build_sigma_rule_prefilter(pseudo_rule, case_profile)


def preflight_sigma_rule(rule_data: dict, case_profile: dict, *, enabled: bool = True) -> dict:
    metadata = extract_sigma_metadata(rule_data)
    if not enabled:
        return {"status": "skipped_disabled", "reason": "disabled", "logsource": metadata.get("logsource") or {}, "fields": extract_sigma_detection_fields(rule_data), "prefilter": {}}

    expansion = expand_sigma_condition_terms(rule_data)
    condition_supported, condition_reason = sigma_condition_supported(str(expansion.get("expanded_condition") or metadata.get("condition") or ""))
    if not condition_supported:
        return {
            "status": "skipped_unsupported_condition",
            "reason": str(expansion.get("reason") or condition_reason),
            "logsource": metadata.get("logsource") or {},
            "fields": extract_sigma_detection_fields(rule_data),
            "prefilter": {},
        }

    logsource = metadata.get("logsource") or {}
    product = str(logsource.get("product") or "").strip().lower()
    service = str(logsource.get("service") or "").strip().lower()
    category = str(logsource.get("category") or "").strip().lower()
    available_fields = set(case_profile.get("available_fields") or [])
    products = set(case_profile.get("source_products") or [])
    channels_present = [str(item).lower() for item in (case_profile.get("channels_present") or {}).keys()]
    fields = extract_sigma_detection_fields(rule_data)

    if product and product in {"windows", "linux", "macos", "cloud"} and product not in products:
        return {
            "status": "skipped_unsupported_platform",
            "reason": product,
            "logsource": logsource,
            "fields": fields,
            "prefilter": {},
        }

    if service:
        hints = SIGMA_SERVICE_CHANNEL_HINTS.get(service, [])
        if hints and not any(any(hint in channel for hint in hints) for channel in channels_present):
            return {
                "status": "skipped_unsupported_logsource",
                "reason": service,
                "logsource": logsource,
                "fields": fields,
                "prefilter": {},
            }

    missing_fields: list[str] = []
    partial_support = False
    for field in fields:
        mapped_fields, used_fallback = _mapped_sigma_fields(field)
        if not any(mapped_field in available_fields for mapped_field in mapped_fields):
            missing_fields.append(field)
        elif used_fallback:
            partial_support = True
    if missing_fields:
        return {
            "status": "skipped_missing_fields",
            "reason": "missing_fields",
            "missing_fields": missing_fields,
            "logsource": logsource,
            "fields": fields,
            "prefilter": {},
        }

    prefilter = build_sigma_rule_prefilter(rule_data, case_profile)
    status = "runnable_partial" if partial_support else "runnable"
    return {
        "status": status,
        "reason": "partial_support" if partial_support else "compatible",
        "missing_fields": [],
        "logsource": logsource,
        "fields": fields,
        "prefilter": prefilter,
    }


def preflight_compiled_sigma_rule(compiled_rule: dict, case_profile: dict, *, enabled: bool = True) -> dict:
    logsource = dict(compiled_rule.get("sigma_logsource") or {})
    fields = [str(item) for item in (compiled_rule.get("sigma_required_fields") or [])]
    compile_status = str(compiled_rule.get("compile_status") or "compiled")
    if not enabled:
        return {"status": "skipped_disabled", "reason": "disabled", "logsource": logsource, "fields": fields, "prefilter": {}}
    if compile_status != "compiled":
        return {
            "status": compile_status if compile_status.startswith("skipped_") else "skipped_compile_error",
            "reason": str(compiled_rule.get("compile_error") or compile_status),
            "logsource": logsource,
            "fields": fields,
            "prefilter": {},
        }
    product = str(logsource.get("product") or "").strip().lower()
    service = str(logsource.get("service") or "").strip().lower()
    available_fields = set(case_profile.get("available_fields") or [])
    products = set(case_profile.get("source_products") or [])
    channels_present = [str(item).lower() for item in (case_profile.get("channels_present") or {}).keys()]
    if product and product in {"windows", "linux", "macos", "cloud"} and product not in products:
        return {"status": "skipped_unsupported_platform", "reason": product, "logsource": logsource, "fields": fields, "prefilter": {}}
    if service:
        hints = SIGMA_SERVICE_CHANNEL_HINTS.get(service, [])
        if hints and not any(any(hint in channel for hint in hints) for channel in channels_present):
            return {"status": "skipped_unsupported_logsource", "reason": service, "logsource": logsource, "fields": fields, "prefilter": {}}
    missing_fields: list[str] = []
    partial_support = False
    field_mappings = dict(compiled_rule.get("sigma_field_mappings") or {})
    selections = dict((compiled_rule.get("compiled_query") or {}).get("selections") or {})
    for field in fields:
        mapped_fields = [str(item) for item in (field_mappings.get(field) or [])]
        clause_list = []
        for items in selections.values():
            clause_list.extend(items or [])
        used_fallback = any(str(clause.get("base_field") or "") == field and bool(clause.get("used_fallback")) for clause in clause_list)
        if not any(mapped_field in available_fields for mapped_field in mapped_fields):
            missing_fields.append(field)
        elif used_fallback:
            partial_support = True
    if missing_fields:
        return {
            "status": "skipped_missing_fields",
            "reason": "missing_fields",
            "missing_fields": missing_fields,
            "logsource": logsource,
            "fields": fields,
            "prefilter": {},
        }
    prefilter = build_sigma_rule_prefilter_from_compiled(compiled_rule, case_profile)
    status = "runnable_partial" if partial_support else "runnable"
    return {
        "status": status,
        "reason": "partial_support" if partial_support else "compatible",
        "missing_fields": [],
        "logsource": logsource,
        "fields": fields,
        "prefilter": prefilter,
    }


def _split_field_and_modifier(field: str) -> tuple[str, str | None]:
    for suffix in MODIFIER_SUFFIXES:
        if field.endswith(suffix):
            return field[: -len(suffix)], suffix[1:]
    return field, None


def _mapped_sigma_fields(field: str) -> tuple[list[str], bool]:
    base_field, _ = _split_field_and_modifier(field)
    mapped = SIGMA_FIELD_MAP.get(base_field)
    if mapped:
        return mapped, False
    if base_field in SEARCH_TEXT_FALLBACK_FIELDS:
        return ["search_text"], True
    return [base_field], False


def _flatten_values(value: object) -> list[object]:
    if isinstance(value, list):
        return value
    return [value]


def _get_nested_value(document: dict, dotted: str) -> object:
    current: object = document
    for part in dotted.split("."):
        if not isinstance(current, dict):
            return None
        current = current.get(part)
    return current


def _document_event_id(document: dict) -> int | None:
    for field in ("windows.event_id", "event.code", "event.id"):
        value = _get_nested_value(document, field)
        if isinstance(value, list):
            value = value[0] if value else None
        if value is None:
            continue
        text = str(value).strip()
        if text.isdigit():
            return int(text)
    return None


def _document_event_labels(document: dict) -> set[str]:
    labels: set[str] = set()
    for field in ("event.type", "event.action", "artifact.type", "artifact.parser"):
        value = _get_nested_value(document, field)
        for item in _stringify_values(value):
            normalized = item.strip().lower().replace("-", "_").replace(" ", "_")
            if normalized:
                labels.add(normalized)
    return labels


def _document_channel(document: dict) -> str:
    return str(_get_nested_value(document, "windows.channel") or _get_nested_value(document, "event.channel") or "").lower()


def document_matches_sigma_logsource(logsource: dict, document: dict) -> tuple[bool, str | None]:
    product = str(logsource.get("product") or "").strip().lower()
    service = str(logsource.get("service") or "").strip().lower()
    category = str(logsource.get("category") or "").strip().lower()
    if product == "windows":
        artifact_type = str(_get_nested_value(document, "artifact.type") or "").strip().lower()
        if artifact_type and artifact_type not in {"windows_event", "evtx_raw"}:
            return False, "logsource_mismatch"
    if service:
        hints = SIGMA_SERVICE_CHANNEL_HINTS.get(service, [])
        channel = _document_channel(document)
        if hints and channel and not any(hint in channel for hint in hints):
            return False, "logsource_mismatch"
    if category:
        event_id = _document_event_id(document)
        hinted_event_ids = set(SIGMA_EVENT_ID_HINTS.get(category, []))
        if event_id is not None and hinted_event_ids and event_id not in hinted_event_ids:
            return False, "logsource_mismatch"
        labels = _document_event_labels(document)
        hinted_labels = set(SIGMA_CATEGORY_EVENT_TYPE_HINTS.get(category, []))
        if event_id is None and hinted_labels and labels and not labels.intersection(hinted_labels):
            return False, "logsource_mismatch"
        if event_id is None and not labels.intersection(hinted_labels):
            return False, "missing_logsource_fields"
    return True, None


def _stringify_values(value: object) -> list[str]:
    if value is None:
        return []
    if isinstance(value, list):
        items: list[str] = []
        for item in value:
            items.extend(_stringify_values(item))
        return items
    if isinstance(value, dict):
        return [str(value)]
    return [str(value)]


def _match_scalar(actual_values: list[str], expected: object, modifier: str | None) -> bool:
    expected_values = [str(item) for item in _flatten_values(expected)]
    if modifier == "all":
        return all(_match_scalar(actual_values, item, None) for item in expected_values)
    if modifier == "contains":
        return any(exp.lower() in actual.lower() for exp in expected_values for actual in actual_values)
    if modifier == "startswith":
        return any(actual.lower().startswith(exp.lower()) for exp in expected_values for actual in actual_values)
    if modifier == "endswith":
        return any(actual.lower().endswith(exp.lower()) for exp in expected_values for actual in actual_values)
    if modifier == "re":
        return any(re.search(exp, actual, re.IGNORECASE) for exp in expected_values for actual in actual_values)
    return any(actual.lower() == exp.lower() for exp in expected_values for actual in actual_values)


def _match_selection(selection_name: str, selection: object, document: dict) -> tuple[bool, dict[str, object], list[str]]:
    if not isinstance(selection, dict):
        return False, {}, [f"{selection_name} is not a valid mapping"]
    matched_fields: dict[str, object] = {}
    data_quality: list[str] = []
    for sigma_field, expected in selection.items():
        mapped_fields, used_fallback = _mapped_sigma_fields(str(sigma_field))
        _, modifier = _split_field_and_modifier(str(sigma_field))
        found = False
        for mapped_field in mapped_fields:
            actual_values = _stringify_values(_get_nested_value(document, mapped_field))
            if _match_scalar(actual_values, expected, modifier):
                matched_fields[str(sigma_field)] = {
                    "mapped_field": mapped_field,
                    "expected": expected,
                    "actual": actual_values[:5],
                }
                found = True
                if used_fallback:
                    data_quality.append("sigma_field_fallback_search_text")
                break
        if not found:
            return False, {}, data_quality
    return True, matched_fields, data_quality


def _tokenize_condition(condition: str) -> list[str]:
    tokens = [token for token in CONDITION_TOKENS_RE.findall(condition or "") if token.strip()]
    if not tokens:
        raise ValueError("Unsupported empty Sigma condition.")
    return [token.lower() if token.lower() in {"and", "or", "not", "(", ")"} else token for token in tokens]


def _to_rpn(tokens: list[str]) -> list[str]:
    precedence = {"or": 1, "and": 2, "not": 3}
    output: list[str] = []
    stack: list[str] = []
    for token in tokens:
        if token == "(":
            stack.append(token)
        elif token == ")":
            while stack and stack[-1] != "(":
                output.append(stack.pop())
            if not stack:
                raise ValueError("Unbalanced parentheses in Sigma condition.")
            stack.pop()
        elif token in precedence:
            while stack and stack[-1] in precedence and precedence[stack[-1]] >= precedence[token]:
                output.append(stack.pop())
            stack.append(token)
        else:
            output.append(token)
    while stack:
        token = stack.pop()
        if token in {"(", ")"}:
            raise ValueError("Unbalanced parentheses in Sigma condition.")
        output.append(token)
    return output


def _expand_selection_tokens(detection: dict, token: str) -> list[str]:
    if "*" not in token:
        return [token]
    pattern = re.compile("^" + re.escape(token).replace("\\*", ".*") + "$")
    return [name for name in detection.keys() if name != "condition" and pattern.match(name)]


def evaluate_sigma_rule(rule_data: dict, document: dict) -> dict:
    logsource_match, logsource_reason = document_matches_sigma_logsource(dict(rule_data.get("logsource") or {}), document)
    if not logsource_match:
        return {
            "matched": False,
            "matched_fields": {},
            "condition_summary": str((rule_data.get("detection") or {}).get("condition") or "").strip(),
            "expanded_condition": str((rule_data.get("detection") or {}).get("condition") or "").strip(),
            "data_quality": [],
            "skip_reason": logsource_reason,
            "expected_logsource": dict(rule_data.get("logsource") or {}),
            "actual_event_source": event_source_summary(document),
        }
    detection = dict(rule_data.get("detection") or {})
    expansion = expand_sigma_condition_terms(rule_data)
    if not expansion.get("supported"):
        raise ValueError(str(expansion.get("reason") or "Unsupported Sigma condition expression."))
    tokens = _tokenize_condition(str(expansion.get("expanded_condition") or detection.get("condition") or ""))
    rpn = _to_rpn(tokens)
    selection_results: dict[str, tuple[bool, dict[str, object], list[str]]] = {}
    stack: list[tuple[bool, dict[str, object], list[str]]] = []
    for token in rpn:
        if token == "not":
            value, matched_fields, qualities = stack.pop()
            stack.append((not value, {} if value else matched_fields, qualities))
            continue
        if token in {"and", "or"}:
            right = stack.pop()
            left = stack.pop()
            if token == "and":
                stack.append((left[0] and right[0], {**left[1], **right[1]}, left[2] + right[2]))
            else:
                matched = right if right[0] else left
                stack.append((left[0] or right[0], matched[1], left[2] + right[2]))
            continue
        expanded = _expand_selection_tokens(detection, token)
        if not expanded:
            raise ValueError(f"Unsupported Sigma condition token: {token}")
        aggregate_match = False
        aggregate_fields: dict[str, object] = {}
        aggregate_quality: list[str] = []
        for selection_name in expanded:
            if selection_name not in selection_results:
                selection_results[selection_name] = _match_selection(selection_name, detection.get(selection_name), document)
            matched, fields, quality = selection_results[selection_name]
            if matched:
                aggregate_match = True
                aggregate_fields.update(fields)
            aggregate_quality.extend(quality)
        stack.append((aggregate_match, aggregate_fields, aggregate_quality))
    if len(stack) != 1:
        raise ValueError("Unsupported Sigma condition expression.")
    matched, fields, quality = stack[0]
    return {
        "matched": matched,
        "matched_fields": fields,
        "condition_summary": str(detection.get("condition") or "").strip(),
        "expanded_condition": str(expansion.get("expanded_condition") or detection.get("condition") or "").strip(),
        "data_quality": sorted(set(quality)),
        "expected_logsource": dict(rule_data.get("logsource") or {}),
        "actual_event_source": event_source_summary(document),
    }


def evaluate_compiled_sigma_rule(compiled_rule: dict, document: dict) -> dict:
    logsource = dict(compiled_rule.get("sigma_logsource") or {})
    logsource_match, logsource_reason = document_matches_sigma_logsource(logsource, document)
    if not logsource_match:
        return {
            "matched": False,
            "matched_fields": {},
            "condition_summary": str(compiled_rule.get("condition") or "").strip(),
            "expanded_condition": str(compiled_rule.get("expanded_condition") or compiled_rule.get("condition") or "").strip(),
            "data_quality": [],
            "skip_reason": logsource_reason,
            "expected_logsource": logsource,
            "actual_event_source": event_source_summary(document),
        }
    selections = dict((compiled_rule.get("compiled_query") or {}).get("selections") or {})
    rpn = list((compiled_rule.get("compiled_query") or {}).get("condition_rpn") or [])
    selection_results: dict[str, tuple[bool, dict[str, object], list[str]]] = {}
    stack: list[tuple[bool, dict[str, object], list[str]]] = []
    for token in rpn:
        if token == "not":
            value, matched_fields, qualities = stack.pop()
            stack.append((not value, {} if value else matched_fields, qualities))
            continue
        if token in {"and", "or"}:
            right = stack.pop()
            left = stack.pop()
            if token == "and":
                stack.append((left[0] and right[0], {**left[1], **right[1]}, left[2] + right[2]))
            else:
                matched = right if right[0] else left
                stack.append((left[0] or right[0], matched[1], left[2] + right[2]))
            continue
        expanded = _expand_selection_tokens({"condition": compiled_rule.get("condition"), **selections}, token)
        if not expanded:
            raise ValueError(f"Unsupported Sigma condition token: {token}")
        aggregate_match = False
        aggregate_fields: dict[str, object] = {}
        aggregate_quality: list[str] = []
        for selection_name in expanded:
            if selection_name not in selection_results:
                matched_fields: dict[str, object] = {}
                qualities: list[str] = []
                matched = True
                for clause in selections.get(selection_name) or []:
                    actual_hit = False
                    modifier = str(clause.get("modifier") or "") or None
                    expected = clause.get("expected")
                    for mapped_field in clause.get("mapped_fields") or []:
                        actual_values = _stringify_values(_get_nested_value(document, str(mapped_field)))
                        if _match_scalar(actual_values, expected, modifier):
                            matched_fields[str(clause.get("sigma_field") or clause.get("base_field"))] = {
                                "mapped_field": mapped_field,
                                "expected": expected,
                                "actual": actual_values[:5],
                            }
                            actual_hit = True
                            if clause.get("used_fallback"):
                                qualities.append("sigma_field_fallback_search_text")
                            break
                    if not actual_hit:
                        matched = False
                        matched_fields = {}
                        break
                selection_results[selection_name] = (matched, matched_fields, qualities)
            matched, fields, quality = selection_results[selection_name]
            if matched:
                aggregate_match = True
                aggregate_fields.update(fields)
            aggregate_quality.extend(quality)
        stack.append((aggregate_match, aggregate_fields, aggregate_quality))
    if len(stack) != 1:
        raise ValueError("Unsupported Sigma condition expression.")
    matched, fields, quality = stack[0]
    return {
        "matched": matched,
        "matched_fields": fields,
        "condition_summary": str(compiled_rule.get("condition") or "").strip(),
        "expanded_condition": str(compiled_rule.get("expanded_condition") or compiled_rule.get("condition") or "").strip(),
        "data_quality": sorted(set(quality)),
        "expected_logsource": logsource,
        "actual_event_source": event_source_summary(document),
    }


def event_source_summary(document: dict) -> dict:
    return {
        "artifact_type": _get_nested_value(document, "artifact.type"),
        "artifact_parser": _get_nested_value(document, "artifact.parser"),
        "channel": _get_nested_value(document, "windows.channel") or _get_nested_value(document, "event.channel"),
        "provider": _get_nested_value(document, "windows.provider") or _get_nested_value(document, "event.provider"),
        "event_id": _document_event_id(document),
        "event_type": _get_nested_value(document, "event.type"),
        "event_action": _get_nested_value(document, "event.action"),
    }


def build_sigma_query(rule_data: dict) -> dict:
    detection = dict(rule_data.get("detection") or {})
    should: list[dict] = []
    for selection_name, selection in detection.items():
        if selection_name == "condition" or not isinstance(selection, dict):
            continue
        for sigma_field, expected in selection.items():
            mapped_fields, _ = _mapped_sigma_fields(str(sigma_field))
            _, modifier = _split_field_and_modifier(str(sigma_field))
            values = [str(item) for item in _flatten_values(expected)]
            for mapped_field in mapped_fields:
                if modifier is None and len(values) == 1:
                    should.append({"term": {mapped_field: values[0]}})
                elif modifier is None and len(values) > 1:
                    should.append({"terms": {mapped_field: values}})
                elif modifier == "startswith" and values:
                    should.append({"prefix": {mapped_field: values[0]}})
                elif modifier == "endswith" and values:
                    should.append({"wildcard": {mapped_field: f"*{values[0]}"}})
                elif modifier == "contains" and values:
                    should.append({"wildcard": {mapped_field: f"*{values[0]}*"}})
                elif modifier == "re" and values:
                    should.append({"regexp": {mapped_field: values[0]}})
    bool_query: dict[str, object] = {"must": []}
    if should:
        bool_query["should"] = should[:50]
        bool_query["minimum_should_match"] = 1
    return {"query": {"bool": bool_query}}


def build_sigma_query_from_compiled(compiled_rule: dict) -> dict:
    should: list[dict] = []
    for clauses in dict((compiled_rule.get("compiled_query") or {}).get("selections") or {}).values():
        for clause in clauses or []:
            mapped_fields = [str(item) for item in (clause.get("mapped_fields") or [])]
            modifier = str(clause.get("modifier") or "") or None
            values = [str(item) for item in _flatten_values(clause.get("expected"))]
            for mapped_field in mapped_fields:
                if modifier is None and len(values) == 1:
                    should.append({"term": {mapped_field: values[0]}})
                elif modifier is None and len(values) > 1:
                    should.append({"terms": {mapped_field: values}})
                elif modifier == "startswith" and values:
                    should.append({"prefix": {mapped_field: values[0]}})
                elif modifier == "endswith" and values:
                    should.append({"wildcard": {mapped_field: f"*{values[0]}"}})
                elif modifier == "contains" and values:
                    should.append({"wildcard": {mapped_field: f"*{values[0]}*"}})
                elif modifier == "re" and values:
                    should.append({"regexp": {mapped_field: values[0]}})
    bool_query: dict[str, object] = {"must": []}
    if should:
        bool_query["should"] = should[:50]
        bool_query["minimum_should_match"] = 1
    return {"query": {"bool": bool_query}}
