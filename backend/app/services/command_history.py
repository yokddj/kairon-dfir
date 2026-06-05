from __future__ import annotations

from collections import Counter
from datetime import UTC, datetime, timedelta
import hashlib
import re
from typing import Any

from dateutil import parser as date_parser

from app.core.opensearch import get_events_index, search_documents
from app.services.host_identity import normalize_host_alias


COMMAND_SOURCE_EVENT_IDS = {1, 4688, 4103, 4104, 400, 403, 600, 4698, 4702, 4700, 4701}
COMMAND_FETCH_LIMIT = 5000
SOURCE_PRIORITY = {
    "sysmon_1": 10,
    "security_4688": 20,
    "powershell_operational": 30,
    "transcript": 40,
    "psreadline": 50,
    "scheduled_task": 60,
    "prefetch": 70,
    "other": 90,
}

POWERSHELL_LAUNCHERS = {"powershell.exe", "powershell", "pwsh.exe", "pwsh", "powershell_ise.exe", "powershell_ise"}
CMD_LAUNCHERS = {"cmd.exe", "cmd"}
SCRIPT_HOST_LAUNCHERS = {"wscript.exe", "wscript", "cscript.exe", "cscript", "mshta.exe", "mshta", "hh.exe", "hh"}
LOLBIN_LAUNCHERS = {
    "rundll32.exe",
    "rundll32",
    "regsvr32.exe",
    "regsvr32",
    "certutil.exe",
    "certutil",
    "bitsadmin.exe",
    "bitsadmin",
    "msiexec.exe",
    "msiexec",
    "installutil.exe",
    "installutil",
    "reg.exe",
    "reg",
    "schtasks.exe",
    "schtasks",
    "wmic.exe",
    "wmic",
    "net.exe",
    "net",
    "net1.exe",
    "net1",
    "nltest.exe",
    "nltest",
    "tasklist.exe",
    "tasklist",
    "taskkill.exe",
    "taskkill",
    "sc.exe",
    "sc",
    "at.exe",
    "at",
    "forfiles.exe",
    "forfiles",
    "odbcconf.exe",
    "odbcconf",
    "cmstp.exe",
    "cmstp",
}
REMOTE_EXEC_LAUNCHERS = {"psexec.exe", "psexec", "psexesvc.exe", "psexesvc", "winrs.exe", "winrs"}
DISCOVERY_LAUNCHERS = {"whoami.exe", "whoami", "net.exe", "net", "net1.exe", "net1", "nltest.exe", "nltest", "ipconfig.exe", "ipconfig", "hostname.exe", "hostname"}
SYSTEM_LAUNCHERS = {"services.exe", "svchost.exe", "lsass.exe", "winlogon.exe", "csrss.exe", "smss.exe", "spoolsv.exe", "conhost.exe"}
BROWSER_LAUNCHERS = {"chrome.exe", "chrome", "msedge.exe", "msedge", "firefox.exe", "firefox", "iexplore.exe", "iexplore"}
INSTALLER_LAUNCHERS = {"setup.exe", "installer.exe", "msiexec.exe", "msiexec"}


def get_command_history(case_id: str, params: dict[str, Any]) -> dict[str, Any]:
    page = max(1, _to_int(params.get("page"), 1) or 1)
    page_size = min(max(_to_int(params.get("page_size"), 100) or 100, 1), 500)
    events = _fetch_candidate_events(case_id, params)
    commands = _dedupe_commands([item for event in events for item in _commands_from_event(case_id, event)])
    commands = _apply_filters(commands, params)
    sort = _resolve_sort(params)
    reverse = sort == "timestamp_desc"
    dated = [item for item in commands if item.get("timestamp")]
    undated = [item for item in commands if not item.get("timestamp")]
    dated.sort(key=lambda item: (_safe_dt(item.get("timestamp")), item.get("command_normalized") or ""), reverse=reverse)
    commands = dated + sorted(undated, key=lambda item: item.get("command_normalized") or "")
    total = len(commands)
    start = (page - 1) * page_size
    items = commands[start:start + page_size]
    return {
        "total": total,
        "page": page,
        "page_size": page_size,
        "sort": sort,
        "sort_by": "timestamp",
        "sort_order": "desc" if reverse else "asc",
        "items": items,
        "facets": _facets(commands),
        "summary": {
            "commands_total": total,
            "suspicious_total": sum(1 for item in commands if int(item.get("risk_score") or 0) >= 50),
            "high_confidence": sum(1 for item in commands if item.get("confidence") == "high"),
            "with_command_line": sum(1 for item in commands if item.get("command")),
            "with_supporting_events": sum(1 for item in commands if len(item.get("supporting_events") or []) > 1),
        },
    }


def _fetch_candidate_events(case_id: str, params: dict[str, Any]) -> list[dict[str, Any]]:
    filters: list[dict[str, Any]] = [{"term": {"case_id": case_id}}]
    evidence_id = str(params.get("evidence_id") or "").strip()
    if evidence_id:
        filters.append({"term": {"evidence_id": evidence_id}})
    # Host aliases are intentionally filtered after retrieval. Some ingests store
    # HOSTA as hosta.domain.local, and a strict OpenSearch terms filter would miss
    # those commands before canonical alias matching can run.
    time_from = str(params.get("time_from") or "").strip()
    time_to = str(params.get("time_to") or "").strip()
    if time_from or time_to:
        range_filter: dict[str, Any] = {}
        if time_from:
            range_filter["gte"] = time_from
        if time_to:
            range_filter["lte"] = time_to
        filters.append({"range": {"@timestamp": range_filter}})
    should = [
        {"term": {"windows.event_id": 1}},
        {"term": {"windows.event_id": 4688}},
        {"terms": {"windows.event_id": [4103, 4104, 400, 403, 600]}},
        {"terms": {"windows.event_id": [4698, 4702, 4700, 4701]}},
        {"exists": {"field": "powershell.command"}},
        {"exists": {"field": "powershell.command_preview"}},
        {"exists": {"field": "task.command"}},
        {"exists": {"field": "process.command_line"}},
        {"term": {"artifact.type": "prefetch"}},
    ]
    q = str(params.get("q") or "").strip()
    if q:
        should.append({"simple_query_string": {"query": q, "fields": ["process.command_line", "powershell.command", "powershell.command_preview", "task.command", "search_text"], "default_operator": "and"}})
    body = {
        "size": COMMAND_FETCH_LIMIT,
        "query": {"bool": {"filter": filters, "should": should, "minimum_should_match": 1}},
        "sort": [{"@timestamp": {"order": "asc", "missing": "_last"}}, {"event_id": {"order": "asc", "missing": "_last"}}],
    }
    result = search_documents(get_events_index(case_id), body)
    events: list[dict[str, Any]] = []
    for hit in result.get("hits", {}).get("hits", []):
        source = dict(hit.get("_source") or {})
        source["id"] = source.get("id") or hit.get("_id")
        events.append(source)
    return events


def _commands_from_event(case_id: str, event: dict[str, Any]) -> list[dict[str, Any]]:
    windows = _obj(event.get("windows"))
    event_id = _to_int(windows.get("event_id") or event.get("event_id"), None)
    process = _obj(event.get("process"))
    parent = _obj(process.get("parent")) or _obj(_obj(event.get("parent")).get("process"))
    powershell = _obj(event.get("powershell"))
    task = _obj(event.get("task"))
    source_type = _source_type(event, event_id)
    commands: list[str] = []
    if source_type in {"sysmon_1", "security_4688"}:
        commands.append(_first(process.get("command_line"), process.get("executable"), process.get("path"), process.get("name")))
    elif source_type == "powershell_operational":
        commands.append(_first(powershell.get("command"), powershell.get("command_preview"), process.get("command_line"), event.get("search_text")))
    elif source_type == "scheduled_task":
        command = " ".join(part for part in [task.get("command"), task.get("arguments")] if part)
        commands.append(command or _first(process.get("command_line"), event.get("search_text")))
    elif source_type == "psreadline":
        commands.append(_first(powershell.get("command"), powershell.get("command_preview"), event.get("search_text")))
    elif source_type == "transcript":
        commands.append(_first(powershell.get("command"), powershell.get("command_preview"), event.get("search_text")))
    elif source_type == "prefetch":
        commands.append(_first(process.get("executable"), process.get("path"), process.get("name"), event.get("key_entity")))
    else:
        commands.append(_first(process.get("command_line"), powershell.get("command"), task.get("command"), event.get("key_entity")))
    output = []
    for command in commands:
        command = _clean(command)
        if not command:
            continue
        classification = _classify_command(command, process, parent, source_type)
        risk_score, risk_reasons = _risk(command, process, parent)
        timestamp = event.get("@timestamp")
        event_doc_id = str(event.get("id") or event.get("search_doc_id") or event.get("opensearch_id") or event.get("event_id") or "")
        windows_event_id = str(event_id or event.get("event_id") or "")
        item = {
            "id": _command_id(case_id, event_doc_id, command),
            "case_id": case_id,
            "evidence_id": event.get("evidence_id"),
            "host": _first(_obj(event.get("host")).get("name"), _obj(event.get("host")).get("hostname")),
            "timestamp": timestamp,
            "timestamp_status": _timestamp_status(event),
            "command": command,
            "command_normalized": _normalize_command(command),
            "shell": classification["shell_family"],
            "launcher": classification["launcher"],
            "launcher_path": classification["launcher_path"],
            "shell_family": classification["shell_family"],
            "classification_confidence": classification["classification_confidence"],
            "parent_shell": classification["parent_shell"],
            "parent_context": classification["parent_context"],
            "source_type": source_type,
            "source_event_id": event_doc_id,
            "windows_event_id": windows_event_id,
            "source_file": event.get("source_file"),
            "user": _first(_obj(event.get("user")).get("name"), powershell.get("user")),
            "process": {
                "name": process.get("name"),
                "executable": _first(process.get("executable"), process.get("path")),
                "pid": process.get("pid"),
                "guid": _first(process.get("guid"), process.get("entity_id")),
                "command_line": process.get("command_line"),
            },
            "parent_process": {
                "name": _first(parent.get("name"), process.get("parent_name")),
                "executable": _first(parent.get("executable"), parent.get("path"), process.get("parent_path")),
                "pid": _first(parent.get("pid"), process.get("parent_pid"), process.get("ppid")),
                "guid": _first(parent.get("guid"), parent.get("entity_id"), process.get("parent_entity_id")),
                "command_line": _first(parent.get("command_line"), process.get("parent_command_line")),
            },
            "working_directory": process.get("working_directory"),
            "risk_score": risk_score,
            "risk_reasons": risk_reasons,
            "confidence": _confidence(source_type, command, timestamp),
            "dedupe_key": "",
            "supporting_events": [_supporting_event(event, source_type)],
            "linked_search_url": _search_url(case_id, event.get("evidence_id"), event_doc_id),
        }
        item["dedupe_key"] = _dedupe_key(item)
        output.append(item)
    return output


def _resolve_sort(params: dict[str, Any]) -> str:
    raw_sort = str(params.get("sort") or "").strip().lower()
    raw_by = str(params.get("sort_by") or "").strip().lower()
    raw_order = str(params.get("sort_order") or "").strip().lower()
    if raw_sort in {"timestamp_asc", "timestamp_desc"}:
        return raw_sort
    if raw_by in {"", "timestamp", "@timestamp"} and raw_order in {"asc", "desc"}:
        return f"timestamp_{raw_order}"
    return "timestamp_desc"


def _dedupe_commands(items: list[dict[str, Any]]) -> list[dict[str, Any]]:
    groups: dict[str, dict[str, Any]] = {}
    for item in items:
        key = str(item.get("dedupe_key") or item.get("id"))
        existing = groups.get(key)
        if not existing:
            groups[key] = item
            continue
        existing["supporting_events"] = _dedupe_supporting((existing.get("supporting_events") or []) + (item.get("supporting_events") or []))
        existing["risk_score"] = max(int(existing.get("risk_score") or 0), int(item.get("risk_score") or 0))
        existing["risk_reasons"] = sorted(set(existing.get("risk_reasons") or []) | set(item.get("risk_reasons") or []))
        if SOURCE_PRIORITY.get(str(item.get("source_type")), 99) < SOURCE_PRIORITY.get(str(existing.get("source_type")), 99):
            item["supporting_events"] = existing["supporting_events"]
            item["risk_score"] = existing["risk_score"]
            item["risk_reasons"] = existing["risk_reasons"]
            groups[key] = item
    return list(groups.values())


def _apply_filters(items: list[dict[str, Any]], params: dict[str, Any]) -> list[dict[str, Any]]:
    q = str(params.get("q") or "").strip().lower()
    shell = str(params.get("shell") or params.get("family") or "").strip().lower()
    launcher = str(params.get("launcher") or "").strip().lower()
    classification_confidence = str(params.get("classification_confidence") or params.get("confidence") or "").strip().lower()
    source_type = str(params.get("source_type") or "").strip().lower()
    user = str(params.get("user") or "").strip().lower()
    host = str(params.get("host") or "").strip()
    host_aliases = _host_aliases(host)
    risk_min = _to_int(params.get("risk_min"), None)
    risk_max = _to_int(params.get("risk_max"), None)
    only_suspicious = _truthy(params.get("only_suspicious"))
    has_supporting = _truthy(params.get("has_supporting_sources"))
    output = []
    for item in items:
        haystack = " ".join(str(item.get(key) or "") for key in ("command", "user", "host", "source_file")).lower()
        if q and q not in haystack:
            continue
        if shell and str(item.get("shell_family") or item.get("shell") or "").lower() != shell:
            continue
        if launcher and launcher not in str(item.get("launcher") or "").lower() and launcher not in str(item.get("launcher_path") or "").lower():
            continue
        if classification_confidence and str(item.get("classification_confidence") or "").lower() != classification_confidence:
            continue
        if source_type and str(item.get("source_type") or "").lower() != source_type:
            continue
        if user and user not in str(item.get("user") or "").lower():
            continue
        if host_aliases and not _host_matches(item.get("host"), host_aliases):
            continue
        if risk_min is not None and int(item.get("risk_score") or 0) < risk_min:
            continue
        if risk_max is not None and int(item.get("risk_score") or 0) > risk_max:
            continue
        if only_suspicious and int(item.get("risk_score") or 0) < 50:
            continue
        if has_supporting and len(item.get("supporting_events") or []) < 2:
            continue
        output.append(item)
    return output


def _facets(items: list[dict[str, Any]]) -> dict[str, dict[str, int]]:
    return {
        "shell": dict(Counter(str(item.get("shell_family") or item.get("shell") or "unknown") for item in items)),
        "family": dict(Counter(str(item.get("shell_family") or item.get("shell") or "unknown") for item in items)),
        "launcher": dict(Counter(str(item.get("launcher") or "unknown") for item in items)),
        "confidence": dict(Counter(str(item.get("classification_confidence") or item.get("confidence") or "unknown") for item in items)),
        "source_type": dict(Counter(str(item.get("source_type") or "other") for item in items)),
        "user": dict(Counter(str(item.get("user") or "unknown") for item in items)),
        "host": dict(Counter(str(item.get("host") or "unknown") for item in items)),
        "risk": dict(Counter(_risk_bucket(int(item.get("risk_score") or 0)) for item in items)),
    }


def _source_type(event: dict[str, Any], event_id: int | None) -> str:
    artifact_type = str(_obj(event.get("artifact")).get("type") or "").lower()
    channel = str(_obj(event.get("event")).get("channel") or _obj(event.get("windows")).get("channel") or "").lower()
    provider = str(_obj(event.get("event")).get("provider") or _obj(event.get("windows")).get("provider") or "").lower()
    source_file = str(event.get("source_file") or "").lower()
    if event_id == 1 and ("sysmon" in channel or "sysmon" in provider):
        return "sysmon_1"
    if event_id == 4688:
        return "security_4688"
    if event_id in {4103, 4104, 400, 403, 600} or "powershell" in channel or artifact_type == "powershell":
        if "consolehost_history" in source_file or "psreadline" in source_file:
            return "psreadline"
        if "transcript" in source_file:
            return "transcript"
        return "powershell_operational"
    if event_id in {4698, 4702, 4700, 4701} or artifact_type == "scheduled_task" or _obj(event.get("task")).get("command"):
        return "scheduled_task"
    if artifact_type == "prefetch":
        return "prefetch"
    return "other"


def _risk(command: str, process: dict[str, Any], parent: dict[str, Any]) -> tuple[int, list[str]]:
    lower = command.lower()
    reasons: list[str] = []
    score = 0
    checks = [
        (("-enc", "-encodedcommand", "frombase64string"), 35, "encoded command or base64 decoding"),
        (("-ep bypass", "executionpolicy bypass", "-executionpolicy bypass"), 30, "PowerShell execution policy bypass"),
        (("-w hidden", "windowstyle hidden", "-windowstyle hidden"), 20, "hidden window execution"),
        (("invoke-webrequest", "webclient", "downloadstring", "curl ", "certutil", "bitsadmin"), 25, "download cradle or file transfer utility"),
        (("rundll32", "regsvr32", "mshta", "wscript", "cscript"), 25, "suspicious LOLBin execution"),
        (("psexec", "psexesvc"), 30, "PsExec activity"),
        (("\\temp\\", "\\downloads\\", "\\appdata\\"), 15, "execution path in user-writable location"),
        (("maintenance.ps1", "example-control.test"), 45, "Synthetic indicator"),
        (("whoami",), 10, "reconnaissance command"),
    ]
    for tokens, points, reason in checks:
        if any(token in lower for token in tokens):
            score += points
            reasons.append(reason)
    parent_name = str(parent.get("name") or process.get("parent_name") or "").lower()
    proc_name = str(process.get("name") or "").lower()
    if any(parent in parent_name for parent in ("winword", "excel", "chrome", "firefox", "msedge", "explorer")) and any(child in proc_name or child in lower for child in ("powershell", "cmd.exe")):
        score += 20
        reasons.append("suspicious parent-child relationship")
    return min(score, 100), sorted(set(reasons))


def _classify_command(command: str, process: dict[str, Any], parent: dict[str, Any], source_type: str) -> dict[str, str]:
    launcher_path = _first(process.get("executable"), process.get("path"))
    launcher = _normalize_launcher(_first(process.get("name"), launcher_path, _first_executable(command)))
    effective = _normalize_launcher(_first_executable(command))
    text = f"{launcher} {launcher_path or ''} {command}".lower()
    parent_shell = _classify_launcher(_normalize_launcher(_first(parent.get("name"), parent.get("executable"))), "").get("family", "")
    if parent_shell == "unknown":
        parent_shell = ""

    source_hint = "medium" if source_type in {"prefetch", "scheduled_task", "transcript", "psreadline"} else "high"
    if source_type in {"powershell_operational", "psreadline", "transcript"}:
        family = "powershell"
        if launcher == "unknown":
            launcher = "powershell"
    elif source_type == "scheduled_task" and launcher == "unknown":
        family = "scheduled_task"
        launcher = effective if effective != "unknown" else "scheduled_task"
    else:
        classified = _classify_launcher(launcher, text)
        family = classified["family"]

    if family in {"cmd", "binary_execution", "unknown"}:
        invoked = _classify_launcher(effective, text)
        if invoked["family"] in {"powershell", "script_host", "remote_exec", "lolbin"}:
            family = invoked["family"]
            if launcher == "unknown":
                launcher = effective

    if "psexec" in text or re.search(r"\\\\[a-z0-9_.-]+\\s+-accepteula", text):
        family = "remote_exec"
    elif any(token in text for token in ("-encodedcommand", " -enc ", "-ep bypass", "executionpolicy bypass", "-nop", "-w hidden")) and ("powershell" in text or launcher == "unknown"):
        family = "powershell"
        if launcher == "unknown":
            launcher = "powershell"

    if family == "unknown" and launcher != "unknown":
        family = "binary_execution"

    confidence = source_hint if launcher != "unknown" or family != "unknown" else "low"
    parent_context = ""
    if source_type == "scheduled_task":
        parent_context = "scheduled_task"
    elif parent_shell:
        parent_context = parent_shell
    return {
        "launcher": launcher,
        "launcher_path": str(launcher_path or ""),
        "shell_family": family,
        "classification_confidence": confidence,
        "parent_shell": parent_shell,
        "parent_context": parent_context,
    }


def _classify_launcher(launcher: str, text: str) -> dict[str, str]:
    if launcher in POWERSHELL_LAUNCHERS or "powershell" in text or "pwsh" in text:
        return {"family": "powershell"}
    if launcher in CMD_LAUNCHERS:
        return {"family": "cmd"}
    if launcher in SCRIPT_HOST_LAUNCHERS:
        return {"family": "script_host"}
    if launcher in REMOTE_EXEC_LAUNCHERS:
        return {"family": "remote_exec"}
    if launcher in LOLBIN_LAUNCHERS or "rundll32" in text or "regsvr32" in text or "mshta" in text:
        return {"family": "lolbin"}
    if launcher in DISCOVERY_LAUNCHERS:
        return {"family": "binary_execution"}
    if launcher in BROWSER_LAUNCHERS:
        return {"family": "browser"}
    if launcher in INSTALLER_LAUNCHERS:
        return {"family": "installer"}
    if launcher in SYSTEM_LAUNCHERS:
        return {"family": "system"}
    if launcher and launcher != "unknown":
        return {"family": "binary_execution"}
    return {"family": "unknown"}


def _normalize_launcher(value: Any) -> str:
    text = str(value or "").strip().strip('"').strip("'")
    if not text:
        return "unknown"
    text = text.replace("/", "\\")
    text = text.rsplit("\\", 1)[-1]
    text = text.split(" ", 1)[0]
    return text.lower() or "unknown"


def _first_executable(command: str) -> str:
    text = str(command or "").strip()
    if not text:
        return ""
    quoted = re.match(r'^"([^"]+)"', text)
    if quoted:
        return quoted.group(1)
    path = re.search(r"(?i)([a-z]:\\[^\s\"']+?\.exe)\b", text)
    if path:
        return path.group(1)
    exe = re.search(r"(?i)\b([a-z0-9_.-]+\.exe)\b", text)
    if exe:
        return exe.group(1)
    token = text.split()[0] if text.split() else ""
    if token.lower() in {"/c", "/k"} and len(text.split()) > 1:
        return text.split()[1]
    return token


def _confidence(source_type: str, command: str, timestamp: Any) -> str:
    if source_type in {"sysmon_1", "security_4688", "powershell_operational"} and command and timestamp:
        return "high"
    if source_type in {"scheduled_task", "transcript"}:
        return "medium"
    return "low"


def _dedupe_key(item: dict[str, Any]) -> str:
    guid = str(_obj(item.get("process")).get("guid") or "").lower()
    if guid:
        return f"{item.get('case_id')}|{item.get('host')}|{guid}|{item.get('command_normalized')}"
    bucket = _time_bucket(item.get("timestamp"))
    proc = _obj(item.get("process"))
    return f"{item.get('case_id')}|{item.get('host')}|{bucket}|{proc.get('pid')}|{proc.get('executable') or proc.get('name')}|{item.get('command_normalized')}"


def _supporting_event(event: dict[str, Any], source_type: str) -> dict[str, Any]:
    artifact = _obj(event.get("artifact"))
    windows = _obj(event.get("windows"))
    return {
        "event_id": event.get("id") or event.get("event_id"),
        "stable_event_id": event.get("stable_event_id") or event.get("event_fingerprint"),
        "source_type": source_type,
        "windows_event_id": windows.get("event_id"),
        "timestamp": event.get("@timestamp"),
        "source_file": event.get("source_file"),
        "artifact_type": artifact.get("type"),
        "parser": artifact.get("parser"),
    }


def _dedupe_supporting(events: list[dict[str, Any]]) -> list[dict[str, Any]]:
    seen = set()
    output = []
    for event in events:
        key = str(event.get("event_id") or event.get("stable_event_id") or event)
        if key in seen:
            continue
        seen.add(key)
        output.append(event)
    return output


def _timestamp_status(event: dict[str, Any]) -> str:
    status = str(event.get("timestamp_status") or "").lower()
    if status in {"suspicious", "invalid"}:
        return "suspicious"
    if event.get("@timestamp"):
        return "forensic"
    return "missing"


def _search_url(case_id: str, evidence_id: Any, event_id: str) -> str:
    params = [f"event_id={event_id}", "tab=results"]
    if evidence_id:
        params.append(f"evidence_id={evidence_id}")
    return f"/cases/{case_id}/search?{'&'.join(params)}"


def _command_id(case_id: str, event_id: str, command: str) -> str:
    return hashlib.sha1(f"{case_id}|{event_id}|{command}".encode("utf-8", errors="ignore")).hexdigest()


def _normalize_command(command: str) -> str:
    return re.sub(r"\s+", " ", command).strip().lower()


def _risk_bucket(score: int) -> str:
    if score >= 75:
        return "critical"
    if score >= 50:
        return "high"
    if score >= 25:
        return "medium"
    if score > 0:
        return "low"
    return "none"


def _time_bucket(value: Any) -> str:
    dt = _safe_dt(value)
    epoch = int(dt.timestamp())
    return str(epoch - (epoch % 2))


def _safe_dt(value: Any) -> datetime:
    if isinstance(value, datetime):
        return value if value.tzinfo else value.replace(tzinfo=UTC)
    if not value:
        return datetime.max.replace(tzinfo=UTC)
    try:
        parsed = date_parser.parse(str(value))
        return parsed if parsed.tzinfo else parsed.replace(tzinfo=UTC)
    except Exception:
        return datetime.max.replace(tzinfo=UTC)


def _obj(value: Any) -> dict[str, Any]:
    return value if isinstance(value, dict) else {}


def _first(*values: Any) -> str:
    for value in values:
        text = _clean(value)
        if text:
            return text
    return ""


def _clean(value: Any) -> str:
    return str(value or "").replace("\x00", " ").strip()


def _to_int(value: Any, default: int | None) -> int | None:
    try:
        return int(value)
    except (TypeError, ValueError):
        return default


def _truthy(value: Any) -> bool:
    return str(value or "").strip().lower() in {"1", "true", "yes", "on"}


def _host_aliases(host: str) -> set[str]:
    normalized = normalize_host_alias(host)
    aliases = {normalized} if normalized else set()
    if normalized and "." in normalized:
        aliases.add(normalized.split(".", 1)[0])
    return {alias for alias in aliases if alias}


def _host_matches(value: Any, aliases: set[str]) -> bool:
    normalized = normalize_host_alias(str(value or ""))
    if not normalized:
        return False
    candidates = {normalized}
    if "." in normalized:
        candidates.add(normalized.split(".", 1)[0])
    return bool(candidates & aliases)
