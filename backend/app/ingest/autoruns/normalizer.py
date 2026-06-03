from __future__ import annotations

from pathlib import Path

from app.ingest.autoruns.helpers import (
    basename_windows,
    classify_autoruns_entry,
    classify_autoruns_suspicion,
    clean_value,
    detect_missing_or_invalid_path,
    detect_user_writable_path,
    extract_arguments_from_launch_string,
    extract_executable_path_from_launch_string,
    extract_urls_domains_paths,
    first_nonempty,
    normalize_windows_path,
    parse_boolish,
    parse_hash,
    parse_timestamp,
    parse_vt_detection,
    suffix_windows,
)
from app.ingest.windows_event_mapping import risk_score_to_severity


def normalize_autoruns_row(document: dict, row: dict, artifact_meta: dict) -> dict:
    hive = clean_value(first_nonempty(row, "Hive"))
    key_path = clean_value(first_nonempty(row, "KeyPath", "Key Path"))
    value_name = clean_value(first_nonempty(row, "ValueName", "Value Name"))
    value_data = clean_value(first_nonempty(row, "ValueData", "Value Data"))
    raw_path = normalize_windows_path(first_nonempty(row, "Path"))
    raw_command = clean_value(first_nonempty(row, "Command"))
    category = clean_value(first_nonempty(row, "Category"))
    entry_location = clean_value(first_nonempty(row, "Entry Location", "EntryLocation", "Run Key")) or key_path or raw_path
    entry_name = clean_value(first_nonempty(row, "Entry", "Name", "Task Name", "Service Name")) or value_name
    enabled = parse_boolish(first_nonempty(row, "Enabled"))
    profile = clean_value(first_nonempty(row, "Profile", "User"))
    description = clean_value(first_nonempty(row, "Description"))
    publisher = clean_value(first_nonempty(row, "Publisher"))
    company = clean_value(first_nonempty(row, "Company"))
    signer = clean_value(first_nonempty(row, "Signer"))
    launch_string = clean_value(first_nonempty(row, "Launch String", "LaunchString", "Command Line", "CommandLine")) or raw_command or value_data or raw_path
    image_path = normalize_windows_path(first_nonempty(row, "Image Path", "ImagePath", "Path"))
    if not image_path:
        image_path = extract_executable_path_from_launch_string(launch_string)
    command_line = launch_string or image_path
    arguments = extract_arguments_from_launch_string(launch_string)
    working_directory = normalize_windows_path(first_nonempty(row, "Working Directory", "WorkingDirectory"))
    classification_location = " ".join(part for part in [entry_location, value_name] if part)
    mechanism, artifact_type = classify_autoruns_entry(classification_location or entry_location, category, image_path, launch_string or value_data)
    timestamp = parse_timestamp(first_nonempty(row, "Time", "Timestamp", "LastWriteTime"))
    last_write = parse_timestamp(first_nonempty(row, "LastWriteTime"))
    timestamp = last_write or timestamp
    signed = parse_boolish(first_nonempty(row, "Signed"))
    verified = parse_boolish(first_nonempty(row, "Verified"))
    vt_detection = parse_vt_detection(first_nonempty(row, "VT detection", "VirusTotal", "VTDetection"))
    urls_domains_paths = extract_urls_domains_paths(command_line, image_path)
    user_name = clean_value(first_nonempty(row, "User"))
    sid = clean_value(first_nonempty(row, "SID"))
    wow64 = parse_boolish(first_nonempty(row, "Wow64"))

    parser_name = str(artifact_meta.get("parser") or "autoruns_csv")
    document["artifact"]["type"] = "autorun"
    document["artifact"]["parser"] = parser_name
    document["event"]["category"] = "persistence"
    document["event"]["type"] = "autorun"
    document["event"]["action"] = "autorun_entry_observed"
    document["event"]["severity"] = "info"
    document["event"]["message"] = f"Autorun entry observed: {entry_location or 'unknown'} -> {command_line or image_path or 'unknown'}"
    registry_hive = hive or ("NTUSER" if document.get("persistence", {}).get("scope") == "user" else "SOFTWARE")

    document["autoruns"].update(
        {
            "artifact_type": artifact_type,
            "category": category,
            "entry_location": entry_location,
            "entry": entry_name,
            "enabled": enabled,
            "profile": profile,
            "description": description,
            "publisher": publisher,
            "company": company,
            "signer": signer,
            "signed": signed,
            "verified": verified,
            "image_path": image_path,
            "launch_string": launch_string,
            "command_line": command_line,
            "arguments": arguments,
            "working_directory": working_directory,
            "hash_md5": parse_hash(first_nonempty(row, "MD5"), {32}),
            "hash_sha1": parse_hash(first_nonempty(row, "SHA-1", "SHA1"), {40}),
            "hash_sha256": parse_hash(first_nonempty(row, "SHA-256", "SHA256"), {64}),
            "pe_sha1": parse_hash(first_nonempty(row, "PESHA1", "PE SHA1"), {40}),
            "pe_sha256": parse_hash(first_nonempty(row, "PESHA256", "PE SHA256"), {64}),
            "virus_total": clean_value(first_nonempty(row, "VirusTotal")),
            "vt_detection": vt_detection,
            "vt_link": clean_value(first_nonempty(row, "VT link", "VTLink")),
            "wow64": wow64,
            "user": user_name,
            "sid": sid,
            "timestamp": timestamp,
            "source_file": artifact_meta.get("source_path") or artifact_meta.get("name"),
            "parser_status": "ready",
            "timestamp_interpretation": "registry_last_write" if last_write else "autoruns_timestamp" if timestamp else "source_file_mtime",
        }
    )
    document["persistence"].update(
        {
            "mechanism": mechanism,
            "location": entry_location,
            "name": entry_name,
            "command": command_line,
            "path": image_path,
            "enabled": enabled,
            "scope": "user" if (hive and hive.upper() in {"NTUSER", "USRCLASS", "HKCU"}) or profile or user_name or sid else "machine",
            "user": user_name or profile,
            "sid": sid,
            "confidence": "medium",
            "source": "autoruns",
        }
    )
    registry_hive = hive or ("NTUSER" if document["persistence"].get("scope") == "user" else "SOFTWARE")
    document["process"]["command_line"] = command_line
    document["process"]["path"] = image_path
    document["process"]["name"] = basename_windows(image_path)
    document["process"]["application"] = basename_windows(image_path) or basename_windows(command_line)
    document["file"]["path"] = image_path
    document["file"]["name"] = basename_windows(image_path)
    document["file"]["extension"] = suffix_windows(image_path)
    document["file"]["md5"] = document["autoruns"]["hash_md5"]
    document["file"]["hash_sha1"] = document["autoruns"]["hash_sha1"]
    document["file"]["hash_sha256"] = document["autoruns"]["hash_sha256"]
    document["execution"].update(
        {
            "source": "autorun",
            "is_execution_confirmed": False,
            "confidence": "low",
            "interpretation": "Autorun artifacts indicate configured persistence/startup execution, not confirmed execution by itself",
        }
    )
    if user_name:
        document["user"]["name"] = user_name
    if sid:
        document["user"]["sid"] = sid
    document["url"]["full"] = urls_domains_paths["urls"][0] if urls_domains_paths["urls"] else None
    document["url"]["domain"] = urls_domains_paths["domains"][0] if urls_domains_paths["domains"] else None
    document["network"]["domain"] = urls_domains_paths["domains"][0] if urls_domains_paths["domains"] else None

    if mechanism in {"run_key", "runonce_key", "ifeo_debugger", "winlogon_shell", "winlogon_userinit", "appinit_dll", "appcert_dll", "lsa_package", "print_monitor", "active_setup", "bootexecute", "shell_extension"}:
        document["registry"]["hive"] = registry_hive
        document["registry"]["key_path"] = key_path or entry_location
        document["registry"]["value_name"] = value_name or entry_name
        document["registry"]["value_data"] = value_data or launch_string or image_path
        document["registry"]["last_write"] = last_write
    if mechanism == "service":
        document["service"]["name"] = entry_name
        document["service"]["image_path"] = image_path
    if mechanism == "driver":
        document["service"]["name"] = entry_name
        document["service"]["image_path"] = image_path
    if mechanism == "scheduled_task":
        document["task"]["name"] = entry_name
        document["task"]["path"] = entry_location
        document["task"]["command"] = command_line
        document["task"]["arguments"] = arguments
    if mechanism == "wmi":
        document["wmi"]["consumer_name"] = entry_name
        document["wmi"]["command_line_template"] = command_line

    tags, reasons, risk = classify_autoruns_suspicion(
        mechanism=mechanism,
        image_path=image_path,
        command_line=command_line,
        signed=signed,
        verified=verified,
        publisher=publisher,
        vt_detection=vt_detection,
    )
    if enabled is False:
        if reasons:
            reasons.append("Disabled suspicious autorun entry")
        risk = max(risk - 10, 0)
    if detect_missing_or_invalid_path(image_path) and mechanism not in {"wmi", "shell_extension", "known_dll"}:
        document["data_quality"].append("missing_path")
    if not timestamp:
        document["data_quality"].append("missing_timestamp")
    if signed is None and verified is None:
        document["data_quality"].append("missing_signature_status")
    if detect_user_writable_path(image_path):
        tags.add("user_writable_path")
    document["tags"] = sorted(set(document.get("tags", [])) | tags)
    document["suspicious_reasons"] = sorted(set(document.get("suspicious_reasons", [])) | set(reasons))
    document["risk_score"] = risk
    document["event"]["severity"] = risk_score_to_severity(risk)
    document["_preserve_risk_score"] = True
    if timestamp:
        document["@timestamp"] = timestamp
        document["timestamp_precision"] = "registry_last_write" if last_write else "autoruns_timestamp"
    else:
        document["autoruns"]["timestamp_interpretation"] = "Source artifact modification time; not necessarily autorun entry creation time"
    return document


__all__ = ["normalize_autoruns_row"]
