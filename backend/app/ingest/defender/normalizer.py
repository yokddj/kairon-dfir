from app.ingest.artifact_normalizers import first_value
from app.ingest.defender.helpers import (
    basename_windows,
    clean_text,
    defender_suspicion,
    extract_hashes_from_defender_text,
    extract_paths_from_defender_resource,
    infer_user_from_path,
    normalize_defender_action,
    normalize_defender_severity,
    normalize_defender_status,
    normalize_threat_name,
    normalize_windows_path,
    parse_defender_timestamp,
)


def normalize_defender_row(document: dict, row: dict, artifact_meta: dict) -> dict:
    first = lambda *names: first_value(row, list(names))
    detection = document.setdefault("detection", {})
    process = document.setdefault("process", {})
    file_data = document.setdefault("file", {})
    user = document.setdefault("user", {})

    detection_type = artifact_meta.get("defender_artifact_type") or first("ArtifactType", "Type") or "defender_generic"
    threat_name = normalize_threat_name(first("ThreatName", "Threat Name", "Threat", "Name"))
    threat_id = clean_text(first("ThreatID", "ThreatId", "Threat ID"))
    severity = normalize_defender_severity(first("Severity", "SeverityName", "Severity Name"))
    category = clean_text(first("Category", "CategoryName", "Category Name"))
    raw_action = clean_text(first("Action", "ActionName", "Action Name", "RemediationAction", "Remediation Action", "Remediation"))
    normalized_action, event_action = normalize_defender_action(raw_action)
    status = normalize_defender_status(first("Status", "CurrentStatus", "Status Description", "StatusDescription", "State"))
    detection_source = clean_text(first("DetectionSource", "Detection Source", "Source", "SourceName", "Source Name"))
    product_name = clean_text(first("ProductName", "Product Name"))
    engine_version = clean_text(first("EngineVersion", "Engine Version"))
    signature_version = clean_text(first("SignatureVersion", "Signature Version", "Security intelligence Version"))
    resource = clean_text(first("Resource", "Resources", "Path", "FilePath"))
    path = normalize_windows_path(first("Path", "FilePath"))
    resource_path, container_file = extract_paths_from_defender_resource(resource)
    container_file = normalize_windows_path(first("ContainerFile")) or container_file
    effective_path = path or resource_path
    process_name = clean_text(first("ProcessName", "Process Name"))
    process_path = normalize_windows_path(first("ProcessPath", "Process Path", "ProcessName", "Process Name"))
    user_name = clean_text(first("User", "DetectionUser", "Detection User", "Remediation User"))
    user_sid = clean_text(first("SID", "UserSid", "User SID", "UserId", "User ID"))
    if not user_name:
        user_name = infer_user_from_path(effective_path)
    event_id = clean_text(first("EventID", "EventId"))
    status_change_time = parse_defender_timestamp(first("LastThreatStatusChangeTime"))
    remediation_time = (
        parse_defender_timestamp(first("RemediationTime"))
        or parse_defender_timestamp(first("LastRemediationTime"))
        or status_change_time
    )
    timestamp = (
        parse_defender_timestamp(first("TimeCreated"))
        or parse_defender_timestamp(first("Timestamp"))
        or parse_defender_timestamp(first("DetectionTime", "Detection Time"))
        or parse_defender_timestamp(first("InitialDetectionTime", "Initial Detection Time"))
        or status_change_time
        or remediation_time
    )
    if timestamp:
        document["@timestamp"] = timestamp
        document["timestamp_precision"] = (
            "event_time" if first("TimeCreated")
            else "defender_detection_time" if first("DetectionTime", "Detection Time")
            else "defender_detection_time" if first("InitialDetectionTime", "Initial Detection Time")
            else "defender_remediation_time" if first("RemediationTime", "LastRemediationTime")
            else "defender_detection_time" if first("LastThreatStatusChangeTime")
            else "defender_detection_time" if first("Timestamp")
            else "unknown"
        )
        document["timezone"] = "UTC"
    else:
        document["timestamp_precision"] = document.get("timestamp_precision") or "unknown"

    lowered_blob = " ".join(
        item for item in [
            str(event_id or ""),
            str(threat_name or ""),
            str(category or ""),
            str(raw_action or ""),
            str(status or ""),
            str(first("CurrentThreatExecutionStatus", "Current Threat Execution Status", "Execution Name") or ""),
            str(first("AdditionalActions", "Additional Actions String") or ""),
            str(first("Message") or ""),
        ] if item
    ).lower()

    event_type = "security_detection"
    event_action_type = event_action
    event_severity = severity or "medium"
    message_prefix = "Defender observed"
    if event_id in {"1116", "1006"} or "detected" in lowered_blob:
        event_type = "malware_detected"
        event_action_type = event_action if event_action != "defender_observed" else "defender_threat_detected"
        message_prefix = "Defender detected"
    elif event_id == "1015" or "suspicious behavior" in lowered_blob or "behavior" in lowered_blob:
        event_type = "suspicious_behavior"
        event_action_type = "defender_suspicious_behavior_observed"
        message_prefix = "Defender detected suspicious behavior"
    elif event_id in {"5007"}:
        event_type = "configuration_change"
        event_action_type = "defender_config_changed"
        event_severity = severity or "medium"
        message_prefix = "Defender configuration changed"
    elif event_id in {"5013"}:
        event_type = "tamper_protection"
        event_action_type = "defender_tamper_protection_observed"
        event_severity = severity or "high"
        message_prefix = "Defender tamper protection event"
    elif event_id in {"1117", "1118", "1119", "1120", "1007"} or any(token in lowered_blob for token in ["quarantine", "removed", "remediat", "cleaned", "blocked", "failed"]):
        event_type = "remediation"
        event_action_type = event_action if event_action != "defender_observed" else "defender_remediation_observed"
        message_prefix = "Defender remediation observed"

    if event_type == "malware_detected" and event_severity in {"info", "low", "medium"}:
        event_severity = "high"
    if event_type == "tamper_protection" and event_severity in {"info", "low", "medium"}:
        event_severity = "high"

    source_file = clean_text(first("SourceFile")) or artifact_meta.get("source_path")
    remediation_action = clean_text(first("RemediationAction", "Remediation Action", "Remediation", "ActionName", "Action Name"))
    current_execution_status = clean_text(first("CurrentThreatExecutionStatus", "Current Threat Execution Status", "Execution Name"))
    error_code = clean_text(first("ErrorCode", "Error Code"))
    hashes = extract_hashes_from_defender_text(
        " ".join(
            item for item in [
                clean_text(first("Sha1", "SHA1")),
                clean_text(first("Sha256", "SHA256")),
                clean_text(first("MD5")),
                resource,
                clean_text(first("Message")),
            ] if item
        )
    )

    detection.update(
        {
            "artifact_type": detection_type,
            "threat_name": threat_name,
            "threat_id": threat_id,
            "severity": severity,
            "category": category,
            "action": normalized_action,
            "status": status,
            "remediation_action": remediation_action,
            "detection_source": detection_source,
            "product_name": product_name,
            "engine_version": engine_version,
            "signature_version": signature_version,
            "path": effective_path,
            "resource": resource,
            "container_file": container_file,
            "user": user_name,
            "user_sid": user_sid,
            "timestamp": timestamp,
            "source_file": source_file,
            "line_number": clean_text(first("LineNumber")),
            "error_code": error_code,
        }
    )
    document.setdefault("threat", {}).update(
        {
            "name": threat_name,
            "id": threat_id,
            "severity": severity,
            "category": category,
            "status": status,
        }
    )
    document.setdefault("defender", {}).update(
        {
            "threat_name": threat_name,
            "threat_id": threat_id,
            "severity": severity,
            "category": category,
            "status": status,
            "action": normalized_action,
            "action_result": status or normalized_action,
            "detection_source": detection_source,
            "path": effective_path,
            "resource": resource,
            "remediation_action": remediation_action,
            "error_code": error_code,
        }
    )

    if effective_path:
        file_data["path"] = effective_path
        file_data["name"] = basename_windows(effective_path)
        file_data["extension"] = ("." + file_data["name"].split(".")[-1].lower()) if file_data.get("name") and "." in str(file_data["name"]) else None
    file_data["hash_sha1"] = hashes.get("sha1")
    file_data["hash_sha256"] = hashes.get("sha256")
    file_data["sha1"] = hashes.get("sha1")
    file_data["sha256"] = hashes.get("sha256")
    file_data["md5"] = hashes.get("md5")

    if process_path:
        process["path"] = process_path
        process["name"] = basename_windows(process_path)
    elif process_name:
        process["name"] = basename_windows(process_name) or process_name

    if user_name:
        user["name"] = user_name
    if user_sid:
        user["sid"] = user_sid

    document["artifact"]["type"] = "detection"
    document["artifact"]["parser"] = artifact_meta.get("parser", "defender_detection_history")
    document["artifact"]["name"] = document["artifact"].get("name") or f"Defender detection - {threat_name or basename_windows(effective_path) or 'unknown'}"
    document["source_tool"] = artifact_meta.get("source_tool") or ("native_evtx" if detection_type == "defender_evtx" else "defender")
    document["source_format"] = artifact_meta.get("source_format") or ("evtx" if detection_type == "defender_evtx" else "raw")
    document["event"]["category"] = "detection"
    document["event"]["type"] = event_type
    document["event"]["action"] = event_action_type
    document["event"]["severity"] = event_severity
    document["event"]["timeline_include"] = bool(document.get("@timestamp"))
    message_target = effective_path or resource or process_path or "resource not extracted"
    document["event"]["message"] = f"{message_prefix} {threat_name or message_target} in {message_target}" if threat_name else f"{message_prefix}: {message_target}"

    execution = document.setdefault("execution", {})
    execution.update(
        {
            "source": "defender",
            "is_execution_confirmed": False,
            "confidence": "medium" if event_type in {"suspicious_behavior", "tamper_protection"} or current_execution_status else "low",
            "interpretation": "Defender detection indicates a security product observed or remediated a threat; execution must be corroborated with execution artifacts",
        }
    )

    tags, reasons, risk = defender_suspicion(effective_path, threat_name, category, normalized_action or status)
    if event_type == "malware_detected":
        reasons = sorted(set(reasons) | {"Defender malware detected"})
        risk = max(risk, 80)
    if event_type == "suspicious_behavior":
        reasons = sorted(set(reasons) | {"Defender detected suspicious behavior"})
        risk = max(risk, 65)
    if event_type == "configuration_change":
        reasons = sorted(set(reasons) | {"Defender configuration changed"})
        risk = max(risk, 30)
    if event_type == "tamper_protection":
        reasons = sorted(set(reasons) | {"Defender tamper protection event"})
        risk = max(risk, 70)
    if event_type == "remediation" and any(token in lowered_blob for token in ["quarantine", "removed", "remediated"]):
        reasons = sorted(set(reasons) | {"Defender quarantined threat"})
        risk = max(risk, 65)
    if any(token in lowered_blob for token in ["failed", "failure"]):
        reasons = sorted(set(reasons) | {"Defender remediation failed"})
        risk = max(risk, 85)
    if not any(token in lowered_blob for token in ["quarantine", "removed", "cleaned", "remediated", "blocked"]) and event_type == "malware_detected":
        reasons = sorted(set(reasons) | {"Defender threat not remediated"})
        risk = max(risk, 85)
    if effective_path:
        lower_path = effective_path.lower()
        if any(token in lower_path for token in ["\\users\\", "\\downloads\\", "\\appdata\\", "\\temp\\", "\\desktop\\", "\\public\\", "\\startup\\"]):
            reasons = sorted(set(reasons) | {"Defender detection in user-writable path"})
            risk = max(risk, 75 if event_type == "malware_detected" else 55)
        if "\\downloads\\" in lower_path:
            reasons = sorted(set(reasons) | {"Defender detection in browser download path"})
        if "\\startup\\" in lower_path:
            reasons = sorted(set(reasons) | {"Defender detection in startup path"})
        if file_data.get("extension") == ".ps1":
            reasons = sorted(set(reasons) | {"Defender detection in PowerShell script"})
    if container_file:
        reasons = sorted(set(reasons) | {"Defender threat inside archive/container"})
        risk = max(risk, 75)
    if severity in {"high", "critical"}:
        reasons = sorted(set(reasons) | {"Defender severe threat"})
        risk = max(risk, 82 if severity == "high" else 92)

    data_quality = set(document.get("data_quality", []))
    if not timestamp:
        data_quality.add("missing_timestamp")
    if not threat_name:
        data_quality.add("missing_threat_name")
    if not effective_path and not resource:
        data_quality.add("missing_resource_path")
    if not user_name and not user_sid:
        data_quality.add("missing_user")
    delimiter_note = artifact_meta.get("defender_delimiter_note")
    if delimiter_note in {"delimiter_autodetected", "delimiter_fallback_used"}:
        data_quality.add(delimiter_note)
    for warning in artifact_meta.get("defender_parse_warnings") or []:
        if warning:
            data_quality.add("defender_parse_warning" if warning not in {"delimiter_autodetected", "delimiter_fallback_used"} else warning)
    document["data_quality"] = sorted(data_quality)

    document["tags"] = sorted(set(document.get("tags", [])) | set(tags))
    document["suspicious_reasons"] = sorted(set(document.get("suspicious_reasons", [])) | set(reasons))
    document["risk_score"] = max(int(document.get("risk_score") or 0), risk)
    return document
