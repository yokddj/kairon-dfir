from __future__ import annotations

from app.analysis.suspicious import detect_suspicious_path, is_suspicious_double_extension, normalize_windows_path_for_classification
from app.ingest.artifact_normalizers import first_value
from app.ingest.identity_extraction import extract_user_from_path
from app.ingest.wmi.helpers import (
    basename_windows,
    classify_wmi_activity_event,
    classify_wmi_suspicion,
    decode_creator_sid_if_possible,
    extract_command_from_consumer,
    extract_script_preview,
    extract_urls_domains_paths,
    extract_wmi_names,
    first_nonempty,
    infer_wmi_artifact_type,
    normalize_windows_path,
    normalize_wmi_class,
    normalize_wmi_namespace,
    normalize_wmi_path,
    suffix_windows,
)


def normalize_wmi_row(document: dict, row: dict, artifact_meta: dict) -> dict:
    first = lambda *names: first_value(row, list(names))
    wmi = document.setdefault("wmi", {})
    process = document.setdefault("process", {})
    file = document.setdefault("file", {})
    persistence = document.setdefault("persistence", {})
    registry = document.setdefault("registry", {})
    url = document.setdefault("url", {})
    network = document.setdefault("network", {})
    host = document.setdefault("host", {})
    user = document.setdefault("user", {})
    velociraptor = document.setdefault("velociraptor", {})
    data_quality = set(document.setdefault("data_quality", []))

    parser = str(artifact_meta.get("parser") or "").lower()
    source_file = normalize_windows_path(first("SourceFile")) or artifact_meta.get("source_path")
    artifact_subtype = infer_wmi_artifact_type(row, artifact_meta)
    names = extract_wmi_names(row)
    namespace = normalize_wmi_namespace(first("Namespace", "EventNamespace"))
    class_name = normalize_wmi_class(first("Class", "ClassName", "__CLASS"))
    creator_sid = decode_creator_sid_if_possible(first("CreatorSID"))
    query = first("Query")
    query_language = first("QueryLanguage")
    command_line_template = first("CommandLineTemplate", "CommandLine", "Command")
    executable_path = normalize_windows_path(first("ExecutablePath"))
    working_directory = normalize_windows_path(first("WorkingDirectory"))
    script_text = first("ScriptText")
    script_preview = extract_script_preview(script_text)
    consumer_type = normalize_wmi_class(first("ConsumerType", "ClassName", "__CLASS"))
    binding_filter = first("BindingFilter", "Filter", "FilterName")
    binding_consumer = first("BindingConsumer", "Consumer", "ConsumerName")
    binding_filter = names["filter_name"] or binding_filter
    binding_consumer = names["consumer_name"] or binding_consumer
    machine_name = first("MachineName")
    repository_path = normalize_windows_path(first("RepositoryPath")) or normalize_windows_path(str(artifact_meta.get("repository_path") or ""))

    if parser == "evtx" or first("EventID", "EventId", "Id"):
        classified = classify_wmi_activity_event(row)
        document["artifact"]["type"] = "wmi"
        document["artifact"]["parser"] = "evtx"
        document["source_tool"] = artifact_meta.get("source_tool") or "evtxecmd"
        document["source_format"] = artifact_meta.get("source_format") or "evtx_csv"
        document["event"].update(
            {
                "category": "wmi",
                "type": classified["event_type"],
                "action": classified["action"],
                "severity": classified["severity"],
                "timeline_include": bool(document.get("@timestamp")),
                "message": classified["message"],
            }
        )
        artifact_subtype = "wmi_activity_event"
        urls = extract_urls_domains_paths(query, command_line_template, script_text)
        document["tags"] = sorted(set(document.get("tags") or []) | set(classified["tags"] or []))
        if first("TimeCreated") and not document.get("@timestamp"):
            document["@timestamp"] = first("TimeCreated")
            document["timestamp_precision"] = "evtx_timecreated"
        wmi.update(
            {
                "artifact_type": artifact_subtype,
                "namespace": namespace or first("NamespaceName"),
                "query": query,
                "consumer_name": first("Consumer"),
                "source_file": source_file,
                "parser_status": "parsed",
            }
        )
        if urls["urls"]:
            url["full"] = urls["urls"][0]
            url["domain"] = urls["domains"][0] if urls["domains"] else None
            network["domain"] = url["domain"]
        if not document.get("timestamp_precision"):
            document["timestamp_precision"] = "unknown"
        return document

    has_binding = artifact_subtype == "wmi_filter_to_consumer_binding" and bool(binding_filter and binding_consumer)
    tags, reasons, risk = classify_wmi_suspicion(
        consumer_type=consumer_type,
        command_line_template=command_line_template,
        executable_path=executable_path,
        script_text=script_text,
        query=query,
        has_binding=has_binding,
        creator_sid=creator_sid,
    )
    tags.add("wmi")

    is_filter = artifact_subtype == "wmi_event_filter"
    is_binding = artifact_subtype == "wmi_filter_to_consumer_binding"
    is_consumer = artifact_subtype in {"wmi_command_line_consumer", "wmi_active_script_consumer", "wmi_consumer"}
    is_inventory = artifact_subtype in {"wmi_namespace_observed", "wmi_generic"}

    if is_filter:
        event_type = "wmi_event_filter"
        action = "wmi_filter_observed"
        category = "persistence"
        message = f"WMI event filter observed: {names['filter_name'] or names['name'] or query or 'filter'}"
        tags.update({"wmi_filter", "persistence"})
        reasons.append("WMI event filter observed")
    elif is_consumer:
        event_type = "wmi_event_consumer"
        action = "wmi_consumer_observed"
        category = "persistence"
        message = f"WMI consumer observed: {names['consumer_name'] or names['name'] or executable_path or 'consumer'}"
        tags.update({"wmi_consumer", "persistence"})
    elif is_binding:
        event_type = "wmi_filter_consumer_binding"
        action = "wmi_binding_observed"
        category = "persistence"
        message = f"WMI binding observed: {binding_filter or names['filter_name'] or 'filter'} -> {binding_consumer or names['consumer_name'] or 'consumer'}"
        tags.update({"wmi_binding", "persistence"})
        risk = max(risk, 35)
        if not has_binding:
            data_quality.add("missing_binding")
    else:
        event_type = "wmi_observed"
        action = "wmi_object_observed"
        category = "inventory" if is_inventory else "configuration"
        message = f"WMI object observed: {names['name'] or class_name or names['path'] or 'WMI object'}"
        risk = 0

    if is_filter and not has_binding:
        risk = min(max(risk, 20), 40)

    urls = extract_urls_domains_paths(command_line_template, script_text, query)
    command = extract_command_from_consumer(command_line_template, executable_path)
    executable_candidate = executable_path or (urls["paths"][0] if urls["paths"] else None)
    executable_name = basename_windows(executable_candidate) or basename_windows(command)

    document["artifact"]["type"] = "wmi"
    document["artifact"]["parser"] = parser or ("autoruns" if "autoruns" in str(artifact_meta.get("source_tool") or "").lower() else "wmi_csv")
    document["source_tool"] = artifact_meta.get("source_tool") or ("autoruns" if document["artifact"]["parser"] == "autoruns" else "wmi_parser")
    document["source_format"] = artifact_meta.get("source_format") or ("jsonl" if parser == "wmi_jsonl" else "json" if parser == "wmi_json" else "csv")
    document["event"].update(
        {
            "category": category,
            "type": event_type,
            "action": action,
            "severity": "high" if risk >= 75 else "medium" if risk >= 45 else "info",
            "timeline_include": False,
            "message": message,
        }
    )

    timestamp = None
    if first("ModifiedTime"):
        document["@timestamp"] = first("ModifiedTime")
        document["timestamp_precision"] = "wmi_modified_time"
        timestamp = document["@timestamp"]
    elif first("LastWriteTime", "Timestamp"):
        document["@timestamp"] = first("LastWriteTime", "Timestamp")
        document["timestamp_precision"] = "wmi_last_write"
        timestamp = document["@timestamp"]
    elif first("CreatedTime"):
        document["@timestamp"] = first("CreatedTime")
        document["timestamp_precision"] = "wmi_created_time"
        timestamp = document["@timestamp"]
    else:
        document["@timestamp"] = None
        document["timestamp_precision"] = "unknown"
    document["timezone"] = "UTC" if timestamp else None

    wmi.update(
        {
            "artifact_type": artifact_subtype,
            "namespace": namespace,
            "class_name": class_name,
            "instance_name": first("InstanceName"),
            "name": names["name"],
            "path": names["path"],
            "relpath": names["relpath"],
            "creator_sid": creator_sid,
            "creator_user": first("CreatorUser"),
            "filter_name": names["filter_name"],
            "consumer_name": names["consumer_name"],
            "query": query,
            "query_language": query_language,
            "event_namespace": normalize_wmi_namespace(first("EventNamespace")),
            "consumer_type": consumer_type,
            "command_line_template": command_line_template,
            "executable_path": executable_path,
            "working_directory": working_directory,
            "script_text": script_text,
            "script_preview": script_preview,
            "scripting_engine": first("ScriptingEngine"),
            "binding_filter": binding_filter,
            "binding_consumer": binding_consumer,
            "delivery_qos": first("DeliveryQoS"),
            "maintain_security_context": first("MaintainSecurityContext"),
            "kill_timeout": first("KillTimeout"),
            "machine_name": first("MachineName"),
            "max_queue_size": first("MaximumQueueSize", "MaxQueueSize"),
            "last_write_time": first("LastWriteTime", "Timestamp"),
            "created_time": first("CreatedTime"),
            "modified_time": first("ModifiedTime"),
            "source_file": source_file,
            "repository_path": repository_path,
            "parser_status": artifact_meta.get("velociraptor_parser_status") or "parsed_native",
            "timestamp_interpretation": document.get("timestamp_precision"),
        }
    )
    if machine_name:
        host["name"] = machine_name
        host["hostname"] = machine_name
    process.update(
        {
            "command_line": command,
            "path": executable_candidate,
            "name": executable_name,
            "application": executable_name,
        }
    )
    file.update(
        {
            "path": executable_candidate,
            "name": basename_windows(executable_candidate),
            "extension": suffix_windows(executable_candidate),
            "source_path": source_file,
        }
    )
    if "registryvaluechangeevent" in str(query or "").lower():
        registry["key_path"] = first("RegistryKeyPath", "KeyPath")
        registry["value_name"] = first("ValueName")
    if urls["urls"]:
        url["full"] = urls["urls"][0]
        url["domain"] = urls["domains"][0] if urls["domains"] else None
        url["scheme"] = url["full"].split("://", 1)[0] if "://" in str(url["full"]) else None
        network["domain"] = url["domain"]
    if urls["paths"] and not file.get("path"):
        file["path"] = urls["paths"][0]
        file["name"] = basename_windows(file["path"])
        file["extension"] = suffix_windows(file["path"])
    if creator_sid and not user.get("sid"):
        user["sid"] = creator_sid
    if first("CreatorUser") and not user.get("name"):
        user["name"] = first("CreatorUser")
    if not user.get("name"):
        user["name"] = extract_user_from_path(str(source_file or ""))
    if str(artifact_meta.get("source_tool") or "").startswith("velociraptor"):
        velociraptor.update(
            {
                "original_path": artifact_meta.get("velociraptor_original_path") or source_file,
                "normalized_windows_path": artifact_meta.get("velociraptor_normalized_windows_path") or source_file,
                "artifact_category": artifact_meta.get("velociraptor_category") or "wmi",
                "parser_status": artifact_meta.get("velociraptor_parser_status") or "parsed",
                "collection_id": artifact_meta.get("velociraptor_collection_id"),
            }
        )

    if is_binding or is_consumer or is_filter:
        persistence_confidence = "high" if is_binding else "medium"
        persistence.update(
            {
                "mechanism": "wmi_event_subscription",
                "location": namespace or "root\\subscription",
                "name": names["consumer_name"] or names["filter_name"] or names["name"] or class_name,
                "command": command_line_template or script_preview or executable_path,
                "path": executable_candidate,
                "enabled": None,
                "scope": "system",
                "user": first("CreatorUser") or user.get("name"),
                "sid": creator_sid,
                "confidence": persistence_confidence,
                "source": source_file,
            }
        )
        data_quality.add("wmi_not_execution_proof")
        if not is_binding:
            data_quality.add("missing_binding")
    else:
        data_quality.add("wmi_inventory_only")

    if not timestamp:
        data_quality.add("missing_timestamp")
    if not (user.get("name") or creator_sid):
        data_quality.add("missing_user")
    if not (host.get("name") or machine_name):
        data_quality.add("missing_host")

    suspicious_path_reasons = detect_suspicious_path(executable_candidate or command)
    normalized_exec_path = normalize_windows_path_for_classification(executable_candidate)
    if normalized_exec_path and any(token in normalized_exec_path.lower() for token in ["\\users\\", "\\appdata\\", "\\temp\\", "\\downloads\\", "\\desktop\\", "\\public\\", "\\programdata\\"]):
        tags.add("user_writable_path")
    if suspicious_path_reasons:
        tags.add("suspicious_path")
        if any(reason in suspicious_path_reasons for reason in {"appdata_path", "temp_path", "downloads_path", "desktop_path", "public_path", "programdata_path"}):
            if "WMI consumer command uses user-writable path" not in reasons:
                reasons.append("WMI consumer command uses user-writable path")
        if "double_extension" in suspicious_path_reasons or is_suspicious_double_extension(executable_name):
            reasons.append("WMI consumer uses suspicious script content")
            risk = max(risk, 70)

    if category == "inventory":
        tags.add("inventory")
    if category == "persistence":
        tags.add("persistence")
        if command or script_preview:
            tags.add("execution_candidate")
        document["event"]["timeline_include"] = bool(timestamp)
    else:
        document["event"]["timeline_include"] = False
    document["_preserve_timeline_include"] = True

    if not command and is_consumer:
        data_quality.add("missing_command")
    if artifact_subtype == "wmi_active_script_consumer" and script_text:
        tags.add("active_script_consumer")

    document["tags"] = sorted(set(document.get("tags") or []) | tags)
    document["suspicious_reasons"] = sorted(set(document.get("suspicious_reasons") or []) | set(reasons))
    document["risk_score"] = risk
    document["data_quality"] = sorted(data_quality)
    execution = document.setdefault("execution", {})
    execution.update(
        {
            "source": "wmi",
            "is_execution_confirmed": False,
            "confidence": "low",
            "interpretation": (
                "WMI namespace/class observation indicates configuration or inventory, not execution by itself"
                if category in {"inventory", "configuration"}
                else "WMI permanent event subscription indicates configured persistence/execution trigger, not confirmed execution by itself"
            ),
        }
    )
    return document


__all__ = ["normalize_wmi_row"]
