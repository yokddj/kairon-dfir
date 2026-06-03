import { useEffect, useMemo, useState } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { api, type DfirCase, type SemiAutoActivity } from "../api/client";
import DebugExportDialog from "../components/DebugExportDialog";
import { useActiveCase } from "../context/ActiveCaseContext";
import { compareValues, nextSortDirection, type SortDirection } from "../lib/sorting";

const sectionConfig: Array<{ key: string; label: string; columns: Array<{ key: string; label: string; from?: "root" | "key_fields" }> }> = [
  { key: "program_executions", label: "Programas ejecutados", columns: [{ key: "timestamp", label: "Timestamp" }, { key: "user", label: "User" }, { key: "process_name", label: "Process", from: "key_fields" }, { key: "process_path", label: "Path", from: "key_fields" }, { key: "source", label: "Fuente", from: "key_fields" }, { key: "run_count", label: "Run count", from: "key_fields" }, { key: "last_run", label: "Last run", from: "key_fields" }, { key: "previous_runs_count", label: "Prev runs", from: "key_fields" }, { key: "confidence_label", label: "Confidence", from: "key_fields" }] },
  { key: "powershell", label: "PowerShell", columns: [{ key: "timestamp", label: "Timestamp" }, { key: "user", label: "User" }, { key: "summary", label: "Command / script" }, { key: "source", label: "Fuente", from: "key_fields" }, { key: "run_count", label: "Run count", from: "key_fields" }, { key: "script_block_id", label: "ScriptBlockId", from: "key_fields" }] },
  { key: "powershell_activity", label: "Actividad PowerShell", columns: [{ key: "timestamp", label: "Timestamp" }, { key: "user", label: "User" }, { key: "command_preview", label: "Command", from: "key_fields" }, { key: "artifact_type", label: "Type", from: "key_fields" }, { key: "source_file", label: "Source file", from: "key_fields" }, { key: "suspicious_reasons", label: "Reasons" }] },
  { key: "powershell_downloads", label: "Descargas vía PowerShell", columns: [{ key: "timestamp", label: "Timestamp" }, { key: "user", label: "User" }, { key: "url", label: "URL", from: "key_fields" }, { key: "domain", label: "Domain", from: "key_fields" }, { key: "command_preview", label: "Command", from: "key_fields" }, { key: "suspicious_reasons", label: "Reasons" }] },
  { key: "powershell_encoded_commands", label: "PowerShell encoded", columns: [{ key: "timestamp", label: "Timestamp" }, { key: "user", label: "User" }, { key: "command_preview", label: "Command", from: "key_fields" }, { key: "decoded_command_preview", label: "Decoded preview", from: "key_fields" }, { key: "source", label: "Fuente", from: "key_fields" }] },
  { key: "powershell_defender_tampering", label: "Defender tampering vía PowerShell", columns: [{ key: "timestamp", label: "Timestamp" }, { key: "user", label: "User" }, { key: "command_preview", label: "Command", from: "key_fields" }, { key: "suspicious_reasons", label: "Reasons" }] },
  { key: "powershell_persistence", label: "Persistencia vía PowerShell", columns: [{ key: "timestamp", label: "Timestamp" }, { key: "user", label: "User" }, { key: "command_preview", label: "Command", from: "key_fields" }, { key: "paths", label: "Paths", from: "key_fields" }, { key: "suspicious_reasons", label: "Reasons" }] },
  { key: "powershell_recon", label: "Recon vía PowerShell", columns: [{ key: "timestamp", label: "Timestamp" }, { key: "user", label: "User" }, { key: "command_preview", label: "Command", from: "key_fields" }, { key: "source", label: "Fuente", from: "key_fields" }] },
  { key: "powershell_credential_access", label: "Credential access vía PowerShell", columns: [{ key: "timestamp", label: "Timestamp" }, { key: "user", label: "User" }, { key: "command_preview", label: "Command", from: "key_fields" }, { key: "suspicious_reasons", label: "Reasons" }] },
  { key: "browser_history", label: "Historial de navegador", columns: [{ key: "timestamp", label: "Timestamp" }, { key: "browser", label: "Browser", from: "key_fields" }, { key: "user", label: "User" }, { key: "title", label: "Title", from: "key_fields" }, { key: "url", label: "URL", from: "key_fields" }, { key: "domain", label: "Domain", from: "key_fields" }, { key: "visit_count", label: "Visits", from: "key_fields" }, { key: "typed_count", label: "Typed", from: "key_fields" }] },
  { key: "downloaded_files", label: "Archivos descargados", columns: [{ key: "timestamp", label: "Timestamp" }, { key: "browser", label: "Browser", from: "key_fields" }, { key: "user", label: "User" }, { key: "profile", label: "Profile", from: "key_fields" }, { key: "file_name", label: "File", from: "key_fields" }, { key: "file_path", label: "Path", from: "key_fields" }, { key: "domain", label: "Domain", from: "key_fields" }, { key: "referrer", label: "Referrer", from: "key_fields" }, { key: "size", label: "Size", from: "key_fields" }, { key: "state", label: "State", from: "key_fields" }] },
  { key: "web_searches", label: "Búsquedas web", columns: [{ key: "timestamp", label: "Timestamp" }, { key: "browser", label: "Browser", from: "key_fields" }, { key: "user", label: "User" }, { key: "search_engine", label: "Engine", from: "key_fields" }, { key: "search_terms", label: "Terms", from: "key_fields" }, { key: "url", label: "URL", from: "key_fields" }] },
  { key: "cloud_activity", label: "Actividad cloud / sharing", columns: [{ key: "timestamp", label: "Timestamp" }, { key: "browser", label: "Browser", from: "key_fields" }, { key: "user", label: "User" }, { key: "domain", label: "Domain", from: "key_fields" }, { key: "url", label: "URL", from: "key_fields" }, { key: "file_name", label: "File", from: "key_fields" }] },
  { key: "suspicious_downloads", label: "Descargas sospechosas", columns: [{ key: "timestamp", label: "Timestamp" }, { key: "browser", label: "Browser", from: "key_fields" }, { key: "user", label: "User" }, { key: "file_name", label: "File", from: "key_fields" }, { key: "file_path", label: "Path", from: "key_fields" }, { key: "domain", label: "Domain", from: "key_fields" }, { key: "summary", label: "Summary" }, { key: "suspicious_reasons", label: "Reasons" }] },
  { key: "downloaded_and_executed", label: "Descargados y ejecutados", columns: [{ key: "timestamp", label: "Timestamp" }, { key: "browser", label: "Browser", from: "key_fields" }, { key: "user", label: "User" }, { key: "file_name", label: "File", from: "key_fields" }, { key: "file_path", label: "Path", from: "key_fields" }, { key: "domain", label: "Domain", from: "key_fields" }, { key: "executed_event", label: "Executed Event", from: "key_fields" }] },
  { key: "program_inventory", label: "Inventario de programas", columns: [{ key: "timestamp", label: "Timestamp" }, { key: "file_name", label: "Program", from: "key_fields" }, { key: "file_path", label: "Path", from: "key_fields" }, { key: "publisher", label: "Publisher", from: "key_fields" }, { key: "product_name", label: "Product", from: "key_fields" }, { key: "version", label: "Version", from: "key_fields" }, { key: "hash_sha1", label: "SHA1", from: "key_fields" }, { key: "source", label: "Source", from: "key_fields" }, { key: "confidence_label", label: "Confidence", from: "key_fields" }] },
  { key: "file_creations", label: "Archivos creados", columns: [{ key: "timestamp", label: "Timestamp" }, { key: "file_name", label: "Name", from: "key_fields" }, { key: "file_path", label: "Path", from: "key_fields" }, { key: "extension", label: "Ext", from: "key_fields" }, { key: "size", label: "Size", from: "key_fields" }, { key: "source", label: "Fuente", from: "key_fields" }] },
  { key: "file_modifications", label: "Archivos modificados", columns: [{ key: "timestamp", label: "Timestamp" }, { key: "file_name", label: "Name", from: "key_fields" }, { key: "file_path", label: "Path", from: "key_fields" }, { key: "filesystem_reason", label: "Reason", from: "key_fields" }, { key: "source", label: "Fuente", from: "key_fields" }] },
  { key: "file_deletions", label: "Archivos borrados", columns: [{ key: "timestamp", label: "Timestamp" }, { key: "file_name", label: "Name", from: "key_fields" }, { key: "file_path", label: "Path", from: "key_fields" }, { key: "deleted", label: "Deleted", from: "key_fields" }, { key: "source", label: "Fuente", from: "key_fields" }] },
  { key: "file_renames", label: "Renombrados", columns: [{ key: "timestamp", label: "Timestamp" }, { key: "file_name", label: "Name", from: "key_fields" }, { key: "file_path", label: "Path", from: "key_fields" }, { key: "filesystem_reason", label: "Reason", from: "key_fields" }, { key: "source", label: "Fuente", from: "key_fields" }] },
  { key: "logons", label: "Logons", columns: [{ key: "timestamp", label: "Timestamp" }, { key: "user", label: "User" }, { key: "logon_type", label: "Logon type", from: "key_fields" }, { key: "source_ip", label: "Source IP", from: "key_fields" }, { key: "workstation", label: "Workstation", from: "key_fields" }] },
  { key: "rdp", label: "RDP", columns: [{ key: "timestamp", label: "Timestamp" }, { key: "user", label: "User" }, { key: "source_ip", label: "Source IP", from: "key_fields" }, { key: "summary", label: "Summary" }] },
  { key: "scheduled_tasks", label: "Tareas programadas", columns: [{ key: "timestamp", label: "Timestamp" }, { key: "task_name", label: "Task", from: "key_fields" }, { key: "command", label: "Command", from: "key_fields" }, { key: "arguments", label: "Arguments", from: "key_fields" }, { key: "user", label: "User" }] },
  { key: "suspicious_tasks", label: "Tareas sospechosas", columns: [{ key: "timestamp", label: "Timestamp" }, { key: "task_name", label: "Task", from: "key_fields" }, { key: "task_path", label: "Task path", from: "key_fields" }, { key: "command", label: "Command", from: "key_fields" }, { key: "arguments", label: "Arguments", from: "key_fields" }, { key: "suspicious_reasons", label: "Reasons" }] },
  { key: "task_executions", label: "Ejecuciones de tareas", columns: [{ key: "timestamp", label: "Timestamp" }, { key: "task_name", label: "Task", from: "key_fields" }, { key: "command", label: "Command", from: "key_fields" }, { key: "executed_event", label: "Executed event", from: "key_fields" }, { key: "user", label: "User" }] },
  { key: "downloaded_and_persisted", label: "Descargados y persistidos", columns: [{ key: "timestamp", label: "Timestamp" }, { key: "task_name", label: "Task", from: "key_fields" }, { key: "command", label: "Command", from: "key_fields" }, { key: "download_domain", label: "Download domain", from: "key_fields" }, { key: "user", label: "User" }] },
  { key: "defender_detections", label: "Detecciones de Defender", columns: [{ key: "timestamp", label: "Timestamp" }, { key: "threat_name", label: "Threat", from: "key_fields" }, { key: "path", label: "Path", from: "key_fields" }, { key: "action", label: "Action", from: "key_fields" }, { key: "severity", label: "Severity", from: "key_fields" }, { key: "user", label: "User" }] },
  { key: "detected_files", label: "Archivos detectados", columns: [{ key: "timestamp", label: "Timestamp" }, { key: "threat_name", label: "Threat", from: "key_fields" }, { key: "path", label: "Path", from: "key_fields" }, { key: "action", label: "Action", from: "key_fields" }, { key: "summary", label: "Summary" }] },
  { key: "detected_downloads", label: "Descargados detectados", columns: [{ key: "timestamp", label: "Timestamp" }, { key: "threat_name", label: "Threat", from: "key_fields" }, { key: "path", label: "Path", from: "key_fields" }, { key: "download_domain", label: "Download domain", from: "key_fields" }, { key: "summary", label: "Summary" }] },
  { key: "detected_executions", label: "Ejecutados detectados", columns: [{ key: "timestamp", label: "Timestamp" }, { key: "threat_name", label: "Threat", from: "key_fields" }, { key: "path", label: "Path", from: "key_fields" }, { key: "executed_event", label: "Executed event", from: "key_fields" }, { key: "summary", label: "Summary" }] },
  { key: "quarantined_items", label: "Elementos en cuarentena", columns: [{ key: "timestamp", label: "Timestamp" }, { key: "threat_name", label: "Threat", from: "key_fields" }, { key: "path", label: "Path", from: "key_fields" }, { key: "action", label: "Action", from: "key_fields" }, { key: "summary", label: "Summary" }] },
  { key: "remediation_failures", label: "Fallos de remediación", columns: [{ key: "timestamp", label: "Timestamp" }, { key: "threat_name", label: "Threat", from: "key_fields" }, { key: "path", label: "Path", from: "key_fields" }, { key: "action", label: "Action", from: "key_fields" }, { key: "summary", label: "Summary" }] },
  { key: "services", label: "Servicios", columns: [{ key: "timestamp", label: "Timestamp" }, { key: "service_name", label: "Service", from: "key_fields" }, { key: "image_path", label: "Image path", from: "key_fields" }, { key: "account", label: "Account", from: "key_fields" }, { key: "start_type", label: "Start type", from: "key_fields" }] },
  { key: "persistence", label: "Persistencia", columns: [{ key: "timestamp", label: "Timestamp" }, { key: "type", label: "Type", from: "key_fields" }, { key: "name", label: "Name", from: "key_fields" }, { key: "command", label: "Command", from: "key_fields" }, { key: "path", label: "Path", from: "key_fields" }, { key: "key_path", label: "Key path", from: "key_fields" }, { key: "user", label: "User" }] },
  { key: "network_connections", label: "Conexiones de red", columns: [{ key: "timestamp", label: "Timestamp" }, { key: "application", label: "Application", from: "key_fields" }, { key: "source_ip", label: "Source", from: "key_fields" }, { key: "destination_ip", label: "Destination", from: "key_fields" }, { key: "protocol", label: "Protocol", from: "key_fields" }] },
  { key: "defender", label: "Defender", columns: [{ key: "timestamp", label: "Timestamp" }, { key: "threat_name", label: "Threat", from: "key_fields" }, { key: "path", label: "Path", from: "key_fields" }, { key: "action", label: "Action", from: "key_fields" }, { key: "severity", label: "Severity", from: "key_fields" }, { key: "user", label: "User" }] },
  { key: "account_changes", label: "Cambios de cuentas", columns: [{ key: "timestamp", label: "Timestamp" }, { key: "title", label: "Title" }, { key: "user", label: "User" }, { key: "summary", label: "Summary" }] },
  { key: "anti_forensics", label: "Anti-forensics", columns: [{ key: "timestamp", label: "Timestamp" }, { key: "title", label: "Title" }, { key: "host", label: "Host" }, { key: "summary", label: "Summary" }] },
  { key: "user_activity", label: "Actividad de usuario", columns: [{ key: "timestamp", label: "Timestamp" }, { key: "user", label: "User" }, { key: "file_path", label: "Path", from: "key_fields" }, { key: "key_path", label: "Registry key", from: "key_fields" }, { key: "source", label: "Fuente", from: "key_fields" }, { key: "summary", label: "Summary" }] },
  { key: "opened_files", label: "Archivos abiertos", columns: [{ key: "timestamp", label: "Timestamp" }, { key: "user", label: "User" }, { key: "app_name", label: "Application", from: "key_fields" }, { key: "file_path", label: "Path", from: "key_fields" }, { key: "extension", label: "Ext", from: "key_fields" }, { key: "interaction_count", label: "Interactions", from: "key_fields" }, { key: "source", label: "Fuente", from: "key_fields" }, { key: "drive_type", label: "Drive type", from: "key_fields" }, { key: "network_path", label: "Network path", from: "key_fields" }] },
  { key: "recent_documents", label: "Documentos recientes", columns: [{ key: "timestamp", label: "Timestamp" }, { key: "user", label: "User" }, { key: "app_name", label: "Application", from: "key_fields" }, { key: "file_path", label: "Path", from: "key_fields" }, { key: "interaction_count", label: "Interactions", from: "key_fields" }, { key: "source", label: "Fuente", from: "key_fields" }] },
  { key: "execution_candidates", label: "Candidatos a ejecución", columns: [{ key: "timestamp", label: "Timestamp" }, { key: "file_name", label: "Name", from: "key_fields" }, { key: "file_path", label: "Path", from: "key_fields" }, { key: "source", label: "Fuente", from: "key_fields" }, { key: "interpretation", label: "Interpretation", from: "key_fields" }, { key: "confidence_label", label: "Confidence", from: "key_fields" }, { key: "executed", label: "Executed", from: "key_fields" }] },
  { key: "downloaded_and_observed_programs", label: "Descargados y observados", columns: [{ key: "timestamp", label: "Timestamp" }, { key: "file_name", label: "Program", from: "key_fields" }, { key: "file_path", label: "Path", from: "key_fields" }, { key: "source", label: "Source", from: "key_fields" }, { key: "confidence_label", label: "Confidence", from: "key_fields" }, { key: "summary", label: "Summary" }] },
  { key: "suspicious_programs", label: "Programas sospechosos", columns: [{ key: "timestamp", label: "Timestamp" }, { key: "file_name", label: "Program", from: "key_fields" }, { key: "file_path", label: "Path", from: "key_fields" }, { key: "publisher", label: "Publisher", from: "key_fields" }, { key: "source", label: "Source", from: "key_fields" }, { key: "summary", label: "Summary" }, { key: "suspicious_reasons", label: "Reasons" }] },
  { key: "network_activity", label: "Actividad de red", columns: [{ key: "timestamp", label: "Timestamp" }, { key: "user", label: "User" }, { key: "application", label: "Application", from: "key_fields" }, { key: "process_path", label: "Path", from: "key_fields" }, { key: "bytes_sent", label: "Bytes sent", from: "key_fields" }, { key: "bytes_received", label: "Bytes received", from: "key_fields" }, { key: "bytes_total", label: "Total", from: "key_fields" }, { key: "interface_profile", label: "Interface/Profile", from: "key_fields" }] },
  { key: "application_network_usage", label: "Uso de red por aplicación", columns: [{ key: "timestamp", label: "Timestamp" }, { key: "user", label: "User" }, { key: "application", label: "Application", from: "key_fields" }, { key: "process_name", label: "Process", from: "key_fields" }, { key: "process_path", label: "Path", from: "key_fields" }, { key: "bytes_sent", label: "Bytes sent", from: "key_fields" }, { key: "bytes_received", label: "Bytes received", from: "key_fields" }, { key: "table", label: "Table", from: "key_fields" }] },
  { key: "high_upload_activity", label: "Alto volumen de subida", columns: [{ key: "timestamp", label: "Timestamp" }, { key: "application", label: "Application", from: "key_fields" }, { key: "process_path", label: "Path", from: "key_fields" }, { key: "bytes_sent", label: "Bytes sent", from: "key_fields" }, { key: "bytes_received", label: "Bytes received", from: "key_fields" }, { key: "upload_ratio", label: "Upload ratio", from: "key_fields" }, { key: "suspicious_reasons", label: "Reasons" }] },
  { key: "remote_access_activity", label: "Acceso remoto con red", columns: [{ key: "timestamp", label: "Timestamp" }, { key: "user", label: "User" }, { key: "application", label: "Application", from: "key_fields" }, { key: "process_path", label: "Path", from: "key_fields" }, { key: "bytes_sent", label: "Bytes sent", from: "key_fields" }, { key: "bytes_received", label: "Bytes received", from: "key_fields" }, { key: "summary", label: "Summary" }] },
  { key: "possible_exfiltration", label: "Posible exfiltración", columns: [{ key: "timestamp", label: "Timestamp" }, { key: "application", label: "Application", from: "key_fields" }, { key: "process_path", label: "Path", from: "key_fields" }, { key: "bytes_sent", label: "Bytes sent", from: "key_fields" }, { key: "bytes_received", label: "Bytes received", from: "key_fields" }, { key: "summary", label: "Summary" }, { key: "suspicious_reasons", label: "Reasons" }] },
  { key: "downloaded_and_network_active_programs", label: "Descargados con actividad de red", columns: [{ key: "timestamp", label: "Timestamp" }, { key: "application", label: "Application", from: "key_fields" }, { key: "process_path", label: "Path", from: "key_fields" }, { key: "download_domain", label: "Download domain", from: "key_fields" }, { key: "execution_event", label: "Execution event", from: "key_fields" }, { key: "summary", label: "Summary" }] },
  { key: "applications_used", label: "Aplicaciones usadas", columns: [{ key: "app_name", label: "Application", from: "key_fields" }, { key: "app_id", label: "AppID", from: "key_fields" }, { key: "user", label: "User" }, { key: "count", label: "Count", from: "key_fields" }, { key: "last_seen", label: "Last seen", from: "key_fields" }, { key: "source_jumplist", label: "Source JumpList", from: "key_fields" }] },
  { key: "recent_files", label: "Recent files / JumpLists", columns: [{ key: "timestamp", label: "Timestamp" }, { key: "user", label: "User" }, { key: "app_name", label: "Application", from: "key_fields" }, { key: "app_id", label: "AppID", from: "key_fields" }, { key: "file_path", label: "Path", from: "key_fields" }, { key: "source_jumplist", label: "Source JumpList", from: "key_fields" }, { key: "interaction_count", label: "Interactions", from: "key_fields" }, { key: "suspicious_reasons", label: "Reasons" }] },
  { key: "downloaded_files_opened", label: "Descargados abiertos", columns: [{ key: "timestamp", label: "Timestamp" }, { key: "user", label: "User" }, { key: "app_name", label: "Application", from: "key_fields" }, { key: "file_path", label: "Path", from: "key_fields" }, { key: "download_domain", label: "Download domain", from: "key_fields" }, { key: "source_jumplist", label: "Source JumpList", from: "key_fields" }, { key: "summary", label: "Summary" }] },
  { key: "deleted_files_opened", label: "Borrados abiertos", columns: [{ key: "timestamp", label: "Timestamp" }, { key: "user", label: "User" }, { key: "app_name", label: "Application", from: "key_fields" }, { key: "file_path", label: "Path", from: "key_fields" }, { key: "source_jumplist", label: "Source JumpList", from: "key_fields" }, { key: "summary", label: "Summary" }] },
  { key: "network_file_activity", label: "Actividad de archivos en red", columns: [{ key: "timestamp", label: "Timestamp" }, { key: "user", label: "User" }, { key: "app_name", label: "Application", from: "key_fields" }, { key: "file_path", label: "Path", from: "key_fields" }, { key: "network_path", label: "Network path", from: "key_fields" }, { key: "machine_id", label: "MachineID", from: "key_fields" }] },
  { key: "usb_file_activity", label: "Actividad de archivos USB", columns: [{ key: "timestamp", label: "Timestamp" }, { key: "user", label: "User" }, { key: "app_name", label: "Application", from: "key_fields" }, { key: "file_path", label: "Path", from: "key_fields" }, { key: "drive_type", label: "Drive type", from: "key_fields" }, { key: "volume_serial", label: "Volume serial", from: "key_fields" }] },
  { key: "cloud_file_activity", label: "Actividad en cloud sync", columns: [{ key: "timestamp", label: "Timestamp" }, { key: "user", label: "User" }, { key: "app_name", label: "Application", from: "key_fields" }, { key: "file_path", label: "Path", from: "key_fields" }, { key: "summary", label: "Summary" }] },
  { key: "suspicious_recent_items", label: "Recent items sospechosos", columns: [{ key: "timestamp", label: "Timestamp" }, { key: "user", label: "User" }, { key: "app_name", label: "Application", from: "key_fields" }, { key: "file_path", label: "Path", from: "key_fields" }, { key: "arguments", label: "Arguments", from: "key_fields" }, { key: "suspicious_reasons", label: "Reasons" }] },
  { key: "scripts_opened", label: "Scripts abiertos", columns: [{ key: "timestamp", label: "Timestamp" }, { key: "user", label: "User" }, { key: "app_name", label: "Application", from: "key_fields" }, { key: "file_path", label: "Target", from: "key_fields" }, { key: "arguments", label: "Arguments", from: "key_fields" }, { key: "source_jumplist", label: "Source JumpList", from: "key_fields" }, { key: "source_lnk", label: "Source LNK", from: "key_fields" }, { key: "suspicious_reasons", label: "Reasons" }] },
  { key: "network_paths", label: "Rutas de red", columns: [{ key: "timestamp", label: "Timestamp" }, { key: "user", label: "User" }, { key: "file_path", label: "Path", from: "key_fields" }, { key: "network_path", label: "Network", from: "key_fields" }, { key: "machine_id", label: "MachineID", from: "key_fields" }, { key: "volume_serial", label: "Volume serial", from: "key_fields" }] },
  { key: "removable_media", label: "USB / removible", columns: [{ key: "timestamp", label: "Timestamp" }, { key: "user", label: "User" }, { key: "file_path", label: "Path", from: "key_fields" }, { key: "drive_type", label: "Drive type", from: "key_fields" }, { key: "machine_id", label: "MachineID", from: "key_fields" }, { key: "volume_serial", label: "Volume serial", from: "key_fields" }] },
  { key: "usb_devices", label: "Dispositivos USB", columns: [{ key: "timestamp", label: "Timestamp" }, { key: "vendor", label: "Vendor", from: "key_fields" }, { key: "product", label: "Product", from: "key_fields" }, { key: "serial", label: "Serial", from: "key_fields" }, { key: "friendly_name", label: "Friendly name", from: "key_fields" }, { key: "drive_letter", label: "Drive", from: "key_fields" }, { key: "volume_serial", label: "Volume serial", from: "key_fields" }] },
  { key: "usb_storage_devices", label: "USB storage", columns: [{ key: "timestamp", label: "Timestamp" }, { key: "vendor", label: "Vendor", from: "key_fields" }, { key: "product", label: "Product", from: "key_fields" }, { key: "serial", label: "Serial", from: "key_fields" }, { key: "friendly_name", label: "Friendly name", from: "key_fields" }, { key: "device_instance_id", label: "Instance ID", from: "key_fields" }, { key: "source", label: "Source", from: "key_fields" }] },
  { key: "usb_volume_mappings", label: "USB volume mappings", columns: [{ key: "timestamp", label: "Timestamp" }, { key: "vendor", label: "Vendor", from: "key_fields" }, { key: "product", label: "Product", from: "key_fields" }, { key: "serial", label: "Serial", from: "key_fields" }, { key: "drive_letter", label: "Drive", from: "key_fields" }, { key: "volume_guid", label: "Volume GUID", from: "key_fields" }, { key: "volume_serial", label: "Volume serial", from: "key_fields" }, { key: "source", label: "Source", from: "key_fields" }] },
  { key: "setupapi_driver_activity", label: "SetupAPI / driver updates", columns: [{ key: "timestamp", label: "Timestamp" }, { key: "device_type", label: "Device type", from: "key_fields" }, { key: "device_instance_id", label: "Instance ID", from: "key_fields" }, { key: "vendor", label: "Vendor", from: "key_fields" }, { key: "product", label: "Product", from: "key_fields" }, { key: "source", label: "Source", from: "key_fields" }, { key: "summary", label: "Summary" }] },
  { key: "download_to_usb", label: "Descargas hacia USB", columns: [{ key: "timestamp", label: "Timestamp" }, { key: "user", label: "User" }, { key: "file_path", label: "Path", from: "key_fields" }, { key: "download_domain", label: "Domain", from: "key_fields" }, { key: "drive_letter", label: "Drive", from: "key_fields" }, { key: "volume_serial", label: "Volume serial", from: "key_fields" }, { key: "summary", label: "Summary" }] },
  { key: "possible_usb_exfiltration", label: "Posible exfiltración a USB", columns: [{ key: "timestamp", label: "Timestamp" }, { key: "user", label: "User" }, { key: "file_path", label: "Path", from: "key_fields" }, { key: "drive_letter", label: "Drive", from: "key_fields" }, { key: "volume_serial", label: "Volume serial", from: "key_fields" }, { key: "source", label: "Source", from: "key_fields" }, { key: "suspicious_reasons", label: "Reasons" }] },
  { key: "suspicious_usb_activity", label: "Actividad USB sospechosa", columns: [{ key: "timestamp", label: "Timestamp" }, { key: "user", label: "User" }, { key: "file_path", label: "Path", from: "key_fields" }, { key: "drive_type", label: "Drive type", from: "key_fields" }, { key: "volume_serial", label: "Volume serial", from: "key_fields" }, { key: "suspicious_reasons", label: "Reasons" }] },
  { key: "background_downloads", label: "Descargas en segundo plano", columns: [{ key: "timestamp", label: "Timestamp" }, { key: "user", label: "User" }, { key: "display_name", label: "Job", from: "key_fields" }, { key: "remote_url", label: "Remote URL", from: "key_fields" }, { key: "local_path", label: "Local path", from: "key_fields" }, { key: "state", label: "State", from: "key_fields" }, { key: "type", label: "Type", from: "key_fields" }, { key: "confidence", label: "Confidence" }] },
  { key: "bits_jobs", label: "Jobs BITS", columns: [{ key: "timestamp", label: "Timestamp" }, { key: "user", label: "User" }, { key: "job_id", label: "Job ID", from: "key_fields" }, { key: "display_name", label: "Display name", from: "key_fields" }, { key: "state", label: "State", from: "key_fields" }, { key: "type", label: "Type", from: "key_fields" }, { key: "remote_url", label: "Remote URL", from: "key_fields" }, { key: "local_path", label: "Local path", from: "key_fields" }] },
  { key: "bits_transfers", label: "Transferencias BITS", columns: [{ key: "timestamp", label: "Timestamp" }, { key: "user", label: "User" }, { key: "display_name", label: "Job", from: "key_fields" }, { key: "file_name", label: "File", from: "key_fields" }, { key: "local_path", label: "Local path", from: "key_fields" }, { key: "remote_url", label: "Remote URL", from: "key_fields" }, { key: "bytes_transferred", label: "Transferred", from: "key_fields" }, { key: "bytes_total", label: "Total", from: "key_fields" }] },
  { key: "suspicious_bits_jobs", label: "Jobs BITS sospechosos", columns: [{ key: "timestamp", label: "Timestamp" }, { key: "user", label: "User" }, { key: "display_name", label: "Job", from: "key_fields" }, { key: "remote_url", label: "Remote URL", from: "key_fields" }, { key: "local_path", label: "Local path", from: "key_fields" }, { key: "notify_cmd_line", label: "Notify cmd", from: "key_fields" }, { key: "suspicious_reasons", label: "Reasons" }] },
  { key: "bits_notify_commands", label: "BITS notify commands", columns: [{ key: "timestamp", label: "Timestamp" }, { key: "user", label: "User" }, { key: "display_name", label: "Job", from: "key_fields" }, { key: "notify_cmd_line", label: "Command", from: "key_fields" }, { key: "remote_url", label: "Remote URL", from: "key_fields" }, { key: "local_path", label: "Local path", from: "key_fields" }, { key: "confidence", label: "Confidence" }] },
  { key: "downloaded_then_executed", label: "BITS descargado y ejecutado", columns: [{ key: "timestamp", label: "Timestamp" }, { key: "user", label: "User" }, { key: "display_name", label: "Job", from: "key_fields" }, { key: "local_path", label: "Local path", from: "key_fields" }, { key: "remote_url", label: "Remote URL", from: "key_fields" }, { key: "execution_event", label: "Execution", from: "key_fields" }, { key: "confidence", label: "Confidence" }] },
  { key: "downloaded_then_detected", label: "BITS descargado y detectado", columns: [{ key: "timestamp", label: "Timestamp" }, { key: "user", label: "User" }, { key: "display_name", label: "Job", from: "key_fields" }, { key: "local_path", label: "Local path", from: "key_fields" }, { key: "remote_url", label: "Remote URL", from: "key_fields" }, { key: "defender_event", label: "Defender", from: "key_fields" }, { key: "confidence", label: "Confidence" }] },
  { key: "cloud_sync_roots", label: "Cloud sync roots", columns: [{ key: "timestamp", label: "Timestamp" }, { key: "provider", label: "Provider", from: "key_fields" }, { key: "user", label: "User" }, { key: "account", label: "Account", from: "key_fields" }, { key: "sync_root", label: "Sync root", from: "key_fields" }, { key: "source", label: "Source", from: "key_fields" }, { key: "confidence", label: "Confidence" }] },
  { key: "network_overview", label: "Resumen de red", columns: [{ key: "timestamp", label: "Timestamp" }, { key: "interface_name", label: "Interface", from: "key_fields" }, { key: "ssid", label: "SSID", from: "key_fields" }, { key: "gateway", label: "Gateway", from: "key_fields" }, { key: "dns_servers", label: "DNS", from: "key_fields" }] },
  { key: "wlan_profiles", label: "Perfiles WLAN", columns: [{ key: "timestamp", label: "Timestamp" }, { key: "ssid", label: "SSID", from: "key_fields" }, { key: "profile_name", label: "Profile", from: "key_fields" }, { key: "interface_name", label: "Interface", from: "key_fields" }, { key: "summary", label: "Summary" }] },
  { key: "wlan_connections", label: "Conexiones WLAN", columns: [{ key: "timestamp", label: "Timestamp" }, { key: "ssid", label: "SSID", from: "key_fields" }, { key: "bssid", label: "BSSID", from: "key_fields" }, { key: "interface_name", label: "Interface", from: "key_fields" }, { key: "summary", label: "Summary" }] },
  { key: "network_profiles", label: "Perfiles de red", columns: [{ key: "timestamp", label: "Timestamp" }, { key: "profile_name", label: "Profile", from: "key_fields" }, { key: "network_category", label: "Category", from: "key_fields" }, { key: "interface_name", label: "Interface", from: "key_fields" }, { key: "summary", label: "Summary" }] },
  { key: "dns_config", label: "Configuración DNS", columns: [{ key: "timestamp", label: "Timestamp" }, { key: "dns_servers", label: "DNS", from: "key_fields" }, { key: "interface_name", label: "Interface", from: "key_fields" }, { key: "gateway", label: "Gateway", from: "key_fields" }, { key: "summary", label: "Summary" }] },
  { key: "dns_cache", label: "Cache DNS", columns: [{ key: "timestamp", label: "Timestamp" }, { key: "domain", label: "Domain", from: "key_fields" }, { key: "ip", label: "IP", from: "key_fields" }, { key: "record_type", label: "Type", from: "key_fields" }, { key: "summary", label: "Summary" }] },
  { key: "hosts_entries", label: "Hosts entries", columns: [{ key: "timestamp", label: "Timestamp" }, { key: "hostname", label: "Hostname", from: "key_fields" }, { key: "ip", label: "IP", from: "key_fields" }, { key: "summary", label: "Summary" }] },
  { key: "suspicious_hosts_entries", label: "Hosts sospechosos", columns: [{ key: "timestamp", label: "Timestamp" }, { key: "hostname", label: "Hostname", from: "key_fields" }, { key: "ip", label: "IP", from: "key_fields" }, { key: "summary", label: "Summary" }, { key: "suspicious_reasons", label: "Reasons" }] },
  { key: "suspicious_dns_config", label: "DNS sospechoso", columns: [{ key: "timestamp", label: "Timestamp" }, { key: "dns_servers", label: "DNS", from: "key_fields" }, { key: "interface_name", label: "Interface", from: "key_fields" }, { key: "summary", label: "Summary" }, { key: "suspicious_reasons", label: "Reasons" }] },
  { key: "network_indicators", label: "Indicadores de red", columns: [{ key: "timestamp", label: "Timestamp" }, { key: "domain", label: "Domain", from: "key_fields" }, { key: "ip", label: "IP", from: "key_fields" }, { key: "source", label: "Source", from: "key_fields" }, { key: "summary", label: "Summary" }] },
  { key: "network_correlations", label: "Correlaciones de red", columns: [{ key: "timestamp", label: "Timestamp" }, { key: "domain", label: "Domain", from: "key_fields" }, { key: "ip", label: "IP", from: "key_fields" }, { key: "summary", label: "Summary" }, { key: "suspicious_reasons", label: "Reasons" }] },
  { key: "cloud_accounts", label: "Cloud accounts", columns: [{ key: "timestamp", label: "Timestamp" }, { key: "provider", label: "Provider", from: "key_fields" }, { key: "account", label: "Account", from: "key_fields" }, { key: "account_email", label: "Email", from: "key_fields" }, { key: "sync_root", label: "Sync root", from: "key_fields" }, { key: "confidence", label: "Confidence" }] },
  { key: "cloud_file_activity", label: "Actividad de archivos cloud", columns: [{ key: "timestamp", label: "Timestamp" }, { key: "provider", label: "Provider", from: "key_fields" }, { key: "file_path", label: "Path", from: "key_fields" }, { key: "action", label: "Action", from: "key_fields" }, { key: "file_type", label: "Type", from: "key_fields" }, { key: "source", label: "Source", from: "key_fields" }] },
  { key: "cloud_sensitive_files", label: "Archivos sensibles en cloud", columns: [{ key: "timestamp", label: "Timestamp" }, { key: "provider", label: "Provider", from: "key_fields" }, { key: "file_path", label: "Path", from: "key_fields" }, { key: "file_type", label: "Type", from: "key_fields" }, { key: "suspicious_reasons", label: "Reasons" }] },
  { key: "cloud_archives", label: "Archivos comprimidos en cloud", columns: [{ key: "timestamp", label: "Timestamp" }, { key: "provider", label: "Provider", from: "key_fields" }, { key: "file_path", label: "Path", from: "key_fields" }, { key: "file_type", label: "Type", from: "key_fields" }, { key: "suspicious_reasons", label: "Reasons" }] },
  { key: "downloaded_to_cloud", label: "Descargados a cloud", columns: [{ key: "timestamp", label: "Timestamp" }, { key: "provider", label: "Provider", from: "key_fields" }, { key: "file_path", label: "Target path", from: "key_fields" }, { key: "download_domain", label: "Domain", from: "key_fields" }, { key: "source", label: "Source", from: "key_fields" }] },
  { key: "copied_to_cloud", label: "Copiados a cloud", columns: [{ key: "timestamp", label: "Timestamp" }, { key: "provider", label: "Provider", from: "key_fields" }, { key: "file_path", label: "Path", from: "key_fields" }, { key: "command_preview", label: "Command", from: "key_fields" }, { key: "suspicious_reasons", label: "Reasons" }] },
  { key: "executable_from_cloud", label: "Ejecutables en cloud", columns: [{ key: "timestamp", label: "Timestamp" }, { key: "provider", label: "Provider", from: "key_fields" }, { key: "file_path", label: "Path", from: "key_fields" }, { key: "source", label: "Source", from: "key_fields" }, { key: "suspicious_reasons", label: "Reasons" }] },
  { key: "defender_detection_in_cloud", label: "Detecciones Defender en cloud", columns: [{ key: "timestamp", label: "Timestamp" }, { key: "provider", label: "Provider", from: "key_fields" }, { key: "file_path", label: "Path", from: "key_fields" }, { key: "threat_name", label: "Threat", from: "key_fields" }, { key: "confidence", label: "Confidence" }] },
  { key: "possible_cloud_staging", label: "Posible staging cloud", columns: [{ key: "timestamp", label: "Timestamp" }, { key: "provider", label: "Provider", from: "key_fields" }, { key: "sync_root", label: "Sync root", from: "key_fields" }, { key: "file_count", label: "File count", from: "key_fields" }, { key: "confidence", label: "Confidence" }, { key: "suspicious_reasons", label: "Reasons" }] },
  { key: "possible_cloud_exfiltration", label: "Posible exfiltración cloud", columns: [{ key: "timestamp", label: "Timestamp" }, { key: "provider", label: "Provider", from: "key_fields" }, { key: "sync_root", label: "Sync root", from: "key_fields" }, { key: "confidence", label: "Confidence" }, { key: "summary", label: "Summary" }, { key: "suspicious_reasons", label: "Reasons" }] },
  { key: "autoruns_persistence", label: "Autoruns / persistencia", columns: [{ key: "timestamp", label: "Timestamp" }, { key: "user", label: "User" }, { key: "mechanism", label: "Mechanism", from: "key_fields" }, { key: "name", label: "Entry", from: "key_fields" }, { key: "location", label: "Location", from: "key_fields" }, { key: "path", label: "Image path", from: "key_fields" }, { key: "publisher", label: "Publisher", from: "key_fields" }, { key: "signer", label: "Signer", from: "key_fields" }] },
  { key: "suspicious_autoruns", label: "Autoruns sospechosos", columns: [{ key: "timestamp", label: "Timestamp" }, { key: "user", label: "User" }, { key: "mechanism", label: "Mechanism", from: "key_fields" }, { key: "name", label: "Entry", from: "key_fields" }, { key: "path", label: "Path", from: "key_fields" }, { key: "command", label: "Command", from: "key_fields" }, { key: "vt_detection", label: "VT", from: "key_fields" }, { key: "suspicious_reasons", label: "Reasons" }] },
  { key: "run_key_persistence", label: "Run Keys", columns: [{ key: "timestamp", label: "Timestamp" }, { key: "name", label: "Entry", from: "key_fields" }, { key: "location", label: "Key path", from: "key_fields" }, { key: "command", label: "Command", from: "key_fields" }, { key: "user", label: "User" }] },
  { key: "startup_folder_persistence", label: "Startup folder", columns: [{ key: "timestamp", label: "Timestamp" }, { key: "name", label: "Entry", from: "key_fields" }, { key: "path", label: "Path", from: "key_fields" }, { key: "publisher", label: "Publisher", from: "key_fields" }, { key: "user", label: "User" }] },
  { key: "service_driver_persistence", label: "Servicios y drivers", columns: [{ key: "timestamp", label: "Timestamp" }, { key: "mechanism", label: "Type", from: "key_fields" }, { key: "name", label: "Entry", from: "key_fields" }, { key: "path", label: "Path", from: "key_fields" }, { key: "signer", label: "Signer", from: "key_fields" }, { key: "user", label: "User" }] },
  { key: "scheduled_task_persistence", label: "Persistencia por tareas", columns: [{ key: "timestamp", label: "Timestamp" }, { key: "name", label: "Entry", from: "key_fields" }, { key: "location", label: "Task path", from: "key_fields" }, { key: "command", label: "Command", from: "key_fields" }, { key: "user", label: "User" }] },
  { key: "ifeo_debugger_persistence", label: "IFEO Debugger", columns: [{ key: "timestamp", label: "Timestamp" }, { key: "name", label: "Entry", from: "key_fields" }, { key: "location", label: "Location", from: "key_fields" }, { key: "command", label: "Debugger", from: "key_fields" }, { key: "suspicious_reasons", label: "Reasons" }] },
  { key: "winlogon_persistence", label: "Winlogon", columns: [{ key: "timestamp", label: "Timestamp" }, { key: "name", label: "Entry", from: "key_fields" }, { key: "location", label: "Location", from: "key_fields" }, { key: "command", label: "Command", from: "key_fields" }, { key: "suspicious_reasons", label: "Reasons" }] },
  { key: "appinit_appcert_persistence", label: "AppInit / AppCert", columns: [{ key: "timestamp", label: "Timestamp" }, { key: "name", label: "Entry", from: "key_fields" }, { key: "path", label: "Path", from: "key_fields" }, { key: "publisher", label: "Publisher", from: "key_fields" }, { key: "suspicious_reasons", label: "Reasons" }] },
  { key: "downloaded_then_persisted", label: "Descargado y luego persistido", columns: [{ key: "timestamp", label: "Timestamp" }, { key: "name", label: "Entry", from: "key_fields" }, { key: "path", label: "Path", from: "key_fields" }, { key: "download_domain", label: "Download domain", from: "key_fields" }, { key: "confidence", label: "Confidence" }] },
  { key: "persisted_then_executed", label: "Persistido y luego ejecutado", columns: [{ key: "timestamp", label: "Timestamp" }, { key: "name", label: "Entry", from: "key_fields" }, { key: "path", label: "Path", from: "key_fields" }, { key: "execution_event", label: "Execution", from: "key_fields" }, { key: "confidence", label: "Confidence" }] },
  { key: "persistence_detected_by_defender", label: "Persistencia detectada por Defender", columns: [{ key: "timestamp", label: "Timestamp" }, { key: "name", label: "Entry", from: "key_fields" }, { key: "path", label: "Path", from: "key_fields" }, { key: "defender_event", label: "Defender", from: "key_fields" }, { key: "confidence", label: "Confidence" }] },
  { key: "suspicious_files", label: "Archivos sospechosos", columns: [{ key: "timestamp", label: "Timestamp" }, { key: "file_name", label: "Name", from: "key_fields" }, { key: "file_path", label: "Path", from: "key_fields" }, { key: "extension", label: "Ext", from: "key_fields" }, { key: "summary", label: "Summary" }, { key: "suspicious_reasons", label: "Reasons" }] },
  { key: "suspicious_findings", label: "Hallazgos sospechosos", columns: [{ key: "timestamp", label: "Timestamp" }, { key: "title", label: "Title" }, { key: "summary", label: "Summary" }, { key: "suspicious_reasons", label: "Reasons" }, { key: "source", label: "Fuente", from: "key_fields" }] },
  { key: "timeline", label: "Timeline global", columns: [{ key: "timestamp", label: "Timestamp" }, { key: "activity_type", label: "Activity" }, { key: "host", label: "Host" }, { key: "user", label: "User" }, { key: "summary", label: "Summary" }] },
];

function valueFor(activity: SemiAutoActivity, key: string, from: "root" | "key_fields" = "root") {
  const source = from === "key_fields" ? activity.key_fields : activity;
  const value = (source as Record<string, unknown>)[key];
  if (Array.isArray(value)) return value.join(", ");
  return value ?? "-";
}

function formatSeconds(value: unknown) {
  if (typeof value !== "number" || !Number.isFinite(value) || value < 0) return "-";
  if (value < 60) return `${Math.round(value)}s`;
  const minutes = Math.floor(value / 60);
  const seconds = Math.round(value % 60);
  if (minutes < 60) return `${minutes}m ${seconds}s`;
  const hours = Math.floor(minutes / 60);
  const remMinutes = minutes % 60;
  return `${hours}h ${remMinutes}m`;
}

export default function SemiAutoAnalysis() {
  const { activeCaseId } = useActiveCase();
  const queryClient = useQueryClient();
  const [caseId, setCaseId] = useState(activeCaseId);
  const [timeFrom, setTimeFrom] = useState("");
  const [timeTo, setTimeTo] = useState("");
  const [debugExportOpen, setDebugExportOpen] = useState(false);
  const [tableSortState, setTableSortState] = useState<Record<string, { key: string; direction: SortDirection }>>({});
  const casesQuery = useQuery({ queryKey: ["cases"], queryFn: api.listCases, staleTime: 30_000, refetchOnWindowFocus: false });
  const normalizedTimeFrom = timeFrom ? new Date(timeFrom).toISOString() : undefined;
  const normalizedTimeTo = timeTo ? new Date(timeTo).toISOString() : undefined;
  const analysisStatusQuery = useQuery({
    queryKey: ["semi-auto-analysis-status", caseId, normalizedTimeFrom, normalizedTimeTo],
    queryFn: () => api.getSemiAutoAnalysisStatus(caseId, { time_from: normalizedTimeFrom, time_to: normalizedTimeTo }),
    enabled: Boolean(caseId),
    staleTime: 2_000,
    refetchInterval: (query) => {
      const state = query.state.data?.status;
      return state === "queued" || state === "running" ? 3000 : false;
    },
    refetchOnWindowFocus: false,
  });
  const startMutation = useMutation({
    mutationFn: () => api.startSemiAutoAnalysis(caseId!, { time_from: normalizedTimeFrom, time_to: normalizedTimeTo }),
    onSuccess: () => void queryClient.invalidateQueries({ queryKey: ["semi-auto-analysis-status", caseId, normalizedTimeFrom, normalizedTimeTo] }),
  });
  const stopMutation = useMutation({
    mutationFn: () => api.stopSemiAutoAnalysis(caseId!, { time_from: normalizedTimeFrom, time_to: normalizedTimeTo }),
    onSuccess: () => void queryClient.invalidateQueries({ queryKey: ["semi-auto-analysis-status", caseId, normalizedTimeFrom, normalizedTimeTo] }),
  });

  async function exportMarkdown() {
    if (!caseId || !analysisStatusQuery.data?.result) return;
    const result = await api.exportSemiAutoAnalysisMarkdown(caseId, {
      time_from: normalizedTimeFrom,
      time_to: normalizedTimeTo,
    });
    const url = URL.createObjectURL(result.blob);
    const anchor = document.createElement("a");
    const match = /filename="?(.*?)"?$/.exec(result.filename);
    anchor.href = url;
    anchor.download = match?.[1] || `semi-auto-analysis-${caseId}.md`;
    document.body.appendChild(anchor);
    anchor.click();
    anchor.remove();
    URL.revokeObjectURL(url);
  }

  async function exportPdf() {
    if (!caseId || !analysisStatusQuery.data?.result) return;
    const result = await api.exportSemiAutoAnalysisPdf(caseId, {
      time_from: normalizedTimeFrom,
      time_to: normalizedTimeTo,
    });
    const url = URL.createObjectURL(result.blob);
    const anchor = document.createElement("a");
    const match = /filename="?(.*?)"?$/.exec(result.filename);
    anchor.href = url;
    anchor.download = match?.[1] || `semi-auto-analysis-${caseId}.pdf`;
    document.body.appendChild(anchor);
    anchor.click();
    anchor.remove();
    URL.revokeObjectURL(url);
  }

  useEffect(() => {
    setCaseId(activeCaseId);
    setTimeFrom("");
    setTimeTo("");
  }, [activeCaseId]);

  const analysis = analysisStatusQuery.data?.result;
  const summaryCards = useMemo(() => {
    const summary = analysis?.summary;
    if (!summary) return [];
    return [
      ["Events", summary.total_events],
      ["Activities", summary.total_activities],
      ["Programs", summary.program_executions],
      ["Inventory", summary.program_inventory ?? 0],
      ["Exec candidates", summary.execution_candidates ?? 0],
      ["Network", summary.network_activity ?? 0],
      ["High upload", summary.high_upload_activity ?? 0],
      ["PowerShell", summary.powershell_executions],
      ["PS downloads", summary.powershell_downloads ?? 0],
      ["PS encoded", summary.powershell_encoded_commands ?? 0],
      ["Logons", summary.logons],
      ["RDP", summary.rdp_sessions],
      ["Services", summary.services_created],
      ["Tasks", summary.scheduled_tasks_observed ?? summary.scheduled_tasks_created ?? 0],
      ["Defender", summary.defender_detections],
      ["USB", summary.usb_devices ?? 0],
      ["BITS", summary.bits_jobs ?? 0],
      ["BITS suspicious", summary.suspicious_bits_jobs ?? 0],
      ["Cloud roots", summary.cloud_sync_roots ?? 0],
      ["Cloud accounts", summary.cloud_accounts ?? 0],
      ["Cloud sensitive", summary.cloud_sensitive_files ?? 0],
      ["Cloud archives", summary.cloud_archives ?? 0],
      ["Downloaded to cloud", summary.downloaded_to_cloud ?? 0],
      ["Copied to cloud", summary.copied_to_cloud ?? 0],
      ["Cloud staging", summary.possible_cloud_staging ?? 0],
      ["Cloud exfiltration", summary.possible_cloud_exfiltration ?? 0],
      ["Autoruns", summary.autoruns_persistence ?? 0],
      ["Autoruns suspicious", summary.suspicious_autoruns ?? 0],
      ["User activity", summary.user_activity ?? 0],
      ["Accounts", summary.account_changes ?? 0],
      ["Anti-forensics", summary.anti_forensics ?? 0],
      ["Suspicious", summary.suspicious_findings],
    ];
  }, [analysis?.summary]);

  const currentStatus = analysisStatusQuery.data?.status ?? "idle";
  const isActive = currentStatus === "queued" || currentStatus === "running";
  const metrics = analysisStatusQuery.data?.metrics ?? {};
  const elapsedSeconds = metrics["elapsed_seconds"];
  const remainingSeconds = metrics["estimated_remaining_seconds"];

  function sectionSort(sectionKey: string) {
    return tableSortState[sectionKey] ?? { key: "timestamp", direction: "desc" as SortDirection };
  }

  function handleSectionSort(sectionKey: string, columnKey: string) {
    const current = sectionSort(sectionKey);
    setTableSortState((previous) => ({
      ...previous,
      [sectionKey]: {
        key: columnKey,
        direction: nextSortDirection(current.key, current.direction, columnKey),
      },
    }));
  }

  return (
    <div className="space-y-6">
      <section className="rounded-[28px] border border-line bg-panel/70 p-6 shadow-panel">
        <p className="font-mono text-xs uppercase tracking-[0.24em] text-accent">Análisis semiautomático</p>
        <h2 className="mt-2 text-2xl font-semibold">Forensic Activity Summary built from normalized EVTX, parsed artifacts and correlated host activity</h2>
        <p className="mt-2 text-sm text-muted">Actividades forenses agrupadas y correlacionadas.</p>
        <div className="mt-4 rounded-2xl border border-line bg-abyss/50 p-4 text-sm text-muted">
          <p className="font-mono text-[11px] uppercase tracking-[0.16em] text-accent">Cuándo usar esta sección</p>
          <p className="mt-2">Úsala para responder rápido qué programas se ejecutaron, qué persistencia existe, qué archivos se abrieron, qué USB aparecen y qué hallazgos merecen revisión, sin empezar mirando evento por evento.</p>
        </div>
        {!caseId ? <p className="mt-2 text-sm text-amber-300">Select a case to generate semi-automatic analysis.</p> : null}
        <div className="mt-5 flex flex-wrap gap-3">
          <select value={caseId} onChange={(event) => setCaseId(event.target.value)} className="rounded-2xl border border-line bg-abyss/80 px-4 py-3 text-sm">
            <option value="">Select case</option>
            {(casesQuery.data ?? []).map((item: DfirCase) => (
              <option key={item.id} value={item.id}>
                {item.name}
              </option>
            ))}
          </select>
          <label className="rounded-2xl border border-line bg-abyss/80 px-4 py-3 text-sm text-muted">
            <span className="mr-2 font-mono text-[11px] uppercase tracking-[0.16em]">From</span>
            <input type="datetime-local" value={timeFrom} onChange={(event) => setTimeFrom(event.target.value)} className="bg-transparent outline-none" />
          </label>
          <label className="rounded-2xl border border-line bg-abyss/80 px-4 py-3 text-sm text-muted">
            <span className="mr-2 font-mono text-[11px] uppercase tracking-[0.16em]">To</span>
            <input type="datetime-local" value={timeTo} onChange={(event) => setTimeTo(event.target.value)} className="bg-transparent outline-none" />
          </label>
          <button
            onClick={() => {
              setTimeFrom("");
              setTimeTo("");
            }}
            className="rounded-2xl border border-line bg-abyss/70 px-4 py-3 text-sm text-muted"
          >
            Clear time filter
          </button>
          <button
            onClick={() => void startMutation.mutateAsync()}
            disabled={!caseId || isActive || startMutation.isPending}
            className="rounded-2xl bg-accent px-4 py-3 text-sm font-semibold text-abyss disabled:opacity-50"
          >
            {isActive ? "Analysis running" : "Run analysis"}
          </button>
          <button
            onClick={() => void stopMutation.mutateAsync()}
            disabled={!caseId || !isActive || stopMutation.isPending}
            className="rounded-2xl border border-danger/40 bg-danger/10 px-4 py-3 text-sm text-danger disabled:opacity-50"
          >
            Stop
          </button>
          <button
            onClick={() => void analysisStatusQuery.refetch()}
            disabled={!caseId || analysisStatusQuery.isFetching}
            className="rounded-2xl border border-line bg-abyss/70 px-4 py-3 text-sm text-muted disabled:opacity-50"
          >
            Refresh status
          </button>
          <button onClick={() => void exportMarkdown()} disabled={!caseId || !analysis} className="rounded-2xl border border-line bg-abyss/70 px-4 py-3 text-sm text-muted disabled:opacity-50">
            Export report (.md)
          </button>
          <button onClick={() => void exportPdf()} disabled={!caseId || !analysis} className="rounded-2xl border border-line bg-abyss/70 px-4 py-3 text-sm text-muted disabled:opacity-50">
            Export report (.pdf)
          </button>
          <button onClick={() => setDebugExportOpen(true)} disabled={!caseId} className="rounded-2xl border border-line bg-abyss/70 px-4 py-3 text-sm text-muted disabled:opacity-50">
            Export analysis debug pack
          </button>
          {analysis ? <span className="rounded-2xl border border-line bg-abyss/70 px-4 py-3 text-sm text-muted">Generated at {analysis.generated_at}</span> : null}
        </div>
        {analysis ? (
          <p className="mt-3 text-sm text-muted">
            Analysing events from {analysis.time_range?.from || "the beginning"} to {analysis.time_range?.to || "the latest event"}.
          </p>
        ) : null}
        {analysis && analysis.summary.total_events === 0 && (timeFrom || timeTo) ? (
          <p className="mt-3 text-sm text-amber-300">
            No events matched the selected time range. Clear the time filter or choose a wider window.
          </p>
        ) : null}
        {caseId ? (
          <div className="mt-4 rounded-2xl border border-line bg-abyss/60 p-4">
            <div className="flex flex-wrap items-center justify-between gap-3">
              <div>
                <p className="font-mono text-[11px] uppercase tracking-[0.16em] text-accent">Analysis status</p>
                <p className="mt-2 text-sm text-muted">
                  Status: <span className="text-primary">{currentStatus}</span>
                  {analysisStatusQuery.data?.current_phase ? ` · Phase: ${analysisStatusQuery.data.current_phase}` : ""}
                  {analysisStatusQuery.data?.cancel_requested ? " · Stop requested" : ""}
                </p>
              </div>
              <div className="text-sm text-muted">
                <span>Elapsed {formatSeconds(elapsedSeconds)}</span>
                <span className="mx-2">·</span>
                <span>ETA {formatSeconds(remainingSeconds)}</span>
              </div>
            </div>
            <div className="mt-3 h-3 overflow-hidden rounded-full bg-panel">
              <div className="h-full rounded-full bg-accent transition-all duration-300" style={{ width: `${analysisStatusQuery.data?.progress_pct ?? 0}%` }} />
            </div>
            <p className="mt-2 text-sm text-muted">{analysisStatusQuery.data?.progress_pct ?? 0}% complete</p>
          </div>
        ) : null}
        {summaryCards.length ? (
          <div className="mt-5 grid gap-3 md:grid-cols-2 xl:grid-cols-5">
            {summaryCards.map(([label, value]) => (
              <div key={String(label)} className="rounded-2xl border border-line bg-abyss/70 px-4 py-3">
                <p className="font-mono text-[11px] uppercase tracking-[0.18em] text-muted">{label}</p>
                <p className="mt-2 text-lg font-semibold">{value}</p>
              </div>
            ))}
          </div>
        ) : null}
      </section>

      {analysisStatusQuery.isLoading ? <div className="rounded-2xl border border-line bg-panel/70 p-4 text-sm text-muted">Checking analysis status…</div> : null}
      {analysisStatusQuery.error instanceof Error ? <div className="rounded-2xl border border-danger/30 bg-danger/10 p-4 text-sm text-danger">Semi-automatic analysis status failed: {analysisStatusQuery.error.message}</div> : null}
      {startMutation.error instanceof Error ? <div className="rounded-2xl border border-danger/30 bg-danger/10 p-4 text-sm text-danger">Could not start analysis: {startMutation.error.message}</div> : null}
      {stopMutation.error instanceof Error ? <div className="rounded-2xl border border-danger/30 bg-danger/10 p-4 text-sm text-danger">Could not stop analysis: {stopMutation.error.message}</div> : null}
      {analysisStatusQuery.data?.status === "failed" && analysisStatusQuery.data.error_message ? (
        <div className="rounded-2xl border border-danger/30 bg-danger/10 p-4 text-sm text-danger">Semi-automatic analysis failed: {analysisStatusQuery.data.error_message}</div>
      ) : null}
      {caseId ? (
        <DebugExportDialog
          open={debugExportOpen}
          onClose={() => setDebugExportOpen(false)}
          caseId={caseId}
          title="Export analysis debug pack"
          defaultRequest={{
            scope: "semiauto",
            include_raw_samples: false,
            include_raw_xml: false,
            include_source_paths: true,
            include_full_raw: false,
            max_events_per_type: 25,
            max_field_length: 2000,
            redact_secrets: true,
            ui_context: {
              page: "SemiAutoAnalysis",
              selected_case: caseId,
              time_from: normalizedTimeFrom,
              time_to: normalizedTimeTo,
            },
          }}
        />
      ) : null}
      {!analysis && !isActive && caseId ? (
        <div className="rounded-2xl border border-line bg-panel/70 p-4 text-sm text-muted">Run analysis to generate the semi-automatic summary for this case.</div>
      ) : null}

      {analysis ? sectionConfig.map((section) => {
        const items = analysis?.sections?.[section.key] ?? [];
        const sortState = sectionSort(section.key);
        const sortedItems = [...items].sort((left, right) => {
          const column = section.columns.find((candidate) => candidate.key === sortState.key);
          const leftValue = valueFor(left, sortState.key, column?.from ?? "root");
          const rightValue = valueFor(right, sortState.key, column?.from ?? "root");
          return compareValues(leftValue, rightValue, sortState.direction);
        });
        return (
          <section key={section.key} className="rounded-[28px] border border-line bg-panel/70 p-6 shadow-panel">
            <div className="mb-4 flex items-center justify-between gap-3">
              <div>
                <p className="font-mono text-xs uppercase tracking-[0.18em] text-accent">{section.label}</p>
                <p className="mt-1 text-sm text-muted">{items.length} items</p>
              </div>
            </div>
            {!items.length ? (
              <div className="rounded-2xl border border-line bg-abyss/50 p-4 text-sm text-muted">No activity surfaced for this section yet.</div>
            ) : (
              <div className="overflow-x-auto">
                <table className="min-w-full text-left text-sm">
                  <thead>
                    <tr className="border-b border-line/60 text-muted">
                      {section.columns.map((column) => (
                        <th key={column.key} className="px-3 py-2 font-mono text-[11px] uppercase tracking-[0.16em]">
                          <button
                            type="button"
                            onClick={() => handleSectionSort(section.key, column.key)}
                            className="inline-flex items-center gap-2 text-left hover:text-ink"
                          >
                            {column.label}
                            {sortState.key === column.key ? (sortState.direction === "asc" ? "↑" : "↓") : ""}
                          </button>
                        </th>
                      ))}
                      <th className="px-3 py-2 font-mono text-[11px] uppercase tracking-[0.16em]">Evidence</th>
                    </tr>
                  </thead>
                  <tbody>
                    {sortedItems.slice(0, section.key === "timeline" ? 100 : 50).map((activity) => (
                      <tr key={activity.id} className="border-b border-line/40 align-top">
                        {section.columns.map((column) => (
                          <td key={column.key} className="px-3 py-3 text-muted">
                            {String(valueFor(activity, column.key, column.from))}
                          </td>
                        ))}
                        <td className="px-3 py-3 text-muted">{activity.evidence_refs.join(", ") || "-"}</td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            )}
          </section>
        );
      }) : null}
    </div>
  );
}
