import { Fragment, useMemo, useState } from "react";
import EventSummary from "./EventSummary";
import TagPill from "./TagPill";
import { useTimezonePreference } from "../context/TimezoneContext";
import { copyToClipboard, formatTimestamp } from "../lib/time";
import { compareValues, getNestedValue, nextSortDirection } from "../lib/sorting";

export type SortField =
  | "timestamp"
  | "@timestamp"
  | "severity"
  | "event.severity"
  | "host"
  | "host.name"
  | "user"
  | "user.name"
  | "category"
  | "event.category"
  | "event.type"
  | "artifact"
  | "artifact.type"
  | "artifact.name"
  | "windows.event_id"
  | "file.created"
  | "file.modified"
  | "file.accessed"
  | "file.changed"
  | "file.size"
  | "mft.entry_number"
  | "process.name"
  | "network.source_ip"
  | "network.destination_ip"
  | "risk_score";
export type SortOrder = "asc" | "desc";
export type EventView = "auto" | "generic" | "evtx" | "filesystem" | "execution" | "execution_artifacts" | "browser" | "network" | "srum" | "persistence" | "registry" | "defender" | "powershell" | "recycle_bin" | "shellbags" | "jumplist" | "usb" | "bits" | "wmi" | "autoruns" | "cloud_sync";

type Props = {
  items: Record<string, unknown>[];
  view?: EventView;
  sortBy?: SortField;
  sortOrder?: SortOrder;
  onSortChange?: (field: SortField) => void;
  selectedIds?: string[];
  onToggleSelect?: (eventId: string) => void;
  onViewProcessTree?: (item: Record<string, unknown>) => void;
};

type Column = { key: string; label: string; render: (item: Record<string, unknown>) => string };

function sortFieldForColumn(key: string): SortField | null {
  if (key === "timestamp") return "@timestamp";
  if (key === "created") return "file.created";
  if (key === "modified") return "file.modified";
  if (key === "accessed") return "file.accessed";
  if (key === "changed") return "file.changed";
  if (key === "severity") return "event.severity";
  if (key === "host") return "host.name";
  if (key === "user") return "user.name";
  if (key === "category") return "event.category";
  if (key === "type") return "event.type";
  if (key === "artifact") return "artifact.type";
  if (key === "event_id") return "windows.event_id";
  if (key === "size") return "file.size";
  if (key === "mft_entry") return "mft.entry_number";
  if (key === "program" || key === "process") return "process.name";
  if (key === "registry_type") return "event.type";
  if (key === "registry_hive") return "artifact.type";
  if (key === "source") return "network.source_ip";
  if (key === "destination") return "network.destination_ip";
  return null;
}

function registryUserDisplay(item: Record<string, unknown>): string {
  const user = (item.user as Record<string, unknown>) ?? {};
  const name = String(user.name ?? "").trim();
  const sid = String(user.sid ?? "").trim();
  if (name && sid) return `${name} (${sid})`;
  return name || sid || "-";
}

function registryProcessServiceFile(item: Record<string, unknown>): string {
  const process = (item.process as Record<string, unknown>) ?? {};
  const service = (item.service as Record<string, unknown>) ?? {};
  const file = (item.file as Record<string, unknown>) ?? {};
  const destination = (item.destination as Record<string, unknown>) ?? {};
  const usb = (item.usb as Record<string, unknown>) ?? {};
  return String(
    process.path
      ?? process.command_line
      ?? service.image_path
      ?? service.name
      ?? file.path
      ?? destination.hostname
      ?? usb.serial
      ?? "-",
  );
}

function filesystemPath(item: Record<string, unknown>): string {
  const file = (item.file as Record<string, unknown>) ?? {};
  const mft = (item.mft as Record<string, unknown>) ?? {};
  return String(file.path ?? mft.full_path ?? mft.file_name ?? "-");
}

function jumplistPathType(item: Record<string, unknown>): string {
  const tags = new Set(((item.tags as string[]) ?? []).map((tag) => String(tag)));
  const file = (item.file as Record<string, unknown>) ?? {};
  if (tags.has("network_path")) return "Network";
  if (tags.has("usb_path") || tags.has("removable_media")) return "USB";
  if (tags.has("cloud_sync")) return "Cloud";
  if (file.is_directory === true || file.is_directory === "true") return "Folder";
  if (tags.has("document")) return "Document";
  if (tags.has("script")) return "Script";
  if (tags.has("executable")) return "Executable";
  return "File";
}

function executionArtifactTypeLabel(item: Record<string, unknown>): string {
  const eventType = String(((item.event as Record<string, unknown>) ?? {}).type ?? "");
  if (eventType === "execution_candidate") return "Execution candidate";
  if (eventType === "installed_program_observed") return "Installed program";
  if (eventType === "program_observed") return "Program observed";
  if (eventType === "file_observed") return "File observed";
  return eventType || "-";
}

function executionArtifactProgramFile(item: Record<string, unknown>): string {
  const amcache = (item.amcache as Record<string, unknown>) ?? {};
  const file = (item.file as Record<string, unknown>) ?? {};
  const process = (item.process as Record<string, unknown>) ?? {};
  const appcompat = (item.appcompat as Record<string, unknown>) ?? {};
  return String(amcache.file_name ?? amcache.program_name ?? file.name ?? process.name ?? appcompat.name ?? "-");
}

function executionArtifactSource(item: Record<string, unknown>): string {
  const execution = (item.execution as Record<string, unknown>) ?? {};
  const artifact = (item.artifact as Record<string, unknown>) ?? {};
  const source = String(execution.source ?? artifact.type ?? "").toLowerCase();
  if (source === "shimcache") return "Shimcache/AppCompatCache";
  if (source === "recentfilecache") return "RecentFileCache";
  if (source === "amcache") return "Amcache";
  return source || "-";
}

function executionArtifactInterpretation(item: Record<string, unknown>): string {
  const execution = (item.execution as Record<string, unknown>) ?? {};
  const appcompat = (item.appcompat as Record<string, unknown>) ?? {};
  return String(execution.interpretation ?? appcompat.interpretation ?? "-");
}

function powershellKeyEntity(item: Record<string, unknown>): string {
  const powershell = (item.powershell as Record<string, unknown>) ?? {};
  const process = (item.process as Record<string, unknown>) ?? {};
  const event = (item.event as Record<string, unknown>) ?? {};
  return String(
    item.key_entity
      ?? powershell.script_path
      ?? powershell.command
      ?? powershell.host_application
      ?? process.command_line
      ?? event.type
      ?? "-",
  );
}

function powershellSnippet(item: Record<string, unknown>): string {
  const powershell = (item.powershell as Record<string, unknown>) ?? {};
  const event = (item.event as Record<string, unknown>) ?? {};
  return String(powershell.command_preview ?? powershell.command ?? event.message ?? "-");
}

export function resolveView(view: EventView, items: Record<string, unknown>[]): EventView {
  if (view !== "auto") return view;
  const first = items[0];
  const artifactType = String(((first?.artifact as Record<string, unknown>) ?? {}).type ?? "");
  const category = String(((first?.event as Record<string, unknown>) ?? {}).category ?? "");
  if (artifactType === "mft" || artifactType === "usn" || category === "filesystem") return "filesystem";
  if (artifactType === "evtx" || category === "windows_event" || category === "logon") return "evtx";
  if (artifactType === "registry" || category === "registry") return "registry";
  if (artifactType === "amcache" || artifactType === "shimcache" || artifactType === "appcompat") return "execution_artifacts";
  if (artifactType === "srum") return "srum";
  if (artifactType === "defender" || category === "detection") return "defender";
  if (artifactType === "powershell" || category === "powershell") return "powershell";
  if (artifactType === "recycle_bin") return "recycle_bin";
  if (artifactType === "shellbags") return "shellbags";
  if (artifactType === "jumplist") return "jumplist";
  if (artifactType === "usb") return "usb";
  if (artifactType === "bits") return "bits";
  if (artifactType === "wmi") return "wmi";
  if (artifactType === "autoruns" || artifactType === "autorun") return "autoruns";
  if (artifactType === "cloud_sync") return "cloud_sync";
  if (((first?.usb as Record<string, unknown> | undefined)?.device_instance_id) || ((first?.usb as Record<string, unknown> | undefined)?.device_type)) return "usb";
  if (((first?.bits as Record<string, unknown> | undefined)?.job_id) || ((first?.bits as Record<string, unknown> | undefined)?.remote_url)) return "bits";
  if (((first?.wmi as Record<string, unknown> | undefined)?.namespace) || ((first?.wmi as Record<string, unknown> | undefined)?.consumer_name) || ((first?.wmi as Record<string, unknown> | undefined)?.filter_name)) return "wmi";
  if (((first?.autoruns as Record<string, unknown> | undefined)?.entry_location) || ((first?.persistence as Record<string, unknown> | undefined)?.mechanism)) return "autoruns";
  if (((first?.cloud as Record<string, unknown> | undefined)?.provider) || ((first?.cloud as Record<string, unknown> | undefined)?.sync_root)) return "cloud_sync";
  if (((first?.jumplist as Record<string, unknown> | undefined)?.source_file) || ((first?.jumplist as Record<string, unknown> | undefined)?.app_id)) return "jumplist";
  if (artifactType === "browser" || category === "web" || category === "file_transfer") return "browser";
  if (category === "execution") return "execution";
  if (category === "browser") return "browser";
  if (category === "network") return "network";
  if (artifactType === "scheduled_task" || category === "persistence" || category === "service" || category === "scheduled_task") return "persistence";
  return "generic";
}

function getColumns(view: EventView): Column[] {
  const timestamp = { key: "timestamp", label: "Timestamp", render: (item: Record<string, unknown>) => String(item["@timestamp"] ?? "No timestamp") };
  const severity = { key: "severity", label: "Severity", render: (item: Record<string, unknown>) => String(((item.event as Record<string, unknown>) ?? {}).severity ?? "info") };
  const host = { key: "host", label: "Host", render: (item: Record<string, unknown>) => String(((item.host as Record<string, unknown>) ?? {}).name ?? "-") };
  const user = { key: "user", label: "User", render: (item: Record<string, unknown>) => String(((item.user as Record<string, unknown>) ?? {}).name ?? "-") };
  const tags = { key: "tags", label: "Tags", render: (item: Record<string, unknown>) => String(((item.tags as string[]) ?? []).join(", ")) };
  const summary = { key: "summary", label: "Summary", render: (item: Record<string, unknown>) => String(((item.event as Record<string, unknown>) ?? {}).message ?? "") };

  switch (view) {
    case "evtx":
      return [
        timestamp,
        severity,
        host,
        user,
        { key: "event_id", label: "Event ID", render: (item) => String(((item.windows as Record<string, unknown>) ?? {}).event_id ?? "-") },
        { key: "channel", label: "Channel", render: (item) => String(((item.windows as Record<string, unknown>) ?? {}).channel ?? "-") },
        { key: "provider", label: "Provider", render: (item) => String(((item.windows as Record<string, unknown>) ?? {}).provider ?? "-") },
        { key: "type", label: "Type", render: (item) => String(((item.event as Record<string, unknown>) ?? {}).type ?? "-") },
        summary,
        tags,
      ];
    case "filesystem":
      return [
        timestamp,
        severity,
        host,
        { key: "file_name", label: "File Name", render: (item) => String(((item.file as Record<string, unknown>) ?? {}).name ?? ((item.mft as Record<string, unknown>) ?? {}).file_name ?? "-") },
        { key: "extension", label: "Extension", render: (item) => String(((item.file as Record<string, unknown>) ?? {}).extension ?? ((item.mft as Record<string, unknown>) ?? {}).extension ?? "-") },
        { key: "path", label: "Path", render: (item) => filesystemPath(item) },
        { key: "summary_score", label: "Summary Score", render: (item) => String(((item.mft as Record<string, unknown>) ?? {}).summary_score ?? "-") },
        {
          key: "summary_reasons",
          label: "Summary Reasons",
          render: (item) => {
            const reasons = ((item.mft as Record<string, unknown>) ?? {}).summary_reasons;
            return Array.isArray(reasons) ? reasons.join(", ") : String(reasons ?? "-");
          },
        },
        { key: "type", label: "Activity / Event Type", render: (item) => String((((item.event as Record<string, unknown>) ?? {}).type) ?? (((item.filesystem as Record<string, unknown>) ?? {}).activity) ?? "-") },
        { key: "size", label: "Size", render: (item) => String(((item.file as Record<string, unknown>) ?? {}).size ?? "-") },
        {
          key: "deleted",
          label: "In Use / Deleted",
          render: (item) => {
            const file = (item.file as Record<string, unknown>) ?? {};
            const inUse = file.in_use;
            const deleted = file.deleted;
            if (deleted === true || deleted === "true") return "Deleted";
            if (inUse === false || inUse === "false") return "Not in use";
            if (inUse === true || inUse === "true") return "In use";
            return "-";
          },
        },
        { key: "artifact", label: "Source Artifact", render: (item) => String(((item.artifact as Record<string, unknown>) ?? {}).name ?? ((item.artifact as Record<string, unknown>) ?? {}).type ?? "-") },
        tags,
      ];
    case "execution":
      return [
        timestamp,
        severity,
        host,
        user,
        { key: "program", label: "Program/Process", render: (item) => String(((item.execution as Record<string, unknown>) ?? {}).program_name ?? ((item.process as Record<string, unknown>) ?? {}).name ?? "-") },
        { key: "run_count", label: "Run count", render: (item) => String(((item.execution as Record<string, unknown>) ?? {}).run_count ?? ((item.prefetch as Record<string, unknown>) ?? {}).run_count ?? "-") },
        { key: "last_run", label: "Last run", render: (item) => String(((item.execution as Record<string, unknown>) ?? {}).last_run ?? ((item.prefetch as Record<string, unknown>) ?? {}).last_run ?? "-") },
        { key: "path", label: "Path", render: (item) => String(((item.file as Record<string, unknown>) ?? {}).path ?? ((item.process as Record<string, unknown>) ?? {}).path ?? "-") },
        { key: "source_pf", label: "Source PF", render: (item) => String(((item.prefetch as Record<string, unknown>) ?? {}).source_file ?? "-") },
        { key: "artifact", label: "Source artifact", render: (item) => String(((item.artifact as Record<string, unknown>) ?? {}).name ?? "-") },
        tags,
      ];
    case "execution_artifacts":
      return [
        timestamp,
        severity,
        host,
        user,
        { key: "program_file", label: "Program / File", render: (item) => executionArtifactProgramFile(item) },
        { key: "path", label: "Path", render: (item) => String(((item.file as Record<string, unknown>) ?? {}).path ?? ((item.process as Record<string, unknown>) ?? {}).path ?? ((item.shimcache as Record<string, unknown>) ?? {}).path ?? ((item.appcompat as Record<string, unknown>) ?? {}).path ?? "-") },
        { key: "source", label: "Source", render: (item) => executionArtifactSource(item) },
        { key: "confidence", label: "Confidence", render: (item) => String(((item.execution as Record<string, unknown>) ?? {}).confidence ?? "-") },
        { key: "interpretation", label: "Interpretation", render: (item) => executionArtifactInterpretation(item) },
        { key: "type", label: "Type", render: (item) => executionArtifactTypeLabel(item) },
        tags,
      ];
    case "browser":
      return [
        timestamp,
        severity,
        host,
        user,
        { key: "browser", label: "Browser", render: (item) => String(((item.browser as Record<string, unknown>) ?? {}).name ?? ((item.browser as Record<string, unknown>) ?? {}).browser ?? "-") },
        { key: "profile", label: "Profile", render: (item) => String(((item.browser as Record<string, unknown>) ?? {}).profile ?? "-") },
        { key: "type", label: "Type", render: (item) => String(((item.browser as Record<string, unknown>) ?? {}).artifact_type ?? ((item.event as Record<string, unknown>) ?? {}).type ?? "-") },
        { key: "domain", label: "Domain", render: (item) => String(((item.url as Record<string, unknown>) ?? {}).domain ?? ((item.browser as Record<string, unknown>) ?? {}).domain ?? "-") },
        { key: "url_or_file", label: "URL / File", render: (item) => String(((item.url as Record<string, unknown>) ?? {}).full ?? ((item.browser as Record<string, unknown>) ?? {}).url ?? ((item.file as Record<string, unknown>) ?? {}).path ?? "-") },
        { key: "title", label: "Title / Filename", render: (item) => String(((item.browser as Record<string, unknown>) ?? {}).title ?? ((item.file as Record<string, unknown>) ?? {}).name ?? ((item.download as Record<string, unknown>) ?? {}).file_name ?? ((item.browser as Record<string, unknown>) ?? {}).search_terms ?? "-") },
        { key: "path", label: "Path", render: (item) => String(((item.file as Record<string, unknown>) ?? {}).path ?? ((item.download as Record<string, unknown>) ?? {}).target_path ?? "-") },
        tags,
      ];
    case "powershell":
      return [
        timestamp,
        severity,
        host,
        user,
        { key: "source", label: "Source", render: (item) => String(((item.powershell as Record<string, unknown>) ?? {}).artifact_type ?? ((item.artifact as Record<string, unknown>) ?? {}).parser ?? "-") },
        { key: "type", label: "Type", render: (item) => String(((item.event as Record<string, unknown>) ?? {}).type ?? "-") },
        { key: "key_entity", label: "Key Entity", render: (item) => powershellKeyEntity(item) },
        { key: "command_preview", label: "Snippet", render: (item) => powershellSnippet(item) },
        { key: "urls_domains", label: "URLs / Domains", render: (item) => String((((item.powershell as Record<string, unknown>) ?? {}).urls as string[] | undefined)?.[0] ?? (((item.powershell as Record<string, unknown>) ?? {}).domains as string[] | undefined)?.[0] ?? "-") },
        { key: "indicators", label: "Indicators", render: (item) => String((((item.powershell as Record<string, unknown>) ?? {}).indicators as string[] | undefined)?.join(", ") ?? "-") },
        tags,
      ];
    case "recycle_bin":
      return [
        timestamp,
        severity,
        host,
        {
          key: "user_sid",
          label: "User / SID",
          render: (item) => {
            const eventUser = (item.user as Record<string, unknown>) ?? {};
            const recycle = (item.recycle as Record<string, unknown>) ?? {};
            return String(eventUser.name ?? eventUser.sid ?? recycle.sid ?? "-");
          },
        },
        { key: "original_file", label: "Original File", render: (item) => String(((item.recycle as Record<string, unknown>) ?? {}).original_file_name ?? ((item.file as Record<string, unknown>) ?? {}).name ?? "-") },
        { key: "original_path", label: "Original Path", render: (item) => String(((item.recycle as Record<string, unknown>) ?? {}).original_path ?? ((item.file as Record<string, unknown>) ?? {}).path ?? "-") },
        { key: "size", label: "Size", render: (item) => String(((item.recycle as Record<string, unknown>) ?? {}).original_size ?? ((item.file as Record<string, unknown>) ?? {}).size ?? "-") },
        { key: "has_content", label: "Has Content", render: (item) => String(((item.recycle as Record<string, unknown>) ?? {}).has_r_file ?? "-") },
        { key: "source", label: "Source", render: (item) => String(((item.artifact as Record<string, unknown>) ?? {}).parser ?? "-") },
        tags,
      ];
    case "shellbags":
      return [
        timestamp,
        severity,
        host,
        user,
        { key: "path", label: "Path", render: (item) => String(((item.shellbag as Record<string, unknown>) ?? {}).path ?? ((item.file as Record<string, unknown>) ?? {}).path ?? "-") },
        { key: "type", label: "Type", render: (item) => String(((item.shellbag as Record<string, unknown>) ?? {}).artifact_type ?? "-") },
        { key: "source_hive", label: "Source Hive / File", render: (item) => String(((item.shellbag as Record<string, unknown>) ?? {}).source_file ?? ((item.shellbag as Record<string, unknown>) ?? {}).hive_path ?? "-") },
        { key: "mru", label: "MRU", render: (item) => String(((item.shellbag as Record<string, unknown>) ?? {}).mru_position ?? ((item.shellbag as Record<string, unknown>) ?? {}).mru ?? "-") },
        tags,
      ];
    case "jumplist":
      return [
        timestamp,
        { key: "timestamp_precision", label: "Timestamp Precision", render: (item) => String(item.timestamp_precision ?? "-") },
        severity,
        user,
        { key: "application", label: "Application / AppID", render: (item) => String(((item.jumplist as Record<string, unknown>) ?? {}).app_name ?? ((item.jumplist as Record<string, unknown>) ?? {}).app_id ?? "-") },
        { key: "destination_type", label: "Destination Type", render: (item) => String(((item.jumplist as Record<string, unknown>) ?? {}).destination_type ?? "-") },
        { key: "entry", label: "Entry", render: (item) => String(((item.jumplist as Record<string, unknown>) ?? {}).entry_number ?? ((item.jumplist as Record<string, unknown>) ?? {}).stream_name ?? "-") },
        { key: "path", label: "Path", render: (item) => String(((item.jumplist as Record<string, unknown>) ?? {}).effective_path ?? ((item.file as Record<string, unknown>) ?? {}).path ?? "-") },
        { key: "path_type", label: "Path Type", render: (item) => jumplistPathType(item) },
        { key: "source_jumplist", label: "Source JumpList", render: (item) => String(((item.jumplist as Record<string, unknown>) ?? {}).source_file ?? "-") },
        tags,
      ];
    case "usb":
      return [
        timestamp,
        { key: "timestamp_precision", label: "Timestamp Precision", render: (item) => String(item.timestamp_precision ?? "-") },
        severity,
        { key: "device_type", label: "Device Type", render: (item) => String(((item.usb as Record<string, unknown>) ?? {}).device_type ?? "-") },
        { key: "vendor_product", label: "Vendor / Product", render: (item) => {
          const usb = (item.usb as Record<string, unknown>) ?? {};
          const vendor = String(usb.vendor ?? "").trim();
          const product = String(usb.product ?? "").trim();
          if (vendor && product) return `${vendor} / ${product}`;
          return vendor || product || "-";
        } },
        { key: "serial", label: "Serial", render: (item) => String(((item.usb as Record<string, unknown>) ?? {}).serial ?? "-") },
        { key: "vid_pid", label: "VID / PID", render: (item) => {
          const usb = (item.usb as Record<string, unknown>) ?? {};
          const vid = String(usb.vid ?? "").trim();
          const pid = String(usb.pid ?? "").trim();
          if (vid && pid) return `${vid} / ${pid}`;
          return vid || pid || "-";
        } },
        { key: "device_instance_id", label: "Device Instance ID", render: (item) => String(((item.usb as Record<string, unknown>) ?? {}).device_instance_id ?? "-") },
        { key: "action", label: "Action", render: (item) => String(((item.event as Record<string, unknown>) ?? {}).type ?? "-") },
        { key: "source_usb", label: "Source", render: (item) => String(((item.usb as Record<string, unknown>) ?? {}).source_file ?? item.source_file ?? "-") },
        tags,
      ];
    case "bits":
      return [
        timestamp,
        severity,
        user,
        { key: "job", label: "Job", render: (item) => String(((item.bits as Record<string, unknown>) ?? {}).display_name ?? ((item.bits as Record<string, unknown>) ?? {}).job_id ?? ((item.bits as Record<string, unknown>) ?? {}).job_guid ?? "-") },
        { key: "state", label: "State", render: (item) => String(((item.bits as Record<string, unknown>) ?? {}).state ?? "-") },
        { key: "type", label: "Type", render: (item) => String(((item.bits as Record<string, unknown>) ?? {}).type ?? ((item.event as Record<string, unknown>) ?? {}).type ?? "-") },
        { key: "remote_url", label: "Remote URL", render: (item) => String(((item.bits as Record<string, unknown>) ?? {}).remote_url ?? ((item.url as Record<string, unknown>) ?? {}).full ?? "-") },
        { key: "local_path", label: "Local Path", render: (item) => String(((item.bits as Record<string, unknown>) ?? {}).local_path ?? ((item.file as Record<string, unknown>) ?? {}).path ?? "-") },
        { key: "bytes", label: "Bytes", render: (item) => {
          const bits = (item.bits as Record<string, unknown>) ?? {};
          const transferred = String(bits.bytes_transferred ?? "").trim();
          const total = String(bits.bytes_total ?? "").trim();
          return transferred || total ? `${transferred || "0"} / ${total || "?"}` : "-";
        } },
        { key: "source_bits", label: "Source", render: (item) => String(((item.bits as Record<string, unknown>) ?? {}).source_file ?? item.source_file ?? "-") },
        tags,
      ];
    case "wmi":
      return [
        timestamp,
        severity,
        host,
        { key: "user_sid", label: "User / SID", render: (item) => {
          const eventUser = (item.user as Record<string, unknown>) ?? {};
          const wmi = (item.wmi as Record<string, unknown>) ?? {};
          return String(eventUser.name ?? eventUser.sid ?? wmi.creator_sid ?? "-");
        } },
        { key: "namespace", label: "Namespace", render: (item) => String(((item.wmi as Record<string, unknown>) ?? {}).namespace ?? "-") },
        { key: "type", label: "Type", render: (item) => String(((item.wmi as Record<string, unknown>) ?? {}).artifact_type ?? ((item.event as Record<string, unknown>) ?? {}).type ?? "-") },
        { key: "name", label: "Name", render: (item) => {
          const wmi = (item.wmi as Record<string, unknown>) ?? {};
          return String(wmi.name ?? wmi.filter_name ?? wmi.consumer_name ?? "-");
        } },
        { key: "query_command", label: "Query / Command", render: (item) => {
          const wmi = (item.wmi as Record<string, unknown>) ?? {};
          return String(wmi.query ?? wmi.command_line_template ?? wmi.script_preview ?? "-");
        } },
        { key: "binding", label: "Binding", render: (item) => {
          const wmi = (item.wmi as Record<string, unknown>) ?? {};
          const filter = String(wmi.binding_filter ?? wmi.filter_name ?? "").trim();
          const consumer = String(wmi.binding_consumer ?? wmi.consumer_name ?? "").trim();
          return filter || consumer ? `${filter || "?"} -> ${consumer || "?"}` : "-";
        } },
        { key: "source_wmi", label: "Source", render: (item) => String(((item.wmi as Record<string, unknown>) ?? {}).source_file ?? item.source_file ?? "-") },
        tags,
      ];
    case "autoruns":
      return [
        timestamp,
        severity,
        host,
        {
          key: "user_profile",
          label: "User / Profile",
          render: (item) => {
            const autoruns = (item.autoruns as Record<string, unknown>) ?? {};
            const eventUser = (item.user as Record<string, unknown>) ?? {};
            return String(autoruns.user ?? autoruns.profile ?? eventUser.name ?? eventUser.sid ?? "-");
          },
        },
        { key: "mechanism", label: "Mechanism", render: (item) => String(((item.persistence as Record<string, unknown>) ?? {}).mechanism ?? ((item.autoruns as Record<string, unknown>) ?? {}).artifact_type ?? "-") },
        { key: "entry", label: "Entry", render: (item) => String(((item.autoruns as Record<string, unknown>) ?? {}).entry ?? ((item.persistence as Record<string, unknown>) ?? {}).name ?? "-") },
        { key: "enabled", label: "Enabled", render: (item) => String(((item.autoruns as Record<string, unknown>) ?? {}).enabled ?? ((item.persistence as Record<string, unknown>) ?? {}).enabled ?? "-") },
        { key: "image_path", label: "Image Path", render: (item) => String(((item.autoruns as Record<string, unknown>) ?? {}).image_path ?? ((item.file as Record<string, unknown>) ?? {}).path ?? "-") },
        {
          key: "publisher_signer",
          label: "Publisher / Signer",
          render: (item) => {
            const autoruns = (item.autoruns as Record<string, unknown>) ?? {};
            return String(autoruns.publisher ?? "-") + (autoruns.signer ? ` / ${String(autoruns.signer)}` : "");
          },
        },
        { key: "source_autoruns", label: "Source", render: (item) => String(((item.autoruns as Record<string, unknown>) ?? {}).source_file ?? item.source_file ?? "-") },
        tags,
      ];
    case "cloud_sync":
      return [
        timestamp,
        severity,
        host,
        user,
        { key: "provider", label: "Provider", render: (item) => String(((item.cloud as Record<string, unknown>) ?? {}).provider ?? "-") },
        { key: "activity", label: "Activity", render: (item) => String(((item.event as Record<string, unknown>) ?? {}).type ?? "-") },
        {
          key: "path",
          label: "Path / Source",
          render: (item) => {
            const cloud = (item.cloud as Record<string, unknown>) ?? {};
            const velociraptor = (item.velociraptor as Record<string, unknown>) ?? {};
            const event = (item.event as Record<string, unknown>) ?? {};
            const source = String(cloud.source_file ?? item.source_file ?? "-");
            if (event.type === "cloud_client_config" || event.type === "cloud_client_log") {
              return String(velociraptor.normalized_windows_path ?? source);
            }
            return String(cloud.local_path ?? ((item.file as Record<string, unknown>) ?? {}).path ?? cloud.sync_root ?? source);
          },
        },
        { key: "account", label: "Account", render: (item) => String(((item.cloud as Record<string, unknown>) ?? {}).account_email ?? ((item.cloud as Record<string, unknown>) ?? {}).account ?? "-") },
        { key: "status", label: "Status", render: (item) => {
          const cloud = (item.cloud as Record<string, unknown>) ?? {};
          return String(cloud.sync_status ?? cloud.status ?? cloud.direction ?? "-");
        } },
        { key: "parser_status", label: "Parser Status", render: (item) => String(((item.cloud as Record<string, unknown>) ?? {}).parser_status ?? "-") },
        { key: "source_cloud", label: "Source", render: (item) => String(((item.cloud as Record<string, unknown>) ?? {}).source_file ?? item.source_file ?? "-") },
        tags,
      ];
    case "network":
      return [
        timestamp,
        severity,
        host,
        user,
        { key: "type", label: "Type", render: (item) => String(((item.event as Record<string, unknown>) ?? {}).type ?? ((item.network as Record<string, unknown>) ?? {}).artifact_type ?? "-") },
        {
          key: "interface_ssid",
          label: "Interface / SSID",
          render: (item) => {
            const network = (item.network as Record<string, unknown>) ?? {};
            const wlan = (item.wlan as Record<string, unknown>) ?? {};
            return String(wlan.ssid ?? wlan.profile_name ?? network.interface_name ?? network.interface_description ?? "-");
          },
        },
        {
          key: "domain_ip",
          label: "Domain / IP",
          render: (item) => {
            const network = (item.network as Record<string, unknown>) ?? {};
            const dns = (item.dns as Record<string, unknown>) ?? {};
            return String(dns.name ?? dns.domain ?? dns.ip ?? network.domain ?? network.destination_ip ?? network.source_ip ?? "-");
          },
        },
        {
          key: "path_source",
          label: "Path / Source",
          render: (item) => String(((item.velociraptor as Record<string, unknown>) ?? {}).normalized_windows_path ?? item.source_file ?? ((item.file as Record<string, unknown>) ?? {}).path ?? "-"),
        },
        {
          key: "status",
          label: "Status",
          render: (item) => {
            const network = (item.network as Record<string, unknown>) ?? {};
            const dns = (item.dns as Record<string, unknown>) ?? {};
            return String(network.state ?? dns.status ?? "-");
          },
        },
        tags,
      ];
    case "srum":
      return [
        timestamp,
        severity,
        host,
        {
          key: "user_sid",
          label: "User / SID",
          render: (item) => {
            const user = (item.user as Record<string, unknown>) ?? {};
            return String(user.name ?? user.sid ?? ((item.srum as Record<string, unknown>) ?? {}).user_sid ?? "-");
          },
        },
        {
          key: "application",
          label: "Application",
          render: (item) => String(((item.srum as Record<string, unknown>) ?? {}).app_name ?? ((item.network as Record<string, unknown>) ?? {}).application ?? ((item.process as Record<string, unknown>) ?? {}).name ?? "-"),
        },
        { key: "path", label: "Process Path", render: (item) => String(((item.process as Record<string, unknown>) ?? {}).path ?? "-") },
        { key: "bytes_sent", label: "Bytes Sent", render: (item) => String(((item.network as Record<string, unknown>) ?? {}).bytes_sent ?? ((item.srum as Record<string, unknown>) ?? {}).bytes_sent ?? "-") },
        { key: "bytes_received", label: "Bytes Received", render: (item) => String(((item.network as Record<string, unknown>) ?? {}).bytes_received ?? ((item.srum as Record<string, unknown>) ?? {}).bytes_received ?? "-") },
        { key: "bytes_total", label: "Total Bytes", render: (item) => String(((item.network as Record<string, unknown>) ?? {}).bytes_total ?? ((item.srum as Record<string, unknown>) ?? {}).bytes_total ?? "-") },
        {
          key: "interface_profile",
          label: "Interface / Profile",
          render: (item) => String(((item.srum as Record<string, unknown>) ?? {}).interface_profile ?? ((item.srum as Record<string, unknown>) ?? {}).network_profile ?? ((item.network as Record<string, unknown>) ?? {}).profile ?? "-"),
        },
        { key: "srum_type", label: "SRUM Type", render: (item) => String(((item.srum as Record<string, unknown>) ?? {}).artifact_type ?? ((item.event as Record<string, unknown>) ?? {}).type ?? "-") },
        tags,
      ];
    case "persistence":
      return [
        timestamp,
        severity,
        host,
        user,
        { key: "type", label: "Type", render: (item) => String(((item.event as Record<string, unknown>) ?? {}).type ?? ((item.task as Record<string, unknown>) ?? {}).artifact_type ?? "-") },
        { key: "task_name", label: "Task / Service", render: (item) => String(((item.task as Record<string, unknown>) ?? {}).name ?? ((item.service as Record<string, unknown>) ?? {}).name ?? ((item.windows as Record<string, unknown>) ?? {}).task_name ?? ((item.windows as Record<string, unknown>) ?? {}).service_name ?? "-") },
        { key: "task_path", label: "Task Path", render: (item) => String(((item.task as Record<string, unknown>) ?? {}).path ?? "-") },
        { key: "enabled", label: "Enabled", render: (item) => String(((item.task as Record<string, unknown>) ?? {}).enabled ?? "-") },
        { key: "hidden", label: "Hidden", render: (item) => String(((item.task as Record<string, unknown>) ?? {}).hidden ?? "-") },
        { key: "run_as", label: "Run As", render: (item) => String(((item.task as Record<string, unknown>) ?? {}).run_as ?? ((item.task as Record<string, unknown>) ?? {}).user_id ?? "-") },
        { key: "path_cmd", label: "Command", render: (item) => String(((item.task as Record<string, unknown>) ?? {}).command ?? ((item.process as Record<string, unknown>) ?? {}).command_line ?? ((item.file as Record<string, unknown>) ?? {}).path ?? "-") },
        { key: "arguments", label: "Arguments", render: (item) => String(((item.task as Record<string, unknown>) ?? {}).arguments ?? "-") },
        { key: "trigger_summary", label: "Trigger Summary", render: (item) => String(((item.task as Record<string, unknown>) ?? {}).trigger_summary ?? "-") },
        tags,
      ];
    case "defender":
      return [
        timestamp,
        severity,
        host,
        {
          key: "user_sid",
          label: "User / SID",
          render: (item) => {
            const itemUser = (item.user as Record<string, unknown>) ?? {};
            const detection = (item.detection as Record<string, unknown>) ?? {};
            return String(itemUser.name ?? itemUser.sid ?? detection.user ?? detection.user_sid ?? "-");
          },
        },
        { key: "threat", label: "Threat", render: (item) => String(((item.detection as Record<string, unknown>) ?? {}).threat_name ?? "-") },
        { key: "category", label: "Category", render: (item) => String(((item.detection as Record<string, unknown>) ?? {}).category ?? "-") },
        { key: "action", label: "Action", render: (item) => String(((item.detection as Record<string, unknown>) ?? {}).action ?? ((item.event as Record<string, unknown>) ?? {}).action ?? "-") },
        { key: "status", label: "Status", render: (item) => String(((item.detection as Record<string, unknown>) ?? {}).status ?? "-") },
        {
          key: "file_resource",
          label: "File / Resource",
          render: (item) => String(((item.file as Record<string, unknown>) ?? {}).path ?? ((item.detection as Record<string, unknown>) ?? {}).path ?? ((item.detection as Record<string, unknown>) ?? {}).resource ?? "-"),
        },
        {
          key: "source",
          label: "Source",
          render: (item) => String(((item.artifact as Record<string, unknown>) ?? {}).parser ?? (item.source_tool as string | undefined) ?? "-"),
        },
        tags,
      ];
    case "registry":
      return [
        timestamp,
        severity,
        host,
        { key: "registry_user", label: "User / SID", render: (item) => registryUserDisplay(item) },
        { key: "registry_type", label: "Registry Type", render: (item) => String((((item.registry as Record<string, unknown>) ?? {}).artifact_type) ?? (((item.event as Record<string, unknown>) ?? {}).type) ?? "-") },
        { key: "registry_hive", label: "Hive", render: (item) => String((((item.registry as Record<string, unknown>) ?? {}).hive) ?? (((item.registry as Record<string, unknown>) ?? {}).hive_path) ?? "-") },
        { key: "registry_key_path", label: "Key Path", render: (item) => String((((item.registry as Record<string, unknown>) ?? {}).key_path) ?? "-") },
        { key: "registry_value_name", label: "Value Name", render: (item) => String((((item.registry as Record<string, unknown>) ?? {}).value_name) ?? "-") },
        { key: "registry_value_data", label: "Value Data", render: (item) => String((((item.registry as Record<string, unknown>) ?? {}).value_data) ?? "-") },
        { key: "registry_target", label: "Process / Service / File", render: (item) => registryProcessServiceFile(item) },
        summary,
        tags,
      ];
    default:
      return [
        timestamp,
        severity,
        host,
        user,
        { key: "category", label: "Category", render: (item) => String(((item.event as Record<string, unknown>) ?? {}).category ?? "-") },
        { key: "type", label: "Type", render: (item) => String(((item.event as Record<string, unknown>) ?? {}).type ?? "-") },
        { key: "artifact", label: "Artifact", render: (item) => String(((item.artifact as Record<string, unknown>) ?? {}).type ?? ((item.artifact as Record<string, unknown>) ?? {}).name ?? "-") },
        summary,
        tags,
      ];
  }
}

function hasProcessTreeContext(item: Record<string, unknown>): boolean {
  const process = (item.process as Record<string, unknown>) ?? {};
  const relatedProcessNodeIds = Array.isArray(item.related_process_node_ids) ? item.related_process_node_ids : [];
  return Boolean(relatedProcessNodeIds.length || process.pid || process.name || process.entity_id || process.command_line);
}

export default function EventTable({ items, view = "generic", sortBy, sortOrder, onSortChange, selectedIds = [], onToggleSelect, onViewProcessTree }: Props) {
  const { effectiveTimezone } = useTimezonePreference();
  const [openId, setOpenId] = useState<string | null>(null);
  const [showColumnChooser, setShowColumnChooser] = useState(false);
  const [hiddenColumns, setHiddenColumns] = useState<string[]>([]);
  const [internalSortBy, setInternalSortBy] = useState<SortField | null>(sortBy ?? null);
  const [internalSortOrder, setInternalSortOrder] = useState<SortOrder>(sortOrder ?? "asc");
  const resolved = useMemo(() => resolveView(view, items), [items, view]);
  const allColumns = useMemo(() => getColumns(resolved), [resolved]);
  const mostlyEmptyColumns = useMemo(() => {
    const output = new Set<string>();
    for (const column of allColumns) {
      if (!items.length) continue;
      const emptyCount = items.filter((item) => {
        const value = column.render(item).trim();
        return value === "" || value === "-" || value === "null" || value === "undefined";
      }).length;
      if (emptyCount / items.length >= 0.95) output.add(column.key);
    }
    return output;
  }, [allColumns, items]);
  const columns = useMemo(() => allColumns.filter((column) => !hiddenColumns.includes(column.key)), [allColumns, hiddenColumns]);

  const effectiveSortBy = sortBy ?? internalSortBy;
  const effectiveSortOrder = sortOrder ?? internalSortOrder;

  const rows = useMemo(() => {
    if (!effectiveSortBy) return items;
    return [...items].sort((left, right) => compareValues(getNestedValue(left, effectiveSortBy), getNestedValue(right, effectiveSortBy), effectiveSortOrder));
  }, [effectiveSortBy, effectiveSortOrder, items]);

  function handleHeaderSort(field: SortField) {
    if (onSortChange) {
      onSortChange(field);
      return;
    }
    setInternalSortOrder((currentDirection) => nextSortDirection(internalSortBy, currentDirection, field));
    setInternalSortBy(field);
  }

  return (
    <div className="overflow-hidden rounded-3xl border border-line bg-panel/70 shadow-panel">
      <div className="flex items-center justify-between border-b border-line px-4 py-3">
        <p className="font-mono text-[11px] uppercase tracking-[0.18em] text-muted">{resolved} view</p>
        <div className="relative">
          <button type="button" onClick={() => setShowColumnChooser((current) => !current)} className="rounded-xl border border-line px-3 py-2 text-xs text-muted">
            Columns
          </button>
          {showColumnChooser ? (
            <div className="absolute right-0 z-10 mt-2 min-w-[220px] rounded-2xl border border-line bg-panel p-3 shadow-panel">
              <div className="space-y-2">
                {allColumns.map((column) => (
                  <label key={column.key} className="flex items-center justify-between gap-3 text-xs text-muted">
                    <span>{column.label}</span>
                    <span className="flex items-center gap-2">
                      {mostlyEmptyColumns.has(column.key) ? <span className="rounded-full border border-line px-2 py-0.5 text-[10px] uppercase tracking-[0.12em]">Mostly empty</span> : null}
                      <input
                        type="checkbox"
                        checked={!hiddenColumns.includes(column.key)}
                        onChange={() =>
                          setHiddenColumns((current) =>
                            current.includes(column.key) ? current.filter((item) => item !== column.key) : [...current, column.key],
                          )
                        }
                      />
                    </span>
                  </label>
                ))}
              </div>
            </div>
          ) : null}
        </div>
      </div>
      <div className="overflow-x-auto">
        <table className="min-w-full text-sm">
          <thead className="border-b border-line">
            <tr className="font-mono text-[11px] uppercase tracking-[0.18em] text-muted">
              {onToggleSelect ? <th className="px-4 py-3 text-left">Select</th> : null}
              {columns.map((column) => (
                <th key={column.key} className="px-4 py-3 text-left">
                  {sortFieldForColumn(column.key) && onSortChange ? (
                    <button type="button" onClick={() => handleHeaderSort(sortFieldForColumn(column.key) as SortField)} className="inline-flex items-center gap-2">
                      <span>{column.label}</span>
                      {effectiveSortBy === sortFieldForColumn(column.key) ? <span>{effectiveSortOrder === "asc" ? "↑" : "↓"}</span> : null}
                    </button>
                  ) : (
                    sortFieldForColumn(column.key) ? (
                      <button type="button" onClick={() => handleHeaderSort(sortFieldForColumn(column.key) as SortField)} className="inline-flex items-center gap-2">
                        <span>{column.label}</span>
                        {effectiveSortBy === sortFieldForColumn(column.key) ? <span>{effectiveSortOrder === "asc" ? "↑" : "↓"}</span> : null}
                      </button>
                    ) : (
                      column.label
                    )
                  )}
                </th>
              ))}
            </tr>
          </thead>
          <tbody className="divide-y divide-line/60">
            {rows.map((item) => {
              const id = String(item.id ?? item.event_id);
              const file = (item.file as Record<string, unknown>) ?? {};
              const process = (item.process as Record<string, unknown>) ?? {};
              const powershell = (item.powershell as Record<string, unknown>) ?? {};
              const keyEntity = String(item.key_entity ?? powershellKeyEntity(item) ?? "");
              const fullCommand = String(powershell.command ?? process.command_line ?? "");
              return (
                <Fragment key={id}>
                  <tr key={id} className="hover:bg-white/5">
                    {onToggleSelect ? (
                      <td className="px-4 py-3">
                        <input type="checkbox" checked={selectedIds.includes(id)} onChange={() => onToggleSelect(id)} />
                      </td>
                    ) : null}
                    {columns.map((column) => (
                      <td key={`${id}-${column.key}`} className="max-w-[320px] px-4 py-3 align-top">
                        <button type="button" onClick={() => setOpenId(openId === id ? null : id)} className="w-full text-left">
                          <span className={`block whitespace-pre-wrap break-words text-ink ${column.key === "key_entity" || column.key === "command_preview" ? "max-h-12 overflow-hidden font-mono text-xs leading-4" : ""}`} title={column.key === "timestamp" ? String(item["@timestamp"] ?? "") : column.render(item)}>
                            {column.key === "timestamp" ? formatTimestamp(item["@timestamp"], effectiveTimezone) : column.render(item)}
                          </span>
                        </button>
                      </td>
                    ))}
                  </tr>
                  {openId === id ? (
                    <tr>
                      <td colSpan={(onToggleSelect ? 1 : 0) + columns.length} className="px-4 py-4">
                        <div className="space-y-3 rounded-2xl border border-line bg-abyss/70 p-4">
                          <div className="flex flex-wrap gap-2">
                            {file.path ? <button type="button" onClick={() => void copyToClipboard(String(file.path))} className="rounded-xl border border-line px-3 py-2 text-xs text-muted">Copy path</button> : null}
                            {process.command_line ? <button type="button" onClick={() => void copyToClipboard(String(process.command_line))} className="rounded-xl border border-line px-3 py-2 text-xs text-muted">Copy command line</button> : null}
                            {fullCommand && fullCommand !== process.command_line ? <button type="button" onClick={() => void copyToClipboard(fullCommand)} className="rounded-xl border border-line px-3 py-2 text-xs text-muted">Copy PowerShell command</button> : null}
                            {keyEntity && keyEntity !== "-" ? <button type="button" onClick={() => void copyToClipboard(keyEntity)} className="rounded-xl border border-line px-3 py-2 text-xs text-muted">Copy key entity</button> : null}
                            {file.sha256 ? <button type="button" onClick={() => void copyToClipboard(String(file.sha256))} className="rounded-xl border border-line px-3 py-2 text-xs text-muted">Copy hash</button> : null}
                            {item.event_id ? <button type="button" onClick={() => void copyToClipboard(String(item.event_id))} className="rounded-xl border border-line px-3 py-2 text-xs text-muted">Copy event id</button> : null}
                            {onViewProcessTree && hasProcessTreeContext(item) ? <button type="button" onClick={() => onViewProcessTree(item)} className="rounded-xl border border-line px-3 py-2 text-xs text-muted">View process tree</button> : null}
                            <button type="button" onClick={() => void copyToClipboard(JSON.stringify(item, null, 2))} className="rounded-xl border border-line px-3 py-2 text-xs text-muted">Copy raw JSON</button>
                          </div>
                          <EventSummary event={item} />
                          <div className="flex flex-wrap gap-2">{((item.tags as string[]) ?? []).map((tag) => <TagPill key={`${id}-${tag}`} tag={tag} />)}</div>
                          <details className="rounded-2xl border border-line bg-panel/40 p-3">
                            <summary className="cursor-pointer font-mono text-[11px] uppercase tracking-[0.16em] text-muted">Raw JSON</summary>
                            <pre className="mt-3 max-h-[28rem] overflow-auto whitespace-pre-wrap break-all text-xs leading-6 text-muted">
                              {JSON.stringify(item, null, 2)}
                            </pre>
                          </details>
                        </div>
                      </td>
                    </tr>
                  ) : null}
                </Fragment>
              );
            })}
          </tbody>
        </table>
      </div>
    </div>
  );
}
