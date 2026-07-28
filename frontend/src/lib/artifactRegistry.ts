import type { EventView } from "../components/EventTable";

export type UiArtifactDefinition = {
  id: string;
  label: string;
  aliases?: string[];
  platforms: string[];
  view: EventView | "execution" | "persistence" | "auto";
  hiddenFromMain?: boolean;
  platformShortcut?: boolean;
};

const ARTIFACT_REGISTRY: UiArtifactDefinition[] = [
  { id: "evtx", label: "Windows Events", aliases: ["windows_event"], platforms: ["windows"], view: "evtx" },
  { id: "powershell", label: "PowerShell", platforms: ["windows"], view: "powershell" },
  { id: "prefetch", label: "Prefetch", platforms: ["windows"], view: "execution" },
  { id: "shimcache", label: "Shimcache", aliases: ["appcompat"], platforms: ["windows"], view: "execution_artifacts" },
  { id: "amcache", label: "Amcache", platforms: ["windows"], view: "execution_artifacts" },
  { id: "lnk", label: "LNK / Shortcuts", platforms: ["windows"], view: "execution" },
  { id: "jumplist", label: "Jump Lists", platforms: ["windows"], view: "jumplist" },
  { id: "browser", label: "Browser History", platforms: ["windows", "linux"], view: "browser" },
  { id: "service", label: "Services", aliases: ["services"], platforms: ["windows"], view: "persistence" },
  { id: "scheduled_task", label: "Scheduled Tasks", aliases: ["scheduled_tasks"], platforms: ["windows"], view: "persistence" },
  { id: "registry", label: "Registry", aliases: ["registry_event", "registry_command"], platforms: ["windows", "memory"], view: "registry" },
  { id: "defender", label: "Defender", platforms: ["windows"], view: "defender" },
  { id: "usb", label: "USB", platforms: ["windows"], view: "usb" },
  { id: "recycle_bin", label: "Recycle Bin", platforms: ["windows"], view: "recycle_bin" },
  { id: "shellbags", label: "Shellbags", aliases: ["shellbag"], platforms: ["windows"], view: "shellbags" },
  { id: "cloud_sync", label: "Cloud Sync", aliases: ["cloud"], platforms: ["windows"], view: "cloud_sync" },
  { id: "autoruns", label: "Autoruns", aliases: ["autorun"], platforms: ["windows"], view: "autoruns" },
  { id: "startup_persistence", label: "Startup & Persistence", aliases: ["registry_persistence"], platforms: ["windows"], view: "autoruns" },
  { id: "bits", label: "BITS", platforms: ["windows"], view: "bits" },
  { id: "wmi", label: "WMI", platforms: ["windows"], view: "wmi" },
  { id: "windows_ui", label: "Windows UI", platforms: ["windows"], view: "auto" },
  { id: "srum", label: "SRUM", platforms: ["windows"], view: "srum" },
  { id: "mft", label: "MFT / Filesystem", aliases: ["ntfs", "usn"], platforms: ["windows"], view: "filesystem" },
  { id: "motw", label: "MOTW / Downloaded Files", aliases: ["zone_identifier"], platforms: ["windows"], view: "auto" },
  { id: "email", label: "Email Artifacts", platforms: ["windows", "linux"], view: "auto" },
  { id: "user_activity", label: "User Activity", platforms: ["windows"], view: "auto" },
  { id: "userassist", label: "UserAssist", platforms: ["windows"], view: "auto" },
  { id: "recentdocs", label: "RecentDocs", platforms: ["windows"], view: "auto" },
  { id: "runmru", label: "RunMRU", platforms: ["windows"], view: "auto" },
  { id: "opensavemru", label: "OpenSaveMRU", platforms: ["windows"], view: "auto" },
  { id: "network", label: "Network", aliases: ["linux_network", "linux_ssh"], platforms: ["windows", "linux", "memory"], view: "network" },
  { id: "linux_journal", label: "Linux Journal", platforms: ["linux"], view: "evtx", platformShortcut: true },
  { id: "linux_auth", label: "Linux Auth", platforms: ["linux"], view: "network", platformShortcut: true },
  { id: "linux_lastlog", label: "Lastlog", platforms: ["linux"], view: "network", platformShortcut: true },
  { id: "linux_syslog", label: "Linux Syslog", platforms: ["linux"], view: "network", platformShortcut: true },
  { id: "linux_audit", label: "Linux Audit", platforms: ["linux"], view: "network", platformShortcut: true },
  { id: "linux_apache", label: "Apache Logs", platforms: ["linux"], view: "network", platformShortcut: true },
  { id: "linux_exim", label: "Exim Logs", platforms: ["linux"], view: "network", platformShortcut: true },
  { id: "linux_shell_history", label: "Linux Shell History", platforms: ["linux"], view: "execution", platformShortcut: true },
  { id: "linux_cron", label: "Linux Cron", platforms: ["linux"], view: "persistence", platformShortcut: true },
  { id: "linux_systemd", label: "Linux Systemd", platforms: ["linux"], view: "persistence", platformShortcut: true },
  { id: "linux_identity", label: "Linux Identity", platforms: ["linux"], view: "auto", platformShortcut: true },
  { id: "linux_sudoers", label: "Linux Sudoers", platforms: ["linux"], view: "persistence", platformShortcut: true },
  { id: "linux_packages", label: "Linux Packages", platforms: ["linux"], view: "auto", platformShortcut: true },
  { id: "linux_os_info", label: "Linux OS Info", platforms: ["linux"], view: "auto", platformShortcut: true },
  { id: "process", label: "Processes", platforms: ["memory"], view: "execution" },
  { id: "vads", label: "VADs", aliases: ["vad"], platforms: ["memory"], view: "auto" },
  { id: "dlls", label: "DLLs", aliases: ["dll"], platforms: ["memory"], view: "auto" },
  { id: "handles", label: "Handles", platforms: ["memory"], view: "auto" },
];

const ARTIFACT_LOOKUP = new Map<string, UiArtifactDefinition>();
for (const definition of ARTIFACT_REGISTRY) {
  ARTIFACT_LOOKUP.set(definition.id, definition);
  for (const alias of definition.aliases ?? []) ARTIFACT_LOOKUP.set(alias, definition);
}

export function getArtifactDefinition(value: string | null | undefined): UiArtifactDefinition | null {
  const normalized = String(value || "").trim().toLowerCase();
  if (!normalized) return null;
  return ARTIFACT_LOOKUP.get(normalized) ?? null;
}

export function artifactLabel(value: string | null | undefined): string {
  const normalized = String(value || "").trim().toLowerCase();
  if (normalized === "ntfs") return "NTFS";
  const definition = getArtifactDefinition(value);
  if (definition) return definition.label;
  const raw = String(value || "").trim();
  if (!raw) return "-";
  return raw.replaceAll("_", " ").replace(/\b\w/g, (letter) => letter.toUpperCase());
}

export function canonicalArtifactView(value: string | null | undefined): string {
  return getArtifactDefinition(value)?.id ?? String(value || "");
}

export function artifactEventView(value: string | null | undefined): EventView | "auto" {
  const definition = getArtifactDefinition(value);
  if (!definition) return "auto";
  if (definition.view === "execution") return "execution";
  if (definition.view === "persistence") return "persistence";
  return definition.view;
}

export function artifactOptions(values: string[], extras: string[] = []): string[] {
  const options = new Set(values.filter(Boolean));
  extras.forEach((value) => options.add(value));
  return Array.from(options).sort((left, right) => artifactLabel(left).localeCompare(artifactLabel(right)));
}

export function artifactOptionsForPlatforms(platforms: string[], options?: { shortcutOnly?: boolean }): string[] {
  const selected = new Set(platforms.map((item) => item.toLowerCase()));
  return ARTIFACT_REGISTRY.filter((entry) => entry.platforms.some((platform) => selected.has(platform)) && (!options?.shortcutOnly || entry.platformShortcut)).map((entry) => entry.id);
}
