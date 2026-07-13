import type { EvidencePlatform, EvidencePlatformCapabilities, EvidencePlatformProfile } from "../api/client";

export type UiPlatformDefinition = {
  id: EvidencePlatform | string;
  label: string;
  description: string;
  disabled?: boolean;
};

export const UI_PLATFORM_REGISTRY: UiPlatformDefinition[] = [
  { id: "auto", label: "Auto-detect", description: "Let Kairon infer Windows, Linux, Memory, Mixed, or unknown from paths, filenames, and collection contents." },
  { id: "windows", label: "Windows", description: "Use for Windows endpoint artifacts such as EVTX, registry hives, prefetch, and user profiles." },
  { id: "linux", label: "Linux", description: "Use for Linux triage artifacts, logs, inventory, persistence and related collections." },
  { id: "memory", label: "Memory", description: "Memory evidence exposes memory-first capabilities and can coexist with disk platforms in mixed evidence." },
  { id: "mixed", label: "Mixed", description: "A single evidence source that contains multiple platform families, such as Linux plus Memory." },
  { id: "macos", label: "macOS planned", description: "Visible for roadmap clarity. macOS artifacts are not supported yet.", disabled: true },
  { id: "unknown", label: "Unknown / Other", description: "Use when the source platform is unclear or non-OS-specific." },
];

export function platformUploadOptions() {
  return UI_PLATFORM_REGISTRY.filter((platform) => !["memory", "mixed"].includes(String(platform.id)));
}

export function capabilityEnabled(profile: Partial<EvidencePlatformProfile> | null | undefined, capability: keyof EvidencePlatformCapabilities): boolean {
  return Boolean(profile?.capabilities?.[capability]);
}
