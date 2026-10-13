/* Which memory views apply to an evidence's platform.

The backend reports, per evidence, what analysis can produce on its
detected platform (MemoryEvidencePreparation.result_views, from
capability_registry): the document families its plugins normalize into
and the frameworks that run them. A view that only ever shows one of
those families (Handles, VADs, Drivers... from Windows plugins) is left
out when the platform has no plugin for it, so a Linux image does not
list Windows-only tabs. Nothing is hidden while the platform is unknown.
*/

import type { MemoryPlatformResultViews } from "../api/client";
import type { MemoryTab } from "./memoryWorkspaceState";

type ViewRequirement = { families?: string[]; frameworks?: string[] };

// Tabs absent here (Overview, Processes, Graph, Timeline, Runs, Raw
// Observations, Artifacts) apply to every platform.
const TAB_REQUIREMENTS: Partial<Record<MemoryTab, ViewRequirement>> = {
  find_evil: { families: ["memory_findevil"] },
  shell_history: { families: ["memory_shell_history"] },
  memprocfs: { frameworks: ["memprocfs"] },
  network: { families: ["memory_network_connection"] },
  modules: { families: ["memory_process_module"] },
  handles: { families: ["memory_handle"] },
  drivers: { families: ["memory_driver"] },
  kernel: { families: ["memory_kernel_module"] },
  suspicious: { families: ["memory_suspicious_region"] },
  vads: { families: ["memory_vad"] },
  files: { families: ["memory_file_object"] },
  system: { families: ["memory_system_info"] },
};

// The Overview's result families (catalogue/landing names).
const FAMILY_REQUIREMENTS: Record<string, ViewRequirement> = {
  system_info: { families: ["memory_system_info"] },
  find_evil: { families: ["memory_findevil"] },
  shell_history: { families: ["memory_shell_history"] },
  modules: { families: ["memory_process_module"] },
  handles: { families: ["memory_handle"] },
  kernel_modules: { families: ["memory_kernel_module"] },
  drivers: { families: ["memory_driver"] },
  suspicious_regions: { families: ["memory_suspicious_region"] },
  network: { families: ["memory_network_connection"] },
};

function satisfied(requirement: ViewRequirement | undefined, views: MemoryPlatformResultViews | null | undefined): boolean {
  if (!requirement || !views) return true;
  const familyOk = !requirement.families || requirement.families.some((f) => views.presentation_families.includes(f));
  const frameworkOk = !requirement.frameworks || requirement.frameworks.some((f) => views.frameworks.includes(f));
  return familyOk && frameworkOk;
}

export function memoryTabApplies(tab: MemoryTab, views: MemoryPlatformResultViews | null | undefined): boolean {
  return satisfied(TAB_REQUIREMENTS[tab], views);
}

export function memoryFamilyApplies(family: string, views: MemoryPlatformResultViews | null | undefined): boolean {
  return satisfied(FAMILY_REQUIREMENTS[family], views);
}
