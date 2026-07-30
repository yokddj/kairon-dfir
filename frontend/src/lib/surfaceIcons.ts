import { Cpu, HardDrive, Home, Layers, ShieldCheck } from "lucide-react";

// Single frontend translation point for the semantic icon identifier the
// backend Surface Registry declares on each workbench
// (SURFACE_REGISTRY.icon, backend/app/services/case_capabilities.py). The
// backend remains the source of truth for which identifier a surface has;
// this module only maps that identifier to a visual icon component -- it
// never derives an icon from a workbench/surface id, and no screen may add
// its own id-based branch for this.
export const SURFACE_ICONS: Record<string, typeof Home> = {
  "hard-drive": HardDrive,
  "shield-check": ShieldCheck,
  cpu: Cpu,
};

const FALLBACK_SURFACE_ICON = Layers;

export function resolveSurfaceIcon(icon: string | null | undefined): typeof Home {
  if (icon && Object.prototype.hasOwnProperty.call(SURFACE_ICONS, icon)) return SURFACE_ICONS[icon];
  return FALLBACK_SURFACE_ICON;
}
