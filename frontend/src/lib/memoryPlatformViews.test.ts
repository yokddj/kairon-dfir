import { describe, expect, it } from "vitest";
import { memoryFamilyApplies, memoryTabApplies } from "./memoryPlatformViews";
import { MEMORY_TABS } from "./memoryWorkspaceState";

const LINUX = { presentation_families: ["memory_network_connection", "memory_process", "memory_shell_history"], frameworks: ["volatility3"] };
const WINDOWS = {
  presentation_families: [
    "memory_driver", "memory_file_object", "memory_findevil", "memory_handle", "memory_kernel_module", "memory_network_connection",
    "memory_process", "memory_process_module", "memory_process_observation", "memory_shell_history", "memory_suspicious_region",
    "memory_system_info", "memory_vad",
  ],
  frameworks: ["memprocfs", "volatility3"],
};

describe("memoryPlatformViews", () => {
  it("keeps only the tabs a Linux image can fill", () => {
    const tabs = MEMORY_TABS.filter((t) => memoryTabApplies(t.key, LINUX)).map((t) => t.key);
    expect(tabs).toEqual(["overview", "processes", "graph", "shell_history", "timeline", "network", "runs", "raw"]);
  });

  it("keeps every tab for Windows and while the platform is unknown", () => {
    expect(MEMORY_TABS.every((t) => memoryTabApplies(t.key, WINDOWS))).toBe(true);
    expect(MEMORY_TABS.every((t) => memoryTabApplies(t.key, null))).toBe(true);
  });

  it("filters Overview families the same way", () => {
    expect(memoryFamilyApplies("handles", LINUX)).toBe(false);
    expect(memoryFamilyApplies("network", LINUX)).toBe(true);
    expect(memoryFamilyApplies("processes", LINUX)).toBe(true);
    expect(memoryFamilyApplies("handles", undefined)).toBe(true);
  });
});
